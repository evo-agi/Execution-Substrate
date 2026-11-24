package admission

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The Nomad token guard has two halves. The runtime half,
// TestEveryNomadJobRequestCarriesTheTokenAndTheSubmitNamespace, drives every
// nomadClient method that talks to Nomad and checks the token header on each
// request. The static half below fails when any non-test Go file in the
// module names a Nomad API path anywhere except as the path argument of a
// request builder that sets ES's token, so a new Nomad submit path cannot be
// added without the token. Two types send requests to Nomad: nomadClient, the
// client of the current submit path, and operationalProvider, PR 12's
// reliable-submit operational provider, whose runtime half is
// TestEveryOperationalNomadRequestCarriesTheTokenAndTheOperationalNamespace.
// A further Nomad client must route its requests through a builder that sets
// X-Nomad-Token from ES's token custody, be added to both tables below, and
// get a runtime check like those two; see the change list in the PR #31
// report, section 8.

// nomadTokenRequestBuilders names, for each type that sends requests to
// Nomad, the methods that set ES's token on every request they build, with
// the index of their path argument.
var nomadTokenRequestBuilders = map[string]map[string]int{
	"nomadClient":         {"newJobRequest": 2, "get": 1},
	"operationalProvider": {"prepareExchange": 2},
}

// nomadTokenHeaderSetters names, for each type in nomadTokenRequestBuilders,
// the builder that makes the HTTP request and sets the token header on it.
// Every other builder of that type must build its request with this one.
var nomadTokenHeaderSetters = map[string]string{
	"nomadClient":         "newJobRequest",
	"operationalProvider": "prepareExchange",
}

// nomadAPIPathPrefixes are the Nomad HTTP API prefixes. None of ES's own
// services (ES's API, ARS, EGS) use them.
var nomadAPIPathPrefixes = []string{
	"/v1/job", "/v1/allocation", "/v1/evaluation", "/v1/deployment", "/v1/client/",
	"/v1/node", "/v1/volume", "/v1/var", "/v1/namespace", "/v1/event/stream",
	"/v1/search", "/v1/service", "/v1/scaling", "/v1/plugin", "/v1/acl/", "/v1/agent/",
	"/v1/operator/", "/v1/status/", "/v1/system/", "/v1/regions", "/v1/metrics",
	"/v1/quota", "/v1/sentinel", "/v1/recommendation",
}

// nomadAccessControlPathPrefix may appear only in nomadClient's
// verifyAccessControl, whose anonymous-policy request deliberately carries no
// token.
const nomadAccessControlPathPrefix = "/v1/acl/"

func TestEveryNomadRequestPathGoesThroughTheTokenBuilder(t *testing.T) {
	root := guardModuleRoot(t)
	var violations []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			name := entry.Name()
			if path != root && (strings.HasPrefix(name, ".") || name == "testdata" || name == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		found, err := nomadRequestGuardViolations(filepath.ToSlash(relative), source)
		if err != nil {
			return err
		}
		violations = append(violations, found...)
		return nil
	})
	if err != nil {
		t.Fatalf("scan module: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("Nomad request paths outside a token-setting builder (route them through nomadClient.newJobRequest, nomadClient.get or operationalProvider.prepareExchange, or add a builder that sets X-Nomad-Token; PR #31 report section 8):\n%s", strings.Join(violations, "\n"))
	}
}

func TestNomadTokenRequestBuildersSetTheToken(t *testing.T) {
	root := guardModuleRoot(t)
	directory := filepath.Join(root, "es", "admission")
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	fileSet := token.NewFileSet()
	methods := map[string]map[string]*ast.FuncDecl{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fileSet, filepath.Join(directory, name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if typeName, receiverName, ok := nomadRequestReceiver(function); ok && receiverName != "" {
				if methods[typeName] == nil {
					methods[typeName] = map[string]*ast.FuncDecl{}
				}
				methods[typeName][function.Name.Name] = function
			}
			ast.Inspect(function, func(node ast.Node) bool {
				if call, ok := node.(*ast.CallExpr); ok && isHeaderCall(call, "Del") && len(call.Args) == 1 && isIdent(call.Args[0], "nomadTokenHeader") {
					t.Errorf("%s: %s deletes the Nomad token header", guardPosition(fileSet, call.Pos()), function.Name.Name)
				}
				return true
			})
		}
	}
	if problem := nomadTokenBuilderProblem(methods); problem != "" {
		t.Fatal(problem)
	}
}

// nomadTokenBuilderProblem checks, for each type in nomadTokenRequestBuilders,
// that its header setter sets the token header from the receiver's token and
// that every other builder of the type builds its request with the setter.
// It returns "" when both hold for every type.
func nomadTokenBuilderProblem(methods map[string]map[string]*ast.FuncDecl) string {
	types := make([]string, 0, len(nomadTokenRequestBuilders))
	for typeName := range nomadTokenRequestBuilders {
		types = append(types, typeName)
	}
	sort.Strings(types)
	for _, typeName := range types {
		if problem := nomadTypeTokenBuilderProblem(typeName, methods[typeName]); problem != "" {
			return problem
		}
	}
	return ""
}

func nomadTypeTokenBuilderProblem(typeName string, methods map[string]*ast.FuncDecl) string {
	for name := range nomadTokenRequestBuilders[typeName] {
		if methods[name] == nil {
			return fmt.Sprintf("%s.%s is missing", typeName, name)
		}
	}
	setter := nomadTokenHeaderSetters[typeName]
	builder := methods[setter]
	if builder == nil {
		return fmt.Sprintf("%s.%s is missing", typeName, setter)
	}
	_, receiver, _ := nomadRequestReceiver(builder)
	setsToken := false
	ast.Inspect(builder.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if ok && isHeaderCall(call, "Set") && len(call.Args) == 2 && isIdent(call.Args[0], "nomadTokenHeader") && isSelector(call.Args[1], receiver, "token") {
			setsToken = true
		}
		return true
	})
	if !setsToken {
		return fmt.Sprintf("%s.%s does not set nomadTokenHeader from the receiver's token", typeName, setter)
	}
	for name := range nomadTokenRequestBuilders[typeName] {
		if name == setter {
			continue
		}
		function := methods[name]
		_, receiver, _ := nomadRequestReceiver(function)
		usesBuilder := false
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok && isSelector(call.Fun, receiver, setter) {
				usesBuilder = true
			}
			return true
		})
		if !usesBuilder {
			return fmt.Sprintf("%s.%s does not build its request with %s", typeName, name, setter)
		}
	}
	return ""
}

// nomadRequestGuardViolations reports each string literal in source that
// names a Nomad API path but is not the leftmost operand of the path argument
// of a token-setting builder of the method's own type, called on the receiver
// of a method of a type in nomadTokenRequestBuilders (or, for access-control
// paths, inside nomadClient.verifyAccessControl). It also reports hand-built
// HTTP requests inside methods of those types other than the type's header
// setter and nomadClient.verifyAccessControl.
func nomadRequestGuardViolations(name string, source []byte) ([]string, error) {
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, name, source, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	approved := map[token.Pos]bool{}
	var violations []string
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		typeName, receiver, isClientMethod := nomadRequestReceiver(function)
		if !isClientMethod || receiver == "" {
			continue
		}
		accessControl := typeName == "nomadClient" && function.Name.Name == "verifyAccessControl"
		if accessControl {
			ast.Inspect(function.Body, func(node ast.Node) bool {
				if literal, ok := node.(*ast.BasicLit); ok && literal.Kind == token.STRING {
					if value, err := strconv.Unquote(literal.Value); err == nil && strings.HasPrefix(value, nomadAccessControlPathPrefix) {
						approved[literal.Pos()] = true
					}
				}
				return true
			})
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if selector, ok := call.Fun.(*ast.SelectorExpr); ok && isIdent(selector.X, receiver) {
				if index, ok := nomadTokenRequestBuilders[typeName][selector.Sel.Name]; ok && index < len(call.Args) {
					if literal := leftmostStringLiteral(call.Args[index]); literal != nil {
						approved[literal.Pos()] = true
					}
				}
			}
			if setter := nomadTokenHeaderSetters[typeName]; function.Name.Name != setter && !accessControl && buildsHTTPRequest(call) {
				violations = append(violations, fmt.Sprintf("%s: %s.%s builds an HTTP request by hand instead of with %s", guardPosition(fileSet, call.Pos()), typeName, function.Name.Name, setter))
			}
			return true
		})
	}
	ast.Inspect(file, func(node ast.Node) bool {
		literal, ok := node.(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING || approved[literal.Pos()] {
			return true
		}
		value, err := strconv.Unquote(literal.Value)
		if err == nil && namesNomadAPIPath(value) {
			violations = append(violations, fmt.Sprintf("%s: %q names a Nomad API path outside a token-setting builder", guardPosition(fileSet, literal.Pos()), value))
		}
		return true
	})
	sort.Strings(violations)
	return violations, nil
}

// namesNomadAPIPath reports whether value holds a Nomad API path anywhere
// (including inside a full URL), or is a leading fragment of one such as
// "/v1/" that a later concatenation could complete.
func namesNomadAPIPath(value string) bool {
	if strings.HasPrefix(value, "v1/") {
		value = "/" + value
	}
	for _, prefix := range nomadAPIPathPrefixes {
		if strings.Contains(value, prefix) {
			return true
		}
		if strings.HasPrefix(value, "/v1") && strings.HasPrefix(prefix, value) {
			return true
		}
	}
	return false
}

// nomadRequestReceiver reports whether function is a method with a pointer
// receiver of a type in nomadTokenRequestBuilders, and returns the type's
// name and the receiver's name ("" when the receiver is unnamed).
func nomadRequestReceiver(function *ast.FuncDecl) (string, string, bool) {
	if function.Recv == nil || len(function.Recv.List) != 1 {
		return "", "", false
	}
	field := function.Recv.List[0]
	star, ok := field.Type.(*ast.StarExpr)
	if !ok {
		return "", "", false
	}
	typeName, ok := star.X.(*ast.Ident)
	if !ok || nomadTokenRequestBuilders[typeName.Name] == nil {
		return "", "", false
	}
	if len(field.Names) != 1 {
		return typeName.Name, "", true
	}
	return typeName.Name, field.Names[0].Name, true
}

func leftmostStringLiteral(expression ast.Expr) *ast.BasicLit {
	for {
		switch node := expression.(type) {
		case *ast.BinaryExpr:
			if node.Op != token.ADD {
				return nil
			}
			expression = node.X
		case *ast.ParenExpr:
			expression = node.X
		case *ast.BasicLit:
			if node.Kind == token.STRING {
				return node
			}
			return nil
		default:
			return nil
		}
	}
}

func buildsHTTPRequest(call *ast.CallExpr) bool {
	if selector, ok := call.Fun.(*ast.SelectorExpr); ok && isIdent(selector.X, "http") {
		switch selector.Sel.Name {
		case "NewRequest", "NewRequestWithContext":
			return true
		}
	}
	return false
}

func isHeaderCall(call *ast.CallExpr, method string) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != method {
		return false
	}
	header, ok := selector.X.(*ast.SelectorExpr)
	return ok && header.Sel.Name == "Header"
}

func isIdent(expression ast.Expr, name string) bool {
	identifier, ok := expression.(*ast.Ident)
	return ok && name != "" && identifier.Name == name
}

func isSelector(expression ast.Expr, receiver string, field string) bool {
	selector, ok := expression.(*ast.SelectorExpr)
	return ok && isIdent(selector.X, receiver) && selector.Sel.Name == field
}

func guardModuleRoot(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil {
			return directory
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			t.Fatal("go.mod not found above the test directory")
		}
		directory = parent
	}
}

// TestNomadRequestGuardCatchesEachBypass proves the static guard refuses each
// way a Nomad request could skip the token, and accepts the current forms.
func TestNomadRequestGuardCatchesEachBypass(t *testing.T) {
	const header = "package admission\n\nimport (\n\t\"context\"\n\t\"net/http\"\n\t\"net/url\"\n)\n\n"
	accepted := map[string]string{
		"builder with literal":      `func (c *nomadClient) submit(ctx context.Context) { _, _ = c.newJobRequest(ctx, http.MethodPost, "/v1/jobs", nil, nil) }`,
		"get with concatenation":    `func (c *nomadClient) read(ctx context.Context, id string) { _, _ = c.get(ctx, "/v1/job/"+id+"/allocations", nil) }`,
		"access control check":      `func (c *nomadClient) verifyAccessControl(ctx context.Context) { u := c.baseURL.ResolveReference(&url.URL{Path: "/v1/acl/token/self"}); _, _ = http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil) }`,
		"ES's own services":         `func read(c *serviceClient, ctx context.Context) { _, _ = c.get(ctx, "/v1/blobs/x"); _ = "/v1/executions/"; _ = "/v1/trust-model" }`,
		"operational register":      `func (p *operationalProvider) prepareRegister(ctx context.Context, body []byte) { _, _ = p.prepareExchange(ctx, http.MethodPost, "/v1/jobs", body) }`,
		"operational observation":   `func (p *operationalProvider) observe(ctx context.Context, name string) { _, _ = p.prepareExchange(ctx, http.MethodGet, "/v1/job/"+name+"/evaluations", nil) }`,
		"operational header setter": `func (p *operationalProvider) prepareExchange(ctx context.Context, method, path string) { _, _ = http.NewRequestWithContext(ctx, method, path, nil) }`,
	}
	for name, body := range accepted {
		t.Run("accepts "+name, func(t *testing.T) {
			violations, err := nomadRequestGuardViolations("accepted.go", []byte(header+body+"\n"))
			if err != nil {
				t.Fatal(err)
			}
			if len(violations) != 0 {
				t.Fatalf("violations = %v, want none", violations)
			}
		})
	}
	refused := map[string]string{
		"another client without the token":     `func (p *otherProvider) observe(ctx context.Context, name string) { _, _ = p.prepareExchange(ctx, http.MethodGet, "/v1/job/"+name, nil) }`,
		"provider builder off the receiver":    `func (d *operationalDomain) send(ctx context.Context, p *operationalProvider) { _, _ = p.prepareExchange(ctx, http.MethodPost, "/v1/jobs", nil) }`,
		"provider builder from a function":     `func register(ctx context.Context, p *operationalProvider) { _, _ = p.prepareExchange(ctx, http.MethodPost, "/v1/jobs", nil) }`,
		"provider with another type's builder": `func (p *operationalProvider) read(ctx context.Context) { _, _ = p.get(ctx, "/v1/job/x", nil) }`,
		"hand-built request in the provider":   `func (p *operationalProvider) raw(ctx context.Context) { _, _ = http.NewRequestWithContext(ctx, http.MethodGet, p.target.String(), nil) }`,
		"provider access control path":         `func (p *operationalProvider) verifyAccessControl(ctx context.Context) { _, _ = p.prepareExchange(ctx, http.MethodGet, "/v1/job/x", nil); _ = "/v1/acl/token/self" }`,
		"provider path not leftmost":           `func (p *operationalProvider) read(ctx context.Context, base string) { _, _ = p.prepareExchange(ctx, http.MethodGet, base+"/v1/job/x", nil) }`,
		"hand-built request in nomadClient":    `func (c *nomadClient) submitRaw(ctx context.Context) { _, _ = http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL.String(), nil) }`,
		"path held in a constant":              `const jobsPath = "/v1/jobs"`,
		"path in a URL literal":                `func (c *nomadClient) build() { _ = url.URL{Path: "/v1/jobs"} }`,
		"split path fragment":                  `func (c *nomadClient) read(ctx context.Context, kind string) { target := "/v1/" + kind; _ = target }`,
		"full URL":                             `var target = "http://127.0.0.1:4646/v1/jobs"`,
		"raw string path":                      "var target = `/v1/allocations`",
		"builder on another value":             `func (c *nomadClient) read(ctx context.Context, other *nomadClient) { _, _ = other.get(ctx, "/v1/job/x", nil) }`,
		"builder from a free function":         `func read(ctx context.Context, c *nomadClient) { _, _ = c.get(ctx, "/v1/job/x", nil) }`,
		"access control path elsewhere":        `func (c *nomadClient) policies(ctx context.Context) { _, _ = c.get(ctx, "/v1/job/x", nil); _ = "/v1/acl/policies" }`,
		"path not leftmost":                    `func (c *nomadClient) read(ctx context.Context, base string) { _, _ = c.get(ctx, base+"/v1/job/x", nil) }`,
	}
	for name, body := range refused {
		t.Run("refuses "+name, func(t *testing.T) {
			violations, err := nomadRequestGuardViolations("refused.go", []byte(header+body+"\n"))
			if err != nil {
				t.Fatal(err)
			}
			if len(violations) == 0 {
				t.Fatal("guard accepted a bypass")
			}
		})
	}
}

// TestNomadTokenBuilderCheckCatchesALostToken proves the builder check fails
// when newJobRequest or the operational provider's prepareExchange stops
// setting the token, or get stops using newJobRequest.
func TestNomadTokenBuilderCheckCatchesALostToken(t *testing.T) {
	const good = `package admission
func (c *nomadClient) newJobRequest(ctx context.Context, method string, requestPath string, query url.Values, body io.Reader) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, method, requestPath, body)
	if err != nil { return nil, err }
	request.Header.Set(nomadTokenHeader, c.token)
	return request, nil
}
func (c *nomadClient) get(ctx context.Context, requestPath string, query url.Values) (*http.Response, error) {
	request, err := c.newJobRequest(ctx, http.MethodGet, requestPath, query, nil)
	if err != nil { return nil, err }
	return c.client.Do(request)
}
func (p *operationalProvider) prepareExchange(ctx context.Context, method, path string, body []byte) (preparedOperationalExchange, error) {
	req, err := http.NewRequestWithContext(ctx, method, path, nil)
	if err != nil { return preparedOperationalExchange{}, err }
	req.Close = true
	req.Header.Set(nomadTokenHeader, p.token)
	return preparedOperationalExchange{request: req}, nil
}
`
	cases := map[string]struct {
		source string
		want   string
	}{
		"current form":                  {good, ""},
		"token header not set":          {strings.Replace(good, "request.Header.Set(nomadTokenHeader, c.token)", "_ = c.token", 1), "does not set nomadTokenHeader"},
		"another value as token":        {strings.Replace(good, "request.Header.Set(nomadTokenHeader, c.token)", `request.Header.Set(nomadTokenHeader, "")`, 1), "does not set nomadTokenHeader"},
		"get bypasses builder":          {strings.Replace(good, "request, err := c.newJobRequest(ctx, http.MethodGet, requestPath, query, nil)", "request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestPath, nil)", 1), "does not build its request with newJobRequest"},
		"provider token not set":        {strings.Replace(good, "req.Header.Set(nomadTokenHeader, p.token)", "_ = p.token", 1), "operationalProvider.prepareExchange does not set nomadTokenHeader"},
		"provider sends another value":  {strings.Replace(good, "req.Header.Set(nomadTokenHeader, p.token)", "req.Header.Set(nomadTokenHeader, p.realm.host)", 1), "operationalProvider.prepareExchange does not set nomadTokenHeader"},
		"provider sends another header": {strings.Replace(good, "req.Header.Set(nomadTokenHeader, p.token)", `req.Header.Set("X-Nomad-Index", p.token)`, 1), "operationalProvider.prepareExchange does not set nomadTokenHeader"},
		"provider builder missing":      {strings.Replace(good, "func (p *operationalProvider) prepareExchange(", "func (p *operationalProvider) prepareOther(", 1), "operationalProvider.prepareExchange is missing"},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "builders.go", testCase.source, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			methods := map[string]map[string]*ast.FuncDecl{}
			for _, declaration := range file.Decls {
				if function, ok := declaration.(*ast.FuncDecl); ok {
					if typeName, _, ok := nomadRequestReceiver(function); ok {
						if methods[typeName] == nil {
							methods[typeName] = map[string]*ast.FuncDecl{}
						}
						methods[typeName][function.Name.Name] = function
					}
				}
			}
			problem := nomadTokenBuilderProblem(methods)
			if testCase.want == "" && problem != "" || testCase.want != "" && !strings.Contains(problem, testCase.want) {
				t.Fatalf("problem = %q, want %q", problem, testCase.want)
			}
		})
	}
}
