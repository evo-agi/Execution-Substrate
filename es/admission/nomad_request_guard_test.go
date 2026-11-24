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
// added without the token. A second Nomad client (for example PR 12's
// reliable-submit operational provider) must route its requests through a
// builder that sets X-Nomad-Token from ES's token custody and be added to
// nomadTokenRequestBuilders, together with a runtime check like the one
// above; see the change list in the PR #31 report, section 8.

// nomadTokenRequestBuilders names the methods of *nomadClient that set ES's
// token on every request they build, with the index of their path argument.
var nomadTokenRequestBuilders = map[string]int{
	"newJobRequest": 2,
	"get":           1,
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
		t.Fatalf("Nomad request paths outside a token-setting builder (route them through nomadClient.newJobRequest or nomadClient.get, or add a builder that sets X-Nomad-Token; PR #31 report section 8):\n%s", strings.Join(violations, "\n"))
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
	methods := map[string]*ast.FuncDecl{}
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
			if receiverName, ok := nomadClientReceiver(function); ok && receiverName != "" {
				methods[function.Name.Name] = function
			}
			ast.Inspect(function, func(node ast.Node) bool {
				if call, ok := node.(*ast.CallExpr); ok && isHeaderCall(call, "Del") && len(call.Args) == 1 && isIdent(call.Args[0], "nomadTokenHeader") {
					t.Errorf("%s: %s deletes the Nomad token header", fileSet.Position(call.Pos()), function.Name.Name)
				}
				return true
			})
		}
	}
	if problem := nomadTokenBuilderProblem(methods); problem != "" {
		t.Fatal(problem)
	}
}

// nomadTokenBuilderProblem checks that newJobRequest sets the token header
// from the client's token and that every other builder builds its request
// with newJobRequest. It returns "" when both hold.
func nomadTokenBuilderProblem(methods map[string]*ast.FuncDecl) string {
	for name := range nomadTokenRequestBuilders {
		if methods[name] == nil {
			return fmt.Sprintf("nomadClient.%s is missing", name)
		}
	}
	builder := methods["newJobRequest"]
	receiver, _ := nomadClientReceiver(builder)
	setsToken := false
	ast.Inspect(builder.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if ok && isHeaderCall(call, "Set") && len(call.Args) == 2 && isIdent(call.Args[0], "nomadTokenHeader") && isSelector(call.Args[1], receiver, "token") {
			setsToken = true
		}
		return true
	})
	if !setsToken {
		return "nomadClient.newJobRequest does not set nomadTokenHeader from the client's token"
	}
	for name := range nomadTokenRequestBuilders {
		if name == "newJobRequest" {
			continue
		}
		function := methods[name]
		receiver, _ := nomadClientReceiver(function)
		usesBuilder := false
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok && isSelector(call.Fun, receiver, "newJobRequest") {
				usesBuilder = true
			}
			return true
		})
		if !usesBuilder {
			return fmt.Sprintf("nomadClient.%s does not build its request with newJobRequest", name)
		}
	}
	return ""
}

// nomadRequestGuardViolations reports each string literal in source that
// names a Nomad API path but is not the leftmost operand of the path argument
// of a token-setting builder called on the receiver of a *nomadClient method
// (or, for access-control paths, inside nomadClient.verifyAccessControl). It
// also reports hand-built HTTP requests inside *nomadClient methods other
// than newJobRequest and verifyAccessControl.
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
		receiver, isClientMethod := nomadClientReceiver(function)
		if !isClientMethod || receiver == "" {
			continue
		}
		if function.Name.Name == "verifyAccessControl" {
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
				if index, ok := nomadTokenRequestBuilders[selector.Sel.Name]; ok && index < len(call.Args) {
					if literal := leftmostStringLiteral(call.Args[index]); literal != nil {
						approved[literal.Pos()] = true
					}
				}
			}
			if function.Name.Name != "newJobRequest" && function.Name.Name != "verifyAccessControl" && buildsHTTPRequest(call) {
				violations = append(violations, fmt.Sprintf("%s: nomadClient.%s builds an HTTP request by hand instead of with newJobRequest", fileSet.Position(call.Pos()), function.Name.Name))
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
			violations = append(violations, fmt.Sprintf("%s: %q names a Nomad API path outside a token-setting builder", fileSet.Position(literal.Pos()), value))
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

func nomadClientReceiver(function *ast.FuncDecl) (string, bool) {
	if function.Recv == nil || len(function.Recv.List) != 1 {
		return "", false
	}
	field := function.Recv.List[0]
	star, ok := field.Type.(*ast.StarExpr)
	if !ok || !isIdent(star.X, "nomadClient") {
		return "", false
	}
	if len(field.Names) != 1 {
		return "", true
	}
	return field.Names[0].Name, true
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
		"builder with literal":   `func (c *nomadClient) submit(ctx context.Context) { _, _ = c.newJobRequest(ctx, http.MethodPost, "/v1/jobs", nil, nil) }`,
		"get with concatenation": `func (c *nomadClient) read(ctx context.Context, id string) { _, _ = c.get(ctx, "/v1/job/"+id+"/allocations", nil) }`,
		"access control check":   `func (c *nomadClient) verifyAccessControl(ctx context.Context) { u := c.baseURL.ResolveReference(&url.URL{Path: "/v1/acl/token/self"}); _, _ = http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil) }`,
		"ES's own services":      `func read(c *serviceClient, ctx context.Context) { _, _ = c.get(ctx, "/v1/blobs/x"); _ = "/v1/executions/"; _ = "/v1/trust-model" }`,
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
		"another client without the token":  `func (p *operationalProvider) observe(ctx context.Context, name string) { _, _ = p.prepareExchange(ctx, http.MethodGet, "/v1/job/"+name, nil) }`,
		"hand-built request in nomadClient": `func (c *nomadClient) submitRaw(ctx context.Context) { _, _ = http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL.String(), nil) }`,
		"path held in a constant":           `const jobsPath = "/v1/jobs"`,
		"path in a URL literal":             `func (c *nomadClient) build() { _ = url.URL{Path: "/v1/jobs"} }`,
		"split path fragment":               `func (c *nomadClient) read(ctx context.Context, kind string) { target := "/v1/" + kind; _ = target }`,
		"full URL":                          `var target = "http://127.0.0.1:4646/v1/jobs"`,
		"raw string path":                   "var target = `/v1/allocations`",
		"builder on another value":          `func (c *nomadClient) read(ctx context.Context, other *nomadClient) { _, _ = other.get(ctx, "/v1/job/x", nil) }`,
		"builder from a free function":      `func read(ctx context.Context, c *nomadClient) { _, _ = c.get(ctx, "/v1/job/x", nil) }`,
		"access control path elsewhere":     `func (c *nomadClient) policies(ctx context.Context) { _, _ = c.get(ctx, "/v1/job/x", nil); _ = "/v1/acl/policies" }`,
		"path not leftmost":                 `func (c *nomadClient) read(ctx context.Context, base string) { _, _ = c.get(ctx, base+"/v1/job/x", nil) }`,
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
// when newJobRequest stops setting the token or get stops using it.
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
`
	cases := map[string]struct {
		source string
		want   string
	}{
		"current form":           {good, ""},
		"token header not set":   {strings.Replace(good, "request.Header.Set(nomadTokenHeader, c.token)", "_ = c.token", 1), "does not set nomadTokenHeader"},
		"another value as token": {strings.Replace(good, "request.Header.Set(nomadTokenHeader, c.token)", `request.Header.Set(nomadTokenHeader, "")`, 1), "does not set nomadTokenHeader"},
		"get bypasses builder":   {strings.Replace(good, "request, err := c.newJobRequest(ctx, http.MethodGet, requestPath, query, nil)", "request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestPath, nil)", 1), "does not build its request with newJobRequest"},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "builders.go", testCase.source, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			methods := map[string]*ast.FuncDecl{}
			for _, declaration := range file.Decls {
				if function, ok := declaration.(*ast.FuncDecl); ok {
					methods[function.Name.Name] = function
				}
			}
			problem := nomadTokenBuilderProblem(methods)
			if testCase.want == "" && problem != "" || testCase.want != "" && !strings.Contains(problem, testCase.want) {
				t.Fatalf("problem = %q, want %q", problem, testCase.want)
			}
		})
	}
}
