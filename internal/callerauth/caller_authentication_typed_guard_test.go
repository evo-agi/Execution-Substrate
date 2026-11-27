package callerauth_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"execution-substrate/internal/testutil"
)

// The typed half of the guard that keeps caller identity reading inside
// internal/callerauth (red-team R4). TestCallerIdentityIsReadOnlyByCallerauth
// matches names in every production file; this half type-checks every
// production package of the module, for each platform the services are built
// for, and matches what a selector refers to, so a read through a variable, a
// type alias or an embedded struct is caught too.

// callerIdentityModule is the module path of this repository.
const callerIdentityModule = "execution-substrate"

const callerauthImportPath = callerIdentityModule + "/internal/callerauth"

// callerIdentityForbiddenImports may be imported only inside
// internal/callerauth: the test support that builds caller certificates.
var callerIdentityForbiddenImports = []string{
	callerauthImportPath + "/callerauthtest",
}

const goSpiffeModule = "github.com/spiffe/go-spiffe/v2/"

// goSpiffeAllowedImports are the only go-spiffe packages that code outside
// internal/callerauth may import (audit 11, A11-1): the ID type and parser,
// which cannot read a certificate (getting a URI out of one is the URIs read
// below; PR 12's private submit handoff uses the ID type), and the packages a
// workload uses to fetch its own identity. Every other go-spiffe package is
// refused, x509svid, spiffetls and spiffegrpc among them, which read a peer's
// identity from its certificate or connection. The list is closed, so a
// package that a later go-spiffe release adds is refused too.
var goSpiffeAllowedImports = []string{
	goSpiffeModule + "spiffeid",
	goSpiffeModule + "workloadapi",
	goSpiffeModule + "svid/jwtsvid",
	goSpiffeModule + "proto/spiffe/workload",
}

// callerIdentityTokenReaders are the functions and methods of the allowed
// go-spiffe packages that read a peer's identity from its JWT-SVID, by
// package. Code outside internal/callerauth may not use them.
var callerIdentityTokenReaders = map[string][]string{
	goSpiffeModule + "svid/jwtsvid":          {"ParseAndValidate", "ParseInsecure"},
	goSpiffeModule + "workloadapi":           {"ValidateJWTSVID"},
	goSpiffeModule + "proto/spiffe/workload": {"ValidateJWTSVID"},
}

func callerIdentityImportForbidden(path string) bool {
	if slices.Contains(callerIdentityForbiddenImports, path) {
		return true
	}
	return strings.HasPrefix(path, goSpiffeModule) && !slices.Contains(goSpiffeAllowedImports, path)
}

// callerIdentityCertificateFields are the x509.Certificate fields that carry
// or encode a caller identity or its issuer: the URI SANs, the issuer name,
// its raw encoding, and the raw extensions (which hold the subjectAltName).
var callerIdentityCertificateFields = []string{"URIs", "Issuer", "RawIssuer", "Extensions"}

// callerIdentityAPIPackages are the import paths of callerIdentityAPIDirs,
// the list the name-based half uses too.
var callerIdentityAPIPackages = func() []string {
	paths := make([]string, 0, len(callerIdentityAPIDirs))
	for _, dir := range callerIdentityAPIDirs {
		paths = append(paths, callerIdentityModule+"/"+dir)
	}
	return paths
}()

// callerConnectionServerPackages are the packages whose http.Server hands
// the TLS connections it accepts to callerauth.ConnContext: ES's server
// setup. Each sets the hook exactly once, as the ConnContext field of an
// http.Server composite literal, and no other code refers to ConnContext.
var callerConnectionServerPackages = []string{callerIdentityModule + "/es/app"}

// callerConnectionAPIPackages are the service API packages that read their
// caller from the connection with Authenticator.AuthenticateConnection:
// ES's. No other code refers to AuthenticateConnection, and these packages
// do not refer to Authenticate, which reads r.TLS.
var callerConnectionAPIPackages = []string{callerIdentityModule + "/es/api"}

// callerauthFunctionName returns the name of the callerauth function, or of
// the callerauth method as Type.Method, that object is, or "".
func callerauthFunctionName(object types.Object) string {
	function, ok := object.(*types.Func)
	if !ok || function.Pkg() == nil || function.Pkg().Path() != callerauthImportPath {
		return ""
	}
	receiver := function.Signature().Recv()
	if receiver == nil {
		return function.Name()
	}
	typ := types.Unalias(receiver.Type())
	if pointer, ok := typ.(*types.Pointer); ok {
		typ = types.Unalias(pointer.Elem())
	}
	if named, ok := typ.(*types.Named); ok {
		return named.Obj().Name() + "." + function.Name()
	}
	return function.Name()
}

// isNamedType reports whether t, through any alias, is the named type
// pkg.name.
func isNamedType(t types.Type, pkg, name string) bool {
	named, ok := types.Unalias(t).(*types.Named)
	return ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == pkg && named.Obj().Name() == name
}

// connContextHooks returns the identifiers in files that are the value of
// the ConnContext field in a composite literal of net/http.Server: the one
// place ES's server setup may refer to callerauth.ConnContext.
func connContextHooks(files []*ast.File, info *types.Info) map[*ast.Ident]bool {
	hooks := map[*ast.Ident]bool{}
	for _, file := range files {
		ast.Inspect(file, func(node ast.Node) bool {
			literal, ok := node.(*ast.CompositeLit)
			if !ok || !isNamedType(info.TypeOf(literal), "net/http", "Server") {
				return true
			}
			for _, element := range literal.Elts {
				pair, ok := element.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := pair.Key.(*ast.Ident)
				if !ok {
					continue
				}
				field, ok := info.Uses[key].(*types.Var)
				if !ok || !field.IsField() || field.Pkg() == nil || field.Pkg().Path() != "net/http" || field.Name() != "ConnContext" || !isFieldOf(field, "Server") {
					continue
				}
				switch value := ast.Unparen(pair.Value).(type) {
				case *ast.Ident:
					hooks[value] = true
				case *ast.SelectorExpr:
					hooks[value.Sel] = true
				}
			}
			return true
		})
	}
	return hooks
}

type callerIdentityBuildTarget struct {
	goos   string
	goarch string
}

func (target callerIdentityBuildTarget) String() string { return target.goos + "/" + target.goarch }

// The services run on Linux, on amd64 (the Remote Alpha box) and on arm64
// (the control-plane images that an Apple-silicon Docker host builds, and the
// supported local proof's runtime support binary); macOS on arm64 is the
// development platform. TestCallerIdentityTypedGuardCoversTheScriptsBuildTargets
// fails when a script builds for another Linux architecture.
var callerIdentityBuildTargets = []callerIdentityBuildTarget{{"linux", "amd64"}, {"linux", "arm64"}, {"darwin", "arm64"}}

type callerIdentityViolation struct {
	file string
	line int
	rule string
}

func (v callerIdentityViolation) String() string {
	return fmt.Sprintf("%s:%d: %s", v.file, v.line, v.rule)
}

type callerIdentityGoListPackage struct {
	ImportPath string
	Dir        string
	GoFiles    []string
	Export     string
	Module     *struct{ Main bool }
	Error      *struct{ Err string }
	DepsErrors []*struct{ Err string }
}

func callerIdentityGoListEnvironment(target callerIdentityBuildTarget) []string {
	replaced := map[string]bool{
		"GOOS": true, "GOARCH": true, "GOTOOLCHAIN": true, "GOENV": true, "CGO_ENABLED": true,
		"GOPROXY": true, "GOSUMDB": true, "GOFLAGS": true,
	}
	environment := make([]string, 0, len(os.Environ())+8)
	for _, entry := range os.Environ() {
		if key, _, found := strings.Cut(entry, "="); found && (replaced[key] || strings.HasPrefix(key, "GIT_")) {
			continue
		}
		environment = append(environment, entry)
	}
	return append(environment,
		"GOOS="+target.goos, "GOARCH="+target.goarch, "GOTOOLCHAIN=local", "GOENV=off",
		"CGO_ENABLED=0", "GOPROXY=off", "GOSUMDB=off", "GOFLAGS=-mod=readonly",
	)
}

func isCallerauthPackage(importPath string) bool {
	return importPath == callerauthImportPath || strings.HasPrefix(importPath, callerauthImportPath+"/")
}

// isFieldOf reports whether field is a field of the struct type typeName
// declared in field's own package.
func isFieldOf(field *types.Var, typeName string) bool {
	named, ok := field.Pkg().Scope().Lookup(typeName).(*types.TypeName)
	if !ok {
		return false
	}
	structure, ok := named.Type().Underlying().(*types.Struct)
	if !ok {
		return false
	}
	for i := 0; i < structure.NumFields(); i++ {
		if structure.Field(i) == field {
			return true
		}
	}
	return false
}

// callerIdentityTypedViolations type-checks every production package of the
// module for target, with the files of overlay (go build's -overlay JSON, or
// "") added, and returns each caller identity read outside
// internal/callerauth, plus the import paths it checked.
func callerIdentityTypedViolations(t *testing.T, target callerIdentityBuildTarget, overlay string) ([]callerIdentityViolation, []string) {
	t.Helper()
	replacements := map[string]string{}
	args := []string{"list", "-deps", "-export", "-json=ImportPath,Dir,GoFiles,Export,Module,Error,DepsErrors"}
	if overlay != "" {
		raw, err := os.ReadFile(overlay)
		if err != nil {
			t.Fatalf("read overlay: %v", err)
		}
		var decoded struct{ Replace map[string]string }
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatalf("decode overlay: %v", err)
		}
		replacements = decoded.Replace
		args = append(args, "-overlay="+overlay)
	}
	args = append(args, "./...")
	command := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), args...)
	command.Dir = testutil.Root
	command.Env = callerIdentityGoListEnvironment(target)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("go list for %s: %v: %s", target, err, stderr.String())
	}

	metadata := map[string]callerIdentityGoListPackage{}
	decoder := json.NewDecoder(&stdout)
	for {
		var item callerIdentityGoListPackage
		err := decoder.Decode(&item)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("decode go list output for %s: %v", target, err)
		}
		if item.Error != nil {
			t.Fatalf("go list %s for %s: %s", item.ImportPath, target, item.Error.Err)
		}
		for _, depErr := range item.DepsErrors {
			t.Fatalf("go list %s for %s: dependency error: %s", item.ImportPath, target, depErr.Err)
		}
		metadata[item.ImportPath] = item
	}

	// Every package of the main module, whether ./... names it or only a
	// dependency reaches it (a directory starting with "_" or named
	// testdata, for example), except internal/callerauth itself.
	var selected []callerIdentityGoListPackage
	for _, item := range metadata {
		if item.Module != nil && item.Module.Main && !isCallerauthPackage(item.ImportPath) {
			selected = append(selected, item)
		}
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].ImportPath < selected[j].ImportPath })

	var violations []callerIdentityViolation
	var checked []string
	connContextHooksSet := map[string]int{}
	authenticateConnectionUses := map[string]int{}
	for _, item := range selected {
		checked = append(checked, item.ImportPath)
		if len(item.GoFiles) == 0 {
			continue
		}
		fset := token.NewFileSet()
		files := make([]*ast.File, 0, len(item.GoFiles))
		for _, name := range item.GoFiles {
			path := filepath.Join(item.Dir, name)
			source := path
			if replacement, ok := replacements[path]; ok {
				source = replacement
			}
			raw, err := os.ReadFile(source)
			if err != nil {
				t.Fatalf("read %s: %v", source, err)
			}
			file, err := parser.ParseFile(fset, path, raw, parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			files = append(files, file)
		}
		info := &types.Info{Selections: map[*ast.SelectorExpr]*types.Selection{}, Uses: map[*ast.Ident]types.Object{}, Types: map[ast.Expr]types.TypeAndValue{}}
		lookup := func(importPath string) (io.ReadCloser, error) {
			dependency, ok := metadata[importPath]
			if !ok || dependency.Export == "" {
				return nil, fmt.Errorf("no export data for %s", importPath)
			}
			return os.Open(dependency.Export)
		}
		config := types.Config{Importer: importer.ForCompiler(fset, "gc", lookup), Sizes: types.SizesFor("gc", target.goarch)}
		if _, err := config.Check(item.ImportPath, fset, files, info); err != nil {
			t.Fatalf("type-check %s for %s: %v", item.ImportPath, target, err)
		}

		// Unadjusted, so a //line directive cannot move a finding to another file.
		at := func(pos token.Pos, rule string) {
			position := fset.PositionFor(pos, false)
			rel, err := filepath.Rel(testutil.Root, position.Filename)
			if err != nil {
				rel = position.Filename
			}
			violations = append(violations, callerIdentityViolation{file: filepath.ToSlash(rel), line: position.Line, rule: rule})
		}
		inAPI := slices.Contains(callerIdentityAPIPackages, item.ImportPath)
		for _, file := range files {
			for _, spec := range file.Imports {
				path, err := strconv.Unquote(spec.Path.Value)
				if err == nil && callerIdentityImportForbidden(path) {
					at(spec.Pos(), "imports "+path)
				}
			}
		}
		connectionServer := slices.Contains(callerConnectionServerPackages, item.ImportPath)
		connectionAPI := slices.Contains(callerConnectionAPIPackages, item.ImportPath)
		hooks := map[*ast.Ident]bool{}
		if connectionServer {
			hooks = connContextHooks(files, info)
		}
		for ident, object := range info.Uses {
			function, ok := object.(*types.Func)
			if ok && function.Pkg() != nil && slices.Contains(callerIdentityTokenReaders[function.Pkg().Path()], function.Name()) {
				at(ident.Pos(), "reads a JWT-SVID with "+function.Pkg().Path()+"."+function.Name())
			}
			// Where a callerauth.Caller or a callerauth.ConnectionCaller can
			// be produced, by what each identifier refers to: a dot import,
			// an import alias, a function or method value and a method
			// expression are the same reference as the plain call.
			switch name := callerauthFunctionName(object); name {
			case "CallerFromConnectionState":
				at(ident.Pos(), "refers to callerauth.CallerFromConnectionState")
			case "NewAuthenticator":
				if !inAPI {
					at(ident.Pos(), "refers to callerauth.NewAuthenticator outside the service API packages")
				}
			case "Authenticator.Authenticate":
				if !inAPI || connectionAPI {
					at(ident.Pos(), "refers to callerauth.Authenticator.Authenticate outside the service API packages that read r.TLS")
				}
			case "Authenticator.AuthenticateConnection":
				if !connectionAPI {
					at(ident.Pos(), "refers to callerauth.Authenticator.AuthenticateConnection outside ES's API")
				} else {
					authenticateConnectionUses[item.ImportPath]++
				}
			case "ConnContext":
				if !hooks[ident] {
					at(ident.Pos(), "refers to callerauth.ConnContext other than as the ConnContext hook of an http.Server literal in ES's server setup")
				} else {
					connContextHooksSet[item.ImportPath]++
				}
			}
		}
		for selector, selection := range info.Selections {
			object := selection.Obj()
			if object.Pkg() == nil {
				continue
			}
			if inAPI && object.Pkg().Path() == "crypto/tls" {
				at(selector.Sel.Pos(), "service API uses crypto/tls."+object.Name())
			}
			field, ok := object.(*types.Var)
			if !ok || !field.IsField() {
				continue
			}
			switch {
			case object.Pkg().Path() == "net/http" && object.Name() == "TLS" && isFieldOf(field, "Request"):
				at(selector.Sel.Pos(), "reads net/http.Request.TLS")
			case object.Pkg().Path() == "crypto/x509" && slices.Contains(callerIdentityCertificateFields, object.Name()) && isFieldOf(field, "Certificate"):
				at(selector.Sel.Pos(), "reads crypto/x509.Certificate."+object.Name())
			}
		}
	}
	// The wiring itself: ES's server hands callerauth its connections once,
	// and ES's API reads its caller from them.
	for _, importPath := range callerConnectionServerPackages {
		if count := connContextHooksSet[importPath]; count != 1 {
			violations = append(violations, callerIdentityViolation{file: strings.TrimPrefix(importPath, callerIdentityModule+"/"), rule: fmt.Sprintf("sets callerauth.ConnContext as an http.Server's ConnContext hook %d times, want once", count)})
		}
	}
	for _, importPath := range callerConnectionAPIPackages {
		if authenticateConnectionUses[importPath] == 0 {
			violations = append(violations, callerIdentityViolation{file: strings.TrimPrefix(importPath, callerIdentityModule+"/"), rule: "does not read its caller with callerauth.Authenticator.AuthenticateConnection"})
		}
	}
	sort.Slice(violations, func(i, j int) bool { return violations[i].String() < violations[j].String() })
	return violations, checked
}

// No production package outside internal/callerauth reads the TLS state of
// a request or an identity or issuer field of a certificate, imports the
// callerauth test support or a go-spiffe package off the closed list, or
// reads a peer's JWT-SVID; and the five service API packages use nothing
// from crypto/tls.
//
// It also checks, by what each identifier refers to, where a caller can be
// produced. No production package outside internal/callerauth refers to
// CallerFromConnectionState; only the five service API packages refer to
// NewAuthenticator, and only the four that read r.TLS to Authenticate. Only
// ES's API (callerConnectionAPIPackages) refers to AuthenticateConnection,
// and it does. Only ES's server setup (callerConnectionServerPackages)
// refers to ConnContext, exactly once, as the ConnContext field of an
// http.Server composite literal. A call through an interface that an
// Authenticator satisfies does not refer to callerauth's method: it needs an
// Authenticator value, and AuthenticateConnection reads only a connection
// that ConnContext kept, whatever request it is given. With the compiler's
// part (a ConnectionCaller has no exported field, and the context key
// ConnContext uses is unexported), a caller that ES's API hands on comes
// from a connection that ES's server accepted. Reflection, unsafe and cgo
// are outside what this sees; the import inventory in es/admission
// (TestOperationalGuardImportInventoryIsExact) pins each production file
// that imports one. Edits to callerauth itself, and to ES's server setup
// (which CA its listener trusts, which listener it serves), are reviewed as
// the trust root.
func TestCallerIdentityIsReadOnlyByCallerauthByType(t *testing.T) {
	for _, target := range callerIdentityBuildTargets {
		t.Run(target.goos+"_"+target.goarch, func(t *testing.T) {
			violations, checked := callerIdentityTypedViolations(t, target, "")
			for _, violation := range violations {
				t.Errorf("%s (use internal/callerauth)", violation)
			}
			if len(checked) < 40 {
				t.Fatalf("checked %d production packages for %s, want at least 40", len(checked), target)
			}
			for _, required := range append(slices.Clone(callerIdentityAPIPackages), "execution-substrate/es/admission", "execution-substrate/internal/callerallowlist") {
				if !slices.Contains(checked, required) {
					t.Errorf("did not check %s for %s", required, target)
				}
			}
			for _, importPath := range checked {
				if isCallerauthPackage(importPath) {
					t.Errorf("checked %s, which owns caller authentication", importPath)
				}
			}
		})
	}
}

// The typed guard catches the PR 27 red-team's sixth copy of the identity
// rule (probes/rtprobe.go.txt and probes/zz_rtprobe.go.txt in
// 05-redteam-evidence), which the name-based guard missed, and other
// spellings of it. The probe files exist only in a go build overlay.
func TestCallerIdentityTypedGuardCatchesSixthCopies(t *testing.T) {
	probes := map[string]string{
		// The red-team's new package: reads the request's TLS state, uses
		// go-spiffe's x509svid, and reads the issuer through a variable.
		"internal/zzcalleridentityprobe/probe.go": `package zzcalleridentityprobe

import (
	"crypto/x509"
	"net/http"
	"net/url"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

func CallerID(r *http.Request) (string, string) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", ""
	}
	cert := r.TLS.PeerCertificates[0]
	id, err := x509svid.IDFromCert(cert)
	if err != nil {
		return "", ""
	}
	issuer := cert.Issuer
	return id.String(), issuer.CommonName
}

type alias = x509.Certificate

type wrapped struct{ *x509.Certificate }

type request struct{ *http.Request }

func Spellings(a *alias, w wrapped, q request) ([]*url.URL, []*url.URL, int, []byte, bool) {
	_, err := spiffeid.FromURI(a.URIs[0])
	return a.URIs, w.URIs, len(w.Extensions), a.RawIssuer, q.TLS != nil && err == nil
}

// A field of the same name in another type is not a caller identity read.
func ResponseState(resp *http.Response) bool { return resp.TLS != nil }
`,
		// go-spiffe's readers of a peer's identity: spiffetls and spiffegrpc
		// (audit 11, A11-1), and the JWT-SVID readers of the packages that
		// the closed list allows, next to a workload's read of its own
		// JWT-SVID, which is allowed.
		"internal/zzcalleridentityprobe/spiffe.go": `package zzcalleridentityprobe

import (
	"context"
	"crypto/tls"

	workloadpb "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffegrpc/grpccredentials"
	"github.com/spiffe/go-spiffe/v2/spiffetls"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func PeerPaths(ctx context.Context, state tls.ConnectionState) string {
	id, _ := spiffetls.PeerIDFromConnectionState(state)
	grpcID, _ := grpccredentials.PeerIDFromContext(ctx)
	return id.Path() + grpcID.Path()
}

func TokenPaths(ctx context.Context, token string, client *workloadapi.Client, api workloadpb.SpiffeWorkloadAPIClient) string {
	checked, _ := jwtsvid.ParseAndValidate(token, nil, []string{"es"})
	parsed, _ := jwtsvid.ParseInsecure(token, []string{"es"})
	validated, _ := workloadapi.ValidateJWTSVID(ctx, token, "es")
	again, _ := client.ValidateJWTSVID(ctx, token, "es")
	_, _ = api.ValidateJWTSVID(ctx, &workloadpb.ValidateJWTSVIDRequest{Audience: "es", Svid: token})
	own, _ := client.FetchJWTSVID(ctx, jwtsvid.Params{Audience: "es"})
	return checked.ID.Path() + parsed.ID.Path() + validated.ID.Path() + again.ID.Path() + own.ID.Path()
}
`,
		// The red-team's file inside a service API package. Its //line
		// directive must not move the findings to another file.
		"ars/api/zz_calleridentityprobe.go": `package api

import (
	"crypto/x509"
	"net/http"

	"execution-substrate/internal/callerauth/callerauthtest"
	"execution-substrate/internal/zzcalleridentityprobe"
)

//line elsewhere.go:1
func zzCallerIdentityProbe(r *http.Request, cert *x509.Certificate) (string, string, string) {
	id, _ := zzcalleridentityprobe.CallerID(r)
	issuer := cert.Issuer
	state := r.TLS
	_ = state.HandshakeComplete
	_ = callerauthtest.RuntimeIssuer
	return id, issuer.CommonName, cert.Subject.CommonName
}

var _ = zzCallerIdentityProbe
`,
	}
	// One probe file per platform, in a package every target builds. Only
	// that platform's build sees the file, so a platform that the guard
	// does not type-check leaves its probe uncaught (audit 11, A11-2).
	const platformProbe = `package admission

import (
	"crypto/x509"
	"net/http"
)

type zzPlatformRequest struct{ *http.Request }

func zzPlatformIssuer(q zzPlatformRequest) string {
	var cert *x509.Certificate = q.TLS.PeerCertificates[0]
	issuer := cert.Issuer
	return issuer.CommonName
}
`
	platformProbes := map[string]string{}
	for _, platform := range []string{"linux_amd64", "linux_arm64", "darwin_arm64"} {
		platformProbes[platform] = "es/admission/zz_calleridentityprobe_" + platform + ".go"
		probes[platformProbes[platform]] = platformProbe
	}
	dir := t.TempDir()
	replace := map[string]string{}
	for rel, content := range probes {
		source := filepath.Join(dir, strings.ReplaceAll(rel, "/", "_"))
		if err := os.WriteFile(source, []byte(content), 0o600); err != nil {
			t.Fatalf("write probe %s: %v", rel, err)
		}
		replace[filepath.Join(testutil.Root, filepath.FromSlash(rel))] = source
	}
	overlay, err := json.Marshal(map[string]any{"Replace": replace})
	if err != nil {
		t.Fatalf("encode overlay: %v", err)
	}
	overlayPath := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(overlayPath, overlay, 0o600); err != nil {
		t.Fatalf("write overlay: %v", err)
	}

	const probe = "internal/zzcalleridentityprobe/probe.go"
	const spiffe = "internal/zzcalleridentityprobe/spiffe.go"
	const api = "ars/api/zz_calleridentityprobe.go"
	common := []string{
		probe + ":9: imports github.com/spiffe/go-spiffe/v2/svid/x509svid",
		probe + ":13: reads net/http.Request.TLS",
		probe + ":16: reads net/http.Request.TLS",
		probe + ":21: reads crypto/x509.Certificate.Issuer",
		probe + ":32: reads crypto/x509.Certificate.URIs",
		probe + ":33: reads crypto/x509.Certificate.URIs",
		probe + ":33: reads crypto/x509.Certificate.Extensions",
		probe + ":33: reads crypto/x509.Certificate.RawIssuer",
		probe + ":33: reads net/http.Request.TLS",
		spiffe + ":8: imports github.com/spiffe/go-spiffe/v2/spiffegrpc/grpccredentials",
		spiffe + ":9: imports github.com/spiffe/go-spiffe/v2/spiffetls",
		spiffe + ":21: reads a JWT-SVID with github.com/spiffe/go-spiffe/v2/svid/jwtsvid.ParseAndValidate",
		spiffe + ":22: reads a JWT-SVID with github.com/spiffe/go-spiffe/v2/svid/jwtsvid.ParseInsecure",
		spiffe + ":23: reads a JWT-SVID with github.com/spiffe/go-spiffe/v2/workloadapi.ValidateJWTSVID",
		spiffe + ":24: reads a JWT-SVID with github.com/spiffe/go-spiffe/v2/workloadapi.ValidateJWTSVID",
		spiffe + ":25: reads a JWT-SVID with github.com/spiffe/go-spiffe/v2/proto/spiffe/workload.ValidateJWTSVID",
		api + ":7: imports execution-substrate/internal/callerauth/callerauthtest",
		api + ":14: reads crypto/x509.Certificate.Issuer",
		api + ":15: reads net/http.Request.TLS",
		api + ":16: service API uses crypto/tls.HandshakeComplete",
	}
	caught := map[string]bool{}
	for _, target := range callerIdentityBuildTargets {
		t.Run(target.goos+"_"+target.goarch, func(t *testing.T) {
			platform, ok := platformProbes[target.goos+"_"+target.goarch]
			if !ok {
				t.Fatalf("no platform probe for the guard target %s; add one", target)
			}
			want := append(slices.Clone(common),
				platform+":11: reads net/http.Request.TLS",
				platform+":12: reads crypto/x509.Certificate.Issuer",
			)
			violations, _ := callerIdentityTypedViolations(t, target, overlayPath)
			got := map[string]bool{}
			for _, violation := range violations {
				got[violation.String()] = true
			}
			for _, violation := range want {
				if !got[violation] {
					t.Errorf("the typed guard missed %s for %s", violation, target)
				}
			}
			for _, violation := range violations {
				if !slices.Contains(want, violation.String()) {
					t.Errorf("unexpected violation %s for %s", violation, target)
				}
			}
			if got[platform+":11: reads net/http.Request.TLS"] && got[platform+":12: reads crypto/x509.Certificate.Issuer"] {
				caught[platform] = true
			}
		})
	}
	for platform, path := range platformProbes {
		if !caught[path] {
			t.Errorf("no guard target caught %s, which only %s builds", path, strings.Replace(platform, "_", "/", 1))
		}
	}
}

// Every platform that a script builds Go code for is a target of the typed
// guard (audit 11, A11-2): each GOOS and GOARCH literal in scripts/, and each
// architecture control_plane_target_arch picks for the control-plane images.
func TestCallerIdentityTypedGuardCoversTheScriptsBuildTargets(t *testing.T) {
	coveredOS := map[string]bool{}
	coveredLinuxArch := map[string]bool{}
	for _, target := range callerIdentityBuildTargets {
		coveredOS[target.goos] = true
		if target.goos == "linux" {
			coveredLinuxArch[target.goarch] = true
		}
	}
	goos := regexp.MustCompile(`GOOS=([a-z0-9]+)`)
	goarch := regexp.MustCompile(`GOARCH=([a-z0-9]+)`)
	foundOS := map[string]string{}
	foundArch := map[string]string{}
	root := filepath.Join(testutil.Root, "scripts")
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(testutil.Root, path)
		for _, match := range goos.FindAllSubmatch(raw, -1) {
			foundOS[string(match[1])] = rel
		}
		for _, match := range goarch.FindAllSubmatch(raw, -1) {
			foundArch[string(match[1])] = rel
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan scripts: %v", err)
	}
	controlPlane, err := os.ReadFile(filepath.Join(root, "internal", "control_plane.sh"))
	if err != nil {
		t.Fatalf("read control_plane.sh: %v", err)
	}
	_, body, found := strings.Cut(string(controlPlane), "\ncontrol_plane_target_arch() {\n")
	body, _, closed := strings.Cut(body, "\n}\n")
	if !found || !closed {
		t.Fatalf("control_plane.sh has no control_plane_target_arch function")
	}
	// Each scan must find what the scripts build today, so that neither
	// passes by finding nothing.
	if foundOS["linux"] == "" || foundArch["amd64"] == "" || foundArch["arm64"] == "" {
		t.Fatalf("the scan found GOOS %v and GOARCH %v in scripts, want at least linux, amd64 and arm64; the scan is broken", foundOS, foundArch)
	}
	controlPlaneArch := map[string]bool{}
	for _, match := range regexp.MustCompile(`printf '([a-z0-9]+)\\n'`).FindAllStringSubmatch(body, -1) {
		controlPlaneArch[match[1]] = true
		foundArch[match[1]] = "scripts/internal/control_plane.sh control_plane_target_arch"
	}
	if !controlPlaneArch["amd64"] || !controlPlaneArch["arm64"] {
		t.Fatalf("control_plane_target_arch prints %v, want at least amd64 and arm64; the scan is broken", controlPlaneArch)
	}
	for value, where := range foundOS {
		if !coveredOS[value] {
			t.Errorf("%s builds for GOOS=%s, which callerIdentityBuildTargets does not cover", where, value)
		}
	}
	for value, where := range foundArch {
		if !coveredLinuxArch[value] {
			t.Errorf("%s builds for linux/%s, which callerIdentityBuildTargets does not cover", where, value)
		}
	}
}

// The typed rules on where a caller can be produced catch each spelling of
// the shapes that re-checks 33 of ES PR #73 used to forge a caller one layer
// below the grant caller (a dot import, an import alias, a function or
// method value, a method expression, a new package), moved onto the
// connection path: a new reference to ConnContext or AuthenticateConnection
// outside the places the rules allow, a second ConnContext hook in ES's
// server setup, a hook set other than as an http.Server literal's field, and
// Authenticate in ES's API. The probe files exist only in a go build
// overlay. The rules do not depend on the platform, so one target is enough
// here; TestCallerIdentityIsReadOnlyByCallerauthByType runs them on all
// three.
func TestCallerConnectionTypedGuardCatchesForgedConnectionCallers(t *testing.T) {
	probes := map[string]string{
		"es/admission/zz_connprobe_dot.go": `package admission

import (
	"context"
	"net"
	"net/http"
	"time"

	. "execution-substrate/internal/callerauth"
)

func zzDotHook(ctx context.Context, c net.Conn) context.Context { return ConnContext(ctx, c) }

func zzDotCaller(w http.ResponseWriter, r *http.Request) context.Context {
	caller, _ := NewAuthenticator("zz-bootstrap").AuthenticateConnection(w, r)
	return WithAuthenticatedCaller(r.Context(), caller)
}

func zzDotState() error { _, err := CallerFromConnectionState(nil, time.Time{}); return err }
`,
		"es/admission/zz_connprobe_alias.go": `package admission

import (
	"context"
	"net/http"

	ca "execution-substrate/internal/callerauth"
	"execution-substrate/internal/zzconnprobe"
)

var zzHookValue = ca.ConnContext

var zzMethodExpression = ca.Authenticator.AuthenticateConnection

func zzMethodValue(ctx context.Context, w http.ResponseWriter, r *http.Request, a ca.Authenticator) context.Context {
	read := a.AuthenticateConnection
	caller, _ := read(w, r)
	return WithAuthenticatedCaller(zzconnprobe.Hook(ctx, nil), caller)
}
`,
		"internal/zzconnprobe/probe.go": `package zzconnprobe

import (
	"context"
	"net"
	"time"

	"execution-substrate/internal/callerauth"
)

func Hook(ctx context.Context, c net.Conn) context.Context { return callerauth.ConnContext(ctx, c) }

func State() error {
	_, err := callerauth.CallerFromConnectionState(nil, time.Time{})
	return err
}
`,
		"es/api/zz_connprobe.go": `package api

import (
	"context"
	"net/http"

	"execution-substrate/internal/callerauth"
)

func zzAPIRebind(w http.ResponseWriter, r *http.Request, a callerauth.Authenticator) context.Context {
	_, _ = a.Authenticate(w, r)
	return callerauth.ConnContext(r.Context(), nil)
}
`,
		"es/app/zz_connprobe.go": `package app

import (
	"context"
	"net"
	"net/http"

	"execution-substrate/internal/callerauth"
)

type zzServer = http.Server

var zzSecondServer = &zzServer{ConnContext: (callerauth.ConnContext)}

type zzHooks struct {
	ConnContext func(context.Context, net.Conn) context.Context
}

var zzOtherStruct = zzHooks{ConnContext: callerauth.ConnContext}

func zzAssignHook(server *http.Server) { server.ConnContext = callerauth.ConnContext }
`,
	}
	dir := t.TempDir()
	replace := map[string]string{}
	for rel, content := range probes {
		source := filepath.Join(dir, strings.ReplaceAll(rel, "/", "_"))
		if err := os.WriteFile(source, []byte(content), 0o600); err != nil {
			t.Fatalf("write probe %s: %v", rel, err)
		}
		replace[filepath.Join(testutil.Root, filepath.FromSlash(rel))] = source
	}
	overlay, err := json.Marshal(map[string]any{"Replace": replace})
	if err != nil {
		t.Fatalf("encode overlay: %v", err)
	}
	overlayPath := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(overlayPath, overlay, 0o600); err != nil {
		t.Fatalf("write overlay: %v", err)
	}

	const dot = "es/admission/zz_connprobe_dot.go"
	const alias = "es/admission/zz_connprobe_alias.go"
	const newPackage = "internal/zzconnprobe/probe.go"
	const api = "es/api/zz_connprobe.go"
	const app = "es/app/zz_connprobe.go"
	const hook = "refers to callerauth.ConnContext other than as the ConnContext hook of an http.Server literal in ES's server setup"
	const read = "refers to callerauth.Authenticator.AuthenticateConnection outside ES's API"
	want := []string{
		dot + ":12: " + hook,
		dot + ":15: refers to callerauth.NewAuthenticator outside the service API packages",
		dot + ":15: " + read,
		dot + ":19: refers to callerauth.CallerFromConnectionState",
		alias + ":11: " + hook,
		alias + ":13: " + read,
		alias + ":16: " + read,
		newPackage + ":11: " + hook,
		newPackage + ":14: refers to callerauth.CallerFromConnectionState",
		api + ":11: refers to callerauth.Authenticator.Authenticate outside the service API packages that read r.TLS",
		api + ":12: " + hook,
		app + ":19: " + hook,
		app + ":21: " + hook,
		"es/app:0: sets callerauth.ConnContext as an http.Server's ConnContext hook 2 times, want once",
	}
	target := callerIdentityBuildTarget{"linux", "amd64"}
	violations, _ := callerIdentityTypedViolations(t, target, overlayPath)
	got := map[string]bool{}
	for _, violation := range violations {
		got[violation.String()] = true
	}
	for _, violation := range want {
		if !got[violation] {
			t.Errorf("the typed guard missed %s", violation)
		}
	}
	for _, violation := range violations {
		if !slices.Contains(want, violation.String()) {
			t.Errorf("unexpected violation %s", violation)
		}
	}
}

// mentionsNamedType reports whether t is target, or is built from it as a
// pointer, slice, array, map, channel, struct field, function result or
// tuple element, without looking inside another named type.
func mentionsNamedType(t types.Type, target *types.TypeName) bool {
	switch t := types.Unalias(t).(type) {
	case *types.Named:
		return t.Obj() == target
	case *types.Pointer:
		return mentionsNamedType(t.Elem(), target)
	case *types.Slice:
		return mentionsNamedType(t.Elem(), target)
	case *types.Array:
		return mentionsNamedType(t.Elem(), target)
	case *types.Map:
		return mentionsNamedType(t.Key(), target) || mentionsNamedType(t.Elem(), target)
	case *types.Chan:
		return mentionsNamedType(t.Elem(), target)
	case *types.Struct:
		for i := 0; i < t.NumFields(); i++ {
			if mentionsNamedType(t.Field(i).Type(), target) {
				return true
			}
		}
	case *types.Signature:
		return mentionsNamedType(t.Results(), target)
	case *types.Tuple:
		for i := 0; i < t.Len(); i++ {
			if mentionsNamedType(t.At(i).Type(), target) {
				return true
			}
		}
	}
	return false
}

// Only callerauth's two readers of a TLS connection state produce a
// callerauth.Caller, and only AuthenticateConnection produces a
// ConnectionCaller, among the exported functions, methods and variables of
// callerauth; the test support adds ConnectionCaller, which no production
// package can import (TestCallerIdentityIsReadOnlyByCallerauthByType). No
// exported name is an alias of either type, and neither type has an
// exported field. The check reads the packages' export data, so it sees
// their exported surface as the compiler does.
func TestOnlyAuthenticateConnectionMakesAConnectionCaller(t *testing.T) {
	target := callerIdentityBuildTarget{runtime.GOOS, runtime.GOARCH}
	command := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "list", "-deps", "-export", "-json=ImportPath,Export", callerauthImportPath+"/...")
	command.Dir = testutil.Root
	command.Env = callerIdentityGoListEnvironment(target)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("go list: %v: %s", err, stderr.String())
	}
	exports := map[string]string{}
	decoder := json.NewDecoder(&stdout)
	for {
		var item struct{ ImportPath, Export string }
		err := decoder.Decode(&item)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		exports[item.ImportPath] = item.Export
	}
	imports := importer.ForCompiler(token.NewFileSet(), "gc", func(importPath string) (io.ReadCloser, error) {
		export, ok := exports[importPath]
		if !ok || export == "" {
			return nil, fmt.Errorf("no export data for %s", importPath)
		}
		return os.Open(export)
	})
	callerauthPackage, err := imports.Import(callerauthImportPath)
	if err != nil {
		t.Fatal(err)
	}
	connectionCaller, _ := callerauthPackage.Scope().Lookup("ConnectionCaller").(*types.TypeName)
	caller, _ := callerauthPackage.Scope().Lookup("Caller").(*types.TypeName)
	if connectionCaller == nil || caller == nil {
		t.Fatal("callerauth declares no ConnectionCaller or Caller type")
	}
	for _, typeName := range []*types.TypeName{connectionCaller, caller} {
		structure, ok := typeName.Type().Underlying().(*types.Struct)
		if !ok {
			t.Fatalf("callerauth.%s is not a struct", typeName.Name())
		}
		for i := 0; i < structure.NumFields(); i++ {
			if structure.Field(i).Exported() {
				t.Errorf("callerauth.%s has the exported field %s", typeName.Name(), structure.Field(i).Name())
			}
		}
	}

	producers := map[*types.TypeName][]string{}
	for _, importPath := range []string{callerauthImportPath, callerauthImportPath + "/callerauthtest"} {
		pkg, err := imports.Import(importPath)
		if err != nil {
			t.Fatal(err)
		}
		record := func(name string, typ types.Type) {
			for _, produced := range []*types.TypeName{connectionCaller, caller} {
				if mentionsNamedType(typ, produced) {
					producers[produced] = append(producers[produced], pkg.Name()+"."+name)
				}
			}
		}
		scope := pkg.Scope()
		for _, name := range scope.Names() {
			object := scope.Lookup(name)
			if !object.Exported() {
				continue
			}
			switch object := object.(type) {
			case *types.Func:
				record(name, object.Signature())
			case *types.Var:
				record(name, object.Type())
			case *types.TypeName:
				if object.IsAlias() {
					for _, produced := range []*types.TypeName{connectionCaller, caller} {
						if mentionsNamedType(object.Type(), produced) {
							t.Errorf("%s.%s is an alias built from callerauth.%s", pkg.Name(), name, produced.Name())
						}
					}
					continue
				}
				if named, ok := object.Type().(*types.Named); ok {
					for i := 0; i < named.NumMethods(); i++ {
						if method := named.Method(i); method.Exported() {
							record(name+"."+method.Name(), method.Signature())
						}
					}
				}
			}
		}
	}
	for produced, want := range map[*types.TypeName][]string{
		connectionCaller: {"callerauth.Authenticator.AuthenticateConnection", "callerauthtest.ConnectionCaller"},
		caller:           {"callerauth.Authenticator.Authenticate", "callerauth.CallerFromConnectionState"},
	} {
		got := producers[produced]
		sort.Strings(got)
		if !slices.Equal(got, want) {
			t.Errorf("exported producers of callerauth.%s: %q, want %q", produced.Name(), got, want)
		}
	}
}
