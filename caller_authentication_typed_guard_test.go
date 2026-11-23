package executionsubstrate_test

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
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The typed half of the guard that keeps caller identity reading inside
// internal/callerauth (red-team R4). TestCallerIdentityIsReadOnlyByCallerauth
// matches names in every production file; this half type-checks every
// production package of the module, for each platform the services are built
// for, and matches what a selector refers to, so a read through a variable, a
// type alias or an embedded struct is caught too.

const callerauthImportPath = "execution-substrate/internal/callerauth"

// callerIdentityForbiddenImports may be imported only inside
// internal/callerauth: go-spiffe's reader of an X.509 SVID's identity, and
// the test support that builds caller certificates. go-spiffe's spiffeid is
// not on the list: it is an ID type and parser that cannot read a
// certificate (getting a URI out of one is the URIs read below), and PR 12's
// private submit handoff uses its ID type.
var callerIdentityForbiddenImports = []string{
	"github.com/spiffe/go-spiffe/v2/svid/x509svid",
	callerauthImportPath + "/callerauthtest",
}

// callerIdentityCertificateFields are the x509.Certificate fields that carry
// or encode a caller identity or its issuer: the URI SANs, the issuer name,
// its raw encoding, and the raw extensions (which hold the subjectAltName).
var callerIdentityCertificateFields = []string{"URIs", "Issuer", "RawIssuer", "Extensions"}

var callerIdentityAPIPackages = []string{
	"execution-substrate/ars/api",
	"execution-substrate/ags/api",
	"execution-substrate/egs/api",
	"execution-substrate/cgs/api",
	"execution-substrate/es/api",
}

type callerIdentityBuildTarget struct {
	goos   string
	goarch string
}

func (target callerIdentityBuildTarget) String() string { return target.goos + "/" + target.goarch }

// The services run on Linux; macOS is the development platform.
var callerIdentityBuildTargets = []callerIdentityBuildTarget{{"linux", "amd64"}, {"darwin", "arm64"}}

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
	command.Dir = executionSubstrateRepoRoot
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
		info := &types.Info{Selections: map[*ast.SelectorExpr]*types.Selection{}}
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

		at := func(pos token.Pos, rule string) {
			position := fset.Position(pos)
			rel, err := filepath.Rel(executionSubstrateRepoRoot, position.Filename)
			if err != nil {
				rel = position.Filename
			}
			violations = append(violations, callerIdentityViolation{file: filepath.ToSlash(rel), line: position.Line, rule: rule})
		}
		inAPI := slices.Contains(callerIdentityAPIPackages, item.ImportPath)
		for _, file := range files {
			for _, spec := range file.Imports {
				path, err := strconv.Unquote(spec.Path.Value)
				if err == nil && slices.Contains(callerIdentityForbiddenImports, path) {
					at(spec.Pos(), "imports "+path)
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
	sort.Slice(violations, func(i, j int) bool { return violations[i].String() < violations[j].String() })
	return violations, checked
}

// No production package outside internal/callerauth reads the TLS state of
// a request, an identity or issuer field of a certificate, or imports
// go-spiffe's X.509 SVID reader or the callerauth test support; and the five
// service API packages use nothing from crypto/tls.
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
`,
		// The red-team's file inside a service API package.
		"ars/api/zz_calleridentityprobe.go": `package api

import (
	"crypto/x509"
	"net/http"

	"execution-substrate/internal/callerauth/callerauthtest"
	"execution-substrate/internal/zzcalleridentityprobe"
)

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
	dir := t.TempDir()
	replace := map[string]string{}
	for rel, content := range probes {
		source := filepath.Join(dir, strings.ReplaceAll(rel, "/", "_"))
		if err := os.WriteFile(source, []byte(content), 0o600); err != nil {
			t.Fatalf("write probe %s: %v", rel, err)
		}
		replace[filepath.Join(executionSubstrateRepoRoot, filepath.FromSlash(rel))] = source
	}
	overlay, err := json.Marshal(map[string]any{"Replace": replace})
	if err != nil {
		t.Fatalf("encode overlay: %v", err)
	}
	overlayPath := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(overlayPath, overlay, 0o600); err != nil {
		t.Fatalf("write overlay: %v", err)
	}

	violations, _ := callerIdentityTypedViolations(t, callerIdentityBuildTargets[0], overlayPath)
	got := map[string]bool{}
	for _, violation := range violations {
		got[violation.String()] = true
	}
	const probe = "internal/zzcalleridentityprobe/probe.go"
	const api = "ars/api/zz_calleridentityprobe.go"
	want := []string{
		probe + ":9: imports github.com/spiffe/go-spiffe/v2/svid/x509svid",
		probe + ":13: reads net/http.Request.TLS",
		probe + ":16: reads net/http.Request.TLS",
		probe + ":21: reads crypto/x509.Certificate.Issuer",
		probe + ":32: reads crypto/x509.Certificate.URIs",
		probe + ":33: reads crypto/x509.Certificate.URIs",
		probe + ":33: reads crypto/x509.Certificate.Extensions",
		probe + ":33: reads crypto/x509.Certificate.RawIssuer",
		probe + ":33: reads net/http.Request.TLS",
		api + ":7: imports execution-substrate/internal/callerauth/callerauthtest",
		api + ":13: reads crypto/x509.Certificate.Issuer",
		api + ":14: reads net/http.Request.TLS",
		api + ":15: service API uses crypto/tls.HandshakeComplete",
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
