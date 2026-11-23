package executionsubstrate_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// No production code outside internal/callerauth reads a certificate's URI
// SANs or issuer common name, and the five service API packages do not
// touch the TLS connection state at all. A sixth copy of the identity rule
// fails here. This half matches names in every production file, whatever
// its build constraints; TestCallerIdentityIsReadOnlyByCallerauthByType
// (caller_authentication_typed_guard_test.go) is the typed half, which also
// catches reads through a variable, an alias or an embedded struct.
func TestCallerIdentityIsReadOnlyByCallerauth(t *testing.T) {
	apiPackages := []string{"ars/api", "ags/api", "egs/api", "cgs/api", "es/api"}
	seenAPI := map[string]bool{}
	files := 0

	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := entry.Name()
		if entry.IsDir() {
			if path != "." && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || name == "testdata" || name == "vendor") {
				return filepath.SkipDir
			}
			if filepath.ToSlash(path) == "internal/callerauth" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		files++
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		dir := filepath.ToSlash(filepath.Dir(path))
		inAPI := slices.Contains(apiPackages, dir)
		if inAPI {
			seenAPI[dir] = true
		}
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			position := fset.PositionFor(selector.Sel.Pos(), false)
			switch selector.Sel.Name {
			case "URIs":
				t.Errorf("%s: reads certificate URI SANs outside internal/callerauth", position)
			case "CommonName":
				if inner, ok := selector.X.(*ast.SelectorExpr); ok && inner.Sel.Name == "Issuer" {
					t.Errorf("%s: reads a certificate issuer common name outside internal/callerauth", position)
				}
			case "TLS", "VerifiedChains", "PeerCertificates":
				if inAPI {
					t.Errorf("%s: service API reads the TLS connection state; use internal/callerauth", position)
				}
			}
			return true
		})
		if inAPI && filepath.Base(path) == "server.go" {
			source := mustRead(t, path)
			for _, required := range []string{`"execution-substrate/internal/callerauth"`, "callerauth.NewAuthenticator(bootstrapIssuerCN)", ".callers.Authenticate(w, r)"} {
				if !strings.Contains(source, required) {
					t.Errorf("%s does not contain %s", path, required)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 100 {
		t.Fatalf("walked %d production Go files, want at least 100", files)
	}
	for _, dir := range apiPackages {
		if !seenAPI[dir] {
			t.Errorf("walk did not reach %s", dir)
		}
	}
}
