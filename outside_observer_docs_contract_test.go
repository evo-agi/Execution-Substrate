package executionsubstrate_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestOutsideObserverStageADocumentationBoundary(t *testing.T) {
	for path, required := range map[string][]string{
		standingAdmissionRulesPath:            {"R6J-R9.28/Stage-A", "RunEntryV4", "untrusted", "control-plane-normal-shell/v1"},
		".docs/system_overview/boundaries.md": {"R6J-R9.28/Stage-A", "proposed observer/receiver endpoint", "permit-consumption authority"},
		".docs/execution_lifecycle/outside_observer_protocol.md": {
			"17 fields", "16 fields", "untrusted", "AUTHORITY", "RunEntryV4",
			"SOURCE_STATE/v2", "issuer_id", "key_id", "R9.28.2", "R9.28.6",
			"Stage B", "Stage C", "Stage D", "Stage E", "control-plane-normal-shell/v1",
		},
	} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, text := range required {
			if !strings.Contains(string(data), text) {
				t.Errorf("%s lacks %q", path, text)
			}
		}
	}
}

// inspectStageAProductionSource checks syntax, including import aliases, rather
// than relying on a literal enabled=false. Its inputs are safe Go source bytes.
func inspectStageAProductionSource(path string, src []byte) error {
	f, err := parser.ParseFile(token.NewFileSet(), path, src, 0)
	if err != nil {
		return err
	}
	for _, imp := range f.Imports {
		name, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			return err
		}
		if strings.Contains(name, "/outsideobserverprotocol") {
			return fmt.Errorf("Stage A production import")
		}
	}
	bad := false
	ast.Inspect(f, func(n ast.Node) bool {
		var s string
		switch v := n.(type) {
		case *ast.Ident:
			s = v.Name
		case *ast.BasicLit:
			if v.Kind == token.STRING {
				s, _ = strconv.Unquote(v.Value)
			}
		}
		s = strings.ToLower(s)
		if strings.Contains(s, "outsideobserver") || strings.Contains(s, "outside_observer") ||
			strings.Contains(s, "r6jreceiver") || strings.Contains(s, "outsideobservation") ||
			strings.Contains(s, "source_journal.log") || strings.Contains(s, "journal_segment_id") {
			bad = true
		}
		return true
	})
	if bad {
		return fmt.Errorf("Stage A production route/config/job/supervisor symbol")
	}
	return nil
}

func inspectStageAPrivateSource(path string, src []byte) error {
	f, err := parser.ParseFile(token.NewFileSet(), path, src, 0)
	if err != nil {
		return err
	}
	allowed := map[string]bool{"bytes": true, "crypto/sha256": true, "encoding/base64": true,
		"encoding/hex": true, "fmt": true, "sort": true, "strconv": true, "strings": true, "unicode/utf8": true}
	for _, imp := range f.Imports {
		name, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			return err
		}
		if !allowed[name] {
			return fmt.Errorf("private package effectful or external import: %s", name)
		}
	}
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Recv == nil && d.Name.Name == "init" {
				return fmt.Errorf("private package init")
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				if v, ok := spec.(*ast.ValueSpec); ok && d.Tok == token.VAR && len(v.Values) > 0 {
					return fmt.Errorf("private package initialized global")
				}
			}
		}
	}
	return nil
}

func TestOutsideObserverStageANoProductionWiring(t *testing.T) {
	for _, dir := range []string{"es/admission", "es/runtimehelper", "es/app", "es/api", "es/config", "cmd/es"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := inspectStageAProductionSource(path, data); err != nil {
				t.Errorf("%s: %v", path, err)
			}
		}
	}
	for _, name := range []string{"canonical.go", "schema.go", "validate.go", "domain.go"} {
		path := filepath.Join("es/internal/outsideobserverprotocol", name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := inspectStageAPrivateSource(path, data); err != nil {
			t.Errorf("%s: %v", path, err)
		}
	}
}

func TestOutsideObserverGuardDetectsSyntheticViolations(t *testing.T) {
	for _, source := range []string{
		`package x; import _ "execution-substrate/es/internal/outsideobserverprotocol"`,
		`package x; import . "execution-substrate/es/internal/outsideobserverprotocol"`,
		`package x; import observer "execution-substrate/es/internal/outsideobserverprotocol"`,
		`package x; const route = "GET /v1/outsideobserver"`,
		`package x; var outsideObservationJob = true`,
	} {
		if err := inspectStageAProductionSource("synthetic.go", []byte(source)); err == nil {
			t.Errorf("guard missed %q", source)
		}
	}
	for _, source := range []string{
		`package outsideobserverprotocol; import "net"`,
		`package outsideobserverprotocol; func init() {}`,
		`package outsideobserverprotocol; var started = run()`,
	} {
		if err := inspectStageAPrivateSource("synthetic.go", []byte(source)); err == nil {
			t.Errorf("private guard missed %q", source)
		}
	}
}
