package scripts_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"execution-substrate/es/config"
	"execution-substrate/internal/testutil"
)

const esConfigCheckSource = "scripts/internal/esconfigcheck/main.go"

// esConfigCheckMainBody is the whole of the helper's main. Any change to it,
// such as a check of its own, fails the test below and so comes to review.
const esConfigCheckMainBody = `{
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: esconfigcheck <absolute path to es.json>")
		os.Exit(2)
	}
	if _, err := config.Load(os.Args[1]); err != nil {
		fmt.Fprintf(os.Stderr, "es config refused: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("es config accepted")
}`

// TestESConfigCheckOnlyCallsConfigLoad keeps the upgrade's config check a
// thin wrapper around the product's config.Load. If the helper grew checks
// of its own, the upgrade could accept a config ES refuses, or refuse one ES
// accepts. The helper may import only fmt, os and es/config, declare only
// main, and call only config.Load (once), len, and the fmt and os functions
// it needs to report the result; and main must be exactly
// esConfigCheckMainBody.
func TestESConfigCheckOnlyCallsConfigLoad(t *testing.T) {
	requireThinConfigCheck(t, "esconfigcheck", esConfigCheckSource, "execution-substrate/es/config", esConfigCheckMainBody)
}

// requireThinConfigCheck holds the config check of one service, in the one
// file source, to these rules: it imports only fmt, os and the service's
// config package (configImport), declares only main, calls only
// config.Load (once), len, and the fmt and os functions it needs to report
// the result, and its main is exactly mainBody.
func requireThinConfigCheck(t *testing.T, name, source, configImport, mainBody string) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, repoPath(source), nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Dir(repoPath(source)))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "main.go" {
		t.Fatalf("%s must be the one file main.go, found %d entries", name, len(entries))
	}

	var imports []string
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			t.Fatal(err)
		}
		if spec.Name != nil {
			t.Fatalf("import %q is renamed to %q", path, spec.Name.Name)
		}
		imports = append(imports, path)
	}
	sort.Strings(imports)
	if got, want := strings.Join(imports, " "), configImport+" fmt os"; got != want {
		t.Fatalf("%s imports %q, want %q", name, got, want)
	}

	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			if d.Tok != token.IMPORT {
				t.Fatalf("%s declares a %s at %s; only main is allowed", name, d.Tok, fset.PositionFor(d.Pos(), false))
			}
		case *ast.FuncDecl:
			if d.Name.Name != "main" || d.Recv != nil {
				t.Fatalf("%s declares func %s at %s; only main is allowed", name, d.Name.Name, fset.PositionFor(d.Pos(), false))
			}
			var body bytes.Buffer
			if err := format.Node(&body, fset, d.Body); err != nil {
				t.Fatal(err)
			}
			if body.String() != mainBody {
				t.Errorf("%s's main changed; it must stay exactly:\n%s\ngot:\n%s", name, mainBody, body.String())
			}
		}
	}

	allowed := map[string]bool{
		"config.Load": true, "len": true,
		"fmt.Fprintln": true, "fmt.Fprintf": true, "fmt.Println": true, "os.Exit": true,
	}
	loads := 0
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			t.Errorf("%s has a function literal at %s", name, fset.PositionFor(node.Pos(), false))
		case *ast.CallExpr:
			called := ""
			switch fun := node.Fun.(type) {
			case *ast.Ident:
				called = fun.Name
			case *ast.SelectorExpr:
				if pkg, ok := fun.X.(*ast.Ident); ok {
					called = pkg.Name + "." + fun.Sel.Name
				}
			}
			if !allowed[called] {
				t.Errorf("%s calls %q at %s; it may call only config.Load and the reporting functions", name, called, fset.PositionFor(node.Pos(), false))
			}
			if called == "config.Load" {
				loads++
			}
		}
		return true
	})
	if loads != 1 {
		t.Fatalf("%s calls config.Load %d times, want once", name, loads)
	}
}

// TestESConfigCheckAgreesWithConfigLoad runs the built helper on the
// submit example and on configs config.Load refuses, and requires the
// helper's answer and reason to be config.Load's own.
func TestESConfigCheckAgreesWithConfigLoad(t *testing.T) {
	helper := buildESConfigCheck(t)
	published, err := os.ReadFile(repoPath(".examples/config/es.json"))
	if err != nil {
		t.Fatal(err)
	}
	// The example verifies with known keys, which ES refuses (contracts.md
	// section 3B); the cases start from it with fresh keys.
	var fresh map[string]any
	if err := json.Unmarshal(published, &fresh); err != nil {
		t.Fatal(err)
	}
	example, err := json.MarshalIndent(testutil.WithFreshSigningKeys(t, fresh), "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	mutate := func(edit func(map[string]any)) []byte {
		var doc map[string]any
		if err := json.Unmarshal(example, &doc); err != nil {
			t.Fatal(err)
		}
		edit(doc)
		out, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	section := func(doc map[string]any, name string) map[string]any { return doc[name].(map[string]any) }

	cases := []struct {
		name string
		data []byte
	}{
		{"submit example", example},
		{"unknown field", mutate(func(d map[string]any) { section(d, "nomad")["token"] = "x" })},
		{"no token_file", mutate(func(d map[string]any) { delete(section(d, "nomad"), "token_file") })},
		{"no retained_result_auth", mutate(func(d map[string]any) { delete(section(d, "execution"), "retained_result_auth") })},
		{"Nomad over plain HTTP", mutate(func(d map[string]any) { section(d, "nomad")["base_url"] = "http://127.0.0.1:4646" })},
		{"no Nomad server key pin", mutate(func(d map[string]any) { delete(section(d, "nomad"), "server_spki_sha256") })},
		{"one-segment prefix", mutate(func(d map[string]any) {
			section(d, "authorization")["allowed_spiffe_path_prefixes"] = []any{"operator"}
		})},
		{"token file inside results", mutate(func(d map[string]any) {
			section(d, "nomad")["token_file"] = section(d, "execution")["results_root_dir"].(string) + "/es-token"
		})},
		{"trailing data", append(append([]byte{}, example...), []byte("{}")...)},
		// A host of the shape the upgrade checks that is still on the
		// repository's published keys is refused here, so its upgrade stops
		// before apply until its keys are rotated. (The Remote Alpha box has
		// another shape and never reaches this check; AGS, EGS and ES
		// refusing to start on the new binaries is what stops it.)
		{"published signing keys", published},
	}
	refused := 0
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "es.json")
			if err := os.WriteFile(path, tc.data, 0o600); err != nil {
				t.Fatal(err)
			}
			_, loadErr := config.Load(path)
			var stdout, stderr bytes.Buffer
			cmd := exec.Command(helper, path)
			cmd.Dir = t.TempDir()
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			runErr := cmd.Run()
			if loadErr == nil {
				if runErr != nil || stdout.String() != "es config accepted\n" || stderr.Len() != 0 {
					t.Fatalf("config.Load accepts it but the helper said %v, stdout %q, stderr %q", runErr, stdout.String(), stderr.String())
				}
				return
			}
			refused++
			var exitErr *exec.ExitError
			if !errors.As(runErr, &exitErr) || exitErr.ExitCode() != 1 {
				t.Fatalf("config.Load refuses it (%v) but the helper exited with %v", loadErr, runErr)
			}
			if want := "es config refused: " + loadErr.Error() + "\n"; stderr.String() != want || stdout.Len() != 0 {
				t.Fatalf("helper said stdout %q, stderr %q; want stderr %q", stdout.String(), stderr.String(), want)
			}
		})
	}
	if refused != len(cases)-1 {
		t.Fatalf("config.Load refused %d of the %d broken configs; a case no longer tests a refusal", refused, len(cases)-1)
	}
}

func buildESConfigCheck(t *testing.T) string {
	t.Helper()
	return buildConfigCheck(t, "esconfigcheck")
}

// buildConfigCheck builds scripts/internal/<name> for the machine running
// the test.
func buildConfigCheck(t *testing.T, name string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-o", out, "execution-substrate/scripts/internal/"+name)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", name, err, output)
	}
	return out
}
