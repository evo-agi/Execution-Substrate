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
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, repoPath(esConfigCheckSource), nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Dir(repoPath(esConfigCheckSource)))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "main.go" {
		t.Fatalf("esconfigcheck must be the one file main.go, found %d entries", len(entries))
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
	if got, want := strings.Join(imports, " "), "execution-substrate/es/config fmt os"; got != want {
		t.Fatalf("esconfigcheck imports %q, want %q", got, want)
	}

	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			if d.Tok != token.IMPORT {
				t.Fatalf("esconfigcheck declares a %s at %s; only main is allowed", d.Tok, fset.PositionFor(d.Pos(), false))
			}
		case *ast.FuncDecl:
			if d.Name.Name != "main" || d.Recv != nil {
				t.Fatalf("esconfigcheck declares func %s at %s; only main is allowed", d.Name.Name, fset.PositionFor(d.Pos(), false))
			}
			var body bytes.Buffer
			if err := format.Node(&body, fset, d.Body); err != nil {
				t.Fatal(err)
			}
			if body.String() != esConfigCheckMainBody {
				t.Errorf("esconfigcheck's main changed; it must stay exactly:\n%s\ngot:\n%s", esConfigCheckMainBody, body.String())
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
			t.Errorf("esconfigcheck has a function literal at %s", fset.PositionFor(node.Pos(), false))
		case *ast.CallExpr:
			name := ""
			switch fun := node.Fun.(type) {
			case *ast.Ident:
				name = fun.Name
			case *ast.SelectorExpr:
				if pkg, ok := fun.X.(*ast.Ident); ok {
					name = pkg.Name + "." + fun.Sel.Name
				}
			}
			if !allowed[name] {
				t.Errorf("esconfigcheck calls %q at %s; it may call only config.Load and the reporting functions", name, fset.PositionFor(node.Pos(), false))
			}
			if name == "config.Load" {
				loads++
			}
		}
		return true
	})
	if loads != 1 {
		t.Fatalf("esconfigcheck calls config.Load %d times, want once", loads)
	}
}

// TestESConfigCheckAgreesWithConfigLoad runs the built helper on the
// submit example and on configs config.Load refuses, and requires the
// helper's answer and reason to be config.Load's own.
func TestESConfigCheckAgreesWithConfigLoad(t *testing.T) {
	helper := buildESConfigCheck(t)
	example, err := os.ReadFile(repoPath(".examples/config/es.json"))
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

// TestESConfigCheckNeedsNoModuleButTheRepository keeps esconfigcheck,
// which check and apply run as root, free of every module but this
// repository's own. The upgrade reads the module lines of the binaries it
// installs, es and es-runtime-support, but not of esconfigcheck, which it
// binds by owner and SHA-256 (the tests run a host build of it, a Mach-O
// file on macOS); build refuses a replaced or unhashed module in all three.
// With no module outside the repository, neither a go.work nor a replace
// can change esconfigcheck's code (red-team audit 32, A32-1). A module
// added here fails this test, and with it that reasoning.
func TestESConfigCheckNeedsNoModuleButTheRepository(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", "-f", "{{with .Module}}{{.Path}}{{end}}", "execution-substrate/scripts/internal/esconfigcheck")
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=readonly", "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -deps esconfigcheck: %v\n%s", err, stderr.String())
	}
	modules := map[string]bool{}
	for _, module := range strings.Fields(string(out)) {
		modules[module] = true
	}
	if len(modules) != 1 || !modules["execution-substrate"] {
		t.Fatalf("esconfigcheck's packages come from the modules %v; want execution-substrate alone", sortedKeys(modules))
	}
}

func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func buildESConfigCheck(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "esconfigcheck")
	cmd := exec.Command("go", "build", "-o", out, "execution-substrate/scripts/internal/esconfigcheck")
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build esconfigcheck: %v\n%s", err, output)
	}
	return out
}
