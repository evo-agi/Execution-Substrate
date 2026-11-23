package testtmpdir_test

import (
	"encoding/json"
	"errors"
	"go/ast"
	"go/build"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"execution-substrate/internal/testtmpdir"
)

func TestMain(m *testing.M) { os.Exit(testtmpdir.Main(m)) }

// childReportVariable names the file to which a child run of
// TestResolvedDirectoryReachesEveryTestAndChild writes what it saw. Only a
// process that the test starts itself has it set.
const childReportVariable = "TESTTMPDIR_CHILD_REPORT"

type childReport struct {
	TMPDIRSet        bool   `json:"tmpdir_set"`
	TMPDIR           string `json:"tmpdir"`
	OSTempDir        string `json:"os_tempdir"`
	TestTempDir      string `json:"test_tempdir"`
	TestTempResolved string `json:"test_tempdir_resolved"`
	Subprocess       string `json:"subprocess"`
}

// physicalTempDir returns a new temporary directory by its physical path.
// The TestMain of this package has already resolved the temporary
// directory; the test still checks it, so that a broken Main cannot make
// the fixtures below go through a symbolic link of the host.
func physicalTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != dir {
		t.Fatalf("t.TempDir() %q goes through a symbolic link to %q in a package that runs under testtmpdir.Main", dir, resolved)
	}
	return dir
}

func childEnvironment(extra ...string) []string {
	var env []string
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "TMPDIR=") || strings.HasPrefix(entry, childReportVariable+"=") {
			continue
		}
		env = append(env, entry)
	}
	return append(env, extra...)
}

func runChild(t *testing.T, env []string) (string, error) {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestResolvedDirectoryReachesEveryTestAndChild$", "-test.count=1", "-test.v")
	command.Env = env
	output, err := command.CombinedOutput()
	return string(output), err
}

func writeChildReport(t *testing.T, path string) {
	value, set := os.LookupEnv("TMPDIR")
	dir := t.TempDir()
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("/bin/sh", "-c", `if [ "${TMPDIR+set}" = set ]; then printf 'set:%s' "$TMPDIR"; else printf unset; fi`).Output()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(childReport{
		TMPDIRSet:        set,
		TMPDIR:           value,
		OSTempDir:        os.TempDir(),
		TestTempDir:      dir,
		TestTempResolved: resolved,
		Subprocess:       string(output),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestResolvedDirectoryReachesEveryTestAndChild runs this test binary again
// under a temporary directory behind a symbolic link, as macOS gives one,
// and checks that its tests and the processes they start see the physical
// path of that directory. It also checks that a physical directory, and an
// unset TMPDIR on a host whose /tmp is physical, are left exactly as they
// were.
func TestResolvedDirectoryReachesEveryTestAndChild(t *testing.T) {
	if path := os.Getenv(childReportVariable); path != "" {
		writeChildReport(t, path)
		return
	}

	base := physicalTempDir(t)
	// The layout of macOS: /var -> private/var, TMPDIR=/var/folders/../T/.
	nested := filepath.Join(base, "private", "var", "folders", "zz", "T")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("private", "var"), filepath.Join(base, "var")); err != nil {
		t.Fatal(err)
	}
	last := filepath.Join(base, "last")
	if err := os.Mkdir(last, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(last, filepath.Join(base, "last-link")); err != nil {
		t.Fatal(err)
	}
	unsetWant := "/tmp"
	if resolved, err := filepath.EvalSymlinks("/tmp"); err != nil {
		t.Fatal(err)
	} else {
		unsetWant = resolved
	}

	cases := []struct {
		name    string
		env     []string
		wantSet bool
		want    string
	}{
		{"ancestor is a symbolic link", []string{"TMPDIR=" + filepath.Join(base, "var", "folders", "zz", "T") + "/"}, true, nested},
		{"last component is a symbolic link", []string{"TMPDIR=" + filepath.Join(base, "last-link")}, true, last},
		{"physical path is kept as given", []string{"TMPDIR=" + nested + "/"}, true, nested + "/"},
		{"unset TMPDIR", nil, unsetWant != "/tmp", unsetWant},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reportPath := filepath.Join(physicalTempDir(t), "report.json")
			output, err := runChild(t, childEnvironment(append(tc.env, childReportVariable+"="+reportPath)...))
			if err != nil {
				t.Fatalf("child run: %v\n%s", err, output)
			}
			data, err := os.ReadFile(reportPath)
			if err != nil {
				t.Fatalf("child wrote no report: %v\n%s", err, output)
			}
			var report childReport
			if err := json.Unmarshal(data, &report); err != nil {
				t.Fatal(err)
			}
			physical := filepath.Clean(tc.want)
			if report.TMPDIRSet != tc.wantSet || (tc.wantSet && report.TMPDIR != tc.want) {
				t.Fatalf("child TMPDIR: set=%t value=%q, want set=%t value=%q", report.TMPDIRSet, report.TMPDIR, tc.wantSet, tc.want)
			}
			wantSubprocess := "unset"
			if tc.wantSet {
				wantSubprocess = "set:" + tc.want
			}
			if report.Subprocess != wantSubprocess {
				t.Fatalf("process started by the child saw %q, want %q", report.Subprocess, wantSubprocess)
			}
			if filepath.Clean(report.OSTempDir) != physical {
				t.Fatalf("child os.TempDir() = %q, want %q", report.OSTempDir, physical)
			}
			if !strings.HasPrefix(report.TestTempDir, physical+string(filepath.Separator)) {
				t.Fatalf("child t.TempDir() = %q is not below %q", report.TestTempDir, physical)
			}
			if report.TestTempResolved != report.TestTempDir {
				t.Fatalf("child t.TempDir() %q goes through a symbolic link to %q", report.TestTempDir, report.TestTempResolved)
			}
		})
	}
}

// TestUnresolvableDirectoryRunsNoTest checks that a test binary whose
// temporary directory cannot be resolved runs none of its tests, says why,
// and exits with ExitResolveFailed.
func TestUnresolvableDirectoryRunsNoTest(t *testing.T) {
	base := physicalTempDir(t)
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "nowhere"), filepath.Join(base, "dangling")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(file, filepath.Join(base, "file-link")); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		tmpdir string
		reason string
	}{
		{"missing directory", filepath.Join(base, "missing"), "no such file or directory"},
		{"relative path", "relative/tmp", "is not an absolute path"},
		{"regular file", file, "is not a directory"},
		{"dangling symbolic link", filepath.Join(base, "dangling"), "no such file or directory"},
		{"symbolic link to a file", filepath.Join(base, "file-link"), "is not a directory"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reportPath := filepath.Join(physicalTempDir(t), "report.json")
			output, err := runChild(t, childEnvironment("TMPDIR="+tc.tmpdir, childReportVariable+"="+reportPath))
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != testtmpdir.ExitResolveFailed {
				t.Fatalf("child exit: %v, want exit status %d\n%s", err, testtmpdir.ExitResolveFailed, output)
			}
			if !strings.Contains("\n"+output, "\ntesttmpdir: ") || !strings.Contains(output, strconv.Quote(tc.tmpdir)) || !strings.Contains(output, tc.reason) {
				t.Fatalf("child did not name the directory %q and the reason %q:\n%s", tc.tmpdir, tc.reason, output)
			}
			if strings.Contains(output, "=== RUN") {
				t.Fatalf("child ran a test:\n%s", output)
			}
			if _, err := os.Lstat(reportPath); !os.IsNotExist(err) {
				t.Fatalf("child wrote a report: %v", err)
			}
		})
	}
}

// minimumTestPackages is the number of directories with test files that
// the module had when the guard below was written. The guard fails when it
// finds fewer, so that a walk that misses the module cannot pass. Lower it
// in the change that removes a package's last test file.
const minimumTestPackages = 22

const testtmpdirImportPath = "execution-substrate/internal/testtmpdir"

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		data, err := os.ReadFile(filepath.Join(dir, "go.mod"))
		if err == nil {
			first, _, _ := strings.Cut(string(data), "\n")
			if strings.TrimSpace(first) != "module execution-substrate" {
				t.Fatalf("%s/go.mod declares %q, not module execution-substrate", dir, first)
			}
			return dir
		}
		if !errors.Is(err, fs.ErrNotExist) {
			t.Fatal(err)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the working directory")
		}
		dir = parent
	}
}

// testPackageDirs returns, relative to the module root, every directory
// that the go command reads as a package of this module and that has test
// files. It follows the go command's rules: directories and files whose
// names begin with "." or "_", directories named testdata or vendor, and
// directories of other modules are not part of the module.
func testPackageDirs(t *testing.T, root string) map[string][]string {
	t.Helper()
	dirs := map[string][]string{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := entry.Name()
		if entry.IsDir() {
			if path == root {
				return nil
			}
			if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || name == "testdata" || name == "vendor" {
				return filepath.SkipDir
			}
			if _, err := os.Lstat(filepath.Join(path, "go.mod")); err == nil {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() || !strings.HasSuffix(name, "_test.go") || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
			return nil
		}
		rel, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		dirs[rel] = append(dirs[rel], name)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return dirs
}

// buildContexts are platforms on which the TestMain file has to build: the
// Linux platforms that ES is built for and the macOS platforms that it is
// developed on. A file name that ends in a GOOS or GOARCH suffix fails at
// least one of them; a //go:build line is refused separately.
func buildContexts() []build.Context {
	var contexts []build.Context
	for _, platform := range [][2]string{{"linux", "amd64"}, {"linux", "arm64"}, {"darwin", "arm64"}, {"darwin", "amd64"}} {
		context := build.Default
		context.GOOS = platform[0]
		context.GOARCH = platform[1]
		context.CgoEnabled = false
		contexts = append(contexts, context)
	}
	return contexts
}

// testMainProblem returns why the TestMain of one package does not run its
// tests through testtmpdir.Main, or "" when it does.
func testMainProblem(root, rel string, files []string) string {
	dir := filepath.Join(root, rel)
	fset := token.NewFileSet()
	var found []string
	var file *ast.File
	var decl *ast.FuncDecl
	for _, name := range files {
		parsed, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			return "cannot parse " + name + ": " + err.Error()
		}
		for _, d := range parsed.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == "TestMain" {
				found = append(found, name)
				file, decl = parsed, fn
			}
		}
	}
	if len(found) != 1 {
		return "has " + strconv.Itoa(len(found)) + " TestMain functions " + strings.Join(found, ", ") + ", want exactly one"
	}
	for _, context := range buildContexts() {
		match, err := context.MatchFile(dir, found[0])
		if err != nil {
			return "cannot read the build constraints of " + found[0] + ": " + err.Error()
		}
		if !match {
			return found[0] + " does not build for " + context.GOOS + "/" + context.GOARCH
		}
	}
	for _, group := range file.Comments {
		if group.Pos() > file.Package {
			break
		}
		for _, comment := range group.List {
			if constraint.IsGoBuild(comment.Text) || constraint.IsPlusBuild(comment.Text) {
				return found[0] + " has a build constraint"
			}
		}
	}
	imports := map[string]string{}
	for _, spec := range file.Imports {
		path, _ := strconv.Unquote(spec.Path.Value)
		name := ""
		if spec.Name != nil {
			name = spec.Name.Name
		}
		imports[path] = name
	}
	if name, ok := imports["os"]; !ok || name != "" {
		return found[0] + " does not import os under its own name"
	}
	if name, ok := imports["testing"]; !ok || name != "" {
		return found[0] + " does not import testing under its own name"
	}
	if name, ok := imports[testtmpdirImportPath]; !ok || name != "" {
		return found[0] + " does not import " + testtmpdirImportPath + " under its own name"
	}
	params := decl.Type.Params.List
	if decl.Type.Results != nil || len(params) != 1 || len(params[0].Names) != 1 {
		return "TestMain in " + found[0] + " does not take exactly one *testing.M"
	}
	star, ok := params[0].Type.(*ast.StarExpr)
	if !ok || !isSelector(star.X, "testing", "M") {
		return "TestMain in " + found[0] + " does not take exactly one *testing.M"
	}
	param := params[0].Names[0].Name
	body := decl.Body.List
	if len(body) != 1 {
		return "TestMain in " + found[0] + " does more than os.Exit(testtmpdir.Main(" + param + "))"
	}
	statement, ok := body[0].(*ast.ExprStmt)
	if !ok {
		return "TestMain in " + found[0] + " is not os.Exit(testtmpdir.Main(" + param + "))"
	}
	exit, ok := statement.X.(*ast.CallExpr)
	if !ok || !isSelector(exit.Fun, "os", "Exit") || len(exit.Args) != 1 || exit.Ellipsis.IsValid() {
		return "TestMain in " + found[0] + " is not os.Exit(testtmpdir.Main(" + param + "))"
	}
	run, ok := exit.Args[0].(*ast.CallExpr)
	if !ok || !isSelector(run.Fun, "testtmpdir", "Main") || len(run.Args) != 1 || run.Ellipsis.IsValid() {
		return "TestMain in " + found[0] + " is not os.Exit(testtmpdir.Main(" + param + "))"
	}
	if arg, ok := run.Args[0].(*ast.Ident); !ok || arg.Name != param {
		return "TestMain in " + found[0] + " is not os.Exit(testtmpdir.Main(" + param + "))"
	}
	return ""
}

func isSelector(expr ast.Expr, pkg, name string) bool {
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != name {
		return false
	}
	ident, ok := selector.X.(*ast.Ident)
	return ok && ident.Name == pkg
}

// TestEveryTestPackageResolvesTheTemporaryDirectory holds the rule of this
// package for the whole module: every package that has tests runs them
// through testtmpdir.Main, from a TestMain in a file without a build
// constraint. A package that adds its first test file adds that TestMain in
// the same change.
func TestEveryTestPackageResolvesTheTemporaryDirectory(t *testing.T) {
	root := moduleRoot(t)
	dirs := testPackageDirs(t, root)
	if len(dirs) < minimumTestPackages {
		t.Fatalf("found %d directories with test files below %s, want at least %d", len(dirs), root, minimumTestPackages)
	}
	for _, required := range []string{".", "es/admission", "es/admission/internal/reliablesubmit", "es/app", filepath.Join("internal", "testtmpdir")} {
		if _, ok := dirs[filepath.FromSlash(required)]; !ok {
			t.Fatalf("the walk of %s did not find the test files of %s", root, required)
		}
	}
	rels := make([]string, 0, len(dirs))
	for rel := range dirs {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	for _, rel := range rels {
		if problem := testMainProblem(root, rel, dirs[rel]); problem != "" {
			t.Errorf("package %s: %s. Add a file with\n\n\tfunc TestMain(m *testing.M) { os.Exit(testtmpdir.Main(m)) }\n\nand the imports os, testing and %s, and no build constraint.", rel, problem, testtmpdirImportPath)
		}
	}
}

// TestGuardRefusesTestMainsThatDoNotResolve checks the guard above on
// packages it writes itself, so that the guard cannot pass by accepting
// everything.
func TestGuardRefusesTestMainsThatDoNotResolve(t *testing.T) {
	const imports = "import (\n\t\"os\"\n\t\"testing\"\n\n\t\"execution-substrate/internal/testtmpdir\"\n)\n\n"
	const good = "package p\n\n" + imports + "func TestMain(m *testing.M) { os.Exit(testtmpdir.Main(m)) }\n"
	cases := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"canonical", map[string]string{"main_test.go": good, "a_test.go": "package p\n"}, ""},
		{"canonical in the external test package", map[string]string{"main_test.go": strings.Replace(good, "package p", "package p_test", 1), "a_test.go": "package p\n"}, ""},
		{"no TestMain", map[string]string{"a_test.go": "package p\n"}, "has 0 TestMain functions"},
		{"TestMain without testtmpdir", map[string]string{"main_test.go": "package p\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestMain(m *testing.M) { os.Exit(m.Run()) }\n"}, "does not import execution-substrate/internal/testtmpdir"},
		{"TestMain that runs the tests directly", map[string]string{"main_test.go": "package p\n\n" + imports + "func TestMain(m *testing.M) { os.Exit(m.Run()) }\n"}, "is not os.Exit(testtmpdir.Main(m))"},
		{"TestMain that does more", map[string]string{"main_test.go": "package p\n\n" + imports + "func TestMain(m *testing.M) {\n\tos.Setenv(\"TMPDIR\", \"/var\")\n\tos.Exit(testtmpdir.Main(m))\n}\n"}, "does more than"},
		{"Linux only", map[string]string{"main_linux_test.go": good}, "does not build for darwin/arm64"},
		{"build constraint", map[string]string{"main_test.go": "//go:build linux\n\n" + good}, "does not build for darwin/arm64"},
		{"build constraint that every checked platform meets", map[string]string{"main_test.go": "//go:build unix\n\n" + good}, "has a build constraint"},
		{"old-style build constraint", map[string]string{"main_test.go": "// +build !windows\n\n" + good}, "has a build constraint"},
		{"comment that only mentions a build constraint", map[string]string{"main_test.go": "// Not a constraint: //go:build linux\n\n" + good}, ""},
		{"renamed import", map[string]string{"main_test.go": strings.Replace(good, "\t\"execution-substrate/internal/testtmpdir\"", "\tt2 \"execution-substrate/internal/testtmpdir\"", 1)}, "under its own name"},
		{"wrong argument", map[string]string{"main_test.go": strings.Replace(good, "testtmpdir.Main(m)", "testtmpdir.Main(nil)", 1)}, "is not os.Exit(testtmpdir.Main(m))"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := physicalTempDir(t)
			var names []string
			for name, content := range tc.files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
				names = append(names, name)
			}
			sort.Strings(names)
			problem := testMainProblem(dir, ".", names)
			if tc.want == "" && problem != "" {
				t.Fatalf("guard refused a canonical TestMain: %s", problem)
			}
			if tc.want != "" && !strings.Contains(problem, tc.want) {
				t.Fatalf("guard problem %q does not contain %q", problem, tc.want)
			}
		})
	}
}

// TestTheRuleIsDocumented holds the description of the rule in the
// capability probing document, which is where test harness rules live.
func TestTheRuleIsDocumented(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(moduleRoot(t), ".docs", "system_overview", "capability_probing.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	start := strings.Index(text, "\n## Test Harness Use\n")
	if start < 0 {
		t.Fatal("capability_probing.md has no section \"Test Harness Use\"")
	}
	section := strings.Join(strings.Fields(text[start:]), " ")
	for _, phrase := range []string{
		"`internal/testtmpdir`",
		"`os.Exit(testtmpdir.Main(m))`",
		"`/var` -> `private/var`",
		"`/tmp` -> `private/tmp`",
		"can pass for the wrong reason",
		"changes nothing where the temporary directory is already physical",
		"runs no test",
		"A guard test",
		"does not weaken any refusal of a symbolic link",
	} {
		if !strings.Contains(section, phrase) {
			t.Errorf("section \"Test Harness Use\" of capability_probing.md does not say %q", phrase)
		}
	}
}
