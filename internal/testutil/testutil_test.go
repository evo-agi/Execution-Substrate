package testutil_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"execution-substrate/internal/testutil"
)

const importPath = "execution-substrate/internal/testutil"

// TestRootIsTheRepositoryRoot checks Root and Path.
func TestRootIsTheRepositoryRoot(t *testing.T) {
	if !filepath.IsAbs(testutil.Root) {
		t.Fatalf("Root %q is not absolute", testutil.Root)
	}
	for _, name := range []string{"go.mod", "AGENTS.md", "PLANS.md", "scripts", "internal/testutil/testutil.go"} {
		if _, err := os.Stat(filepath.Join(testutil.Root, name)); err != nil {
			t.Errorf("Root %q: %v", testutil.Root, err)
		}
	}
	if got, want := testutil.Path("PLANS.md"), filepath.Join(testutil.Root, "PLANS.md"); got != want {
		t.Errorf("Path(PLANS.md) = %q, want %q", got, want)
	}
	if got := testutil.Path("/etc/hostname"); got != "/etc/hostname" {
		t.Errorf("Path(/etc/hostname) = %q, want it unchanged", got)
	}
}

// TestOnlyTestFilesImportTestutil keeps this package out of every binary
// but test binaries.
func TestOnlyTestFilesImportTestutil(t *testing.T) {
	for dir, files := range goPackageDirs(t) {
		for _, file := range files.nonTest {
			if importsTestutil(t, file) {
				rel, _ := filepath.Rel(testutil.Root, file)
				t.Errorf("%s imports %s; only test files may", rel, importPath)
			}
		}
		_ = dir
	}
}

// rootTestFiles are the test files that the repository root keeps besides
// its docs tests, which are named *_docs_contract_test.go.
var rootTestFiles = []string{"artifact_hygiene_test.go", "docs_contract_test.go", "testtmpdir_main_test.go"}

// TestRootKeepsOnlyItsDocsTests holds the layout of the repository root's
// tests: the root keeps the tests that check the repository's docs, named
// by what they check, and the tests of the scripts live in scripts/, next
// to the scripts. A script test added at the root would compile and pass
// there, so nothing else would notice it.
func TestRootKeepsOnlyItsDocsTests(t *testing.T) {
	entries, err := os.ReadDir(testutil.Root)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".go") {
			names = append(names, entry.Name())
		}
	}
	for _, problem := range rootLayoutProblems(names) {
		t.Error(problem)
	}
}

// TestRootLayoutCheckFindsEachKindOfProblem shows that the check above
// refuses a script test, a test named otherwise, and a non-test file at the
// root, and notices a missing file.
func TestRootLayoutCheckFindsEachKindOfProblem(t *testing.T) {
	good := []string{
		"ars_blob_verification_docs_contract_test.go",
		"artifact_hygiene_test.go",
		"caller_authentication_docs_contract_test.go",
		"codex_agent_configs_docs_contract_test.go",
		"docs_contract_test.go",
		"host_access_docs_contract_test.go",
		"outside_observer_docs_contract_test.go",
		"testtmpdir_main_test.go",
	}
	if problems := rootLayoutProblems(good); len(problems) != 0 {
		t.Errorf("problems in the agreed layout, want none:\n%s", strings.Join(problems, "\n"))
	}
	bad := []string{
		"artifact_hygiene_test.go",
		"docs_contract_test.go",
		"remote_alpha_spire_agent_test.go",
		"remote_alpha_firewall_docs_contract_test.go",
		"hygiene_test.go",
		"helpers.go",
	}
	want := []string{
		"remote_alpha_spire_agent_test.go: " + rootLayoutRule,
		"remote_alpha_firewall_docs_contract_test.go: " + rootLayoutRule,
		"hygiene_test.go: " + rootLayoutRule,
		"helpers.go: " + rootLayoutRule,
		"testtmpdir_main_test.go is missing from the repository root",
	}
	if problems := rootLayoutProblems(bad); strings.Join(problems, "\n") != strings.Join(want, "\n") {
		t.Errorf("problems:\n%s\nwant:\n%s", strings.Join(problems, "\n"), strings.Join(want, "\n"))
	}
}

const rootLayoutRule = "the repository root keeps only the tests of its docs, named *_docs_contract_test.go " +
	"and without remote_alpha in the name, and artifact_hygiene_test.go, docs_contract_test.go and testtmpdir_main_test.go; " +
	"a test of a script belongs in scripts/, next to the script"

// rootLayoutProblems checks the names of the Go files at the repository
// root against the agreed layout.
func rootLayoutProblems(names []string) []string {
	var problems []string
	for _, name := range names {
		docsTest := strings.HasSuffix(name, "_docs_contract_test.go") && !strings.Contains(name, "remote_alpha")
		if !docsTest && !slices.Contains(rootTestFiles, name) {
			problems = append(problems, name+": "+rootLayoutRule)
		}
	}
	for _, name := range rootTestFiles {
		if !slices.Contains(names, name) {
			problems = append(problems, name+" is missing from the repository root")
		}
	}
	return problems
}

// TestImportersNameRepositoryPathsFromTheRoot holds the rule in the package
// documentation for every package outside the repository root whose tests
// import this package: a repository path written relative to the
// repository root has to go through Path or Read (or a helper built on
// them), and every command those tests start has to get a working
// directory of its own. A relative path that slipped through would name a
// missing file below the package directory: a read would fail loudly, but
// a check that a file does not exist, a glob or a directory walk would pass
// without checking anything. The working directory is never changed or
// read.
func TestImportersNameRepositoryPathsFromTheRoot(t *testing.T) {
	checked := map[string]int{}
	for dir, files := range goPackageDirs(t) {
		if dir == testutil.Root {
			continue
		}
		imports := false
		for _, file := range files.test {
			if importsTestutil(t, file) {
				imports = true
			}
		}
		if !imports {
			continue
		}
		rel, err := filepath.Rel(testutil.Root, dir)
		if err != nil {
			t.Fatal(err)
		}
		fset := token.NewFileSet()
		var parsed []*ast.File
		for _, file := range append(append([]string{}, files.nonTest...), files.test...) {
			f, err := parser.ParseFile(fset, file, nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			parsed = append(parsed, f)
		}
		checked[filepath.ToSlash(rel)] = len(parsed)
		for _, problem := range repoPathProblems(fset, parsed, repoRelativeNames(t, dir)) {
			t.Errorf("%s/%s", filepath.ToSlash(rel), problem)
		}
	}
	// The check must not pass by finding nothing: scripts/ holds the tests
	// of the Remote Alpha scripts, which moved there from the repository
	// root.
	if checked["scripts"] < 33 {
		t.Fatalf("checked %v, want scripts with at least 33 Go files", checked)
	}
}

// TestRepoPathCheckFindsEachKindOfProblem shows that the check above reports
// each kind of problem it is meant to find, and nothing in code that follows
// the rule.
func TestRepoPathCheckFindsEachKindOfProblem(t *testing.T) {
	entries := map[string]bool{"PLANS.md": true, "scripts": true, ".codex": true, "es": true}
	const bad = `package p

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const retired = "scripts/retired.sh"

var removed = map[string]string{".codex/hooks": "removed"}

func f(t *testing.T) {
	os.ReadFile("PLANS.md")
	os.Stat(retired)
	filepath.Glob("es/admission/*.go")
	filepath.WalkDir(".", nil)
	os.ReadDir(filepath.Join("scripts", "internal"))
	os.Lstat("scripts/" + "x.sh")
	for path := range removed {
		os.Stat(path)
	}
	for _, name := range []string{"PLANS.md"} {
		os.Open(name)
	}
	local := ".codex/config.toml"
	os.Stat(local)
	cmd := exec.Command("bash", "scripts/x.sh")
	cmd.Dir = "/somewhere"
	exec.Command("/bin/true").Run()
	noDir := exec.Command("/bin/true")
	noDir.Run()
	os.Chdir("/")
	os.Getwd()
	t.Chdir("/")
	os.Symlink("/target", "scripts/link")
	os.Rename("/from", "es/to")
	read(t, "PLANS.md")
	for _, r := range routes {
		os.ReadFile(r.path)
	}
	filepath.Join(testutil.Root, "moved_test.go")
	testutil.Read(t, "missing/x.md")
	filepath.Glob(filepath.Join(root, "*.nothing"))
}

func read(t *testing.T, name string) {
	os.ReadFile(name)
}

type route struct{ path string }

var routes = []route{{path: "scripts/a.sh"}}

var root = testutil.Root
`
	const good = `package p

import (
	"os"
	"os/exec"
	"path/filepath"
)

const script = "scripts/x.sh"

func g(dir string) {
	os.ReadFile(repoPath("PLANS.md"))
	os.Stat(repoPath(script))
	filepath.Glob(filepath.Join(repoRoot, "es/admission/*.go"))
	os.ReadFile(filepath.Join(dir, "scripts", "x.sh"))
	os.ReadFile("/etc/hostname")
	os.ReadFile("testdata/own.txt")
	os.Stat(dir)
	os.Symlink("scripts/relative-target", filepath.Join(dir, "link"))
	cmd := exec.Command("/bin/bash", repoPath(script), "es")
	cmd.Dir = repoRoot
	cmd.Run()
	filepath.Join(testutil.Root, "scripts", "x.sh")
	filepath.Join(rootDir(), "*_test.go")
	testutil.Path("PLANS.md")
}

func rootDir() string { return testutil.Root }
`
	fset := token.NewFileSet()
	parse := func(name, source string) []*ast.File {
		file, err := parser.ParseFile(fset, name, source, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		return []*ast.File{file}
	}
	problems := repoPathProblems(fset, parse("bad.go", bad), entries)
	want := []string{
		`bad.go:15: os.ReadFile gets the repository-relative path "PLANS.md"`,
		`bad.go:16: os.Stat gets the repository-relative path "scripts/retired.sh"`,
		`bad.go:17: filepath.Glob gets the repository-relative path "es/admission/*.go"`,
		`bad.go:18: filepath.WalkDir gets the repository-relative path "."`,
		`bad.go:19: os.ReadDir gets the repository-relative path "scripts"`,
		`bad.go:20: os.Lstat gets the repository-relative path "scripts/"`,
		`bad.go:22: os.Stat gets the repository-relative path ".codex/hooks"`,
		`bad.go:25: os.Open gets the repository-relative path "PLANS.md"`,
		`bad.go:28: os.Stat gets the repository-relative path ".codex/config.toml"`,
		`bad.go:29: exec.Command gets the repository-relative path "scripts/x.sh"`,
		`bad.go:31: exec.Command is not assigned to a variable whose Dir is set`,
		`bad.go:32: exec.Command is not assigned to a variable whose Dir is set`,
		`bad.go:34: os.Chdir changes or reads the working directory`,
		`bad.go:35: os.Getwd changes or reads the working directory`,
		`bad.go:36: Chdir changes or reads the working directory`,
		`bad.go:37: os.Symlink gets the repository-relative path "scripts/link"`,
		`bad.go:38: os.Rename gets the repository-relative path "es/to"`,
		`bad.go:39: read gets the repository-relative path "PLANS.md"`,
		`bad.go:41: os.ReadFile gets the repository-relative path "scripts/a.sh"`,
		`bad.go:43: filepath.Join resolves "moved_test.go" against the repository root, which holds no such name`,
		`bad.go:44: testutil.Read resolves "missing/x.md" against the repository root, which holds no such name`,
		`bad.go:45: filepath.Join resolves "*.nothing" against the repository root, which holds no such name`,
	}
	if strings.Join(problems, "\n") != strings.Join(want, "\n") {
		t.Errorf("problems in bad.go:\n%s\nwant:\n%s", strings.Join(problems, "\n"), strings.Join(want, "\n"))
	}
	if problems := repoPathProblems(fset, parse("good.go", good), entries); len(problems) != 0 {
		t.Errorf("problems in good.go, want none:\n%s", strings.Join(problems, "\n"))
	}
}

type packageFiles struct{ nonTest, test []string }

// goPackageDirs returns the Go files of every directory that go list ./...
// would visit, by absolute directory path.
func goPackageDirs(t *testing.T) map[string]*packageFiles {
	t.Helper()
	dirs := map[string]*packageFiles{}
	err := filepath.WalkDir(testutil.Root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := entry.Name()
		if entry.IsDir() {
			if path != testutil.Root && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || name == "testdata" || name == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || !entry.Type().IsRegular() {
			return nil
		}
		dir := filepath.Dir(path)
		if dirs[dir] == nil {
			dirs[dir] = &packageFiles{}
		}
		if strings.HasSuffix(name, "_test.go") {
			dirs[dir].test = append(dirs[dir].test, path)
		} else {
			dirs[dir].nonTest = append(dirs[dir].nonTest, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(dirs) < 20 {
		t.Fatalf("found %d Go package directories below %s, want at least 20", len(dirs), testutil.Root)
	}
	return dirs
}

func importsTestutil(t *testing.T, file string) bool {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range f.Imports {
		if path, err := strconv.Unquote(spec.Path.Value); err == nil && path == importPath {
			return true
		}
	}
	return false
}

// repoRelativeNames returns the names at the repository root that a path
// relative to dir could mistake for its own: those that dir does not hold
// itself. A relative path whose first element is one of them, or ".",
// is taken as written relative to the repository root.
func repoRelativeNames(t *testing.T, dir string) map[string]bool {
	t.Helper()
	rootEntries, err := os.ReadDir(testutil.Root)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, entry := range rootEntries {
		if entry.Name() == ".git" {
			continue
		}
		if _, err := os.Lstat(filepath.Join(dir, entry.Name())); err == nil {
			continue
		}
		names[entry.Name()] = true
	}
	for _, name := range []string{"AGENTS.md", "PLANS.md", "go.mod", "scripts", ".docs", "es"} {
		if !names[name] {
			t.Fatalf("repository root %q has no %s, or %s holds one too", testutil.Root, name, dir)
		}
	}
	return names
}

// pathCalls are the calls whose arguments at the given indexes are paths
// that the working directory resolves. The target of os.Symlink is not:
// the link's own directory resolves it.
var pathCalls = map[string][]int{
	"os.ReadFile":           {0},
	"os.Stat":               {0},
	"os.Lstat":              {0},
	"os.Open":               {0},
	"os.OpenFile":           {0},
	"os.Create":             {0},
	"os.ReadDir":            {0},
	"os.Readlink":           {0},
	"os.DirFS":              {0},
	"os.OpenRoot":           {0},
	"os.OpenInRoot":         {0},
	"os.CopyFS":             {0},
	"os.Remove":             {0},
	"os.RemoveAll":          {0},
	"os.Rename":             {0, 1},
	"os.Link":               {0, 1},
	"os.Symlink":            {1},
	"os.Chmod":              {0},
	"os.Chown":              {0},
	"os.Lchown":             {0},
	"os.Chtimes":            {0},
	"os.Truncate":           {0},
	"os.WriteFile":          {0},
	"os.Mkdir":              {0},
	"os.MkdirAll":           {0},
	"os.MkdirTemp":          {0},
	"os.CreateTemp":         {0},
	"filepath.Glob":         {0},
	"filepath.Walk":         {0},
	"filepath.WalkDir":      {0},
	"filepath.EvalSymlinks": {0},
	"filepath.Abs":          {0},
}

// workingDirectoryCalls are refused outright.
var workingDirectoryCalls = map[string]bool{"os.Chdir": true, "os.Getwd": true}

func repoPathProblems(fset *token.FileSet, files []*ast.File, entries map[string]bool) []string {
	isRepoRelative := func(value string) bool {
		if value == "." || value == "./" {
			return true
		}
		if value == "" || filepath.IsAbs(value) {
			return false
		}
		first := strings.SplitN(strings.TrimPrefix(value, "./"), "/", 2)[0]
		return entries[first]
	}
	// A command argument counts as a repository path when it has a "/" or
	// names a file at the root. A bare directory name such as "es" is a
	// common argument that names no path.
	isRepoRelativeArgument := func(value string) bool {
		return strings.Contains(value, "/") && isRepoRelative(value) || value != "" && entries[value] && !isDirectoryName(value)
	}
	// Values of package-level constants and variables, by name.
	packageBindings := map[string][]ast.Expr{}
	var funcs []*ast.FuncDecl
	for _, file := range files {
		for _, decl := range file.Decls {
			switch decl := decl.(type) {
			case *ast.GenDecl:
				bindSpecs(decl, packageBindings)
			case *ast.FuncDecl:
				if decl.Body != nil {
					funcs = append(funcs, decl)
				}
			}
		}
	}
	// Names of the repository root: package variables bound to
	// testutil.Root, and functions without parameters that return it.
	rootVars := map[string]bool{}
	for name, values := range packageBindings {
		for _, value := range values {
			if isTestutilRoot(value) {
				rootVars[name] = true
			}
		}
	}
	rootFuncs := map[string]bool{}
	for _, fn := range funcs {
		if fn.Recv == nil && fn.Type.Params.NumFields() == 0 && len(fn.Body.List) == 1 {
			if ret, ok := fn.Body.List[0].(*ast.ReturnStmt); ok && len(ret.Results) == 1 {
				if isTestutilRoot(ret.Results[0]) {
					rootFuncs[fn.Name.Name] = true
				}
				if ident, ok := ret.Results[0].(*ast.Ident); ok && rootVars[ident.Name] {
					rootFuncs[fn.Name.Name] = true
				}
			}
		}
	}
	rules := pathRules{
		isRepoRelative:         isRepoRelative,
		isRepoRelativeArgument: isRepoRelativeArgument,
		missingAtRoot:          missingAtRoot,
		isRoot: func(expr ast.Expr) bool {
			switch e := expr.(type) {
			case *ast.Ident:
				return rootVars[e.Name]
			case *ast.CallExpr:
				ident, ok := e.Fun.(*ast.Ident)
				return ok && len(e.Args) == 0 && rootFuncs[ident.Name]
			}
			return isTestutilRoot(expr)
		},
	}
	// pathParams records, for each function of the package, the parameters
	// that reach a path, a command argument or a path anchored at the
	// repository root, so that a call of that function is checked like the
	// call it makes. It grows until no function adds a parameter.
	pathParams := map[string]map[int]string{}
	var problems []string
	for {
		problems = nil
		grew := false
		for _, fn := range funcs {
			problems = append(problems, functionProblems(fset, fn, packageBindings, pathParams, rules, &grew)...)
		}
		if !grew {
			break
		}
	}
	sort.SliceStable(problems, func(i, j int) bool { return lineOrder(problems[i]) < lineOrder(problems[j]) })
	return problems
}

// Kinds of path argument: a file-system path, a command argument, or a
// path that is resolved against the repository root.
const (
	pathArgument     = "path"
	commandArgument  = "command"
	anchoredArgument = "anchored"
)

// anchoredCalls are the calls whose argument at the given index is
// resolved against the repository root.
var anchoredCalls = map[string]int{"testutil.Path": 0, "testutil.Read": 1}

// pathRules are what the check knows about one package's directory.
type pathRules struct {
	// isRepoRelative reports whether a path argument is written relative
	// to the repository root, and isRepoRelativeArgument the same for a
	// command argument.
	isRepoRelative, isRepoRelativeArgument func(string) bool
	// missingAtRoot reports whether a path resolved against the
	// repository root starts with a name that the root does not hold.
	missingAtRoot func(string) bool
	// isRoot reports whether an expression is the repository root.
	isRoot func(ast.Expr) bool
}

func functionProblems(fset *token.FileSet, fn *ast.FuncDecl, packageBindings map[string][]ast.Expr, pathParams map[string]map[int]string, rules pathRules, grew *bool) []string {
	var problems []string
	report := func(pos token.Pos, format string, args ...any) {
		p := fset.Position(pos)
		problems = append(problems, fmt.Sprintf("%s:%d: %s", filepath.Base(p.Filename), p.Line, fmt.Sprintf(format, args...)))
	}
	params := map[string]int{}
	index := 0
	for _, field := range fn.Type.Params.List {
		if len(field.Names) == 0 {
			index++
			continue
		}
		for _, name := range field.Names {
			params[name.Name] = index
			index++
		}
	}
	bindings := functionBindings(fn.Body)
	lookup := func(name string) []ast.Expr {
		return append(append([]ast.Expr{}, bindings[name]...), packageBindings[name]...)
	}
	markParams := func(expr ast.Expr, kind string) {
		for _, param := range reachedParams(expr, params, bindings, 0) {
			if fn.Recv != nil {
				continue
			}
			if pathParams[fn.Name.Name] == nil {
				pathParams[fn.Name.Name] = map[int]string{}
			}
			if _, ok := pathParams[fn.Name.Name][param]; !ok {
				pathParams[fn.Name.Name][param] = kind
				*grew = true
			}
		}
	}
	check := func(call *ast.CallExpr, name string, arg ast.Expr, kind string) {
		relative, format := rules.isRepoRelative, "%s gets the repository-relative path %q"
		switch kind {
		case commandArgument:
			relative = rules.isRepoRelativeArgument
		case anchoredArgument:
			relative, format = rules.missingAtRoot, "%s resolves %q against the repository root, which holds no such name"
		}
		for _, value := range leadingValues(arg, lookup, 0) {
			if relative(value) {
				report(call.Pos(), format, name, value)
				break
			}
		}
		markParams(arg, kind)
	}
	dirSet := dirAssignments(fn.Body)
	var stack []ast.Node
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := callName(call)
		if workingDirectoryCalls[name] || isMethodCall(call, "Chdir") {
			report(call.Pos(), "%s changes or reads the working directory", displayName(call, name))
			return true
		}
		for _, index := range pathCalls[name] {
			if index < len(call.Args) {
				check(call, name, call.Args[index], pathArgument)
			}
		}
		if index, ok := anchoredCalls[name]; ok && index < len(call.Args) {
			check(call, name, call.Args[index], anchoredArgument)
		}
		if (name == "filepath.Join" || name == "path.Join") && len(call.Args) > 1 && rules.isRoot(call.Args[0]) {
			check(call, name, call.Args[1], anchoredArgument)
		}
		if name == "exec.Command" || name == "exec.CommandContext" {
			args := call.Args
			if name == "exec.CommandContext" && len(args) > 0 {
				args = args[1:]
			}
			for _, arg := range args {
				check(call, name, arg, commandArgument)
			}
			if variable := assignedVariable(stack); variable == "" || !dirSet[variable] {
				report(call.Pos(), "%s is not assigned to a variable whose Dir is set", name)
			}
		}
		if ident, ok := call.Fun.(*ast.Ident); ok {
			for param, kind := range pathParams[ident.Name] {
				if param < len(call.Args) {
					check(call, ident.Name, call.Args[param], kind)
				}
			}
		}
		return true
	})
	return problems
}

// reachedParams returns the parameters an expression is built from, as far
// as leadingValues follows expressions.
func reachedParams(expr ast.Expr, params map[string]int, bindings map[string][]ast.Expr, depth int) []int {
	if depth > 12 || expr == nil {
		return nil
	}
	switch e := expr.(type) {
	case *ast.ParenExpr:
		return reachedParams(e.X, params, bindings, depth+1)
	case *ast.BinaryExpr:
		if e.Op == token.ADD {
			return reachedParams(e.X, params, bindings, depth+1)
		}
	case *ast.CallExpr:
		if name := callName(e); (name == "filepath.Join" || name == "path.Join") && len(e.Args) > 0 {
			return reachedParams(e.Args[0], params, bindings, depth+1)
		}
		if name := callName(e); name == "filepath.Abs" || name == "filepath.Clean" {
			return reachedParams(e.Args[0], params, bindings, depth+1)
		}
	case *ast.Ident:
		var reached []int
		if index, ok := params[e.Name]; ok {
			reached = append(reached, index)
		}
		for _, bound := range bindings[e.Name] {
			reached = append(reached, reachedParams(bound, params, bindings, depth+1)...)
		}
		return reached
	}
	return nil
}

// isTestutilRoot reports whether an expression is testutil.Root.
func isTestutilRoot(expr ast.Expr) bool {
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := selector.X.(*ast.Ident)
	return ok && pkg.Name == "testutil" && selector.Sel.Name == "Root"
}

// missingAtRoot reports whether a relative path starts with a name, or a
// pattern, that matches nothing at the repository root. Such a path named
// from a test outside the root usually names a file of the test's own
// directory, or one that moved.
func missingAtRoot(value string) bool {
	if value == "" || filepath.IsAbs(value) {
		return false
	}
	first := strings.SplitN(strings.TrimPrefix(value, "./"), "/", 2)[0]
	if first == "" || first == "." || first == ".." {
		return false
	}
	if strings.ContainsAny(first, "*?[") {
		matches, err := filepath.Glob(filepath.Join(testutil.Root, first))
		return err == nil && len(matches) == 0
	}
	_, err := os.Lstat(filepath.Join(testutil.Root, first))
	return os.IsNotExist(err)
}

// isDirectoryName reports whether a top-level name is one of the
// repository's directories. A bare directory name such as "es" is a common
// command argument that names no path, so only file names count when an
// argument is a single element.
func isDirectoryName(name string) bool {
	info, err := os.Stat(testutil.Path(name))
	return err == nil && info.IsDir()
}

func lineOrder(problem string) string {
	parts := strings.SplitN(problem, ":", 3)
	if len(parts) < 2 {
		return problem
	}
	line, _ := strconv.Atoi(parts[1])
	return fmt.Sprintf("%s:%08d", parts[0], line)
}

func callName(call *ast.CallExpr) string {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	pkg, ok := selector.X.(*ast.Ident)
	if !ok {
		return ""
	}
	return pkg.Name + "." + selector.Sel.Name
}

func isMethodCall(call *ast.CallExpr, method string) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	return ok && selector.Sel.Name == method
}

func displayName(call *ast.CallExpr, name string) string {
	if name == "os.Chdir" || name == "os.Getwd" {
		return name
	}
	return "Chdir"
}

// bindSpecs records the values of const and var specs.
func bindSpecs(gen *ast.GenDecl, bindings map[string][]ast.Expr) {
	if gen.Tok != token.CONST && gen.Tok != token.VAR {
		return
	}
	for _, spec := range gen.Specs {
		value, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for i, name := range value.Names {
			if i < len(value.Values) {
				bindings[name.Name] = append(bindings[name.Name], value.Values[i])
			}
		}
	}
}

// functionBindings records what each name in a function body can hold:
// constants, variables, assignments, and the keys and values of range
// loops over literal maps and slices. Names are not scoped, so a name
// collects every value given to it anywhere in the body; the check can then
// only report too much, never too little.
func functionBindings(body *ast.BlockStmt) map[string][]ast.Expr {
	bindings := map[string][]ast.Expr{}
	bind := func(lhs ast.Expr, value ast.Expr) {
		if ident, ok := lhs.(*ast.Ident); ok && ident.Name != "_" && value != nil {
			bindings[ident.Name] = append(bindings[ident.Name], value)
		}
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.DeclStmt:
			if gen, ok := n.Decl.(*ast.GenDecl); ok {
				bindSpecs(gen, bindings)
			}
		case *ast.AssignStmt:
			if len(n.Lhs) == len(n.Rhs) {
				for i := range n.Lhs {
					bind(n.Lhs[i], n.Rhs[i])
				}
			}
		case *ast.RangeStmt:
			bind(n.Key, &rangeKeys{n.X})
			bind(n.Value, &rangeValues{n.X})
		}
		return true
	})
	return bindings
}

// rangeKeys and rangeValues stand for the keys and the values of a range
// loop's collection.
type rangeKeys struct{ ast.Expr }
type rangeValues struct{ ast.Expr }

// leadingValues returns the string values an expression can start with, as
// far as literals, constants, variables, string concatenation, path joins
// and range loops over literals show them. repoPath and other calls give
// nothing, which is what makes them the way to name a repository path.
func leadingValues(expr ast.Expr, lookup func(string) []ast.Expr, depth int) []string {
	if depth > 12 || expr == nil {
		return nil
	}
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			if value, err := strconv.Unquote(e.Value); err == nil {
				return []string{value}
			}
		}
	case *ast.ParenExpr:
		return leadingValues(e.X, lookup, depth+1)
	case *ast.BinaryExpr:
		if e.Op == token.ADD {
			return leadingValues(e.X, lookup, depth+1)
		}
	case *ast.Ident:
		var values []string
		for _, bound := range lookup(e.Name) {
			values = append(values, leadingValues(bound, lookup, depth+1)...)
		}
		return values
	case *ast.CallExpr:
		if name := callName(e); (name == "filepath.Join" || name == "path.Join") && len(e.Args) > 0 {
			return leadingValues(e.Args[0], lookup, depth+1)
		}
	case *ast.SelectorExpr:
		if x, ok := e.X.(*ast.Ident); ok {
			var values []string
			for _, bound := range lookup(x.Name) {
				values = append(values, fieldValues(bound, e.Sel.Name, lookup, depth+1)...)
			}
			return values
		}
	case *rangeKeys:
		return collectionValues(e.Expr, lookup, depth+1, true)
	case *rangeValues:
		return collectionValues(e.Expr, lookup, depth+1, false)
	}
	return nil
}

// fieldValues returns the string values that the field of a struct value
// can start with, where the struct value is a keyed composite literal, a
// pointer to one, or an element of a range loop over a literal collection
// of them.
func fieldValues(expr ast.Expr, field string, lookup func(string) []ast.Expr, depth int) []string {
	if depth > 12 || expr == nil {
		return nil
	}
	switch e := expr.(type) {
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			return fieldValues(e.X, field, lookup, depth+1)
		}
	case *ast.Ident:
		var values []string
		for _, bound := range lookup(e.Name) {
			values = append(values, fieldValues(bound, field, lookup, depth+1)...)
		}
		return values
	case *ast.CompositeLit:
		var values []string
		for _, element := range e.Elts {
			if pair, ok := element.(*ast.KeyValueExpr); ok {
				if key, ok := pair.Key.(*ast.Ident); ok && key.Name == field {
					values = append(values, leadingValues(pair.Value, lookup, depth+1)...)
				}
			}
		}
		return values
	case *rangeValues:
		var values []string
		for _, element := range collectionElements(e.Expr, lookup, depth+1) {
			values = append(values, fieldValues(element, field, lookup, depth+1)...)
		}
		return values
	}
	return nil
}

// collectionElements returns the elements of a literal slice, array or map
// (its values), following names to their literals.
func collectionElements(expr ast.Expr, lookup func(string) []ast.Expr, depth int) []ast.Expr {
	if depth > 12 {
		return nil
	}
	switch e := expr.(type) {
	case *ast.Ident:
		var elements []ast.Expr
		for _, bound := range lookup(e.Name) {
			elements = append(elements, collectionElements(bound, lookup, depth+1)...)
		}
		return elements
	case *ast.CompositeLit:
		var elements []ast.Expr
		for _, element := range e.Elts {
			if pair, ok := element.(*ast.KeyValueExpr); ok {
				element = pair.Value
			}
			elements = append(elements, element)
		}
		return elements
	}
	return nil
}

func collectionValues(expr ast.Expr, lookup func(string) []ast.Expr, depth int, keys bool) []string {
	if depth > 12 {
		return nil
	}
	switch e := expr.(type) {
	case *ast.Ident:
		var values []string
		for _, bound := range lookup(e.Name) {
			values = append(values, collectionValues(bound, lookup, depth+1, keys)...)
		}
		return values
	case *ast.CompositeLit:
		var values []string
		for _, element := range e.Elts {
			if pair, ok := element.(*ast.KeyValueExpr); ok {
				if _, isMap := e.Type.(*ast.MapType); isMap {
					if keys {
						values = append(values, leadingValues(pair.Key, lookup, depth+1)...)
					} else {
						values = append(values, leadingValues(pair.Value, lookup, depth+1)...)
					}
				}
				continue
			}
			if !keys {
				values = append(values, leadingValues(element, lookup, depth+1)...)
			}
		}
		return values
	}
	return nil
}

// dirAssignments returns the names of variables whose Dir field the body
// sets.
func dirAssignments(body *ast.BlockStmt) map[string]bool {
	set := map[string]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, lhs := range assign.Lhs {
			if selector, ok := lhs.(*ast.SelectorExpr); ok && selector.Sel.Name == "Dir" {
				if ident, ok := selector.X.(*ast.Ident); ok {
					set[ident.Name] = true
				}
			}
		}
		return true
	})
	return set
}

// assignedVariable returns the variable that the innermost call on the
// stack is assigned to, or "".
func assignedVariable(stack []ast.Node) string {
	if len(stack) < 2 {
		return ""
	}
	call := stack[len(stack)-1]
	switch parent := stack[len(stack)-2].(type) {
	case *ast.AssignStmt:
		for i, rhs := range parent.Rhs {
			if rhs == call && i < len(parent.Lhs) {
				if ident, ok := parent.Lhs[i].(*ast.Ident); ok {
					return ident.Name
				}
			}
		}
	case *ast.ValueSpec:
		for i, value := range parent.Values {
			if value == call && i < len(parent.Names) {
				return parent.Names[i].Name
			}
		}
	}
	return ""
}
