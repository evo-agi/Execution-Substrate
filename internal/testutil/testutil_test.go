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
// directory that is not relative. A relative path that slipped through
// would name a missing file below the package directory: a read would fail
// loudly, but a check that a file does not exist, a glob or a directory
// walk would pass without checking anything. So a path that the working
// directory resolves has to name, in full, something the package directory
// holds. The working directory is never changed or read.
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
		for _, problem := range repoPathProblems(fset, parsed, packageLayout(t, dir)) {
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
// the rule. It runs on a repository root and package directory of its own.
func TestRepoPathCheckFindsEachKindOfProblem(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{
		"PLANS.md",
		"docs_contract_test.go",
		".codex/config/x.toml",
		"es/admission/a.go",
		"internal/callerauth/callerauth.go",
		"scripts/x.sh",
		"scripts/own.sh",
		"scripts/testdata/own.txt",
		"scripts/internal/own.sh",
	} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	paths := &layout{root: root, dir: filepath.Join(root, "scripts")}
	const bad = `package p

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const retired = "scripts/retired.sh"

var removed = map[string]string{".codex/hooks": "removed"}

func f(t *testing.T, unknown string) {
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
	here := exec.Command("/bin/true")
	here.Dir = "."
	empty := exec.Command("/bin/true")
	empty.Dir = ""
	runIn(".")
	(&exec.Cmd{Path: "/bin/true"}).Run()
	sub := &exec.Cmd{Path: "/bin/true", Dir: "sub/" + unknown}
	sub.Run()
	os.Stat("internal/callerauth/callerauth.go")
	os.Stat(filepath.Join("internal", "callerauth", "callerauth.go"))
	os.ReadDir(filepath.Join("internal", unknown))
	statUnder("internal")
	os.Stat("internal/missing.sh")
	os.Stat("nothing/here")
	os.ReadDir(filepath.Join("nothing", unknown))
	os.ReadFile("../PLANS.md")
	exec.Command("bash", filepath.Join("scripts", unknown))
	stat := os.Stat
	stat("PLANS.md")
	reader := read
	reader(t, "PLANS.md")
	chdir := t.Chdir
	chdir("/")
}

func read(t *testing.T, name string) {
	os.ReadFile(name)
}

type route struct{ path string }

var routes = []route{{path: "scripts/a.sh"}}

var root = testutil.Root

func runIn(dir string) {
	c := exec.Command("/bin/true")
	c.Dir = dir
	c.Run()
}

func statUnder(dir string) {
	os.Stat(filepath.Join(dir, "own.sh"))
}

var remove = os.RemoveAll
`
	const renamed = `package p

import (
	fp "path/filepath"
	. "os"
)

func h() {
	fp.Glob("es/*.go")
	ReadFile("PLANS.md")
}
`
	const good = `package p

import (
	"os"
	"os/exec"
	"path/filepath"
)

const script = "scripts/x.sh"

func g(dir string, name string) {
	os.ReadFile(repoPath("PLANS.md"))
	os.Stat(repoPath(script))
	filepath.Glob(filepath.Join(repoRoot, "es/admission/*.go"))
	os.ReadFile(filepath.Join(dir, "scripts", "x.sh"))
	os.ReadFile("/etc/hostname")
	os.ReadFile("testdata/own.txt")
	os.ReadFile(filepath.Join("testdata", name))
	os.ReadFile("own.sh")
	os.ReadFile("./internal/own.sh")
	filepath.Glob("*.sh")
	os.MkdirTemp("", "x")
	os.Stat(dir)
	os.Symlink("scripts/relative-target", filepath.Join(dir, "link"))
	cmd := exec.Command("/bin/bash", repoPath(script), "es")
	cmd.Dir = repoRoot
	cmd.Run()
	work := exec.Command("/bin/true")
	work.Dir = filepath.Join(dir, "work")
	work.Run()
	built := &exec.Cmd{Path: "/bin/true", Dir: repoRoot}
	built.Run()
	later := &exec.Cmd{Path: "/bin/true"}
	later.Dir = dir
	later.Run()
	filepath.Join(testutil.Root, "scripts", "x.sh")
	filepath.Join(rootDir(), "*_test.go")
	testutil.Path("PLANS.md")
	readOwn("own.sh")
	for _, own := range []string{"own.sh", "testdata/own.txt"} {
		os.Stat(own)
	}
}

func rootDir() string { return testutil.Root }

func readOwn(name string) {
	os.ReadFile(name)
}
`
	fset := token.NewFileSet()
	parse := func(name, source string) *ast.File {
		file, err := parser.ParseFile(fset, name, source, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		return file
	}
	problems := repoPathProblems(fset, []*ast.File{parse("bad.go", bad), parse("renamed.go", renamed)}, paths)
	want := []string{
		`bad.go:15: os.ReadFile gets the repository-relative path "PLANS.md"`,
		`bad.go:16: os.Stat gets the repository-relative path "scripts/retired.sh"`,
		`bad.go:17: filepath.Glob gets the repository-relative path "es/admission/*.go"`,
		`bad.go:18: filepath.WalkDir gets the repository-relative path "."`,
		`bad.go:19: os.ReadDir gets the repository-relative path "scripts/internal"`,
		`bad.go:20: os.Lstat gets the repository-relative path "scripts/x.sh"`,
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
		`bad.go:47: here.Dir gets the relative working directory "."`,
		`bad.go:49: empty.Dir gets the relative working directory ""`,
		`bad.go:50: runIn gets the relative working directory "."`,
		`bad.go:51: exec.Cmd is built without a Dir and is not assigned to a variable whose Dir is set`,
		`bad.go:52: exec.Cmd gets a relative working directory starting "sub/"`,
		`bad.go:54: os.Stat gets the path "internal/callerauth/callerauth.go", which the package directory does not hold but the repository root does`,
		`bad.go:55: os.Stat gets the path "internal/callerauth/callerauth.go", which the package directory does not hold but the repository root does`,
		`bad.go:56: os.ReadDir gets a path starting "internal/", which both the package directory and the repository root hold`,
		`bad.go:57: statUnder gets a path starting "internal/", which both the package directory and the repository root hold`,
		`bad.go:58: os.Stat gets the path "internal/missing.sh", which neither the package directory nor the repository root holds`,
		`bad.go:59: os.Stat gets the path "nothing/here", which neither the package directory nor the repository root holds`,
		`bad.go:60: os.ReadDir gets a path starting "nothing/", which neither the package directory nor the repository root holds`,
		`bad.go:61: os.ReadFile gets the path "../PLANS.md", which climbs out of the package directory`,
		`bad.go:62: exec.Command gets the repository-relative path "scripts/"`,
		`bad.go:62: exec.Command is not assigned to a variable whose Dir is set`,
		`bad.go:63: os.Stat is used as a value, so the check cannot see the arguments it gets`,
		`bad.go:65: read is used as a value, so the check cannot see the arguments it gets`,
		`bad.go:67: Chdir is used as a value, so the check cannot see the arguments it gets`,
		`bad.go:91: os.RemoveAll is used as a value, so the check cannot see the arguments it gets`,
		`renamed.go:4: imports path/filepath as fp, which the check does not follow`,
		`renamed.go:5: imports os as ., which the check does not follow`,
	}
	if strings.Join(problems, "\n") != strings.Join(want, "\n") {
		t.Errorf("problems in bad.go and renamed.go:\n%s\nwant:\n%s", strings.Join(problems, "\n"), strings.Join(want, "\n"))
	}
	if problems := repoPathProblems(fset, []*ast.File{parse("good.go", good)}, paths); len(problems) != 0 {
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

// layout is where the paths of one package resolve: the repository root,
// and the package directory, which go test makes the working directory of
// the package's tests.
type layout struct {
	root, dir string
	seen      map[string]bool
}

// packageLayout returns the layout of a package directory, after checking
// that the repository root holds names that the package directory does
// not, so that the check has something to find.
func packageLayout(t *testing.T, dir string) *layout {
	t.Helper()
	paths := &layout{root: testutil.Root, dir: dir}
	for _, name := range []string{"AGENTS.md", "PLANS.md", "go.mod", "scripts", ".docs", "es"} {
		if !paths.rootOnly(name) {
			t.Fatalf("repository root %q has no %s, or %s holds one too", testutil.Root, name, dir)
		}
	}
	return paths
}

// holds reports whether base holds a relative path, or a match of it when
// it is a pattern.
func (l *layout) holds(base, rel string) bool {
	key := base + "\x00" + rel
	if held, ok := l.seen[key]; ok {
		return held
	}
	var held bool
	if strings.ContainsAny(rel, "*?[") {
		matches, err := filepath.Glob(filepath.Join(base, rel))
		held = err == nil && len(matches) > 0
	} else {
		_, err := os.Lstat(filepath.Join(base, rel))
		held = err == nil
	}
	if l.seen == nil {
		l.seen = map[string]bool{}
	}
	l.seen[key] = held
	return held
}

func (l *layout) atRoot(rel string) bool    { return l.holds(l.root, rel) }
func (l *layout) inPackage(rel string) bool { return l.holds(l.dir, rel) }

// rootOnly reports whether a name is at the repository root and not in the
// package directory. A relative path that starts with such a name is taken
// as written relative to the repository root.
func (l *layout) rootOnly(name string) bool { return l.atRoot(name) && !l.inPackage(name) }

// isRootDirectory reports whether a top-level name is one of the
// repository's directories. A bare directory name such as "es" is a common
// command argument that names no path, so only file names count when an
// argument is a single element.
func (l *layout) isRootDirectory(name string) bool {
	info, err := os.Stat(filepath.Join(l.root, name))
	return err == nil && info.IsDir()
}

// knownElements returns the part of a value whose path elements are known
// in full: all of a whole value, and up to the last "/" of a value that
// goes on.
func knownElements(v pathValue) (string, bool) {
	if !v.partial {
		return v.text, true
	}
	if i := strings.LastIndex(v.text, "/"); i >= 0 {
		return v.text[:i+1], true
	}
	return "", false
}

func firstElement(path string) string {
	return strings.SplitN(filepath.ToSlash(filepath.Clean(path)), "/", 2)[0]
}

// pathProblem checks a path that the working directory resolves.
func (l *layout) pathProblem(v pathValue) string {
	if v.text == "" || filepath.IsAbs(v.text) {
		return ""
	}
	known, ok := knownElements(v)
	if !ok {
		// Not even the first element is known in full. Report what the
		// value starts with when that is a name the root alone holds.
		if v.text == "." || l.rootOnly(v.text) {
			return fmt.Sprintf("gets the repository-relative path %q", v.text)
		}
		return ""
	}
	first := firstElement(known)
	switch {
	case first == "." || l.rootOnly(first):
		return fmt.Sprintf("gets the repository-relative path %q", v.text)
	case first == "..":
		return fmt.Sprintf("gets the path %q, which climbs out of the package directory", v.text)
	case !v.partial:
		path := filepath.Clean(v.text)
		switch {
		case l.inPackage(path):
			return ""
		case l.atRoot(path):
			return fmt.Sprintf("gets the path %q, which the package directory does not hold but the repository root does", v.text)
		}
		return fmt.Sprintf("gets the path %q, which neither the package directory nor the repository root holds", v.text)
	case !l.inPackage(first):
		return fmt.Sprintf("gets a path starting %q, which neither the package directory nor the repository root holds", v.text)
	case l.atRoot(first):
		return fmt.Sprintf("gets a path starting %q, which both the package directory and the repository root hold", v.text)
	}
	return ""
}

// commandProblem checks a command argument. It counts as a repository path
// when it has a "/" or names a file at the root. A bare directory name such
// as "es" is a common argument that names no path.
func (l *layout) commandProblem(v pathValue) string {
	text := v.text
	if text == "" || filepath.IsAbs(text) {
		return ""
	}
	first := firstElement(text)
	if strings.ContainsAny(first, "*?[") {
		return ""
	}
	repoRelative := strings.Contains(text, "/") && (first == "." || l.rootOnly(first)) ||
		!v.partial && l.rootOnly(text) && !l.isRootDirectory(text)
	if repoRelative {
		return fmt.Sprintf("gets the repository-relative path %q", text)
	}
	return ""
}

// anchoredProblem checks a path that is resolved against the repository
// root: one whose first element, or the start of it, matches nothing at
// the root usually names a file of the test's own directory, or one that
// moved.
func (l *layout) anchoredProblem(v pathValue) string {
	if v.text == "" || filepath.IsAbs(v.text) {
		return ""
	}
	missing := func() bool {
		known, ok := knownElements(v)
		if !ok {
			return !l.atRoot(v.text + "*")
		}
		first := firstElement(known)
		return first != "." && first != ".." && !l.atRoot(first)
	}
	if missing() {
		return fmt.Sprintf("resolves %q against the repository root, which holds no such name", v.text)
	}
	return ""
}

// dirProblem checks the working directory of a command: a relative one,
// including "" and ".", is the package directory, while every command
// these tests start runs at the repository root or in a directory of its
// own.
func dirProblem(v pathValue) string {
	switch {
	case filepath.IsAbs(v.text):
		return ""
	case !v.partial:
		return fmt.Sprintf("gets the relative working directory %q", v.text)
	case v.text != "":
		return fmt.Sprintf("gets a relative working directory starting %q", v.text)
	}
	return ""
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

// anchoredCalls are the calls whose argument at the given index is
// resolved against the repository root.
var anchoredCalls = map[string]int{"testutil.Path": 0, "testutil.Read": 1}

// isCoveredCall reports whether the check reads the arguments of calls of
// a package function.
func isCoveredCall(name string) bool {
	_, path := pathCalls[name]
	_, anchored := anchoredCalls[name]
	return path || anchored || workingDirectoryCalls[name] ||
		name == "exec.Command" || name == "exec.CommandContext" || name == "filepath.Join" || name == "path.Join"
}

// followedImports are the packages whose functions the check knows by the
// name the package is imported under, which is its own.
var followedImports = map[string]string{
	"os":                                    "os",
	"os/exec":                               "exec",
	"path":                                  "path",
	"path/filepath":                         "filepath",
	"execution-substrate/internal/testutil": "testutil",
}

func repoPathProblems(fset *token.FileSet, files []*ast.File, paths *layout) []string {
	var problems []string
	report := func(pos token.Pos, format string, args ...any) {
		p := fset.Position(pos)
		problems = append(problems, fmt.Sprintf("%s:%d: %s", filepath.Base(p.Filename), p.Line, fmt.Sprintf(format, args...)))
	}
	// Values of package-level constants and variables, by name.
	packageBindings := map[string][]ast.Expr{}
	var funcs []*ast.FuncDecl
	for _, file := range files {
		for _, spec := range file.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if name, followed := followedImports[path]; err == nil && followed && spec.Name != nil && spec.Name.Name != name && spec.Name.Name != "_" {
				report(spec.Pos(), "imports %s as %s, which the check does not follow", path, spec.Name.Name)
			}
		}
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
		problem: map[string]func(pathValue) string{
			pathArgument:     paths.pathProblem,
			commandArgument:  paths.commandProblem,
			anchoredArgument: paths.anchoredProblem,
			dirArgument:      dirProblem,
		},
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
	// that reach a path, a command argument, a path anchored at the
	// repository root or a working directory, so that a call of that
	// function is checked like the call it makes. It grows until no
	// function adds a parameter.
	pathParams := map[string]map[int]map[paramUse]bool{}
	var functionProblemsFound []string
	for {
		functionProblemsFound = nil
		grew := false
		for _, fn := range funcs {
			functionProblemsFound = append(functionProblemsFound, functionProblems(fset, fn, packageBindings, pathParams, rules, &grew)...)
		}
		if !grew {
			break
		}
	}
	problems = append(problems, functionProblemsFound...)
	for _, file := range files {
		problems = append(problems, valueProblems(fset, file, pathParams)...)
	}
	sort.SliceStable(problems, func(i, j int) bool {
		if a, b := lineOrder(problems[i]), lineOrder(problems[j]); a != b {
			return a < b
		}
		return problems[i] < problems[j]
	})
	return slices.Compact(problems)
}

// Kinds of path argument: a file-system path, a command argument, a path
// that is resolved against the repository root, or a command's working
// directory.
const (
	pathArgument     = "path"
	commandArgument  = "command"
	anchoredArgument = "anchored"
	dirArgument      = "dir"
)

// pathRules are what the check knows about one package's directory.
type pathRules struct {
	// problem checks a value given as each kind of argument, and
	// describes what is wrong with it.
	problem map[string]func(pathValue) string
	// isRoot reports whether an expression is the repository root.
	isRoot func(ast.Expr) bool
}

// paramUse is how a parameter reaches a path: as which kind of argument,
// and with what after it. rest is "" when the parameter is the whole value,
// "/" when more path elements follow it, and "+" when more of its own last
// element follows it.
type paramUse struct{ kind, rest string }

func functionProblems(fset *token.FileSet, fn *ast.FuncDecl, packageBindings map[string][]ast.Expr, pathParams map[string]map[int]map[paramUse]bool, rules pathRules, grew *bool) []string {
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
	markParams := func(expr ast.Expr, kind, rest string) {
		if fn.Recv != nil {
			return
		}
		for _, reached := range reachedParams(expr, params, bindings, 0) {
			use := paramUse{kind: kind, rest: reached.rest}
			if use.rest == "" {
				use.rest = rest
			}
			if pathParams[fn.Name.Name] == nil {
				pathParams[fn.Name.Name] = map[int]map[paramUse]bool{}
			}
			if pathParams[fn.Name.Name][reached.index] == nil {
				pathParams[fn.Name.Name][reached.index] = map[paramUse]bool{}
			}
			if !pathParams[fn.Name.Name][reached.index][use] {
				pathParams[fn.Name.Name][reached.index][use] = true
				*grew = true
			}
		}
	}
	check := func(node ast.Node, name string, arg ast.Expr, kind, rest string) {
		for _, value := range continued(pathValues(arg, lookup, 0), rest) {
			if problem := rules.problem[kind](value); problem != "" {
				report(node.Pos(), "%s %s", name, problem)
				break
			}
		}
		markParams(arg, kind, rest)
	}
	dirSet := dirAssignments(fn.Body)
	var stack []ast.Node
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		switch n := n.(type) {
		case *ast.AssignStmt:
			if len(n.Lhs) == len(n.Rhs) {
				for i, lhs := range n.Lhs {
					if selector, ok := lhs.(*ast.SelectorExpr); ok && selector.Sel.Name == "Dir" {
						name := "Dir"
						if ident, ok := selector.X.(*ast.Ident); ok {
							name = ident.Name + ".Dir"
						}
						check(n, name, n.Rhs[i], dirArgument, "")
					}
				}
			}
			return true
		case *ast.CompositeLit:
			if !isExecCmd(n.Type) {
				return true
			}
			hasDir := false
			for _, element := range n.Elts {
				if pair, ok := element.(*ast.KeyValueExpr); ok {
					if key, ok := pair.Key.(*ast.Ident); ok && key.Name == "Dir" {
						hasDir = true
						check(n, "exec.Cmd", pair.Value, dirArgument, "")
					}
				}
			}
			if variable := assignedVariable(stack); !hasDir && (variable == "" || !dirSet[variable]) {
				report(n.Pos(), "exec.Cmd is built without a Dir and is not assigned to a variable whose Dir is set")
			}
			return true
		case *ast.CallExpr:
			call := n
			name := callName(call)
			if workingDirectoryCalls[name] || isMethodCall(call, "Chdir") {
				report(call.Pos(), "%s changes or reads the working directory", displayName(call, name))
				return true
			}
			for _, index := range pathCalls[name] {
				if index < len(call.Args) {
					check(call, name, call.Args[index], pathArgument, "")
				}
			}
			if index, ok := anchoredCalls[name]; ok && index < len(call.Args) {
				check(call, name, call.Args[index], anchoredArgument, "")
			}
			if (name == "filepath.Join" || name == "path.Join") && len(call.Args) > 1 && rules.isRoot(call.Args[0]) {
				check(call, name, call.Args[1], anchoredArgument, "")
			}
			if name == "exec.Command" || name == "exec.CommandContext" {
				args := call.Args
				if name == "exec.CommandContext" && len(args) > 0 {
					args = args[1:]
				}
				for _, arg := range args {
					check(call, name, arg, commandArgument, "")
				}
				if variable := assignedVariable(stack); variable == "" || !dirSet[variable] {
					report(call.Pos(), "%s is not assigned to a variable whose Dir is set", name)
				}
			}
			if ident, ok := call.Fun.(*ast.Ident); ok {
				for param, uses := range pathParams[ident.Name] {
					if param < len(call.Args) {
						for use := range uses {
							check(call, ident.Name, call.Args[param], use.kind, use.rest)
						}
					}
				}
			}
		}
		return true
	})
	return problems
}

// valueProblems reports the functions whose calls the check reads, and the
// package's functions whose parameters reach a path, where they are used
// as values instead of called: a call through such a value would be out of
// the check's sight.
func valueProblems(fset *token.FileSet, file *ast.File, pathParams map[string]map[int]map[paramUse]bool) []string {
	var problems []string
	report := func(pos token.Pos, name string) {
		p := fset.Position(pos)
		problems = append(problems, fmt.Sprintf("%s:%d: %s is used as a value, so the check cannot see the arguments it gets", filepath.Base(p.Filename), p.Line, name))
	}
	var stack []ast.Node
	var locals map[string]bool
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		if _, ok := n.(*ast.ImportSpec); ok {
			stack = stack[:len(stack)-1]
			return false
		}
		if fn, ok := n.(*ast.FuncDecl); ok {
			locals = localNames(fn)
		}
		if len(stack) < 2 {
			return true
		}
		parent := stack[len(stack)-2]
		if call, ok := parent.(*ast.CallExpr); ok && call.Fun == n {
			return true
		}
		switch n := n.(type) {
		case *ast.SelectorExpr:
			if pkg, ok := n.X.(*ast.Ident); ok && isCoveredCall(pkg.Name+"."+n.Sel.Name) {
				report(n.Pos(), pkg.Name+"."+n.Sel.Name)
			} else if n.Sel.Name == "Chdir" {
				report(n.Pos(), "Chdir")
			}
		case *ast.Ident:
			if pathParams[n.Name] == nil || locals[n.Name] {
				return true
			}
			switch parent := parent.(type) {
			case *ast.FuncDecl, *ast.Field, *ast.ValueSpec, *ast.LabeledStmt, *ast.BranchStmt, *ast.TypeSpec:
				return true
			case *ast.SelectorExpr:
				if parent.Sel == n {
					return true
				}
			case *ast.KeyValueExpr:
				if parent.Key == n {
					return true
				}
			case *ast.AssignStmt:
				if slices.Contains(parent.Lhs, ast.Expr(n)) {
					return true
				}
			}
			report(n.Pos(), n.Name)
		}
		return true
	})
	return problems
}

// localNames returns the names a function declares for itself: its
// parameters and results, those of the function literals in it, and the
// names its body binds.
func localNames(fn *ast.FuncDecl) map[string]bool {
	names := map[string]bool{}
	ast.Inspect(fn, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncDecl:
			return n == fn
		case *ast.Field:
			for _, name := range n.Names {
				names[name.Name] = true
			}
		case *ast.AssignStmt:
			if n.Tok == token.DEFINE {
				for _, lhs := range n.Lhs {
					if ident, ok := lhs.(*ast.Ident); ok {
						names[ident.Name] = true
					}
				}
			}
		case *ast.ValueSpec:
			for _, name := range n.Names {
				names[name.Name] = true
			}
		case *ast.RangeStmt:
			if n.Tok == token.DEFINE {
				for _, bound := range []ast.Expr{n.Key, n.Value} {
					if ident, ok := bound.(*ast.Ident); ok {
						names[ident.Name] = true
					}
				}
			}
		}
		return true
	})
	return names
}

func isExecCmd(expr ast.Expr) bool {
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := selector.X.(*ast.Ident)
	return ok && pkg.Name == "exec" && selector.Sel.Name == "Cmd"
}

// reachedParam is a parameter that an expression is built from, with what
// follows it in the expression (see paramUse).
type reachedParam struct {
	index int
	rest  string
}

// reachedParams returns the parameters an expression is built from, as far
// as pathValues follows expressions.
func reachedParams(expr ast.Expr, params map[string]int, bindings map[string][]ast.Expr, depth int) []reachedParam {
	if depth > 12 || expr == nil {
		return nil
	}
	followedBy := func(reached []reachedParam, rest string) []reachedParam {
		for i := range reached {
			if reached[i].rest == "" {
				reached[i].rest = rest
			}
		}
		return reached
	}
	switch e := expr.(type) {
	case *ast.ParenExpr:
		return reachedParams(e.X, params, bindings, depth+1)
	case *ast.BinaryExpr:
		if e.Op == token.ADD {
			return followedBy(reachedParams(e.X, params, bindings, depth+1), "+")
		}
	case *ast.CallExpr:
		if name := callName(e); (name == "filepath.Join" || name == "path.Join") && len(e.Args) > 0 {
			reached := reachedParams(e.Args[0], params, bindings, depth+1)
			if len(e.Args) > 1 {
				reached = followedBy(reached, "/")
			}
			return reached
		}
		if name := callName(e); (name == "filepath.Abs" || name == "filepath.Clean") && len(e.Args) > 0 {
			return reachedParams(e.Args[0], params, bindings, depth+1)
		}
	case *ast.Ident:
		var reached []reachedParam
		if index, ok := params[e.Name]; ok {
			reached = append(reached, reachedParam{index: index})
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

// pathValue is a string value that an expression can have. When partial,
// only its start is known: more follows text, as further path elements
// when text ends with "/".
type pathValue struct {
	text    string
	partial bool
}

// continued returns values as followed by more, as paramUse.rest says.
func continued(values []pathValue, rest string) []pathValue {
	if rest == "" {
		return values
	}
	out := make([]pathValue, 0, len(values))
	for _, v := range values {
		switch {
		case v.partial:
		case rest == "/" && v.text != "":
			v.text = strings.TrimSuffix(v.text, "/") + "/"
		}
		v.partial = true
		out = append(out, v)
	}
	return out
}

// maxValues bounds the values that a join or a concatenation combines.
// Past it, only the start of the value is kept.
const maxValues = 1024

// pathValues returns the string values an expression can have, as far as
// literals, constants, variables, string concatenation, path joins and
// range loops over literals show them. A value whose end is not known is
// partial. repoPath and other calls give nothing, which is what makes them
// the way to name a repository path.
func pathValues(expr ast.Expr, lookup func(string) []ast.Expr, depth int) []pathValue {
	if depth > 12 || expr == nil {
		return nil
	}
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			if value, err := strconv.Unquote(e.Value); err == nil {
				return []pathValue{{text: value}}
			}
		}
	case *ast.ParenExpr:
		return pathValues(e.X, lookup, depth+1)
	case *ast.BinaryExpr:
		if e.Op == token.ADD {
			left := pathValues(e.X, lookup, depth+1)
			right := pathValues(e.Y, lookup, depth+1)
			if len(right) == 0 || len(left)*len(right) > maxValues {
				return continued(left, "+")
			}
			var values []pathValue
			for _, l := range left {
				if l.partial {
					values = append(values, l)
					continue
				}
				for _, r := range right {
					values = append(values, pathValue{text: l.text + r.text, partial: r.partial})
				}
			}
			return values
		}
	case *ast.Ident:
		var values []pathValue
		for _, bound := range lookup(e.Name) {
			values = append(values, pathValues(bound, lookup, depth+1)...)
		}
		return values
	case *ast.CallExpr:
		if name := callName(e); (name == "filepath.Join" || name == "path.Join") && len(e.Args) > 0 && !e.Ellipsis.IsValid() {
			return joinValues(e.Args, lookup, depth+1)
		}
	case *ast.SelectorExpr:
		if x, ok := e.X.(*ast.Ident); ok {
			var values []pathValue
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

// joinValues returns the values of a path join, as filepath.Join gives
// them, as far as its arguments' values are known.
func joinValues(args []ast.Expr, lookup func(string) []ast.Expr, depth int) []pathValue {
	var done []pathValue
	joined := []pathValue{{}}
	for i, arg := range args {
		values := pathValues(arg, lookup, depth+1)
		switch {
		case i == 0 && len(values) == 0:
			return nil
		case i == 0 && len(values) > maxValues:
			if len(args) > 1 {
				return continued(values, "/")
			}
			return values
		case len(values) == 0 || len(joined)*len(values) > maxValues:
			return append(done, continued(joined, "/")...)
		}
		var next []pathValue
		for _, j := range joined {
			for _, v := range values {
				text := filepath.Join(j.text, v.text)
				if v.partial {
					// More follows: a further element when v ends one,
					// or when nothing of v is known.
					if (v.text == "" || strings.HasSuffix(v.text, "/")) && text != "" {
						text = strings.TrimSuffix(text, "/") + "/"
					}
					done = append(done, pathValue{text: text, partial: true})
					continue
				}
				next = append(next, pathValue{text: text})
			}
		}
		joined = next
	}
	return append(done, joined...)
}

// fieldValues returns the string values that the field of a struct value
// can have, where the struct value is a keyed composite literal, a pointer
// to one, or an element of a range loop over a literal collection of them.
func fieldValues(expr ast.Expr, field string, lookup func(string) []ast.Expr, depth int) []pathValue {
	if depth > 12 || expr == nil {
		return nil
	}
	switch e := expr.(type) {
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			return fieldValues(e.X, field, lookup, depth+1)
		}
	case *ast.Ident:
		var values []pathValue
		for _, bound := range lookup(e.Name) {
			values = append(values, fieldValues(bound, field, lookup, depth+1)...)
		}
		return values
	case *ast.CompositeLit:
		var values []pathValue
		for _, element := range e.Elts {
			if pair, ok := element.(*ast.KeyValueExpr); ok {
				if key, ok := pair.Key.(*ast.Ident); ok && key.Name == field {
					values = append(values, pathValues(pair.Value, lookup, depth+1)...)
				}
			}
		}
		return values
	case *rangeValues:
		var values []pathValue
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

func collectionValues(expr ast.Expr, lookup func(string) []ast.Expr, depth int, keys bool) []pathValue {
	if depth > 12 {
		return nil
	}
	switch e := expr.(type) {
	case *ast.Ident:
		var values []pathValue
		for _, bound := range lookup(e.Name) {
			values = append(values, collectionValues(bound, lookup, depth+1, keys)...)
		}
		return values
	case *ast.CompositeLit:
		var values []pathValue
		for _, element := range e.Elts {
			if pair, ok := element.(*ast.KeyValueExpr); ok {
				if _, isMap := e.Type.(*ast.MapType); isMap {
					if keys {
						values = append(values, pathValues(pair.Key, lookup, depth+1)...)
					} else {
						values = append(values, pathValues(pair.Value, lookup, depth+1)...)
					}
				}
				continue
			}
			if !keys {
				values = append(values, pathValues(element, lookup, depth+1)...)
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

// assignedVariable returns the variable that the innermost node on the
// stack, a call or a composite literal, possibly behind &, is assigned to,
// or "".
func assignedVariable(stack []ast.Node) string {
	if len(stack) < 2 {
		return ""
	}
	node := stack[len(stack)-1]
	parent := stack[len(stack)-2]
	if unary, ok := parent.(*ast.UnaryExpr); ok && unary.Op == token.AND && len(stack) >= 3 {
		node, parent = unary, stack[len(stack)-3]
	}
	switch parent := parent.(type) {
	case *ast.AssignStmt:
		for i, rhs := range parent.Rhs {
			if rhs == node && i < len(parent.Lhs) {
				if ident, ok := parent.Lhs[i].(*ast.Ident); ok {
					return ident.Name
				}
			}
		}
	case *ast.ValueSpec:
		for i, value := range parent.Values {
			if value == node && i < len(parent.Names) {
				return parent.Names[i].Name
			}
		}
	}
	return ""
}
