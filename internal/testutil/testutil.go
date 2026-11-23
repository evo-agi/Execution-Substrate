// Package testutil holds helpers that only tests use: the repository root,
// and reading and searching the repository's documents. Only test files
// import it, which a test of this package checks.
//
// go test runs the tests of a package in the package's directory. A test
// outside the repository root therefore names a repository file through
// Path or Read, which resolve a relative path against Root, and never by
// changing the working directory: the go test cache does not see a change
// of directory made while a test binary starts, so after a file changed it
// could replay a stale result. The tests of this package check that the
// packages which import it name no repository path relative to their own
// directory, and that the repository root keeps only its docs tests: the
// tests of the scripts live in scripts/.
package testutil

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Root is the absolute path of the repository root.
var Root = mustRoot()

func mustRoot() string {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok || sourceFile == "" || !filepath.IsAbs(sourceFile) {
		panic("testutil: cannot resolve an absolute path for its own source file")
	}
	root := filepath.Dir(filepath.Dir(filepath.Dir(sourceFile)))
	module, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		panic("testutil: repository root " + root + " has no readable go.mod: " + err.Error())
	}
	if !strings.HasPrefix(string(module), "module execution-substrate\n") {
		panic("testutil: " + filepath.Join(root, "go.mod") + " is not the go.mod of module execution-substrate")
	}
	return root
}

// Path returns an absolute path. A relative path names a file of the
// repository.
func Path(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(Root, path)
}

// Read returns the content of a file. A relative path names a file of the
// repository.
func Read(t testing.TB, path string) string {
	t.Helper()
	data, err := os.ReadFile(Path(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

// Compact joins the words of a text with single spaces.
func Compact(text string) string {
	return strings.Join(strings.Fields(text), " ")
}

// Section returns the part of a document that starts at the first start
// and ends before the next end. An empty end means the end of the
// document.
func Section(t testing.TB, doc string, start string, end string) string {
	t.Helper()

	startIndex := strings.Index(doc, start)
	if startIndex == -1 {
		t.Fatalf("document section start %q not found", start)
	}
	section := doc[startIndex:]
	if end == "" {
		return section
	}
	endIndex := strings.Index(section, end)
	if endIndex == -1 {
		t.Fatalf("document section end %q not found after %q", end, start)
	}
	return section[:endIndex]
}

// CompactSection is Section followed by Compact.
func CompactSection(t testing.TB, doc string, start string, end string) string {
	t.Helper()
	return Compact(Section(t, doc, start, end))
}

// ContainsAll fails the test when text lacks any of the required phrases.
func ContainsAll(t testing.TB, label string, text string, required ...string) {
	t.Helper()

	for _, phrase := range required {
		if !strings.Contains(text, phrase) {
			t.Fatalf("%s missing %q", label, phrase)
		}
	}
}

// ContainsNone fails the test when text holds any of the forbidden phrases.
func ContainsNone(t testing.TB, label string, text string, forbidden ...string) {
	t.Helper()

	for _, phrase := range forbidden {
		if strings.Contains(text, phrase) {
			t.Fatalf("%s must not contain %q", label, phrase)
		}
	}
}
