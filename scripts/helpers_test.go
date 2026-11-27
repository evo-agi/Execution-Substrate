package scripts_test

import (
	"path/filepath"
	"runtime"
	"testing"

	"execution-substrate/internal/testutil"
)

// go test runs these tests in this directory, not at the repository root.
// They name repository files through the helpers below, which resolve a
// relative path against the repository root, and the commands they start
// run at the repository root. See package testutil.

// executionSubstrateRepoRoot is the absolute path of the repository root.
var executionSubstrateRepoRoot = testutil.Root

func remoteAlphaOperatorRepoRoot() string {
	return testutil.Root
}

// testPackageDir is the absolute path of this directory, which holds the
// test sources that some tests read.
var testPackageDir = mustTestPackageDir()

func mustTestPackageDir() string {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok || !filepath.IsAbs(sourceFile) {
		panic("cannot resolve an absolute path for the scripts test sources")
	}
	return filepath.Dir(sourceFile)
}

// repoPath returns an absolute path. A relative path names a file of the
// repository.
func repoPath(path string) string {
	return testutil.Path(path)
}

// standingRouteRulesPath holds the Remote Alpha operator route rules (P0i
// to P0v) that moved out of PLANS.md unreworded. They keep PLANS.md's rank
// in the AGENTS.md authority hierarchy. Checks of those rules read it.
const standingRouteRulesPath = ".docs/standing_rules/remote_alpha_operator_routes.md"

// standingHostRuntimePath holds the host and runtime boundary slice rules,
// among them the Remote Alpha host network boundary slice, which moved out
// of PLANS.md the same way. Its last section is that slice.
const standingHostRuntimePath = ".docs/standing_rules/host_and_runtime_boundary.md"

// mustRead, compactText, docSection, compactDocSection, assertContainsAll
// and assertContainsNone are the helpers of package testutil, under the
// names these tests use. The tests at the repository root use them too.

func mustRead(t *testing.T, path string) string {
	t.Helper()
	return testutil.Read(t, path)
}

func compactText(text string) string {
	return testutil.Compact(text)
}

func docSection(t *testing.T, doc string, start string, end string) string {
	t.Helper()
	return testutil.Section(t, doc, start, end)
}

func compactDocSection(t *testing.T, doc string, start string, end string) string {
	t.Helper()
	return testutil.CompactSection(t, doc, start, end)
}

func assertContainsAll(t *testing.T, label string, text string, required ...string) {
	t.Helper()
	testutil.ContainsAll(t, label, text, required...)
}

func assertContainsNone(t *testing.T, label string, text string, forbidden ...string) {
	t.Helper()
	testutil.ContainsNone(t, label, text, forbidden...)
}
