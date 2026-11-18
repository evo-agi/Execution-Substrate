package admission

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestQualifiedExecutionRootsAcceptSamePresentationSiblings(t *testing.T) {
	parent := physicalTestTempDir(t)
	staging := filepath.Join(parent, "staging")
	results := filepath.Join(parent, "results")
	for _, root := range []string{staging, results} {
		if err := os.Mkdir(root, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	roots, err := qualifyExecutionRoots(staging, results, nil)
	if err != nil {
		t.Fatalf("same-presentation siblings were rejected: %v", err)
	}
	defer roots.close()
	if !roots.staging.observed() || !roots.results.observed() {
		t.Fatal("existing sibling roots were recorded as missing intent")
	}
}

func TestQualifiedExecutionRootsRejectEqualAndVisibleAncestorRoots(t *testing.T) {
	root := physicalTestTempDir(t)
	if roots, err := qualifyExecutionRoots(root, root, nil); err == nil {
		_ = roots.close()
		t.Fatal("equal roots were accepted")
	}
	child := filepath.Join(root, "child")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	if roots, err := qualifyExecutionRoots(root, child, nil); err == nil {
		_ = roots.close()
		t.Fatal("staging ancestor of results was accepted")
	}
	if roots, err := qualifyExecutionRoots(child, root, nil); err == nil {
		_ = roots.close()
		t.Fatal("results ancestor of staging was accepted")
	}
}

func TestQualifiedExecutionRootsSeparatesObservedObjectsFromMissingIntent(t *testing.T) {
	parent := physicalTestTempDir(t)
	results := filepath.Join(parent, "results")
	if err := os.Mkdir(results, 0o755); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(parent, "staging")
	roots, err := qualifyExecutionRoots(staging, results, nil)
	if err != nil {
		t.Fatalf("one missing sibling intent was rejected: %v", err)
	}
	defer roots.close()
	if roots.staging.observed() || len(roots.staging.missingSuffix) != 1 || roots.staging.missingSuffix[0] != "staging" {
		t.Fatalf("staging absence was not retained as one missing suffix: %#v", roots.staging.missingSuffix)
	}
	if !roots.results.observed() {
		t.Fatal("existing results root was not observed")
	}
	if _, err := os.Stat(staging); !os.IsNotExist(err) {
		t.Fatal("qualification mutated missing staging intent")
	}
}

func TestQualifiedExecutionRootsRejectDualMissingLookupAmbiguity(t *testing.T) {
	parent := physicalTestTempDir(t)
	staging := filepath.Join(parent, "Area")
	results := filepath.Join(parent, "area")
	if roots, err := qualifyExecutionRoots(staging, results, nil); err == nil {
		_ = roots.close()
		t.Fatal("dual-unobserved names in one lookup context were accepted")
	}
	for _, path := range []string{staging, results} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("dual-missing qualification changed %s", path)
		}
	}
}

func TestQualifiedExecutionRootsRejectMissingNestedIntentBeforeProvisioning(t *testing.T) {
	staging := physicalTestTempDir(t)
	results := filepath.Join(staging, "nested", "results")
	if roots, err := qualifyExecutionRoots(staging, results, nil); err == nil {
		_ = roots.close()
		t.Fatal("missing result intent within staging was accepted")
	}
	if _, err := os.Stat(filepath.Join(staging, "nested")); !os.IsNotExist(err) {
		t.Fatal("nested missing intent was provisioned before refusal")
	}
}

func TestStartupProvisioningReobservesAfterEveryCreatedRootComponent(t *testing.T) {
	base := physicalTestTempDir(t)
	stagingParent := filepath.Join(base, "staging-parent")
	results := filepath.Join(base, "results")
	for _, path := range []string{stagingParent, results} {
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	staging := filepath.Join(stagingParent, "one", "two")
	ledger := &executionRootAcquisitionLedger{}
	roots, err := provisionExecutionRoots(staging, results, ledger)
	if err != nil {
		t.Fatalf("provision roots: %v", err)
	}
	defer roots.close()
	if ledger.Count != 3 {
		t.Fatalf("expected initial acquisition and one reobservation per created component, got %d", ledger.Count)
	}
	if !roots.staging.observed() || !roots.results.observed() {
		t.Fatal("provisioning did not return two observed roots")
	}
}

func TestStartupProvisioningReprovesBeforeCreatingResultsRoot(t *testing.T) {
	base := physicalTestTempDir(t)
	stagingParent := filepath.Join(base, "staging-parent")
	resultsParent := filepath.Join(base, "results-parent")
	for _, path := range []string{stagingParent, resultsParent} {
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	staging := filepath.Join(stagingParent, "staging")
	results := filepath.Join(resultsParent, "results")
	ledger := &executionRootAcquisitionLedger{}
	roots, err := provisionExecutionRoots(staging, results, ledger)
	if err != nil {
		t.Fatalf("provision disjoint missing roots: %v", err)
	}
	defer roots.close()
	if ledger.Count != 3 {
		t.Fatalf("expected a new pair proof after staging and after results creation, got %d", ledger.Count)
	}
	for _, root := range []string{staging, results} {
		if info, err := os.Stat(root); err != nil || !info.IsDir() {
			t.Fatalf("root was not provisioned: %s err=%v", root, err)
		}
	}
}

func TestQualifiedExecutionRootsDetectReplacementBeforeEffect(t *testing.T) {
	parent := physicalTestTempDir(t)
	staging := filepath.Join(parent, "staging")
	results := filepath.Join(parent, "results")
	for _, root := range []string{staging, results} {
		if err := os.Mkdir(root, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	sentinel := filepath.Join(results, "sentinel")
	if err := os.WriteFile(sentinel, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := qualifyExecutionRoots(staging, results, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer roots.close()
	displaced := results + "-displaced"
	if err := os.Rename(results, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(results, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := roots.reobserve(); err == nil {
		t.Fatal("visible results-root replacement was accepted")
	}
	content, err := os.ReadFile(filepath.Join(displaced, "sentinel"))
	if err != nil || string(content) != "unchanged" {
		t.Fatalf("replacement detection changed sentinel: %q err=%v", content, err)
	}
}

func TestExecutionRootCapabilityProbeCoversBothConfiguredRoots(t *testing.T) {
	parent := physicalTestTempDir(t)
	staging := filepath.Join(parent, "staging")
	results := filepath.Join(parent, "results")
	for _, root := range []string{staging, results} {
		if err := os.Mkdir(root, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	ledger := &executionRootAcquisitionLedger{}
	roots, err := qualifyExecutionRoots(staging, results, ledger)
	if err != nil {
		t.Fatal(err)
	}
	defer roots.close()
	owner, err := roots.owner()
	if err != nil {
		t.Fatal(err)
	}
	if err := roots.probeCapabilities(owner); err != nil {
		t.Fatalf("probe both roots: %v", err)
	}
	if ledger.Count < 10 {
		t.Fatalf("capability probe skipped checked root boundaries: got %d acquisitions", ledger.Count)
	}
	for _, test := range []struct {
		root   string
		prefix string
	}{
		{staging, ".execution-substrate-staging-probe-"},
		{results, ".execution-substrate-results-probe-"},
	} {
		entries, err := os.ReadDir(test.root)
		want := 2
		if test.root == results {
			want = 3
		}
		if err != nil || len(entries) != want {
			t.Fatalf("capability probe retained fixtures in %s: entries=%v err=%v", test.root, entries, err)
		}
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), test.prefix) &&
				!(test.root == results && strings.HasPrefix(entry.Name(), ".execution-substrate-result-dir-probe-")) {
				t.Fatalf("unexpected retained probe entry %q", entry.Name())
			}
		}
	}
}

func TestRetainedResultReviewNaturalDirectoryProbeRejectsExpectedOwnerMismatch(t *testing.T) {
	parent := physicalTestTempDir(t)
	stage := filepath.Join(parent, "stage")
	results := filepath.Join(parent, "results")
	for _, path := range []string{stage, results} {
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	roots, err := qualifyExecutionRoots(stage, results, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer roots.close()
	actual, err := roots.owner()
	if err != nil {
		t.Fatal(err)
	}
	wrong := actual
	wrong.UID++
	if err := roots.probeNaturalResultDirectory(wrong, "owner-mismatch"); err == nil || !strings.Contains(err.Error(), "natural retained result directory creation is unavailable") {
		t.Fatalf("natural owner mismatch passed: %v", err)
	}
	path := filepath.Join(results, ".execution-substrate-result-dir-probe-owner-mismatch")
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != retainedResultRunDirMode {
		t.Fatalf("mismatched probe was repaired or removed: info=%v err=%v", info, err)
	}
}

func TestRetainedResultReviewExistingRunDirectoryIsNotRepaired(t *testing.T) {
	root := physicalTestTempDir(t)
	runID := "run-0123456789abcdef"
	path := filepath.Join(root, runID)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	directory, _, err := openRetainedResultDirectory(root, runID, executionPlatformStateOwner{UID: os.Getuid(), GID: os.Getgid()}, true)
	if directory != nil {
		defer directory.close()
	}
	if err == nil {
		t.Fatal("pre-existing wrong-mode result directory was accepted")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("pre-existing directory was repaired or removed: info=%v err=%v", info, err)
	}
}
