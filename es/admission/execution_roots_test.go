package admission

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
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
	// The staging root holds the probe directory and its symbolic link. The
	// probe directory holds the nested directory, and that holds one entry
	// for each mode staging uses, with the roots' owner and the exact mode.
	stagingEntries, err := os.ReadDir(staging)
	if err != nil || len(stagingEntries) != 2 {
		t.Fatalf("capability probe retained fixtures in %s: entries=%v err=%v", staging, stagingEntries, err)
	}
	probeName := ""
	for _, entry := range stagingEntries {
		switch {
		case strings.HasPrefix(entry.Name(), ".execution-substrate-staging-probe-") && strings.HasSuffix(entry.Name(), "-symlink"):
		case strings.HasPrefix(entry.Name(), ".execution-substrate-staging-probe-") && entry.IsDir():
			probeName = entry.Name()
		default:
			t.Fatalf("unexpected retained probe entry %q", entry.Name())
		}
	}
	if probeName == "" {
		t.Fatalf("capability probe retained no probe directory in %s", staging)
	}
	requireTestProbeEntries(t, filepath.Join(staging, probeName), owner, map[string]uint32{
		nestedStagingProbeName: unix.S_IFDIR | stableStageDirMode,
	})
	wantStaged := map[string]uint32{}
	for _, mode := range stagedDirectoryModes() {
		if mode != stableStageDirMode {
			wantStaged[fmt.Sprintf("directory-%04o", uint32(mode))] = unix.S_IFDIR | uint32(mode)
		}
	}
	for _, mode := range stagedFileModes() {
		wantStaged[fmt.Sprintf("file-%04o", uint32(mode))] = unix.S_IFREG | uint32(mode)
	}
	if len(wantStaged) != 6 {
		t.Fatalf("staged modes = %v, want five file modes and one directory mode beyond the stable stage mode", wantStaged)
	}
	requireTestProbeEntries(t, filepath.Join(staging, probeName, nestedStagingProbeName), owner, wantStaged)

	// The results root holds the natural result directory, and that holds
	// what retention would leave: the evidence-mode file, the collision
	// target, and the bundle-mode file under the free name it was renamed to.
	resultEntries, err := os.ReadDir(results)
	if err != nil || len(resultEntries) != 1 || !resultEntries[0].IsDir() || !strings.HasPrefix(resultEntries[0].Name(), ".execution-substrate-result-dir-probe-") {
		t.Fatalf("capability probe retained fixtures in %s: entries=%v err=%v", results, resultEntries, err)
	}
	resultDir := filepath.Join(results, resultEntries[0].Name())
	requireTestProbeEntries(t, resultDir, owner, map[string]uint32{
		"evidence":  unix.S_IFREG | retainedNormalizationEvidenceFileMode,
		"collision": unix.S_IFREG,
		"renamed":   unix.S_IFREG | retainedResultBundleFileMode,
	})
}

// requireTestProbeEntries checks that directory holds exactly the named
// entries. A want value with permission bits must match the entry's type and
// exact mode, and the entry must have the roots' owner; a want value of a type
// alone checks the type only.
func requireTestProbeEntries(t *testing.T, directory string, owner executionPlatformStateOwner, want map[string]uint32) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(want) {
		t.Fatalf("probe entries in %s = %v, want %v", directory, entries, want)
	}
	for _, entry := range entries {
		wantMode, ok := want[entry.Name()]
		if !ok {
			t.Fatalf("unexpected probe entry %s in %s", entry.Name(), directory)
		}
		var stat unix.Stat_t
		if err := unix.Lstat(filepath.Join(directory, entry.Name()), &stat); err != nil {
			t.Fatal(err)
		}
		mode := uint32(stat.Mode)
		if wantMode&0o7777 == 0 {
			if mode&unix.S_IFMT != wantMode {
				t.Fatalf("probe entry %s has mode %o, want type %o", entry.Name(), mode, wantMode)
			}
			continue
		}
		if !sameCustodyRecordedMode(mode, wantMode) || int(stat.Uid) != owner.UID || int(stat.Gid) != owner.GID {
			t.Fatalf("probe entry %s = mode %o owner %d:%d, want mode %o owner %d:%d", entry.Name(), mode, stat.Uid, stat.Gid, wantMode, owner.UID, owner.GID)
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
