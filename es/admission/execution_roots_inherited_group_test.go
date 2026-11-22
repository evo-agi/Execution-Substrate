package admission

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// TestExecutionRootProbeRefusesWhenStagingCannotOwnNestedDirectories pins that
// configured-Submit startup refuses roots that staging cannot use. The fixture
// gives both roots a group this process is not a member of, with the setgid
// bit, as a workspace under a shared project directory gets on Linux. New
// entries created directly in the roots inherit that group, so probes that
// stop there see the roots' owner. Staging sets its run directory to 0750,
// which drops the setgid bit, so a directory it creates inside gets this
// process's effective GID, and giving it the roots' GID needs membership of
// that group. Where new entries always take their parent's group, staging
// succeeds, and the probe must then succeed too. Either way the probe and
// staging must agree.
func TestExecutionRootProbeRefusesWhenStagingCannotOwnNestedDirectories(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root may give an entry any group, so the inherited-group condition needs a non-root process")
	}
	if output, err := exec.Command("sudo", "-n", "true").CombinedOutput(); err != nil {
		t.Skipf("needs passwordless sudo to give the fixture roots a group this process is not in: %v: %s", err, strings.TrimSpace(string(output)))
	}
	foreignGID := testGroupIDOutsideProcessGroups(t)
	parent := physicalTestTempDir(t)
	staging := filepath.Join(parent, "staging")
	results := filepath.Join(parent, "results")
	for _, root := range []string{staging, results} {
		if err := os.Mkdir(root, 0o755); err != nil {
			t.Fatal(err)
		}
		runTestSudo(t, "chgrp", strconv.Itoa(foreignGID), root)
		runTestSudo(t, "chmod", "2755", root)
		requireTestRootOwnerAndSetgid(t, root, os.Getuid(), foreignGID)
	}

	roots, err := provisionExecutionRoots(staging, results, nil)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := roots.owner()
	if err != nil {
		_ = roots.close()
		t.Fatal(err)
	}
	if owner.UID != os.Getuid() || owner.GID != foreignGID {
		_ = roots.close()
		t.Fatalf("roots owner = %d:%d, want %d:%d", owner.UID, owner.GID, os.Getuid(), foreignGID)
	}
	probeErr := roots.probeCapabilities(owner)
	if err := roots.close(); err != nil {
		t.Fatal(err)
	}

	stageErr := stageTestNestedDirectoryLikeSubmit(staging, results, owner)
	t.Logf("startup probe: %v; staging a nested directory: %v", probeErr, stageErr)
	if (probeErr == nil) != (stageErr == nil) {
		t.Fatalf("startup probe and staging disagree: probe=%v staging=%v", probeErr, stageErr)
	}
	if stageErr != nil && !errors.Is(stageErr, unix.EPERM) {
		t.Fatalf("staging failed for another reason than the nested ownership change: %v", stageErr)
	}
	if probeErr != nil && !strings.Contains(probeErr.Error(), "nested staging directory ownership is unavailable") {
		t.Fatalf("startup probe refused for another reason: %v", probeErr)
	}
}

// TestExecutionRootProbeAcceptsSetgidRootsWithTheProcessGroup pins that the
// nested staging probe refuses only the ownership condition, not setgid roots
// as such: roots whose inherited group is this process's effective GID pass
// startup, the probe's nested directory carries the roots' owner and the
// exact stable stage mode, and staging works.
func TestExecutionRootProbeAcceptsSetgidRootsWithTheProcessGroup(t *testing.T) {
	requireSetgidRootsPassProbeAndStaging(t, os.Getegid())
}

// TestExecutionRootProbeAcceptsSetgidRootsWithASupplementaryGroup pins that the
// probe changes the nested directory's group rather than only checking it:
// roots that inherit a supplementary group of this process are usable, because
// staging may give a nested directory any group the process is a member of.
func TestExecutionRootProbeAcceptsSetgidRootsWithASupplementaryGroup(t *testing.T) {
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range groups {
		if group != os.Getegid() {
			requireSetgidRootsPassProbeAndStaging(t, group)
			return
		}
	}
	t.Skip("this process has no supplementary group besides its effective GID")
}

func requireSetgidRootsPassProbeAndStaging(t *testing.T, gid int) {
	t.Helper()
	parent := physicalTestTempDir(t)
	staging := filepath.Join(parent, "staging")
	results := filepath.Join(parent, "results")
	for _, root := range []string{staging, results} {
		if err := os.Mkdir(root, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(root, os.Geteuid(), gid); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(root, 0o755|os.ModeSetgid); err != nil {
			t.Fatal(err)
		}
		requireTestRootOwnerAndSetgid(t, root, os.Geteuid(), gid)
	}

	roots, err := provisionExecutionRoots(staging, results, nil)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := roots.owner()
	if err != nil {
		_ = roots.close()
		t.Fatal(err)
	}
	if err := roots.probeCapabilities(owner); err != nil {
		_ = roots.close()
		t.Fatalf("startup probe refused setgid roots with group %d: %v", gid, err)
	}
	if err := roots.close(); err != nil {
		t.Fatal(err)
	}

	probeDirs, err := filepath.Glob(filepath.Join(staging, ".execution-substrate-staging-probe-*"))
	if err != nil {
		t.Fatal(err)
	}
	var probeDir string
	for _, candidate := range probeDirs {
		if !strings.HasSuffix(candidate, "-symlink") {
			if probeDir != "" {
				t.Fatalf("more than one staging probe directory: %v", probeDirs)
			}
			probeDir = candidate
		}
	}
	if probeDir == "" {
		t.Fatalf("no staging probe directory in %v", probeDirs)
	}
	entries, err := os.ReadDir(probeDir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "nested" {
		t.Fatalf("staging probe directory entries = %v, err=%v; want exactly \"nested\"", entries, err)
	}
	nested, err := os.Lstat(filepath.Join(probeDir, "nested"))
	if err != nil {
		t.Fatal(err)
	}
	nestedStat, ok := nested.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("no stat for the nested staging probe")
	}
	if !nested.IsDir() || nested.Mode() != os.ModeDir|stableStageDirMode || int(nestedStat.Uid) != owner.UID || int(nestedStat.Gid) != owner.GID {
		t.Fatalf("nested staging probe = mode %v owner %d:%d, want mode %v owner %d:%d", nested.Mode(), nestedStat.Uid, nestedStat.Gid, os.ModeDir|stableStageDirMode, owner.UID, owner.GID)
	}

	if err := stageTestNestedDirectoryLikeSubmit(staging, results, owner); err != nil {
		t.Fatalf("staging a nested directory under setgid roots with group %d: %v", gid, err)
	}
}

// stageTestNestedDirectoryLikeSubmit claims a run staging root the way Submit
// does and creates the first directory staging creates inside it.
func stageTestNestedDirectoryLikeSubmit(staging string, results string, owner executionPlatformStateOwner) error {
	roots, err := qualifyExecutionRoots(staging, results, nil)
	if err != nil {
		return err
	}
	if err := roots.reobserve(); err != nil {
		_ = roots.close()
		return err
	}
	stagingRoot, err := roots.takeStagingQualifiedDirectory()
	if err != nil {
		_ = roots.close()
		return err
	}
	custody, err := claimStagingCustodyFromQualifiedRoot(stagingRoot, "run-0123456789abcdef", owner)
	if closeErr := roots.close(); closeErr != nil && err == nil {
		_ = custody.close()
		return closeErr
	}
	if err != nil {
		return err
	}
	return errors.Join(custody.ensureDirectory(executionPayloadStageDirName, stableStageDirMode), custody.close())
}

func testGroupIDOutsideProcessGroups(t *testing.T) int {
	t.Helper()
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	member := map[int]bool{os.Getegid(): true, os.Getgid(): true}
	for _, group := range groups {
		member[group] = true
	}
	for candidate := 54321; candidate < 54321+1024; candidate++ {
		if !member[candidate] {
			return candidate
		}
	}
	t.Fatal("no group ID outside this process's groups")
	return -1
}

func runTestSudo(t *testing.T, args ...string) {
	t.Helper()
	output, err := exec.Command("sudo", append([]string{"-n"}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("sudo %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
}

func requireTestRootOwnerAndSetgid(t *testing.T, root string, uid int, gid int) {
	t.Helper()
	info, err := os.Lstat(root)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("no stat for %s", root)
	}
	if !info.IsDir() || info.Mode()&os.ModeSetgid == 0 || int(stat.Uid) != uid || int(stat.Gid) != gid {
		t.Fatalf("fixture root %s = mode %v owner %d:%d, want a setgid directory owned by %d:%d", root, info.Mode(), stat.Uid, stat.Gid, uid, gid)
	}
}
