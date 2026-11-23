package admission

// Tests for two rules that came with the repair of the startup probe findings
// RT-1 and RT-3 (red-team report 14 of pull request #20). They need neither
// sudo nor bindfs, so they gate on every host. The red-team's own tests, in
// execution_roots_probe_use_agreement_linux_test.go, show the setups behind
// the rules.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// TestStagingRefusesModesTheStartupProbeDoesNotProve pins the rule that ties
// staging to the startup probe: staging gives entries only the modes the probe
// stages, so a new mode cannot reach staging without reaching the probe.
func TestStagingRefusesModesTheStartupProbeDoesNotProve(t *testing.T) {
	stagingRoot := physicalTestTempDir(t)
	custody, layout := claimTestStagingCustody(t, stagingRoot, "run-0123456789abcdef")
	if err := custody.ensureDirectory("payload", 0o700); err == nil || !strings.Contains(err.Error(), "staging directory mode 0700 is not proved by the startup probe") {
		t.Fatalf("staging accepted a directory mode the startup probe does not prove: %v", err)
	}
	if err := custody.writeFile("payload/file", []byte("x"), 0o700); err == nil || !strings.Contains(err.Error(), "staging file mode 0700 is not proved by the startup probe") {
		t.Fatalf("staging accepted a file mode the startup probe does not prove: %v", err)
	}
	if err := custody.writeFileWithParentMode("mounts/file", []byte("x"), governedMountFileMode, 0o700); err == nil || !strings.Contains(err.Error(), "staging directory mode 0700 is not proved by the startup probe") {
		t.Fatalf("staging accepted a parent directory mode the startup probe does not prove: %v", err)
	}
	if entries, err := os.ReadDir(layout.stageRootDir); err != nil || len(entries) != 0 {
		t.Fatalf("refused modes left entries: %v %v", entries, err)
	}
	for _, mode := range stagedDirectoryModes() {
		name := fmt.Sprintf("directory-%04o", uint32(mode))
		if err := custody.ensureDirectory(name, mode); err != nil {
			t.Fatalf("staging refused probed directory mode %04o: %v", uint32(mode), err)
		}
		assertStagedExactMode(t, filepath.Join(layout.stageRootDir, name), mode, true)
	}
	for _, mode := range stagedFileModes() {
		name := fmt.Sprintf("file-%04o", uint32(mode))
		if err := custody.writeFile(name, []byte("x"), mode); err != nil {
			t.Fatalf("staging refused probed file mode %04o: %v", uint32(mode), err)
		}
		assertStagedExactMode(t, filepath.Join(layout.stageRootDir, name), mode, false)
	}
}

// TestDirectoriesOpenedByNameNeverChangeOwningUser pins the rule behind the
// repair of RT-3 at each kind of place that creates a directory, opens it by
// name and then gives it the roots' owner: the startup probe, the claim of a
// run staging root, and staging's directories inside it. Nothing ties the open
// to the creation, so the open may find another user's directory. ES refuses
// any directory whose owning user is not already the roots' owning user,
// before it changes owner or mode. The tests stand in for the swap with an
// owner that the directories ES creates do not get. Run as root, a missing
// check would hand the directory to that owner; run as another user, the owner
// change would fail with another error. The case inside a run staging root
// runs as root only, through sudo when the test does not run as root.
//
// Each case also requires the directory's mode to be the one it was created
// with. ES creates these directories with mode 0750 and later sets 0750 again,
// so under the usual process mask a mode change would leave no trace. Each case
// therefore runs in a process of its own under the mask 0077: the directory is
// created as 0700, and a mode change before the refusal would leave 0750
// (audit finding A16-1).
func TestDirectoriesOpenedByNameNeverChangeOwningUser(t *testing.T) {
	foreign := executionPlatformStateOwner{UID: 54321, GID: os.Getgid()}
	if os.Getuid() == foreign.UID {
		foreign.UID++
	}
	if os.Geteuid() == 0 {
		foreign.GID = 54321
	}
	requireUntouched := func(t *testing.T, path string) {
		t.Helper()
		var stat unix.Stat_t
		if err := unix.Lstat(path, &stat); err != nil {
			t.Fatal(err)
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR || int(stat.Uid) != os.Getuid() {
			t.Fatalf("%s = mode %o owner %d, want a directory still owned by this process (%d)", path, stat.Mode, stat.Uid, os.Getuid())
		}
		if stat.Mode&0o7777 != 0o700 {
			t.Fatalf("%s has mode %04o after the refusal, want 0700, the mode it was created with under the mask 0077: ES changed its mode before the owner check", path, stat.Mode&0o7777)
		}
	}

	t.Run("claimed run staging root", func(t *testing.T) {
		if rerunTestUnderOwnerOnlyProcessMask(t) {
			return
		}
		stagingRoot := physicalTestTempDir(t)
		custody, err := claimStagingCustody(stagingRoot, "run-0123456789abcdef", foreign)
		if err == nil {
			_ = custody.close()
			t.Fatal("claim accepted a run staging root whose owning user is not the roots' owning user")
		}
		if !strings.Contains(err.Error(), "claimed staging root does not belong to the execution roots' owning user") {
			t.Fatalf("claim refused for another reason: %v", err)
		}
		requireUntouched(t, filepath.Join(stagingRoot, "run-0123456789abcdef"))
	})

	t.Run("staging directory", func(t *testing.T) {
		// A directory inside a run staging root is created only after the
		// claim, which already refuses roots whose owning user the created
		// root does not get. So this case stands in for the swap with roots
		// that belong to another user, after the claim, and that needs root.
		if os.Geteuid() != 0 {
			rerunTestAsRootThroughSudo(t)
			return
		}
		if rerunTestUnderOwnerOnlyProcessMask(t) {
			return
		}
		stagingRoot := physicalTestTempDir(t)
		custody, layout := claimTestStagingCustody(t, stagingRoot, "run-0123456789abcdef")
		if err := unix.Fchown(custody.rootFD, foreign.UID, foreign.GID); err != nil {
			t.Fatal(err)
		}
		custody.owner = foreign
		err := custody.ensureDirectory("payload", stableStageDirMode)
		if err == nil || !strings.Contains(err.Error(), "staging directory does not belong to the execution roots' owning user") {
			t.Fatalf("staging directory: %v", err)
		}
		requireUntouched(t, filepath.Join(layout.stageRootDir, "payload"))
	})

	t.Run("startup probe directory", func(t *testing.T) {
		if rerunTestUnderOwnerOnlyProcessMask(t) {
			return
		}
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
			t.Fatal(err)
		}
		defer roots.close()
		fd, err := roots.probeStagedDirectory(roots.staging.existingFD, "probe", stableStageDirMode, foreign, "staging probe directory")
		if err == nil {
			_ = unix.Close(fd)
			t.Fatal("startup probe accepted a directory whose owning user is not the roots' owning user")
		}
		if fd != -1 || !strings.Contains(err.Error(), "staging probe directory does not belong to the execution roots' owning user") {
			t.Fatalf("startup probe: fd=%d err=%v", fd, err)
		}
		requireUntouched(t, filepath.Join(staging, "probe"))
	})
}

// ownerOnlyProcessMaskEnv marks a process of the test binary that
// rerunTestUnderOwnerOnlyProcessMask started.
const ownerOnlyProcessMaskEnv = "ES_TEST_OWNER_ONLY_PROCESS_MASK"

// rerunTestUnderOwnerOnlyProcessMask runs the current test again in a new
// process of the test binary whose process mask is 0077, and reports true; the
// caller then returns. In that process it sets the mask and reports false, so
// the caller runs the case there. The process mask belongs to the whole
// process, so the test sets it only in a process that runs nothing else.
func rerunTestUnderOwnerOnlyProcessMask(t *testing.T) bool {
	t.Helper()
	if os.Getenv(ownerOnlyProcessMaskEnv) == "1" {
		syscall.Umask(0o077)
		return false
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	pattern := "^" + strings.ReplaceAll(t.Name(), "/", "$/^") + "$"
	command := exec.Command(self, "-test.run", pattern, "-test.v", "-test.count=1")
	command.Env = append(os.Environ(), ownerOnlyProcessMaskEnv+"=1")
	output, err := command.CombinedOutput()
	t.Logf("the same test under the process mask 0077:\n%s", output)
	if err != nil {
		t.Fatalf("the test failed under the process mask 0077: %v", err)
	}
	if !strings.Contains(string(output), "--- PASS: "+t.Name()) {
		t.Fatal("the test did not run under the process mask 0077")
	}
	return true
}

// rerunTestAsRootThroughSudo runs the current test again, as root, in a new
// process of the test binary, and fails when that run fails. It skips when
// passwordless sudo is not available.
func rerunTestAsRootThroughSudo(t *testing.T) {
	t.Helper()
	if output, err := exec.Command("sudo", "-n", "true").CombinedOutput(); err != nil {
		t.Skipf("needs root or passwordless sudo: %v: %s", err, strings.TrimSpace(string(output)))
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	pattern := "^" + strings.ReplaceAll(t.Name(), "/", "$/^") + "$"
	output, err := exec.Command("sudo", "-n", self, "-test.run", pattern, "-test.v", "-test.count=1").CombinedOutput()
	t.Logf("the same test as root:\n%s", output)
	if err != nil {
		t.Fatalf("the test failed as root: %v", err)
	}
	if !strings.Contains(string(output), "--- PASS: "+t.Name()) {
		t.Fatal("the test did not run as root")
	}
}
