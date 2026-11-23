package admission

// Proposed regression tests from the red-team of pull request #20 at eb6eea9
// (report 14-red-team-pr20.md, findings RT-1, RT-2 and RT-3). They are not
// part of that pull request. Each one pins a setup in which configured-Submit
// startup and real use disagree, or in which a refused start changes an
// owner. On eb6eea9 and on its base f9537a8 every test in this file fails
// where its fixture can be built, so they belong to the change that repairs
// the finding, not to trunk as it is.
//
// All of them follow the rule the pull request set for its own test: the
// startup probe and real use must agree, in either direction. A repair may
// make the probe refuse the setup or make use work in it.
//
// The tests need passwordless sudo, or root. Two of them also need bindfs
// and skip without it, so a runner that is to gate them has to install it.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	esconfig "execution-substrate/es/config"

	"golang.org/x/sys/unix"
)

// TestExecutionRootProbeAgreesWithStagingOnOverlayWithSeparateLayerFileSystems
// pins RT-1 in its kernel-only shape. On an overlay whose lower and upper
// layers are on different file systems, mounted without xino, a directory
// reports the overlay's device and a regular file reports another device.
// Staging refuses every file whose device differs from the staging root's, so
// no payload can be staged there. The startup probe creates only directories
// in the staging root, so it does not see this.
func TestExecutionRootProbeAgreesWithStagingOnOverlayWithSeparateLayerFileSystems(t *testing.T) {
	requireTestMountPrivilege(t)
	parent := physicalTestTempDir(t)
	lower := filepath.Join(parent, "lower-fs")
	upper := filepath.Join(parent, "upper-fs")
	merged := filepath.Join(parent, "merged")
	for _, dir := range []string{lower, upper, merged} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mountTestFileSystem(t, lower, "-t", "tmpfs", "tmpfs", lower)
	mountTestFileSystem(t, upper, "-t", "tmpfs", "tmpfs", upper)
	runTestPrivileged(t, "mkdir", filepath.Join(lower, "layer"), filepath.Join(upper, "layer"), filepath.Join(upper, "work"))
	options := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s,xino=off", filepath.Join(lower, "layer"), filepath.Join(upper, "layer"), filepath.Join(upper, "work"))
	mountTestFileSystem(t, merged, "-t", "overlay", "overlay", "-o", options, merged)
	staging, results := createTestRootsOwnedByThisProcess(t, merged)

	// The fixture must produce the condition, or the test would pass for no reason.
	witness := filepath.Join(staging, "device-witness")
	if err := os.WriteFile(witness, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var rootStat, fileStat syscall.Stat_t
	if err := syscall.Lstat(staging, &rootStat); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Lstat(witness, &fileStat); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(witness); err != nil {
		t.Fatal(err)
	}
	if rootStat.Dev == fileStat.Dev {
		t.Fatalf("fixture overlay gives files the device of its directories (%d); the layers are not on separate file systems or xino is on", rootStat.Dev)
	}

	probeErr, owner := probeTestRootsLikeStartup(t, staging, results)
	stageErr := stageTestRunLikeSubmit(staging, results, owner)
	t.Logf("startup probe: %v; staging a run: %v", probeErr, stageErr)
	if (probeErr == nil) != (stageErr == nil) {
		t.Fatalf("startup probe and staging disagree: probe=%v staging=%v", probeErr, stageErr)
	}
}

// TestExecutionRootProbeAgreesWithStagingWhenTheFileSystemFixesModes pins
// RT-1 in its mode shapes. Staging requires exact modes: directories 0750 and
// 0755, files 0600, 0640, 0644, 0750 and 0755. The startup probe exercises
// one of them in the staging root, a directory at 0750. On a file system that
// does not store the mode it is asked for, the probe passes when 0750
// directories happen to come out right, and staging then fails on the first
// file or on the first mount directory. The fixtures use bindfs, a FUSE file
// system, to get such file systems without a server.
func TestExecutionRootProbeAgreesWithStagingWhenTheFileSystemFixesModes(t *testing.T) {
	bindfs := requireTestBindfs(t)
	requireTestMountPrivilege(t)
	uid, gid := strconv.Itoa(os.Getuid()), strconv.Itoa(os.Getgid())
	for _, fixture := range []struct {
		name       string
		options    []string
		defaultACL string
	}{
		{
			// What a share without POSIX modes looks like: every file 0640,
			// every directory 0750, one owner, mode and owner changes accepted
			// and ignored.
			name:    "files always 0640",
			options: []string{"--force-user=" + uid, "--force-group=" + gid, "--perms=0640:ud+x:gd+x", "--chmod-ignore", "--chown-ignore", "--chgrp-ignore"},
		},
		{
			// Mode changes accepted and ignored, and a default ACL that makes
			// every new directory 0750: the 0755 mount directories cannot be made.
			name:       "mode changes ignored under a default ACL",
			options:    []string{"--chmod-ignore"},
			defaultACL: "u::rwx,g::r-x,o::---",
		},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			if fixture.defaultACL != "" {
				if _, err := exec.LookPath("setfacl"); err != nil {
					t.Skipf("needs setfacl: %v", err)
				}
			}
			mount := mountTestBindfs(t, bindfs, fixture.options...)
			staging, results := createTestRootsOwnedByThisProcess(t, mount)
			if fixture.defaultACL != "" {
				runTestPrivileged(t, "setfacl", "-d", "-m", fixture.defaultACL, staging, results)
			}
			probeErr, owner := probeTestRootsLikeStartup(t, staging, results)
			stageErr := stageTestRunLikeSubmit(staging, results, owner)
			t.Logf("startup probe: %v; staging a run: %v", probeErr, stageErr)
			if (probeErr == nil) != (stageErr == nil) {
				t.Fatalf("startup probe and staging disagree: probe=%v staging=%v", probeErr, stageErr)
			}
		})
	}
}

// TestExecutionRootProbeAgreesWithRetentionWhenRenameRejectsNoReplace pins
// RT-2. Result retention publishes its bundle with a no-replace rename. The
// startup probe checks that primitive only against a name that exists and
// accepts any error. Linux answers "file exists" for that case before it asks
// the file system, so a file system whose rename accepts no flags passes
// startup, and then no result can ever be retained. The fixture uses bindfs,
// whose rename accepted no flags in the version this was found with (1.14.7).
func TestExecutionRootProbeAgreesWithRetentionWhenRenameRejectsNoReplace(t *testing.T) {
	bindfs := requireTestBindfs(t)
	requireTestMountPrivilege(t)
	mount := mountTestBindfs(t, bindfs)
	staging, results := createTestRootsOwnedByThisProcess(t, mount)

	// The fixture must produce the condition, or the test would pass for no reason.
	if err := os.WriteFile(filepath.Join(results, "rename-witness-from"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	resultsFD, err := unix.Open(results, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	witnessErr := platformRenameNoReplace(resultsFD, "rename-witness-from", resultsFD, "rename-witness-to")
	_ = unix.Close(resultsFD)
	for _, name := range []string{"rename-witness-from", "rename-witness-to"} {
		if err := os.Remove(filepath.Join(results, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	}
	if witnessErr == nil {
		t.Skip("this bindfs supports no-replace renames, so the fixture cannot produce the condition; use a file system whose rename accepts no flags")
	}
	t.Logf("no-replace rename to a free name on the fixture: %v", witnessErr)

	probeErr, _ := probeTestRootsLikeStartup(t, staging, results)
	retainErr := retainTestResultLikeTerminalRun(t, staging, results)
	t.Logf("startup probe: %v; retaining a result: %v", probeErr, retainErr)
	if (probeErr == nil) != (retainErr == nil) {
		t.Fatalf("startup probe and result retention disagree: probe=%v retention=%v", probeErr, retainErr)
	}
}

// TestExecutionRootProbeHandsNoDirectoryToAnotherUser pins the condition
// behind RT-3 in a form that needs no race. A root process on roots that
// belong to another user is refused at startup on every ordinary file system,
// because retained result directories are created without an owner change.
// Before it refuses, the probe creates directories in the staging root, opens
// them by name and gives them to the roots' owner. The roots' owner can
// rename entries of the staging root, so between the creation and the open
// they can put a directory of somebody else's there, and root then gives them
// that one (measured: 6 of 1000 starts for the nested directory, 18 of 1000
// for the probe directory). So a refused start must not leave a directory
// behind that changed its owning user.
//
// The test presumes the repair by which ES never changes the owning user of a
// directory it opened by name, and refuses instead. No working setup needs
// such a change, because retained result directories are never given an
// owner. If the repair binds the open to the creation instead, this test has
// to give way to one that is driven through a hook between the two calls.
func TestExecutionRootProbeHandsNoDirectoryToAnotherUser(t *testing.T) {
	if os.Geteuid() != 0 {
		requireTestSudo(t)
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		output, err := exec.Command("sudo", "-n", self, "-test.run", "^"+t.Name()+"$", "-test.v", "-test.count=1").CombinedOutput()
		t.Logf("the same test as root:\n%s", output)
		if err != nil {
			t.Fatalf("the test failed as root: %v", err)
		}
		if !strings.Contains(string(output), "--- PASS: "+t.Name()) {
			t.Fatal("the test did not run as root")
		}
		return
	}
	const otherUID, otherGID = 54321, 54321
	parent := physicalTestTempDir(t)
	staging := filepath.Join(parent, "staging")
	results := filepath.Join(parent, "results")
	for _, root := range []string{staging, results} {
		if err := os.Mkdir(root, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(root, otherUID, otherGID); err != nil {
			t.Fatal(err)
		}
	}
	probeErr, owner := probeTestRootsLikeStartup(t, staging, results)
	if owner.UID != otherUID || owner.GID != otherGID {
		t.Fatalf("roots owner = %d:%d, want %d:%d", owner.UID, owner.GID, otherUID, otherGID)
	}
	if probeErr == nil {
		t.Skip("this file system creates entries with the roots' owner for a root process, so startup is not refused here")
	}
	t.Logf("startup probe: %v", probeErr)
	for _, root := range []string{staging, results} {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if path == root {
				return nil
			}
			var stat syscall.Stat_t
			if err := syscall.Lstat(path, &stat); err != nil {
				return err
			}
			if stat.Mode&syscall.S_IFMT == syscall.S_IFDIR && stat.Uid != 0 {
				t.Errorf("refused start left directory %s owned by %d:%d; a root process gave a directory it opened by name to the roots' owner", strings.TrimPrefix(path, parent), stat.Uid, stat.Gid)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// probeTestRootsLikeStartup runs what configured-Submit startup runs on the
// two roots and returns the probe's verdict and the owner it derived.
func probeTestRootsLikeStartup(t *testing.T, staging string, results string) (error, executionPlatformStateOwner) {
	t.Helper()
	roots, err := provisionExecutionRoots(staging, results, nil)
	if err != nil {
		t.Fatalf("provision execution roots: %v", err)
	}
	owner, err := roots.owner()
	if err != nil {
		_ = roots.close()
		t.Fatalf("derive execution roots owner: %v", err)
	}
	probeErr := roots.probeCapabilities(owner)
	if err := roots.close(); err != nil {
		t.Fatal(err)
	}
	return probeErr, owner
}

// stageTestRunLikeSubmit claims a run staging root the way Submit does and
// stages one of everything materialization stages there: the payload, the
// runtime-support binary, the workload trust material, and a mount tree with
// a plain and an executable file.
func stageTestRunLikeSubmit(staging string, results string, owner executionPlatformStateOwner) error {
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
		return fmt.Errorf("claim run staging root: %w", err)
	}
	defer custody.close()
	layout := executionPackageLayout{}
	if err := layout.stagePayload(custody, []byte("payload")); err != nil {
		return fmt.Errorf("stage payload: %w", err)
	}
	if err := layout.stageCapturedRuntimeSupportBinary(custody, []byte("#!/bin/sh\n")); err != nil {
		return fmt.Errorf("stage runtime-support binary: %w", err)
	}
	if _, err := layout.stageWorkloadVaultTrustMaterial(custody, resolvedTrustMaterial{vaultCACertBytes: []byte("ca\n"), workloadTLSBundleBytes: []byte("bundle\n")}); err != nil {
		return fmt.Errorf("stage workload trust material: %w", err)
	}
	mountDir := executionMountsStageDirName + "/00/contents/sub"
	if err := custody.ensureDirectory(mountDir, governedMountDirMode); err != nil {
		return fmt.Errorf("stage mount directory: %w", err)
	}
	if err := custody.writeFileWithParentMode(mountDir+"/file", []byte("m"), governedMountFileMode, governedMountDirMode); err != nil {
		return fmt.Errorf("stage mount file: %w", err)
	}
	if err := custody.writeFileWithParentMode(mountDir+"/exec", []byte("m"), governedMountExecFileMode, governedMountDirMode); err != nil {
		return fmt.Errorf("stage executable mount file: %w", err)
	}
	if err := custody.revalidateBeforeHandoff(); err != nil {
		return fmt.Errorf("revalidate before handoff: %w", err)
	}
	return nil
}

// retainTestResultLikeTerminalRun stands in for a finished workload: it puts
// two result files where a run leaves them and runs the real retention and
// read path.
func retainTestResultLikeTerminalRun(t *testing.T, staging string, results string) error {
	t.Helper()
	locator := newExecutionLocatorFromRunID("run-fedcba9876543210")
	service := &Service{
		cfg: esconfig.Config{
			Execution: esconfig.ExecutionConfig{
				StagingRootDir:     staging,
				ResultsRootDir:     results,
				RetainedResultAuth: esconfig.RetainedResultAuthConfig{StoreID: "test_store", KeyID: "test_key", KeyFile: "/synthetic/retained-result-key"},
			},
		},
		resultAuth: syntheticResultAuthenticator(),
	}
	layout := newExecutionPackageLayout(service.cfg, locator)
	if err := os.MkdirAll(filepath.Join(layout.resultStageDir, "nested"), 0o755); err != nil {
		t.Fatalf("workload stand-in: %v", err)
	}
	for _, name := range []string{"summary.txt", "nested/result.json"} {
		if err := os.WriteFile(filepath.Join(layout.resultStageDir, name), []byte("ok\n"), 0o644); err != nil {
			t.Fatalf("workload stand-in: %v", err)
		}
	}
	retained, err := service.retainTerminalResult(locator)
	if err != nil {
		return fmt.Errorf("retain terminal result: %w", err)
	}
	if !retained {
		return errors.New("retain terminal result: nothing was retained")
	}
	bundle, ok, resultErr := service.readRetainedResultBundle(locator)
	if resultErr != nil {
		return fmt.Errorf("read retained result: status=%d message=%q", resultErr.Status, resultErr.Message)
	}
	if !ok || len(bundle.Payload) == 0 {
		return errors.New("read retained result: the bundle is not readable")
	}
	return nil
}

// createTestRootsOwnedByThisProcess makes a staging and a results directory in
// a mount this process may not write to itself, owned by this process.
func createTestRootsOwnedByThisProcess(t *testing.T, mount string) (string, string) {
	t.Helper()
	staging := filepath.Join(mount, "staging")
	results := filepath.Join(mount, "results")
	owner := fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())
	runTestPrivileged(t, "mkdir", staging, results)
	runTestPrivileged(t, "chown", owner, staging, results)
	runTestPrivileged(t, "chmod", "0755", staging, results)
	for _, root := range []string{staging, results} {
		var stat syscall.Stat_t
		if err := syscall.Lstat(root, &stat); err != nil {
			t.Fatal(err)
		}
		// The mode is not checked: some fixtures exist to not store it.
		if stat.Mode&syscall.S_IFMT != syscall.S_IFDIR || int(stat.Uid) != os.Getuid() || int(stat.Gid) != os.Getgid() {
			t.Fatalf("fixture root %s = mode %o owner %d:%d, want a directory owned by %s", root, stat.Mode, stat.Uid, stat.Gid, owner)
		}
	}
	return staging, results
}

func requireTestSudo(t *testing.T) {
	t.Helper()
	if output, err := exec.Command("sudo", "-n", "true").CombinedOutput(); err != nil {
		t.Skipf("needs passwordless sudo: %v: %s", err, strings.TrimSpace(string(output)))
	}
}

func requireTestMountPrivilege(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		requireTestSudo(t)
	}
}

func requireTestBindfs(t *testing.T) string {
	t.Helper()
	bindfs, err := exec.LookPath("bindfs")
	if err != nil {
		t.Skipf("needs bindfs for a file system with other rules than the kernel's own: %v", err)
	}
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skipf("needs FUSE: %v", err)
	}
	return bindfs
}

func runTestPrivileged(t *testing.T, args ...string) {
	t.Helper()
	command := exec.Command(args[0], args[1:]...)
	if os.Geteuid() != 0 {
		command = exec.Command("sudo", append([]string{"-n"}, args...)...)
	}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("%s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
}

// mountTestFileSystem runs mount with the given arguments and unmounts the
// mount point again when the test ends, before the test's temporary directory
// is removed.
func mountTestFileSystem(t *testing.T, mountPoint string, mountArgs ...string) {
	t.Helper()
	runTestPrivileged(t, append([]string{"mount"}, mountArgs...)...)
	t.Cleanup(func() { unmountTestFileSystem(t, mountPoint) })
}

func unmountTestFileSystem(t *testing.T, mountPoint string) {
	t.Helper()
	command := exec.Command("umount", mountPoint)
	if os.Geteuid() != 0 {
		command = exec.Command("sudo", "-n", "umount", mountPoint)
	}
	if output, err := command.CombinedOutput(); err != nil {
		t.Errorf("umount %s: %v: %s", mountPoint, err, strings.TrimSpace(string(output)))
	}
}

// mountTestBindfs mirrors a fresh directory through bindfs with the given
// options and returns the mount point. Other users may enter the mount, and
// the kernel checks permissions there, as on a system-wide mount.
func mountTestBindfs(t *testing.T, bindfs string, options ...string) string {
	t.Helper()
	parent := physicalTestTempDir(t)
	backing := filepath.Join(parent, "backing")
	mount := filepath.Join(parent, "mount")
	for _, dir := range []string{backing, mount} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// The temporary directory is private to this user; root must be able to
	// serve it and other users to reach the mount point.
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	args := append([]string{bindfs}, options...)
	runTestPrivileged(t, append(args, backing, mount)...)
	t.Cleanup(func() {
		unmountTestFileSystem(t, mount)
		// Entries made through the mount belong to root's view of the backing
		// directory; hand them back so the temporary directory can be removed.
		runTestPrivileged(t, "chown", "-R", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), backing)
		runTestPrivileged(t, "chmod", "-R", "u+rwX", backing)
	})
	return mount
}
