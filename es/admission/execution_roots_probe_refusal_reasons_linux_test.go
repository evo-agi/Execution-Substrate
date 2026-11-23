package admission

// The red-team's tests in execution_roots_probe_use_agreement_linux_test.go
// require only that the startup probe and use agree. Several checks of the
// repaired probe can stand behind one agreement: on a bindfs mount, for
// example, the free-name rename refuses even when a file mode check is
// missing. The test below names the check that has to refuse each setup, so
// that each check is held on its own. Two setups put the roots on different
// file systems, which the red-team's tests do not: a results root that
// cannot hold retention's files under a staging root that works.
//
// Like the red-team's tests, it needs passwordless sudo, or root, and bindfs.

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestExecutionRootProbeNamesTheCheckThatRefuses(t *testing.T) {
	bindfs := requireTestBindfs(t)
	requireTestMountPrivilege(t)
	uid, gid := strconv.Itoa(os.Getuid()), strconv.Itoa(os.Getgid())
	filesAlways0640 := []string{"--force-user=" + uid, "--force-group=" + gid, "--perms=0640:ud+x:gd+x", "--chmod-ignore", "--chown-ignore", "--chgrp-ignore"}
	plainRoot := func(t *testing.T, name string) string {
		t.Helper()
		root := filepath.Join(physicalTestTempDir(t), name)
		if err := os.Mkdir(root, 0o755); err != nil {
			t.Fatal(err)
		}
		return root
	}
	for _, test := range []struct {
		name  string
		roots func(t *testing.T) (string, string)
		use   string
		want  string
	}{
		{
			name: "staging on an overlay with separate layer file systems",
			roots: func(t *testing.T) (string, string) {
				return createTestRootsOwnedByThisProcess(t, mountTestSplitLayerOverlay(t))
			},
			use:  "stage",
			want: "staged files report another device than the staging root",
		},
		{
			name: "staging where every directory is 0750",
			roots: func(t *testing.T) (string, string) {
				return createTestRootsOwnedByThisProcess(t, mountTestBindfs(t, bindfs, filesAlways0640...))
			},
			use:  "stage",
			want: "staged 0755 directory mode is unavailable",
		},
		{
			name: "staging where files lose their execute bits",
			roots: func(t *testing.T) (string, string) {
				return createTestRootsOwnedByThisProcess(t, mountTestBindfs(t, bindfs, "--chmod-filter=uf-x:gf-x:of-x"))
			},
			use:  "stage",
			want: "staged file mode 0750 is unavailable",
		},
		{
			// The roots' group is set on the file system below, because the
			// mount ignores group changes made through it. For a process that
			// is not root it is a group the process is in, where it has one,
			// so that the kernel passes the change on to the file system,
			// which then ignores it.
			name: "roots on a file system that ignores group changes",
			roots: func(t *testing.T) (string, string) {
				group := "54321"
				if os.Geteuid() != 0 {
					if groups, err := os.Getgroups(); err == nil {
						for _, candidate := range groups {
							if candidate != os.Getgid() {
								group = strconv.Itoa(candidate)
								break
							}
						}
					}
				}
				mount := mountTestBindfs(t, bindfs, "--chown-ignore", "--chgrp-ignore")
				backing := filepath.Join(filepath.Dir(mount), "backing")
				for _, name := range []string{"staging", "results"} {
					runTestPrivileged(t, "mkdir", filepath.Join(backing, name))
					runTestPrivileged(t, "chown", uid+":"+group, filepath.Join(backing, name))
					runTestPrivileged(t, "chmod", "0755", filepath.Join(backing, name))
				}
				return filepath.Join(mount, "staging"), filepath.Join(mount, "results")
			},
			use:  "stage",
			want: "staging probe directory ownership is unavailable",
		},
		{
			name: "results on an overlay with separate layer file systems",
			roots: func(t *testing.T) (string, string) {
				_, results := createTestRootsOwnedByThisProcess(t, mountTestSplitLayerOverlay(t))
				return plainRoot(t, "staging"), results
			},
			use:  "retain",
			want: "retained result files report another device than the results root",
		},
		{
			name: "results where every file is 0640",
			roots: func(t *testing.T) (string, string) {
				_, results := createTestRootsOwnedByThisProcess(t, mountTestBindfs(t, bindfs, filesAlways0640...))
				return plainRoot(t, "staging"), results
			},
			use:  "retain",
			want: "retained result file mode 0600 is unavailable",
		},
		{
			name: "results whose rename accepts no flags",
			roots: func(t *testing.T) (string, string) {
				_, results := createTestRootsOwnedByThisProcess(t, mountTestBindfs(t, bindfs))
				return plainRoot(t, "staging"), results
			},
			use:  "retain",
			want: "no-replace rename to a free result name is unavailable",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			staging, results := test.roots(t)
			probeErr, owner := probeTestRootsLikeStartup(t, staging, results)
			var useErr error
			switch test.use {
			case "stage":
				useErr = stageTestRunLikeSubmit(staging, results, owner)
			case "retain":
				if useErr = stageTestRunLikeSubmit(staging, results, owner); useErr != nil {
					t.Fatalf("staging failed on a staging root that works: %v", useErr)
				}
				useErr = retainTestResultLikeTerminalRun(t, staging, results)
			}
			t.Logf("startup probe: %v; use: %v", probeErr, useErr)
			if probeErr == nil || !strings.Contains(probeErr.Error(), test.want) {
				t.Fatalf("startup probe = %v, want a refusal that names %q", probeErr, test.want)
			}
			if useErr == nil {
				t.Fatalf("the probe refused a setup in which use works")
			}
		})
	}
}

// TestStartupProbeFileChecksRefuseAnOwnerTheFileSystemIgnores holds the owner
// check that follows the owner change of each file the startup probe creates
// (audit 16 of pull request #20, mutants F2 and R9). In a whole probe, the
// check of the probe directories refuses such a file system first, so the two
// file probes are called directly here, in a directory on a file system that
// accepts owner and group changes and ignores them.
func TestStartupProbeFileChecksRefuseAnOwnerTheFileSystemIgnores(t *testing.T) {
	bindfs := requireTestBindfs(t)
	requireTestMountPrivilege(t)
	owner := executionPlatformStateOwner{UID: 54321, GID: 54321}
	if os.Geteuid() != 0 {
		// The kernel passes a group change on to the file system only when
		// the file's owner names a group the owner is in.
		owner = executionPlatformStateOwner{UID: os.Getuid(), GID: -1}
		if groups, err := os.Getgroups(); err == nil {
			for _, group := range groups {
				if group != os.Getgid() {
					owner.GID = group
					break
				}
			}
		}
		if owner.GID == -1 {
			t.Skip("needs root or a supplementary group, so that the kernel passes the group change on to the file system")
		}
	}
	mount := mountTestBindfs(t, bindfs, "--chown-ignore", "--chgrp-ignore")
	backing := filepath.Join(filepath.Dir(mount), "backing")
	runTestPrivileged(t, "mkdir", filepath.Join(backing, "dir"))
	runTestPrivileged(t, "chown", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), filepath.Join(backing, "dir"))
	runTestPrivileged(t, "chmod", "0755", filepath.Join(backing, "dir"))
	directoryFD, err := unix.Open(filepath.Join(mount, "dir"), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(directoryFD)
	var directory unix.Stat_t
	if err := unix.Fstat(directoryFD, &directory); err != nil {
		t.Fatal(err)
	}
	device := uint64(directory.Dev)
	if err := probeStagedFile(directoryFD, stableStageFileMode, owner, device); err == nil || err.Error() != "staged file ownership is unavailable" {
		t.Fatalf("staged file probe = %v, want the owner check after the ignored owner change to refuse", err)
	}
	fd, err := probeRetainedResultFile(directoryFD, "bundle", retainedResultBundleFileMode, owner, device)
	if err == nil {
		_ = unix.Close(fd)
	}
	if err == nil || err.Error() != "retained result file ownership is unavailable" {
		t.Fatalf("retained result file probe = %v, want the owner check after the ignored owner change to refuse", err)
	}
}

// TestStartupRefusesStagingThatCannotHoldGovernedMountModes pins the choice
// made for audit finding A16-2 of pull request #20: the startup probe stages
// every mode a submission can need, including the 0755 directories and the
// 0644 and 0755 files that only governed mounts use, so ES refuses to start on
// a staging file system that cannot keep them, although submissions without
// governed mounts would work there. The fixture is a mount that drops the
// permission bits for others.
func TestStartupRefusesStagingThatCannotHoldGovernedMountModes(t *testing.T) {
	bindfs := requireTestBindfs(t)
	requireTestMountPrivilege(t)
	staging, _ := createTestRootsOwnedByThisProcess(t, mountTestBindfs(t, bindfs, "--perms=o-rwx"))
	results := filepath.Join(physicalTestTempDir(t), "results")
	if err := os.Mkdir(results, 0o755); err != nil {
		t.Fatal(err)
	}
	probeErr, owner := probeTestRootsLikeStartup(t, staging, results)
	if probeErr == nil || !strings.Contains(probeErr.Error(), "staged 0755 directory mode is unavailable") {
		t.Fatalf("startup probe = %v, want a refusal that names the 0755 directory mode governed mounts need", probeErr)
	}

	// What ES refuses to start on would still stage a submission without
	// governed mounts, and fail one with them.
	roots, err := qualifyExecutionRoots(staging, results, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := roots.reobserve(); err != nil {
		_ = roots.close()
		t.Fatal(err)
	}
	stagingRoot, err := roots.takeStagingQualifiedDirectory()
	if err != nil {
		_ = roots.close()
		t.Fatal(err)
	}
	custody, err := claimStagingCustodyFromQualifiedRoot(stagingRoot, "run-0123456789abcdef", owner)
	if closeErr := roots.close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if err != nil {
		t.Fatalf("claim run staging root: %v", err)
	}
	defer custody.close()
	layout := executionPackageLayout{}
	if err := layout.stagePayload(custody, []byte("payload")); err != nil {
		t.Fatalf("stage payload: %v", err)
	}
	if err := layout.stageCapturedRuntimeSupportBinary(custody, []byte("#!/bin/sh\n")); err != nil {
		t.Fatalf("stage runtime-support binary: %v", err)
	}
	if _, err := layout.stageWorkloadVaultTrustMaterial(custody, resolvedTrustMaterial{vaultCACertBytes: []byte("ca\n"), workloadTLSBundleBytes: []byte("bundle\n")}); err != nil {
		t.Fatalf("stage workload trust material: %v", err)
	}
	if err := custody.revalidateBeforeHandoff(); err != nil {
		t.Fatalf("revalidate a run without governed mounts: %v", err)
	}
	if err := custody.ensureDirectory(executionMountsStageDirName+"/00/contents", governedMountDirMode); err == nil {
		t.Fatal("staged a governed mount directory on a file system that cannot keep its mode")
	}
}

// mountTestSplitLayerOverlay mounts an overlay whose lower and upper layers
// are on two tmpfs file systems, without xino, and returns its mount point.
// Directories there report the overlay's device, regular files another one.
func mountTestSplitLayerOverlay(t *testing.T) string {
	t.Helper()
	parent := physicalTestTempDir(t)
	lower := filepath.Join(parent, "lower-fs")
	upper := filepath.Join(parent, "upper-fs")
	merged := filepath.Join(parent, "merged")
	for _, dir := range []string{lower, upper, merged} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	mountTestFileSystem(t, lower, "-t", "tmpfs", "tmpfs", lower)
	mountTestFileSystem(t, upper, "-t", "tmpfs", "tmpfs", upper)
	runTestPrivileged(t, "mkdir", filepath.Join(lower, "layer"), filepath.Join(upper, "layer"), filepath.Join(upper, "work"))
	options := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s,xino=off", filepath.Join(lower, "layer"), filepath.Join(upper, "layer"), filepath.Join(upper, "work"))
	mountTestFileSystem(t, merged, "-t", "overlay", "overlay", "-o", options, merged)
	return merged
}
