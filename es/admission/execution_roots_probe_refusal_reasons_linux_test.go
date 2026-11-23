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
