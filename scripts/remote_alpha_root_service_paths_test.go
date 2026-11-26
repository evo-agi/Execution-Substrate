package scripts_test

// Regression tests for the whole-trunk red-team's findings RT-1, RT-2 and
// RT-3 (2026-11-24): root scripts that acted by path on names a service
// account controls, so a link that account planted made root change another
// file. Each test plants that link and checks that the victim keeps its
// owner, mode and bytes. Run as an ordinary user, the service account is the
// user running the test, and a followed link still shows as a changed mode.
// Run as root, the service account is uid and gid 65534, so the tests also
// see owners change.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

type rootPathOwner struct {
	uid, gid int
}

// rootPathServiceOwner is the owner the scripts under test give to service
// paths: uid and gid 65534 as root, the user running the test otherwise.
func rootPathServiceOwner() rootPathOwner {
	if os.Geteuid() == 0 {
		return rootPathOwner{65534, 65534}
	}
	return rootPathOwner{os.Getuid(), os.Getgid()}
}

type rootPathState struct {
	uid, gid int
	mode     os.FileMode
	symlink  bool
	bytes    string
}

func rootPathStat(t *testing.T, path string) rootPathState {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat %s: %v", path, err)
	}
	sys := info.Sys().(*syscall.Stat_t)
	state := rootPathState{uid: int(sys.Uid), gid: int(sys.Gid), mode: info.Mode().Perm(), symlink: info.Mode()&os.ModeSymlink != 0}
	if info.Mode().IsRegular() {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		state.bytes = string(data)
	}
	return state
}

// rootPathOwnerName returns the name of the account that owns path, without
// following a link, as the stat of the host prints it: GNU stat takes -c and
// the stat of macOS takes -f.
func rootPathOwnerName(t *testing.T, path string) string {
	t.Helper()
	format := []string{"-c", "%U"}
	if runtime.GOOS == "darwin" {
		format = []string{"-f", "%Su"}
	}
	cmd := exec.Command("stat", append(format, path)...)
	cmd.Dir = executionSubstrateRepoRoot
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return strings.TrimSpace(string(out))
}

func rootPathChown(t *testing.T, owner rootPathOwner, paths ...string) {
	t.Helper()
	for _, path := range paths {
		if err := os.Lchown(path, owner.uid, owner.gid); err != nil {
			t.Fatalf("lchown %s: %v", path, err)
		}
	}
}

func rootPathChmod(t *testing.T, mode os.FileMode, paths ...string) {
	t.Helper()
	for _, path := range paths {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatalf("chmod %s: %v", path, err)
		}
	}
}

// arsStateFixture is an ARS state tree laid out as on the box: the state root
// directly under a parent the service account cannot change, with blobs/ and
// index.json directly under the state root, and a victim file and directory
// outside it.
type arsStateFixture struct {
	parent, state, blobs, blob, index, victim, victimDir, meta, fakeBin string
	owner                                                               rootPathOwner
}

func newARSStateFixture(t *testing.T) arsStateFixture {
	t.Helper()
	base := t.TempDir()
	f := arsStateFixture{
		parent:    filepath.Join(base, "lib"),
		victim:    filepath.Join(base, "victim"),
		victimDir: filepath.Join(base, "victim-dir"),
		meta:      filepath.Join(base, "runtime.json"),
		fakeBin:   filepath.Join(base, "bin"),
		owner:     rootPathServiceOwner(),
	}
	f.state = filepath.Join(f.parent, "ars")
	f.blobs = filepath.Join(f.state, "blobs")
	f.index = filepath.Join(f.state, "index.json")
	blobDir := filepath.Join(f.blobs, "sha256", "ab", "cd")
	f.blob = filepath.Join(blobDir, "sha256:abcd")
	for _, dir := range []string{blobDir, f.victimDir, f.fakeBin} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	for path, content := range map[string]string{f.blob: "blob\n", f.index: "{}\n", f.victim: "victim\n"} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	rootPathChmod(t, 0o755, f.parent, f.state, f.blobs)
	rootPathChmod(t, 0o640, f.victim)
	rootPathChmod(t, 0o711, f.victimDir)
	// The tree as the first hardening run leaves it: owned by the service
	// account.
	if err := filepath.Walk(f.state, func(path string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(path, f.owner.uid, f.owner.gid)
	}); err != nil {
		t.Fatalf("chown state tree: %v", err)
	}
	meta := fmt.Sprintf(`{"storage": {"state_root_dir": %q, "root_dir": %q, "index_file": %q}}`, f.state, f.blobs, f.index)
	if err := os.WriteFile(f.meta, []byte(meta), 0o600); err != nil {
		t.Fatalf("write runtime metadata: %v", err)
	}
	writeExecutable(t, f.fakeBin, "id", fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = -u ] && [ \"$2\" = ars ]; then echo %d; exit 0; fi\nexec /usr/bin/id \"$@\"\n", f.owner.uid))
	writeExecutable(t, f.fakeBin, "getent", fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = group ] && [ \"$2\" = ars ]; then echo ars:x:%d:; exit 0; fi\nexit 2\n", f.owner.gid))
	return f
}

func (f arsStateFixture) run(t *testing.T) (string, error) {
	t.Helper()
	body := fmt.Sprintf("REMOTE_ALPHA_SERVICE_USER=ars\nREMOTE_ALPHA_SERVICE_GROUP=ars\nremote_alpha_ars_hardening_apply_state_permissions %q", f.meta)
	output, err := runSourcedARSHardeningHelper(t, envWithPath(f.fakeBin), body)
	return string(output), err
}

// RT-1: a rerun of the ARS hardening step must not follow a link the ARS
// account put in its own state tree, and a refused tree stays as it was.
func TestRemoteAlphaARSHardeningStateStepNeverFollowsLinks(t *testing.T) {
	t.Parallel()

	refusals := []struct {
		name    string
		plant   func(t *testing.T, f arsStateFixture)
		message string
	}{
		{"index file is a link to a root file", func(t *testing.T, f arsStateFixture) {
			replaceWithSymlink(t, f.victim, f.index)
		}, "index.json is missing, is not a regular file or is a symbolic link"},
		{"blob directory is a link to a root directory", func(t *testing.T, f arsStateFixture) {
			if err := os.Rename(f.blobs, f.blobs+".moved"); err != nil {
				t.Fatal(err)
			}
			replaceWithSymlink(t, f.victimDir, f.blobs)
		}, "blobs is not a directory or is a symbolic link"},
		{"link deeper in the tree", func(t *testing.T, f arsStateFixture) {
			replaceWithSymlink(t, f.victim, filepath.Join(f.blobs, "sha256", "planted"))
		}, "sha256/planted is not a directory or a regular file"},
		{"index file is a hard link to another file", func(t *testing.T, f arsStateFixture) {
			if err := os.Remove(f.index); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(f.victim, f.index); err != nil {
				t.Fatal(err)
			}
		}, "index.json must be a regular file with one link"},
		{"blob is a hard link to another file", func(t *testing.T, f arsStateFixture) {
			if err := os.Link(f.victim, filepath.Join(f.blobs, "sha256", "ab", "linked")); err != nil {
				t.Fatal(err)
			}
		}, "sha256/ab/linked must be a regular file with one link"},
		{"named pipe in the tree", func(t *testing.T, f arsStateFixture) {
			if err := syscall.Mkfifo(filepath.Join(f.blobs, "pipe"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "blobs/pipe is not a directory or a regular file"},
		{"state root is a link", func(t *testing.T, f arsStateFixture) {
			if err := os.Rename(f.state, f.state+".moved"); err != nil {
				t.Fatal(err)
			}
			replaceWithSymlink(t, f.victimDir, f.state)
		}, "ars is not a directory or is a symbolic link"},
		{"tree deeper than 16 directories", func(t *testing.T, f arsStateFixture) {
			deep := f.blobs
			for i := 0; i < 17; i++ {
				deep = filepath.Join(deep, "d")
			}
			if err := os.MkdirAll(deep, 0o755); err != nil {
				t.Fatal(err)
			}
		}, "is more than 16 directories below the state root"},
		{"parent writable by its group", func(t *testing.T, f arsStateFixture) {
			rootPathChmod(t, 0o775, f.parent)
		}, "must belong to the user running this step and must not be writable by group or others"},
	}
	for _, tc := range refusals {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newARSStateFixture(t)
			tc.plant(t, f)
			victim, victimDir := rootPathStat(t, f.victim), rootPathStat(t, f.victimDir)
			state := rootPathStat(t, f.state)
			output, err := f.run(t)
			if err == nil {
				t.Fatalf("the state step accepted a tree with %s:\n%s", tc.name, output)
			}
			if !strings.Contains(output, tc.message) || !strings.Contains(output, "stopped without changing it") {
				t.Fatalf("refusal does not say %q:\n%s", tc.message, output)
			}
			if got := rootPathStat(t, f.victim); got != victim {
				t.Fatalf("victim file changed from %+v to %+v", victim, got)
			}
			if got := rootPathStat(t, f.victimDir); got != victimDir {
				t.Fatalf("victim directory changed from %+v to %+v", victimDir, got)
			}
			// The first walk only checks, so a refused tree keeps its modes.
			if got := rootPathStat(t, f.state); got != state {
				t.Fatalf("refused state root changed from %+v to %+v", state, got)
			}
		})
	}

	for _, firstRun := range []bool{true, false} {
		firstRun := firstRun
		name := "rerun on a tree the service account owns"
		if firstRun {
			name = "first run on a tree the running user owns"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newARSStateFixture(t)
			if firstRun {
				self := rootPathOwner{os.Geteuid(), os.Getegid()}
				rootPathChown(t, self, f.state, f.blobs, filepath.Join(f.blobs, "sha256"), f.blob, f.index)
			} else {
				rootPathChmod(t, 0o750, f.state, f.blobs)
				rootPathChmod(t, 0o600, f.index)
			}
			victim := rootPathStat(t, f.victim)
			if output, err := f.run(t); err != nil {
				t.Fatalf("the state step failed on a clean tree: %v\n%s", err, output)
			}
			for path, mode := range map[string]os.FileMode{f.state: 0o750, f.blobs: 0o750, f.index: 0o600, f.blob: 0o644} {
				got := rootPathStat(t, path)
				if got.uid != f.owner.uid || got.gid != f.owner.gid || got.mode != mode || got.symlink {
					t.Fatalf("%s is %d:%d %o, want %d:%d %o", path, got.uid, got.gid, got.mode, f.owner.uid, f.owner.gid, mode)
				}
			}
			if got := rootPathStat(t, f.victim); got != victim {
				t.Fatalf("victim file changed from %+v to %+v", victim, got)
			}
		})
	}
}

func replaceWithSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.RemoveAll(link); err != nil {
		t.Fatalf("remove %s: %v", link, err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink %s: %v", link, err)
	}
}

// vaultResetShell sources the reset helper with sudo, systemctl and pgrep as
// stand-ins (sudo runs the command as the test user; pgrep reports what the
// test asks), then runs body.
func vaultResetShell(t *testing.T, pgrepFinds bool, body string) (string, error) {
	t.Helper()
	pgrep := "pgrep() { return 1; }"
	if pgrepFinds {
		pgrep = "pgrep() { return 0; }"
	}
	script := fmt.Sprintf("source %q\nsudo() { \"$@\"; }\nsystemctl() { :; }\n%s\nSERVICE_NAME=vault\n%s\n",
		filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_reset_disposable_vault.sh"), pgrep, body)
	cmd := exec.Command("/bin/bash", "-c", script)
	cmd.Dir = executionSubstrateRepoRoot
	output, err := cmd.CombinedOutput()
	return string(output), err
}

type vaultRaftFixture struct {
	base, raft, backup, victim, victimProgram string
	owner                                     rootPathOwner
}

func newVaultRaftFixture(t *testing.T) vaultRaftFixture {
	t.Helper()
	dir := t.TempDir()
	f := vaultRaftFixture{
		base:   filepath.Join(dir, "opt-vault"),
		victim: filepath.Join(dir, "victim-bin"),
		owner:  rootPathServiceOwner(),
	}
	f.raft = filepath.Join(f.base, "raft")
	f.backup = f.raft + ".remote-alpha-reset-backup-test"
	f.victimProgram = filepath.Join(f.victim, "es")
	for _, d := range []string{f.raft, f.victim} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(f.victimProgram, []byte("#!/bin/sh\necho the real program\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	rootPathChmod(t, 0o755, f.base, f.victim)
	rootPathChmod(t, 0o700, f.raft)
	// As on the box: /opt/vault and its raft directory belong to the Vault
	// account, the victim to root.
	rootPathChown(t, f.owner, f.base, f.raft)
	return f
}

func (f vaultRaftFixture) replace(t *testing.T, pgrepFinds bool) (string, error) {
	t.Helper()
	return vaultResetShell(t, pgrepFinds, fmt.Sprintf("VAULT_RAFT_PATH=%q\nreplace_raft_directory %d %d %q", f.raft, f.owner.uid, f.owner.gid, f.backup))
}

// RT-2: a process still running as the Vault account races root for the raft
// path between the move and the recreation, 20 times. It must never get the
// victim directory, whoever wins the name.
func TestRemoteAlphaResetDisposableVaultNeverHandsOverAPlantedRaftLink(t *testing.T) {
	t.Parallel()
	const trials = 20
	planted := 0
	for i := 0; i < trials; i++ {
		f := newVaultRaftFixture(t)
		victim, program := rootPathStat(t, f.victim), rootPathStat(t, f.victimProgram)
		stop := make(chan struct{})
		won := make(chan bool, 1)
		go func() {
			for {
				select {
				case <-stop:
					won <- false
					return
				default:
				}
				if os.Symlink(f.victim, f.raft) == nil {
					won <- true
					return
				}
			}
		}()
		output, err := f.replace(t, false)
		close(stop)
		attackerWon := <-won
		if got := rootPathStat(t, f.victim); got != victim {
			t.Fatalf("trial %d: the victim directory changed from %+v to %+v\n%s", i, victim, got, output)
		}
		if got := rootPathStat(t, f.victimProgram); got != program {
			t.Fatalf("trial %d: the victim program changed from %+v to %+v", i, program, got)
		}
		if _, statErr := os.Stat(f.backup); statErr != nil {
			t.Fatalf("trial %d: the old raft directory is not at the backup path: %v\n%s", i, statErr, output)
		}
		if attackerWon {
			planted++
			if err == nil || !strings.Contains(output, "something created "+f.raft+" after the move") {
				t.Fatalf("trial %d: the reset did not stop at the planted link: %v\n%s", i, err, output)
			}
			// The old directory has moved by then, so the reset must say where
			// it is, not that nothing was moved.
			if !strings.Contains(output, "was not recreated after the move; the old data is in "+f.backup) || strings.Contains(output, "nothing was moved") {
				t.Fatalf("trial %d: the reset did not report that the old raft directory moved to the backup:\n%s", i, output)
			}
			continue
		}
		if err != nil {
			t.Fatalf("trial %d: the reset failed without a planted link: %v\n%s", i, err, output)
		}
		got := rootPathStat(t, f.raft)
		if got.symlink || got.uid != f.owner.uid || got.gid != f.owner.gid || got.mode != 0o700 {
			t.Fatalf("trial %d: the new raft directory is %+v", i, got)
		}
	}
	t.Logf("the racing process planted its link in %d of %d trials", planted, trials)
	if planted == 0 {
		t.Fatalf("the racing process never planted its link in %d trials, so the race was not exercised", trials)
	}
}

// RT-2: the reset moves nothing while a process still runs as the Vault
// account after the stop, and moves only a real directory that already
// belongs to that account.
func TestRemoteAlphaResetDisposableVaultRefusesUnsafeRaftStates(t *testing.T) {
	t.Parallel()

	t.Run("a process survives the stop", func(t *testing.T) {
		t.Parallel()
		f := newVaultRaftFixture(t)
		output, err := f.replace(t, true)
		if err == nil || !strings.Contains(output, "processes still run as") || !strings.Contains(output, "nothing was moved") {
			t.Fatalf("the reset went on with a surviving process: %v\n%s", err, output)
		}
		if got := rootPathStat(t, f.raft); got.symlink || got.mode != 0o700 {
			t.Fatalf("the raft directory changed: %+v", got)
		}
		if _, statErr := os.Lstat(f.backup); !os.IsNotExist(statErr) {
			t.Fatalf("a backup exists although nothing should have moved: %v", statErr)
		}
	})

	t.Run("raft directory of another owner when the move starts", func(t *testing.T) {
		t.Parallel()
		f := newVaultRaftFixture(t)
		// The step checks the owner again on the descriptor it moves from,
		// whatever the check before the confirmation saw.
		output, err := vaultResetShell(t, false, fmt.Sprintf("VAULT_RAFT_PATH=%q\nreplace_raft_directory %d %d %q", f.raft, f.owner.uid+1, f.owner.gid, f.backup))
		if err == nil || !strings.Contains(output, "is no longer a directory of the Vault service user") || !strings.Contains(output, "nothing was moved") {
			t.Fatalf("the reset moved a raft directory of another owner: %v\n%s", err, output)
		}
		if got := rootPathStat(t, f.raft); got.symlink || got.uid != f.owner.uid || got.mode != 0o700 {
			t.Fatalf("the raft directory changed: %+v", got)
		}
		if _, statErr := os.Lstat(f.backup); !os.IsNotExist(statErr) {
			t.Fatalf("a backup exists although nothing should have moved: %v", statErr)
		}
	})

	check := func(t *testing.T, path, user string) (string, error) {
		return vaultResetShell(t, false, fmt.Sprintf("require_vault_owned_raft_dir %q %q && echo accepted", path, user))
	}
	t.Run("raft directory of the Vault account", func(t *testing.T) {
		t.Parallel()
		f := newVaultRaftFixture(t)
		if output, err := check(t, f.raft, rootPathOwnerName(t, f.raft)); err != nil || !strings.Contains(output, "accepted") {
			t.Fatalf("a raft directory of the Vault account was refused: %v\n%s", err, output)
		}
	})
	t.Run("raft path of another owner", func(t *testing.T) {
		t.Parallel()
		f := newVaultRaftFixture(t)
		output, err := check(t, f.victim, "vault-account-under-test")
		if err == nil || !strings.Contains(output, "not to the Vault service user vault-account-under-test; refusing to move it") {
			t.Fatalf("a raft path of another owner was accepted: %v\n%s", err, output)
		}
	})
	t.Run("raft path is a link", func(t *testing.T) {
		t.Parallel()
		f := newVaultRaftFixture(t)
		replaceWithSymlink(t, f.victim, f.raft)
		output, err := check(t, f.raft, rootPathOwnerName(t, f.victim))
		if err == nil || !strings.Contains(output, "Vault raft path is a symbolic link") {
			t.Fatalf("a raft path that is a link was accepted: %v\n%s", err, output)
		}
	})
}

// vaultMigrationFixture is the Vault service-user migration fixture laid out
// as on the box: the Vault directory and everything in it belong to the Vault
// account (uid and gid 65534 as root), and a victim file and directory belong
// to the user running the test.
type vaultMigrationFixture struct {
	vaultServiceUserMigrationFixture
	fakeBin, vaultDir, preflight, summary, mutations string
	victim, victimDir, foreignDir                    string
	owner                                            rootPathOwner
}

func newVaultMigrationFixture(t *testing.T) vaultMigrationFixture {
	t.Helper()
	dir := t.TempDir()
	f := vaultMigrationFixture{
		fakeBin:   filepath.Join(dir, "bin"),
		vaultDir:  filepath.Join(dir, "vault"),
		preflight: filepath.Join(dir, "check-only.json"),
		summary:   filepath.Join(dir, "apply-summary.json"),
		mutations: filepath.Join(dir, "mutations.log"),
		victim:    filepath.Join(dir, "victim", "secret"),
		victimDir: filepath.Join(dir, "victim-dir"),
		owner:     rootPathServiceOwner(),
	}
	f.vaultServiceUserMigrationFixture = setupVaultServiceUserMigrationFixture(t, dir)
	for _, d := range []string{f.fakeBin, filepath.Dir(f.victim), f.victimDir, filepath.Join(f.StorageDir, "raft")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for path, content := range map[string]string{
		f.victim:                                "the victim's bytes\n",
		filepath.Join(f.StorageDir, "vault.db"): "vault db\n",
		filepath.Join(f.StorageDir, "raft", "raft.db"): "raft db\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rootPathChmod(t, 0o711, f.victimDir)
	// A directory that is not dedicated to Vault: one root owns, as root;
	// /usr/share otherwise, which the test user cannot change either way.
	f.foreignDir = "/usr/share"
	if os.Geteuid() == 0 {
		f.foreignDir = filepath.Join(dir, "shared")
		if err := os.MkdirAll(f.foreignDir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	setupFakeVaultServiceUserMigrationCommands(t, f.fakeBin, fakeVaultServiceUserAccount{
		Present: true, UID: f.owner.uid, GID: f.owner.gid, GroupName: "vault",
	}, f.vaultServiceUserMigrationFixture, f.mutations)
	// The real chown and chmod stay in PATH, so a return to changes by path
	// would show on the victim rather than vanish into a stand-in.
	for _, name := range []string{"chown", "chmod"} {
		if err := os.Remove(filepath.Join(f.fakeBin, name)); err != nil {
			t.Fatal(err)
		}
	}
	// As on the box: /etc/vault.d and /opt/vault belong to the Vault account.
	if err := filepath.Walk(f.vaultDir, func(path string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(path, f.owner.uid, f.owner.gid)
	}); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f vaultMigrationFixture) run(t *testing.T, args string) (string, error) {
	t.Helper()
	output, err := runSourcedVaultServiceUserMigrationHelper(t, envWithPath(f.fakeBin, "REMOTE_ALPHA_TEST_MUTATION_LOG_PATH="+f.mutations),
		"remote_alpha_migrate_vault_service_user_main "+args)
	return string(output), err
}

// checkOnly writes the preflight the apply step reuses and returns it.
func (f vaultMigrationFixture) checkOnly(t *testing.T) map[string]any {
	t.Helper()
	// A blocked plan exits 1 and still writes its summary, which callers read.
	output, _ := f.run(t, fmt.Sprintf("--summary-path %q --es-config-path %q --healthcheck-env-path %q", f.preflight, f.ESConfigPath, f.HealthEnvPath))
	summary := readJSONFile(t, f.preflight)
	if summary == nil {
		t.Fatalf("check-only wrote no summary\n%s", output)
	}
	return summary
}

func (f vaultMigrationFixture) apply(t *testing.T) (map[string]any, string, error) {
	t.Helper()
	output, err := f.run(t, fmt.Sprintf("--apply --summary-path %q --preflight-path %q --backup-root-dir %q --es-config-path %q --healthcheck-env-path %q",
		f.summary, f.preflight, f.BackupRootDir, f.ESConfigPath, f.HealthEnvPath))
	return readJSONFile(t, f.summary), output, err
}

func (f vaultMigrationFixture) mustBeReady(t *testing.T) {
	t.Helper()
	plan := nestedMap(t, f.checkOnly(t), "plan")
	if plan["apply_ready"] != true {
		t.Fatalf("the fixture's plan is not ready: %s", mustRead(t, f.preflight))
	}
}

func (f vaultMigrationFixture) editVaultConfig(t *testing.T, edit func(config map[string]any)) {
	t.Helper()
	config := readJSONFile(t, f.VaultConfigPath)
	edit(config)
	writeJSONFile(t, f.VaultConfigPath, config)
}

// RT-3: a name the Vault account swaps for a link after the plan must not
// make root change the link's target. Each case plans, plants, applies, and
// checks that the apply refused before changing anything and that the victim
// file and directory kept their owner, mode and bytes.
func TestRemoteAlphaVaultServiceUserMigrationApplyNeverFollowsPlantedLinks(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, refusal string
		plant         func(t *testing.T, f vaultMigrationFixture)
	}{
		{"config file is a link", "Vault config: ", func(t *testing.T, f vaultMigrationFixture) {
			replaceWithSymlink(t, f.victim, f.VaultConfigPath)
		}},
		{"TLS file is a link", "is not a regular file or is a symbolic link", func(t *testing.T, f vaultMigrationFixture) {
			replaceWithSymlink(t, f.victim, filepath.Join(f.TLSDir, "vault-server-key.pem"))
		}},
		{"TLS directory is a link", "Vault listener TLS path parent directory: ", func(t *testing.T, f vaultMigrationFixture) {
			replaceWithSymlink(t, f.victimDir, f.TLSDir)
		}},
		{"log file is a link", "Vault log file: ", func(t *testing.T, f vaultMigrationFixture) {
			replaceWithSymlink(t, f.victim, f.LogPath)
		}},
		{"audit directory is a link", "Vault audit file parent directory: ", func(t *testing.T, f vaultMigrationFixture) {
			replaceWithSymlink(t, f.victimDir, f.AuditDir)
		}},
		{"storage directory is a link", "is not a directory or is a symbolic link", func(t *testing.T, f vaultMigrationFixture) {
			replaceWithSymlink(t, f.victimDir, f.StorageDir)
		}},
		{"link inside the storage directory", "is not a directory or a regular file", func(t *testing.T, f vaultMigrationFixture) {
			if err := os.Symlink(f.victim, filepath.Join(f.StorageDir, "raft", "snapshot")); err != nil {
				t.Fatal(err)
			}
		}},
		{"hard link inside the storage directory", "must be a regular file with one link", func(t *testing.T, f vaultMigrationFixture) {
			if err := os.Link(f.victim, filepath.Join(f.StorageDir, "raft", "snapshot")); err != nil {
				t.Fatal(err)
			}
		}},
		{"fifo inside the storage directory", "is not a directory or a regular file", func(t *testing.T, f vaultMigrationFixture) {
			if err := syscall.Mkfifo(filepath.Join(f.StorageDir, "raft", "fifo"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"preflight names a directory not dedicated to Vault", "is not dedicated to Vault", func(t *testing.T, f vaultMigrationFixture) {
			preflight := readJSONFile(t, f.preflight)
			logAccess := nestedMap(t, nestedMap(t, preflight, "validation"), "log_access")
			logAccess["path"] = filepath.Join(f.foreignDir, "vault-rt3-test.log")
			logAccess["apply_adjustment_required"] = true
			writeJSONFile(t, f.preflight, preflight)
		}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newVaultMigrationFixture(t)
			f.mustBeReady(t)
			victim, victimDir, foreign := rootPathStat(t, f.victim), rootPathStat(t, f.victimDir), rootPathStat(t, f.foreignDir)
			tc.plant(t, f)
			summary, output, err := f.apply(t)
			if got := rootPathStat(t, f.victim); got.uid != victim.uid || got.gid != victim.gid || got.mode != victim.mode || got.bytes != victim.bytes {
				t.Errorf("the victim file changed from %+v to %+v", victim, got)
			}
			if got := rootPathStat(t, f.victimDir); got != victimDir {
				t.Errorf("the victim directory changed from %+v to %+v", victimDir, got)
			}
			if got := rootPathStat(t, f.foreignDir); got != foreign {
				t.Errorf("%s changed from %+v to %+v", f.foreignDir, foreign, got)
			}
			result := nestedMap(t, summary, "result")
			text := fmt.Sprint(result["summary"])
			if err == nil || result["ok"] != false || !strings.Contains(text, tc.refusal) || !strings.Contains(text, "no path was changed") {
				t.Fatalf("the apply did not refuse before changing anything: %v\nresult=%+v\n%s", err, result, output)
			}
			if _, statErr := os.Lstat(f.ServiceDropInPath); !os.IsNotExist(statErr) {
				t.Fatalf("the Vault drop-in was installed although the path step refused: %v", statErr)
			}
			if log, _ := os.ReadFile(f.mutations); strings.Contains(string(log), "systemctl restart") {
				t.Fatalf("Vault restarted although the path step refused:\n%s", log)
			}
		})
	}
}

// RT-3: the plan itself refuses paths the apply step must never change: a log
// or audit file in a shared or foreign directory, a storage directory outside
// Vault's own, a path through a link, and a directory that would need two
// owners.
func TestRemoteAlphaVaultServiceUserMigrationPlanRefusesPathsOutsideVault(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, blocker, summary string
		edit                   func(f vaultMigrationFixture, config map[string]any)
	}{
		{"log file in a shared system directory", "log_access", "/var/log is a shared system directory", func(f vaultMigrationFixture, config map[string]any) {
			config["log_file"] = "/var/log/vault-rt3-test.log"
		}},
		{"audit file in a directory not dedicated to Vault", "audit_access", "is not dedicated to Vault", func(f vaultMigrationFixture, config map[string]any) {
			config["audit"] = []map[string]any{{"type": "file", "path": filepath.Join(f.foreignDir, "vault-rt3-audit.log")}}
		}},
		{"storage directory outside Vault's own", "storage_access", "and its parent", func(f vaultMigrationFixture, config map[string]any) {
			storage := f.foreignDir
			if os.Geteuid() == 0 {
				storage = filepath.Join(f.foreignDir, "data")
				if err := os.MkdirAll(storage, 0o755); err != nil {
					panic(err)
				}
			}
			config["storage"] = []map[string]any{{"type": "raft", "path": storage}}
		}},
		{"TLS path through a link", "tls_read_paths", "goes through the symbolic link", func(f vaultMigrationFixture, config map[string]any) {
			link := filepath.Join(f.vaultDir, "tls-link")
			if err := os.Symlink(f.TLSDir, link); err != nil {
				panic(err)
			}
			listener := config["listener"].([]any)[0].(map[string]any)
			listener["tls_key_file"] = filepath.Join(link, "vault-server-key.pem")
		}},
		{"log file next to the config", "path_ownership_conflict", "would have to belong to both", func(f vaultMigrationFixture, config map[string]any) {
			config["log_file"] = filepath.Join(f.vaultDir, "vault.log")
		}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newVaultMigrationFixture(t)
			f.editVaultConfig(t, func(config map[string]any) { tc.edit(f, config) })
			summary := f.checkOnly(t)
			if nestedMap(t, summary, "plan")["apply_ready"] != false {
				t.Fatalf("the plan accepted it: %s", mustRead(t, f.preflight))
			}
			found := false
			for _, raw := range summary["blockers"].([]any) {
				blocker := jsonMap(t, raw)
				if blocker["name"] == tc.blocker && strings.Contains(fmt.Sprint(blocker["summary"]), tc.summary) {
					found = true
				}
			}
			if !found {
				t.Fatalf("no %s blocker mentioning %q: %+v", tc.blocker, tc.summary, summary["blockers"])
			}
		})
	}
}

// RT-3: with nothing planted, the apply step leaves the config and TLS files
// root:vault 0640 in root:vault 0750 directories, and gives the storage tree,
// the log and audit files and their directories to the Vault account.
func TestRemoteAlphaVaultServiceUserMigrationApplySetsVaultPathOwners(t *testing.T) {
	t.Parallel()
	f := newVaultMigrationFixture(t)
	if os.Geteuid() == 0 {
		// As when Vault ran as root: its storage files belong to root.
		rootPathChown(t, rootPathOwner{0, 0}, filepath.Join(f.StorageDir, "vault.db"), filepath.Join(f.StorageDir, "raft", "raft.db"))
	}
	f.mustBeReady(t)
	summary, output, err := f.apply(t)
	if err != nil || nestedMap(t, summary, "result")["ok"] != true {
		t.Fatalf("the apply failed: %v\nresult=%+v\n%s", err, nestedMap(t, summary, "result"), output)
	}
	rootRead := rootPathOwner{os.Geteuid(), f.owner.gid}
	expect := func(path string, owner rootPathOwner, mode os.FileMode) {
		t.Helper()
		if got := rootPathStat(t, path); got.symlink || got.uid != owner.uid || got.gid != owner.gid || got.mode != mode {
			t.Errorf("%s is %+v, want %d:%d %o", path, got, owner.uid, owner.gid, mode)
		}
	}
	expect(f.vaultDir, rootRead, 0o750)
	expect(f.VaultConfigPath, rootRead, 0o640)
	expect(f.TLSDir, rootRead, 0o750)
	for _, name := range []string{"vault-server-cert.pem", "vault-server-key.pem", "vault-client-ca.pem"} {
		expect(filepath.Join(f.TLSDir, name), rootRead, 0o640)
	}
	expect(f.StorageDir, f.owner, 0o750)
	expect(filepath.Join(f.StorageDir, "vault.db"), f.owner, 0o600)
	expect(filepath.Join(f.StorageDir, "raft"), f.owner, 0o755)
	expect(filepath.Join(f.StorageDir, "raft", "raft.db"), f.owner, 0o600)
	expect(f.LogDir, f.owner, 0o750)
	expect(f.LogPath, f.owner, 0o640)
	expect(f.AuditDir, f.owner, 0o750)
	expect(f.AuditPath, f.owner, 0o640)
	if log := mustRead(t, f.mutations); !strings.Contains(log, "systemctl restart vault.service") {
		t.Fatalf("Vault did not restart after a clean apply:\n%s", log)
	}
}

// RT-3: the Vault account keeps swapping a TLS file for a link to the victim
// while the apply runs, 20 times. Root must never change the victim, whether
// the apply sees the file or the link.
func TestRemoteAlphaVaultServiceUserMigrationApplyNeverFollowsARacingLink(t *testing.T) {
	t.Parallel()
	const trials = 20
	refused := 0
	for i := 0; i < trials; i++ {
		f := newVaultMigrationFixture(t)
		f.mustBeReady(t)
		victim := rootPathStat(t, f.victim)
		key := filepath.Join(f.TLSDir, "vault-server-key.pem")
		stop := make(chan struct{})
		done := make(chan struct{})
		go func() {
			defer close(done)
			link, real := key+".link", key+".real"
			for n := 0; ; n++ {
				select {
				case <-stop:
					_ = os.WriteFile(real, []byte("key\n"), 0o600)
					_ = os.Rename(real, key)
					return
				default:
				}
				_ = os.Remove(link)
				if os.Symlink(f.victim, link) == nil {
					_ = os.Rename(link, key)
				}
				if os.WriteFile(real, []byte("key\n"), 0o600) == nil {
					_ = os.Rename(real, key)
				}
			}
		}()
		summary, output, err := f.apply(t)
		close(stop)
		<-done
		if got := rootPathStat(t, f.victim); got.uid != victim.uid || got.gid != victim.gid || got.mode != victim.mode || got.bytes != victim.bytes {
			t.Fatalf("trial %d: the victim changed from %+v to %+v\n%s", i, victim, got, output)
		}
		if err != nil {
			text := fmt.Sprint(nestedMap(t, summary, "result")["summary"])
			if !strings.Contains(text, "vault-server-key.pem") {
				t.Fatalf("trial %d: the apply failed for another reason: %v\n%s\n%s", i, err, text, output)
			}
			refused++
		}
	}
	t.Logf("the apply met the racing link and refused in %d of %d trials", refused, trials)
	if refused == 0 {
		t.Fatalf("the apply never met the racing link in %d trials, so the race was not exercised", trials)
	}
}

// byPathOwnershipChange matches a line that changes an owner or mode by name,
// which follows a link someone else planted: chown, chmod (os.chmod and
// pathlib's .chmod included), and install -d. fchown, fchmod and lchown do
// not match.
var byPathOwnershipChange = regexp.MustCompile(`(?:^|[^A-Za-z_])(?:chown|chmod)(?:[^A-Za-z_]|$)|(?:^|[^A-Za-z_])install\b[^#\n]*\s-[A-Za-z]*d\b|"install",\s*"-d"`)

func byPathOwnershipChangeLines(source string) []string {
	var lines []string
	for _, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if byPathOwnershipChange.MatchString(trimmed) {
			lines = append(lines, trimmed)
		}
	}
	return lines
}

// byPathOwnershipChangeAllowance is the number of lines in each shell script
// under scripts/ that change an owner or mode by name, as of the red-team
// fixes (RT-1 to RT-3, 2026-11-24). Most run as root in folders only root
// can change, or on the operator's own files. A new one must not act in a
// folder a service account owns: open it without following links (see
// remote_alpha_harden_ars_service.sh or
// remote_alpha_migrate_vault_service_user.sh) or show the whole path is
// root's, and then raise the count here. When a count falls, lower it.
//
// remote_alpha_host_firewall.sh came with #35 and was checked at the #49
// sync: it runs as root only, in /etc/execution-substrate/host-firewall,
// /var/lib/es-host-firewall and /etc/systemd/system, which only root can
// change, and one of its seven lines is the text of a refusal.
//
// 70_linux_setup.sh's three lines for Nomad's TLS material came with the
// Nomad lock's part 2b. install -d makes /etc/nomad.d/tls root:root 0755
// inside /etc/nomad.d, which setup makes root:root 0755 before, and removes
// a link at /etc/nomad.d/tls before (Nomad's package gives /etc/nomad.d to
// the nomad account on every install or upgrade; audit 46, P46-1). In
// nomad_tls_issue, which runs as root on a host, one line makes the
// destination folder 0755 (setup's /etc/nomad.d/tls, or the same folder
// when remote_alpha_upgrade_es.py creates it after checking that
// /etc/nomad.d is root:root 0755 and that the folder does not exist yet),
// and the other sets the modes of the new files inside the caller's own
// mktemp -d folder (0700), which no one else can enter. Audit 46 (P46-1)
// took out its two lines that re-owned and re-moded nomad.hcl by name, which
// followed a link there: the file is now created root:root 0640 under a
// temporary name and renamed into place.
//
// remote_alpha_upgrade_es.sh's two lines came with RT60-2's wrapper check
// (ES PR #63, audit 31). Both are the text of its refusals, which tell the
// operator how to hand the clone over; the wrapper changes no owner or mode.
var byPathOwnershipChangeAllowance = map[string]int{
	"scripts/01_bringup.sh":                                           1,
	"scripts/70_linux_setup.sh":                                       9,
	"scripts/72_supported_local_setup.sh":                             7,
	"scripts/73_supported_local_proof.sh":                             1,
	"scripts/internal/control_plane.sh":                               3,
	"scripts/internal/nomad_acl.sh":                                   1,
	"scripts/internal/remote_alpha_deploy_es_binaries.sh":             14,
	"scripts/internal/remote_alpha_es_service_tls_renew.sh":           7,
	"scripts/internal/remote_alpha_harden_ags_service.sh":             10,
	"scripts/internal/remote_alpha_harden_ars_service.sh":             10,
	"scripts/internal/remote_alpha_harden_egs_service.sh":             10,
	"scripts/internal/remote_alpha_host_firewall.sh":                  7,
	"scripts/internal/remote_alpha_migrate_vault_service_user.sh":     2,
	"scripts/internal/remote_alpha_operator_healthcheck_tls_renew.sh": 1,
	"scripts/internal/remote_alpha_prepare_es_config_tls.sh":          9,
	"scripts/internal/remote_alpha_stage_es_config_tls_prep.sh":       3,
	"scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh":  1,
	"scripts/internal/remote_alpha_vault_workload_auth_check.sh":      2,
	"scripts/nomad_acl_setup.sh":                                      1,
	"scripts/remote_alpha_operator.sh":                                10,
	"scripts/remote_alpha_runtime_identity_helper_summary.sh":         2,
	"scripts/remote_alpha_upgrade_es.sh":                              2,
}

// Red-team section 9 item 5: a source guard. Scripts may not add by-name
// owner or mode changes without someone raising the count above.
func TestRootScriptByNameOwnershipChangesStayCounted(t *testing.T) {
	t.Parallel()
	got := map[string]int{}
	root := filepath.Join(executionSubstrateRepoRoot, "scripts")
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".sh") {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if n := len(byPathOwnershipChangeLines(string(data))); n > 0 {
			rel, _ := filepath.Rel(executionSubstrateRepoRoot, path)
			got[filepath.ToSlash(rel)] = n
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for script, n := range got {
		if allowed := byPathOwnershipChangeAllowance[script]; n > allowed {
			t.Errorf("%s has %d lines that change an owner or mode by name, %d allowed; act through descriptors opened without following links, or raise the count in byPathOwnershipChangeAllowance with the reason the path is root's all the way", script, n, allowed)
		}
	}
	for script, allowed := range byPathOwnershipChangeAllowance {
		if got[script] < allowed {
			t.Errorf("%s now has %d lines that change an owner or mode by name; lower its count in byPathOwnershipChangeAllowance from %d", script, got[script], allowed)
		}
	}
	if t.Failed() {
		t.Logf("current counts: %v", got)
	}
}

// The three steps the red-team found acting by name in service folders now
// change owners and modes only through descriptors.
func TestRedTeamFixedStepsChangeOwnersOnlyThroughDescriptors(t *testing.T) {
	t.Parallel()
	read := func(parts ...string) string {
		return mustRead(t, filepath.Join(append([]string{executionSubstrateRepoRoot, "scripts"}, parts...)...))
	}

	// RT-1
	ars := docSection(t, read("internal", "remote_alpha_harden_ars_service.sh"),
		"remote_alpha_ars_hardening_apply_state_permissions() {", "\n}\n")
	if lines := byPathOwnershipChangeLines(ars); len(lines) > 0 {
		t.Errorf("the ARS state step changes owners or modes by name: %q", lines)
	}
	assertContainsAll(t, "ARS state step", ars, "os.O_NOFOLLOW", "os.fchown(", "os.fchmod(", "st_nlink != 1")

	// RT-2: the reset changes no owner or mode by name, and moves and
	// recreates the raft directory through its parent's descriptor (audit
	// 03, A03-1).
	reset := read("remote_alpha_reset_disposable_vault.sh")
	if lines := byPathOwnershipChangeLines(reset); len(lines) > 0 {
		t.Errorf("the Vault reset changes owners or modes by name: %q", lines)
	}
	replace := docSection(t, reset, "replace_raft_directory() {", "\n}\n")
	assertContainsAll(t, "Vault reset raft step", replace, "os.O_NOFOLLOW", "dir_fd=parent_fd", "os.fchown(new_fd", "os.fchmod(new_fd", "sudo pgrep -u")

	// RT-3
	migrate := read("internal", "remote_alpha_migrate_vault_service_user.sh")
	applyStep := docSection(t, migrate, "def split_parent(path_value, label):", "def build_apply_summary(")
	if lines := byPathOwnershipChangeLines(applyStep); len(lines) > 0 {
		t.Errorf("the Vault migration's apply step changes owners or modes by name: %q", lines)
	}
	assertContainsAll(t, "Vault migration apply step", applyStep, "DIR_OPEN_FLAGS", "os.fchown(", "os.fchmod(", "for apply in (False, True):")
	assertContainsNone(t, "Vault migration helper", migrate, `["chown"`, `["chmod"`, `"-R"`)

	// #35, converted at the #49 sync: the bootstrap's temporary-config step
	// rewrites Vault's configuration file in a folder the Vault account may
	// own. It reads the file without following a link and sets the new
	// file's owner and mode through mkstemp's descriptor.
	bootstrap := read("internal", "remote_alpha_vault_workload_auth_bootstrap.sh")
	temporary := docSection(t, bootstrap, "class TemporaryGenerateRootAccess:", "\ndef decode_generated_root_token(")
	if lines := byPathOwnershipChangeLines(temporary); len(lines) > 0 {
		t.Errorf("the bootstrap's temporary-config step changes owners or modes by name: %q", lines)
	}
	assertContainsAll(t, "bootstrap temporary-config step", temporary, "os.fchown(handle.fileno()", "os.fchmod(handle.fileno()", "read_regular_file_no_follow(path)", "read_regular_file_no_follow(VAULT_CONFIG_PATH)")
	assertContainsNone(t, "bootstrap temporary-config step", temporary, "read_bytes(", "os.lstat(", "os.stat(")
	readStep := docSection(t, bootstrap, "def read_regular_file_no_follow(path):", "\n\n\n")
	assertContainsAll(t, "bootstrap no-follow read", readStep, "os.O_NOFOLLOW", "os.fstat(fd)", "stat.S_ISREG(info.st_mode)", "os.read(fd,")
	preflight := docSection(t, bootstrap, "def preflight_temporary_generate_root_access():", "\n\n\n")
	assertContainsAll(t, "bootstrap temporary-config preflight", preflight, "read_regular_file_no_follow(path)")
	assertContainsNone(t, "bootstrap temporary-config preflight", preflight, "read_bytes(")
}

// Audit 03 of PR #49 (2026-11-24) added the four tests below.

// RT-1: the first walk only checks. On a first run (a tree the running user
// owns), a tree with an entry the step refuses, found late in the walk, must
// keep every owner: no object may already have gone to the ARS account.
// Owners show as root (account 65534) and, unprivileged, when the user has a
// second group to hand over; otherwise only the refusal is checked.
func TestRemoteAlphaARSHardeningRefusedFirstRunKeepsOwners(t *testing.T) {
	t.Parallel()
	f := newARSStateFixture(t)
	self := rootPathOwner{os.Geteuid(), os.Getegid()}
	if os.Geteuid() != 0 {
		groups, _ := os.Getgroups()
		for _, g := range groups {
			if g != self.gid {
				f.owner = rootPathOwner{self.uid, g}
				break
			}
		}
		if f.owner == self {
			t.Log("this user has no second group, so a handed-over owner would not show; checking only the refusal")
		}
		writeExecutable(t, f.fakeBin, "id", fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = -u ] && [ \"$2\" = ars ]; then echo %d; exit 0; fi\nexec /usr/bin/id \"$@\"\n", f.owner.uid))
		writeExecutable(t, f.fakeBin, "getent", fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = group ] && [ \"$2\" = ars ]; then echo ars:x:%d:; exit 0; fi\nexit 2\n", f.owner.gid))
	}
	tree := []string{f.state, f.blobs, filepath.Join(f.blobs, "sha256"), filepath.Join(f.blobs, "sha256", "ab"), filepath.Join(f.blobs, "sha256", "ab", "cd"), f.blob, f.index}
	rootPathChown(t, self, tree...)
	// Sorted after sha256/, so a walk that changes as it goes has already
	// handed over the state root and the blob tree when it gets here.
	if err := syscall.Mkfifo(filepath.Join(f.blobs, "zz-pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := map[string]rootPathState{}
	for _, path := range tree {
		before[path] = rootPathStat(t, path)
	}
	output, err := f.run(t)
	if err == nil {
		t.Fatalf("the state step accepted a tree with a named pipe:\n%s", output)
	}
	for _, path := range tree {
		if got := rootPathStat(t, path); got != before[path] {
			t.Errorf("%s changed from %+v to %+v although the step refused the tree", path, before[path], got)
		}
	}
}

// RT-2: the Vault account chooses the raft path (it can rewrite vault.hcl
// while /etc/vault.d is vault-owned) and owns the directories in it below
// /opt/vault. After the ownership check, it swaps a directory above the raft
// directory for a link to a root directory holding an entry of the same name.
// The reset must not move or recreate that entry.
func TestRemoteAlphaResetDisposableVaultNeverFollowsALinkAboveTheRaftDirectory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	owner := rootPathServiceOwner()
	vaultBase := filepath.Join(dir, "opt-vault")
	inner := filepath.Join(vaultBase, "x")
	raft := filepath.Join(inner, "system")
	victimParent := filepath.Join(dir, "etc-systemd")
	victim := filepath.Join(victimParent, "system")
	unit := filepath.Join(victim, "es.service")
	for _, d := range []string{raft, victim} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(unit, []byte("[Service]\nExecStart=/usr/local/bin/es\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rootPathChmod(t, 0o755, vaultBase, inner, victimParent, victim)
	rootPathChmod(t, 0o700, raft)
	rootPathChown(t, owner, vaultBase, inner, raft)
	victimBefore, unitBefore := rootPathStat(t, victim), rootPathStat(t, unit)

	if output, err := vaultResetShell(t, false, fmt.Sprintf("require_vault_owned_raft_dir %q %q && echo accepted", raft, rootPathOwnerName(t, raft))); err != nil || !strings.Contains(output, "accepted") {
		t.Fatalf("the check before the confirmation refused the real raft directory: %v\n%s", err, output)
	}
	// While the operator reads the confirmation prompt.
	if err := os.Rename(inner, inner+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victimParent, inner); err != nil {
		t.Fatal(err)
	}
	backup := raft + ".remote-alpha-reset-backup-test"
	output, err := vaultResetShell(t, false, fmt.Sprintf("VAULT_RAFT_PATH=%q\nreplace_raft_directory %d %d %q", raft, owner.uid, owner.gid, backup))
	if err == nil {
		t.Errorf("the reset went through a link above the raft directory:\n%s", output)
	}
	if _, statErr := os.Lstat(filepath.Join(victimParent, "system.remote-alpha-reset-backup-test")); !os.IsNotExist(statErr) {
		t.Errorf("the reset moved the root directory aside: %v\n%s", statErr, output)
	}
	if got, err := os.Lstat(victim); err != nil {
		t.Fatalf("the root directory is gone: %v\n%s", err, output)
	} else if !got.IsDir() {
		t.Fatalf("the root directory was replaced\n%s", output)
	}
	if got := rootPathStat(t, victim); got != victimBefore {
		t.Errorf("the root directory changed from %+v to %+v\n%s", victimBefore, got, output)
	}
	if _, err := os.Lstat(unit); err != nil {
		t.Fatalf("the root directory no longer holds its file: %v\n%s", err, output)
	}
	if got := rootPathStat(t, unit); got != unitBefore {
		t.Errorf("the file in the root directory changed from %+v to %+v", unitBefore, got)
	}
}

// RT-3: a directory the Vault account can read but not write (root:vault
// 0750) must not become writable by that account because the config names a
// log file in it. Only root can build that directory, so as an ordinary user
// the test only says so.
func TestRemoteAlphaVaultServiceUserMigrationKeepsAReadOnlyVaultDirectoryReadOnly(t *testing.T) {
	t.Parallel()
	if os.Geteuid() != 0 {
		t.Log("only root can make a directory the Vault account reads but cannot write; nothing to check as this user")
		return
	}
	f := newVaultMigrationFixture(t)
	dir := filepath.Join(t.TempDir(), "root-vault-dir")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	rootPathChown(t, rootPathOwner{0, f.owner.gid}, dir)
	rootPathChmod(t, 0o750, dir)
	before := rootPathStat(t, dir)
	f.editVaultConfig(t, func(config map[string]any) { config["log_file"] = filepath.Join(dir, "vault.log") })
	if nestedMap(t, f.checkOnly(t), "plan")["apply_ready"] == true {
		_, _, _ = f.apply(t)
	}
	if got := rootPathStat(t, dir); got != before {
		t.Fatalf("%s changed from %+v to %+v: the Vault account can now write a directory it could only read", dir, before, got)
	}
}

// RT-3: the apply's first pass only checks. A refusal at the last target
// (the audit directory) must leave every earlier target as it was: the
// config and TLS directories, the storage tree and the log directory. The
// storage files start with another owner (root as root, a second group
// unprivileged) so a hand-over during the check pass would show.
func TestRemoteAlphaVaultServiceUserMigrationRefusedApplyChangesNoPath(t *testing.T) {
	t.Parallel()
	f := newVaultMigrationFixture(t)
	other := rootPathOwner{0, 0}
	if os.Geteuid() != 0 {
		other = f.owner
		groups, _ := os.Getgroups()
		for _, g := range groups {
			if g != f.owner.gid {
				other = rootPathOwner{f.owner.uid, g}
				break
			}
		}
		if other == f.owner {
			t.Log("this user has no second group, so a storage hand-over would not show")
		}
	}
	storageFiles := []string{filepath.Join(f.StorageDir, "vault.db"), filepath.Join(f.StorageDir, "raft"), filepath.Join(f.StorageDir, "raft", "raft.db")}
	rootPathChown(t, other, storageFiles...)
	f.mustBeReady(t)
	paths := append([]string{f.vaultDir, f.VaultConfigPath, f.TLSDir, f.StorageDir, f.LogDir, f.LogPath}, storageFiles...)
	entries, err := os.ReadDir(f.TLSDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		paths = append(paths, filepath.Join(f.TLSDir, entry.Name()))
	}
	before := map[string]rootPathState{}
	for _, path := range paths {
		before[path] = rootPathStat(t, path)
	}
	victimDir := rootPathStat(t, f.victimDir)
	replaceWithSymlink(t, f.victimDir, f.AuditDir)
	summary, output, err := f.apply(t)
	result := nestedMap(t, summary, "result")
	if err == nil || result["ok"] != false || !strings.Contains(result["summary"].(string), "no path was changed") {
		t.Fatalf("the apply did not refuse in its check pass: %v\nresult=%+v\n%s", err, result, output)
	}
	for _, path := range paths {
		if got := rootPathStat(t, path); got != before[path] {
			t.Errorf("%s changed from %+v to %+v although the apply said no path was changed", path, before[path], got)
		}
	}
	if got := rootPathStat(t, f.victimDir); got != victimDir {
		t.Errorf("the victim directory changed from %+v to %+v", victimDir, got)
	}
}

// RT-3, audit 03 A03-2: a storage directory that vault can only read must not
// become vault's, unless it sits in a directory vault can write already. A
// missing storage directory may still be created in a directory dedicated to
// Vault that vault can only read: the new directory goes to vault and the
// parent stays as it was. Only root can build a directory the Vault account
// reads but cannot write, so as an ordinary user the test only says so.
func TestRemoteAlphaVaultServiceUserMigrationStorageInAReadOnlyVaultDirectory(t *testing.T) {
	t.Parallel()
	if os.Geteuid() != 0 {
		t.Log("only root can make a directory the Vault account reads but cannot write; nothing to check as this user")
		return
	}
	readOnlyVaultDir := func(t *testing.T, f vaultMigrationFixture, parts ...string) string {
		dir := filepath.Join(append([]string{t.TempDir()}, parts...)...)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		rootPathChown(t, rootPathOwner{0, f.owner.gid}, dir)
		rootPathChmod(t, 0o750, dir)
		return dir
	}

	t.Run("existing storage directory is refused", func(t *testing.T) {
		t.Parallel()
		f := newVaultMigrationFixture(t)
		parent := readOnlyVaultDir(t, f, "read-only-parent")
		storage := filepath.Join(parent, "data")
		if err := os.Mkdir(storage, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(storage, "root-file"), []byte("root's bytes\n"), 0o640); err != nil {
			t.Fatal(err)
		}
		rootPathChown(t, rootPathOwner{0, f.owner.gid}, storage)
		rootPathChmod(t, 0o750, storage)
		before := map[string]rootPathState{}
		for _, path := range []string{parent, storage, filepath.Join(storage, "root-file")} {
			before[path] = rootPathStat(t, path)
		}
		f.editVaultConfig(t, func(config map[string]any) {
			config["storage"] = []map[string]any{{"type": "raft", "path": storage}}
		})
		summary := f.checkOnly(t)
		if nestedMap(t, summary, "plan")["apply_ready"] != false {
			t.Fatalf("the plan accepted a storage directory vault can only read: %s", mustRead(t, f.preflight))
		}
		found := false
		for _, raw := range summary["blockers"].([]any) {
			blocker := jsonMap(t, raw)
			if blocker["name"] == "storage_access" && strings.Contains(fmt.Sprint(blocker["summary"]), "is not writable by") {
				found = true
			}
		}
		if !found {
			t.Fatalf("no storage_access blocker saying the directory is not writable by vault: %+v", summary["blockers"])
		}
		for path, state := range before {
			if got := rootPathStat(t, path); got != state {
				t.Errorf("%s changed from %+v to %+v", path, state, got)
			}
		}
	})

	t.Run("missing storage directory is created", func(t *testing.T) {
		t.Parallel()
		f := newVaultMigrationFixture(t)
		parent := readOnlyVaultDir(t, f, "read-only-parent")
		storage := filepath.Join(parent, "data")
		parentBefore := rootPathStat(t, parent)
		f.editVaultConfig(t, func(config map[string]any) {
			config["storage"] = []map[string]any{{"type": "raft", "path": storage}}
		})
		f.mustBeReady(t)
		summary, output, err := f.apply(t)
		if err != nil || nestedMap(t, summary, "result")["ok"] != true {
			t.Fatalf("the apply failed: %v\n%+v\n%s", err, summary["result"], output)
		}
		if got := rootPathStat(t, parent); got != parentBefore {
			t.Errorf("the parent changed from %+v to %+v; it should stay one vault can only read", parentBefore, got)
		}
		if got := rootPathStat(t, storage); got.uid != f.owner.uid || got.gid != f.owner.gid || got.mode != 0o750 {
			t.Errorf("the new storage directory is %+v, want vault's with mode 0750", got)
		}
	})
}

// RT-2, audit 03 A03-1: the reset refuses a link above the raft directory even
// when the directory it leads to holds a directory of the Vault account under
// the raft directory's name, so root never renames or creates entries in a
// directory the link leads to. (The owner check alone would let this through.)
func TestRemoteAlphaResetDisposableVaultRefusesALinkAboveTheRaftDirectoryToAVaultFolder(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	owner := rootPathServiceOwner()
	vaultBase := filepath.Join(dir, "opt-vault")
	inner := filepath.Join(vaultBase, "x")
	raft := filepath.Join(inner, "raft")
	elsewhere := filepath.Join(dir, "elsewhere")
	lookalike := filepath.Join(elsewhere, "raft")
	for _, d := range []string{raft, lookalike} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	rootPathChmod(t, 0o755, vaultBase, inner, elsewhere)
	rootPathChmod(t, 0o700, raft, lookalike)
	rootPathChown(t, owner, vaultBase, inner, raft, lookalike)
	elsewhereBefore, lookalikeBefore := rootPathStat(t, elsewhere), rootPathStat(t, lookalike)

	if err := os.Rename(inner, inner+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, inner); err != nil {
		t.Fatal(err)
	}
	backup := raft + ".remote-alpha-reset-backup-test"
	output, err := vaultResetShell(t, false, fmt.Sprintf("VAULT_RAFT_PATH=%q\nreplace_raft_directory %d %d %q", raft, owner.uid, owner.gid, backup))
	if err == nil || !strings.Contains(output, inner+" is not a directory or is a symbolic link") {
		t.Fatalf("the reset did not refuse the link above the raft directory: %v\n%s", err, output)
	}
	entries, readErr := os.ReadDir(elsewhere)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 1 || entries[0].Name() != "raft" {
		t.Errorf("the reset renamed or created entries where the link led: %v\n%s", entries, output)
	}
	if got := rootPathStat(t, elsewhere); got != elsewhereBefore {
		t.Errorf("%s changed from %+v to %+v", elsewhere, elsewhereBefore, got)
	}
	if got := rootPathStat(t, lookalike); got != lookalikeBefore {
		t.Errorf("%s changed from %+v to %+v", lookalike, lookalikeBefore, got)
	}
}

// vaultRunsAsVault installs the drop-in the migration writes, so the unit
// reports that Vault already runs as the Vault user.
func (f vaultMigrationFixture) vaultRunsAsVault(t *testing.T) {
	t.Helper()
	if err := os.MkdirAll(f.ServiceDropInDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.ServiceDropInPath, []byte("[Service]\nUser=vault\nGroup=vault\nUMask=0027\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// vaultUnreadableFile writes a root-only file (root's, 0600) in dir, which
// the Vault account (uid 65534 when the test runs as root) cannot read.
func (f vaultMigrationFixture) vaultUnreadableFile(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "root-only.key")
	if err := os.WriteFile(path, []byte("root keeps this from vault\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func lstatOwnerMode(t *testing.T, path string) (int, int, os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat %s: %v", path, err)
	}
	sys := info.Sys().(*syscall.Stat_t)
	return int(sys.Uid), int(sys.Gid), info.Mode().Perm()
}

// RT-3 residual RC-1 (red-team re-check 06 of PR #49): once Vault runs as the
// Vault user, a file in a directory that account owns, but which it cannot
// read, must not be opened up to it, whether the account names it as a TLS
// file in the config it owns or moves it into the storage tree. While the unit
// still runs as root, the apply hands config and TLS files over as before.
func TestRemoteAlphaVaultServiceUserMigrationKeepsFilesVaultCannotReadFromVault(t *testing.T) {
	t.Parallel()
	if os.Geteuid() != 0 {
		t.Log("only root can make a file in a Vault directory that the Vault account cannot read; nothing to check as this user")
		return
	}
	nameAsTLSFile := func(t *testing.T, f vaultMigrationFixture, secret string) {
		f.editVaultConfig(t, func(config map[string]any) {
			listener := config["listener"].([]any)[0].(map[string]any)
			listener["tls_client_ca_file"] = secret
		})
		rootPathChown(t, f.owner, f.VaultConfigPath)
	}

	t.Run("named as a TLS file", func(t *testing.T) {
		t.Parallel()
		f := newVaultMigrationFixture(t)
		f.vaultRunsAsVault(t)
		f.mustBeReady(t)
		secret := f.vaultUnreadableFile(t, f.TLSDir)
		uid, gid, mode := lstatOwnerMode(t, secret)
		nameAsTLSFile(t, f, secret)

		// The plan blocks it.
		preflight := f.checkOnly(t)
		if nestedMap(t, preflight, "plan")["apply_ready"] == true || !strings.Contains(mustRead(t, f.preflight), "is not readable by vault now") {
			t.Fatalf("the plan did not block a TLS file vault cannot read:\n%s", mustRead(t, f.preflight))
		}
		// An apply from a preflight that lists it anyway refuses before any change.
		tls := nestedMap(t, nestedMap(t, preflight, "validation"), "tls_read_paths")
		tls["classification"] = "pass"
		items := tls["items"].([]any)
		for _, raw := range items {
			item := raw.(map[string]any)
			item["classification"] = "pass"
			if item["path"] == secret {
				item["apply_adjustment_required"] = true
			}
		}
		plan := nestedMap(t, preflight, "plan")
		plan["apply_ready"] = true
		preflight["blockers"] = []any{}
		preflight["overall_classification"] = "pass"
		writeJSONFile(t, f.preflight, preflight)
		summary, output, err := f.apply(t)
		result := fmt.Sprint(nestedMap(t, summary, "result")["summary"])
		if err == nil || !strings.Contains(result, "Vault listener TLS path: "+secret+" is not readable by vault now") || !strings.Contains(result, "no path was changed") {
			t.Fatalf("the apply opened up a TLS file vault cannot read: %v\nresult=%s\n%s", err, result, output)
		}
		if gotUID, gotGID, gotMode := lstatOwnerMode(t, secret); gotUID != uid || gotGID != gid || gotMode != mode {
			t.Fatalf("the file changed from %d:%d %04o to %d:%d %04o", uid, gid, mode, gotUID, gotGID, gotMode)
		}
	})

	t.Run("named as a TLS file while Vault still runs as root", func(t *testing.T) {
		t.Parallel()
		f := newVaultMigrationFixture(t)
		secret := f.vaultUnreadableFile(t, f.TLSDir)
		nameAsTLSFile(t, f, secret)
		f.mustBeReady(t)
		if summary, output, err := f.apply(t); err != nil {
			t.Fatalf("the first migration refused a TLS file root keeps: %v\nresult=%v\n%s", err, summary["result"], output)
		}
		if uid, gid, mode := lstatOwnerMode(t, secret); uid != 0 || gid != f.owner.gid || mode != 0o640 {
			t.Fatalf("the first migration should hand the TLS file to root:vault 0640, it is %d:%d %04o", uid, gid, mode)
		}
	})

	t.Run("moved into the storage tree", func(t *testing.T) {
		t.Parallel()
		f := newVaultMigrationFixture(t)
		f.vaultRunsAsVault(t)
		moved := filepath.Join(f.StorageDir, "root-only.key")
		// The account moves the file within directories it owns.
		if err := os.Rename(f.vaultUnreadableFile(t, f.TLSDir), moved); err != nil {
			t.Fatal(err)
		}
		f.mustBeReady(t)
		storage := rootPathStat(t, f.StorageDir)
		before := rootPathStat(t, moved)
		summary, output, err := f.apply(t)
		result := fmt.Sprint(nestedMap(t, summary, "result")["summary"])
		if err == nil || !strings.Contains(result, moved+" belongs to uid 0, not to vault") || !strings.Contains(result, "no path was changed") {
			t.Fatalf("the apply gave the account a storage entry it did not own: %v\nresult=%s\n%s", err, result, output)
		}
		if got := rootPathStat(t, moved); got != before {
			t.Fatalf("the moved file changed from %+v to %+v", before, got)
		}
		if got := rootPathStat(t, f.StorageDir); got != storage {
			t.Fatalf("the storage directory changed from %+v to %+v", storage, got)
		}
	})
}

// RC-1 follow-up (diff check 09 of PR #49): the refusals that apply once
// Vault runs as the Vault user must not refuse what the migration itself
// produces. A completed migration leaves config and TLS files root:vault 0640,
// which vault reads through its group, and a storage directory the step
// creates is root's and empty until it is handed over.
func TestRemoteAlphaVaultServiceUserMigrationKeepsWorkingOnceVaultRunsAsVault(t *testing.T) {
	t.Parallel()
	if os.Geteuid() != 0 {
		t.Log("only root can hand files to root:vault; nothing to check as this user")
		return
	}

	t.Run("a completed migration runs again", func(t *testing.T) {
		t.Parallel()
		f := newVaultMigrationFixture(t)
		f.mustBeReady(t)
		if summary, output, err := f.apply(t); err != nil {
			t.Fatalf("the first migration failed: %v\nresult=%v\n%s", err, summary["result"], output)
		}
		f.vaultRunsAsVault(t)
		f.mustBeReady(t)
		if summary, output, err := f.apply(t); err != nil {
			t.Fatalf("a second migration refused what the first one produced: %v\nresult=%v\n%s", err, summary["result"], output)
		}
		for _, path := range []string{f.VaultConfigPath, filepath.Join(f.TLSDir, "vault-server-key.pem")} {
			if uid, gid, mode := lstatOwnerMode(t, path); uid != 0 || gid != f.owner.gid || mode != 0o640 {
				t.Errorf("%s is %d:%d %04o after the second migration, want 0:%d 0640", path, uid, gid, mode, f.owner.gid)
			}
		}
	})

	t.Run("a missing storage directory is created", func(t *testing.T) {
		t.Parallel()
		f := newVaultMigrationFixture(t)
		f.vaultRunsAsVault(t)
		if err := os.RemoveAll(f.StorageDir); err != nil {
			t.Fatal(err)
		}
		f.mustBeReady(t)
		if summary, output, err := f.apply(t); err != nil {
			t.Fatalf("the apply refused to create a missing storage directory while Vault runs as vault: %v\nresult=%v\n%s", err, summary["result"], output)
		}
		if uid, gid, mode := lstatOwnerMode(t, f.StorageDir); uid != f.owner.uid || gid != f.owner.gid || mode != 0o750 {
			t.Errorf("the new storage directory is %d:%d %04o, want %d:%d 0750", uid, gid, mode, f.owner.uid, f.owner.gid)
		}
	})
}
