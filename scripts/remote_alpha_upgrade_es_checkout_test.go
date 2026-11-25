package scripts_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// Red-team RT60-2 of ES PR #60: check, apply and rollback run code from the
// clone as root (the upgrade itself, the setup's nomad_tls functions,
// nomad_acl_setup.sh with nomad_acl.py, nomad_tls_identity.py), so each
// refuses, before it reads the host, unless no account but root can change
// that code. Under a test --host-root the guard runs only when the test
// names the uid that stands in for root.

const checkoutRefusal = "can change the code this upgrade runs as root"

// upgradeClone is a copy of the upgrade's own files in a clone that only
// the user running the tests can change, in a folder of its own.
type upgradeClone struct {
	t       *testing.T
	base    string // the folder that holds the clone
	root    string // the clone
	scripts string
	python  string
	host    string // an empty --host-root
	bin     string // a stand-in systemctl, first on PATH
}

func newUpgradeClone(t *testing.T) *upgradeClone {
	t.Helper()
	// The guard refuses a clone reached through any symbolic link; this
	// package's TestMain (testtmpdir) keeps temporary folders off such paths,
	// as on macOS, where /var leads to /private/var.
	base := t.TempDir()
	c := &upgradeClone{t: t, base: base, root: filepath.Join(base, "clone"), host: t.TempDir(), bin: t.TempDir()}
	// check asks systemctl about the services once the guard lets it
	// through; the stand-in answers as for units it does not know, so a
	// passing case does not depend on the machine running the tests (macOS
	// has no systemctl).
	if err := os.WriteFile(filepath.Join(c.bin, "systemctl"), []byte("#!/bin/sh\nexit 3\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(c.bin, "systemctl"), 0o755); err != nil {
		t.Fatal(err)
	}
	c.scripts = filepath.Join(c.root, "scripts")
	c.python = filepath.Join(c.scripts, "internal", "remote_alpha_upgrade_es.py")
	for _, dir := range []string{c.root, c.scripts, filepath.Join(c.scripts, "internal")} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		// The test process's umask must not decide the mode.
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for rel, mode := range map[string]os.FileMode{
		"scripts/remote_alpha_upgrade_es.sh":          0o755,
		"scripts/internal/remote_alpha_upgrade_es.py": 0o644,
	} {
		data, err := os.ReadFile(repoPath(rel))
		if err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(c.root, filepath.FromSlash(rel))
		if err := os.WriteFile(dst, data, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dst, mode); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

// run starts the clone's upgrade with args. hostRoot "" runs it as on a
// host (no --host-root); owner "" leaves the test guard off.
func (c *upgradeClone) run(python, hostRoot, owner string, args ...string) (string, string, int) {
	c.t.Helper()
	argv := []string{"-I", python}
	if hostRoot != "" {
		argv = append(argv, "--host-root", hostRoot)
	}
	cmd := exec.Command("python3", append(argv, args...)...)
	cmd.Dir = c.t.TempDir()
	cmd.Env = c.env(owner)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			c.t.Fatalf("run %v: %v", args, err)
		}
		code = exitErr.ExitCode()
	}
	return stdout.String(), stderr.String(), code
}

// env is the test process's environment without ES_UPGRADE_TEST_*, with
// the stand-in systemctl first on PATH and, unless owner is "", the uid the
// guard checks for.
func (c *upgradeClone) env(owner string) []string {
	var env []string
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "ES_UPGRADE_TEST_") && !strings.HasPrefix(entry, "PATH=") {
			env = append(env, entry)
		}
	}
	env = append(env, "PATH="+c.bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if owner != "" {
		env = append(env, "ES_UPGRADE_TEST_CHECKOUT_OWNER="+owner)
	}
	return env
}

func (c *upgradeClone) check(owner string) (string, string, int) {
	c.t.Helper()
	return c.run(c.python, c.host, owner, "check", "--payload", filepath.Join(c.host, "payload"), "--commit", upgradeTestCommit)
}

// wrapper starts check through the shell wrapper at path, as an operator
// does, with the same environment as run.
func (c *upgradeClone) wrapper(path, owner string) (string, string, int) {
	c.t.Helper()
	cmd := exec.Command(path, "--host-root", c.host, "check", "--payload", filepath.Join(c.host, "payload"), "--commit", upgradeTestCommit)
	cmd.Dir = c.t.TempDir()
	cmd.Env = c.env(owner)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	code := 0
	if err := cmd.Run(); err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			c.t.Fatalf("wrapper %s: %v", path, err)
		}
		code = exitErr.ExitCode()
	}
	return stdout.String(), stderr.String(), code
}

func (c *upgradeClone) chmod(path string, mode os.FileMode) {
	c.t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		c.t.Fatal(err)
	}
}

// refused requires the checkout refusal naming want, before the host was
// read: no report on stdout.
func refused(t *testing.T, label, stdout, stderr string, code int, want string) {
	t.Helper()
	if code != 1 || !strings.Contains(stderr, checkoutRefusal) || !strings.Contains(stderr, want) ||
		!strings.Contains(stderr, "nothing was changed") || stdout != "" {
		t.Fatalf("%s: want the checkout refusal naming %q before any host read, got exit %d\nstdout %s\nstderr %s",
			label, want, code, stdout, stderr)
	}
}

// passed requires that the guard let the command through to its own
// checks: on an empty host root, check prints its report and refuses on
// the host, not on the checkout.
func passed(t *testing.T, label, stdout, stderr string) {
	t.Helper()
	if strings.Contains(stderr, checkoutRefusal) || !strings.Contains(stdout, `"shape"`) {
		t.Fatalf("%s: want the guard to let check through to its report, got\nstdout %s\nstderr %s", label, stdout, stderr)
	}
}

func TestRemoteAlphaUpgradeESRefusesACloneOthersCanChange(t *testing.T) {
	uid := strconv.Itoa(os.Getuid())

	t.Run("a clone only the owner can change passes", func(t *testing.T) {
		c := newUpgradeClone(t)
		stdout, stderr, _ := c.check(uid)
		passed(t, "clean clone", stdout, stderr)
	})

	t.Run("without the test uid the guard is off under a test host root", func(t *testing.T) {
		c := newUpgradeClone(t)
		c.chmod(c.python, 0o666)
		stdout, stderr, _ := c.check("")
		passed(t, "guard off", stdout, stderr)
	})

	cases := []struct {
		name  string
		setup func(c *upgradeClone) string // returns what the refusal must name
	}{
		{"a script writable by its group", func(c *upgradeClone) string {
			c.chmod(c.python, 0o664)
			return c.python + " is writable by its group or others (0664)"
		}},
		{"a script writable by others", func(c *upgradeClone) string {
			path := filepath.Join(c.scripts, "remote_alpha_upgrade_es.sh")
			c.chmod(path, 0o757)
			return path + " is writable by its group or others (0757)"
		}},
		{"a folder under scripts writable by others", func(c *upgradeClone) string {
			dir := filepath.Join(c.scripts, "internal")
			c.chmod(dir, 0o757)
			return dir + " is writable by its group or others (0757)"
		}},
		{"the scripts folder writable by its group", func(c *upgradeClone) string {
			c.chmod(c.scripts, 0o775)
			return c.scripts + " is writable by its group or others (0775)"
		}},
		{"a new file the group can change", func(c *upgradeClone) string {
			path := filepath.Join(c.scripts, "70_linux_setup.sh")
			if err := os.WriteFile(path, []byte("#!/usr/bin/env bash\n"), 0o664); err != nil {
				c.t.Fatal(err)
			}
			c.chmod(path, 0o664)
			return path + " is writable by its group or others (0664)"
		}},
		{"a symbolic link under scripts", func(c *upgradeClone) string {
			link := filepath.Join(c.scripts, "nomad_acl_setup.sh")
			if err := os.Symlink(filepath.Join(c.base, "elsewhere.sh"), link); err != nil {
				c.t.Fatal(err)
			}
			return link + " is a symbolic link"
		}},
		{"a named pipe under scripts", func(c *upgradeClone) string {
			fifo := filepath.Join(c.scripts, "internal", "pipe")
			if err := syscall.Mkfifo(fifo, 0o644); err != nil {
				c.t.Fatal(err)
			}
			return fifo + " is neither a folder nor a regular file"
		}},
		{"a folder above the clone writable by others without the sticky bit", func(c *upgradeClone) string {
			c.chmod(c.base, 0o777)
			return c.base + " is writable by its group or others (0777) without the sticky bit"
		}},
		{"a folder above the clone that only others can write", func(c *upgradeClone) string {
			c.chmod(c.base, 0o757)
			return c.base + " is writable by its group or others (0757) without the sticky bit"
		}},
		{"a sticky folder under scripts that anyone can write", func(c *upgradeClone) string {
			// The sticky bit keeps others from replacing an entry, not from
			// adding one, so under scripts it does not help.
			dir := filepath.Join(c.scripts, "lib")
			if err := os.Mkdir(dir, 0o755); err != nil {
				c.t.Fatal(err)
			}
			c.chmod(dir, 0o777|os.ModeSticky)
			return dir + " is writable by its group or others (1777)"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newUpgradeClone(t)
			want := tc.setup(c)
			stdout, stderr, code := c.check(uid)
			refused(t, "check", stdout, stderr, code, want)
		})
	}

	t.Run("a folder above the clone with the sticky bit passes", func(t *testing.T) {
		c := newUpgradeClone(t)
		c.chmod(c.base, 0o777|os.ModeSticky)
		stdout, stderr, _ := c.check(uid)
		passed(t, "sticky folder", stdout, stderr)
	})

	t.Run("a folder under scripts the guard cannot read", func(t *testing.T) {
		// What the guard cannot list, it cannot vouch for. Root can list any
		// folder, so this happens only under a test --host-root.
		if os.Getuid() == 0 {
			t.Skip("root can list any folder")
		}
		c := newUpgradeClone(t)
		dir := filepath.Join(c.scripts, "sealed")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		c.chmod(dir, 0o300)
		t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
		stdout, stderr, code := c.check(uid)
		refused(t, "check", stdout, stderr, code, dir+": Permission denied")
	})

	t.Run("files of another owner", func(t *testing.T) {
		c := newUpgradeClone(t)
		other := strconv.Itoa(os.Getuid() + 1)
		stdout, stderr, code := c.check(other)
		// The scripts folder is named whoever runs the tests. The folders
		// above it are named too, unless the tests run as root: the guard
		// accepts root's folders above the clone.
		refused(t, "check", stdout, stderr, code, c.scripts+" belongs to uid "+uid)
		if os.Getuid() != 0 && !strings.Contains(stderr, c.root+" belongs to uid "+uid) {
			t.Fatalf("the refusal does not name the clone's own folder, which is above scripts:\n%s", stderr)
		}
		if !strings.Contains(stderr, "someone other than uid "+other) {
			t.Fatalf("the refusal does not name the uid that may change the clone:\n%s", stderr)
		}
	})

	t.Run("a clone reached through a symbolic link", func(t *testing.T) {
		c := newUpgradeClone(t)
		alias := filepath.Join(c.base, "alias")
		if err := os.Symlink(c.root, alias); err != nil {
			t.Fatal(err)
		}
		python := filepath.Join(alias, "scripts", "internal", "remote_alpha_upgrade_es.py")
		stdout, stderr, code := c.run(python, c.host, uid, "check", "--payload", filepath.Join(c.host, "payload"), "--commit", upgradeTestCommit)
		refused(t, "check", stdout, stderr, code, filepath.Join(alias, "scripts")+" is reached through a symbolic link ("+c.scripts+")")
	})

	t.Run("apply and rollback refuse the same clone", func(t *testing.T) {
		c := newUpgradeClone(t)
		c.chmod(c.python, 0o664)
		want := c.python + " is writable by its group or others (0664)"
		stdout, stderr, code := c.run(c.python, c.host, uid, "apply", "--payload", filepath.Join(c.host, "payload"), "--commit", upgradeTestCommit)
		refused(t, "apply", stdout, stderr, code, want)
		stdout, stderr, code = c.run(c.python, c.host, uid, "rollback", "--backup-dir", filepath.Join(c.host, "backup"))
		refused(t, "rollback", stdout, stderr, code, want)
	})

	t.Run("on a host the guard always runs, for root", func(t *testing.T) {
		// No --host-root: the guard runs before check reads anything, so this
		// reads nothing of the machine running the tests.
		c := newUpgradeClone(t)
		c.chmod(c.python, 0o664)
		stdout, stderr, code := c.run(c.python, "", "", "check", "--payload", filepath.Join(c.host, "payload"), "--commit", upgradeTestCommit)
		refused(t, "check on a host", stdout, stderr, code, c.python+" is writable by its group or others (0664)")
		if !strings.Contains(stderr, "someone other than root") {
			t.Fatalf("on a host the refusal must name root:\n%s", stderr)
		}
		if os.Getuid() != 0 {
			// A clone that only this (non-root) user can change is still not
			// root's.
			c.chmod(c.python, 0o644)
			stdout, stderr, code = c.run(c.python, "", "", "rollback", "--backup-dir", filepath.Join(c.host, "backup"))
			refused(t, "rollback on a host", stdout, stderr, code, c.root+" belongs to uid "+uid)
		}
	})

	t.Run("through the wrapper, a clone only the owner can change passes", func(t *testing.T) {
		c := newUpgradeClone(t)
		stdout, stderr, _ := c.wrapper(filepath.Join(c.scripts, "remote_alpha_upgrade_es.sh"), uid)
		passed(t, "wrapper", stdout, stderr)
	})

	t.Run("through the wrapper, a clone reached through a symbolic link is refused", func(t *testing.T) {
		// The documented entry point is the wrapper. It must hand the guard
		// the path it was started from, not the resolved one.
		c := newUpgradeClone(t)
		alias := filepath.Join(c.base, "alias")
		if err := os.Symlink(c.root, alias); err != nil {
			t.Fatal(err)
		}
		stdout, stderr, code := c.wrapper(filepath.Join(alias, "scripts", "remote_alpha_upgrade_es.sh"), uid)
		refused(t, "wrapper", stdout, stderr, code, filepath.Join(alias, "scripts")+" is reached through a symbolic link ("+c.scripts+")")
	})

	// Not "/tmp/..": on macOS /tmp is a link and that names /private.
	for _, spelling := range []string{"//", "/.", "/..", "/usr/.."} {
		t.Run("--host-root "+spelling+" is the host", func(t *testing.T) {
			// Another spelling of "/" must not turn on test mode, which would
			// turn the guard off while every path is the host's.
			c := newUpgradeClone(t)
			c.chmod(c.python, 0o664)
			stdout, stderr, code := c.run(c.python, spelling, "", "check", "--payload", filepath.Join(c.host, "payload"), "--commit", upgradeTestCommit)
			refused(t, "check", stdout, stderr, code, c.python+" is writable by its group or others (0664)")
			if !strings.Contains(stderr, "someone other than root") {
				t.Fatalf("--host-root %s must be the host, where the refusal names root:\n%s", spelling, stderr)
			}
		})
	}

	t.Run("build is not guarded", func(t *testing.T) {
		// build runs unprivileged in the operator's own clone, before it is
		// handed to root.
		c := newUpgradeClone(t)
		c.chmod(c.python, 0o664)
		_, stderr, code := c.run(c.python, "", "", "build", "--out", filepath.Join(c.base, "payload"), "--commit", "not-a-commit")
		if code != 1 || strings.Contains(stderr, checkoutRefusal) || !strings.Contains(stderr, "full lower-case 40-character SHA-1") {
			t.Fatalf("build must reach its own checks, got exit %d\n%s", code, stderr)
		}
	})
}

// A file under scripts that another account owns can be changed by that
// account whatever its mode, even when every folder above it passes. The
// test hands one file to root with sudo, as the real-Nomad upgrade test uses
// sudo; CI has passwordless sudo.
func TestRemoteAlphaUpgradeESRefusesACloneFileOfAnotherOwner(t *testing.T) {
	probe := exec.Command("sudo", "-n", "true")
	probe.Dir = t.TempDir()
	if err := probe.Run(); err != nil {
		t.Skip("needs passwordless sudo to give a file to root")
	}
	if os.Getuid() == 0 {
		t.Skip("runs as root, so root's file is the owner's")
	}
	c := newUpgradeClone(t)
	path := filepath.Join(c.scripts, "nomad_acl_setup.sh")
	if err := os.WriteFile(path, []byte("#!/usr/bin/env bash\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	chown := exec.Command("sudo", "-n", "chown", "0:0", path)
	chown.Dir = c.base
	if out, err := chown.CombinedOutput(); err != nil {
		t.Fatalf("sudo chown: %v: %s", err, out)
	}
	uid := strconv.Itoa(os.Getuid())
	stdout, stderr, code := c.check(uid)
	refused(t, "check", stdout, stderr, code, path+" belongs to uid 0")
	if strings.Contains(stderr, c.root+" belongs") || strings.Contains(stderr, c.base+" belongs") {
		t.Fatalf("only the file should be named, not the folders above it:\n%s", stderr)
	}
}
