package scripts_test

import (
	"bytes"
	"fmt"
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
// names the uid that stands in for root. The shell wrapper, the documented
// entry point, checks on its own and for every command, before any of the
// clone's Python runs, that no account but root (for a run by another user,
// root and that user) can change the code it would run, and that it was
// started by that code's physical path.

const checkoutRefusal = "can change the code this upgrade runs as root"

// The wrapper's own refusals, which come before any of the clone's Python.
const (
	wrapperRefusal     = "can change the code the wrapper would run"
	wrapperLinkRefusal = "start it by the path of the clone itself, not through a symbolic link: "
	decoyRan           = "the decoy ran"
)

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
	return c.wrapperIn(c.t.TempDir(), path, owner)
}

// wrapperIn is wrapper started from the folder dir, with extra environment
// entries.
func (c *upgradeClone) wrapperIn(dir, path, owner string, extra ...string) (string, string, int) {
	c.t.Helper()
	return c.start(dir, path, append(c.env(owner), extra...),
		"--host-root", c.host, "check", "--payload", filepath.Join(c.host, "payload"), "--commit", upgradeTestCommit)
}

// start runs the program at path with args from the folder dir, with the
// environment env.
func (c *upgradeClone) start(dir, path string, env []string, args ...string) (string, string, int) {
	c.t.Helper()
	cmd := exec.Command(path, args...)
	cmd.Dir = dir
	cmd.Env = env
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

// wrapperRefused requires the wrapper's own refusal naming want, before
// any of the clone's Python ran: neither a report nor the upgrade's own
// checkout refusal.
func wrapperRefused(t *testing.T, label, stdout, stderr string, code int, want string) {
	t.Helper()
	if code != 1 || !strings.Contains(stderr, wrapperRefusal) || !strings.Contains(stderr, want) ||
		!strings.Contains(stderr, "nothing was changed") || strings.Contains(stderr, checkoutRefusal) || stdout != "" {
		t.Fatalf("%s: want the wrapper's refusal naming %q before any of the clone's Python ran, got exit %d\nstdout %s\nstderr %s",
			label, want, code, stdout, stderr)
	}
}

// wrapperLinkRefused requires the wrapper's refusal of a start path with a
// symbolic link, naming want, before any of the clone's Python ran.
func wrapperLinkRefused(t *testing.T, label, stdout, stderr string, code int, want string) {
	t.Helper()
	if code != 1 || !strings.Contains(stderr, wrapperLinkRefusal+want+"; nothing was changed") ||
		strings.Contains(stderr, checkoutRefusal) || stdout != "" {
		t.Fatalf("%s: want the wrapper's refusal of a symbolic link, naming %q, before any of the clone's Python ran, got exit %d\nstdout %s\nstderr %s",
			label, want, code, stdout, stderr)
	}
}

// plantDecoy writes dir/internal/remote_alpha_upgrade_es.py, which only
// prints decoyRan, as an account that can write to dir could.
func plantDecoy(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "internal"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "internal", "remote_alpha_upgrade_es.py"), []byte("print('"+decoyRan+"')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// noDecoy requires that no decoy ran.
func noDecoy(t *testing.T, label, stdout, stderr string) {
	t.Helper()
	if strings.Contains(stdout+stderr, decoyRan) {
		t.Fatalf("%s: a decoy ran\nstdout %s\nstderr %s", label, stdout, stderr)
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
		// The documented entry point is the wrapper. It finds its Python by
		// the physical path and refuses, on its own, a start path that is
		// not that path.
		c := newUpgradeClone(t)
		alias := filepath.Join(c.base, "alias")
		if err := os.Symlink(c.root, alias); err != nil {
			t.Fatal(err)
		}
		stdout, stderr, code := c.wrapper(filepath.Join(alias, "scripts", "remote_alpha_upgrade_es.sh"), uid)
		wrapperLinkRefused(t, "wrapper", stdout, stderr, code, filepath.Join(alias, "scripts", "remote_alpha_upgrade_es.sh")+
			" is reached through a symbolic link ("+filepath.Join(c.scripts, "remote_alpha_upgrade_es.sh")+")")
	})

	// Root starts its own symbolic link to the wrapper, kept in a folder
	// anyone can write, as sudo /tmp/up.sh. The link itself is root's and
	// the sticky bit keeps others from replacing it, but anyone could put
	// internal/remote_alpha_upgrade_es.py beside it; a wrapper that took its
	// folder from the start path's text would run that as root (audit 31,
	// A31-1). The wrapper finds its Python by the physical path, and refuses
	// the link.
	t.Run("through the wrapper, a symbolic link to it in a shared sticky folder runs nothing beside the link", func(t *testing.T) {
		c := newUpgradeClone(t)
		shared := filepath.Join(c.base, "shared")
		if err := os.Mkdir(shared, 0o755); err != nil {
			t.Fatal(err)
		}
		c.chmod(shared, 0o777|os.ModeSticky)
		plantDecoy(t, shared)
		link := filepath.Join(shared, "up.sh")
		if err := os.Symlink(filepath.Join(c.scripts, "remote_alpha_upgrade_es.sh"), link); err != nil {
			t.Fatal(err)
		}
		stdout, stderr, code := c.wrapper(link, uid)
		noDecoy(t, "symbolic link", stdout, stderr)
		wrapperLinkRefused(t, "symbolic link", stdout, stderr, code, link+" is a symbolic link ("+filepath.Join(c.scripts, "remote_alpha_upgrade_es.sh")+")")
	})

	t.Run("through the wrapper, a symbolic link to it beside it is refused", func(t *testing.T) {
		// The start path must be the physical path itself, even where the
		// link's folder is the wrapper's own; the upgrade's guard is off.
		c := newUpgradeClone(t)
		link := filepath.Join(c.scripts, "up.sh")
		if err := os.Symlink("remote_alpha_upgrade_es.sh", link); err != nil {
			t.Fatal(err)
		}
		stdout, stderr, code := c.wrapper(link, "")
		wrapperLinkRefused(t, "link beside the wrapper", stdout, stderr, code, link+" is a symbolic link ("+filepath.Join(c.scripts, "remote_alpha_upgrade_es.sh")+")")
	})

	// A hard link names the wrapper in another folder, so that folder is the
	// wrapper's folder and must pass on its own: a folder anyone can write
	// does not, whatever its sticky bit.
	t.Run("through the wrapper, a hard link to it in a shared sticky folder runs nothing beside the link", func(t *testing.T) {
		c := newUpgradeClone(t)
		shared := filepath.Join(c.base, "shared")
		if err := os.Mkdir(shared, 0o755); err != nil {
			t.Fatal(err)
		}
		c.chmod(shared, 0o777|os.ModeSticky)
		plantDecoy(t, shared)
		link := filepath.Join(shared, "up.sh")
		if err := os.Link(filepath.Join(c.scripts, "remote_alpha_upgrade_es.sh"), link); err != nil {
			t.Fatal(err)
		}
		stdout, stderr, code := c.wrapper(link, uid)
		noDecoy(t, "hard link", stdout, stderr)
		wrapperRefused(t, "hard link", stdout, stderr, code, shared+" is writable by its group or others (1777)")
	})

	// A process may hand on a PWD that names the working folder through a
	// symbolic link and a "..": bash keeps it, since the kernel resolves it
	// to the working folder, while its text names another folder (audit 31,
	// A31-1). The wrapper reads the working folder from the kernel.
	t.Run("through the wrapper, an inherited PWD does not choose the folder", func(t *testing.T) {
		c := newUpgradeClone(t)
		decoy := filepath.Join(c.base, "decoy")
		plantDecoy(t, decoy)
		if err := os.Symlink(filepath.Join(c.scripts, "internal"), filepath.Join(decoy, "alias")); err != nil {
			t.Fatal(err)
		}
		stdout, stderr, _ := c.wrapperIn(c.scripts, "./remote_alpha_upgrade_es.sh", uid, "PWD="+decoy+"/alias/..")
		noDecoy(t, "inherited PWD", stdout, stderr)
		passed(t, "inherited PWD", stdout, stderr)
	})

	// A root shell that did cd <decoy>/lnk, where lnk leads to
	// scripts/internal, keeps the link in PWD; ../remote_alpha_upgrade_es.sh
	// is then the clone's wrapper to the kernel and <decoy>/... to the text
	// (audit 31, A31-2). The wrapper refuses a leading ".." too.
	t.Run("through the wrapper, a path starting with .. is refused", func(t *testing.T) {
		c := newUpgradeClone(t)
		decoy := filepath.Join(c.base, "decoy")
		plantDecoy(t, decoy)
		lnk := filepath.Join(decoy, "lnk")
		if err := os.Symlink(filepath.Join(c.scripts, "internal"), lnk); err != nil {
			t.Fatal(err)
		}
		// exec.Cmd sets no PWD when Env is given; a shell would.
		stdout, stderr, code := c.wrapperIn(lnk, "../remote_alpha_upgrade_es.sh", uid, "PWD="+lnk)
		noDecoy(t, "leading ..", stdout, stderr)
		if code != 1 || stdout != "" || !strings.Contains(stderr, `start it by a path without ".." (../remote_alpha_upgrade_es.sh); nothing was changed`) {
			t.Fatalf("want the wrapper's refusal of ../remote_alpha_upgrade_es.sh, got exit %d\nstdout %s\nstderr %s", code, stdout, stderr)
		}
	})

	t.Run("through the wrapper, a path starting with // passes", func(t *testing.T) {
		// "//" names "/" here; the wrapper must not take it for a link.
		c := newUpgradeClone(t)
		stdout, stderr, _ := c.wrapper("/"+filepath.Join(c.scripts, "remote_alpha_upgrade_es.sh"), uid)
		passed(t, "wrapper by //", stdout, stderr)
	})

	t.Run("through the wrapper, PYTHONPATH loads no other code", func(t *testing.T) {
		// Both Pythons the wrapper starts ignore PYTHON* variables (-I).
		c := newUpgradeClone(t)
		planted := filepath.Join(c.base, "pythonpath")
		if err := os.Mkdir(planted, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"sitecustomize.py", "argparse.py"} {
			if err := os.WriteFile(filepath.Join(planted, name), []byte("raise SystemExit('"+decoyRan+"')\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		stdout, stderr, _ := c.wrapperIn(c.t.TempDir(), filepath.Join(c.scripts, "remote_alpha_upgrade_es.sh"), uid, "PYTHONPATH="+planted)
		noDecoy(t, "PYTHONPATH", stdout, stderr)
		passed(t, "PYTHONPATH", stdout, stderr)
	})

	// The wrapper checks the code it would run on its own, before any of
	// the clone's Python runs, so these hold with the upgrade's own guard
	// off (no test uid).
	who := "someone other than root and uid " + uid + " can change the code the wrapper would run: "
	if os.Getuid() == 0 {
		who = "someone other than root can change the code the wrapper would run as root: "
	}
	wrapperCases := []struct {
		name  string
		setup func(c *upgradeClone) string // returns what the refusal must name
	}{
		{"the upgrade's Python writable by others", func(c *upgradeClone) string {
			c.chmod(c.python, 0o666)
			return c.python + " is writable by its group or others (0666)"
		}},
		{"the internal folder writable by its group", func(c *upgradeClone) string {
			dir := filepath.Join(c.scripts, "internal")
			c.chmod(dir, 0o775)
			return dir + " is writable by its group or others (0775)"
		}},
		{"the wrapper's folder writable by anyone, with the sticky bit", func(c *upgradeClone) string {
			c.chmod(c.scripts, 0o777|os.ModeSticky)
			return c.scripts + " is writable by its group or others (1777)"
		}},
		{"the wrapper writable by others", func(c *upgradeClone) string {
			path := filepath.Join(c.scripts, "remote_alpha_upgrade_es.sh")
			c.chmod(path, 0o757)
			return path + " is writable by its group or others (0757)"
		}},
		{"a folder above the clone that only others can write", func(c *upgradeClone) string {
			c.chmod(c.base, 0o757)
			return c.base + " is writable by its group or others (0757) without the sticky bit"
		}},
		{"the internal folder a symbolic link", func(c *upgradeClone) string {
			dir := filepath.Join(c.scripts, "internal")
			moved := filepath.Join(c.base, "internal")
			if err := os.Rename(dir, moved); err != nil {
				c.t.Fatal(err)
			}
			if err := os.Symlink(moved, dir); err != nil {
				c.t.Fatal(err)
			}
			return dir + " is a symbolic link"
		}},
	}
	for _, tc := range wrapperCases {
		t.Run("through the wrapper, before any Python of the clone runs, "+tc.name+" is refused", func(t *testing.T) {
			c := newUpgradeClone(t)
			want := tc.setup(c)
			stdout, stderr, code := c.wrapper(filepath.Join(c.scripts, "remote_alpha_upgrade_es.sh"), "")
			wrapperRefused(t, "wrapper", stdout, stderr, code, want)
			if !strings.Contains(stderr, who+want) {
				t.Fatalf("the refusal must open with %q:\n%s", who, stderr)
			}
		})
	}

	t.Run("through the wrapper, a folder above the clone with the sticky bit passes", func(t *testing.T) {
		c := newUpgradeClone(t)
		c.chmod(c.base, 0o777|os.ModeSticky)
		stdout, stderr, _ := c.wrapper(filepath.Join(c.scripts, "remote_alpha_upgrade_es.sh"), "")
		passed(t, "wrapper below a sticky folder", stdout, stderr)
	})

	t.Run("through the wrapper, build is checked as well", func(t *testing.T) {
		// build runs no code as root, but root installs what it builds.
		c := newUpgradeClone(t)
		c.chmod(c.python, 0o664)
		stdout, stderr, code := c.start(c.t.TempDir(), filepath.Join(c.scripts, "remote_alpha_upgrade_es.sh"), c.env(""),
			"build", "--out", filepath.Join(c.base, "payload"), "--commit", "not-a-commit")
		wrapperRefused(t, "build", stdout, stderr, code, c.python+" is writable by its group or others (0664)")
	})

	// The kernel resolves a ".." after following the link before it; cd -L
	// drops it with that link's name. Here the kernel reads the clone's own
	// wrapper, while cd -L would lead to a folder that holds another
	// internal/remote_alpha_upgrade_es.py, which root would run before any
	// check. The wrapper refuses any path with "..".
	t.Run("through the wrapper, a path with .. after a symbolic link is refused", func(t *testing.T) {
		c := newUpgradeClone(t)
		decoy := filepath.Join(c.base, "decoy")
		if err := os.MkdirAll(filepath.Join(decoy, "internal"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(decoy, "internal", "remote_alpha_upgrade_es.py"), []byte("print('the decoy ran')\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(c.scripts, "internal"), filepath.Join(decoy, "alias")); err != nil {
			t.Fatal(err)
		}
		path := decoy + "/alias/../remote_alpha_upgrade_es.sh" // not filepath.Join, which drops the ".."
		stdout, stderr, code := c.wrapper(path, uid)
		if code != 1 || stdout != "" || !strings.Contains(stderr, `start it by a path without ".." (`+path+`); nothing was changed`) {
			t.Fatalf("want the wrapper's refusal of %s, got exit %d\nstdout %s\nstderr %s", path, code, stdout, stderr)
		}
	})

	t.Run("through the wrapper, a path with .. is refused", func(t *testing.T) {
		c := newUpgradeClone(t)
		path := c.scripts + "/internal/../remote_alpha_upgrade_es.sh"
		stdout, stderr, code := c.wrapper(path, uid)
		if code != 1 || stdout != "" || !strings.Contains(stderr, `start it by a path without ".."`) {
			t.Fatalf("want the wrapper's refusal of %s, got exit %d\nstdout %s\nstderr %s", path, code, stdout, stderr)
		}
	})

	t.Run("through the wrapper, CDPATH does not choose the folder", func(t *testing.T) {
		// Started as scripts/remote_alpha_upgrade_es.sh from the clone: a
		// shell's cd would look that relative folder up through CDPATH. The
		// wrapper uses no cd; this keeps it so.
		c := newUpgradeClone(t)
		elsewhere := filepath.Join(c.base, "elsewhere")
		if err := os.MkdirAll(filepath.Join(elsewhere, "scripts", "internal"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(elsewhere, "scripts", "internal", "remote_alpha_upgrade_es.py"), []byte("print('elsewhere ran')\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		stdout, stderr, _ := c.wrapperIn(c.root, "scripts/remote_alpha_upgrade_es.sh", uid, "CDPATH="+elsewhere)
		passed(t, "wrapper with CDPATH", stdout, stderr)
	})

	t.Run("--host-root through a symbolic link to / is the host", func(t *testing.T) {
		// Canonicalising the text alone ("//" to "/") would leave a link to
		// "/" in test mode, with the guard off.
		c := newUpgradeClone(t)
		link := filepath.Join(c.base, "host")
		if err := os.Symlink("/", link); err != nil {
			t.Fatal(err)
		}
		c.chmod(c.python, 0o664)
		stdout, stderr, code := c.run(c.python, link, "", "check", "--payload", filepath.Join(c.host, "payload"), "--commit", upgradeTestCommit)
		refused(t, "check", stdout, stderr, code, c.python+" is writable by its group or others (0664)")
		if !strings.Contains(stderr, "someone other than root") {
			t.Fatalf("--host-root %s must be the host, where the refusal names root:\n%s", link, stderr)
		}
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

// The wrapper accepts code that root or the user running it owns. Code of
// any other account is refused before it runs, and a run as root, through
// sudo as the contract has it, accepts root's code only.
func TestRemoteAlphaUpgradeESWrapperRefusesCodeOfAnotherOwner(t *testing.T) {
	asRoot := func(dir string, args ...string) error {
		var cmd *exec.Cmd
		if os.Getuid() == 0 {
			cmd = exec.Command(args[0], args[1:]...)
		} else {
			cmd = exec.Command("sudo", append([]string{"-n"}, args...)...)
		}
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v: %v: %s", args, err, out)
		}
		return nil
	}
	if err := asRoot(t.TempDir(), "true"); err != nil {
		t.Skip("needs root or passwordless sudo to give a file to another account")
	}
	uid := strconv.Itoa(os.Getuid())

	t.Run("the upgrade's Python of another account", func(t *testing.T) {
		c := newUpgradeClone(t)
		if err := asRoot(c.base, "chown", "65534", c.python); err != nil {
			t.Fatal(err)
		}
		stdout, stderr, code := c.wrapper(filepath.Join(c.scripts, "remote_alpha_upgrade_es.sh"), "")
		wrapperRefused(t, "wrapper", stdout, stderr, code, c.python+" belongs to uid 65534")
	})

	t.Run("through sudo, a clone of the user running sudo", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("runs as root, so the clone is root's")
		}
		c := newUpgradeClone(t)
		stdout, stderr, code := c.start(c.t.TempDir(), "sudo", c.env(""), "-n", filepath.Join(c.scripts, "remote_alpha_upgrade_es.sh"),
			"--host-root", c.host, "check", "--payload", filepath.Join(c.host, "payload"), "--commit", upgradeTestCommit)
		wrapperRefused(t, "sudo wrapper", stdout, stderr, code, c.scripts+" belongs to uid "+uid)
		if !strings.Contains(stderr, "someone other than root can change the code the wrapper would run as root: ") {
			t.Fatalf("as root the wrapper must accept root's code only:\n%s", stderr)
		}
	})
}
