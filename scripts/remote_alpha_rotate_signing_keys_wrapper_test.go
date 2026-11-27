package scripts_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The rotation runs as root and handles every signing key on the box, so
// its shell wrapper, the documented entry point, checks on its own and for
// every command, before any of the clone's Python runs, that no account but
// root (for a run by another user, root and that user) can change the code
// it would run, and that it was started by that code's physical path. A
// check inside the helper alone is gone once someone replaces the helper
// (audits of ES PR #76: S76-1, and F1 of the Opus re-audit). These tests
// start the wrapper of a copied clone and plant decoys that must never run.

const (
	rotationWrapperRefusal     = "can change the code the wrapper would run"
	rotationWrapperLinkRefusal = "start it by the path of the clone itself, not through a symbolic link: "
	rotationDecoyRan           = "the rotation decoy ran"
	rotationReportSchema       = `"schema": "execution-substrate.remote-alpha.signing-key-rotation.v1"`
)

// rotationClone is a copy of the rotation's wrapper and helper in a clone
// that only the user running the tests can change, in a folder of its own.
type rotationClone struct {
	t       *testing.T
	base    string // the folder that holds the clone
	root    string // the clone
	scripts string
	wrapper string
	helper  string
	host    string // an empty --host-root
	bin     string // a stand-in systemctl
}

func newRotationClone(t *testing.T) *rotationClone {
	t.Helper()
	// The wrapper refuses a clone reached through any symbolic link; this
	// package's TestMain (testtmpdir) keeps temporary folders off such
	// paths, as on macOS, where /var leads to /private/var.
	base := t.TempDir()
	c := &rotationClone{t: t, base: base, root: filepath.Join(base, "clone"), host: t.TempDir(), bin: t.TempDir()}
	c.scripts = filepath.Join(c.root, "scripts")
	c.wrapper = filepath.Join(c.scripts, "remote_alpha_rotate_signing_keys.sh")
	c.helper = filepath.Join(c.scripts, "internal", "remote_alpha_rotate_signing_keys.py")
	// check asks systemctl about the units once the wrapper lets it
	// through; the stand-in answers as for units it does not know, so a
	// passing case does not depend on the machine (macOS has no systemctl).
	stub := filepath.Join(c.bin, "systemctl")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\nexit 3\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	c.chmod(stub, 0o755)
	for _, dir := range []string{c.root, c.scripts, filepath.Join(c.scripts, "internal")} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		// The test process's umask must not decide the mode.
		c.chmod(dir, 0o755)
	}
	for rel, mode := range map[string]os.FileMode{rotateSigningKeysWrapper: 0o755, rotateSigningKeysPython: 0o644} {
		data, err := os.ReadFile(repoPath(rel))
		if err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(c.root, filepath.FromSlash(rel))
		if err := os.WriteFile(dst, data, mode); err != nil {
			t.Fatal(err)
		}
		c.chmod(dst, mode)
	}
	return c
}

func (c *rotationClone) chmod(path string, mode os.FileMode) {
	c.t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		c.t.Fatal(err)
	}
}

// env is the test process's environment without the rotation's test
// variables, with the stand-in systemctl named for the helper.
func (c *rotationClone) env(extra ...string) []string {
	var env []string
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "SIGNING_KEY_ROTATION_TEST_") {
			env = append(env, entry)
		}
	}
	env = append(env, "SIGNING_KEY_ROTATION_TEST_SYSTEMCTL="+filepath.Join(c.bin, "systemctl"))
	return append(env, extra...)
}

// start runs the program at path with args from the folder dir, with the
// environment env.
func (c *rotationClone) start(dir, path string, env []string, args ...string) (string, string, int) {
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

// check starts check through the wrapper at path from the folder dir, as an
// operator does, on the empty test host root.
func (c *rotationClone) check(dir, path string, extra ...string) (string, string, int) {
	c.t.Helper()
	return c.start(dir, path, c.env(extra...), "--host-root", c.host, "check")
}

// plantRotationDecoy writes dir/internal/remote_alpha_rotate_signing_keys.py,
// which only prints rotationDecoyRan, as an account that can write to dir
// could.
func plantRotationDecoy(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "internal"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "internal", "remote_alpha_rotate_signing_keys.py"),
		[]byte("print('"+rotationDecoyRan+"')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func noRotationDecoy(t *testing.T, label, stdout, stderr string) {
	t.Helper()
	if strings.Contains(stdout+stderr, rotationDecoyRan) {
		t.Fatalf("%s: a decoy ran\nstdout %s\nstderr %s", label, stdout, stderr)
	}
}

// rotationWrapperPassed requires that the wrapper let check through to the
// helper: on an empty host root, check prints its report and refuses on the
// host, not on the checkout.
func rotationWrapperPassed(t *testing.T, label, stdout, stderr string) {
	t.Helper()
	if strings.Contains(stderr, rotationWrapperRefusal) || strings.Contains(stderr, "can change the code this rotation runs as root") ||
		!strings.Contains(stdout, rotationReportSchema) {
		t.Fatalf("%s: want the wrapper to let check through to its report, got\nstdout %s\nstderr %s", label, stdout, stderr)
	}
}

// rotationWrapperRefused requires the wrapper's own refusal naming want,
// before any of the clone's Python ran: no report and no decoy.
func rotationWrapperRefused(t *testing.T, label, stdout, stderr string, code int, want string) {
	t.Helper()
	noRotationDecoy(t, label, stdout, stderr)
	if code != 1 || !strings.Contains(stderr, rotationWrapperRefusal) || !strings.Contains(stderr, want) ||
		!strings.Contains(stderr, "nothing was changed") || stdout != "" {
		t.Fatalf("%s: want the wrapper's refusal naming %q before any of the clone's Python ran, got exit %d\nstdout %s\nstderr %s",
			label, want, code, stdout, stderr)
	}
}

// rotationWrapperLinkRefused requires the wrapper's refusal of a start path
// with a symbolic link, naming want, before any of the clone's Python ran.
func rotationWrapperLinkRefused(t *testing.T, label, stdout, stderr string, code int, want string) {
	t.Helper()
	noRotationDecoy(t, label, stdout, stderr)
	if code != 1 || !strings.Contains(stderr, rotationWrapperLinkRefusal+want+"; nothing was changed") || stdout != "" {
		t.Fatalf("%s: want the wrapper's refusal of a symbolic link, naming %q, before any of the clone's Python ran, got exit %d\nstdout %s\nstderr %s",
			label, want, code, stdout, stderr)
	}
}

func rotationWrapperDotDotRefused(t *testing.T, label, path, stdout, stderr string, code int) {
	t.Helper()
	noRotationDecoy(t, label, stdout, stderr)
	if code != 1 || stdout != "" || !strings.Contains(stderr, `start it by a path without ".." (`+path+`); nothing was changed`) {
		t.Fatalf("%s: want the wrapper's refusal of %s, got exit %d\nstdout %s\nstderr %s", label, path, code, stdout, stderr)
	}
}

func TestSigningKeyRotationWrapperRefusesACloneOthersCanChange(t *testing.T) {
	uid := strconv.Itoa(os.Getuid())

	t.Run("a clone only the owner can change passes", func(t *testing.T) {
		c := newRotationClone(t)
		stdout, stderr, _ := c.check(t.TempDir(), c.wrapper)
		rotationWrapperPassed(t, "wrapper", stdout, stderr)
	})

	t.Run("a path starting with // passes", func(t *testing.T) {
		// "//" names "/" here; the wrapper must not take it for a link.
		c := newRotationClone(t)
		stdout, stderr, _ := c.check(t.TempDir(), "/"+c.wrapper)
		rotationWrapperPassed(t, "wrapper by //", stdout, stderr)
	})

	t.Run("a folder above the clone with the sticky bit passes", func(t *testing.T) {
		c := newRotationClone(t)
		c.chmod(c.base, 0o777|os.ModeSticky)
		stdout, stderr, _ := c.check(t.TempDir(), c.wrapper)
		rotationWrapperPassed(t, "below a sticky folder", stdout, stderr)
	})

	// The helper replaced through a folder its group can write: the helper's
	// own check would be gone with it (Opus re-audit F1, probe 1b).
	t.Run("a helper replaced through a writable internal folder never runs", func(t *testing.T) {
		c := newRotationClone(t)
		internal := filepath.Join(c.scripts, "internal")
		c.chmod(internal, 0o775)
		plantRotationDecoy(t, c.scripts)
		stdout, stderr, code := c.check(t.TempDir(), c.wrapper)
		rotationWrapperRefused(t, "replaced helper", stdout, stderr, code, internal+" is writable by its group or others (0775)")
	})

	t.Run("a clone reached through a symbolic link is refused", func(t *testing.T) {
		c := newRotationClone(t)
		alias := filepath.Join(c.base, "alias")
		if err := os.Symlink(c.root, alias); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(alias, "scripts", "remote_alpha_rotate_signing_keys.sh")
		stdout, stderr, code := c.check(t.TempDir(), path)
		rotationWrapperLinkRefused(t, "alias", stdout, stderr, code, path+" is reached through a symbolic link ("+c.wrapper+")")
	})

	// Root starts its own symbolic link to the wrapper, kept in a folder
	// anyone can write. The link itself is root's and the sticky bit keeps
	// others from replacing it, but anyone could put
	// internal/remote_alpha_rotate_signing_keys.py beside it; a wrapper that
	// took its folder from the start path's text would run that as root
	// (Opus re-audit F1, probe 3). The wrapper finds the helper by the
	// physical path, and refuses the link.
	t.Run("a symbolic link to it in a shared sticky folder runs nothing beside the link", func(t *testing.T) {
		c := newRotationClone(t)
		shared := filepath.Join(c.base, "shared")
		if err := os.Mkdir(shared, 0o755); err != nil {
			t.Fatal(err)
		}
		c.chmod(shared, 0o777|os.ModeSticky)
		plantRotationDecoy(t, shared)
		link := filepath.Join(shared, "rot.sh")
		if err := os.Symlink(c.wrapper, link); err != nil {
			t.Fatal(err)
		}
		stdout, stderr, code := c.check(t.TempDir(), link)
		rotationWrapperLinkRefused(t, "symbolic link", stdout, stderr, code, link+" is a symbolic link ("+c.wrapper+")")
	})

	t.Run("a symbolic link to it beside it is refused", func(t *testing.T) {
		c := newRotationClone(t)
		link := filepath.Join(c.scripts, "rot.sh")
		if err := os.Symlink("remote_alpha_rotate_signing_keys.sh", link); err != nil {
			t.Fatal(err)
		}
		stdout, stderr, code := c.check(t.TempDir(), link)
		rotationWrapperLinkRefused(t, "link beside the wrapper", stdout, stderr, code, link+" is a symbolic link ("+c.wrapper+")")
	})

	// A hard link names the wrapper in another folder, so that folder is
	// the wrapper's folder and must pass on its own: a folder anyone can
	// write does not, whatever its sticky bit.
	t.Run("a hard link to it in a shared sticky folder runs nothing beside the link", func(t *testing.T) {
		c := newRotationClone(t)
		shared := filepath.Join(c.base, "shared")
		if err := os.Mkdir(shared, 0o755); err != nil {
			t.Fatal(err)
		}
		c.chmod(shared, 0o777|os.ModeSticky)
		plantRotationDecoy(t, shared)
		link := filepath.Join(shared, "rot.sh")
		if err := os.Link(c.wrapper, link); err != nil {
			t.Fatal(err)
		}
		stdout, stderr, code := c.check(t.TempDir(), link)
		rotationWrapperRefused(t, "hard link", stdout, stderr, code, shared+" is writable by its group or others (1777)")
	})

	// A process may hand on a PWD that names the working folder through a
	// symbolic link and a "..": bash keeps it, since the kernel resolves it
	// to the working folder, while its text names another folder. The
	// wrapper reads the working folder from the kernel.
	t.Run("an inherited PWD does not choose the folder", func(t *testing.T) {
		c := newRotationClone(t)
		decoy := filepath.Join(c.base, "decoy")
		plantRotationDecoy(t, decoy)
		if err := os.Symlink(filepath.Join(c.scripts, "internal"), filepath.Join(decoy, "alias")); err != nil {
			t.Fatal(err)
		}
		stdout, stderr, _ := c.check(c.scripts, "./remote_alpha_rotate_signing_keys.sh", "PWD="+decoy+"/alias/..")
		noRotationDecoy(t, "inherited PWD", stdout, stderr)
		rotationWrapperPassed(t, "inherited PWD", stdout, stderr)
	})

	// The kernel resolves a ".." after following the link before it; cd -L
	// drops it with that link's name (Opus re-audit F1, probe 2). The
	// wrapper refuses any start path with "..", leading or not.
	t.Run("a path with .. after a symbolic link is refused", func(t *testing.T) {
		c := newRotationClone(t)
		decoy := filepath.Join(c.base, "decoy")
		plantRotationDecoy(t, decoy)
		if err := os.Symlink(filepath.Join(c.scripts, "internal"), filepath.Join(decoy, "alias")); err != nil {
			t.Fatal(err)
		}
		path := decoy + "/alias/../remote_alpha_rotate_signing_keys.sh" // not filepath.Join, which drops the ".."
		stdout, stderr, code := c.check(t.TempDir(), path)
		rotationWrapperDotDotRefused(t, "dotdot after a link", path, stdout, stderr, code)
	})

	t.Run("a path starting with .. is refused", func(t *testing.T) {
		c := newRotationClone(t)
		decoy := filepath.Join(c.base, "decoy")
		plantRotationDecoy(t, decoy)
		lnk := filepath.Join(decoy, "lnk")
		if err := os.Symlink(filepath.Join(c.scripts, "internal"), lnk); err != nil {
			t.Fatal(err)
		}
		// exec.Cmd sets no PWD when Env is given; a shell would.
		stdout, stderr, code := c.check(lnk, "../remote_alpha_rotate_signing_keys.sh", "PWD="+lnk)
		rotationWrapperDotDotRefused(t, "leading dotdot", "../remote_alpha_rotate_signing_keys.sh", stdout, stderr, code)
	})

	t.Run("a path with .. inside the clone is refused", func(t *testing.T) {
		c := newRotationClone(t)
		path := c.scripts + "/internal/../remote_alpha_rotate_signing_keys.sh"
		stdout, stderr, code := c.check(t.TempDir(), path)
		rotationWrapperDotDotRefused(t, "dotdot", path, stdout, stderr, code)
	})

	t.Run("CDPATH does not choose the folder", func(t *testing.T) {
		c := newRotationClone(t)
		elsewhere := filepath.Join(c.base, "elsewhere")
		plantRotationDecoy(t, filepath.Join(elsewhere, "scripts"))
		stdout, stderr, _ := c.check(c.root, "scripts/remote_alpha_rotate_signing_keys.sh", "CDPATH="+elsewhere)
		noRotationDecoy(t, "CDPATH", stdout, stderr)
		rotationWrapperPassed(t, "CDPATH", stdout, stderr)
	})

	t.Run("PYTHONPATH loads no other code", func(t *testing.T) {
		// Both Pythons the wrapper starts ignore PYTHON* variables (-I).
		c := newRotationClone(t)
		planted := filepath.Join(c.base, "pythonpath")
		if err := os.Mkdir(planted, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"sitecustomize.py", "argparse.py", "stat.py"} {
			if err := os.WriteFile(filepath.Join(planted, name), []byte("raise SystemExit('"+rotationDecoyRan+"')\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		stdout, stderr, _ := c.check(t.TempDir(), c.wrapper, "PYTHONPATH="+planted)
		noRotationDecoy(t, "PYTHONPATH", stdout, stderr)
		rotationWrapperPassed(t, "PYTHONPATH", stdout, stderr)
	})

	// Each entry the wrapper checks, made changeable by others.
	who := "someone other than root and uid " + uid + " can change the code the wrapper would run: "
	if os.Getuid() == 0 {
		who = "someone other than root can change the code the wrapper would run as root: "
	}
	for _, tc := range []struct {
		name  string
		setup func(c *rotationClone) string // returns what the refusal must name
	}{
		{"the helper writable by others", func(c *rotationClone) string {
			c.chmod(c.helper, 0o666)
			return c.helper + " is writable by its group or others (0666)"
		}},
		{"the internal folder writable by anyone, with the sticky bit", func(c *rotationClone) string {
			dir := filepath.Join(c.scripts, "internal")
			c.chmod(dir, 0o777|os.ModeSticky)
			return dir + " is writable by its group or others (1777)"
		}},
		{"the wrapper's folder writable by anyone, with the sticky bit", func(c *rotationClone) string {
			c.chmod(c.scripts, 0o777|os.ModeSticky)
			return c.scripts + " is writable by its group or others (1777)"
		}},
		{"the wrapper writable by others", func(c *rotationClone) string {
			c.chmod(c.wrapper, 0o757)
			return c.wrapper + " is writable by its group or others (0757)"
		}},
		{"a folder above the clone that others can write", func(c *rotationClone) string {
			c.chmod(c.base, 0o757)
			return c.base + " is writable by its group or others (0757) without the sticky bit"
		}},
		{"the internal folder a symbolic link", func(c *rotationClone) string {
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
		{"the helper a symbolic link", func(c *rotationClone) string {
			moved := filepath.Join(c.base, "helper.py")
			if err := os.Rename(c.helper, moved); err != nil {
				c.t.Fatal(err)
			}
			if err := os.Symlink(moved, c.helper); err != nil {
				c.t.Fatal(err)
			}
			return c.helper + " is a symbolic link"
		}},
		{"no helper", func(c *rotationClone) string {
			if err := os.Remove(c.helper); err != nil {
				c.t.Fatal(err)
			}
			return c.helper + ": No such file or directory"
		}},
		// Python runs a folder that holds __main__.py, so a helper folder
		// that passes the owner and mode checks could still run code that
		// others can change inside it.
		{"the helper a folder Python would run", func(c *rotationClone) string {
			if err := os.Remove(c.helper); err != nil {
				c.t.Fatal(err)
			}
			if err := os.Mkdir(c.helper, 0o755); err != nil {
				c.t.Fatal(err)
			}
			c.chmod(c.helper, 0o755)
			main := filepath.Join(c.helper, "__main__.py")
			if err := os.WriteFile(main, []byte("print('"+rotationDecoyRan+"')\n"), 0o666); err != nil {
				c.t.Fatal(err)
			}
			c.chmod(main, 0o666)
			return c.helper + " is not a regular file"
		}},
		{"the internal folder a file", func(c *rotationClone) string {
			dir := filepath.Join(c.scripts, "internal")
			if err := os.RemoveAll(dir); err != nil {
				c.t.Fatal(err)
			}
			if err := os.WriteFile(dir, nil, 0o644); err != nil {
				c.t.Fatal(err)
			}
			c.chmod(dir, 0o644)
			return dir + " is not a folder"
		}},
	} {
		for _, command := range [][]string{{"check"}, {"apply"}, {"rollback", "--backup-dir", "/nonexistent"}} {
			t.Run(tc.name+" is refused before any Python of the clone runs/"+command[0], func(t *testing.T) {
				c := newRotationClone(t)
				want := tc.setup(c)
				stdout, stderr, code := c.start(t.TempDir(), c.wrapper, c.env(), append([]string{"--host-root", c.host}, command...)...)
				rotationWrapperRefused(t, command[0], stdout, stderr, code, want)
				if !strings.Contains(stderr, who+want) {
					t.Fatalf("the refusal must open with %q:\n%s", who, stderr)
				}
			})
		}
	}
}

// As root, as the contract runs it, the wrapper accepts only code that root
// owns: code of any other account, an ordinary user's clone included, is
// refused before it runs. Giving files to other accounts needs root, so
// the test skips itself without root; go.yml runs it as root in the step
// "Listed tests pass as root", the only step of the job that uses sudo.
func TestSigningKeyRotationWrapperRefusesCodeOfAnotherOwnerAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to give files to other accounts")
	}
	t.Run("a clone root owns", func(t *testing.T) {
		c := newRotationClone(t)
		stdout, stderr, code := c.check(t.TempDir(), c.wrapper)
		if code != 1 {
			// The stand-in systemctl knows no unit, so check refuses the
			// host; what counts is that the clone's helper ran.
			t.Fatalf("check of a host without units: exit %d\n%s", code, stderr)
		}
		rotationWrapperPassed(t, "root's clone", stdout, stderr)
	})
	// Each entry the wrapper checks, given to another account: 65534
	// (nobody) or 1 (daemon), since a host's service accounts have uids
	// below 1000, and 1000, the first ordinary user of a Linux host.
	for _, tc := range []struct {
		name    string
		uid     int
		chown   func(c *rotationClone) []string
		problem func(c *rotationClone) string
	}{
		{"the helper of another account", 65534,
			func(c *rotationClone) []string { return []string{c.helper} },
			func(c *rotationClone) string { return c.helper }},
		{"the wrapper of a system account", 1,
			func(c *rotationClone) []string { return []string{c.wrapper} },
			func(c *rotationClone) string { return c.wrapper }},
		{"the internal folder of a system account", 1,
			func(c *rotationClone) []string { return []string{filepath.Join(c.scripts, "internal")} },
			func(c *rotationClone) string { return filepath.Join(c.scripts, "internal") }},
		{"a folder above the wrapper's folder of a system account", 1,
			func(c *rotationClone) []string { return []string{c.root} },
			func(c *rotationClone) string { return c.root }},
		{"a clone of an ordinary user", 1000,
			func(c *rotationClone) []string {
				return []string{c.root, c.scripts, filepath.Join(c.scripts, "internal"), c.wrapper, c.helper}
			},
			func(c *rotationClone) string { return c.scripts }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newRotationClone(t)
			for _, path := range tc.chown(c) {
				if err := os.Lchown(path, tc.uid, -1); err != nil {
					t.Fatal(err)
				}
			}
			stdout, stderr, code := c.check(t.TempDir(), c.wrapper)
			rotationWrapperRefused(t, "wrapper", stdout, stderr, code, fmt.Sprintf("%s belongs to uid %d", tc.problem(c), tc.uid))
			if !strings.Contains(stderr, "someone other than root can change the code the wrapper would run as root: ") {
				t.Fatalf("as root the wrapper must accept root's code only:\n%s", stderr)
			}
		})
	}
	// The helper's own check, the second line for a start without the
	// wrapper, also asks who owns the folders above scripts/ (red-team
	// RT10-9, mutant N41).
	t.Run("the helper on its own, under a folder of a system account", func(t *testing.T) {
		c := newRotationClone(t)
		if err := os.Lchown(c.root, 1, -1); err != nil {
			t.Fatal(err)
		}
		stdout, stderr, code := c.start(t.TempDir(), "/usr/bin/python3", c.env("SIGNING_KEY_ROTATION_TEST_CHECKOUT_OWNER=0"),
			"-I", "-B", c.helper, "--host-root", c.host, "check")
		if code != 1 || stdout != "" || !strings.Contains(stderr, "someone other than root can change the code this rotation runs as root") ||
			!strings.Contains(stderr, c.root+" belongs to uid 1") {
			t.Fatalf("the helper on its own: exit %d\nstdout %s\nstderr %s", code, stdout, stderr)
		}
	})
}

// rotationWrapperGuard returns the parts of a wrapper's embedded program
// that check the clone: from reading its arguments to the end of
// problems_of, and from reading the working folder to the refusal of a
// start path through a symbolic link, with the script's own names put back
// to the ES upgrade's. What a wrapper does between the two parts (the
// upgrade refuses two of its own words there) is its own.
func rotationWrapperGuard(t *testing.T, text string, names map[string]string) string {
	t.Helper()
	first := regexp.MustCompile(`(?s)start, args = sys\.argv\[1\], sys\.argv\[2:\]\n.*?\n    return found\n`).FindString(text)
	second := regexp.MustCompile(`(?s)\ntry:\n    here = os\.getcwd\(\)\n.*?% \(invoked, how, wrapper\)\)\n`).FindString(text)
	if first == "" || second == "" {
		return ""
	}
	m := first + second
	for from, to := range names {
		m = strings.ReplaceAll(m, from, to)
	}
	return m
}

// TestSigningKeyRotationWrapperGuardMatchesTheUpgrade holds the rotation's
// wrapper check to the ES upgrade wrapper's, word for word apart from the
// names, so that a repair of one reaches the other. The upgrade's wrapper
// carries the check from ES PR #63 on; until that merges, the upgrade's
// wrapper has none and this test only requires the rotation's.
func TestSigningKeyRotationWrapperGuardMatchesTheUpgrade(t *testing.T) {
	rotation, err := os.ReadFile(repoPath(rotateSigningKeysWrapper))
	if err != nil {
		t.Fatal(err)
	}
	guard := rotationWrapperGuard(t, string(rotation), map[string]string{
		"remote alpha signing key rotation refused: ": "remote alpha ES upgrade refused: ",
		"remote_alpha_rotate_signing_keys.py":         "remote_alpha_upgrade_es.py",
		"helper":                                      "upgrade",
	})
	if guard == "" {
		t.Fatal("the rotation's wrapper carries no clone check")
	}
	upgrade, err := os.ReadFile(repoPath("scripts/remote_alpha_upgrade_es.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(upgrade), "exec /usr/bin/python3 -I -B -c '") {
		t.Logf("the ES upgrade's wrapper has no embedded clone check yet (ES PR #63); nothing to compare")
		return
	}
	theirs := rotationWrapperGuard(t, string(upgrade), nil)
	if theirs != guard {
		t.Fatalf("the rotation's wrapper check and the ES upgrade's differ; make them the same\n--- rotation (names as the upgrade's)\n%s\n--- upgrade\n%s", guard, theirs)
	}
}
