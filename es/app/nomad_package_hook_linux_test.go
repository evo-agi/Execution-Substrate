package app_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// Red-team 45's O45-1, the part the setup's own take-back cannot reach:
// HashiCorp's nomad package runs `chown -R nomad:nomad /etc/nomad.d` and
// `chown nomad:nomad /opt/nomad/data` in its postinst on every install or
// upgrade (2.1.0 and 2.1.1 read; on an upgrade the old version's postrm has
// already restarted Nomad). Nomad's unit runs as root and reads those files
// when it next starts. The setup now installs a program that takes them back
// and a dpkg configuration that runs it as root after each dpkg run.

// nomadPackageHookRegion is the setup's nomad_package_hook region.
func nomadPackageHookRegion(t *testing.T) string {
	t.Helper()
	text := linuxSetupText(t)
	start := strings.Index(text, "\n# BEGIN nomad_package_hook")
	end := strings.Index(text, "\n# END nomad_package_hook\n")
	if start < 0 || end < start {
		t.Fatal("70_linux_setup.sh has no nomad_package_hook region")
	}
	return text[start+1 : end+1]
}

// runNomadPackageHookRegion runs steps after the region's functions, as the
// test user, with the given arguments as "$@".
func runNomadPackageHookRegion(t *testing.T, steps string, args ...string) (string, string, error) {
	t.Helper()
	command := exec.Command("bash", append([]string{"-c", "set -euo pipefail\n" + nomadPackageHookRegion(t) + steps, "bash"}, args...)...)
	command.Env = []string{"PATH=" + os.Getenv("PATH")}
	var stdout, stderr strings.Builder
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	return stdout.String(), stderr.String(), err
}

// nomadTakeBackProgram writes the program the setup installs to a file of
// the test's, mode 0755, and returns its path.
func nomadTakeBackProgram(t *testing.T) string {
	t.Helper()
	program, stderr, err := runNomadPackageHookRegion(t, "nomad_take_back_program\n")
	if err != nil {
		t.Fatalf("nomad_take_back_program: %v %s", err, stderr)
	}
	path := filepath.Join(t.TempDir(), "execution-substrate-nomad-take-back")
	if err := os.WriteFile(path, []byte(program), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// runTakeBack runs the program on a config folder and a data folder, as
// root through sudo when asRoot, otherwise as the test user.
func runTakeBack(t *testing.T, program string, asRoot bool, config, data string) (string, string, error) {
	t.Helper()
	argv := []string{"python3", "-I", program, config, data}
	if asRoot {
		argv = append([]string{"sudo", "-n"}, argv...)
	}
	command := exec.Command(argv[0], argv[1:]...)
	var stdout, stderr strings.Builder
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	return stdout.String(), stderr.String(), err
}

// rootTempDir is a temporary folder that sudo removes at the end, since the
// program leaves root's files in it.
func rootTempDir(t *testing.T) string {
	t.Helper()
	if exec.Command("sudo", "-n", "true").Run() != nil {
		t.Fatal("this test needs passwordless sudo, as CI has")
	}
	dir := t.TempDir()
	t.Cleanup(func() { runTestSudo(t, "rm", "-rf", "--", dir) })
	return dir
}

// sudoRead reads a file as root.
func sudoRead(t *testing.T, path string) string {
	t.Helper()
	output, err := exec.Command("sudo", "-n", "cat", "--", path).Output()
	if err != nil {
		t.Fatalf("sudo cat %s: %v", path, err)
	}
	return string(output)
}

// requireTaken fails unless path is a regular file of root's with mode and
// content, at a new inode, with no ACL.
func requireTaken(t *testing.T, path, content string, mode os.FileMode, old uint64) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode()&(os.ModePerm|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != mode {
		t.Fatalf("%s is %v, want a regular file %v", path, info.Mode(), mode)
	}
	requireOwner(t, path, 0, 0)
	if got := sudoRead(t, path); got != content {
		t.Fatalf("%s holds %q, want %q", path, got, content)
	}
	if inode(t, path) == old {
		t.Fatalf("%s was changed in place, not replaced by a new file", path)
	}
	requireNoACL(t, path)
}

// requireFolder fails unless path is a folder of uid:gid with mode and no
// ACL.
func requireFolder(t *testing.T, path string, uid, gid int, mode os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode().Perm() != mode || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		t.Fatalf("%s is %v, want a folder %v", path, info.Mode(), mode)
	}
	requireOwner(t, path, uid, gid)
	requireNoACL(t, path)
}

// takeBackReports is the program's lines that report a change.
func takeBackReports(output string) []string {
	var lines []string
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "execution-substrate: ") {
			lines = append(lines, line)
		}
	}
	return lines
}

// What the package leaves, with an ACL planted on the config folder and on
// one file, and files Nomad does not read: the program, run as root, takes
// back the three folders and each file Nomad reads, keeps the rest as they
// are, reports each change, and finds nothing to do the second time.
func TestNomadTakeBackProgramTakesBackWhatThePackageGaveAway(t *testing.T) {
	root := rootTempDir(t)
	config := filepath.Join(root, "etc")
	tlsDir := filepath.Join(config, "tls")
	data := filepath.Join(root, "data")
	for _, folder := range []string{tlsDir, data} {
		if err := os.MkdirAll(folder, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	type entry struct {
		path, content string
		mode, after   os.FileMode
	}
	taken := []entry{
		{filepath.Join(config, "extra.json"), "{\"datacenter\": \"dc1\"}\n", 0o666, 0o644},
		{filepath.Join(config, "nomad.env"), "", 0o644, 0o644},
		{filepath.Join(config, "nomad.hcl"), "# Managed by Execution Substrate\n", 0o640, 0o640},
		{filepath.Join(config, "setuid.hcl"), "# setuid\n", os.ModeSetuid | 0o775, 0o755},
		{filepath.Join(tlsDir, "ca.pem"), "ca\n", 0o644, 0o644},
		{filepath.Join(tlsDir, "server-key.pem"), "key\n", 0o600, 0o600},
		{filepath.Join(tlsDir, "server.pem"), "certificate\n", 0o644, 0o644},
	}
	kept := []entry{
		{filepath.Join(config, "README"), "readme\n", 0o666, 0o666},
		{filepath.Join(config, "nomad.hcl.execution-substrate.bak.20261126000000"), "# backup\n", 0o666, 0o666},
		{filepath.Join(config, "notes.hcl.txt"), "notes\n", 0o666, 0o666},
	}
	inodes := map[string]uint64{}
	for _, e := range append(append([]entry{}, taken...), kept...) {
		if err := os.WriteFile(e.path, []byte(e.content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(e.path, e.mode); err != nil {
			t.Fatal(err)
		}
		inodes[e.path] = inode(t, e.path)
	}
	// A file of root's but of another group: the group alone is reason to
	// take it back (re-check 50 of #66, O50-2, for the program).
	// It is made before the folder's default ACL, which it would inherit.
	grouped := entry{filepath.Join(config, "grouped.hcl"), "# grouped\n", 0o640, 0o640}
	if err := os.WriteFile(grouped.path, []byte(grouped.content), 0o640); err != nil {
		t.Fatal(err)
	}
	runTestSudo(t, "chown", "0:65534", "--", grouped.path)
	inodes[grouped.path] = inode(t, grouped.path)
	reading := encodedACL([][3]uint32{
		{aclUserObj, 6, aclNoID},
		{aclUser, 7, 65534},
		{aclGroupObj, 4, aclNoID},
		{aclMask, 4, aclNoID},
		{aclOther, 4, aclNoID},
	})
	if err := syscall.Setxattr(filepath.Join(config, "nomad.env"), "system.posix_acl_access", reading, 0); err != nil {
		t.Fatal(err)
	}
	plantACLs(t, config)
	// A key that stays root's, with its mode, but that an access ACL lets
	// the account read: the ACL alone is reason to take it back. Setting
	// the ACL shows its mask as the group's bits.
	aclOnly := entry{filepath.Join(tlsDir, "client-key.pem"), "client key\n", 0o600, 0o640}
	if err := os.WriteFile(aclOnly.path, []byte(aclOnly.content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Setxattr(aclOnly.path, "system.posix_acl_access", encodedACL([][3]uint32{
		{aclUserObj, 6, aclNoID},
		{aclUser, 4, 65534},
		{aclGroupObj, 0, aclNoID},
		{aclMask, 4, aclNoID},
		{aclOther, 0, aclNoID},
	}), 0); err != nil {
		t.Fatal(err)
	}
	runTestSudo(t, "chown", "0:0", "--", aclOnly.path)
	inodes[aclOnly.path] = inode(t, aclOnly.path)
	// What Nomad does not read either: a folder, and an editor's lock file,
	// which is a link.
	folder := filepath.Join(config, "conf.d.hcl")
	if err := os.Mkdir(folder, 0o755); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(config, ".#extra.hcl")
	if err := os.Symlink("operator@host.1234:1700000000", lock); err != nil {
		t.Fatal(err)
	}
	// A link left at the temporary name of a file the program takes back
	// (by a run cut off, or by the account while it owned the folder): it
	// is removed, not followed or refused.
	leftTarget := filepath.Join(t.TempDir(), "left")
	if err := os.WriteFile(leftTarget, []byte("left\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(leftTarget, filepath.Join(config, "extra.json.execution-substrate-new")); err != nil {
		t.Fatal(err)
	}
	// A handle opened while the file was still writable.
	handle, err := os.OpenFile(filepath.Join(config, "extra.json"), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	// The package's postinst: everything below the config folder, and the
	// data folder, to another account (65534 stands in for nomad).
	others := []string{config, tlsDir, data, folder}
	for _, e := range append(append([]entry{}, taken...), kept...) {
		others = append(others, e.path)
	}
	runTestSudo(t, append([]string{"chown", "65534:65534", "--"}, others...)...)
	// chown dropped the setuid bit; the account may set it again.
	runTestSudo(t, "chmod", "4775", "--", filepath.Join(config, "setuid.hcl"))
	program := nomadTakeBackProgram(t)

	stdout, stderr, err := runTakeBack(t, program, true, config, data)
	if err != nil {
		t.Fatalf("the program: %v %s %s", err, stdout, stderr)
	}
	was := func(path, from string) string {
		return "execution-substrate: took " + path + " back (it was " + from + "); Nomad reads it as root, so check what it sets"
	}
	want := []string{
		// The access ACL's mask shows as the group's bits.
		"execution-substrate: took " + config + " back (it was uid 65534, gid 65534, 0775)",
		"execution-substrate: removed the default ACL that was left on " + config,
		"execution-substrate: removed the access ACL that was left on " + config,
		was(filepath.Join(config, "extra.json"), "uid 65534, gid 65534, 0666"),
		was(grouped.path, "uid 0, gid 65534, 0640"),
		was(filepath.Join(config, "nomad.env"), "uid 65534, gid 65534, 0644, with an ACL"),
		was(filepath.Join(config, "nomad.hcl"), "uid 65534, gid 65534, 0640"),
		was(filepath.Join(config, "setuid.hcl"), "uid 65534, gid 65534, 4775"),
		"execution-substrate: took " + tlsDir + " back (it was uid 65534, gid 65534, 0755)",
		was(filepath.Join(tlsDir, "ca.pem"), "uid 65534, gid 65534, 0644"),
		was(aclOnly.path, "uid 0, gid 0, 0640, with an ACL"),
		was(filepath.Join(tlsDir, "server-key.pem"), "uid 65534, gid 65534, 0600"),
		was(filepath.Join(tlsDir, "server.pem"), "uid 65534, gid 65534, 0644"),
		"execution-substrate: took " + data + " back (it was uid 65534, gid 65534, 0755)",
	}
	if got := takeBackReports(stdout); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the program reported\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if stderr != "" {
		t.Fatalf("the program wrote to its error output: %s", stderr)
	}
	requireFolder(t, config, 0, 0, 0o755)
	requireFolder(t, tlsDir, 0, 0, 0o755)
	requireFolder(t, data, 0, 0, 0o700)
	for _, e := range append(append([]entry{}, taken...), aclOnly, grouped) {
		requireTaken(t, e.path, e.content, e.after, inodes[e.path])
	}
	for _, e := range kept {
		requireRegularFile(t, e.path, e.content, e.after)
		requireOwner(t, e.path, 65534, 65534)
		if inode(t, e.path) != inodes[e.path] {
			t.Fatalf("%s was replaced", e.path)
		}
	}
	requireOwner(t, folder, 65534, 65534)
	if target, err := os.Readlink(lock); err != nil || target != "operator@host.1234:1700000000" {
		t.Fatalf("the lock file was changed: %q %v", target, err)
	}
	// The handle opened before reaches the old file only.
	if _, err := handle.WriteString("{\"datacenter\": \"elsewhere\"}\n"); err != nil {
		t.Fatal(err)
	}
	if got := sudoRead(t, filepath.Join(config, "extra.json")); got != "{\"datacenter\": \"dc1\"}\n" {
		t.Fatalf("a handle opened before the take-back still writes the config: %q", got)
	}
	requireRegularFile(t, leftTarget, "left\n", 0o644)
	for _, folder := range []string{config, tlsDir} {
		entries, err := os.ReadDir(folder)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".execution-substrate-new") {
				t.Fatalf("a temporary file was left in %s: %s", folder, e.Name())
			}
		}
	}

	// A second run takes nothing back and replaces nothing.
	after := map[string]uint64{}
	for _, e := range taken {
		after[e.path] = inode(t, e.path)
	}
	stdout, stderr, err = runTakeBack(t, program, true, config, data)
	if err != nil || stdout != "" || stderr != "" {
		t.Fatalf("a second run: %v %q %q", err, stdout, stderr)
	}
	for _, e := range taken {
		if inode(t, e.path) != after[e.path] {
			t.Fatalf("a second run replaced %s", e.path)
		}
	}
}

// Where Nomad reads a folder or file, what the program cannot take back (a
// link, a FIFO) is refused. A refusal stops nothing else: the rest is taken
// back first, then the program fails and names each refusal and the command
// to run again. A folder that is not there is passed over.
func TestNomadTakeBackProgramRefusesWhatItCannotTakeBackAndTakesBackTheRest(t *testing.T) {
	program := nomadTakeBackProgram(t)
	type layout struct{ config, tlsDir, data string }
	setup := func(t *testing.T) layout {
		t.Helper()
		root := t.TempDir()
		l := layout{filepath.Join(root, "etc"), filepath.Join(root, "etc", "tls"), filepath.Join(root, "data")}
		for _, folder := range []string{l.tlsDir, l.data} {
			if err := os.MkdirAll(folder, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		// Files of the test user's that group and others can write, which
		// the program takes back to the test user.
		for _, path := range []string{filepath.Join(l.config, "nomad.hcl"), filepath.Join(l.tlsDir, "ca.pem")} {
			if err := os.WriteFile(path, []byte("x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o666); err != nil {
				t.Fatal(err)
			}
		}
		return l
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(outside, 0o666); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		plant   func(t *testing.T, l layout) string
		refused string
		// Whether the TLS folder's file is still taken back.
		tlsTaken bool
	}{
		{"a link at an extra config file", func(t *testing.T, l layout) string {
			path := filepath.Join(l.config, "extra.hcl")
			if err := os.Symlink(outside, path); err != nil {
				t.Fatal(err)
			}
			return path
		}, "is a link, not a regular file", true},
		{"a link at nomad.env", func(t *testing.T, l layout) string {
			path := filepath.Join(l.config, "nomad.env")
			if err := os.Symlink(outside, path); err != nil {
				t.Fatal(err)
			}
			return path
		}, "is a link, not a regular file", true},
		{"a FIFO at nomad.env", func(t *testing.T, l layout) string {
			path := filepath.Join(l.config, "nomad.env")
			if err := syscall.Mkfifo(path, 0o644); err != nil {
				t.Fatal(err)
			}
			return path
		}, "is neither a file nor a folder, not a regular file", true},
		{"a link at the server key", func(t *testing.T, l layout) string {
			path := filepath.Join(l.tlsDir, "server-key.pem")
			if err := os.Symlink(outside, path); err != nil {
				t.Fatal(err)
			}
			return path
		}, "is a link, not a regular file", true},
		{"a link at the TLS folder", func(t *testing.T, l layout) string {
			target := filepath.Join(filepath.Dir(l.data), "elsewhere")
			if err := os.Rename(l.tlsDir, target); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, l.tlsDir); err != nil {
				t.Fatal(err)
			}
			return l.tlsDir
		}, "is a link, not a folder", false},
		{"a file at the TLS folder", func(t *testing.T, l layout) string {
			if err := os.RemoveAll(l.tlsDir); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(l.tlsDir, nil, 0o644); err != nil {
				t.Fatal(err)
			}
			return l.tlsDir
		}, "is a file, not a folder", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := setup(t)
			if err := os.Chmod(l.data, 0o755); err != nil {
				t.Fatal(err)
			}
			path := tc.plant(t, l)
			stdout, stderr, err := runTakeBack(t, program, false, l.config, l.data)
			if err == nil {
				t.Fatalf("the program took back %s: %s", path, stdout)
			}
			want := "execution-substrate: " + path + " " + tc.refused + ", and Nomad's unit reads it as root\n" +
				"execution-substrate: fix that, then run " + program + " " + l.config + " " + l.data + " again\n"
			if stderr != want {
				t.Fatalf("the program said\n%s\nwant\n%s", stderr, want)
			}
			// The rest is taken back.
			requireRegularFile(t, filepath.Join(l.config, "nomad.hcl"), "x\n", 0o644)
			requireFolder(t, l.data, os.Getuid(), os.Getgid(), 0o700)
			if tc.tlsTaken {
				requireRegularFile(t, filepath.Join(l.tlsDir, "ca.pem"), "x\n", 0o644)
			}
			requireRegularFile(t, outside, "outside\n", 0o666)
		})
	}

	t.Run("a link at the config folder", func(t *testing.T) {
		l := setup(t)
		target := filepath.Join(filepath.Dir(l.data), "elsewhere")
		if err := os.Rename(l.config, target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, l.config); err != nil {
			t.Fatal(err)
		}
		_, stderr, err := runTakeBack(t, program, false, l.config, l.data)
		if err == nil || !strings.Contains(stderr, "execution-substrate: "+l.config+" is a link, not a folder, and Nomad's unit reads it as root\n") {
			t.Fatalf("the program took back the config folder through a link: %v %s", err, stderr)
		}
		requireRegularFile(t, filepath.Join(target, "nomad.hcl"), "x\n", 0o666)
		requireFolder(t, l.data, os.Getuid(), os.Getgid(), 0o700)
	})

	t.Run("missing folders are passed over", func(t *testing.T) {
		root := t.TempDir()
		stdout, stderr, err := runTakeBack(t, program, false, filepath.Join(root, "etc"), filepath.Join(root, "data"))
		if err != nil || stdout != "" || stderr != "" {
			t.Fatalf("with no folders: %v %q %q", err, stdout, stderr)
		}
		config := filepath.Join(root, "etc")
		if err := os.Mkdir(config, 0o755); err != nil {
			t.Fatal(err)
		}
		stdout, stderr, err = runTakeBack(t, program, false, config, filepath.Join(root, "data"))
		if err != nil || stdout != "" || stderr != "" {
			t.Fatalf("with no TLS or data folder: %v %q %q", err, stdout, stderr)
		}
	})
}

// Each file is synced before it is renamed over the old one, and each folder
// after its last rename, so a crash cannot leave an empty or missing file
// where Nomad reads its config. A folder is made the caller's before its
// mode is set and its ACLs removed: until then the former owner may change
// the mode or set an ACL again. The program runs with os.fsync, os.rename,
// os.fchown, os.fchmod and os.removexattr wrapped to log their order.
func TestNomadTakeBackProgramSyncsAndTakesFoldersInOrder(t *testing.T) {
	program := nomadTakeBackProgram(t)
	root := t.TempDir()
	config := filepath.Join(root, "etc")
	tlsDir := filepath.Join(config, "tls")
	if err := os.MkdirAll(tlsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// The config folder open to others, with a default ACL, as the former
	// owner may leave it.
	if err := os.Chmod(config, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Setxattr(config, "system.posix_acl_default", grantingACL(), 0); err != nil {
		t.Fatal(err)
	}
	files := []string{filepath.Join(config, "extra.hcl"), filepath.Join(config, "nomad.hcl"), filepath.Join(tlsDir, "ca.pem")}
	for _, path := range files {
		if err := os.WriteFile(path, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o666); err != nil {
			t.Fatal(err)
		}
	}
	wrapper := `
import os, runpy, stat, sys
real_fsync, real_rename = os.fsync, os.rename
def fsync(fd):
    st = os.fstat(fd)
    print(("folder" if stat.S_ISDIR(st.st_mode) else "file") + " synced " + str(st.st_ino))
    real_fsync(fd)
def rename(src, dst, *args, **kwargs):
    print("renamed " + str(os.lstat(src).st_ino) + " " + str(dst))
    real_rename(src, dst, *args, **kwargs)
def logged(name, real):
    def call(fd, *args):
        st = os.fstat(fd)
        if stat.S_ISDIR(st.st_mode):
            print(name + " folder " + str(st.st_ino) + "".join(" " + str(a) for a in args if isinstance(a, str)))
        return real(fd, *args)
    return call
os.fsync, os.rename = fsync, rename
os.fchown, os.fchmod, os.removexattr = logged("fchown", os.fchown), logged("fchmod", os.fchmod), logged("removexattr", os.removexattr)
sys.argv = sys.argv[1:]
runpy.run_path(sys.argv[0], run_name="__main__")
`
	output, err := exec.Command("python3", "-I", "-c", wrapper, program, config, filepath.Join(root, "data")).CombinedOutput()
	if err != nil {
		t.Fatalf("the program: %v %s", err, output)
	}
	var log []string
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "file synced ") || strings.HasPrefix(line, "folder synced ") || strings.HasPrefix(line, "renamed ") ||
			strings.HasPrefix(line, "fchown folder ") || strings.HasPrefix(line, "fchmod folder ") || strings.HasPrefix(line, "removexattr folder ") {
			log = append(log, line)
		}
	}
	folderInode := func(path string) string { return strconv.FormatUint(inode(t, path), 10) }
	want := []string{"fchown folder " + folderInode(config), "fchmod folder " + folderInode(config),
		"removexattr folder " + folderInode(config) + " system.posix_acl_default"}
	for i, path := range files {
		ino := folderInode(path)
		want = append(want, "file synced "+ino, "renamed "+ino+" "+path)
		if i == 1 {
			want = append(want, "folder synced "+folderInode(config))
		}
	}
	want = append(want, "folder synced "+folderInode(tlsDir))
	if strings.Join(log, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the program synced and renamed\n%s\nwant\n%s", strings.Join(log, "\n"), strings.Join(want, "\n"))
	}
}

// The program and the setup's own take-back agree on which files Nomad
// reads: the program takes back what the setup does, and nomad.hcl, which
// the setup writes new instead.
func TestNomadTakeBackProgramTakesBackWhatTheSetupDoesAndNomadHCL(t *testing.T) {
	names := []string{"nomad.hcl", "nomad.env", "extra.hcl", "extra.json", "a.b.hcl", ".hidden.hcl", "#hash.json", ".#lock.hcl",
		"README", "nomad.env.bak", "x.hcl.txt", "x.json~", "#x.hcl#", "x.HCL", "nomad.hcl.execution-substrate.bak.1"}
	plant := func(t *testing.T) string {
		t.Helper()
		folder := t.TempDir()
		for _, name := range names {
			path := filepath.Join(folder, name)
			if err := os.WriteFile(path, []byte(name+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o666); err != nil {
				t.Fatal(err)
			}
		}
		return folder
	}
	taken := func(t *testing.T, folder string) []string {
		t.Helper()
		var got []string
		for _, name := range names {
			info, err := os.Lstat(filepath.Join(folder, name))
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() == 0o644 {
				got = append(got, name)
			}
		}
		return got
	}

	program := nomadTakeBackProgram(t)
	byProgram := plant(t)
	if _, stderr, err := runTakeBack(t, program, false, byProgram, filepath.Join(t.TempDir(), "data")); err != nil {
		t.Fatalf("the program: %v %s", err, stderr)
	}
	bySetup := plant(t)
	text := linuxSetupText(t)
	steps := "sudo() { \"$@\"; }\n" + linuxSetupFunction(t, text, "nomad_config_files_take_back") + "nomad_config_files_take_back \"$1\"\n"
	if output, err := exec.Command("bash", "-c", "set -euo pipefail\n"+steps, "bash", bySetup).CombinedOutput(); err != nil {
		t.Fatalf("the setup's take-back: %v %s", err, output)
	}
	got, want := taken(t, byProgram), append([]string{"nomad.hcl"}, taken(t, bySetup)...)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("the program took back %v, the setup %v (and nomad.hcl): they disagree on what Nomad reads", got, want)
	}
}

// install_nomad_package_hook writes the program and the dpkg configuration,
// each as a new file of the caller's renamed into place (a link at either
// name is replaced, not followed), and runs the program once. A rerun
// writes the same bytes. A folder others can write is refused, and so is
// anything the program refuses.
func TestLinuxSetupInstallsTheNomadPackageHook(t *testing.T) {
	root := t.TempDir()
	program := filepath.Join(root, "sbin", "execution-substrate-nomad-take-back")
	hook := filepath.Join(root, "dpkg.cfg.d", "execution-substrate-nomad")
	config := filepath.Join(root, "etc")
	data := filepath.Join(root, "data")
	for _, folder := range []string{config, data, filepath.Dir(hook)} {
		if err := os.MkdirAll(folder, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	nomadHCL := filepath.Join(config, "nomad.hcl")
	if err := os.WriteFile(nomadHCL, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(nomadHCL, 0o666); err != nil {
		t.Fatal(err)
	}
	// Links at both names, to files outside that must not change.
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, hook); err != nil {
		t.Fatal(err)
	}

	install := "install_nomad_package_hook \"$1\" \"$2\" \"$3\" \"$4\"\n"
	stdout, stderr, err := runNomadPackageHookRegion(t, install, program, hook, config, data)
	if err != nil {
		t.Fatalf("install_nomad_package_hook: %v %s", err, stderr)
	}
	expected, _, err := runNomadPackageHookRegion(t, "nomad_take_back_program\n")
	if err != nil {
		t.Fatal(err)
	}
	requireRegularFile(t, program, expected, 0o755)
	requireFolder(t, filepath.Dir(program), os.Getuid(), os.Getgid(), 0o755)
	wantHook := "# Written by Execution Substrate (scripts/70_linux_setup.sh, or the box upgrade). After each dpkg\n" +
		"# run, take Nomad's folders and the files it reads back from the nomad account, which the nomad\n" +
		"# package's postinst gives them to. Remove this file and the program together.\n" +
		"post-invoke=\"if [ -e " + program + " ]; then " + program + " " + config + " " + data + "; fi\"\n"
	requireRegularFile(t, hook, wantHook, 0o644)
	requireRegularFile(t, outside, "outside\n", 0o644)
	// The program ran once: nomad.hcl and the data folder are taken back.
	requireRegularFile(t, nomadHCL, "x\n", 0o644)
	requireFolder(t, data, os.Getuid(), os.Getgid(), 0o700)
	if !strings.Contains(stdout, "execution-substrate: took "+nomadHCL+" back") {
		t.Fatalf("the program's report is missing: %s", stdout)
	}

	// dpkg strips the quotes around the option's value and runs it with
	// sh -c: so run, it runs the program, and runs nothing once the
	// program is gone.
	value := strings.TrimSuffix(strings.TrimPrefix(strings.Split(wantHook, "\n")[3], "post-invoke=\""), "\"")
	if err := os.Chmod(nomadHCL, 0o666); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("sh", "-c", value).CombinedOutput(); err != nil || !strings.Contains(string(output), "took "+nomadHCL+" back") {
		t.Fatalf("sh -c %q: %v %s", value, err, output)
	}
	gone := strings.ReplaceAll(value, program, program+".gone")
	if output, err := exec.Command("sh", "-c", gone).CombinedOutput(); err != nil || len(output) != 0 {
		t.Fatalf("with the program gone, sh -c %q: %v %s", gone, err, output)
	}

	// A rerun writes the same bytes, as new files, past what a cut-off run
	// may leave at the temporary names: a file, and a link that is removed,
	// not followed.
	if err := os.WriteFile(program+".execution-substrate-new", []byte("cut off\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, hook+".execution-substrate-new"); err != nil {
		t.Fatal(err)
	}
	before := inode(t, program)
	if _, stderr, err := runNomadPackageHookRegion(t, install, program, hook, config, data); err != nil {
		t.Fatalf("install_nomad_package_hook, again: %v %s", err, stderr)
	}
	requireRegularFile(t, program, expected, 0o755)
	requireRegularFile(t, hook, wantHook, 0o644)
	requireRegularFile(t, outside, "outside\n", 0o644)
	if inode(t, program) == before {
		t.Fatal("a rerun wrote the program in place")
	}
	for _, folder := range []string{filepath.Dir(program), filepath.Dir(hook)} {
		entries, err := os.ReadDir(folder)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 {
			t.Fatalf("%s holds %d entries, want only the file written", folder, len(entries))
		}
	}

	t.Run("a folder others can write is refused", func(t *testing.T) {
		if err := os.Chmod(filepath.Dir(hook), 0o777); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(filepath.Dir(hook), 0o755) })
		_, stderr, err := runNomadPackageHookRegion(t, install, program, hook, config, data)
		if err == nil || !strings.Contains(stderr, "nomad: "+filepath.Dir(hook)+" is not owned by uid "+strconv.Itoa(os.Getuid())+
			" and closed to group and others (uid "+strconv.Itoa(os.Getuid())+", 0777); refusing to write "+hook+" there") {
			t.Fatalf("the hook was written into a folder others can write: %v %s", err, stderr)
		}
	})

	t.Run("what the program refuses stops the install", func(t *testing.T) {
		link := filepath.Join(config, "extra.hcl")
		if err := os.Symlink(outside, link); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(link) })
		_, stderr, err := runNomadPackageHookRegion(t, install, program, hook, config, data)
		if err == nil || !strings.Contains(stderr, link+" is a link, not a regular file") {
			t.Fatalf("the install went on past a link the program refused: %v %s", err, stderr)
		}
	})
}

// The setup installs the hook as root, right after the service config and
// before it qualifies Nomad, with its own paths; the root wrapper hands
// every function the install needs to sudo's bash.
func TestLinuxSetupInstallsTheNomadPackageHookAsRootAfterTheServiceConfig(t *testing.T) {
	text := linuxSetupText(t)
	call := `nomad_package_hook_as_root install_nomad_package_hook "${NOMAD_TAKE_BACK_PROGRAM}" "${NOMAD_DPKG_HOOK}" "${NOMAD_CONFIG_DIR}" "${NOMAD_DATA_DIR}"` + "\n"
	if !strings.Contains(text, "\ninstall_nomad_service_config\n"+call+"warn_existing_nomad_processes\n") {
		t.Fatalf("the setup does not install the hook right after install_nomad_service_config:\n%s", call)
	}
	for _, line := range []string{
		`NOMAD_TAKE_BACK_PROGRAM="/usr/local/sbin/execution-substrate-nomad-take-back"`,
		`NOMAD_DPKG_HOOK="/etc/dpkg/dpkg.cfg.d/execution-substrate-nomad"`,
	} {
		if !regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(line) + `$`).MatchString(text) {
			t.Fatalf("the setup does not define %s", line)
		}
	}
	// dpkg reads only the files in dpkg.cfg.d whose names are letters,
	// digits, "_" and "-".
	if !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString("execution-substrate-nomad") {
		t.Fatal("dpkg would skip the hook's file name")
	}

	// The wrapper runs the install under sudo, with the region's functions.
	root := t.TempDir()
	calls := filepath.Join(root, "sudo-calls.log")
	program := filepath.Join(root, "sbin", "take-back")
	hook := filepath.Join(root, "hook", "execution-substrate-nomad")
	steps := `sudo() { printf '%s\n' "$1 $2 ${@: -5:1}" >>"` + calls + `"; "$@"; }` + "\n" +
		"nomad_package_hook_as_root install_nomad_package_hook \"$1\" \"$2\" \"$3\" \"$4\"\n"
	if _, stderr, err := runNomadPackageHookRegion(t, steps, program, hook, filepath.Join(root, "etc"), filepath.Join(root, "data")); err != nil {
		t.Fatalf("nomad_package_hook_as_root: %v %s", err, stderr)
	}
	body, err := os.ReadFile(calls)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(body)); got != "bash -c install_nomad_package_hook" {
		t.Fatalf("sudo ran %q, want the install under bash -c", got)
	}
	requireFileMode(t, program, 0o755)
	requireFileMode(t, hook, 0o644)
}

// nomad_new_file_write syncs the new file before its rename and the folder
// after it, so a crash cannot leave an empty program or dpkg configuration
// in place. python3 is redefined to run the function's code with os.fsync
// and os.rename wrapped to log their order.
func TestLinuxSetupWritesTheHookFilesSyncedBeforeTheirRename(t *testing.T) {
	folder := t.TempDir()
	path := filepath.Join(folder, "execution-substrate-nomad")
	wrapper := `
import os, stat, sys
real_fsync, real_rename = os.fsync, os.rename
def fsync(fd):
    st = os.fstat(fd)
    print(("folder" if stat.S_ISDIR(st.st_mode) else "file") + " synced " + str(st.st_ino))
    real_fsync(fd)
def rename(src, dst, *args, **kwargs):
    print("renamed " + str(os.lstat(src, dir_fd=kwargs.get("src_dir_fd")).st_ino) + " " + dst)
    real_rename(src, dst, *args, **kwargs)
os.fsync, os.rename = fsync, rename
code = sys.argv[1]
sys.argv = ["-c"] + sys.argv[2:]
exec(compile(code, "<nomad_new_file_write>", "exec"))
`
	steps := "python3() { [[ \"$1 $2\" == \"-I -c\" ]] || return 99; command python3 -I -c \"$WRAPPER\" \"${@:3}\"; }\n" +
		"printf 'post-invoke=x\\n' | nomad_new_file_write 0644 \"$1\"\n"
	command := exec.Command("bash", "-c", "set -euo pipefail\n"+nomadPackageHookRegion(t)+steps, "bash", path)
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "WRAPPER=" + wrapper}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("nomad_new_file_write: %v %s", err, output)
	}
	requireRegularFile(t, path, "post-invoke=x\n", 0o644)
	file := strconv.FormatUint(inode(t, path), 10)
	want := "file synced " + file + "\nrenamed " + file + " execution-substrate-nomad\nfolder synced " + strconv.FormatUint(inode(t, folder), 10) + "\n"
	if string(output) != want {
		t.Fatalf("nomad_new_file_write synced and renamed\n%s\nwant\n%s", output, want)
	}
}

// Re-check 50 (Sonnet's O50-1 on #66, for the program): the nomad account
// chose the names the program reports. A name with a newline would forge a
// line of dpkg's output, one that is not UTF-8 would print raw bytes, and
// one with a letter that only looks like ASCII (a Cyrillic a) could pass for
// another file, so a name that is not plain printable ASCII is shown
// quoted, with Python's escapes, in a take-back line and in a refusal.
func TestNomadTakeBackProgramShowsANameThatIsNotPlainPrintableASCIIEscaped(t *testing.T) {
	root := rootTempDir(t)
	config := filepath.Join(root, "etc")
	data := filepath.Join(root, "data")
	if err := os.Mkdir(config, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	names := []string{"a\nexecution-substrate: took forged back.hcl", "bad\xff.json", "nomаd.hcl"}
	var paths []string
	for _, name := range names {
		path := filepath.Join(config, name)
		if err := os.WriteFile(path, []byte("# kept\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	if err := os.Symlink("/etc/hostname", filepath.Join(config, "link\nx.hcl")); err != nil {
		t.Fatal(err)
	}
	runTestSudo(t, append([]string{"chown", "65534:65534", "--"}, paths...)...)
	runTestSudo(t, "chown", "0:0", "--", config, data)
	program := nomadTakeBackProgram(t)

	stdout, stderr, err := runTakeBack(t, program, true, config, data)
	if err == nil {
		t.Fatalf("the program took a link back: %s %s", stdout, stderr)
	}
	was := " back (it was uid 65534, gid 65534, 0644); Nomad reads it as root, so check what it sets"
	want := []string{
		"execution-substrate: took '" + config + "/a\\nexecution-substrate: took forged back.hcl'" + was,
		"execution-substrate: took '" + config + "/bad\\udcff.json'" + was,
		"execution-substrate: took '" + config + "/nom\\u0430d.hcl'" + was,
	}
	if got := takeBackReports(stdout); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the program reported\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	refusal := "execution-substrate: '" + config + "/link\\nx.hcl' is a link, not a regular file, and Nomad's unit reads it as root"
	if !strings.Contains(stderr, refusal) {
		t.Fatalf("want %q in: %s", refusal, stderr)
	}
	for _, path := range paths {
		requireTaken(t, path, "# kept\n", 0o644, 0)
	}
}
