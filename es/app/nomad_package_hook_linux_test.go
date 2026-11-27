package app_test

import (
	"encoding/json"
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
// and a dpkg configuration that runs it as root after each dpkg run, and it
// runs the program itself before it writes there. What the program cannot
// take back it sets aside, out of Nomad's reach (audit 51 of #83, A51-4).

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

// setAsideRun is the pattern of the name of the folder that one run of the
// program sets entries aside in: the time, and eight random hex digits.
const setAsideRun = `[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}`

// setAsideFolder is where the program sets aside entries of folder.
func setAsideFolder(folder string) string {
	return folder + ".execution-substrate-set-aside"
}

// setAsideLine is the pattern of the program's line for path, which it set
// aside from folder (into the run folder's sub, when not "") because of why.
func setAsideLine(path, why, folder, sub string) string {
	target := regexp.QuoteMeta(setAsideFolder(folder)+"/") + setAsideRun + "/"
	if sub != "" {
		target += regexp.QuoteMeta(sub + "/")
	}
	target += regexp.QuoteMeta(filepath.Base(path))
	return regexp.QuoteMeta("execution-substrate: set aside "+path+" ("+why+"): it is ") + target +
		regexp.QuoteMeta(" now, which Nomad does not read")
}

// lookLine is the pattern of the program's line that sends the operator to
// what it set aside from folder.
func lookLine(folder string) string {
	aside := setAsideFolder(folder)
	return regexp.QuoteMeta("execution-substrate: look at what is set aside in " + aside +
		", then remove that folder (rm -rf -- " + aside + "); until then Execution Substrate's setup and box upgrade refuse this host")
}

// requireLines fails unless output is one line for each pattern, in order.
func requireLines(t *testing.T, output string, patterns []string) {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(output, "\n"), "\n")
	if output == "" {
		lines = nil
	}
	ok := len(lines) == len(patterns)
	for i := 0; ok && i < len(lines); i++ {
		ok = regexp.MustCompile("^" + patterns[i] + "$").MatchString(lines[i])
	}
	if !ok {
		t.Fatalf("the program said\n%s\nwant lines matching\n%s", output, strings.Join(patterns, "\n"))
	}
}

// entryStat is what lstat says of an entry.
type entryStat struct {
	UID, GID int
	Mode     uint32
	Ino      uint64
	ACL      []string
}

// kind is the entry's file type (syscall.S_IFREG and so on).
func (st entryStat) kind() uint32 { return st.Mode & syscall.S_IFMT }

// setAsideEntry is the path of the one entry named name that a run set
// aside from folder (in the run folder's sub, when not ""), and what lstat
// says of it. The set-aside folder and the run folder (and sub) are
// uid:gid's (the program's caller), 0700, with no ACL. They are looked at
// as root when uid is 0, since then only root can look into them.
func setAsideEntry(t *testing.T, folder, sub, name string, uid, gid int) (string, entryStat) {
	t.Helper()
	script := `
import json, os, sys
aside, sub, name = sys.argv[1:]
def info(path):
    st = os.lstat(path)
    acl = [a for a in os.listxattr(path, follow_symlinks=False) if a.startswith("system.posix_acl_")]
    return {"UID": st.st_uid, "GID": st.st_gid, "Mode": st.st_mode, "Ino": st.st_ino, "ACL": acl}
runs = sorted(os.listdir(aside))
out = {"runs": runs, "aside": info(aside)}
if len(runs) == 1:
    run = os.path.join(aside, runs[0])
    out["run"] = info(run)
    if sub:
        out["sub"] = info(os.path.join(run, sub))
    try:
        out["entry"] = info(os.path.join(run, sub, name))
    except FileNotFoundError:
        pass
print(json.dumps(out))
`
	argv := []string{"python3", "-I", "-c", script, setAsideFolder(folder), sub, name}
	if uid == 0 {
		argv = append([]string{"sudo", "-n"}, argv...)
	}
	output, err := exec.Command(argv[0], argv[1:]...).Output()
	if err != nil {
		t.Fatalf("looking into %s: %v", setAsideFolder(folder), err)
	}
	var got struct {
		Runs                   []string
		Aside, Run, Sub, Entry *entryStat
	}
	if err := json.Unmarshal(output, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Runs) != 1 || !regexp.MustCompile("^"+setAsideRun+"$").MatchString(got.Runs[0]) {
		t.Fatalf("%s holds %v, want one run folder", setAsideFolder(folder), got.Runs)
	}
	run := filepath.Join(setAsideFolder(folder), got.Runs[0])
	folders := map[string]*entryStat{setAsideFolder(folder): got.Aside, run: got.Run}
	if sub != "" {
		folders[filepath.Join(run, sub)] = got.Sub
	}
	for path, st := range folders {
		if st == nil || st.kind() != syscall.S_IFDIR || st.Mode&0o7777 != 0o700 || st.UID != uid || st.GID != gid || len(st.ACL) != 0 {
			t.Fatalf("%s is %+v, want a folder of %d:%d, 0700, with no ACL", path, st, uid, gid)
		}
	}
	path := filepath.Join(run, sub, name)
	if got.Entry == nil {
		t.Fatalf("%s is not there", path)
	}
	return path, *got.Entry
}

// sudoStat is what stat says of path, as root: its owner, group, mode and
// file type.
func sudoStat(t *testing.T, path string) string {
	t.Helper()
	output, err := exec.Command("sudo", "-n", "stat", "-c", "%u:%g %a %F", "--", path).Output()
	if err != nil {
		t.Fatalf("sudo stat %s: %v", path, err)
	}
	return strings.TrimSpace(string(output))
}

// requireNothingSetAside fails if the program set anything aside from
// folder.
func requireNothingSetAside(t *testing.T, folder string) {
	t.Helper()
	if _, err := os.Lstat(setAsideFolder(folder)); !os.IsNotExist(err) {
		t.Fatalf("%s is there (%v), but nothing was to be set aside", setAsideFolder(folder), err)
	}
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
// are, reports each change, sets nothing aside, and finds nothing to do the
// second time.
func TestNomadTakeBackProgramTakesBackWhatThePackageGaveAway(t *testing.T) {
	root := rootTempDir(t)
	config := filepath.Join(root, "etc")
	tlsDir := filepath.Join(config, "tls")
	data := filepath.Join(root, "data")
	// Nomad's server folder, root's as Nomad makes it: kept.
	server := filepath.Join(data, "server")
	for _, folder := range []string{tlsDir, server} {
		if err := os.MkdirAll(folder, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	runTestSudo(t, "chown", "0:0", "--", server)
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
	// What a run cut off leaves at the program's temporary names (or the
	// account, while it owned the folder): a file and a link are removed (the
	// link not followed), a folder is kept, and none is taken back or set
	// aside (audit 51 of #83, A51-1). An earlier version's temporary name,
	// which Nomad never reads, is kept as it is, in the config folder and in
	// the TLS folder.
	leftTarget := filepath.Join(t.TempDir(), "left")
	if err := os.WriteFile(leftTarget, []byte("left\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	leftFiles := []string{filepath.Join(config, ".execution-substrate-take-back-0123456789abcdef"),
		filepath.Join(tlsDir, ".execution-substrate-take-back-fedcba9876543210")}
	for _, path := range leftFiles {
		if err := os.WriteFile(path, []byte("cut off\n"), 0o666); err != nil {
			t.Fatal(err)
		}
	}
	leftLink := filepath.Join(config, ".execution-substrate-take-back-link")
	if err := os.Symlink(leftTarget, leftLink); err != nil {
		t.Fatal(err)
	}
	leftFolder := filepath.Join(config, ".execution-substrate-take-back-folder")
	if err := os.Mkdir(leftFolder, 0o755); err != nil {
		t.Fatal(err)
	}
	legacyLink := filepath.Join(config, "extra.json.execution-substrate-new")
	if err := os.Symlink(leftTarget, legacyLink); err != nil {
		t.Fatal(err)
	}
	legacyFile := filepath.Join(tlsDir, "server.pem.execution-substrate-new")
	if err := os.WriteFile(legacyFile, []byte("cut off\n"), 0o600); err != nil {
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
	others := []string{config, tlsDir, data, folder, leftFolder, legacyFile}
	others = append(others, leftFiles...)
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
			if strings.HasPrefix(e.Name(), ".execution-substrate-take-back-") && filepath.Join(folder, e.Name()) != leftFolder {
				t.Fatalf("a temporary name was left in %s: %s", folder, e.Name())
			}
		}
	}
	requireOwner(t, leftFolder, 65534, 65534)
	if target, err := os.Readlink(legacyLink); err != nil || target != leftTarget {
		t.Fatalf("the earlier version's temporary name was changed: %q %v", target, err)
	}
	if got := sudoStat(t, legacyFile); got != "65534:65534 600 regular file" || sudoRead(t, legacyFile) != "cut off\n" {
		t.Fatalf("the earlier version's temporary name in the TLS folder was changed: %s", got)
	}
	if got := sudoStat(t, server); got != "0:0 755 directory" {
		t.Fatalf("Nomad's server folder is %s now, want it kept (0:0 755 directory)", got)
	}
	requireNothingSetAside(t, config)
	requireNothingSetAside(t, data)

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
// link, a FIFO, a file where a folder belongs, a file larger than 1 MiB, an
// entry it fails on) it sets aside: it moves it, without reading or
// following it, into a folder of the caller's beside the config folder, so
// Nomad does not read it, and names it. That stops nothing else: the rest is
// taken back, and the program exits 0, so dpkg and apt go on (audit 51 of
// #83, A51-1, A51-3 and A51-4). A second run finds nothing more to do.
func TestNomadTakeBackProgramSetsAsideWhatItCannotTakeBackAndTakesBackTheRest(t *testing.T) {
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
		for _, path := range []string{filepath.Join(l.config, "nomad.hcl"), filepath.Join(l.config, "z.hcl"), filepath.Join(l.tlsDir, "ca.pem")} {
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
	link := func(path string) func(t *testing.T, l layout) string {
		return func(t *testing.T, l layout) string {
			if err := os.Symlink(outside, filepath.Join(l.config, path)); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(l.config, path)
		}
	}
	file := func(name string, mode os.FileMode, size int64) func(t *testing.T, l layout) string {
		return func(t *testing.T, l layout) string {
			path := filepath.Join(l.config, name)
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Truncate(path, size); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			return path
		}
	}
	cases := []struct {
		name  string
		plant func(t *testing.T, l layout) string
		why   string
		// The run folder's subfolder that it is set aside in, and the kind
		// of entry found there.
		sub  string
		kind uint32
		// Whether the TLS folder's file is still taken back.
		tlsTaken bool
	}{
		{"a link at an extra config file", link("extra.hcl"), "a link, not a regular file", "", syscall.S_IFLNK, true},
		{"a link at nomad.env", link("nomad.env"), "a link, not a regular file", "", syscall.S_IFLNK, true},
		{"a FIFO at nomad.env", func(t *testing.T, l layout) string {
			path := filepath.Join(l.config, "nomad.env")
			if err := syscall.Mkfifo(path, 0o644); err != nil {
				t.Fatal(err)
			}
			return path
		}, "a FIFO, not a regular file", "", syscall.S_IFIFO, true},
		{"a link at the server key", link("tls/server-key.pem"), "a link, not a regular file", "tls", syscall.S_IFLNK, true},
		{"a link at the TLS folder", func(t *testing.T, l layout) string {
			target := filepath.Join(filepath.Dir(l.data), "elsewhere")
			if err := os.Rename(l.tlsDir, target); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, l.tlsDir); err != nil {
				t.Fatal(err)
			}
			return l.tlsDir
		}, "a link, not a folder", "", syscall.S_IFLNK, false},
		{"a file at the TLS folder", func(t *testing.T, l layout) string {
			if err := os.RemoveAll(l.tlsDir); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(l.tlsDir, nil, 0o644); err != nil {
				t.Fatal(err)
			}
			return l.tlsDir
		}, "a file, not a folder", "", syscall.S_IFREG, false},
		// A sparse file costs its owner no disk; a copy would cost root its
		// whole size (A51-3). It is moved, not read.
		{"a file larger than 1 MiB", file("big.json", 0o666, 1<<30), "1073741824 bytes, more than the 1048576 a file Nomad reads may hold", "", syscall.S_IFREG, true},
		// The test user cannot read a file of its own without read
		// permission: an OSError, which stops nothing else (A51-1).
		{"a file the program cannot read", file("a.hcl", 0o222, 3), "it could not be taken back: Permission denied", "", syscall.S_IFREG, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := setup(t)
			if err := os.Chmod(l.data, 0o755); err != nil {
				t.Fatal(err)
			}
			path := tc.plant(t, l)
			planted := inode(t, path)
			stdout, stderr, err := runTakeBack(t, program, false, l.config, l.data)
			if err != nil {
				t.Fatalf("the program failed: %v %s %s", err, stdout, stderr)
			}
			requireLines(t, stderr, []string{setAsideLine(path, tc.why, l.config, tc.sub), lookLine(l.config)})
			// The entry is gone from where Nomad reads it, and is in the
			// set-aside folder as it was: the same inode, not followed.
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatalf("%s is still there (%v)", path, err)
			}
			moved, st := setAsideEntry(t, l.config, tc.sub, filepath.Base(path), os.Getuid(), os.Getgid())
			if st.kind() != tc.kind || st.Ino != planted {
				t.Fatalf("%s is %+v, want what was planted: type %o, inode %d", moved, st, tc.kind, planted)
			}
			requireNothingSetAside(t, l.data)
			// The rest is taken back, after the entry too.
			for _, name := range []string{"nomad.hcl", "z.hcl"} {
				requireRegularFile(t, filepath.Join(l.config, name), "x\n", 0o644)
			}
			requireFolder(t, l.data, os.Getuid(), os.Getgid(), 0o700)
			if tc.tlsTaken {
				requireRegularFile(t, filepath.Join(l.tlsDir, "ca.pem"), "x\n", 0o644)
			}
			requireRegularFile(t, outside, "outside\n", 0o666)
			if !strings.Contains(stdout, "execution-substrate: took "+filepath.Join(l.config, "z.hcl")+" back") {
				t.Fatalf("the program did not report z.hcl: %s", stdout)
			}
			// A second run sets nothing more aside, and says nothing.
			stdout, stderr, err = runTakeBack(t, program, false, l.config, l.data)
			if err != nil || stdout != "" || stderr != "" {
				t.Fatalf("a second run: %v %q %q", err, stdout, stderr)
			}
		})
	}

	// A file of 1 MiB, the most a file Nomad reads may hold, is taken back.
	t.Run("a file of 1 MiB", func(t *testing.T) {
		l := setup(t)
		path := file("full.json", 0o666, 1<<20)(t, l)
		stdout, stderr, err := runTakeBack(t, program, false, l.config, l.data)
		if err != nil || stderr != "" {
			t.Fatalf("the program: %v %s %s", err, stdout, stderr)
		}
		requireRegularFile(t, path, strings.Repeat("\x00", 1<<20), 0o644)
		requireNothingSetAside(t, l.config)
	})

	// Where the config folder or the data folder should be, only root can
	// put something else (their parents are root's): the program takes back
	// the rest, then fails and names it and the command to run again.
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
		want := "execution-substrate: " + l.config + " (a link, not a folder) cannot be taken back, and Nomad's unit reads it as root\n" +
			"execution-substrate: fix that, then run " + program + " " + l.config + " " + l.data + " again\n"
		if err == nil || stderr != want {
			t.Fatalf("the program took back the config folder through a link: %v\n%s\nwant\n%s", err, stderr, want)
		}
		requireRegularFile(t, filepath.Join(target, "nomad.hcl"), "x\n", 0o666)
		requireFolder(t, l.data, os.Getuid(), os.Getgid(), 0o700)
		requireNothingSetAside(t, l.config)
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

// The set-aside folder is the program's: an earlier one left open to others
// or with an ACL is closed again. One the program cannot use (another
// account's, a link) leaves the entry where it is, and the program takes back
// the rest, then fails and names it.
func TestNomadTakeBackProgramSetsAsideOnlyIntoAFolderOfItsOwn(t *testing.T) {
	program := nomadTakeBackProgram(t)
	plant := func(t *testing.T, root string) (config, data, entry string) {
		t.Helper()
		config, data = filepath.Join(root, "etc"), filepath.Join(root, "data")
		for _, folder := range []string{config, data} {
			if err := os.Mkdir(folder, 0o755); err != nil {
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
		entry = filepath.Join(config, "extra.hcl")
		if err := os.Symlink("/etc/hostname", entry); err != nil {
			t.Fatal(err)
		}
		return config, data, entry
	}

	t.Run("an earlier one left open", func(t *testing.T) {
		config, data, entry := plant(t, t.TempDir())
		if err := os.Mkdir(setAsideFolder(config), 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(setAsideFolder(config), 0o777); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Setxattr(setAsideFolder(config), "system.posix_acl_default", grantingACL(), 0); err != nil {
			t.Fatal(err)
		}
		stdout, stderr, err := runTakeBack(t, program, false, config, data)
		if err != nil {
			t.Fatalf("the program: %v %s %s", err, stdout, stderr)
		}
		requireLines(t, stderr, []string{setAsideLine(entry, "a link, not a regular file", config, ""), lookLine(config)})
		if _, st := setAsideEntry(t, config, "", "extra.hcl", os.Getuid(), os.Getgid()); st.kind() != syscall.S_IFLNK {
			t.Fatalf("what was set aside is %+v, want the link", st)
		}
	})

	cannot := func(t *testing.T, config, data, entry, reason string, err error, stderr string) {
		t.Helper()
		want := "execution-substrate: " + entry + " (a link, not a regular file) could not be set aside in " + setAsideFolder(config) +
			" (" + reason + "), and Nomad's unit reads it as root\n" +
			"execution-substrate: fix that, then run " + program + " " + config + " " + data + " again\n"
		if err == nil || stderr != want {
			t.Fatalf("the program: %v\n%s\nwant\n%s", err, stderr, want)
		}
		if target, err := os.Readlink(entry); err != nil || target != "/etc/hostname" {
			t.Fatalf("%s was changed: %q %v", entry, target, err)
		}
		requireRegularFile(t, filepath.Join(config, "nomad.hcl"), "x\n", 0o644)
		requireFolder(t, data, os.Getuid(), os.Getgid(), 0o700)
	}

	t.Run("one of another account", func(t *testing.T) {
		root := rootTempDir(t)
		config, data, entry := plant(t, root)
		// Open to the program, so it is the owner that it refuses.
		runTestSudo(t, "mkdir", "-m", "0755", "--", setAsideFolder(config))
		_, stderr, err := runTakeBack(t, program, false, config, data)
		cannot(t, config, data, entry, "it is uid 0's, not uid "+strconv.Itoa(os.Getuid())+"'s", err, stderr)
	})

	t.Run("a link", func(t *testing.T) {
		root := t.TempDir()
		config, data, entry := plant(t, root)
		elsewhere := filepath.Join(root, "elsewhere")
		if err := os.Mkdir(elsewhere, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(elsewhere, setAsideFolder(config)); err != nil {
			t.Fatal(err)
		}
		_, stderr, err := runTakeBack(t, program, false, config, data)
		// O_NOFOLLOW with O_DIRECTORY: Linux says ENOTDIR for a link.
		cannot(t, config, data, entry, "Not a directory", err, stderr)
		if entries, err := os.ReadDir(elsewhere); err != nil || len(entries) != 0 {
			t.Fatalf("something was set aside through the link: %v %v", entries, err)
		}
	})
}

// Audit 51 of #83, A51-1, and Sonnet's A83-1: the nomad account, while it
// owns the folders, plants one entry that stopped the take-back of
// everything after it when the temporary name was the file's name plus a
// suffix. With a short random temporary name each is passed over or taken
// back, and the TLS folder, its key and the data folder are taken back
// too, with nothing set aside. Also what a run cut off leaves.
func TestNomadTakeBackProgramIsNotStoppedByOneEntryTheAccountPlants(t *testing.T) {
	program := nomadTakeBackProgram(t)
	cases := []struct {
		name  string
		plant func(t *testing.T, config string) string
	}{
		{"a file whose old temporary name was too long", func(t *testing.T, config string) string {
			path := filepath.Join(config, strings.Repeat("a", 236)+".hcl")
			runTestSudo(t, "-u", "#65534", "touch", path)
			return path
		}},
		{"a file whose name is 255 characters", func(t *testing.T, config string) string {
			path := filepath.Join(config, strings.Repeat("a", 251)+".hcl")
			runTestSudo(t, "-u", "#65534", "touch", path)
			return path
		}},
		{"a folder at nomad.env's old temporary name", func(t *testing.T, config string) string {
			runTestSudo(t, "-u", "#65534", "mkdir", filepath.Join(config, "nomad.env.execution-substrate-new"))
			return ""
		}},
		{"a file at a TLS file's old temporary name (also what an interrupted run left)", func(t *testing.T, config string) string {
			runTestSudo(t, "-u", "#65534", "touch", filepath.Join(config, "tls", "server-key.pem.execution-substrate-new"))
			return ""
		}},
		{"folders at temporary names", func(t *testing.T, config string) string {
			for _, folder := range []string{config, filepath.Join(config, "tls")} {
				runTestSudo(t, "-u", "#65534", "mkdir", filepath.Join(folder, ".execution-substrate-take-back-0123456789abcdef"))
			}
			return ""
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config, tlsDir, data := packageLayout(t)
			planted := tc.plant(t, config)
			stdout, stderr, err := runTakeBack(t, program, true, config, data)
			if err != nil || stderr != "" {
				t.Fatalf("the program: %v\n%s\n%s", err, stdout, stderr)
			}
			for _, path := range []string{config, tlsDir, filepath.Join(config, "nomad.env"), filepath.Join(config, "nomad.hcl"),
				filepath.Join(tlsDir, "server-key.pem"), data} {
				requireOwner(t, path, 0, 0)
			}
			if planted != "" {
				requireTaken(t, planted, "", 0o644, 0)
			}
			requireNothingSetAside(t, config)
			requireNothingSetAside(t, data)
		})
	}
}

// packageLayout makes what the package leaves: a config folder with
// nomad.env, nomad.hcl and a TLS folder with the server key, and a data
// folder holding a root-owned server folder; then gives the config folder
// (with everything in it) and the data folder itself to uid 65534, which
// stands in for the nomad account, as the postinst does (audit 51 of #83).
func packageLayout(t *testing.T) (config, tlsDir, data string) {
	t.Helper()
	root := rootTempDir(t)
	// uid 65534 must reach the folders: t.TempDir's parent is 0700.
	for _, folder := range []string{filepath.Dir(root), root} {
		if err := os.Chmod(folder, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	config, data = filepath.Join(root, "etc", "nomad.d"), filepath.Join(root, "opt", "nomad", "data")
	tlsDir = filepath.Join(config, "tls")
	for _, folder := range []string{tlsDir, filepath.Join(data, "server")} {
		if err := os.MkdirAll(folder, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for path, content := range map[string]string{
		filepath.Join(config, "nomad.env"):            "",
		filepath.Join(config, "nomad.hcl"):            "data_dir = \"x\"\n",
		filepath.Join(tlsDir, "server-key.pem"):       "key\n",
		filepath.Join(data, "server", "serf.keyring"): "[\"k\"]\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runTestSudo(t, "chown", "-R", "0:0", filepath.Join(data, "server"))
	runTestSudo(t, "chown", "-R", "65534:65534", config)
	runTestSudo(t, "chown", "65534:65534", data)
	return config, tlsDir, data
}

// Audit 51 of #83, A51-2: while the nomad account owns the data folder it
// can rename root's entries there and put its own in their place (here
// Nomad's server folder, which holds the Raft state and the gossip
// keyring). Nomad runs as root and makes each entry there, so each entry of
// another owner is set aside, and root's are kept.
func TestNomadTakeBackProgramSetsAsideAnEntryOfAnotherAccountInTheDataFolder(t *testing.T) {
	program := nomadTakeBackProgram(t)
	config, _, data := packageLayout(t)
	server := filepath.Join(data, "server")
	runTestSudo(t, "-u", "#65534", "mv", server, filepath.Join(data, "server.old"))
	runTestSudo(t, "-u", "#65534", "mkdir", "-m", "0700", server)
	runTestSudo(t, "-u", "#65534", "ln", "-s", "/etc/hostname", filepath.Join(data, "link"))
	runTestSudo(t, "-u", "#65534", "touch", filepath.Join(data, "file"))
	planted := map[string]uint64{}
	for _, name := range []string{"file", "link", "server"} {
		planted[name] = inode(t, filepath.Join(data, name))
	}
	stdout, stderr, err := runTakeBack(t, program, true, config, data)
	if err != nil {
		t.Fatalf("the program: %v\n%s\n%s", err, stdout, stderr)
	}
	requireLines(t, stderr, []string{
		setAsideLine(filepath.Join(data, "file"), "a file of uid 65534, not uid 0", data, ""),
		setAsideLine(filepath.Join(data, "link"), "a link of uid 65534, not uid 0", data, ""),
		setAsideLine(server, "a folder of uid 65534, not uid 0", data, ""),
		lookLine(data),
	})
	for name, old := range planted {
		if moved, st := setAsideEntry(t, data, "", name, 0, 0); st.Ino != old || st.UID != 65534 {
			t.Fatalf("%s is %+v, not what was planted (inode %d)", moved, st, old)
		}
	}
	if output, err := exec.Command("sudo", "-n", "ls", "-A", "--", data).Output(); err != nil || string(output) != "server.old\n" {
		t.Fatalf("the data folder holds %q (%v), want root's server.old only", output, err)
	}
	if got := sudoStat(t, filepath.Join(data, "server.old")); got != "0:0 755 directory" {
		t.Fatalf("root's server folder is %s now, want it kept", got)
	}
	if got := sudoRead(t, filepath.Join(data, "server.old", "serf.keyring")); got != "[\"k\"]\n" {
		t.Fatalf("root's keyring holds %q now", got)
	}
	requireFolder(t, data, 0, 0, 0o700)
	requireNothingSetAside(t, config)
}

// The checks the program makes between looking at an entry and opening it:
// it opens a folder or a file without following a link, and only if it is
// the one it looked at, and reads no more than 1 MiB of it. The program runs
// with os.open wrapped to change the entry just before it is opened (Sonnet's
// A83-4 on #83: these guards were each pinned by no test).
func TestNomadTakeBackProgramTakesBackOnlyWhatItLookedAt(t *testing.T) {
	program := nomadTakeBackProgram(t)
	wrapper := `
import os, runpy, sys
target, change = os.environ["CHANGED"], os.environ["CHANGE"]
real_open = os.open
changed = []
def changing_open(path, flags, *args, **kwargs):
    if path == target and not changed:
        changed.append(path)
        if change in ("link", "folder", "file"):
            os.rename(path, path + ".old")
        if change == "link":
            os.symlink(path + ".old", path)
        elif change == "folder":
            os.mkdir(path, 0o777)
        elif change == "file":
            with open(path, "x") as new:
                new.write("changed\n")
            os.chmod(path, 0o666)
        elif change == "grow":
            with open(path, "ab") as grown:
                grown.write(b"#" * (1 << 20))
    return real_open(path, flags, *args, **kwargs)
os.open = changing_open
sys.argv = sys.argv[1:]
runpy.run_path(sys.argv[0], run_name="__main__")
`
	cases := []struct {
		name, entry, change, why string
		sub                      string
		kind                     uint32
	}{
		// O_NOFOLLOW with O_DIRECTORY: Linux says ENOTDIR for a link.
		{"the TLS folder made a link", "tls", "link", "it could not be taken back: Not a directory", "", syscall.S_IFLNK},
		{"the TLS folder replaced", "tls", "folder", "it changed while it was taken back", "", syscall.S_IFDIR},
		{"a file made a link", "extra.hcl", "link", "it could not be taken back: Too many levels of symbolic links", "", syscall.S_IFLNK},
		{"a file replaced", "extra.hcl", "file", "it changed while it was taken back", "", syscall.S_IFREG},
		{"a file grown past 1 MiB", "extra.hcl", "grow", "more than the 1048576 bytes a file Nomad reads may hold, once read", "", syscall.S_IFREG},
		{"a TLS file made a link", "tls/ca.pem", "link", "it could not be taken back: Too many levels of symbolic links", "tls", syscall.S_IFLNK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			config, data := filepath.Join(root, "etc"), filepath.Join(root, "data")
			tlsDir := filepath.Join(config, "tls")
			for _, folder := range []string{tlsDir, data} {
				if err := os.MkdirAll(folder, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Chmod(tlsDir, 0o777); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{filepath.Join(config, "extra.hcl"), filepath.Join(config, "z.hcl"), filepath.Join(tlsDir, "ca.pem")} {
				if err := os.WriteFile(path, []byte("x\n"), 0o666); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0o666); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(config, tc.entry)
			command := exec.Command("python3", "-I", "-c", wrapper, program, config, data)
			command.Env = []string{"PATH=" + os.Getenv("PATH"), "CHANGED=" + path, "CHANGE=" + tc.change}
			var stdout, stderr strings.Builder
			command.Stdout, command.Stderr = &stdout, &stderr
			if err := command.Run(); err != nil {
				t.Fatalf("the program: %v\n%s\n%s", err, stdout.String(), stderr.String())
			}
			requireLines(t, stderr.String(), []string{setAsideLine(path, tc.why, config, tc.sub), lookLine(config)})
			if moved, st := setAsideEntry(t, config, tc.sub, filepath.Base(path), os.Getuid(), os.Getgid()); st.kind() != tc.kind {
				t.Fatalf("%s is %+v, want type %o", moved, st, tc.kind)
			}
			// What was there before the change is not taken back: the
			// program did not reach it.
			if tc.change != "grow" {
				if info, err := os.Lstat(path + ".old"); err != nil || info.Mode().Perm() != 0o777 && info.Mode().Perm() != 0o666 {
					t.Fatalf("%s.old was changed: %v %v", path, info, err)
				}
			}
			requireRegularFile(t, filepath.Join(config, "z.hcl"), "x\n", 0o644)
			requireFolder(t, data, os.Getuid(), os.Getgid(), 0o700)
		})
	}
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

// Which files in the config folder the program takes back: nomad.env, which
// HashiCorp's nomad.service reads as its EnvironmentFile, and each *.hcl and
// *.json, which `nomad agent -config /etc/nomad.d` loads, names that look
// hidden (".x.hcl") or temporary ("#x.hcl") included; it skips only an
// editor's ".#" lock files. The setup has no take-back of its own any more:
// it runs this program (audit 51 of #83, O51-2).
func TestNomadTakeBackProgramTakesBackWhatNomadLoads(t *testing.T) {
	names := []string{"nomad.hcl", "nomad.env", "extra.hcl", "extra.json", "a.b.hcl", ".hidden.hcl", "#hash.json", ".#lock.hcl",
		"README", "nomad.env.bak", "x.hcl.txt", "x.json~", "#x.hcl#", "x.HCL", "nomad.hcl.execution-substrate.bak.1"}
	want := []string{"nomad.hcl", "nomad.env", "extra.hcl", "extra.json", "a.b.hcl", ".hidden.hcl", "#hash.json"}
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
	program := nomadTakeBackProgram(t)
	if _, stderr, err := runTakeBack(t, program, false, folder, filepath.Join(t.TempDir(), "data")); err != nil || stderr != "" {
		t.Fatalf("the program: %v %s", err, stderr)
	}
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
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("the program took back %v, want %v", got, want)
	}
	text := linuxSetupText(t)
	if strings.Contains(text, "nomad_config_files_take_back") {
		t.Fatal("the setup still has a take-back of the config files of its own, beside the program")
	}
}

// A folder already of the right owner and mode can still carry an ACL (a
// run cut off after its fchown and fchmod leaves one): the program removes
// it, as the setup's nomad_folder_take_back does (audit 51 of #83, A51-5).
func TestNomadTakeBackProgramRemovesAFolderACLEvenWhenOwnerAndModeAreRight(t *testing.T) {
	program := nomadTakeBackProgram(t)
	root := t.TempDir()
	config, data := filepath.Join(root, "etc"), filepath.Join(root, "data")
	for folder, mode := range map[string]os.FileMode{config: 0o755, data: 0o700} {
		if err := os.Mkdir(folder, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(folder, mode); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Setxattr(folder, "system.posix_acl_default", grantingACL(), 0); err != nil {
			t.Fatal(err)
		}
	}
	stdout, stderr, err := runTakeBack(t, program, false, config, data)
	if err != nil {
		t.Fatalf("the program: %v\n%s%s", err, stdout, stderr)
	}
	want := []string{
		"execution-substrate: removed the default ACL that was left on " + config,
		"execution-substrate: removed the default ACL that was left on " + data,
	}
	if got := takeBackReports(stdout); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the program reported\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	requireFolder(t, config, os.Getuid(), os.Getgid(), 0o755)
	requireFolder(t, data, os.Getuid(), os.Getgid(), 0o700)
}

// install_nomad_package_hook writes the program and the dpkg configuration,
// each as a new file of the caller's renamed into place (a link at either
// name is replaced, not followed), and runs the program once. A rerun
// writes the same bytes. Anything the program sets aside stops the install,
// on this run and each one after, until that folder is removed.
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

	t.Run("what the program sets aside stops the install", func(t *testing.T) {
		link := filepath.Join(config, "extra.hcl")
		if err := os.Symlink(outside, link); err != nil {
			t.Fatal(err)
		}
		_, stderr, err := runNomadPackageHookRegion(t, install, program, hook, config, data)
		stop := "nomad: " + setAsideFolder(config) + " holds what was set aside from Nomad's folders, where Nomad would have read it as root; " +
			"look at it, then remove it (rm -rf -- " + setAsideFolder(config) + ") and rerun\n"
		if err == nil || !regexp.MustCompile(setAsideLine(link, "a link, not a regular file", config, "")).MatchString(stderr) ||
			!strings.HasSuffix(stderr, stop) {
			t.Fatalf("the install went on past a link the program set aside: %v %s", err, stderr)
		}
		if _, err := os.Lstat(link); !os.IsNotExist(err) {
			t.Fatalf("the link is still where Nomad reads it: %v", err)
		}
		// A rerun stops too, though it sets nothing aside itself.
		_, stderr, err = runNomadPackageHookRegion(t, install, program, hook, config, data)
		if err == nil || stderr != stop {
			t.Fatalf("a rerun went on past what an earlier run set aside: %v %s", err, stderr)
		}
		// So does what was set aside from the data folder.
		if err := os.RemoveAll(setAsideFolder(config)); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(setAsideFolder(data), 0o700); err != nil {
			t.Fatal(err)
		}
		_, stderr, err = runNomadPackageHookRegion(t, install, program, hook, config, data)
		if err == nil || !strings.Contains(stderr, "nomad: "+setAsideFolder(data)+" holds what was set aside") {
			t.Fatalf("the install went on past what was set aside from the data folder: %v %s", err, stderr)
		}
		// Once it is removed, the install goes through again.
		if err := os.Remove(setAsideFolder(data)); err != nil {
			t.Fatal(err)
		}
		if _, stderr, err := runNomadPackageHookRegion(t, install, program, hook, config, data); err != nil {
			t.Fatalf("with nothing set aside: %v %s", err, stderr)
		}
	})
}

// nomad_new_file_write writes the program and the dpkg configuration only
// into a folder of the caller's that neither its group nor others can
// write, and not through a link: each part of that rule on its own (audit
// 51 of #83, A51-5, and Sonnet's A83-4). Debian's /usr/local/sbin is
// root:staff 2775.
func TestLinuxSetupWritesTheHookFilesOnlyIntoAFolderOfItsOwnClosedToOthers(t *testing.T) {
	root := rootTempDir(t)
	uid := strconv.Itoa(os.Getuid())
	cases := []struct {
		name    string
		prepare func(t *testing.T, folder string)
		refusal string
	}{
		{"its group can write it", func(t *testing.T, folder string) {
			if err := os.Chmod(folder, 0o775); err != nil {
				t.Fatal(err)
			}
		}, "is not owned by uid " + uid + " and closed to group and others (uid " + uid + ", 0775)"},
		{"others can write it", func(t *testing.T, folder string) {
			if err := os.Chmod(folder, 0o757); err != nil {
				t.Fatal(err)
			}
		}, "is not owned by uid " + uid + " and closed to group and others (uid " + uid + ", 0757)"},
		{"another account owns it", func(t *testing.T, folder string) {
			runTestSudo(t, "chown", "65534", "--", folder)
		}, "is not owned by uid " + uid + " and closed to group and others (uid 65534, 0755)"},
		{"it is a link", func(t *testing.T, folder string) {
			target := folder + ".target"
			if err := os.Rename(folder, target); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, folder); err != nil {
				t.Fatal(err)
			}
		}, ""},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			folder := filepath.Join(root, strconv.Itoa(i), "sbin")
			if err := os.MkdirAll(folder, 0o755); err != nil {
				t.Fatal(err)
			}
			tc.prepare(t, folder)
			path := filepath.Join(folder, "execution-substrate-nomad-take-back")
			_, stderr, err := runNomadPackageHookRegion(t, "printf 'x\\n' | nomad_new_file_write 0755 \"$1\"\n", path)
			want := "nomad: " + folder + " " + tc.refusal + "; refusing to write " + path + " there\n"
			if tc.refusal == "" {
				// O_NOFOLLOW with O_DIRECTORY: Linux says ENOTDIR for a link.
				want = "nomad: could not write " + path + ": [Errno 20] Not a directory: '" + folder + "'\n"
			}
			if err == nil || stderr != want {
				t.Fatalf("nomad_new_file_write: %v\n%s\nwant\n%s", err, stderr, want)
			}
			if entries, err := filepath.Glob(filepath.Join(folder+"*", "*")); err != nil || len(entries) != 0 {
				t.Fatalf("something was written: %v %v", entries, err)
			}
		})
	}
}

// The setup installs the hook as root, with its own paths, as the first step
// of the service config: the program then takes Nomad's folders and files
// back, and stops the setup if it set anything aside, before the setup
// writes there (audit 51 of #83, O51-2). The root wrapper hands every
// function the install needs to sudo's bash.
func TestLinuxSetupInstallsTheNomadPackageHookAsRootFirstInTheServiceConfig(t *testing.T) {
	text := linuxSetupText(t)
	call := `nomad_package_hook_as_root install_nomad_package_hook "${NOMAD_TAKE_BACK_PROGRAM}" "${NOMAD_DPKG_HOOK}" "${NOMAD_CONFIG_DIR}" "${NOMAD_DATA_DIR}"` + "\n"
	var first []string
	for _, line := range strings.Split(linuxSetupFunction(t, text, "install_nomad_service_config"), "\n")[1:] {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, "local ") && !strings.HasPrefix(trimmed, "echo ") {
			first = append(first, trimmed)
		}
	}
	if len(first) < 2 || first[0]+"\n" != call || first[1] != `nomad_folder_take_back 0755 "${NOMAD_CONFIG_DIR}"` {
		t.Fatalf("the hook's install is not the first step of install_nomad_service_config: %q", first[:min(len(first), 2)])
	}
	if strings.Count(text, call) != 1 || !strings.Contains(text, "\ninstall_nomad_service_config\nwarn_existing_nomad_processes\n") {
		t.Fatal("the setup installs the hook somewhere else as well")
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
// quoted, with Python's escapes, in a take-back line and in a set-aside
// line.
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
	if err != nil {
		t.Fatalf("the program: %v %s %s", err, stdout, stderr)
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
	requireLines(t, stderr, []string{
		regexp.QuoteMeta("execution-substrate: set aside '"+config+"/link\\nx.hcl' (a link, not a regular file): it is '"+setAsideFolder(config)+"/") +
			setAsideRun + regexp.QuoteMeta("/link\\nx.hcl' now, which Nomad does not read"),
		lookLine(config),
	})
	for _, path := range paths {
		requireTaken(t, path, "# kept\n", 0o644, 0)
	}
}
