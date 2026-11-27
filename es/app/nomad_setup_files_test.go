package app_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// Re-check 49 of ES PR #66. S49-1: the tests run the setup with sudo
// standing in for itself, so nothing pinned that the take-back of each
// folder runs its python3 under sudo, after install -d; without sudo, the
// setup stops at the ACL of a folder root owns, on the hosts the repair is
// for. O49-2 (red-team 45's O45-1): HashiCorp's package gives every file in
// /etc/nomad.d to the nomad account, and the setup took back only nomad.hcl,
// so nomad.env (the unit's EnvironmentFile) and any other *.hcl or *.json
// Nomad loads stayed that account's to write. The setup now takes them back
// too. Since audit 51 of #83 (O51-2) it does so by running, as root, the
// take-back program it installs for dpkg (nomad_take_back_program), before
// it writes there: one set of rules, and what the program cannot take back
// it sets aside, which stops the setup until someone has looked.

// The re-check's proposed test, with the take-back program added: it
// redefines sudo to record what it runs, and requires the program's install
// and run under sudo's bash first, then, for each of Nomad's three folders,
// install -d and then python3 on it, both under sudo.
func TestLinuxSetupTakesEachFolderBackAsRootAndRemovesItsACLsAfterwards(t *testing.T) {
	data := t.TempDir()
	config := filepath.Join(data, "etc")
	if err := os.Mkdir(config, 0o755); err != nil {
		t.Fatal(err)
	}
	calls := filepath.Join(t.TempDir(), "sudo-calls.log")
	steps := `sudo() { printf '%s %s\n' "$1" "${@: -1}" >>"` + calls + `"; "$@"; }` + "\n" +
		"install_nomad_service_config\n"
	if _, stderr, err := runLinuxSetupServiceHarness(t, data, steps); err != nil {
		t.Fatalf("install_nomad_service_config: %v %s", err, stderr)
	}
	body, err := os.ReadFile(calls)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		if strings.HasPrefix(line, "install ") || strings.HasPrefix(line, "python3 ") || strings.HasPrefix(line, "bash ") {
			got = append(got, line)
		}
	}
	// The program's install and run end with the data folder, its last
	// argument.
	want := []string{"bash " + data}
	for _, folder := range []string{config, data, filepath.Join(config, "tls")} {
		want = append(want, "install "+folder, "python3 "+folder)
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("sudo ran\n%s\nwant the take-back program first, then, for each folder, install -d and then python3, "+
			"all under sudo:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// configEntry is one entry the files' take-back test places in the config
// folder.
type configEntry struct {
	name, content string
	mode          os.FileMode
	others        bool // given to the account with ID 65534, as the package gives them to nomad
}

// inode is path's inode number, not following a link.
func inode(t *testing.T, path string) uint64 {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Sys().(*syscall.Stat_t).Ino
}

// requireOwner fails unless path (not followed) belongs to uid and gid.
func requireOwner(t *testing.T, path string, uid, gid int) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	if int(st.Uid) != uid || int(st.Gid) != gid {
		t.Fatalf("%s belongs to %d:%d, want %d:%d", path, st.Uid, st.Gid, uid, gid)
	}
}

// tookBack is the lines of output that report a file's take-back.
func tookBack(output string) []string {
	var lines []string
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "execution-substrate: took ") && strings.HasSuffix(line, "; Nomad reads it as root, so check what it sets") {
			lines = append(lines, line)
		}
	}
	return lines
}

// tookBackLine is the take-back program's line for a file it took back from
// was ("uid U, gid G, MODE").
func tookBackLine(path, was string) string {
	return "execution-substrate: took " + path + " back (it was " + was + "); Nomad reads it as root, so check what it sets"
}

// The setup's take-back program takes back each file in the config folder
// that Nomad's unit reads as root and that is not the caller's alone,
// nomad.hcl included, before the setup backs nomad.hcl up and writes it new.
func TestLinuxSetupTakesBackTheFilesNomadReadsAsRoot(t *testing.T) {
	data := t.TempDir()
	config := filepath.Join(data, "etc")
	if err := os.Mkdir(config, 0o755); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	me := "uid " + strconv.Itoa(uid) + ", gid " + strconv.Itoa(gid)
	taken := []configEntry{
		{"extra.hcl", "acl { enabled = true }\n", 0o666, true},
		{"loose.hcl", "# loose\n", 0o666, false},
		{"nomad.env", "NOMAD_LICENSE_PATH=/etc/nomad.d/license\n", 0o644, true},
		{"setuid.json", "{}\n", os.ModeSetuid | 0o775, false},
	}
	kept := []configEntry{
		// Already the caller's, with no write for group or others.
		{"extra.json", "{\"datacenter\": \"dc1\"}\n", 0o640, false},
		// Names Nomad's unit does not read.
		{"README", "readme\n", 0o666, true},
		{"nomad.hcl.execution-substrate.bak.20261126000000", "# backup\n", 0o666, true},
		{"notes.hcl.txt", "notes\n", 0o666, true},
	}
	inodes := map[string]uint64{}
	for _, entry := range append(append([]configEntry{}, taken...), kept...) {
		path := filepath.Join(config, entry.name)
		if err := os.WriteFile(path, []byte(entry.content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, entry.mode); err != nil {
			t.Fatal(err)
		}
	}
	// A handle opened while the file was still writable, as the package's
	// account can keep one.
	handle, err := os.OpenFile(filepath.Join(config, "extra.hcl"), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	for _, entry := range append(append([]configEntry{}, taken...), kept...) {
		path := filepath.Join(config, entry.name)
		if entry.others {
			runTestSudo(t, "chown", "65534:65534", path)
		}
		inodes[entry.name] = inode(t, path)
	}
	// nomad.hcl is taken back first too; the setup then backs it up and
	// writes it new.
	nomadHCL := filepath.Join(config, "nomad.hcl")
	if err := os.WriteFile(nomadHCL, []byte("# the operator's own config\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(nomadHCL, 0o666); err != nil {
		t.Fatal(err)
	}
	runTestSudo(t, "chown", "65534:65534", nomadHCL)
	// What Nomad does not read either: a folder, and an editor's lock file,
	// which is a link.
	folder := filepath.Join(config, "conf.d.hcl")
	if err := os.Mkdir(folder, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(folder, 0o777); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(config, ".#extra.hcl")
	if err := os.Symlink("operator@host.1234:1700000000", lock); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, err := runLinuxSetupServiceHarness(t, data, "install_nomad_service_config\n")
	if err != nil {
		t.Fatalf("install_nomad_service_config: %v %s", err, stderr)
	}
	want := []string{
		tookBackLine(filepath.Join(config, "extra.hcl"), "uid 65534, gid 65534, 0666"),
		tookBackLine(filepath.Join(config, "loose.hcl"), me+", 0666"),
		tookBackLine(filepath.Join(config, "nomad.env"), "uid 65534, gid 65534, 0644"),
		tookBackLine(nomadHCL, "uid 65534, gid 65534, 0666"),
		tookBackLine(filepath.Join(config, "setuid.json"), me+", 4775"),
	}
	if got := tookBack(stdout); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the setup reported\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, entry := range taken {
		path := filepath.Join(config, entry.name)
		requireRegularFile(t, path, entry.content, entry.mode.Perm()&0o755)
		requireOwner(t, path, uid, gid)
		if info, err := os.Lstat(path); err != nil || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			t.Fatalf("%s kept a setuid, setgid or sticky bit: %v %v", path, info, err)
		}
		if inode(t, path) == inodes[entry.name] {
			t.Fatalf("%s was changed in place, not replaced by a new file", path)
		}
	}
	for _, entry := range kept {
		path := filepath.Join(config, entry.name)
		requireRegularFile(t, path, entry.content, entry.mode.Perm())
		if entry.others {
			requireOwner(t, path, 65534, 65534)
		}
		if inode(t, path) != inodes[entry.name] {
			t.Fatalf("%s was replaced", path)
		}
	}
	if info, err := os.Lstat(folder); err != nil || !info.IsDir() || info.Mode().Perm() != 0o777 {
		t.Fatalf("the folder %s was changed: %v %v", folder, info, err)
	}
	if target, err := os.Readlink(lock); err != nil || target != "operator@host.1234:1700000000" {
		t.Fatalf("the lock file was changed: %q %v", target, err)
	}
	// The handle opened before reaches the old file only.
	if _, err := handle.WriteString("acl { enabled = false }\n"); err != nil {
		t.Fatal(err)
	}
	requireRegularFile(t, filepath.Join(config, "extra.hcl"), "acl { enabled = true }\n", 0o644)
	entries, err := os.ReadDir(config)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		if strings.HasPrefix(name, ".execution-substrate-take-back-") {
			t.Fatalf("a temporary file was left: %v", names)
		}
	}
	requireRegularFile(t, nomadHCL, renderedNomadConfig(t, data, config)+"\n", 0o640)
	if backup, err := os.ReadFile(nomadHCL + ".execution-substrate.bak.20261127000000"); err != nil || string(backup) != "# the operator's own config\n" {
		t.Fatalf("the operator's nomad.hcl was not backed up: %q %v", backup, err)
	}

	// A second run finds nothing to take back.
	after := map[string]uint64{}
	for _, entry := range taken {
		after[entry.name] = inode(t, filepath.Join(config, entry.name))
	}
	stdout, stderr, err = runLinuxSetupServiceHarness(t, data, "install_nomad_service_config\n")
	if err != nil {
		t.Fatalf("install_nomad_service_config, again: %v %s", err, stderr)
	}
	if got := tookBack(stdout); len(got) != 0 {
		t.Fatalf("a second run took files back again: %v", got)
	}
	for _, entry := range taken {
		if inode(t, filepath.Join(config, entry.name)) != after[entry.name] {
			t.Fatalf("a second run replaced %s", entry.name)
		}
	}
}

// What the program cannot take back where Nomad reads (a link, a FIFO, a
// file it cannot read) it sets aside, out of Nomad's reach, and the setup
// stops before it records a restart or writes nomad.hcl, and again on each
// rerun, until someone has looked and removed what was set aside; then a
// rerun goes through (audit 51 of #83, A51-4).
func TestLinuxSetupStopsAfterTheProgramSetsAsideAFileNomadReads(t *testing.T) {
	setup := func(t *testing.T) (data, config string) {
		t.Helper()
		data = t.TempDir()
		config = filepath.Join(data, "etc")
		if err := os.Mkdir(config, 0o755); err != nil {
			t.Fatal(err)
		}
		return data, config
	}
	aside := func(config string) string { return config + ".execution-substrate-set-aside" }
	stop := func(config string) string {
		return "nomad: " + aside(config) + " holds what was set aside from Nomad's folders, where Nomad would have read it as root; " +
			"look at it, then remove it (rm -rf -- " + aside(config) + ") and rerun\n"
	}
	stopped := func(t *testing.T, data, config, at, why string) {
		t.Helper()
		_, stderr, err := runLinuxSetupServiceHarness(t, data, "install_nomad_service_config\n")
		line := regexp.QuoteMeta("execution-substrate: set aside "+at+" ("+why+"): it is "+aside(config)+"/") +
			`[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}/` + regexp.QuoteMeta(filepath.Base(at)+" now, which Nomad does not read")
		if err == nil || !regexp.MustCompile(`(?m)^`+line+`$`).MatchString(stderr) || !strings.HasSuffix(stderr, stop(config)) {
			t.Fatalf("install_nomad_service_config went on (%v), or did not say why: %s", err, stderr)
		}
		requireNotWritten := func() {
			t.Helper()
			if _, err := os.Lstat(filepath.Join(config, "nomad.hcl")); !os.IsNotExist(err) {
				t.Fatalf("nomad.hcl was written: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(data, "execution-substrate-restart-pending")); !os.IsNotExist(err) {
				t.Fatalf("a restart was recorded: %v", err)
			}
		}
		requireNotWritten()
		if _, err := os.Lstat(at); !os.IsNotExist(err) {
			t.Fatalf("%s is still where Nomad reads it: %v", at, err)
		}
		// A rerun stops too, though it sets nothing aside itself.
		_, stderr, err = runLinuxSetupServiceHarness(t, data, "install_nomad_service_config\n")
		if err == nil || stderr != stop(config) {
			t.Fatalf("a rerun went on past what an earlier run set aside (%v): %s", err, stderr)
		}
		requireNotWritten()
		// Once that is removed, a rerun goes through.
		runTestSudo(t, "rm", "-rf", "--", aside(config))
		if _, stderr, err := runLinuxSetupServiceHarness(t, data, "install_nomad_service_config\n"); err != nil {
			t.Fatalf("with nothing set aside, install_nomad_service_config: %v %s", err, stderr)
		}
		requireRegularFile(t, filepath.Join(config, "nomad.hcl"), renderedNomadConfig(t, data, config)+"\n", 0o640)
	}

	for _, name := range []string{"extra.hcl", "extra.json", "nomad.env", "nomad.hcl"} {
		t.Run("a link at "+name+" to a file outside", func(t *testing.T) {
			data, config := setup(t)
			victim := filepath.Join(t.TempDir(), "victim")
			if err := os.WriteFile(victim, []byte("victim\n"), 0o666); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(victim, 0o666); err != nil {
				t.Fatal(err)
			}
			at := filepath.Join(config, name)
			if err := os.Symlink(victim, at); err != nil {
				t.Fatal(err)
			}
			stopped(t, data, config, at, "a link, not a regular file")
			requireRegularFile(t, victim, "victim\n", 0o666)
		})
	}
	t.Run("a FIFO at nomad.env, which is not opened", func(t *testing.T) {
		data, config := setup(t)
		at := filepath.Join(config, "nomad.env")
		if err := syscall.Mkfifo(at, 0o666); err != nil {
			t.Fatal(err)
		}
		stopped(t, data, config, at, "a FIFO, not a regular file")
	})
	t.Run("a link at the TLS folder", func(t *testing.T) {
		data, config := setup(t)
		folder := t.TempDir()
		at := filepath.Join(config, "tls")
		if err := os.Symlink(folder, at); err != nil {
			t.Fatal(err)
		}
		stopped(t, data, config, at, "a link, not a folder")
		if entries, err := os.ReadDir(folder); err != nil || len(entries) != 0 {
			t.Fatalf("something was written into the linked folder: %v %v", entries, err)
		}
	})
	t.Run("a file the caller cannot read", func(t *testing.T) {
		data, config := setup(t)
		at := filepath.Join(config, "secret.hcl")
		if err := os.WriteFile(at, []byte("# secret\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		runTestSudo(t, "chown", "65534:65534", at)
		stopped(t, data, config, at, "it could not be taken back: Permission denied")
	})
}

// Re-check 50 (T50-1): Nomad 2.1.1 loads every *.hcl and *.json in its
// config folder but an editor's ".#" lock file, names that look hidden or
// temporary to a person included (`nomad config validate` loads
// ".hidden.hcl" and "#hash.hcl"), so the take-back covers them too, with
// each prefix and each suffix (re-check 51 of #66, Sonnet's S51-1).
func TestLinuxSetupTakesBackNomadLoadedNamesThatLookHidden(t *testing.T) {
	data := t.TempDir()
	config := filepath.Join(data, "etc")
	if err := os.Mkdir(config, 0o755); err != nil {
		t.Fatal(err)
	}
	names := []string{".hidden.hcl", ".hidden.json", "#hash.hcl", "#hash.json"}
	for _, name := range names {
		path := filepath.Join(config, name)
		if err := os.WriteFile(path, []byte("# "+name+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o666); err != nil {
			t.Fatal(err)
		}
	}
	stdout, stderr, err := runLinuxSetupServiceHarness(t, data, "install_nomad_service_config\n")
	if err != nil {
		t.Fatalf("install_nomad_service_config: %v %s", err, stderr)
	}
	got := strings.Join(tookBack(stdout), "\n")
	for _, name := range names {
		path := filepath.Join(config, name)
		if !strings.Contains(got, "execution-substrate: took "+path+" back (it was ") {
			t.Fatalf("%s, which Nomad loads, was not taken back: %q", name, got)
		}
		requireRegularFile(t, path, "# "+name+"\n", 0o644)
	}
}

// Re-check 50 (T50-2, S50-1), with the program's temporary names (audit 51
// of #83, A51-1): a run killed after it made a file's temporary name leaves
// that name behind. The next run removes it, so a stale file, or a link the
// former owner left there, neither stops the setup nor is written through.
// The name an earlier version used, which Nomad never reads, is left as it
// is.
func TestLinuxSetupClearsATemporaryNameAKilledRunLeft(t *testing.T) {
	for _, stale := range []string{"a file", "a link to a file outside"} {
		t.Run(stale, func(t *testing.T) {
			data := t.TempDir()
			config := filepath.Join(data, "etc")
			if err := os.Mkdir(config, 0o755); err != nil {
				t.Fatal(err)
			}
			victim := filepath.Join(t.TempDir(), "victim")
			if err := os.WriteFile(victim, []byte("victim\n"), 0o666); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(victim, 0o666); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(config, "extra.hcl")
			if err := os.WriteFile(target, []byte("acl { enabled = true }\n"), 0o666); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(target, 0o666); err != nil {
				t.Fatal(err)
			}
			runTestSudo(t, "chown", "65534:65534", target)
			temporary := filepath.Join(config, ".execution-substrate-take-back-0123456789abcdef")
			earlier := target + ".execution-substrate-new"
			for _, path := range []string{temporary, earlier} {
				if stale == "a file" {
					if err := os.WriteFile(path, []byte("half"), 0o600); err != nil {
						t.Fatal(err)
					}
				} else if err := os.Symlink(victim, path); err != nil {
					t.Fatal(err)
				}
			}
			stdout, stderr, err := runLinuxSetupServiceHarness(t, data, "install_nomad_service_config\n")
			if err != nil {
				t.Fatalf("install_nomad_service_config stopped at the stale temporary name: %v %s", err, stderr)
			}
			if got := tookBack(stdout); len(got) != 1 || !strings.HasPrefix(got[0], "execution-substrate: took "+target+" back") {
				t.Fatalf("the setup reported %v", got)
			}
			requireRegularFile(t, target, "acl { enabled = true }\n", 0o644)
			requireRegularFile(t, victim, "victim\n", 0o666)
			if _, err := os.Lstat(temporary); !os.IsNotExist(err) {
				t.Fatalf("the temporary name is still there: %v", err)
			}
			if stale == "a file" {
				requireRegularFile(t, earlier, "half", 0o600)
			} else if link, err := os.Readlink(earlier); err != nil || link != victim {
				t.Fatalf("the earlier version's temporary name was changed: %q %v", link, err)
			}
		})
	}
}

// Re-check 50 (O50-2): a file of the caller's but of another group is
// taken back too. The documented end state is the caller's group, and #67's
// check refuses a nomad.env of another group, so the two agree.
func TestLinuxSetupTakesBackAFileOfAnotherGroup(t *testing.T) {
	data := t.TempDir()
	config := filepath.Join(data, "etc")
	if err := os.Mkdir(config, 0o755); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	path := filepath.Join(config, "grouped.hcl")
	if err := os.WriteFile(path, []byte("acl { enabled = true }\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	runTestSudo(t, "chown", strconv.Itoa(uid)+":65534", path)
	before := inode(t, path)
	stdout, stderr, err := runLinuxSetupServiceHarness(t, data, "install_nomad_service_config\n")
	if err != nil {
		t.Fatalf("install_nomad_service_config: %v %s", err, stderr)
	}
	want := tookBackLine(path, "uid "+strconv.Itoa(uid)+", gid 65534, 0640")
	if got := tookBack(stdout); len(got) != 1 || got[0] != want {
		t.Fatalf("the setup reported %v, want %q", got, want)
	}
	requireOwner(t, path, uid, gid)
	if inode(t, path) == before {
		t.Fatalf("%s was changed in place, not replaced by a new file", path)
	}
}

// Re-check 50 (O50-1): the former owner of the folder chose the names the
// take-back reports. A name with a newline would forge a line of the report,
// one that is not UTF-8 could not be printed, and one with a letter that
// only looks like ASCII ("nom\u0430d.hcl", a Cyrillic a) could pass for another
// file, so a name that is not plain printable ASCII is shown quoted, with
// Python's escapes, in the report and in a set-aside line.
func TestLinuxSetupShowsANameThatIsNotPlainPrintableASCIIEscaped(t *testing.T) {
	t.Run("in the report", func(t *testing.T) {
		data := t.TempDir()
		config := filepath.Join(data, "etc")
		if err := os.Mkdir(config, 0o755); err != nil {
			t.Fatal(err)
		}
		forged := filepath.Join(config, "a\nexecution-substrate: took forged back.hcl")
		undecodable := filepath.Join(config, "bad\xff.json")
		lookalike := filepath.Join(config, "nom\u0430d.hcl")
		for _, path := range []string{forged, undecodable, lookalike} {
			if err := os.WriteFile(path, []byte("# kept\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o666); err != nil {
				t.Fatal(err)
			}
		}
		stdout, stderr, err := runLinuxSetupServiceHarness(t, data, "install_nomad_service_config\n")
		if err != nil {
			t.Fatalf("install_nomad_service_config: %v %s", err, stderr)
		}
		was := "uid " + strconv.Itoa(os.Getuid()) + ", gid " + strconv.Itoa(os.Getgid()) + ", 0666"
		want := []string{
			tookBackLine("'"+config+"/a\\nexecution-substrate: took forged back.hcl'", was),
			tookBackLine("'"+config+"/bad\\udcff.json'", was),
			tookBackLine("'"+config+"/nom\\u0430d.hcl'", was),
		}
		if got := tookBack(stdout); strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Fatalf("the setup reported\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
		for _, path := range []string{forged, undecodable, lookalike} {
			requireRegularFile(t, path, "# kept\n", 0o644)
		}
	})
	// Re-check 51 of #66 (Sonnet's S51-1): a control character other than
	// a newline (a carriage return or an escape sequence can overwrite what
	// the operator's terminal already shows; a tab or a DEL can hide a
	// character) is shown escaped too.
	t.Run("with a control character other than a newline", func(t *testing.T) {
		data := t.TempDir()
		config := filepath.Join(data, "etc")
		if err := os.Mkdir(config, 0o755); err != nil {
			t.Fatal(err)
		}
		escaped := map[string]string{
			"cr\rx.hcl":       `cr\rx.hcl`,
			"del\x7fx.hcl":    `del\x7fx.hcl`,
			"esc\x1b[2Kx.hcl": `esc\x1b[2Kx.hcl`,
			"tab\tx.hcl":      `tab\tx.hcl`,
		}
		var names []string
		for name := range escaped {
			path := filepath.Join(config, name)
			if err := os.WriteFile(path, []byte("# kept\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o666); err != nil {
				t.Fatal(err)
			}
			names = append(names, name)
		}
		sort.Strings(names)
		stdout, stderr, err := runLinuxSetupServiceHarness(t, data, "install_nomad_service_config\n")
		if err != nil {
			t.Fatalf("install_nomad_service_config: %v %s", err, stderr)
		}
		was := "uid " + strconv.Itoa(os.Getuid()) + ", gid " + strconv.Itoa(os.Getgid()) + ", 0666"
		var want []string
		for _, name := range names {
			want = append(want, tookBackLine("'"+config+"/"+escaped[name]+"'", was))
		}
		if got := tookBack(stdout); strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Fatalf("the setup reported\n%q\nwant\n%q", got, want)
		}
		if strings.ContainsAny(stdout, "\r\x1b\x7f\t") {
			t.Fatalf("the setup's output holds a raw control character: %q", stdout)
		}
		for _, name := range names {
			requireRegularFile(t, filepath.Join(config, name), "# kept\n", 0o644)
		}
	})
	t.Run("in a set-aside line", func(t *testing.T) {
		data := t.TempDir()
		config := filepath.Join(data, "etc")
		if err := os.Mkdir(config, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/etc/hostname", filepath.Join(config, "link\nx.hcl")); err != nil {
			t.Fatal(err)
		}
		_, stderr, err := runLinuxSetupServiceHarness(t, data, "install_nomad_service_config\n")
		want := "execution-substrate: set aside '" + config + "/link\\nx.hcl' (a link, not a regular file): it is '" + config + ".execution-substrate-set-aside/"
		if err == nil || !strings.Contains(stderr, want) {
			t.Fatalf("install_nomad_service_config went on (%v); want %q in: %s", err, want, stderr)
		}
	})
}
