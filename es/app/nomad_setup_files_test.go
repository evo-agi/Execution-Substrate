package app_test

import (
	"os"
	"path/filepath"
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
// too, right after the folder.

// The re-check's proposed test, with the files' take-back added: it
// redefines sudo to record what it runs, and requires, for each of Nomad's
// three folders, install -d and then python3 on it, both under sudo, and, for
// the config folder, the files' take-back's python3 under sudo after them.
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
		if strings.HasPrefix(line, "install ") || strings.HasPrefix(line, "python3 ") {
			got = append(got, line)
		}
	}
	tlsDir := filepath.Join(config, "tls")
	want := []string{"install " + config, "python3 " + config, "python3 " + config}
	for _, folder := range []string{data, tlsDir} {
		want = append(want, "install "+folder, "python3 "+folder)
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("sudo ran\n%s\nwant, for each folder, install -d and then python3, and the config files' python3 "+
			"after the config folder's, all under sudo:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
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
		if strings.HasPrefix(line, "nomad: took ") {
			lines = append(lines, line)
		}
	}
	return lines
}

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
	// nomad.hcl is left to the step that backs it up and writes it new.
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
		"nomad: took " + filepath.Join(config, "extra.hcl") + " back (uid 65534, gid 65534, 0666); Nomad's unit reads it as root, so check what it sets",
		"nomad: took " + filepath.Join(config, "loose.hcl") + " back (" + me + ", 0666); Nomad's unit reads it as root, so check what it sets",
		"nomad: took " + filepath.Join(config, "nomad.env") + " back (uid 65534, gid 65534, 0644); Nomad's unit reads it as root, so check what it sets",
		"nomad: took " + filepath.Join(config, "setuid.json") + " back (" + me + ", 4775); Nomad's unit reads it as root, so check what it sets",
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
		if strings.HasSuffix(name, ".execution-substrate-new") {
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

func TestLinuxSetupStopsAtAFileNomadReadsThatItCannotTakeBack(t *testing.T) {
	setup := func(t *testing.T) (data, config string) {
		t.Helper()
		data = t.TempDir()
		config = filepath.Join(data, "etc")
		if err := os.Mkdir(config, 0o755); err != nil {
			t.Fatal(err)
		}
		return data, config
	}
	stopped := func(t *testing.T, data, config, want string) {
		t.Helper()
		_, stderr, err := runLinuxSetupServiceHarness(t, data, "install_nomad_service_config\n")
		if err == nil || !strings.Contains(stderr, want) {
			t.Fatalf("install_nomad_service_config went on (%v); want %q in: %s", err, want, stderr)
		}
		if _, err := os.Lstat(filepath.Join(config, "nomad.hcl")); !os.IsNotExist(err) {
			t.Fatalf("nomad.hcl was written: %v", err)
		}
		if _, err := os.Lstat(filepath.Join(data, "execution-substrate-restart-pending")); !os.IsNotExist(err) {
			t.Fatalf("a restart was recorded: %v", err)
		}
	}
	notRegular := func(path string) string {
		return "nomad: " + path + " is not a regular file, and Nomad's unit reads it as root; remove it, or put a regular file there, and rerun"
	}

	for _, name := range []string{"extra.hcl", "extra.json", "nomad.env"} {
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
			stopped(t, data, config, notRegular(at))
			requireRegularFile(t, victim, "victim\n", 0o666)
			if target, err := os.Readlink(at); err != nil || target != victim {
				t.Fatalf("the link was changed: %q %v", target, err)
			}
		})
	}
	t.Run("a FIFO at nomad.env, which is not opened", func(t *testing.T) {
		data, config := setup(t)
		at := filepath.Join(config, "nomad.env")
		if err := syscall.Mkfifo(at, 0o666); err != nil {
			t.Fatal(err)
		}
		stopped(t, data, config, notRegular(at))
	})
	t.Run("a file the caller cannot read", func(t *testing.T) {
		data, config := setup(t)
		at := filepath.Join(config, "secret.hcl")
		if err := os.WriteFile(at, []byte("# secret\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		runTestSudo(t, "chown", "65534:65534", at)
		stopped(t, data, config, "nomad: cannot take back the files Nomad reads in "+config+": [Errno 13] Permission denied: '"+at+"'")
		requireOwner(t, at, 65534, 65534)
	})
}
