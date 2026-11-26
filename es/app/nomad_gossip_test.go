package app_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Red-team RT60-1 of ES PR #60: without a gossip key, Nomad's serf port
// accepts any process that reaches it as a peer, so a local account could
// start its own Nomad server, join, and be listed as a member and a raft
// non-voter. scripts/70_linux_setup.sh now writes a keyring into Nomad's data
// directory before Nomad starts, and the readiness checks refuse a Nomad that
// does not encrypt its gossip.

// nomadGossipSetupFunctions runs a shell snippet with the setup script's
// nomad_gossip functions defined (and nothing else from the script).
func nomadGossipSetupFunctions(snippet string, args ...string) (string, error) {
	setup := filepath.Join(executionPlatformRepoRootPath(), "scripts", "70_linux_setup.sh")
	command := exec.Command("bash", append([]string{"-c",
		`set -euo pipefail; eval "$(sed -n '/^# BEGIN nomad_gossip/,/^# END nomad_gossip/p' "$1")"; shift; ` + snippet,
		"bash", setup}, args...)...)
	command.Env = []string{"PATH=" + os.Getenv("PATH")}
	output, err := command.CombinedOutput()
	return string(output), err
}

// nomadGossipKeyringPath is where Nomad reads its gossip keyring.
func nomadGossipKeyringPath(dataDir string) string {
	return filepath.Join(dataDir, "server", "serf.keyring")
}

// issueNomadGossipKeyring writes a keyring into dataDir with the setup
// script's own nomad_gossip_issue, so every test Nomad runs as hosts do.
func issueNomadGossipKeyring(dataDir string) error {
	if output, err := nomadGossipSetupFunctions(`nomad_gossip_issue "$1"`, nomadGossipKeyringPath(dataDir)); err != nil {
		return fmt.Errorf("issue nomad gossip keyring: %v: %s", err, strings.TrimSpace(output))
	}
	return nil
}

var nomadGossipIssuedKeyring = regexp.MustCompile(`^\["([A-Za-z0-9+/]{43}=)"\]$`)

// readIssuedNomadGossipKey returns the one key of a keyring
// nomad_gossip_issue wrote, failing unless the file has exactly that form.
func readIssuedNomadGossipKey(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	match := nomadGossipIssuedKeyring.FindSubmatch(data)
	if match == nil {
		t.Fatalf("keyring is not one base64 key in a JSON list: %q", data)
	}
	key, err := base64.StdEncoding.DecodeString(string(match[1]))
	if err != nil || len(key) != 32 {
		t.Fatalf("keyring key is not 32 bytes of base64: %v (%d bytes)", err, len(key))
	}
	return string(match[1])
}

func requireFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s has mode %04o, want %04o", path, got, want)
	}
	if uid := info.Sys().(*syscall.Stat_t).Uid; int(uid) != os.Getuid() {
		t.Fatalf("%s belongs to uid %d, want %d", path, uid, os.Getuid())
	}
}

func TestLinuxSetupIssuesANomadGossipKeyring(t *testing.T) {
	dataDir := t.TempDir()
	keyring := nomadGossipKeyringPath(dataDir)
	if err := issueNomadGossipKeyring(dataDir); err != nil {
		t.Fatal(err)
	}
	// When the issuer writes first, it creates <data_dir>/server 0700 (Nomad,
	// when it starts first, creates it 0755 under umask 022).
	requireFileMode(t, filepath.Dir(keyring), 0o700)
	requireFileMode(t, keyring, 0o600)
	first := readIssuedNomadGossipKey(t, keyring)
	if output, err := nomadGossipSetupFunctions(`nomad_gossip_keyring_ok "$1"`, keyring); err != nil {
		t.Fatalf("the issued keyring fails nomad_gossip_keyring_ok: %v %s", err, output)
	}

	// A second issue replaces the keyring with a new key and leaves no
	// temporary file behind. Its temporary file is in the keyring's own
	// folder, whatever TMPDIR says: here TMPDIR names a missing folder.
	if output, err := nomadGossipSetupFunctions(`TMPDIR="$2" nomad_gossip_issue "$1"`, keyring, filepath.Join(t.TempDir(), "missing")); err != nil {
		t.Fatalf("nomad_gossip_issue with TMPDIR naming a missing folder: %v %s", err, output)
	}
	requireFileMode(t, keyring, 0o600)
	if second := readIssuedNomadGossipKey(t, keyring); second == first {
		t.Fatal("a second nomad_gossip_issue kept the old key")
	}
	entries, err := os.ReadDir(filepath.Dir(keyring))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "serf.keyring" {
		t.Fatalf("the keyring's folder holds %v, want only serf.keyring", entries)
	}

	// An existing folder is used as it is.
	other := t.TempDir()
	if err := os.Mkdir(filepath.Join(other, "server"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := issueNomadGossipKeyring(other); err != nil {
		t.Fatal(err)
	}
	readIssuedNomadGossipKey(t, nomadGossipKeyringPath(other))

	// A folder in the keyring's place is refused and left as it was, with
	// no key in it or beside it.
	folderData := t.TempDir()
	folder := nomadGossipKeyringPath(folderData)
	if err := os.MkdirAll(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := issueNomadGossipKeyring(folderData); err == nil {
		t.Fatal("nomad_gossip_issue wrote a keyring into a folder in the keyring's place")
	}
	for _, dir := range []string{folder, filepath.Dir(folder)} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if want := map[string]int{folder: 0, filepath.Dir(folder): 1}[dir]; len(entries) != want {
			t.Fatalf("after the refusal %s holds %v", dir, entries)
		}
	}

	// A link in the keyring's place is replaced by the keyring; the folder
	// it points to gets nothing.
	linkData, elsewhere := t.TempDir(), t.TempDir()
	link := nomadGossipKeyringPath(linkData)
	if err := os.Mkdir(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, link); err != nil {
		t.Fatal(err)
	}
	if err := issueNomadGossipKeyring(linkData); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(link); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("the keyring in place of a link: %v %v", info, err)
	}
	readIssuedNomadGossipKey(t, link)
	if entries, err := os.ReadDir(elsewhere); err != nil || len(entries) != 0 {
		t.Fatalf("the folder the link pointed to holds %v (%v)", entries, err)
	}

	// The issuer creates its temporary file only where nothing has the name
	// mktemp chose: a file of that name (here a mktemp that names an existing
	// file) is refused and kept as it was, and no keyring is written.
	occupiedData := t.TempDir()
	occupiedKeyring := nomadGossipKeyringPath(occupiedData)
	if err := os.Mkdir(filepath.Dir(occupiedKeyring), 0o700); err != nil {
		t.Fatal(err)
	}
	occupied := filepath.Join(filepath.Dir(occupiedKeyring), ".serf.keyring.TAKEN0")
	if err := os.WriteFile(occupied, []byte("not the issuer's\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if output, err := nomadGossipSetupFunctions(`occupied=$2; mktemp() { printf '%s\n' "${occupied}"; }; nomad_gossip_issue "$1"`, occupiedKeyring, occupied); err == nil {
		t.Fatalf("nomad_gossip_issue wrote over a file it did not create: %s", output)
	}
	requireFileMode(t, occupied, 0o640)
	if data, err := os.ReadFile(occupied); err != nil || string(data) != "not the issuer's\n" {
		t.Fatalf("the file that had the temporary file's name now holds %q (%v)", data, err)
	}
	if entries, err := os.ReadDir(filepath.Dir(occupiedKeyring)); err != nil || len(entries) != 1 {
		t.Fatalf("after the refusal the keyring's folder holds %v (%v)", entries, err)
	}

	// The key goes in only once the temporary file's mode is 0600: here stat
	// reports it 0644, and the issuer refuses, leaving no file behind.
	looseData := t.TempDir()
	looseKeyring := nomadGossipKeyringPath(looseData)
	if output, err := nomadGossipSetupFunctions(`stat() { if [[ "${@: -1}" == */.serf.keyring.* ]]; then echo 644; else command stat "$@"; fi; }; nomad_gossip_issue "$1"`, looseKeyring); err == nil {
		t.Fatalf("nomad_gossip_issue wrote the key into a temporary file of mode 0644: %s", output)
	}
	if entries, err := os.ReadDir(filepath.Dir(looseKeyring)); err != nil || len(entries) != 0 {
		t.Fatalf("after the refusal the keyring's folder holds %v (%v)", entries, err)
	}

	// The issuer gives the caller's own traps back, after a refusal too.
	trapsData := t.TempDir()
	if err := os.MkdirAll(nomadGossipKeyringPath(filepath.Join(trapsData, "refused")), 0o700); err != nil {
		t.Fatal(err)
	}
	output, err := nomadGossipSetupFunctions(`trap 'echo caller' TERM
nomad_gossip_issue "$1"
echo "issued: $(trap -p HUP INT TERM)"
if nomad_gossip_issue "$2" 2>/dev/null; then echo "a folder took the keyring"; fi
echo "refused: $(trap -p HUP INT TERM)"`,
		nomadGossipKeyringPath(filepath.Join(trapsData, "issued")), nomadGossipKeyringPath(filepath.Join(trapsData, "refused")))
	if want := "issued: trap -- 'echo caller' SIGTERM\nrefused: trap -- 'echo caller' SIGTERM\n"; err != nil || output != want {
		t.Fatalf("the caller's traps after nomad_gossip_issue: %v\n%s\nwant\n%s", err, output, want)
	}
}

// Audit 41 of ES PR #67: a hangup, interrupt or termination that reached
// the issuer while its temporary file held the new key left that file
// behind. Re-audit 42 of ES PR #66: one that reached it before its traps
// were set left an empty one. Here mktemp (choosing the temporary file's
// name, before the traps), stat (before the key goes in) or mv (before the
// rename) holds; the signal goes to the issuer's whole process group, as a
// terminal or the box upgrade sends it. While mktemp holds, no file exists
// yet. The issuer fails (bash dies of the signal; but after an interrupt
// under the traps, the subshell's trap ends the subshell and the issuer
// returns 1), and once the group is gone, neither a temporary file nor a
// keyring is left.
func TestLinuxSetupLeavesNoKeyringTemporaryFileWhenStopped(t *testing.T) {
	// The held command touches HELD_MARKER and sleeps when its last argument
	// matches HELD_PATTERN (after running the real one if HELD_AFTER is set);
	// otherwise it runs the real one.
	held := `#!/usr/bin/env bash
if [[ "${@: -1}" == ${HELD_PATTERN} ]]; then
  if [[ -n "${HELD_AFTER}" ]]; then
    "${REAL_COMMAND}" "$@" >/dev/null || exit
  fi
  : >"${HELD_MARKER}"
  exec sleep 30
fi
exec "${REAL_COMMAND}" "$@"
`
	setup := filepath.Join(executionPlatformRepoRootPath(), "scripts", "70_linux_setup.sh")
	for _, hold := range []struct {
		command string
		pattern string
		// file is what the keyring's folder holds while the command holds:
		// nothing, an empty temporary file, or one holding the key.
		file string
		// trapped: the command holds under the issuer's traps.
		trapped bool
		// after: the command runs before it holds (mktemp, so that a file it
		// created would be there).
		after bool
	}{
		{"mktemp", "*/.serf.keyring.XXXXXX", "nothing", false, true},
		{"stat", "*/.serf.keyring.*", "empty", true, false},
		{"mv", "*/serf.keyring", "key", true, false},
	} {
		realCommand, err := exec.LookPath(hold.command)
		if err != nil {
			t.Fatal(err)
		}
		bin := t.TempDir()
		if err := os.WriteFile(filepath.Join(bin, hold.command), []byte(held), 0o755); err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			name   string
			signal syscall.Signal
		}{
			{"hangup", syscall.SIGHUP},
			{"interrupt", syscall.SIGINT},
			{"termination", syscall.SIGTERM},
		} {
			killed := !(hold.trapped && tc.signal == syscall.SIGINT)
			t.Run(hold.command+"/"+tc.name, func(t *testing.T) {
				dataDir := t.TempDir()
				keyring := nomadGossipKeyringPath(dataDir)
				if err := os.Mkdir(filepath.Dir(keyring), 0o700); err != nil {
					t.Fatal(err)
				}
				marker := filepath.Join(dataDir, "held")
				// GNU env gives bash these three signals' default actions, so
				// a shell that started this test with them ignored (nohup, or
				// a background job) cannot keep the issuer from trapping them.
				command := exec.Command("env", "--default-signal=HUP,INT,TERM", "bash", "-c",
					`set -euo pipefail; eval "$(sed -n '/^# BEGIN nomad_gossip/,/^# END nomad_gossip/p' "$1")"; nomad_gossip_issue "$2"`,
					"bash", setup, keyring)
				command.Env = []string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
					"HELD_PATTERN=" + hold.pattern, "HELD_MARKER=" + marker, "REAL_COMMAND=" + realCommand,
					"HELD_AFTER=" + map[bool]string{true: "1", false: ""}[hold.after]}
				command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
				// The issuer writes to a file, which the test reads while it runs.
				outputPath := filepath.Join(t.TempDir(), "output")
				outputFile, err := os.Create(outputPath)
				if err != nil {
					t.Fatal(err)
				}
				command.Stdout, command.Stderr = outputFile, outputFile
				err = command.Start()
				outputFile.Close()
				if err != nil {
					t.Fatal(err)
				}
				output := func() string {
					data, _ := os.ReadFile(outputPath)
					return string(data)
				}
				done := make(chan error, 1)
				go func() { done <- command.Wait() }()
				ended := false
				t.Cleanup(func() {
					if !ended {
						_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
						<-done
					}
				})
				for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(20 * time.Millisecond) {
					if _, err := os.Stat(marker); err == nil {
						break
					}
					if time.Now().After(deadline) {
						t.Fatalf("the issuer never ran %s on its temporary file or keyring: %s", hold.command, output())
					}
				}
				// While mktemp holds, the folder is empty; while stat holds,
				// the temporary file is empty; while mv holds, it holds the
				// new key.
				entries, err := os.ReadDir(filepath.Dir(keyring))
				if err != nil {
					t.Fatal(err)
				}
				if hold.file == "nothing" {
					if len(entries) != 0 {
						t.Fatalf("the keyring's folder holds %v before the issuer's traps are set", entries)
					}
				} else if len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), ".serf.keyring.") {
					t.Fatalf("the keyring's folder while %s holds: %v", hold.command, entries)
				} else if tmp := filepath.Join(filepath.Dir(keyring), entries[0].Name()); hold.file == "key" {
					readIssuedNomadGossipKey(t, tmp)
				} else if data, err := os.ReadFile(tmp); err != nil || len(data) != 0 {
					t.Fatalf("the temporary file while stat holds: %d bytes (%v)", len(data), err)
				}

				if err := syscall.Kill(-command.Process.Pid, tc.signal); err != nil {
					t.Fatal(err)
				}
				select {
				case err = <-done:
					ended = true
				case <-time.After(15 * time.Second):
					t.Fatalf("the issuer did not end within 15 s of the %s", tc.name)
				}
				var exit *exec.ExitError
				if !errors.As(err, &exit) {
					t.Fatalf("the issuer after a %s: %v\n%s", tc.name, err, output())
				}
				status := exit.Sys().(syscall.WaitStatus)
				if killed && !(status.Signaled() && status.Signal() == tc.signal) || !killed && status.ExitStatus() != 1 {
					t.Fatalf("the issuer after a %s: %v, want %s\n%s", tc.name, err,
						map[bool]string{true: "death by that signal", false: "exit status 1"}[killed], output())
				}
				// The subshell that held the traps may outlive bash for as
				// long as it takes to remove the temporary file and be reaped.
				for deadline := time.Now().Add(15 * time.Second); syscall.Kill(-command.Process.Pid, 0) == nil; time.Sleep(20 * time.Millisecond) {
					if time.Now().After(deadline) {
						t.Fatalf("the issuer's process group outlived it by 15 s after a %s", tc.name)
					}
				}
				if entries, err := os.ReadDir(filepath.Dir(keyring)); err != nil || len(entries) != 0 {
					t.Fatalf("after a %s the keyring's folder holds %v (%v)", tc.name, entries, err)
				}
			})
		}
	}
}

// Re-audit 42 of ES PR #66 found two points no test can hold: a signal
// between mktemp's creating the temporary file and the subshell's setting
// its traps, and one while the subshell starts a command substitution
// (bash then fails to run the trap), each left an empty temporary file.
// So the issuer's own code must name the file before its traps (mktemp -u
// creates nothing), create it only once all three traps and noclobber are
// set, and run no command substitution while the traps are set.
func TestLinuxSetupIssuerCreatesItsTemporaryFileOnlyUnderItsTraps(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(executionPlatformRepoRootPath(), "scripts", "70_linux_setup.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	start := strings.Index(text, "\nnomad_gossip_issue() {\n")
	if start < 0 {
		t.Fatal("70_linux_setup.sh has no nomad_gossip_issue")
	}
	end := strings.Index(text[start:], "\n}\n")
	if end < 0 {
		t.Fatal("nomad_gossip_issue does not end")
	}
	var code []string
	for _, line := range strings.Split(text[start:start+end], "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			code = append(code, line)
		}
	}
	at := func(want string) int {
		t.Helper()
		found := -1
		for i, line := range code {
			if line == want {
				if found >= 0 {
					t.Fatalf("nomad_gossip_issue has %q twice", want)
				}
				found = i
			}
		}
		if found < 0 {
			t.Fatalf("nomad_gossip_issue has no line %q", want)
		}
		return found
	}
	name := at(`tmp="$(mktemp -u "${dir}/.serf.keyring.XXXXXX")" || return 1`)
	open := at(`if ! (`)
	traps := []int{
		at(`trap 'rm -f -- "${tmp}"; exit 129' HUP`),
		at(`trap 'rm -f -- "${tmp}"; exit 130' INT`),
		at(`trap 'rm -f -- "${tmp}"; exit 143' TERM`),
	}
	noclobber := at(`set -C`)
	create := at(`: >"${tmp}" || exit 1`)
	closing := at(`); then`)
	if !(name < open && open < traps[0] && traps[0] < traps[1] && traps[1] < traps[2] &&
		traps[2] < noclobber && noclobber < create && create < closing) {
		t.Fatalf("nomad_gossip_issue's order: name %d, subshell %d, traps %v, noclobber %d, create %d, end %d",
			name, open, traps, noclobber, create, closing)
	}
	for i, line := range code {
		if strings.Contains(line, "mktemp") && i != name {
			t.Errorf("nomad_gossip_issue runs mktemp again: %q", line)
		}
		if strings.Contains(line, "${tmp}") && i != name && (i < traps[0] || i > traps[2]) && (i < create || i > closing) {
			t.Errorf("nomad_gossip_issue uses its temporary file outside its traps: %q", line)
		}
		if i > open && i < closing {
			for _, substitution := range []string{"$(", "`", "<(", ">("} {
				if strings.Contains(line, substitution) {
					t.Errorf("nomad_gossip_issue runs %s while its traps are set: %q", substitution, line)
				}
			}
		}
	}
}

func TestLinuxSetupChecksTheNomadGossipKeyring(t *testing.T) {
	key := func(n int) string { return base64.StdEncoding.EncodeToString(make([]byte, n)) }
	write := func(t *testing.T, content string, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "serf.keyring")
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	sound := `["` + key(32) + `"]`
	for _, test := range []struct {
		name  string
		path  func(t *testing.T) string
		sound bool
	}{
		{"one 32-byte key", func(t *testing.T) string { return write(t, sound, 0o600) }, true},
		{"two 32-byte keys", func(t *testing.T) string { return write(t, `["`+key(32)+`","`+key(32)+`"]`, 0o600) }, true},
		{"spaced JSON", func(t *testing.T) string { return write(t, "[\n  \""+key(32)+"\"\n]\n", 0o600) }, true},
		{"missing", func(t *testing.T) string { return filepath.Join(t.TempDir(), "serf.keyring") }, false},
		{"readable by others", func(t *testing.T) string { return write(t, sound, 0o644) }, false},
		{"read-only", func(t *testing.T) string { return write(t, sound, 0o400) }, false},
		{"a folder", func(t *testing.T) string {
			path := filepath.Join(t.TempDir(), "serf.keyring")
			if err := os.Mkdir(path, 0o600); err != nil {
				t.Fatal(err)
			}
			return path
		}, false},
		{"a symbolic link to a sound keyring", func(t *testing.T) string {
			target := write(t, sound, 0o600)
			link := filepath.Join(t.TempDir(), "serf.keyring")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			return link
		}, false},
		{"not JSON", func(t *testing.T) string { return write(t, key(32), 0o600) }, false},
		{"an object", func(t *testing.T) string { return write(t, `{"key":"`+key(32)+`"}`, 0o600) }, false},
		// Its names and values are sound keys: only the list check refuses it.
		{"an object of sound keys", func(t *testing.T) string { return write(t, `{"`+key(32)+`":"`+key(32)+`"}`, 0o600) }, false},
		{"an empty list", func(t *testing.T) string { return write(t, `[]`, 0o600) }, false},
		{"a 16-byte key", func(t *testing.T) string { return write(t, `["`+key(16)+`"]`, 0o600) }, false},
		{"a key that is not base64", func(t *testing.T) string { return write(t, `["not a key!"]`, 0o600) }, false},
		// A lenient decoder would drop the "*" and find 32 bytes.
		{"a key with a character outside base64", func(t *testing.T) string {
			return write(t, `["`+key(32)[:10]+"*"+key(32)[10:]+`"]`, 0o600)
		}, false},
		{"a number", func(t *testing.T) string { return write(t, `[32]`, 0o600) }, false},
		{"a sound key, then a short one", func(t *testing.T) string { return write(t, `["`+key(32)+`","`+key(24)+`"]`, 0o600) }, false},
		{"empty", func(t *testing.T) string { return write(t, ``, 0o600) }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			output, err := nomadGossipSetupFunctions(`nomad_gossip_keyring_ok "$1"`, test.path(t))
			if (err == nil) != test.sound {
				t.Fatalf("nomad_gossip_keyring_ok: sound=%v, want %v: %s", err == nil, test.sound, output)
			}
		})
	}

	t.Run("a keyring of another owner", func(t *testing.T) {
		// On a host the check runs as root, who can read anyone's keyring,
		// so only the owner check refuses one root does not own. The test
		// runs the check as root: directly, or through passwordless sudo
		// against a keyring the test user owns.
		path := write(t, sound, 0o600)
		var output []byte
		var err error
		switch {
		case os.Getuid() == 0:
			if err := os.Chown(path, 65534, 65534); err != nil {
				t.Fatal(err)
			}
			var text string
			text, err = nomadGossipSetupFunctions(`nomad_gossip_keyring_ok "$1"`, path)
			output = []byte(text)
		case exec.Command("sudo", "-n", "true").Run() == nil:
			setup := filepath.Join(executionPlatformRepoRootPath(), "scripts", "70_linux_setup.sh")
			output, err = exec.Command("sudo", "-n", "env", "PATH="+os.Getenv("PATH"), "bash", "-c",
				`set -euo pipefail; eval "$(sed -n '/^# BEGIN nomad_gossip/,/^# END nomad_gossip/p' "$1")"; nomad_gossip_keyring_ok "$2"`,
				"bash", setup, path).CombinedOutput()
		default:
			t.Skip("needs root or passwordless sudo to check the keyring as root")
		}
		if err == nil {
			t.Fatalf("root accepted a keyring it does not own: %s", output)
		}
	})
}

// installNomadGossipKeyring runs the setup script's
// install_nomad_gossip_keyring for a data directory, with sudo standing in
// for itself, and returns NOMAD_CONFIG_CHANGED and NOMAD_GOSSIP_ISSUED.
func installNomadGossipKeyring(t *testing.T, dataDir string) (string, string) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(executionPlatformRepoRoot(t), "scripts", "70_linux_setup.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	start := strings.Index(text, "\n# BEGIN nomad_gossip")
	install := strings.Index(text, "\ninstall_nomad_gossip_keyring() {\n")
	if start < 0 || install < start {
		t.Fatal("70_linux_setup.sh has no nomad_gossip region followed by install_nomad_gossip_keyring")
	}
	end := strings.Index(text[install:], "\n}\n")
	if end < 0 {
		t.Fatal("install_nomad_gossip_keyring does not end")
	}
	functions := text[start : install+end+3]
	script := "set -euo pipefail\nsudo() { \"$@\"; }\n" + functions +
		"NOMAD_GOSSIP_KEYRING=\"$1/server/serf.keyring\"\nNOMAD_CONFIG_CHANGED=0\nNOMAD_GOSSIP_ISSUED=0\n" +
		"install_nomad_gossip_keyring >&2\nprintf '%s %s' \"${NOMAD_CONFIG_CHANGED}\" \"${NOMAD_GOSSIP_ISSUED}\"\n"
	command := exec.Command("bash", "-c", script, "bash", dataDir)
	command.Env = []string{"PATH=" + os.Getenv("PATH")}
	var stdout, stderr strings.Builder
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("install_nomad_gossip_keyring: %v %s", err, stderr.String())
	}
	changed, issued, _ := strings.Cut(stdout.String(), " ")
	return changed, issued
}

func TestLinuxSetupKeepsASoundNomadGossipKeyringAndReplacesAnUnsoundOne(t *testing.T) {
	dataDir := t.TempDir()
	keyring := nomadGossipKeyringPath(dataDir)

	if changed, issued := installNomadGossipKeyring(t, dataDir); changed != "1" || issued != "1" {
		t.Fatalf("no keyring: NOMAD_CONFIG_CHANGED=%s NOMAD_GOSSIP_ISSUED=%s, want 1 1 (Nomad must restart to read it)", changed, issued)
	}
	first := readIssuedNomadGossipKey(t, keyring)

	if changed, issued := installNomadGossipKeyring(t, dataDir); changed != "0" || issued != "0" {
		t.Fatalf("sound keyring: NOMAD_CONFIG_CHANGED=%s NOMAD_GOSSIP_ISSUED=%s, want 0 0", changed, issued)
	}
	if kept := readIssuedNomadGossipKey(t, keyring); kept != first {
		t.Fatal("a sound keyring was replaced")
	}

	if err := os.Chmod(keyring, 0o644); err != nil {
		t.Fatal(err)
	}
	if changed, issued := installNomadGossipKeyring(t, dataDir); changed != "1" || issued != "1" {
		t.Fatalf("keyring others can read: NOMAD_CONFIG_CHANGED=%s NOMAD_GOSSIP_ISSUED=%s, want 1 1", changed, issued)
	}
	requireFileMode(t, keyring, 0o600)
	if replaced := readIssuedNomadGossipKey(t, keyring); replaced == first {
		t.Fatal("a keyring others could read kept its key")
	}
}

// The setup writes the keyring into Nomad's data directory, under the
// root-only data directory it creates, before the config that starts or
// restarts Nomad, and no key appears in nomad.hcl.
func TestLinuxSetupWritesTheNomadGossipKeyringBeforeNomadStarts(t *testing.T) {
	root := executionPlatformRepoRoot(t)
	body, err := os.ReadFile(filepath.Join(root, "scripts", "70_linux_setup.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, "\nNOMAD_GOSSIP_KEYRING=\"${NOMAD_DATA_DIR}/server/serf.keyring\"\n") {
		t.Fatal("70_linux_setup.sh does not keep the gossip keyring where Nomad reads it")
	}
	start := strings.Index(text, "\ninstall_nomad_service_config() {\n")
	if start < 0 {
		t.Fatal("70_linux_setup.sh has no install_nomad_service_config")
	}
	service := text[start : start+strings.Index(text[start:], "\n}\n")]
	dataDir := strings.Index(service, `sudo install -d -o root -g root -m 0700 "${NOMAD_DATA_DIR}"`)
	install := strings.Index(service, "\n  install_nomad_gossip_keyring\n")
	config := strings.Index(service, `sudo tee "${NOMAD_CONFIG_PATH}"`)
	if dataDir < 0 || install < dataDir || config < install {
		t.Fatalf("install_nomad_service_config must create the data directory, then write the keyring, then the config (offsets %d %d %d)", dataDir, install, config)
	}
	for _, rel := range []string{filepath.Join("scripts", "70_linux_setup.sh"), filepath.Join(".examples", "config", "nomad.hcl")} {
		data, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		if regexp.MustCompile(`(?m)^\s*encrypt\s*=`).Match(data) {
			t.Fatalf("%s names a gossip key; Nomad reads it from the keyring", rel)
		}
	}
}

// A real Nomad started with the keyring the setup writes encrypts its
// gossip, and a Nomad server without the key cannot join it.
func TestRealNomadRefusesAGossipPeerWithoutTheKey(t *testing.T) {
	harness := startACLTestNomad(t, nomadHarnessOptions{})

	members := func() []string {
		status, body := nomadRawRequest(t, http.MethodGet, harness.addr+"/v1/agent/members", harness.managementToken, nil)
		if status != http.StatusOK {
			t.Fatalf("agent members: HTTP %d %s", status, body)
		}
		var answer struct {
			Members []struct {
				Name string `json:"Name"`
			} `json:"Members"`
		}
		if err := json.Unmarshal([]byte(body), &answer); err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, member := range answer.Members {
			names = append(names, member.Name)
		}
		return names
	}
	if got := members(); len(got) != 1 {
		t.Fatalf("the harness Nomad lists %v before the rogue starts, want only itself", got)
	}

	rootDir := newExecutionWorkspaceTempDir(t, "nomad-rogue-")
	ports := make([]int, 3)
	for i := range ports {
		port, err := reserveTCPPortValue()
		if err != nil {
			t.Fatal(err)
		}
		ports[i] = port
	}
	config := fmt.Sprintf(`data_dir = %q
bind_addr = "127.0.0.1"
ports {
  http = %d
  rpc  = %d
  serf = %d
}
advertise {
  http = "127.0.0.1:%d"
  rpc  = "127.0.0.1:%d"
  serf = "127.0.0.1:%d"
}
client {
  enabled = false
}
server {
  enabled = true
  server_join {
    retry_join     = [%q]
    retry_interval = "1s"
  }
}
`, filepath.Join(rootDir, "data"), ports[0], ports[1], ports[2], ports[0], ports[1], ports[2], harness.serfAddr)
	configPath := filepath.Join(rootDir, "rogue.hcl")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(rootDir, "rogue.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	rogue := exec.Command("nomad", "agent", "-config="+configPath)
	rogue.Stdout, rogue.Stderr = logFile, logFile
	if err := rogue.Start(); err != nil {
		t.Fatal(err)
	}
	_ = logFile.Close()
	t.Cleanup(func() {
		_ = rogue.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { _ = rogue.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = rogue.Process.Kill()
			<-done
		}
	})

	// The rogue's own log says why each join fails; wait for that, then the
	// harness must still list only itself.
	const refusal = "remote state is encrypted and encryption is not configured"
	deadline := time.Now().Add(30 * time.Second)
	for {
		data, _ := os.ReadFile(logPath)
		if strings.Contains(string(data), refusal) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the rogue Nomad never logged %q:\n%s", refusal, data)
		}
		time.Sleep(250 * time.Millisecond)
	}
	if got := members(); len(got) != 1 {
		t.Fatalf("a Nomad without the gossip key joined: the harness lists %v", got)
	}

	status, body := nomadRawRequest(t, http.MethodGet, harness.addr+"/v1/agent/self", harness.managementToken, nil)
	if status != http.StatusOK {
		t.Fatalf("agent self: HTTP %d %s", status, body)
	}
	var self struct {
		Stats struct {
			Serf map[string]any `json:"serf"`
		} `json:"stats"`
	}
	if err := json.Unmarshal([]byte(body), &self); err != nil {
		t.Fatal(err)
	}
	// The checks compare with the string Nomad reports.
	if got, ok := self.Stats.Serf["encrypted"].(string); !ok || got != strconv.FormatBool(true) {
		t.Fatalf("the harness Nomad reports stats.serf.encrypted %#v, want the string \"true\"", self.Stats.Serf["encrypted"])
	}
}
