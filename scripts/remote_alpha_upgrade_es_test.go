package scripts_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

const upgradeESPython = "scripts/internal/remote_alpha_upgrade_es.py"

func runUpgradeESPython(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command("python3", append([]string{"-I", repoPath(upgradeESPython)}, args...)...)
	cmd.Dir = t.TempDir()
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("run %v: %v", args, err)
		}
		code = exitErr.ExitCode()
	}
	return stdout.String(), stderr.String(), code
}

// preSubmitAuthExample is the submit example without the two keys current
// ES requires and the box's older build does not know: the shape of the
// box's es.json as far as these keys go.
func preSubmitAuthExample(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile(repoPath(".examples/config/es.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	delete(doc["nomad"].(map[string]any), "token_file")
	delete(doc["execution"].(map[string]any), "retained_result_auth")
	return doc
}

var upgradeAuthArgs = []string{
	"--token-file", "/etc/execution-substrate/nomad-acl/es-token",
	"--store-id", "remote-alpha",
	"--key-id", "k1",
	"--key-file", "/etc/execution-substrate/retained-result-auth/es.key",
}

func TestRemoteAlphaUpgradeESMigratedConfigIsAcceptedByES(t *testing.T) {
	helper := buildESConfigCheck(t)
	dir := t.TempDir()
	oldPath, newPath := filepath.Join(dir, "old.json"), filepath.Join(dir, "new.json")
	writeJSONFile(t, oldPath, preSubmitAuthExample(t))

	refuses := exec.Command(helper, oldPath)
	refuses.Dir = dir
	if out, err := refuses.CombinedOutput(); err == nil {
		t.Fatalf("current ES accepts the pre-upgrade shape, so this test proves nothing: %s", out)
	}
	stdout, stderr, code := runUpgradeESPython(t, append([]string{"migrate-config", "--input", oldPath, "--output", newPath}, upgradeAuthArgs...)...)
	if code != 0 {
		t.Fatalf("migrate-config exited %d: %s", code, stderr)
	}
	if strings.TrimSpace(stdout) != `{"changes": ["nomad.token_file", "execution.retained_result_auth"]}` {
		t.Fatalf("migrate-config reported %q", stdout)
	}
	accepts := exec.Command(helper, newPath)
	accepts.Dir = dir
	if out, err := accepts.CombinedOutput(); err != nil {
		t.Fatalf("ES refuses the migrated config: %v %s", err, out)
	}

	var migrated map[string]any
	data, err := os.ReadFile(newPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &migrated); err != nil {
		t.Fatal(err)
	}
	if got := migrated["nomad"].(map[string]any)["token_file"]; got != "/etc/execution-substrate/nomad-acl/es-token" {
		t.Fatalf("token_file = %v", got)
	}
	auth := migrated["execution"].(map[string]any)["retained_result_auth"].(map[string]any)
	if auth["store_id"] != "remote-alpha" || auth["key_id"] != "k1" || auth["key_file"] != "/etc/execution-substrate/retained-result-auth/es.key" || len(auth) != 3 {
		t.Fatalf("retained_result_auth = %v", auth)
	}
	// Nothing else changed.
	delete(migrated["nomad"].(map[string]any), "token_file")
	delete(migrated["execution"].(map[string]any), "retained_result_auth")
	want, _ := json.Marshal(preSubmitAuthExample(t))
	got, _ := json.Marshal(migrated)
	if !bytes.Equal(want, got) {
		t.Fatalf("migrate-config changed more than the two keys:\nwant %s\ngot  %s", want, got)
	}
	if st, err := os.Stat(newPath); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("migrated file mode: %v %v", st.Mode(), err)
	}

	// A rerun on the migrated file changes nothing; other values refuse.
	stdout, stderr, code = runUpgradeESPython(t, append([]string{"migrate-config", "--input", newPath}, upgradeAuthArgs...)...)
	if code != 0 || strings.TrimSpace(stdout) != `{"changes": []}` {
		t.Fatalf("rerun: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	other := append([]string{}, upgradeAuthArgs...)
	other[1] = "/etc/elsewhere/es-token"
	_, stderr, code = runUpgradeESPython(t, append([]string{"migrate-config", "--input", newPath}, other...)...)
	if code != 1 || !strings.Contains(stderr, "already has nomad.token_file or execution.retained_result_auth with other values") {
		t.Fatalf("rerun with other values: exit %d, stderr %q", code, stderr)
	}
}

func TestRemoteAlphaUpgradeESMigrateConfigRefusesWhatItWasNotWrittenFor(t *testing.T) {
	dir := t.TempDir()
	expectedPaths := filepath.Join(dir, "expected-paths")
	doc := preSubmitAuthExample(t)
	var paths []string
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		switch val := v.(type) {
		case map[string]any:
			for k, c := range val {
				p := k
				if prefix != "" {
					p = prefix + "." + k
				}
				walk(p, c)
			}
		case []any:
			for _, c := range val {
				walk(prefix+"[]", c)
			}
		default:
			paths = append(paths, prefix)
		}
	}
	walk("", doc)
	if err := os.WriteFile(expectedPaths, []byte(strings.Join(paths, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	run := func(name string, edit func(map[string]any), extra []string, wantCode int, wantText string) {
		t.Run(name, func(t *testing.T) {
			d := preSubmitAuthExample(t)
			edit(d)
			in := filepath.Join(t.TempDir(), "es.json")
			writeJSONFile(t, in, d)
			args := append([]string{"migrate-config", "--input", in, "--expected-paths", expectedPaths}, upgradeAuthArgs...)
			args = append(args, extra...)
			_, stderr, code := runUpgradeESPython(t, args...)
			if code != wantCode || !strings.Contains(stderr, wantText) {
				t.Fatalf("exit %d (want %d), stderr %q (want %q)", code, wantCode, stderr, wantText)
			}
		})
	}
	run("expected shape", func(map[string]any) {}, nil, 0, "")
	run("unexpected key", func(d map[string]any) { d["http"].(map[string]any)["extra"] = 1 }, nil, 1, "unexpected ['http.extra']")
	run("missing key", func(d map[string]any) { delete(d["nomad"].(map[string]any), "datacenter") }, nil, 1, "missing ['nomad.datacenter']")
	run("no nomad", func(d map[string]any) { delete(d, "nomad") }, nil, 1, "no nomad.base_url")
	run("bad store id", func(map[string]any) {}, []string{"--store-id", "Remote"}, 1, "canonical 1-32 byte identifiers")
	run("key equals token", func(map[string]any) {}, []string{"--key-file", "/etc/execution-substrate/nomad-acl/es-token"}, 1, "different from the token file")
	run("relative token", func(map[string]any) {}, []string{"--token-file", "es-token"}, 1, "clean absolute path")
}

func TestRemoteAlphaUpgradeESProvisionKey(t *testing.T) {
	uid, gid := strconv.Itoa(os.Getuid()), strconv.Itoa(os.Getgid())
	base := t.TempDir()
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(base, "retained-result-auth", "es.key")
	provision := func(extra ...string) (string, string, int) {
		return runUpgradeESPython(t, append([]string{"provision-key", "--key-file", key, "--owner-uid", uid, "--owner-gid", gid}, extra...)...)
	}

	stdout, stderr, code := provision("--dry-run")
	if code != 0 || !strings.Contains(stdout, `"would create"`) {
		t.Fatalf("dry run: exit %d, %q %q", code, stdout, stderr)
	}
	if _, err := os.Lstat(filepath.Dir(key)); !os.IsNotExist(err) {
		t.Fatalf("dry run created the key directory: %v", err)
	}

	stdout, stderr, code = provision()
	if code != 0 || !strings.Contains(stdout, `"created"`) {
		t.Fatalf("create: exit %d, %q %q", code, stdout, stderr)
	}
	first, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Lstat(key)
	if err != nil {
		t.Fatal(err)
	}
	sys := st.Sys().(*syscall.Stat_t)
	if len(first) != 32 || st.Mode().Perm() != 0o400 || !st.Mode().IsRegular() || sys.Nlink != 1 || int(sys.Uid) != os.Getuid() {
		t.Fatalf("key: %d bytes, mode %v, links %d, uid %d", len(first), st.Mode(), sys.Nlink, sys.Uid)
	}
	if bytes.Equal(first, make([]byte, 32)) {
		t.Fatal("key is all zero")
	}
	if dst, err := os.Stat(filepath.Dir(key)); err != nil || dst.Mode().Perm() != 0o755 {
		t.Fatalf("key directory mode: %v %v", dst.Mode(), err)
	}
	if strings.Contains(stdout+stderr, string(first)) {
		t.Fatal("provision-key printed the key")
	}

	// A rerun keeps the key as it is.
	stdout, _, code = provision()
	second, _ := os.ReadFile(key)
	if code != 0 || !strings.Contains(stdout, `"exists"`) || !bytes.Equal(first, second) {
		t.Fatalf("rerun: exit %d, %q, key kept %v", code, stdout, bytes.Equal(first, second))
	}

	refuse := func(name, want string, setup func(), undo func()) {
		t.Run(name, func(t *testing.T) {
			setup()
			defer undo()
			before, _ := os.ReadFile(key)
			_, stderr, code := provision()
			if code != 1 || !strings.Contains(stderr, want) {
				t.Fatalf("exit %d, stderr %q, want %q", code, stderr, want)
			}
			if after, _ := os.ReadFile(key); !bytes.Equal(after, before) {
				t.Fatal("a refused run changed the key")
			}
		})
	}
	refuse("world-readable key", "mode must be 0400 or 0600",
		func() { _ = os.Chmod(key, 0o644) }, func() { _ = os.Chmod(key, 0o400) })
	refuse("group-writable directory", "must not be group- or world-writable",
		func() { _ = os.Chmod(filepath.Dir(key), 0o775) }, func() { _ = os.Chmod(filepath.Dir(key), 0o755) })
	refuse("second link", "exactly one link",
		func() { _ = os.Link(key, key+".link") }, func() { _ = os.Remove(key + ".link") })
	refuse("short key", "exactly 32 bytes",
		func() { _ = os.Chmod(key, 0o600); _ = os.WriteFile(key, first[:31], 0o600) },
		func() { _ = os.WriteFile(key, first, 0o600); _ = os.Chmod(key, 0o400) })
	moved := key + ".moved"
	refuse("symlink", "not a regular file",
		func() { _ = os.Rename(key, moved); _ = os.Symlink(moved, key) },
		func() { _ = os.Remove(key); _ = os.Rename(moved, key) })
	dir := filepath.Dir(key)
	refuse("symlinked directory", "symbolic link or not a directory",
		func() { _ = os.Rename(dir, dir+".real"); _ = os.Symlink(dir+".real", dir) },
		func() { _ = os.Remove(dir); _ = os.Rename(dir+".real", dir) })
	t.Run("other owner", func(t *testing.T) {
		// As root, the root-owned directory passes and the key's owner is
		// wrong; as another user, the directory's owner is already wrong.
		want := "the key file must be owned by ES's user"
		if os.Getuid() != 0 {
			want = "the key's parent directory must be owned by ES's user or root"
		}
		_, stderr, code := runUpgradeESPython(t, "provision-key", "--key-file", key,
			"--owner-uid", strconv.Itoa(os.Getuid()+4242), "--owner-gid", gid)
		if code != 1 || !strings.Contains(stderr, want) {
			t.Fatalf("exit %d, stderr %q, want %q", code, stderr, want)
		}
	})
}

func TestRemoteAlphaUpgradeESBackupAndRestore(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "es.json")
	unit := filepath.Join(root, "es.service")
	binary := filepath.Join(root, "es")
	absent := filepath.Join(root, "es-token")
	files := map[string]struct {
		data []byte
		mode os.FileMode
	}{
		config: {[]byte(`{"old":true}` + "\n"), 0o640},
		unit:   {[]byte("[Service]\nUser=es\n"), 0o644},
		binary: {[]byte("\x7fELF old binary"), 0o755},
	}
	for path, f := range files {
		if err := os.WriteFile(path, f.data, f.mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, f.mode); err != nil {
			t.Fatal(err)
		}
	}
	backup := filepath.Join(root, "backup")
	args := []string{"backup", "--backup-dir", backup}
	for _, p := range []string{config, unit, binary, absent} {
		args = append(args, "--path", p)
	}
	stdout, stderr, code := runUpgradeESPython(t, args...)
	if code != 0 || !strings.Contains(stdout, `"files": 4`) {
		t.Fatalf("backup: exit %d, %q %q", code, stdout, stderr)
	}
	if st, err := os.Stat(backup); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("backup directory mode: %v %v", st.Mode(), err)
	}
	// A second backup into the same directory refuses rather than mixing.
	if _, _, code := runUpgradeESPython(t, args...); code == 0 {
		t.Fatal("a second backup into an existing directory succeeded")
	}

	// The upgrade changes the files: new content, new mode, a link in place
	// of the unit, and a new token file.
	if err := os.WriteFile(config, []byte(`{"new":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(config, 0o600)
	_ = os.Remove(unit)
	if err := os.Symlink(binary, unit); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, []byte("\x7fELF new binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(absent, []byte("token"), 0o400); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code = runUpgradeESPython(t, "restore", "--backup-dir", backup)
	if code != 0 {
		t.Fatalf("restore: exit %d, %q", code, stderr)
	}
	var report struct {
		Restored []struct {
			Path    string `json:"path"`
			Changed bool   `json:"changed"`
		} `json:"restored"`
		AbsentAtBackup []string `json:"absent_at_backup"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Restored) != 3 || len(report.AbsentAtBackup) != 1 || report.AbsentAtBackup[0] != absent {
		t.Fatalf("restore report: %s", stdout)
	}
	for path, f := range files {
		st, err := os.Lstat(path)
		if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != f.mode {
			t.Fatalf("%s after restore: %v %v", path, st.Mode(), err)
		}
		if got, _ := os.ReadFile(path); !bytes.Equal(got, f.data) {
			t.Fatalf("%s after restore holds %q", path, got)
		}
	}
	if _, err := os.Stat(absent); err != nil {
		t.Fatalf("restore removed a file that was absent at backup time: %v", err)
	}

	// A second restore changes nothing.
	stdout, _, code = runUpgradeESPython(t, "restore", "--backup-dir", backup)
	if code != 0 || strings.Contains(stdout, `"changed": true`) {
		t.Fatalf("second restore: exit %d, %q", code, stdout)
	}

	// A tampered copy stops the restore before anything is written.
	if err := os.WriteFile(config, []byte(`{"new":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	copies, _ := filepath.Glob(filepath.Join(backup, "files", "*-es"))
	if len(copies) != 1 {
		t.Fatalf("binary copy: %v", copies)
	}
	if err := os.WriteFile(copies[0], []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, stderr, code = runUpgradeESPython(t, "restore", "--backup-dir", backup)
	if code != 1 || !strings.Contains(stderr, "does not match its manifest") {
		t.Fatalf("tampered restore: exit %d, %q", code, stderr)
	}
	if got, _ := os.ReadFile(config); string(got) != `{"new":true}` {
		t.Fatal("a refused restore wrote a file")
	}

	// A backup directory others can read is refused.
	_ = os.Chmod(backup, 0o755)
	if _, stderr, code := runUpgradeESPython(t, "restore", "--backup-dir", backup); code != 1 || !strings.Contains(stderr, "0700") {
		t.Fatalf("open backup directory: exit %d, %q", code, stderr)
	}
}
