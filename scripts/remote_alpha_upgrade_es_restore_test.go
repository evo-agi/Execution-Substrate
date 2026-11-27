package scripts_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The restore path's rules that a manifest or the host can break between a
// backup and its restore, each refused before the first file is put back
// rather than ending part way in a traceback (re-check 52 of #67: Opus's
// N67-10 and the two rules its mutants Q1 and Q8 found unpinned, Sonnet's
// S52-1 and O52-1). The rollback command runs the same checks before it
// stops a service (TestRemoteAlphaUpgradeESRollsBackOnlyTheApplyThatLeftTheHost).

// restoreFixture backs up root/a.json (mode 0600) and root/sub/b.json (mode
// 0640), both holding "old\n", into root/backup, then writes "new\n" into
// both, so that a restore that went ahead would have to change them.
func restoreFixture(t *testing.T) (root, first, second, backup string) {
	t.Helper()
	root = t.TempDir()
	first, second = filepath.Join(root, "a.json"), filepath.Join(root, "sub", "b.json")
	if err := os.Mkdir(filepath.Dir(second), 0o755); err != nil {
		t.Fatal(err)
	}
	for p, mode := range map[string]os.FileMode{first: 0o600, second: 0o640} {
		if err := os.WriteFile(p, []byte("old\n"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	backup = filepath.Join(root, "backup")
	if _, stderr, code := runUpgradeESPython(t, "backup", "--backup-dir", backup, "--path", first, "--path", second); code != 0 {
		t.Fatalf("backup: exit %d, %q", code, stderr)
	}
	for _, p := range []string{first, second} {
		if err := os.WriteFile(p, []byte("new\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root, first, second, backup
}

// editManifest replaces old, which must occur once, with replacement in the
// backup's manifest.json, byte for byte.
func editManifest(t *testing.T, backup, old, replacement string) {
	t.Helper()
	manifest := filepath.Join(backup, "manifest.json")
	data, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(data, []byte(old)) != 1 {
		t.Fatalf("%s is not once in %s", old, data)
	}
	if err := os.WriteFile(manifest, bytes.Replace(data, []byte(old), []byte(replacement), 1), 0o600); err != nil {
		t.Fatal(err)
	}
}

// restoreRefused runs restore and requires a refusal saying each of says,
// with no traceback, and each of files as restoreFixture left it.
func restoreRefused(t *testing.T, backup string, says []string, files ...string) {
	t.Helper()
	_, stderr, code := runUpgradeESPython(t, "restore", "--backup-dir", backup)
	if code != 1 || strings.Contains(stderr, "Traceback") || !strings.Contains(stderr, "remote alpha ES upgrade refused: ") {
		t.Fatalf("restore: exit %d, want a refusal: %s", code, stderr)
	}
	for _, part := range says {
		if !strings.Contains(stderr, part) {
			t.Fatalf("restore's refusal does not say %q: %s", part, stderr)
		}
	}
	for _, p := range files {
		if got, _ := os.ReadFile(p); string(got) != "new\n" {
			t.Fatalf("a refused restore wrote %s: %q", p, got)
		}
	}
}

// N67-10: JSON's "\ud800" is a Python string no file name can hold: open()
// and lstat() raise UnicodeEncodeError, not OSError. In a copy's name it was
// a traceback before anything changed; in a path, one after the first file
// was put back.
func TestRemoteAlphaUpgradeESRestoreRefusesAManifestStringNoFileNameCanHold(t *testing.T) {
	t.Run("in a copy's name", func(t *testing.T) {
		_, first, second, backup := restoreFixture(t)
		editManifest(t, backup, `"01-b.json"`, `"01-b.json\ud800"`)
		restoreRefused(t, backup, []string{"/manifest.json is not the manifest apply writes (file 1's copy name holds a character no file name can hold); nothing was changed"}, first, second)
	})
	t.Run("in a path", func(t *testing.T) {
		_, first, second, backup := restoreFixture(t)
		editManifest(t, backup, `"`+second+`"`, `"`+second+`\ud800"`)
		restoreRefused(t, backup, []string{"/manifest.json is not the manifest apply writes (file 1's path holds a character no file name can hold); nothing was changed"}, first, second)
	})
}

// Q8: a copy that cannot be opened (its name is too long) is refused by
// message, before anything is written.
func TestRemoteAlphaUpgradeESRestoreRefusesACopyItCannotOpen(t *testing.T) {
	_, first, second, backup := restoreFixture(t)
	editManifest(t, backup, `"00-a.json"`, `"00-`+strings.Repeat("a", 300)+`"`)
	restoreRefused(t, backup, []string{"/files/00-" + strings.Repeat("a", 300) + ", cannot be read (", "; nothing was changed"}, first, second)
}

// Q1 and Sonnet's R16: a file standing where a file's folder was is refused
// like a folder that is gone. With only "exists" asked, the first file went
// back and the second rename ended in NotADirectoryError.
func TestRemoteAlphaUpgradeESRestoreRefusesAFileWhereAFolderBelongs(t *testing.T) {
	_, first, second, backup := restoreFixture(t)
	folder := filepath.Dir(second)
	if err := os.RemoveAll(folder); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(folder, []byte("not a folder\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	restoreRefused(t, backup, []string{folder + ", where the backup puts " + second + " back, is not a folder; no file was put back"}, first)
}

// Sonnet's R15: only a file that existed at backup time needs its folder. One
// that was absent is left as it is and reported, so its folder being gone
// does not stop the restore of the others.
func TestRemoteAlphaUpgradeESRestoreDoesNotNeedTheFolderOfAFileThatWasAbsent(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "es.json")
	if err := os.WriteFile(config, []byte("old\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	absent := filepath.Join(sub, "es-runtime-support")
	backup := filepath.Join(root, "backup")
	if _, stderr, code := runUpgradeESPython(t, "backup", "--backup-dir", backup, "--path", config, "--path", absent); code != 0 {
		t.Fatalf("backup: exit %d, %q", code, stderr)
	}
	if err := os.WriteFile(config, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(sub); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code := runUpgradeESPython(t, "restore", "--backup-dir", backup)
	var report struct {
		AbsentAtBackup []string `json:"absent_at_backup"`
	}
	if code != 0 || json.Unmarshal([]byte(stdout), &report) != nil || len(report.AbsentAtBackup) != 1 || report.AbsentAtBackup[0] != absent {
		t.Fatalf("restore with the folder of an absent file gone: exit %d, %q %q", code, stdout, stderr)
	}
	if got, _ := os.ReadFile(config); string(got) != "old\n" {
		t.Fatalf("the file that existed was not put back: %q", got)
	}
}

// Sonnet's Q11: a mode is exactly four octal digits. With any length, 17777
// went back as 7777 and was then refused, the file changed, and a long one
// ended in an OverflowError traceback.
func TestRemoteAlphaUpgradeESRestoreRefusesAModeThatIsNotFourOctalDigits(t *testing.T) {
	for _, mode := range []string{"640", "00640", "17777", "1000000000000"} {
		t.Run(mode, func(t *testing.T) {
			_, first, second, backup := restoreFixture(t)
			editManifest(t, backup, `"mode": "0600"`, `"mode": "`+mode+`"`)
			restoreRefused(t, backup, []string{"/manifest.json is not the manifest apply writes (file 0, ",
				"lacks its copy's name, digest, size, mode, owner or group); nothing was changed"}, first, second)
		})
	}
}

// O52-1: a folder standing where a file goes back cannot be replaced by a
// rename. It was found by the rename, after the first file was put back (and,
// in a rollback, after ES and Nomad stopped), and left the new file's
// temporary name beside it.
func TestRemoteAlphaUpgradeESRestoreRefusesAFolderWhereAFileGoesBack(t *testing.T) {
	_, first, second, backup := restoreFixture(t)
	if err := os.Remove(second); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(second, 0o755); err != nil {
		t.Fatal(err)
	}
	restoreRefused(t, backup, []string{second + ", which the backup puts back as a file, is a folder now; remove it; no file was put back"}, first)
	entries, err := os.ReadDir(filepath.Dir(second))
	if err != nil || len(entries) != 1 {
		t.Fatalf("the folder of %s holds %v (%v), want only the folder", second, entries, err)
	}
}

// A path the restore cannot look at (a name too long for the file system)
// is refused before the first file is put back, not by open() after it.
func TestRemoteAlphaUpgradeESRestoreRefusesAPathItCannotLookAt(t *testing.T) {
	_, first, second, backup := restoreFixture(t)
	long := filepath.Join(filepath.Dir(second), strings.Repeat("b", 300))
	editManifest(t, backup, `"`+second+`"`, `"`+long+`"`)
	restoreRefused(t, backup, []string{long + ", which the backup puts back, cannot be looked at (File name too long); no file was put back"}, first, second)
}
