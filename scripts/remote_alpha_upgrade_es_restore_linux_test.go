package scripts_test

import (
	"os"
	"path/filepath"
	"testing"
)

// The other side of N67-10 (re-check 52 of #67): a name with a byte the file
// system encoding cannot decode reaches Python as a surrogate that stands for
// that byte, which a file name can hold, so the manifest check lets it
// through and the file is put back. Linux only: macOS file systems hold only
// UTF-8 names.
func TestRemoteAlphaUpgradeESRestorePutsBackANameWithAByteThatIsNotUTF8(t *testing.T) {
	root := t.TempDir()
	odd := filepath.Join(root, "b\xff.json")
	if err := os.WriteFile(odd, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(root, "backup")
	if _, stderr, code := runUpgradeESPython(t, "backup", "--backup-dir", backup, "--path", odd); code != 0 {
		t.Fatalf("backup: exit %d, %q", code, stderr)
	}
	if err := os.WriteFile(odd, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := runUpgradeESPython(t, "restore", "--backup-dir", backup); code != 0 {
		t.Fatalf("restore: exit %d, %q", code, stderr)
	}
	if got, _ := os.ReadFile(odd); string(got) != "old\n" {
		t.Fatalf("restore left %q", got)
	}
}
