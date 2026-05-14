package admission

import (
	"os"
	"path/filepath"
	"testing"
)

const (
	skipUnreadableFixtureBypassed = "skipping permission-denied fixture: current process can read chmod 000 path"
	skipDeleteFixtureBypassed     = "skipping permission-denied fixture: current process can delete from chmod 500 directory"
)

func requireChmod000ReadDenied(t *testing.T, path string) {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat permission-denied fixture %s: %v", path, err)
	}
	originalMode := info.Mode().Perm()
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod permission-denied fixture %s: %v", path, err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(path, originalMode)
	})

	if _, err := os.ReadDir(path); err == nil {
		t.Skip(skipUnreadableFixtureBypassed)
	} else if !os.IsPermission(err) {
		t.Fatalf("probe permission-denied fixture read %s: %v", path, err)
	}
}

func requireChmod500DeleteDenied(t *testing.T, dir string) {
	t.Helper()

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat permission-denied fixture %s: %v", dir, err)
	}
	originalMode := info.Mode().Perm()
	probePath := filepath.Join(dir, ".delete-permission-probe")
	if err := os.WriteFile(probePath, []byte("probe\n"), 0o600); err != nil {
		t.Fatalf("write permission-denied fixture %s: %v", probePath, err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod permission-denied fixture %s: %v", dir, err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(dir, originalMode)
		_ = os.Remove(probePath)
	})

	if err := os.Remove(probePath); err == nil {
		t.Skip(skipDeleteFixtureBypassed)
	} else if !os.IsPermission(err) {
		t.Fatalf("probe permission-denied fixture delete %s: %v", probePath, err)
	}
}
