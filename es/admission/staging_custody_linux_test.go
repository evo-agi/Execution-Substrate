//go:build linux

package admission

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLinuxStagingCustodyUsesOpenat2AndRenameat2(t *testing.T) {
	root := t.TempDir()
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rootFD)
	if err := os.Mkdir(filepath.Join(root, "actual"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("actual", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if fd, err := platformOpenAtNoFollow(rootFD, "link", unix.O_RDONLY|unix.O_DIRECTORY, 0, true); err == nil {
		_ = unix.Close(fd)
		t.Fatal("openat2 accepted a symbolic link")
	}
	if err := os.Mkdir(filepath.Join(root, "source"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "destination"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := platformRenameNoReplace(rootFD, "source", rootFD, "destination"); !errors.Is(err, unix.EEXIST) {
		t.Fatalf("renameat2 no-replace returned %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "source-file"), []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "destination-file"), []byte("destination"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := platformRenameNoReplace(rootFD, "source-file", rootFD, "destination-file"); !errors.Is(err, unix.EEXIST) {
		t.Fatalf("renameat2 no-replace for regular file returned %v", err)
	}
	for _, name := range []string{"source-file", "destination-file"} {
		if info, err := os.Stat(filepath.Join(root, name)); err != nil || !info.Mode().IsRegular() {
			t.Fatalf("no-replace rename did not preserve regular file %s: %v", name, err)
		}
	}
}

func TestLinuxStagingCustodyRejectsMountCrossing(t *testing.T) {
	rootFD, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rootFD)
	if fd, err := platformOpenAtNoFollow(rootFD, "proc", unix.O_RDONLY|unix.O_DIRECTORY, 0, true); err == nil {
		_ = unix.Close(fd)
		t.Fatal("openat2 RESOLVE_NO_XDEV accepted the procfs mount crossing")
	} else if !errors.Is(err, unix.EXDEV) {
		t.Fatalf("expected EXDEV for procfs mount crossing, got %v", err)
	}
}
