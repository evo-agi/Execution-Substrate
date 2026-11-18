//go:build darwin

package admission

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDarwinStagingCustodyUsesNoFollowAnyAndExclusiveRename(t *testing.T) {
	root := physicalTestTempDir(t)
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rootFD)

	if err := os.Mkdir(filepath.Join(root, "actual"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "actual", "file"), []byte("bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("actual", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if fd, err := platformOpenAtNoFollow(rootFD, "link/file", unix.O_RDONLY, 0, false); err == nil {
		_ = unix.Close(fd)
		t.Fatal("O_NOFOLLOW_ANY accepted an ancestor symbolic link")
	}

	if err := os.Mkdir(filepath.Join(root, "source"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "destination"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := platformRenameNoReplace(rootFD, "source", rootFD, "destination"); err == nil {
		t.Fatal("exclusive Darwin rename replaced an existing destination")
	}
	for _, name := range []string{"source", "destination"} {
		if info, err := os.Stat(filepath.Join(root, name)); err != nil || !info.IsDir() {
			t.Fatalf("exclusive rename did not preserve %s: %v", name, err)
		}
	}

	if err := os.WriteFile(filepath.Join(root, "source-file"), []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "destination-file"), []byte("destination"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := platformRenameNoReplace(rootFD, "source-file", rootFD, "destination-file"); err == nil {
		t.Fatal("exclusive Darwin rename replaced an existing regular file")
	}
	for _, name := range []string{"source-file", "destination-file"} {
		if info, err := os.Stat(filepath.Join(root, name)); err != nil || !info.Mode().IsRegular() {
			t.Fatalf("exclusive rename did not preserve regular file %s: %v", name, err)
		}
	}
}

func TestDarwinStagingCustodyCapabilityProbeExercisesActualSyscalls(t *testing.T) {
	root := physicalTestTempDir(t)
	if err := probeStagingCustodyCapabilities(root, executionPlatformStateOwner{UID: os.Getuid(), GID: os.Getgid()}); err != nil {
		t.Fatalf("Darwin custody capability probe failed: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("capability probe did not retain its unproven cleanup names: %v", entries)
	}
}

func TestDarwinStagingCustodyRevalidationRefusesRootReplacementAndRetainsIt(t *testing.T) {
	root := physicalTestTempDir(t)
	runID := "run-0123456789abcdef"
	custody, _ := claimTestStagingCustody(t, root, runID)
	if err := custody.writeFile("payload/file", []byte("owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	displaced := filepath.Join(root, "displaced")
	if err := os.Rename(filepath.Join(root, runID), displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, runID), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, runID, "replacement"), []byte("retain"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := custody.revalidateBeforeHandoff(); err == nil {
		t.Fatal("handoff revalidation accepted a replaced visible run root")
	}
	if content, err := os.ReadFile(filepath.Join(root, runID, "replacement")); err != nil || string(content) != "retain" {
		t.Fatal("revalidation changed the replacement run root")
	}
	if content, err := os.ReadFile(filepath.Join(displaced, "payload", "file")); err != nil || string(content) != "owned" {
		t.Fatal("revalidation changed the displaced held run root")
	}
	if err := custody.close(); err != nil {
		t.Fatal(err)
	}
}
