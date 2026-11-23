package admission

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func physicalTestTempDir(t *testing.T) string {
	t.Helper()
	return resolvePhysicalTestTempDir(t, t.TempDir())
}

func resolvePhysicalTestTempDir(t *testing.T, allocated string) string {
	t.Helper()
	physical, err := filepath.EvalSymlinks(allocated)
	if err != nil {
		t.Fatalf("resolve physical test temporary directory: %v", err)
	}
	if !filepath.IsAbs(physical) {
		t.Fatalf("physical test temporary directory is not absolute: %q", physical)
	}
	allocatedInfo, err := os.Stat(allocated)
	if err != nil {
		t.Fatalf("stat allocated test temporary directory: %v", err)
	}
	physicalInfo, err := os.Stat(physical)
	if err != nil {
		t.Fatalf("stat physical test temporary directory: %v", err)
	}
	if !physicalInfo.IsDir() {
		t.Fatalf("physical test temporary path is not a directory: %q", physical)
	}
	if !os.SameFile(allocatedInfo, physicalInfo) {
		t.Fatalf("physical test temporary path %q does not identify allocation %q", physical, allocated)
	}
	resolvedAgain, err := filepath.EvalSymlinks(physical)
	if err != nil {
		t.Fatalf("re-resolve physical test temporary directory: %v", err)
	}
	if resolvedAgain != physical {
		t.Fatalf("physical test temporary directory still has symlinked ancestry: got %q want %q", physical, resolvedAgain)
	}
	return physical
}

func TestPhysicalTestTempDirResolvesSameAllocationAndPreservesCleanupOwnership(t *testing.T) {
	allocated := t.TempDir()
	physical := resolvePhysicalTestTempDir(t, allocated)
	allocatedInfo, err := os.Stat(allocated)
	if err != nil {
		t.Fatal(err)
	}
	physicalInfo, err := os.Stat(physical)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(allocatedInfo, physicalInfo) {
		t.Fatalf("resolved path %q is not the allocated directory %q", physical, allocated)
	}
	if resolved, err := filepath.EvalSymlinks(physical); err != nil || resolved != physical {
		t.Fatalf("submitted test path is not already physical: resolved=%q err=%v", resolved, err)
	}

	var cleaned string
	t.Run("subtest allocation", func(t *testing.T) {
		cleaned = physicalTestTempDir(t)
		if err := os.WriteFile(filepath.Join(cleaned, "owned-by-testing"), []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	})
	if _, err := os.Stat(cleaned); !os.IsNotExist(err) {
		t.Fatalf("testing cleanup did not remove physical temporary directory %q: %v", cleaned, err)
	}
}

func TestPhysicalTestTempDirPreservesIntentionalSymlinkRefusal(t *testing.T) {
	physical := physicalTestTempDir(t)
	actual := filepath.Join(physical, "actual")
	if err := os.Mkdir(actual, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(physical, "link")
	if err := os.Symlink(actual, link); err != nil {
		t.Fatal(err)
	}
	runID := "run-0123456789abcdef"
	if custody, err := claimStagingCustody(link, runID, executionPlatformStateOwner{UID: os.Getuid(), GID: os.Getgid()}); err == nil {
		_ = custody.close()
		t.Fatal("intentional symlinked staging ancestor was accepted")
	}
	if _, err := os.Stat(filepath.Join(actual, runID)); !os.IsNotExist(err) {
		t.Fatalf("symlink refusal changed the target directory: %v", err)
	}
}

func TestRetainedResultReviewExactAncestryReopenPreservesComponents(t *testing.T) {
	workspace := physicalTestTempDir(t)
	exactAncestor := filepath.Join(workspace, "auth ")
	otherAncestor := filepath.Join(workspace, "auth")
	for _, path := range []string{exactAncestor, otherAncestor} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(path, "keys"), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	rootFD, err := openAbsoluteDirectoryNoFollow(string(os.PathSeparator))
	if err != nil {
		t.Fatalf("reopen filesystem root: %v", err)
	}
	var rootStat unix.Stat_t
	if err := unix.Fstat(rootFD, &rootStat); err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(rootFD); err != nil {
		t.Fatal(err)
	}
	var visibleRoot unix.Stat_t
	if err := unix.Lstat(string(os.PathSeparator), &visibleRoot); err != nil ||
		!sameCustodyObject(custodyIdentityFromStat(rootStat), custodyIdentityFromStat(visibleRoot)) {
		t.Fatalf("filesystem root reopener changed identity: %v", err)
	}

	ancestorFD, err := openAbsoluteDirectoryNoFollow(exactAncestor)
	if err != nil {
		t.Fatalf("reopen exact space-bearing ancestor: %v", err)
	}
	var openedAncestor unix.Stat_t
	if err := unix.Fstat(ancestorFD, &openedAncestor); err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(ancestorFD); err != nil {
		t.Fatal(err)
	}
	var visibleAncestor unix.Stat_t
	if err := unix.Lstat(exactAncestor, &visibleAncestor); err != nil ||
		!sameCustodyObject(custodyIdentityFromStat(openedAncestor), custodyIdentityFromStat(visibleAncestor)) {
		t.Fatalf("exact ancestor reopener changed identity: %v", err)
	}
	var alternateAncestor unix.Stat_t
	if err := unix.Lstat(otherAncestor, &alternateAncestor); err != nil ||
		sameCustodyObject(custodyIdentityFromStat(openedAncestor), custodyIdentityFromStat(alternateAncestor)) {
		t.Fatalf("fixture ancestors are not distinct: %v", err)
	}

	qualified, err := openQualifiedDirectoryExact(filepath.Join(exactAncestor, "keys"))
	if err != nil {
		t.Fatalf("qualify nested exact parent: %v", err)
	}
	defer qualified.close()
	if !sameCustodyObject(qualified.parentIdentity, custodyIdentityFromStat(visibleAncestor)) {
		t.Fatal("qualified parent descriptor is not the exact ancestor")
	}
	if err := qualified.verifyVisible(); err != nil {
		t.Fatalf("unchanged exact ancestry failed verification: %v", err)
	}

	displaced := filepath.Join(workspace, "displaced-auth")
	if err := os.Rename(exactAncestor, displaced); err != nil {
		t.Fatal(err)
	}
	if fd, err := openAbsoluteDirectoryNoFollow(exactAncestor); err == nil {
		_ = unix.Close(fd)
		t.Fatal("missing exact ancestor fell back to trimmed alternative")
	}
	if err := qualified.verifyVisible(); err == nil {
		t.Fatal("missing exact ancestor passed ancestry verification")
	}
	if err := os.Mkdir(exactAncestor, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := qualified.verifyVisible(); err == nil {
		t.Fatal("replaced exact ancestor passed ancestry verification")
	}
	if err := os.Remove(exactAncestor); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(otherAncestor, exactAncestor); err != nil {
		t.Fatal(err)
	}
	if fd, err := openAbsoluteDirectoryNoFollow(exactAncestor); err == nil {
		_ = unix.Close(fd)
		t.Fatal("symlinked exact ancestor was followed")
	}
	if err := qualified.verifyVisible(); err == nil {
		t.Fatal("symlinked exact ancestor passed ancestry verification")
	}
	if info, err := os.Lstat(exactAncestor); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("verification changed symlink fixture: info=%v err=%v", info, err)
	}
	if info, err := os.Lstat(displaced); err != nil || !info.IsDir() {
		t.Fatalf("verification changed held directory fixture: info=%v err=%v", info, err)
	}
}

type scriptedDirectoryEntryReader struct {
	entries []os.DirEntry
	index   int
	reads   int
}

func (reader *scriptedDirectoryEntryReader) ReadDir(count int) ([]os.DirEntry, error) {
	reader.reads++
	if count != 1 {
		return nil, io.ErrUnexpectedEOF
	}
	if reader.index == len(reader.entries) {
		return nil, io.EOF
	}
	entry := reader.entries[reader.index]
	reader.index++
	return []os.DirEntry{entry}, nil
}

type scriptedDirectoryEntry string

func (entry scriptedDirectoryEntry) Name() string         { return string(entry) }
func (scriptedDirectoryEntry) IsDir() bool                { return false }
func (scriptedDirectoryEntry) Type() os.FileMode          { return 0 }
func (scriptedDirectoryEntry) Info() (os.FileInfo, error) { return nil, nil }

func scriptedDirectoryEntries(names ...string) []os.DirEntry {
	entries := make([]os.DirEntry, 0, len(names))
	for _, name := range names {
		entries = append(entries, scriptedDirectoryEntry(name))
	}
	return entries
}

func expectedFileChildren(names ...string) map[string]*custodyExpectedNode {
	children := make(map[string]*custodyExpectedNode, len(names))
	for _, name := range names {
		children[name] = newCustodyExpectedFile(custodyIdentity{Mode: unix.S_IFREG})
	}
	return children
}

func claimTestStagingCustody(t *testing.T, stagingRoot string, runID string) (*stagingCustody, executionPackageLayout) {
	t.Helper()
	owner := executionPlatformStateOwner{UID: os.Getuid(), GID: os.Getgid()}
	custody, err := claimStagingCustody(stagingRoot, runID, owner)
	if err != nil {
		t.Fatalf("claim test staging custody: %v", err)
	}
	t.Cleanup(func() {
		if err := custody.close(); err != nil {
			t.Errorf("close test staging custody: %v", err)
		}
	})
	layout := newExecutionPackageLayoutFromHost(hostMaterializationContext{stagingRootDir: stagingRoot, owner: owner}, newExecutionLocatorFromRunID(runID))
	return custody, layout
}

func assertStagedExactMode(t *testing.T, path string, wantPerm os.FileMode, wantDirectory bool) os.FileInfo {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat staged object %s: %v", path, err)
	}
	if wantDirectory && !info.IsDir() || !wantDirectory && !info.Mode().IsRegular() {
		t.Fatalf("%s type = %v, want directory=%t", path, info.Mode().Type(), wantDirectory)
	}
	if got := info.Mode().Perm(); got != wantPerm {
		t.Fatalf("%s permissions = %04o, want %04o", path, got, wantPerm)
	}
	if special := info.Mode() & (os.ModeSetuid | os.ModeSetgid | os.ModeSticky); special != 0 {
		t.Fatalf("%s retained special mode bits %v", path, special)
	}
	return info
}

func mutateStagedSpecialBitForTest(t *testing.T, path string, wantPerm os.FileMode, wantDirectory bool, specialBit os.FileMode) os.FileInfo {
	t.Helper()
	before := assertStagedExactMode(t, path, wantPerm, wantDirectory)
	beforeUID, beforeGID, err := ownershipIDsFromInfo(before)
	if err != nil {
		t.Fatalf("read staged owner before mutation: %v", err)
	}
	if err := os.Chmod(path, wantPerm|specialBit); err != nil {
		t.Fatalf("add special bit to staged object: %v", err)
	}
	after, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat staged object after mutation: %v", err)
	}
	if after.Mode()&specialBit == 0 {
		t.Skipf("filesystem did not retain special mode bit %v after successful chmod on %s", specialBit, path)
	}
	if !os.SameFile(before, after) || before.Mode().Type() != after.Mode().Type() || after.Mode().Perm() != wantPerm {
		t.Fatalf("special-bit mutation changed object identity, type, or ordinary permissions: before=%v after=%v", before.Mode(), after.Mode())
	}
	afterUID, afterGID, err := ownershipIDsFromInfo(after)
	if err != nil || afterUID != beforeUID || afterGID != beforeGID {
		t.Fatalf("special-bit mutation changed owner: before=%d:%d after=%d:%d err=%v", beforeUID, beforeGID, afterUID, afterGID, err)
	}
	return after
}

func assertStagedMutationRetained(t *testing.T, path string, mutated os.FileInfo) {
	t.Helper()
	retained, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("mutated staged object was removed: %v", err)
	}
	if !os.SameFile(mutated, retained) || retained.Mode() != mutated.Mode() {
		t.Fatalf("mutated staged object was replaced or repaired: before=%v after=%v", mutated.Mode(), retained.Mode())
	}
	mutatedUID, mutatedGID, beforeErr := ownershipIDsFromInfo(mutated)
	retainedUID, retainedGID, afterErr := ownershipIDsFromInfo(retained)
	if beforeErr != nil || afterErr != nil || mutatedUID != retainedUID || mutatedGID != retainedGID {
		t.Fatalf("mutated staged owner changed: %d:%d -> %d:%d, errors %v %v", mutatedUID, mutatedGID, retainedUID, retainedGID, beforeErr, afterErr)
	}
}

type registrationWindowModeMutation struct {
	called bool
	before unix.Stat_t
	after  unix.Stat_t
	err    error
}

func (mutation *registrationWindowModeMutation) apply(fd int, intendedMode uint32, specialBit uint32) {
	mutation.called = true
	if mutation.err = unix.Fstat(fd, &mutation.before); mutation.err != nil {
		return
	}
	if mutation.err = unix.Fchmod(fd, intendedMode|specialBit); mutation.err != nil {
		return
	}
	mutation.err = unix.Fstat(fd, &mutation.after)
}

func (mutation *registrationWindowModeMutation) assertRetained(t *testing.T, path string, fileType uint32, intendedMode uint32, specialBit uint32) {
	t.Helper()
	if !mutation.called || mutation.err != nil {
		t.Fatalf("registration-window mutation called=%t, error=%v", mutation.called, mutation.err)
	}
	if uint32(mutation.after.Mode)&specialBit == 0 {
		t.Skipf("filesystem did not retain special mode bit %#o after successful descriptor chmod on %s", specialBit, path)
	}
	before := custodyIdentityFromStat(mutation.before)
	after := custodyIdentityFromStat(mutation.after)
	if !sameCustodyRecordedMode(before.Mode, fileType|intendedMode) ||
		!sameCustodyRecordedMode(after.Mode, fileType|intendedMode|specialBit) ||
		!sameCustodyObject(before, after) ||
		before.UID != after.UID || before.GID != after.GID ||
		mutation.before.Size != mutation.after.Size {
		t.Fatalf("registration-window mutation changed non-mode custody state: before=%+v after=%+v", before, after)
	}
	var visible unix.Stat_t
	if err := unix.Lstat(path, &visible); err != nil {
		t.Fatalf("retained child is missing: %v", err)
	}
	retained := custodyIdentityFromStat(visible)
	if !sameCustodyObject(after, retained) ||
		!sameCustodyRecordedMode(after.Mode, retained.Mode) ||
		after.UID != retained.UID || after.GID != retained.GID ||
		mutation.after.Size != visible.Size {
		t.Fatalf("registration-window child was replaced or repaired: after=%+v retained=%+v", after, retained)
	}
}

func TestStagingCustodyWriteFileWithParentModePreservesPrivateDefault(t *testing.T) {
	custody, layout := claimTestStagingCustody(t, physicalTestTempDir(t), "run-0123456789abcdef")
	if err := custody.writeFile("payload/archive", []byte("private"), stableStageFileMode); err != nil {
		t.Fatalf("write default private file: %v", err)
	}
	if err := custody.ensureDirectory("mounts", governedMountDirMode); err != nil {
		t.Fatalf("create mount root: %v", err)
	}
	if err := custody.writeFileWithParentMode("mounts/nested/app.conf", []byte("visible"), governedMountFileMode, governedMountDirMode); err != nil {
		t.Fatalf("write mount file: %v", err)
	}
	for _, check := range []struct {
		path      string
		mode      os.FileMode
		directory bool
	}{
		{layout.stageRootDir, stableStageDirMode, true},
		{filepath.Join(layout.stageRootDir, "payload"), stableStageDirMode, true},
		{filepath.Join(layout.stageRootDir, "payload/archive"), stableStageFileMode, false},
		{filepath.Join(layout.stageRootDir, "mounts"), governedMountDirMode, true},
		{filepath.Join(layout.stageRootDir, "mounts/nested"), governedMountDirMode, true},
		{filepath.Join(layout.stageRootDir, "mounts/nested/app.conf"), governedMountFileMode, false},
	} {
		assertStagedExactMode(t, check.path, check.mode, check.directory)
	}
	if err := custody.revalidateBeforeHandoff(); err != nil {
		t.Fatalf("complete-tree revalidation: %v", err)
	}
}

func TestStagingCustodyRevalidationRejectsRecordedSpecialBitMutation(t *testing.T) {
	for _, test := range []struct {
		name       string
		relative   string
		mode       os.FileMode
		directory  bool
		specialBit os.FileMode
	}{
		{name: "regular file setgid", relative: "mounts/00/contents/config/app.conf", mode: governedMountFileMode, specialBit: os.ModeSetgid},
		{name: "directory sticky", relative: "mounts/00/contents/config", mode: governedMountDirMode, directory: true, specialBit: os.ModeSticky},
		{name: "claimed root sticky", relative: "", mode: stableStageDirMode, directory: true, specialBit: os.ModeSticky},
	} {
		t.Run(test.name, func(t *testing.T) {
			custody, layout := claimTestStagingCustody(t, physicalTestTempDir(t), "run-0123456789abcdef")
			if err := custody.ensureDirectory("mounts/00/contents/config", governedMountDirMode); err != nil {
				t.Fatalf("register governed directory: %v", err)
			}
			if err := custody.writeFileWithParentMode("mounts/00/contents/config/app.conf", []byte("retained"), governedMountFileMode, governedMountDirMode); err != nil {
				t.Fatalf("register governed file: %v", err)
			}
			target := filepath.Join(layout.stageRootDir, filepath.FromSlash(test.relative))
			mutated := mutateStagedSpecialBitForTest(t, target, test.mode, test.directory, test.specialBit)
			if err := custody.revalidateBeforeHandoff(); err == nil {
				t.Fatal("complete-tree validation accepted a recorded special-bit change")
			}
			assertStagedMutationRetained(t, target, mutated)
			if _, err := os.Lstat(layout.stageRootDir); err != nil {
				t.Fatalf("failed validation removed claimed root: %v", err)
			}
			assertFileContent(t, filepath.Join(layout.stageRootDir, "mounts/00/contents/config/app.conf"), "retained")
		})
	}
}

func TestStagingCustodyRegistrationWindowRejectsSpecialBitDirectory(t *testing.T) {
	custody, layout := claimTestStagingCustody(t, physicalTestTempDir(t), "run-0123456789abcdef")
	if err := custody.ensureDirectory("already-registered", stableStageDirMode); err != nil {
		t.Fatalf("register control directory: %v", err)
	}
	var mutation registrationWindowModeMutation
	hookCalls := 0
	if beforeStagingChildRegistrationStatForTest != nil {
		t.Fatal("registration-window test hook is already installed")
	}
	beforeStagingChildRegistrationStatForTest = func(relativePath string, fd int, directory bool) {
		hookCalls++
		if relativePath == "window-directory" && directory {
			mutation.apply(fd, uint32(governedMountDirMode), unix.S_ISVTX)
		}
	}
	t.Cleanup(func() { beforeStagingChildRegistrationStatForTest = nil })
	if err := custody.ensureDirectory("already-registered", stableStageDirMode); err != nil || hookCalls != 0 {
		t.Fatalf("registered directory traversal invoked creation hook: calls=%d err=%v", hookCalls, err)
	}
	registrationErr := custody.ensureDirectory("window-directory", governedMountDirMode)
	path := filepath.Join(layout.stageRootDir, "window-directory")
	mutation.assertRetained(t, path, unix.S_IFDIR, uint32(governedMountDirMode), unix.S_ISVTX)
	if registrationErr == nil || hookCalls != 1 {
		t.Fatalf("special-bit directory was registered: calls=%d err=%v", hookCalls, registrationErr)
	}
	if _, registered := custody.expectedRoot.children["window-directory"]; registered {
		t.Fatal("failed directory entered the expected tree")
	}
	if err := custody.revalidateBeforeHandoff(); err == nil || !strings.Contains(err.Error(), "unexpected child") {
		t.Fatalf("retained unregistered directory did not fail handoff as unexpected: %v", err)
	}
	mutation.assertRetained(t, path, unix.S_IFDIR, uint32(governedMountDirMode), unix.S_ISVTX)
	if _, err := os.Lstat(layout.stageRootDir); err != nil {
		t.Fatalf("failed directory registration removed claimed root: %v", err)
	}
}

func TestStagingCustodyRegistrationWindowRejectsSpecialBitFile(t *testing.T) {
	custody, layout := claimTestStagingCustody(t, physicalTestTempDir(t), "run-0123456789abcdef")
	content := []byte("complete retained registration-window bytes")
	var mutation registrationWindowModeMutation
	hookCalls := 0
	if beforeStagingChildRegistrationStatForTest != nil {
		t.Fatal("registration-window test hook is already installed")
	}
	beforeStagingChildRegistrationStatForTest = func(relativePath string, fd int, directory bool) {
		hookCalls++
		if relativePath == "window-file" && !directory {
			mutation.apply(fd, uint32(stableStageFileMode), unix.S_ISGID)
		}
	}
	t.Cleanup(func() { beforeStagingChildRegistrationStatForTest = nil })
	registrationErr := custody.writeFile("window-file", content, stableStageFileMode)
	path := filepath.Join(layout.stageRootDir, "window-file")
	mutation.assertRetained(t, path, unix.S_IFREG, uint32(stableStageFileMode), unix.S_ISGID)
	if registrationErr == nil || hookCalls != 1 {
		t.Fatalf("special-bit file was registered: calls=%d err=%v", hookCalls, registrationErr)
	}
	if mutation.before.Size != int64(len(content)) {
		t.Fatalf("file hook ran before content was complete: size=%d want=%d", mutation.before.Size, len(content))
	}
	if _, registered := custody.expectedRoot.children["window-file"]; registered {
		t.Fatal("failed file entered the expected tree")
	}
	assertFileContent(t, path, string(content))
	if err := custody.revalidateBeforeHandoff(); err == nil || !strings.Contains(err.Error(), "unexpected child") {
		t.Fatalf("retained unregistered file did not fail handoff as unexpected: %v", err)
	}
	mutation.assertRetained(t, path, unix.S_IFREG, uint32(stableStageFileMode), unix.S_ISGID)
	assertFileContent(t, path, string(content))
	if _, err := os.Lstat(layout.stageRootDir); err != nil {
		t.Fatalf("failed file registration removed claimed root: %v", err)
	}
}

func TestStagingCustodyRefusesEveryPreExistingObjectWithoutChangingIt(t *testing.T) {
	creators := map[string]func(string) error{
		"directory": func(path string) error { return os.Mkdir(path, 0o700) },
		"regular":   func(path string) error { return os.WriteFile(path, []byte("retain"), 0o600) },
		"symlink":   func(path string) error { return os.Symlink("missing-target", path) },
		"fifo":      func(path string) error { return unix.Mkfifo(path, 0o600) },
	}
	for name, create := range creators {
		t.Run(name, func(t *testing.T) {
			stagingRoot := physicalTestTempDir(t)
			runID := "run-0123456789abcdef"
			preExisting := filepath.Join(stagingRoot, runID)
			if err := create(preExisting); err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat(preExisting)
			if err != nil {
				t.Fatal(err)
			}
			custody, err := claimStagingCustody(stagingRoot, runID, executionPlatformStateOwner{UID: os.Getuid(), GID: os.Getgid()})
			if err == nil {
				_ = custody.close()
				t.Fatal("expected exclusive run-root refusal")
			}
			after, err := os.Lstat(preExisting)
			if err != nil {
				t.Fatalf("pre-existing object disappeared: %v", err)
			}
			if before.Mode() != after.Mode() {
				t.Fatalf("pre-existing object mode changed: %v -> %v", before.Mode(), after.Mode())
			}
			if name == "regular" {
				content, err := os.ReadFile(preExisting)
				if err != nil || string(content) != "retain" {
					t.Fatalf("pre-existing regular file changed: %q %v", content, err)
				}
			}
		})
	}
}

func TestStagingCustodyCreatesNoMarkerAndCloseRetainsRoot(t *testing.T) {
	stagingRoot := physicalTestTempDir(t)
	runID := "run-0123456789abcdef"
	custody, layout := claimTestStagingCustody(t, stagingRoot, runID)
	if err := custody.writeFile("payload/file", []byte("owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := custody.revalidateBeforeHandoff(); err != nil {
		t.Fatalf("revalidate expected tree: %v", err)
	}
	entries, err := os.ReadDir(layout.stageRootDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != "payload" {
			t.Fatalf("unexpected custody metadata %q", entry.Name())
		}
	}
	if err := custody.close(); err != nil {
		t.Fatal(err)
	}
	if err := custody.close(); err != nil {
		t.Fatalf("second close was not idempotent: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(layout.stageRootDir, "payload", "file"))
	if err != nil || string(content) != "owned" {
		t.Fatalf("close did not retain materialized root: %q %v", content, err)
	}
}

func TestStagingCustodyAcceptsDeepIterativeExpectedTree(t *testing.T) {
	stagingRoot := physicalTestTempDir(t)
	custody, _ := claimTestStagingCustody(t, stagingRoot, "run-0123456789abcdef")
	segments := make([]string, 256)
	for index := range segments {
		segments[index] = "d"
	}
	deepest := strings.Join(segments, "/")
	if err := custody.ensureDirectory(deepest, stableStageDirMode); err != nil {
		t.Fatalf("materialize deepest accepted directory: %v", err)
	}
	if err := custody.writeFile(deepest+"/leaf", []byte("deep"), stableStageFileMode); err != nil {
		t.Fatalf("materialize deepest accepted leaf: %v", err)
	}
	if err := custody.revalidateBeforeHandoff(); err != nil {
		t.Fatalf("iteratively validate deepest accepted tree: %v", err)
	}
	nodes, directories, ownedSegmentBytes := expectedTreeAccounting(t, custody.expectedRoot)
	if nodes != 258 || directories != 257 || ownedSegmentBytes != 256+len("leaf") {
		t.Fatalf("deep tree accounting = nodes %d directories %d bytes %d", nodes, directories, ownedSegmentBytes)
	}
}

func TestResolvedPlanCustodyRepairWideTreeBoundedDescriptors(t *testing.T) {
	const childMarker = "ES_CUSTODY_REPAIR_WIDE_CHILD=1"
	if os.Getenv("ES_CUSTODY_REPAIR_WIDE_CHILD") != "1" {
		command := exec.Command(os.Args[0], "-test.run=^TestResolvedPlanCustodyRepairWideTreeBoundedDescriptors$", "-test.v")
		command.Env = append(os.Environ(), childMarker)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("bounded child validation failed: %v\n%s", err, output)
		}
		return
	}

	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		t.Fatal(err)
	}
	if limit.Cur > 96 {
		limit.Cur = 96
		if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
			t.Fatal(err)
		}
	}
	if limit.Cur < 32 {
		t.Fatalf("child descriptor limit %d cannot run bounded fixture", limit.Cur)
	}
	root := physicalTestTempDir(t)
	custody, layout := claimTestStagingCustody(t, root, "run-0123456789abcdef")
	for index := 0; index < 1024; index++ {
		if err := custody.ensureDirectory(fmt.Sprintf("wide/dir-%04d", index), stableStageDirMode); err != nil {
			t.Fatalf("create wide directory %d: %v", index, err)
		}
	}
	for index := 0; index < 16; index++ {
		if err := custody.ensureDirectory(fmt.Sprintf("mixed/branch-%02d/one/two", index), stableStageDirMode); err != nil {
			t.Fatalf("create mixed directory %d: %v", index, err)
		}
	}
	if err := custody.revalidateBeforeHandoff(); err != nil {
		t.Fatalf("warm up wide validation: %v", err)
	}
	before := openCustodyTestDescriptorCount(t)
	for attempt := 0; attempt < 8; attempt++ {
		if err := custody.revalidateBeforeHandoff(); err != nil {
			t.Fatalf("wide validation attempt %d: %v", attempt+1, err)
		}
	}
	after := openCustodyTestDescriptorCount(t)
	if after > before+2 {
		t.Fatalf("repeated validation accumulated descriptors: before=%d after=%d", before, after)
	}
	child := filepath.Join(layout.stageRootDir, "wide", "dir-0000")
	displaced := child + "-displaced"
	if err := os.Rename(child, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(displaced, child); err != nil {
		t.Fatal(err)
	}
	if err := custody.revalidateBeforeHandoff(); err == nil {
		t.Fatal("replaced child was accepted")
	}
	afterFailure := openCustodyTestDescriptorCount(t)
	if afterFailure > before+2 {
		t.Fatalf("failed validation accumulated descriptors: before=%d after=%d", before, afterFailure)
	}
	if _, err := os.Lstat(layout.stageRootDir); err != nil {
		t.Fatalf("failed validation removed claimed root: %v", err)
	}
	if _, err := os.Lstat(displaced); err != nil {
		t.Fatalf("failed validation removed displaced child: %v", err)
	}
}

func openCustodyTestDescriptorCount(t *testing.T) int {
	t.Helper()
	directory, err := os.Open("/dev/fd")
	if err != nil {
		t.Fatal(err)
	}
	names, readErr := directory.Readdirnames(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("read descriptor inventory: read=%v close=%v", readErr, closeErr)
	}
	return len(names)
}

func TestResolvedPlanCustodyRepairCleanupRetainsDisplacedStagingLeaf(t *testing.T) {
	for _, replacementKind := range []string{"regular", "symlink"} {
		t.Run(replacementKind, func(t *testing.T) {
			root := physicalTestTempDir(t)
			custody, layout := claimTestStagingCustody(t, root, "run-0123456789abcdef")
			leaf := filepath.Join(layout.stageRootDir, "payload", "leaf")
			displaced := leaf + "-displaced"
			injected := errors.New("injected staging write fault")
			var replacementBefore os.FileInfo
			err := custody.writeFileWithHook("payload/leaf", []byte("owned"), stableStageFileMode, func(_ int, _ string) error {
				if err := os.Rename(leaf, displaced); err != nil {
					return err
				}
				if replacementKind == "regular" {
					if err := os.WriteFile(leaf, []byte("replacement"), 0o600); err != nil {
						return err
					}
				} else if err := os.Symlink(filepath.Base(displaced), leaf); err != nil {
					return err
				}
				var err error
				replacementBefore, err = os.Lstat(leaf)
				if err != nil {
					return err
				}
				return injected
			})
			if !errors.Is(err, injected) {
				t.Fatalf("primary write fault was hidden: %v", err)
			}
			after, err := os.Lstat(leaf)
			if err != nil || !os.SameFile(replacementBefore, after) || replacementBefore.Mode() != after.Mode() {
				t.Fatalf("replacement leaf changed: before=%v after=%v err=%v", replacementBefore, after, err)
			}
			if replacementKind == "regular" {
				assertFileContent(t, leaf, "replacement")
			} else if target, err := os.Readlink(leaf); err != nil || target != filepath.Base(displaced) {
				t.Fatalf("replacement symlink changed: target=%q err=%v", target, err)
			}
			if _, err := os.Lstat(displaced); err != nil {
				t.Fatalf("displaced owned leaf was removed: %v", err)
			}
			if _, err := os.Lstat(layout.stageRootDir); err != nil {
				t.Fatalf("claimed staging root was removed: %v", err)
			}
		})
	}
}

func TestStagingCustodyExpectedTreeSharesPrefixesAndOwnsEachEdgeOnce(t *testing.T) {
	stagingRoot := physicalTestTempDir(t)
	custody, _ := claimTestStagingCustody(t, stagingRoot, "run-0123456789abcdef")
	prefixSegments := make([]string, 64)
	for index := range prefixSegments {
		prefixSegments[index] = "shared"
	}
	prefix := strings.Join(prefixSegments, "/")
	for _, relativePath := range []string{prefix + "/left/file", prefix + "/right/file"} {
		if err := custody.writeFile(relativePath, []byte("owned"), stableStageFileMode); err != nil {
			t.Fatalf("materialize shared-prefix path: %v", err)
		}
	}
	if err := custody.revalidateBeforeHandoff(); err != nil {
		t.Fatalf("validate shared-prefix tree: %v", err)
	}
	nodes, directories, ownedSegmentBytes := expectedTreeAccounting(t, custody.expectedRoot)
	wantNodes := 1 + len(prefixSegments) + 2 + 2
	wantDirectories := 1 + len(prefixSegments) + 2
	wantSegmentBytes := len(prefixSegments)*len("shared") + len("left") + len("right") + 2*len("file")
	if nodes != wantNodes || directories != wantDirectories || ownedSegmentBytes != wantSegmentBytes {
		t.Fatalf("shared-prefix tree accounting = nodes %d directories %d bytes %d; want %d %d %d", nodes, directories, ownedSegmentBytes, wantNodes, wantDirectories, wantSegmentBytes)
	}
}

func TestStagingCustodyExpectedTreeRegistrationIsIdempotentAndRejectsConflicts(t *testing.T) {
	stagingRoot := physicalTestTempDir(t)
	custody, layout := claimTestStagingCustody(t, stagingRoot, "run-0123456789abcdef")
	if err := custody.ensureDirectory("shared/path", stableStageDirMode); err != nil {
		t.Fatal(err)
	}
	beforeNodes, beforeDirectories, beforeBytes := expectedTreeAccounting(t, custody.expectedRoot)
	if err := custody.ensureDirectory("shared/path", stableStageDirMode); err != nil {
		t.Fatalf("repeat identical directory registration: %v", err)
	}
	afterNodes, afterDirectories, afterBytes := expectedTreeAccounting(t, custody.expectedRoot)
	if beforeNodes != afterNodes || beforeDirectories != afterDirectories || beforeBytes != afterBytes {
		t.Fatalf("identical registration changed expected tree accounting: before %d/%d/%d after %d/%d/%d", beforeNodes, beforeDirectories, beforeBytes, afterNodes, afterDirectories, afterBytes)
	}
	if err := custody.ensureDirectory("shared/path", governedMountDirMode); err == nil || !strings.Contains(err.Error(), "staging directory registration conflicts with an owned child") {
		t.Fatalf("conflicting directory mode registration was accepted: %v", err)
	}
	if err := custody.writeFile("file-child", []byte("owned"), stableStageFileMode); err != nil {
		t.Fatal(err)
	}
	if err := custody.ensureDirectory("file-child", stableStageDirMode); err == nil {
		t.Fatal("conflicting file-to-directory registration was accepted")
	}
	visible := filepath.Join(layout.stageRootDir, "shared", "path")
	displaced := filepath.Join(layout.stageRootDir, "displaced")
	if err := os.Rename(visible, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(visible, stableStageDirMode); err != nil {
		t.Fatal(err)
	}
	if err := custody.ensureDirectory("shared/path", stableStageDirMode); err == nil {
		t.Fatal("conflicting directory identity registration was accepted")
	}
}

func expectedTreeAccounting(t *testing.T, root *custodyExpectedNode) (nodes int, directories int, ownedSegmentBytes int) {
	t.Helper()
	if root == nil || !root.isDirectory() {
		t.Fatal("expected tree root is not a directory")
	}
	stack := []*custodyExpectedNode{root}
	for len(stack) != 0 {
		index := len(stack) - 1
		node := stack[index]
		stack = stack[:index]
		nodes++
		if node.isDirectory() {
			directories++
			for segment, child := range node.children {
				if !validCustodyComponent(segment) || strings.Contains(segment, "/") {
					t.Fatalf("expected tree retained a non-segment key %q", segment)
				}
				if child == nil {
					t.Fatalf("expected tree retained nil child for %q", segment)
				}
				ownedSegmentBytes += len(segment)
				stack = append(stack, child)
			}
		} else if node.children != nil {
			t.Fatal("non-directory expected node owns a child map")
		}
	}
	return nodes, directories, ownedSegmentBytes
}

func TestExpectedDirectoryEnumerationIsLedgerBounded(t *testing.T) {
	tests := []struct {
		name              string
		expected          map[string]*custodyExpectedNode
		observed          []string
		wantError         bool
		wantValidated     int
		wantObservedCount int
	}{
		{name: "empty expected directory", expected: expectedFileChildren(), wantObservedCount: 0},
		{name: "exact expected population", expected: expectedFileChildren("alpha", "beta"), observed: []string{"beta", "alpha"}, wantValidated: 2, wantObservedCount: 2},
		{name: "missing expected child", expected: expectedFileChildren("alpha", "beta"), observed: []string{"alpha"}, wantError: true, wantValidated: 1, wantObservedCount: 1},
		{name: "duplicate observation", expected: expectedFileChildren("alpha"), observed: []string{"alpha", "alpha"}, wantError: true, wantValidated: 1, wantObservedCount: 2},
		{name: "first observation unexpected", expected: expectedFileChildren(), observed: []string{"private-attacker-name"}, wantError: true, wantObservedCount: 1},
		{name: "expected then one unexpected", expected: expectedFileChildren("alpha", "beta"), observed: []string{"alpha", "beta", "private-attacker-name"}, wantError: true, wantValidated: 2, wantObservedCount: 3},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := &scriptedDirectoryEntryReader{entries: scriptedDirectoryEntries(test.observed...)}
			validated := 0
			err := validateExpectedDirectoryEntries(reader, test.expected, func(name string, expected *custodyExpectedNode) error {
				validated++
				if test.expected[name] != expected {
					t.Fatalf("validation projection for %q changed expected-node identity", name)
				}
				return nil
			})
			if (err != nil) != test.wantError {
				t.Fatalf("error = %v, wantError = %v", err, test.wantError)
			}
			if err != nil && strings.Contains(err.Error(), "private-attacker-name") {
				t.Fatalf("error disclosed unexpected name: %v", err)
			}
			if validated != test.wantValidated {
				t.Fatalf("validated = %d, want %d", validated, test.wantValidated)
			}
			if reader.index != test.wantObservedCount {
				t.Fatalf("observed entries = %d, want %d", reader.index, test.wantObservedCount)
			}
		})
	}
}

func TestExpectedDirectoryEnumerationRejectsWithoutConsumingAll257Entries(t *testing.T) {
	names := make([]string, 257)
	for index := range names {
		names[index] = "untrusted-entry"
	}
	reader := &scriptedDirectoryEntryReader{entries: scriptedDirectoryEntries(names...)}
	err := validateExpectedDirectoryEntries(reader, expectedFileChildren(), func(string, *custodyExpectedNode) error {
		t.Fatal("unexpected entry reached identity validation")
		return nil
	})
	if err == nil {
		t.Fatal("unexpected population was accepted")
	}
	if reader.index != 1 {
		t.Fatalf("consumed %d of 257 entries, want exactly 1", reader.index)
	}
}

func TestStagingCustodyValidationUsesFreshCursorAndIsRepeatable(t *testing.T) {
	stagingRoot := physicalTestTempDir(t)
	custody, _ := claimTestStagingCustody(t, stagingRoot, "run-0123456789abcdef")
	if err := custody.writeFile("payload/file", []byte("owned"), 0o600); err != nil {
		t.Fatal(err)
	}

	duplicateFD, err := unix.Dup(custody.rootFD)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := os.NewFile(uintptr(duplicateFD), "consumed-custody-duplicate")
	if duplicate == nil {
		_ = unix.Close(duplicateFD)
		t.Fatal("wrap duplicated directory descriptor")
	}
	entries, err := duplicate.ReadDir(1)
	if err != nil {
		_ = duplicate.Close()
		t.Fatalf("consume duplicated directory cursor: %v", err)
	}
	if len(entries) != 1 {
		_ = duplicate.Close()
		t.Fatalf("consumed entries = %d, want 1", len(entries))
	}
	if err := duplicate.Close(); err != nil {
		t.Fatal(err)
	}

	for attempt := 0; attempt < 2; attempt++ {
		if err := custody.revalidateBeforeHandoff(); err != nil {
			t.Fatalf("validation attempt %d after consumed duplicate: %v", attempt+1, err)
		}
	}
}

func TestStagingCustodyRevalidatesEmptyExpectedDirectory(t *testing.T) {
	stagingRoot := physicalTestTempDir(t)
	custody, _ := claimTestStagingCustody(t, stagingRoot, "run-0123456789abcdef")
	if err := custody.revalidateBeforeHandoff(); err != nil {
		t.Fatalf("revalidate empty expected root: %v", err)
	}
}

func TestStagingCustodyMaterializationRefusesPreExistingLeaf(t *testing.T) {
	stagingRoot := physicalTestTempDir(t)
	custody, layout := claimTestStagingCustody(t, stagingRoot, "run-0123456789abcdef")
	if err := custody.ensureDirectory("payload", 0o750); err != nil {
		t.Fatal(err)
	}
	leaf := filepath.Join(layout.payloadStageDir, "file")
	if err := os.WriteFile(leaf, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := custody.writeFile("payload/file", []byte("owned"), 0o600); err == nil {
		t.Fatal("expected exclusive leaf refusal")
	}
	content, err := os.ReadFile(leaf)
	if err != nil || string(content) != "outside" {
		t.Fatalf("pre-existing leaf changed: %q %v", content, err)
	}
}

func TestStagingCustodyRevalidationDetectsReplacementAndRetainsBothTrees(t *testing.T) {
	stagingRoot := physicalTestTempDir(t)
	runID := "run-0123456789abcdef"
	custody, layout := claimTestStagingCustody(t, stagingRoot, runID)
	if err := custody.writeFile("payload/file", []byte("held"), 0o600); err != nil {
		t.Fatal(err)
	}
	displaced := filepath.Join(stagingRoot, "displaced")
	if err := os.Rename(layout.stageRootDir, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(layout.stageRootDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(layout.stageRootDir, "replacement"), []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := custody.revalidateBeforeHandoff(); err == nil {
		t.Fatal("revalidation accepted a replaced visible root")
	}
	_ = custody.close()
	assertFileContent(t, filepath.Join(displaced, "payload", "file"), "held")
	assertFileContent(t, filepath.Join(layout.stageRootDir, "replacement"), "outside")
}

func TestStagingCustodyRevalidationDetectsHardLinkAndSymlinkReplacement(t *testing.T) {
	for _, kind := range []string{"hardlink", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			stagingRoot := physicalTestTempDir(t)
			custody, layout := claimTestStagingCustody(t, stagingRoot, "run-0123456789abcdef")
			if err := custody.writeFile("payload/file", []byte("held"), 0o600); err != nil {
				t.Fatal(err)
			}
			leaf := filepath.Join(layout.payloadStageDir, "file")
			outside := filepath.Join(stagingRoot, "outside")
			if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(leaf); err != nil {
				t.Fatal(err)
			}
			var err error
			if kind == "hardlink" {
				err = os.Link(outside, leaf)
			} else {
				err = os.Symlink(outside, leaf)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := custody.revalidateBeforeHandoff(); err == nil {
				t.Fatalf("revalidation accepted %s replacement", kind)
			}
			_ = custody.close()
			assertFileContent(t, outside, "outside")
		})
	}
}

func TestStagingCustodyRevalidationRejectsEveryUnexpectedChildWithoutMutation(t *testing.T) {
	tests := []struct {
		name         string
		relativePath string
		create       func(string) error
	}{
		{name: "root regular", relativePath: "unexpected", create: func(path string) error { return os.WriteFile(path, []byte("retain"), 0o600) }},
		{name: "root directory", relativePath: "unexpected", create: func(path string) error { return os.Mkdir(path, 0o700) }},
		{name: "root symlink", relativePath: "unexpected", create: func(path string) error { return os.Symlink("missing-target", path) }},
		{name: "root fifo", relativePath: "unexpected", create: func(path string) error { return unix.Mkfifo(path, 0o600) }},
		{name: "payload child", relativePath: "payload/unexpected", create: func(path string) error { return os.WriteFile(path, []byte("retain"), 0o600) }},
		{name: "platform child", relativePath: "run/platform/unexpected", create: func(path string) error { return os.WriteFile(path, []byte("retain"), 0o600) }},
		{name: "result child", relativePath: "run/result/unexpected", create: func(path string) error { return os.Mkdir(path, 0o700) }},
		{name: "mount-root child", relativePath: "mounts/unexpected", create: func(path string) error { return os.Mkdir(path, 0o700) }},
		{name: "nested mount child", relativePath: "mounts/00/contents/unexpected", create: func(path string) error { return os.WriteFile(path, []byte("retain"), 0o600) }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stagingRoot := physicalTestTempDir(t)
			custody, layout := claimTestStagingCustody(t, stagingRoot, "run-0123456789abcdef")
			materializeStagingEnumerationFixture(t, custody)

			unexpected := filepath.Join(layout.stageRootDir, filepath.FromSlash(test.relativePath))
			if err := test.create(unexpected); err != nil {
				t.Fatalf("create unexpected child: %v", err)
			}
			before, err := os.Lstat(unexpected)
			if err != nil {
				t.Fatal(err)
			}

			if err := custody.revalidateBeforeHandoff(); err == nil {
				t.Fatalf("revalidation accepted unexpected child %q", test.relativePath)
			}
			after, err := os.Lstat(unexpected)
			if err != nil {
				t.Fatalf("unexpected child was removed: %v", err)
			}
			if before.Mode() != after.Mode() {
				t.Fatalf("unexpected child mode changed: %v -> %v", before.Mode(), after.Mode())
			}
			if before.Mode().IsRegular() {
				assertFileContent(t, unexpected, "retain")
			}
			assertStagingEnumerationFixtureRetained(t, layout)
		})
	}
}

func TestStagingCustodyRevalidationRejectsMissingExpectedChildWithoutCleanup(t *testing.T) {
	stagingRoot := physicalTestTempDir(t)
	custody, layout := claimTestStagingCustody(t, stagingRoot, "run-0123456789abcdef")
	materializeStagingEnumerationFixture(t, custody)

	missing := filepath.Join(layout.payloadStageDir, executionPayloadArchiveName)
	if err := os.Remove(missing); err != nil {
		t.Fatal(err)
	}
	if err := custody.revalidateBeforeHandoff(); err == nil {
		t.Fatal("revalidation accepted a missing registered child")
	}
	if _, err := os.Stat(layout.stageRootDir); err != nil {
		t.Fatalf("failed revalidation removed the retained run root: %v", err)
	}
	assertFileContent(t, layout.runtimeSupportPath, "runtime-support")
	assertFileContent(t, filepath.Join(layout.mountsStageRootDir, "00", "contents", "config"), "mount")
}

func materializeStagingEnumerationFixture(t *testing.T, custody *stagingCustody) {
	t.Helper()
	if err := custody.writeFile("payload/"+executionPayloadArchiveName, []byte("payload"), stableStageFileMode); err != nil {
		t.Fatal(err)
	}
	if err := custody.writeFile("run/platform/"+executionRuntimeSupportName, []byte("runtime-support"), stableStageFileMode); err != nil {
		t.Fatal(err)
	}
	if err := custody.ensureDirectory("run/result", stableStageDirMode); err != nil {
		t.Fatal(err)
	}
	if err := custody.writeFile("mounts/00/contents/config", []byte("mount"), stableStageFileMode); err != nil {
		t.Fatal(err)
	}
}

func assertStagingEnumerationFixtureRetained(t *testing.T, layout executionPackageLayout) {
	t.Helper()
	assertFileContent(t, layout.payloadArchivePath, "payload")
	assertFileContent(t, layout.runtimeSupportPath, "runtime-support")
	assertFileContent(t, filepath.Join(layout.mountsStageRootDir, "00", "contents", "config"), "mount")
}

func TestStagingCustodyCapabilityProbeRetainsUnlinkUnprovenObjects(t *testing.T) {
	root := physicalTestTempDir(t)
	sentinel := filepath.Join(root, "sentinel")
	if err := os.WriteFile(sentinel, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := probeStagingCustodyCapabilities(root, executionPlatformStateOwner{UID: os.Getuid(), GID: os.Getgid()}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Fatalf("probe changed sibling inventory: %v", entries)
	}
	probeEntries := 0
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".execution-substrate-capability-probe-") {
			probeEntries++
		}
	}
	if probeEntries != 3 {
		t.Fatalf("probe retained %d owned names, want 3", probeEntries)
	}
	assertFileContent(t, sentinel, "outside")
}

func assertFileContent(t *testing.T, path string, want string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil || string(content) != want {
		t.Fatalf("%s content = %q, err = %v; want %q", path, content, err, want)
	}
}
