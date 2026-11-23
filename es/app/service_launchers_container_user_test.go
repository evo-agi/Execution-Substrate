package app_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// TestServiceLaunchersContainerUser pins the container user that
// scripts/02_start_ars.sh, 03_start_egs.sh and 04_start_ags.sh pass to docker
// run. Each launcher runs its service as the caller's numeric effective UID and
// primary GID (control_plane_operator_user), so no service holds more host
// authority than the operator who started it. A fake id that prints a UID
// different from the GID pins which ID goes where, also on hosts whose UID
// equals their GID. A launcher refuses before any image, storage or container
// effect when id fails or prints a non-numeric ID, because docker run --user
// with an empty UID runs as root. ARS also checks its storage before starting:
// it creates a missing storage root as the caller and refuses a missing index
// file, and then does what ARS does with its storage in a container that runs
// exactly as ARS will: the same image, the UID:GID passed to docker run --user,
// the same mounts and ARS's container name. The cases that reach that container
// run it in real Docker as the identity they name; only the ARS container
// itself is faked. The kernel therefore decides access for that identity, with
// no supplementary groups, so access that only the caller's supplementary
// groups grant does not count.
func TestServiceLaunchersContainerUser(t *testing.T) {
	repo := executionPlatformRepoRoot(t)
	realID, err := exec.LookPath("id")
	if err != nil {
		t.Fatal(err)
	}
	callerUser := strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid())
	// The "UID different from the GID" case keeps the caller's UID, so ARS's
	// storage, which the caller owns, passes the check on every host, and
	// pairs it with a GID that differs from both of the caller's IDs.
	callerUID := strconv.Itoa(os.Getuid())
	callerGID := strconv.Itoa(os.Getgid())
	distinctGID := testDistinctGID()
	const idCalls = "id -u\nid -g\n"
	const launchEvents = idCalls + "docker image\ndocker rm\ndocker run\n"
	// ARS runs its storage check container before its own container. The
	// launcher removes the ARS container it replaces first, because the
	// check uses ARS's container name.
	const arsLaunchEvents = launchEvents + "docker run\n"
	const hostRefusalEvents = idCalls + "docker image\ndocker rm\n"
	const checkRefusalEvents = hostRefusalEvents + "docker run\n"
	const chownHint = "if an earlier bring-up wrote this storage as root, or it is shared through another group, hand it back with: sudo "

	type testCase struct {
		name string
		// idMode selects the fake id's answers: "real" runs the host's id,
		// "fake" prints fakeUID and fakeGID, "fail" exits 1.
		idMode           string
		fakeUID, fakeGID string
		wantUser         string
		wantEvents       string
		// refusal, when set, means the launcher must fail before any
		// container call, with this text in its output.
		refusal string
		// arrange changes the ARS storage fixture before the launcher runs.
		arrange func(t *testing.T, storage, index string)
		// needsNonRoot marks cases whose fixture relies on permission bits
		// that root bypasses.
		needsNonRoot bool
		// fix names the ownership hint a storage refusal must give: "storage"
		// for a recursive chown of the storage root, "index" or "index
		// directory" for a non-recursive chown of that one path, because the
		// index may share its directory with other state.
		fix string
		// hintUser is the UID:GID the hint must name; empty means the caller's.
		hintUser string
		// needsSudo marks cases whose fixture gives storage to another owner
		// with passwordless sudo; needsSupplementaryGroup and needsSetfacl
		// mark the other fixture requirements.
		needsSudo, needsSupplementaryGroup, needsSetfacl bool
		// refusalTail, when set, is more text the refusal must contain.
		refusalTail string
		// after, when set, runs after the launcher with the index as it was
		// right after arrange.
		after func(t *testing.T, storage, index string, before testIndexSnapshot)
		// storageUnderIndexDir, when set, puts the storage root below the
		// index directory, under this directory, so that ARS gets one mount
		// for both.
		storageUnderIndexDir string
		// symlinkedStorage makes the configured storage root a symbolic link
		// to the directory that holds the storage.
		symlinkedStorage bool
		// existingARSContainer creates a container with ARS's name in real
		// Docker before the launcher runs.
		existingARSContainer bool
		// checkCreatedRoot requires the storage root to exist afterwards,
		// owned by the caller.
		checkCreatedRoot bool
		// pythonHook, when set, runs the launcher's python3 with a
		// sitecustomize that changes how ACLs can be read: "no-acl-reads"
		// removes os.getxattr, as on hosts other than Linux, and
		// "acl-read-error" makes it fail with EACCES. The check no longer
		// reads ACLs, so neither may change its outcome.
		pythonHook string
		// storageParent, when set, puts the storage root one directory
		// deeper, under this directory of the proof directory, so that
		// arrange can change that parent's mode.
		storageParent string
	}
	identityCases := []testCase{
		{name: "caller's IDs", idMode: "real", wantUser: callerUser, wantEvents: launchEvents},
		{name: "UID different from the GID", idMode: "fake", fakeUID: callerUID, fakeGID: distinctGID, wantUser: callerUID + ":" + distinctGID, wantEvents: launchEvents},
		{name: "empty UID refused", idMode: "fake", fakeGID: "4343", wantEvents: idCalls, refusal: "as the operator: id -u and id -g must print numeric IDs, got '' and 4343"},
		{name: "user name with a digit refused", idMode: "fake", fakeUID: "staff1", fakeGID: "4343", wantEvents: idCalls, refusal: "as the operator: id -u and id -g must print numeric IDs, got staff1 and 4343"},
		{name: "group name with a digit refused", idMode: "fake", fakeUID: "4242", fakeGID: "staff1", wantEvents: idCalls, refusal: "as the operator: id -u and id -g must print numeric IDs, got 4242 and staff1"},
		{name: "UID with trailing characters refused", idMode: "fake", fakeUID: "4242x", fakeGID: "4343", wantEvents: idCalls, refusal: "as the operator: id -u and id -g must print numeric IDs, got 4242x and 4343"},
		{name: "GID with trailing characters refused", idMode: "fake", fakeUID: "4242", fakeGID: "4343x", wantEvents: idCalls, refusal: "as the operator: id -u and id -g must print numeric IDs, got 4242 and 4343x"},
		{name: "failing id refused", idMode: "fail", wantEvents: "id -u\n", refusal: "id: synthetic failure"},
	}
	// Every case below that reaches the container part of the check runs
	// it in real Docker, as the identity the case names, through the mounts
	// ARS would get. Only the ARS container itself is faked.
	arsStorageCases := []testCase{
		{
			name: "missing storage root created as the caller", idMode: "real", wantUser: callerUser, wantEvents: launchEvents, checkCreatedRoot: true,
			arrange: func(t *testing.T, storage, index string) {
				if err := os.Remove(storage); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			// The caller owns the storage and could use it, but the container
			// runs as 4242:4343, which may only read it through the other
			// permission class.
			name: "storage the caller can use but the container identity cannot refused", idMode: "fake", fakeUID: "4242", fakeGID: "4343", wantEvents: checkRefusalEvents,
			refusal: "ARS storage check failed: ARS cannot create files in this directory as 4242:4343", fix: "index directory", hintUser: "4242:4343",
		},
		{
			// The identity may write to the index directory through the
			// other class but not search it, so ARS could not reach the
			// index. The index itself is readable through the other class.
			name: "index directory the container identity cannot search refused", idMode: "fake", fakeUID: "4242", fakeGID: "4343", wantEvents: checkRefusalEvents,
			refusal: "ARS storage check failed: ARS cannot search this directory as 4242:4343", fix: "index directory", hintUser: "4242:4343",
			arrange: func(t *testing.T, storage, index string) {
				for path, mode := range map[string]os.FileMode{filepath.Dir(index): 0o772, index: 0o644} {
					if err := os.Chmod(path, mode); err != nil {
						t.Fatal(err)
					}
				}
			},
		},
		{
			// Storage the caller owns and shares with the identity's GID,
			// which is the caller's primary GID. The identity is another UID,
			// so only the group class lets it in. Python cannot read ACLs
			// here, as on every host but Linux; the check no longer reads
			// them, so that changes nothing.
			name: "storage shared through the identity's GID accepted where Python cannot read ACLs", idMode: "fake", fakeUID: "4242", fakeGID: callerGID,
			wantUser: "4242:" + callerGID, wantEvents: launchEvents, pythonHook: "no-acl-reads",
			arrange: shareTestStorageThroughGroup,
		},
		{
			name: "storage shared through the identity's GID accepted where reading an ACL fails", idMode: "fake", fakeUID: "4242", fakeGID: callerGID,
			wantUser: "4242:" + callerGID, wantEvents: launchEvents, pythonHook: "acl-read-error",
			arrange: shareTestStorageThroughGroup,
		},
		{
			name: "missing index file refused", idMode: "real", wantEvents: hostRefusalEvents,
			refusal: "ARS storage check failed: storage.index_file must be an existing regular file",
			arrange: func(t *testing.T, storage, index string) {
				if err := os.Remove(index); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			// Root in the container may use any directory and read any file,
			// as the kernel lets it, so mode bits that deny everyone else do
			// not stop it.
			name: "root identity accepted without permission bits", idMode: "fake", fakeUID: "0", fakeGID: "0", wantUser: "0:0", wantEvents: launchEvents,
			arrange: func(t *testing.T, storage, index string) {
				for path, mode := range map[string]os.FileMode{storage: 0o700, filepath.Dir(index): 0o700, index: 0o600} {
					if err := os.Chmod(path, mode); err != nil {
						t.Fatal(err)
					}
				}
			},
		},
		{
			name: "index that is a directory refused", idMode: "real", wantEvents: hostRefusalEvents,
			refusal: "ARS storage check failed: storage.index_file must be an existing regular file",
			arrange: func(t *testing.T, storage, index string) {
				if err := os.Remove(index); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(index, 0o755); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			// Audit finding A12-2 (b): ARS replaces the index with a regular
			// file at its first write, and the container sees only the index
			// directory, so a symbolic link is refused before any container.
			name: "index that is a symbolic link refused", idMode: "real", wantEvents: hostRefusalEvents,
			refusal: "ARS storage check failed: storage.index_file must be a regular file, not a symbolic link",
			arrange: func(t *testing.T, storage, index string) {
				target := filepath.Join(filepath.Dir(filepath.Dir(index)), "index-elsewhere.json")
				if err := os.Rename(index, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, index); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			// The caller cannot search the index directory, so the check
			// cannot reach the index; it refuses with the path instead of
			// failing with a traceback.
			name: "index the check cannot reach refused", idMode: "real", wantEvents: hostRefusalEvents,
			refusal: "ARS storage check failed: cannot reach storage.index_file as you: ", needsNonRoot: true,
			arrange: func(t *testing.T, storage, index string) {
				dir := filepath.Dir(index)
				if err := os.Chmod(dir, 0o600); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
			},
		},
		{
			name: "storage root the check cannot reach refused", idMode: "real", wantEvents: hostRefusalEvents,
			refusal: "ARS storage check failed: cannot reach storage.root_dir as you: ", needsNonRoot: true, storageParent: "locked",
			arrange: func(t *testing.T, storage, index string) {
				dir := filepath.Dir(storage)
				if err := os.Chmod(dir, 0o000); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
			},
		},
		{
			name: "missing storage root the caller cannot create refused", idMode: "real", wantEvents: hostRefusalEvents,
			refusal: "ARS storage check failed: cannot create storage.root_dir as you: ", needsNonRoot: true, storageParent: "read-only",
			arrange: func(t *testing.T, storage, index string) {
				if err := os.Remove(storage); err != nil {
					t.Fatal(err)
				}
				dir := filepath.Dir(storage)
				if err := os.Chmod(dir, 0o555); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
			},
		},
		{
			// The caller cannot search the directory, but root in the
			// container can, and the check walks the storage there, as ARS's
			// identity, not as the caller (O-12-1).
			name: "storage entry the caller cannot reach accepted for a root identity", idMode: "fake", fakeUID: "0", fakeGID: "0", wantUser: "0:0", wantEvents: launchEvents,
			needsNonRoot: true,
			arrange: func(t *testing.T, storage, index string) {
				dir := filepath.Join(storage, "sha256")
				if err := os.Mkdir(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "blob"), []byte("blob"), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(dir, 0o644); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
			},
		},
		{
			name: "relative storage root refused", idMode: "real", wantEvents: hostRefusalEvents,
			refusal: "ARS storage check failed: storage.root_dir must be an absolute path",
		},
		{
			name: "relative index file refused", idMode: "real", wantEvents: hostRefusalEvents,
			refusal: "ARS storage check failed: storage.index_file must be an absolute path",
		},
		{
			name: "storage root that is a file refused", idMode: "real", wantEvents: hostRefusalEvents,
			refusal: "ARS storage check failed: storage.root_dir is not a directory",
			arrange: func(t *testing.T, storage, index string) {
				if err := os.Remove(storage); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(storage, []byte("not a directory\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			// Searchable and writable, so ARS could use it, but the check
			// cannot list it to find the files below.
			name: "storage directory the check cannot list refused", idMode: "real", wantEvents: checkRefusalEvents,
			refusal: "ARS storage check failed: the check cannot see the files below this directory, because ARS cannot list it", needsNonRoot: true, fix: "storage",
			arrange: func(t *testing.T, storage, index string) {
				dir := filepath.Join(storage, "sha256")
				if err := os.Mkdir(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(dir, 0o300); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
			},
		},
		{
			name: "storage directory the caller cannot write refused", idMode: "real", wantEvents: checkRefusalEvents,
			refusal: "ARS storage check failed: ARS cannot create files in this directory", needsNonRoot: true, fix: "storage",
			arrange: func(t *testing.T, storage, index string) {
				dir := filepath.Join(storage, "sha256", "ab")
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(dir, 0o555); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
			},
		},
		{
			// Writable but not searchable: ARS could not reach anything in it.
			name: "storage directory the caller cannot search refused", idMode: "real", wantEvents: checkRefusalEvents,
			refusal: "ARS storage check failed: ARS cannot search this directory", needsNonRoot: true, fix: "storage",
			arrange: func(t *testing.T, storage, index string) {
				dir := filepath.Join(storage, "sha256")
				if err := os.Mkdir(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(dir, 0o600); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
			},
		},
		{
			name: "storage file the caller cannot read refused", idMode: "real", wantEvents: checkRefusalEvents,
			refusal: "ARS storage check failed: ARS cannot read this file", needsNonRoot: true, fix: "storage",
			arrange: func(t *testing.T, storage, index string) {
				dir := filepath.Join(storage, "sha256", "ab", "cd")
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				blob := filepath.Join(dir, "sha256:abcd")
				if err := os.WriteFile(blob, []byte("blob"), 0o000); err != nil {
					t.Fatal(err)
				}
			},
			after: requireTestIndexUntouched,
		},
		{
			// The walk covers entries whose names start with a dot too.
			name: "hidden storage file the caller cannot read refused", idMode: "real", wantEvents: checkRefusalEvents,
			refusal: "ARS storage check failed: ARS cannot read this file", needsNonRoot: true, fix: "storage",
			arrange: func(t *testing.T, storage, index string) {
				dir := filepath.Join(storage, ".partial")
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, ".blob"), []byte("blob"), 0o000); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "index directory the caller cannot write refused", idMode: "real", wantEvents: checkRefusalEvents,
			refusal: "ARS storage check failed: ARS cannot create files in this directory", needsNonRoot: true, fix: "index directory",
			arrange: func(t *testing.T, storage, index string) {
				dir := filepath.Dir(index)
				if err := os.Chmod(dir, 0o555); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
			},
		},
		{
			name: "index file the caller cannot read refused", idMode: "real", wantEvents: checkRefusalEvents,
			refusal: "ARS storage check failed: ARS cannot read the index file", needsNonRoot: true, fix: "index",
			arrange: func(t *testing.T, storage, index string) {
				if err := os.Chmod(index, 0o000); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			// The index is checked before the storage walk, which may be
			// long, so an unreadable index is reported first.
			name: "unreadable index refused before the storage walk", idMode: "real", wantEvents: checkRefusalEvents,
			refusal: "ARS storage check failed: ARS cannot read the index file", needsNonRoot: true, fix: "index",
			arrange: func(t *testing.T, storage, index string) {
				if err := os.WriteFile(filepath.Join(storage, "sha256:abcd"), []byte("blob"), 0o000); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(index, 0o000); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			// Audit finding A11-1: root owns the storage and shares it with a
			// supplementary group of the caller. The caller's own process
			// could use it, but the container has no supplementary groups.
			name: "storage usable only through a supplementary group refused", idMode: "real", wantEvents: checkRefusalEvents,
			refusal: "ARS storage check failed: ARS cannot search this directory", fix: "storage",
			needsNonRoot: true, needsSudo: true, needsSupplementaryGroup: true,
			arrange: func(t *testing.T, storage, index string) {
				giveTestStorageToRoot(t, storage, testSupplementaryGroup(t), 0o770, 0o660)
			},
		},
		{
			// Root owns the storage and shares it with the caller's primary
			// group, which the container keeps.
			name: "storage shared through the primary group accepted", idMode: "real", wantUser: callerUser, wantEvents: launchEvents,
			needsNonRoot: true, needsSudo: true,
			arrange: func(t *testing.T, storage, index string) {
				giveTestStorageToRoot(t, storage, os.Getegid(), 0o770, 0o640)
			},
		},
		{
			// Root owns the storage with a group the caller is not in, so the
			// mode bits deny the caller, and an access ACL entry for the
			// caller's UID grants it. The kernel decides by the ACL.
			name: "storage with an access ACL that grants the identity accepted", idMode: "real", wantUser: callerUser, wantEvents: launchEvents,
			needsNonRoot: true, needsSudo: true, needsSetfacl: true,
			arrange: func(t *testing.T, storage, index string) {
				giveTestStorageToRoot(t, storage, 0, 0o770, 0o640)
				runTestSudo(t, "setfacl", "-R", "-m", "u:"+strconv.Itoa(os.Getuid())+":rwX", storage)
			},
		},
		{
			// Root owns the storage and shares it with the caller's primary
			// group, which would let the caller in, but a named-user ACL entry
			// for the caller's UID takes precedence and denies it.
			name: "storage with an access ACL that denies the identity refused", idMode: "real", wantEvents: checkRefusalEvents,
			refusal: "ARS storage check failed: ARS cannot search this directory", fix: "storage",
			needsNonRoot: true, needsSudo: true, needsSetfacl: true,
			arrange: func(t *testing.T, storage, index string) {
				giveTestStorageToRoot(t, storage, os.Getegid(), 0o770, 0o640)
				runTestSudo(t, "setfacl", "-m", "u:"+strconv.Itoa(os.Getuid())+":---", storage)
			},
		},
		{
			// The ACL's owner entry is the owner mode bits, so an entry the
			// identity owns is decided by them even when it has an ACL.
			name: "storage the identity owns with an access ACL accepted", idMode: "real", wantUser: callerUser, wantEvents: launchEvents,
			needsSetfacl: true,
			arrange: func(t *testing.T, storage, index string) {
				if output, err := exec.Command("setfacl", "-m", "g:"+strconv.Itoa(os.Getegid())+":rx", storage).CombinedOutput(); err != nil {
					t.Fatalf("setfacl: %v: %s", err, output)
				}
			},
		},
		{
			// Audit finding A12-1: the storage root lies below the index
			// directory, so ARS gets one mount, the index directory, and
			// reaches the root through a directory between them. The caller
			// owns that directory with 0700, so 4242:4343 cannot search it.
			name: "storage root behind a directory the identity cannot search refused", idMode: "fake", fakeUID: "4242", fakeGID: "4343", wantEvents: checkRefusalEvents,
			refusal: "ARS storage check failed: ARS cannot search this directory on its way to storage.root_dir as 4242:4343: ", storageUnderIndexDir: "data",
			refusalTail: ". ARS runs as 4242:4343, your UID and primary group, with no supplementary groups; give that identity search permission on this directory, or choose a path it can reach",
			arrange: func(t *testing.T, storage, index string) {
				for path, mode := range map[string]os.FileMode{filepath.Dir(index): 0o777, index: 0o644, filepath.Dir(storage): 0o700, storage: 0o777} {
					if err := os.Chmod(path, mode); err != nil {
						t.Fatal(err)
					}
				}
			},
		},
		{
			// The same layout with a directory between them that the identity
			// may search: one mount, and the check passes.
			name: "storage root below the index directory accepted", idMode: "fake", fakeUID: "4242", fakeGID: "4343", wantUser: "4242:4343", wantEvents: launchEvents,
			storageUnderIndexDir: "data",
			arrange: func(t *testing.T, storage, index string) {
				for path, mode := range map[string]os.FileMode{filepath.Dir(index): 0o777, index: 0o644, filepath.Dir(storage): 0o755, storage: 0o777} {
					if err := os.Chmod(path, mode); err != nil {
						t.Fatal(err)
					}
				}
			},
		},
		{
			// Audit finding A12-2 (a): the index directory has the sticky
			// bit, and the identity owns neither it nor the index. It may
			// create files there and read the index, but the kernel refuses
			// to let it rename a file over the index, which is how ARS writes
			// it. The refusal leaves the index as it was.
			name: "index in a sticky directory the identity owns neither of refused", idMode: "fake", fakeUID: "4242", fakeGID: "4343", wantEvents: checkRefusalEvents,
			refusal: "ARS storage check failed: ARS cannot rename a new file over the index file as 4242:4343: ", fix: "index", hintUser: "4242:4343",
			refusalTail: ". ARS writes the index that way; in a directory with the sticky bit, only the owner of the file or of the directory may. ARS runs as 4242:4343,",
			arrange: func(t *testing.T, storage, index string) {
				for path, mode := range map[string]os.FileMode{filepath.Dir(index): 0o777 | os.ModeSticky, index: 0o644, storage: 0o777} {
					if err := os.Chmod(path, mode); err != nil {
						t.Fatal(err)
					}
				}
			},
			after: requireTestIndexUntouched,
		},
		{
			// The identity owns the index, so the sticky rule lets it replace
			// it (C24 of the audit).
			name: "index the identity owns in a sticky directory accepted", idMode: "real", wantUser: callerUser, wantEvents: launchEvents,
			arrange: func(t *testing.T, storage, index string) {
				if err := os.Chmod(filepath.Dir(index), 0o777|os.ModeSticky); err != nil {
					t.Fatal(err)
				}
			},
			after: requireTestIndexRewrittenLikeARS,
		},
		{
			// O-12-2 (Q07): GID 0 is not root. 4242:0 gets the other class on
			// storage the caller owns with 0700, as on a host where the caller
			// is root, and is refused.
			name: "identity with GID 0 refused on storage only its owner may use", idMode: "fake", fakeUID: "4242", fakeGID: "0", wantEvents: checkRefusalEvents,
			refusal: "ARS storage check failed: ARS cannot search this directory as 4242:0", fix: "storage", hintUser: "4242:0",
			arrange: func(t *testing.T, storage, index string) {
				for path, mode := range map[string]os.FileMode{storage: 0o700, filepath.Dir(index): 0o777, index: 0o644} {
					if err := os.Chmod(path, mode); err != nil {
						t.Fatal(err)
					}
				}
			},
		},
		{
			// O-12-2 (Q27): Docker resolves a bind source that is a symbolic
			// link, so a symlinked storage root works for ARS and passes.
			name: "symlinked storage root accepted", idMode: "real", wantUser: callerUser, wantEvents: launchEvents, symlinkedStorage: true,
		},
		{
			// A passing check writes the index the way ARS does: same content,
			// a new 0600 file, and nothing left behind.
			name: "passing check rewrites the index like ARS and leaves nothing behind", idMode: "real", wantUser: callerUser, wantEvents: launchEvents,
			arrange: func(t *testing.T, storage, index string) {
				dir := filepath.Join(storage, "sha256", "ab")
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "sha256:ab"), []byte("blob"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			after: requireTestIndexRewrittenLikeARS,
		},
		{
			// The check runs in a container with ARS's name, so Docker
			// refuses it while an ARS container still exists, and the check
			// never writes an index that a running ARS may be writing.
			name: "check refused while an ARS container exists", idMode: "real", wantEvents: checkRefusalEvents,
			refusal: "is already in use", existingARSContainer: true,
			refusalTail: "; ARS's container still exists, so stop it first, for example with scripts/01_bringup.sh down",
			after:       requireTestIndexUntouched,
		},
	}

	for _, service := range []struct {
		name, script, label string
		cases               []testCase
	}{
		{name: "ars", script: "02_start_ars.sh", label: "ARS", cases: append(append([]testCase{}, identityCases...), arsStorageCases...)},
		{name: "egs", script: "03_start_egs.sh", label: "EGS", cases: identityCases},
		{name: "ags", script: "04_start_ags.sh", label: "AGS", cases: identityCases},
	} {
		for _, test := range service.cases {
			t.Run(service.label+" "+test.name, func(t *testing.T) {
				if test.needsNonRoot && os.Geteuid() == 0 {
					t.Skip("root bypasses the permission bits this case relies on")
				}
				// A refusal from the check container has the calls of a
				// launch without ARS's own docker run.
				wantEvents := test.wantEvents
				if service.name == "ars" && test.refusal == "" && wantEvents == launchEvents {
					wantEvents = arsLaunchEvents
				}
				var docker testStorageCheckDocker
				if service.name == "ars" && strings.HasSuffix(wantEvents, "docker run\n") {
					docker = requireTestStorageCheckDocker(t)
				}
				if test.needsSudo {
					if output, err := exec.Command("sudo", "-n", "true").CombinedOutput(); err != nil {
						t.Skipf("needs passwordless sudo to give the storage to another owner: %v: %s", err, strings.TrimSpace(string(output)))
					}
				}
				if test.needsSupplementaryGroup && testSupplementaryGroup(t) < 0 {
					t.Skip("this process has no supplementary group besides its effective GID")
				}
				if test.needsSetfacl {
					if _, err := exec.LookPath("setfacl"); err != nil {
						t.Skip("needs setfacl to give the storage an access ACL")
					}
				}
				workspace, err := filepath.EvalSymlinks(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				proof := filepath.Join(workspace, "proof")
				if err := os.Mkdir(proof, 0o755); err != nil {
					t.Fatal(err)
				}
				config := filepath.Join(proof, service.name+".json")
				storage := filepath.Join(proof, test.storageParent, "ars-storage")
				indexDir := filepath.Join(proof, "ars-index")
				index := filepath.Join(indexDir, "index.json")
				if test.storageUnderIndexDir != "" {
					storage = filepath.Join(indexDir, test.storageUnderIndexDir, "ars-storage")
				}
				settings := map[string]any{}
				var indexBefore testIndexSnapshot
				if service.name == "ars" {
					for _, dir := range []string{storage, indexDir} {
						if test.symlinkedStorage && dir == storage {
							target := filepath.Join(proof, "ars-storage-target")
							if err := os.Mkdir(target, 0o755); err != nil {
								t.Fatal(err)
							}
							if err := os.Symlink(target, storage); err != nil {
								t.Fatal(err)
							}
							continue
						}
						if err := os.MkdirAll(dir, 0o755); err != nil {
							t.Fatal(err)
						}
					}
					if err := os.WriteFile(index, []byte("{}\n"), 0o600); err != nil {
						t.Fatal(err)
					}
					root, indexSetting := storage, index
					if strings.HasPrefix(test.name, "relative storage root") {
						root = "ars-storage"
					}
					if strings.HasPrefix(test.name, "relative index file") {
						indexSetting = filepath.Join("ars-index", "index.json")
					}
					settings["storage"] = map[string]any{"root_dir": root, "index_file": indexSetting}
					if test.arrange != nil {
						test.arrange(t, storage, index)
					}
					indexBefore = snapshotTestIndex(t, index)
				}
				data, err := json.Marshal(settings)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(config, data, 0o600); err != nil {
					t.Fatal(err)
				}
				dockerfile := filepath.Join(proof, "Dockerfile")
				if err := os.WriteFile(dockerfile, []byte("synthetic fixture\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				bin := filepath.Join(workspace, "bin")
				if err := os.Mkdir(bin, 0o700); err != nil {
					t.Fatal(err)
				}
				// The fake daemon answers only the calls the launcher is
				// expected to make; anything else fails the run with exit 97.
				// It hands ARS's storage check container to the real daemon
				// and records the arguments of the service container instead
				// of running it. The fake id answers only -u and -g; anything
				// else fails with exit 96.
				if test.pythonHook != "" {
					writeTestPythonHook(t, bin, test.pythonHook)
				}
				for name, body := range map[string]string{
					"id": `#!/bin/sh
printf 'id %s\n' "$*" >> "$LAUNCHER_EVENTS"
[ "$#" -eq 1 ] || exit 96
case "$LAUNCHER_ID_MODE $1" in
  "real -u"|"real -g") exec "$LAUNCHER_REAL_ID" "$1" ;;
  "fake -u") printf '%s\n' "$LAUNCHER_FAKE_UID"; exit 0 ;;
  "fake -g") printf '%s\n' "$LAUNCHER_FAKE_GID"; exit 0 ;;
  "fail -u"|"fail -g") echo 'id: synthetic failure' >&2; exit 1 ;;
esac
exit 96
`,
					"docker": `#!/bin/sh
printf 'docker %s\n' "$1" >> "$LAUNCHER_EVENTS"
case "$1 $2" in
  "image inspect"|"rm -f") exit 0 ;;
  "run --rm")
    for arg in "$@"; do
      if [ "$arg" = ars-storage-probe ]; then
        printf '%s\0' "$@" > "$LAUNCHER_CHECK_ARGS"
        exec "$LAUNCHER_REAL_DOCKER" "$@"
      fi
    done
    for arg in "$@"; do printf '%s\n' "$arg"; done > "$LAUNCHER_RUN_ARGS"
    exit 0 ;;
esac
exit 97
`,
				} {
					if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o700); err != nil {
						t.Fatal(err)
					}
				}
				events := filepath.Join(workspace, "events")
				runArgs := filepath.Join(workspace, "run-args")
				checkArgs := filepath.Join(workspace, "check-args")
				bringupDir := filepath.Join(workspace, "bringup")
				if test.existingARSContainer {
					name := testControlPlaneContainerName(bringupDir, "ars")
					docker.run(t, "create", "--name", name, testStorageCheckImage, "true")
					t.Cleanup(func() { _ = exec.Command(docker.path, "rm", "-f", name).Run() })
				}
				configVar := strings.ToUpper(service.name) + "_CONFIG"
				command := exec.Command("/bin/bash", filepath.Join(repo, "scripts", service.script))
				command.Dir = workspace
				command.Env = auditControlledScriptEnv(t, append([]string{
					"PATH=" + bin + string(os.PathListSeparator) + auditSafeScriptPath(t),
					"LAUNCHER_EVENTS=" + events, "LAUNCHER_RUN_ARGS=" + runArgs, "LAUNCHER_CHECK_ARGS=" + checkArgs,
					"LAUNCHER_REAL_ID=" + realID, "LAUNCHER_ID_MODE=" + test.idMode,
					"LAUNCHER_FAKE_UID=" + test.fakeUID, "LAUNCHER_FAKE_GID=" + test.fakeGID,
					"LAUNCHER_REAL_DOCKER=" + docker.path,
					configVar + "=" + config,
					"BRINGUP_DIR=" + bringupDir,
					"CONTROL_PLANE_IMAGE=" + testStorageCheckImage,
					"CONTROL_PLANE_IMAGE_BUILD=never", "CONTROL_PLANE_TARGETARCH=amd64",
					"CONTROL_PLANE_DOCKERFILE=" + dockerfile,
				}, docker.env...)...)
				output, err := command.CombinedOutput()
				eventBytes, eventErr := os.ReadFile(events)
				if eventErr != nil || string(eventBytes) != wantEvents {
					t.Fatalf("launcher calls = %q (err=%v), want %q; launcher err=%v output=%q", eventBytes, eventErr, wantEvents, err, output)
				}
				if test.after != nil {
					defer test.after(t, storage, index, indexBefore)
				}
				// The check container runs exactly as ARS will: ARS's
				// container name, the identity ARS gets, ARS's mounts and
				// image, with no network.
				if service.name == "ars" && strings.HasSuffix(test.wantEvents, "docker run\n") {
					identity := callerUser
					if test.idMode == "fake" {
						identity = test.fakeUID + ":" + test.fakeGID
					}
					want := []string{"run", "--rm", "--name", testControlPlaneContainerName(bringupDir, "ars"), "--network", "none", "--user", identity}
					want = append(want, testARSMountArgs(indexDir, storage, config, test.storageUnderIndexDir != "")...)
					want = append(want, "--entrypoint", "/bin/sh", testStorageCheckImage, "-c")
					checkBytes, err := os.ReadFile(checkArgs)
					if err != nil {
						t.Fatalf("the launcher ran no storage check container: %v", err)
					}
					got := strings.Split(strings.TrimSuffix(string(checkBytes), "\x00"), "\x00")
					tail := []string{"ars-storage-probe", storage, index}
					if len(got) != len(want)+1+len(tail) || strings.Join(got[:len(want)], "\n") != strings.Join(want, "\n") ||
						strings.Join(got[len(want)+1:], "\n") != strings.Join(tail, "\n") {
						t.Fatalf("storage check container args = %q, want %q, the probe, then %q", got, want, tail)
					}
				}
				if test.refusal != "" {
					if err == nil {
						t.Fatalf("launcher succeeded, want refusal %q: output=%q", test.refusal, output)
					}
					if !strings.Contains(string(output), test.refusal) {
						t.Fatalf("launcher output = %q, want refusal %q", output, test.refusal)
					}
					if test.refusalTail != "" && !strings.Contains(string(output), test.refusalTail) {
						t.Fatalf("launcher output = %q, want %q in the refusal", output, test.refusalTail)
					}
					hintUser := test.hintUser
					if hintUser == "" {
						hintUser = callerUser
					}
					wantFix := ""
					switch test.fix {
					case "storage":
						wantFix = chownHint + "chown -R " + hintUser + " " + storage + "\n"
					case "index":
						wantFix = chownHint + "chown " + hintUser + " " + index + "\n"
					case "index directory":
						wantFix = chownHint + "chown " + hintUser + " " + indexDir + "\n"
					}
					if wantFix != "" && !strings.Contains(string(output), wantFix) {
						t.Fatalf("launcher output = %q, want the ownership hint %q", output, wantFix)
					}
					if strings.Contains(string(output), "docker run") {
						t.Fatalf("refusing launcher printed a docker run command: %q", output)
					}
					if _, err := os.Stat(runArgs); !os.IsNotExist(err) {
						t.Fatalf("refusing launcher ran a container: %v", err)
					}
					if strings.HasPrefix(test.name, "relative storage root") {
						if _, err := os.Stat(filepath.Join(workspace, "ars-storage")); !os.IsNotExist(err) {
							t.Fatalf("refusing launcher created a relative storage root: %v", err)
						}
					}
					return
				}
				if err != nil {
					t.Fatalf("launcher failed: %v output=%q", err, output)
				}
				argBytes, err := os.ReadFile(runArgs)
				if err != nil {
					t.Fatal(err)
				}
				got := strings.Split(strings.TrimSuffix(string(argBytes), "\n"), "\n")
				want := []string{"run", "--rm", "--name", "", "--network", "host", "--user", test.wantUser}
				if service.name == "ars" {
					want = append(want, testARSMountArgs(indexDir, storage, config, test.storageUnderIndexDir != "")...)
				} else {
					want = append(want, "-v", config+":"+config+":ro")
				}
				want = append(want,
					testStorageCheckImage,
					"/usr/local/bin/"+service.name, "-config", config,
				)
				if len(got) != len(want) {
					t.Fatalf("docker run args = %q, want %q", got, want)
				}
				for index := range want {
					if index == 3 {
						if !strings.HasPrefix(got[index], "execution-substrate-") || !strings.HasSuffix(got[index], "-"+service.name) {
							t.Fatalf("docker run container name = %q, want an execution-substrate %s name", got[index], service.label)
						}
						continue
					}
					if got[index] != want[index] {
						t.Fatalf("docker run args = %q, want %q", got, want)
					}
				}
				if !strings.Contains(string(output), " --user "+test.wantUser+" ") {
					t.Fatalf("launcher did not print --user %s: %q", test.wantUser, output)
				}
				if test.checkCreatedRoot {
					info, err := os.Stat(storage)
					if err != nil || !info.IsDir() {
						t.Fatalf("ARS launcher left no storage root %s: %v", storage, err)
					}
					owner, ok := info.Sys().(*syscall.Stat_t)
					if !ok || int(owner.Uid) != os.Getuid() || int(owner.Gid) != os.Getgid() {
						t.Fatalf("ARS storage root %s is not owned by the caller %s: %+v", storage, callerUser, info.Sys())
					}
				}
			})
		}
	}
}

// TestBringupUpChecksARSStorageBeforeStartingServices pins that
// scripts/01_bringup.sh up runs ARS's storage check before it starts any
// service, so storage that ARS cannot use as the operator stops bring-up at
// once instead of after ARS's readiness timeout, and that the check runs as
// the identity ARS will run as: with a fake id that prints 4242 and 4343, the
// check container runs as 4242:4343 in real Docker, and storage the caller
// owns with mode 0755 is refused for it.
func TestBringupUpChecksARSStorageBeforeStartingServices(t *testing.T) {
	for _, scenario := range []struct {
		name      string
		fakeID    string
		withIndex bool
		refusal   string
		// beforeAnyEffect marks a refusal that must come before Docker,
		// the image, the bring-up logs or the storage are touched.
		beforeAnyEffect bool
		// runsCheck marks a refusal that comes from the check container,
		// which runs in real Docker.
		runsCheck bool
	}{
		{name: "missing index", refusal: "ARS storage check failed: storage.index_file must be an existing regular file"},
		{name: "storage the container identity cannot use", fakeID: "4242:4343", withIndex: true, runsCheck: true,
			refusal: "ARS storage check failed: ARS cannot create files in this directory as 4242:4343: "},
		{name: "non-numeric identity refused before any effect", fakeID: "operator:4343", withIndex: true,
			refusal: `cannot run ARS as the operator: id -u and id -g must print numeric IDs, got operator and 4343`, beforeAnyEffect: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			testBringupUpARSStorageRefusal(t, scenario.fakeID, scenario.withIndex, scenario.refusal, scenario.beforeAnyEffect, scenario.runsCheck)
		})
	}
}

// testBringupUpARSStorageRefusal runs 01_bringup.sh up with fake Docker and
// requires it to stop with refusal before any service container. fakeID,
// when set as "U:G", replaces id so that id -u prints U and id -g prints G.
// With runsCheck, the fake Docker hands the storage check container to the
// real daemon.
func testBringupUpARSStorageRefusal(t *testing.T, fakeID string, withIndex bool, refusal string, beforeAnyEffect, runsCheck bool) {
	repo := executionPlatformRepoRoot(t)
	var docker testStorageCheckDocker
	if runsCheck {
		docker = requireTestStorageCheckDocker(t)
	}
	realPython, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	proof := filepath.Join(workspace, "proof")
	if err := os.Mkdir(proof, 0o755); err != nil {
		t.Fatal(err)
	}
	writeJSON := func(name string, value any) string {
		path := filepath.Join(proof, name)
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	esConfig := writeJSON("es.json", map[string]any{"execution": map[string]any{
		"staging_root_dir": filepath.Join(proof, "es-staging"),
		"results_root_dir": filepath.Join(proof, "es-results"),
	}})
	// Without withIndex the index file is missing, which ARS refuses at
	// startup.
	arsConfig := writeJSON("ars.json", map[string]any{"storage": map[string]any{
		"root_dir":   filepath.Join(proof, "ars-storage"),
		"index_file": filepath.Join(proof, "ars-index", "index.json"),
	}})
	if withIndex {
		if err := os.Mkdir(filepath.Join(proof, "ars-index"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(proof, "ars-index", "index.json"), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	otherConfig := writeJSON("other.json", map[string]any{})
	for _, name := range []string{"Dockerfile", "ca.pem", "operator.pem", "operator-key.pem"} {
		if err := os.WriteFile(filepath.Join(proof, name), []byte("synthetic fixture\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bin := filepath.Join(workspace, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	// The storage check container is recorded as "docker storage-check"
	// and run by the real daemon; every other call is recorded with its
	// arguments and faked.
	fakes := map[string]string{
		"docker": `#!/bin/sh
for arg in "$@"; do
  if [ "$arg" = ars-storage-probe ]; then
    printf 'docker storage-check\n' >> "$ROOT_EVENTS"
    exec "$ROOT_REAL_DOCKER" "$@"
  fi
done
printf 'docker %s\n' "$*" >> "$ROOT_EVENTS"
case "$1 $2" in
  "info "|"image inspect") exit 0 ;;
  "run --rm") printf 'slice0-host-loopback-ok\n'; exit 0 ;;
esac
exit 97
`,
		"python3": `#!/bin/sh
if [ "$1 $2" = "-m http.server" ]; then
  printf 'fake-http-server\n' >> "$ROOT_EVENTS"
  exit 0
fi
exec "$ROOT_REAL_PYTHON" "$@"
`,
		"sleep": "#!/bin/sh\nexit 0\n",
		"curl":  "#!/bin/sh\nprintf 'unexpected curl\\n' >> \"$ROOT_EVENTS\"\nexit 97\n",
	}
	fakeUID, fakeGID, _ := strings.Cut(fakeID, ":")
	if fakeID != "" {
		fakes["id"] = "#!/bin/sh\ncase \"$*\" in\n  -u) echo " + fakeUID + " ;;\n  -g) echo " + fakeGID + " ;;\n  *) exit 96 ;;\nesac\n"
	}
	for name, body := range fakes {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	events := filepath.Join(workspace, "events")
	bringupDir := filepath.Join(workspace, "bringup")
	command := exec.Command("/bin/bash", filepath.Join(repo, "scripts", "01_bringup.sh"), "up")
	command.Env = auditControlledScriptEnv(t, append([]string{
		"PATH=" + bin + string(os.PathListSeparator) + auditSafeScriptPath(t),
		"ROOT_REAL_PYTHON=" + realPython, "ROOT_EVENTS=" + events, "ROOT_REAL_DOCKER=" + docker.path,
		"BRINGUP_PROFILE=prepare-only", "BRINGUP_DIR=" + bringupDir,
		"CONTROL_PLANE_IMAGE=" + testStorageCheckImage,
		"CONTROL_PLANE_IMAGE_BUILD=never", "CONTROL_PLANE_TARGETARCH=amd64",
		"CONTROL_PLANE_DOCKERFILE=" + filepath.Join(proof, "Dockerfile"),
		"ARS_CONFIG=" + arsConfig, "EGS_CONFIG=" + otherConfig, "AGS_CONFIG=" + otherConfig, "ES_CONFIG=" + esConfig,
		"ARS_URL=https://127.0.0.1:1", "EGS_URL=https://127.0.0.1:2",
		"AGS_URL=https://127.0.0.1:3", "ES_URL=https://127.0.0.1:4",
		"CA_CERT=" + filepath.Join(proof, "ca.pem"),
		"OPERATOR_CERT=" + filepath.Join(proof, "operator.pem"),
		"OPERATOR_KEY=" + filepath.Join(proof, "operator-key.pem"),
	}, docker.env...)...)
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), refusal) {
		t.Fatalf("bring-up up did not refuse at the ARS storage check with %q: err=%v output=%q", refusal, err, output)
	}
	if beforeAnyEffect {
		if _, err := os.Stat(events); !os.IsNotExist(err) {
			eventBytes, _ := os.ReadFile(events)
			t.Fatalf("bring-up up ran Docker or the HTTP server before refusing: events=%q", eventBytes)
		}
		if _, err := os.Stat(bringupDir); !os.IsNotExist(err) {
			t.Fatalf("bring-up up created its bring-up directory before refusing: %v", err)
		}
		if _, err := os.Stat(filepath.Join(proof, "ars-storage")); !os.IsNotExist(err) {
			t.Fatalf("bring-up up created the ARS storage root before refusing: %v", err)
		}
		return
	}
	if fakeID != "" && !strings.Contains(string(output), "hand it back with: sudo chown "+fakeID+" "+filepath.Join(proof, "ars-index")+"\n") {
		t.Fatalf("bring-up up did not evaluate the storage for %s: output=%q", fakeID, output)
	}
	eventBytes, err := os.ReadFile(events)
	if err != nil {
		t.Fatal(err)
	}
	// The host-loopback probe runs a throwaway container; no service
	// container may be removed or started.
	if strings.Contains(string(eventBytes), "docker rm") || strings.Contains(string(eventBytes), "--name") ||
		strings.Contains(string(eventBytes), "unexpected ") {
		t.Fatalf("bring-up up touched a service container before the ARS storage check: events=%q", eventBytes)
	}
	loopback := strings.Index(string(eventBytes), "docker run --rm --network host")
	if loopback < 0 {
		t.Fatalf("bring-up up did not reach the host-loopback probe before the ARS storage check: events=%q", eventBytes)
	}
	check := strings.Index(string(eventBytes), "docker storage-check\n")
	if runsCheck != (check > loopback) || strings.Count(string(eventBytes), "docker storage-check\n") > 1 {
		t.Fatalf("bring-up up ran the storage check container %v, want %v, once after the host-loopback probe: events=%q", check >= 0, runsCheck, eventBytes)
	}
	if entries, err := os.ReadDir(filepath.Join(bringupDir, "logs")); err != nil {
		t.Fatal(err)
	} else {
		for _, entry := range entries {
			if entry.Name() != "control-plane-image-build.log" {
				t.Fatalf("bring-up up started a service before the ARS storage check: log %s", entry.Name())
			}
		}
	}
	if _, err := os.Stat(filepath.Join(proof, "ars-index")); !withIndex && !os.IsNotExist(err) {
		t.Fatalf("bring-up up created the ARS index directory: %v", err)
	}
}

// writeTestPythonHook puts a python3 into bin that runs the host's python3
// with a sitecustomize for hook, which changes how the ARS storage check can
// read ACLs. "no-acl-reads" removes os.getxattr, as on hosts other than Linux;
// "acl-read-error" makes every os.getxattr call fail with EACCES.
func writeTestPythonHook(t *testing.T, bin, hook string) {
	t.Helper()
	realPython, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	hookDir := filepath.Join(filepath.Dir(bin), "python-hook")
	if err := os.Mkdir(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	var site string
	switch hook {
	case "no-acl-reads":
		site = "import os\nif hasattr(os, \"getxattr\"):\n    del os.getxattr\n"
	case "acl-read-error":
		site = "import errno, os\n\n\ndef getxattr(path, name, *args, **kwargs):\n" +
			"    raise OSError(errno.EACCES, os.strerror(errno.EACCES), path)\n\n\nos.getxattr = getxattr\n"
	default:
		t.Fatalf("unknown python hook %q", hook)
	}
	if err := os.WriteFile(filepath.Join(hookDir, "sitecustomize.py"), []byte(site), 0o600); err != nil {
		t.Fatal(err)
	}
	wrapper := "#!/bin/sh\nPYTHONPATH=" + strconv.Quote(hookDir) + " exec " + strconv.Quote(realPython) + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "python3"), []byte(wrapper), 0o700); err != nil {
		t.Fatal(err)
	}
}

// testDistinctGID returns a GID, as text, that differs from this process's
// real UID and real GID.
func testDistinctGID() string {
	gid := 4343
	for gid == os.Getuid() || gid == os.Getgid() {
		gid++
	}
	return strconv.Itoa(gid)
}

// testStorageCheckBaseImage is the base of the generated control-plane image,
// whose BusyBox provides everything the ARS storage check runs.
// testStorageCheckImage is the local tag for it that these tests pass as the
// control-plane image, so that a check that ran in any other image fails them.
const (
	testStorageCheckBaseImage = "alpine:3.20"
	testStorageCheckImage     = "execution-substrate/ars-storage-check-test:alpine-3.20"
)

// testStorageCheckDocker is the host's real docker and the environment it
// needs to reach the daemon from the launchers' controlled environment, whose
// HOME holds no Docker context.
type testStorageCheckDocker struct {
	path string
	env  []string
}

func (docker testStorageCheckDocker) command(args ...string) *exec.Cmd {
	command := exec.Command(docker.path, args...)
	command.Env = append(os.Environ(), docker.env...)
	return command
}

func (docker testStorageCheckDocker) run(t *testing.T, args ...string) {
	t.Helper()
	if output, err := docker.command(args...).CombinedOutput(); err != nil {
		t.Fatalf("docker %s: %v: %s", strings.Join(args, " "), err, output)
	}
}

// requireTestStorageCheckDocker returns the real docker for cases that reach
// the ARS storage check container, or skips. The cases pin how the Linux
// kernel decides access for the container identity through bind mounts; on
// macOS, Docker Desktop's file sharing decides instead, so they run only on
// Linux, with a reachable daemon.
func requireTestStorageCheckDocker(t *testing.T) testStorageCheckDocker {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the storage check cases pin how the Linux kernel decides access through bind mounts")
	}
	path, err := exec.LookPath("docker")
	if err != nil {
		t.Skip("needs docker to run the ARS storage check container")
	}
	docker := testStorageCheckDocker{path: path}
	host := os.Getenv("DOCKER_HOST")
	if host == "" {
		if output, err := exec.Command(path, "context", "inspect", "--format", "{{.Endpoints.docker.Host}}").Output(); err == nil {
			host = strings.TrimSpace(string(output))
		}
	}
	if host != "" {
		docker.env = append(docker.env, "DOCKER_HOST="+host)
	}
	for _, name := range []string{"DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"} {
		if value, ok := os.LookupEnv(name); ok {
			docker.env = append(docker.env, name+"="+value)
		}
	}
	if output, err := docker.command("version", "--format", "{{.Server.Version}}").CombinedOutput(); err != nil {
		t.Skipf("needs a reachable Docker daemon to run the ARS storage check container: %v: %s", err, strings.TrimSpace(string(output)))
	}
	if docker.command("image", "inspect", testStorageCheckImage).Run() != nil {
		if docker.command("image", "inspect", testStorageCheckBaseImage).Run() != nil {
			docker.run(t, "pull", "--quiet", testStorageCheckBaseImage)
		}
		docker.run(t, "tag", testStorageCheckBaseImage, testStorageCheckImage)
	}
	return docker
}

// testARSMountArgs is the docker run mount arguments ARS gets: its read-write
// directories in sorted order, where a storage root below the index directory
// shares that directory's mount, then its config read-only.
func testARSMountArgs(indexDir, storage, config string, storageUnderIndexDir bool) []string {
	args := []string{"-v", indexDir + ":" + indexDir + ":rw"}
	if !storageUnderIndexDir {
		args = append(args, "-v", storage+":"+storage+":rw")
	}
	return append(args, "-v", config+":"+config+":ro")
}

// testControlPlaneContainerName is control_plane_container_name for
// BRINGUP_DIR bringupDir.
func testControlPlaneContainerName(bringupDir, service string) string {
	digest := sha256.Sum256([]byte(bringupDir))
	return "execution-substrate-" + hex.EncodeToString(digest[:])[:12] + "-" + service
}

// testIndexSnapshot is what the ARS storage check may change about the index
// file: which file it is, its owner, its mode and its content.
type testIndexSnapshot struct {
	regular, readable bool
	ino               uint64
	uid               uint32
	mode              os.FileMode
	content           string
}

// snapshotTestIndex records the index as the caller can see it. A path the
// caller cannot reach, or one that is not a regular file, gives the zero
// snapshot.
func snapshotTestIndex(t *testing.T, index string) testIndexSnapshot {
	t.Helper()
	info, err := os.Lstat(index)
	if err != nil || !info.Mode().IsRegular() {
		return testIndexSnapshot{}
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("no stat data for the index %s", index)
	}
	snapshot := testIndexSnapshot{regular: true, ino: uint64(stat.Ino), uid: stat.Uid, mode: info.Mode()}
	if content, err := os.ReadFile(index); err == nil {
		snapshot.readable, snapshot.content = true, string(content)
	}
	return snapshot
}

// requireTestIndexUntouched requires a refused check to leave the index as it
// found it, and nothing of its own behind.
func requireTestIndexUntouched(t *testing.T, storage, index string, before testIndexSnapshot) {
	t.Helper()
	if !before.regular || !before.readable {
		t.Fatalf("the index fixture %s was not a readable regular file", index)
	}
	if after := snapshotTestIndex(t, index); after != before {
		t.Fatalf("the refused storage check changed the index %s: before %+v, after %+v", index, before, after)
	}
	requireNoTestStorageCheckLeftovers(t, storage, index)
}

// requireTestIndexRewrittenLikeARS requires a passing check, run as the
// caller's UID, to have written the index the way ARS does: a new regular
// file with mode 0600, owned by that UID, with the content it had.
func requireTestIndexRewrittenLikeARS(t *testing.T, storage, index string, before testIndexSnapshot) {
	t.Helper()
	if !before.regular || !before.readable {
		t.Fatalf("the index fixture %s was not a readable regular file", index)
	}
	after := snapshotTestIndex(t, index)
	if !after.regular || !after.readable || after.content != before.content || after.ino == before.ino ||
		after.mode != 0o600 || int(after.uid) != os.Getuid() {
		t.Fatalf("the storage check did not write the index %s the way ARS does: before %+v, after %+v", index, before, after)
	}
	requireNoTestStorageCheckLeftovers(t, storage, index)
}

// requireNoTestStorageCheckLeftovers requires that no file the check creates
// remains under the storage root or in the index directory.
func requireNoTestStorageCheckLeftovers(t *testing.T, storage, index string) {
	t.Helper()
	for _, dir := range []string{storage, filepath.Dir(index)} {
		_ = filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
			if err == nil && (strings.HasPrefix(entry.Name(), ".ars-storage-check.") || strings.HasPrefix(entry.Name(), ".artifact-index-check.")) {
				t.Errorf("the storage check left %s behind", path)
			}
			return nil
		})
	}
}

// shareTestStorageThroughGroup lets the caller's primary group, and no one
// else, use the storage the caller owns.
func shareTestStorageThroughGroup(t *testing.T, storage, index string) {
	t.Helper()
	for path, mode := range map[string]os.FileMode{storage: 0o770, filepath.Dir(index): 0o770, index: 0o640} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
}

// testSupplementaryGroup returns a supplementary group of this process other
// than its effective GID, or -1 when it has none.
func testSupplementaryGroup(t *testing.T) int {
	t.Helper()
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range groups {
		if group != os.Getegid() {
			return group
		}
	}
	return -1
}

// giveTestStorageToRoot puts a blob under storage, then gives storage and
// everything under it to root and group gid, with dirMode on directories and
// fileMode on files, through passwordless sudo. A cleanup hands it back to the
// caller so the temporary directory can be removed.
func giveTestStorageToRoot(t *testing.T, storage string, gid int, dirMode, fileMode os.FileMode) {
	t.Helper()
	dir := filepath.Join(storage, "sha256", "ab", "cd")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sha256:abcd"), []byte("blob"), 0o600); err != nil {
		t.Fatal(err)
	}
	caller := strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid())
	t.Cleanup(func() {
		_ = exec.Command("sudo", "-n", "setfacl", "-R", "-b", storage).Run()
		_ = exec.Command("sudo", "-n", "chown", "-R", caller, storage).Run()
		_ = exec.Command("sudo", "-n", "chmod", "-R", "u+rwX", storage).Run()
	})
	runTestSudo(t, "chown", "-R", "0:"+strconv.Itoa(gid), storage)
	runTestSudo(t, "find", storage, "-type", "d", "-exec", "chmod", strconv.FormatUint(uint64(dirMode), 8), "{}", "+")
	runTestSudo(t, "find", storage, "-type", "f", "-exec", "chmod", strconv.FormatUint(uint64(fileMode), 8), "{}", "+")
}

func runTestSudo(t *testing.T, args ...string) {
	t.Helper()
	if output, err := exec.Command("sudo", append([]string{"-n"}, args...)...).CombinedOutput(); err != nil {
		t.Fatalf("sudo %s: %v: %s", strings.Join(args, " "), err, output)
	}
}
