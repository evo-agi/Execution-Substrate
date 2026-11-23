package admission

// Held on its own: the identity check the startup probe applies to each file
// it creates the way retention creates its files. In a whole probe, earlier
// checks refuse most file systems that would reach this one, and a file just
// created with O_EXCL cannot have a second link unless something links it in
// between, so the check is held here with crafted identities (audit 16 of pull
// request #20, mutants R9 and R13).

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRetainedResultFileIdentityErrorNamesEachCheck(t *testing.T) {
	owner := executionPlatformStateOwner{UID: 4242, GID: 4343}
	const device = uint64(77)
	good := custodyIdentity{Device: device, Inode: 9, Mode: unix.S_IFREG | 0o600, Links: 1, UID: owner.UID, GID: owner.GID}
	if err := retainedResultFileIdentityError(good, retainedResultBundleFileMode, owner, device); err != nil {
		t.Fatalf("refused a retained result file with the expected identity: %v", err)
	}
	for _, test := range []struct {
		name   string
		change func(*custodyIdentity)
		want   string
	}{
		{"a second link", func(identity *custodyIdentity) { identity.Links = 2 }, "retained result file has an invalid identity"},
		{"a directory", func(identity *custodyIdentity) { identity.Mode = unix.S_IFDIR | 0o600 }, "retained result file has an invalid identity"},
		{"a symbolic link", func(identity *custodyIdentity) { identity.Mode = unix.S_IFLNK | 0o600 }, "retained result file has an invalid identity"},
		{"another device", func(identity *custodyIdentity) { identity.Device = device + 1 }, "retained result files report another device than the results root"},
		{"another owning user", func(identity *custodyIdentity) { identity.UID = owner.UID + 1 }, "retained result file ownership is unavailable"},
		{"another group", func(identity *custodyIdentity) { identity.GID = owner.GID + 1 }, "retained result file ownership is unavailable"},
		{"another mode", func(identity *custodyIdentity) { identity.Mode = unix.S_IFREG | 0o640 }, "retained result file mode 0600 is unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			identity := good
			test.change(&identity)
			err := retainedResultFileIdentityError(identity, retainedResultBundleFileMode, owner, device)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("retained result file identity check = %v, want %q", err, test.want)
			}
		})
	}
}
