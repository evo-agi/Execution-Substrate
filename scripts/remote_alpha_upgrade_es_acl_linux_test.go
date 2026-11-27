package scripts_test

import (
	"encoding/binary"
	"os"
	"strings"
	"syscall"
	"testing"
)

// Re-check 48 of ES PR #66, R48-1, mirrored in the upgrade (N67-4). An
// account that owns a folder may set an ACL on it, and HashiCorp's package
// gives /etc/nomad.d and Nomad's data directory to the nomad account; the
// owner and mode do not show the ACL. A default ACL decides the mode of each
// file root then creates in the folder, so the upgrade's new nomad.hcl would
// carry an entry for that account. check and apply refuse a Nomad folder
// that has either ACL, before they change anything. The setup removes both
// when it takes the folders back.

// upgradeGrantingACL gives the account with ID 65534 (nobody, standing in for
// the nomad account) every right, under a mask that lets the entry count,
// encoded as the kernel's ACL attribute: version 2, then each entry's tag,
// permission bits and ID, little-endian, in the kernel's order (owner, named
// user, owning group, mask, others). It needs no acl package.
func upgradeGrantingACL() []byte {
	const noID = 0xffffffff
	value := binary.LittleEndian.AppendUint32(nil, 2)
	for _, entry := range [][3]uint32{{0x01, 7, noID}, {0x02, 7, 65534}, {0x04, 5, noID}, {0x10, 7, noID}, {0x20, 5, noID}} {
		value = binary.LittleEndian.AppendUint16(value, uint16(entry[0]))
		value = binary.LittleEndian.AppendUint16(value, uint16(entry[1]))
		value = binary.LittleEndian.AppendUint32(value, entry[2])
	}
	return value
}

func TestRemoteAlphaUpgradeESRefusesANomadFolderWithAnACL(t *testing.T) {
	helper := buildESConfigCheck(t)
	setACL := func(h *upgradeHost, rel, name string) {
		h.t.Helper()
		path := h.path(rel)
		info, err := os.Stat(path)
		if err != nil {
			h.t.Fatal(err)
		}
		if err := syscall.Setxattr(path, name, upgradeGrantingACL(), 0); err != nil {
			h.t.Fatalf("setting %s on %s: %v", name, rel, err)
		}
		// An access ACL sets the group bits to its mask; put the mode back,
		// as the account would to hide the ACL from a check of the mode.
		// The mask then caps the entry, and the ACL stays.
		if err := os.Chmod(path, info.Mode().Perm()); err != nil {
			h.t.Fatal(err)
		}
	}
	cases := []struct {
		name  string
		plant func(h *upgradeHost)
		scope string
		says  string
	}{
		{"Nomad's config folder has a default ACL", func(h *upgradeHost) {
			setACL(h, "etc/nomad.d", "system.posix_acl_default")
		}, "nomad_dirs", "/etc/nomad.d has an ACL (system.posix_acl_default)"},
		{"Nomad's config folder has an access ACL", func(h *upgradeHost) {
			setACL(h, "etc/nomad.d", "system.posix_acl_access")
		}, "nomad_dirs", "/etc/nomad.d has an ACL (system.posix_acl_access)"},
		{"Nomad's data directory has both ACLs", func(h *upgradeHost) {
			setACL(h, "opt/nomad/data", "system.posix_acl_access")
			setACL(h, "opt/nomad/data", "system.posix_acl_default")
		}, "nomad_dirs", "/opt/nomad/data has an ACL (system.posix_acl_access, system.posix_acl_default)"},
		{"the folder above the data directory has a default ACL", func(h *upgradeHost) {
			setACL(h, "opt/nomad", "system.posix_acl_default")
		}, "nomad_dirs", "/opt/nomad has an ACL (system.posix_acl_default)"},
		{"Nomad's TLS directory has a default ACL", func(h *upgradeHost) {
			h.issueTLS()
			setACL(h, "etc/nomad.d/tls", "system.posix_acl_default")
		}, "shape", "Nomad's TLS directory: present, but has an ACL (system.posix_acl_default)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newUpgradeHost(t, helper)
			tc.plant(h)
			before := h.snapshot()
			report, stderr, code := h.check()
			if code != 1 || !strings.Contains(stderr, "blocker(s); nothing was changed") {
				t.Fatalf("check exited %d: %s", code, stderr)
			}
			found := false
			for _, b := range report["blockers"].([]any) {
				blocker := b.(map[string]any)
				if blocker["scope"] == tc.scope && strings.Contains(blocker["summary"].(string), tc.says) {
					found = true
				}
			}
			if !found {
				t.Fatalf("no %s blocker saying %q in %v", tc.scope, tc.says, report["blockers"])
			}
			assertRestored(t, before, h.snapshot())
			onlyReads(t, h, "a refused check")

			h.clearCalls()
			_, stderr, code = h.apply()
			if code != 1 || !strings.Contains(stderr, "nothing was changed") {
				t.Fatalf("apply exited %d: %s", code, stderr)
			}
			assertRestored(t, before, h.snapshot())
			if _, err := os.Lstat(h.path("var/backups/execution-substrate-es-upgrade")); err == nil {
				t.Fatalf("a refused apply wrote a backup")
			}
			onlyReads(t, h, "a refused apply")
		})
	}
}
