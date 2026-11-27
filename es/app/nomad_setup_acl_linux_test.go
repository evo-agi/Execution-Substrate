package app_test

import (
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Re-check 48 of ES PR #66, R48-1. HashiCorp's Nomad package gives Nomad's
// folders to the nomad account, and an account may set an ACL on a folder it
// owns. A default ACL decides the mode of each file then created in the
// folder, whatever the umask: under one that grants that account write, the
// setup's new nomad.hcl was 0664 with an entry for it, so the account kept
// write access to the config root's Nomad loads. The setup now removes both
// ACLs of each folder it takes back, before it writes anything there, and
// sets the new file's mode with chmod as well.

// The kernel's ACL entry tags, and the ID of entries that name no one.
const (
	aclUserObj  = 0x01
	aclUser     = 0x02
	aclGroupObj = 0x04
	aclMask     = 0x10
	aclOther    = 0x20
	aclNoID     = 0xffffffff
)

// aclNames are the attributes that hold a file's ACLs.
var aclNames = []string{"system.posix_acl_access", "system.posix_acl_default"}

// grantingACL gives the account with ID 65534 (nobody, standing in for the
// account the package gave the folders to) every right, under a mask that
// lets the entry count. It is encoded as the kernel's ACL attribute: version
// 2, then each entry's tag, permission bits and ID, little-endian, in the
// kernel's order. Writing the attribute directly needs no acl package.
func grantingACL() []byte {
	value := binary.LittleEndian.AppendUint32(nil, 2)
	for _, entry := range [][3]uint32{
		{aclUserObj, 7, aclNoID},
		{aclUser, 7, 65534},
		{aclGroupObj, 5, aclNoID},
		{aclMask, 7, aclNoID},
		{aclOther, 5, aclNoID},
	} {
		value = binary.LittleEndian.AppendUint16(value, uint16(entry[0]))
		value = binary.LittleEndian.AppendUint16(value, uint16(entry[1]))
		value = binary.LittleEndian.AppendUint32(value, entry[2])
	}
	return value
}

// plantACLs gives folder an access ACL and a default ACL that grant the
// other account everything, as that account can while it owns the folder.
func plantACLs(t *testing.T, folder string) {
	t.Helper()
	for _, name := range aclNames {
		if err := syscall.Setxattr(folder, name, grantingACL(), 0); err != nil {
			t.Fatalf("setting %s on %s: %v", name, folder, err)
		}
	}
}

// hasACL reports whether path has the ACL attribute name.
func hasACL(t *testing.T, path, name string) bool {
	t.Helper()
	_, err := syscall.Getxattr(path, name, nil)
	if errors.Is(err, syscall.ENODATA) {
		return false
	}
	if err != nil {
		t.Fatalf("reading %s of %s: %v", name, path, err)
	}
	return true
}

// requireNoACL fails if path has either ACL.
func requireNoACL(t *testing.T, path string) {
	t.Helper()
	for _, name := range aclNames {
		if hasACL(t, path, name) {
			t.Fatalf("%s still has %s", path, name)
		}
	}
}

// serviceFolders makes the data folder, Nomad's config folder and its TLS
// folder as linuxSetupServiceHarness places them.
func serviceFolders(t *testing.T) (data, config, tlsDir string) {
	t.Helper()
	data = t.TempDir()
	config = filepath.Join(data, "etc")
	tlsDir = filepath.Join(config, "tls")
	if err := os.MkdirAll(tlsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	return data, config, tlsDir
}

func TestLinuxSetupTakesNomadFoldersBackWithoutAnACL(t *testing.T) {
	data, config, tlsDir := serviceFolders(t)
	for _, folder := range []string{data, config, tlsDir} {
		plantACLs(t, folder)
	}
	// The plant works on this file system: a file created in the config
	// folder now takes the default ACL, whatever the umask.
	probe := filepath.Join(config, "probe")
	if err := os.WriteFile(probe, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if !hasACL(t, probe, "system.posix_acl_access") {
		t.Fatal("a file created under the planted default ACL has no ACL; the test proves nothing here")
	}
	if err := os.Remove(probe); err != nil {
		t.Fatal(err)
	}

	// A stand-in chmod records the mode of the new nomad.hcl before it
	// changes it, so the test sees the mode the file was created with.
	// The caller's umask is 0: only the setup's own umask makes the file
	// 0640 from its creation.
	realChmod, err := exec.LookPath("chmod")
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	stand := "#!/bin/sh\nfor last; do :; done\n" +
		"case \"$last\" in *.execution-substrate-new) stat -c '%a' -- \"$last\" >>\"$CHMOD_LOG\" ;; esac\n" +
		"exec " + realChmod + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "chmod"), []byte(stand), 0o755); err != nil {
		t.Fatal(err)
	}
	chmodLog := filepath.Join(t.TempDir(), "chmod.log")
	run := func() string {
		t.Helper()
		command := exec.Command("bash", "-c", linuxSetupServiceHarness(t)+"umask 0\ninstall_nomad_service_config\n", "bash", data)
		command.Env = []string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "CHMOD_LOG=" + chmodLog}
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("install_nomad_service_config: %v %s", err, output)
		}
		return string(output)
	}
	output := run()
	// Each removal is reported, in the order the setup takes the folders
	// back.
	var removed []string
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "nomad: removed the ") {
			removed = append(removed, line)
		}
	}
	var want []string
	for _, folder := range []string{config, data, tlsDir} {
		want = append(want, "nomad: removed the default ACL that was left on "+folder,
			"nomad: removed the access ACL that was left on "+folder)
	}
	if strings.Join(removed, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the run reported removing\n%s\nwant\n%s", strings.Join(removed, "\n"), strings.Join(want, "\n"))
	}

	for folder, mode := range map[string]os.FileMode{data: 0o700, config: 0o755, tlsDir: 0o755} {
		requireNoACL(t, folder)
		requireFileMode(t, folder, mode)
	}
	nomadHCL := filepath.Join(config, "nomad.hcl")
	requireRegularFile(t, nomadHCL, renderedNomadConfig(t, data, config)+"\n", 0o640)
	requireNoACL(t, nomadHCL)
	if logged, err := os.ReadFile(chmodLog); err != nil || string(logged) != "640\n" {
		t.Fatalf("the new nomad.hcl was created with mode %q before chmod (%v), want one chmod of a 0640 file", logged, err)
	}

	// A second run finds no ACL and reports none.
	if output := run(); strings.Contains(output, "nomad: removed the ") {
		t.Fatalf("a run on folders without an ACL reported a removal: %s", output)
	}
}

// nomad_config_write on its own, in a folder that still has the default ACL:
// chmod 0640 caps the inherited entry at read (the mask), so the other
// account cannot write the result. It is the second line: the setup removes
// the default ACL first, as a handle opened before the chmod keeps writing.
func TestNomadConfigWriteCapsAnInheritedACLAtRead(t *testing.T) {
	data, config, _ := serviceFolders(t)
	plantACLs(t, config)
	if _, stderr, err := runLinuxSetupServiceHarness(t, data, "printf 'config\\n' | nomad_config_write \"${NOMAD_CONFIG_PATH}\"\n"); err != nil {
		t.Fatalf("nomad_config_write: %v %s", err, stderr)
	}
	nomadHCL := filepath.Join(config, "nomad.hcl")
	if !hasACL(t, nomadHCL, "system.posix_acl_access") {
		t.Fatal("nomad.hcl did not take the folder's default ACL; the test proves nothing here")
	}
	// With an ACL, the group bits of the mode are the mask.
	requireRegularFile(t, nomadHCL, "config\n", 0o640)
}

// An ACL the setup cannot remove stops it before it writes anything in the
// folder. Root owns the folder here, as the setup's install -d makes it, and
// the harness's sudo runs as the test's account, which cannot change it.
func TestLinuxSetupStopsWhenItCannotRemoveAFolderACL(t *testing.T) {
	// No TLS folder inside: the test's account must be able to remove the
	// root-owned folder when the test ends, so it stays empty.
	data := t.TempDir()
	config := filepath.Join(data, "etc")
	if err := os.Mkdir(config, 0o755); err != nil {
		t.Fatal(err)
	}
	plantACLs(t, config)
	runTestSudo(t, "chown", "0:0", config)
	_, stderr, err := runLinuxSetupServiceHarness(t, data, "install() { :; }\ninstall_nomad_service_config\n")
	if err == nil || !strings.Contains(stderr, "nomad: cannot remove the ACLs of "+config+": [Errno 1] Operation not permitted") {
		t.Fatalf("install_nomad_service_config went on past an ACL it could not remove: %v %s", err, stderr)
	}
	if _, err := os.Lstat(filepath.Join(config, "nomad.hcl")); !os.IsNotExist(err) {
		t.Fatalf("nomad.hcl was written: %v", err)
	}
	if !hasACL(t, config, "system.posix_acl_default") {
		t.Fatal("the folder lost its default ACL; the refusal was not reached")
	}
}
