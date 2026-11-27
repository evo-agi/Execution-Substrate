package app_test

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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
	return encodedACL([][3]uint32{
		{aclUserObj, 7, aclNoID},
		{aclUser, 7, 65534},
		{aclGroupObj, 5, aclNoID},
		{aclMask, 7, aclNoID},
		{aclOther, 5, aclNoID},
	})
}

// encodedACL is the kernel's encoding of the ACL entries (tag, permission
// bits, ID), given in the kernel's order.
func encodedACL(entries [][3]uint32) []byte {
	value := binary.LittleEndian.AppendUint32(nil, 2)
	for _, entry := range entries {
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
	// Each removal is reported, by the take-back program, which the setup
	// runs first, in the order it takes the folders back; the setup's own
	// take-back then finds none.
	removals := func(output string) []string {
		var removed []string
		for _, line := range strings.Split(output, "\n") {
			if strings.HasPrefix(line, "nomad: removed the ") || strings.HasPrefix(line, "execution-substrate: removed the ") {
				removed = append(removed, line)
			}
		}
		return removed
	}
	removed := removals(output)
	var want []string
	for _, folder := range []string{config, tlsDir, data} {
		want = append(want, "execution-substrate: removed the default ACL that was left on "+folder,
			"execution-substrate: removed the access ACL that was left on "+folder)
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
	if output := run(); len(removals(output)) != 0 {
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

// A folder the setup cannot take back, its ACL included, stops it before it
// writes anything in the folder. Root owns the folder here, as the setup's
// install -d makes it, and the harness's sudo runs as the test's account,
// which cannot change it. The take-back program, which the setup runs first,
// stops it; its own take-back, which comes next, stops it too.
func TestLinuxSetupStopsWhenItCannotRemoveAFolderACL(t *testing.T) {
	for _, step := range []string{"the take-back program", "nomad_folder_take_back"} {
		t.Run(step, func(t *testing.T) {
			// No TLS folder inside: the test's account must be able to remove
			// the root-owned folder when the test ends, so it stays empty.
			data := t.TempDir()
			config := filepath.Join(data, "etc")
			if err := os.Mkdir(config, 0o755); err != nil {
				t.Fatal(err)
			}
			plantACLs(t, config)
			runTestSudo(t, "chown", "0:0", config)
			steps, want := "install() { :; }\n", []string{
				"execution-substrate: " + config + " could not be taken back (Operation not permitted), and Nomad's unit reads it as root\n",
				"execution-substrate: fix that, then run " + filepath.Join(data, "sbin", "execution-substrate-nomad-take-back") + " " + config + " " + data + " again\n",
			}
			if step == "nomad_folder_take_back" {
				steps, want = steps+"nomad_package_hook_as_root() { :; }\n", []string{"nomad: cannot remove the ACLs of " + config + ": [Errno 1] Operation not permitted"}
			}
			_, stderr, err := runLinuxSetupServiceHarness(t, data, steps+"install_nomad_service_config\n")
			if err == nil {
				t.Fatalf("install_nomad_service_config went on past a folder it could not take back: %s", stderr)
			}
			for _, line := range want {
				if !strings.Contains(stderr, line) {
					t.Fatalf("want %q in: %s", line, stderr)
				}
			}
			if _, err := os.Lstat(filepath.Join(config, "nomad.hcl")); !os.IsNotExist(err) {
				t.Fatalf("nomad.hcl was written: %v", err)
			}
			if !hasACL(t, config, "system.posix_acl_default") {
				t.Fatal("the folder lost its default ACL; the refusal was not reached")
			}
		})
	}
}

// Re-check 49 (O49-2): a file Nomad loads from the config folder, with an
// access ACL left by the account that owned it, is taken back as a new file
// with no ACL, even when its owner and mode bits are already right. The mask
// caps the entry for that account at read here, so the mode bits show
// nothing amiss.
func TestLinuxSetupTakesBackAConfigFileWithAnACL(t *testing.T) {
	data, config, _ := serviceFolders(t)
	extra := filepath.Join(config, "extra.hcl")
	if err := os.WriteFile(extra, []byte("# extra\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	reading := encodedACL([][3]uint32{
		{aclUserObj, 6, aclNoID},
		{aclUser, 7, 65534},
		{aclGroupObj, 4, aclNoID},
		{aclMask, 4, aclNoID},
		{aclOther, 4, aclNoID},
	})
	if err := syscall.Setxattr(extra, "system.posix_acl_access", reading, 0); err != nil {
		t.Fatal(err)
	}
	requireFileMode(t, extra, 0o644)
	stdout, stderr, err := runLinuxSetupServiceHarness(t, data, "install_nomad_service_config\n")
	if err != nil {
		t.Fatalf("install_nomad_service_config: %v %s", err, stderr)
	}
	want := tookBackLine(extra, "uid "+strconv.Itoa(os.Getuid())+", gid "+strconv.Itoa(os.Getgid())+", 0644, with an ACL")
	if got := tookBack(stdout); len(got) != 1 || got[0] != want {
		t.Fatalf("the setup reported %q, want %q", got, want)
	}
	requireRegularFile(t, extra, "# extra\n", 0o644)
	requireNoACL(t, extra)
}

// Re-check 49 (T49-1): the take-back removes a folder's ACLs only after
// install -d has made root its owner. Until then the former owner may set an
// ACL again, and it can watch the folder for the removal. A stand-in install
// plants the granting default ACL on the folder before it takes it, as the
// owner may in its last moment; the removal that follows must clear it. (The
// re-check's proposed test.)
func TestLinuxSetupRemovesFolderACLsOnlyAfterTakingTheFolder(t *testing.T) {
	data, config, tlsDir := serviceFolders(t)
	steps := `eval "standin_$(declare -f install)"
install() {
  local folder="${!#}"
  if [[ -d "${folder}" ]]; then
    python3 -I -c 'import os, sys; os.setxattr(sys.argv[1], "system.posix_acl_default", bytes.fromhex(sys.argv[2]))' "${folder}" ` + hex.EncodeToString(grantingACL()) + `
  fi
  standin_install "$@"
}
install_nomad_service_config
`
	if _, stderr, err := runLinuxSetupServiceHarness(t, data, steps); err != nil {
		t.Fatalf("install_nomad_service_config: %v %s", err, stderr)
	}
	for _, folder := range []string{config, data, tlsDir} {
		requireNoACL(t, folder)
	}
}

// Re-check 49 (T49-2): the TLS folder is taken back before the issuer writes
// into it; until then the former owner may rename and replace what the
// issuer puts there. A stand-in issuer fails if the folder still holds the
// ACL planted while that account owned it. (The re-check's proposed test.)
func TestLinuxSetupTakesTheTLSFolderBackBeforeItIssues(t *testing.T) {
	data, _, tlsDir := serviceFolders(t)
	plantACLs(t, tlsDir)
	steps := `install_nomad_tls_material() {
  if ! python3 -I -c 'import os, sys; sys.exit("system.posix_acl_default" in os.listxattr(sys.argv[1]))' "${NOMAD_TLS_DIR}"; then
    echo "the TLS folder was not yet taken back when the material was issued" >&2
    return 1
  fi
}
install_nomad_service_config
`
	if _, stderr, err := runLinuxSetupServiceHarness(t, data, steps); err != nil {
		t.Fatalf("install_nomad_service_config: %v %s", err, stderr)
	}
}
