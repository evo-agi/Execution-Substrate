package app_test

import (
	"encoding/json"
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
// it creates a missing storage root as the caller, and refuses a missing index
// file or storage that the container identity cannot use, before any container
// call. That identity is the UID:GID passed to docker run --user, with no
// supplementary groups, so access that only the caller's supplementary groups
// grant does not count.
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
	distinctGID := testDistinctGID()
	const idCalls = "id -u\nid -g\n"
	const launchEvents = idCalls + "docker image\ndocker rm\ndocker run\n"
	const storageRefusalEvents = idCalls + "docker image\n"
	const chownHint = "if an earlier bring-up wrote this storage as root, or it is shared through another group, hand it back with: sudo "
	const accessRefusal = "is not writable and searchable by your UID and primary group"
	foreignIdentityRefusal := testForeignIdentityDirectoryRefusal()

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
		// needsACLReads marks cases about entries the identity does not own
		// that the check decides by their mode bits. That needs a host where
		// Python can read ACLs, which is Linux; elsewhere the check refuses
		// such entries, which "storage the identity does not own refused
		// where ACLs cannot be read" covers.
		needsACLReads bool
		// checkCreatedRoot requires the storage root to exist afterwards,
		// owned by the caller.
		checkCreatedRoot bool
		// pythonHook, when set, runs the launcher's python3 with a
		// sitecustomize that changes how ACLs can be read: "no-acl-reads"
		// removes os.getxattr, as on hosts other than Linux, and
		// "acl-read-error" makes it fail with EACCES.
		pythonHook string
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
			name: "storage the caller can use but the container identity cannot refused", idMode: "fake", fakeUID: "4242", fakeGID: "4343", wantEvents: storageRefusalEvents,
			refusal: "ARS storage check failed: " + foreignIdentityRefusal, fix: "index directory", hintUser: "4242:4343",
		},
		{
			// The identity may write to the index directory through the
			// other class but not search it, so ARS could not reach the
			// index. The index itself is readable through the other class.
			name: "index directory the container identity cannot search refused", idMode: "fake", fakeUID: "4242", fakeGID: "4343", wantEvents: storageRefusalEvents,
			refusal: "ARS storage check failed: " + foreignIdentityRefusal, fix: "index directory", hintUser: "4242:4343",
			arrange: func(t *testing.T, storage, index string) {
				for path, mode := range map[string]os.FileMode{filepath.Dir(index): 0o772, index: 0o644} {
					if err := os.Chmod(path, mode); err != nil {
						t.Fatal(err)
					}
				}
			},
		},
		{
			// Python can read ACLs only on Linux. Elsewhere the check cannot
			// tell whether an entry the identity does not own has one, so it
			// refuses the entry.
			name: "storage the identity does not own refused where ACLs cannot be read", idMode: "fake", fakeUID: "4242", fakeGID: "4343", wantEvents: storageRefusalEvents,
			pythonHook: "no-acl-reads", fix: "index directory", hintUser: "4242:4343",
			refusal: "ARS storage check failed: directory is not owned by your UID, and this host cannot show whether it has an access ACL",
		},
		{
			name: "storage whose access ACL cannot be read refused", idMode: "fake", fakeUID: "4242", fakeGID: "4343", wantEvents: storageRefusalEvents,
			pythonHook: "acl-read-error", fix: "index directory", hintUser: "4242:4343",
			refusal: "ARS storage check failed: cannot read the access ACL of this directory (Permission denied)",
		},
		{
			name: "missing index file refused", idMode: "real", wantEvents: storageRefusalEvents,
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
			name: "relative storage root refused", idMode: "real", wantEvents: storageRefusalEvents,
			refusal: "ARS storage check failed: storage.root_dir must be an absolute path",
		},
		{
			name: "relative index file refused", idMode: "real", wantEvents: storageRefusalEvents,
			refusal: "ARS storage check failed: storage.index_file must be an absolute path",
		},
		{
			name: "storage root that is a file refused", idMode: "real", wantEvents: storageRefusalEvents,
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
			name: "storage directory the check cannot list refused", idMode: "real", wantEvents: storageRefusalEvents,
			refusal: "ARS storage check failed: cannot list directory", needsNonRoot: true, fix: "storage",
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
			name: "storage directory the caller cannot write refused", idMode: "real", wantEvents: storageRefusalEvents,
			refusal: "ARS storage check failed: directory " + accessRefusal, needsNonRoot: true, fix: "storage",
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
			name: "storage directory the caller cannot search refused", idMode: "real", wantEvents: storageRefusalEvents,
			refusal: "ARS storage check failed: directory " + accessRefusal, needsNonRoot: true, fix: "storage",
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
			name: "storage file the caller cannot read refused", idMode: "real", wantEvents: storageRefusalEvents,
			refusal: "ARS storage check failed: file is not readable by your UID and primary group", needsNonRoot: true, fix: "storage",
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
		},
		{
			name: "index directory the caller cannot write refused", idMode: "real", wantEvents: storageRefusalEvents,
			refusal: "ARS storage check failed: directory " + accessRefusal, needsNonRoot: true, fix: "index directory",
			arrange: func(t *testing.T, storage, index string) {
				dir := filepath.Dir(index)
				if err := os.Chmod(dir, 0o555); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
			},
		},
		{
			name: "index file the caller cannot read refused", idMode: "real", wantEvents: storageRefusalEvents,
			refusal: "ARS storage check failed: file is not readable by your UID and primary group", needsNonRoot: true, fix: "index",
			arrange: func(t *testing.T, storage, index string) {
				if err := os.Chmod(index, 0o000); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			// Audit finding A11-1: root owns the storage and shares it with a
			// supplementary group of the caller. The caller's own process
			// could use it, but the container has no supplementary groups.
			name: "storage usable only through a supplementary group refused", idMode: "real", wantEvents: storageRefusalEvents,
			refusal: "ARS storage check failed: directory " + accessRefusal, fix: "storage",
			needsNonRoot: true, needsSudo: true, needsSupplementaryGroup: true, needsACLReads: true,
			arrange: func(t *testing.T, storage, index string) {
				giveTestStorageToRoot(t, storage, testSupplementaryGroup(t), 0o770, 0o660)
			},
		},
		{
			// Root owns the storage and shares it with the caller's primary
			// group, which the container keeps.
			name: "storage shared through the primary group accepted", idMode: "real", wantUser: callerUser, wantEvents: launchEvents,
			needsNonRoot: true, needsSudo: true, needsACLReads: true,
			arrange: func(t *testing.T, storage, index string) {
				giveTestStorageToRoot(t, storage, os.Getegid(), 0o770, 0o640)
			},
		},
		{
			// An access ACL can grant or deny differently from the mode bits
			// the check reads, so an entry the identity does not own and that
			// carries one is refused.
			name: "storage with an access ACL that the identity does not own refused", idMode: "real", wantEvents: storageRefusalEvents,
			refusal: "ARS storage check failed: directory is not owned by your UID and has an access ACL, which this check does not evaluate", fix: "storage",
			needsNonRoot: true, needsSudo: true, needsSetfacl: true, needsACLReads: true,
			arrange: func(t *testing.T, storage, index string) {
				giveTestStorageToRoot(t, storage, os.Getegid(), 0o770, 0o640)
				runTestSudo(t, "setfacl", "-m", "u:"+strconv.Itoa(os.Getuid())+":rwx", storage)
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
				if test.needsACLReads && runtime.GOOS != "linux" {
					t.Skip("on this host the check refuses entries the identity does not own, because Python cannot read their ACLs here")
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
				storage := filepath.Join(proof, "ars-storage")
				indexDir := filepath.Join(proof, "ars-index")
				index := filepath.Join(indexDir, "index.json")
				settings := map[string]any{}
				if service.name == "ars" {
					for _, dir := range []string{storage, indexDir} {
						if err := os.Mkdir(dir, 0o755); err != nil {
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
				// The fake id answers only -u and -g; anything else fails with
				// exit 96.
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
				configVar := strings.ToUpper(service.name) + "_CONFIG"
				command := exec.Command("/bin/bash", filepath.Join(repo, "scripts", service.script))
				command.Dir = workspace
				command.Env = auditControlledScriptEnv(t,
					"PATH="+bin+string(os.PathListSeparator)+auditSafeScriptPath(t),
					"LAUNCHER_EVENTS="+events, "LAUNCHER_RUN_ARGS="+runArgs,
					"LAUNCHER_REAL_ID="+realID, "LAUNCHER_ID_MODE="+test.idMode,
					"LAUNCHER_FAKE_UID="+test.fakeUID, "LAUNCHER_FAKE_GID="+test.fakeGID,
					configVar+"="+config,
					"BRINGUP_DIR="+filepath.Join(workspace, "bringup"),
					"CONTROL_PLANE_IMAGE=execution-substrate/control-plane:supported-local",
					"CONTROL_PLANE_IMAGE_BUILD=never", "CONTROL_PLANE_TARGETARCH=amd64",
					"CONTROL_PLANE_DOCKERFILE="+dockerfile,
				)
				output, err := command.CombinedOutput()
				eventBytes, eventErr := os.ReadFile(events)
				if eventErr != nil || string(eventBytes) != test.wantEvents {
					t.Fatalf("launcher calls = %q (err=%v), want %q; launcher err=%v output=%q", eventBytes, eventErr, test.wantEvents, err, output)
				}
				if test.refusal != "" {
					if err == nil {
						t.Fatalf("launcher succeeded, want refusal %q: output=%q", test.refusal, output)
					}
					if !strings.Contains(string(output), test.refusal) {
						t.Fatalf("launcher output = %q, want refusal %q", output, test.refusal)
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
					// The launcher lists read-write mounts in sorted order.
					want = append(want,
						"-v", indexDir+":"+indexDir+":rw",
						"-v", storage+":"+storage+":rw",
					)
				}
				want = append(want,
					"-v", config+":"+config+":ro",
					"execution-substrate/control-plane:supported-local",
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
// once instead of after ARS's readiness timeout, and that the check evaluates
// the identity ARS will run as: with a fake id that prints 4242 and 4343,
// storage the caller owns with mode 0755 must be refused for 4242:4343.
func TestBringupUpChecksARSStorageBeforeStartingServices(t *testing.T) {
	for _, scenario := range []struct {
		name      string
		fakeID    string
		withIndex bool
		refusal   string
		// beforeAnyEffect marks a refusal that must come before Docker,
		// the image, the bring-up logs or the storage are touched.
		beforeAnyEffect bool
	}{
		{name: "missing index", refusal: "ARS storage check failed: storage.index_file must be an existing regular file"},
		{name: "storage the container identity cannot use", fakeID: "4242:4343", withIndex: true,
			refusal: "ARS storage check failed: " + testForeignIdentityDirectoryRefusal()},
		{name: "non-numeric identity refused before any effect", fakeID: "operator:4343", withIndex: true,
			refusal: `cannot run ARS as the operator: id -u and id -g must print numeric IDs, got operator and 4343`, beforeAnyEffect: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			testBringupUpARSStorageRefusal(t, scenario.fakeID, scenario.withIndex, scenario.refusal, scenario.beforeAnyEffect)
		})
	}
}

// testBringupUpARSStorageRefusal runs 01_bringup.sh up with fake Docker and
// requires it to stop with refusal before any service container. fakeID,
// when set as "U:G", replaces id so that id -u prints U and id -g prints G.
func testBringupUpARSStorageRefusal(t *testing.T, fakeID string, withIndex bool, refusal string, beforeAnyEffect bool) {
	repo := executionPlatformRepoRoot(t)
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
	fakes := map[string]string{
		"docker": `#!/bin/sh
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
	command.Env = auditControlledScriptEnv(t,
		"PATH="+bin+string(os.PathListSeparator)+auditSafeScriptPath(t),
		"ROOT_REAL_PYTHON="+realPython, "ROOT_EVENTS="+events,
		"BRINGUP_PROFILE=prepare-only", "BRINGUP_DIR="+bringupDir,
		"CONTROL_PLANE_IMAGE=execution-substrate/control-plane:supported-local",
		"CONTROL_PLANE_IMAGE_BUILD=never", "CONTROL_PLANE_TARGETARCH=amd64",
		"CONTROL_PLANE_DOCKERFILE="+filepath.Join(proof, "Dockerfile"),
		"ARS_CONFIG="+arsConfig, "EGS_CONFIG="+otherConfig, "AGS_CONFIG="+otherConfig, "ES_CONFIG="+esConfig,
		"ARS_URL=https://127.0.0.1:1", "EGS_URL=https://127.0.0.1:2",
		"AGS_URL=https://127.0.0.1:3", "ES_URL=https://127.0.0.1:4",
		"CA_CERT="+filepath.Join(proof, "ca.pem"),
		"OPERATOR_CERT="+filepath.Join(proof, "operator.pem"),
		"OPERATOR_KEY="+filepath.Join(proof, "operator-key.pem"),
	)
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
	if !strings.Contains(string(eventBytes), "docker run --rm --network host") {
		t.Fatalf("bring-up up did not reach the host-loopback probe before the ARS storage check: events=%q", eventBytes)
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

// testForeignIdentityDirectoryRefusal is the refusal the ARS storage check
// gives for a 0755 directory owned by the caller when the container identity
// is another UID with a GID that is not the directory's. On Linux the check
// reads the directory's access ACL, finds none, and decides by the other
// permission bits. Python can read ACLs only on Linux, so elsewhere the check
// refuses every entry the identity does not own.
func testForeignIdentityDirectoryRefusal() string {
	if runtime.GOOS == "linux" {
		return "directory is not writable and searchable by your UID and primary group"
	}
	return "directory is not owned by your UID, and this host cannot show whether it has an access ACL"
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
