package app_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
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
// file or storage the caller cannot use, before any container call.
func TestServiceLaunchersContainerUser(t *testing.T) {
	repo := executionPlatformRepoRoot(t)
	realID, err := exec.LookPath("id")
	if err != nil {
		t.Fatal(err)
	}
	callerUser := strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid())
	const idCalls = "id -u\nid -g\n"
	const launchEvents = idCalls + "docker image\ndocker rm\ndocker run\n"
	const storageRefusalEvents = idCalls + "docker image\n"
	const chownHint = "if an earlier bring-up wrote this storage as root, hand it back with: sudo "

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
	}
	identityCases := []testCase{
		{name: "caller's IDs", idMode: "real", wantUser: callerUser, wantEvents: launchEvents},
		{name: "UID different from the GID", idMode: "fake", fakeUID: "4242", fakeGID: "4343", wantUser: "4242:4343", wantEvents: launchEvents},
		{name: "empty UID refused", idMode: "fake", fakeGID: "4343", wantEvents: idCalls, refusal: "as the operator: id -u and id -g must print numeric IDs, got '' and 4343"},
		{name: "group name with a digit refused", idMode: "fake", fakeUID: "4242", fakeGID: "staff1", wantEvents: idCalls, refusal: "as the operator: id -u and id -g must print numeric IDs, got 4242 and staff1"},
		{name: "failing id refused", idMode: "fail", wantEvents: "id -u\n", refusal: "id: synthetic failure"},
	}
	arsStorageCases := []testCase{
		{
			name: "missing storage root created as the caller", idMode: "fake", fakeUID: "4242", fakeGID: "4343", wantUser: "4242:4343", wantEvents: launchEvents,
			arrange: func(t *testing.T, storage, index string) {
				if err := os.Remove(storage); err != nil {
					t.Fatal(err)
				}
			},
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
			name: "relative storage root refused", idMode: "real", wantEvents: storageRefusalEvents,
			refusal: "ARS storage check failed: storage.root_dir must be an absolute path",
		},
		{
			name: "storage directory the caller cannot write refused", idMode: "real", wantEvents: storageRefusalEvents,
			refusal: "ARS storage check failed: directory is not writable and searchable by you", needsNonRoot: true, fix: "storage",
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
			name: "storage file the caller cannot read refused", idMode: "real", wantEvents: storageRefusalEvents,
			refusal: "ARS storage check failed: file is not readable by you", needsNonRoot: true, fix: "storage",
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
			refusal: "ARS storage check failed: directory is not writable and searchable by you", needsNonRoot: true, fix: "index directory",
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
			refusal: "ARS storage check failed: file is not readable by you", needsNonRoot: true, fix: "index",
			arrange: func(t *testing.T, storage, index string) {
				if err := os.Chmod(index, 0o000); err != nil {
					t.Fatal(err)
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
					root := storage
					if strings.HasPrefix(test.name, "relative storage root") {
						root = "ars-storage"
					}
					settings["storage"] = map[string]any{"root_dir": root, "index_file": index}
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
					wantFix := ""
					switch test.fix {
					case "storage":
						wantFix = chownHint + "chown -R " + callerUser + " " + storage + "\n"
					case "index":
						wantFix = chownHint + "chown " + callerUser + " " + index + "\n"
					case "index directory":
						wantFix = chownHint + "chown " + callerUser + " " + indexDir + "\n"
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
				if service.name == "ars" {
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
// once instead of after ARS's readiness timeout.
func TestBringupUpChecksARSStorageBeforeStartingServices(t *testing.T) {
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
	// The index file is missing, which ARS refuses at startup.
	arsConfig := writeJSON("ars.json", map[string]any{"storage": map[string]any{
		"root_dir":   filepath.Join(proof, "ars-storage"),
		"index_file": filepath.Join(proof, "ars-index", "index.json"),
	}})
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
	for name, body := range map[string]string{
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
	} {
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
	if err == nil || !strings.Contains(string(output), "ARS storage check failed: storage.index_file must be an existing regular file") {
		t.Fatalf("bring-up up did not refuse at the ARS storage check: err=%v output=%q", err, output)
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
	if _, err := os.Stat(filepath.Join(proof, "ars-index")); !os.IsNotExist(err) {
		t.Fatalf("bring-up up created the ARS index directory: %v", err)
	}
}
