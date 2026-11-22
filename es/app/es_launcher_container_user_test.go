package app_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestESLauncherContainerUser pins the ES container user that
// scripts/05_start_es.sh passes to docker run. Without a supported-local roots
// profile, the launcher creates the execution roots as the calling operator,
// and ES's startup capability probe requires a naturally created result
// directory to carry the roots' UID and GID, so ES runs as the caller's
// effective UID and primary GID. A fake id that prints a UID different from
// the GID pins which ID goes where, also on hosts whose UID equals their GID,
// such as the GitHub runner. The launcher refuses before any image, root or
// container effect when id fails or prints a non-numeric ID, because docker
// run --user with an empty UID runs as root. The service-root-v1 profile keeps
// the image's default user, because its roots are 0:0; its launcher path calls
// no id and creates no roots.
func TestESLauncherContainerUser(t *testing.T) {
	repo := executionPlatformRepoRoot(t)
	realPython, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	realID, err := exec.LookPath("id")
	if err != nil {
		t.Fatal(err)
	}
	callerUser := strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid())
	// The generic path asks id for the effective UID, then the primary GID,
	// before the image check, root creation and container calls.
	const idCalls = "id -u\nid -g\n"
	const genericEvents = idCalls + "docker image\ndocker rm\ndocker run\n"

	for _, test := range []struct {
		name    string
		profile bool
		// idMode selects the fake id's answers: "real" runs the host's id,
		// "fake" prints fakeUID and fakeGID, "fail" exits 1.
		idMode     string
		fakeUID    string
		fakeGID    string
		wantUser   string
		wantEvents string
		// refusal, when set, means the launcher must fail before any image,
		// root or container effect, with this text in its output.
		refusal string
	}{
		{name: "generic path with the caller's IDs", idMode: "real", wantUser: callerUser, wantEvents: genericEvents},
		{name: "generic path with a UID different from the GID", idMode: "fake", fakeUID: "4242", fakeGID: "4343", wantUser: "4242:4343", wantEvents: genericEvents},
		{name: "service-root-v1 profile", profile: true, idMode: "fake", fakeUID: "4242", fakeGID: "4343", wantEvents: "docker image\nroot-check check\ndocker rm\ndocker run\n"},
		{name: "empty UID refused", idMode: "fake", fakeGID: "4343", wantEvents: idCalls, refusal: "id -u and id -g must print numeric IDs, got '' and 4343"},
		{name: "group name with a digit refused", idMode: "fake", fakeUID: "4242", fakeGID: "staff1", wantEvents: idCalls, refusal: "id -u and id -g must print numeric IDs, got 4242 and staff1"},
		{name: "failing id refused", idMode: "fail", wantEvents: "id -u\n", refusal: "id: synthetic failure"},
	} {
		t.Run(test.name, func(t *testing.T) {
			workspace, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			proof := filepath.Join(workspace, "proof")
			if err := os.Mkdir(proof, 0o755); err != nil {
				t.Fatal(err)
			}
			config := filepath.Join(proof, "es.json")
			staging := filepath.Join(proof, "es-staging")
			results := filepath.Join(proof, "es-results")
			data, err := json.Marshal(map[string]any{"execution": map[string]any{
				"staging_root_dir": staging,
				"results_root_dir": results,
			}})
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
			// The fake daemon answers only the calls the launcher is expected
			// to make; anything else fails the run with exit 97. The fake id
			// answers only -u and -g; anything else fails with exit 96. The
			// fake Python passes the profile's static root check, which needs
			// 0:0 roots that a non-root test cannot create, and runs
			// everything else with the real interpreter.
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
				"python3": `#!/bin/sh
if [ "$1" = "$LAUNCHER_REPO/scripts/internal/supported_local_execution_roots.py" ]; then
  printf 'root-check %s\n' "$2" >> "$LAUNCHER_EVENTS"
  exit 0
fi
exec "$LAUNCHER_REAL_PYTHON" "$@"
`,
			} {
				if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			events := filepath.Join(workspace, "events")
			runArgs := filepath.Join(workspace, "run-args")
			env := []string{
				"PATH=" + bin + string(os.PathListSeparator) + auditSafeScriptPath(t),
				"LAUNCHER_EVENTS=" + events, "LAUNCHER_RUN_ARGS=" + runArgs,
				"LAUNCHER_REPO=" + repo, "LAUNCHER_REAL_PYTHON=" + realPython,
				"LAUNCHER_REAL_ID=" + realID, "LAUNCHER_ID_MODE=" + test.idMode,
				"LAUNCHER_FAKE_UID=" + test.fakeUID, "LAUNCHER_FAKE_GID=" + test.fakeGID,
				"ES_CONFIG=" + config,
				"BRINGUP_DIR=" + filepath.Join(workspace, "bringup"),
				"CONTROL_PLANE_IMAGE=execution-substrate/control-plane:supported-local",
				"CONTROL_PLANE_IMAGE_BUILD=never", "CONTROL_PLANE_TARGETARCH=amd64",
				"CONTROL_PLANE_DOCKERFILE=" + dockerfile,
			}
			if test.profile {
				env = append(env,
					"SUPPORTED_LOCAL_ES_ROOTS_PROFILE=service-root-v1",
					"SUPPORTED_LOCAL_PROOF_DIR="+proof, "SUPPORTED_LOCAL_PROOF_ID=fixture-proof",
				)
			}
			command := exec.Command("/bin/bash", filepath.Join(repo, "scripts", "05_start_es.sh"))
			command.Env = auditControlledScriptEnv(t, env...)
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
				if strings.Contains(string(output), "docker run") {
					t.Fatalf("refusing launcher printed a docker run command: %q", output)
				}
				if _, err := os.Stat(runArgs); !os.IsNotExist(err) {
					t.Fatalf("refusing launcher ran a container: %v", err)
				}
				for _, root := range []string{staging, results} {
					if _, err := os.Stat(root); !os.IsNotExist(err) {
						t.Fatalf("refusing launcher created or found execution root %s: %v", root, err)
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
			want := []string{"run", "--rm", "--name", "", "--network", "host"}
			if test.wantUser != "" {
				want = append(want, "--user", test.wantUser)
			}
			want = append(want,
				// The launcher lists read-write mounts in sorted order.
				"-v", results+":"+results+":rw",
				"-v", staging+":"+staging+":rw",
				"-v", config+":"+config+":ro",
				"execution-substrate/control-plane:supported-local",
				"/usr/local/bin/es", "-config", config,
			)
			if len(got) != len(want) {
				t.Fatalf("docker run args = %q, want %q", got, want)
			}
			for index := range want {
				if index == 3 {
					if !strings.HasPrefix(got[index], "execution-substrate-") || !strings.HasSuffix(got[index], "-es") {
						t.Fatalf("docker run container name = %q, want an execution-substrate ES name", got[index])
					}
					continue
				}
				if got[index] != want[index] {
					t.Fatalf("docker run args = %q, want %q", got, want)
				}
			}
			for _, root := range []string{staging, results} {
				info, err := os.Stat(root)
				if test.profile {
					if !os.IsNotExist(err) {
						t.Fatalf("profile launcher created or found execution root %s: %v", root, err)
					}
					continue
				}
				if err != nil || !info.IsDir() {
					t.Fatalf("generic launcher did not create execution root %s: %v", root, err)
				}
			}
			if test.wantUser == "" {
				if strings.Contains(string(output), "--user") {
					t.Fatalf("profile launcher printed a --user option: %q", output)
				}
			} else if !strings.Contains(string(output), " --user "+test.wantUser+" ") {
				t.Fatalf("launcher did not print --user %s: %q", test.wantUser, output)
			}
		})
	}
}
