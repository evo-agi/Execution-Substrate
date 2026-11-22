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
// directory to carry the roots' owner, so ES runs as the caller's UID:GID. The
// service-root-v1 profile keeps the image's default user, because its roots
// are 0:0, and its launcher path creates no roots.
func TestESLauncherContainerUser(t *testing.T) {
	repo := executionPlatformRepoRoot(t)
	realPython, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	callerUser := strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid())

	for _, test := range []struct {
		name     string
		profile  bool
		wantUser string
	}{
		{name: "generic path", wantUser: callerUser},
		{name: "service-root-v1 profile", profile: true},
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
			// to make; anything else fails the run with exit 97. The fake
			// Python passes the profile's static root check, which needs 0:0
			// roots that a non-root test cannot create, and runs everything
			// else with the real interpreter.
			for name, body := range map[string]string{
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
				"ES_CONFIG=" + config,
				"BRINGUP_DIR=" + filepath.Join(workspace, "bringup"),
				"CONTROL_PLANE_IMAGE=execution-substrate/control-plane:supported-local",
				"CONTROL_PLANE_IMAGE_BUILD=never", "CONTROL_PLANE_TARGETARCH=amd64",
				"CONTROL_PLANE_DOCKERFILE=" + dockerfile,
			}
			wantEvents := "docker image\ndocker rm\ndocker run\n"
			if test.profile {
				env = append(env,
					"SUPPORTED_LOCAL_ES_ROOTS_PROFILE=service-root-v1",
					"SUPPORTED_LOCAL_PROOF_DIR="+proof, "SUPPORTED_LOCAL_PROOF_ID=fixture-proof",
				)
				wantEvents = "docker image\nroot-check check\ndocker rm\ndocker run\n"
			}
			command := exec.Command("/bin/bash", filepath.Join(repo, "scripts", "05_start_es.sh"))
			command.Env = auditControlledScriptEnv(t, env...)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("launcher failed: %v output=%q", err, output)
			}
			eventBytes, err := os.ReadFile(events)
			if err != nil || string(eventBytes) != wantEvents {
				t.Fatalf("launcher calls = %q (err=%v), want %q", eventBytes, err, wantEvents)
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
