package executionsubstrate_test

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const remoteAlphaRuntimeImageRef = "execution-substrate/control-plane-normal-shell:supported-local"
const remoteAlphaRuntimeImageBuildScript = "scripts/remote_alpha_build_normal_shell_runtime_image.sh"
const remoteAlphaRuntimeImageDockerfile = "es/runtimeprofiles/control_plane_normal_shell/Dockerfile"
const executionSubstrateRepoRoot = "/Users/ds/Repositories/Execution Substrate"

func runSourcedRuntimeImageHelper(t *testing.T, env []string, shellBody string) ([]byte, error) {
	t.Helper()
	helperPath := filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_normal_shell_runtime_image_check.sh")
	script := fmt.Sprintf("set -euo pipefail\nsource %q\n%s\n", helperPath, shellBody)
	cmd := exec.Command("/bin/bash", "-c", script)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = env
	return cmd.CombinedOutput()
}

func setupFakeRuntimeImageCommands(t *testing.T, dir string) {
	t.Helper()

	writeExecutable(t, dir, "hostname", "#!/bin/sh\necho m75q-test\n")
	writeExecutable(t, dir, "id", `#!/bin/sh
if [ "$1" = "-u" ]; then
  echo 0
  exit 0
fi
if [ "$1" = "-nG" ] && [ "$2" = "ds" ]; then
  echo "ds adm wheel"
  exit 0
fi
exec /usr/bin/id "$@"
`)
	writeExecutable(t, dir, "systemctl", `#!/bin/sh
case "$1:$3" in
  is-active:docker|is-active:nomad)
    exit 0
    ;;
esac
exit 1
`)
	writeExecutable(t, dir, "nomad", `#!/bin/sh
if [ "$1" = "node" ] && [ "$2" = "status" ] && [ "$3" = "-json" ]; then
  cat <<'EOF'
[
  {
    "ID": "node-1",
    "Status": "ready"
  }
]
EOF
  exit 0
fi
exit 1
`)
	writeExecutable(t, dir, "docker", `#!/bin/sh
if [ "$1" = "info" ]; then
  exit 0
fi
if [ "$1" = "image" ] && [ "$2" = "inspect" ]; then
  if [ "${FAKE_DOCKER_IMAGE_PRESENT:-0}" = "1" ] && [ "$3" = "execution-substrate/control-plane-normal-shell:supported-local" ]; then
    cat <<'EOF'
[
  {
    "Id": "sha256:test-image",
    "RepoDigests": [
      "execution-substrate/control-plane-normal-shell@sha256:test-image"
    ],
    "Architecture": "amd64",
    "Os": "linux",
    "Created": "2026-04-23T17:47:16Z",
    "Size": 123456789
  }
]
EOF
    exit 0
  fi
  exit 1
fi
if [ "$1" = "run" ]; then
  if [ -n "${FAKE_DOCKER_RUN_STDOUT:-}" ]; then
    printf '%s' "${FAKE_DOCKER_RUN_STDOUT}"
  fi
  if [ -n "${FAKE_DOCKER_RUN_STDERR:-}" ]; then
    printf '%s' "${FAKE_DOCKER_RUN_STDERR}" >&2
  fi
  exit "${FAKE_DOCKER_RUN_EXIT:-0}"
fi
exit 64
`)
}

func TestRemoteAlphaBuildNormalShellRuntimeImageWrapperUsesRemoteAlphaRecipe(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	dockerArgsPath := filepath.Join(tmpDir, "docker-args.txt")
	writeExecutable(t, fakeBin, "docker", fmt.Sprintf(`#!/bin/sh
if [ "$1" != "build" ]; then
  exit 64
fi
printf '%%s\n' "$@" > %q
	exit 0
`, dockerArgsPath))

	cmd := exec.Command("/bin/bash", filepath.Join(executionSubstrateRepoRoot, remoteAlphaRuntimeImageBuildScript))
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = envWithPath(fakeBin)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("wrapper failed: %v\n%s", err, output)
	}

	if got := strings.TrimSpace(string(output)); got != remoteAlphaRuntimeImageRef {
		t.Fatalf("unexpected wrapper output %q", got)
	}

	args := strings.Split(strings.TrimSpace(mustRead(t, dockerArgsPath)), "\n")
	if len(args) == 0 || args[0] != "build" {
		t.Fatalf("unexpected docker args %v", args)
	}
	if !containsArg(args, "-t", remoteAlphaRuntimeImageRef) {
		t.Fatalf("docker build did not use remote alpha image ref: %v", args)
	}
	if !containsArg(args, "-f", filepath.Join(executionSubstrateRepoRoot, remoteAlphaRuntimeImageDockerfile)) {
		t.Fatalf("docker build did not use repo-owned Dockerfile: %v", args)
	}
	if !containsArg(args, "--build-arg", "CODEX_CLI_PATH=/usr/local/bin/codex") {
		t.Fatalf("docker build did not use proof-safe codex cli path: %v", args)
	}
	if !containsArg(args, "--build-arg", "CODEX_REALIZATION=proof") {
		t.Fatalf("docker build did not use proof realization: %v", args)
	}
}

func TestRemoteAlphaBuildNormalShellRuntimeImageWrapperRejectsConflictingRecipeOverrides(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		env     string
		snippet string
	}{
		{
			name:    "dockerfile",
			env:     "CONTROL_PLANE_NORMAL_SHELL_DOCKERFILE=/tmp/not-repo/Dockerfile",
			snippet: "CONTROL_PLANE_NORMAL_SHELL_DOCKERFILE",
		},
		{
			name:    "image ref",
			env:     "CONTROL_PLANE_NORMAL_SHELL_IMAGE=execution-substrate/control-plane-normal-shell:local",
			snippet: "CONTROL_PLANE_NORMAL_SHELL_IMAGE",
		},
		{
			name:    "codex cli path",
			env:     "CONTROL_PLANE_NORMAL_SHELL_CODEX_CLI_PATH=/tmp/not-codex",
			snippet: "CONTROL_PLANE_NORMAL_SHELL_CODEX_CLI_PATH",
		},
		{
			name:    "realization",
			env:     "CONTROL_PLANE_NORMAL_SHELL_CODEX_REALIZATION=npm",
			snippet: "CONTROL_PLANE_NORMAL_SHELL_CODEX_REALIZATION",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tmpDir := t.TempDir()
			fakeBin := filepath.Join(tmpDir, "bin")
			if err := os.MkdirAll(fakeBin, 0o755); err != nil {
				t.Fatalf("mkdir fake bin: %v", err)
			}

			dockerArgsPath := filepath.Join(tmpDir, "docker-args.txt")
			writeExecutable(t, fakeBin, "docker", fmt.Sprintf(`#!/bin/sh
printf '%%s\n' "$@" > %q
exit 0
`, dockerArgsPath))

			cmd := exec.Command("/bin/bash", filepath.Join(executionSubstrateRepoRoot, remoteAlphaRuntimeImageBuildScript))
			cmd.Dir = executionSubstrateRepoRoot
			cmd.Env = envWithPath(fakeBin, tc.env)
			output, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("expected wrapper failure for %s override, got success\n%s", tc.name, output)
			}
			if !strings.Contains(string(output), tc.snippet) {
				t.Fatalf("expected output to mention %q, got %q", tc.snippet, output)
			}
			if _, statErr := os.Stat(dockerArgsPath); !os.IsNotExist(statErr) {
				t.Fatalf("docker should not be invoked for conflicting override %s; stat err=%v", tc.name, statErr)
			}
		})
	}
}

func containsArg(args []string, flag, want string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == want {
			return true
		}
	}
	return false
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func TestRemoteAlphaRuntimeImageCheckPassWritesSafeSummary(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	setupFakeRuntimeImageCommands(t, fakeBin)

	summaryPath := filepath.Join(tmpDir, "normal-shell-runtime-image-summary.json")
	output, err := runSourcedRuntimeImageHelper(t, envWithPath(fakeBin,
		"REMOTE_ALPHA_SUMMARY_PATH="+summaryPath,
		"REMOTE_ALPHA_TEST_PASSWORDLESS_SUDO_FOR_DS=false",
		"FAKE_DOCKER_IMAGE_PRESENT=1",
		"FAKE_DOCKER_RUN_STDOUT=Python 3.11.2\ngit version 2.39.5\ncodex-proof-shim supported-local-proof-codex-shim/v1\n",
		"FAKE_DOCKER_RUN_EXIT=0",
	), "remote_alpha_runtime_image_check_main")
	if err != nil {
		t.Fatalf("check failed: %v\n%s", err, output)
	}

	summary := readJSONFile(t, summaryPath)
	summaryText := mustRead(t, summaryPath)

	if got := summary["schema_version"]; got != "execution-substrate.remote-alpha.normal-shell-runtime-image-summary.v1" {
		t.Fatalf("unexpected schema version %v", got)
	}

	image := jsonMap(t, summary["image"])
	for field, want := range map[string]any{
		"ref":     remoteAlphaRuntimeImageRef,
		"present": true,
		"os":      "linux",
	} {
		if got := image[field]; got != want {
			t.Fatalf("unexpected image %s=%v want %v", field, got, want)
		}
	}
	if got := fmt.Sprint(image["image_id"]); got != "sha256:test-image" {
		t.Fatalf("unexpected image id %q", got)
	}

	build := jsonMap(t, summary["build"])
	expectedRecipeScriptText := mustRead(t, filepath.Join(executionSubstrateRepoRoot, remoteAlphaRuntimeImageBuildScript))
	expectedRecipeScriptSHA := fmt.Sprintf("%x", sha256.Sum256([]byte(expectedRecipeScriptText)))
	for field, want := range map[string]any{
		"expected_recipe_script":                    remoteAlphaRuntimeImageBuildScript,
		"expected_recipe_script_present":            true,
		"recipe_matches_slice":                      true,
		"codex_realization":                         "proof",
		"codex_credential_posture":                  "no_real_credentials",
		"real_codex_credentials_required_for_build": false,
	} {
		if got := build[field]; got != want {
			t.Fatalf("unexpected build %s=%v want %v", field, got, want)
		}
	}
	if got := fmt.Sprint(build["expected_recipe_script_sha256"]); got != expectedRecipeScriptSHA {
		t.Fatalf("unexpected expected recipe script sha %q", got)
	}
	contextFiles := jsonStringSlice(t, build["build_context_files"])
	if len(contextFiles) < 4 {
		t.Fatalf("unexpected build context files %v", contextFiles)
	}
	if !containsString(contextFiles, remoteAlphaRuntimeImageBuildScript) {
		t.Fatalf("expected build context files to include recipe script, got %v", contextFiles)
	}

	host := jsonMap(t, summary["host"])
	for field, want := range map[string]any{
		"hostname":              "m75q-test",
		"docker_service_active": true,
		"nomad_ready":           true,
	} {
		if got := host[field]; got != want {
			t.Fatalf("unexpected host %s=%v want %v", field, got, want)
		}
	}

	validation := jsonMap(t, summary["validation"])
	if got := validation["image_present"]; got != "pass" {
		t.Fatalf("unexpected image_present %v", got)
	}
	if got := validation["docker_info_ok"]; got != true {
		t.Fatalf("unexpected docker_info_ok %v", got)
	}
	if got := validation["codex_realization_expected"]; got != true {
		t.Fatalf("unexpected codex_realization_expected %v", got)
	}
	minimalRun := jsonMap(t, validation["minimal_container_run"])
	for field, want := range map[string]any{
		"status": "pass",
		"safe":   true,
	} {
		if got := minimalRun[field]; got != want {
			t.Fatalf("unexpected minimal run %s=%v want %v", field, got, want)
		}
	}
	stdoutLines := jsonStringSlice(t, minimalRun["stdout_lines"])
	if len(stdoutLines) != 3 || stdoutLines[2] != "codex-proof-shim supported-local-proof-codex-shim/v1" {
		t.Fatalf("unexpected minimal run stdout lines %v", stdoutLines)
	}

	security := jsonMap(t, summary["security"])
	for field, want := range map[string]any{
		"ds_not_in_docker_group":                     true,
		"passwordless_sudo_for_ds":                   false,
		"no_real_codex_credentials_in_build_context": true,
		"no_api_keys_or_tokens_printed":              true,
	} {
		if got := security[field]; got != want {
			t.Fatalf("unexpected security %s=%v want %v", field, got, want)
		}
	}

	readiness := jsonMap(t, summary["readiness_not_claimed"])
	for field, want := range map[string]string{
		"runtime_profile_ready":        "not_claimed",
		"submit_ready":                 "not_claimed",
		"es_services_healthy":          "not_claimed",
		"producer_contract_compatible": "not_claimed",
		"retained_result_fetch":        "not_claimed",
	} {
		if got := readiness[field]; got != want {
			t.Fatalf("unexpected readiness %s=%v want %v", field, got, want)
		}
	}

	for _, denied := range []string{"eyJ", "hvs.", "sk-", "-----BEGIN "} {
		if strings.Contains(summaryText, denied) {
			t.Fatalf("summary unexpectedly contained denied token %q", denied)
		}
	}
}

func TestRemoteAlphaRuntimeImageCheckRejectsSliceOverrideEnv(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		env     string
		snippet string
	}{
		{
			name:    "runtime image ref",
			env:     "REMOTE_ALPHA_RUNTIME_IMAGE_REF=alternate:image",
			snippet: "REMOTE_ALPHA_RUNTIME_IMAGE_REF",
		},
		{
			name:    "codex cli path",
			env:     "REMOTE_ALPHA_CODEX_CLI_PATH=/tmp/not-codex",
			snippet: "REMOTE_ALPHA_CODEX_CLI_PATH",
		},
		{
			name:    "build script",
			env:     "REMOTE_ALPHA_BUILD_SCRIPT=/tmp/not-recipe.sh",
			snippet: "REMOTE_ALPHA_BUILD_SCRIPT",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tmpDir := t.TempDir()
			fakeBin := filepath.Join(tmpDir, "bin")
			if err := os.MkdirAll(fakeBin, 0o755); err != nil {
				t.Fatalf("mkdir fake bin: %v", err)
			}

			output, err := runSourcedRuntimeImageHelper(t, envWithPath(fakeBin, tc.env), "remote_alpha_runtime_image_check_main")
			if err == nil {
				t.Fatalf("expected slice override rejection for %s, got success\n%s", tc.name, output)
			}
			if !strings.Contains(string(output), tc.snippet) {
				t.Fatalf("expected output to mention %q, got %q", tc.snippet, output)
			}
		})
	}
}

func TestRemoteAlphaRuntimeImageCheckRejectsSliceOverrideFlags(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		body    string
		snippet string
	}{
		{
			name:    "image ref",
			body:    "remote_alpha_runtime_image_check_main --image-ref alternate:image",
			snippet: "--image-ref",
		},
		{
			name:    "codex cli path",
			body:    "remote_alpha_runtime_image_check_main --codex-cli-path /tmp/not-codex",
			snippet: "--codex-cli-path",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			output, err := runSourcedRuntimeImageHelper(t, os.Environ(), tc.body)
			if err == nil {
				t.Fatalf("expected slice flag rejection for %s, got success\n%s", tc.name, output)
			}
			if !strings.Contains(string(output), tc.snippet) {
				t.Fatalf("expected output to mention %q, got %q", tc.snippet, output)
			}
		})
	}
}

func TestRemoteAlphaRuntimeImageCheckFailsHonestlyWhenImageIsMissing(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	setupFakeRuntimeImageCommands(t, fakeBin)

	summaryPath := filepath.Join(tmpDir, "normal-shell-runtime-image-summary.json")
	output, err := runSourcedRuntimeImageHelper(t, envWithPath(fakeBin,
		"REMOTE_ALPHA_SUMMARY_PATH="+summaryPath,
		"REMOTE_ALPHA_TEST_PASSWORDLESS_SUDO_FOR_DS=false",
		"FAKE_DOCKER_IMAGE_PRESENT=0",
		"FAKE_DOCKER_RUN_STDERR=unexpected docker run",
		"FAKE_DOCKER_RUN_EXIT=64",
	), "remote_alpha_runtime_image_check_main")
	if err == nil {
		t.Fatalf("expected missing-image failure, got success\n%s", output)
	}

	summary := readJSONFile(t, summaryPath)

	image := jsonMap(t, summary["image"])
	if got := image["present"]; got != false {
		t.Fatalf("unexpected image presence %v", got)
	}

	validation := jsonMap(t, summary["validation"])
	if got := validation["image_present"]; got != "fail" {
		t.Fatalf("unexpected image_present %v", got)
	}
	minimalRun := jsonMap(t, validation["minimal_container_run"])
	if got := minimalRun["status"]; got != "not_exercised" {
		t.Fatalf("unexpected minimal run status %v", got)
	}

	readiness := jsonMap(t, summary["readiness_not_claimed"])
	for field, want := range map[string]string{
		"runtime_profile_ready":        "not_claimed",
		"submit_ready":                 "not_claimed",
		"es_services_healthy":          "not_claimed",
		"producer_contract_compatible": "not_claimed",
		"retained_result_fetch":        "not_claimed",
	} {
		if got := readiness[field]; got != want {
			t.Fatalf("unexpected readiness %s=%v want %v", field, got, want)
		}
	}

	failureReasons, ok := summary["failure_reasons"].([]any)
	if !ok {
		t.Fatalf("unexpected failure reasons payload %T", summary["failure_reasons"])
	}
	joined := make([]string, 0, len(failureReasons))
	for _, item := range failureReasons {
		joined = append(joined, fmt.Sprint(item))
	}
	if !strings.Contains(strings.Join(joined, " | "), "runtime image is not present") {
		t.Fatalf("expected missing image reason, got %v", joined)
	}
}

func TestRemoteAlphaRuntimeImageCheckFailsWhenExpectedRecipeScriptIsMissing(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	setupFakeRuntimeImageCommands(t, fakeBin)

	tempRepoRoot := filepath.Join(tmpDir, "repo")
	for _, rel := range []string{
		"scripts/build_control_plane_normal_shell_image.sh",
		"es/runtimeprofiles/control_plane_normal_shell/Dockerfile",
		"es/runtimeprofiles/control_plane_normal_shell/proof-codex-shim.py",
		".dockerignore",
	} {
		targetPath := filepath.Join(tempRepoRoot, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", rel, err)
		}
		if err := os.WriteFile(targetPath, []byte(mustRead(t, filepath.Join(executionSubstrateRepoRoot, filepath.FromSlash(rel)))), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}

	summaryPath := filepath.Join(tmpDir, "normal-shell-runtime-image-summary.json")
	output, err := runSourcedRuntimeImageHelper(t, envWithPath(fakeBin,
		"REPO_ROOT="+tempRepoRoot,
		"REMOTE_ALPHA_SUMMARY_PATH="+summaryPath,
		"REMOTE_ALPHA_TEST_PASSWORDLESS_SUDO_FOR_DS=false",
		"FAKE_DOCKER_IMAGE_PRESENT=1",
		"FAKE_DOCKER_RUN_STDOUT=Python 3.11.2\ngit version 2.39.5\ncodex-proof-shim supported-local-proof-codex-shim/v1\n",
		"FAKE_DOCKER_RUN_EXIT=0",
	), "remote_alpha_runtime_image_check_main")
	if err == nil {
		t.Fatalf("expected missing recipe script failure, got success\n%s", output)
	}

	summary := readJSONFile(t, summaryPath)
	build := jsonMap(t, summary["build"])
	if got := build["expected_recipe_script"]; got != remoteAlphaRuntimeImageBuildScript {
		t.Fatalf("unexpected expected_recipe_script %v", got)
	}
	if got := build["expected_recipe_script_present"]; got != false {
		t.Fatalf("unexpected expected_recipe_script_present %v", got)
	}
	if got := build["recipe_matches_slice"]; got != false {
		t.Fatalf("unexpected recipe_matches_slice %v", got)
	}

	failureReasons, ok := summary["failure_reasons"].([]any)
	if !ok {
		t.Fatalf("unexpected failure reasons payload %T", summary["failure_reasons"])
	}
	joined := make([]string, 0, len(failureReasons))
	for _, item := range failureReasons {
		joined = append(joined, fmt.Sprint(item))
	}
	if !strings.Contains(strings.Join(joined, " | "), "expected recipe script is missing") {
		t.Fatalf("expected missing recipe script reason, got %v", joined)
	}
}

func TestRemoteAlphaRuntimeImageCheckFailsWhenProofPostureIsNotProved(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	setupFakeRuntimeImageCommands(t, fakeBin)

	summaryPath := filepath.Join(tmpDir, "normal-shell-runtime-image-summary.json")
	output, err := runSourcedRuntimeImageHelper(t, envWithPath(fakeBin,
		"REMOTE_ALPHA_SUMMARY_PATH="+summaryPath,
		"REMOTE_ALPHA_TEST_PASSWORDLESS_SUDO_FOR_DS=false",
		"FAKE_DOCKER_IMAGE_PRESENT=1",
		"FAKE_DOCKER_RUN_STDOUT=Python 3.11.2\ngit version 2.39.5\ncodex 0.1.0\n",
		"FAKE_DOCKER_RUN_EXIT=0",
	), "remote_alpha_runtime_image_check_main")
	if err == nil {
		t.Fatalf("expected non-proof posture failure, got success\n%s", output)
	}

	summary := readJSONFile(t, summaryPath)
	build := jsonMap(t, summary["build"])
	if got := build["codex_realization"]; got != "unknown" {
		t.Fatalf("unexpected codex realization %v", got)
	}
	if got := build["codex_credential_posture"]; got != "undetermined" {
		t.Fatalf("unexpected codex credential posture %v", got)
	}
	validation := jsonMap(t, summary["validation"])
	if got := validation["codex_realization_expected"]; got != false {
		t.Fatalf("unexpected codex_realization_expected %v", got)
	}
}

func TestRemoteAlphaRuntimeImageCheckRejectsPlaceholderPosture(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	setupFakeRuntimeImageCommands(t, fakeBin)

	summaryPath := filepath.Join(tmpDir, "normal-shell-runtime-image-summary.json")
	output, err := runSourcedRuntimeImageHelper(t, envWithPath(fakeBin,
		"REMOTE_ALPHA_SUMMARY_PATH="+summaryPath,
		"REMOTE_ALPHA_TEST_PASSWORDLESS_SUDO_FOR_DS=false",
		"FAKE_DOCKER_IMAGE_PRESENT=1",
		"FAKE_DOCKER_RUN_STDOUT=Python 3.11.2\ngit version 2.39.5\ncodex-placeholder supported-local-placeholder-codex/v1\n",
		"FAKE_DOCKER_RUN_EXIT=0",
	), "remote_alpha_runtime_image_check_main")
	if err == nil {
		t.Fatalf("expected placeholder posture failure, got success\n%s", output)
	}

	summary := readJSONFile(t, summaryPath)
	build := jsonMap(t, summary["build"])
	if got := build["codex_realization"]; got != "placeholder" {
		t.Fatalf("unexpected codex realization %v", got)
	}
	if got := build["codex_credential_posture"]; got != "undetermined" {
		t.Fatalf("unexpected codex credential posture %v", got)
	}
	validation := jsonMap(t, summary["validation"])
	if got := validation["codex_realization_expected"]; got != false {
		t.Fatalf("unexpected codex_realization_expected %v", got)
	}
}

func TestRemoteAlphaRuntimeImageValidateSummaryRejectsSecretLikeMaterial(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	summaryPath := filepath.Join(tmpDir, "summary.json")
	secretSummary := `{"schema_version":"execution-substrate.remote-alpha.normal-shell-runtime-image-summary.v1","token":"hvs.secretmaterial123456","api_key":"sk-123456789012345678901234"}`
	if err := os.WriteFile(summaryPath, []byte(secretSummary), 0o600); err != nil {
		t.Fatalf("write summary: %v", err)
	}

	output, err := runSourcedRuntimeImageHelper(t, os.Environ(), fmt.Sprintf("remote_alpha_runtime_image_validate_summary_file %q", summaryPath))
	if err == nil {
		t.Fatalf("expected validator to fail for secret-like material")
	}
	if !strings.Contains(string(output), "summary contains secret-like material") {
		t.Fatalf("unexpected validator output %q", output)
	}
}
