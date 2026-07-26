package executionsubstrate_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type esBinaryDeploymentFixture struct {
	RepoRoot         string
	PayloadDir       string
	LiveESBinaryPath string
	LiveRuntimePath  string
	ConfigPath       string
	HealthEnvPath    string
	ServiceUnitPath  string
	MutationLogPath  string
}

func runSourcedESBinaryDeploymentHelper(t *testing.T, env []string, shellBody string) ([]byte, error) {
	t.Helper()
	helperPath := filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_deploy_es_binaries.sh")
	script := fmt.Sprintf("set -euo pipefail\nsource %q\n%s\n", helperPath, shellBody)
	cmd := exec.Command("/bin/bash", "-c", script)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = env
	return cmd.CombinedOutput()
}

func esBinaryDeploymentExpectedSliceShell(f esBinaryDeploymentFixture) string {
	return fmt.Sprintf(`
export REPO_ROOT=%q
remote_alpha_deploy_es_binaries_expected_binary_path=%q
remote_alpha_deploy_es_binaries_expected_runtime_support_path=%q
remote_alpha_deploy_es_binaries_expected_config_path=%q
remote_alpha_deploy_es_binaries_expected_healthcheck_env_path=%q
remote_alpha_deploy_es_binaries_expected_service_unit_path=%q
`, f.RepoRoot, f.LiveESBinaryPath, f.LiveRuntimePath, f.ConfigPath, f.HealthEnvPath, f.ServiceUnitPath)
}

func setupESBinaryDeploymentFixture(t *testing.T, tmpDir string) esBinaryDeploymentFixture {
	t.Helper()

	repoRoot := filepath.Join(tmpDir, "repo")
	payloadDir := filepath.Join(repoRoot, "payload")
	liveES := filepath.Join(tmpDir, "live", "bin", "es")
	liveRuntime := filepath.Join(tmpDir, "live", "bin", "es-runtime-support")
	configPath := filepath.Join(tmpDir, "config", "es.json")
	healthEnvPath := filepath.Join(tmpDir, "config", "healthcheck.env")
	serviceUnitPath := filepath.Join(tmpDir, "systemd", "es.service")
	mutationLogPath := filepath.Join(tmpDir, "mutations.log")

	for _, dir := range []string{
		payloadDir,
		filepath.Dir(liveES),
		filepath.Dir(configPath),
		filepath.Dir(serviceUnitPath),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	if err := os.WriteFile(filepath.Join(payloadDir, "es"), []byte("new es payload\n"), 0o755); err != nil {
		t.Fatalf("write payload es: %v", err)
	}
	if err := os.WriteFile(filepath.Join(payloadDir, "es-runtime-support"), []byte("new runtime payload\n"), 0o755); err != nil {
		t.Fatalf("write payload runtime support: %v", err)
	}
	buildProvenance := map[string]any{
		"source_kind":      "staged_payload",
		"git_commit":       "002b4d8c2f2484bb5d2b2dcc12134c8a145bc7bd",
		"dirty_worktree":   true,
		"git_status_short": []string{" M scripts/internal/remote_alpha_deploy_es_binaries.sh"},
	}
	buildProvenanceBytes, err := json.MarshalIndent(buildProvenance, "", "  ")
	if err != nil {
		t.Fatalf("marshal build provenance: %v", err)
	}
	if err := os.WriteFile(filepath.Join(payloadDir, "build-provenance.json"), append(buildProvenanceBytes, '\n'), 0o644); err != nil {
		t.Fatalf("write build provenance: %v", err)
	}

	if err := os.WriteFile(liveES, []byte("old es live binary\n"), 0o755); err != nil {
		t.Fatalf("write live es: %v", err)
	}
	if err := os.WriteFile(liveRuntime, []byte("old runtime live binary\n"), 0o755); err != nil {
		t.Fatalf("write live runtime support: %v", err)
	}

	configPayload := map[string]any{
		"http": map[string]any{
			"bind_address": "127.0.0.1",
			"port":         8445,
		},
	}
	configBytes, err := json.MarshalIndent(configPayload, "", "  ")
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(configPath, append(configBytes, '\n'), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	healthEnv := "CA_CERT=/tmp/ca.pem\nOPERATOR_CERT=/tmp/op.pem\nOPERATOR_KEY=/tmp/op.key\n"
	if err := os.WriteFile(healthEnvPath, []byte(healthEnv), 0o600); err != nil {
		t.Fatalf("write health env: %v", err)
	}
	if err := os.WriteFile(serviceUnitPath, []byte("[Service]\nExecStart=/placeholder\n"), 0o644); err != nil {
		t.Fatalf("write service unit: %v", err)
	}

	return esBinaryDeploymentFixture{
		RepoRoot:         repoRoot,
		PayloadDir:       payloadDir,
		LiveESBinaryPath: liveES,
		LiveRuntimePath:  liveRuntime,
		ConfigPath:       configPath,
		HealthEnvPath:    healthEnvPath,
		ServiceUnitPath:  serviceUnitPath,
		MutationLogPath:  mutationLogPath,
	}
}

func setupFakeESBinaryDeploymentCommands(t *testing.T, dir string, fixture esBinaryDeploymentFixture) {
	t.Helper()

	writeExecutable(t, dir, "id", `#!/bin/sh
if [ "$1" = "-u" ] && [ $# -eq 1 ]; then
  echo 0
  exit 0
fi
exec /usr/bin/id "$@"
`)

	writeExecutable(t, dir, "systemctl", fmt.Sprintf(`#!/bin/sh
case "$1" in
  restart)
    if [ -n "${REMOTE_ALPHA_TEST_MUTATION_LOG_PATH:-}" ]; then
      printf '%%s\n' "systemctl restart" >> "${REMOTE_ALPHA_TEST_MUTATION_LOG_PATH}"
    fi
    exit 0
    ;;
  show)
    user="${REMOTE_ALPHA_TEST_SYSTEMCTL_USER:-es}"
    group="${REMOTE_ALPHA_TEST_SYSTEMCTL_GROUP:-es}"
    cat <<EOF
ExecStart={ path=%s ; argv[]=%s -config %s ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
User=$user
Group=$group
ActiveState=%s
SubState=%s
FragmentPath=%s
DropInPaths=
EOF
    exit 0
    ;;
esac
exit 1
`, fixture.LiveESBinaryPath, fixture.LiveESBinaryPath, fixture.ConfigPath, "${REMOTE_ALPHA_TEST_SYSTEMCTL_ACTIVE_STATE:-active}", "${REMOTE_ALPHA_TEST_SYSTEMCTL_SUB_STATE:-running}", fixture.ServiceUnitPath))

	writeExecutable(t, dir, "curl", `#!/bin/sh
url=""
for arg in "$@"; do
  case "$arg" in
    http://*|https://*)
      url="$arg"
      ;;
  esac
done
case "$url" in
  https://127.0.0.1:8445/health)
    cat <<'EOF'
{"status":"healthy","ready":true}
EOF
    ;;
  https://127.0.0.1:8445/v1/executions:contract)
    cat <<'EOF'
{"schema_version":"execution-substrate.producer-contract/v1"}
EOF
    ;;
  *)
    echo "unexpected curl url: $url" >&2
    exit 1
    ;;
esac
`)
}

func parseESBinaryDeploymentOutput(t *testing.T, output []byte) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(output, &payload); err != nil {
		t.Fatalf("decode binary deployment helper output: %v\noutput=%s", err, string(output))
	}
	return payload
}

func TestRemoteAlphaESBinaryDeploymentStageSudoUnavailableIsStructured(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	sshLogPath := filepath.Join(tmpDir, "ssh.log")
	scpLogPath := filepath.Join(tmpDir, "scp.log")
	writeExecutable(t, fakeBin, "ssh", fmt.Sprintf(`#!/bin/sh
printf '%%s\n' "$*" >> %q
exit 1
`, sshLogPath))
	writeExecutable(t, fakeBin, "scp", fmt.Sprintf(`#!/bin/sh
printf '%%s\n' "$*" >> %q
exit 0
`, scpLogPath))
	writeExecutable(t, fakeBin, "go", `#!/bin/sh
if [ "$1" = "version" ]; then
  echo "go version go1.26.5 linux/amd64"
  exit 0
fi
exit 0
`)

	outputDir := filepath.Join(tmpDir, "output")
	shellBody := fmt.Sprintf(`
remote_alpha_deploy_es_binaries_stage_make_local_payload_tree() {
  local payload_dir=$1
  mkdir -p "$payload_dir"
  printf 'es\n' > "$payload_dir/es"
  printf 'runtime\n' > "$payload_dir/es-runtime-support"
  printf '{}\n' > "$payload_dir/build-provenance.json"
}
remote_alpha_deploy_es_binaries_stage_main --ssh-target fake-target --run-id sudo-unavailable --output-dir %q
`, outputDir)
	output, err := runSourcedESBinaryDeploymentHelper(t, envWithPath(fakeBin), shellBody)
	if err == nil {
		t.Fatalf("expected noninteractive sudo preflight failure\noutput=%q", output)
	}

	if _, err := os.Stat(scpLogPath); !os.IsNotExist(err) {
		t.Fatalf("scp should not run when sudo preflight fails: %v", err)
	}
	provenance := readJSONFile(t, filepath.Join(outputDir, "es-binary-deployment-helper-staging-record.json"))
	if got := provenance["staging_occurred"]; got != false {
		t.Fatalf("expected staging_occurred=false, got %v", got)
	}
	if got := provenance["checker_ran"]; got != false {
		t.Fatalf("expected checker_ran=false, got %v", got)
	}
	if got := provenance["sudo_unavailable"]; got != true {
		t.Fatalf("expected sudo_unavailable=true, got %v", got)
	}
	if got := provenance["wrapper_tooling_error"]; got != false {
		t.Fatalf("expected wrapper_tooling_error=false, got %v", got)
	}
	if got := provenance["failure_classification"]; got != "sudo_unavailable" {
		t.Fatalf("expected failure_classification=sudo_unavailable, got %v", got)
	}
	if got := provenance["sudo_or_preflight_blocker"]; got == "" {
		t.Fatalf("expected sudo_or_preflight_blocker to be recorded, got %v", got)
	}
}

func TestRemoteAlphaESBinaryDeploymentCheckOnlyIsDefaultAndNonMutating(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	fixture := setupESBinaryDeploymentFixture(t, tmpDir)
	setupFakeESBinaryDeploymentCommands(t, fakeBin, fixture)

	shellBody := esBinaryDeploymentExpectedSliceShell(fixture) + `
remote_alpha_deploy_es_binaries_main
`
	output, err := runSourcedESBinaryDeploymentHelper(t, envWithPath(fakeBin), shellBody)
	if err != nil {
		t.Fatalf("helper failed: %v\noutput=%s", err, string(output))
	}

	payload := parseESBinaryDeploymentOutput(t, output)
	mode := nestedMap(t, payload, "mode")
	proof := nestedMap(t, payload, "proof")
	plan := nestedMap(t, payload, "plan")
	if mode["name"] != "check_only" || mode["non_mutating"] != true {
		t.Fatalf("unexpected mode payload: %+v", mode)
	}
	if proof["host_mutation_performed"] != false {
		t.Fatalf("expected host_mutation_performed=false, got %+v", proof)
	}
	if plan["deployment_needed"] != true {
		t.Fatalf("expected deployment_needed=true, got %v", plan["deployment_needed"])
	}
	if payload["overall_classification"] != "warning" {
		t.Fatalf("expected warning classification, got %v", payload["overall_classification"])
	}
	if got := nestedMap(t, payload, "validation")["es_service_posture"]; got == nil {
		t.Fatalf("expected service posture validation, got nil")
	}
	if got := nestedMap(t, payload, "not_claimed")["service_user_change"]; got != true {
		t.Fatalf("expected not_claimed.service_user_change=true, got %v", got)
	}
	if _, err := os.Stat(fixture.MutationLogPath); !os.IsNotExist(err) {
		t.Fatalf("mutation log should not exist in check-only mode")
	}
}

func TestRemoteAlphaESBinaryDeploymentApplyReplacesOnlyPinnedBinariesAndRestartsOnce(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	fixture := setupESBinaryDeploymentFixture(t, tmpDir)
	setupFakeESBinaryDeploymentCommands(t, fakeBin, fixture)

	originalConfigBytes, err := os.ReadFile(fixture.ConfigPath)
	if err != nil {
		t.Fatalf("read original config: %v", err)
	}
	originalServiceUnitBytes, err := os.ReadFile(fixture.ServiceUnitPath)
	if err != nil {
		t.Fatalf("read original service unit: %v", err)
	}

	summaryPath := filepath.Join(tmpDir, "apply-summary.json")
	shellBody := esBinaryDeploymentExpectedSliceShell(fixture) + fmt.Sprintf(`
remote_alpha_deploy_es_binaries_main --apply --summary-path %q
`, summaryPath)
	output, err := runSourcedESBinaryDeploymentHelper(
		t,
		envWithPath(
			fakeBin,
			"REMOTE_ALPHA_TEST_MUTATION_LOG_PATH="+fixture.MutationLogPath,
			"REMOTE_ALPHA_TEST_BACKUP_ROOT="+filepath.Join(tmpDir, "backup-root"),
		),
		shellBody,
	)
	if err != nil {
		t.Fatalf("apply helper failed: %v\noutput=%s", err, string(output))
	}

	summaryBytes, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatalf("read apply summary: %v", err)
	}
	payload := parseESBinaryDeploymentOutput(t, summaryBytes)
	if payload["overall_classification"] != "pass" {
		t.Fatalf("expected overall pass, got %v\noutput=%s", payload["overall_classification"], string(summaryBytes))
	}
	proof := nestedMap(t, payload, "proof")
	if proof["host_mutation_performed"] != true {
		t.Fatalf("expected host mutation performed, got %+v", proof)
	}
	if changed, ok := payload["changed_paths"].([]any); !ok || len(changed) != 2 {
		t.Fatalf("expected exactly 2 changed paths, got %T %+v", payload["changed_paths"], payload["changed_paths"])
	}
	backup := nestedMap(t, payload, "backup")
	backupPath, _ := backup["path"].(string)
	if backupPath == "" {
		t.Fatalf("expected backup path, got %+v", backup)
	}
	if _, err := os.Stat(filepath.Join(backupPath, "es.pre-apply")); err != nil {
		t.Fatalf("expected pre-apply es backup: %v", err)
	}
	if _, err := os.Stat(filepath.Join(backupPath, "es-runtime-support.pre-apply")); err != nil {
		t.Fatalf("expected pre-apply runtime-support backup: %v", err)
	}
	rollbackNotes, ok := backup["rollback_notes"].([]any)
	if !ok || len(rollbackNotes) == 0 {
		t.Fatalf("expected rollback notes, got %+v", backup["rollback_notes"])
	}

	liveESBytes, err := os.ReadFile(fixture.LiveESBinaryPath)
	if err != nil {
		t.Fatalf("read live es after apply: %v", err)
	}
	if string(liveESBytes) != "new es payload\n" {
		t.Fatalf("unexpected live es content after apply: %q", string(liveESBytes))
	}
	liveRuntimeBytes, err := os.ReadFile(fixture.LiveRuntimePath)
	if err != nil {
		t.Fatalf("read live runtime support after apply: %v", err)
	}
	if string(liveRuntimeBytes) != "new runtime payload\n" {
		t.Fatalf("unexpected live runtime support content after apply: %q", string(liveRuntimeBytes))
	}

	configBytes, err := os.ReadFile(fixture.ConfigPath)
	if err != nil {
		t.Fatalf("read config after apply: %v", err)
	}
	if string(configBytes) != string(originalConfigBytes) {
		t.Fatalf("config changed unexpectedly during binary apply")
	}
	serviceUnitBytes, err := os.ReadFile(fixture.ServiceUnitPath)
	if err != nil {
		t.Fatalf("read service unit after apply: %v", err)
	}
	if string(serviceUnitBytes) != string(originalServiceUnitBytes) {
		t.Fatalf("service unit changed unexpectedly during binary apply")
	}

	postApply := nestedMap(t, payload, "post_apply_validation")
	posture := nestedMap(t, postApply, "es_service_posture")
	if posture["effective_user"] != "es" || posture["effective_group"] != "es" {
		t.Fatalf("expected es:es posture after apply, got %+v", posture)
	}
	if nestedMap(t, postApply, "health")["classification"] != "pass" {
		t.Fatalf("expected health validation pass, got %+v", nestedMap(t, postApply, "health"))
	}
	if nestedMap(t, postApply, "contract")["classification"] != "pass" {
		t.Fatalf("expected contract validation pass, got %+v", nestedMap(t, postApply, "contract"))
	}

	mutationLogBytes, err := os.ReadFile(fixture.MutationLogPath)
	if err != nil {
		t.Fatalf("read mutation log: %v", err)
	}
	if got := strings.Count(string(mutationLogBytes), "systemctl restart"); got != 1 {
		t.Fatalf("expected exactly one restart, got %d in %q", got, string(mutationLogBytes))
	}
}

func TestRemoteAlphaESBinaryDeploymentApplyPreservesAcceptedCurrentESServiceUserPosture(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	fixture := setupESBinaryDeploymentFixture(t, tmpDir)
	setupFakeESBinaryDeploymentCommands(t, fakeBin, fixture)

	summaryPath := filepath.Join(tmpDir, "apply-summary.json")
	shellBody := esBinaryDeploymentExpectedSliceShell(fixture) + fmt.Sprintf(`
remote_alpha_deploy_es_binaries_main --apply --summary-path %q
`, summaryPath)
	output, err := runSourcedESBinaryDeploymentHelper(
		t,
		envWithPath(
			fakeBin,
			"REMOTE_ALPHA_TEST_MUTATION_LOG_PATH="+fixture.MutationLogPath,
			"REMOTE_ALPHA_TEST_BACKUP_ROOT="+filepath.Join(tmpDir, "backup-root"),
			"REMOTE_ALPHA_TEST_SYSTEMCTL_USER=es",
			"REMOTE_ALPHA_TEST_SYSTEMCTL_GROUP=es",
		),
		shellBody,
	)
	if err != nil {
		t.Fatalf("apply helper failed: %v\noutput=%s", err, string(output))
	}

	summaryBytes, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatalf("read apply summary: %v", err)
	}
	payload := parseESBinaryDeploymentOutput(t, summaryBytes)
	if payload["overall_classification"] != "pass" {
		t.Fatalf("expected overall pass, got %v\noutput=%s", payload["overall_classification"], string(summaryBytes))
	}
	postApply := nestedMap(t, payload, "post_apply_validation")
	posture := nestedMap(t, postApply, "es_service_posture")
	if posture["effective_user"] != "es" || posture["effective_group"] != "es" {
		t.Fatalf("expected es:es posture after apply, got %+v", posture)
	}

	mutationLogBytes, err := os.ReadFile(fixture.MutationLogPath)
	if err != nil {
		t.Fatalf("read mutation log: %v", err)
	}
	if got := strings.Count(string(mutationLogBytes), "systemctl restart"); got != 1 {
		t.Fatalf("expected exactly one restart, got %d in %q", got, string(mutationLogBytes))
	}
}

func TestRemoteAlphaESBinaryDeploymentBlocksWhenServicePostureIsNotAccepted(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	fixture := setupESBinaryDeploymentFixture(t, tmpDir)
	setupFakeESBinaryDeploymentCommands(t, fakeBin, fixture)

	shellBody := esBinaryDeploymentExpectedSliceShell(fixture) + `
remote_alpha_deploy_es_binaries_main
`
	output, err := runSourcedESBinaryDeploymentHelper(
		t,
		envWithPath(
			fakeBin,
			"REMOTE_ALPHA_TEST_SYSTEMCTL_ACTIVE_STATE=active",
			"REMOTE_ALPHA_TEST_SYSTEMCTL_SUB_STATE=running",
			"REMOTE_ALPHA_TEST_SYSTEMCTL_USER=root",
			"REMOTE_ALPHA_TEST_SYSTEMCTL_GROUP=root",
		),
		shellBody,
	)
	if err == nil {
		t.Fatalf("expected helper to fail when service posture is not the current supported es:es posture, output=%s", string(output))
	}
}
