package scripts_test

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
	// ConfigCheckLog holds one line per run of a payload config check:
	// its name and the config it judged.
	ConfigCheckLog string
}

// esBinaryDeploymentConfigChecks are the payload's config checks and the
// configs they judge, next to es.json.
var esBinaryDeploymentConfigChecks = []struct{ checker, config string }{
	{"esconfigcheck", "es.json"},
	{"agsconfigcheck", "ags.json"},
	{"egsconfigcheck", "egs.json"},
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
	// The fake config checks log each run, and refuse a config next to which
	// a test put <config>.refuse, as the real ones refuse a config their
	// service would not start with.
	configCheckLog := filepath.Join(tmpDir, "config-checks.log")
	for _, c := range esBinaryDeploymentConfigChecks {
		service := strings.TrimSuffix(c.config, ".json")
		script := fmt.Sprintf(`#!/bin/sh
printf '%%s %%s\n' %q "$1" >> %q
if [ -e "$1.refuse" ]; then
  echo "%s config refused: decode config: the test refuses it" >&2
  exit 1
fi
echo "%s config accepted"
`, c.checker, configCheckLog, service, service)
		if err := os.WriteFile(filepath.Join(payloadDir, c.checker), []byte(script), 0o755); err != nil {
			t.Fatalf("write payload %s: %v", c.checker, err)
		}
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
		ConfigCheckLog:   configCheckLog,
	}
}

// requireConfigChecksRan fails unless each payload config check ran exactly
// once, on the config next to es.json that it judges.
func requireConfigChecksRan(t *testing.T, f esBinaryDeploymentFixture) {
	t.Helper()
	var want []string
	for _, c := range esBinaryDeploymentConfigChecks {
		want = append(want, c.checker+" "+filepath.Join(filepath.Dir(f.ConfigPath), c.config))
	}
	if got := strings.TrimSpace(readIfExists(f.ConfigCheckLog)); got != strings.Join(want, "\n") {
		t.Fatalf("config checks ran as\n%s\nwant\n%s", got, strings.Join(want, "\n"))
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
  printf 'check\n' > "$payload_dir/esconfigcheck"
  printf 'check\n' > "$payload_dir/agsconfigcheck"
  printf 'check\n' > "$payload_dir/egsconfigcheck"
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
	requireConfigChecksRan(t, fixture)
	checks := nestedMap(t, nestedMap(t, payload, "validation"), "config_checks")
	for _, service := range []string{"es", "ags", "egs"} {
		if got := nestedMap(t, checks, service)["classification"]; got != "pass" {
			t.Fatalf("config check of %s: %v", service, nestedMap(t, checks, service))
		}
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
	requireConfigChecksRan(t, fixture)
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

// TestRemoteAlphaESBinaryDeploymentStopsOnAConfigTheNewBinariesRefuse: the
// ES, AGS and EGS of the payload's tree refuse a config the running ones
// accepted, such as one still on the repository's published signing keys
// (.docs/system_overview/contracts.md, section 3B). When any of the three
// config checks refuses its config, check-only names it as a blocker, and
// apply installs nothing and restarts nothing. A payload without its config
// checks is refused the same way.
func TestRemoteAlphaESBinaryDeploymentStopsOnAConfigTheNewBinariesRefuse(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		setup func(t *testing.T, f esBinaryDeploymentFixture)
		scope string
		want  string
	}{}
	for _, c := range esBinaryDeploymentConfigChecks {
		c := c
		service := strings.TrimSuffix(c.config, ".json")
		cases = append(cases, struct {
			name  string
			setup func(t *testing.T, f esBinaryDeploymentFixture)
			scope string
			want  string
		}{"the new " + service + " refuses " + c.config, func(t *testing.T, f esBinaryDeploymentFixture) {
			if err := os.WriteFile(filepath.Join(filepath.Dir(f.ConfigPath), c.config+".refuse"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}, service + "_config_check", "the new " + service + " would refuse " + string(filepath.Separator) + filepath.Join("config", c.config) +
			", so nothing is installed: " + service + " config refused: decode config: the test refuses it"})
	}
	cases = append(cases, struct {
		name  string
		setup func(t *testing.T, f esBinaryDeploymentFixture)
		scope string
		want  string
	}{"the payload has no AGS config check", func(t *testing.T, f esBinaryDeploymentFixture) {
		if err := os.Remove(filepath.Join(f.PayloadDir, "agsconfigcheck")); err != nil {
			t.Fatal(err)
		}
	}, "local_payload", "staged payload config checks are missing from the sealed helper payload directory: agsconfigcheck"})

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for _, mode := range []string{"check-only", "apply"} {
				tmpDir := t.TempDir()
				fakeBin := filepath.Join(tmpDir, "bin")
				if err := os.MkdirAll(fakeBin, 0o755); err != nil {
					t.Fatal(err)
				}
				fixture := setupESBinaryDeploymentFixture(t, tmpDir)
				setupFakeESBinaryDeploymentCommands(t, fakeBin, fixture)
				tc.setup(t, fixture)
				// Both modes get a summary path in the test's folder: the
				// default one is under /var/tmp, which macOS reaches through
				// a symbolic link that the output folder check refuses.
				summaryPath := filepath.Join(tmpDir, "apply-summary.json")
				args := fmt.Sprintf("--summary-path %q", summaryPath)
				if mode == "apply" {
					args = "--apply " + args
				}
				output, err := runSourcedESBinaryDeploymentHelper(t, envWithPath(fakeBin,
					"REMOTE_ALPHA_TEST_MUTATION_LOG_PATH="+fixture.MutationLogPath,
					"REMOTE_ALPHA_TEST_BACKUP_ROOT="+filepath.Join(tmpDir, "backup-root"),
				), esBinaryDeploymentExpectedSliceShell(fixture)+"remote_alpha_deploy_es_binaries_main "+args+"\n")
				if err == nil {
					t.Fatalf("%s passed with a config the new binaries refuse:\n%s", mode, output)
				}
				report := output
				if mode == "apply" {
					if report, err = os.ReadFile(summaryPath); err != nil {
						t.Fatalf("apply wrote no summary: %v\n%s", err, output)
					}
				}
				payload := parseESBinaryDeploymentOutput(t, report)
				found := false
				for _, raw := range payload["blockers"].([]any) {
					blocker := raw.(map[string]any)
					summary := strings.Replace(fmt.Sprint(blocker["summary"]), tmpDir, "", 1)
					if blocker["scope"] == tc.scope && strings.Contains(summary, tc.want) {
						found = true
					}
				}
				if !found {
					t.Fatalf("%s: no %s blocker saying %q in %v", mode, tc.scope, tc.want, payload["blockers"])
				}
				if live, _ := os.ReadFile(fixture.LiveESBinaryPath); string(live) != "old es live binary\n" {
					t.Fatalf("%s installed the es binary: %q", mode, live)
				}
				if live, _ := os.ReadFile(fixture.LiveRuntimePath); string(live) != "old runtime live binary\n" {
					t.Fatalf("%s installed the runtime support binary: %q", mode, live)
				}
				if _, err := os.Stat(fixture.MutationLogPath); !os.IsNotExist(err) {
					t.Fatalf("%s restarted the service: %s", mode, readIfExists(fixture.MutationLogPath))
				}
				if backups, _ := filepath.Glob(filepath.Join(tmpDir, "backup-root", "es-binary-deployment-*")); len(backups) != 0 {
					t.Fatalf("%s made a backup: %v", mode, backups)
				}
			}
		})
	}
}

// runESBinaryDeploymentCheckOnly runs the deployment in check-only mode
// after mutate has changed the fixture, and returns its report.
func runESBinaryDeploymentCheckOnly(t *testing.T, mutate func(t *testing.T, f esBinaryDeploymentFixture), extraEnv ...string) map[string]any {
	t.Helper()
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatal(err)
	}
	fixture := setupESBinaryDeploymentFixture(t, tmpDir)
	setupFakeESBinaryDeploymentCommands(t, fakeBin, fixture)
	mutate(t, fixture)
	summaryPath := filepath.Join(tmpDir, "check-summary.json")
	output, _ := runSourcedESBinaryDeploymentHelper(t, envWithPath(fakeBin, extraEnv...),
		esBinaryDeploymentExpectedSliceShell(fixture)+fmt.Sprintf("remote_alpha_deploy_es_binaries_main --summary-path %q\n", summaryPath))
	return parseESBinaryDeploymentOutput(t, output)
}

// A staged config check that is there but cannot run is a blocker, not a
// pass (Sonnet shadow audit D08; a check missing from the payload is
// another branch, tested above).
func TestRemoteAlphaESBinaryDeploymentConfigCheckThatCannotRunIsABlocker(t *testing.T) {
	t.Parallel()
	payload := runESBinaryDeploymentCheckOnly(t, func(t *testing.T, f esBinaryDeploymentFixture) {
		if err := os.Chmod(filepath.Join(f.PayloadDir, "agsconfigcheck"), 0o644); err != nil {
			t.Fatal(err)
		}
	})
	ags := nestedMap(t, nestedMap(t, nestedMap(t, payload, "validation"), "config_checks"), "ags")
	if ags["classification"] != "blocker" || !strings.Contains(fmt.Sprint(ags["summary"]), "the config check agsconfigcheck could not run") {
		t.Fatalf("a config check that cannot run is not a blocker: %v", ags)
	}
}

// The staged config checks run with an environment of their own, not the
// caller's (Sonnet shadow audit D05): a check that fails when a variable of
// the caller is set must still pass.
func TestRemoteAlphaESBinaryDeploymentConfigChecksDoNotSeeTheCallersEnvironment(t *testing.T) {
	t.Parallel()
	payload := runESBinaryDeploymentCheckOnly(t, func(t *testing.T, f esBinaryDeploymentFixture) {
		script := "#!/bin/sh\nif [ -n \"${DEPLOYMENT_TEST_CALLER_VARIABLE:-}\" ]; then echo \"saw the caller's environment\" >&2; exit 1; fi\nexit 0\n"
		if err := os.WriteFile(filepath.Join(f.PayloadDir, "esconfigcheck"), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}, "DEPLOYMENT_TEST_CALLER_VARIABLE=1")
	es := nestedMap(t, nestedMap(t, nestedMap(t, payload, "validation"), "config_checks"), "es")
	if es["classification"] != "pass" {
		t.Fatalf("the config check saw the caller's environment: %v", es)
	}
}
