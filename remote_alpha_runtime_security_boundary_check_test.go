package executionsubstrate_test

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const defaultFakeNomadExecStart = "{ path=/usr/bin/nomad ; argv[]=/usr/bin/nomad agent -config=/etc/nomad.d ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"

func runRemoteRuntimeSecurityBoundaryCheckScript(t *testing.T, env []string, args ...string) ([]byte, error) {
	t.Helper()

	scriptPath := filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_runtime_security_boundary_check.sh")
	cmdArgs := append([]string{scriptPath}, args...)
	cmd := exec.Command("/bin/bash", cmdArgs...)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = env
	return cmd.CombinedOutput()
}

func runSourcedRuntimeSecurityBoundaryHelper(t *testing.T, env []string, shellBody string) ([]byte, error) {
	t.Helper()

	helperPath := filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_runtime_security_boundary_check.sh")
	script := fmt.Sprintf("set -euo pipefail\nsource %q\n%s\n", helperPath, shellBody)
	cmd := exec.Command("/bin/bash", "-c", script)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = env
	return cmd.CombinedOutput()
}

func writeRuntimeSecurityBoundaryConfig(t *testing.T, path, runtimeSupportBinary, spireSocketPath string) {
	t.Helper()

	payload := map[string]any{
		"execution": map[string]any{
			"runtime_support_binary":         runtimeSupportBinary,
			"spire_workload_api_socket_path": spireSocketPath,
		},
	}
	writeJSONFile(t, path, payload)
}

func writeRuntimeSecurityBoundaryWorkloadZoneConfig(t *testing.T, path string) {
	t.Helper()

	payload := map[string]any{
		"vault_config": map[string]any{
			"address":       "https://172.17.0.1:8200",
			"auth_mount":    "jwt",
			"auth_role":     "service_execution",
			"jwt_audience":  "vault",
			"ca_bundle_pem": "",
		},
	}
	writeJSONFile(t, path, payload)
}

func writeRuntimeSecurityBoundaryNomadRoleConfig(t *testing.T, path string, serverEnabled, clientEnabled bool) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir nomad config dir: %v", err)
	}
	content := fmt.Sprintf("server {\n  enabled = %t\n}\nclient {\n  enabled = %t\n}\n", serverEnabled, clientEnabled)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write nomad role config: %v", err)
	}
}

func setupFakeRuntimeSecurityBoundaryCommands(
	t *testing.T,
	dir string,
	mutationLogPath string,
	nomadExecStart string,
	withSystemctl bool,
	withSpireServer bool,
) {
	t.Helper()

	if withSystemctl {
		writeExecutable(t, dir, "systemctl", fmt.Sprintf(`#!/bin/sh
if [ "$1" = "show" ] && [ "$2" = "nomad" ]; then
  cat <<'EOF'
User=
Group=
FragmentPath=/etc/systemd/system/nomad.service
ExecStart=%s
EOF
  exit 0
fi
if [ "$1" = "show" ] && [ "$2" = "vault" ]; then
  cat <<'EOF'
User=vault
Group=vault
FragmentPath=/etc/systemd/system/vault.service
ExecStart={ path=/usr/bin/vault ; argv[]=/usr/bin/vault server -config=/etc/vault.d/vault.hcl ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
EOF
  exit 0
fi
exit 1
`, nomadExecStart))
	}

	if withSpireServer {
		writeExecutable(t, dir, "spire-server", `#!/bin/sh
if [ "$1" = "entry" ] && [ "$2" = "show" ]; then
  cat <<'EOF'
Entry ID         : test-entry
SPIFFE ID        : spiffe://execution.internal/workload
Selector         : unix:uid:0
Selector         : unix:gid:0
EOF
  exit 0
fi
exit 1
`)
	}

	for _, name := range []string{"ssh", "chown", "chmod", "rm", "tar", "install", "mv"} {
		writeExecutable(t, dir, name, fmt.Sprintf(`#!/bin/sh
printf '%%s\n' %q >> %q
exit 97
`, name, mutationLogPath))
	}
}

func fakeUbuntuProCVEOutput(cveID, classification string) string {
	switch classification {
	case "fixed":
		return cveID + " is resolved\nNo affected packages remain"
	case "not_affected":
		return cveID + " does not affect your system\nnot affected"
	case "vulnerable":
		return cveID + " is not resolved\nPackages are still affected\nNo fix is available yet"
	default:
		return cveID + " status could not be determined"
	}
}

func setupFakeRuntimeSecurityBoundaryCVECommands(
	t *testing.T,
	dir string,
	mutationLogPath string,
	cve31431Classification string,
	cve31465Classification string,
	moduleLoaded bool,
	autoloadBlocked bool,
) {
	t.Helper()

	writeExecutable(t, dir, "pro", fmt.Sprintf(`#!/bin/sh
if [ "$1" = "fix" ] && [ "$2" = "CVE-2026-31431" ]; then
  cat <<'EOF'
%s
EOF
  exit 0
fi
if [ "$1" = "fix" ] && [ "$2" = "CVE-2026-31465" ]; then
  cat <<'EOF'
%s
EOF
  exit 0
fi
exit 1
`, fakeUbuntuProCVEOutput("CVE-2026-31431", cve31431Classification), fakeUbuntuProCVEOutput("CVE-2026-31465", cve31465Classification)))

	lsmodOutput := "Module                  Size  Used by\n"
	if moduleLoaded {
		lsmodOutput += "algif_aead             16384  0\n"
	}
	writeExecutable(t, dir, "lsmod", fmt.Sprintf(`#!/bin/sh
cat <<'EOF'
%s
EOF
`, strings.TrimRight(lsmodOutput, "\n")))

	writeExecutable(t, dir, "modinfo", `#!/bin/sh
if [ "$1" = "-F" ] && [ "$2" = "filename" ] && [ "$3" = "algif_aead" ]; then
  echo /lib/modules/fake/kernel/crypto/algif_aead.ko
  exit 0
fi
exit 1
`)

	showconfigOutput := ""
	dryRunOutput := "insmod /lib/modules/fake/kernel/crypto/algif_aead.ko\n"
	if autoloadBlocked {
		showconfigOutput = "blacklist algif_aead\ninstall algif_aead /bin/false\n"
		dryRunOutput = "install /bin/false\n"
	}
	writeExecutable(t, dir, "modprobe", fmt.Sprintf(`#!/bin/sh
if [ "$1" = "--showconfig" ]; then
  cat <<'EOF'
%s
EOF
  exit 0
fi
if [ "$1" = "-n" ] && [ "$2" = "-v" ] && [ "$3" = "algif_aead" ]; then
  cat <<'EOF'
%s
EOF
  exit 0
fi
printf 'modprobe %%s\n' "$*" >> %q
exit 97
`, strings.TrimRight(showconfigOutput, "\n"), strings.TrimRight(dryRunOutput, "\n"), mutationLogPath))
}

type runtimeSecurityBoundaryFixtureResult struct {
	payload         map[string]any
	output          []byte
	err             error
	mutationLogPath string
}

func runRuntimeSecurityBoundaryCVEFixture(
	t *testing.T,
	cve31431Classification string,
	moduleLoaded bool,
	autoloadBlocked bool,
	args ...string,
) runtimeSecurityBoundaryFixtureResult {
	t.Helper()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	runtimeSupportPath := filepath.Join(tmpDir, "bin", "es-runtime-support")
	if err := os.WriteFile(runtimeSupportPath, []byte("runtime-support\n"), 0o755); err != nil {
		t.Fatalf("write runtime support binary: %v", err)
	}

	spireDir, err := os.MkdirTemp("/tmp", "es-runtime-security-spire-")
	if err != nil {
		t.Fatalf("mkdir temp spire dir: %v", err)
	}
	spireSocketPath := filepath.Join(spireDir, "agent.sock")
	listener, err := net.Listen("unix", spireSocketPath)
	if err != nil {
		t.Fatalf("listen on unix socket: %v", err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
	})

	configPath := filepath.Join(tmpDir, "es.json")
	workloadZoneConfigPath := filepath.Join(tmpDir, "workload-zone-vault-config.json")
	writeRuntimeSecurityBoundaryConfig(t, configPath, runtimeSupportPath, spireSocketPath)
	writeRuntimeSecurityBoundaryWorkloadZoneConfig(t, workloadZoneConfigPath)

	mutationLogPath := filepath.Join(tmpDir, "mutations.log")
	setupFakeRuntimeSecurityBoundaryCommands(t, fakeBin, mutationLogPath, defaultFakeNomadExecStart, true, true)
	setupFakeRuntimeSecurityBoundaryCVECommands(t, fakeBin, mutationLogPath, cve31431Classification, "not_affected", moduleLoaded, autoloadBlocked)
	writeExecutable(t, fakeBin, "uname", `#!/bin/sh
if [ "$1" = "-a" ]; then
  echo "Linux m75q-test 6.17.0-14-generic x86_64 GNU/Linux"
  exit 0
fi
if [ "$1" = "-r" ]; then
  echo "6.17.0-14-generic"
  exit 0
fi
exit 1
`)
	procModulesPath := filepath.Join(tmpDir, "proc_modules")
	procModulesText := ""
	if moduleLoaded {
		procModulesText = "algif_aead 16384 0 - Live 0x00000000\n"
	}
	if err := os.WriteFile(procModulesPath, []byte(procModulesText), 0o644); err != nil {
		t.Fatalf("write fake proc modules: %v", err)
	}

	baseArgs := []string{
		"--config-path", configPath,
		"--workload-zone-config-path", workloadZoneConfigPath,
	}
	baseArgs = append(baseArgs, args...)
	output, err := runRemoteRuntimeSecurityBoundaryCheckScript(
		t,
		envWithPath(fakeBin, "REMOTE_ALPHA_RUNTIME_SECURITY_BOUNDARY_PROC_MODULES_PATH="+procModulesPath),
		baseArgs...,
	)
	return runtimeSecurityBoundaryFixtureResult{
		payload:         parseRuntimeSecurityBoundaryOutput(t, output),
		output:          output,
		err:             err,
		mutationLogPath: mutationLogPath,
	}
}

func envWithExactPath(t *testing.T, path string, extra ...string) []string {
	t.Helper()

	values := map[string]string{}
	for _, entry := range os.Environ() {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		values[key] = value
	}
	values["PATH"] = path
	for _, entry := range extra {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		values[key] = value
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	env := make([]string, 0, len(keys))
	for _, key := range keys {
		env = append(env, key+"="+values[key])
	}
	return env
}

func parseRuntimeSecurityBoundaryOutput(t *testing.T, output []byte) map[string]any {
	t.Helper()

	var payload map[string]any
	if err := json.Unmarshal(output, &payload); err != nil {
		t.Fatalf("decode checker output: %v\noutput=%s", err, string(output))
	}
	return payload
}

func mustJSONMapField(t *testing.T, payload map[string]any, key string) map[string]any {
	t.Helper()

	value, ok := payload[key]
	if !ok {
		t.Fatalf("missing key %q", key)
	}
	result, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("key %q was %T, want map[string]any", key, value)
	}
	return result
}

func mustJSONArray(t *testing.T, payload map[string]any, key string) []any {
	t.Helper()

	value, ok := payload[key]
	if !ok {
		t.Fatalf("missing key %q", key)
	}
	result, ok := value.([]any)
	if !ok {
		t.Fatalf("key %q was %T, want []any", key, value)
	}
	return result
}

func arrayMapBySurface(t *testing.T, items []any) map[string]map[string]any {
	t.Helper()

	result := map[string]map[string]any{}
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("expected map entry, got %T", item)
		}
		name := fmt.Sprint(entry["surface"])
		result[name] = entry
	}
	return result
}

func TestRemoteAlphaRuntimeSecurityBoundaryCheckDefaultsToNonMutating(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	runtimeSupportPath := filepath.Join(tmpDir, "bin", "es-runtime-support")
	if err := os.WriteFile(runtimeSupportPath, []byte("runtime-support\n"), 0o755); err != nil {
		t.Fatalf("write runtime support binary: %v", err)
	}

	spireDir, err := os.MkdirTemp("/tmp", "es-runtime-security-spire-")
	if err != nil {
		t.Fatalf("mkdir temp spire dir: %v", err)
	}
	spireSocketPath := filepath.Join(spireDir, "agent.sock")
	listener, err := net.Listen("unix", spireSocketPath)
	if err != nil {
		t.Fatalf("listen on unix socket: %v", err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
	})

	configPath := filepath.Join(tmpDir, "es.json")
	workloadZoneConfigPath := filepath.Join(tmpDir, "workload-zone-vault-config.json")
	writeRuntimeSecurityBoundaryConfig(t, configPath, runtimeSupportPath, spireSocketPath)
	writeRuntimeSecurityBoundaryWorkloadZoneConfig(t, workloadZoneConfigPath)

	mutationLogPath := filepath.Join(tmpDir, "mutations.log")
	setupFakeRuntimeSecurityBoundaryCommands(t, fakeBin, mutationLogPath, defaultFakeNomadExecStart, true, true)
	setupFakeRuntimeSecurityBoundaryCVECommands(t, fakeBin, mutationLogPath, "fixed", "not_affected", false, false)

	output, _ := runRemoteRuntimeSecurityBoundaryCheckScript(t, envWithPath(fakeBin),
		"--config-path", configPath,
		"--workload-zone-config-path", workloadZoneConfigPath,
	)

	payload := parseRuntimeSecurityBoundaryOutput(t, output)
	if got := payload["mode"]; got != "check_only" {
		t.Fatalf("unexpected mode %v", got)
	}
	if got := payload["non_mutating"]; got != true {
		t.Fatalf("unexpected non_mutating %v", got)
	}
	if _, err := os.Stat(mutationLogPath); !os.IsNotExist(err) {
		t.Fatalf("mutation log should not exist, got %q", mutationLogPath)
	}
}

func TestRemoteAlphaRuntimeSecurityBoundaryCheckSchemaAndClassificationsAreStable(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	runtimeSupportPath := filepath.Join(tmpDir, "bin", "es-runtime-support")
	if err := os.WriteFile(runtimeSupportPath, []byte("runtime-support\n"), 0o755); err != nil {
		t.Fatalf("write runtime support binary: %v", err)
	}

	spireDir, err := os.MkdirTemp("/tmp", "es-runtime-security-spire-")
	if err != nil {
		t.Fatalf("mkdir temp spire dir: %v", err)
	}
	spireSocketPath := filepath.Join(spireDir, "agent.sock")
	listener, err := net.Listen("unix", spireSocketPath)
	if err != nil {
		t.Fatalf("listen on unix socket: %v", err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
	})

	configPath := filepath.Join(tmpDir, "es.json")
	workloadZoneConfigPath := filepath.Join(tmpDir, "workload-zone-vault-config.json")
	writeRuntimeSecurityBoundaryConfig(t, configPath, runtimeSupportPath, spireSocketPath)
	writeRuntimeSecurityBoundaryWorkloadZoneConfig(t, workloadZoneConfigPath)

	setupFakeRuntimeSecurityBoundaryCommands(t, fakeBin, filepath.Join(tmpDir, "mutations.log"), defaultFakeNomadExecStart, true, true)

	output, _ := runRemoteRuntimeSecurityBoundaryCheckScript(t, envWithPath(fakeBin),
		"--config-path", configPath,
		"--workload-zone-config-path", workloadZoneConfigPath,
	)
	payload := parseRuntimeSecurityBoundaryOutput(t, output)

	wantKeys := []string{
		"accepted_compatibility_edges",
		"blockers",
		"cve_readiness",
		"explicit_non_claims",
		"generated_at",
		"host",
		"least_privilege_findings",
		"mode",
		"non_authority_labels",
		"non_mutating",
		"not_evaluated",
		"redaction",
		"runtime_chain",
		"runtime_inventory",
		"schema",
		"surfaces",
	}
	gotKeys := make([]string, 0, len(payload))
	for key := range payload {
		gotKeys = append(gotKeys, key)
	}
	sort.Strings(gotKeys)
	if strings.Join(gotKeys, ",") != strings.Join(wantKeys, ",") {
		t.Fatalf("unexpected top-level keys %v want %v", gotKeys, wantKeys)
	}
	if got := payload["schema"]; got != "execution-substrate.remote-alpha.runtime-security-boundary-check.v1" {
		t.Fatalf("unexpected schema %v", got)
	}

	notEvaluated := arrayMapBySurface(t, mustJSONArray(t, payload, "not_evaluated"))
	for _, surfaceName := range []string{
		"nomad_server_privilege_posture",
		"nomad_client_privilege_posture",
	} {
		if _, ok := notEvaluated[surfaceName]; !ok {
			t.Fatalf("expected %s in not_evaluated list, got %v", surfaceName, notEvaluated)
		}
	}

	surfaces := mustJSONMapField(t, payload, "surfaces")
	runtimeInventory := mustJSONMapField(t, payload, "runtime_inventory")
	if got := runtimeInventory["classification"]; got != "runtime_inventory_evidence_only" {
		t.Fatalf("unexpected runtime inventory classification %v", got)
	}
	cveReadiness := mustJSONMapField(t, payload, "cve_readiness")
	if got := cveReadiness["classification"]; got != "cve_runtime_inventory_evidence_only" {
		t.Fatalf("unexpected cve readiness classification %v", got)
	}
	runtimeChain := mustJSONMapField(t, payload, "runtime_chain")
	if got := runtimeChain["classification"]; got != "runtime_chain_evidence_only" {
		t.Fatalf("unexpected runtime chain classification %v", got)
	}

	nomadServer := mustJSONMapField(t, surfaces, "nomad_server_privilege_posture")
	if got := nomadServer["classification"]; got != "not_evaluated" {
		t.Fatalf("unexpected nomad server classification %v", got)
	}
	if got := nomadServer["independently_evaluated"]; got != false {
		t.Fatalf("unexpected nomad server independently_evaluated %v", got)
	}
	if got := nomadServer["evaluation_source"]; got != "combined_nomad_systemd_unit" {
		t.Fatalf("unexpected nomad server evaluation_source %v", got)
	}

	nomadClient := mustJSONMapField(t, surfaces, "nomad_client_privilege_posture")
	if got := nomadClient["classification"]; got != "not_evaluated" {
		t.Fatalf("unexpected nomad client classification %v", got)
	}
	if got := nomadClient["independently_evaluated"]; got != false {
		t.Fatalf("unexpected nomad client independently_evaluated %v", got)
	}
	if got := nomadClient["evaluation_source"]; got != "combined_nomad_systemd_unit" {
		t.Fatalf("unexpected nomad client evaluation_source %v", got)
	}

	nomadRootDependency := mustJSONMapField(t, surfaces, "nomad_client_root_dependency")
	if got := nomadRootDependency["classification"]; got != "accepted_mvp_substrate_dependency" {
		t.Fatalf("unexpected nomad root dependency classification %v", got)
	}
	if got := nomadRootDependency["de_rooted"]; got != false {
		t.Fatalf("unexpected nomad de_rooted marker %v", got)
	}

	nomadTaskUser := mustJSONMapField(t, surfaces, "nomad_task_user_posture")
	if got := nomadTaskUser["classification"]; got != "accepted_compatibility_edge" {
		t.Fatalf("unexpected nomad task user classification %v", got)
	}
	if got := nomadTaskUser["task_user"]; got != "0:0" {
		t.Fatalf("unexpected nomad task user %v", got)
	}

	runtimeHelper := mustJSONMapField(t, surfaces, "runtime_helper_root_start_posture")
	if got := runtimeHelper["classification"]; got != "accepted_compatibility_edge" {
		t.Fatalf("unexpected runtime helper classification %v", got)
	}
	if got := runtimeHelper["root_start"]; got != true {
		t.Fatalf("unexpected runtime helper root_start %v", got)
	}

	spireTraversal := mustJSONMapField(t, surfaces, "spire_helper_private_socket_traversal")
	if got := spireTraversal["helper_private"]; got != true {
		t.Fatalf("unexpected helper_private %v", got)
	}
	if got := spireTraversal["raw_socket_visible_to_workloads"]; got != false {
		t.Fatalf("unexpected raw_socket_visible_to_workloads %v", got)
	}

	workloadIdentity := mustJSONMapField(t, surfaces, "workload_visible_identity_endpoint_contract")
	if got := workloadIdentity["endpoint_env_var"]; got != "EXEC_WORKLOAD_IDENTITY_ENDPOINT" {
		t.Fatalf("unexpected endpoint env var %v", got)
	}

	vaultBrokerage := mustJSONMapField(t, surfaces, "es_vault_token_brokerage")
	if got := vaultBrokerage["brokered_by_es"]; got != false {
		t.Fatalf("unexpected brokered_by_es %v", got)
	}

	supportArtifacts := mustJSONMapField(t, surfaces, "support_evidence_non_authoritative")
	if got := supportArtifacts["non_authoritative"]; got != true {
		t.Fatalf("unexpected non_authoritative %v", got)
	}

	labels := jsonStringSlice(t, payload["non_authority_labels"])
	if !containsString(labels, "not_support_bundle_authority") {
		t.Fatalf("expected non_authority_labels to contain not_support_bundle_authority, got %v", labels)
	}
	nonClaims := jsonStringSlice(t, payload["explicit_non_claims"])
	for _, required := range []string{
		"not_full_es_runtime_deroot",
		"not_rootless_nomad_client",
		"not_governed_execution_proof",
		"not_service_health",
		"not_submit_readiness",
		"not_runtime_profile_readiness",
		"not_vault_production_ready",
		"not_workload_credential_success_proof",
		"not_support_bundle_authority",
		"not_cve_patch_authority",
		"not_kernel_patch",
		"not_production_safety_proof",
	} {
		if !containsString(nonClaims, required) {
			t.Fatalf("expected explicit_non_claims to contain %q, got %v", required, nonClaims)
		}
	}
}

func TestRemoteAlphaRuntimeSecurityBoundaryCVE31431VulnerableWithoutMitigationBlocks(t *testing.T) {
	t.Parallel()

	result := runRuntimeSecurityBoundaryCVEFixture(t, "vulnerable", false, false)
	cveReadiness := mustJSONMapField(t, result.payload, "cve_readiness")
	cve31431 := mustJSONMapField(t, cveReadiness, "cve_2026_31431")
	if got := cve31431["classification"]; got != "vulnerable" {
		t.Fatalf("unexpected CVE-2026-31431 classification %v", got)
	}
	algif := mustJSONMapField(t, cveReadiness, "algif_aead")
	if got := algif["algif_aead_loaded"]; got != false {
		t.Fatalf("unexpected algif_aead_loaded %v", got)
	}
	if got := algif["algif_aead_autoload_blocked"]; got != false {
		t.Fatalf("unexpected algif_aead_autoload_blocked %v", got)
	}
	if got := algif["algif_aead_mitigation_verified"]; got != false {
		t.Fatalf("unexpected algif_aead_mitigation_verified %v", got)
	}

	surfaces := mustJSONMapField(t, result.payload, "surfaces")
	surface := mustJSONMapField(t, surfaces, "cve_2026_31431_readiness")
	if got := surface["classification"]; got != "blocker" {
		t.Fatalf("unexpected cve surface classification %v", got)
	}
	blockers := arrayMapBySurface(t, mustJSONArray(t, result.payload, "blockers"))
	if _, ok := blockers["cve_2026_31431_readiness"]; !ok {
		t.Fatalf("expected CVE-2026-31431 readiness blocker, got %v", blockers)
	}
}

func TestRemoteAlphaRuntimeSecurityBoundaryCVE31431MitigatedNotFixedBlocksWithoutRiskAcceptance(t *testing.T) {
	t.Parallel()

	result := runRuntimeSecurityBoundaryCVEFixture(t, "vulnerable", false, true)
	cveReadiness := mustJSONMapField(t, result.payload, "cve_readiness")
	cve31431 := mustJSONMapField(t, cveReadiness, "cve_2026_31431")
	if got := cve31431["classification"]; got != "mitigated_not_fixed" {
		t.Fatalf("unexpected CVE-2026-31431 classification %v", got)
	}
	if got := cve31431["vendor_package_classification"]; got != "vulnerable" {
		t.Fatalf("unexpected vendor_package_classification %v", got)
	}
	if got := cve31431["risk_accepted_for_internal_alpha"]; got != false {
		t.Fatalf("unexpected risk acceptance marker %v", got)
	}
	algif := mustJSONMapField(t, cveReadiness, "algif_aead")
	if got := algif["algif_aead_autoload_blocked"]; got != true {
		t.Fatalf("unexpected algif_aead_autoload_blocked %v", got)
	}
	if got := algif["algif_aead_mitigation_verified"]; got != true {
		t.Fatalf("unexpected algif_aead_mitigation_verified %v", got)
	}
	if got := fmt.Sprint(algif["algif_aead_blocking_policy_source"]); got == "" {
		t.Fatalf("expected algif blocking policy source, got %v", algif)
	}

	surfaces := mustJSONMapField(t, result.payload, "surfaces")
	surface := mustJSONMapField(t, surfaces, "cve_2026_31431_readiness")
	if got := surface["classification"]; got != "blocker" {
		t.Fatalf("unexpected cve surface classification %v", got)
	}
	blockers := arrayMapBySurface(t, mustJSONArray(t, result.payload, "blockers"))
	if _, ok := blockers["cve_2026_31431_readiness"]; !ok {
		t.Fatalf("expected mitigated_not_fixed to block without explicit risk acceptance, got %v", blockers)
	}
}

func TestRemoteAlphaRuntimeSecurityBoundaryCVE31431MitigatedNotFixedCanBeAcceptedForInternalAlpha(t *testing.T) {
	t.Parallel()

	result := runRuntimeSecurityBoundaryCVEFixture(
		t,
		"vulnerable",
		false,
		true,
		"--accept-cve-31431-mitigation-risk-for-internal-alpha",
	)
	cveReadiness := mustJSONMapField(t, result.payload, "cve_readiness")
	cve31431 := mustJSONMapField(t, cveReadiness, "cve_2026_31431")
	if got := cve31431["classification"]; got != "mitigated_not_fixed" {
		t.Fatalf("unexpected CVE-2026-31431 classification %v", got)
	}
	if got := cve31431["risk_accepted_for_internal_alpha"]; got != true {
		t.Fatalf("unexpected risk acceptance marker %v", got)
	}

	surfaces := mustJSONMapField(t, result.payload, "surfaces")
	surface := mustJSONMapField(t, surfaces, "cve_2026_31431_readiness")
	if got := surface["classification"]; got != "evidence_only" {
		t.Fatalf("unexpected cve surface classification %v", got)
	}
	blockers := arrayMapBySurface(t, mustJSONArray(t, result.payload, "blockers"))
	if _, ok := blockers["cve_2026_31431_readiness"]; ok {
		t.Fatalf("did not expect CVE-2026-31431 blocker with explicit bounded risk acceptance, got %v", blockers)
	}
}

func TestRemoteAlphaRuntimeSecurityBoundaryCVE31431UnprovedMitigationStaysVulnerable(t *testing.T) {
	t.Parallel()

	result := runRuntimeSecurityBoundaryCVEFixture(t, "vulnerable", false, false)
	cveReadiness := mustJSONMapField(t, result.payload, "cve_readiness")
	cve31431 := mustJSONMapField(t, cveReadiness, "cve_2026_31431")
	if got := cve31431["classification"]; got != "vulnerable" {
		t.Fatalf("unexpected CVE-2026-31431 classification %v", got)
	}
}

func TestRemoteAlphaRuntimeSecurityBoundaryCVE31431UnknownVendorStateBlocks(t *testing.T) {
	t.Parallel()

	result := runRuntimeSecurityBoundaryCVEFixture(t, "unknown", false, true)
	cveReadiness := mustJSONMapField(t, result.payload, "cve_readiness")
	cve31431 := mustJSONMapField(t, cveReadiness, "cve_2026_31431")
	if got := cve31431["classification"]; got != "unknown" {
		t.Fatalf("unexpected CVE-2026-31431 classification %v", got)
	}

	blockers := arrayMapBySurface(t, mustJSONArray(t, result.payload, "blockers"))
	if _, ok := blockers["cve_2026_31431_readiness"]; !ok {
		t.Fatalf("expected unknown CVE-2026-31431 readiness blocker, got %v", blockers)
	}
}

func TestRemoteAlphaRuntimeSecurityBoundaryCheckCombinedSingleNodeNomadIsHonest(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	runtimeSupportPath := filepath.Join(tmpDir, "bin", "es-runtime-support")
	if err := os.WriteFile(runtimeSupportPath, []byte("runtime-support\n"), 0o755); err != nil {
		t.Fatalf("write runtime support binary: %v", err)
	}

	spireDir, err := os.MkdirTemp("/tmp", "es-runtime-security-spire-")
	if err != nil {
		t.Fatalf("mkdir temp spire dir: %v", err)
	}
	spireSocketPath := filepath.Join(spireDir, "agent.sock")
	listener, err := net.Listen("unix", spireSocketPath)
	if err != nil {
		t.Fatalf("listen on unix socket: %v", err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
	})

	configPath := filepath.Join(tmpDir, "es.json")
	workloadZoneConfigPath := filepath.Join(tmpDir, "workload-zone-vault-config.json")
	writeRuntimeSecurityBoundaryConfig(t, configPath, runtimeSupportPath, spireSocketPath)
	writeRuntimeSecurityBoundaryWorkloadZoneConfig(t, workloadZoneConfigPath)

	nomadConfigDir := filepath.Join(tmpDir, "nomad.d")
	nomadConfigPath := filepath.Join(nomadConfigDir, "roles.hcl")
	writeRuntimeSecurityBoundaryNomadRoleConfig(t, nomadConfigPath, true, true)

	nomadExecStart := fmt.Sprintf(
		"{ path=/usr/bin/nomad ; argv[]=/usr/bin/nomad agent -config=%s ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }",
		nomadConfigDir,
	)
	setupFakeRuntimeSecurityBoundaryCommands(t, fakeBin, filepath.Join(tmpDir, "mutations.log"), nomadExecStart, true, true)

	output, _ := runRemoteRuntimeSecurityBoundaryCheckScript(t, envWithPath(fakeBin),
		"--config-path", configPath,
		"--workload-zone-config-path", workloadZoneConfigPath,
	)
	payload := parseRuntimeSecurityBoundaryOutput(t, output)
	surfaces := mustJSONMapField(t, payload, "surfaces")

	for _, surfaceName := range []string{
		"nomad_server_privilege_posture",
		"nomad_client_privilege_posture",
	} {
		surface := mustJSONMapField(t, surfaces, surfaceName)
		if got := surface["classification"]; got != "blocker" {
			t.Fatalf("unexpected %s classification %v", surfaceName, got)
		}
		if got := surface["independently_evaluated"]; got != false {
			t.Fatalf("unexpected %s independently_evaluated %v", surfaceName, got)
		}
		if got := surface["evaluation_source"]; got != "combined_nomad_systemd_unit" {
			t.Fatalf("unexpected %s evaluation_source %v", surfaceName, got)
		}
		if got := surface["combined_single_node_service"]; got != true {
			t.Fatalf("unexpected %s combined_single_node_service %v", surfaceName, got)
		}
		if got := jsonStringSlice(t, surface["nomad_roles_detected"]); strings.Join(got, ",") != "server,client" {
			t.Fatalf("unexpected %s roles_detected %v", surfaceName, got)
		}
		roleEvidence := mustJSONMapField(t, surface, "role_evidence")
		localConfig := mustJSONMapField(t, roleEvidence, "local_config")
		if got := jsonStringSlice(t, localConfig["config_paths_read"]); len(got) != 1 || got[0] != nomadConfigPath {
			t.Fatalf("unexpected %s config_paths_read %v", surfaceName, got)
		}
	}

	nomadRootDependency := mustJSONMapField(t, surfaces, "nomad_client_root_dependency")
	if got := nomadRootDependency["de_rooted"]; got != false {
		t.Fatalf("unexpected nomad client root dependency de_rooted %v", got)
	}
	if got := nomadRootDependency["independently_evaluated"]; got != false {
		t.Fatalf("unexpected nomad client root dependency independently_evaluated %v", got)
	}
}

func TestRemoteAlphaRuntimeSecurityBoundaryCheckMissingToolsStayHonest(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	pythonPath, err := exec.LookPath("python3")
	if err != nil {
		t.Fatalf("look up python3: %v", err)
	}
	writeExecutable(t, fakeBin, "python3", fmt.Sprintf("#!/bin/sh\nexec %q \"$@\"\n", pythonPath))

	runtimeSupportPath := filepath.Join(tmpDir, "es-runtime-support")
	if err := os.WriteFile(runtimeSupportPath, []byte("runtime-support\n"), 0o755); err != nil {
		t.Fatalf("write runtime support binary: %v", err)
	}
	spireDir, err := os.MkdirTemp("/tmp", "es-runtime-security-spire-")
	if err != nil {
		t.Fatalf("mkdir temp spire dir: %v", err)
	}
	spireSocketPath := filepath.Join(spireDir, "agent.sock")
	listener, err := net.Listen("unix", spireSocketPath)
	if err != nil {
		t.Fatalf("listen on unix socket: %v", err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
	})

	configPath := filepath.Join(tmpDir, "es.json")
	workloadZoneConfigPath := filepath.Join(tmpDir, "workload-zone-vault-config.json")
	writeRuntimeSecurityBoundaryConfig(t, configPath, runtimeSupportPath, spireSocketPath)
	writeRuntimeSecurityBoundaryWorkloadZoneConfig(t, workloadZoneConfigPath)

	output, _ := runRemoteRuntimeSecurityBoundaryCheckScript(t, envWithExactPath(t, fakeBin+string(os.PathListSeparator)+"/usr/bin"+string(os.PathListSeparator)+"/bin",
		"HOME="+os.Getenv("HOME"),
	), "--config-path", configPath, "--workload-zone-config-path", workloadZoneConfigPath)

	payload := parseRuntimeSecurityBoundaryOutput(t, output)
	notEvaluated := arrayMapBySurface(t, mustJSONArray(t, payload, "not_evaluated"))
	for _, surface := range []string{
		"nomad_server_privilege_posture",
		"nomad_client_privilege_posture",
		"vault_service_account_posture",
		"broad_root_selector_posture",
	} {
		if _, ok := notEvaluated[surface]; !ok {
			t.Fatalf("expected %s to be not_evaluated, got %v", surface, notEvaluated)
		}
	}

	blockers := arrayMapBySurface(t, mustJSONArray(t, payload, "blockers"))
	if _, ok := blockers["nomad_server_privilege_posture"]; !ok {
		t.Fatalf("expected nomad_server_privilege_posture blocker, got %v", blockers)
	}
	if _, ok := blockers["nomad_client_privilege_posture"]; !ok {
		t.Fatalf("expected nomad_client_privilege_posture blocker, got %v", blockers)
	}
}

func TestRemoteAlphaRuntimeSecurityBoundaryValidateSummaryRejectsSecretLikeMaterial(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	summaryPath := filepath.Join(tmpDir, "summary.json")
	secretSummary := `{"schema":"execution-substrate.remote-alpha.runtime-security-boundary-check.v1","jwt":"eyJhbGciOiJub25lIn0.eyJzdWIiOiJzcGlmZmU6Ly9leGVjdXRpb24uaW50ZXJuYWwvd29ya2xvYWQifQ.signature","token":"hvs.secretmaterial123456"}`
	if err := os.WriteFile(summaryPath, []byte(secretSummary), 0o600); err != nil {
		t.Fatalf("write summary: %v", err)
	}

	output, err := runSourcedRuntimeSecurityBoundaryHelper(t, os.Environ(), fmt.Sprintf(
		"remote_alpha_runtime_security_boundary_validate_summary_file %q",
		summaryPath,
	))
	if err == nil {
		t.Fatalf("expected validator to fail for secret-like material")
	}
	if !strings.Contains(string(output), "summary contains secret-like material") {
		t.Fatalf("unexpected validator output %q", output)
	}
}

func TestRemoteAlphaRuntimeSecurityBoundaryValidateSummaryRejectsLabeledSecretLikeMaterial(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload string
	}{
		{
			name:    "root token label",
			payload: `{"schema":"execution-substrate.remote-alpha.runtime-security-boundary-check.v1","root_token":"supersecretvalue1234"}`,
		},
		{
			name:    "unseal key label",
			payload: `{"schema":"execution-substrate.remote-alpha.runtime-security-boundary-check.v1","unseal_key":"supersecretvalue1234"}`,
		},
		{
			name:    "client token label",
			payload: `{"schema":"execution-substrate.remote-alpha.runtime-security-boundary-check.v1","client_token":"supersecretvalue1234"}`,
		},
		{
			name:    "raw secret payload label",
			payload: `{"schema":"execution-substrate.remote-alpha.runtime-security-boundary-check.v1","raw_secret_payload":"supersecretvalue1234"}`,
		},
		{
			name:    "codex credential label",
			payload: `{"schema":"execution-substrate.remote-alpha.runtime-security-boundary-check.v1","codex_credential":"supersecretvalue1234"}`,
		},
		{
			name:    "codex token label",
			payload: `{"schema":"execution-substrate.remote-alpha.runtime-security-boundary-check.v1","codex_token":"supersecretvalue1234"}`,
		},
		{
			name:    "codex api key label",
			payload: `{"schema":"execution-substrate.remote-alpha.runtime-security-boundary-check.v1","codex_api_key":"supersecretvalue1234"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tmpDir := t.TempDir()
			summaryPath := filepath.Join(tmpDir, "summary.json")
			if err := os.WriteFile(summaryPath, []byte(tt.payload), 0o600); err != nil {
				t.Fatalf("write summary: %v", err)
			}

			output, err := runSourcedRuntimeSecurityBoundaryHelper(t, os.Environ(), fmt.Sprintf(
				"remote_alpha_runtime_security_boundary_validate_summary_file %q",
				summaryPath,
			))
			if err == nil {
				t.Fatalf("expected validator to fail for labeled secret-like material")
			}
			if !strings.Contains(string(output), "summary contains secret-like material") {
				t.Fatalf("unexpected validator output %q", output)
			}
		})
	}
}

func TestRemoteAlphaRuntimeSecurityBoundaryValidateSummaryAllowsBooleanRedactionFlags(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	summaryPath := filepath.Join(tmpDir, "summary.json")
	safeSummary := `{
  "schema":"execution-substrate.remote-alpha.runtime-security-boundary-check.v1",
  "redaction":{
    "root_tokens_persisted":false,
    "unseal_keys_persisted":false,
    "raw_secret_payloads_persisted":false,
    "codex_credentials_persisted":false
  }
}`
	if err := os.WriteFile(summaryPath, []byte(safeSummary), 0o600); err != nil {
		t.Fatalf("write summary: %v", err)
	}

	output, err := runSourcedRuntimeSecurityBoundaryHelper(t, os.Environ(), fmt.Sprintf(
		"remote_alpha_runtime_security_boundary_validate_summary_file %q",
		summaryPath,
	))
	if err != nil {
		t.Fatalf("expected validator to allow boolean redaction flags, got err=%v output=%s", err, string(output))
	}
}

func TestRemoteAlphaRuntimeSecurityBoundaryValidateSummaryRejectsOverclaimText(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	summaryPath := filepath.Join(tmpDir, "summary.json")
	overclaimSummary := `{"schema":"execution-substrate.remote-alpha.runtime-security-boundary-check.v1","summary":"this check proves full ES/runtime de-root"}`
	if err := os.WriteFile(summaryPath, []byte(overclaimSummary), 0o600); err != nil {
		t.Fatalf("write summary: %v", err)
	}

	output, err := runSourcedRuntimeSecurityBoundaryHelper(t, os.Environ(), fmt.Sprintf(
		"remote_alpha_runtime_security_boundary_validate_summary_file %q",
		summaryPath,
	))
	if err == nil {
		t.Fatalf("expected validator to fail for overclaim text")
	}
	if !strings.Contains(string(output), "summary contains overclaim text") {
		t.Fatalf("unexpected validator output %q", output)
	}
}
