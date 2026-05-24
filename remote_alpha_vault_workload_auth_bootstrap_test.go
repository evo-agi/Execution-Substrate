package executionsubstrate_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func remoteAlphaVaultWorkloadAuthBootstrapScriptPath() string {
	return filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_vault_workload_auth_bootstrap.sh")
}

func remoteAlphaVaultWorkloadAuthBootstrapInternalPath() string {
	return filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_vault_workload_auth_bootstrap.sh")
}

func runRemoteAlphaBootstrapHelperWithEnv(env []string, args ...string) (string, error) {
	cmd := exec.Command("/bin/bash", append([]string{remoteAlphaVaultWorkloadAuthBootstrapScriptPath()}, args...)...)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func runRemoteAlphaBootstrapHelperWithPTYInput(t *testing.T, env []string, input string, args ...string) (string, error) {
	t.Helper()
	python := `
import os
import pty
import select
import sys

repo_root = os.environ["ES_REPO_ROOT"]
input_data = os.environ.pop("ES_PTY_INPUT").encode()
child_env = os.environ.copy()
input_lines = input_data.splitlines(keepends=True)
cmd = sys.argv[1:]
pid, master_fd = pty.fork()
if pid == 0:
    os.chdir(repo_root)
    os.execvpe(cmd[0], cmd, child_env)
chunks = []
sent = 0
buffer = b""
child_done = False
status = 0
while True:
    ready, _, _ = select.select([master_fd], [], [], 0.1)
    if ready:
        try:
            data = os.read(master_fd, 4096)
        except OSError:
            break
        if not data:
            break
        chunks.append(data)
        buffer += data
    if sent == 0 and b"Vault bootstrap authority token" in buffer and len(input_lines) > 0:
        os.write(master_fd, input_lines[0])
        sent = 1
    if sent == 1 and b"Proof secret value" in buffer and len(input_lines) > 1:
        os.write(master_fd, input_lines[1])
        sent = 2
    if not child_done:
        done_pid, wait_status = os.waitpid(pid, os.WNOHANG)
        if done_pid == pid:
            child_done = True
            status = wait_status
    if child_done and not ready:
        break
os.close(master_fd)
if not child_done:
    _, status = os.waitpid(pid, 0)
sys.stdout.buffer.write(b"".join(chunks))
if os.WIFEXITED(status):
    sys.exit(os.WEXITSTATUS(status))
if os.WIFSIGNALED(status):
    sys.exit(128 + os.WTERMSIG(status))
sys.exit(1)
`
	commandArgs := append([]string{"-c", python, "/bin/bash", remoteAlphaVaultWorkloadAuthBootstrapScriptPath()}, args...)
	cmd := exec.Command("python3", commandArgs...)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = append(env, "ES_REPO_ROOT="+executionSubstrateRepoRoot, "ES_PTY_INPUT="+input)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

type fakeBootstrapVaultRequest struct {
	Method string
	Path   string
	Body   map[string]any
}

type fakeBootstrapVaultServer struct {
	t             *testing.T
	expectedToken string
	requests      []fakeBootstrapVaultRequest
	failPath      string
	failStatus    int
	failBody      string
}

func (f *fakeBootstrapVaultServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.t.Helper()
	if got := r.Header.Get("X-Vault-Token"); got != f.expectedToken {
		f.t.Fatalf("unexpected bootstrap Vault token header for %s %s", r.Method, r.URL.Path)
	}

	var body map[string]any
	if r.Body != nil {
		defer r.Body.Close()
		if r.ContentLength != 0 {
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				f.t.Fatalf("decode request body for %s %s: %v", r.Method, r.URL.Path, err)
			}
		}
	}
	f.requests = append(f.requests, fakeBootstrapVaultRequest{
		Method: r.Method,
		Path:   r.URL.Path,
		Body:   body,
	})

	if f.failPath == r.URL.Path {
		w.WriteHeader(f.failStatus)
		_, _ = w.Write([]byte(f.failBody))
		return
	}

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/sys/auth":
		writeJSON(w, http.StatusOK, map[string]any{})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/sys/auth/jwt":
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/sys/mounts":
		writeJSON(w, http.StatusOK, map[string]any{})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/sys/mounts/proof-secrets":
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPut && r.URL.Path == "/v1/sys/policies/acl/runtime-identity-proof":
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/jwt/config":
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/jwt/role/service_execution":
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/proof-secrets/data/runtime-identity-vault-login":
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/proof-secrets/data/codex-runtime-profile":
		w.WriteHeader(http.StatusNoContent)
	default:
		writeJSON(w, http.StatusNotFound, map[string]any{"errors": []string{"unexpected path"}})
	}
}

func startFakeBootstrapVault(t *testing.T, expectedToken string) (*httptest.Server, *fakeBootstrapVaultServer, string) {
	t.Helper()
	state := &fakeBootstrapVaultServer{t: t, expectedToken: expectedToken}
	server := httptest.NewTLSServer(state)
	t.Cleanup(server.Close)
	return server, state, encodeCertificatePEM(t, server.Certificate())
}

func startFailingFakeBootstrapVault(t *testing.T, expectedToken, failPath string, failStatus int) (*httptest.Server, *fakeBootstrapVaultServer, string) {
	t.Helper()
	state := &fakeBootstrapVaultServer{
		t:             t,
		expectedToken: expectedToken,
		failPath:      failPath,
		failStatus:    failStatus,
		failBody:      `{"errors":["raw Vault output must not be summarized","X-Vault-Token: hvs.rawbodytokenvalue123456789012345","traceback sentinel"]}`,
	}
	server := httptest.NewTLSServer(state)
	t.Cleanup(server.Close)
	return server, state, encodeCertificatePEM(t, server.Certificate())
}

func setupFakeBootstrapSpireServer(t *testing.T, dir string) string {
	t.Helper()
	logPath := filepath.Join(dir, "spire-server.log")
	writeExecutable(t, dir, "spire-server", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
printf 'args=%%s\n' "$*" >> %q
env | sort | sed -n '/TOKEN/p;/SECRET/p;/PASSWORD/p' >> %q
cat <<'JSON'
{"keys":[{"kty":"RSA","use":"jwt-svid","n":"AQAB","e":"AQAB"}]}
JSON
`, logPath, logPath))
	return logPath
}

func assertBootstrapSummaryRedactionScanPasses(t *testing.T, summaryPath string, secretValues ...string) {
	t.Helper()
	args := append([]string{remoteAlphaVaultWorkloadAuthBootstrapInternalPath(), summaryPath}, secretValues...)
	script := `set -euo pipefail
source "$1"
shift
remote_alpha_vault_workload_auth_bootstrap_validate_summary_file "$@"
`
	cmd := exec.Command("/bin/bash", append([]string{"-c", script, "redaction-scan"}, args...)...)
	cmd.Dir = executionSubstrateRepoRoot
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected summary redaction scan to pass for %s: %v\n%s", summaryPath, err, output)
	}
}

func assertBootstrapFailureSummary(t *testing.T, summaryPath, phase, failureClass string, secretPromptsStarted, vaultOperationsStarted bool, secretValues ...string) map[string]any {
	t.Helper()
	summaryRaw := mustRead(t, summaryPath)
	assertContainsNone(t, "bootstrap failure summary forbidden material", summaryRaw,
		"X-Vault-Token",
		"raw Vault output",
		"traceback sentinel",
		"Traceback",
		"BEGIN PRIVATE KEY",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		"hvs.rawbodytokenvalue123456789012345",
	)
	assertContainsNone(t, "bootstrap failure summary fake secrets", summaryRaw, secretValues...)
	assertBootstrapSummaryRedactionScanPasses(t, summaryPath, secretValues...)

	summary := readJSONFile(t, summaryPath)
	if got := summary["overall_status"]; got != "fail" {
		t.Fatalf("expected failure summary overall_status=fail, got %#v", got)
	}
	if got := summary["failure_phase"]; got != phase {
		t.Fatalf("expected failure_phase=%s, got %#v\nsummary=%s", phase, got, summaryRaw)
	}
	if got := summary["failure_class"]; got != failureClass {
		t.Fatalf("expected failure_class=%s, got %#v\nsummary=%s", failureClass, got, summaryRaw)
	}
	if got := summary["secret_prompts_started"]; got != secretPromptsStarted {
		t.Fatalf("expected secret_prompts_started=%v, got %#v\nsummary=%s", secretPromptsStarted, got, summaryRaw)
	}
	if got := summary["vault_operations_started"]; got != vaultOperationsStarted {
		t.Fatalf("expected vault_operations_started=%v, got %#v\nsummary=%s", vaultOperationsStarted, got, summaryRaw)
	}
	operations, ok := summary["operations"].(map[string]any)
	if !ok {
		t.Fatalf("unexpected operations block %#v", summary["operations"])
	}
	operation, ok := operations[phase].(map[string]any)
	if !ok {
		t.Fatalf("expected operation %s failure, got operations=%#v\nsummary=%s", phase, operations, summaryRaw)
	}
	if got := operation["status"]; got != "fail" {
		t.Fatalf("expected operation %s status=fail, got %#v\nsummary=%s", phase, got, summaryRaw)
	}
	if got := operation["error_classification"]; got != failureClass {
		t.Fatalf("expected operation %s error_classification=%s, got %#v\nsummary=%s", phase, failureClass, got, summaryRaw)
	}
	return summary
}

func TestRemoteAlphaVaultWorkloadAuthBootstrapHelpDocumentsSecretPosture(t *testing.T) {
	output, err := runRemoteAlphaBootstrapHelperWithEnv(os.Environ(), "--help")
	if err != nil {
		t.Fatalf("bootstrap helper --help failed: %v\n%s", err, output)
	}
	assertContainsAll(t, "bootstrap helper help", output,
		"Configure the Remote Alpha Vault workload-auth objects",
		"The human operator enters Vault bootstrap authority and the proof secret",
		"never accepted through CLI",
		"preflights summary writability and workload-zone config readability",
		"fixed SPIRE server bundle-read command",
		"summary_preflight_failed",
		"spire_bundle_show_failed",
		"safe phase/class labels",
		"never raw",
		"in-process Python HTTPS client",
		"does not use",
		"VAULT_TOKEN",
		"vault login",
		"auth mount jwt",
		"role service_execution",
		"runtime-identity-proof",
		"proof-secrets/data/runtime-identity-vault-login",
		"proof-secrets/data/codex-runtime-profile",
		"api_key",
		"does not run workload-auth checks, reset, unseal, IM refresh",
		"does not claim workload-auth success",
	)
}

func TestRemoteAlphaVaultWorkloadAuthBootstrapRejectsSecretArgsAndEnvLikeArgs(t *testing.T) {
	for _, args := range [][]string{
		{"--root-token", "dummy"},
		{"--vault-token=dummy"},
		{"--api-key=dummy"},
		{"--proof-secret-value", "dummy"},
		{"VAULT_TOKEN=dummy"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			output, err := runRemoteAlphaBootstrapHelperWithEnv(os.Environ(), args...)
			if err == nil {
				t.Fatalf("expected bootstrap helper refusal for %v:\n%s", args, output)
			}
			assertContainsNone(t, "bootstrap helper refusal output", output,
				"Remote Alpha Vault workload-auth bootstrap helper finished.",
			)
		})
	}

	output, err := runRemoteAlphaBootstrapHelperWithEnv(append(os.Environ(), "VAULT_TOKEN=dummy"))
	if err == nil {
		t.Fatalf("expected bootstrap helper to reject VAULT_TOKEN env:\n%s", output)
	}
	assertContainsAll(t, "bootstrap helper env refusal", output,
		"VAULT_TOKEN must not be supplied through the environment",
	)
}

func TestRemoteAlphaVaultWorkloadAuthBootstrapPreflightFailsBeforePromptsAndVaultWrites(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("summary parent writability preflight requires non-root test user")
	}

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	setupFakeBootstrapSpireServer(t, fakeBin)

	rootToken := "root-token-for-preflight-test"
	proofSecret := "proof-value-for-preflight-test"
	server, state, caBundle := startFakeBootstrapVault(t, rootToken)
	configPath := filepath.Join(tmpDir, "workload-zone-vault-config.json")
	writeWorkloadZoneConfig(t, configPath, server.URL, "jwt", "service_execution", "vault", caBundle)

	summaryParent := filepath.Join(tmpDir, "summary-parent")
	if err := os.Mkdir(summaryParent, 0o500); err != nil {
		t.Fatalf("mkdir unwritable summary parent: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(summaryParent, 0o700)
	})
	summaryPath := filepath.Join(summaryParent, "vault-workload-auth-bootstrap-summary.json")

	output, err := runRemoteAlphaBootstrapHelperWithPTYInput(t,
		envWithPath(fakeBin,
			"REMOTE_ALPHA_BOOTSTRAP_WORKLOAD_ZONE_CONFIG_PATH="+configPath,
			"REMOTE_ALPHA_BOOTSTRAP_SUMMARY_PATH="+summaryPath,
		),
		rootToken+"\n"+proofSecret+"\n",
	)
	if err == nil {
		t.Fatalf("expected bootstrap helper preflight failure before prompts:\n%s", output)
	}
	assertContainsAll(t, "bootstrap helper preflight failure", output,
		"Remote Alpha Vault workload-auth bootstrap preflight failed.",
		"failure_class=summary_preflight_failed",
		"error_classification=summary_parent_not_writable",
		"summary_path="+summaryPath,
		"summary_parent="+summaryParent,
		"No Vault bootstrap prompts were read and no Vault writes were attempted.",
	)
	assertContainsNone(t, "bootstrap helper preflight failure output", output,
		"Vault bootstrap authority token",
		"Proof secret value",
		"Remote Alpha Vault workload-auth bootstrap helper finished.",
		rootToken,
		proofSecret,
	)
	if got := len(state.requests); got != 0 {
		t.Fatalf("preflight failure must not call fake Vault API, got %d requests", got)
	}
	if _, err := os.Stat(summaryPath); !os.IsNotExist(err) {
		t.Fatalf("preflight failure must not write summary, stat err=%v", err)
	}
	tmpMatches, err := filepath.Glob(filepath.Join(summaryParent, "*.tmp"))
	if err != nil {
		t.Fatalf("glob temp summaries: %v", err)
	}
	hiddenTmpMatches, err := filepath.Glob(filepath.Join(summaryParent, ".*.tmp"))
	if err != nil {
		t.Fatalf("glob hidden temp summaries: %v", err)
	}
	if len(tmpMatches)+len(hiddenTmpMatches) != 0 {
		t.Fatalf("preflight failure must not leave temp summaries, visible=%v hidden=%v", tmpMatches, hiddenTmpMatches)
	}
}

func TestRemoteAlphaVaultWorkloadAuthBootstrapConfigLoadFailureWritesSafeSummaryBeforePrompts(t *testing.T) {
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	setupFakeBootstrapSpireServer(t, fakeBin)

	rootToken := "hvs.fakeRootTokenForConfigFailure1234567890"
	proofSecret := "sk-fakeProofSecretForConfigFailure1234567890"
	summaryPath := filepath.Join(tmpDir, "summary", "vault-workload-auth-bootstrap-summary.json")
	missingConfigPath := filepath.Join(tmpDir, "missing-workload-zone-vault-config.json")

	output, err := runRemoteAlphaBootstrapHelperWithEnv(
		envWithPath(fakeBin,
			"REMOTE_ALPHA_BOOTSTRAP_WORKLOAD_ZONE_CONFIG_PATH="+missingConfigPath,
			"REMOTE_ALPHA_BOOTSTRAP_SUMMARY_PATH="+summaryPath,
		),
	)
	if err == nil {
		t.Fatalf("expected config-load failure:\n%s", output)
	}
	assertContainsNone(t, "config-load failure output", output,
		"Vault bootstrap authority token",
		"Proof secret value",
		rootToken,
		proofSecret,
		"Traceback",
	)
	summary := assertBootstrapFailureSummary(t, summaryPath, "config_load", "config_missing", false, false, rootToken, proofSecret)
	if got := summary["next_operation"]; got != "config_load" {
		t.Fatalf("expected next_operation=config_load for config failure, got %#v", got)
	}
}

func TestRemoteAlphaVaultWorkloadAuthBootstrapConfigUnreadablePreflightFailsBeforePrompts(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("unreadable config preflight requires a non-root test process")
	}

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	setupFakeBootstrapSpireServer(t, fakeBin)

	rootToken := "hvs.fakeRootTokenForUnreadableConfig1234567890"
	proofSecret := "sk-fakeProofSecretForUnreadableConfig1234567890"
	server, state, caBundle := startFakeBootstrapVault(t, rootToken)
	configPath := filepath.Join(tmpDir, "workload-zone-vault-config.json")
	writeWorkloadZoneConfig(t, configPath, server.URL, "jwt", "service_execution", "vault", caBundle)
	if err := os.Chmod(configPath, 0o000); err != nil {
		t.Fatalf("chmod unreadable config: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(configPath, 0o600)
	})
	summaryPath := filepath.Join(tmpDir, "summary", "vault-workload-auth-bootstrap-summary.json")

	output, err := runRemoteAlphaBootstrapHelperWithPTYInput(t,
		envWithPath(fakeBin,
			"REMOTE_ALPHA_BOOTSTRAP_WORKLOAD_ZONE_CONFIG_PATH="+configPath,
			"REMOTE_ALPHA_BOOTSTRAP_SUMMARY_PATH="+summaryPath,
		),
		rootToken+"\n"+proofSecret+"\n",
	)
	if err == nil {
		t.Fatalf("expected unreadable config preflight failure:\n%s", output)
	}
	assertContainsNone(t, "unreadable config preflight output", output,
		"Vault bootstrap authority token",
		"Proof secret value",
		rootToken,
		proofSecret,
		"X-Vault-Token",
		"Traceback",
	)
	if got := len(state.requests); got != 0 {
		t.Fatalf("config preflight failure must not call fake Vault API, got %d requests", got)
	}
	summary := assertBootstrapFailureSummary(t, summaryPath, "config_load", "config_unreadable", false, false, rootToken, proofSecret)
	if got := summary["failure_message_class"]; got != "permission_denied" && got != "permission_error" {
		t.Fatalf("expected permission failure message class, got %#v", got)
	}
	if got := summary["last_completed_operation"]; got != "summary_preflight" {
		t.Fatalf("expected last_completed_operation=summary_preflight before config failure, got %#v", got)
	}
	if got := summary["next_operation"]; got != "config_load" {
		t.Fatalf("expected next_operation=config_load for config failure, got %#v", got)
	}
	tmpMatches, err := filepath.Glob(filepath.Join(filepath.Dir(summaryPath), "*.tmp"))
	if err != nil {
		t.Fatalf("glob temp summaries after config failure: %v", err)
	}
	hiddenTmpMatches, err := filepath.Glob(filepath.Join(filepath.Dir(summaryPath), ".*.tmp"))
	if err != nil {
		t.Fatalf("glob hidden temp summaries after config failure: %v", err)
	}
	if len(tmpMatches)+len(hiddenTmpMatches) != 0 {
		t.Fatalf("config preflight failure must not leave temp summaries, visible=%v hidden=%v", tmpMatches, hiddenTmpMatches)
	}
}

func TestRemoteAlphaVaultWorkloadAuthBootstrapSpireBundlePreflightFailsBeforePromptsAndVaultWrites(t *testing.T) {
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	const spireRawSentinel = "FAKE-SPIRE-BUNDLE-MATERIAL-MUST-NOT-LEAK"
	writeExecutable(t, fakeBin, "spire-server", `#!/usr/bin/env bash
set -euo pipefail
printf '`+spireRawSentinel+`\n'
printf 'raw SPIRE stderr must not be printed\n' >&2
exit 17
`)

	rootToken := "hvs.fakeRootTokenForSpireFailure1234567890"
	proofSecret := "sk-fakeProofSecretForSpireFailure1234567890"
	server, state, caBundle := startFakeBootstrapVault(t, rootToken)
	configPath := filepath.Join(tmpDir, "workload-zone-vault-config.json")
	summaryPath := filepath.Join(tmpDir, "summary", "vault-workload-auth-bootstrap-summary.json")
	writeWorkloadZoneConfig(t, configPath, server.URL, "jwt", "service_execution", "vault", caBundle)

	output, err := runRemoteAlphaBootstrapHelperWithPTYInput(t,
		envWithPath(fakeBin,
			"REMOTE_ALPHA_BOOTSTRAP_WORKLOAD_ZONE_CONFIG_PATH="+configPath,
			"REMOTE_ALPHA_BOOTSTRAP_SUMMARY_PATH="+summaryPath,
		),
		rootToken+"\n"+proofSecret+"\n",
	)
	if err == nil {
		t.Fatalf("expected SPIRE bundle-read preflight failure:\n%s", output)
	}
	assertContainsNone(t, "SPIRE bundle preflight output", output,
		"Vault bootstrap authority token",
		"Proof secret value",
		rootToken,
		proofSecret,
		spireRawSentinel,
		"raw SPIRE stderr",
		"X-Vault-Token",
		"Traceback",
	)
	if got := len(state.requests); got != 0 {
		t.Fatalf("SPIRE preflight failure must not call fake Vault API, got %d requests", got)
	}
	summaryRaw := mustRead(t, summaryPath)
	assertContainsNone(t, "SPIRE bundle preflight summary forbidden material", summaryRaw,
		rootToken,
		proofSecret,
		spireRawSentinel,
		"raw SPIRE stderr",
		"X-Vault-Token",
		"Traceback",
		`"keys"`,
		"jwt-svid",
	)
	assertBootstrapSummaryRedactionScanPasses(t, summaryPath, rootToken, proofSecret, spireRawSentinel)
	summary := readJSONFile(t, summaryPath)
	if got := summary["overall_status"]; got != "fail" {
		t.Fatalf("expected overall_status=fail, got %#v", got)
	}
	if got := summary["failure_phase"]; got != "jwt_auth_config" {
		t.Fatalf("expected failure_phase=jwt_auth_config, got %#v\nsummary=%s", got, summaryRaw)
	}
	if got := summary["failure_class"]; got != "invalid_response" {
		t.Fatalf("expected failure_class=invalid_response, got %#v\nsummary=%s", got, summaryRaw)
	}
	if got := summary["secret_prompts_started"]; got != false {
		t.Fatalf("expected secret_prompts_started=false, got %#v\nsummary=%s", got, summaryRaw)
	}
	if got := summary["vault_operations_started"]; got != false {
		t.Fatalf("expected vault_operations_started=false, got %#v\nsummary=%s", got, summaryRaw)
	}
	if got := summary["failure_message_class"]; got != "spire_bundle_show_failed" {
		t.Fatalf("expected spire_bundle_show_failed message class, got %#v", got)
	}
	if got := summary["last_completed_operation"]; got != "workload_zone_config" {
		t.Fatalf("expected last_completed_operation=workload_zone_config before SPIRE failure, got %#v", got)
	}
	if got := summary["next_operation"]; got != "jwt_auth_config" {
		t.Fatalf("expected next_operation=jwt_auth_config for SPIRE failure, got %#v", got)
	}
	operations, ok := summary["operations"].(map[string]any)
	if !ok {
		t.Fatalf("unexpected operations block %#v", summary["operations"])
	}
	spireOp, ok := operations["spire_jwt_validation_material"].(map[string]any)
	if !ok || spireOp["status"] != "fail" || spireOp["error_classification"] != "invalid_response" {
		t.Fatalf("expected spire_jwt_validation_material failure, got %#v", operations["spire_jwt_validation_material"])
	}
}

func TestRemoteAlphaVaultWorkloadAuthBootstrapPromptUnavailableWritesSafeSummaryWithoutSecretValues(t *testing.T) {
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	setupFakeBootstrapSpireServer(t, fakeBin)

	rootToken := "hvs.fakeRootTokenForPromptFailure1234567890"
	proofSecret := "sk-fakeProofSecretForPromptFailure1234567890"
	server, state, caBundle := startFakeBootstrapVault(t, rootToken)
	configPath := filepath.Join(tmpDir, "workload-zone-vault-config.json")
	summaryPath := filepath.Join(tmpDir, "summary", "vault-workload-auth-bootstrap-summary.json")
	writeWorkloadZoneConfig(t, configPath, server.URL, "jwt", "service_execution", "vault", caBundle)

	output, err := runRemoteAlphaBootstrapHelperWithEnv(
		envWithPath(fakeBin,
			"REMOTE_ALPHA_BOOTSTRAP_WORKLOAD_ZONE_CONFIG_PATH="+configPath,
			"REMOTE_ALPHA_BOOTSTRAP_SUMMARY_PATH="+summaryPath,
		),
	)
	if err == nil {
		t.Fatalf("expected prompt-unavailable failure:\n%s", output)
	}
	assertContainsNone(t, "prompt-unavailable failure output", output,
		rootToken,
		proofSecret,
		"X-Vault-Token",
		"Traceback",
	)
	if got := len(state.requests); got != 0 {
		t.Fatalf("prompt failure must not call fake Vault API, got %d requests", got)
	}
	summary := assertBootstrapFailureSummary(t, summaryPath, "prompt_bootstrap_authority", "prompt_unavailable", true, false, rootToken, proofSecret)
	if got := summary["last_completed_operation"]; got != "spire_jwt_validation_material" {
		t.Fatalf("expected last_completed_operation=spire_jwt_validation_material before prompt failure, got %#v", got)
	}
}

func TestRemoteAlphaVaultWorkloadAuthBootstrapVaultAPIFailuresWriteSafePhaseSummary(t *testing.T) {
	cases := []struct {
		name         string
		failPath     string
		failStatus   int
		phase        string
		failureClass string
	}{
		{name: "jwt_auth_mount", failPath: "/v1/sys/auth", failStatus: http.StatusForbidden, phase: "jwt_auth_mount", failureClass: "vault_permission_denied"},
		{name: "kv_v2_mount", failPath: "/v1/sys/mounts", failStatus: http.StatusInternalServerError, phase: "kv_v2_mount", failureClass: "vault_api_error"},
		{name: "runtime_identity_policy", failPath: "/v1/sys/policies/acl/runtime-identity-proof", failStatus: http.StatusForbidden, phase: "runtime_identity_policy", failureClass: "vault_permission_denied"},
		{name: "jwt_auth_config", failPath: "/v1/auth/jwt/config", failStatus: http.StatusInternalServerError, phase: "jwt_auth_config", failureClass: "vault_api_error"},
		{name: "service_execution_role", failPath: "/v1/auth/jwt/role/service_execution", failStatus: http.StatusForbidden, phase: "service_execution_role", failureClass: "vault_permission_denied"},
		{name: "proof_secret_runtime_identity_vault_login", failPath: "/v1/proof-secrets/data/runtime-identity-vault-login", failStatus: http.StatusForbidden, phase: "proof_secret_runtime_identity_vault_login", failureClass: "vault_permission_denied"},
		{name: "proof_secret_codex_runtime_profile", failPath: "/v1/proof-secrets/data/codex-runtime-profile", failStatus: http.StatusInternalServerError, phase: "proof_secret_codex_runtime_profile", failureClass: "vault_api_error"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			fakeBin := filepath.Join(tmpDir, "bin")
			if err := os.MkdirAll(fakeBin, 0o755); err != nil {
				t.Fatalf("mkdir fake bin: %v", err)
			}
			setupFakeBootstrapSpireServer(t, fakeBin)

			rootToken := "hvs.fakeRootTokenForVaultFailure1234567890"
			proofSecret := "sk-fakeProofSecretForVaultFailure1234567890"
			server, state, caBundle := startFailingFakeBootstrapVault(t, rootToken, tc.failPath, tc.failStatus)
			configPath := filepath.Join(tmpDir, "workload-zone-vault-config.json")
			summaryPath := filepath.Join(tmpDir, "summary", "vault-workload-auth-bootstrap-summary.json")
			writeWorkloadZoneConfig(t, configPath, server.URL, "jwt", "service_execution", "vault", caBundle)

			output, err := runRemoteAlphaBootstrapHelperWithPTYInput(t,
				envWithPath(fakeBin,
					"REMOTE_ALPHA_BOOTSTRAP_WORKLOAD_ZONE_CONFIG_PATH="+configPath,
					"REMOTE_ALPHA_BOOTSTRAP_SUMMARY_PATH="+summaryPath,
				),
				rootToken+"\n"+proofSecret+"\n",
			)
			if err == nil {
				t.Fatalf("expected fake Vault API failure for %s:\n%s", tc.phase, output)
			}
			assertContainsNone(t, "fake Vault API failure output", output,
				rootToken,
				proofSecret,
				"X-Vault-Token",
				"raw Vault output",
				"Traceback",
			)
			if len(state.requests) == 0 {
				t.Fatalf("expected fake Vault API to be called for %s", tc.phase)
			}
			summary := assertBootstrapFailureSummary(t, summaryPath, tc.phase, tc.failureClass, true, true, rootToken, proofSecret)
			if got := summary["next_operation"]; got != tc.phase {
				t.Fatalf("expected next_operation=%s, got %#v", tc.phase, got)
			}
			if got := summary["failure_message_class"]; got == nil {
				t.Fatalf("expected safe failure_message_class for %s\nsummary=%s", tc.phase, mustRead(t, summaryPath))
			}
		})
	}
}

func TestRemoteAlphaVaultWorkloadAuthBootstrapUnexpectedExceptionAfterPreflightWritesSafeSummary(t *testing.T) {
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	spireCommandDirectory := filepath.Join(tmpDir, "spire-directory")
	if err := os.Mkdir(spireCommandDirectory, 0o755); err != nil {
		t.Fatalf("mkdir fake spire command directory: %v", err)
	}

	rootToken := "hvs.fakeRootTokenForUnexpectedFailure1234567890"
	proofSecret := "sk-fakeProofSecretForUnexpectedFailure1234567890"
	server, state, caBundle := startFakeBootstrapVault(t, rootToken)
	configPath := filepath.Join(tmpDir, "workload-zone-vault-config.json")
	summaryPath := filepath.Join(tmpDir, "summary", "vault-workload-auth-bootstrap-summary.json")
	writeWorkloadZoneConfig(t, configPath, server.URL, "jwt", "service_execution", "vault", caBundle)

	output, err := runRemoteAlphaBootstrapHelperWithEnv(
		envWithPath(fakeBin,
			"REMOTE_ALPHA_BOOTSTRAP_WORKLOAD_ZONE_CONFIG_PATH="+configPath,
			"REMOTE_ALPHA_BOOTSTRAP_SUMMARY_PATH="+summaryPath,
			"REMOTE_ALPHA_BOOTSTRAP_SPIRE_SERVER_COMMAND="+spireCommandDirectory,
		),
	)
	if err == nil {
		t.Fatalf("expected unexpected post-preflight failure:\n%s", output)
	}
	assertContainsNone(t, "unexpected failure output", output,
		"Vault bootstrap authority token",
		"Proof secret value",
		rootToken,
		proofSecret,
		"Traceback",
	)
	if got := len(state.requests); got != 0 {
		t.Fatalf("unexpected pre-prompt failure must not call fake Vault API, got %d requests", got)
	}
	summary := assertBootstrapFailureSummary(t, summaryPath, "jwt_auth_config", "unexpected_exception", false, false, rootToken, proofSecret)
	if got := summary["failure_message_class"]; got != "permission_error" {
		t.Fatalf("expected sanitized permission_error message class, got %#v", got)
	}
}

func TestRemoteAlphaVaultWorkloadAuthBootstrapPreflightSucceedsWhenSummaryPathIsPreparedWritable(t *testing.T) {
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	setupFakeBootstrapSpireServer(t, fakeBin)

	rootToken := "root-token-for-prepared-preflight"
	proofSecret := "proof-value-for-prepared-preflight"
	server, state, caBundle := startFakeBootstrapVault(t, rootToken)
	configPath := filepath.Join(tmpDir, "workload-zone-vault-config.json")
	writeWorkloadZoneConfig(t, configPath, server.URL, "jwt", "service_execution", "vault", caBundle)

	summaryParent := filepath.Join(tmpDir, "summary-parent")
	if err := os.Mkdir(summaryParent, 0o750); err != nil {
		t.Fatalf("mkdir prepared summary parent: %v", err)
	}
	summaryPath := filepath.Join(summaryParent, "vault-workload-auth-bootstrap-summary.json")

	output, err := runRemoteAlphaBootstrapHelperWithPTYInput(t,
		envWithPath(fakeBin,
			"REMOTE_ALPHA_BOOTSTRAP_WORKLOAD_ZONE_CONFIG_PATH="+configPath,
			"REMOTE_ALPHA_BOOTSTRAP_SUMMARY_PATH="+summaryPath,
		),
		rootToken+"\n"+proofSecret+"\n",
	)
	if err != nil {
		t.Fatalf("bootstrap helper should pass after prepared writable summary path: %v\noutput=%s", err, output)
	}
	if len(state.requests) == 0 {
		t.Fatalf("prepared writable summary preflight should allow fake Vault API calls")
	}
	summary := readJSONFile(t, summaryPath)
	operations, ok := summary["operations"].(map[string]any)
	if !ok {
		t.Fatalf("unexpected operations block %#v", summary["operations"])
	}
	summaryPreflight, ok := operations["summary_preflight"].(map[string]any)
	if !ok || summaryPreflight["status"] != "pass" {
		t.Fatalf("expected summary preflight pass after prepared writable path, got %#v", operations["summary_preflight"])
	}
	assertContainsNone(t, "prepared writable bootstrap output secrets", output,
		rootToken,
		proofSecret,
		"summary_preflight_failed",
	)
	tmpMatches, err := filepath.Glob(filepath.Join(summaryParent, "*.tmp"))
	if err != nil {
		t.Fatalf("glob temp summaries after prepared writable success: %v", err)
	}
	hiddenTmpMatches, err := filepath.Glob(filepath.Join(summaryParent, ".*.tmp"))
	if err != nil {
		t.Fatalf("glob hidden temp summaries after prepared writable success: %v", err)
	}
	if len(tmpMatches)+len(hiddenTmpMatches) != 0 {
		t.Fatalf("prepared writable success must not leave temp summaries, visible=%v hidden=%v", tmpMatches, hiddenTmpMatches)
	}
}

func TestRemoteAlphaVaultWorkloadAuthBootstrapFakeVaultWritesExpectedObjectsAndSafeSummary(t *testing.T) {
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	spireLog := setupFakeBootstrapSpireServer(t, fakeBin)

	rootToken := "root-token-for-fake-bootstrap"
	proofSecret := "proof-value-for-fake-bootstrap"
	server, state, caBundle := startFakeBootstrapVault(t, rootToken)
	configPath := filepath.Join(tmpDir, "workload-zone-vault-config.json")
	summaryPath := filepath.Join(tmpDir, "summary", "vault-workload-auth-bootstrap-summary.json")
	writeWorkloadZoneConfig(t, configPath, server.URL, "jwt", "service_execution", "vault", caBundle)

	output, err := runRemoteAlphaBootstrapHelperWithPTYInput(t,
		envWithPath(fakeBin,
			"REMOTE_ALPHA_BOOTSTRAP_WORKLOAD_ZONE_CONFIG_PATH="+configPath,
			"REMOTE_ALPHA_BOOTSTRAP_SUMMARY_PATH="+summaryPath,
		),
		rootToken+"\n"+proofSecret+"\n",
	)
	if err != nil {
		t.Fatalf("bootstrap helper fake run failed: %v\noutput=%s\nsummary=%s\nspire=%s", err, output, readIfExists(summaryPath), readIfExists(spireLog))
	}
	assertContainsAll(t, "bootstrap helper fake output", output,
		"Remote Alpha Vault workload-auth bootstrap helper finished.",
		"Remote summary path:",
		"Summary is non-secret evidence/projection only",
		"Workload-auth check, reset/unseal, IM refresh, support-bundle collection, CP proof, and runtime identity generation were not run.",
		"not workload-auth success",
		"not ES Vault token brokerage",
	)
	assertContainsNone(t, "bootstrap helper fake output secrets", output,
		rootToken,
		proofSecret,
		"raw Vault",
	)

	var seen []string
	for _, request := range state.requests {
		seen = append(seen, request.Method+" "+request.Path)
	}
	joined := strings.Join(seen, "\n")
	assertContainsAll(t, "fake bootstrap Vault requests", joined,
		"GET /v1/sys/auth",
		"POST /v1/sys/auth/jwt",
		"GET /v1/sys/mounts",
		"POST /v1/sys/mounts/proof-secrets",
		"PUT /v1/sys/policies/acl/runtime-identity-proof",
		"POST /v1/auth/jwt/config",
		"POST /v1/auth/jwt/role/service_execution",
		"POST /v1/proof-secrets/data/runtime-identity-vault-login",
		"POST /v1/proof-secrets/data/codex-runtime-profile",
	)
	assertContainsNone(t, "fake bootstrap Vault requests forbidden live checks", joined,
		"/auth/jwt/login",
		"/auth/token/lookup-self",
		"/auth/token/revoke-self",
		"reset",
		"unseal",
	)

	roleRequest := findFakeBootstrapRequest(t, state.requests, "POST", "/v1/auth/jwt/role/service_execution")
	if got := roleRequest.Body["role_type"]; got != "jwt" {
		t.Fatalf("expected role_type jwt, got %#v", got)
	}
	if got := roleRequest.Body["user_claim"]; got != "sub" {
		t.Fatalf("expected user_claim sub, got %#v", got)
	}
	if got := fmt.Sprint(roleRequest.Body["bound_subject"]); got != "spiffe://execution.internal/workload" {
		t.Fatalf("unexpected bound_subject %q", got)
	}

	proofRequest := findFakeBootstrapRequest(t, state.requests, "POST", "/v1/proof-secrets/data/codex-runtime-profile")
	proofData, ok := proofRequest.Body["data"].(map[string]any)
	if !ok || proofData["api_key"] != proofSecret {
		t.Fatalf("expected fake proof secret api_key to be written to Vault API body, got %#v", proofRequest.Body)
	}

	summaryRaw := mustRead(t, summaryPath)
	assertContainsNone(t, "bootstrap summary secrets", summaryRaw,
		rootToken,
		proofSecret,
		"X-Vault-Token",
		`"keys"`,
		`"n":`,
		`"e":`,
		"jwt-svid",
		"AQAB",
	)
	summary := readJSONFile(t, summaryPath)
	if got := summary["schema_version"]; got != "execution-substrate.remote-alpha.vault-workload-auth-bootstrap-summary.v1" {
		t.Fatalf("unexpected summary schema %#v", got)
	}
	if got := summary["overall_status"]; got != "pass" {
		t.Fatalf("unexpected summary status %#v", got)
	}
	operations, ok := summary["operations"].(map[string]any)
	if !ok {
		t.Fatalf("unexpected operations block %#v", summary["operations"])
	}
	summaryPreflight, ok := operations["summary_preflight"].(map[string]any)
	if !ok || summaryPreflight["status"] != "pass" {
		t.Fatalf("expected summary preflight pass, got %#v", operations["summary_preflight"])
	}
	configLoad, ok := operations["config_load"].(map[string]any)
	if !ok || configLoad["status"] != "pass" {
		t.Fatalf("expected config load pass after readable config preflight, got %#v", operations["config_load"])
	}
	spireMaterial, ok := operations["spire_jwt_validation_material"].(map[string]any)
	if !ok || spireMaterial["status"] != "pass" || spireMaterial["public_key_digest"] == "" {
		t.Fatalf("expected SPIRE JWT validation material preflight pass with digest only, got %#v", operations["spire_jwt_validation_material"])
	}
	redaction, ok := summary["redaction"].(map[string]any)
	if !ok || redaction["root_token_recorded"] != false || redaction["proof_secret_value_recorded"] != false {
		t.Fatalf("unexpected redaction block %#v", summary["redaction"])
	}
	assertContainsAll(t, "bootstrap summary safe labels", summaryRaw,
		`"operation_mode": "execute_bootstrap"`,
		`"summary_preflight": {`,
		`"auth_mount": "jwt"`,
		`"role": "service_execution"`,
		`"policy": "runtime-identity-proof"`,
		`"proof_runtime_secret_field_label": "api_key"`,
		`"workload_auth_success"`,
		`"not_es_vault_token_brokerage"`,
	)
	tmpMatches, err := filepath.Glob(filepath.Join(filepath.Dir(summaryPath), "*.tmp"))
	if err != nil {
		t.Fatalf("glob temp summaries after success: %v", err)
	}
	hiddenTmpMatches, err := filepath.Glob(filepath.Join(filepath.Dir(summaryPath), ".*.tmp"))
	if err != nil {
		t.Fatalf("glob hidden temp summaries after success: %v", err)
	}
	if len(tmpMatches)+len(hiddenTmpMatches) != 0 {
		t.Fatalf("successful bootstrap must not leave temp summaries, visible=%v hidden=%v", tmpMatches, hiddenTmpMatches)
	}

	spireLogRaw := readIfExists(spireLog)
	assertContainsAll(t, "fake spire log", spireLogRaw,
		"bundle show -format spiffe",
	)
	assertContainsNone(t, "fake spire log must not receive secrets", spireLogRaw,
		rootToken,
		proofSecret,
		"VAULT_TOKEN",
	)
}

func TestRemoteAlphaVaultWorkloadAuthBootstrapSourceKeepsRedactionBeforeFinalSummaryMove(t *testing.T) {
	source := mustRead(t, remoteAlphaVaultWorkloadAuthBootstrapInternalPath())
	writeSummarySection := docSection(t, source, "def write_summary(secrets=()):", "\ndef prompt_secret(prompt):")

	redactionIndex := strings.Index(writeSummarySection, "validate_summary_no_secrets(text, secrets)")
	tempIndex := strings.Index(writeSummarySection, "tempfile.NamedTemporaryFile")
	moveIndex := strings.Index(writeSummarySection, "temp_path.replace(SUMMARY_PATH)")
	cleanupIndex := strings.Index(writeSummarySection, "cleanup_path(temp_path)")
	for label, index := range map[string]int{
		"redaction": redactionIndex,
		"temp":      tempIndex,
		"move":      moveIndex,
		"cleanup":   cleanupIndex,
	} {
		if index < 0 {
			t.Fatalf("write_summary missing %s operation:\n%s", label, writeSummarySection)
		}
	}
	if !(redactionIndex < tempIndex && tempIndex < moveIndex) {
		t.Fatalf("write_summary must validate redaction before temp write and final move:\n%s", writeSummarySection)
	}
}

func TestRemoteAlphaVaultWorkloadAuthBootstrapSourceKeepsPreflightAndBoundaries(t *testing.T) {
	source := mustRead(t, remoteAlphaVaultWorkloadAuthBootstrapInternalPath())
	mainSection := docSection(t, source, "def main():", "\n\nraise SystemExit(main())")
	executeSection := docSection(t, source, "remote_alpha_vault_workload_auth_bootstrap_execute() {", "\nPY\n}")

	assertContainsAll(t, "bootstrap helper preflight source", mainSection,
		"preflight_summary_writable()",
		"preflight_config_readable()",
		"load_config()",
		"preflight_spire_bundle_read()",
		`set_next_operation("prompt_bootstrap_authority")`,
	)
	summaryIndex := strings.Index(mainSection, "preflight_summary_writable()")
	configIndex := strings.Index(mainSection, "preflight_config_readable()")
	spireIndex := strings.Index(mainSection, "preflight_spire_bundle_read()")
	promptIndex := strings.Index(mainSection, `set_next_operation("prompt_bootstrap_authority")`)
	if summaryIndex < 0 || configIndex < 0 || spireIndex < 0 || promptIndex < 0 || !(summaryIndex < configIndex && configIndex < spireIndex && spireIndex < promptIndex) {
		t.Fatalf("expected summary/config/SPIRE preflights before prompt in main:\n%s", mainSection)
	}

	assertContainsNone(t, "bootstrap helper executable source forbidden surfaces", executeSection,
		`os.environ["VAULT_TOKEN"]`,
		"VAULT_TOKEN=",
		"vault login",
		" tee ",
		"script ",
		"script -",
		"remote_alpha_vault_workload_auth_check",
		"remote_alpha_reset_disposable_vault",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		"cp-proof",
		"runtime_identity_generation",
	)
}

func TestRemoteAlphaVaultWorkloadAuthBootstrapSummaryRedactionScanRejectsSecretLikeContent(t *testing.T) {
	tmpDir := t.TempDir()
	summaryPath := filepath.Join(tmpDir, "bad-summary.json")
	if err := os.WriteFile(summaryPath, []byte(`{"schema_version":"execution-substrate.remote-alpha.vault-workload-auth-bootstrap-summary.v1","leaked":"hvs.secretmaterial123456789012345"}`), 0o600); err != nil {
		t.Fatalf("write bad summary: %v", err)
	}
	script := fmt.Sprintf("set -euo pipefail\nsource %q\nremote_alpha_vault_workload_auth_bootstrap_validate_summary_file %q\n", remoteAlphaVaultWorkloadAuthBootstrapInternalPath(), summaryPath)
	cmd := exec.Command("/bin/bash", "-c", script)
	cmd.Dir = executionSubstrateRepoRoot
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected summary redaction scan failure:\n%s", output)
	}
	assertContainsAll(t, "summary redaction scan failure", string(output),
		"summary contains secret-like material",
	)
}

func findFakeBootstrapRequest(t *testing.T, requests []fakeBootstrapVaultRequest, method, path string) fakeBootstrapVaultRequest {
	t.Helper()
	for _, request := range requests {
		if request.Method == method && request.Path == path {
			return request
		}
	}
	t.Fatalf("missing fake Vault request %s %s", method, path)
	return fakeBootstrapVaultRequest{}
}
