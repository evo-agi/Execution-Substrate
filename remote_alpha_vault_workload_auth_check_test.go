package executionsubstrate_test

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const (
	remoteAlphaDefaultProofReadPath           = "proof-secrets/data/runtime-identity-vault-login"
	remoteAlphaDefaultProofRuntimeSecretPath  = "proof-secrets/data/codex-runtime-profile"
	remoteAlphaDefaultProofRuntimeSecretField = "api_key"
	remoteAlphaDefaultProofRuntimeSecretValue = "proof-runtime-placeholder-token"
)

type fakeVaultServer struct {
	t                  *testing.T
	expectedJWT        string
	clientToken        string
	loginFail          bool
	loginStatus        int
	loginResponse      map[string]any
	loginRawBody       string
	proofPath          string
	runtimeSecretPath  string
	runtimeSecretField string
	lookupCalls        int
	revokeCalls        int
}

func (f *fakeVaultServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.t.Helper()

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/sys/health":
		writeJSON(w, http.StatusOK, map[string]any{
			"initialized":  true,
			"sealed":       false,
			"storage_type": "file",
		})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/jwt/login":
		defer r.Body.Close()
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			f.t.Fatalf("decode login request: %v", err)
		}
		if got := strings.TrimSpace(fmt.Sprint(payload["role"])); got != "service_execution" {
			f.t.Fatalf("unexpected login role %q", got)
		}
		if got := strings.TrimSpace(fmt.Sprint(payload["jwt"])); got != f.expectedJWT {
			f.t.Fatalf("unexpected login jwt %q", got)
		}
		if f.loginFail {
			status := f.loginStatus
			if status == 0 {
				status = http.StatusForbidden
			}
			if f.loginRawBody != "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_, _ = w.Write([]byte(f.loginRawBody))
				return
			}
			payload := f.loginResponse
			if payload == nil {
				payload = map[string]any{"errors": []string{"permission denied"}}
			}
			writeJSON(w, status, payload)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"auth": map[string]any{
				"client_token":   f.clientToken,
				"lease_duration": 300,
				"policies": []string{
					"default",
					"runtime-identity-proof",
				},
			},
		})
	case r.Method == http.MethodGet && r.URL.Path == "/v1/auth/token/lookup-self":
		if got := r.Header.Get("X-Vault-Token"); got != f.clientToken {
			f.t.Fatalf("unexpected lookup token %q", got)
		}
		f.lookupCalls++
		writeJSON(w, http.StatusOK, map[string]any{
			"data": map[string]any{
				"policies": []string{"default", "runtime-identity-proof"},
				"ttl":      300,
			},
		})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/token/revoke-self":
		if got := r.Header.Get("X-Vault-Token"); got != f.clientToken {
			f.t.Fatalf("unexpected revoke token %q", got)
		}
		f.revokeCalls++
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodGet && f.proofPath != "" && r.URL.Path == "/v1/"+strings.TrimPrefix(f.proofPath, "/"):
		if got := r.Header.Get("X-Vault-Token"); got != f.clientToken {
			f.t.Fatalf("unexpected proof token %q", got)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"data": map[string]any{
				"proof": "ok",
			},
		})
	case r.Method == http.MethodGet && f.runtimeSecretPath != "" && r.URL.Path == "/v1/"+strings.TrimPrefix(f.runtimeSecretPath, "/"):
		if got := r.Header.Get("X-Vault-Token"); got != f.clientToken {
			f.t.Fatalf("unexpected runtime secret token %q", got)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"data": map[string]any{
				"data": map[string]any{
					f.runtimeSecretField: remoteAlphaDefaultProofRuntimeSecretValue,
				},
			},
		})
	default:
		writeJSON(w, http.StatusNotFound, map[string]any{"errors": []string{"not found"}})
	}
}

func writeJSON(w http.ResponseWriter, status int, payload map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		panic(err)
	}
}

func encodeJWTPart(t *testing.T, payload map[string]any) string {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal jwt payload: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

func buildJWT(t *testing.T, subject string, audience []string) string {
	t.Helper()
	header := encodeJWTPart(t, map[string]any{
		"alg": "none",
		"typ": "JWT",
	})
	claims := encodeJWTPart(t, map[string]any{
		"sub": subject,
		"aud": audience,
		"iss": "spiffe://execution.internal",
	})
	return header + "." + claims + ".signature"
}

func writeExecutable(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func startFakeVault(t *testing.T, jwt string, loginFail bool, proofPath string, runtimeSecretPath string, runtimeSecretField string) (*httptest.Server, *fakeVaultServer, string) {
	t.Helper()

	state := &fakeVaultServer{
		t:                  t,
		expectedJWT:        jwt,
		clientToken:        "client-token-1234567890",
		loginFail:          loginFail,
		proofPath:          proofPath,
		runtimeSecretPath:  runtimeSecretPath,
		runtimeSecretField: runtimeSecretField,
	}
	server := httptest.NewTLSServer(state)
	t.Cleanup(server.Close)

	cert := server.Certificate()
	if cert == nil {
		t.Fatal("test server certificate was nil")
	}
	return server, state, encodeCertificatePEM(t, cert)
}

func startFakeVaultWithLoginFailure(t *testing.T, jwt string, status int, payload map[string]any, rawBody string) (*httptest.Server, *fakeVaultServer, string) {
	t.Helper()

	server, state, caBundlePEM := startFakeVault(
		t,
		jwt,
		true,
		"",
		remoteAlphaDefaultProofRuntimeSecretPath,
		remoteAlphaDefaultProofRuntimeSecretField,
	)
	state.loginStatus = status
	state.loginResponse = payload
	state.loginRawBody = rawBody
	return server, state, caBundlePEM
}

func encodeCertificatePEM(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		t.Fatalf("encode certificate: %v", err)
	}
	return buf.String()
}

func writeWorkloadZoneConfig(t *testing.T, path, address, authMount, authRole, audience, caBundlePEM string) {
	t.Helper()
	payload := map[string]any{
		"vault_config": map[string]any{
			"address":       address,
			"auth_mount":    authMount,
			"auth_role":     authRole,
			"jwt_audience":  audience,
			"ca_bundle_pem": caBundlePEM,
		},
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func setupFakeCommands(t *testing.T, dir, jwt string) {
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
  is-active:vault|is-active:spire-agent|is-active:spire-server|is-enabled:vault|is-enabled:spire-agent|is-enabled:spire-server)
    exit 0
    ;;
esac
exit 1
`)
	writeExecutable(t, dir, "spire-agent", fmt.Sprintf(`#!/bin/sh
if [ "$1" = "healthcheck" ]; then
  exit 0
fi
if [ "$1" = "api" ] && [ "$2" = "fetch" ] && [ "$3" = "jwt" ]; then
  printf 'token: %s\n' %q
  exit 0
fi
exit 1
`, jwt, jwt))
	writeExecutable(t, dir, "spire-server", `#!/bin/sh
if [ "$1" = "healthcheck" ]; then
  exit 0
fi
if [ "$1" = "bundle" ] && [ "$2" = "show" ]; then
  echo "spiffe://execution.internal"
  exit 0
fi
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
	writeExecutable(t, dir, "ss", `#!/bin/sh
cat <<'EOF'
LISTEN 0 128 172.17.0.1:8200 0.0.0.0:*
EOF
`)
}

func runSourcedHelper(t *testing.T, env []string, shellBody string) ([]byte, error) {
	t.Helper()
	helperPath := filepath.Join("/Users/ds/Repositories/Execution Substrate", "scripts", "internal", "remote_alpha_vault_workload_auth_check.sh")
	script := fmt.Sprintf("set -euo pipefail\nsource %q\n%s\n", helperPath, shellBody)
	cmd := exec.Command("/bin/bash", "-c", script)
	cmd.Dir = "/Users/ds/Repositories/Execution Substrate"
	cmd.Env = env
	return cmd.CombinedOutput()
}

func readJSONFile(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	return payload
}

func jsonMap(t *testing.T, value any) map[string]any {
	t.Helper()
	payload, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("expected map, got %T", value)
	}
	return payload
}

func jsonStringSlice(t *testing.T, value any) []string {
	t.Helper()
	values, ok := value.([]any)
	if !ok {
		t.Fatalf("expected []any, got %T", value)
	}
	result := make([]string, 0, len(values))
	for _, item := range values {
		text, ok := item.(string)
		if !ok {
			t.Fatalf("expected string slice entry, got %T", item)
		}
		result = append(result, text)
	}
	return result
}

func envWithPath(fakeBin string, extra ...string) []string {
	values := map[string]string{}
	for _, entry := range os.Environ() {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		values[key] = value
	}
	values["PATH"] = fakeBin + string(os.PathListSeparator) + values["PATH"]
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

func runWorkloadAuthCheckForFakeVault(t *testing.T, jwt string, serverURL string, caBundlePEM string) (map[string]any, string, []byte, error) {
	t.Helper()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	setupFakeCommands(t, fakeBin, jwt)

	configPath := filepath.Join(tmpDir, "workload-zone-vault-config.json")
	summaryPath := filepath.Join(tmpDir, "vault-workload-auth-summary.json")
	writeWorkloadZoneConfig(t, configPath, serverURL, "jwt", "service_execution", "vault", caBundlePEM)

	output, err := runSourcedHelper(t, envWithPath(fakeBin,
		"REMOTE_ALPHA_VAULT_ADDRESS="+serverURL,
		"REMOTE_ALPHA_WORKLOAD_ZONE_CONFIG_PATH="+configPath,
		"REMOTE_ALPHA_SUMMARY_PATH="+summaryPath,
		"REMOTE_ALPHA_TEST_PASSWORDLESS_SUDO_FOR_DS=false",
		"REMOTE_ALPHA_TEST_RAW_SPIRE_SOCKET_ACCESS_DS=false",
		"REMOTE_ALPHA_TEST_RAW_SPIRE_SOCKET_ACCESS_UID_10000=false",
	), "remote_alpha_vault_workload_auth_check_main")
	if _, statErr := os.Stat(summaryPath); statErr != nil {
		return nil, "", output, err
	}

	return readJSONFile(t, summaryPath), mustRead(t, summaryPath), output, err
}

func TestRemoteAlphaVaultWorkloadAuthCheckPassWritesSafeSummary(t *testing.T) {
	t.Parallel()

	jwt := buildJWT(t, "spiffe://execution.internal/workload", []string{"vault"})
	server, state, caBundlePEM := startFakeVault(
		t,
		jwt,
		false,
		remoteAlphaDefaultProofReadPath,
		remoteAlphaDefaultProofRuntimeSecretPath,
		remoteAlphaDefaultProofRuntimeSecretField,
	)

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	setupFakeCommands(t, fakeBin, jwt)

	configPath := filepath.Join(tmpDir, "workload-zone-vault-config.json")
	summaryPath := filepath.Join(tmpDir, "vault-workload-auth-summary.json")
	writeWorkloadZoneConfig(t, configPath, server.URL, "jwt", "service_execution", "vault", caBundlePEM)

	output, err := runSourcedHelper(t, envWithPath(fakeBin,
		"REMOTE_ALPHA_VAULT_ADDRESS="+server.URL,
		"REMOTE_ALPHA_WORKLOAD_ZONE_CONFIG_PATH="+configPath,
		"REMOTE_ALPHA_SUMMARY_PATH="+summaryPath,
		"REMOTE_ALPHA_TEST_PASSWORDLESS_SUDO_FOR_DS=false",
		"REMOTE_ALPHA_TEST_RAW_SPIRE_SOCKET_ACCESS_DS=false",
		"REMOTE_ALPHA_TEST_RAW_SPIRE_SOCKET_ACCESS_UID_10000=false",
	), "remote_alpha_vault_workload_auth_check_main")
	if err != nil {
		t.Fatalf("check failed: %v\n%s", err, output)
	}

	summary := readJSONFile(t, summaryPath)
	summaryText := mustRead(t, summaryPath)

	if got := summary["schema_version"]; got != "execution-substrate.remote-alpha.vault-workload-auth-summary.v1" {
		t.Fatalf("unexpected schema version %v", got)
	}
	if got := summary["vault_workload_auth_smoke"]; got != "pass" {
		t.Fatalf("unexpected smoke result %v", got)
	}

	vault := jsonMap(t, summary["vault"])
	if got := vault["address"]; got != server.URL {
		t.Fatalf("unexpected vault address %v", got)
	}
	if got := vault["auth_mount"]; got != "jwt" {
		t.Fatalf("unexpected auth mount %v", got)
	}
	if got := vault["role"]; got != "service_execution" {
		t.Fatalf("unexpected role %v", got)
	}
	if got := vault["audience"]; got != "vault" {
		t.Fatalf("unexpected audience %v", got)
	}
	if got := vault["initialized"]; got != true {
		t.Fatalf("unexpected initialized %v", got)
	}
	if got := vault["sealed"]; got != false {
		t.Fatalf("unexpected sealed %v", got)
	}
	if got := vault["storage"]; got != "file" {
		t.Fatalf("unexpected storage %v", got)
	}
	policies := jsonStringSlice(t, vault["policy_names"])
	if len(policies) != 2 || policies[1] != "runtime-identity-proof" {
		t.Fatalf("unexpected policies %v", policies)
	}

	spire := jsonMap(t, summary["spire"])
	if got := spire["trust_domain"]; got != "execution.internal" {
		t.Fatalf("unexpected trust domain %v", got)
	}

	workload := jsonMap(t, summary["workload"])
	if got := workload["spiffe_id"]; got != "spiffe://execution.internal/workload" {
		t.Fatalf("unexpected workload spiffe id %v", got)
	}
	selectors := jsonStringSlice(t, workload["registration_selector_scope"])
	if len(selectors) != 2 || selectors[0] != "unix:gid:0" || selectors[1] != "unix:uid:0" {
		t.Fatalf("unexpected selector scope %v", selectors)
	}
	if got := workload["registration_alpha_only"]; got != true {
		t.Fatalf("unexpected alpha-only marker %v", got)
	}

	authSmoke := jsonMap(t, summary["auth_smoke"])
	for field, want := range map[string]any{
		"jwt_fetch":             "pass",
		"vault_login":           "pass",
		"token_lookup":          "pass",
		"proof_read":            "pass",
		"proof_runtime_secret":  "pass",
		"token_revoked":         "pass",
		"jwt_audience_verified": true,
		"jwt_subject_verified":  true,
		"jwt_issuer_verified":   true,
	} {
		if got := authSmoke[field]; got != want {
			t.Fatalf("unexpected auth smoke %s=%v want %v", field, got, want)
		}
	}
	requirements := jsonMap(t, summary["auth_smoke_requirements"])
	for field, want := range map[string]any{
		"token_lookup_required":         true,
		"proof_read_required":           true,
		"proof_runtime_secret_required": true,
		"token_revoked_required":        true,
		"proof_read_path":               remoteAlphaDefaultProofReadPath,
		"proof_runtime_secret_path":     remoteAlphaDefaultProofRuntimeSecretPath,
		"proof_runtime_secret_field":    remoteAlphaDefaultProofRuntimeSecretField,
	} {
		if got := requirements[field]; got != want {
			t.Fatalf("unexpected auth smoke requirement %s=%v want %v", field, got, want)
		}
	}
	proofRuntimeSecret := jsonMap(t, summary["proof_runtime_secret"])
	for field, want := range map[string]any{
		"status":         "pass",
		"path":           remoteAlphaDefaultProofRuntimeSecretPath,
		"field":          remoteAlphaDefaultProofRuntimeSecretField,
		"field_present":  true,
		"field_nonempty": true,
		"field_shape":    "string",
	} {
		if got := proofRuntimeSecret[field]; got != want {
			t.Fatalf("unexpected proof runtime secret %s=%v want %v", field, got, want)
		}
	}

	reachability := jsonMap(t, summary["reachability"])
	if got := reachability["host_vault_health"]; got != "pass" {
		t.Fatalf("unexpected host reachability %v", got)
	}
	if got := reachability["docker_bridge_vault_health"]; got != "not_exercised" {
		t.Fatalf("unexpected docker reachability %v", got)
	}

	config := jsonMap(t, summary["workload_zone_config"])
	if got := config["validation_result"]; got != "pass" {
		t.Fatalf("unexpected config validation %v", got)
	}
	if got := config["address"]; got != server.URL {
		t.Fatalf("unexpected config address %v", got)
	}
	if got := config["ca_bundle_present"]; got != true {
		t.Fatalf("unexpected ca bundle presence %v", got)
	}
	if digest := fmt.Sprint(config["digest"]); !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("unexpected config digest %q", digest)
	}

	security := jsonMap(t, summary["security"])
	for field, want := range map[string]any{
		"ds_not_in_docker_group":            true,
		"passwordless_sudo_for_ds":          false,
		"raw_spire_socket_access_ds":        false,
		"raw_spire_socket_access_uid_10000": false,
	} {
		if got := security[field]; got != want {
			t.Fatalf("unexpected security %s=%v want %v", field, got, want)
		}
	}

	redaction := jsonMap(t, summary["redaction"])
	for field := range redaction {
		if got := redaction[field]; got != false {
			t.Fatalf("unexpected redaction %s=%v", field, got)
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

	if strings.Contains(summaryText, jwt) {
		t.Fatal("summary unexpectedly contained jwt material")
	}
	if strings.Contains(summaryText, state.clientToken) {
		t.Fatal("summary unexpectedly contained client token material")
	}
	if strings.Contains(summaryText, remoteAlphaDefaultProofRuntimeSecretValue) {
		t.Fatal("summary unexpectedly contained runtime secret material")
	}
	if strings.Contains(summaryText, "-----BEGIN CERTIFICATE-----") {
		t.Fatal("summary unexpectedly contained certificate material")
	}
	if state.lookupCalls != 1 {
		t.Fatalf("expected one lookup call, got %d", state.lookupCalls)
	}
	if state.revokeCalls != 1 {
		t.Fatalf("expected one revoke call, got %d", state.revokeCalls)
	}
}

func TestRemoteAlphaVaultWorkloadAuthCheckWritesSafeFailureSummaryOnVaultLoginFailure(t *testing.T) {
	t.Parallel()

	jwt := buildJWT(t, "spiffe://execution.internal/workload", []string{"vault"})
	server, state, caBundlePEM := startFakeVault(
		t,
		jwt,
		true,
		"",
		remoteAlphaDefaultProofRuntimeSecretPath,
		remoteAlphaDefaultProofRuntimeSecretField,
	)

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	setupFakeCommands(t, fakeBin, jwt)

	configPath := filepath.Join(tmpDir, "workload-zone-vault-config.json")
	summaryPath := filepath.Join(tmpDir, "vault-workload-auth-summary.json")
	writeWorkloadZoneConfig(t, configPath, server.URL, "jwt", "service_execution", "vault", caBundlePEM)

	output, err := runSourcedHelper(t, envWithPath(fakeBin,
		"REMOTE_ALPHA_VAULT_ADDRESS="+server.URL,
		"REMOTE_ALPHA_WORKLOAD_ZONE_CONFIG_PATH="+configPath,
		"REMOTE_ALPHA_SUMMARY_PATH="+summaryPath,
		"REMOTE_ALPHA_TEST_PASSWORDLESS_SUDO_FOR_DS=false",
		"REMOTE_ALPHA_TEST_RAW_SPIRE_SOCKET_ACCESS_DS=false",
		"REMOTE_ALPHA_TEST_RAW_SPIRE_SOCKET_ACCESS_UID_10000=false",
	), "remote_alpha_vault_workload_auth_check_main")
	if err == nil {
		t.Fatalf("expected login failure, got success\n%s", output)
	}
	if _, statErr := os.Stat(summaryPath); statErr != nil {
		t.Fatalf("expected failure summary to be written: %v\n%s", statErr, output)
	}

	summary := readJSONFile(t, summaryPath)
	summaryText := mustRead(t, summaryPath)

	if got := summary["vault_workload_auth_smoke"]; got != "fail" {
		t.Fatalf("unexpected smoke result %v", got)
	}
	authSmoke := jsonMap(t, summary["auth_smoke"])
	for field, want := range map[string]any{
		"jwt_fetch":                      "pass",
		"vault_login":                    "fail",
		"token_lookup":                   "not_exercised",
		"proof_read":                     "not_exercised",
		"proof_runtime_secret":           "not_exercised",
		"token_revoked":                  "not_exercised",
		"jwt_audience_verified":          true,
		"jwt_subject_verified":           true,
		"jwt_issuer_verified":            true,
		"vault_login_failure_phase":      "vault_login",
		"vault_login_failure_class":      "permission_denied",
		"vault_login_http_status":        float64(http.StatusForbidden),
		"vault_login_error_count":        float64(1),
		"vault_login_error_class":        "permission_denied",
		"vault_login_raw_error_recorded": false,
	} {
		if got := authSmoke[field]; got != want {
			t.Fatalf("unexpected auth smoke %s=%v want %v", field, got, want)
		}
	}
	requirements := jsonMap(t, summary["auth_smoke_requirements"])
	if got := requirements["proof_read_path"]; got != remoteAlphaDefaultProofReadPath {
		t.Fatalf("unexpected proof read path %v", got)
	}
	if got := requirements["proof_runtime_secret_path"]; got != remoteAlphaDefaultProofRuntimeSecretPath {
		t.Fatalf("unexpected proof runtime secret path %v", got)
	}
	if got := requirements["proof_runtime_secret_field"]; got != remoteAlphaDefaultProofRuntimeSecretField {
		t.Fatalf("unexpected proof runtime secret field %v", got)
	}

	if strings.Contains(summaryText, jwt) {
		t.Fatal("summary unexpectedly contained jwt material")
	}
	if strings.Contains(summaryText, state.clientToken) {
		t.Fatal("summary unexpectedly contained client token material")
	}
	if strings.Contains(summaryText, "permission denied") {
		t.Fatal("summary unexpectedly contained raw Vault login error text")
	}
	if state.lookupCalls != 0 {
		t.Fatalf("unexpected lookup calls %d", state.lookupCalls)
	}
	if state.revokeCalls != 0 {
		t.Fatalf("unexpected revoke calls %d", state.revokeCalls)
	}
}

func TestRemoteAlphaVaultWorkloadAuthCheckClassifiesVaultLoginHTTPFailures(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		status     int
		payload    map[string]any
		wantClass  string
		rawSnippet string
	}{
		{
			name:       "400 invalid audience",
			status:     http.StatusBadRequest,
			payload:    map[string]any{"errors": []string{"audience claim does not match bound audience"}},
			wantClass:  "invalid_audience",
			rawSnippet: "audience claim does not match bound audience",
		},
		{
			name:       "403 permission denied",
			status:     http.StatusForbidden,
			payload:    map[string]any{"errors": []string{"permission denied"}},
			wantClass:  "permission_denied",
			rawSnippet: "permission denied",
		},
		{
			name:       "500 vault api error",
			status:     http.StatusInternalServerError,
			payload:    map[string]any{"errors": []string{"internal server error"}},
			wantClass:  "vault_api_error",
			rawSnippet: "internal server error",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			jwt := buildJWT(t, "spiffe://execution.internal/workload", []string{"vault"})
			server, state, caBundlePEM := startFakeVaultWithLoginFailure(t, jwt, tc.status, tc.payload, "")

			summary, summaryText, output, err := runWorkloadAuthCheckForFakeVault(t, jwt, server.URL, caBundlePEM)
			if err == nil {
				t.Fatalf("expected login failure, got success\n%s", output)
			}
			if got := summary["vault_workload_auth_smoke"]; got != "fail" {
				t.Fatalf("unexpected smoke result %v", got)
			}

			authSmoke := jsonMap(t, summary["auth_smoke"])
			for field, want := range map[string]any{
				"jwt_fetch":                      "pass",
				"jwt_audience_verified":          true,
				"jwt_subject_verified":           true,
				"jwt_issuer_verified":            true,
				"vault_login":                    "fail",
				"vault_login_failure_phase":      "vault_login",
				"vault_login_failure_class":      tc.wantClass,
				"vault_login_http_status":        float64(tc.status),
				"vault_login_error_count":        float64(1),
				"vault_login_error_class":        tc.wantClass,
				"vault_login_raw_error_recorded": false,
				"token_lookup":                   "not_exercised",
				"proof_read":                     "not_exercised",
				"proof_runtime_secret":           "not_exercised",
				"token_revoked":                  "not_exercised",
			} {
				if got := authSmoke[field]; got != want {
					t.Fatalf("unexpected auth smoke %s=%v want %v", field, got, want)
				}
			}

			if strings.Contains(summaryText, jwt) {
				t.Fatal("summary unexpectedly contained jwt material")
			}
			if strings.Contains(summaryText, state.clientToken) {
				t.Fatal("summary unexpectedly contained client token material")
			}
			if strings.Contains(summaryText, tc.rawSnippet) {
				t.Fatalf("summary unexpectedly contained raw Vault login error text %q", tc.rawSnippet)
			}
			if state.lookupCalls != 0 {
				t.Fatalf("unexpected lookup calls %d", state.lookupCalls)
			}
			if state.revokeCalls != 0 {
				t.Fatalf("unexpected revoke calls %d", state.revokeCalls)
			}
		})
	}
}

func TestRemoteAlphaVaultWorkloadAuthCheckClassifiesMissingLoginTokenAsInvalidResponse(t *testing.T) {
	t.Parallel()

	jwt := buildJWT(t, "spiffe://execution.internal/workload", []string{"vault"})
	rawMarker := "raw-login-response-marker-missing-client-token"
	server, state, caBundlePEM := startFakeVaultWithLoginFailure(t, jwt, http.StatusOK, map[string]any{
		"auth": map[string]any{
			"lease_duration": 300,
			"policies":       []string{"default"},
		},
		"debug": rawMarker,
	}, "")

	summary, summaryText, output, err := runWorkloadAuthCheckForFakeVault(t, jwt, server.URL, caBundlePEM)
	if err == nil {
		t.Fatalf("expected missing client token failure, got success\n%s", output)
	}

	authSmoke := jsonMap(t, summary["auth_smoke"])
	for field, want := range map[string]any{
		"vault_login":                    "fail",
		"vault_login_failure_phase":      "vault_login",
		"vault_login_failure_class":      "invalid_response",
		"vault_login_http_status":        float64(http.StatusOK),
		"vault_login_error_count":        float64(0),
		"vault_login_error_class":        "invalid_response",
		"vault_login_raw_error_recorded": false,
		"token_lookup":                   "not_exercised",
		"proof_read":                     "not_exercised",
		"proof_runtime_secret":           "not_exercised",
		"token_revoked":                  "not_exercised",
	} {
		if got := authSmoke[field]; got != want {
			t.Fatalf("unexpected auth smoke %s=%v want %v", field, got, want)
		}
	}

	if strings.Contains(summaryText, rawMarker) {
		t.Fatal("summary unexpectedly contained raw Vault login response body")
	}
	if strings.Contains(summaryText, jwt) {
		t.Fatal("summary unexpectedly contained jwt material")
	}
	if strings.Contains(summaryText, state.clientToken) {
		t.Fatal("summary unexpectedly contained client token material")
	}
	if state.lookupCalls != 0 {
		t.Fatalf("unexpected lookup calls %d", state.lookupCalls)
	}
	if state.revokeCalls != 0 {
		t.Fatalf("unexpected revoke calls %d", state.revokeCalls)
	}
}

func TestRemoteAlphaVaultWorkloadAuthCheckDoesNotPersistSecretLikeLoginErrors(t *testing.T) {
	t.Parallel()

	jwt := buildJWT(t, "spiffe://execution.internal/workload", []string{"vault"})
	vaultToken := "hvs.secretmaterial123456"
	rootToken := "root-token-secret-value"
	proofSecret := remoteAlphaDefaultProofRuntimeSecretValue
	apiKey := "sk-live-secret-api-key-123456"
	privateKey := "-----BEGIN PRIVATE KEY-----"
	rawHeader := "X-Vault-Token: " + vaultToken
	authHeader := "Authorization: Bearer " + vaultToken
	rawMarker := "raw-login-response-marker-secret-bearing"
	rawError := strings.Join([]string{
		"role rejected",
		rawMarker,
		jwt,
		vaultToken,
		rootToken,
		proofSecret,
		apiKey,
		privateKey,
		rawHeader,
		authHeader,
	}, " ")

	server, state, caBundlePEM := startFakeVaultWithLoginFailure(t, jwt, http.StatusBadRequest, map[string]any{
		"errors": []string{rawError},
	}, "")

	summary, summaryText, output, err := runWorkloadAuthCheckForFakeVault(t, jwt, server.URL, caBundlePEM)
	if err == nil {
		t.Fatalf("expected secret-bearing login error failure, got success\n%s", output)
	}

	authSmoke := jsonMap(t, summary["auth_smoke"])
	for field, want := range map[string]any{
		"vault_login":                    "fail",
		"vault_login_failure_phase":      "vault_login",
		"vault_login_failure_class":      "role_missing_or_rejected",
		"vault_login_http_status":        float64(http.StatusBadRequest),
		"vault_login_error_count":        float64(1),
		"vault_login_error_class":        "role_missing_or_rejected",
		"vault_login_raw_error_recorded": false,
		"token_lookup":                   "not_exercised",
		"proof_read":                     "not_exercised",
		"proof_runtime_secret":           "not_exercised",
		"token_revoked":                  "not_exercised",
	} {
		if got := authSmoke[field]; got != want {
			t.Fatalf("unexpected auth smoke %s=%v want %v", field, got, want)
		}
	}

	for _, forbidden := range []string{
		jwt,
		vaultToken,
		rootToken,
		proofSecret,
		apiKey,
		privateKey,
		rawHeader,
		authHeader,
		rawMarker,
		rawError,
	} {
		if strings.Contains(summaryText, forbidden) {
			t.Fatalf("summary unexpectedly contained secret or raw login material %q", forbidden)
		}
	}
	if state.lookupCalls != 0 {
		t.Fatalf("unexpected lookup calls %d", state.lookupCalls)
	}
	if state.revokeCalls != 0 {
		t.Fatalf("unexpected revoke calls %d", state.revokeCalls)
	}
}

func TestRemoteAlphaVaultWorkloadAuthCheckSourceKeepsLoginFailureTriageRedacted(t *testing.T) {
	t.Parallel()

	source := mustRead(t, "scripts/internal/remote_alpha_vault_workload_auth_check.sh")
	for _, required := range []string{
		"SAFE_CLASSES",
		"error_count",
		"failure_class",
		"raw_error_recorded",
		"vault_login_raw_error_recorded",
		"remote_alpha_vault_validate_summary_file",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("workload-auth check source missing redaction/classification guard %q", required)
		}
	}
	for _, forbidden := range []string{
		"VAULT_TOKEN=",
		"ROOT_TOKEN",
		"Authorization",
		"raw_headers",
		"Traceback",
		".out",
		"tee ",
		"script ",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("workload-auth check source unexpectedly contains forbidden logging/env/report surface %q", forbidden)
		}
	}
}

func TestRemoteAlphaVaultValidateSummaryRejectsSecretLikeMaterial(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	summaryPath := filepath.Join(tmpDir, "summary.json")
	secretSummary := `{"schema_version":"execution-substrate.remote-alpha.vault-workload-auth-summary.v1","bad":"eyJhbGciOiJub25lIn0.eyJzdWIiOiJzcGlmZmU6Ly9leGVjdXRpb24uaW50ZXJuYWwvd29ya2xvYWQifQ.signature","token":"hvs.secretmaterial123456"}`
	if err := os.WriteFile(summaryPath, []byte(secretSummary), 0o600); err != nil {
		t.Fatalf("write summary: %v", err)
	}

	output, err := runSourcedHelper(t, os.Environ(), fmt.Sprintf("remote_alpha_vault_validate_summary_file %q", summaryPath))
	if err == nil {
		t.Fatalf("expected validator to fail for secret-like material")
	}
	if !strings.Contains(string(output), "summary contains secret-like material") {
		t.Fatalf("unexpected validator output %q", output)
	}
}

func TestRemoteAlphaVaultValidateWorkloadZoneConfigRejectsMismatchedAudience(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "workload-zone-vault-config.json")
	writeWorkloadZoneConfig(t, configPath, "https://127.0.0.1:8200", "jwt", "service_execution", "wrong-audience", "")

	output, err := runSourcedHelper(t, os.Environ(), fmt.Sprintf(
		"remote_alpha_vault_validate_workload_zone_config %q %q %q %q %q",
		configPath,
		"https://127.0.0.1:8200",
		"jwt",
		"service_execution",
		"vault",
	))
	if err != nil {
		t.Fatalf("validation helper failed unexpectedly: %v\n%s", err, output)
	}

	var payload map[string]any
	if err := json.Unmarshal(output, &payload); err != nil {
		t.Fatalf("unmarshal validation output: %v\n%s", err, output)
	}
	if got := payload["validation_result"]; got != "fail" {
		t.Fatalf("unexpected validation result %v", got)
	}
	if message := fmt.Sprint(payload["validation_error"]); !strings.Contains(message, "jwt_audience") {
		t.Fatalf("unexpected validation error %q", message)
	}
}

func TestRemoteAlphaVaultWorkloadAuthCheckFailsWhenRequiredProofReadDoesNotPass(t *testing.T) {
	t.Parallel()

	jwt := buildJWT(t, "spiffe://execution.internal/workload", []string{"vault"})
	server, state, caBundlePEM := startFakeVault(
		t,
		jwt,
		false,
		"",
		remoteAlphaDefaultProofRuntimeSecretPath,
		remoteAlphaDefaultProofRuntimeSecretField,
	)

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	setupFakeCommands(t, fakeBin, jwt)

	configPath := filepath.Join(tmpDir, "workload-zone-vault-config.json")
	summaryPath := filepath.Join(tmpDir, "vault-workload-auth-summary.json")
	writeWorkloadZoneConfig(t, configPath, server.URL, "jwt", "service_execution", "vault", caBundlePEM)

	output, err := runSourcedHelper(t, envWithPath(fakeBin,
		"REMOTE_ALPHA_VAULT_ADDRESS="+server.URL,
		"REMOTE_ALPHA_WORKLOAD_ZONE_CONFIG_PATH="+configPath,
		"REMOTE_ALPHA_SUMMARY_PATH="+summaryPath,
		"REMOTE_ALPHA_TEST_PASSWORDLESS_SUDO_FOR_DS=false",
		"REMOTE_ALPHA_TEST_RAW_SPIRE_SOCKET_ACCESS_DS=false",
		"REMOTE_ALPHA_TEST_RAW_SPIRE_SOCKET_ACCESS_UID_10000=false",
	), "remote_alpha_vault_workload_auth_check_main")
	if err == nil {
		t.Fatalf("expected proof read failure, got success\n%s", output)
	}

	summary := readJSONFile(t, summaryPath)
	if got := summary["vault_workload_auth_smoke"]; got != "fail" {
		t.Fatalf("unexpected smoke result %v", got)
	}
	authSmoke := jsonMap(t, summary["auth_smoke"])
	if got := authSmoke["token_lookup"]; got != "pass" {
		t.Fatalf("unexpected token lookup result %v", got)
	}
	if got := authSmoke["proof_read"]; got != "not_exercised" {
		t.Fatalf("unexpected proof read result %v", got)
	}
	if got := authSmoke["proof_runtime_secret"]; got != "pass" {
		t.Fatalf("unexpected proof runtime secret result %v", got)
	}
	failureReasons, ok := summary["failure_reasons"].([]any)
	if !ok {
		t.Fatalf("unexpected failure reasons payload %T", summary["failure_reasons"])
	}
	joined := make([]string, 0, len(failureReasons))
	for _, item := range failureReasons {
		joined = append(joined, fmt.Sprint(item))
	}
	if !strings.Contains(strings.Join(joined, " | "), "proof path was not present") {
		t.Fatalf("expected proof read failure reason, got %v", joined)
	}
	if state.lookupCalls != 1 {
		t.Fatalf("expected one lookup call, got %d", state.lookupCalls)
	}
	if state.revokeCalls != 1 {
		t.Fatalf("expected one revoke call, got %d", state.revokeCalls)
	}
}

func TestRemoteAlphaVaultWorkloadAuthCheckFailsWhenRequiredProofRuntimeSecretDoesNotPass(t *testing.T) {
	t.Parallel()

	jwt := buildJWT(t, "spiffe://execution.internal/workload", []string{"vault"})
	server, state, caBundlePEM := startFakeVault(
		t,
		jwt,
		false,
		remoteAlphaDefaultProofReadPath,
		"",
		remoteAlphaDefaultProofRuntimeSecretField,
	)

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	setupFakeCommands(t, fakeBin, jwt)

	configPath := filepath.Join(tmpDir, "workload-zone-vault-config.json")
	summaryPath := filepath.Join(tmpDir, "vault-workload-auth-summary.json")
	writeWorkloadZoneConfig(t, configPath, server.URL, "jwt", "service_execution", "vault", caBundlePEM)

	output, err := runSourcedHelper(t, envWithPath(fakeBin,
		"REMOTE_ALPHA_VAULT_ADDRESS="+server.URL,
		"REMOTE_ALPHA_WORKLOAD_ZONE_CONFIG_PATH="+configPath,
		"REMOTE_ALPHA_SUMMARY_PATH="+summaryPath,
		"REMOTE_ALPHA_TEST_PASSWORDLESS_SUDO_FOR_DS=false",
		"REMOTE_ALPHA_TEST_RAW_SPIRE_SOCKET_ACCESS_DS=false",
		"REMOTE_ALPHA_TEST_RAW_SPIRE_SOCKET_ACCESS_UID_10000=false",
	), "remote_alpha_vault_workload_auth_check_main")
	if err == nil {
		t.Fatalf("expected proof runtime secret failure, got success\n%s", output)
	}

	summary := readJSONFile(t, summaryPath)
	if got := summary["vault_workload_auth_smoke"]; got != "fail" {
		t.Fatalf("unexpected smoke result %v", got)
	}
	authSmoke := jsonMap(t, summary["auth_smoke"])
	if got := authSmoke["proof_read"]; got != "pass" {
		t.Fatalf("unexpected proof read result %v", got)
	}
	if got := authSmoke["proof_runtime_secret"]; got != "not_exercised" {
		t.Fatalf("unexpected proof runtime secret result %v", got)
	}
	proofRuntimeSecret := jsonMap(t, summary["proof_runtime_secret"])
	if got := proofRuntimeSecret["path"]; got != remoteAlphaDefaultProofRuntimeSecretPath {
		t.Fatalf("unexpected proof runtime secret path %v", got)
	}
	if got := proofRuntimeSecret["field"]; got != remoteAlphaDefaultProofRuntimeSecretField {
		t.Fatalf("unexpected proof runtime secret field %v", got)
	}
	failureReasons, ok := summary["failure_reasons"].([]any)
	if !ok {
		t.Fatalf("unexpected failure reasons payload %T", summary["failure_reasons"])
	}
	joined := make([]string, 0, len(failureReasons))
	for _, item := range failureReasons {
		joined = append(joined, fmt.Sprint(item))
	}
	if !strings.Contains(strings.Join(joined, " | "), "proof runtime secret path was not present") {
		t.Fatalf("expected proof runtime secret failure reason, got %v", joined)
	}
	if state.lookupCalls != 1 {
		t.Fatalf("expected one lookup call, got %d", state.lookupCalls)
	}
	if state.revokeCalls != 1 {
		t.Fatalf("expected one revoke call, got %d", state.revokeCalls)
	}
}
