//go:build linux

package app_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This is a native-Linux bootstrap validation for scripts/72_supported_local_setup.sh.
// On the current Mac + Lima supported-local path, the canonical end-to-end validation
// remains scripts/73_supported_local_proof.sh run because the guest consumes staged
// host inputs and the mounted repo view is not the authoritative proof surface.
func TestSupportedLocalSetupScriptBootstrapsRealSPIREAndVaultDevTarget(t *testing.T) {
	for _, name := range []string{"go", "openssl", "python3", "vault", "curl", "tar"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Skipf("supported-local setup validation requires %s: %v", name, err)
		}
	}

	repoRoot := executionPlatformRepoRoot(t)
	rootDir := newExecutionWorkspaceTempDir(t, "supported-local-setup-")
	proofDir := filepath.Join(rootDir, "proof")
	fakeBinDir := filepath.Join(rootDir, "fake-bin")
	if err := os.MkdirAll(fakeBinDir, 0o755); err != nil {
		t.Fatalf("mkdir fake bin dir: %v", err)
	}
	writeFakeCommand(t, filepath.Join(fakeBinDir, "docker"))
	writeFakeCommand(t, filepath.Join(fakeBinDir, "nomad"))

	vaultPort := reserveTCPPort(t)
	command := exec.Command(filepath.Join(repoRoot, "scripts", "72_supported_local_setup.sh"), "setup")
	command.Dir = repoRoot
	command.Env = append(os.Environ(),
		"EXECUTION_SUBSTRATE_REPO_ROOT="+repoRoot,
		"PATH="+fakeBinDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"SUPPORTED_LOCAL_PROOF_DIR="+proofDir,
		"SUPPORTED_LOCAL_PROOF_ID=validation-proof",
		"SUPPORTED_LOCAL_RUNTIME_SUPPORT_BINARY="+filepath.Join(proofDir, "bin", "es-runtime-support"),
		"SUPPORTED_LOCAL_VAULT_BIND_ADDRESS=127.0.0.1",
		"SUPPORTED_LOCAL_VAULT_PUBLIC_HOST=127.0.0.1",
		"SUPPORTED_LOCAL_VAULT_PORT="+strconv.Itoa(vaultPort),
	)
	if spireTarball := strings.TrimSpace(os.Getenv("SUPPORTED_LOCAL_TEST_SPIRE_TARBALL")); spireTarball != "" {
		command.Env = append(command.Env, "SUPPORTED_LOCAL_PREBUILT_SPIRE_TARBALL="+spireTarball)
	}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("run supported-local setup: %v output=%s", err, string(output))
	}

	t.Cleanup(func() {
		stopProcessFromPIDFile(t, filepath.Join(proofDir, "vault-dev.pid"))
		stopProcessFromPIDFile(t, filepath.Join(proofDir, "spire-agent.pid"))
		stopProcessFromPIDFile(t, filepath.Join(proofDir, "spire-server.pid"))
	})

	managedSecretsPath := filepath.Join(proofDir, "managed-secrets.conf")
	info, err := os.Stat(managedSecretsPath)
	if err != nil {
		t.Fatalf("stat managed-secrets.conf: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected managed-secrets.conf mode 0600, got %o", info.Mode().Perm())
	}

	managed := readShellAssignments(t, managedSecretsPath)
	for _, key := range []string{
		"PROOF_RUNTIME_SUPPORT_BINARY",
		"PROOF_VAULT_ADDR",
		"PROOF_VAULT_LOCAL_ADDR",
		"PROOF_VAULT_AUTH_MOUNT",
		"PROOF_VAULT_AUTH_ROLE",
		"PROOF_VAULT_BOUND_AUDIENCE",
		"PROOF_VAULT_BOUND_SUBJECT",
		"PROOF_VAULT_BOUND_ISSUER",
		"PROOF_VAULT_SECRET_PATH",
		"PROOF_VAULT_SECRET_MOUNT",
		"PROOF_VAULT_SECRET_LOGICAL_PATH",
		"PROOF_VAULT_SECRET_VALUE",
		"PROOF_VAULT_ROOT_TOKEN",
		"PROOF_VAULT_CA_CERT_FILE",
		"PROOF_CODEX_RUNTIME_PROFILE_IMAGE",
		"PROOF_CODEX_CLI_PATH",
		"PROOF_CODEX_REALIZATION",
		"PROOF_CODEX_CREDENTIAL_SECRET_PATH",
		"PROOF_CODEX_CREDENTIAL_SECRET_FIELD",
		"PROOF_CODEX_CREDENTIAL_VALUE",
		"PROOF_SPIRE_VERSION",
		"PROOF_SPIRE_TRUST_DOMAIN",
		"PROOF_SPIRE_JWT_ISSUER",
		"PROOF_SPIRE_AGENT_SPIFFE_ID",
		"PROOF_SPIRE_SERVER_SOCKET_PATH",
		"PROOF_SPIRE_AGENT_SOCKET_PATH",
		"PROOF_SPIRE_BUNDLE_FILE",
		"PROOF_SPIRE_JWT_VALIDATION_PUB_FILE",
	} {
		if strings.TrimSpace(managed[key]) == "" {
			t.Fatalf("expected %s in managed-secrets.conf", key)
		}
	}

	if _, err := os.Stat(filepath.Join(proofDir, "mock-spire.sock")); !os.IsNotExist(err) {
		t.Fatalf("did not expect canonical proof setup to leave mock-spire.sock behind: %v", err)
	}
	if _, err := os.Stat(filepath.Join(proofDir, "bin", "es-workload-api-mock")); !os.IsNotExist(err) {
		t.Fatalf("did not expect canonical proof setup to stage es-workload-api-mock in proof bin: %v", err)
	}

	assertPathIsUnixSocket(t, managed["PROOF_SPIRE_SERVER_SOCKET_PATH"])
	assertPathIsUnixSocket(t, managed["PROOF_SPIRE_AGENT_SOCKET_PATH"])

	serverHealth := runCommand(t, proofDir, filepath.Join(proofDir, "bin", "spire-server"), "healthcheck", "-socketPath", managed["PROOF_SPIRE_SERVER_SOCKET_PATH"])
	if !strings.Contains(serverHealth, "healthy") {
		t.Fatalf("expected healthy spire-server output, got %q", serverHealth)
	}
	agentHealth := runCommand(t, proofDir, filepath.Join(proofDir, "bin", "spire-agent"), "healthcheck", "-socketPath", managed["PROOF_SPIRE_AGENT_SOCKET_PATH"])
	if !strings.Contains(agentHealth, "healthy") {
		t.Fatalf("expected healthy spire-agent output, got %q", agentHealth)
	}

	entryShow := runCommand(
		t,
		proofDir,
		filepath.Join(proofDir, "bin", "spire-server"),
		"entry",
		"show",
		"-socketPath", managed["PROOF_SPIRE_SERVER_SOCKET_PATH"],
		"-spiffeID", managed["PROOF_VAULT_BOUND_SUBJECT"],
	)
	for _, want := range []string{
		managed["PROOF_VAULT_BOUND_SUBJECT"],
		managed["PROOF_SPIRE_AGENT_SPIFFE_ID"],
		"unix:uid:0",
		"unix:gid:0",
	} {
		if !strings.Contains(entryShow, want) {
			t.Fatalf("expected %q in SPIRE workload entry output, got %q", want, entryShow)
		}
	}

	bundleBytes, err := os.ReadFile(managed["PROOF_SPIRE_BUNDLE_FILE"])
	if err != nil {
		t.Fatalf("read SPIRE bundle file: %v", err)
	}
	if !strings.Contains(string(bundleBytes), "\"jwt-svid\"") {
		t.Fatalf("expected SPIRE bundle to carry a jwt-svid authority, got %s", string(bundleBytes))
	}

	jwtValue := mintJWTFromSpireServer(
		t,
		proofDir,
		filepath.Join(proofDir, "bin", "spire-server"),
		managed["PROOF_SPIRE_SERVER_SOCKET_PATH"],
		managed["PROOF_VAULT_BOUND_SUBJECT"],
		managed["PROOF_VAULT_BOUND_AUDIENCE"],
	)
	claims := decodeJWTClaimsUnverifiedForTest(t, jwtValue)
	if got := strings.TrimSpace(claims["iss"]); got != managed["PROOF_VAULT_BOUND_ISSUER"] {
		t.Fatalf("expected issuer %q, got %q", managed["PROOF_VAULT_BOUND_ISSUER"], got)
	}
	if got := strings.TrimSpace(claims["sub"]); got != managed["PROOF_VAULT_BOUND_SUBJECT"] {
		t.Fatalf("expected subject %q, got %q", managed["PROOF_VAULT_BOUND_SUBJECT"], got)
	}
	if !jwtAudienceContains(claims, managed["PROOF_VAULT_BOUND_AUDIENCE"]) {
		t.Fatalf("expected audience %q in claims %#v", managed["PROOF_VAULT_BOUND_AUDIENCE"], claims)
	}

	clientToken := loginToProofVault(
		t,
		managed["PROOF_VAULT_LOCAL_ADDR"],
		managed["PROOF_VAULT_CA_CERT_FILE"],
		managed["PROOF_VAULT_AUTH_MOUNT"],
		managed["PROOF_VAULT_AUTH_ROLE"],
		jwtValue,
	)
	if strings.TrimSpace(clientToken) == "" {
		t.Fatal("expected Vault client token")
	}

	assertSupportedLocalVaultBootstrapState(t, proofDir, managed)

	secretMessage := readProofVaultSecret(
		t,
		managed["PROOF_VAULT_LOCAL_ADDR"],
		managed["PROOF_VAULT_CA_CERT_FILE"],
		managed["PROOF_VAULT_SECRET_PATH"],
		clientToken,
	)
	if secretMessage != managed["PROOF_VAULT_SECRET_VALUE"] {
		t.Fatalf("expected secret message %q, got %q", managed["PROOF_VAULT_SECRET_VALUE"], secretMessage)
	}
	codexCredential := readProofVaultField(
		t,
		managed["PROOF_VAULT_LOCAL_ADDR"],
		managed["PROOF_VAULT_CA_CERT_FILE"],
		managed["PROOF_CODEX_CREDENTIAL_SECRET_PATH"],
		managed["PROOF_CODEX_CREDENTIAL_SECRET_FIELD"],
		clientToken,
	)
	if codexCredential != managed["PROOF_CODEX_CREDENTIAL_VALUE"] {
		t.Fatalf("expected codex credential material %q, got %q", managed["PROOF_CODEX_CREDENTIAL_VALUE"], codexCredential)
	}

	assertSupportedLocalVaultBlobAlignment(t, proofDir, managed)
	assertSupportedLocalSPIRERuntimeAlignment(t, proofDir, managed)
}

func writeFakeCommand(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write fake command %s: %v", path, err)
	}
}

func stopProcessFromPIDFile(t *testing.T, pidPath string) {
	t.Helper()

	pidBytes, err := os.ReadFile(pidPath)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		t.Fatalf("read pid file %s: %v", pidPath, err)
	}
	pidValue, err := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
	if err != nil {
		t.Fatalf("parse pid file %s: %v", pidPath, err)
	}
	process, err := os.FindProcess(pidValue)
	if err != nil {
		t.Fatalf("find process %d: %v", pidValue, err)
	}
	_ = process.Kill()
}

func readShellAssignments(t *testing.T, path string) map[string]string {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read shell assignments %s: %v", path, err)
	}

	values := map[string]string{}
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, rawValue, found := strings.Cut(line, "=")
		if !found {
			t.Fatalf("expected shell assignment in %s, got %q", path, line)
		}
		value, err := strconv.Unquote(strings.TrimSpace(rawValue))
		if err != nil {
			t.Fatalf("unquote %s in %s: %v", name, path, err)
		}
		values[strings.TrimSpace(name)] = value
	}
	return values
}

func runCommand(t *testing.T, workDir string, name string, args ...string) string {
	t.Helper()

	command := exec.Command(name, args...)
	command.Dir = workDir
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("run %s %v: %v output=%s", name, args, err, string(output))
	}
	return strings.TrimSpace(string(output))
}

func runCommandWithEnv(t *testing.T, workDir string, env []string, name string, args ...string) string {
	t.Helper()

	command := exec.Command(name, args...)
	command.Dir = workDir
	command.Env = append(os.Environ(), env...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("run %s %v: %v output=%s", name, args, err, string(output))
	}
	return strings.TrimSpace(string(output))
}

func assertPathIsUnixSocket(t *testing.T, path string) {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat socket path %s: %v", path, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("expected %s to be a unix socket, got mode %v", path, info.Mode())
	}
}

func mintJWTFromSpireServer(t *testing.T, workDir string, binaryPath string, socketPath string, spiffeID string, audience string) string {
	t.Helper()

	outputPath := filepath.Join(workDir, "minted-workload.jwt")
	command := exec.Command(binaryPath, "jwt", "mint",
		"-socketPath", socketPath,
		"-spiffeID", spiffeID,
		"-audience", audience,
		"-write", outputPath,
	)
	command.Dir = workDir
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("mint SPIRE jwt-svid: %v output=%s", err, string(output))
	}
	tokenBytes, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read minted SPIRE jwt-svid %s: %v", outputPath, err)
	}
	return strings.TrimSpace(string(tokenBytes))
}

func decodeJWTClaimsUnverifiedForTest(t *testing.T, token string) map[string]string {
	t.Helper()

	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) < 2 {
		t.Fatalf("expected jwt with at least two parts, got %q", token)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode jwt payload: %v", err)
	}
	var rawClaims map[string]any
	if err := json.Unmarshal(payload, &rawClaims); err != nil {
		t.Fatalf("unmarshal jwt claims: %v", err)
	}

	claims := map[string]string{}
	for key, value := range rawClaims {
		switch typed := value.(type) {
		case string:
			claims[key] = typed
		case []any:
			items := make([]string, 0, len(typed))
			for _, item := range typed {
				items = append(items, fmt.Sprint(item))
			}
			claims[key] = strings.Join(items, ",")
		default:
			claims[key] = fmt.Sprint(value)
		}
	}
	return claims
}

func newProofVaultHTTPClient(t *testing.T, caCertPath string) *http.Client {
	t.Helper()

	caPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		t.Fatalf("read vault ca cert %s: %v", caCertPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatalf("append vault ca cert %s", caCertPath)
	}

	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    pool,
			},
		},
	}
}

func loginToProofVault(t *testing.T, vaultAddr string, caCertPath string, authMount string, authRole string, jwtValue string) string {
	t.Helper()

	payload := map[string]string{
		"role": authRole,
		"jwt":  jwtValue,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal vault login payload: %v", err)
	}

	url := strings.TrimRight(vaultAddr, "/") + "/v1/auth/" + strings.Trim(authMount, "/") + "/login"
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build vault login request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := newProofVaultHTTPClient(t, caCertPath).Do(request)
	if err != nil {
		t.Fatalf("perform vault login: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected vault login 200, got %d body=%s", response.StatusCode, string(mustReadBody(t, response.Body)))
	}

	var payloadOut struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payloadOut); err != nil {
		t.Fatalf("decode vault login response: %v", err)
	}
	return strings.TrimSpace(payloadOut.Auth.ClientToken)
}

func readProofVaultSecret(t *testing.T, vaultAddr string, caCertPath string, secretPath string, clientToken string) string {
	t.Helper()
	return readProofVaultField(t, vaultAddr, caCertPath, secretPath, "message", clientToken)
}

func readProofVaultField(t *testing.T, vaultAddr string, caCertPath string, secretPath string, field string, clientToken string) string {
	t.Helper()

	url := strings.TrimRight(vaultAddr, "/") + "/v1/" + strings.TrimLeft(secretPath, "/")
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build vault read request: %v", err)
	}
	request.Header.Set("X-Vault-Token", clientToken)

	response, err := newProofVaultHTTPClient(t, caCertPath).Do(request)
	if err != nil {
		t.Fatalf("perform vault read: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected vault read 200, got %d body=%s", response.StatusCode, string(mustReadBody(t, response.Body)))
	}

	var payload struct {
		Data map[string]any `json:"data"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode vault read response: %v", err)
	}
	data, ok := payload.Data["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected nested data object in vault read response: %+v", payload)
	}
	value := strings.TrimSpace(fmt.Sprint(data[field]))
	if value == "" {
		t.Fatalf("expected secret field %q in %s response: %+v", field, secretPath, payload)
	}
	return value
}

func runProofVaultCommand(t *testing.T, workDir string, managed map[string]string, args ...string) string {
	t.Helper()

	return runCommandWithEnv(
		t,
		workDir,
		[]string{
			"VAULT_ADDR=" + managed["PROOF_VAULT_LOCAL_ADDR"],
			"VAULT_CACERT=" + managed["PROOF_VAULT_CA_CERT_FILE"],
			"VAULT_TOKEN=" + managed["PROOF_VAULT_ROOT_TOKEN"],
		},
		"vault",
		args...,
	)
}

func assertSupportedLocalVaultBootstrapState(t *testing.T, proofDir string, managed map[string]string) {
	t.Helper()

	authListJSON := runProofVaultCommand(t, proofDir, managed, "auth", "list", "-format=json")
	var authList map[string]struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal([]byte(authListJSON), &authList); err != nil {
		t.Fatalf("decode vault auth list: %v", err)
	}
	authMount := strings.Trim(managed["PROOF_VAULT_AUTH_MOUNT"], "/") + "/"
	authEntry, ok := authList[authMount]
	if !ok {
		t.Fatalf("expected auth mount %q in %s", authMount, authListJSON)
	}
	if authEntry.Type != "jwt" {
		t.Fatalf("expected auth mount %q type jwt, got %q", authMount, authEntry.Type)
	}

	secretsListJSON := runProofVaultCommand(t, proofDir, managed, "secrets", "list", "-format=json")
	var secretsList map[string]struct {
		Type    string            `json:"type"`
		Options map[string]string `json:"options"`
	}
	if err := json.Unmarshal([]byte(secretsListJSON), &secretsList); err != nil {
		t.Fatalf("decode vault secrets list: %v", err)
	}
	secretMount := strings.Trim(managed["PROOF_VAULT_SECRET_MOUNT"], "/") + "/"
	secretEntry, ok := secretsList[secretMount]
	if !ok {
		t.Fatalf("expected secret mount %q in %s", secretMount, secretsListJSON)
	}
	if secretEntry.Type != "kv" {
		t.Fatalf("expected secret mount %q type kv, got %q", secretMount, secretEntry.Type)
	}
	if got := strings.TrimSpace(secretEntry.Options["version"]); got != "2" {
		t.Fatalf("expected secret mount %q version 2, got %q", secretMount, got)
	}

	authConfigJSON := runProofVaultCommand(
		t,
		proofDir,
		managed,
		"read",
		"-format=json",
		"auth/"+strings.Trim(managed["PROOF_VAULT_AUTH_MOUNT"], "/")+"/config",
	)
	var authConfig struct {
		Data struct {
			BoundIssuer          string   `json:"bound_issuer"`
			JWTValidationPubkeys []string `json:"jwt_validation_pubkeys"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(authConfigJSON), &authConfig); err != nil {
		t.Fatalf("decode vault auth config: %v", err)
	}
	if authConfig.Data.BoundIssuer != managed["PROOF_VAULT_BOUND_ISSUER"] {
		t.Fatalf("expected auth bound issuer %q, got %q", managed["PROOF_VAULT_BOUND_ISSUER"], authConfig.Data.BoundIssuer)
	}
	if len(authConfig.Data.JWTValidationPubkeys) == 0 {
		t.Fatalf("expected jwt validation pubkeys in auth config, got %s", authConfigJSON)
	}

	roleJSON := runProofVaultCommand(
		t,
		proofDir,
		managed,
		"read",
		"-format=json",
		"auth/"+strings.Trim(managed["PROOF_VAULT_AUTH_MOUNT"], "/")+"/role/"+strings.Trim(managed["PROOF_VAULT_AUTH_ROLE"], "/"),
	)
	var role struct {
		Data struct {
			RoleType       string   `json:"role_type"`
			UserClaim      string   `json:"user_claim"`
			BoundAudiences []string `json:"bound_audiences"`
			BoundSubject   string   `json:"bound_subject"`
			TokenPolicies  []string `json:"token_policies"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(roleJSON), &role); err != nil {
		t.Fatalf("decode vault role: %v", err)
	}
	if role.Data.RoleType != "jwt" {
		t.Fatalf("expected vault role_type jwt, got %q", role.Data.RoleType)
	}
	if role.Data.UserClaim != "sub" {
		t.Fatalf("expected vault user_claim sub, got %q", role.Data.UserClaim)
	}
	if role.Data.BoundSubject != managed["PROOF_VAULT_BOUND_SUBJECT"] {
		t.Fatalf("expected vault bound subject %q, got %q", managed["PROOF_VAULT_BOUND_SUBJECT"], role.Data.BoundSubject)
	}
	if !sliceContains(role.Data.BoundAudiences, managed["PROOF_VAULT_BOUND_AUDIENCE"]) {
		t.Fatalf("expected vault bound audience %q in %#v", managed["PROOF_VAULT_BOUND_AUDIENCE"], role.Data.BoundAudiences)
	}
	if !sliceContains(role.Data.TokenPolicies, "runtime-identity-proof") {
		t.Fatalf("expected runtime-identity-proof policy in %#v", role.Data.TokenPolicies)
	}

	policyText := runProofVaultCommand(t, proofDir, managed, "policy", "read", "runtime-identity-proof")
	if !strings.Contains(policyText, `path "`+managed["PROOF_VAULT_SECRET_PATH"]+`"`) {
		t.Fatalf("expected policy to include secret path %q, got %s", managed["PROOF_VAULT_SECRET_PATH"], policyText)
	}
	if !strings.Contains(policyText, `path "`+managed["PROOF_CODEX_CREDENTIAL_SECRET_PATH"]+`"`) {
		t.Fatalf("expected policy to include Codex credential path %q, got %s", managed["PROOF_CODEX_CREDENTIAL_SECRET_PATH"], policyText)
	}
}

func sliceContains(items []string, want string) bool {
	for _, item := range items {
		if strings.TrimSpace(item) == want {
			return true
		}
	}
	return false
}

func assertSupportedLocalVaultBlobAlignment(t *testing.T, proofDir string, managed map[string]string) {
	t.Helper()

	digestBytes, err := os.ReadFile(filepath.Join(proofDir, "workload-zone-vault-config-digest.txt"))
	if err != nil {
		t.Fatalf("read workload-zone-vault-config digest: %v", err)
	}
	digest := strings.TrimSpace(string(digestBytes))
	if !strings.HasPrefix(digest, "sha256:") || len(digest) < len("sha256:")+4 {
		t.Fatalf("unexpected digest %q", digest)
	}

	blobPath := filepath.Join(
		proofDir,
		"ars-storage",
		"sha256",
		digest[7:9],
		digest[9:11],
		digest,
	)
	blobBytes, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatalf("read workload-zone-vault blob %s: %v", blobPath, err)
	}

	var payload struct {
		VaultConfig struct {
			Address     string `json:"address"`
			AuthMount   string `json:"auth_mount"`
			AuthRole    string `json:"auth_role"`
			JWTAudience string `json:"jwt_audience"`
		} `json:"vault_config"`
	}
	if err := json.Unmarshal(blobBytes, &payload); err != nil {
		t.Fatalf("decode workload-zone-vault blob: %v", err)
	}

	if payload.VaultConfig.Address != managed["PROOF_VAULT_ADDR"] {
		t.Fatalf("expected blob address %q, got %q", managed["PROOF_VAULT_ADDR"], payload.VaultConfig.Address)
	}
	if payload.VaultConfig.AuthMount != managed["PROOF_VAULT_AUTH_MOUNT"] {
		t.Fatalf("expected blob auth mount %q, got %q", managed["PROOF_VAULT_AUTH_MOUNT"], payload.VaultConfig.AuthMount)
	}
	if payload.VaultConfig.AuthRole != managed["PROOF_VAULT_AUTH_ROLE"] {
		t.Fatalf("expected blob auth role %q, got %q", managed["PROOF_VAULT_AUTH_ROLE"], payload.VaultConfig.AuthRole)
	}
	if payload.VaultConfig.JWTAudience != managed["PROOF_VAULT_BOUND_AUDIENCE"] {
		t.Fatalf("expected blob jwt audience %q, got %q", managed["PROOF_VAULT_BOUND_AUDIENCE"], payload.VaultConfig.JWTAudience)
	}
}

func assertSupportedLocalSPIRERuntimeAlignment(t *testing.T, proofDir string, managed map[string]string) {
	t.Helper()

	configBytes, err := os.ReadFile(filepath.Join(proofDir, "es.json"))
	if err != nil {
		t.Fatalf("read es config: %v", err)
	}

	var payload struct {
		Execution struct {
			RuntimeSupportBinary   string `json:"runtime_support_binary"`
			SPIREWorkloadAPISocket string `json:"spire_workload_api_socket_path"`
			RuntimeProfiles        struct {
				ControlPlaneNormalShell struct {
					Enabled                    bool   `json:"enabled"`
					Image                      string `json:"image"`
					CodexCLIPath               string `json:"codex_cli_path"`
					CredentialVaultSecretPath  string `json:"credential_vault_secret_path"`
					CredentialVaultSecretField string `json:"credential_vault_secret_field"`
				} `json:"control_plane_normal_shell"`
			} `json:"runtime_profiles"`
		} `json:"execution"`
	}
	if err := json.Unmarshal(configBytes, &payload); err != nil {
		t.Fatalf("decode es config: %v", err)
	}

	if payload.Execution.RuntimeSupportBinary != managed["PROOF_RUNTIME_SUPPORT_BINARY"] {
		t.Fatalf("expected runtime support binary %q, got %q", managed["PROOF_RUNTIME_SUPPORT_BINARY"], payload.Execution.RuntimeSupportBinary)
	}
	if payload.Execution.SPIREWorkloadAPISocket != managed["PROOF_SPIRE_AGENT_SOCKET_PATH"] {
		t.Fatalf("expected ES SPIRE socket path %q, got %q", managed["PROOF_SPIRE_AGENT_SOCKET_PATH"], payload.Execution.SPIREWorkloadAPISocket)
	}
	profile := payload.Execution.RuntimeProfiles.ControlPlaneNormalShell
	if !profile.Enabled {
		t.Fatalf("expected control-plane normal-shell runtime profile to be enabled")
	}
	if profile.Image != managed["PROOF_CODEX_RUNTIME_PROFILE_IMAGE"] {
		t.Fatalf("expected profile image %q, got %q", managed["PROOF_CODEX_RUNTIME_PROFILE_IMAGE"], profile.Image)
	}
	if profile.CodexCLIPath != managed["PROOF_CODEX_CLI_PATH"] {
		t.Fatalf("expected Codex CLI path %q, got %q", managed["PROOF_CODEX_CLI_PATH"], profile.CodexCLIPath)
	}
	if managed["PROOF_CODEX_REALIZATION"] != "proof" {
		t.Fatalf("expected supported-local Codex realization proof, got %q", managed["PROOF_CODEX_REALIZATION"])
	}
	if profile.CredentialVaultSecretPath != managed["PROOF_CODEX_CREDENTIAL_SECRET_PATH"] {
		t.Fatalf("expected Codex credential secret path %q, got %q", managed["PROOF_CODEX_CREDENTIAL_SECRET_PATH"], profile.CredentialVaultSecretPath)
	}
	if profile.CredentialVaultSecretField != managed["PROOF_CODEX_CREDENTIAL_SECRET_FIELD"] {
		t.Fatalf("expected Codex credential secret field %q, got %q", managed["PROOF_CODEX_CREDENTIAL_SECRET_FIELD"], profile.CredentialVaultSecretField)
	}
}
