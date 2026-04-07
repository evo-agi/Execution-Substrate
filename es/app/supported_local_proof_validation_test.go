package app_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	workloadpb "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestSupportedLocalSetupScriptBootstrapsRealVaultDevTarget(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("supported-local setup validation requires Linux")
	}

	for _, name := range []string{"go", "openssl", "python3", "vault"} {
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
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("run supported-local setup: %v output=%s", err, string(output))
	}

	t.Cleanup(func() {
		stopProcessFromPIDFile(t, filepath.Join(proofDir, "vault-dev.pid"))
		stopProcessFromPIDFile(t, filepath.Join(proofDir, "mock-spire.pid"))
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
		"PROOF_VAULT_SECRET_LOGICAL_PATH",
		"PROOF_VAULT_SECRET_VALUE",
		"PROOF_VAULT_ROOT_TOKEN",
		"PROOF_VAULT_CA_CERT_FILE",
		"PROOF_WORKLOAD_JWT_SIGNING_KEY_FILE",
		"PROOF_WORKLOAD_JWT_VALIDATION_PUB_FILE",
	} {
		if strings.TrimSpace(managed[key]) == "" {
			t.Fatalf("expected %s in managed-secrets.conf", key)
		}
	}

	jwtValue := fetchJWTSVIDFromSocket(t, filepath.Join(proofDir, "mock-spire.sock"), managed["PROOF_VAULT_BOUND_AUDIENCE"])
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

	assertSupportedLocalVaultBlobAlignment(t, proofDir, managed)
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

func fetchJWTSVIDFromSocket(t *testing.T, socketPath string, audience string) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dialer := func(ctx context.Context, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socketPath)
	}
	conn, err := grpc.DialContext(
		ctx,
		"unix://"+socketPath,
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatalf("dial mock spire socket: %v", err)
	}
	defer conn.Close()

	response, err := workloadpb.NewSpiffeWorkloadAPIClient(conn).FetchJWTSVID(ctx, &workloadpb.JWTSVIDRequest{
		Audience: []string{audience},
	})
	if err != nil {
		t.Fatalf("fetch jwt svid: %v", err)
	}
	if len(response.Svids) != 1 {
		t.Fatalf("expected one jwt svid, got %d", len(response.Svids))
	}
	return strings.TrimSpace(response.Svids[0].Svid)
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
		Data struct {
			Data struct {
				Message string `json:"message"`
			} `json:"data"`
		} `json:"data"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode vault read response: %v", err)
	}
	return strings.TrimSpace(payload.Data.Data.Message)
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
