package executionsubstrate_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// realVault is a Vault server started for one test the way the Remote Alpha
// box runs it: not dev mode, raft storage, a TLS listener, initialized with
// one key share and unsealed. Its configuration file is the one that the
// helper's temporary-config changes and a SIGHUP reloads.
type realVault struct {
	t          *testing.T
	address    string
	caPEM      string
	configPath string
	unsealKey  string
	rootToken  string
	pid        int
	client     *http.Client
}

func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

// loopbackTLSFiles writes a throwaway CA and a server certificate for
// 127.0.0.1, and returns the CA PEM.
func loopbackTLSFiles(t *testing.T, dir string) (caPEM, certPath, keyPath string) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "bootstrap-test-vault-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server certificate: %v", err)
	}
	caPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	certPath = filepath.Join(dir, "vault-cert.pem")
	keyPath = filepath.Join(dir, "vault-key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}), 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return caPEM, certPath, keyPath
}

func startRealVault(t *testing.T, vaultBin string) *realVault {
	t.Helper()
	dir := t.TempDir()
	caPEM, certPath, keyPath := loopbackTLSFiles(t, dir)
	apiPort, clusterPort := freeLoopbackPort(t), freeLoopbackPort(t)
	for apiPort == clusterPort {
		clusterPort = freeLoopbackPort(t)
	}
	raftDir := filepath.Join(dir, "raft")
	homeDir := filepath.Join(dir, "home")
	for _, d := range []string{raftDir, homeDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	configPath := filepath.Join(dir, "vault.d", "vault.hcl")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	config := fmt.Sprintf(`ui = false
disable_mlock = true

storage "raft" {
  path    = %q
  node_id = "bootstrap-test"
}

listener "tcp" {
  address         = "127.0.0.1:%d"
  cluster_address = "127.0.0.1:%d"
  tls_cert_file   = %q
  tls_key_file    = %q
}

api_addr     = "https://127.0.0.1:%d"
cluster_addr = "https://127.0.0.1:%d"
`, raftDir, apiPort, clusterPort, certPath, keyPath, apiPort, clusterPort)
	if err := os.WriteFile(configPath, []byte(config), 0o640); err != nil {
		t.Fatalf("write vault config: %v", err)
	}
	logFile, err := os.Create(filepath.Join(dir, "vault.log"))
	if err != nil {
		t.Fatalf("create vault log: %v", err)
	}
	cmd := exec.Command(vaultBin, "server", "-config="+configPath)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + homeDir}
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start vault: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = logFile.Close()
	})

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(caPEM))
	v := &realVault{
		t:          t,
		address:    fmt.Sprintf("https://127.0.0.1:%d", apiPort),
		caPEM:      caPEM,
		configPath: configPath,
		pid:        cmd.Process.Pid,
		// sys/init can take more than 10 s on a loaded machine.
		client: &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}},
	}
	v.waitFor(func() bool {
		status, _ := v.call("", http.MethodGet, "sys/seal-status", nil)
		return status == http.StatusOK
	}, "Vault to listen", logFile.Name())
	status, body := v.call("", http.MethodPut, "sys/init", map[string]any{"secret_shares": 1, "secret_threshold": 1})
	if status != http.StatusOK {
		t.Fatalf("vault init: %d %s", status, body["errors"])
	}
	keys, _ := body["keys_base64"].([]any)
	if len(keys) != 1 {
		t.Fatalf("vault init returned %d key shares", len(keys))
	}
	v.unsealKey, _ = keys[0].(string)
	v.rootToken, _ = body["root_token"].(string)
	if status, body := v.call("", http.MethodPut, "sys/unseal", map[string]any{"key": v.unsealKey}); status != http.StatusOK {
		t.Fatalf("vault unseal: %d %s", status, body["errors"])
	}
	v.waitFor(func() bool {
		status, _ := v.call(v.rootToken, http.MethodGet, "sys/mounts", nil)
		return status == http.StatusOK
	}, "Vault to become active", logFile.Name())
	return v
}

func (v *realVault) waitFor(ready func() bool, what, logPath string) {
	v.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for !ready() {
		if time.Now().After(deadline) {
			log, _ := os.ReadFile(logPath)
			v.t.Fatalf("timed out waiting for %s\n%s", what, log)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// call sends one request and returns the status and the decoded JSON body.
func (v *realVault) call(token, method, path string, payload any) (int, map[string]any) {
	v.t.Helper()
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			v.t.Fatalf("marshal: %v", err)
		}
		body = bytes.NewReader(raw)
	}
	request, err := http.NewRequest(method, v.address+"/v1/"+path, body)
	if err != nil {
		v.t.Fatalf("request: %v", err)
	}
	if token != "" {
		request.Header.Set("X-Vault-Token", token)
	}
	response, err := v.client.Do(request)
	if err != nil {
		return 0, map[string]any{"errors": []string{err.Error()}}
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	decoded := map[string]any{}
	_ = json.Unmarshal(raw, &decoded)
	return response.StatusCode, decoded
}

func (v *realVault) mustCall(token, method, path string, payload any, want int) map[string]any {
	v.t.Helper()
	status, body := v.call(token, method, path, payload)
	if status != want {
		v.t.Fatalf("%s %s: want %d, got %d %v", method, path, want, status, body["errors"])
	}
	return body
}

func (v *realVault) accessors() []string {
	v.t.Helper()
	body := v.mustCall(v.rootToken, "LIST", "auth/token/accessors", nil, http.StatusOK)
	data, _ := body["data"].(map[string]any)
	raw, _ := data["keys"].([]any)
	keys := make([]string, 0, len(raw))
	for _, key := range raw {
		keys = append(keys, fmt.Sprint(key))
	}
	sort.Strings(keys)
	return keys
}

func signTestJWTSVID(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	encode := func(value any) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	input := encode(map[string]any{"alg": "RS256", "typ": "JWT"}) + "." + encode(claims)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// TestRemoteAlphaVaultWorkloadAuthBootstrapUnsealKeyWithRealVault runs the
// helper with REMOTE_ALPHA_BOOTSTRAP_AUTHORITY=unseal-key,
// REMOTE_ALPHA_BOOTSTRAP_PROOF_VALUE=generate and
// REMOTE_ALPHA_BOOTSTRAP_GENERATE_ROOT_ACCESS=temporary-config against a
// real Vault server. It checks what the fake Vault cannot: that Vault 2.x
// refuses generate-root without a token until the configuration names it,
// that a SIGHUP reload turns that on and off without sealing Vault, that the
// generated root token and the short-lived token are really revoked (the
// token accessor list is the same before and after), that earlier proof
// versions are gone, and that a workload login gets the role's TTL and only
// from the role's addresses. CI installs Vault 2.2.2, so this runs there; it
// skips itself only where no vault binary is on PATH.
func TestRemoteAlphaVaultWorkloadAuthBootstrapUnsealKeyWithRealVault(t *testing.T) {
	vaultBin, err := exec.LookPath("vault")
	if err != nil {
		t.Skip("needs the vault binary on PATH (CI installs Vault 2.2.2)")
	}
	v := startRealVault(t, vaultBin)

	// Vault 2.x default: no generate-root without a token.
	if status, _ := v.call("", http.MethodGet, "sys/generate-root/attempt", nil); status != http.StatusForbidden {
		t.Fatalf("expected Vault to refuse generate-root without a token by default, got %d", status)
	}

	// An API key written by hand earlier, in two versions, that the run must
	// discard for good.
	v.mustCall(v.rootToken, http.MethodPost, "sys/mounts/proof-secrets", map[string]any{"type": "kv", "options": map[string]any{"version": "2"}}, http.StatusNoContent)
	oldValues := []string{"sk-handWrittenOldApiKeyValue000000000001", "sk-handWrittenOldApiKeyValue000000000002"}
	for _, old := range oldValues {
		v.mustCall(v.rootToken, http.MethodPost, "proof-secrets/data/codex-runtime-profile", map[string]any{"data": map[string]any{"api_key": old}}, http.StatusOK)
	}
	before := v.accessors()
	configBefore := mustRead(t, v.configPath)

	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	bundleKey := fakeSpireJWTValidationKey{
		N: base64.RawURLEncoding.EncodeToString(signingKey.PublicKey.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(signingKey.PublicKey.E)).Bytes()),
	}
	dir := t.TempDir()
	fakeBin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	setupFakeBootstrapSpireServerWithBundle(t, fakeBin, fakeSpireJWTValidationBundle(bundleKey))
	reload := filepath.Join(dir, "reload-vault")
	if err := os.WriteFile(reload, []byte(fmt.Sprintf("#!/bin/sh\nexec kill -HUP %d\n", v.pid)), 0o755); err != nil {
		t.Fatalf("write reload: %v", err)
	}
	configPath := filepath.Join(dir, "workload-zone-vault-config.json")
	writeWorkloadZoneConfig(t, configPath, v.address, "jwt", "service_execution", "vault", v.caPEM)

	run := func(name, input string, extra ...string) (string, string, error) {
		summaryPath := filepath.Join(dir, name, "summary.json")
		env := envWithPath(fakeBin, append([]string{
			"REMOTE_ALPHA_BOOTSTRAP_WORKLOAD_ZONE_CONFIG_PATH=" + configPath,
			"REMOTE_ALPHA_BOOTSTRAP_SUMMARY_PATH=" + summaryPath,
			"REMOTE_ALPHA_BOOTSTRAP_AUTHORITY=unseal-key",
			"REMOTE_ALPHA_BOOTSTRAP_PROOF_VALUE=generate",
			"REMOTE_ALPHA_BOOTSTRAP_GENERATE_ROOT_ACCESS=temporary-config",
			"REMOTE_ALPHA_BOOTSTRAP_VAULT_CONFIG_PATH=" + v.configPath,
			"REMOTE_ALPHA_BOOTSTRAP_VAULT_RELOAD_COMMAND=" + reload,
		}, extra...)...)
		output, err := runRemoteAlphaBootstrapHelperWithPTYInput(t, env, input)
		return output, summaryPath, err
	}
	checkAfterRun := func(label, output, summaryPath string) {
		t.Helper()
		assertContainsNone(t, label+" output", output, v.unsealKey, v.rootToken)
		assertContainsNone(t, label+" summary", mustRead(t, summaryPath), v.unsealKey, v.rootToken)
		if got := mustRead(t, v.configPath); got != configBefore {
			t.Fatalf("%s: Vault's configuration file is not back byte for byte:\n%s", label, got)
		}
		if status, _ := v.call("", http.MethodGet, "sys/generate-root/attempt", nil); status != http.StatusForbidden {
			t.Fatalf("%s: Vault must refuse generate-root without a token again, got %d", label, status)
		}
		attempt := v.mustCall(v.rootToken, http.MethodGet, "sys/generate-root/attempt", nil, http.StatusOK)
		if attempt["started"] != false {
			t.Fatalf("%s: a generate-root attempt was left open", label)
		}
		if seal := v.mustCall("", http.MethodGet, "sys/seal-status", nil, http.StatusOK); seal["sealed"] != false {
			t.Fatalf("%s: Vault must stay unsealed", label)
		}
		if after := v.accessors(); fmt.Sprint(after) != fmt.Sprint(before) {
			t.Fatalf("%s: tokens made by the run are still valid: %d accessors before, %d after", label, len(before), len(after))
		}
	}
	proofValue := func() string {
		t.Helper()
		metadata := v.mustCall(v.rootToken, http.MethodGet, "proof-secrets/metadata/codex-runtime-profile", nil, http.StatusOK)
		data := metadata["data"].(map[string]any)
		versions, _ := data["versions"].(map[string]any)
		if fmt.Sprint(data["current_version"]) != "1" || len(versions) != 1 {
			t.Fatalf("earlier proof versions must be gone: current_version %v, %d versions", data["current_version"], len(versions))
		}
		profile := v.mustCall(v.rootToken, http.MethodGet, "proof-secrets/data/codex-runtime-profile", nil, http.StatusOK)
		value, _ := profile["data"].(map[string]any)["data"].(map[string]any)["api_key"].(string)
		login := v.mustCall(v.rootToken, http.MethodGet, "proof-secrets/data/runtime-identity-vault-login", nil, http.StatusOK)
		message, _ := login["data"].(map[string]any)["data"].(map[string]any)["message"].(string)
		if len(value) < 32 || message != value {
			t.Fatalf("expected one generated value of at least 32 characters on both proof paths")
		}
		for _, old := range oldValues {
			if value == old {
				t.Fatalf("the hand-written value is still there")
			}
		}
		return value
	}
	workloadJWT := func() string {
		now := time.Now().Unix()
		return signTestJWTSVID(t, signingKey, map[string]any{
			"iss": "spiffe://execution.internal",
			"sub": "spiffe://execution.internal/workload",
			"aud": []string{"vault"},
			"iat": now,
			"nbf": now - 5,
			"exp": now + 300,
		})
	}

	// Run 1: the role allows logins from 127.0.0.1, so this test can log in.
	output, summaryPath, err := run("first", v.unsealKey+"\n", "REMOTE_ALPHA_BOOTSTRAP_TOKEN_BOUND_CIDRS=127.0.0.1/32")
	if err != nil {
		t.Fatalf("first run failed: %v\n%s\nsummary=%s", err, output, readIfExists(summaryPath))
	}
	assertContainsAll(t, "first run output", output,
		"Vault's configuration file is back byte for byte, and Vault again refuses generate-root without a token.",
		"The root token made from the unseal key was revoked at once; the short-lived token for this run is revoked too.",
		// The initial root token from sys/init never expires.
		"WARNING: Vault holds 1 root token(s) that never expire.",
		"overall_status=pass",
	)
	checkAfterRun("first run", output, summaryPath)
	firstValue := proofValue()
	role := v.mustCall(v.rootToken, http.MethodGet, "auth/jwt/role/service_execution", nil, http.StatusOK)["data"].(map[string]any)
	if fmt.Sprint(role["token_ttl"]) != "900" || fmt.Sprint(role["token_max_ttl"]) != "1800" {
		t.Fatalf("expected role token_ttl 900 and token_max_ttl 1800, got %v and %v", role["token_ttl"], role["token_max_ttl"])
	}
	if got := fmt.Sprint(role["token_bound_cidrs"]); !strings.Contains(got, "127.0.0.1") {
		t.Fatalf("expected token_bound_cidrs with 127.0.0.1, got %s", got)
	}
	loginBody := v.mustCall("", http.MethodPost, "auth/jwt/login", map[string]any{"role": "service_execution", "jwt": workloadJWT()}, http.StatusOK)
	auth := loginBody["auth"].(map[string]any)
	if fmt.Sprint(auth["lease_duration"]) != "900" {
		t.Fatalf("expected a workload token that lives 900 seconds, got %v", auth["lease_duration"])
	}
	workloadToken := auth["client_token"].(string)
	read := v.mustCall(workloadToken, http.MethodGet, "proof-secrets/data/codex-runtime-profile", nil, http.StatusOK)
	if read["data"].(map[string]any)["data"].(map[string]any)["api_key"] != firstValue {
		t.Fatalf("the workload token must read the proof value")
	}
	v.mustCall(workloadToken, http.MethodPost, "auth/token/revoke-self", nil, http.StatusNoContent)

	// Run 2: the default addresses (the Docker bridge). A login from
	// 127.0.0.1 must now be refused, and the proof history is cut again.
	output, summaryPath, err = run("second", v.unsealKey+"\n")
	if err != nil {
		t.Fatalf("second run failed: %v\n%s\nsummary=%s", err, output, readIfExists(summaryPath))
	}
	checkAfterRun("second run", output, summaryPath)
	if secondValue := proofValue(); secondValue == firstValue {
		t.Fatalf("each run must write a new generated value")
	}
	// The same JWT logged in after run 1; only the address limit changed.
	// Vault answers a login from outside token_bound_cidrs with a plain 403.
	if status, body := v.call("", http.MethodPost, "auth/jwt/login", map[string]any{"role": "service_execution", "jwt": workloadJWT()}); status != http.StatusForbidden {
		t.Fatalf("a login from 127.0.0.1 must be refused (403) when the role allows only 172.17.0.0/16, got %d %v", status, body["errors"])
	}

	// Run 3: a wrong unseal key changes nothing and leaves nothing open.
	wrongKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	output, summaryPath, err = run("wrong-key", wrongKey+"\n")
	if err == nil {
		t.Fatalf("a wrong unseal key must fail:\n%s", output)
	}
	assertContainsAll(t, "wrong key output", output, "failure_phase=generate_root_token", "Vault's configuration file is back byte for byte")
	assertContainsNone(t, "wrong key output", output, wrongKey)
	checkAfterRun("wrong key run", output, summaryPath)

	// Run 4, last because it revokes the initial root token this test uses:
	// REMOTE_ALPHA_BOOTSTRAP_STANDING_ROOT_TOKENS=revoke removes every root
	// token that never expires.
	output, summaryPath, err = run("revoke-standing", v.unsealKey+"\n", "REMOTE_ALPHA_BOOTSTRAP_STANDING_ROOT_TOKENS=revoke")
	if err != nil {
		t.Fatalf("revoke run failed: %v\n%s\nsummary=%s", err, output, readIfExists(summaryPath))
	}
	assertContainsAll(t, "revoke run output", output, "Revoked 1 root token(s) that never expired", "overall_status=pass")
	assertContainsNone(t, "revoke run output", output, v.unsealKey, v.rootToken, "WARNING")
	if status, _ := v.call(v.rootToken, http.MethodGet, "auth/token/lookup-self", nil); status != http.StatusForbidden {
		t.Fatalf("the initial root token must be revoked, lookup-self answered %d", status)
	}
	if got := mustRead(t, v.configPath); got != configBefore {
		t.Fatalf("revoke run: Vault's configuration file is not back byte for byte")
	}
	if status, _ := v.call("", http.MethodGet, "sys/generate-root/attempt", nil); status != http.StatusForbidden {
		t.Fatalf("revoke run: Vault must refuse generate-root without a token again, got %d", status)
	}
}

// TestRemoteAlphaVaultWorkloadAuthBootstrapSignalsWithRealVault delivers
// SIGINT, SIGTERM, SIGHUP and SIGQUIT to the helper from inside its own
// Vault reload command: during the reload that enables unauthenticated
// generate-root, and during the reload that puts it back (after generate-root
// and the short-lived token). The signals must wait until the root token is
// revoked and the configuration is back; then the run stops before any
// configuration, revokes the short-lived token and leaves nothing open.
func TestRemoteAlphaVaultWorkloadAuthBootstrapSignalsWithRealVault(t *testing.T) {
	vaultBin, err := exec.LookPath("vault")
	if err != nil {
		t.Skip("needs the vault binary on PATH (CI installs Vault 2.2.2)")
	}
	v := startRealVault(t, vaultBin)
	configBefore := mustRead(t, v.configPath)
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	bundleKey := fakeSpireJWTValidationKey{
		N: base64.RawURLEncoding.EncodeToString(signingKey.PublicKey.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(signingKey.PublicKey.E)).Bytes()),
	}
	dir := t.TempDir()
	fakeBin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	setupFakeBootstrapSpireServerWithBundle(t, fakeBin, fakeSpireJWTValidationBundle(bundleKey))
	configPath := filepath.Join(dir, "workload-zone-vault-config.json")
	writeWorkloadZoneConfig(t, configPath, v.address, "jwt", "service_execution", "vault", v.caPEM)

	cases := []struct {
		name   string
		reload int // 1 = the enable reload, 2 = the restore reload
		signal string
		exit   int
	}{
		{"sigint_during_restore_reload", 2, "INT", 130},
		{"sigterm_during_restore_reload", 2, "TERM", 143},
		{"sighup_during_restore_reload", 2, "HUP", 129},
		{"sigquit_during_restore_reload", 2, "QUIT", 131},
		{"sigint_during_enable_reload", 1, "INT", 130},
		{"sigterm_during_enable_reload", 1, "TERM", 143},
		{"sighup_during_enable_reload", 1, "HUP", 129},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := v.accessors()
			caseDir := filepath.Join(dir, tc.name)
			if err := os.MkdirAll(caseDir, 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			// The reload really reloads Vault, then signals the helper (its
			// parent) and returns success after the helper had time to act.
			counter := filepath.Join(caseDir, "reload-count")
			script := fmt.Sprintf(`#!/bin/sh
n=$(cat %[1]s 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > %[1]s
kill -HUP %[2]d
if [ "$n" = "%[3]d" ]; then sleep 1; kill -%[4]s "$PPID"; sleep 2; fi
exit 0
`, counter, v.pid, tc.reload, tc.signal)
			reload := filepath.Join(caseDir, "reload-vault")
			if err := os.WriteFile(reload, []byte(script), 0o755); err != nil {
				t.Fatalf("write reload: %v", err)
			}
			summaryPath := filepath.Join(caseDir, "run", "summary.json")
			env := envWithPath(fakeBin,
				"REMOTE_ALPHA_BOOTSTRAP_WORKLOAD_ZONE_CONFIG_PATH="+configPath,
				"REMOTE_ALPHA_BOOTSTRAP_SUMMARY_PATH="+summaryPath,
				"REMOTE_ALPHA_BOOTSTRAP_AUTHORITY=unseal-key",
				"REMOTE_ALPHA_BOOTSTRAP_PROOF_VALUE=generate",
				"REMOTE_ALPHA_BOOTSTRAP_GENERATE_ROOT_ACCESS=temporary-config",
				"REMOTE_ALPHA_BOOTSTRAP_VAULT_CONFIG_PATH="+v.configPath,
				"REMOTE_ALPHA_BOOTSTRAP_VAULT_RELOAD_COMMAND="+reload,
			)
			output, runErr := runRemoteAlphaBootstrapHelperWithPTYInput(t, env, v.unsealKey+"\n")
			assertContainsNone(t, "output", output, v.unsealKey, v.rootToken)
			if runErr == nil {
				t.Fatalf("an interrupted run must not exit 0:\n%s", output)
			}
			var exitErr *exec.ExitError
			if !errors.As(runErr, &exitErr) || exitErr.ExitCode() != tc.exit {
				t.Fatalf("expected exit %d, got %v:\n%s", tc.exit, runErr, output)
			}
			if got := readIfExists(counter); strings.TrimSpace(got) != "2" {
				t.Fatalf("both reloads (enable and restore) must run, got %q:\n%s", got, output)
			}
			if after := v.accessors(); fmt.Sprint(after) != fmt.Sprint(before) {
				t.Fatalf("a token made by the run is still valid: %d accessors before, %d after:\n%s", len(before), len(after), output)
			}
			if got := mustRead(t, v.configPath); got != configBefore {
				t.Fatalf("Vault's configuration file is not back byte for byte:\n%s", got)
			}
			if status, _ := v.call("", http.MethodGet, "sys/generate-root/attempt", nil); status != http.StatusForbidden {
				t.Fatalf("Vault must refuse generate-root without a token again, got %d", status)
			}
			if attempt := v.mustCall(v.rootToken, http.MethodGet, "sys/generate-root/attempt", nil, http.StatusOK); attempt["started"] != false {
				t.Fatalf("a generate-root attempt was left open")
			}
			auths := v.mustCall(v.rootToken, http.MethodGet, "sys/auth", nil, http.StatusOK)
			if _, ok := auths["jwt/"]; ok {
				t.Fatalf("no configuration may run after the signal; the jwt auth mount exists")
			}
			assertContainsAll(t, "output", output,
				"Interrupted by SIG"+tc.signal+"; cleanup ran before exit.",
				"The root token made from the unseal key was revoked at once; the short-lived token for this run is revoked too.",
				"Vault's configuration file is back byte for byte, and Vault again refuses generate-root without a token.",
				"overall_status=fail",
				"failure_class=interrupted",
			)
			summary := readJSONFile(t, summaryPath)
			if summary["interrupted_by"] != "SIG"+tc.signal || summary["failure_class"] != "interrupted" {
				t.Fatalf("summary must record the interruption, got interrupted_by=%v failure_class=%v", summary["interrupted_by"], summary["failure_class"])
			}
			assertContainsNone(t, "summary", mustRead(t, summaryPath), v.unsealKey, v.rootToken)
		})
	}
}
