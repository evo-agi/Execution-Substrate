package scripts_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
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

// bootstrapNotDumpableProbe records whether this host can do what the helper
// requires before it reads anything: make the process not dumpable with
// prctl(PR_SET_DUMPABLE, 0) and read that back. It makes the same ctypes calls
// as the helper, in a python3 of its own, so it tests the capability and not
// the operating system's name (AGENTS.md section 12).
var bootstrapNotDumpableProbe struct {
	once   sync.Once
	reason string
}

const bootstrapNotDumpableProbeScript = `
import ctypes
try:
    prctl = ctypes.CDLL(None, use_errno=True).prctl
except (OSError, AttributeError) as exc:
    raise SystemExit("prctl is not available (%s)" % type(exc).__name__)
zero = ctypes.c_ulong(0)
if prctl(ctypes.c_int(4), zero, zero, zero, zero) != 0:
    raise SystemExit("prctl(PR_SET_DUMPABLE, 0) failed")
if prctl(ctypes.c_int(3), zero, zero, zero, zero) != 0:
    raise SystemExit("the process is still dumpable after prctl(PR_SET_DUMPABLE, 0)")
`

// requireBootstrapNotDumpableCapability skips a test that runs the helper past
// its core dump step on a host where the helper refuses to run at that step.
// TestRemoteAlphaVaultWorkloadAuthBootstrapRefusesWhenTheProcessStaysDumpable
// tests that refusal on every host.
func requireBootstrapNotDumpableCapability(t *testing.T) {
	t.Helper()
	bootstrapNotDumpableProbe.once.Do(func() {
		output, err := exec.Command("python3", "-I", "-c", bootstrapNotDumpableProbeScript).CombinedOutput()
		if err != nil {
			bootstrapNotDumpableProbe.reason = strings.TrimSpace(string(output))
			if bootstrapNotDumpableProbe.reason == "" {
				bootstrapNotDumpableProbe.reason = err.Error()
			}
		}
	})
	if bootstrapNotDumpableProbe.reason != "" {
		t.Skipf("the helper stops before it reads anything on a host that cannot make a process not dumpable, and this host cannot: %s", bootstrapNotDumpableProbe.reason)
	}
}

// runRemoteAlphaBootstrapHelperWithPTYInput runs the helper with a terminal,
// answering its prompts with input. Every such run passes the helper's core
// dump step, so it first checks that this host lets the helper pass it.
func runRemoteAlphaBootstrapHelperWithPTYInput(t *testing.T, env []string, input string, args ...string) (string, error) {
	t.Helper()
	requireBootstrapNotDumpableCapability(t)
	return runRemoteAlphaBootstrapHelperWithPTYInputOnAnyHost(t, env, input, args...)
}

// runRemoteAlphaBootstrapHelperWithPTYInputOnAnyHost is the same run without
// that check, for a test that expects the helper to stop at the core dump step.
func runRemoteAlphaBootstrapHelperWithPTYInputOnAnyHost(t *testing.T, env []string, input string, args ...string) (string, error) {
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
    if sent == 0 and (b"Vault bootstrap authority token" in buffer or b"Vault unseal key" in buffer) and len(input_lines) > 0:
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
	// Token is the X-Vault-Token header the request carried ("" for none).
	Token string
}

type fakeBootstrapVaultServer struct {
	t             *testing.T
	expectedToken string
	requests      []fakeBootstrapVaultRequest
	failPath      string
	failStatus    int
	failBody      string
	// generateRoot, when set, serves sys/generate-root and the token
	// endpoints of REMOTE_ALPHA_BOOTSTRAP_AUTHORITY=unseal-key. The
	// configuration requests must then carry the short-lived child token.
	generateRoot *fakeGenerateRoot
}

// fakeGenerateRoot models the parts of Vault that the unseal-key authority
// uses: sys/generate-root with one key share, auth/token/create-orphan,
// auth/token/revoke-self, and the accessor list, lookup and revoke of the
// standing root token check.
type fakeGenerateRoot struct {
	unsealKey  string
	rootToken  string
	childToken string
	otp        string
	nonce      string
	required   int
	// alreadyStarted makes GET sys/generate-root/attempt report an attempt
	// that someone else started.
	alreadyStarted   bool
	started          bool
	failCreateOrphan bool
	// failRevokeFor makes revoke-self fail for this token value.
	failRevokeFor string
	revoked       []string
	cancelled     int
	// refuseUnauthenticated models Vault 2.x: generate-root without a token
	// answers 403 unless the configuration that Vault last loaded, the file
	// loadedConfigPath, enables it.
	refuseUnauthenticated bool
	loadedConfigPath      string
	// openAtCreateOrphan, openAtRootRevoke and openAtConfiguration record
	// whether unauthenticated generate-root was still enabled when the child
	// token was made, when the root token was revoked, and at the first
	// configuration request.
	openAtCreateOrphan  bool
	openAtRootRevoke    bool
	openAtConfiguration bool
	// afterFirstStatus runs once, right after the first GET of
	// sys/generate-root/attempt (the read-only preflight) is answered, to
	// model Vault changing between the preflight and generate-root.
	afterFirstStatus func(g *fakeGenerateRoot)
	statusReads      int
	// otherTokens are the tokens, other than the child, that the accessor
	// list shows, by accessor.
	otherTokens      map[string]fakeVaultTokenInfo
	failAccessorList bool
	// listVanished adds an accessor to the list whose token is gone by the
	// time it is looked up (Vault answers 400).
	listVanished      bool
	revokedAccessors  []string
	childAccessorSeen bool
}

// fakeVaultTokenInfo is what auth/token/lookup-accessor reports.
type fakeVaultTokenInfo struct {
	policies   []string
	expireTime string
	period     int
}

const fakeChildAccessor = "fakeChildTokenAccessor0000001"

func (g *fakeGenerateRoot) unauthenticatedAllowed() bool {
	if !g.refuseUnauthenticated {
		return true
	}
	data, err := os.ReadFile(g.loadedConfigPath)
	return err == nil && strings.Contains(string(data), `enable_unauthenticated_access = ["generate-root"]`)
}

func (g *fakeGenerateRoot) serve(t *testing.T, w http.ResponseWriter, r *http.Request, token string, body map[string]any) bool {
	t.Helper()
	if token == g.childToken && r.URL.Path == "/v1/sys/auth" {
		g.openAtConfiguration = g.refuseUnauthenticated && g.unauthenticatedAllowed()
	}
	if strings.HasPrefix(r.URL.Path, "/v1/sys/generate-root/") && !g.unauthenticatedAllowed() {
		g.afterStatusRead(r)
		writeJSON(w, http.StatusForbidden, map[string]any{"errors": []string{"permission denied"}})
		return true
	}
	switch {
	case r.URL.Path == "/v1/sys/generate-root/attempt":
		if token != "" {
			t.Errorf("%s %s must not carry a Vault token", r.Method, r.URL.Path)
		}
		switch r.Method {
		case http.MethodGet:
			started := g.alreadyStarted || g.started
			g.afterStatusRead(r)
			writeJSON(w, http.StatusOK, map[string]any{"started": started, "progress": 0, "required": g.required, "complete": false})
		case http.MethodPut:
			g.started = true
			writeJSON(w, http.StatusOK, map[string]any{"started": true, "nonce": g.nonce, "otp": g.otp, "otp_length": len(g.otp), "progress": 0, "required": g.required, "complete": false})
		case http.MethodDelete:
			g.started = false
			g.cancelled++
			w.WriteHeader(http.StatusNoContent)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"errors": []string{}})
		}
		return true
	case r.Method == http.MethodPut && r.URL.Path == "/v1/sys/generate-root/update":
		if token != "" {
			t.Errorf("%s %s must not carry a Vault token", r.Method, r.URL.Path)
		}
		if !g.started || body["nonce"] != g.nonce || body["key"] != g.unsealKey {
			writeJSON(w, http.StatusBadRequest, map[string]any{"errors": []string{"unable to authenticate"}})
			return true
		}
		g.started = false
		mixed := make([]byte, len(g.rootToken))
		for i := range mixed {
			mixed[i] = g.rootToken[i] ^ g.otp[i]
		}
		writeJSON(w, http.StatusOK, map[string]any{"complete": true, "progress": 1, "required": 1, "nonce": g.nonce, "encoded_token": base64.RawStdEncoding.EncodeToString(mixed)})
		return true
	case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/token/create-orphan":
		if token != g.rootToken {
			t.Errorf("create-orphan must use the generated root token")
			writeJSON(w, http.StatusForbidden, map[string]any{"errors": []string{"permission denied"}})
			return true
		}
		g.openAtCreateOrphan = g.refuseUnauthenticated && g.unauthenticatedAllowed()
		if g.failCreateOrphan {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"errors": []string{"raw Vault output must not be summarized"}})
			return true
		}
		writeJSON(w, http.StatusOK, map[string]any{"auth": map[string]any{"client_token": g.childToken, "accessor": fakeChildAccessor, "policies": []string{"root"}, "lease_duration": 900, "renewable": false}})
		return true
	case r.Method == "LIST" && r.URL.Path == "/v1/auth/token/accessors":
		if token != g.childToken {
			t.Errorf("the accessor list must be read with the short-lived token")
		}
		if g.failAccessorList {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"errors": []string{"raw Vault output must not be summarized"}})
			return true
		}
		keys := []string{fakeChildAccessor}
		if g.listVanished {
			keys = append(keys, "fakeVanishedTokenAccessor001")
		}
		for accessor := range g.otherTokens {
			keys = append(keys, accessor)
		}
		sort.Strings(keys)
		writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"keys": keys}})
		return true
	case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/token/lookup-accessor":
		if token != g.childToken {
			t.Errorf("lookup-accessor must use the short-lived token")
		}
		accessor, _ := body["accessor"].(string)
		if accessor == fakeChildAccessor {
			g.childAccessorSeen = true
			writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"accessor": accessor, "policies": []string{"root"}, "expire_time": "2026-11-23T20:15:00Z", "ttl": 899}})
			return true
		}
		info, ok := g.otherTokens[accessor]
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]any{"errors": []string{"invalid accessor"}})
			return true
		}
		data := map[string]any{"accessor": accessor, "policies": info.policies, "ttl": 0, "expire_time": nil}
		if info.expireTime != "" {
			data["expire_time"] = info.expireTime
			data["ttl"] = 600
		}
		if info.period != 0 {
			data["period"] = info.period
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": data})
		return true
	case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/token/revoke-accessor":
		if token != g.childToken {
			t.Errorf("revoke-accessor must use the short-lived token")
		}
		accessor, _ := body["accessor"].(string)
		if _, ok := g.otherTokens[accessor]; !ok {
			t.Errorf("revoke-accessor for an accessor that is not a listed token")
			writeJSON(w, http.StatusBadRequest, map[string]any{"errors": []string{"invalid accessor"}})
			return true
		}
		delete(g.otherTokens, accessor)
		g.revokedAccessors = append(g.revokedAccessors, accessor)
		w.WriteHeader(http.StatusNoContent)
		return true
	case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/token/revoke-self":
		if token != g.rootToken && token != g.childToken {
			t.Errorf("revoke-self with an unknown token")
			writeJSON(w, http.StatusForbidden, map[string]any{"errors": []string{"permission denied"}})
			return true
		}
		if token == g.rootToken {
			g.openAtRootRevoke = g.refuseUnauthenticated && g.unauthenticatedAllowed()
		}
		if token == g.failRevokeFor {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"errors": []string{"raw Vault output must not be summarized"}})
			return true
		}
		g.revoked = append(g.revoked, token)
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	return false
}

// afterStatusRead runs afterFirstStatus once, after the first GET of
// sys/generate-root/attempt.
func (g *fakeGenerateRoot) afterStatusRead(r *http.Request) {
	if r.Method != http.MethodGet || r.URL.Path != "/v1/sys/generate-root/attempt" {
		return
	}
	g.statusReads++
	if g.statusReads == 1 && g.afterFirstStatus != nil {
		g.afterFirstStatus(g)
	}
}

func (f *fakeBootstrapVaultServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.t.Helper()
	token := r.Header.Get("X-Vault-Token")

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
		Token:  token,
	})

	if f.generateRoot != nil && f.generateRoot.serve(f.t, w, r, token, body) {
		return
	}
	if token != f.expectedToken {
		f.t.Fatalf("unexpected bootstrap Vault token header for %s %s", r.Method, r.URL.Path)
	}

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
	case r.Method == http.MethodDelete && r.URL.Path == "/v1/proof-secrets/metadata/runtime-identity-vault-login":
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodDelete && r.URL.Path == "/v1/proof-secrets/metadata/codex-runtime-profile":
		// Vault answers 404 for a path that never existed; the helper accepts it.
		writeJSON(w, http.StatusNotFound, map[string]any{"errors": []string{}})
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

type fakeSpireJWTValidationKey struct {
	N   string
	E   string
	PEM string
}

func generateFakeSpireJWTValidationKey(t *testing.T) fakeSpireJWTValidationKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate fake SPIRE JWT validation key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal fake SPIRE JWT validation public key: %v", err)
	}
	return fakeSpireJWTValidationKey{
		N:   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
		PEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
	}
}

func fakeSpireJWTValidationBundle(keys ...fakeSpireJWTValidationKey) string {
	entries := make([]string, 0, len(keys))
	for _, key := range keys {
		entries = append(entries, fmt.Sprintf(`{"kty":"RSA","use":"jwt-svid","n":%q,"e":%q}`, key.N, key.E))
	}
	return fmt.Sprintf(`{"keys":[%s]}`, strings.Join(entries, ","))
}

func setupFakeBootstrapSpireServerWithBundle(t *testing.T, dir string, bundleJSON string) string {
	t.Helper()
	logPath := filepath.Join(dir, "spire-server.log")
	// It also records the core file limits it inherited from the helper and,
	// where /proc exists, who owns the helper's /proc/<pid>/status: root, for
	// a process that is not dumpable. (The /proc/<pid> directory itself keeps
	// the process's own user either way.)
	writeExecutable(t, dir, "spire-server", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
printf 'args=%%s\n' "$*" >> %[1]q
printf 'core_limit=%%s/%%s\n' "$(ulimit -c)" "$(ulimit -H -c)" >> %[1]q
if [ -r "/proc/$PPID/status" ]; then printf 'uid=%%s helper_proc_status_owner=%%s\n' "$(id -u)" "$(stat -c %%u "/proc/$PPID/status")" >> %[1]q; fi
env | sort | sed -n '/TOKEN/p;/SECRET/p;/PASSWORD/p' >> %[1]q
cat <<'JSON'
%[2]s
JSON
`, logPath, bundleJSON))
	return logPath
}

func setupFakeBootstrapSpireServer(t *testing.T, dir string) string {
	t.Helper()
	key := generateFakeSpireJWTValidationKey(t)
	return setupFakeBootstrapSpireServerWithBundle(t, dir, fakeSpireJWTValidationBundle(key))
}

func assertValidationPubkeysMatch(t *testing.T, validationKeys []any, want ...fakeSpireJWTValidationKey) {
	t.Helper()
	if len(validationKeys) != len(want) {
		t.Fatalf("expected %d jwt_validation_pubkeys entries, got %#v", len(want), validationKeys)
	}
	for index, wantKey := range want {
		validationPEM, ok := validationKeys[index].(string)
		if !ok || !strings.Contains(validationPEM, "-----BEGIN PUBLIC KEY-----") {
			t.Fatalf("expected PEM public key validation material at index %d, got %#v", index, validationKeys[index])
		}
		if validationPEM != wantKey.PEM {
			t.Fatalf("unexpected validation key at index %d", index)
		}
		block, _ := pem.Decode([]byte(validationPEM))
		if block == nil || block.Type != "PUBLIC KEY" {
			t.Fatalf("expected parseable PUBLIC KEY PEM at index %d, got block %#v", index, block)
		}
		parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			t.Fatalf("parse validation public key at index %d: %v", index, err)
		}
		if _, ok := parsedKey.(*rsa.PublicKey); !ok {
			t.Fatalf("expected RSA validation public key at index %d, got %T", index, parsedKey)
		}
	}
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
		"Ctrl-Z (SIGTSTP, SIGTTIN, SIGTTOU) waits the same way.",
		"Core dumps: off (core file limit 0, and not dumpable through prctl)\n  before anything is read, so a crash writes no secret to disk. Where\n  either cannot be done (a host without prctl, such as macOS), the helper\n  stops before it reads anything.",
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

func TestRemoteAlphaVaultWorkloadAuthBootstrapRejectsInvalidRoleTokenLimitsBeforePromptsAndVaultWrites(t *testing.T) {
	cases := []struct {
		name         string
		env          []string
		messageClass string
	}{
		{name: "ttl_not_duration", env: []string{"REMOTE_ALPHA_BOOTSTRAP_TOKEN_TTL=forever"}, messageClass: "token_ttl_not_a_duration"},
		{name: "ttl_zero", env: []string{"REMOTE_ALPHA_BOOTSTRAP_TOKEN_TTL=0m"}, messageClass: "token_ttl_not_a_duration"},
		{name: "max_ttl_not_duration", env: []string{"REMOTE_ALPHA_BOOTSTRAP_TOKEN_MAX_TTL=1d"}, messageClass: "token_ttl_not_a_duration"},
		{name: "ttl_above_max", env: []string{"REMOTE_ALPHA_BOOTSTRAP_TOKEN_TTL=45m"}, messageClass: "token_ttl_out_of_range"},
		{name: "max_ttl_above_ceiling", env: []string{"REMOTE_ALPHA_BOOTSTRAP_TOKEN_MAX_TTL=25h"}, messageClass: "token_ttl_out_of_range"},
		{name: "cidr_invalid", env: []string{"REMOTE_ALPHA_BOOTSTRAP_TOKEN_BOUND_CIDRS=172.17.0.1/16"}, messageClass: "token_bound_cidr_invalid"},
		{name: "cidr_everything", env: []string{"REMOTE_ALPHA_BOOTSTRAP_TOKEN_BOUND_CIDRS=0.0.0.0/0"}, messageClass: "token_bound_cidr_matches_everything"},
		{name: "cidr_empty", env: []string{"REMOTE_ALPHA_BOOTSTRAP_TOKEN_BOUND_CIDRS= "}, messageClass: "token_bound_cidrs_empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			fakeBin := filepath.Join(tmpDir, "bin")
			if err := os.MkdirAll(fakeBin, 0o755); err != nil {
				t.Fatalf("mkdir fake bin: %v", err)
			}
			setupFakeBootstrapSpireServer(t, fakeBin)

			rootToken := "hvs.fakeRootTokenForTokenLimits1234567890"
			proofSecret := "sk-fakeProofSecretForTokenLimits1234567890"
			server, state, caBundle := startFakeBootstrapVault(t, rootToken)
			configPath := filepath.Join(tmpDir, "workload-zone-vault-config.json")
			summaryPath := filepath.Join(tmpDir, "summary", "vault-workload-auth-bootstrap-summary.json")
			writeWorkloadZoneConfig(t, configPath, server.URL, "jwt", "service_execution", "vault", caBundle)

			env := append([]string{
				"REMOTE_ALPHA_BOOTSTRAP_WORKLOAD_ZONE_CONFIG_PATH=" + configPath,
				"REMOTE_ALPHA_BOOTSTRAP_SUMMARY_PATH=" + summaryPath,
			}, tc.env...)
			output, err := runRemoteAlphaBootstrapHelperWithPTYInput(t,
				envWithPath(fakeBin, env...),
				rootToken+"\n"+proofSecret+"\n",
			)
			if err == nil {
				t.Fatalf("expected invalid role token limits to fail:\n%s", output)
			}
			assertContainsNone(t, "invalid role token limits output", output,
				"Vault bootstrap authority token",
				"Proof secret value",
				rootToken,
				proofSecret,
				"Traceback",
			)
			if got := len(state.requests); got != 0 {
				t.Fatalf("invalid role token limits must not call Vault, got %d requests", got)
			}
			summary := assertBootstrapFailureSummary(t, summaryPath, "role_token_limits", "config_invalid", false, false, rootToken, proofSecret)
			if got := summary["failure_message_class"]; got != tc.messageClass {
				t.Fatalf("expected failure_message_class=%s, got %#v\nsummary=%s", tc.messageClass, got, mustRead(t, summaryPath))
			}
		})
	}
}

func TestRemoteAlphaVaultWorkloadAuthBootstrapConfigLoadFailureWritesSafeSummaryBeforePrompts(t *testing.T) {
	requireBootstrapNotDumpableCapability(t)
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
	// P0q-R1: the role token limits are validated (no Vault request) after
	// the summary preflight and before the config is loaded.
	if got := summary["last_completed_operation"]; got != "role_token_limits" {
		t.Fatalf("expected last_completed_operation=role_token_limits before config failure, got %#v", got)
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
	requireBootstrapNotDumpableCapability(t)
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
		{name: "proof_secret_prior_versions", failPath: "/v1/proof-secrets/metadata/runtime-identity-vault-login", failStatus: http.StatusForbidden, phase: "proof_secret_prior_versions", failureClass: "vault_permission_denied"},
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
	requireBootstrapNotDumpableCapability(t)
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
		"DELETE /v1/proof-secrets/metadata/runtime-identity-vault-login",
		"DELETE /v1/proof-secrets/metadata/codex-runtime-profile",
		"POST /v1/proof-secrets/data/runtime-identity-vault-login",
		"POST /v1/proof-secrets/data/codex-runtime-profile",
	)
	// Earlier versions go before the new value is written, never after.
	for _, path := range []string{"runtime-identity-vault-login", "codex-runtime-profile"} {
		deleteIndex := strings.Index(joined, "DELETE /v1/proof-secrets/metadata/"+path)
		writeIndex := strings.Index(joined, "POST /v1/proof-secrets/data/"+path)
		if deleteIndex < 0 || writeIndex < 0 || deleteIndex > writeIndex {
			t.Fatalf("metadata of %s must be deleted before the new value is written:\n%s", path, joined)
		}
	}
	assertContainsNone(t, "fake bootstrap Vault requests forbidden live checks", joined,
		"/auth/jwt/login",
		"/auth/token/lookup-self",
		"/auth/token/revoke-self",
		"reset",
		"unseal",
	)

	jwtConfigRequest := findFakeBootstrapRequest(t, state.requests, "POST", "/v1/auth/jwt/config")
	if got := jwtConfigRequest.Body["bound_issuer"]; got != "spiffe://execution.internal" {
		t.Fatalf("expected bound_issuer spiffe://execution.internal, got %#v", got)
	}
	validationKeys, ok := jwtConfigRequest.Body["jwt_validation_pubkeys"].([]any)
	if !ok || len(validationKeys) != 1 {
		t.Fatalf("expected one jwt_validation_pubkeys entry, got %#v", jwtConfigRequest.Body["jwt_validation_pubkeys"])
	}
	validationPEM, ok := validationKeys[0].(string)
	if !ok || !strings.Contains(validationPEM, "-----BEGIN PUBLIC KEY-----") {
		t.Fatalf("expected PEM public key validation material, got %#v", validationKeys[0])
	}
	block, _ := pem.Decode([]byte(validationPEM))
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Fatalf("expected parseable PUBLIC KEY PEM, got block %#v", block)
	}
	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse validation public key: %v", err)
	}
	if _, ok := parsedKey.(*rsa.PublicKey); !ok {
		t.Fatalf("expected RSA validation public key, got %T", parsedKey)
	}

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
	if got := roleRequest.Body["token_ttl"]; got != "15m" {
		t.Fatalf("expected token_ttl 15m, got %#v", got)
	}
	if got := roleRequest.Body["token_max_ttl"]; got != "30m" {
		t.Fatalf("expected token_max_ttl 30m, got %#v", got)
	}
	if got := fmt.Sprint(roleRequest.Body["token_bound_cidrs"]); got != "[172.17.0.0/16]" {
		t.Fatalf("expected token_bound_cidrs [172.17.0.0/16], got %s", got)
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
	if got := spireMaterial["vault_jwt_config_shape"]; got != "jwt_validation_pubkeys_array_pem_bound_issuer" {
		t.Fatalf("expected safe Vault JWT config shape label, got %#v", got)
	}
	if got := spireMaterial["jwt_validation_pubkeys_count"]; got != float64(1) {
		t.Fatalf("expected one validation pubkey diagnostic, got %#v", got)
	}
	if digestSet := jsonStringSlice(t, spireMaterial["public_key_digest_set"]); len(digestSet) != 1 || !strings.HasPrefix(digestSet[0], "sha256:") {
		t.Fatalf("expected one safe public key digest, got %#v", spireMaterial["public_key_digest_set"])
	}
	jwtAuthConfig, ok := operations["jwt_auth_config"].(map[string]any)
	if !ok || jwtAuthConfig["validation_material_field"] != "jwt_validation_pubkeys" || jwtAuthConfig["vault_jwt_config_shape"] != "jwt_validation_pubkeys_array_pem_bound_issuer" {
		t.Fatalf("expected jwt auth config safe shape labels, got %#v", operations["jwt_auth_config"])
	}
	if got := jwtAuthConfig["jwt_validation_pubkeys_count"]; got != float64(1) {
		t.Fatalf("expected one configured validation pubkey diagnostic, got %#v", got)
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
		`"proof_path_history": "all_earlier_versions_and_metadata_deleted_before_write"`,
		`"token_ttl": "15m"`,
		`"token_max_ttl": "30m"`,
		`"proof_secret_prior_versions": {`,
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
	assertBootstrapCoreDumpsOff(t, spireLogRaw, summary)
}

// assertBootstrapCoreDumpsOff checks, through a command the helper started
// before its first prompt (the SPIRE server), that core dumps were off by
// then: the inherited core file limit is 0, and, where the helper's
// /proc/<pid>/status exists and the test does not run as root, that file
// belongs to root, which is what a process that is not dumpable looks like.
// The summary must record both. (RT07-2)
func assertBootstrapCoreDumpsOff(t *testing.T, spireLog string, summary map[string]any) {
	t.Helper()
	if !strings.Contains(spireLog, "core_limit=0/0\n") {
		t.Fatalf("commands the helper starts must inherit a core file limit of 0 (soft and hard), got:\n%s", spireLog)
	}
	if uid := os.Getuid(); uid != 0 && strings.Contains(spireLog, "helper_proc_status_owner=") {
		if !strings.Contains(spireLog, fmt.Sprintf("uid=%d helper_proc_status_owner=0\n", uid)) {
			t.Fatalf("the helper must not be dumpable (its /proc/<pid>/status must belong to root), got:\n%s", spireLog)
		}
	}
	operation, ok := summary["operations"].(map[string]any)["disable_core_dumps"].(map[string]any)
	if !ok || operation["status"] != "pass" || operation["rlimit_core"] != float64(0) || operation["dumpable"] != false {
		t.Fatalf("the summary must record disable_core_dumps pass with rlimit_core 0 and dumpable false, got %#v", summary["operations"])
	}
}

func TestRemoteAlphaVaultWorkloadAuthBootstrapWritesAllValidationKeysForWorkloadTrustDomain(t *testing.T) {
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	firstKey := generateFakeSpireJWTValidationKey(t)
	secondKey := generateFakeSpireJWTValidationKey(t)
	thirdKey := generateFakeSpireJWTValidationKey(t)
	setupFakeBootstrapSpireServerWithBundle(t, fakeBin, fakeSpireJWTValidationBundle(firstKey, secondKey, thirdKey))

	rootToken := "root-token-for-all-validation-keys"
	proofSecret := "proof-value-for-all-validation-keys"
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
		t.Fatalf("bootstrap helper fake run failed: %v\noutput=%s\nsummary=%s", err, output, readIfExists(summaryPath))
	}

	jwtConfigRequest := findFakeBootstrapRequest(t, state.requests, "POST", "/v1/auth/jwt/config")
	validationKeys, ok := jwtConfigRequest.Body["jwt_validation_pubkeys"].([]any)
	if !ok {
		t.Fatalf("expected jwt_validation_pubkeys array, got %#v", jwtConfigRequest.Body["jwt_validation_pubkeys"])
	}
	assertValidationPubkeysMatch(t, validationKeys, firstKey, secondKey, thirdKey)
	if got := jwtConfigRequest.Body["bound_issuer"]; got != "spiffe://execution.internal" {
		t.Fatalf("expected bound issuer to stay repo-derived, got %#v", got)
	}

	summaryRaw := mustRead(t, summaryPath)
	assertContainsNone(t, "bootstrap all-key summary forbidden material", summaryRaw,
		firstKey.PEM,
		secondKey.PEM,
		thirdKey.PEM,
		firstKey.N,
		secondKey.N,
		thirdKey.N,
		rootToken,
		proofSecret,
	)
	summary := readJSONFile(t, summaryPath)
	operations := jsonMap(t, summary["operations"])
	spireMaterial := jsonMap(t, operations["spire_jwt_validation_material"])
	for field, want := range map[string]any{
		"validation_material_source":   "spiffe_bundle_direct_workload_trust_domain",
		"selected_trust_domain":        "execution.internal",
		"trust_domain_count":           float64(1),
		"key_count":                    float64(3),
		"jwt_svid_rsa_key_count":       float64(3),
		"jwt_validation_pubkeys_count": float64(3),
		"vault_jwt_config_shape":       "jwt_validation_pubkeys_array_pem_bound_issuer",
	} {
		if got := spireMaterial[field]; got != want {
			t.Fatalf("unexpected spire material diagnostic %s=%#v want %#v", field, got, want)
		}
	}
	digestSet := jsonStringSlice(t, spireMaterial["public_key_digest_set"])
	if len(digestSet) != 3 {
		t.Fatalf("expected three safe public key digests, got %#v", digestSet)
	}
	for _, digest := range digestSet {
		if !strings.HasPrefix(digest, "sha256:") {
			t.Fatalf("expected safe sha256 digest, got %q", digest)
		}
	}
	if aggregateDigest := fmt.Sprint(spireMaterial["public_key_digest"]); !strings.HasPrefix(aggregateDigest, "sha256:") {
		t.Fatalf("expected aggregate public key digest, got %q", aggregateDigest)
	}
	jwtAuthConfig := jsonMap(t, operations["jwt_auth_config"])
	if got := jwtAuthConfig["jwt_validation_pubkeys_count"]; got != float64(3) {
		t.Fatalf("expected three configured validation pubkeys, got %#v", got)
	}
}

func TestRemoteAlphaVaultWorkloadAuthBootstrapSelectsValidationKeysForWorkloadTrustDomain(t *testing.T) {
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	foreignKey := generateFakeSpireJWTValidationKey(t)
	localKeyA := generateFakeSpireJWTValidationKey(t)
	localKeyB := generateFakeSpireJWTValidationKey(t)
	bundleJSON := fmt.Sprintf(`{"trust_domains":{"foreign.internal":{"keys":[{"kty":"RSA","use":"jwt-svid","n":%q,"e":%q}]},"execution.internal":{"keys":[{"kty":"RSA","use":"jwt-svid","n":%q,"e":%q},{"kty":"RSA","use":"jwt-svid","n":%q,"e":%q}]}}}`,
		foreignKey.N,
		foreignKey.E,
		localKeyA.N,
		localKeyA.E,
		localKeyB.N,
		localKeyB.E,
	)
	setupFakeBootstrapSpireServerWithBundle(t, fakeBin, bundleJSON)

	rootToken := "root-token-for-trust-domain-selection"
	proofSecret := "proof-value-for-trust-domain-selection"
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
		t.Fatalf("bootstrap helper fake run failed: %v\noutput=%s\nsummary=%s", err, output, readIfExists(summaryPath))
	}

	jwtConfigRequest := findFakeBootstrapRequest(t, state.requests, "POST", "/v1/auth/jwt/config")
	validationKeys, ok := jwtConfigRequest.Body["jwt_validation_pubkeys"].([]any)
	if !ok {
		t.Fatalf("expected jwt_validation_pubkeys array, got %#v", jwtConfigRequest.Body["jwt_validation_pubkeys"])
	}
	assertValidationPubkeysMatch(t, validationKeys, localKeyA, localKeyB)
	if got := jwtConfigRequest.Body["bound_issuer"]; got != "spiffe://execution.internal" {
		t.Fatalf("expected bound issuer to stay repo-derived, got %#v", got)
	}

	summaryRaw := mustRead(t, summaryPath)
	assertContainsNone(t, "bootstrap trust-domain selection summary forbidden material", summaryRaw,
		localKeyA.PEM,
		localKeyB.PEM,
		foreignKey.PEM,
		localKeyA.N,
		localKeyB.N,
		foreignKey.N,
		rootToken,
		proofSecret,
	)
	summary := readJSONFile(t, summaryPath)
	operations := jsonMap(t, summary["operations"])
	spireMaterial := jsonMap(t, operations["spire_jwt_validation_material"])
	for field, want := range map[string]any{
		"validation_material_source":   "spiffe_bundle_map_workload_trust_domain",
		"selected_trust_domain":        "execution.internal",
		"trust_domain_count":           float64(2),
		"key_count":                    float64(2),
		"jwt_svid_rsa_key_count":       float64(2),
		"jwt_validation_pubkeys_count": float64(2),
		"vault_jwt_config_shape":       "jwt_validation_pubkeys_array_pem_bound_issuer",
	} {
		if got := spireMaterial[field]; got != want {
			t.Fatalf("unexpected spire material diagnostic %s=%#v want %#v", field, got, want)
		}
	}
	if digest := fmt.Sprint(spireMaterial["public_key_digest"]); !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("expected safe public key digest, got %q", digest)
	}
	if digestSet := jsonStringSlice(t, spireMaterial["public_key_digest_set"]); len(digestSet) != 2 {
		t.Fatalf("expected two safe public key digests, got %#v", digestSet)
	}
}

func TestRemoteAlphaVaultWorkloadAuthBootstrapIgnoresNonJWTSVIDRSAKeys(t *testing.T) {
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	x509OnlyKey := generateFakeSpireJWTValidationKey(t)
	missingUseKey := generateFakeSpireJWTValidationKey(t)
	validKey := generateFakeSpireJWTValidationKey(t)
	bundleJSON := fmt.Sprintf(`{"keys":[{"kty":"RSA","use":"x509-svid","n":%q,"e":%q},{"kty":"RSA","n":%q,"e":%q},{"kty":"EC","use":"jwt-svid","crv":"P-256","x":"abc","y":"def"},{"kty":"RSA","use":"jwt-svid","n":%q,"e":%q}]}`,
		x509OnlyKey.N,
		x509OnlyKey.E,
		missingUseKey.N,
		missingUseKey.E,
		validKey.N,
		validKey.E,
	)
	setupFakeBootstrapSpireServerWithBundle(t, fakeBin, bundleJSON)

	rootToken := "root-token-for-mixed-validation-keys"
	proofSecret := "proof-value-for-mixed-validation-keys"
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
		t.Fatalf("bootstrap helper fake run failed: %v\noutput=%s\nsummary=%s", err, output, readIfExists(summaryPath))
	}

	jwtConfigRequest := findFakeBootstrapRequest(t, state.requests, "POST", "/v1/auth/jwt/config")
	validationKeys, ok := jwtConfigRequest.Body["jwt_validation_pubkeys"].([]any)
	if !ok {
		t.Fatalf("expected jwt_validation_pubkeys array, got %#v", jwtConfigRequest.Body["jwt_validation_pubkeys"])
	}
	assertValidationPubkeysMatch(t, validationKeys, validKey)

	summaryRaw := mustRead(t, summaryPath)
	assertContainsNone(t, "bootstrap mixed-key summary forbidden material", summaryRaw,
		x509OnlyKey.PEM,
		missingUseKey.PEM,
		validKey.PEM,
		x509OnlyKey.N,
		missingUseKey.N,
		validKey.N,
		rootToken,
		proofSecret,
	)
	summary := readJSONFile(t, summaryPath)
	operations := jsonMap(t, summary["operations"])
	spireMaterial := jsonMap(t, operations["spire_jwt_validation_material"])
	for field, want := range map[string]any{
		"key_count":                    float64(4),
		"jwt_svid_rsa_key_count":       float64(1),
		"jwt_validation_pubkeys_count": float64(1),
	} {
		if got := spireMaterial[field]; got != want {
			t.Fatalf("unexpected spire material diagnostic %s=%#v want %#v", field, got, want)
		}
	}
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

// RT07-2 (Low; secret hygiene, at the edge of the stated "not protection against
// root" boundary): the Vault workload-auth bootstrap keeps the unseal key, the
// generated root token, the short-lived token and the proof secret in ordinary
// Python memory, and goes to lengths to hold the generated root token for only
// two requests. It never disables core dumps, so a crash while a secret is in
// memory (a genuine fault, or kill -ABRT/-SEGV) writes that secret to a core
// file that persists on disk, defeating the minimal-lifetime design. The
// catchable termination signals (INT/TERM/HUP/QUIT) are already deferred across
// the generate-root window and proven so by TestRemoteAlphaVault...SignalsWithRealVault;
// this is the one on-disk leak path left for a crash.
//
// Fix: disable core dumps before reading any secret, e.g.
//
//	import resource; resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
//
// and/or prctl(PR_SET_DUMPABLE, 0); `ulimit -c 0` in the bash wrapper also works.
func TestRemoteAlphaVaultWorkloadAuthBootstrapDisablesCoreDumpsBeforeSecrets(t *testing.T) {
	source := mustRead(t, remoteAlphaVaultWorkloadAuthBootstrapInternalPath())
	disablers := []string{
		"RLIMIT_CORE",
		"PR_SET_DUMPABLE",
		"prctl",
		"ulimit -c 0",
		"ulimit -c unlimited\nulimit -c 0", // any explicit zero core limit
	}
	firstDisabler := -1
	for _, d := range disablers {
		if i := strings.Index(source, d); i >= 0 {
			firstDisabler = i
			break
		}
	}
	if firstDisabler < 0 {
		t.Errorf("RT07-2: bootstrap never disables core dumps; a crash while the unseal key or a root token is in memory can persist it to a core file")
		return
	}
	// The run marks the point just before it reads the first secret.
	firstPrompt := strings.Index(source, `summary["secret_prompts_started"] = True`)
	if firstPrompt >= 0 && firstDisabler > firstPrompt {
		t.Errorf("RT07-2: core dumps are disabled only after secret prompts start (disabler at %d, prompts start at %d)", firstDisabler, firstPrompt)
	}
}

// bootstrapPrctlShim is a sitecustomize module that changes ctypes.CDLL in
// every python3 that has its directory on PYTHONPATH, and so in the helper's.
// ES_TEST_PRCTL picks what the helper's prctl lookup and calls then see.
// PR_SET_DUMPABLE is 4 and PR_GET_DUMPABLE is 3.
const bootstrapPrctlShim = `import ctypes
import os

_mode = os.environ.get("ES_TEST_PRCTL", "")
_RealCDLL = ctypes.CDLL


def _option(value):
    return getattr(value, "value", value)


class _TestCDLL(_RealCDLL):
    def __init__(self, *args, **kwargs):
        if _mode == "no_c_library":
            raise OSError("test: the C library cannot be opened")
        super().__init__(*args, **kwargs)

    def __getattr__(self, name):
        if name == "prctl" and _mode == "no_prctl":
            raise AttributeError(name)
        if name == "prctl" and _mode == "set_fails":
            return lambda option, *rest: -1 if _option(option) == 4 else 0
        if name == "prctl" and _mode == "still_dumpable":
            return lambda option, *rest: 0 if _option(option) == 4 else 1
        return super().__getattr__(name)


ctypes.CDLL = _TestCDLL
`

// TestRemoteAlphaVaultWorkloadAuthBootstrapRefusesWhenTheProcessStaysDumpable
// runs the helper with a python3 whose ctypes cannot make the process not
// dumpable, in each way that can happen: the C library cannot be opened, it
// has no prctl (macOS, for example), prctl(PR_SET_DUMPABLE, 0) fails, or the
// process is still dumpable when read back. The helper must stop at phase
// disable_core_dumps before any prompt, SPIRE command or Vault request, and
// must not fall back to running without it. The same setup with the module
// in place but nothing changed runs to the end, so it is the change that
// stops the helper. The refusals do not need prctl on this host and run on
// every host. (Codex review of PR #35: no operating system branch.)
func TestRemoteAlphaVaultWorkloadAuthBootstrapRefusesWhenTheProcessStaysDumpable(t *testing.T) {
	for _, mode := range []string{"no_c_library", "no_prctl", "set_fails", "still_dumpable", "unchanged"} {
		t.Run(mode, func(t *testing.T) {
			tmpDir := t.TempDir()
			fakeBin := filepath.Join(tmpDir, "bin")
			if err := os.MkdirAll(fakeBin, 0o755); err != nil {
				t.Fatalf("mkdir fake bin: %v", err)
			}
			spireLog := setupFakeBootstrapSpireServer(t, fakeBin)
			shimDir := filepath.Join(tmpDir, "python-shim")
			if err := os.MkdirAll(shimDir, 0o755); err != nil {
				t.Fatalf("mkdir python shim dir: %v", err)
			}
			if err := os.WriteFile(filepath.Join(shimDir, "sitecustomize.py"), []byte(bootstrapPrctlShim), 0o644); err != nil {
				t.Fatalf("write sitecustomize.py: %v", err)
			}

			rootToken := "hvs.fakeRootTokenForDumpableRefusal1234567890"
			proofSecret := "sk-fakeProofSecretForDumpableRefusal1234567890"
			server, state, caBundle := startFakeBootstrapVault(t, rootToken)
			configPath := filepath.Join(tmpDir, "workload-zone-vault-config.json")
			summaryPath := filepath.Join(tmpDir, "summary", "vault-workload-auth-bootstrap-summary.json")
			writeWorkloadZoneConfig(t, configPath, server.URL, "jwt", "service_execution", "vault", caBundle)
			env := envWithPath(fakeBin,
				"REMOTE_ALPHA_BOOTSTRAP_WORKLOAD_ZONE_CONFIG_PATH="+configPath,
				"REMOTE_ALPHA_BOOTSTRAP_SUMMARY_PATH="+summaryPath,
				"PYTHONPATH="+shimDir,
				"ES_TEST_PRCTL="+mode,
			)
			input := rootToken + "\n" + proofSecret + "\n"

			if mode == "unchanged" {
				output, err := runRemoteAlphaBootstrapHelperWithPTYInput(t, env, input)
				if err != nil {
					t.Fatalf("with the module in place and nothing changed, the helper must run to the end: %v\noutput=%s", err, output)
				}
				if len(state.requests) == 0 {
					t.Fatalf("with nothing changed, the helper must reach Vault:\n%s", output)
				}
				assertBootstrapCoreDumpsOff(t, mustRead(t, spireLog), readJSONFile(t, summaryPath))
				return
			}

			output, err := runRemoteAlphaBootstrapHelperWithPTYInputOnAnyHost(t, env, input)
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
				t.Fatalf("a helper that cannot make itself not dumpable must exit 1, got %v\noutput=%s", err, output)
			}
			assertContainsAll(t, "dumpable refusal output", output,
				"failure_phase=disable_core_dumps failure_class=core_dumps_not_disabled",
			)
			assertContainsNone(t, "dumpable refusal output", output,
				"Vault bootstrap authority token",
				"Proof secret value",
				rootToken,
				proofSecret,
				"Traceback",
			)
			if got := len(state.requests); got != 0 {
				t.Fatalf("a helper that cannot make itself not dumpable must not call Vault, got %d requests", got)
			}
			if _, statErr := os.Stat(spireLog); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("a helper that cannot make itself not dumpable must not start the SPIRE server command (log: %v)", statErr)
			}
			summary := assertBootstrapFailureSummary(t, summaryPath, "disable_core_dumps", "core_dumps_not_disabled", false, false, rootToken, proofSecret)
			if got := summary["failure_message_class"]; got != "process_still_dumpable" {
				t.Fatalf("expected failure_message_class=process_still_dumpable, got %#v", got)
			}
			if got := summary["last_completed_operation"]; got == "disable_core_dumps" {
				t.Fatalf("the core dump step must not be recorded as completed, got %#v", got)
			}
		})
	}
}

// TestRemoteAlphaVaultWorkloadAuthBootstrapDoesNotBranchOnTheOperatingSystem
// pins AGENTS.md section 12 for this helper: it requires both core dump
// settings on every host and finds a host that cannot make the process not
// dumpable by trying, not by the operating system's name. On Linux, an
// operating system branch behaves the same as no branch, so only the source
// can show it.
func TestRemoteAlphaVaultWorkloadAuthBootstrapDoesNotBranchOnTheOperatingSystem(t *testing.T) {
	for _, path := range []string{remoteAlphaVaultWorkloadAuthBootstrapScriptPath(), remoteAlphaVaultWorkloadAuthBootstrapInternalPath()} {
		assertContainsNone(t, filepath.Base(filepath.Dir(path))+"/"+filepath.Base(path)+" operating system checks", mustRead(t, path),
			"sys.platform",
			"platform.system",
			"platform.platform",
			"import platform",
			"os.uname",
			"uname",
			"OSTYPE",
			"darwin",
			"Darwin",
		)
	}
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

// newFakeGenerateRoot returns a generate-root model whose root token and
// one-time password have the same length, as Vault's do.
func newFakeGenerateRoot() *fakeGenerateRoot {
	return &fakeGenerateRoot{
		unsealKey:  "fakeUnsealKeyShareForBootstrapTest0123456789+/=",
		rootToken:  "fake-generated-root-token-01",
		childToken: "fake-short-lived-child-token",
		otp:        "OneTimePasswordOfLength28abc",
		nonce:      "2dbd10f1-8528-6246-09e7-82b25b8aba63",
		required:   1,
	}
}

type unsealKeyBootstrapRun struct {
	output      string
	err         error
	summaryPath string
	state       *fakeBootstrapVaultServer
	spireLog    string
}

func runUnsealKeyBootstrap(t *testing.T, g *fakeGenerateRoot, failPath string, failStatus int, input string, extraEnv ...string) unsealKeyBootstrapRun {
	t.Helper()
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	spireLog := setupFakeBootstrapSpireServer(t, fakeBin)
	state := &fakeBootstrapVaultServer{
		t:             t,
		expectedToken: g.childToken,
		generateRoot:  g,
		failPath:      failPath,
		failStatus:    failStatus,
		failBody:      `{"errors":["raw Vault output must not be summarized"]}`,
	}
	server := httptest.NewTLSServer(state)
	t.Cleanup(server.Close)
	configPath := filepath.Join(tmpDir, "workload-zone-vault-config.json")
	summaryPath := filepath.Join(tmpDir, "summary", "vault-workload-auth-bootstrap-summary.json")
	writeWorkloadZoneConfig(t, configPath, server.URL, "jwt", "service_execution", "vault", encodeCertificatePEM(t, server.Certificate()))
	env := append([]string{
		"REMOTE_ALPHA_BOOTSTRAP_WORKLOAD_ZONE_CONFIG_PATH=" + configPath,
		"REMOTE_ALPHA_BOOTSTRAP_SUMMARY_PATH=" + summaryPath,
		"REMOTE_ALPHA_BOOTSTRAP_AUTHORITY=unseal-key",
		"REMOTE_ALPHA_BOOTSTRAP_PROOF_VALUE=generate",
	}, extraEnv...)
	output, err := runRemoteAlphaBootstrapHelperWithPTYInput(t, envWithPath(fakeBin, env...), input)
	return unsealKeyBootstrapRun{output: output, err: err, summaryPath: summaryPath, state: state, spireLog: spireLog}
}

func fakeBootstrapRequestLines(requests []fakeBootstrapVaultRequest, g *fakeGenerateRoot) []string {
	lines := make([]string, 0, len(requests))
	for _, request := range requests {
		who := "none"
		switch request.Token {
		case "":
		case g.rootToken:
			who = "root"
		case g.childToken:
			who = "child"
		default:
			who = "other"
		}
		lines = append(lines, request.Method+" "+request.Path+" token="+who)
	}
	return lines
}

func indexOfLine(lines []string, want string) int {
	for i, line := range lines {
		if line == want {
			return i
		}
	}
	return -1
}

func TestRemoteAlphaVaultWorkloadAuthBootstrapUnsealKeyAuthorityRevokesGeneratedTokens(t *testing.T) {
	g := newFakeGenerateRoot()
	run := runUnsealKeyBootstrap(t, g, "", 0, g.unsealKey+"\n")
	if run.err != nil {
		t.Fatalf("unseal-key bootstrap failed: %v\noutput=%s\nsummary=%s", run.err, run.output, readIfExists(run.summaryPath))
	}
	lines := fakeBootstrapRequestLines(run.state.requests, g)
	joined := strings.Join(lines, "\n")

	// The order: make the root token, make the short-lived child with it,
	// revoke the root token at once (the next request), check for standing
	// root tokens, configure with the child only, revoke the child.
	order := []string{
		"GET /v1/sys/generate-root/attempt token=none",
		"PUT /v1/sys/generate-root/attempt token=none",
		"PUT /v1/sys/generate-root/update token=none",
		"POST /v1/auth/token/create-orphan token=root",
		"POST /v1/auth/token/revoke-self token=root",
		"LIST /v1/auth/token/accessors token=child",
		"POST /v1/auth/token/lookup-accessor token=child",
		"GET /v1/sys/auth token=child",
		"POST /v1/auth/jwt/role/service_execution token=child",
		"POST /v1/proof-secrets/data/codex-runtime-profile token=child",
		"POST /v1/auth/token/revoke-self token=child",
	}
	last := -1
	for _, want := range order {
		index := indexOfLine(lines, want)
		if index <= last {
			t.Fatalf("expected %q after the step before it:\n%s", want, joined)
		}
		last = index
	}
	if lines[len(lines)-1] != "POST /v1/auth/token/revoke-self token=child" {
		t.Fatalf("revoking the short-lived token must be the last request:\n%s", joined)
	}
	rootRevoke := indexOfLine(lines, "POST /v1/auth/token/revoke-self token=root")
	if create := indexOfLine(lines, "POST /v1/auth/token/create-orphan token=root"); rootRevoke != create+1 {
		t.Fatalf("the root token must be revoked by the request right after the child is made:\n%s", joined)
	}
	for i, line := range lines {
		if strings.HasSuffix(line, "token=root") && i > rootRevoke {
			t.Fatalf("the generated root token was used after it was revoked:\n%s", joined)
		}
		if strings.HasSuffix(line, "token=other") {
			t.Fatalf("a request carried a token the helper should not have:\n%s", joined)
		}
	}
	if g.cancelled != 0 {
		t.Fatalf("a completed generate-root attempt must not be cancelled, cancelled %d times", g.cancelled)
	}
	if fmt.Sprint(g.revoked) != fmt.Sprint([]string{g.rootToken, g.childToken}) {
		t.Fatalf("expected the root token and then the child token revoked")
	}

	update := findFakeBootstrapRequest(t, run.state.requests, http.MethodPut, "/v1/sys/generate-root/update")
	if update.Body["key"] != g.unsealKey || update.Body["nonce"] != g.nonce {
		t.Fatalf("generate-root update must send the typed key and the attempt's nonce")
	}
	create := findFakeBootstrapRequest(t, run.state.requests, http.MethodPost, "/v1/auth/token/create-orphan")
	if got := fmt.Sprint(create.Body["policies"]); got != "[root]" {
		t.Fatalf("expected policies [root], got %s", got)
	}
	for _, field := range []string{"ttl", "explicit_max_ttl"} {
		if got := create.Body[field]; got != "15m" {
			t.Fatalf("expected %s 15m, got %#v", field, got)
		}
	}
	if got := create.Body["renewable"]; got != false {
		t.Fatalf("expected renewable false, got %#v", got)
	}

	// The generated proof value goes to both proof paths and nowhere else.
	readPath := findFakeBootstrapRequest(t, run.state.requests, http.MethodPost, "/v1/proof-secrets/data/runtime-identity-vault-login")
	profile := findFakeBootstrapRequest(t, run.state.requests, http.MethodPost, "/v1/proof-secrets/data/codex-runtime-profile")
	readData, _ := readPath.Body["data"].(map[string]any)
	profileData, _ := profile.Body["data"].(map[string]any)
	proofValue, _ := profileData["api_key"].(string)
	if len(proofValue) < 32 || readData["message"] != proofValue {
		t.Fatalf("expected one generated proof value of at least 32 characters on both proof paths")
	}

	secrets := []string{g.unsealKey, g.rootToken, g.childToken, g.otp, g.nonce, proofValue}
	assertContainsNone(t, "unseal-key bootstrap output", run.output, secrets...)
	assertContainsAll(t, "unseal-key bootstrap output", run.output,
		"Vault unseal key (input hidden; not logged;",
		"The root token made from the unseal key was revoked at once; the short-lived token for this run is revoked too.",
		"Vault holds no root token that never expires.",
		"overall_status=pass",
	)
	assertContainsNone(t, "unseal-key bootstrap output", run.output, "Proof secret value", "WARNING")
	assertContainsNone(t, "fake spire log", readIfExists(run.spireLog), secrets...)

	summaryRaw := mustRead(t, run.summaryPath)
	assertContainsNone(t, "unseal-key bootstrap summary", summaryRaw, secrets...)
	assertBootstrapSummaryRedactionScanPasses(t, run.summaryPath, secrets...)
	summary := readJSONFile(t, run.summaryPath)
	if summary["overall_status"] != "pass" {
		t.Fatalf("expected pass, got %s", summaryRaw)
	}
	operations := summary["operations"].(map[string]any)
	for _, name := range []string{"bootstrap_choices", "generate_root_token", "short_lived_authority_token", "generated_root_token_revoke", "standing_root_tokens", "short_lived_authority_token_revoke"} {
		operation, ok := operations[name].(map[string]any)
		if !ok || operation["status"] != "pass" {
			t.Fatalf("expected operation %s pass, got %#v", name, operations[name])
		}
	}
	standing := operations["standing_root_tokens"].(map[string]any)
	if fmt.Sprintf("%v %v %v", standing["found"], standing["revoked"], standing["action"]) != "0 0 report" {
		t.Fatalf("expected no standing root token found and none revoked, got %#v", standing)
	}
	proofPrompt := operations["prompt_proof_secret"].(map[string]any)
	if proofPrompt["prompt_source"] != "generated" {
		t.Fatalf("expected the proof value to be recorded as generated, got %#v", proofPrompt)
	}
	assertContainsAll(t, "unseal-key bootstrap summary", summaryRaw,
		`"authority_source": "unseal-key"`,
		`"proof_value_source": "generate"`,
	)
}

func TestRemoteAlphaVaultWorkloadAuthBootstrapUnsealKeyAuthorityFailures(t *testing.T) {
	cases := []struct {
		name         string
		setup        func(g *fakeGenerateRoot)
		input        func(g *fakeGenerateRoot) string
		failPath     string
		phase        string
		failureClass string
		// requests that must and must not appear (method path token=who)
		want    []string
		notWant []string
		// cancelled is how often the generate-root attempt must be cancelled.
		cancelled int
		// beforePrompts: the case fails before the unseal key is asked for.
		beforePrompts bool
		revoked       func(g *fakeGenerateRoot) []string
		output        []string
	}{
		{
			name:          "attempt_already_running",
			setup:         func(g *fakeGenerateRoot) { g.alreadyStarted = true },
			beforePrompts: true,
			phase:         "generate_root_access_preflight",
			failureClass:  "generate_root_attempt_in_progress",
			want:          []string{"GET /v1/sys/generate-root/attempt token=none"},
			notWant:       []string{"PUT /v1/sys/generate-root/attempt token=none", "DELETE /v1/sys/generate-root/attempt token=none"},
		},
		{
			name:         "more_than_one_key_share",
			setup:        func(g *fakeGenerateRoot) { g.required = 2 },
			phase:        "generate_root_token",
			failureClass: "unsupported_key_threshold",
			want:         []string{"PUT /v1/sys/generate-root/attempt token=none", "DELETE /v1/sys/generate-root/attempt token=none"},
			notWant:      []string{"PUT /v1/sys/generate-root/update token=none"},
			cancelled:    1,
		},
		{
			name:         "wrong_unseal_key",
			input:        func(g *fakeGenerateRoot) string { return "notTheUnsealKeyButSomethingElse0123456789+/=\n" },
			phase:        "generate_root_token",
			failureClass: "vault_api_error",
			want:         []string{"PUT /v1/sys/generate-root/update token=none", "DELETE /v1/sys/generate-root/attempt token=none"},
			notWant:      []string{"POST /v1/auth/token/create-orphan token=root"},
			cancelled:    1,
		},
		{
			name:         "create_orphan_fails",
			setup:        func(g *fakeGenerateRoot) { g.failCreateOrphan = true },
			phase:        "short_lived_authority_token",
			failureClass: "vault_api_error",
			want:         []string{"POST /v1/auth/token/revoke-self token=root"},
			revoked:      func(g *fakeGenerateRoot) []string { return []string{g.rootToken} },
		},
		{
			name:         "create_orphan_and_root_revoke_fail",
			setup:        func(g *fakeGenerateRoot) { g.failCreateOrphan = true; g.failRevokeFor = g.rootToken },
			phase:        "generated_root_token_revoke",
			failureClass: "root_token_revoke_failed",
			want:         []string{"POST /v1/auth/token/revoke-self token=root"},
			output:       []string{"WARNING: the root token made from the unseal key could NOT be revoked"},
		},
		{
			name:         "root_revoke_fails",
			setup:        func(g *fakeGenerateRoot) { g.failRevokeFor = g.rootToken },
			phase:        "generated_root_token_revoke",
			failureClass: "root_token_revoke_failed",
			want:         []string{"POST /v1/auth/token/revoke-self token=root", "POST /v1/auth/token/revoke-self token=child"},
			revoked:      func(g *fakeGenerateRoot) []string { return []string{g.childToken} },
			output:       []string{"WARNING: the root token made from the unseal key could NOT be revoked"},
		},
		{
			// Pins the in-generate check: Vault reports an attempt only after
			// the preflight read.
			name:         "attempt_started_after_preflight",
			setup:        func(g *fakeGenerateRoot) { g.afterFirstStatus = func(g *fakeGenerateRoot) { g.alreadyStarted = true } },
			phase:        "generate_root_token",
			failureClass: "generate_root_attempt_in_progress",
			want:         []string{"GET /v1/sys/generate-root/attempt token=none"},
			notWant:      []string{"PUT /v1/sys/generate-root/attempt token=none", "DELETE /v1/sys/generate-root/attempt token=none"},
		},
		{
			name:         "standing_root_token_check_fails",
			setup:        func(g *fakeGenerateRoot) { g.failAccessorList = true },
			phase:        "standing_root_tokens",
			failureClass: "vault_api_error",
			want:         []string{"POST /v1/auth/token/revoke-self token=root", "LIST /v1/auth/token/accessors token=child", "POST /v1/auth/token/revoke-self token=child"},
			revoked:      func(g *fakeGenerateRoot) []string { return []string{g.rootToken, g.childToken} },
			output:       []string{"the short-lived token for this run is revoked too"},
		},
		{
			name:         "configuration_fails",
			failPath:     "/v1/sys/policies/acl/runtime-identity-proof",
			phase:        "runtime_identity_policy",
			failureClass: "vault_api_error",
			want:         []string{"POST /v1/auth/token/revoke-self token=root", "POST /v1/auth/token/revoke-self token=child"},
			revoked:      func(g *fakeGenerateRoot) []string { return []string{g.rootToken, g.childToken} },
			output:       []string{"the short-lived token for this run is revoked too"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newFakeGenerateRoot()
			if tc.setup != nil {
				tc.setup(g)
			}
			input := g.unsealKey + "\n"
			if tc.input != nil {
				input = tc.input(g)
			}
			run := runUnsealKeyBootstrap(t, g, tc.failPath, http.StatusInternalServerError, input)
			if run.err == nil {
				t.Fatalf("expected a failure:\n%s", run.output)
			}
			lines := fakeBootstrapRequestLines(run.state.requests, g)
			joined := strings.Join(lines, "\n")
			for _, want := range tc.want {
				if indexOfLine(lines, want) < 0 {
					t.Fatalf("missing request %q:\n%s", want, joined)
				}
			}
			for _, notWant := range tc.notWant {
				if indexOfLine(lines, notWant) >= 0 {
					t.Fatalf("unexpected request %q:\n%s", notWant, joined)
				}
			}
			if tc.phase != "runtime_identity_policy" {
				for _, line := range lines {
					if strings.Contains(line, "/v1/sys/auth") || strings.Contains(line, "/v1/proof-secrets/") {
						t.Fatalf("no configuration request may follow a failed authority step:\n%s", joined)
					}
				}
			}
			if g.cancelled != tc.cancelled {
				t.Fatalf("expected the generate-root attempt cancelled %d times, got %d", tc.cancelled, g.cancelled)
			}
			var wantRevoked []string
			if tc.revoked != nil {
				wantRevoked = tc.revoked(g)
			}
			if fmt.Sprint(g.revoked) != fmt.Sprint(wantRevoked) {
				t.Fatalf("revoked tokens differ from what the case expects (%d revoked, want %d)", len(g.revoked), len(wantRevoked))
			}
			secrets := []string{g.unsealKey, g.rootToken, g.childToken, g.otp, g.nonce, strings.TrimSpace(input)}
			assertContainsNone(t, "unseal-key failure output", run.output, secrets...)
			assertContainsAll(t, "unseal-key failure output", run.output,
				"overall_status=fail",
				"failure_phase="+tc.phase+" failure_class="+tc.failureClass,
			)
			assertContainsAll(t, "unseal-key failure output", run.output, tc.output...)
			if tc.beforePrompts {
				assertContainsNone(t, "unseal-key failure output", run.output, "Vault unseal key")
			}
			assertBootstrapFailureSummary(t, run.summaryPath, tc.phase, tc.failureClass, !tc.beforePrompts, true, secrets...)
		})
	}
}

func TestRemoteAlphaVaultWorkloadAuthBootstrapRejectsInvalidChoicesBeforePromptsAndVaultWrites(t *testing.T) {
	cases := []struct {
		name         string
		env          string
		messageClass string
	}{
		{name: "authority", env: "REMOTE_ALPHA_BOOTSTRAP_AUTHORITY=root", messageClass: "authority_not_root_token_or_unseal_key"},
		{name: "authority_partial", env: "REMOTE_ALPHA_BOOTSTRAP_AUTHORITY=unseal", messageClass: "authority_not_root_token_or_unseal_key"},
		{name: "proof_value", env: "REMOTE_ALPHA_BOOTSTRAP_PROOF_VALUE=random", messageClass: "proof_value_not_prompt_or_generate"},
		{name: "standing_root_tokens", env: "REMOTE_ALPHA_BOOTSTRAP_STANDING_ROOT_TOKENS=delete", messageClass: "standing_root_tokens_not_report_or_revoke"},
		{name: "standing_root_tokens_revoke_needs_unseal_key", env: "REMOTE_ALPHA_BOOTSTRAP_STANDING_ROOT_TOKENS=revoke REMOTE_ALPHA_BOOTSTRAP_AUTHORITY=root-token", messageClass: "standing_root_tokens_revoke_needs_unseal_key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newFakeGenerateRoot()
			run := runUnsealKeyBootstrap(t, g, "", 0, g.unsealKey+"\n", strings.Fields(tc.env)...)
			if run.err == nil {
				t.Fatalf("expected an invalid choice to fail:\n%s", run.output)
			}
			if len(run.state.requests) != 0 {
				t.Fatalf("an invalid choice must fail before any Vault request, got %d", len(run.state.requests))
			}
			assertContainsNone(t, "invalid choice output", run.output, "Vault unseal key", "Vault bootstrap authority token", "Proof secret value")
			summary := assertBootstrapFailureSummary(t, run.summaryPath, "bootstrap_choices", "config_invalid", false, false)
			if got := summary["failure_message_class"]; got != tc.messageClass {
				t.Fatalf("expected failure_message_class %s, got %#v", tc.messageClass, got)
			}
		})
	}
}

// temporaryAccessFixture is a Vault configuration file and a fake reload
// command. The reload copies the file to the path that the fake Vault reads
// as its loaded configuration, like Vault reading its file on SIGHUP.
type temporaryAccessFixture struct {
	configPath string
	loadedPath string
	countPath  string
	sigBlkPath string
	original   []byte
	mode       os.FileMode
}

func newTemporaryAccessFixture(t *testing.T, content string, reloadMode string) (temporaryAccessFixture, []string) {
	t.Helper()
	dir := t.TempDir()
	f := temporaryAccessFixture{
		configPath: filepath.Join(dir, "vault.d", "vault.hcl"),
		loadedPath: filepath.Join(dir, "loaded.hcl"),
		countPath:  filepath.Join(dir, "reload-count"),
		sigBlkPath: filepath.Join(dir, "helper-sigblk"),
		original:   []byte(content),
		mode:       0o640,
	}
	if err := os.MkdirAll(filepath.Dir(f.configPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(f.configPath, f.original, f.mode); err != nil {
		t.Fatalf("write vault config: %v", err)
	}
	if err := os.Chmod(f.configPath, f.mode); err != nil {
		t.Fatalf("chmod vault config: %v", err)
	}
	if err := os.WriteFile(f.loadedPath, f.original, 0o600); err != nil {
		t.Fatalf("write loaded config: %v", err)
	}
	reload := filepath.Join(dir, "fake-reload")
	// Each reload also records the signals its parent, the helper, holds
	// blocked (Linux only).
	script := fmt.Sprintf(`#!/bin/sh
n=$(cat %[1]q 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > %[1]q
[ -r "/proc/$PPID/status" ] && sed -n 's/^SigBlk:[[:space:]]*//p' "/proc/$PPID/status" >> %[5]q
case %[2]q in
  fail) exit 1 ;;
  noeffect) exit 0 ;;
  fail-second) [ "$n" -ge 2 ] && exit 1 ;;
  noeffect-second) [ "$n" -ge 2 ] && exit 0 ;;
esac
cp %[3]q %[4]q
`, f.countPath, reloadMode, f.configPath, f.loadedPath, f.sigBlkPath)
	if err := os.WriteFile(reload, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake reload: %v", err)
	}
	return f, []string{
		"REMOTE_ALPHA_BOOTSTRAP_VAULT_CONFIG_PATH=" + f.configPath,
		"REMOTE_ALPHA_BOOTSTRAP_VAULT_RELOAD_COMMAND=" + reload + " vault.service",
	}
}

// assertSignalsHeldDuringReloads checks that during both reloads the helper
// held blocked the signals it defers (INT, TERM, HUP, QUIT) and the
// terminal's stop signals (TSTP, TTIN, TTOU), so that neither Ctrl-C nor
// Ctrl-Z can end or freeze it while generate-root is open.
func (f temporaryAccessFixture) assertSignalsHeldDuringReloads(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/proc/self/status"); err != nil {
		return
	}
	lines := strings.Fields(readIfExists(f.sigBlkPath))
	if len(lines) != 2 {
		t.Fatalf("expected the helper's blocked signals from both reloads, got %q", lines)
	}
	for _, line := range lines {
		mask, err := strconv.ParseUint(line, 16, 64)
		if err != nil {
			t.Fatalf("parse SigBlk %q: %v", line, err)
		}
		for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU} {
			if mask&(1<<(uint(sig)-1)) == 0 {
				t.Fatalf("the helper must hold %v blocked during the reload, SigBlk=%s", sig, line)
			}
		}
	}
}

func (f temporaryAccessFixture) reloads(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(f.countPath)
	if err != nil {
		return "0"
	}
	return strings.TrimSpace(string(data))
}

func (f temporaryAccessFixture) assertUnchanged(t *testing.T) {
	t.Helper()
	data, err := os.ReadFile(f.configPath)
	if err != nil {
		t.Fatalf("read vault config: %v", err)
	}
	if string(data) != string(f.original) {
		t.Fatalf("Vault's configuration file must be back byte for byte, got:\n%s", data)
	}
	info, err := os.Lstat(f.configPath)
	if err != nil {
		t.Fatalf("stat vault config: %v", err)
	}
	if info.Mode() != f.mode {
		t.Fatalf("Vault's configuration file mode must stay %v, got %v", f.mode, info.Mode())
	}
	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(f.configPath), ".*.tmp"))
	if len(leftovers) != 0 {
		t.Fatalf("temporary files left beside Vault's configuration: %v", leftovers)
	}
}

func TestRemoteAlphaVaultWorkloadAuthBootstrapTemporaryGenerateRootAccess(t *testing.T) {
	const original = "ui = false\nlistener \"tcp\" {\n  address = \"172.17.0.1:8200\"\n}\n"
	t.Run("enables_generates_revokes_the_root_token_then_restores", func(t *testing.T) {
		g := newFakeGenerateRoot()
		f, env := newTemporaryAccessFixture(t, original, "ok")
		g.refuseUnauthenticated, g.loadedConfigPath = true, f.loadedPath
		run := runUnsealKeyBootstrap(t, g, "", 0, g.unsealKey+"\n", append(env, "REMOTE_ALPHA_BOOTSTRAP_GENERATE_ROOT_ACCESS=temporary-config")...)
		if run.err != nil {
			t.Fatalf("temporary-config run failed: %v\n%s\nsummary=%s", run.err, run.output, readIfExists(run.summaryPath))
		}
		f.assertUnchanged(t)
		if got := f.reloads(t); got != "2" {
			t.Fatalf("expected two reloads (enable and restore), got %s", got)
		}
		// The root token never expires, so it is revoked before the slow
		// restore (reload and wait); configuration starts only once Vault
		// refuses generate-root without a token again.
		if !g.openAtCreateOrphan || !g.openAtRootRevoke {
			t.Fatalf("the root token must be used and revoked before Vault's configuration is put back")
		}
		if g.openAtConfiguration {
			t.Fatalf("unauthenticated generate-root must be closed again before any configuration request")
		}
		if fmt.Sprint(g.revoked) != fmt.Sprint([]string{g.rootToken, g.childToken}) {
			t.Fatalf("expected the root token and then the child token revoked")
		}
		f.assertSignalsHeldDuringReloads(t)
		assertContainsAll(t, "temporary-config output", run.output,
			"Vault's configuration file is back byte for byte, and Vault again refuses generate-root without a token.",
			"overall_status=pass",
		)
		summary := readJSONFile(t, run.summaryPath)
		operations := summary["operations"].(map[string]any)
		for _, name := range []string{"vault_config_preflight", "generate_root_access_enable", "generate_root_access_restore", "generate_root_token"} {
			operation, ok := operations[name].(map[string]any)
			if !ok || operation["status"] != "pass" {
				t.Fatalf("expected %s pass, got %#v", name, operations[name])
			}
		}
		restore := operations["generate_root_access_restore"].(map[string]any)
		for _, field := range []string{"file_restored_byte_for_byte", "vault_reloaded", "vault_refuses_generate_root_without_token_again"} {
			if restore[field] != true {
				t.Fatalf("expected restore %s true, got %#v", field, restore)
			}
		}
		probe := operations["generate_root_access_probe"].(map[string]any)
		if probe["vault_allows_generate_root_without_token"] != false {
			t.Fatalf("expected the probe to record that Vault refused, got %#v", probe)
		}
	})

	failures := []struct {
		name         string
		content      string
		reloadMode   string
		access       string
		authority    string
		phase        string
		failureClass string
		prompts      bool
		vaultOps     bool
		reloads      string
		warning      bool
		revoked      func(g *fakeGenerateRoot) []string
		// loadedExtra is appended to the configuration Vault has loaded
		// (not to the file), for a Vault that allows generate-root in
		// memory only; afterFirstStatus does it after the preflight read.
		loadedExtra      string
		afterFirstStatus bool
		output           string
	}{
		{name: "as_configured_refused", content: original, reloadMode: "ok", access: "as-configured", phase: "generate_root_access_preflight", failureClass: "generate_root_unauthenticated_access_disabled", vaultOps: true, reloads: "0"},
		{name: "config_already_mentions_the_setting", content: original + "enable_unauthenticated_access = [\"rekey\"]\n", reloadMode: "ok", access: "temporary-config", phase: "vault_config_preflight", failureClass: "config_invalid", reloads: "0"},
		{name: "needs_unseal_key_authority", content: original, reloadMode: "ok", access: "temporary-config", authority: "root-token", phase: "bootstrap_choices", failureClass: "config_invalid", reloads: "0"},
		{name: "reload_fails", content: original, reloadMode: "fail", access: "temporary-config", phase: "generate_root_access_enable", failureClass: "vault_reload_failed", prompts: true, vaultOps: true, reloads: "2", warning: true},
		{name: "reload_has_no_effect", content: original, reloadMode: "noeffect", access: "temporary-config", phase: "generate_root_access_enable", failureClass: "generate_root_access_not_enabled", prompts: true, vaultOps: true, reloads: "2"},
		{name: "restore_reload_fails", content: original, reloadMode: "fail-second", access: "temporary-config", phase: "generate_root_access_restore", failureClass: "vault_config_restore_failed", prompts: true, vaultOps: true, reloads: "2", warning: true, revoked: func(g *fakeGenerateRoot) []string { return []string{g.rootToken, g.childToken} }},
		{name: "no_final_newline", content: "ui = false", reloadMode: "fail-second", access: "temporary-config", phase: "generate_root_access_restore", failureClass: "vault_config_restore_failed", prompts: true, vaultOps: true, reloads: "2", warning: true, revoked: func(g *fakeGenerateRoot) []string { return []string{g.rootToken, g.childToken} }},
		// The restore reload succeeds but Vault keeps answering: the wait
		// for the refusal must notice.
		{name: "restore_reload_has_no_effect", content: original, reloadMode: "noeffect-second", access: "temporary-config", phase: "generate_root_access_restore", failureClass: "vault_config_restore_failed", prompts: true, vaultOps: true, reloads: "2", warning: true, revoked: func(g *fakeGenerateRoot) []string { return []string{g.rootToken, g.childToken} }},
		// What a run killed during the restore leaves: the file is clean but
		// Vault still answers generate-root without a token.
		{name: "vault_open_but_file_clean", content: original, reloadMode: "ok", access: "temporary-config", phase: "generate_root_access_preflight", failureClass: "generate_root_access_open_outside_config_file", vaultOps: true, reloads: "0", loadedExtra: "enable_unauthenticated_access = [\"generate-root\"]\n", output: "Reload Vault ("},
		{name: "vault_opens_after_preflight", content: original, reloadMode: "ok", access: "temporary-config", phase: "generate_root_token", failureClass: "generate_root_access_open_outside_config_file", prompts: true, vaultOps: true, reloads: "0", loadedExtra: "enable_unauthenticated_access = [\"generate-root\"]\n", afterFirstStatus: true, output: "Reload Vault ("},
	}
	for _, tc := range failures {
		t.Run(tc.name, func(t *testing.T) {
			g := newFakeGenerateRoot()
			f, env := newTemporaryAccessFixture(t, tc.content, tc.reloadMode)
			g.refuseUnauthenticated, g.loadedConfigPath = true, f.loadedPath
			if tc.loadedExtra != "" {
				openInMemory := func(*fakeGenerateRoot) {
					if err := os.WriteFile(f.loadedPath, append(append([]byte{}, f.original...), tc.loadedExtra...), 0o600); err != nil {
						t.Errorf("write loaded config: %v", err)
					}
				}
				if tc.afterFirstStatus {
					g.afterFirstStatus = openInMemory
				} else {
					openInMemory(g)
				}
			}
			env = append(env, "REMOTE_ALPHA_BOOTSTRAP_GENERATE_ROOT_ACCESS="+tc.access)
			if tc.authority != "" {
				env = append(env, "REMOTE_ALPHA_BOOTSTRAP_AUTHORITY="+tc.authority)
			}
			run := runUnsealKeyBootstrap(t, g, "", 0, g.unsealKey+"\n", env...)
			if run.err == nil {
				t.Fatalf("expected a failure:\n%s", run.output)
			}
			f.assertUnchanged(t)
			if got := f.reloads(t); got != tc.reloads {
				t.Fatalf("expected %s reloads, got %s", tc.reloads, got)
			}
			for _, line := range fakeBootstrapRequestLines(run.state.requests, g) {
				if line == "POST /v1/auth/token/revoke-self token=child" {
					continue
				}
				if strings.Contains(line, "token=child") || strings.Contains(line, "/v1/proof-secrets/") {
					t.Fatalf("no configuration may follow a failed generate-root access step:\n%s", line)
				}
			}
			var wantRevoked []string
			if tc.revoked != nil {
				wantRevoked = tc.revoked(g)
			}
			if fmt.Sprint(g.revoked) != fmt.Sprint(wantRevoked) {
				t.Fatalf("revoked tokens differ from what the case expects (%d revoked, want %d)", len(g.revoked), len(wantRevoked))
			}
			if g.started {
				t.Fatalf("a generate-root attempt was left open")
			}
			if tc.warning {
				assertContainsAll(t, "output", run.output, "WARNING: Vault's configuration file "+f.configPath+" may still hold the line")
			} else {
				assertContainsNone(t, "output", run.output, "WARNING")
			}
			if tc.output != "" {
				assertContainsAll(t, "output", run.output, tc.output)
			}
			secrets := []string{g.unsealKey, g.rootToken, g.childToken, g.otp, g.nonce}
			assertContainsNone(t, "output", run.output, secrets...)
			assertBootstrapFailureSummary(t, run.summaryPath, tc.phase, tc.failureClass, tc.prompts, tc.vaultOps, secrets...)
		})
	}
}

func TestRemoteAlphaVaultWorkloadAuthBootstrapStandingRootTokens(t *testing.T) {
	others := func() map[string]fakeVaultTokenInfo {
		return map[string]fakeVaultTokenInfo{
			"fakeStandingRootAccessor0001": {policies: []string{"root"}},
			"fakePeriodicRootAccessor0001": {policies: []string{"root"}, expireTime: "2026-11-23T21:00:00Z", period: 3600},
			"fakeExpiringRootAccessor0001": {policies: []string{"root"}, expireTime: "2026-11-23T20:30:00Z"},
			"fakeWorkloadTokenAccessor001": {policies: []string{"default", "runtime-identity-proof"}},
		}
	}
	accessors := []string{"fakeStandingRootAccessor0001", "fakePeriodicRootAccessor0001", "fakeExpiringRootAccessor0001", "fakeWorkloadTokenAccessor001", "fakeVanishedTokenAccessor001", fakeChildAccessor}
	cases := []struct {
		name        string
		env         []string
		wantRevoked []string
		wantOutput  string
		notOutput   string
		wantCounts  string
	}{
		{name: "report", wantOutput: "WARNING: Vault holds 2 root token(s) that never expire.", notOutput: "Revoked ", wantCounts: "2 0 report"},
		{
			name:        "revoke",
			env:         []string{"REMOTE_ALPHA_BOOTSTRAP_STANDING_ROOT_TOKENS=revoke"},
			wantRevoked: []string{"fakePeriodicRootAccessor0001", "fakeStandingRootAccessor0001"},
			wantOutput:  "Revoked 2 root token(s) that never expired, as REMOTE_ALPHA_BOOTSTRAP_STANDING_ROOT_TOKENS=revoke asked.",
			notOutput:   "WARNING",
			wantCounts:  "2 2 revoke",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newFakeGenerateRoot()
			g.otherTokens = others()
			g.listVanished = true
			run := runUnsealKeyBootstrap(t, g, "", 0, g.unsealKey+"\n", tc.env...)
			if run.err != nil {
				t.Fatalf("run failed: %v\n%s\nsummary=%s", run.err, run.output, readIfExists(run.summaryPath))
			}
			if fmt.Sprint(g.revokedAccessors) != fmt.Sprint(tc.wantRevoked) {
				t.Fatalf("revoked accessors %v, want %v", g.revokedAccessors, tc.wantRevoked)
			}
			lines := fakeBootstrapRequestLines(run.state.requests, g)
			joined := strings.Join(lines, "\n")
			lastCheck := -1
			for i, line := range lines {
				if strings.Contains(line, "/v1/auth/token/lookup-accessor") || strings.Contains(line, "/v1/auth/token/revoke-accessor") {
					lastCheck = i
				}
			}
			if config := indexOfLine(lines, "GET /v1/sys/auth token=child"); lastCheck < 0 || config < lastCheck {
				t.Fatalf("the standing root token check must finish before configuration:\n%s", joined)
			}
			assertContainsAll(t, "output", run.output, tc.wantOutput, "overall_status=pass")
			assertContainsNone(t, "output", run.output, tc.notOutput)
			summaryRaw := mustRead(t, run.summaryPath)
			assertContainsNone(t, "output", run.output, accessors...)
			assertContainsNone(t, "summary", summaryRaw, accessors...)
			standing := readJSONFile(t, run.summaryPath)["operations"].(map[string]any)["standing_root_tokens"].(map[string]any)
			if got := fmt.Sprintf("%v %v %v", standing["found"], standing["revoked"], standing["action"]); got != tc.wantCounts {
				t.Fatalf("expected found, revoked, action %q, got %q", tc.wantCounts, got)
			}
		})
	}
}

// TestRemoteAlphaVaultWorkloadAuthBootstrapP0qR1Docs pins the documented
// P0q-R1 refinement (PLANS.md slice and the system-overview subsection) to
// the behaviour the tests above check.
func TestRemoteAlphaVaultWorkloadAuthBootstrapP0qR1Docs(t *testing.T) {
	plans := compactDocSection(t, mustRead(t, "PLANS.md"), "## Current Remote Alpha Host Network Boundary Slice", "## Future ES Privilege-Boundary Design Track")
	assertContainsAll(t, "PLANS.md P0q-R1 slice", plans,
		"the same tranche refines the P0q workload-auth bootstrap helper (INF-04, INF-05, and the root-token half of INF-06)",
		"`enable_unauthenticated_access = [\"generate-root\"]`",
		"one key share; CI installs Vault 2.2.2",
		"SIGINT, SIGTERM, SIGHUP and SIGQUIT wait until the root token is revoked and Vault's configuration is back, and Ctrl-Z (SIGTSTP, SIGTTIN, SIGTTOU) takes effect only then; core dumps are off before anything is read;",
		"`REMOTE_ALPHA_BOOTSTRAP_STANDING_ROOT_TOKENS=revoke` revokes them",
	)
	section := compactDocSection(t, mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"), "#### P0q-R1 Bootstrap Token Limits, Proof History And Unseal-Key Authority", "### Historical P0r Mac-Side Runtime Identity Summary — Superseded and Non-Authoritative")
	assertContainsAll(t, "P0q-R1 docs subsection", section,
		"`REMOTE_ALPHA_BOOTSTRAP_TOKEN_TTL` (default `15m`)",
		"`REMOTE_ALPHA_BOOTSTRAP_TOKEN_MAX_TTL` (default `30m`)",
		"`REMOTE_ALPHA_BOOTSTRAP_TOKEN_BOUND_CIDRS` (default `172.17.0.0/16`",
		"otherwise it fails at phase `role_token_limits` with `config_invalid`",
		"The box's own workload-auth check connects from the bridge address only while the host firewall's `host_to_vault_source` chain is loaded",
		"`proof_path_history=all_earlier_versions_and_metadata_deleted_before_write`",
		"`REMOTE_ALPHA_BOOTSTRAP_PROOF_VALUE=generate` writes a random value made in helper memory to both proof paths and never shows it",
		"`REMOTE_ALPHA_BOOTSTRAP_AUTHORITY=unseal-key` prompts for the single unseal key share instead.",
		"requires a threshold of exactly one share",
		"`ttl` and `explicit_max_ttl` `15m` and `renewable=false`, then revokes the root token with `auth/token/revoke-self` as the very next request, before Vault's configuration is put back",
		"SIGINT, SIGTERM, SIGHUP and SIGQUIT are blocked",
		"before it reads anything, the helper turns core dumps off (`RLIMIT_CORE` 0, which the commands it starts inherit, and `PR_SET_DUMPABLE` 0 through `prctl`, which also stops a `core_pattern` pipe such as systemd-coredump), and it stops (phase `disable_core_dumps`) if either does not hold.",
		"It reads both back and does not look at the operating system's name: on a host without `prctl`, such as macOS, it stops there with `core_dumps_not_disabled` (message class `process_still_dumpable`), and there is no fallback.",
		"The terminal's stop signals (SIGTSTP from Ctrl-Z, SIGTTIN, SIGTTOU) are held over the same section, so the run stops only after it; SIGSTOP cannot be held",
		"the exit code is 128 plus the signal number",
		"SIGKILL and a power loss cannot be deferred.",
		"`generate_root_access_open_outside_config_file`",
		"operation `standing_root_tokens`, before any configuration request.",
		"`REMOTE_ALPHA_BOOTSTRAP_STANDING_ROOT_TOKENS=revoke` (unseal-key only) revokes them with `auth/token/revoke-accessor`",
		"The summary records counts, never accessors",
		"a generate-root attempt that someone else started is refused, not cancelled",
		"`root_token_revoke_failed`",
		"phase `generate_root_access_preflight`",
		"`generate_root_unauthenticated_access_disabled`",
		"once the 15-minute token is made and the root token is revoked, it writes the original bytes back with the same owner and mode, reloads again, and waits until Vault refuses again, all before any configuration request.",
		"`vault_config_restore_failed`",
		"one test runs the helper against a real local Vault server (not dev mode; raft, TLS, one key share).",
		"A second real-Vault test sends SIGINT, SIGTERM, SIGHUP and SIGQUIT from inside the enable and the restore reload",
	)
}
