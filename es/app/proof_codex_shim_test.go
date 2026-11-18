package app_test

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
)

func TestProofCodexShimAcquiresCredentialAndMutatesWorkspace(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skipf("proof Codex shim test requires python3: %v", err)
	}

	repoRoot := executionPlatformRepoRoot(t)
	shimPath := filepath.Join(repoRoot, "es", "runtimeprofiles", "control_plane_normal_shell", "proof-codex-shim.py")
	if _, err := os.Stat(shimPath); err != nil {
		t.Fatalf("stat proof Codex shim: %v", err)
	}

	versionOutput, err := exec.Command("python3", shimPath, "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("run proof Codex shim --version: %v output=%s", err, string(versionOutput))
	}
	if !strings.Contains(string(versionOutput), "supported-local-proof-codex-shim/v1") {
		t.Fatalf("unexpected proof Codex shim version output: %s", string(versionOutput))
	}

	workspace := t.TempDir()
	socketFixture := newProofUnixSocketFixture(t)
	identityEndpoint := startProofIdentityEndpoint(t, socketFixture.socketPath)
	vaultServer, loginRequests, secretReads := startProofCodexVaultServer(t)
	defer vaultServer.Close()
	vaultCAPEMPath := filepath.Join(t.TempDir(), "vault-ca.pem")
	if err := os.WriteFile(vaultCAPEMPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: vaultServer.Certificate().Raw}), 0o600); err != nil {
		t.Fatalf("write Vault CA bundle: %v", err)
	}

	prompt := "Apply the Execution Substrate supported-local normal-shell proof mutation.\n"
	finalPath := filepath.Join(workspace, "final-message.txt")
	command := exec.Command("python3", shimPath, "exec", "--cwd", workspace, "--output-last-message", finalPath, "-")
	command.Stdin = strings.NewReader(prompt)
	command.Env = append(os.Environ(),
		"EXEC_CODEX_CREDENTIAL_SOURCE=workload_vault",
		"EXEC_CODEX_CREDENTIAL_VAULT_SECRET_PATH=proof-secrets/data/codex-runtime-profile",
		"EXEC_CODEX_CREDENTIAL_VAULT_SECRET_FIELD=api_key",
		"EXEC_WORKLOAD_IDENTITY_ENDPOINT=unix://"+socketFixture.socketPath,
		"EXEC_WORKLOAD_VAULT_AUTH_MOUNT=jwt",
		"EXEC_WORKLOAD_VAULT_AUTH_ROLE=service_execution",
		"VAULT_ADDR="+vaultServer.URL,
		"VAULT_CACERT="+vaultCAPEMPath,
		"SSL_CERT_FILE="+vaultCAPEMPath,
	)

	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("run proof Codex shim: %v output=%s", err, string(output))
	}
	if !strings.Contains(string(output), "CODEX-PROOF-SHIM-START") {
		t.Fatalf("expected proof start marker, got output=%s", string(output))
	}
	if !strings.Contains(string(output), "ES control-plane normal-shell proof completed") {
		t.Fatalf("expected final proof marker, got output=%s", string(output))
	}

	mutationPath := filepath.Join(workspace, ".codex-proof", "normal-shell-proof.txt")
	mutationBytes, err := os.ReadFile(mutationPath)
	if err != nil {
		t.Fatalf("read workspace mutation: %v", err)
	}
	if !strings.Contains(string(mutationBytes), "ES_CONTROL_PLANE_NORMAL_SHELL_PROOF") {
		t.Fatalf("expected workspace mutation marker, got %s", string(mutationBytes))
	}

	reportBytes, err := os.ReadFile(filepath.Join(workspace, ".codex-proof", "codex-proof-result.json"))
	if err != nil {
		t.Fatalf("read proof report: %v", err)
	}
	var report map[string]any
	if err := json.Unmarshal(reportBytes, &report); err != nil {
		t.Fatalf("decode proof report: %v body=%s", err, string(reportBytes))
	}
	if report["realization"] != "supported-local-proof-codex-shim/v1" {
		t.Fatalf("unexpected proof realization: %+v", report)
	}
	if report["credential_material_present"] != true {
		t.Fatalf("expected credential material presence in report: %+v", report)
	}
	if got := strings.TrimSpace(fmt.Sprint(report["prompt_sha256"])); got != fmt.Sprintf("%x", sha256.Sum256([]byte(prompt))) {
		t.Fatalf("unexpected prompt digest %q report=%+v", got, report)
	}

	finalBytes, err := os.ReadFile(finalPath)
	if err != nil {
		t.Fatalf("read final message: %v", err)
	}
	if !strings.Contains(string(finalBytes), "ES control-plane normal-shell proof completed") {
		t.Fatalf("unexpected final message: %s", string(finalBytes))
	}
	if got := atomic.LoadInt32(&identityEndpoint.requests); got != 1 {
		t.Fatalf("expected one identity request, got %d", got)
	}
	if got := atomic.LoadInt32(loginRequests); got != 1 {
		t.Fatalf("expected one Vault login, got %d", got)
	}
	if got := atomic.LoadInt32(secretReads); got != 1 {
		t.Fatalf("expected one Vault secret read, got %d", got)
	}
}

func TestProofCodexShimShortUnixSocketFixtureBindsUsesClosesAndCleansUpDespiteLongCallerTempContext(t *testing.T) {
	longCallerContext := t.TempDir()
	for range 12 {
		longCallerContext = filepath.Join(longCallerContext, "long-caller-temp-context")
	}
	if err := os.MkdirAll(longCallerContext, 0o700); err != nil {
		t.Fatalf("create long caller temp context: %v", err)
	}

	fixture := newProofUnixSocketFixture(t)
	if fixture.dir == longCallerContext || strings.HasPrefix(fixture.dir, longCallerContext+string(filepath.Separator)) {
		t.Fatalf("short socket fixture %q depends on caller temp context %q", fixture.dir, longCallerContext)
	}
	endpoint := startProofIdentityEndpoint(t, fixture.socketPath)

	connection, err := net.Dial("unix", fixture.socketPath)
	if err != nil {
		t.Fatalf("dial short proof identity endpoint: %v", err)
	}
	if _, err := io.WriteString(connection, `{"kind":"jwt_svid","target":"workload_vault"}`+"\n"); err != nil {
		_ = connection.Close()
		t.Fatalf("write short proof identity request: %v", err)
	}
	response, err := bufio.NewReader(connection).ReadString('\n')
	if closeErr := connection.Close(); err == nil && closeErr != nil {
		err = closeErr
	}
	if err != nil {
		t.Fatalf("read and close short proof identity response: %v", err)
	}
	var payload map[string]string
	if err := json.Unmarshal([]byte(strings.TrimSpace(response)), &payload); err != nil {
		t.Fatalf("decode short proof identity response: %v body=%q", err, response)
	}
	if payload["jwt"] != "proof.jwt.value" {
		t.Fatalf("short proof identity response = %v, want synthetic JWT", payload)
	}
	if got := atomic.LoadInt32(&endpoint.requests); got != 1 {
		t.Fatalf("short proof identity request count = %d, want 1", got)
	}

	endpoint.close(t)
	fixture.cleanup(t)
	if _, err := os.Lstat(fixture.dir); !os.IsNotExist(err) {
		t.Fatalf("short socket fixture directory remains after cleanup: %q err=%v", fixture.dir, err)
	}
	if info, err := os.Lstat(longCallerContext); err != nil || !info.IsDir() {
		t.Fatalf("socket fixture cleanup changed caller temp context: info=%v err=%v", info, err)
	}
}

func TestControlPlaneNormalShellEntrypointWorkspaceDiffIncludesUntrackedProofMutation(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skipf("control-plane normal-shell entrypoint test requires python3: %v", err)
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("control-plane normal-shell entrypoint test requires git: %v", err)
	}

	repoRoot := executionPlatformRepoRoot(t)
	entrypointPath := filepath.Join(repoRoot, ".examples", "control_plane_normal_shell_runtime", "entrypoint")
	if _, err := os.Stat(entrypointPath); err != nil {
		t.Fatalf("stat control-plane normal-shell entrypoint: %v", err)
	}

	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "README.md"), []byte("baseline\n"), 0o600); err != nil {
		t.Fatalf("write baseline file: %v", err)
	}
	runGit := func(args ...string) {
		t.Helper()
		command := exec.Command("git", args...)
		command.Dir = workspace
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("git %s: %v output=%s", strings.Join(args, " "), err, string(output))
		}
	}
	runGit("init")
	runGit("config", "user.email", "proof@example.invalid")
	runGit("config", "user.name", "Execution Substrate Proof")
	runGit("add", ".")
	runGit("commit", "-m", "baseline")

	proofDir := filepath.Join(workspace, ".codex-proof")
	if err := os.MkdirAll(proofDir, 0o700); err != nil {
		t.Fatalf("create proof dir: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(proofDir, "normal-shell-proof.txt"),
		[]byte("ES_CONTROL_PLANE_NORMAL_SHELL_PROOF\n"),
		0o600,
	); err != nil {
		t.Fatalf("write untracked proof mutation: %v", err)
	}

	snippet := `
import importlib.machinery
import importlib.util
import pathlib
import sys

loader = importlib.machinery.SourceFileLoader("cp_normal_shell_entrypoint", sys.argv[1])
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)
sys.stdout.write(module.workspace_diff(pathlib.Path(sys.argv[2])))
`
	command := exec.Command("python3", "-c", snippet, entrypointPath, workspace)
	command.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("render workspace diff: %v output=%s", err, string(output))
	}
	if !strings.Contains(string(output), "ES_CONTROL_PLANE_NORMAL_SHELL_PROOF") {
		t.Fatalf("expected untracked proof mutation in workspace diff, got %s", string(output))
	}
}

type proofUnixSocketFixture struct {
	dir        string
	socketPath string
	identity   os.FileInfo
	cleaned    bool
}

func newProofUnixSocketFixture(t *testing.T) *proofUnixSocketFixture {
	t.Helper()

	allocated, err := os.MkdirTemp("/tmp", "espc-")
	if err != nil {
		t.Fatalf("create short proof Unix-socket directory: %v", err)
	}
	allocatedInfo, err := os.Lstat(allocated)
	if err != nil {
		_ = os.Remove(allocated)
		t.Fatalf("lstat short proof Unix-socket directory: %v", err)
	}
	fixture := &proofUnixSocketFixture{dir: allocated, identity: allocatedInfo}
	t.Cleanup(func() { fixture.cleanup(t) })

	if err := os.Chmod(allocated, 0o700); err != nil {
		t.Fatalf("set short proof Unix-socket directory mode: %v", err)
	}
	physical, err := filepath.EvalSymlinks(allocated)
	if err != nil {
		t.Fatalf("resolve short proof Unix-socket directory: %v", err)
	}
	physicalTmp, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		t.Fatalf("resolve proof Unix-socket scratch parent: %v", err)
	}
	if !filepath.IsAbs(physical) || filepath.Dir(physical) != physicalTmp {
		t.Fatalf("short proof Unix-socket directory %q is not directly beneath physical /tmp %q", physical, physicalTmp)
	}
	resolvedAgain, err := filepath.EvalSymlinks(physical)
	if err != nil || resolvedAgain != physical {
		t.Fatalf("short proof Unix-socket directory is not a physical presentation: resolved=%q err=%v", resolvedAgain, err)
	}
	logicalInfo, err := os.Stat(allocated)
	if err != nil {
		t.Fatalf("stat allocated short proof Unix-socket directory: %v", err)
	}
	physicalInfo, err := os.Lstat(physical)
	if err != nil {
		t.Fatalf("lstat physical short proof Unix-socket directory: %v", err)
	}
	if physicalInfo.Mode()&os.ModeSymlink != 0 || !physicalInfo.IsDir() || !os.SameFile(logicalInfo, physicalInfo) {
		t.Fatalf("short proof Unix-socket path does not identify its real allocated directory: logical=%v physical=%v", logicalInfo.Mode(), physicalInfo.Mode())
	}
	if physicalInfo.Mode().Perm() != 0o700 {
		t.Fatalf("short proof Unix-socket directory mode = %04o, want 0700", physicalInfo.Mode().Perm())
	}
	uid, gid, ok := proofUnixSocketOwner(physicalInfo)
	if !ok {
		t.Fatalf("short proof Unix-socket directory has no Unix ownership metadata")
	}
	if uid != uint32(os.Getuid()) {
		t.Fatalf("short proof Unix-socket directory owner UID = %d, want current test owner UID %d (group GID %d)", uid, os.Getuid(), gid)
	}

	fixture.dir = physical
	fixture.socketPath = filepath.Join(physical, "i.sock")
	fixture.identity = physicalInfo
	return fixture
}

func proofUnixSocketOwner(info os.FileInfo) (uint32, uint32, bool) {
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return metadata.Uid, metadata.Gid, true
}

func (fixture *proofUnixSocketFixture) cleanup(t *testing.T) {
	t.Helper()
	if fixture == nil || fixture.cleaned {
		return
	}
	fixture.cleaned = true

	info, err := os.Lstat(fixture.dir)
	if err != nil {
		t.Errorf("lstat short proof Unix-socket directory during cleanup: %v", err)
		return
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || !os.SameFile(fixture.identity, info) {
		t.Errorf("short proof Unix-socket cleanup path no longer identifies the allocated directory: %q mode=%v", fixture.dir, info.Mode())
		return
	}
	uid, gid, ok := proofUnixSocketOwner(info)
	if !ok || uid != uint32(os.Getuid()) || info.Mode().Perm() != 0o700 {
		t.Errorf("short proof Unix-socket directory owner UID or mode changed before cleanup: owner=%d:%d owner_known=%t mode=%04o", uid, gid, ok, info.Mode().Perm())
		return
	}
	entries, err := os.ReadDir(fixture.dir)
	if err != nil {
		t.Errorf("read short proof Unix-socket directory before cleanup: %v", err)
		return
	}
	if len(entries) != 0 {
		t.Errorf("short proof Unix-socket directory is not empty after endpoint close: %q entries=%v", fixture.dir, entries)
		return
	}
	if err := os.Remove(fixture.dir); err != nil {
		t.Errorf("remove exact short proof Unix-socket directory: %v", err)
		return
	}
	if _, err := os.Lstat(fixture.dir); err == nil {
		t.Errorf("short proof Unix-socket directory still exists after cleanup: %q", fixture.dir)
	} else if !os.IsNotExist(err) {
		t.Errorf("verify short proof Unix-socket directory removal: %v", err)
	}
}

type proofIdentityEndpoint struct {
	listener    net.Listener
	socketPath  string
	requests    int32
	acceptDone  chan struct{}
	activity    sync.WaitGroup
	mu          sync.Mutex
	connections map[net.Conn]struct{}
	closeOnce   sync.Once
}

func startProofIdentityEndpoint(t *testing.T, socketPath string) *proofIdentityEndpoint {
	t.Helper()

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen on required proof identity Unix socket: %v", err)
	}
	if unixListener, ok := listener.(*net.UnixListener); ok {
		unixListener.SetUnlinkOnClose(true)
	}
	endpoint := &proofIdentityEndpoint{
		listener:    listener,
		socketPath:  socketPath,
		acceptDone:  make(chan struct{}),
		connections: make(map[net.Conn]struct{}),
	}
	t.Cleanup(func() { endpoint.close(t) })
	go func() {
		defer close(endpoint.acceptDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			endpoint.mu.Lock()
			endpoint.connections[conn] = struct{}{}
			endpoint.activity.Add(1)
			endpoint.mu.Unlock()
			go func(conn net.Conn) {
				defer endpoint.activity.Done()
				defer func() {
					endpoint.mu.Lock()
					delete(endpoint.connections, conn)
					endpoint.mu.Unlock()
					_ = conn.Close()
				}()
				line, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					return
				}
				var payload map[string]string
				if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &payload); err != nil {
					_, _ = io.WriteString(conn, `{"error":"invalid json"}`+"\n")
					return
				}
				if payload["kind"] != "jwt_svid" || payload["target"] != "workload_vault" {
					_, _ = io.WriteString(conn, `{"error":"unexpected request"}`+"\n")
					return
				}
				atomic.AddInt32(&endpoint.requests, 1)
				_, _ = io.WriteString(conn, `{"jwt":"proof.jwt.value"}`+"\n")
			}(conn)
		}
	}()
	return endpoint
}

func (endpoint *proofIdentityEndpoint) close(t *testing.T) {
	t.Helper()
	if endpoint == nil {
		return
	}
	endpoint.closeOnce.Do(func() {
		if err := endpoint.listener.Close(); err != nil {
			t.Errorf("close proof identity Unix listener: %v", err)
		}
		<-endpoint.acceptDone
		endpoint.mu.Lock()
		connections := make([]net.Conn, 0, len(endpoint.connections))
		for connection := range endpoint.connections {
			connections = append(connections, connection)
		}
		endpoint.mu.Unlock()
		for _, connection := range connections {
			if err := connection.Close(); err != nil {
				t.Errorf("close active proof identity connection: %v", err)
			}
		}
		endpoint.activity.Wait()
		if _, err := os.Lstat(endpoint.socketPath); err == nil {
			t.Errorf("proof identity Unix socket remains after listener close: %q", endpoint.socketPath)
		} else if !os.IsNotExist(err) {
			t.Errorf("verify proof identity Unix socket removal: %v", err)
		}
	})
}

func startProofCodexVaultServer(t *testing.T) (*httptest.Server, *int32, *int32) {
	t.Helper()

	var loginRequests int32
	var secretReads int32
	token := "proof-vault-client-token"

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON := func(status int, payload any) {
			body, err := json.Marshal(payload)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write(body)
		}

		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/jwt/login":
			var payload struct {
				Role string `json:"role"`
				JWT  string `json:"jwt"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				writeJSON(http.StatusBadRequest, map[string]any{"errors": []string{"invalid json"}})
				return
			}
			if payload.Role != "service_execution" || strings.TrimSpace(payload.JWT) == "" {
				writeJSON(http.StatusForbidden, map[string]any{"errors": []string{"invalid login"}})
				return
			}
			atomic.AddInt32(&loginRequests, 1)
			writeJSON(http.StatusOK, map[string]any{"auth": map[string]any{"client_token": token}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/proof-secrets/data/codex-runtime-profile":
			if r.Header.Get("X-Vault-Token") != token {
				writeJSON(http.StatusForbidden, map[string]any{"errors": []string{"invalid token"}})
				return
			}
			atomic.AddInt32(&secretReads, 1)
			writeJSON(http.StatusOK, map[string]any{
				"data": map[string]any{
					"data": map[string]any{
						"api_key": "proof-codex-material",
					},
				},
			})
		default:
			writeJSON(http.StatusNotFound, map[string]any{"errors": []string{"not found"}})
		}
	}))
	return server, &loginRequests, &secretReads
}
