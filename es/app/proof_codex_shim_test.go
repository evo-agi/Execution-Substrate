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
	"sync/atomic"
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
	socketPath := filepath.Join(t.TempDir(), "identity.sock")
	identityRequests := startProofIdentityEndpoint(t, socketPath)
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
		"EXEC_WORKLOAD_IDENTITY_ENDPOINT=unix://"+socketPath,
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
	if got := atomic.LoadInt32(identityRequests); got != 1 {
		t.Fatalf("expected one identity request, got %d", got)
	}
	if got := atomic.LoadInt32(loginRequests); got != 1 {
		t.Fatalf("expected one Vault login, got %d", got)
	}
	if got := atomic.LoadInt32(secretReads); got != 1 {
		t.Fatalf("expected one Vault secret read, got %d", got)
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

func startProofIdentityEndpoint(t *testing.T, socketPath string) *int32 {
	t.Helper()

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Skipf("proof Codex shim test requires Unix sockets: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	var requests int32
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
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
				atomic.AddInt32(&requests, 1)
				_, _ = io.WriteString(conn, `{"jwt":"proof.jwt.value"}`+"\n")
			}(conn)
		}
	}()
	return &requests
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
