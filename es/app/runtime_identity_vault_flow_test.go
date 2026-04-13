package app_test

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"execution-substrate/es/admission"
)

func TestSubmitFlowUsesPlatformOwnedIdentityForVaultLoginAndSecretRead(t *testing.T) {
	requireSlice1RuntimeIdentityCapabilities(t)

	gateway := dockerBridgeGateway(t)
	mockVault := startMockVaultCompatServer(t, newExecutionWorkspaceTempDir(t, "mock-vault-"), mockVaultCompatServerOptions{
		bindAddress: "0.0.0.0",
		publicHost:  gateway,
		authMount:   "jwt",
		role:        "service_execution",
		audience:    "vault",
		subject:     "spiffe://execution.internal/workload",
		secretPath:  "proof-secrets/data/runtime-identity-vault-login",
		secretValue: "runtime-identity-ok",
	})

	stack := startSubmitStackWithOptions(t, submitStackOptions{
		baseImage:                "python:3.13-alpine",
		networkAccess:            true,
		workloadVaultAddress:     "https://" + net.JoinHostPort(gateway, strconv.Itoa(mockVault.port(t))),
		workloadVaultCABundlePEM: mockVault.caBundle(t),
	})

	entrypointPath := filepath.Join(executionPlatformRepoRoot(t), ".examples", "runtime_identity_vault_login", "entrypoint")
	entrypointBytes, err := os.ReadFile(entrypointPath)
	if err != nil {
		t.Fatalf("read runtime identity vault entrypoint: %v", err)
	}

	publishSubmitArtifactArchiveWithOptions(t, stack, buildArchiveFromScript(t, string(entrypointBytes)), publishSubmitArtifactOptions{
		environmentVariables: []string{
			"WORKLOAD_VAULT_SECRET_PATH",
		},
		networkAccess: true,
	})

	response := submitExecutionRequest(t, stack, buildSubmitRequestBodyWithEnv(t, stack, map[string]string{
		"WORKLOAD_VAULT_SECRET_PATH": "proof-secrets/data/runtime-identity-vault-login",
	}))
	defer response.Body.Close()

	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}

	var payload admission.SubmitResult
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode submit response: %v", err)
	}

	jobID := stack.nomad.waitForExecutionJob(t, payload.RunID)
	job := stack.nomad.fetchJobDetail(t, jobID)
	assertNoRawSPIREEnvLeak(t, job.task(t).Env, stack.mockSPIRE.socketPath)
	if job.task(t).Env["VAULT_CACERT"] != "/execution/run/platform/workload-vault-ca.pem" {
		t.Fatalf("expected workload Vault CA cert env, got %#v", job.task(t).Env["VAULT_CACERT"])
	}
	if job.task(t).Env["SSL_CERT_FILE"] != "/execution/run/platform/workload-ca-bundle.pem" {
		t.Fatalf("expected workload TLS bundle env, got %#v", job.task(t).Env["SSL_CERT_FILE"])
	}

	endpointURI := job.task(t).Env[workloadIdentityEndpointEnvKey]
	spireMount := findTaskMountByTarget(t, job.taskConfig(t)["mounts"], runtimeIdentitySPIRESourceDirFromEndpoint(t, endpointURI))
	if spireMount["source"] != filepath.Dir(stack.mockSPIRE.socketPath) {
		t.Fatalf("expected helper-private SPIRE mount source dir %q, got %#v", filepath.Dir(stack.mockSPIRE.socketPath), spireMount["source"])
	}

	alloc := stack.nomad.waitForTerminalAllocation(t, jobID)
	if alloc.ClientStatus != "complete" {
		t.Fatalf("expected complete allocation, got %q allocation=%+v", alloc.ClientStatus, alloc)
	}
	taskState := alloc.TaskStates["task"]
	if taskState.Failed || taskState.exitCode() != 0 {
		t.Fatalf("expected successful task state, got %+v logs=%q", taskState, stack.nomad.allocLogs(t, alloc.ID))
	}

	logs := stack.nomad.allocLogs(t, alloc.ID)
	for _, marker := range []string{
		helperReadyLogMarker,
		"PLATFORM-ENDPOINT-USED",
		"RAW-SPIRE-DENIED",
		"IDENTITY-JWT-RECEIVED",
		"VAULT-LOGIN-SUCCESS",
		"SECRET-READ-SUCCESS:runtime-identity-ok",
	} {
		if !strings.Contains(logs, marker) {
			t.Fatalf("expected %q in workload logs, got %q", marker, logs)
		}
	}
	if !strings.Contains(logs, `"status":"ok"`) && !strings.Contains(logs, `"status": "ok"`) {
		t.Fatalf("expected final success marker in logs, got %q", logs)
	}

	if attempts := mockVault.loginAttempts(); attempts != 1 {
		t.Fatalf("expected exactly one mock vault login, got %d", attempts)
	}
	if reads := mockVault.secretReads(); reads != 1 {
		t.Fatalf("expected exactly one mock vault secret read, got %d", reads)
	}
}
