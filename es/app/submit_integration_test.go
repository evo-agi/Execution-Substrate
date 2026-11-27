package app_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	workloadpb "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agsapp "execution-substrate/ags/app"
	agsconfig "execution-substrate/ags/config"
	arsapi "execution-substrate/ars/api"
	arsapp "execution-substrate/ars/app"
	arsconfig "execution-substrate/ars/config"
	arsindex "execution-substrate/ars/index"
	arsstore "execution-substrate/ars/store"
	egsapp "execution-substrate/egs/app"
	egsconfig "execution-substrate/egs/config"
	egsmodel "execution-substrate/egs/model"
	"execution-substrate/es/admission"
	esapp "execution-substrate/es/app"
	esconfig "execution-substrate/es/config"
	runtimeconfigv1 "execution-substrate/internal/contracts/runtimeconfig/v1"
)

const (
	workloadIdentityEndpointEnvKey = "EXEC_WORKLOAD_IDENTITY_ENDPOINT"
	helperReadyLogMarker           = "RUNTIME-HELPER-READY"
	helperCapsLogPrefix            = "RUNTIME-HELPER-CAPS"
	workloadBoundaryLogPrefix      = "RUNTIME-WORKLOAD-BOUNDARY"

	dockerDaemonCapabilitySkipPrefix      = "integration test requires healthy Docker daemon"
	dockerBackedNomadCapabilitySkipPrefix = "integration test requires healthy Docker-backed Nomad client"
	runtimeIdentityCapabilitySkipPrefix   = "runtime identity integration requires Linux/Nomad/Docker substrate with bind-mounted SPIRE Workload API Unix socket support"
)

var dockerDaemonCapabilityProbe struct {
	once   sync.Once
	reason string
}

var dockerBackedNomadCapabilityProbe struct {
	once   sync.Once
	reason string
}

var slice1RuntimeIdentityCapabilityProbe struct {
	once   sync.Once
	reason string
}

func TestRuntimeIdentityIntegrationCapabilityProbe(t *testing.T) {
	requireSlice1RuntimeIdentityCapabilities(t)
}

func TestSubmitFlowRunsStaticScriptInNomadDocker(t *testing.T) {
	stack := startRuntimeIdentitySubmitStack(t)

	response := doJSONRequest(
		t,
		stack.es.Addr(),
		http.MethodPost,
		"/v1/executions:submit",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "operator/local", false),
		buildSubmitRequestBody(t, stack),
	)
	defer response.Body.Close()

	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}

	var payload admission.SubmitResult
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode submit response: %v", err)
	}
	if !payload.Success || !payload.Submitted {
		t.Fatalf("expected successful submission, got %+v", payload)
	}
	if strings.TrimSpace(payload.RunID) == "" {
		t.Fatalf("expected run_id in submit response")
	}
	if payload.Status != "submitted" {
		t.Fatalf("unexpected status: %q", payload.Status)
	}

	jobID := stack.nomad.waitForExecutionJob(t, payload.RunID)
	job := stack.nomad.fetchJobDetail(t, jobID)
	if networkMode := job.taskConfig(t)["network_mode"]; networkMode != "none" {
		t.Fatalf("expected network_mode=none for network_access=false, got %#v", networkMode)
	}

	alloc := stack.nomad.waitForTerminalAllocation(t, jobID)
	if alloc.ClientStatus != "complete" {
		t.Fatalf("expected complete allocation, got %q", alloc.ClientStatus)
	}
	task, ok := alloc.TaskStates["task"]
	if !ok {
		t.Fatalf("expected task state for task")
	}
	if task.Failed {
		t.Fatalf("expected successful task, got failed task state: %+v", task)
	}
	if exitCode := task.exitCode(); exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	logs := stack.nomad.allocLogs(t, alloc.ID)
	t.Logf("nomad allocation logs:\n%s", logs)
	if !strings.Contains(logs, "START-BANNER") {
		t.Fatalf("expected start banner in logs, got %q", logs)
	}
	if !strings.Contains(logs, "HEARTBEAT:1") || !strings.Contains(logs, "HEARTBEAT:2") || !strings.Contains(logs, "HEARTBEAT:3") {
		t.Fatalf("expected heartbeat lines in logs, got %q", logs)
	}
	if !strings.Contains(logs, `"status":"ok"`) || !strings.Contains(logs, stack.publishResponse.ArtifactDigest) {
		t.Fatalf("expected final json marker in logs, got %q", logs)
	}
}

func TestSubmitValidOperatorCallerReturnsAcceptedSubmissionReceipt(t *testing.T) {
	stack := startSubmitStack(t)

	response := submitExecutionRequest(t, stack, buildSubmitRequestBody(t, stack))
	defer response.Body.Close()

	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}

	var payload admission.SubmitResult
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode submit response: %v", err)
	}
	if !payload.Success || !payload.Submitted || strings.TrimSpace(payload.RunID) == "" {
		t.Fatalf("expected accepted operator submission receipt, got %+v", payload)
	}
	assertDefaultAuthorityHandoff(t, payload.AuthorityHandoff, stack, payload.RunID)

	jobID := stack.nomad.waitForExecutionJob(t, payload.RunID)
	if jobID != "exec-"+payload.RunID {
		t.Fatalf("expected job id %q, got %q", "exec-"+payload.RunID, jobID)
	}

	statusResponse := executionStatusRequestWithCaller(t, stack, payload.RunID, "operator/local")
	defer statusResponse.Body.Close()
	if statusResponse.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from operator status, got %d body=%s", statusResponse.StatusCode, strings.TrimSpace(string(mustReadBody(t, statusResponse.Body))))
	}

	var statusPayload admission.ExecutionStatusResult
	if err := json.NewDecoder(statusResponse.Body).Decode(&statusPayload); err != nil {
		t.Fatalf("decode operator status response: %v", err)
	}
	if !statusPayload.Success || statusPayload.RunID != payload.RunID {
		t.Fatalf("expected operator status for run %q, got %+v", payload.RunID, statusPayload)
	}
	assertDefaultAuthorityHandoff(t, statusPayload.AuthorityHandoff, stack, payload.RunID)
}

func assertDefaultAuthorityHandoff(t *testing.T, handoff *admission.ExecutionAuthorityHandoff, stack *submitStack, runID string) {
	t.Helper()

	if handoff == nil {
		t.Fatalf("expected authority_handoff for submitted run")
	}
	if handoff.AuthorityPath != "workload_identity_endpoint/workload_vault" {
		t.Fatalf("unexpected authority path %+v", handoff)
	}
	if handoff.RuntimeProfile.Name != "static-script/default" {
		t.Fatalf("unexpected runtime profile %+v", handoff.RuntimeProfile)
	}
	if handoff.IdentityHandoff.Mode != "workload_identity_endpoint" ||
		handoff.IdentityHandoff.EndpointEnv != workloadIdentityEndpointEnvKey ||
		!strings.HasPrefix(handoff.IdentityHandoff.EndpointURI, "unix:///run/es-runtime-identity/"+runID+"/") ||
		handoff.IdentityHandoff.JWTSVIDTarget != "workload_vault" {
		t.Fatalf("unexpected identity handoff %+v", handoff.IdentityHandoff)
	}
	if handoff.WorkloadVault.AuthMode != string(esconfig.WorkloadVaultAuthModeVaultIdentityJWT) ||
		handoff.WorkloadVault.Address != "https://vault.internal:8200" ||
		handoff.WorkloadVault.AuthMount != "jwt" ||
		handoff.WorkloadVault.AuthRole != "service_execution" ||
		handoff.WorkloadVault.JWTAudience != "vault" {
		t.Fatalf("unexpected workload vault handoff %+v", handoff.WorkloadVault)
	}
	if handoff.RuntimeConfigRefs.WorkloadZoneVaultConfig.Digest != stack.workloadZoneVaultDigest {
		t.Fatalf("unexpected runtime config refs %+v", handoff.RuntimeConfigRefs)
	}
	if handoff.CodexCredentialLocation != nil {
		t.Fatalf("did not expect codex credential location for default profile: %+v", handoff.CodexCredentialLocation)
	}
	if handoff.Evidence.Source != "submitted_runtime_spec" ||
		handoff.Evidence.IdentityHandoff != "submitted_runtime_environment" ||
		handoff.Evidence.RuntimeConfigRefs != "submitted_runtime_metadata" {
		t.Fatalf("unexpected authority evidence %+v", handoff.Evidence)
	}
}

func TestSubmitFlowAllowsConfiguredControlPlaneCallerHandoff(t *testing.T) {
	stack := startSubmitStackWithOptions(t, submitStackOptions{
		allowedAGSCallerPrefixes:       []string{"operator/local", "service/control-plane"},
		allowedExecutionCallerPrefixes: []string{"operator/local", "service/control-plane"},
		publishCallerPath:              "service/control-plane",
		executionCallerPath:            "service/control-plane",
	})

	discovery := stack.loadDiscovery(t, stack.publishResponse.ArtifactDigest)
	var evidence map[string]any
	readJSONBlob(t, stack.arsRootDir, discovery.Evidence.Digest, &evidence)
	publication := evidence["claims"].(map[string]any)["package"].(map[string]any)["publication"].(map[string]any)
	invoker := publication["invoker"].(map[string]any)
	if got := invoker["service"]; got != "service/control-plane" {
		t.Fatalf("expected control-plane invoker service, got %v", got)
	}
	if got := invoker["principal"]; got != "spiffe://execution.internal/service/control-plane" {
		t.Fatalf("expected control-plane invoker principal, got %v", got)
	}

	response := submitExecutionRequest(t, stack, buildSubmitRequestBody(t, stack))
	defer response.Body.Close()

	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}

	var payload admission.SubmitResult
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode submit response: %v", err)
	}
	if !payload.Success || !payload.Submitted {
		t.Fatalf("expected successful control-plane submission, got %+v", payload)
	}

	jobID := stack.nomad.waitForExecutionJob(t, payload.RunID)
	if jobID != "exec-"+payload.RunID {
		t.Fatalf("expected job id %q, got %q", "exec-"+payload.RunID, jobID)
	}

	statusResponse := executionStatusRequestWithCaller(t, stack, payload.RunID, "service/control-plane")
	defer statusResponse.Body.Close()
	if statusResponse.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from control-plane status, got %d body=%s", statusResponse.StatusCode, strings.TrimSpace(string(mustReadBody(t, statusResponse.Body))))
	}
	var statusPayload admission.ExecutionStatusResult
	if err := json.NewDecoder(statusResponse.Body).Decode(&statusPayload); err != nil {
		t.Fatalf("decode control-plane status response: %v", err)
	}
	if !statusPayload.Success || statusPayload.RunID != payload.RunID {
		t.Fatalf("expected control-plane status for run %q, got %+v", payload.RunID, statusPayload)
	}
}

func TestExecutionWorkspaceTempDirUsesDotOut(t *testing.T) {
	dir := newExecutionWorkspaceTempDir(t, "es-submit-")
	outputRoot := filepath.Join(repoRootFromTestFile(t), ".out")

	if filepath.Dir(dir) != outputRoot {
		t.Fatalf("expected workspace temp dir parent %q, got %q", outputRoot, filepath.Dir(dir))
	}
	if !strings.HasPrefix(filepath.Base(dir), "es-submit-") {
		t.Fatalf("expected workspace temp dir base to start with %q, got %q", "es-submit-", filepath.Base(dir))
	}
}

func TestSubmitFlowUsesBridgeNetworkWhenNetworkAccessEnabled(t *testing.T) {
	stack := startRuntimeIdentitySubmitStackWithNetworkAccess(t, true)

	response := doJSONRequest(
		t,
		stack.es.Addr(),
		http.MethodPost,
		"/v1/executions:submit",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "operator/local", false),
		buildSubmitRequestBody(t, stack),
	)
	defer response.Body.Close()

	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}

	var payload admission.SubmitResult
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode submit response: %v", err)
	}
	if !payload.Success || !payload.Submitted {
		t.Fatalf("expected successful submission, got %+v", payload)
	}

	jobID := stack.nomad.waitForExecutionJob(t, payload.RunID)
	job := stack.nomad.fetchJobDetail(t, jobID)
	if networkMode := job.taskConfig(t)["network_mode"]; networkMode != "bridge" {
		t.Fatalf("expected network_mode=bridge for network_access=true, got %#v", networkMode)
	}

	alloc := stack.nomad.waitForTerminalAllocation(t, jobID)
	if alloc.ClientStatus != "complete" {
		t.Fatalf("expected complete allocation, got %q", alloc.ClientStatus)
	}
	task, ok := alloc.TaskStates["task"]
	if !ok {
		t.Fatalf("expected task state for task")
	}
	if task.Failed {
		t.Fatalf("expected successful task, got failed task state: %+v", task)
	}
	if exitCode := task.exitCode(); exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
}

func TestSubmitReturns403WhenCallerIsDisallowed(t *testing.T) {
	stack := startSubmitStackWithoutNomad(t)

	response := submitExecutionRequestWithCaller(t, stack, "service/execution", buildSubmitRequestBody(t, stack))
	defer response.Body.Close()

	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}
	if got := strings.TrimSpace(string(mustReadBody(t, response.Body))); got != "Caller not authorized for this operation" {
		t.Fatalf("unexpected body: %q", got)
	}
}

func TestSubmitReturns403WhenDeploymentCallerIsUsed(t *testing.T) {
	stack := startSubmitStackWithoutNomad(t)

	response := submitExecutionRequestWithCaller(t, stack, "service/deployment", buildSubmitRequestBody(t, stack))
	defer response.Body.Close()

	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}
	if got := strings.TrimSpace(string(mustReadBody(t, response.Body))); got != "Caller not authorized for this operation" {
		t.Fatalf("unexpected body: %q", got)
	}
}

func TestSubmitFlowInjectsWorkloadIdentityEndpointAndLifecycleStillWorks(t *testing.T) {
	stack := startRuntimeIdentitySubmitStackWithOptions(t, submitStackOptions{
		baseImage: "python:3.13-alpine",
	})

	publishSubmitArtifactArchive(t, stack, buildArchiveFromScript(t, `#!/bin/sh
set -eu
echo "${EXEC_WORKLOAD_IDENTITY_ENDPOINT}"
echo "${EXEC_WORKLOAD_VAULT_AUTH_MODE}"
echo "IDENTITY-ENDPOINT-ENV-OK"
echo "{\"status\":\"ok\",\"artifact_digest\":\"${EXEC_ARTIFACT_DIGEST}\"}"
`))

	response := submitExecutionRequest(t, stack, buildSubmitRequestBody(t, stack))
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
	if networkMode := job.taskConfig(t)["network_mode"]; networkMode != "none" {
		t.Fatalf("expected network_mode=none, got %#v", networkMode)
	}

	taskConfig := job.task(t)
	endpointURI := taskConfig.Env[workloadIdentityEndpointEnvKey]
	if !strings.HasPrefix(endpointURI, "unix://") {
		t.Fatalf("expected canonical workload identity endpoint env to carry a unix URI, got %q", endpointURI)
	}
	if strings.Contains(endpointURI, "/execution/") {
		t.Fatalf("did not expect canonical workload identity endpoint env to expose container runtime path conventions, got %q", endpointURI)
	}

	mountConfig := findTaskMountByTarget(t, job.taskConfig(t)["mounts"], runtimeIdentityWorkspaceFromEndpoint(t, endpointURI))
	if mountType := mountConfig["type"]; mountType != "tmpfs" {
		t.Fatalf("expected tmpfs runtime identity workspace mount, got %#v", mountType)
	}
	if _, ok := mountConfig["source"]; ok {
		t.Fatalf("did not expect host source for tmpfs runtime identity mount, got %#v", mountConfig["source"])
	}
	if readonly, ok := mountConfig["readonly"].(bool); !ok || readonly {
		t.Fatalf("expected writable runtime identity workspace mount, got %#v", mountConfig["readonly"])
	}
	tmpfsOptions, ok := mountConfig["tmpfs_options"].(map[string]any)
	if !ok {
		t.Fatalf("expected tmpfs_options for runtime identity mount, got %#v", mountConfig["tmpfs_options"])
	}
	if size := tmpfsOptions["size"]; size != float64(1<<20) && size != int64(1<<20) && size != int(1<<20) {
		t.Fatalf("expected default tmpfs size 1048576, got %#v", size)
	}

	allocation := stack.nomad.waitForTerminalAllocation(t, jobID)
	if allocation.ClientStatus != "complete" {
		t.Fatalf("expected complete allocation, got %q", allocation.ClientStatus)
	}

	statusResponse := doJSONRequest(
		t,
		stack.es.Addr(),
		http.MethodGet,
		"/v1/executions/"+payload.RunID+"/status",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "operator/local", false),
		nil,
	)
	defer statusResponse.Body.Close()
	if statusResponse.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from status, got %d body=%s", statusResponse.StatusCode, strings.TrimSpace(string(mustReadBody(t, statusResponse.Body))))
	}

	logsResponse := doJSONRequest(
		t,
		stack.es.Addr(),
		http.MethodGet,
		"/v1/executions/"+payload.RunID+"/logs",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "operator/local", false),
		nil,
	)
	defer logsResponse.Body.Close()
	if logsResponse.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from logs, got %d body=%s", logsResponse.StatusCode, strings.TrimSpace(string(mustReadBody(t, logsResponse.Body))))
	}

	logs := string(mustReadBody(t, logsResponse.Body))
	if !strings.Contains(logs, endpointURI) || !strings.Contains(logs, "IDENTITY-ENDPOINT-ENV-OK") {
		t.Fatalf("expected workload identity endpoint env markers in logs, got %q", logs)
	}
	if strings.Contains(logs, "unix:///execution/runtime-identity/endpoint") {
		t.Fatalf("did not expect logs to depend on the legacy fixed workload identity endpoint value, got %q", logs)
	}
	if !strings.Contains(logs, "vault_identity_jwt") {
		t.Fatalf("expected bounded auth mode marker in logs, got %q", logs)
	}
}

const mountFixtureDiagnosticStreamLimit = 4096

func formatMountFixtureAllocationFailure(status string, stdout string, stdoutErr error, stderr string, stderrErr error) string {
	formatStream := func(content string, err error) string {
		if err != nil {
			return fmt.Sprintf("unavailable (%v)", err)
		}
		if len(content) > mountFixtureDiagnosticStreamLimit {
			return fmt.Sprintf("%q [truncated from %d bytes]", content[:mountFixtureDiagnosticStreamLimit], len(content))
		}
		return fmt.Sprintf("%q", content)
	}
	return fmt.Sprintf("expected complete allocation, got %q; test-owned stdout=%s; test-owned stderr=%s",
		status, formatStream(stdout, stdoutErr), formatStream(stderr, stderrErr))
}

func TestSubmitMountFixtureFailureDiagnosticIsBounded(t *testing.T) {
	message := formatMountFixtureAllocationFailure("failed", "START-BANNER\n", nil, "cat: permission denied\n", nil)
	for _, want := range []string{`expected complete allocation, got "failed"`, `test-owned stdout="START-BANNER\n"`, `test-owned stderr="cat: permission denied\n"`} {
		if !strings.Contains(message, want) {
			t.Fatalf("diagnostic %q missing %q", message, want)
		}
	}
	long := strings.Repeat("x", mountFixtureDiagnosticStreamLimit+100)
	message = formatMountFixtureAllocationFailure("failed", long, nil, "", errors.New("logs unavailable"))
	if strings.Contains(message, long) || !strings.Contains(message, "truncated from 4196 bytes") || !strings.Contains(message, "test-owned stderr=unavailable (logs unavailable)") {
		t.Fatalf("diagnostic was unbounded or hid unavailable stream: %q", message)
	}
}

func TestWorkloadCanCreateAndUseLocalRuntimeIdentityEndpointFromTmpfsWorkspace(t *testing.T) {
	requireHealthyDockerDaemon(t)

	const endpointEnvValue = "unix:///runtime-identity-smoke/endpoint"
	command := exec.Command(
		"docker", "run", "--rm",
		"--tmpfs", runtimeIdentityWorkspaceFromEndpoint(t, endpointEnvValue)+":rw,size=1048576",
		"-e", workloadIdentityEndpointEnvKey+"="+endpointEnvValue,
		"python:3.13-alpine",
		"sh", "-lc",
		`python3 - <<'PY'
import os
import socket
import threading

endpoint = os.environ["EXEC_WORKLOAD_IDENTITY_ENDPOINT"]
if not endpoint.startswith("unix://"):
    raise SystemExit(f"unexpected endpoint: {endpoint}")
path = endpoint[len("unix://"):]
os.makedirs(os.path.dirname(path), exist_ok=True)
try:
    os.remove(path)
except FileNotFoundError:
    pass

server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(path)
server.listen(1)

def serve():
    connection, _ = server.accept()
    connection.sendall(b"identity-ok\n")
    connection.close()
    server.close()

thread = threading.Thread(target=serve, daemon=True)
thread.start()

client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.settimeout(5)
client.connect(path)
print(client.recv(64).decode().strip())
client.close()
print("ENDPOINT-ACCESS-OK")
PY`,
	)
	output, err := command.CombinedOutput()
	logs := string(output)
	if err != nil {
		t.Fatalf("docker runtime identity workspace smoke failed: %v output=%s", err, strings.TrimSpace(logs))
	}
	if !strings.Contains(logs, "identity-ok") || !strings.Contains(logs, "ENDPOINT-ACCESS-OK") {
		t.Fatalf("expected workload identity endpoint access markers, got %q", logs)
	}
}

func runtimeIdentityWorkspaceFromEndpoint(t *testing.T, endpointURI string) string {
	t.Helper()

	if !strings.HasPrefix(endpointURI, "unix://") {
		t.Fatalf("expected unix endpoint URI, got %q", endpointURI)
	}
	endpointPath := strings.TrimPrefix(endpointURI, "unix://")
	if strings.TrimSpace(endpointPath) == "" {
		t.Fatalf("expected endpoint path in %q", endpointURI)
	}
	return path.Dir(endpointPath)
}

func runtimeIdentitySPIRESourceDirFromEndpoint(t *testing.T, endpointURI string) string {
	t.Helper()
	return path.Join(runtimeIdentityWorkspaceFromEndpoint(t, endpointURI), "internal", "source")
}

func TestSubmitFlowUsesConfiguredRuntimeIdentityTmpfsSize(t *testing.T) {
	stack := startSubmitStackWithOptions(t, submitStackOptions{
		runtimeIdentityTmpfsSize: 2 << 20,
	})

	response := submitExecutionRequest(t, stack, buildSubmitRequestBody(t, stack))
	defer response.Body.Close()

	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}

	var payload admission.SubmitResult
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode submit response: %v", err)
	}

	job := stack.nomad.fetchExecutionJobDetail(t, payload.RunID)
	taskConfig := job.task(t)
	mountConfig := findTaskMountByTarget(t, job.taskConfig(t)["mounts"], runtimeIdentityWorkspaceFromEndpoint(t, taskConfig.Env[workloadIdentityEndpointEnvKey]))
	tmpfsOptions, ok := mountConfig["tmpfs_options"].(map[string]any)
	if !ok {
		t.Fatalf("expected tmpfs_options for runtime identity mount, got %#v", mountConfig["tmpfs_options"])
	}
	if size := tmpfsOptions["size"]; size != float64(2<<20) && size != int64(2<<20) && size != int(2<<20) {
		t.Fatalf("expected configured tmpfs size %d, got %#v", 2<<20, size)
	}
}

func TestSubmitFlowProvidesPlatformOwnedRuntimeIdentityThroughBoundedEndpoint(t *testing.T) {
	stack := startRuntimeIdentitySubmitStackWithOptions(t, submitStackOptions{
		baseImage:       "python:3.13-alpine",
		mockSPIREJWTTTL: 20 * time.Second,
	})

	publishSubmitArtifactArchive(t, stack, buildArchiveWithEntries(t, []archiveEntry{
		{
			Name: "entrypoint",
			Mode: 0o755,
			Body: []byte(`#!/usr/bin/env python3
import json
import os
import socket
import stat
import urllib.parse

print("WORKLOAD-START", flush=True)
endpoint = os.environ["EXEC_WORKLOAD_IDENTITY_ENDPOINT"]
parsed = urllib.parse.urlparse(endpoint)
if parsed.scheme != "unix":
    raise SystemExit("unexpected endpoint scheme")
socket_path = parsed.path
if not socket_path:
    raise SystemExit("missing endpoint path")

if os.getuid() != 10000 or os.getgid() != 10000:
    raise SystemExit(f"unexpected uid/gid: {os.getuid()}:{os.getgid()}")
if os.getgroups():
    raise SystemExit(f"unexpected supplemental groups: {os.getgroups()}")
if os.stat("/execution/run/work/modeprobe").st_mode & 0o6000:
    raise SystemExit("setuid/setgid bits survived sanitization")
print("MODEPROBE-SANITIZED", flush=True)

status = {}
with open("/proc/self/status", "r", encoding="utf-8") as handle:
    for line in handle:
        if ":" in line:
            key, value = line.split(":", 1)
            status[key.strip()] = value.strip()
if status.get("NoNewPrivs") != "1":
    raise SystemExit(f"NoNewPrivs not set: {status.get('NoNewPrivs')}")
for key in ("CapEff", "CapPrm", "CapAmb", "CapBnd"):
    if status.get(key) != "0000000000000000":
        raise SystemExit(f"{key} not cleared: {status.get(key)}")

env_dump = "\n".join(f"{k}={v}" for k, v in os.environ.items())
if "spire-agent.sock" in env_dump:
    raise SystemExit("raw spire path leaked into workload env")

raw_spire = os.path.join(os.path.dirname(socket_path), "internal", "spire-agent.sock")
client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.settimeout(1)
try:
    client.connect(raw_spire)
    raise SystemExit("raw spire socket unexpectedly reachable")
except OSError:
    print("RAW-SPIRE-DENIED", flush=True)
finally:
    client.close()

client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.settimeout(5)
client.connect(socket_path)
client.sendall((json.dumps({"kind": "jwt_svid", "target": "workload_vault"}) + "\n").encode("utf-8"))
response = b""
while b"\n" not in response:
    chunk = client.recv(4096)
    if not chunk:
        break
    response += chunk
client.close()
payload = json.loads(response.decode("utf-8").strip())
jwt_value = str(payload.get("jwt", "")).strip()
if not jwt_value:
    raise SystemExit(f"missing jwt in response: {payload}")
print("JWT-RECEIVED", flush=True)
print(json.dumps({"status": "ok", "artifact_digest": os.environ.get("EXEC_ARTIFACT_DIGEST", "")}, sort_keys=True), flush=True)
`),
		},
		{
			Name: "modeprobe",
			Mode: 0o6755,
			Body: []byte("modeprobe\n"),
		},
	}))

	response := submitExecutionRequest(t, stack, buildSubmitRequestBody(t, stack))
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
	taskConfig := job.task(t)
	if got := taskConfig.User; got != "0:0" {
		t.Fatalf("expected task to start as platform-owned root supervisor, got %#v", got)
	}
	if got := taskConfig.Config["privileged"]; got != false {
		t.Fatalf("expected privileged=false, got %#v", got)
	}
	securityOpt, ok := taskConfig.Config["security_opt"].([]any)
	if !ok || len(securityOpt) != 1 || securityOpt[0] != "no-new-privileges" {
		t.Fatalf("expected no-new-privileges docker security_opt, got %#v", taskConfig.Config["security_opt"])
	}
	assertNoRawSPIREEnvLeak(t, taskConfig.Env, stack.mockSPIRE.socketPath)

	endpointURI := taskConfig.Env[workloadIdentityEndpointEnvKey]
	spireMount := findTaskMountByTarget(t, job.taskConfig(t)["mounts"], runtimeIdentitySPIRESourceDirFromEndpoint(t, endpointURI))
	if spireMount["source"] != filepath.Dir(stack.mockSPIRE.socketPath) {
		t.Fatalf("expected helper-private SPIRE mount source dir %q, got %#v", filepath.Dir(stack.mockSPIRE.socketPath), spireMount["source"])
	}
	if spireMount["target"] != runtimeIdentitySPIRESourceDirFromEndpoint(t, endpointURI) {
		t.Fatalf("expected helper-private SPIRE source dir target %q, got %#v", runtimeIdentitySPIRESourceDirFromEndpoint(t, endpointURI), spireMount["target"])
	}

	alloc := stack.nomad.waitForTerminalAllocation(t, jobID)
	if alloc.ClientStatus != "complete" {
		t.Fatalf("expected complete allocation, got %q", alloc.ClientStatus)
	}
	taskState := alloc.TaskStates["task"]
	if taskState.Failed || taskState.exitCode() != 0 {
		t.Fatalf("expected successful task state, got %+v", taskState)
	}

	logs := stack.nomad.allocLogs(t, alloc.ID)
	if !strings.Contains(logs, helperReadyLogMarker) {
		t.Fatalf("expected helper readiness marker in logs, got %q", logs)
	}
	if !strings.Contains(logs, helperCapsLogPrefix+" cap_eff=0000000000000000") ||
		!strings.Contains(logs, "cap_prm=0000000000000000") ||
		!strings.Contains(logs, "cap_amb=0000000000000000") {
		t.Fatalf("expected helper capability drop markers in logs, got %q", logs)
	}
	if !strings.Contains(logs, workloadBoundaryLogPrefix+" uid=10000 gid=10000 groups=[]") || !strings.Contains(logs, "no_new_privs=true") {
		t.Fatalf("expected workload boundary marker in logs, got %q", logs)
	}
	if !strings.Contains(logs, "MODEPROBE-SANITIZED") || !strings.Contains(logs, "RAW-SPIRE-DENIED") || !strings.Contains(logs, "JWT-RECEIVED") {
		t.Fatalf("expected workload runtime identity markers in logs, got %q", logs)
	}
	if !strings.Contains(logs, `"status":"ok"`) && !strings.Contains(logs, `"status": "ok"`) {
		t.Fatalf("expected final success marker in logs, got %q", logs)
	}
	helperReadyIndex := strings.Index(logs, helperReadyLogMarker)
	workloadStartIndex := strings.Index(logs, "WORKLOAD-START")
	if helperReadyIndex < 0 || workloadStartIndex < 0 || helperReadyIndex > workloadStartIndex {
		t.Fatalf("expected helper readiness before workload start, got logs=%q", logs)
	}
}

func TestSubmitFlowRejectsRuntimeIdentityPassthroughRequests(t *testing.T) {
	stack := startRuntimeIdentitySubmitStackWithOptions(t, submitStackOptions{
		baseImage: "python:3.13-alpine",
	})

	publishSubmitArtifactArchive(t, stack, buildArchiveFromScript(t, `#!/usr/bin/env python3
import json
import os
import socket
import urllib.parse

parsed = urllib.parse.urlparse(os.environ["EXEC_WORKLOAD_IDENTITY_ENDPOINT"])
socket_path = parsed.path
client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.settimeout(5)
client.connect(socket_path)
client.sendall(b'{"kind":"jwt_request","audience":"vault"}\n')
response = b""
while b"\n" not in response:
    chunk = client.recv(4096)
    if not chunk:
        break
    response += chunk
client.close()
payload = json.loads(response.decode("utf-8").strip())
if payload.get("error") != "unsupported_request":
    raise SystemExit(f"unexpected passthrough response: {payload}")
print("PASSTHROUGH-REJECTED", flush=True)
client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.settimeout(5)
client.connect(socket_path)
client.sendall((json.dumps({"kind": "jwt_svid", "target": "workload_vault"}) + "\n").encode("utf-8"))
response = b""
while b"\n" not in response:
    chunk = client.recv(4096)
    if not chunk:
        break
    response += chunk
client.close()
payload = json.loads(response.decode("utf-8").strip())
if not payload.get("jwt"):
    raise SystemExit(f"missing bounded jwt response: {payload}")
print("VALID-JWT-RECEIVED", flush=True)
print(json.dumps({"status": "ok", "artifact_digest": os.environ.get("EXEC_ARTIFACT_DIGEST", "")}, sort_keys=True), flush=True)
`))

	response := submitExecutionRequest(t, stack, buildSubmitRequestBody(t, stack))
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}
	var payload admission.SubmitResult
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode submit response: %v", err)
	}

	alloc := stack.nomad.waitForTerminalExecutionAllocation(t, payload.RunID)
	if alloc.ClientStatus != "complete" {
		t.Fatalf("expected complete allocation, got %q", alloc.ClientStatus)
	}
	logs := stack.nomad.allocLogs(t, alloc.ID)
	if !strings.Contains(logs, "PASSTHROUGH-REJECTED") || !strings.Contains(logs, "VALID-JWT-RECEIVED") {
		t.Fatalf("expected bounded helper endpoint markers in logs, got %q", logs)
	}
}

func TestSubmitFlowDoesNotStartWorkloadBeforeHelperReadiness(t *testing.T) {
	stack := startRuntimeIdentitySubmitStackWithOptions(t, submitStackOptions{
		baseImage:           "python:3.13-alpine",
		mockSPIREFetchError: true,
	})

	publishSubmitArtifactArchive(t, stack, buildArchiveFromScript(t, `#!/usr/bin/env python3
print("WORKLOAD-STARTED", flush=True)
`))

	response := submitExecutionRequest(t, stack, buildSubmitRequestBody(t, stack))
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}
	var payload admission.SubmitResult
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode submit response: %v", err)
	}

	alloc := stack.nomad.waitForTerminalExecutionAllocation(t, payload.RunID)
	if alloc.ClientStatus != "failed" {
		t.Fatalf("expected failed allocation when helper cannot prove readiness, got %q", alloc.ClientStatus)
	}
	taskState := alloc.TaskStates["task"]
	if !taskState.Failed {
		t.Fatalf("expected failed task state when helper readiness fails, got %+v", taskState)
	}
	logs := stack.nomad.allocLogs(t, alloc.ID)
	if strings.Contains(logs, "WORKLOAD-STARTED") {
		t.Fatalf("did not expect workload to start before helper readiness, got %q", logs)
	}
}

func TestSubmitFlowHelperDeathIsTaskFatal(t *testing.T) {
	stack := startRuntimeIdentitySubmitStackWithOptions(t, submitStackOptions{
		baseImage:       "python:3.13-alpine",
		mockSPIREJWTTTL: 4 * time.Second,
	})

	publishSubmitArtifactArchive(t, stack, buildArchiveFromScript(t, `#!/usr/bin/env python3
import json
import os
import socket
import time
import urllib.parse

parsed = urllib.parse.urlparse(os.environ["EXEC_WORKLOAD_IDENTITY_ENDPOINT"])
socket_path = parsed.path
client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.settimeout(5)
client.connect(socket_path)
client.sendall((json.dumps({"kind": "jwt_svid", "target": "workload_vault"}) + "\n").encode("utf-8"))
response = b""
while b"\n" not in response:
    chunk = client.recv(4096)
    if not chunk:
        break
    response += chunk
client.close()
payload = json.loads(response.decode("utf-8").strip())
if not payload.get("jwt"):
    raise SystemExit("missing jwt")
print("WORKLOAD-STARTED", flush=True)
for i in range(30):
    print(f"WORKLOAD-HEARTBEAT:{i}", flush=True)
    time.sleep(1)
print("WORKLOAD-COMPLETE", flush=True)
`))

	response := submitExecutionRequest(t, stack, buildSubmitRequestBody(t, stack))
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}
	var payload admission.SubmitResult
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode submit response: %v", err)
	}

	jobID := stack.nomad.waitForExecutionJob(t, payload.RunID)
	alloc := stack.nomad.waitForLatestAllocation(t, jobID)
	stack.nomad.waitForAllocationLogsContaining(t, alloc.ID, "WORKLOAD-STARTED", 15*time.Second)
	stack.mockSPIRE.setFailFetch(true)

	terminalAlloc := stack.nomad.waitForTerminalAllocation(t, jobID)
	if terminalAlloc.ClientStatus != "failed" {
		t.Fatalf("expected helper death to fail the task, got %q", terminalAlloc.ClientStatus)
	}
	taskState := terminalAlloc.TaskStates["task"]
	if !taskState.Failed {
		t.Fatalf("expected task failure after helper death, got %+v", taskState)
	}
	logs := stack.nomad.allocLogs(t, terminalAlloc.ID)
	if !strings.Contains(logs, "WORKLOAD-STARTED") {
		t.Fatalf("expected workload to reach steady state before helper death, got %q", logs)
	}
	if strings.Contains(logs, "WORKLOAD-COMPLETE") {
		t.Fatalf("did not expect workload to continue after helper death, got %q", logs)
	}
}

func TestSubmitFlowRejectsWorkloadArchiveWithSymlinkEntry(t *testing.T) {
	stack := startRuntimeIdentitySubmitStackWithOptions(t, submitStackOptions{
		baseImage: "python:3.13-alpine",
	})

	entrypoint := archiveEntry{
		Name: "entrypoint",
		Mode: 0o755,
		Body: []byte("#!/bin/sh\necho WORKLOAD-STARTED\n"),
	}
	publishSubmitArtifactArchive(t, stack, buildArchiveWithEntries(t, []archiveEntry{
		entrypoint,
		{
			Name:     "escape",
			Typeflag: tar.TypeSymlink,
			Linkname: "/etc/passwd",
			Mode:     0o777,
		},
	}))

	// A link entry anywhere in a static-script archive makes the required
	// admission policy input unavailable: ES refuses before policy allow, run
	// assignment, materialization or provider registration
	// (.docs/execution_lifecycle/contracts.md, static-script policy input).
	response := submitExecutionRequest(t, stack, buildSubmitRequestBody(t, stack))
	defer response.Body.Close()
	body := strings.TrimSpace(string(mustReadBody(t, response.Body)))
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for symlink workload archive, got %d body=%s", response.StatusCode, body)
	}
	var refusal admission.ErrorResponse
	decoder := json.NewDecoder(strings.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&refusal); err != nil {
		t.Fatalf("decode refusal body: %v body=%s", err, body)
	}
	if refusal.Success || refusal.Code != "admission_policy_input_unavailable" || refusal.Error != "admission policy input unavailable" {
		t.Fatalf("unexpected refusal for symlink workload archive: %s", body)
	}
	if jobs := listNomadJobIDs(t, stack.nomad); len(jobs) != 0 {
		t.Fatalf("symlink workload archive reached Nomad registration: jobs=%v", jobs)
	}
	stageEntries, err := os.ReadDir(filepath.Join(stack.rootDir, "es-stage"))
	if err != nil {
		t.Fatalf("read staging root: %v", err)
	}
	for _, entry := range stageEntries {
		if strings.HasPrefix(entry.Name(), "run-") {
			t.Fatalf("symlink workload archive was materialized into run root %q", entry.Name())
		}
	}

	// Control: the same stack admits and runs the same archive without the link
	// entry, so the refusal above is caused by the link entry alone.
	publishSubmitArtifactArchive(t, stack, buildArchiveWithEntries(t, []archiveEntry{entrypoint}))
	controlResponse := submitExecutionRequest(t, stack, buildSubmitRequestBody(t, stack))
	defer controlResponse.Body.Close()
	if controlResponse.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202 for the archive without the link entry, got %d body=%s", controlResponse.StatusCode, strings.TrimSpace(string(mustReadBody(t, controlResponse.Body))))
	}
	var payload admission.SubmitResult
	if err := json.NewDecoder(controlResponse.Body).Decode(&payload); err != nil {
		t.Fatalf("decode submit response: %v", err)
	}
	alloc := stack.nomad.waitForTerminalExecutionAllocation(t, payload.RunID)
	if logs := stack.nomad.allocLogs(t, alloc.ID); !strings.Contains(logs, "WORKLOAD-STARTED") {
		t.Fatalf("expected the archive without the link entry to start, got status=%q logs=%q", alloc.ClientStatus, logs)
	}
}

// listNomadJobIDs returns every job the test's own Nomad agent knows.
func listNomadJobIDs(t *testing.T, harness *nomadHarness) []string {
	t.Helper()

	response, err := harness.httpClient(5 * time.Second).Get(harness.baseURL() + "/v1/jobs")
	if err != nil {
		t.Fatalf("list Nomad jobs: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("list Nomad jobs: status %d", response.StatusCode)
	}
	var payload []nomadJobListEntry
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode Nomad job list: %v", err)
	}
	ids := make([]string, 0, len(payload))
	for _, entry := range payload {
		ids = append(ids, strings.TrimSpace(entry.ID))
	}
	return ids
}

func TestSubmitFlowMountsGovernedArtifactAndLifecycleStillWorks(t *testing.T) {
	stack := startRuntimeIdentitySubmitStack(t)
	publishSubmitArtifactArchiveWithOptions(t, stack, buildArchiveFromScript(t, `#!/bin/sh
set -eu
echo START-BANNER
cat /execution/mounts/config/app.conf
echo "{\"status\":\"ok\",\"artifact_digest\":\"${EXEC_ARTIFACT_DIGEST}\"}"
`), publishSubmitArtifactOptions{mountTargets: []string{mountedSourceTarget}})
	mountArtifact := publishAuxiliaryArtifactArchive(t, stack, buildArchiveWithEntries(t, []archiveEntry{{Name: "app.conf", Mode: 0o644, Body: []byte(mountedSourceText)}}), "runtime-mount")
	response := submitExecutionRequest(t, stack, buildSubmitRequestBodyWithMounts(t, stack, []admission.RuntimeMount{{Source: admission.MountSource{ArtifactDigest: mountArtifact.ArtifactDigest}, TargetPath: mountedSourceTarget, ReadOnly: true}}))
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
	mountConfig := findTaskMountByTarget(t, job.taskConfig(t)["mounts"], mountedSourceTarget)
	if readonly, ok := mountConfig["readonly"].(bool); !ok || !readonly {
		t.Fatalf("expected readonly runtime mount config, got %#v", mountConfig["readonly"])
	}
	allocation := stack.nomad.waitForTerminalAllocation(t, jobID)
	if allocation.ClientStatus != "complete" {
		stdout, stdoutErr := stack.nomad.tryAllocLogs(allocation.ID)
		stderr, stderrErr := stack.nomad.tryAllocStderrLogs(allocation.ID)
		t.Fatal(formatMountFixtureAllocationFailure(allocation.ClientStatus, stdout, stdoutErr, stderr, stderrErr))
	}
	statusResponse := doJSONRequest(t, stack.es.Addr(), http.MethodGet, "/v1/executions/"+payload.RunID+"/status", stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "operator/local", false), nil)
	defer statusResponse.Body.Close()
	if statusResponse.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from status, got %d body=%s", statusResponse.StatusCode, strings.TrimSpace(string(mustReadBody(t, statusResponse.Body))))
	}
	logsResponse := doJSONRequest(t, stack.es.Addr(), http.MethodGet, "/v1/executions/"+payload.RunID+"/logs", stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "operator/local", false), nil)
	defer logsResponse.Body.Close()
	if logsResponse.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from logs, got %d body=%s", logsResponse.StatusCode, strings.TrimSpace(string(mustReadBody(t, logsResponse.Body))))
	}
	logs := string(mustReadBody(t, logsResponse.Body))
	if !strings.Contains(logs, "START-BANNER") || !strings.Contains(logs, "MOUNT-CONTENT") {
		t.Fatalf("expected mounted content in logs, got %q", logs)
	}
}

// This native qualification sibling subsumes the portable mount/lifecycle
// assertions above and adds the actual installed-source identity witness.
func TestSubmitFlowMountsGovernedArtifactAndLifecycleWithInstalledSourceIdentity(t *testing.T) {
	requireMountedSourceNativeCapabilities(t)
	envelope := requireMountedSourceWitnessEnvelope(t)
	capture := &mountedSourceRegistrationCapture{}
	stack := startRuntimeIdentitySubmitStackWithOptions(t, submitStackOptions{
		mountRegistrationCapture:         capture,
		mountedSourceDockerTaskNameLabel: true,
	})
	t.Cleanup(func() { _ = capture.close() })
	session := newMountedSourceWitnessSession(capture)
	session.cancelFunc = stack.nomad.cancelMountedJob
	t.Cleanup(func() {
		session.teardown()
		if session.stopResult == "request_failed" || session.stopResult == "request_unavailable" || session.jobCancelResult == "request_failed" || session.handleCloseResult == "failed" {
			t.Errorf("mount witness: task-owned teardown incomplete (stop=%s job=%s handles=%s)", session.stopResult, session.jobCancelResult, session.handleCloseResult)
		}
	})
	publishSubmitArtifactArchiveWithOptions(t, stack, buildArchiveFromScript(t, `#!/bin/sh
set -eu
printf 'MOUNT-OBSERVER-READY\n' > /execution/run/result/.mount-observer-ready
echo START-BANNER
cat /execution/mounts/config/app.conf
echo "{\"status\":\"ok\",\"artifact_digest\":\"${EXEC_ARTIFACT_DIGEST}\"}"
count=0
while [ ! -f /execution/run/result/.mount-observer-release ]; do
  count=$((count + 1))
  [ "$count" -lt 120 ] || exit 78
  sleep 1
done
`), publishSubmitArtifactOptions{mountTargets: []string{mountedSourceTarget}})

	mountArtifact := publishAuxiliaryArtifactArchive(t, stack, buildArchiveWithEntries(t, []archiveEntry{
		{
			Name: "app.conf",
			Mode: 0o644,
			Body: []byte("MOUNT-CONTENT\n"),
		},
	}), "runtime-mount")

	response := submitExecutionRequest(t, stack, buildSubmitRequestBodyWithMounts(t, stack, []admission.RuntimeMount{
		{
			Source: admission.MountSource{
				ArtifactDigest: mountArtifact.ArtifactDigest,
			},
			TargetPath: "/execution/mounts/config",
			ReadOnly:   true,
		},
	}))
	if response.StatusCode != http.StatusAccepted {
		_ = response.Body.Close()
		t.Fatal("mount witness: Submit was not accepted")
	}
	responseBytes, err := readMountedBounded(response.Body, 8*1024)
	if err != nil {
		t.Fatal("mount witness: bounded Submit receipt unavailable")
	}
	var payload admission.SubmitResult
	if json.Unmarshal(responseBytes, &payload) != nil || !validMountedRunID(payload.RunID) {
		t.Fatal("mount witness: malformed Submit receipt")
	}
	anchor, err := capture.require(payload.RunID)
	if err != nil {
		t.Fatalf("mount registration anchor: %v", err)
	}

	jobCtx, cancelJobRead := context.WithTimeout(context.Background(), 10*time.Second)
	_, err = stack.nomad.fetchMountedSourceJob(jobCtx, anchor)
	cancelJobRead()
	if err != nil {
		t.Fatalf("mount witness: bounded job observation failed: %v", err)
	}
	allocation, err := stack.nomad.waitForUniqueRunningMountedAllocation(anchor.jobID, anchor.taskName, 45*time.Second)
	if err != nil {
		t.Fatalf("mounted-source witness allocation: %v", err)
	}
	observation, err := observeMountedSourceIdentity(anchor, allocation, session)
	if err != nil {
		t.Fatalf("mounted-source witness observation: %v", err)
	}
	if err := compareMountedSourceIdentity(anchor, observation); err != nil {
		t.Fatalf("mounted-source witness comparison: %v", err)
	}
	if err := session.release(); err != nil {
		t.Fatalf("mounted-source witness barrier release: %v", err)
	}

	terminalAt, err := stack.nomad.waitForMountedTerminalAllocation(anchor, observation.allocationID, 45*time.Second)
	if err != nil {
		t.Fatalf("mount witness: bounded terminal observation failed: %v", err)
	}
	if err := session.markTerminal(terminalAt); err != nil {
		t.Fatal(err)
	}

	statusResponse := doJSONRequest(
		t,
		stack.es.Addr(),
		http.MethodGet,
		"/v1/executions/"+payload.RunID+"/status",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "operator/local", false),
		nil,
	)
	defer statusResponse.Body.Close()
	if statusResponse.StatusCode != http.StatusOK {
		t.Fatal("mount witness: status read failed")
	}

	logsResponse := doJSONRequest(
		t,
		stack.es.Addr(),
		http.MethodGet,
		"/v1/executions/"+payload.RunID+"/logs",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "operator/local", false),
		nil,
	)
	if logsResponse.StatusCode != http.StatusOK {
		_ = logsResponse.Body.Close()
		t.Fatal("mount witness: logs read failed")
	}
	logsBytes, err := readMountedBounded(logsResponse.Body, 64*1024)
	if err != nil {
		t.Fatal("mount witness: bounded lifecycle logs unavailable")
	}
	logs := string(logsBytes)
	if !strings.Contains(logs, "START-BANNER") || !strings.Contains(logs, "MOUNT-CONTENT") {
		t.Fatal("mount witness: required synthetic lifecycle logs absent")
	}
	if err := session.complete(); err != nil {
		t.Fatalf("mounted-source witness cleanup: %v", err)
	}
	logMountedSourceWitnessEvidence(t, envelope, anchor, observation, session)
}

func requireMountedSourceNativeCapabilities(t *testing.T) {
	t.Helper()
	socketInfo, err := os.Lstat("/var/run/docker.sock")
	if err != nil || socketInfo.Mode()&os.ModeSocket == 0 {
		t.Skip("mounted-source native witness not qualified by this test: direct Docker Unix socket unavailable")
	}
	if _, err := readMountedBootID(); err != nil {
		t.Skip("mounted-source native witness not qualified by this test: host boot ID unavailable")
	}
	requireSlice1RuntimeIdentityCapabilities(t)
}

func TestSubmitFlowRemovesRuntimeMountArchiveResidueAfterExtraction(t *testing.T) {
	stack := startSubmitStack(t)
	publishSubmitArtifactArchiveWithOptions(t, stack, buildArchiveFromScript(t, `#!/bin/sh
set -eu
echo START-BANNER
cat /execution/mounts/config/app.conf
echo "{\"status\":\"ok\",\"artifact_digest\":\"${EXEC_ARTIFACT_DIGEST}\"}"
`), publishSubmitArtifactOptions{mountTargets: []string{"/execution/mounts/config"}})

	mountArtifact := publishAuxiliaryArtifactArchive(t, stack, buildArchiveWithEntries(t, []archiveEntry{
		{
			Name: "app.conf",
			Mode: 0o644,
			Body: []byte("MOUNT-CONTENT\n"),
		},
	}), "runtime-mount")

	response := submitExecutionRequest(t, stack, buildSubmitRequestBodyWithMounts(t, stack, []admission.RuntimeMount{
		{
			Source: admission.MountSource{
				ArtifactDigest: mountArtifact.ArtifactDigest,
			},
			TargetPath: "/execution/mounts/config",
			ReadOnly:   true,
		},
	}))
	defer response.Body.Close()

	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}

	var payload admission.SubmitResult
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode submit response: %v", err)
	}

	job := stack.nomad.fetchExecutionJobDetail(t, payload.RunID)
	mountConfig := findTaskMountByTarget(t, job.taskConfig(t)["mounts"], "/execution/mounts/config")
	sourceDir, ok := mountConfig["source"].(string)
	if !ok || strings.TrimSpace(sourceDir) == "" {
		t.Fatalf("expected host source dir for staged runtime mount, got %#v", mountConfig["source"])
	}

	mountArchivePath := filepath.Join(filepath.Dir(sourceDir), "artifact.tar.gz")
	if _, err := os.Stat(mountArchivePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected extracted runtime mount archive residue to be removed, got err=%v", err)
	}
}

func TestSubmitRejectsMountArtifactWhenEvidenceBlobIsMissing(t *testing.T) {
	stack := startSubmitStackWithOptionsWithoutNomad(t, submitStackOptions{mountTargets: []string{"/execution/mounts/config"}})

	mountArtifact := publishAuxiliaryArtifactArchive(t, stack, buildArchiveWithEntries(t, []archiveEntry{
		{
			Name: "app.conf",
			Mode: 0o644,
			Body: []byte("MOUNT-CONTENT\n"),
		},
	}), "runtime-mount")

	discovery := stack.loadDiscovery(t, mountArtifact.ArtifactDigest)
	removeBlob(t, stack.arsRootDir, discovery.Evidence.Digest)

	response := submitExecutionRequest(t, stack, buildSubmitRequestBodyWithMounts(t, stack, []admission.RuntimeMount{
		{
			Source:     admission.MountSource{ArtifactDigest: mountArtifact.ArtifactDigest},
			TargetPath: "/execution/mounts/config",
			ReadOnly:   true,
		},
	}))
	defer response.Body.Close()

	assertErrorResponseCode(t, response, http.StatusServiceUnavailable, "artifact_evidence_unavailable")
}

func TestSubmitRejectsMountArtifactWithPathTraversalArchive(t *testing.T) {
	stack := startSubmitStackWithOptionsWithoutNomad(t, submitStackOptions{mountTargets: []string{"/execution/mounts/config"}})

	mountArtifact := publishAuxiliaryArtifactArchive(t, stack, buildArchiveWithEntries(t, []archiveEntry{
		{
			Name: "../escape",
			Mode: 0o644,
			Body: []byte("nope"),
		},
	}), "runtime-mount")

	response := submitExecutionRequest(t, stack, buildSubmitRequestBodyWithMounts(t, stack, []admission.RuntimeMount{
		{
			Source:     admission.MountSource{ArtifactDigest: mountArtifact.ArtifactDigest},
			TargetPath: "/execution/mounts/config",
			ReadOnly:   true,
		},
	}))
	defer response.Body.Close()

	assertErrorResponseCode(t, response, http.StatusConflict, "mount_artifact_invalid")
}

func TestSubmitRejectsMountArtifactWithSymlinkEscape(t *testing.T) {
	stack := startSubmitStackWithOptionsWithoutNomad(t, submitStackOptions{mountTargets: []string{"/execution/mounts/config"}})

	mountArtifact := publishAuxiliaryArtifactArchive(t, stack, buildArchiveWithEntries(t, []archiveEntry{
		{
			Name:     "link",
			Typeflag: tar.TypeSymlink,
			Linkname: "/etc/passwd",
			Mode:     0o777,
		},
	}), "runtime-mount")

	response := submitExecutionRequest(t, stack, buildSubmitRequestBodyWithMounts(t, stack, []admission.RuntimeMount{
		{
			Source:     admission.MountSource{ArtifactDigest: mountArtifact.ArtifactDigest},
			TargetPath: "/execution/mounts/config",
			ReadOnly:   true,
		},
	}))
	defer response.Body.Close()

	assertErrorResponseCode(t, response, http.StatusConflict, "mount_artifact_invalid")
}

func TestSubmitRejectsMountArtifactThatExceedsSizeLimit(t *testing.T) {
	stack := startSubmitStackWithOptionsWithoutNomad(t, submitStackOptions{mountTargets: []string{"/execution/mounts/config"}})

	mountArtifact := publishAuxiliaryArtifactArchive(t, stack, buildArchiveWithEntries(t, []archiveEntry{
		{
			Name: "large.bin",
			Mode: 0o644,
			Body: bytes.Repeat([]byte("a"), 9<<20),
		},
	}), "runtime-mount")

	response := submitExecutionRequest(t, stack, buildSubmitRequestBodyWithMounts(t, stack, []admission.RuntimeMount{
		{
			Source:     admission.MountSource{ArtifactDigest: mountArtifact.ArtifactDigest},
			TargetPath: "/execution/mounts/config",
			ReadOnly:   true,
		},
	}))
	defer response.Body.Close()

	assertErrorResponseCode(t, response, http.StatusConflict, "mount_artifact_invalid")
}

// The stack publishes through the real AGS, so these cases check that the
// mount_targets AGS signs is what ES reads back from the evidence. ES refuses
// before it reads the mount artifact or contacts Nomad: the stack's Nomad
// stand-in fails the test on any call.
func TestSubmitRefusesAMountTheSignedArtifactDoesNotDeclare(t *testing.T) {
	for _, testCase := range []struct {
		name         string
		mountTargets []string
	}{
		{name: "no mount_targets", mountTargets: nil},
		{name: "empty mount_targets", mountTargets: []string{}},
		{name: "another target declared", mountTargets: []string{"/execution/mounts/data"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			stack := startSubmitStackWithOptionsWithoutNomad(t, submitStackOptions{mountTargets: testCase.mountTargets})
			mountArtifact := publishAuxiliaryArtifactArchive(t, stack, buildArchiveWithEntries(t, []archiveEntry{
				{Name: "app.conf", Mode: 0o644, Body: []byte("MOUNT-CONTENT\n")},
			}), "runtime-mount")
			discovery := stack.loadDiscovery(t, mountArtifact.ArtifactDigest)
			// With the mount artifact's evidence gone, a Submit that read
			// it would fail with 503 artifact_evidence_unavailable instead.
			removeBlob(t, stack.arsRootDir, discovery.Evidence.Digest)

			response := submitExecutionRequest(t, stack, buildSubmitRequestBodyWithMounts(t, stack, []admission.RuntimeMount{
				{
					Source:     admission.MountSource{ArtifactDigest: mountArtifact.ArtifactDigest},
					TargetPath: "/execution/mounts/config",
					ReadOnly:   true,
				},
			}))
			defer response.Body.Close()

			body := strings.TrimSpace(string(mustReadBody(t, response.Body)))
			if response.StatusCode != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d body=%s", response.StatusCode, body)
			}
			var payload admission.ErrorResponse
			if err := json.Unmarshal([]byte(body), &payload); err != nil {
				t.Fatalf("decode error response: %v body=%s", err, body)
			}
			if payload.Code != "invalid_request" || !strings.Contains(payload.Error, "mount target_path is not declared by the runtime interface: /execution/mounts/config") {
				t.Fatalf("expected the undeclared mount target refusal, got %s", body)
			}
		})
	}
}

func TestSubmitRejectsOverlappingMountTargets(t *testing.T) {
	// Both targets are declared, so the refusal comes from the overlap and
	// not from the declaration check.
	stack := startSubmitStackWithOptionsWithoutNomad(t, submitStackOptions{mountTargets: []string{"/execution/mounts/config", "/execution/mounts/config/sub"}})

	response := submitExecutionRequest(t, stack, buildSubmitRequestBodyWithMounts(t, stack, []admission.RuntimeMount{
		{
			Source:     admission.MountSource{ArtifactDigest: stack.publishResponse.ArtifactDigest},
			TargetPath: "/execution/mounts/config",
			ReadOnly:   true,
		},
		{
			Source:     admission.MountSource{ArtifactDigest: stack.publishResponse.ArtifactDigest},
			TargetPath: "/execution/mounts/config/sub",
			ReadOnly:   true,
		},
	}))
	defer response.Body.Close()

	assertErrorResponseCode(t, response, http.StatusConflict, "mount_conflict")
}

type submitStack struct {
	fixture    *tlsFixture
	rootDir    string
	arsRootDir string
	indexPath  string

	publishCallerPath   string
	executionCallerPath string

	nomad       *nomadHarness
	nomadServer *httptest.Server
	mockSPIRE   *mockWorkloadAPIServer

	ars *arsapp.App
	egs *egsapp.App
	ags *agsapp.App
	es  *esapp.App

	arsRunning bool
	egsRunning bool
	agsRunning bool
	esRunning  bool

	publishResponse         submitPublishResponse
	intentDigest            string
	derivationSpecDigest    string
	outputID                string
	workloadZoneVaultDigest string
}

type submitPublishResponse struct {
	Published      bool   `json:"published"`
	ArtifactDigest string `json:"artifact_digest"`
}

type submitStackOptions struct {
	networkAccess                    bool
	baseImage                        string
	runtimeIdentityTmpfsSize         int64
	mockSPIREJWTTTL                  time.Duration
	mockSPIREFetchError              bool
	workloadVaultAddress             string
	workloadVaultCABundlePEM         string
	allowedAGSCallerPrefixes         []string
	allowedExecutionCallerPrefixes   []string
	publishCallerPath                string
	executionCallerPath              string
	nomadHandler                     http.Handler
	mountRegistrationCapture         *mountedSourceRegistrationCapture
	mountedSourceDockerTaskNameLabel bool
	// nomadACLDisabled starts the stack's real Nomad without ACLs.
	nomadACLDisabled bool
	// nomadESConfig, when set, changes ES's Nomad config after the stack
	// fills it in (for example a pin for another key).
	nomadESConfig func(*esconfig.NomadConfig)
	// mountTargets, when set, is the signed mount_targets list of the
	// stack's default artifact. Unset, that artifact declares none and ES
	// admits no caller mount against it.
	mountTargets []string
}

func (opts submitStackOptions) nomadHarnessOptions() nomadHarnessOptions {
	return nomadHarnessOptions{dockerTaskNameLabel: opts.mountedSourceDockerTaskNameLabel, aclDisabled: opts.nomadACLDisabled}
}

func startSubmitStack(t *testing.T) *submitStack {
	return startSubmitStackWithOptions(t, submitStackOptions{})
}

func startSubmitStackWithNetworkAccess(t *testing.T, networkAccess bool) *submitStack {
	return startSubmitStackWithOptions(t, submitStackOptions{networkAccess: networkAccess})
}

func startSubmitStackWithoutNomad(t *testing.T) *submitStack {
	t.Helper()
	return startSubmitStackWithOptionsWithoutNomad(t, submitStackOptions{})
}

func startSubmitStackWithOptionsWithoutNomad(t *testing.T, opts submitStackOptions) *submitStack {
	t.Helper()
	opts.nomadHandler = unexpectedNomadDependencyHandler()
	return startSubmitStackWithOptions(t, opts)
}

func startSubmitStackWithNomadHandler(t *testing.T, opts submitStackOptions, handler http.Handler) *submitStack {
	t.Helper()
	opts.nomadHandler = handler
	return startSubmitStackWithOptions(t, opts)
}

func TestPrepareSubmitStackExecutionRootsCreatesIndependentEmptyRoots(t *testing.T) {
	rootDir := newExecutionWorkspaceTempDir(t, "es-submit-root-fixture-")
	rootInfo, err := os.Lstat(rootDir)
	if err != nil {
		t.Fatalf("lstat fixture workspace root: %v", err)
	}
	rootUID, rootGID := fixtureOwnerIDs(t, rootInfo)

	stagingRoot, resultsRoot := prepareSubmitStackExecutionRoots(t, rootDir)
	if stagingRoot != filepath.Join(rootDir, "es-stage") {
		t.Fatalf("staging root = %q, want %q", stagingRoot, filepath.Join(rootDir, "es-stage"))
	}
	if resultsRoot != filepath.Join(rootDir, "es-results") {
		t.Fatalf("results root = %q, want %q", resultsRoot, filepath.Join(rootDir, "es-results"))
	}

	infos := make(map[string]os.FileInfo, 2)
	for label, root := range map[string]string{
		"staging": stagingRoot,
		"results": resultsRoot,
	} {
		info, err := os.Lstat(root)
		if err != nil {
			t.Fatalf("lstat %s execution root: %v", label, err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("%s execution root mode = %v, want a real directory", label, info.Mode())
		}
		if got := info.Mode().Perm(); got != 0o755 {
			t.Fatalf("%s execution root mode = %04o, want 0755", label, got)
		}
		uid, gid := fixtureOwnerIDs(t, info)
		if uid != rootUID || gid != rootGID {
			t.Fatalf("%s execution root owner = %d:%d, want fixture owner %d:%d", label, uid, gid, rootUID, rootGID)
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatalf("read %s execution root: %v", label, err)
		}
		if len(entries) != 0 {
			t.Fatalf("%s execution root entries = %v, want empty root", label, entries)
		}
		infos[label] = info
	}
	if os.SameFile(infos["staging"], infos["results"]) {
		t.Fatal("staging and results execution roots resolve to the same filesystem object")
	}
}

func prepareSubmitStackExecutionRoots(t *testing.T, rootDir string) (string, string) {
	t.Helper()

	stagingRoot := filepath.Join(rootDir, "es-stage")
	resultsRoot := filepath.Join(rootDir, "es-results")
	if err := os.Mkdir(stagingRoot, 0o755); err != nil {
		t.Fatalf("create empty staging execution root: %v", err)
	}
	if err := os.Mkdir(resultsRoot, 0o755); err != nil {
		if cleanupErr := os.Remove(stagingRoot); cleanupErr != nil {
			t.Fatalf("create empty results execution root: %v; remove newly created staging execution root: %v", err, cleanupErr)
		}
		t.Fatalf("create empty results execution root: %v", err)
	}
	for _, root := range []string{stagingRoot, resultsRoot} {
		if err := os.Chmod(root, 0o755); err != nil {
			t.Fatalf("set exact mode on test-owned execution root: %v", err)
		}
	}
	return stagingRoot, resultsRoot
}

func newSubmitStackSyntheticRetainedResultAuth(t *testing.T, rootDir string) esconfig.RetainedResultAuthConfig {
	t.Helper()
	keyDir := filepath.Join(rootDir, "es-auth")
	if err := os.Mkdir(keyDir, 0o700); err != nil {
		t.Fatalf("create synthetic result auth directory: %v", err)
	}
	keyPath := filepath.Join(keyDir, "key")
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{0x53}, 32), 0o600); err != nil {
		t.Fatalf("write synthetic result auth key: %v", err)
	}
	return esconfig.RetainedResultAuthConfig{StoreID: "test_store", KeyID: "test_key", KeyFile: keyPath}
}

func TestRetainedResultReviewLegacySubmitFixtureAuthSetup(t *testing.T) {
	rootDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	stage, results := prepareSubmitStackExecutionRoots(t, rootDir)
	auth := newSubmitStackSyntheticRetainedResultAuth(t, rootDir)
	cfg := esconfig.ExecutionConfig{
		StagingRootDir: stage, ResultsRootDir: results,
		RetainedResultAuth:         auth,
		BaseImage:                  "alpine:3.20",
		RuntimeSupportBinary:       "/synthetic/es-runtime-support",
		SPIREWorkloadAPISocketPath: "/synthetic/spire-agent.sock",
	}
	if err := cfg.Validate("execution"); err != nil {
		t.Fatalf("shared submit fixture authentication config: %v", err)
	}
	info, err := os.Lstat(auth.KeyFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() != 32 {
		t.Fatalf("shared submit fixture key has invalid shape: info=%v err=%v", info, err)
	}
	if auth.StoreID != "test_store" || auth.KeyID != "test_key" ||
		strings.HasPrefix(auth.KeyFile, stage+string(os.PathSeparator)) ||
		strings.HasPrefix(auth.KeyFile, results+string(os.PathSeparator)) {
		t.Fatal("shared submit fixture authentication is not independent of execution roots")
	}
}

func fixtureOwnerIDs(t *testing.T, info os.FileInfo) (uint32, uint32) {
	t.Helper()

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("filesystem metadata for %q does not expose Unix ownership", info.Name())
	}
	return stat.Uid, stat.Gid
}

func startSubmitStackWithOptions(t *testing.T, opts submitStackOptions) *submitStack {
	t.Helper()
	rootDir := newExecutionWorkspaceTempDir(t, "es-submit-")
	stagingRoot, resultsRoot := prepareSubmitStackExecutionRoots(t, rootDir)
	resultAuth := newSubmitStackSyntheticRetainedResultAuth(t, rootDir)
	fixture := newTLSFixture(t)
	var nomad *nomadHarness
	var nomadServer *httptest.Server
	var nomadTLS nomadTLSMaterial
	nomadBaseURL := ""
	nomadTokenFile := ""
	if opts.nomadHandler != nil {
		// The stand-in presents a certificate from the setup script's issuer,
		// so ES's HTTPS checks pass exactly as they do for a real Nomad.
		var err error
		if nomadTLS, err = issueNomadTLSMaterial(filepath.Join(rootDir, "nomad-tls")); err != nil {
			t.Fatal(err)
		}
		if nomadServer, err = nomadTLS.startTLSServer(lockedFakeNomadHandler(opts.nomadHandler)); err != nil {
			t.Fatalf("start fake nomad: %v", err)
		}
		nomadBaseURL = nomadServer.URL
		nomadTokenFile = writeFakeNomadTokenFile(t, rootDir)
	} else {
		requireHealthyDockerBackedNomadClient(t)
		nomad = startNomadHarnessWithOptions(t, rootDir, opts.nomadHarnessOptions())
		nomadTLS = nomad.tls
		nomadBaseURL = nomad.baseURL()
		nomadTokenFile = nomad.esTokenFile
		if opts.mountRegistrationCapture != nil {
			proxy, proxyErr := newMountedSourceRegistrationProxy(nomadBaseURL, nomadTLS, stagingRoot, opts.mountRegistrationCapture)
			if proxyErr != nil {
				t.Fatalf("build mounted-source registration proxy: %v", proxyErr)
			}
			nomadServer = proxy
			nomadBaseURL = proxy.URL
		}
	}
	runtimeSupportBinary := buildRuntimeSupportBinary(t, rootDir)
	mockSPIRE := startMockWorkloadAPIServer(t, rootDir, mockWorkloadAPIServerOptions{
		jwtTTL:    firstNonZeroDuration(opts.mockSPIREJWTTTL, 20*time.Second),
		failFetch: opts.mockSPIREFetchError,
	})

	arsRootDir := filepath.Join(rootDir, "ars-storage")
	if err := os.MkdirAll(arsRootDir, 0o755); err != nil {
		t.Fatalf("mkdir ars storage root: %v", err)
	}
	indexPath := filepath.Join(rootDir, "artifact-index.json")
	if err := os.WriteFile(indexPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write empty artifact index: %v", err)
	}

	vaultConfig := map[string]any{
		"address":      firstNonEmpty(opts.workloadVaultAddress, "https://vault.internal:8200"),
		"auth_mount":   "jwt",
		"auth_role":    "service_execution",
		"jwt_audience": "vault",
	}
	if strings.TrimSpace(opts.workloadVaultCABundlePEM) != "" {
		vaultConfig["ca_bundle_pem"] = opts.workloadVaultCABundlePEM
	}
	workloadZoneVaultBytes := mustMarshalJSON(t, map[string]any{
		"vault_config": vaultConfig,
	})
	workloadZoneVaultDigest := writeBlobBytes(t, arsRootDir, workloadZoneVaultBytes)

	allowedAGSCallerPrefixes := []string{"operator/local"}
	if len(opts.allowedAGSCallerPrefixes) > 0 {
		allowedAGSCallerPrefixes = append([]string(nil), opts.allowedAGSCallerPrefixes...)
	}
	allowedExecutionCallerPrefixes := []string{"operator/local"}
	if len(opts.allowedExecutionCallerPrefixes) > 0 {
		allowedExecutionCallerPrefixes = append([]string(nil), opts.allowedExecutionCallerPrefixes...)
	}
	publishCallerPath := firstNonEmpty(opts.publishCallerPath, "operator/local")
	executionCallerPath := firstNonEmpty(opts.executionCallerPath, "operator/local")

	stack := &submitStack{
		fixture:                 fixture,
		rootDir:                 rootDir,
		arsRootDir:              arsRootDir,
		indexPath:               indexPath,
		publishCallerPath:       publishCallerPath,
		executionCallerPath:     executionCallerPath,
		nomad:                   nomad,
		nomadServer:             nomadServer,
		mockSPIRE:               mockSPIRE,
		intentDigest:            labeledDigest("aa"),
		derivationSpecDigest:    labeledDigest("bb"),
		outputID:                "runtime",
		workloadZoneVaultDigest: workloadZoneVaultDigest,
	}

	arsCfg := arsconfig.Config{
		HTTP: arsconfig.HTTPConfig{
			BindAddress:            "127.0.0.1",
			Port:                   0,
			ReadTimeoutSeconds:     5,
			WriteTimeoutSeconds:    5,
			ShutdownTimeoutSeconds: 5,
		},
		TLS: arsconfig.TLSConfig{
			CertFile:     fixture.arsServerCertPath,
			KeyFile:      fixture.arsServerKeyPath,
			ClientCAFile: fixture.clientCAPath,
		},
		Security: arsconfig.SecurityConfig{
			BootstrapIssuerCommonName: fixture.bootstrapCACN,
		},
		Authorization: arsconfig.AuthorizationConfig{
			AllowedSPIFFEPathPrefixes: []string{"service/execution"},
		},
		Storage: arsconfig.StorageConfig{
			RootDir:   arsRootDir,
			IndexFile: indexPath,
		},
	}
	arsService, err := arsapp.New(arsCfg)
	if err != nil {
		t.Fatalf("build ars app: %v", err)
	}
	stack.ars = arsService
	startService(t, arsService.Start, arsService.Addr, fixture.clientTLSConfigForServer(t, fixture.arsServerName, "service/execution", false))
	stack.arsRunning = true

	egsCfg := egsconfig.Config{
		HTTP: egsconfig.HTTPConfig{
			BindAddress:            "127.0.0.1",
			Port:                   0,
			ReadTimeoutSeconds:     5,
			WriteTimeoutSeconds:    5,
			ShutdownTimeoutSeconds: 5,
		},
		TLS: egsconfig.TLSConfig{
			CertFile:     fixture.egsServerCertPath,
			KeyFile:      fixture.egsServerKeyPath,
			ClientCAFile: fixture.clientCAPath,
		},
		Security: egsconfig.SecurityConfig{
			BootstrapIssuerCommonName: fixture.bootstrapCACN,
		},
		Signer: egsconfig.SignerConfig{
			Algorithm:     "ed25519",
			KeyID:         fixture.egsKeyID,
			PrivateKeyHex: fixture.egsPrivateKeyHex,
			PublicKeyHex:  fixture.egsPublicKeyHex,
		},
		RuntimeTrust: egsmodel.RuntimeTrustPolicy{
			SignerPolicy: egsmodel.SignerPolicy{
				AllowedSigners: []string{fixture.agsKeyID},
				RevokedSigners: []string{},
			},
			ArtifactPolicy: egsmodel.ArtifactPolicy{
				RevokedArtifacts: []string{},
			},
		},
		Publication: egsmodel.PublicationMetadata{
			UpdateRevision: 7,
			Version:        "1.0.0",
		},
	}
	egsService, err := egsapp.New(egsCfg)
	if err != nil {
		t.Fatalf("build egs app: %v", err)
	}
	stack.egs = egsService
	startService(t, egsService.Start, egsService.Addr, fixture.clientTLSConfigForServer(t, fixture.egsServerName, "service/execution", false))
	stack.egsRunning = true

	agsCfg := agsconfig.Config{
		HTTP: agsconfig.HTTPConfig{
			BindAddress:            "127.0.0.1",
			Port:                   0,
			ReadTimeoutSeconds:     5,
			WriteTimeoutSeconds:    5,
			ShutdownTimeoutSeconds: 5,
		},
		TLS: agsconfig.TLSConfig{
			CertFile:     fixture.agsServerCertPath,
			KeyFile:      fixture.agsServerKeyPath,
			ClientCAFile: fixture.clientCAPath,
		},
		Security: agsconfig.SecurityConfig{
			BootstrapIssuerCommonName: fixture.bootstrapCACN,
		},
		Authorization: agsconfig.AuthorizationConfig{
			AllowedSPIFFEPathPrefixes: allowedAGSCallerPrefixes,
		},
		Dependencies: agsconfig.DependenciesConfig{
			ArtifactRegistry: agsconfig.DependencyConfig{
				BaseURL:        "https://" + stack.ars.Addr(),
				ServerName:     fixture.arsServerName,
				ClientCertFile: fixture.agsClientCertPath,
				ClientKeyFile:  fixture.agsClientKeyPath,
				RootCAFile:     fixture.runtimeCAPath,
				TimeoutSeconds: 5,
			},
		},
		Signer: agsconfig.SignerConfig{
			Algorithm:     "ed25519",
			KeyID:         fixture.agsKeyID,
			PrivateKeyHex: fixture.agsPrivateKeyHex,
			PublicKeyHex:  fixture.agsPublicKeyHex,
		},
	}
	agsService, err := agsapp.New(agsCfg)
	if err != nil {
		t.Fatalf("build ags app: %v", err)
	}
	stack.ags = agsService
	startService(t, agsService.Start, agsService.Addr, fixture.clientTLSConfigForServer(t, fixture.agsServerName, "operator/local", false))
	stack.agsRunning = true

	esCfg := esconfig.Config{
		HTTP: esconfig.HTTPConfig{
			BindAddress:            "127.0.0.1",
			Port:                   0,
			ReadTimeoutSeconds:     5,
			WriteTimeoutSeconds:    5,
			ShutdownTimeoutSeconds: 5,
		},
		TLS: esconfig.TLSConfig{
			CertFile:     fixture.esServerCertPath,
			KeyFile:      fixture.esServerKeyPath,
			ClientCAFile: fixture.clientCAPath,
		},
		Security: esconfig.SecurityConfig{
			BootstrapIssuerCommonName: fixture.bootstrapCACN,
		},
		Authorization: esconfig.AuthorizationConfig{
			AllowedSPIFFEPathPrefixes: allowedExecutionCallerPrefixes,
		},
		Dependencies: esconfig.DependenciesConfig{
			ArtifactRegistry: esconfig.DependencyConfig{
				BaseURL:        "https://" + stack.ars.Addr(),
				ServerName:     fixture.arsServerName,
				ClientCertFile: fixture.executionClientCertPath,
				ClientKeyFile:  fixture.executionClientKeyPath,
				RootCAFile:     fixture.runtimeCAPath,
				TimeoutSeconds: 5,
			},
			ExecutionGovernance: esconfig.DependencyConfig{
				BaseURL:        "https://" + stack.egs.Addr(),
				ServerName:     fixture.egsServerName,
				ClientCertFile: fixture.executionClientCertPath,
				ClientKeyFile:  fixture.executionClientKeyPath,
				RootCAFile:     fixture.runtimeCAPath,
				TimeoutSeconds: 5,
			},
		},
		RuntimeConfig: esconfig.RuntimeConfigConfig{
			WorkloadZoneVaultConfigRef: runtimeconfigv1.WorkloadZoneVaultConfigRef{
				Digest: workloadZoneVaultDigest,
			},
		},
		Verification: esconfig.VerificationConfig{
			TrustModel: esconfig.SignerVerifierConfig{
				Algorithm:    "ed25519",
				KeyID:        fixture.egsKeyID,
				PublicKeyHex: fixture.egsPublicKeyHex,
			},
			Provenance: esconfig.SignerVerifierConfig{
				Algorithm:    "ed25519",
				KeyID:        fixture.agsKeyID,
				PublicKeyHex: fixture.agsPublicKeyHex,
			},
			DerivationAttestation: esconfig.SignerVerifierConfig{
				Algorithm:    "ed25519",
				KeyID:        fixture.agsKeyID,
				PublicKeyHex: fixture.agsPublicKeyHex,
			},
			WorkloadIdentityBinding: esconfig.SignerVerifierConfig{
				Algorithm:    "ed25519",
				KeyID:        fixture.agsKeyID,
				PublicKeyHex: fixture.agsPublicKeyHex,
			},
		},
		WorkloadVaultAuth: esconfig.WorkloadVaultAuthConfig{
			DefaultMode: esconfig.WorkloadVaultAuthModeVaultIdentityJWT,
		},
		Nomad: nomadTLS.esNomadConfig(nomadBaseURL, nomadTokenFile),
		Execution: esconfig.ExecutionConfig{
			StagingRootDir:             stagingRoot,
			ResultsRootDir:             resultsRoot,
			RetainedResultAuth:         resultAuth,
			BaseImage:                  firstNonEmpty(opts.baseImage, "alpine:3.20"),
			RuntimeIdentityTmpfsSize:   opts.runtimeIdentityTmpfsSize,
			RuntimeSupportBinary:       runtimeSupportBinary,
			SPIREWorkloadAPISocketPath: mockSPIRE.socketPath,
		},
	}
	if opts.nomadESConfig != nil {
		opts.nomadESConfig(&esCfg.Nomad)
	}
	esService, err := esapp.New(esCfg)
	if err != nil {
		t.Fatalf("build es app: %v", err)
	}
	stack.es = esService
	startService(t, esService.Start, esService.Addr, fixture.clientTLSConfigForServer(t, fixture.esServerName, "operator/local", false))
	stack.esRunning = true

	publishSubmitArtifact(t, stack, opts.networkAccess, opts.mountTargets)

	t.Cleanup(func() { stack.shutdownAll(t) })
	return stack
}

func firstNonEmpty(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func firstNonZeroDuration(value time.Duration, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return value
}

func startRuntimeIdentitySubmitStack(t *testing.T) *submitStack {
	t.Helper()
	requireSlice1RuntimeIdentityCapabilities(t)
	return startSubmitStack(t)
}

func startRuntimeIdentitySubmitStackWithOptions(t *testing.T, opts submitStackOptions) *submitStack {
	t.Helper()
	requireSlice1RuntimeIdentityCapabilities(t)
	return startSubmitStackWithOptions(t, opts)
}

func startRuntimeIdentitySubmitStackWithNetworkAccess(t *testing.T, networkAccess bool) *submitStack {
	t.Helper()
	requireSlice1RuntimeIdentityCapabilities(t)
	return startSubmitStackWithNetworkAccess(t, networkAccess)
}

func requireHealthyDockerDaemon(t *testing.T) {
	t.Helper()

	if reason := dockerDaemonCapabilityReason(); reason != "" {
		t.Skip(dockerDaemonCapabilitySkipReason(reason))
	}
}

func dockerDaemonCapabilityReason() string {
	dockerDaemonCapabilityProbe.once.Do(func() {
		dockerDaemonCapabilityProbe.reason = probeHealthyDockerDaemonCapability()
	})
	return dockerDaemonCapabilityProbe.reason
}

func requireHealthyDockerBackedNomadClient(t *testing.T) {
	t.Helper()

	dockerBackedNomadCapabilityProbe.once.Do(func() {
		dockerBackedNomadCapabilityProbe.reason = probeHealthyDockerBackedNomadClientCapability()
	})
	if reason := dockerBackedNomadCapabilityProbe.reason; reason != "" {
		t.Skip(reason)
	}
}

func probeHealthyDockerDaemonCapability() string {
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Sprintf("docker binary lookup failed: %v", err)
	}
	if output, err := exec.Command("docker", "info").CombinedOutput(); err != nil {
		return fmt.Sprintf("docker daemon probe failed: %v output=%s", err, strings.TrimSpace(string(output)))
	}
	return ""
}

func probeHealthyDockerBackedNomadClientCapability() string {
	if reason := dockerDaemonCapabilityReason(); reason != "" {
		return reason
	}
	if _, err := exec.LookPath("nomad"); err != nil {
		return fmt.Sprintf("nomad binary lookup failed: %v", err)
	}

	probeWorkspace, err := runtimeIdentityCapabilityProbeWorkspace()
	if err != nil {
		return fmt.Sprintf("create Nomad capability probe workspace: %v", err)
	}
	defer os.RemoveAll(probeWorkspace)

	harness, reason := startNomadHarnessForCapabilityProbe(probeWorkspace)
	if reason != "" {
		return reason
	}
	harness.stop()
	return ""
}

func requireSlice1RuntimeIdentityCapabilities(t *testing.T) {
	t.Helper()
	requireHealthyDockerBackedNomadClient(t)

	slice1RuntimeIdentityCapabilityProbe.once.Do(func() {
		probeRoot, err := socketTestRootDirPath()
		if err != nil {
			slice1RuntimeIdentityCapabilityProbe.reason = runtimeIdentityCapabilitySkipReason(fmt.Sprintf("socket probe root unavailable: %v", err))
			return
		}
		if err := os.MkdirAll(probeRoot, 0o755); err != nil {
			slice1RuntimeIdentityCapabilityProbe.reason = runtimeIdentityCapabilitySkipReason(fmt.Sprintf("create socket probe root: %v", err))
			return
		}
		socketDir, err := os.MkdirTemp(probeRoot, "execution-substrate-socket-probe-")
		if err != nil {
			slice1RuntimeIdentityCapabilityProbe.reason = runtimeIdentityCapabilitySkipReason(fmt.Sprintf("create socket probe dir: %v", err))
			return
		}
		defer os.RemoveAll(socketDir)

		socketPath := filepath.Join(socketDir, "spire-agent.sock")
		listener, err := net.Listen("unix", socketPath)
		if err != nil {
			slice1RuntimeIdentityCapabilityProbe.reason = runtimeIdentityCapabilitySkipReason(fmt.Sprintf("listen on socket probe path: %v", err))
			return
		}
		defer listener.Close()
		go acceptRuntimeIdentitySocketProbeConnections(listener)

		if reason := probeDockerRuntimeIdentitySocketMount(socketDir); reason != "" {
			slice1RuntimeIdentityCapabilityProbe.reason = runtimeIdentityCapabilitySkipReason(reason)
			return
		}

		probeWorkspace, err := runtimeIdentityCapabilityProbeWorkspace()
		if err != nil {
			slice1RuntimeIdentityCapabilityProbe.reason = runtimeIdentityCapabilitySkipReason(fmt.Sprintf("create Nomad allocation probe workspace: %v", err))
			return
		}
		defer os.RemoveAll(probeWorkspace)

		if reason := probeNomadRuntimeIdentitySocketAllocation(probeWorkspace, socketDir); reason != "" {
			slice1RuntimeIdentityCapabilityProbe.reason = runtimeIdentityCapabilitySkipReason(reason)
			return
		}
	})

	if slice1RuntimeIdentityCapabilityProbe.reason != "" {
		t.Skip(slice1RuntimeIdentityCapabilityProbe.reason)
	}
}

func runtimeIdentityCapabilitySkipReason(detail string) string {
	detail = strings.TrimSpace(detail)
	if runtimeIdentityProbeLooksLikeDockerDesktopMacOS(detail) {
		return runtimeIdentityCapabilitySkipPrefix + "; Docker Desktop/macOS failed capability probe: " + detail
	}
	if detail == "" {
		return runtimeIdentityCapabilitySkipPrefix + "; capability probe failed"
	}
	return runtimeIdentityCapabilitySkipPrefix + "; capability probe failed: " + detail
}

func dockerBackedNomadCapabilitySkipReason(detail string) string {
	if strings.TrimSpace(detail) == "" {
		return dockerBackedNomadCapabilitySkipPrefix + "; capability probe failed"
	}
	return dockerBackedNomadCapabilitySkipPrefix + "; capability probe failed: " + detail
}

func dockerDaemonCapabilitySkipReason(detail string) string {
	if strings.TrimSpace(detail) == "" {
		return dockerDaemonCapabilitySkipPrefix + "; capability probe failed"
	}
	return dockerDaemonCapabilitySkipPrefix + "; capability probe failed: " + detail
}

func runtimeIdentityProbeLooksLikeDockerDesktopMacOS(detail string) bool {
	lower := strings.ToLower(detail)
	return strings.Contains(detail, "OSError: [Errno 95]") ||
		strings.Contains(detail, "Errno 95") ||
		strings.Contains(lower, "not supported")
}

func unexpectedNomadDependencyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "test unexpectedly reached Nomad dependency; this scenario should not require a healthy Docker-backed Nomad client", http.StatusServiceUnavailable)
	})
}

func missingExecutionNomadHandler(runID string) http.Handler {
	jobID := "exec-" + strings.TrimSpace(runID)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/job/"+jobID {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "test unexpectedly reached Nomad dependency; this scenario should only probe a missing execution lookup", http.StatusServiceUnavailable)
	})
}

func acceptRuntimeIdentitySocketProbeConnections(listener net.Listener) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		_ = connection.Close()
	}
}

func probeDockerRuntimeIdentitySocketMount(socketDir string) string {
	command := exec.Command("docker", "run", "--rm",
		"--tmpfs", "/runtime:rw,size=1048576",
		"--mount", "type=bind,src="+socketDir+",dst=/runtime/internal/source",
		"python:3.13-alpine",
		"sh", "-ceu", runtimeIdentitySocketProbeScript("DOCKER-RUNTIME-IDENTITY-SOCKET-PROBE-OK"),
	)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Docker bind-mounted SPIRE socket source directory probe failed: %v output=%s", err, strings.TrimSpace(string(output)))
	}
	if !strings.Contains(string(output), "DOCKER-RUNTIME-IDENTITY-SOCKET-PROBE-OK") {
		return fmt.Sprintf("Docker bind-mounted SPIRE socket source directory probe did not report success output=%s", strings.TrimSpace(string(output)))
	}
	return ""
}

func probeNomadRuntimeIdentitySocketAllocation(rootDir string, socketDir string) string {
	harness, reason := startNomadHarnessForCapabilityProbe(rootDir)
	if reason != "" {
		return fmt.Sprintf("Nomad Docker allocation execution probe failed: %s", reason)
	}
	defer harness.stop()

	jobID := fmt.Sprintf("runtime-identity-capability-probe-%d", time.Now().UnixNano())
	jobSpec := map[string]any{
		"Job": map[string]any{
			"ID":          jobID,
			"Name":        jobID,
			"Type":        "batch",
			"Datacenters": []string{"dc1"},
			"TaskGroups": []any{
				map[string]any{
					"Name":  "group",
					"Count": 1,
					"RestartPolicy": map[string]any{
						"Attempts": 0,
						"Mode":     "fail",
						"Interval": int64(time.Minute),
						"Delay":    int64(10 * time.Second),
					},
					"ReschedulePolicy": map[string]any{
						"Attempts":      0,
						"Unlimited":     false,
						"Delay":         int64(0),
						"DelayFunction": "constant",
						"MaxDelay":      int64(0),
					},
					"Tasks": []any{
						map[string]any{
							"Name":   "task",
							"Driver": "docker",
							"Config": map[string]any{
								"image":   "python:3.13-alpine",
								"command": "sh",
								"args": []string{
									"-ceu",
									runtimeIdentitySocketProbeScript("NOMAD-RUNTIME-IDENTITY-SOCKET-PROBE-OK"),
								},
								"network_mode": "none",
								"mounts": []any{
									map[string]any{
										"type":     "tmpfs",
										"target":   "/runtime",
										"readonly": false,
										"tmpfs_options": map[string]any{
											"size": int64(1 << 20),
										},
									},
									map[string]any{
										"type":     "bind",
										"source":   socketDir,
										"target":   "/runtime/internal/source",
										"readonly": true,
									},
								},
							},
							"Resources": map[string]any{
								"CPU":      10,
								"MemoryMB": 64,
							},
						},
					},
				},
			},
		},
	}

	body, err := json.Marshal(jobSpec)
	if err != nil {
		return fmt.Sprintf("marshal Nomad allocation probe job failed: %v", err)
	}
	response, err := harness.httpClient(5*time.Second).Post(harness.addr+"/v1/jobs", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Sprintf("submit Nomad allocation probe job failed: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(response.Body)
		return fmt.Sprintf("submit Nomad allocation probe job returned status %d body=%s", response.StatusCode, strings.TrimSpace(string(payload)))
	}

	allocation, waitReason := harness.waitForTerminalAllocationResult(jobID, 45*time.Second)
	if waitReason != "" {
		return waitReason
	}
	stdout, stdoutErr := harness.tryAllocLogs(allocation.ID)
	if allocation.ClientStatus != "complete" {
		stderr, _ := harness.tryAllocStderrLogs(allocation.ID)
		return fmt.Sprintf("Nomad Docker allocation probe expected complete status, got %q task_state=%+v stdout=%q stderr=%q", allocation.ClientStatus, allocation.TaskStates["task"], stdout, stderr)
	}
	taskState := allocation.TaskStates["task"]
	if taskState.Failed || taskState.exitCode() != 0 {
		stderr, _ := harness.tryAllocStderrLogs(allocation.ID)
		return fmt.Sprintf("Nomad Docker allocation probe task failed: task_state=%+v stdout=%q stderr=%q", taskState, stdout, stderr)
	}
	if stdoutErr != nil {
		return fmt.Sprintf("Nomad Docker allocation probe log read failed: %v output=%s", stdoutErr, strings.TrimSpace(stdout))
	}
	if !strings.Contains(stdout, "NOMAD-RUNTIME-IDENTITY-SOCKET-PROBE-OK") {
		return fmt.Sprintf("Nomad Docker allocation probe did not report mounted socket reachability: stdout=%q", stdout)
	}
	return ""
}

func runtimeIdentitySocketProbeScript(successMarker string) string {
	return `ln -s /runtime/internal/source/spire-agent.sock /runtime/internal-spire-agent.sock
python3 - <<'PY'
import socket

client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.settimeout(5)
client.connect("/runtime/internal-spire-agent.sock")
client.close()
print("` + successMarker + `", flush=True)
PY`
}

func runtimeIdentityCapabilityProbeWorkspace() (string, error) {
	repoRoot, err := repoRootFromCallerFile()
	if err != nil {
		return "", err
	}
	workspaceRoot := filepath.Join(repoRoot, ".out")
	if err := os.MkdirAll(workspaceRoot, 0o755); err != nil {
		return "", err
	}
	return os.MkdirTemp(workspaceRoot, "runtime-identity-capability-")
}

func buildSubmitRequestBody(t *testing.T, stack *submitStack) []byte {
	t.Helper()
	return buildSubmitRequestBodyWithEnv(t, stack, map[string]string{
		"APP_MODE": "test",
	})
}

func buildSubmitRequestBodyWithEnv(t *testing.T, stack *submitStack, env map[string]string) []byte {
	t.Helper()
	return mustMarshalJSON(t, admission.PrepareRequest{
		SchemaVersion: "v1",
		Invocation: admission.ArtifactInvocation{
			SchemaVersion:        "v1",
			ArtifactDigest:       stack.publishResponse.ArtifactDigest,
			DerivationSpecDigest: stack.derivationSpecDigest,
			OutputID:             stack.outputID,
			Env:                  env,
		},
		Mode: admission.ExecutionModeAsync,
		Resources: &admission.ExecutionResources{
			CPU:      10,
			MemoryMB: 128,
		},
	})
}

func buildSubmitRequestBodyWithMounts(t *testing.T, stack *submitStack, mounts []admission.RuntimeMount) []byte {
	t.Helper()
	return mustMarshalJSON(t, admission.PrepareRequest{
		SchemaVersion: "v1",
		Invocation: admission.ArtifactInvocation{
			SchemaVersion:        "v1",
			ArtifactDigest:       stack.publishResponse.ArtifactDigest,
			DerivationSpecDigest: stack.derivationSpecDigest,
			OutputID:             stack.outputID,
			Env: map[string]string{
				"APP_MODE": "test",
			},
			Mounts: mounts,
		},
		Mode: admission.ExecutionModeAsync,
		Resources: &admission.ExecutionResources{
			CPU:      10,
			MemoryMB: 128,
		},
	})
}

// submitArtifactRuntimeInterface is the runtime interface the stack's
// publish helpers sign. mount_targets is sent only when the test sets it, so
// an artifact published without it has the same shape as before the field
// existed.
func submitArtifactRuntimeInterface(environmentVariables []string, mountTargets []string) map[string]any {
	runtime := map[string]any{
		"environment_variables": environmentVariables,
		"required_capabilities": []string{},
	}
	if mountTargets != nil {
		runtime["mount_targets"] = mountTargets
	}
	return runtime
}

func publishSubmitArtifact(t *testing.T, stack *submitStack, networkAccess bool, mountTargets []string) {
	t.Helper()

	requestBody := mustMarshalJSON(t, map[string]any{
		"artifact_payload_b64": base64.StdEncoding.EncodeToString(buildStaticScriptArchive(t)),
		"artifact": map[string]any{
			"artifact_type": "static-script",
			"intent_digest": stack.intentDigest,
		},
		"publication": map[string]any{
			"policy_decisions": []map[string]any{
				{"rule": "allow", "result": "applied"},
			},
			"build_log_digest": labeledDigest("ee"),
		},
		"admission": map[string]any{
			"runtime": submitArtifactRuntimeInterface([]string{"APP_MODE"}, mountTargets),
			"access": map[string]any{
				"network_access": networkAccess,
			},
			"derivation": map[string]any{
				"derivation_spec_digest": stack.derivationSpecDigest,
				"output_id":              stack.outputID,
			},
			"workload": map[string]any{
				"target_platform": "docker",
			},
		},
	})

	response := doJSONRequest(
		t,
		stack.ags.Addr(),
		http.MethodPost,
		"/v1/artifacts:publish",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.agsServerName, stack.publishCallerPath, false),
		requestBody,
	)
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}
	if err := json.NewDecoder(response.Body).Decode(&stack.publishResponse); err != nil {
		t.Fatalf("decode publish response: %v", err)
	}
	if !stack.publishResponse.Published {
		t.Fatalf("expected published response")
	}
}

func buildStaticScriptArchive(t *testing.T) []byte {
	t.Helper()

	var archiveBuffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&archiveBuffer)
	gzipWriter.Header.ModTime = time.Unix(0, 0)
	tarWriter := tar.NewWriter(gzipWriter)

	script := "#!/bin/sh\nset -eu\necho START-BANNER\nfor i in 1 2 3; do\n  echo HEARTBEAT:$i\n  sleep 2\ndone\necho \"{\\\"status\\\":\\\"ok\\\",\\\"artifact_digest\\\":\\\"${EXEC_ARTIFACT_DIGEST}\\\"}\"\n"
	scriptBytes := []byte(script)
	header := &tar.Header{
		Name:    "entrypoint",
		Mode:    0o755,
		Size:    int64(len(scriptBytes)),
		ModTime: time.Unix(0, 0),
	}
	if err := tarWriter.WriteHeader(header); err != nil {
		t.Fatalf("write tar header: %v", err)
	}
	if _, err := tarWriter.Write(scriptBytes); err != nil {
		t.Fatalf("write tar payload: %v", err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	return archiveBuffer.Bytes()
}

type archiveEntry struct {
	Name     string
	Mode     int64
	Body     []byte
	Typeflag byte
	Linkname string
}

func buildArchiveWithEntries(t *testing.T, entries []archiveEntry) []byte {
	t.Helper()

	var archiveBuffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&archiveBuffer)
	gzipWriter.Header.ModTime = time.Unix(0, 0)
	tarWriter := tar.NewWriter(gzipWriter)

	for _, entry := range entries {
		typeflag := entry.Typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		header := &tar.Header{
			Name:     entry.Name,
			Mode:     entry.Mode,
			Size:     int64(len(entry.Body)),
			Typeflag: typeflag,
			Linkname: entry.Linkname,
			ModTime:  time.Unix(0, 0),
		}
		if typeflag != tar.TypeReg && typeflag != tar.TypeRegA {
			header.Size = 0
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
		if header.Size > 0 {
			if _, err := tarWriter.Write(entry.Body); err != nil {
				t.Fatalf("write tar payload: %v", err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	return archiveBuffer.Bytes()
}

func publishAuxiliaryArtifactArchive(t *testing.T, stack *submitStack, archive []byte, artifactType string) submitPublishResponse {
	t.Helper()

	requestBody := mustMarshalJSON(t, map[string]any{
		"artifact_payload_b64": base64.StdEncoding.EncodeToString(archive),
		"artifact": map[string]any{
			"artifact_type": artifactType,
			"intent_digest": labeledDigest("f1"),
		},
		"publication": map[string]any{
			"policy_decisions": []map[string]any{
				{"rule": "allow", "result": "applied"},
			},
			"build_log_digest": labeledDigest("f2"),
		},
		"admission": map[string]any{
			"runtime": map[string]any{
				"environment_variables": []string{},
				"required_capabilities": []string{},
			},
			"access": map[string]any{
				"network_access": false,
			},
			"derivation": map[string]any{
				"derivation_spec_digest": labeledDigest("f3"),
				"output_id":              "mount-output",
			},
			"workload": map[string]any{
				"target_platform": "docker",
			},
		},
	})

	response := doJSONRequest(
		t,
		stack.ags.Addr(),
		http.MethodPost,
		"/v1/artifacts:publish",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.agsServerName, stack.publishCallerPath, false),
		requestBody,
	)
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}

	var payload submitPublishResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode publish response: %v", err)
	}
	if !payload.Published {
		t.Fatalf("expected auxiliary publish response")
	}
	return payload
}

func submitExecutionRequest(t *testing.T, stack *submitStack, requestBody []byte) *http.Response {
	t.Helper()

	return submitExecutionRequestWithCaller(t, stack, stack.executionCallerPath, requestBody)
}

func submitExecutionRequestWithCaller(t *testing.T, stack *submitStack, callerPath string, requestBody []byte) *http.Response {
	t.Helper()

	return doJSONRequest(
		t,
		stack.es.Addr(),
		http.MethodPost,
		"/v1/executions:submit",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, callerPath, false),
		requestBody,
	)
}

func executionStatusRequestWithCaller(t *testing.T, stack *submitStack, runID string, callerPath string) *http.Response {
	t.Helper()

	return doJSONRequest(
		t,
		stack.es.Addr(),
		http.MethodGet,
		"/v1/executions/"+runID+"/status",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, callerPath, false),
		nil,
	)
}

func executionLogsRequestWithCaller(t *testing.T, stack *submitStack, runID string, callerPath string) *http.Response {
	t.Helper()

	return doJSONRequest(
		t,
		stack.es.Addr(),
		http.MethodGet,
		"/v1/executions/"+runID+"/logs",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, callerPath, false),
		nil,
	)
}

func executionResultRequestWithCaller(t *testing.T, stack *submitStack, runID string, callerPath string) *http.Response {
	t.Helper()

	return doJSONRequest(
		t,
		stack.es.Addr(),
		http.MethodGet,
		"/v1/executions/"+runID+"/result",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, callerPath, false),
		nil,
	)
}

func executionCancelRequestWithCaller(t *testing.T, stack *submitStack, runID string, callerPath string) *http.Response {
	t.Helper()

	return doJSONRequest(
		t,
		stack.es.Addr(),
		http.MethodPost,
		"/v1/executions/"+runID+":cancel",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, callerPath, false),
		nil,
	)
}

func assertErrorResponseCode(t *testing.T, response *http.Response, expectedStatus int, expectedCode string) {
	t.Helper()

	body := strings.TrimSpace(string(mustReadBody(t, response.Body)))
	if response.StatusCode != expectedStatus {
		t.Fatalf("expected %d, got %d body=%s", expectedStatus, response.StatusCode, body)
	}

	var payload admission.ErrorResponse
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("decode error response: %v body=%s", err, body)
	}
	if payload.Code != expectedCode {
		t.Fatalf("expected error code %q, got %q body=%s", expectedCode, payload.Code, body)
	}
}

func (s *submitStack) loadIndexEntry(t *testing.T, artifactDigest string) arsindex.Entry {
	t.Helper()
	data, err := os.ReadFile(s.indexPath)
	if err != nil {
		t.Fatalf("read artifact index: %v", err)
	}
	var entries map[string]arsindex.Entry
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatalf("decode artifact index: %v", err)
	}
	entry, ok := entries[artifactDigest]
	if !ok {
		t.Fatalf("missing artifact index entry for %s", artifactDigest)
	}
	return entry
}

func (s *submitStack) loadDiscovery(t *testing.T, artifactDigest string) arsapi.ArtifactDiscovery {
	t.Helper()

	entry := s.loadIndexEntry(t, artifactDigest)
	discoveryPath, err := arsstore.ResolvePath(s.arsRootDir, entry.DiscoveryDigest)
	if err != nil {
		t.Fatalf("resolve discovery blob path: %v", err)
	}
	data, err := os.ReadFile(discoveryPath)
	if err != nil {
		t.Fatalf("read discovery blob: %v", err)
	}
	var discovery arsapi.ArtifactDiscovery
	if err := json.Unmarshal(data, &discovery); err != nil {
		t.Fatalf("decode discovery blob: %v", err)
	}
	return discovery
}

func findTaskMountByTarget(t *testing.T, rawMounts any, target string) map[string]any {
	t.Helper()

	mounts, ok := rawMounts.([]any)
	if !ok {
		t.Fatalf("expected []any mounts config, got %#v", rawMounts)
	}
	for _, candidate := range mounts {
		mountConfig, ok := candidate.(map[string]any)
		if !ok {
			continue
		}
		if mountTarget, ok := mountConfig["target"].(string); ok && mountTarget == target {
			return mountConfig
		}
	}
	t.Fatalf("expected mount targeting %q in %#v", target, rawMounts)
	return nil
}

func assertNoRawSPIREEnvLeak(t *testing.T, env map[string]string, rawSPIREPath string) {
	t.Helper()

	for key, value := range env {
		if strings.Contains(strings.TrimSpace(value), "spire-agent.sock") {
			t.Fatalf("did not expect workload env %q to expose helper-private SPIRE socket path: %q", key, value)
		}
		if strings.TrimSpace(rawSPIREPath) != "" && strings.Contains(strings.TrimSpace(value), strings.TrimSpace(rawSPIREPath)) {
			t.Fatalf("did not expect workload env %q to expose raw SPIRE source path: %q", key, value)
		}
	}
}

type nomadHarness struct {
	addr string
	// tls is the harness Nomad's HTTPS identity, issued by the setup
	// script's own nomad_tls_issue.
	tls        nomadTLSMaterial
	configPath string
	cmd        *exec.Cmd
	outputPath string
	// aclEnabled is false only for a harness started with
	// nomadHarnessOptions.aclDisabled.
	aclEnabled bool
	// managementToken is the test operator's token: the harness's own reads
	// and test-owned writes use it. ES uses only esTokenFile.
	managementToken   string
	esTokenFile       string
	observerTokenFile string
}

type nomadAllocationSummary struct {
	ID           string                    `json:"ID"`
	JobID        string                    `json:"JobID"`
	ModifyIndex  uint64                    `json:"ModifyIndex"`
	ClientStatus string                    `json:"ClientStatus"`
	TaskStates   map[string]nomadTaskState `json:"TaskStates"`
}

type nomadJobListEntry struct {
	ID string `json:"ID"`
}

type nomadJobDetail struct {
	ID         string                 `json:"ID"`
	Meta       map[string]string      `json:"Meta"`
	TaskGroups []nomadTaskGroupDetail `json:"TaskGroups"`
}

type nomadTaskGroupDetail struct {
	Tasks []nomadTaskDetail `json:"Tasks"`
}

type nomadTaskDetail struct {
	Name   string            `json:"Name"`
	User   string            `json:"User"`
	Config map[string]any    `json:"Config"`
	Env    map[string]string `json:"Env"`
	Meta   map[string]string `json:"Meta"`
}

type nomadTaskState struct {
	State  string           `json:"State"`
	Failed bool             `json:"Failed"`
	Events []nomadTaskEvent `json:"Events"`
}

type nomadTaskEvent struct {
	Type           string `json:"Type"`
	ExitCode       int    `json:"ExitCode"`
	DisplayMessage string `json:"DisplayMessage"`
	Message        string `json:"Message"`
}

func (s nomadTaskState) exitCode() int {
	for i := len(s.Events) - 1; i >= 0; i-- {
		if s.Events[i].Type == "Terminated" {
			return s.Events[i].ExitCode
		}
	}
	return -1
}

type nomadHarnessOptions struct {
	dockerTaskNameLabel bool
	// aclDisabled starts Nomad without ACLs, a Nomad ES must refuse; ES then
	// gets a well-formed token file that Nomad never issued.
	aclDisabled bool
	// aclUnbootstrapped starts Nomad with ACLs on but neither bootstrapped
	// nor provisioned, for a test whose own setup does both.
	aclUnbootstrapped bool
	// leaderOnly skips the wait for a schedulable Docker client node, for
	// tests that only register, plan or read jobs.
	leaderOnly bool
}

func startNomadHarness(t *testing.T, rootDir string) *nomadHarness {
	return startNomadHarnessWithOptions(t, rootDir, nomadHarnessOptions{})
}

func startNomadHarnessWithOptions(t *testing.T, rootDir string, opts nomadHarnessOptions) *nomadHarness {
	t.Helper()

	harness, reason := startNomadHarnessForCapabilityProbeWithOptions(rootDir, opts, (*exec.Cmd).Start)
	if reason != "" {
		t.Fatalf("%s", reason)
	}
	return harness
}

func startNomadHarnessForCapabilityProbe(rootDir string) (*nomadHarness, string) {
	return startNomadHarnessForCapabilityProbeWithOptions(rootDir, nomadHarnessOptions{}, (*exec.Cmd).Start)
}

func startNomadHarnessForCapabilityProbeWithOptions(rootDir string, opts nomadHarnessOptions, launch func(*exec.Cmd) error) (*nomadHarness, string) {
	httpPort, err := reserveTCPPortValue()
	if err != nil {
		return nil, fmt.Sprintf("reserve nomad http port: %v", err)
	}
	rpcPort, err := reserveTCPPortValue()
	if err != nil {
		return nil, fmt.Sprintf("reserve nomad rpc port: %v", err)
	}
	serfPort, err := reserveTCPPortValue()
	if err != nil {
		return nil, fmt.Sprintf("reserve nomad serf port: %v", err)
	}
	clientCPUOverride := ""
	if raw := strings.TrimSpace(os.Getenv("NOMAD_CLIENT_CPU_TOTAL_COMPUTE")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value <= 0 {
			return nil, fmt.Sprintf("NOMAD_CLIENT_CPU_TOTAL_COMPUTE must be a positive integer, got %q", raw)
		}
		clientCPUOverride = fmt.Sprintf("\n  cpu_total_compute = %d", value)
	}

	configPath := filepath.Join(rootDir, "nomad.hcl")
	dataDir := filepath.Join(rootDir, "nomad-data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Sprintf("mkdir nomad data dir: %v", err)
	}
	// Every real Nomad these tests start serves HTTPS and RPC over TLS 1.3
	// only, with a certificate the setup script's own issuer wrote.
	tlsMaterial, err := issueNomadTLSMaterial(filepath.Join(rootDir, "nomad-tls"))
	if err != nil {
		return nil, err.Error()
	}
	if err := registerTestNomadCA(tlsMaterial.caFile); err != nil {
		return nil, fmt.Sprintf("register nomad test CA: %v", err)
	}
	// Every real Nomad these tests start enables only the Docker driver and
	// carries the supported Docker plugin limits, so ES jobs run under them.
	clientDockerConfig := supportedNomadClientOptions
	dockerPluginConfig := supportedNomadDockerPluginBlock
	if opts.dockerTaskNameLabel {
		dockerPluginConfig = supportedNomadDockerPluginBlockWithTaskNameLabel()
	}
	aclConfig := "acl {\n  enabled = true\n}\n"
	if opts.aclDisabled {
		aclConfig = ""
	}
	config := fmt.Sprintf(`data_dir = %q
bind_addr = "127.0.0.1"
%sserver {
  enabled = true
  bootstrap_expect = 1
}
client {
  enabled = true
%s
%s
%s
}
%sports {
  http = %d
  rpc  = %d
  serf = %d
}
advertise {
  http = "127.0.0.1:%d"
  rpc  = "127.0.0.1:%d"
  serf = "127.0.0.1:%d"
}
%s`, dataDir, aclConfig, clientCPUOverride, supportedNomadClientNetworkInterface, clientDockerConfig, dockerPluginConfig, httpPort, rpcPort, serfPort, httpPort, rpcPort, serfPort, supportedNomadTLSBlock(tlsMaterial.dir))
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		return nil, fmt.Sprintf("write nomad config: %v", err)
	}

	outputPath := filepath.Join(rootDir, "nomad.log")
	logFile, err := os.Create(outputPath)
	if err != nil {
		return nil, fmt.Sprintf("create nomad log file: %v", err)
	}

	cmd := exec.Command("nomad", "agent", "-dev", "-config="+configPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := launch(cmd); err != nil {
		_ = logFile.Close()
		return nil, fmt.Sprintf("start nomad agent: %v", err)
	}
	if err := logFile.Close(); err != nil {
		_ = cmd.Process.Kill()
		return nil, fmt.Sprintf("close nomad log file: %v", err)
	}

	harness := &nomadHarness{
		addr:       fmt.Sprintf("https://127.0.0.1:%d", httpPort),
		tls:        tlsMaterial,
		configPath: configPath,
		cmd:        cmd,
		outputPath: outputPath,
		aclEnabled: !opts.aclDisabled,
	}
	if reason := harness.waitLeaderResult(15 * time.Second); reason != "" {
		harness.stop()
		return nil, reason
	}
	if opts.aclDisabled {
		tokenFile, err := writeUnissuedNomadTokenFile(rootDir)
		if err != nil {
			harness.stop()
			return nil, fmt.Sprintf("write unissued nomad token file: %v", err)
		}
		harness.esTokenFile = tokenFile
	} else if opts.aclUnbootstrapped {
		// The test's own setup bootstraps and provisions this Nomad.
	} else if reason := harness.provisionACL(rootDir); reason != "" {
		harness.stop()
		return nil, reason
	}
	if opts.leaderOnly {
		return harness, ""
	}
	if reason := harness.waitReadyResult(15 * time.Second); reason != "" {
		harness.stop()
		return nil, reason
	}
	return harness, ""
}

func (n *nomadHarness) baseURL() string {
	return n.addr
}

func (n *nomadHarness) waitReady(t *testing.T) {
	t.Helper()

	if reason := n.waitReadyResult(15 * time.Second); reason != "" {
		t.Fatalf("%s", reason)
	}
}

func (n *nomadHarness) waitReadyResult(timeout time.Duration) string {
	client := n.httpClient(2 * time.Second)
	deadline := time.Now().Add(timeout)
	lastReason := "nomad node did not become schedulable"
	for time.Now().Before(deadline) {
		leaderResponse, leaderErr := client.Get(n.addr + "/v1/status/leader")
		if leaderErr == nil {
			var leader string
			decodeErr := json.NewDecoder(leaderResponse.Body).Decode(&leader)
			leaderResponse.Body.Close()
			if decodeErr == nil && strings.TrimSpace(strings.Trim(leader, `"`)) != "" {
				nodesResponse, nodesErr := client.Get(n.addr + "/v1/nodes")
				if nodesErr == nil {
					var nodes []struct {
						ID     string `json:"ID"`
						Name   string `json:"Name"`
						Status string `json:"Status"`
					}
					decodeNodesErr := json.NewDecoder(nodesResponse.Body).Decode(&nodes)
					nodesResponse.Body.Close()
					if decodeNodesErr == nil {
						schedulable, reason := n.readySchedulableNode(client, nodes)
						if schedulable {
							return ""
						}
						if reason != "" {
							lastReason = reason
						}
					}
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	output, _ := os.ReadFile(n.outputPath)
	return fmt.Sprintf("%s; logs=%s", lastReason, strings.TrimSpace(string(output)))
}

func (n *nomadHarness) readySchedulableNode(client *http.Client, nodes []struct {
	ID     string `json:"ID"`
	Name   string `json:"Name"`
	Status string `json:"Status"`
}) (bool, string) {
	readyNodes := make([]struct {
		ID     string `json:"ID"`
		Name   string `json:"Name"`
		Status string `json:"Status"`
	}, 0, len(nodes))
	for _, node := range nodes {
		if strings.TrimSpace(node.Status) == "ready" {
			readyNodes = append(readyNodes, node)
		}
	}
	if len(readyNodes) == 0 {
		return false, "nomad: no ready client nodes"
	}

	reasons := make([]string, 0, len(readyNodes))
	for _, node := range readyNodes {
		nodeID := strings.TrimSpace(node.ID)
		nodeName := strings.TrimSpace(node.Name)
		if nodeName == "" {
			nodeName = nodeID
		}
		if nodeName == "" {
			nodeName = "unknown"
		}
		if nodeID == "" {
			reasons = append(reasons, nodeName+"=missing-id")
			continue
		}

		response, err := client.Get(n.addr + "/v1/node/" + nodeID)
		if err != nil {
			reasons = append(reasons, nodeName+"=detail-unavailable:"+err.Error())
			continue
		}
		if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			reasons = append(reasons, fmt.Sprintf("%s=detail-status:%d", nodeName, response.StatusCode))
			continue
		}

		var detail struct {
			Attributes map[string]any `json:"Attributes"`
			Drivers    map[string]struct {
				Healthy           bool   `json:"Healthy"`
				HealthDescription string `json:"HealthDescription"`
			} `json:"Drivers"`
			NodeResources struct {
				Networks []struct {
					Mode string `json:"Mode"`
				} `json:"Networks"`
			} `json:"NodeResources"`
		}
		decodeErr := json.NewDecoder(response.Body).Decode(&detail)
		response.Body.Close()
		if decodeErr != nil {
			reasons = append(reasons, nodeName+"=detail-decode:"+decodeErr.Error())
			continue
		}

		cpuTotalCompute := parseNomadAttributeInt(detail.Attributes["cpu.totalcompute"])
		if cpuTotalCompute <= 0 {
			reasons = append(reasons, fmt.Sprintf("%s=cpu.totalcompute:%d", nodeName, cpuTotalCompute))
			continue
		}

		docker := detail.Drivers["docker"]
		if !docker.Healthy {
			description := strings.TrimSpace(docker.HealthDescription)
			if description == "" {
				description = "unhealthy"
			}
			reasons = append(reasons, nodeName+"=docker:"+description)
			continue
		}

		// ES's jobs need a host-mode network on the node, as bring-up
		// readiness (scripts/internal/bringup.sh) requires.
		hostNetwork := false
		for _, network := range detail.NodeResources.Networks {
			hostNetwork = hostNetwork || network.Mode == "host"
		}
		if !hostNetwork {
			reasons = append(reasons, nodeName+"=no-host-network")
			continue
		}

		return true, ""
	}

	reason := "nomad: no ready client nodes with positive cpu.totalcompute, healthy docker driver and a host-mode network"
	if len(reasons) > 0 {
		reason += "; " + strings.Join(reasons, ", ")
		if allReasonsHaveZeroCPU(reasons) {
			reason += "; rerun only with explicit NOMAD_CLIENT_CPU_TOTAL_COMPUTE as a bounded troubleshooting override"
		}
	}
	return false, reason
}

func parseNomadAttributeInt(value any) int {
	switch typed := value.(type) {
	case float64:
		return int(typed)
	case int:
		return typed
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(typed))
		if err == nil {
			return parsed
		}
	}
	return 0
}

func allReasonsHaveZeroCPU(reasons []string) bool {
	if len(reasons) == 0 {
		return false
	}
	for _, reason := range reasons {
		if !strings.Contains(reason, "=cpu.totalcompute:0") {
			return false
		}
	}
	return true
}

func (n *nomadHarness) waitForJob(t *testing.T, jobID string) {
	t.Helper()

	client := n.httpClient(2 * time.Second)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		response, err := client.Get(n.addr + "/v1/job/" + jobID)
		if err == nil {
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("nomad job %s did not appear", jobID)
}

func (n *nomadHarness) waitForExecutionJob(t *testing.T, runID string) string {
	t.Helper()

	trimmed := strings.TrimSpace(runID)
	if trimmed == "" {
		t.Fatalf("expected non-empty run_id")
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if jobID, ok := n.findExecutionJobID(trimmed); ok {
			return jobID
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("nomad job for run_id %s did not appear", trimmed)
	return ""
}

func (n *nomadHarness) fetchJobDetail(t *testing.T, jobID string) nomadJobDetail {
	t.Helper()

	response, err := n.httpClient(2 * time.Second).Get(n.addr + "/v1/job/" + jobID)
	if err != nil {
		t.Fatalf("fetch job %s: %v", jobID, err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("fetch job %s: unexpected status %d body=%s", jobID, response.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload nomadJobDetail
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode job %s: %v", jobID, err)
	}
	return payload
}

func (n *nomadHarness) fetchExecutionJobDetail(t *testing.T, runID string) nomadJobDetail {
	t.Helper()
	return n.fetchJobDetail(t, n.waitForExecutionJob(t, runID))
}

func (j nomadJobDetail) taskConfig(t *testing.T) map[string]any {
	t.Helper()

	return j.task(t).Config
}

func (j nomadJobDetail) task(t *testing.T) nomadTaskDetail {
	t.Helper()

	if len(j.TaskGroups) == 0 {
		t.Fatalf("expected at least one task group in job")
	}
	if len(j.TaskGroups[0].Tasks) == 0 {
		t.Fatalf("expected at least one task in job")
	}
	return j.TaskGroups[0].Tasks[0]
}

func (j nomadJobDetail) runID() string {
	if value := strings.TrimSpace(j.Meta["run_id"]); value != "" {
		return value
	}
	if len(j.TaskGroups) == 0 || len(j.TaskGroups[0].Tasks) == 0 {
		return ""
	}
	return strings.TrimSpace(j.TaskGroups[0].Tasks[0].Meta["run_id"])
}

func (n *nomadHarness) findExecutionJobID(runID string) (string, bool) {
	response, err := n.httpClient(2 * time.Second).Get(n.addr + "/v1/jobs")
	if err != nil {
		return "", false
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return "", false
	}

	var payload []nomadJobListEntry
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return "", false
	}

	for _, entry := range payload {
		detail, ok := n.tryFetchJobDetail(strings.TrimSpace(entry.ID))
		if ok && detail.runID() == runID {
			return strings.TrimSpace(entry.ID), true
		}
	}
	return "", false
}

func (n *nomadHarness) tryFetchJobDetail(jobID string) (nomadJobDetail, bool) {
	response, err := n.httpClient(2 * time.Second).Get(n.addr + "/v1/job/" + jobID)
	if err != nil {
		return nomadJobDetail{}, false
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nomadJobDetail{}, false
	}

	var payload nomadJobDetail
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return nomadJobDetail{}, false
	}
	return payload, true
}

func (n *nomadHarness) waitForTerminalAllocation(t *testing.T, jobID string) nomadAllocationSummary {
	t.Helper()

	allocation, reason := n.waitForTerminalAllocationResult(jobID, 45*time.Second)
	if reason != "" {
		t.Fatalf("%s", reason)
	}
	return allocation
}

func (n *nomadHarness) waitForTerminalAllocationResult(jobID string, timeout time.Duration) (nomadAllocationSummary, string) {
	client := n.httpClient(2 * time.Second)
	deadline := time.Now().Add(timeout)
	var lastObserved *nomadAllocationSummary
	for time.Now().Before(deadline) {
		response, err := client.Get(n.addr + "/v1/job/" + jobID + "/allocations")
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		var allocations []nomadAllocationSummary
		decodeErr := json.NewDecoder(response.Body).Decode(&allocations)
		response.Body.Close()
		if decodeErr == nil && len(allocations) > 0 {
			sort.SliceStable(allocations, func(i, j int) bool {
				return allocations[i].ModifyIndex > allocations[j].ModifyIndex
			})
			alloc, ok := n.tryFetchAllocation(allocations[0].ID)
			if ok {
				lastObserved = &alloc
				switch alloc.ClientStatus {
				case "complete", "failed", "lost":
					return alloc, ""
				}
			}
		}
		time.Sleep(250 * time.Millisecond)
	}

	output, _ := os.ReadFile(n.outputPath)
	if lastObserved != nil {
		return nomadAllocationSummary{}, fmt.Sprintf("nomad allocation for job %s did not reach a terminal client status; last allocation=%+v logs=%s", jobID, *lastObserved, strings.TrimSpace(string(output)))
	}
	return nomadAllocationSummary{}, fmt.Sprintf("nomad allocation for job %s did not reach a terminal state; logs=%s", jobID, strings.TrimSpace(string(output)))
}

func (n *nomadHarness) waitForLatestAllocation(t *testing.T, jobID string) nomadAllocationSummary {
	t.Helper()

	client := n.httpClient(2 * time.Second)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		response, err := client.Get(n.addr + "/v1/job/" + jobID + "/allocations")
		if err == nil {
			var allocations []nomadAllocationSummary
			decodeErr := json.NewDecoder(response.Body).Decode(&allocations)
			response.Body.Close()
			if decodeErr == nil && len(allocations) > 0 {
				sort.SliceStable(allocations, func(i, j int) bool {
					return allocations[i].ModifyIndex > allocations[j].ModifyIndex
				})
				if allocation, ok := n.tryFetchAllocation(allocations[0].ID); ok {
					return allocation
				}
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("nomad allocation for job %s did not appear", jobID)
	return nomadAllocationSummary{}
}

func (n *nomadHarness) waitForTerminalExecutionAllocation(t *testing.T, runID string) nomadAllocationSummary {
	t.Helper()
	return n.waitForTerminalAllocation(t, n.waitForExecutionJob(t, runID))
}

func (n *nomadHarness) tryFetchAllocation(allocationID string) (nomadAllocationSummary, bool) {
	response, err := n.httpClient(2 * time.Second).Get(n.addr + "/v1/allocation/" + allocationID)
	if err != nil {
		return nomadAllocationSummary{}, false
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nomadAllocationSummary{}, false
	}

	var payload nomadAllocationSummary
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return nomadAllocationSummary{}, false
	}
	return payload, true
}

func (n *nomadHarness) fetchAllocation(t *testing.T, allocationID string) nomadAllocationSummary {
	t.Helper()

	response, err := n.httpClient(2 * time.Second).Get(n.addr + "/v1/allocation/" + allocationID)
	if err != nil {
		t.Fatalf("fetch allocation %s: %v", allocationID, err)
	}
	defer response.Body.Close()

	var payload nomadAllocationSummary
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode allocation %s: %v", allocationID, err)
	}
	return payload
}

func (n *nomadHarness) allocLogs(t *testing.T, allocationID string) string {
	t.Helper()

	output, err := n.tryAllocLogs(allocationID)
	if err != nil {
		t.Fatalf("fetch allocation logs: %v output=%s", err, strings.TrimSpace(output))
	}
	return output
}

func (n *nomadHarness) allocStderrLogs(t *testing.T, allocationID string) string {
	t.Helper()

	output, err := n.tryAllocStderrLogs(allocationID)
	if err != nil {
		t.Fatalf("fetch allocation stderr logs: %v output=%s", err, strings.TrimSpace(output))
	}
	return output
}

func (n *nomadHarness) tryAllocStderrLogs(allocationID string) (string, error) {
	command := exec.Command("nomad", "alloc", "logs", "-stderr", allocationID)
	command.Env = append(os.Environ(), n.cliEnv()...)
	output, err := command.CombinedOutput()
	return string(output), err
}

func (n *nomadHarness) tryAllocLogs(allocationID string) (string, error) {
	command := exec.Command("nomad", "alloc", "logs", "-stdout", allocationID)
	command.Env = append(os.Environ(), n.cliEnv()...)
	output, err := command.CombinedOutput()
	return string(output), err
}

func (n *nomadHarness) waitForAllocationLogsContaining(t *testing.T, allocationID string, substring string, timeout time.Duration) string {
	t.Helper()

	deadline := time.Now().Add(timeout)
	lastLogs := ""
	lastErr := ""
	for time.Now().Before(deadline) {
		logs, err := n.tryAllocLogs(allocationID)
		if err != nil {
			trimmed := strings.TrimSpace(logs)
			if strings.Contains(trimmed, "not started yet. No logs available") {
				lastErr = trimmed
				time.Sleep(500 * time.Millisecond)
				continue
			}
			t.Fatalf("fetch allocation logs: %v output=%s", err, trimmed)
		}
		lastLogs = logs
		if strings.Contains(logs, substring) {
			return logs
		}
		time.Sleep(500 * time.Millisecond)
	}
	if lastErr != "" {
		t.Fatalf("allocation %s logs did not contain %q within %s; last log wait error=%s last_logs=%q", allocationID, substring, timeout, lastErr, lastLogs)
	}
	t.Fatalf("allocation %s logs did not contain %q within %s; last_logs=%q", allocationID, substring, timeout, lastLogs)
	return ""
}

func (n *nomadHarness) waitForExecutionJobTerminalStatus(t *testing.T, runID string) nomadJobSummary {
	t.Helper()
	return n.waitForJobTerminalStatus(t, n.waitForExecutionJob(t, runID))
}

func (n *nomadHarness) shutdown(t *testing.T) {
	t.Helper()
	n.stop()
}

func (n *nomadHarness) stop() {
	if n == nil || n.cmd == nil || n.cmd.Process == nil {
		return
	}
	_ = n.cmd.Process.Signal(os.Interrupt)
	done := make(chan error, 1)
	go func() {
		done <- n.cmd.Wait()
	}()

	select {
	case <-time.After(10 * time.Second):
		_ = n.cmd.Process.Kill()
		<-done
	case <-done:
	}
}

func (s *submitStack) shutdownAll(t *testing.T) {
	t.Helper()
	for _, step := range []struct {
		running *bool
		name    string
		stop    func(context.Context) error
	}{
		{&s.esRunning, "es", func(ctx context.Context) error { return s.es.Shutdown(ctx) }},
		{&s.agsRunning, "ags", func(ctx context.Context) error { return s.ags.Shutdown(ctx) }},
		{&s.egsRunning, "egs", func(ctx context.Context) error { return s.egs.Shutdown(ctx) }},
		{&s.arsRunning, "ars", func(ctx context.Context) error { return s.ars.Shutdown(ctx) }},
	} {
		if step.running == nil || !*step.running {
			continue
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := step.stop(shutdownCtx)
		cancel()
		if err != nil {
			t.Fatalf("shutdown %s: %v", step.name, err)
		}
		*step.running = false
	}
	if s.mockSPIRE != nil {
		s.mockSPIRE.stop()
	}
	if s.nomadServer != nil {
		s.nomadServer.Close()
		s.nomadServer = nil
	}
	s.nomad.shutdown(t)
}

type mockWorkloadAPIServerOptions struct {
	jwtTTL    time.Duration
	failFetch bool
}

type mockWorkloadAPIServer struct {
	workloadpb.UnimplementedSpiffeWorkloadAPIServer

	socketDir  string
	socketPath string
	listener   net.Listener
	server     *grpc.Server
	signer     jose.Signer
	subject    string

	mu        sync.RWMutex
	jwtTTL    time.Duration
	failFetch bool
}

func startMockWorkloadAPIServer(t *testing.T, rootDir string, opts mockWorkloadAPIServerOptions) *mockWorkloadAPIServer {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate mock workload api signing key: %v", err)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "mock-workload-api"),
	)
	if err != nil {
		t.Fatalf("build mock workload api signer: %v", err)
	}

	socketDir, err := os.MkdirTemp(socketTestRootDir(t), "execution-substrate-spire-")
	if err != nil {
		t.Fatalf("create mock workload api socket dir: %v", err)
	}
	socketPath := filepath.Join(socketDir, "spire-agent.sock")
	_ = os.Remove(socketPath)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		_ = os.RemoveAll(socketDir)
		t.Fatalf("listen on mock workload api socket: %v", err)
	}

	server := &mockWorkloadAPIServer{
		socketDir:  socketDir,
		socketPath: socketPath,
		listener:   listener,
		server:     grpc.NewServer(),
		signer:     signer,
		subject:    "spiffe://execution.internal/workload",
		jwtTTL:     firstNonZeroDuration(opts.jwtTTL, 20*time.Second),
		failFetch:  opts.failFetch,
	}
	workloadpb.RegisterSpiffeWorkloadAPIServer(server.server, server)

	go func() {
		_ = server.server.Serve(listener)
	}()

	return server
}

func (s *mockWorkloadAPIServer) stop() {
	if s == nil {
		return
	}
	s.server.Stop()
	if s.listener != nil {
		_ = s.listener.Close()
	}
	if strings.TrimSpace(s.socketPath) != "" {
		_ = os.Remove(s.socketPath)
	}
	if strings.TrimSpace(s.socketDir) != "" {
		_ = os.RemoveAll(s.socketDir)
	}
}

func (s *mockWorkloadAPIServer) setFailFetch(value bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failFetch = value
}

func (s *mockWorkloadAPIServer) FetchJWTSVID(ctx context.Context, request *workloadpb.JWTSVIDRequest) (*workloadpb.JWTSVIDResponse, error) {
	s.mu.RLock()
	failFetch := s.failFetch
	jwtTTL := s.jwtTTL
	s.mu.RUnlock()

	if failFetch {
		return nil, status.Error(codes.Unavailable, "mock workload api is configured to fail fetches")
	}
	if len(request.Audience) == 0 {
		return nil, status.Error(codes.InvalidArgument, "audience is required")
	}
	if strings.TrimSpace(request.SpiffeId) != "" && strings.TrimSpace(request.SpiffeId) != s.subject {
		return nil, status.Error(codes.NotFound, "unknown spiffe id")
	}

	claims := jwt.Claims{
		Subject:  s.subject,
		Audience: jwt.Audience(request.Audience),
		IssuedAt: jwt.NewNumericDate(time.Now().UTC()),
		Expiry:   jwt.NewNumericDate(time.Now().UTC().Add(jwtTTL)),
	}

	token, err := jwt.Signed(s.signer).Claims(claims).Serialize()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "mint jwt-svid: %v", err)
	}

	return &workloadpb.JWTSVIDResponse{
		Svids: []*workloadpb.JWTSVID{
			{
				SpiffeId: s.subject,
				Svid:     token,
				Hint:     "default",
			},
		},
	}, nil
}

func buildRuntimeSupportBinary(t *testing.T, rootDir string) string {
	t.Helper()

	outputPath := filepath.Join(rootDir, "es-runtime-support")
	command := exec.Command("go", "build", "-o", outputPath, "./cmd/es-runtime-support")
	command.Dir = repoRootFromTestFile(t)
	command.Env = append(os.Environ(),
		"CGO_ENABLED=0",
		"GOOS=linux",
		"GOARCH="+runtime.GOARCH,
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("build runtime support binary: %v output=%s", err, strings.TrimSpace(string(output)))
	}
	return outputPath
}

func newExecutionWorkspaceTempDir(t *testing.T, prefix string) string {
	t.Helper()

	workspaceRoot := filepath.Join(repoRootFromTestFile(t), ".out")
	if err := os.MkdirAll(workspaceRoot, 0o755); err != nil {
		t.Fatalf("create workspace output root: %v", err)
	}

	dir, err := os.MkdirTemp(workspaceRoot, prefix)
	if err != nil {
		t.Fatalf("create workspace temp dir: %v", err)
	}
	if os.Getenv("EXECUTION_PLATFORM_KEEP_TEST_WORKSPACE") != "1" {
		t.Cleanup(func() {
			_ = os.RemoveAll(dir)
		})
	} else {
		t.Logf("keeping workspace temp dir: %s", dir)
	}
	return dir
}

func repoRootFromTestFile(t *testing.T) string {
	t.Helper()

	root, err := repoRootFromCallerFile()
	if err != nil {
		t.Fatalf("resolve test file path: %v", err)
	}
	return root
}

func repoRootFromCallerFile() (string, error) {
	_, filePath, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("runtime caller unavailable")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filePath), "..", "..")), nil
}

func socketTestRootDir(t *testing.T) string {
	t.Helper()

	root, err := socketTestRootDirPath()
	if err != nil {
		t.Fatalf("resolve socket test root: %v", err)
	}
	return root
}

func socketTestRootDirPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir for socket tests: %w", err)
	}
	root := filepath.Join(homeDir, ".ess")
	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", fmt.Errorf("create socket test root: %w", err)
	}
	return root, nil
}

func TestSubmitPublicRouteRejectsStructuralReliableBody(t *testing.T) {
	stack := startStack(t, stackOptions{}) // local TLS/ARS/EGS fixtures; Submit is unavailable
	var body map[string]any
	if err := json.Unmarshal(buildPrepareRequestBody(t, stack), &body); err != nil {
		t.Fatal(err)
	}
	body["schema_version"] = "execution-substrate.reliable-submit-request/v1"
	body["reliable_submit"] = map[string]any{
		"contract":   "execution-substrate.reliable-submit/v1",
		"submit_key": "fixture-key",
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	response := doJSONRequest(t, stack.es.Addr(), http.MethodPost, "/v1/executions:submit",
		stack.fixture.clientTLSConfig(t, "operator/local", false), encoded)
	defer response.Body.Close()
	assertErrorResponseCode(t, response, http.StatusBadRequest, "invalid_request")
}
