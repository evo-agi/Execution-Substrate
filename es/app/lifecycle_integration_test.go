package app_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"execution-platform/es/admission"
)

func TestExecutionStatusReflectsNomadJobState(t *testing.T) {
	stack := startSubmitStack(t)
	submitted := submitExecution(t, stack, 10, 128)

	stack.nomad.waitForJob(t, submitted.NomadJobID)

	var status admission.ExecutionStatusResult
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		response := doJSONRequest(
			t,
			stack.es.Addr(),
			http.MethodGet,
			"/v1/executions/"+submitted.RunID+"/status",
			stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "service/deployment", false),
			nil,
		)
		if response.StatusCode != http.StatusOK {
			body := strings.TrimSpace(string(mustReadBody(t, response.Body)))
			response.Body.Close()
			t.Fatalf("expected 200, got %d body=%s", response.StatusCode, body)
		}
		if err := json.NewDecoder(response.Body).Decode(&status); err != nil {
			response.Body.Close()
			t.Fatalf("decode status response: %v", err)
		}
		response.Body.Close()
		if strings.TrimSpace(status.AllocationID) != "" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if strings.TrimSpace(status.AllocationID) == "" {
		t.Fatalf("expected allocation_id in status response: %+v", status)
	}

	job := stack.nomad.fetchJob(t, submitted.NomadJobID)
	if !status.Success {
		t.Fatalf("expected success status response: %+v", status)
	}
	if status.RunID != submitted.RunID {
		t.Fatalf("expected run_id %q, got %q", submitted.RunID, status.RunID)
	}
	if status.NomadJobID != submitted.NomadJobID {
		t.Fatalf("expected nomad_job_id %q, got %q", submitted.NomadJobID, status.NomadJobID)
	}
	if status.JobStatus != job.Status {
		t.Fatalf("expected job_status %q, got %q", job.Status, status.JobStatus)
	}

	allocation := stack.nomad.fetchAllocation(t, status.AllocationID)
	if status.AllocationClientStatus != allocation.ClientStatus {
		t.Fatalf("expected allocation_client_status %q, got %q", allocation.ClientStatus, status.AllocationClientStatus)
	}
	task, ok := allocation.TaskStates["task"]
	if !ok {
		if status.TaskState != "" {
			t.Fatalf("expected empty task_state when Nomad task state is unavailable, got %q", status.TaskState)
		}
		return
	}
	if status.TaskState != task.State {
		t.Fatalf("expected task_state %q, got %q", task.State, status.TaskState)
	}
}

func TestExecutionLogsReturnRealContainerOutput(t *testing.T) {
	stack := startSubmitStack(t)
	submitted := submitExecution(t, stack, 10, 128)

	stack.nomad.waitForJob(t, submitted.NomadJobID)
	allocation := stack.nomad.waitForTerminalAllocation(t, submitted.NomadJobID)
	if allocation.ClientStatus != "complete" {
		t.Fatalf("expected complete allocation, got %q", allocation.ClientStatus)
	}

	response := doJSONRequest(
		t,
		stack.es.Addr(),
		http.MethodGet,
		"/v1/executions/"+submitted.RunID+"/logs",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "service/deployment", false),
		nil,
	)
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}

	logs := string(mustReadBody(t, response.Body))
	if !strings.Contains(logs, "START-BANNER") {
		t.Fatalf("expected start banner in logs, got %q", logs)
	}
	if !strings.Contains(logs, "HEARTBEAT:1") || !strings.Contains(logs, "HEARTBEAT:2") || !strings.Contains(logs, "HEARTBEAT:3") {
		t.Fatalf("expected heartbeat lines in logs, got %q", logs)
	}
	if !strings.Contains(logs, `"status":"ok"`) || !strings.Contains(logs, submitted.ArtifactDigest) {
		t.Fatalf("expected final json marker in logs, got %q", logs)
	}
}

func TestExecutionCancelStopsNomadJob(t *testing.T) {
	stack := startSubmitStack(t)
	publishSubmitArtifactArchive(t, stack, buildArchiveFromScript(t, `#!/bin/sh
set -eu
echo START-BANNER
i=1
while [ "$i" -le 30 ]; do
  echo HEARTBEAT:$i
  sleep 1
  i=$((i + 1))
done
echo "{\"status\":\"ok\",\"artifact_digest\":\"${EXEC_ARTIFACT_DIGEST}\"}"
`))

	submitted := submitExecution(t, stack, 10, 128)
	stack.nomad.waitForJob(t, submitted.NomadJobID)

	response := doJSONRequest(
		t,
		stack.es.Addr(),
		http.MethodPost,
		"/v1/executions/"+submitted.RunID+":cancel",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "service/deployment", false),
		nil,
	)
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}

	var payload admission.ExecutionCancelResult
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode cancel response: %v", err)
	}
	if !payload.Success {
		t.Fatalf("expected successful cancel response: %+v", payload)
	}
	if payload.RunID != submitted.RunID || payload.NomadJobID != submitted.NomadJobID {
		t.Fatalf("unexpected cancel response: %+v", payload)
	}

	job := stack.nomad.waitForJobTerminalStatus(t, submitted.NomadJobID)
	if job.Status != "dead" {
		t.Fatalf("expected dead job after cancel, got %q", job.Status)
	}
}

func TestExecutionLifecycleRejectsInvalidRunID(t *testing.T) {
	stack := startSubmitStack(t)

	response := doJSONRequest(
		t,
		stack.es.Addr(),
		http.MethodGet,
		"/v1/executions/not-a-run-id/status",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "service/deployment", false),
		nil,
	)
	defer response.Body.Close()

	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}
}

func TestExecutionLifecycleMissingJobReturns404(t *testing.T) {
	stack := startSubmitStack(t)

	response := doJSONRequest(
		t,
		stack.es.Addr(),
		http.MethodGet,
		"/v1/executions/run-deadbeefdeadbeef/status",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "service/deployment", false),
		nil,
	)
	defer response.Body.Close()

	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}
}

func TestExecutionLogsReturnConflictWhenAllocationNotReady(t *testing.T) {
	stack := startSubmitStack(t)
	submitted := submitExecution(t, stack, 999999, 999999)
	stack.nomad.waitForJob(t, submitted.NomadJobID)

	response := doJSONRequest(
		t,
		stack.es.Addr(),
		http.MethodGet,
		"/v1/executions/"+submitted.RunID+"/logs",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "service/deployment", false),
		nil,
	)
	defer response.Body.Close()

	if response.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}
}

func TestExecutionStatusReturns503WhenNomadUnavailable(t *testing.T) {
	stack := startSubmitStack(t)
	submitted := submitExecution(t, stack, 10, 128)
	stack.nomad.waitForJob(t, submitted.NomadJobID)
	stack.nomad.shutdown(t)

	response := doJSONRequest(
		t,
		stack.es.Addr(),
		http.MethodGet,
		"/v1/executions/"+submitted.RunID+"/status",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "service/deployment", false),
		nil,
	)
	defer response.Body.Close()

	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}
}

func TestExecutionStatusReflectsFailedAllocation(t *testing.T) {
	stack := startSubmitStack(t)
	publishSubmitArtifactArchive(t, stack, buildArchiveFromScript(t, `#!/bin/sh
set -eu
echo START-BANNER
echo FAILING
exit 7
`))

	submitted := submitExecution(t, stack, 10, 128)
	stack.nomad.waitForJob(t, submitted.NomadJobID)
	stack.nomad.waitForTerminalAllocation(t, submitted.NomadJobID)

	response := doJSONRequest(
		t,
		stack.es.Addr(),
		http.MethodGet,
		"/v1/executions/"+submitted.RunID+"/status",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "service/deployment", false),
		nil,
	)
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}

	var payload admission.ExecutionStatusResult
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode status response: %v", err)
	}
	if !payload.Terminal {
		t.Fatalf("expected terminal status for failed allocation: %+v", payload)
	}
	if payload.ExitCode == nil || *payload.ExitCode != 7 {
		t.Fatalf("expected exit code 7, got %+v", payload)
	}
	if payload.AllocationClientStatus != "failed" {
		t.Fatalf("expected failed allocation status, got %+v", payload)
	}
}

func submitExecution(t *testing.T, stack *submitStack, cpu int, memoryMB int) admission.SubmitResult {
	t.Helper()

	requestBody := mustMarshalJSON(t, admission.PrepareRequest{
		SchemaVersion: "v1",
		Invocation: admission.ArtifactInvocation{
			SchemaVersion:        "v1",
			ArtifactDigest:       stack.publishResponse.ArtifactDigest,
			DerivationSpecDigest: stack.derivationSpecDigest,
			OutputID:             stack.outputID,
			Env: map[string]string{
				"APP_MODE": "test",
			},
		},
		Mode: admission.ExecutionModeAsync,
		Resources: &admission.ExecutionResources{
			CPU:      cpu,
			MemoryMB: memoryMB,
		},
	})

	response := doJSONRequest(
		t,
		stack.es.Addr(),
		http.MethodPost,
		"/v1/executions:submit",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "service/deployment", false),
		requestBody,
	)
	defer response.Body.Close()

	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}

	var payload admission.SubmitResult
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode submit response: %v", err)
	}
	return payload
}

func publishSubmitArtifactArchive(t *testing.T, stack *submitStack, archive []byte) {
	t.Helper()

	requestBody := mustMarshalJSON(t, map[string]any{
		"artifact_payload_b64": base64.StdEncoding.EncodeToString(archive),
		"manifest": map[string]any{
			"artifact_type": "static-script",
			"intent_digest": stack.intentDigest,
			"runtime_interface": map[string]any{
				"parameters":            []string{},
				"environment_variables": []string{"APP_MODE"},
				"required_capabilities": []string{},
			},
		},
		"provenance": map[string]any{
			"builder_service": "artifact-governance",
			"invoker": map[string]any{
				"service":   "deployment",
				"principal": "spiffe://monolith.internal/service/deployment",
			},
			"policy_decisions": []map[string]any{
				{"rule": "allow", "result": "applied"},
			},
			"build_log_digest": labeledDigest("ee"),
		},
		"derivation_metadata": map[string]any{
			"derivation_spec_digest": stack.derivationSpecDigest,
			"output_id":              stack.outputID,
			"producer_run_id":        "build-run-1",
		},
		"derivation_attestation": map[string]any{
			"constraints": map[string]any{
				"allowed_toolchains":      []string{},
				"forbidden_toolchains":    []string{},
				"os":                      "linux",
				"arch":                    "amd64",
				"network_access":          false,
				"writable_paths":          []string{},
				"forbidden_paths":         []string{},
				"determinism_expectation": "deterministic",
			},
			"policy_version":         "2026-03-31",
			"expected_artifact_type": "static-script",
		},
		"workload_identity_binding": map[string]any{
			"artifact_class":       "service",
			"workload_type":        "service",
			"module_path":          "services.execution.ExecutionServer",
			"policy_version":       "2026-03-31",
			"service_name":         "execution",
			"target_platform":      "docker",
			"description":          "Execution workload",
			"workload_identity_id": stack.workloadIdentityID,
		},
	})

	response := doJSONRequest(
		t,
		stack.ags.Addr(),
		http.MethodPost,
		"/v1/artifacts:publish",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.agsServerName, "service/deployment", false),
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

func buildArchiveFromScript(t *testing.T, script string) []byte {
	t.Helper()

	var archiveBuffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&archiveBuffer)
	tarWriter := tar.NewWriter(gzipWriter)

	scriptBytes := []byte(strings.TrimPrefix(script, "\n"))
	header := &tar.Header{
		Name: "entrypoint",
		Mode: 0o755,
		Size: int64(len(scriptBytes)),
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

type nomadJobSummary struct {
	ID     string `json:"ID"`
	Status string `json:"Status"`
}

func (n *nomadHarness) fetchJob(t *testing.T, jobID string) nomadJobSummary {
	t.Helper()

	response, err := (&http.Client{Timeout: 2 * time.Second}).Get(n.addr + "/v1/job/" + jobID)
	if err != nil {
		t.Fatalf("fetch job %s: %v", jobID, err)
	}
	defer response.Body.Close()

	var payload nomadJobSummary
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode job %s: %v", jobID, err)
	}
	return payload
}

func (n *nomadHarness) waitForJobTerminalStatus(t *testing.T, jobID string) nomadJobSummary {
	t.Helper()

	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		response, err := client.Get(n.addr + "/v1/job/" + jobID)
		if err == nil {
			var payload nomadJobSummary
			decodeErr := json.NewDecoder(response.Body).Decode(&payload)
			response.Body.Close()
			if decodeErr == nil && payload.Status == "dead" {
				return payload
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("nomad job %s did not reach terminal status", jobID)
	return nomadJobSummary{}
}
