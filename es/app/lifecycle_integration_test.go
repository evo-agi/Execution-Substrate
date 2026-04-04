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
	jobID := stack.nomad.waitForExecutionJob(t, submitted.RunID)

	var status admission.ExecutionStatusResult
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		response := doJSONRequest(
			t,
			stack.es.Addr(),
			http.MethodGet,
			"/v1/executions/"+submitted.RunID+"/status",
			stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "operator", false),
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
		if status.Status != "submitted" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if status.Status == "submitted" {
		t.Fatalf("expected status to advance beyond submitted: %+v", status)
	}

	allocation := stack.nomad.waitForTerminalAllocation(t, jobID)
	task, ok := allocation.TaskStates["task"]
	if !ok {
		t.Fatalf("expected task state for task")
	}

	response := doJSONRequest(
		t,
		stack.es.Addr(),
		http.MethodGet,
		"/v1/executions/"+submitted.RunID+"/status",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "operator", false),
		nil,
	)
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}
	if err := json.NewDecoder(response.Body).Decode(&status); err != nil {
		t.Fatalf("decode terminal status response: %v", err)
	}

	if !status.Success {
		t.Fatalf("expected success status response: %+v", status)
	}
	if status.RunID != submitted.RunID {
		t.Fatalf("expected run_id %q, got %q", submitted.RunID, status.RunID)
	}
	if status.Status != "terminal" {
		t.Fatalf("expected terminal status, got %+v", status)
	}
	if !status.Terminal {
		t.Fatalf("expected terminal=true once allocation is terminal: %+v", status)
	}
	if exitCode := task.exitCode(); status.ExitCode == nil || *status.ExitCode != exitCode {
		t.Fatalf("expected exit code %d, got %+v", exitCode, status)
	}
}

func TestExecutionLogsReturnRealContainerOutput(t *testing.T) {
	stack := startSubmitStack(t)
	submitted := submitExecution(t, stack, 10, 128)
	allocation := stack.nomad.waitForTerminalExecutionAllocation(t, submitted.RunID)
	if allocation.ClientStatus != "complete" {
		t.Fatalf("expected complete allocation, got %q", allocation.ClientStatus)
	}

	response := doJSONRequest(
		t,
		stack.es.Addr(),
		http.MethodGet,
		"/v1/executions/"+submitted.RunID+"/logs",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "operator", false),
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
	if !strings.Contains(logs, `"status":"ok"`) || !strings.Contains(logs, stack.publishResponse.ArtifactDigest) {
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
	stack.nomad.waitForExecutionJob(t, submitted.RunID)

	response := doJSONRequest(
		t,
		stack.es.Addr(),
		http.MethodPost,
		"/v1/executions/"+submitted.RunID+":cancel",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "operator", false),
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
	if payload.RunID != submitted.RunID {
		t.Fatalf("unexpected cancel response: %+v", payload)
	}
	if payload.Status != "cancel_requested" {
		t.Fatalf("expected cancel_requested status, got %+v", payload)
	}

	job := stack.nomad.waitForExecutionJobTerminalStatus(t, submitted.RunID)
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
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "operator", false),
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
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "operator", false),
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
	stack.nomad.waitForExecutionJob(t, submitted.RunID)

	response := doJSONRequest(
		t,
		stack.es.Addr(),
		http.MethodGet,
		"/v1/executions/"+submitted.RunID+"/logs",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "operator", false),
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
	stack.nomad.waitForExecutionJob(t, submitted.RunID)
	stack.nomad.shutdown(t)

	response := doJSONRequest(
		t,
		stack.es.Addr(),
		http.MethodGet,
		"/v1/executions/"+submitted.RunID+"/status",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "operator", false),
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
	stack.nomad.waitForExecutionJob(t, submitted.RunID)
	stack.nomad.waitForTerminalExecutionAllocation(t, submitted.RunID)

	response := doJSONRequest(
		t,
		stack.es.Addr(),
		http.MethodGet,
		"/v1/executions/"+submitted.RunID+"/status",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "operator", false),
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
	if payload.Status != "terminal" {
		t.Fatalf("expected terminal status label, got %+v", payload)
	}
	if payload.ExitCode == nil || *payload.ExitCode != 7 {
		t.Fatalf("expected exit code 7, got %+v", payload)
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
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "operator", false),
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
			"runtime": map[string]any{
				"environment_variables": []string{"APP_MODE"},
				"required_capabilities": []string{},
			},
			"access": map[string]any{
				"network_access": false,
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
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.agsServerName, "operator", false),
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
