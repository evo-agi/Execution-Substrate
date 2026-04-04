package app_test

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"execution-platform/es/admission"
)

func TestExecutionStatusCleansSuccessfulStageRootAndLogsStillWork(t *testing.T) {
	stack := startSubmitStack(t)
	submitted := submitExecution(t, stack, 10, 128)
	stageRoot := filepath.Join(stack.rootDir, "es-stage", submitted.RunID)

	requirePathExists(t, stageRoot)
	allocation := stack.nomad.waitForTerminalExecutionAllocation(t, submitted.RunID)
	if allocation.ClientStatus != "complete" {
		t.Fatalf("expected complete allocation, got %q", allocation.ClientStatus)
	}

	status := fetchExecutionStatus(t, stack, submitted.RunID)
	if !status.Terminal || status.Status != "terminal" {
		t.Fatalf("expected terminal success status, got %+v", status)
	}
	if status.ExitCode == nil || *status.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %+v", status)
	}

	waitForPathRemoved(t, stageRoot)

	logs := fetchExecutionLogs(t, stack, submitted.RunID)
	if !strings.Contains(logs, "START-BANNER") {
		t.Fatalf("expected logs to remain readable after cleanup, got %q", logs)
	}
}

func TestExecutionStatusRetainsFailedStageRootForDebugging(t *testing.T) {
	stack := startSubmitStack(t)
	publishSubmitArtifactArchive(t, stack, buildArchiveFromScript(t, `#!/bin/sh
set -eu
echo START-BANNER
echo FAILING
exit 7
`))

	submitted := submitExecution(t, stack, 10, 128)
	stageRoot := filepath.Join(stack.rootDir, "es-stage", submitted.RunID)

	requirePathExists(t, stageRoot)
	stack.nomad.waitForTerminalExecutionAllocation(t, submitted.RunID)

	status := fetchExecutionStatus(t, stack, submitted.RunID)
	if !status.Terminal || status.Status != "terminal" {
		t.Fatalf("expected terminal failure status, got %+v", status)
	}
	if status.ExitCode == nil || *status.ExitCode != 7 {
		t.Fatalf("expected exit code 7, got %+v", status)
	}

	requirePathExists(t, stageRoot)

	logs := fetchExecutionLogs(t, stack, submitted.RunID)
	if !strings.Contains(logs, "FAILING") {
		t.Fatalf("expected failure logs to remain readable, got %q", logs)
	}
}

func TestExecutionCancelRetainsStageRootForDebugging(t *testing.T) {
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
	stageRoot := filepath.Join(stack.rootDir, "es-stage", submitted.RunID)

	requirePathExists(t, stageRoot)
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

	var cancelPayload admission.ExecutionCancelResult
	if err := json.NewDecoder(response.Body).Decode(&cancelPayload); err != nil {
		t.Fatalf("decode cancel response: %v", err)
	}
	if cancelPayload.Status != "cancel_requested" {
		t.Fatalf("expected cancel_requested status, got %+v", cancelPayload)
	}

	stack.nomad.waitForJobTerminalStatus(t, "exec-"+submitted.RunID)
	fetchExecutionStatus(t, stack, submitted.RunID)

	requirePathExists(t, stageRoot)
}

func TestExecutionLoopScriptSuccessCleansSuccessfulStageRootsAcrossRepeatedRuns(t *testing.T) {
	stack := startSubmitStack(t)

	specPath := writeExecutionLoopSpec(
		t,
		t.TempDir(),
		"cleanup-loop-success",
		`#!/bin/sh
set -eu
echo START-BANNER
echo "{\"status\":\"ok\",\"artifact_digest\":\"${EXEC_ARTIFACT_DIGEST}\"}"
`,
		"build log cleanup proof\n",
	)

	first := runExecutionLoopScript(t, stack, specPath, t.TempDir())
	if first.ExitCode != 0 || !first.Summary.OK {
		t.Fatalf("expected first loop run to succeed, got exit=%d summary=%+v stdout=%s", first.ExitCode, first.Summary, first.Stdout)
	}
	waitForPathRemoved(t, filepath.Join(stack.rootDir, "es-stage", first.Summary.RunID))

	second := runExecutionLoopScript(t, stack, specPath, t.TempDir())
	if second.ExitCode != 0 || !second.Summary.OK {
		t.Fatalf("expected second loop run to succeed, got exit=%d summary=%+v stdout=%s", second.ExitCode, second.Summary, second.Stdout)
	}
	waitForPathRemoved(t, filepath.Join(stack.rootDir, "es-stage", second.Summary.RunID))

	stageEntries, err := os.ReadDir(filepath.Join(stack.rootDir, "es-stage"))
	if err != nil {
		t.Fatalf("read staging root: %v", err)
	}
	if len(stageEntries) != 0 {
		t.Fatalf("expected no successful stage roots to remain, found %d", len(stageEntries))
	}
}

func fetchExecutionStatus(t *testing.T, stack *submitStack, runID string) admission.ExecutionStatusResult {
	t.Helper()

	response := doJSONRequest(
		t,
		stack.es.Addr(),
		http.MethodGet,
		"/v1/executions/"+runID+"/status",
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
	return payload
}

func fetchExecutionLogs(t *testing.T, stack *submitStack, runID string) string {
	t.Helper()

	response := doJSONRequest(
		t,
		stack.es.Addr(),
		http.MethodGet,
		"/v1/executions/"+runID+"/logs",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "operator", false),
		nil,
	)
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}
	return string(mustReadBody(t, response.Body))
}

func requirePathExists(t *testing.T, target string) {
	t.Helper()

	if _, err := os.Stat(target); err != nil {
		t.Fatalf("expected path %s to exist: %v", target, err)
	}
}

func waitForPathRemoved(t *testing.T, target string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(target); os.IsNotExist(err) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}

	if _, err := os.Stat(target); err == nil {
		t.Fatalf("expected path %s to be removed", target)
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat %s: %v", target, err)
	}
}
