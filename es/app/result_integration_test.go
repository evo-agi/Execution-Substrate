package app_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"execution-substrate/es/admission"
)

func TestExecutionResultBundleAndStageRetainedAcrossStatusAndRepeatFetch(t *testing.T) {
	stack := startRuntimeIdentitySubmitStack(t)
	publishSubmitArtifactArchive(t, stack, buildArchiveFromScript(t, `#!/bin/sh
set -eu
echo START-BANNER
mkdir -p /execution/run/result/nested
printf 'artifact_digest=%s\n' "${EXEC_ARTIFACT_DIGEST}" > /execution/run/result/summary.txt
printf '{"status":"ok","kind":"retained-result"}\n' > /execution/run/result/nested/result.json
echo RESULT-WROTE
`))

	submitted := submitExecution(t, stack, 10, 128)
	stageRoot := filepath.Join(stack.rootDir, "es-stage", submitted.RunID)
	requirePathExists(t, stageRoot)

	allocation := stack.nomad.waitForTerminalExecutionAllocation(t, submitted.RunID)
	if allocation.ClientStatus != "complete" {
		t.Fatalf("expected complete allocation, got %q stdout=%q stderr=%q", allocation.ClientStatus, stack.nomad.allocLogs(t, allocation.ID), stack.nomad.allocStderrLogs(t, allocation.ID))
	}

	status := fetchExecutionStatus(t, stack, submitted.RunID)
	if !status.Terminal || status.ExitCode == nil || *status.ExitCode != 0 {
		t.Fatalf("expected terminal success status, got %+v", status)
	}
	requirePathExists(t, stageRoot)

	first := fetchExecutionResultBundle(t, stack, submitted.RunID, "operator/local")
	second := fetchExecutionResultBundle(t, stack, submitted.RunID, "operator/local")
	if !bytes.Equal(first, second) {
		t.Fatalf("expected repeat result fetch to return stable retained bundle bytes")
	}

	entries := readResultBundleEntries(t, first)
	if got := strings.TrimSpace(entries["summary.txt"]); got != "artifact_digest="+stack.publishResponse.ArtifactDigest {
		t.Fatalf("unexpected summary.txt content %q entries=%v", got, entries)
	}
	if got := strings.TrimSpace(entries["nested/result.json"]); got != `{"status":"ok","kind":"retained-result"}` {
		t.Fatalf("unexpected nested result content %q entries=%v", got, entries)
	}
	requirePathExists(t, stageRoot)
}

func TestExecutionResultReturns404ForTerminalExecutionWithoutResultOutput(t *testing.T) {
	stack := startRuntimeIdentitySubmitStack(t)
	submitted := submitExecution(t, stack, 10, 128)
	stageRoot := filepath.Join(stack.rootDir, "es-stage", submitted.RunID)
	stack.nomad.waitForTerminalExecutionAllocation(t, submitted.RunID)
	fetchExecutionStatus(t, stack, submitted.RunID)

	response := executionResultRequestWithCaller(t, stack, submitted.RunID, "operator/local")
	defer response.Body.Close()

	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}
	var payload admission.ErrorResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode result error response: %v", err)
	}
	if payload.Code != "result_not_found" {
		t.Fatalf("expected result_not_found, got %+v", payload)
	}
	requirePathExists(t, stageRoot)
}

func TestExecutionResultReturns403WhenCallerIsDisallowed(t *testing.T) {
	stack := startSubmitStackWithoutNomad(t)

	response := executionResultRequestWithCaller(t, stack, "run-deadbeefdeadbeef", "service/deployment")
	defer response.Body.Close()

	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}
	if got := strings.TrimSpace(string(mustReadBody(t, response.Body))); got != "Caller not authorized for this operation" {
		t.Fatalf("unexpected body: %q", got)
	}
}

func fetchExecutionResultBundle(t *testing.T, stack *submitStack, runID string, callerPath string) []byte {
	t.Helper()

	response := executionResultRequestWithCaller(t, stack, runID, callerPath)
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}
	if contentType := response.Header.Get("Content-Type"); contentType != "application/gzip" {
		t.Fatalf("expected application/gzip content type, got %q", contentType)
	}
	return mustReadBody(t, response.Body)
}

func readResultBundleEntries(t *testing.T, payload []byte) map[string]string {
	t.Helper()

	gzipReader, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("open result bundle gzip stream: %v", err)
	}
	defer gzipReader.Close()

	entries := map[string]string{}
	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read result bundle tar entry: %v", err)
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			continue
		}
		body, err := io.ReadAll(tarReader)
		if err != nil {
			t.Fatalf("read result bundle entry %s: %v", header.Name, err)
		}
		entries[header.Name] = string(body)
	}
	return entries
}
