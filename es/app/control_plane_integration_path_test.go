package app_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestControlPlaneStaticScriptAPIPathFetchesRetainedResultBundle(t *testing.T) {
	stack := startRuntimeIdentitySubmitStackWithOptions(t, submitStackOptions{
		allowedAGSCallerPrefixes:       []string{"operator", "service/control-plane"},
		allowedExecutionCallerPrefixes: []string{"operator", "service/control-plane"},
	})

	repoRoot := executionPlatformRepoRoot(t)
	scriptPath := filepath.Join(repoRoot, ".examples", "control_plane_static_script", "run.sh")
	controlPlaneCertPath, controlPlaneKeyPath := writeLeafCertificateFiles(
		t,
		t.TempDir(),
		"control-plane-result-api",
		stack.fixture.runtimeCA,
		stack.fixture.runtimeCAKey,
		"client.control-plane",
		[]*url.URL{mustSPIFFEURL(t, "spiffe://execution.internal/service/control-plane")},
	)

	agsHost, agsPort, err := splitHostPort(t, stack.ags.Addr())
	if err != nil {
		t.Fatalf("split ags addr: %v", err)
	}
	esHost, esPort, err := splitHostPort(t, stack.es.Addr())
	if err != nil {
		t.Fatalf("split es addr: %v", err)
	}

	workdirBase := t.TempDir()
	buildLogPath := filepath.Join(workdirBase, "build.log")
	if err := os.WriteFile(buildLogPath, []byte("control-plane retained result build log\n"), 0o600); err != nil {
		t.Fatalf("write control-plane build log: %v", err)
	}

	cmd := exec.Command(scriptPath)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"AGS_URL=https://"+stack.fixture.agsServerName+":"+agsPort,
		"AGS_RESOLVE="+stack.fixture.agsServerName+":"+agsPort+":"+agsHost,
		"ES_URL=https://"+stack.fixture.esServerName+":"+esPort,
		"ES_RESOLVE="+stack.fixture.esServerName+":"+esPort+":"+esHost,
		"CA_CERT="+stack.fixture.runtimeCAPath,
		"CONTROL_PLANE_CERT="+controlPlaneCertPath,
		"CONTROL_PLANE_KEY="+controlPlaneKeyPath,
		"WORKDIR_BASE="+workdirBase,
		"BUILD_LOG_PATH="+buildLogPath,
		"TIMEOUT_SECONDS=20",
		"POLL_INTERVAL_SECONDS=1",
		"WAIT_FOR_TERMINAL=1",
		"FETCH_LOGS=0",
		"GENERATE_RESULT_PAYLOAD=1",
		"FETCH_RESULT=1",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run control-plane retained result api path: %v output=%s", err, string(output))
	}

	text := string(output)
	if !strings.Contains(text, "publish: success artifact_digest=") {
		t.Fatalf("expected publish success marker, got %s", text)
	}
	if !strings.Contains(text, "submit: success run_id=run-") {
		t.Fatalf("expected submit success marker, got %s", text)
	}
	if !strings.Contains(text, "result: success bytes=") {
		t.Fatalf("expected result success marker, got %s", text)
	}

	summaryPath := summaryPathFromScriptOutput(t, text)
	summaryBytes, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatalf("read summary path %s: %v", summaryPath, err)
	}
	var summary map[string]any
	if err := json.Unmarshal(summaryBytes, &summary); err != nil {
		t.Fatalf("decode summary json: %v", err)
	}
	if got := summary["caller_path"]; got != "spiffe://execution.internal/service/control-plane" {
		t.Fatalf("expected control-plane caller path in summary, got %v", got)
	}
	if got := summary["result_retrieved"]; got != true {
		t.Fatalf("expected result_retrieved=true in summary, got %v", got)
	}

	workdir, ok := summary["workdir"].(string)
	if !ok || strings.TrimSpace(workdir) == "" {
		t.Fatalf("expected workdir in summary, got %#v", summary["workdir"])
	}
	resultPath := filepath.Join(workdir, "result.tar.gz")
	resultBytes, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatalf("read result bundle %s: %v", resultPath, err)
	}
	entries := readResultBundleEntries(t, resultBytes)
	if !strings.Contains(entries["summary.txt"], "artifact_digest=sha256:") {
		t.Fatalf("expected artifact digest summary in result bundle, got entries=%v", entries)
	}
	if got := strings.TrimSpace(entries["nested/result.json"]); got != `{"status":"ok","source":"control-plane-static-script"}` {
		t.Fatalf("unexpected nested result content %q entries=%v", got, entries)
	}
}

func TestControlPlaneStaticScriptAPIPathCancelSucceeds(t *testing.T) {
	stack := startRuntimeIdentitySubmitStackWithOptions(t, submitStackOptions{
		allowedAGSCallerPrefixes:       []string{"operator", "service/control-plane"},
		allowedExecutionCallerPrefixes: []string{"operator", "service/control-plane"},
	})

	repoRoot := executionPlatformRepoRoot(t)
	scriptPath := filepath.Join(repoRoot, ".examples", "control_plane_static_script", "run.sh")
	controlPlaneCertPath, controlPlaneKeyPath := writeLeafCertificateFiles(
		t,
		t.TempDir(),
		"control-plane-api",
		stack.fixture.runtimeCA,
		stack.fixture.runtimeCAKey,
		"client.control-plane",
		[]*url.URL{mustSPIFFEURL(t, "spiffe://execution.internal/service/control-plane")},
	)

	agsHost, agsPort, err := splitHostPort(t, stack.ags.Addr())
	if err != nil {
		t.Fatalf("split ags addr: %v", err)
	}
	esHost, esPort, err := splitHostPort(t, stack.es.Addr())
	if err != nil {
		t.Fatalf("split es addr: %v", err)
	}

	workdirBase := t.TempDir()
	payloadPath := filepath.Join(workdirBase, "control-plane-long-running.tar.gz")
	if err := os.WriteFile(payloadPath, buildArchiveFromScript(t, `#!/bin/sh
set -eu
echo START-BANNER
i=1
while [ "$i" -le 30 ]; do
  echo HEARTBEAT:$i
  sleep 1
  i=$((i + 1))
done
echo "{\"status\":\"ok\",\"artifact_digest\":\"${EXEC_ARTIFACT_DIGEST}\"}"
`), 0o600); err != nil {
		t.Fatalf("write control-plane cancel payload archive: %v", err)
	}
	buildLogPath := filepath.Join(workdirBase, "build.log")
	if err := os.WriteFile(buildLogPath, []byte("control-plane integration build log\n"), 0o600); err != nil {
		t.Fatalf("write control-plane build log: %v", err)
	}

	cmd := exec.Command(scriptPath)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"AGS_URL=https://"+stack.fixture.agsServerName+":"+agsPort,
		"AGS_RESOLVE="+stack.fixture.agsServerName+":"+agsPort+":"+agsHost,
		"ES_URL=https://"+stack.fixture.esServerName+":"+esPort,
		"ES_RESOLVE="+stack.fixture.esServerName+":"+esPort+":"+esHost,
		"CA_CERT="+stack.fixture.runtimeCAPath,
		"CONTROL_PLANE_CERT="+controlPlaneCertPath,
		"CONTROL_PLANE_KEY="+controlPlaneKeyPath,
		"WORKDIR_BASE="+workdirBase,
		"PAYLOAD_PATH="+payloadPath,
		"BUILD_LOG_PATH="+buildLogPath,
		"TIMEOUT_SECONDS=15",
		"POLL_INTERVAL_SECONDS=1",
		"WAIT_FOR_TERMINAL=1",
		"CANCEL_AFTER_SUBMIT=1",
		"FETCH_LOGS=0",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run control-plane cancel api path: %v output=%s", err, string(output))
	}

	text := string(output)
	if !strings.Contains(text, "publish: success artifact_digest=") {
		t.Fatalf("expected publish success marker, got %s", text)
	}
	if !strings.Contains(text, "submit: success run_id=run-") {
		t.Fatalf("expected submit success marker, got %s", text)
	}
	if !strings.Contains(text, "status: success state=") {
		t.Fatalf("expected status success marker, got %s", text)
	}
	if !strings.Contains(text, "cancel: success status=cancel_requested") {
		t.Fatalf("expected cancel success marker, got %s", text)
	}
	if strings.Contains(text, "logs: success bytes=") {
		t.Fatalf("did not expect logs success marker in explicit cancel mode, got %s", text)
	}

	summaryPath := summaryPathFromScriptOutput(t, text)
	summaryBytes, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatalf("read summary path %s: %v", summaryPath, err)
	}
	var summary map[string]any
	if err := json.Unmarshal(summaryBytes, &summary); err != nil {
		t.Fatalf("decode summary json: %v", err)
	}
	if got := summary["caller_path"]; got != "spiffe://execution.internal/service/control-plane" {
		t.Fatalf("expected control-plane caller path in summary, got %v", got)
	}
	if got := summary["api_surface"]; got != "direct_https_mtls" {
		t.Fatalf("expected direct api surface marker, got %v", got)
	}
	if got := summary["logs_retrieved"]; got != false {
		t.Fatalf("expected logs_retrieved=false in explicit cancel mode, got %v", got)
	}
	if got := summary["cancel_requested"]; got != true {
		t.Fatalf("expected cancel_requested=true in summary, got %v", got)
	}
	if got := summary["cancel_status"]; got != "cancel_requested" {
		t.Fatalf("expected cancel_status=cancel_requested in summary, got %v", got)
	}

	runID, ok := summary["run_id"].(string)
	if !ok || strings.TrimSpace(runID) == "" {
		t.Fatalf("expected run_id in summary, got %#v", summary["run_id"])
	}
	workdir, ok := summary["workdir"].(string)
	if !ok || strings.TrimSpace(workdir) == "" {
		t.Fatalf("expected workdir in summary, got %#v", summary["workdir"])
	}
	if _, err := os.Stat(filepath.Join(workdir, "cancel-response.json")); err != nil {
		t.Fatalf("expected script cancel response file: %v", err)
	}

	job := stack.nomad.waitForExecutionJobTerminalStatus(t, runID)
	if job.Status != "dead" {
		t.Fatalf("expected dead control-plane job after cancel, got %q", job.Status)
	}

	cancelResponse := executionCancelRequestWithCaller(t, stack, runID, "service/deployment")
	defer cancelResponse.Body.Close()
	if cancelResponse.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 from deployment cancel caller, got %d body=%s", cancelResponse.StatusCode, strings.TrimSpace(string(mustReadBody(t, cancelResponse.Body))))
	}
	if !strings.Contains(strings.TrimSpace(string(mustReadBody(t, cancelResponse.Body))), "Caller not authorized for this operation") {
		t.Fatalf("expected deployment cancel authorization failure body")
	}
}

func TestControlPlaneStaticScriptAPIPathRejectsDisallowedCaller(t *testing.T) {
	stack := startSubmitStackWithOptions(t, submitStackOptions{
		allowedAGSCallerPrefixes:       []string{"operator", "service/control-plane"},
		allowedExecutionCallerPrefixes: []string{"operator", "service/control-plane"},
	})

	repoRoot := executionPlatformRepoRoot(t)
	scriptPath := filepath.Join(repoRoot, ".examples", "control_plane_static_script", "run.sh")
	disallowedCertPath, disallowedKeyPath := writeLeafCertificateFiles(
		t,
		t.TempDir(),
		"deployment-api",
		stack.fixture.runtimeCA,
		stack.fixture.runtimeCAKey,
		"client.deployment",
		[]*url.URL{mustSPIFFEURL(t, "spiffe://execution.internal/service/deployment")},
	)

	agsHost, agsPort, err := splitHostPort(t, stack.ags.Addr())
	if err != nil {
		t.Fatalf("split ags addr: %v", err)
	}
	esHost, esPort, err := splitHostPort(t, stack.es.Addr())
	if err != nil {
		t.Fatalf("split es addr: %v", err)
	}

	cmd := exec.Command(scriptPath)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"AGS_URL=https://"+stack.fixture.agsServerName+":"+agsPort,
		"AGS_RESOLVE="+stack.fixture.agsServerName+":"+agsPort+":"+agsHost,
		"ES_URL=https://"+stack.fixture.esServerName+":"+esPort,
		"ES_RESOLVE="+stack.fixture.esServerName+":"+esPort+":"+esHost,
		"CA_CERT="+stack.fixture.runtimeCAPath,
		"CONTROL_PLANE_CERT="+disallowedCertPath,
		"CONTROL_PLANE_KEY="+disallowedKeyPath,
		"WORKDIR_BASE="+t.TempDir(),
	)

	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected disallowed control-plane api path to fail, output=%s", string(output))
	}
	text := string(output)
	if !strings.Contains(text, "publish failed: http_status=403") {
		t.Fatalf("expected publish 403 marker, got %s", text)
	}
	if !strings.Contains(text, "Caller not authorized for this operation") {
		t.Fatalf("expected caller authorization failure body, got %s", text)
	}
}

func summaryPathFromScriptOutput(t *testing.T, output string) string {
	t.Helper()

	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "summary=") {
			return strings.TrimSpace(strings.TrimPrefix(line, "summary="))
		}
	}
	t.Fatalf("missing summary= line in output: %s", output)
	return ""
}
