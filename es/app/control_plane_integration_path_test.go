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

	"execution-substrate/es/admission"
)

func TestControlPlaneStaticScriptAPIPathSucceeds(t *testing.T) {
	stack := startSubmitStackWithOptions(t, submitStackOptions{
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
	payloadPath := filepath.Join(workdirBase, "control-plane-static-script.tar.gz")
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
		t.Fatalf("write control-plane payload archive: %v", err)
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
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run control-plane api path: %v output=%s", err, string(output))
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

	statusResponse := executionStatusRequestWithCaller(t, stack, runID, "service/control-plane")
	defer statusResponse.Body.Close()
	if statusResponse.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from control-plane status, got %d body=%s", statusResponse.StatusCode, strings.TrimSpace(string(mustReadBody(t, statusResponse.Body))))
	}
	var statusPayload admission.ExecutionStatusResult
	if err := json.NewDecoder(statusResponse.Body).Decode(&statusPayload); err != nil {
		t.Fatalf("decode control-plane status response: %v", err)
	}
	if !statusPayload.Success || statusPayload.RunID != runID {
		t.Fatalf("expected control-plane status for run %q, got %+v", runID, statusPayload)
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
