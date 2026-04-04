package app_test

import (
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type executionLoopSummary struct {
	OK                   bool   `json:"ok"`
	FailedPhase          string `json:"failed_phase"`
	Message              string `json:"message"`
	ErrorCode            string `json:"error_code"`
	HTTPStatus           *int   `json:"http_status"`
	ArtifactDigest       string `json:"artifact_digest"`
	IntentDigest         string `json:"intent_digest"`
	DerivationSpecDigest string `json:"derivation_spec_digest"`
	BuildLogDigest       string `json:"build_log_digest"`
	RunID                string `json:"run_id"`
	State                string `json:"state"`
	Terminal             bool   `json:"terminal"`
	ExitCode             *int   `json:"exit_code"`
	LogsPath             string `json:"logs_path"`
	LogsAvailable        bool   `json:"logs_available"`
	SpecPath             string `json:"spec_path"`
	Workdir              string `json:"workdir"`
}

type executionLoopResult struct {
	Summary  executionLoopSummary
	Logs     string
	Stdout   string
	Stderr   string
	ExitCode int
}

func TestExecuteLoopScriptSuccessAndDeterministicDigests(t *testing.T) {
	stack := startSubmitStack(t)

	specPath := writeExecutionLoopSpec(
		t,
		t.TempDir(),
		"loop-success",
		`#!/bin/sh
set -eu
echo START-BANNER
echo "APP_MODE=${APP_MODE}"
echo "UNICODE=pi-π"
echo "{\"status\":\"ok\",\"artifact_digest\":\"${EXEC_ARTIFACT_DIGEST}\"}"
`,
		"build log café\n",
	)

	first := runExecutionLoopScript(t, stack, specPath, t.TempDir())
	if first.ExitCode != 0 {
		t.Fatalf("expected success exit code, got %d stdout=%s stderr=%s", first.ExitCode, first.Stdout, first.Stderr)
	}
	if !first.Summary.OK {
		t.Fatalf("expected ok summary, got %+v", first.Summary)
	}
	if first.Summary.FailedPhase != "" {
		t.Fatalf("expected empty failed_phase, got %q", first.Summary.FailedPhase)
	}
	if first.Summary.State != "terminal" || !first.Summary.Terminal {
		t.Fatalf("expected terminal summary state, got %+v", first.Summary)
	}
	if first.Summary.ExitCode == nil || *first.Summary.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %+v", first.Summary)
	}
	if !first.Summary.LogsAvailable {
		t.Fatalf("expected logs_available=true, got %+v", first.Summary)
	}
	if !strings.Contains(first.Logs, "START-BANNER") || !strings.Contains(first.Logs, "UNICODE=pi-π") {
		t.Fatalf("expected log markers in %q", first.Logs)
	}
	if !strings.Contains(first.Logs, first.Summary.ArtifactDigest) {
		t.Fatalf("expected artifact digest in logs, got %q", first.Logs)
	}

	second := runExecutionLoopScript(t, stack, specPath, t.TempDir())
	if second.ExitCode != 0 || !second.Summary.OK {
		t.Fatalf("expected second run success, got exit=%d summary=%+v stdout=%s stderr=%s", second.ExitCode, second.Summary, second.Stdout, second.Stderr)
	}

	if first.Summary.IntentDigest != second.Summary.IntentDigest {
		t.Fatalf("expected stable intent digest, got %q vs %q", first.Summary.IntentDigest, second.Summary.IntentDigest)
	}
	if first.Summary.DerivationSpecDigest != second.Summary.DerivationSpecDigest {
		t.Fatalf("expected stable derivation spec digest, got %q vs %q", first.Summary.DerivationSpecDigest, second.Summary.DerivationSpecDigest)
	}
	if first.Summary.BuildLogDigest != second.Summary.BuildLogDigest {
		t.Fatalf("expected stable build log digest, got %q vs %q", first.Summary.BuildLogDigest, second.Summary.BuildLogDigest)
	}
	if first.Summary.ArtifactDigest != second.Summary.ArtifactDigest {
		t.Fatalf("expected stable artifact digest, got %q vs %q", first.Summary.ArtifactDigest, second.Summary.ArtifactDigest)
	}
}

func TestExecuteLoopScriptFailureSummary(t *testing.T) {
	stack := startSubmitStack(t)

	specPath := writeExecutionLoopSpec(
		t,
		t.TempDir(),
		"loop-failure",
		`#!/bin/sh
set -eu
echo FAIL-BANNER
echo "{\"status\":\"fail\",\"artifact_digest\":\"${EXEC_ARTIFACT_DIGEST}\"}"
exit 7
`,
		"build log failure path\n",
	)

	result := runExecutionLoopScript(t, stack, specPath, t.TempDir())
	if result.ExitCode == 0 {
		t.Fatalf("expected non-zero exit code, got success stdout=%s stderr=%s", result.Stdout, result.Stderr)
	}
	if result.Summary.OK {
		t.Fatalf("expected failed summary, got %+v", result.Summary)
	}
	if result.Summary.FailedPhase != "execution" {
		t.Fatalf("expected execution failure, got %+v", result.Summary)
	}
	if result.Summary.ExitCode == nil || *result.Summary.ExitCode != 7 {
		t.Fatalf("expected exit code 7, got %+v", result.Summary)
	}
	if !result.Summary.Terminal {
		t.Fatalf("expected terminal failure summary, got %+v", result.Summary)
	}
	if !result.Summary.LogsAvailable {
		t.Fatalf("expected logs_available=true on failed execution, got %+v", result.Summary)
	}
	if !strings.Contains(result.Logs, "FAIL-BANNER") {
		t.Fatalf("expected failure banner in logs, got %q", result.Logs)
	}
}

func runExecutionLoopScript(t *testing.T, stack *submitStack, specPath string, workdirBase string) executionLoopResult {
	t.Helper()

	deployCertPath, deployKeyPath := writeLeafCertificateFiles(
		t,
		t.TempDir(),
		"loop-deployment",
		stack.fixture.runtimeCA,
		stack.fixture.runtimeCAKey,
		"loop-deployment-client",
		[]*url.URL{mustSPIFFEURL(t, "spiffe://execution.internal/service/deployment")},
	)

	agsHost, agsPort, err := net.SplitHostPort(stack.ags.Addr())
	if err != nil {
		t.Fatalf("split ags addr: %v", err)
	}
	esHost, esPort, err := net.SplitHostPort(stack.es.Addr())
	if err != nil {
		t.Fatalf("split es addr: %v", err)
	}

	repoRoot := executionPlatformRepoRoot(t)
	scriptPath := filepath.Join(repoRoot, "scripts", "60_execute_loop.sh")

	cmd := exec.Command(scriptPath, specPath)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"AGS_URL=https://"+stack.fixture.agsServerName+":"+agsPort,
		"ES_URL=https://"+stack.fixture.esServerName+":"+esPort,
		"AGS_RESOLVE="+stack.fixture.agsServerName+":"+agsPort+":"+agsHost,
		"ES_RESOLVE="+stack.fixture.esServerName+":"+esPort+":"+esHost,
		"CA_CERT="+stack.fixture.runtimeCAPath,
		"DEPLOY_CERT="+deployCertPath,
		"DEPLOY_KEY="+deployKeyPath,
		"WORKDIR_BASE="+workdirBase,
	)

	output, err := cmd.CombinedOutput()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("run execution loop script: %v output=%s", err, string(output))
		}
	}

	subdirs, err := os.ReadDir(workdirBase)
	if err != nil {
		t.Fatalf("read workdir base: %v", err)
	}
	if len(subdirs) != 1 {
		t.Fatalf("expected exactly one workdir in %s, found %d output=%s", workdirBase, len(subdirs), string(output))
	}
	workdir := filepath.Join(workdirBase, subdirs[0].Name())
	summaryPath := filepath.Join(workdir, "summary.json")
	logsPath := filepath.Join(workdir, "logs.txt")

	var summary executionLoopSummary
	summaryBytes, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatalf("read summary: %v output=%s", err, string(output))
	}
	if err := json.Unmarshal(summaryBytes, &summary); err != nil {
		t.Fatalf("decode summary: %v body=%s", err, string(summaryBytes))
	}

	logsBytes, err := os.ReadFile(logsPath)
	if err != nil {
		t.Fatalf("read logs: %v", err)
	}

	return executionLoopResult{
		Summary:  summary,
		Logs:     string(logsBytes),
		Stdout:   string(output),
		Stderr:   "",
		ExitCode: exitCode,
	}
}

func writeExecutionLoopSpec(t *testing.T, dir string, name string, script string, buildLog string) string {
	t.Helper()

	archivePath := filepath.Join(dir, "artifact.tar.gz")
	if err := os.WriteFile(archivePath, buildArchiveFromScript(t, script), 0o600); err != nil {
		t.Fatalf("write archive: %v", err)
	}

	buildLogPath := filepath.Join(dir, "build.log")
	if err := os.WriteFile(buildLogPath, []byte(buildLog), 0o600); err != nil {
		t.Fatalf("write build log: %v", err)
	}

	spec := map[string]any{
		"name":         name,
		"payload_path": "./artifact.tar.gz",
		"intent": map[string]any{
			"kind":       "static-script-smoke",
			"entrypoint": "./entrypoint",
			"args":       []any{"--alpha", "βeta"},
			"metadata": map[string]any{
				"zeta":  "last",
				"alpha": "first",
			},
			"note": "unicode π and stable ordering",
		},
		"derivation_spec": map[string]any{
			"platform":            "docker",
			"kind":                "static-script",
			"constraints_profile": "bounded-default",
			"metadata": map[string]any{
				"nested": map[string]any{
					"z": "last",
					"a": "first",
				},
				"whitespace": "line 1\nline 2",
			},
		},
		"build_log": map[string]any{
			"path": "./build.log",
		},
		"publish": map[string]any{
			"artifact_type": "static-script",
			"caller":        "deployment",
			"runtime_interface": map[string]any{
				"environment_variables": []any{"APP_MODE"},
				"required_capabilities": []any{},
			},
			"provenance": map[string]any{
				"policy_decisions": []any{
					map[string]any{"rule": "allow", "result": "applied"},
				},
			},
			"derivation": map[string]any{
				"output_id": "runtime",
			},
			"access": map[string]any{
				"network_access": false,
			},
			"workload": map[string]any{
				"target_platform": "docker",
			},
		},
		"prepare": map[string]any{
			"env": map[string]any{
				"APP_MODE": "test",
			},
		},
		"submit": map[string]any{
			"mode": "async",
			"resources": map[string]any{
				"cpu":       10,
				"memory_mb": 128,
			},
			"timeout_seconds": 120,
		},
	}

	specPath := filepath.Join(dir, "input.json")
	if err := os.WriteFile(specPath, mustMarshalJSON(t, spec), 0o600); err != nil {
		t.Fatalf("write input spec: %v", err)
	}
	return specPath
}

func executionPlatformRepoRoot(t *testing.T) string {
	t.Helper()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("resolve current file")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
}
