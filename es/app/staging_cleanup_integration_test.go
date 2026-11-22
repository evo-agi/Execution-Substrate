package app_test

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"execution-substrate/es/admission"
)

func TestExecutionStatusRetainsSuccessfulStageRootAndLogsStillWork(t *testing.T) {
	stack := startRuntimeIdentitySubmitStack(t)
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

	requirePathExists(t, stageRoot)

	logs := fetchExecutionLogs(t, stack, submitted.RunID)
	if !strings.Contains(logs, "START-BANNER") {
		t.Fatalf("expected logs to remain readable with retained staging, got %q", logs)
	}
	requirePathExists(t, stageRoot)
}

func TestExecutionStatusRetainsFailedStageRootForDebugging(t *testing.T) {
	stack := startRuntimeIdentitySubmitStack(t)
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
	stack := startRuntimeIdentitySubmitStack(t)
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
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "operator/local", false),
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

func TestFailedAndAmbiguousSubmitRetainCreatedStageRoot(t *testing.T) {
	tests := []struct {
		name      string
		ambiguous bool
	}{
		{name: "nomad rejection"},
		{name: "ambiguous nomad registration", ambiguous: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var registrations atomic.Int32
			stack := startSubmitStackWithNomadHandler(t, submitStackOptions{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/v1/jobs" {
					t.Fatalf("unexpected Nomad request %s %s", r.Method, r.URL.Path)
				}
				registrations.Add(1)
				if test.ambiguous {
					panic(http.ErrAbortHandler)
				}
				http.Error(w, "registration rejected", http.StatusServiceUnavailable)
			}))

			response := submitExecutionRequest(t, stack, buildSubmitRequestBody(t, stack))
			defer response.Body.Close()
			body := string(mustReadBody(t, response.Body))
			if response.StatusCode != http.StatusServiceUnavailable || !strings.Contains(body, `"code":"submission_failed"`) {
				t.Fatalf("expected primary 503 submission_failed response, got status=%d body=%s", response.StatusCode, body)
			}
			if strings.Contains(body, "submission failed and staged execution cleanup failed") {
				t.Fatalf("response exposed deleted cleanup error: %s", body)
			}
			if got := registrations.Load(); got != 1 {
				t.Fatalf("Nomad registration calls = %d, want exactly 1", got)
			}

			stageRoot := filepath.Join(stack.rootDir, "es-stage")
			entries, err := os.ReadDir(stageRoot)
			if err != nil {
				t.Fatalf("read retained staging root: %v", err)
			}
			if len(entries) != 3 {
				t.Fatalf("retained stage entries = %d, want one run root and one probe directory/symlink pair", len(entries))
			}
			runNamePattern := regexp.MustCompile(`^run-[0-9a-f]{16}$`)
			probeNamePattern := regexp.MustCompile(`^\.execution-substrate-staging-probe-[0-9a-f]{32}$`)
			var runName, probeName, probeLinkName string
			for _, entry := range entries {
				name := entry.Name()
				if strings.Contains(name, "quarantine") {
					t.Fatalf("unexpected quarantine name %q", name)
				}
				info, err := os.Lstat(filepath.Join(stageRoot, name))
				if err != nil {
					t.Fatalf("lstat retained stage entry: %v", err)
				}
				switch {
				case runNamePattern.MatchString(name):
					if runName != "" || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
						t.Fatalf("invalid retained run root %q", name)
					}
					runName = name
				case probeNamePattern.MatchString(name):
					if probeName != "" || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
						t.Fatalf("invalid retained staging probe directory %q", name)
					}
					probeName = name
				case strings.HasSuffix(name, "-symlink") && probeNamePattern.MatchString(strings.TrimSuffix(name, "-symlink")):
					if probeLinkName != "" || info.Mode()&os.ModeSymlink == 0 {
						t.Fatalf("invalid retained staging probe symlink %q", name)
					}
					probeLinkName = name
				default:
					t.Fatalf("unexpected retained stage entry %q", name)
				}
			}
			if runName == "" || probeName == "" || probeLinkName != probeName+"-symlink" {
				t.Fatalf("retained stage inventory lacks one run root and one matching staging probe pair")
			}
			linkTarget, err := os.Readlink(filepath.Join(stageRoot, probeLinkName))
			if err != nil || linkTarget != probeName {
				t.Fatalf("retained staging probe symlink target mismatch: %v", err)
			}
			runRoot := filepath.Join(stageRoot, runName)
			requirePathExists(t, runRoot)
			if _, err := os.Stat(filepath.Join(runRoot, ".execution-substrate-stage-claim-v1")); !os.IsNotExist(err) {
				t.Fatalf("unexpected staging claim marker: %v", err)
			}
			runEntries, err := os.ReadDir(runRoot)
			if err != nil || len(runEntries) == 0 {
				t.Fatalf("retained run root lacks materialized state: entries=%v err=%v", runEntries, err)
			}
		})
	}
}

func TestExecutionLoopScriptSuccessRetainsDistinctStageRootsAcrossRepeatedRuns(t *testing.T) {
	stack := startRuntimeIdentitySubmitStack(t)

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
	firstStageRoot := filepath.Join(stack.rootDir, "es-stage", first.Summary.RunID)
	requirePathExists(t, firstStageRoot)

	second := runExecutionLoopScript(t, stack, specPath, t.TempDir())
	if second.ExitCode != 0 || !second.Summary.OK {
		t.Fatalf("expected second loop run to succeed, got exit=%d summary=%+v stdout=%s", second.ExitCode, second.Summary, second.Stdout)
	}
	secondStageRoot := filepath.Join(stack.rootDir, "es-stage", second.Summary.RunID)
	requirePathExists(t, secondStageRoot)

	// The staging root holds exactly the two successful run roots plus the one
	// exclusive startup probe directory/symlink pair that ES retains by
	// contract (.docs/execution_lifecycle/capability_probing.md); nothing else.
	runNames := retainedStageRunRoots(t, filepath.Join(stack.rootDir, "es-stage"))
	if len(runNames) != 2 {
		t.Fatalf("expected two successful stage roots to remain, found %d: %v", len(runNames), runNames)
	}
	if firstStageRoot == secondStageRoot {
		t.Fatal("repeated successful runs reused a staging root")
	}
	for _, runID := range []string{first.Summary.RunID, second.Summary.RunID} {
		if _, ok := runNames[runID]; !ok {
			t.Fatalf("retained stage roots %v lack run root %q", runNames, runID)
		}
	}
}

// retainedStageRunRoots reads the complete staging-root inventory and returns
// the set of run roots. Every other entry must be the single exclusive startup
// probe directory and its matching symlink; any other entry, a second probe
// pair, a quarantine name or a non-directory run root fails the test.
func retainedStageRunRoots(t *testing.T, stageRoot string) map[string]struct{} {
	t.Helper()

	entries, err := os.ReadDir(stageRoot)
	if err != nil {
		t.Fatalf("read staging root: %v", err)
	}
	runNamePattern := regexp.MustCompile(`^run-[0-9a-f]{16}$`)
	probeNamePattern := regexp.MustCompile(`^\.execution-substrate-staging-probe-[0-9a-f]{32}$`)
	runNames := make(map[string]struct{}, len(entries))
	var probeName, probeLinkName string
	for _, entry := range entries {
		name := entry.Name()
		if strings.Contains(name, "quarantine") {
			t.Fatalf("unexpected quarantine name %q", name)
		}
		info, err := os.Lstat(filepath.Join(stageRoot, name))
		if err != nil {
			t.Fatalf("lstat staging root entry: %v", err)
		}
		switch {
		case runNamePattern.MatchString(name):
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				t.Fatalf("invalid retained run root %q", name)
			}
			runNames[name] = struct{}{}
		case probeNamePattern.MatchString(name):
			if probeName != "" || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				t.Fatalf("invalid retained staging probe directory %q", name)
			}
			probeName = name
		case strings.HasSuffix(name, "-symlink") && probeNamePattern.MatchString(strings.TrimSuffix(name, "-symlink")):
			if probeLinkName != "" || info.Mode()&os.ModeSymlink == 0 {
				t.Fatalf("invalid retained staging probe symlink %q", name)
			}
			probeLinkName = name
		default:
			t.Fatalf("unexpected staging root entry %q", name)
		}
	}
	if probeName == "" || probeLinkName != probeName+"-symlink" {
		t.Fatalf("staging root lacks exactly one matching startup probe pair: probe=%q link=%q", probeName, probeLinkName)
	}
	linkTarget, err := os.Readlink(filepath.Join(stageRoot, probeLinkName))
	if err != nil || linkTarget != probeName {
		t.Fatalf("staging probe symlink target = %q, want %q: %v", linkTarget, probeName, err)
	}
	return runNames
}

func fetchExecutionStatus(t *testing.T, stack *submitStack, runID string) admission.ExecutionStatusResult {
	t.Helper()

	response := doJSONRequest(
		t,
		stack.es.Addr(),
		http.MethodGet,
		"/v1/executions/"+runID+"/status",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "operator/local", false),
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
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "operator/local", false),
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
