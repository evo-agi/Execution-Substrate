package admission

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	esconfig "execution-substrate/es/config"
)

func TestRepresentsTerminalSuccessRequiresZeroExitCode(t *testing.T) {
	successful := &nomadAllocationDetail{
		ClientStatus: "complete",
		TaskStates: map[string]nomadTaskState{
			nomadTaskName: {
				State: "dead",
				Events: []nomadTaskEvent{
					{Type: "Started"},
					{Type: "Terminated", ExitCode: 0},
				},
			},
		},
	}
	if !representsTerminalSuccess(successful) {
		t.Fatalf("expected dead task with zero exit code to be treated as terminal success")
	}

	failed := &nomadAllocationDetail{
		ClientStatus: "failed",
		TaskStates: map[string]nomadTaskState{
			nomadTaskName: {
				State: "dead",
				Events: []nomadTaskEvent{
					{Type: "Terminated", ExitCode: 1},
				},
			},
		},
	}
	if representsTerminalSuccess(failed) {
		t.Fatalf("did not expect nonzero exit code to be treated as terminal success")
	}
}

func TestMaybeCleanupSuccessfulStageRootRemovesOnlySuccessfulRuns(t *testing.T) {
	stagingRoot := t.TempDir()
	service := Service{
		cfg: esconfig.Config{
			Execution: esconfig.ExecutionConfig{
				StagingRootDir: stagingRoot,
				ResultsRootDir: t.TempDir(),
			},
		},
	}
	locator := newExecutionLocatorFromRunID("run-0123456789abcdef")
	layout := newExecutionPackageLayout(service.cfg, locator)

	if err := os.MkdirAll(layout.stageRootDir, 0o755); err != nil {
		t.Fatalf("mkdir stage root: %v", err)
	}
	service.maybeCleanupSuccessfulStageRoot(locator, &nomadAllocationDetail{
		ClientStatus: "failed",
		TaskStates: map[string]nomadTaskState{
			nomadTaskName: {
				State:  "dead",
				Events: []nomadTaskEvent{{Type: "Terminated", ExitCode: 1}},
			},
		},
	})
	if _, err := os.Stat(layout.stageRootDir); err != nil {
		t.Fatalf("expected failed allocation stage root to remain for debugging, got %v", err)
	}

	if err := os.WriteFile(filepath.Join(layout.stageRootDir, "marker"), []byte("keep me until success"), 0o600); err != nil {
		t.Fatalf("write stage marker: %v", err)
	}
	service.maybeCleanupSuccessfulStageRoot(locator, &nomadAllocationDetail{
		ClientStatus: "complete",
		TaskStates: map[string]nomadTaskState{
			nomadTaskName: {
				State:  "dead",
				Events: []nomadTaskEvent{{Type: "Terminated", ExitCode: 0}},
			},
		},
	})
	if _, err := os.Stat(layout.stageRootDir); !os.IsNotExist(err) {
		t.Fatalf("expected successful allocation stage root to be removed, got %v", err)
	}
}

func TestStatusRetainsLostStageRootForDebugging(t *testing.T) {
	stagingRoot := t.TempDir()
	service := Service{
		cfg: esconfig.Config{
			Execution: esconfig.ExecutionConfig{
				StagingRootDir: stagingRoot,
				ResultsRootDir: t.TempDir(),
			},
		},
		nomadClient: newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/v1/job/exec-run-0123456789abcdef":
				_, _ = w.Write([]byte(`{"ID":"exec-run-0123456789abcdef","Status":"running","ModifyIndex":10}`))
			case "/v1/job/exec-run-0123456789abcdef/allocations":
				_, _ = w.Write([]byte(`[{"ID":"alloc-lost","ModifyIndex":20}]`))
			case "/v1/allocation/alloc-lost":
				_, _ = w.Write([]byte(`{"ID":"alloc-lost","ClientStatus":"lost","ModifyIndex":25,"TaskStates":{"task":{"State":"dead","Events":[{"Type":"Started"},{"Type":"Terminated","ExitCode":137}]}}}`))
			default:
				t.Fatalf("unexpected path %q", r.URL.Path)
			}
		})),
	}
	locator := newExecutionLocatorFromRunID("run-0123456789abcdef")
	layout := newExecutionPackageLayout(service.cfg, locator)

	if err := os.MkdirAll(layout.stageRootDir, 0o755); err != nil {
		t.Fatalf("mkdir stage root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(layout.stageRootDir, "marker"), []byte("retain lost run"), 0o600); err != nil {
		t.Fatalf("write stage marker: %v", err)
	}

	result, err := service.Status(context.Background(), locator.RunID)
	if err != nil {
		t.Fatalf("status: %+v", err)
	}
	if result.Status != executionLifecycleStatusTerminal || !result.Terminal {
		t.Fatalf("expected terminal lost status, got %+v", result)
	}
	if result.ExitCode == nil || *result.ExitCode != 137 {
		t.Fatalf("expected lost allocation exit code 137, got %+v", result)
	}
	if _, statErr := os.Stat(layout.stageRootDir); statErr != nil {
		t.Fatalf("expected lost allocation stage root to remain for debugging, got %v", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(layout.stageRootDir, "marker")); statErr != nil {
		t.Fatalf("expected lost allocation marker to remain, got %v", statErr)
	}
	if _, statErr := os.Stat(service.retainedResultBundlePath(locator)); !os.IsNotExist(statErr) {
		t.Fatalf("did not expect retained result bundle for lost allocation, got %v", statErr)
	}
}
