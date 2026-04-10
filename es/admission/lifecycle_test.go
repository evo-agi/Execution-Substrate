package admission

import (
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
