package executionsubstrate_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runRemoteAlphaPlanOldRootCleanup(t *testing.T, args ...string) map[string]any {
	t.Helper()
	scriptPath := filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_plan_old_root_cleanup.sh")
	cmd := exec.Command("/bin/bash", append([]string{scriptPath}, args...)...)
	cmd.Dir = executionSubstrateRepoRoot
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("old-root cleanup planner failed: %v\noutput=%s", err, string(output))
	}
	var payload map[string]any
	if err := json.Unmarshal(output, &payload); err != nil {
		t.Fatalf("decode planner output: %v\noutput=%s", err, string(output))
	}
	return payload
}

func writeOldRootCleanupFixture(t *testing.T, path string, payload map[string]any) {
	t.Helper()
	writeJSONFile(t, path, payload)
}

func TestRemoteAlphaPlanOldRootCleanupDefaultsToRetainWhileRollbackWindowActive(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	artifactPath := filepath.Join(tmpDir, "es-writable-state-ownership-apply-summary.json")
	stagingRoot := "/var/lib/execution-substrate/es/staging.pre-es-writable-state-ownership-20260427T012922Z"
	resultsRoot := "/var/lib/execution-substrate/es/results.pre-es-writable-state-ownership-20260427T012922Z"

	writeOldRootCleanupFixture(t, artifactPath, map[string]any{
		"schema_version": "execution-substrate.remote-alpha.es-writable-state-ownership-summary.v1",
		"preserved_roots": map[string]any{
			"staging": map[string]any{
				"path": stagingRoot,
			},
			"results": map[string]any{
				"path": resultsRoot,
			},
		},
		"backup": map[string]any{
			"snapshot": map[string]any{
				"quarantined_roots_observed": []any{
					map[string]any{"path": stagingRoot},
					map[string]any{"path": resultsRoot},
				},
			},
		},
	})

	plan := runRemoteAlphaPlanOldRootCleanup(t, artifactPath)
	if plan["non_mutating"] != true || plan["local_only"] != true {
		t.Fatalf("expected non-mutating local-only plan, got %+v", plan)
	}
	if plan["ssh_used"] != false || plan["sudo_used"] != false {
		t.Fatalf("expected no ssh/sudo usage, got %+v", plan)
	}
	if nestedMap(t, plan, "rollback_window")["status"] != "active" {
		t.Fatalf("expected active rollback window, got %+v", nestedMap(t, plan, "rollback_window"))
	}

	roots, ok := plan["roots"].([]any)
	if !ok || len(roots) != 2 {
		t.Fatalf("expected two preserved roots, got %+v", plan["roots"])
	}
	for _, raw := range roots {
		root := jsonMap(t, raw)
		if root["recommended_action"] != "retain" {
			t.Fatalf("expected retain action, got %+v", root)
		}
		if root["root_kind"] != "preserved_root_rotation" {
			t.Fatalf("expected preserved_root_rotation kind, got %+v", root)
		}
		refs, ok := root["source_references"].([]any)
		if !ok || len(refs) == 0 {
			t.Fatalf("expected source references, got %+v", root)
		}
		if warnings := jsonStringSlice(t, root["warnings"]); len(warnings) == 0 {
			t.Fatalf("expected rollback warning for root, got %+v", root)
		}
		preconditions := jsonStringSlice(t, root["preconditions_before_deletion"])
		if len(preconditions) < 4 {
			t.Fatalf("expected deletion preconditions, got %+v", root)
		}
	}

	warnings := jsonStringSlice(t, plan["warnings"])
	if len(warnings) == 0 {
		t.Fatalf("expected top-level warnings, got %+v", plan)
	}
}

func TestRemoteAlphaPlanOldRootCleanupCanRecommendArchiveLaterAndDeleteLater(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	rotationArtifact := filepath.Join(tmpDir, "es-writable-state-ownership-apply-summary.json")
	reconcileArtifact := filepath.Join(tmpDir, "es-writable-state-ownership-reconcile-apply-summary.json")
	stagingRoot := "/var/lib/execution-substrate/es/staging.pre-es-writable-state-ownership-20260427T012922Z"
	resultsRoot := "/var/lib/execution-substrate/es/results.pre-es-writable-state-ownership-20260427T012922Z"
	reconcileStaging := "/var/lib/execution-substrate/es/staging.reconcile-es-writable-state-ownership-20260427T022000Z"
	reconcileResults := "/var/lib/execution-substrate/es/results.reconcile-es-writable-state-ownership-20260427T022000Z"

	writeOldRootCleanupFixture(t, rotationArtifact, map[string]any{
		"schema_version": "execution-substrate.remote-alpha.es-writable-state-ownership-summary.v1",
		"preserved_roots": map[string]any{
			"staging": map[string]any{"path": stagingRoot},
			"results": map[string]any{"path": resultsRoot},
		},
	})
	writeOldRootCleanupFixture(t, reconcileArtifact, map[string]any{
		"schema_version": "execution-substrate.remote-alpha.es-writable-state-ownership-summary.v1",
		"quarantine_paths": map[string]any{
			"staging": reconcileStaging,
			"results": reconcileResults,
		},
	})

	archivePlan := runRemoteAlphaPlanOldRootCleanup(t,
		"--rollback-window", "closed",
		rotationArtifact,
		reconcileArtifact,
	)
	archiveWarnings := jsonStringSlice(t, archivePlan["warnings"])
	if len(archiveWarnings) == 0 {
		t.Fatalf("expected archive-later warning, got %+v", archivePlan)
	}
	archiveRoots, ok := archivePlan["roots"].([]any)
	if !ok || len(archiveRoots) != 4 {
		t.Fatalf("expected four preserved/quarantine roots, got %+v", archivePlan["roots"])
	}
	for _, raw := range archiveRoots {
		root := jsonMap(t, raw)
		if root["recommended_action"] != "archive_later" {
			t.Fatalf("expected archive_later action, got %+v", root)
		}
	}

	deletePlan := runRemoteAlphaPlanOldRootCleanup(t,
		"--rollback-window", "closed",
		"--archive-evidence", "captured",
		rotationArtifact,
		reconcileArtifact,
	)
	deleteRoots, ok := deletePlan["roots"].([]any)
	if !ok || len(deleteRoots) != 4 {
		t.Fatalf("expected four preserved/quarantine roots, got %+v", deletePlan["roots"])
	}

	seenKinds := map[string]bool{}
	for _, raw := range deleteRoots {
		root := jsonMap(t, raw)
		if root["recommended_action"] != "delete_later" {
			t.Fatalf("expected delete_later action, got %+v", root)
		}
		kind, ok := root["root_kind"].(string)
		if !ok {
			t.Fatalf("expected root_kind string, got %+v", root)
		}
		seenKinds[kind] = true
		if len(jsonStringSlice(t, root["warnings"])) != 0 {
			t.Fatalf("expected no rollback/archive warnings once archive evidence is captured, got %+v", root)
		}
	}
	if !seenKinds["preserved_root_rotation"] || !seenKinds["artifact_reconciliation_quarantine_root"] {
		t.Fatalf("expected both preserved and reconciliation root kinds, got %+v", seenKinds)
	}
}

func TestRemoteAlphaPlanOldRootCleanupWritesOutputFileWhenRequested(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	artifactPath := filepath.Join(tmpDir, "es-writable-state-ownership-apply-summary.json")
	outputPath := filepath.Join(tmpDir, "plan.json")
	writeOldRootCleanupFixture(t, artifactPath, map[string]any{
		"schema_version": "execution-substrate.remote-alpha.es-writable-state-ownership-summary.v1",
		"preserved_roots": map[string]any{
			"staging": map[string]any{
				"path": "/var/lib/execution-substrate/es/staging.pre-es-writable-state-ownership-20260427T012922Z",
			},
		},
	})

	scriptPath := filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_plan_old_root_cleanup.sh")
	cmd := exec.Command("/bin/bash", scriptPath, "--output", outputPath, artifactPath)
	cmd.Dir = executionSubstrateRepoRoot
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("planner with output file failed: %v\noutput=%s", err, string(output))
	}
	gotPath := strings.TrimSpace(string(output))
	gotInfo, err := os.Stat(gotPath)
	if err != nil {
		t.Fatalf("stat returned output path %q: %v", gotPath, err)
	}
	expectedInfo, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("stat expected output path %q: %v", outputPath, err)
	}
	if !os.SameFile(gotInfo, expectedInfo) {
		t.Fatalf("expected output path %q, got %q", outputPath, gotPath)
	}
	if _, err := os.Stat(outputPath); err != nil {
		t.Fatalf("expected plan output file: %v", err)
	}
	payload := readJSONFile(t, outputPath)
	if payload["non_mutating"] != true {
		t.Fatalf("expected non-mutating written plan, got %+v", payload)
	}
}
