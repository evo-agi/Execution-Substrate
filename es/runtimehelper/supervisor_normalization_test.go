package runtimehelper

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"execution-substrate/es/internal/ownershipnorm"
)

func TestPostWorkloadNormalizationPhaseEmitsMarkerAfterSuccessfulNormalization(t *testing.T) {
	skipIfCurrentIdentityMatchesWorkloadBoundary(t)

	runID := "run-0123456789abcdef"
	cfg, platformDir := newPostWorkloadNormalizationFixture(t, runID)
	markerPath := ownershipnorm.MarkerPath(platformDir)
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Fatalf("expected marker to be absent before normalization, got %v", err)
	}

	if err := postWorkloadNormalizationPhase(cfg); err != nil {
		t.Fatalf("post-workload normalization phase: %v", err)
	}

	markerInfo, err := os.Lstat(markerPath)
	if err != nil {
		t.Fatalf("stat emitted marker: %v", err)
	}
	markerUID, markerGID, err := fileOwnerIDs(markerInfo)
	if err != nil {
		t.Fatalf("marker ownership: %v", err)
	}
	if markerUID != os.Getuid() || markerGID != os.Getgid() {
		t.Fatalf("expected marker owner %d:%d, got %d:%d", os.Getuid(), os.Getgid(), markerUID, markerGID)
	}
	if markerInfo.Mode().Perm() != markerFileMode {
		t.Fatalf("expected marker mode %o, got %o", markerFileMode, markerInfo.Mode().Perm())
	}
	if err := ensureMarkerAuthorityBoundary(platformDir, markerPath, workloadUID, workloadGID); err != nil {
		t.Fatalf("expected emitted marker boundary to remain workload-safe: %v", err)
	}

	payload, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatalf("read emitted marker: %v", err)
	}
	var marker ownershipnorm.Marker
	if err := json.Unmarshal(payload, &marker); err != nil {
		t.Fatalf("decode emitted marker: %v", err)
	}
	if err := ownershipnorm.Validate(marker, ownershipnorm.ValidationOptions{
		RunID:       runID,
		ExpectedUID: intPtrForTest(os.Getuid()),
		ExpectedGID: intPtrForTest(os.Getgid()),
	}); err != nil {
		t.Fatalf("expected emitted marker to validate, got %v", err)
	}
}

func TestPostWorkloadNormalizationPhaseFailsWhenMarkerCannotBeWritten(t *testing.T) {
	skipIfCurrentIdentityMatchesWorkloadBoundary(t)

	runID := "run-deadbeefdeadbeef"
	cfg, platformDir := newPostWorkloadNormalizationFixture(t, runID)
	markerPath := ownershipnorm.MarkerPath(platformDir)

	restore := writeMarkerFile
	writeMarkerFile = func(string, []byte, os.FileMode) error {
		return errors.New("disk full")
	}
	defer func() {
		writeMarkerFile = restore
	}()

	err := postWorkloadNormalizationPhase(cfg)
	if err == nil || !strings.Contains(err.Error(), "write ownership-normalization marker") {
		t.Fatalf("expected marker write failure, got %v", err)
	}
	if _, statErr := os.Stat(markerPath); !os.IsNotExist(statErr) {
		t.Fatalf("expected marker to remain absent after write failure, got %v", statErr)
	}
}

func TestCombineWorkloadAndNormalizationErrorMarksSuccessfulWorkloadAsFailed(t *testing.T) {
	err := combineWorkloadAndNormalizationError(nil, errors.New("marker validation failed"))
	if err == nil {
		t.Fatalf("expected normalization failure to produce an error")
	}
	var exitErr *exitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected normalization failure to surface as exitError, got %T %v", err, err)
	}
	if exitErr.code != 1 {
		t.Fatalf("expected normalization failure exit code 1, got %d", exitErr.code)
	}
	if !strings.Contains(err.Error(), "post-workload normalization failed") {
		t.Fatalf("expected normalization failure context, got %v", err)
	}
}

func newPostWorkloadNormalizationFixture(t *testing.T, runID string) (supervisorConfig, string) {
	t.Helper()

	rootDir := t.TempDir()
	runDir := filepath.Join(rootDir, "run")
	platformDir := filepath.Join(runDir, "platform")
	workDir := filepath.Join(runDir, "work")
	resultDir := filepath.Join(runDir, "result")
	t.Setenv("EXEC_RUN_ID", runID)

	if err := os.MkdirAll(platformDir, 0o755); err != nil {
		t.Fatalf("mkdir platform dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(workDir, "bin"), 0o755); err != nil {
		t.Fatalf("mkdir work dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(resultDir, "nested"), 0o755); err != nil {
		t.Fatalf("mkdir result dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(platformDir, "es-runtime-support"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write platform binary: %v", err)
	}
	if err := os.WriteFile(filepath.Join(platformDir, "workload-ca-bundle.pem"), []byte("bundle\n"), 0o644); err != nil {
		t.Fatalf("write platform file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "entrypoint"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write work entrypoint: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "bin", "notes.txt"), []byte("notes\n"), 0o600); err != nil {
		t.Fatalf("write work file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(resultDir, "summary.txt"), []byte("ok\n"), 0o600); err != nil {
		t.Fatalf("write result file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(resultDir, "nested", "runner"), []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatalf("write executable result file: %v", err)
	}

	return supervisorConfig{
		workDir:    workDir,
		resultDir:  resultDir,
		entrypoint: filepath.Join(workDir, "entrypoint"),
	}, platformDir
}

func skipIfCurrentIdentityMatchesWorkloadBoundary(t *testing.T) {
	t.Helper()
	if os.Getuid() == workloadUID || os.Getgid() == workloadGID {
		t.Skip("current test uid/gid matches workload uid/gid; cannot model workload-forgeability boundary safely")
	}
}

func intPtrForTest(value int) *int {
	return &value
}
