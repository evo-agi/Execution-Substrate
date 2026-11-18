package runtimehelper

import (
	"encoding/json"
	"errors"
	"fmt"
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
	t.Setenv("VAULT_CACERT", filepath.Join(platformDir, "workload-vault-ca.pem"))
	t.Setenv("SSL_CERT_FILE", filepath.Join(platformDir, "workload-ca-bundle.pem"))
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
	runDirInfo, err := os.Stat(filepath.Dir(cfg.workDir))
	if err != nil {
		t.Fatalf("stat run dir: %v", err)
	}
	if runDirInfo.Mode().Perm() != normalizedDirMode {
		t.Fatalf("expected run dir mode %o, got %o", normalizedDirMode, runDirInfo.Mode().Perm())
	}
	platformInfo, err := os.Stat(platformDir)
	if err != nil {
		t.Fatalf("stat platform dir: %v", err)
	}
	if platformInfo.Mode().Perm() != normalizedDirMode {
		t.Fatalf("expected platform dir mode %o, got %o", normalizedDirMode, platformInfo.Mode().Perm())
	}
	trustInfo, err := os.Stat(filepath.Join(platformDir, "workload-ca-bundle.pem"))
	if err != nil {
		t.Fatalf("stat workload trust bundle: %v", err)
	}
	if trustInfo.Mode().Perm() != normalizedFileMode {
		t.Fatalf("expected workload trust bundle mode %o, got %o", normalizedFileMode, trustInfo.Mode().Perm())
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

func TestPostWorkloadNormalizationPhaseUsesDeclaredPlatformStateOwner(t *testing.T) {
	skipIfCurrentIdentityMatchesWorkloadBoundary(t)

	runID := "run-0f0f0f0f0f0f0f0f"
	cfg, platformDir := newPostWorkloadNormalizationFixture(t, runID)
	t.Setenv("VAULT_CACERT", filepath.Join(platformDir, "workload-vault-ca.pem"))
	t.Setenv("SSL_CERT_FILE", filepath.Join(platformDir, "workload-ca-bundle.pem"))
	t.Setenv(platformStateOwnerSchemaEnvKey, platformStateOwnerSchemaV1)
	t.Setenv(platformStateOwnerUIDEnvKey, intToString(os.Getuid()))
	t.Setenv(platformStateOwnerGIDEnvKey, intToString(os.Getgid()))

	if err := postWorkloadNormalizationPhase(cfg); err != nil {
		t.Fatalf("post-workload normalization phase: %v", err)
	}

	payload, err := os.ReadFile(ownershipnorm.MarkerPath(platformDir))
	if err != nil {
		t.Fatalf("read emitted marker: %v", err)
	}
	var marker ownershipnorm.Marker
	if err := json.Unmarshal(payload, &marker); err != nil {
		t.Fatalf("decode emitted marker: %v", err)
	}
	if marker.TargetUID == nil || *marker.TargetUID != os.Getuid() {
		t.Fatalf("expected marker target uid %d, got %+v", os.Getuid(), marker.TargetUID)
	}
	if marker.TargetGID == nil || *marker.TargetGID != os.Getgid() {
		t.Fatalf("expected marker target gid %d, got %+v", os.Getgid(), marker.TargetGID)
	}
}

func TestPostWorkloadNormalizationPhaseFailsWhenDeclaredPlatformStateOwnerIsMalformed(t *testing.T) {
	skipIfCurrentIdentityMatchesWorkloadBoundary(t)

	runID := "run-badbadbadbadbadb"
	cfg, _ := newPostWorkloadNormalizationFixture(t, runID)
	t.Setenv(platformStateOwnerSchemaEnvKey, platformStateOwnerSchemaV1)
	t.Setenv(platformStateOwnerUIDEnvKey, "not-a-number")
	t.Setenv(platformStateOwnerGIDEnvKey, intToString(os.Getgid()))

	err := postWorkloadNormalizationPhase(cfg)
	if err == nil || !strings.Contains(err.Error(), "runtime platform state owner uid is invalid") {
		t.Fatalf("expected malformed declared owner to fail closed, got %v", err)
	}
}

func TestPostWorkloadNormalizationPhaseFailsWhenMarkerCannotBeWritten(t *testing.T) {
	skipIfCurrentIdentityMatchesWorkloadBoundary(t)

	runID := "run-deadbeefdeadbeef"
	cfg, platformDir := newPostWorkloadNormalizationFixture(t, runID)
	t.Setenv("VAULT_CACERT", filepath.Join(platformDir, "workload-vault-ca.pem"))
	t.Setenv("SSL_CERT_FILE", filepath.Join(platformDir, "workload-ca-bundle.pem"))
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

func TestPrepareActiveWorkloadVisibilityMakesRunRootTraversableAndTrustFilesReadable(t *testing.T) {
	runID := "run-1111222233334444"
	cfg, platformDir := newPostWorkloadNormalizationFixture(t, runID)
	t.Setenv("VAULT_CACERT", filepath.Join(platformDir, "workload-vault-ca.pem"))
	t.Setenv("SSL_CERT_FILE", filepath.Join(platformDir, "workload-ca-bundle.pem"))

	if err := prepareActiveWorkloadVisibility(cfg.workDir, platformDir); err != nil {
		t.Fatalf("prepare active workload visibility: %v", err)
	}

	runDirInfo, err := os.Stat(filepath.Dir(cfg.workDir))
	if err != nil {
		t.Fatalf("stat run dir: %v", err)
	}
	if runDirInfo.Mode().Perm() != activeRunTraversalDirMode {
		t.Fatalf("expected run dir mode %o, got %o", activeRunTraversalDirMode, runDirInfo.Mode().Perm())
	}

	platformInfo, err := os.Stat(platformDir)
	if err != nil {
		t.Fatalf("stat platform dir: %v", err)
	}
	if platformInfo.Mode().Perm() != activePlatformTraversalDirMode {
		t.Fatalf("expected platform dir mode %o, got %o", activePlatformTraversalDirMode, platformInfo.Mode().Perm())
	}

	trustInfo, err := os.Stat(filepath.Join(platformDir, "workload-ca-bundle.pem"))
	if err != nil {
		t.Fatalf("stat workload trust bundle: %v", err)
	}
	if trustInfo.Mode().Perm() != activeTrustFileMode {
		t.Fatalf("expected workload trust bundle mode %o, got %o", activeTrustFileMode, trustInfo.Mode().Perm())
	}

	runtimeSupportInfo, err := os.Stat(filepath.Join(platformDir, "es-runtime-support"))
	if err != nil {
		t.Fatalf("stat runtime support binary: %v", err)
	}
	if runtimeSupportInfo.Mode().Perm() != 0o755 {
		t.Fatalf("expected runtime support mode to stay 0755 in the fixture, got %o", runtimeSupportInfo.Mode().Perm())
	}
}

func TestPrepareActiveWorkloadVisibilityFailsWhenTrustPathEscapesPlatformDir(t *testing.T) {
	runID := "run-5555666677778888"
	cfg, platformDir := newPostWorkloadNormalizationFixture(t, runID)
	t.Setenv("VAULT_CACERT", filepath.Join(filepath.Dir(platformDir), "not-under-platform.pem"))

	err := prepareActiveWorkloadVisibility(cfg.workDir, platformDir)
	if err == nil || !strings.Contains(err.Error(), "VAULT_CACERT must remain under") {
		t.Fatalf("expected trust path escape to fail closed, got %v", err)
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
	runtimeSupportPath := filepath.Join(platformDir, "es-runtime-support")
	if err := os.WriteFile(runtimeSupportPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write platform binary: %v", err)
	}
	if err := os.Chmod(runtimeSupportPath, 0o755); err != nil {
		t.Fatalf("set exact mode on test-owned runtime support binary: %v", err)
	}
	if err := os.WriteFile(filepath.Join(platformDir, "workload-vault-ca.pem"), []byte("vault\n"), 0o644); err != nil {
		t.Fatalf("write workload vault ca file: %v", err)
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

func intToString(value int) string {
	return fmt.Sprintf("%d", value)
}
