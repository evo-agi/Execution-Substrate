package admission

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	esconfig "execution-substrate/es/config"
)

func TestStageExecutionInputsSucceedsWithOwnerOnlyStagingRoot(t *testing.T) {
	rootDir := t.TempDir()
	stagingRootDir := filepath.Join(rootDir, "stage")
	mkdirWithMode(t, stagingRootDir, 0o700)
	resultsRootDir := filepath.Join(rootDir, "results")
	mkdirWithMode(t, resultsRootDir, 0o700)

	runtimeSupportBinary := filepath.Join(rootDir, "es-runtime-support")
	writeFileWithMode(t, runtimeSupportBinary, []byte("#!/bin/sh\n"), 0o700)

	service := &Service{
		cfg: esconfig.Config{
			Execution: esconfig.ExecutionConfig{
				StagingRootDir:       stagingRootDir,
				ResultsRootDir:       resultsRootDir,
				RuntimeSupportBinary: runtimeSupportBinary,
			},
		},
	}
	locator := newExecutionLocatorFromRunID("run-0123456789abcdef")

	stage, err := service.stageExecutionInputs(locator, []byte("payload"), executionPlatformStateOwner{UID: os.Getuid(), GID: os.Getgid()})
	if err != nil {
		t.Fatalf("stage execution inputs: %v", err)
	}

	requirePathExists(t, stage.layout.stageRootDir)
	requirePathExists(t, stage.layout.payloadArchivePath)
	requirePathExists(t, stage.layout.runStageDir)
	requirePathExists(t, stage.layout.platformStageDir)
	requirePathExists(t, stage.layout.resultStageDir)
	requirePathExists(t, stage.layout.runtimeSupportPath)
	if info, err := os.Stat(stage.layout.stageRootDir); err != nil {
		t.Fatalf("stat %s: %v", stage.layout.stageRootDir, err)
	} else {
		if info.Mode().Perm() != stableStageDirMode {
			t.Fatalf("expected %s mode %o, got %o", stage.layout.stageRootDir, stableStageDirMode, info.Mode().Perm())
		}
		uid, gid, err := ownershipIDsFromInfo(info)
		if err != nil {
			t.Fatalf("ownership for %s: %v", stage.layout.stageRootDir, err)
		}
		if uid != os.Getuid() || gid != os.Getgid() {
			t.Fatalf("expected %s owner %d:%d, got %d:%d", stage.layout.stageRootDir, os.Getuid(), os.Getgid(), uid, gid)
		}
	}
	for _, dir := range []string{
		stage.layout.payloadStageDir,
		stage.layout.runStageDir,
		stage.layout.platformStageDir,
		stage.layout.resultStageDir,
	} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("stat %s: %v", dir, err)
		}
		if info.Mode().Perm() != stableStageDirMode {
			t.Fatalf("expected %s mode %o, got %o", dir, stableStageDirMode, info.Mode().Perm())
		}
		uid, gid, err := ownershipIDsFromInfo(info)
		if err != nil {
			t.Fatalf("ownership for %s: %v", dir, err)
		}
		if uid != os.Getuid() || gid != os.Getgid() {
			t.Fatalf("expected %s owner %d:%d, got %d:%d", dir, os.Getuid(), os.Getgid(), uid, gid)
		}
	}
	if info, err := os.Stat(stage.layout.runtimeSupportPath); err != nil {
		t.Fatalf("stat runtime support: %v", err)
	} else if info.Mode().Perm() != stableStageExecFileMode {
		t.Fatalf("expected runtime support mode %o, got %o", stableStageExecFileMode, info.Mode().Perm())
	}
}

func TestRuntimeMountExtractionSucceedsWithOwnerOnlyMountStageRoot(t *testing.T) {
	stageRootDir := filepath.Join(t.TempDir(), "mount-stage")
	mkdirWithMode(t, stageRootDir, 0o700)

	archiveBytes := mustRuntimeMountArchiveBytes(t,
		runtimeMountArchiveEntry{name: "config", typeflag: tar.TypeDir, mode: 0o755},
		runtimeMountArchiveEntry{name: "config/app.conf", body: []byte("mode=owner-only\n"), typeflag: tar.TypeReg, mode: 0o640},
	)
	archivePath := filepath.Join(stageRootDir, executionPayloadArchiveName)
	writeFileWithMode(t, archivePath, archiveBytes, 0o600)

	contentsDir := filepath.Join(stageRootDir, "contents")
	mkdirWithMode(t, contentsDir, 0o700)

	extractedBytes, err := extractRuntimeMountArchive(contentsDir, archiveBytes, maxRuntimeMountBytes, maxRuntimeMountTotalBytes, executionPlatformStateOwner{UID: os.Getuid(), GID: os.Getgid()})
	if err != nil {
		t.Fatalf("extract runtime mount archive: %v", err)
	}
	if extractedBytes != int64(len("mode=owner-only\n")) {
		t.Fatalf("unexpected extracted byte count %d", extractedBytes)
	}
	if err := os.Remove(archivePath); err != nil {
		t.Fatalf("remove staged runtime mount archive: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(contentsDir, "config", "app.conf"))
	if err != nil {
		t.Fatalf("read extracted runtime mount file: %v", err)
	}
	if string(content) != "mode=owner-only\n" {
		t.Fatalf("unexpected extracted runtime mount file %q", string(content))
	}
}

func TestRetainTerminalResultPackagesOwnerOnlyReadableResultTreeWithoutNormalizationMarker(t *testing.T) {
	service, locator, layout := newResultTestService(t)

	mkdirWithMode(t, filepath.Join(layout.resultStageDir, "nested"), 0o700)
	writeFileWithMode(t, filepath.Join(layout.resultStageDir, "summary.txt"), []byte("ok\n"), 0o600)
	writeFileWithMode(t, filepath.Join(layout.resultStageDir, "nested", "result.json"), []byte("{\"status\":\"ok\"}\n"), 0o600)

	retained, err := service.retainTerminalResult(locator)
	if err != nil {
		t.Fatalf("retain terminal result: %v", err)
	}
	if !retained {
		t.Fatalf("expected retained result bundle")
	}

	bundle, ok, resultErr := service.readRetainedResultBundle(locator)
	if resultErr != nil {
		t.Fatalf("read retained result bundle: %+v", resultErr)
	}
	if !ok {
		t.Fatalf("expected retained result bundle to be readable")
	}
	entries := readAdmissionResultBundleEntries(t, bundle.Payload)
	if entries["summary.txt"] != "ok\n" {
		t.Fatalf("unexpected summary entry %q", entries["summary.txt"])
	}
}

func TestRetainTerminalResultAcceptsValidOwnershipNormalizationMarker(t *testing.T) {
	service, locator, layout := newResultTestService(t)

	writeFileWithMode(t, filepath.Join(layout.resultStageDir, "summary.txt"), []byte("ok\n"), 0o600)
	writeOwnershipNormalizationMarker(t, layout.platformStageDir, validOwnershipNormalizationMarker(locator.RunID), 0o600)

	retained, err := service.retainTerminalResult(locator)
	if err != nil {
		t.Fatalf("retain terminal result: %v", err)
	}
	if !retained {
		t.Fatalf("expected retained result bundle")
	}
}

func TestRetainTerminalResultFailsClosedWhenOwnershipNormalizationMarkerIsInvalid(t *testing.T) {
	service, locator, layout := newResultTestService(t)

	writeFileWithMode(t, filepath.Join(layout.resultStageDir, "summary.txt"), []byte("ok\n"), 0o600)
	marker := validOwnershipNormalizationMarker("run-deadbeefdeadbeef")
	writeOwnershipNormalizationMarker(t, layout.platformStageDir, marker, 0o600)

	retained, err := service.retainTerminalResult(locator)
	if err == nil {
		t.Fatalf("expected invalid normalization marker to fail closed")
	}
	if retained {
		t.Fatalf("did not expect retained result bundle with invalid normalization marker")
	}
	if _, statErr := os.Stat(service.retainedResultBundlePath(locator)); !os.IsNotExist(statErr) {
		t.Fatalf("expected no retained result bundle, got %v", statErr)
	}
}

func TestResultServesRetainedBundleAfterStageCleanup(t *testing.T) {
	service, locator, layout := newResultTestService(t)

	writeFileWithMode(t, filepath.Join(layout.resultStageDir, "summary.txt"), []byte("retained\n"), 0o600)
	retained, err := service.retainTerminalResult(locator)
	if err != nil {
		t.Fatalf("retain terminal result: %v", err)
	}
	if !retained {
		t.Fatalf("expected retained result bundle")
	}
	if err := os.RemoveAll(layout.stageRootDir); err != nil {
		t.Fatalf("remove stage root: %v", err)
	}

	bundle, resultErr := service.Result(context.Background(), locator.RunID)
	if resultErr != nil {
		t.Fatalf("result after stage cleanup: %+v", resultErr)
	}
	if string(bundle.Payload) == "" {
		t.Fatalf("expected retained result payload")
	}
	entries := readAdmissionResultBundleEntries(t, bundle.Payload)
	if entries["summary.txt"] != "retained\n" {
		t.Fatalf("unexpected summary entry %q", entries["summary.txt"])
	}
}

func TestReadRetainedResultBundleReconcilesExistingRetainedArtifacts(t *testing.T) {
	service, locator, _ := newResultTestService(t)

	resultDir := service.retainedResultRunDir(locator)
	mkdirWithMode(t, resultDir, 0o777)
	writeFileWithMode(t, service.retainedResultBundlePath(locator), []byte("already retained"), 0o644)

	bundle, ok, resultErr := service.readRetainedResultBundle(locator)
	if resultErr != nil {
		t.Fatalf("read retained result bundle: %+v", resultErr)
	}
	if !ok {
		t.Fatal("expected retained result bundle to remain readable")
	}
	if string(bundle.Payload) != "already retained" {
		t.Fatalf("unexpected retained payload %q", string(bundle.Payload))
	}

	if info, err := os.Stat(resultDir); err != nil {
		t.Fatalf("stat retained result dir: %v", err)
	} else if info.Mode().Perm() != retainedResultRunDirMode {
		t.Fatalf("expected retained result dir mode %o, got %o", retainedResultRunDirMode, info.Mode().Perm())
	}
	if info, err := os.Stat(service.retainedResultBundlePath(locator)); err != nil {
		t.Fatalf("stat retained result bundle: %v", err)
	} else if info.Mode().Perm() != retainedResultBundleFileMode {
		t.Fatalf("expected retained result bundle mode %o, got %o", retainedResultBundleFileMode, info.Mode().Perm())
	}
}

func TestStatusTerminalSuccessWithValidNormalizationMarkerRetainsResultCleansStageAndServesRepeatFetch(t *testing.T) {
	fixture := newSyntheticNormalizedRunFixture(t, "run-1111111111111111")
	fixture.service.nomadClient = terminalSuccessNomadClient(t, fixture.locator.JobID())
	marker := validOwnershipNormalizationMarker(fixture.locator.RunID)
	fixture.writeNormalizedRunState(t, &marker)

	status, err := fixture.service.Status(context.Background(), fixture.locator.RunID)
	if err != nil {
		t.Fatalf("status: %+v", err)
	}
	if !status.Terminal || status.Status != executionLifecycleStatusTerminal {
		t.Fatalf("expected terminal success status, got %+v", status)
	}
	if status.ExitCode == nil || *status.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %+v", status)
	}
	if _, statErr := os.Stat(fixture.layout.stageRootDir); !os.IsNotExist(statErr) {
		t.Fatalf("expected successful cleanup to remove the stage root, got %v", statErr)
	}

	first, resultErr := fixture.service.Result(context.Background(), fixture.locator.RunID)
	if resultErr != nil {
		t.Fatalf("result first fetch: %+v", resultErr)
	}
	second, resultErr := fixture.service.Result(context.Background(), fixture.locator.RunID)
	if resultErr != nil {
		t.Fatalf("result second fetch: %+v", resultErr)
	}
	if !bytes.Equal(first.Payload, second.Payload) {
		t.Fatalf("expected repeat retained-result fetch to stay stable")
	}
	evidencePath := fixture.service.retainedNormalizationEvidencePath(fixture.locator)
	if _, err := os.Stat(evidencePath); err != nil {
		t.Fatalf("expected preserved normalization evidence after cleanup: %v", err)
	}
	if _, _, _, err := loadValidatedOwnershipNormalizationMarker(
		evidencePath,
		fixture.service.retainedResultRunDir(fixture.locator),
		ownershipExpectationsForRun(fixture.locator.RunID, executionPlatformStateOwner{UID: os.Getuid(), GID: os.Getgid()}, false),
	); err != nil {
		t.Fatalf("expected preserved normalization evidence to validate, got %v", err)
	}

	entries := readAdmissionResultBundleEntries(t, first.Payload)
	if entries["summary.txt"] != "synthetic-ok\n" {
		t.Fatalf("unexpected summary entry %q", entries["summary.txt"])
	}
}

func TestStatusTerminalSuccessWithoutNormalizationMarkerRemainsAlphaCompatible(t *testing.T) {
	fixture := newSyntheticNormalizedRunFixture(t, "run-2222222222222222")
	fixture.service.nomadClient = terminalSuccessNomadClient(t, fixture.locator.JobID())
	fixture.writeNormalizedRunState(t, nil)

	status, err := fixture.service.Status(context.Background(), fixture.locator.RunID)
	if err != nil {
		t.Fatalf("status: %+v", err)
	}
	if !status.Terminal || status.Status != executionLifecycleStatusTerminal {
		t.Fatalf("expected terminal success status, got %+v", status)
	}
	if _, statErr := os.Stat(fixture.layout.stageRootDir); !os.IsNotExist(statErr) {
		t.Fatalf("expected alpha-compatible successful cleanup to remove the stage root, got %v", statErr)
	}

	bundle, ok, resultErr := fixture.service.readRetainedResultBundle(fixture.locator)
	if resultErr != nil {
		t.Fatalf("read retained result bundle: %+v", resultErr)
	}
	if !ok {
		t.Fatalf("expected retained result bundle in alpha-compatible mode without marker")
	}
	entries := readAdmissionResultBundleEntries(t, bundle.Payload)
	if entries["summary.txt"] != "synthetic-ok\n" {
		t.Fatalf("unexpected summary entry %q", entries["summary.txt"])
	}
	if _, err := os.Stat(fixture.service.retainedNormalizationEvidencePath(fixture.locator)); !os.IsNotExist(err) {
		t.Fatalf("did not expect preserved normalization evidence without a marker, got %v", err)
	}
}

func TestResultFailsClosedWhenPreservedNormalizationEvidenceIsInvalid(t *testing.T) {
	service, locator, _ := newResultTestService(t)

	resultDir := service.retainedResultRunDir(locator)
	mkdirWithMode(t, resultDir, retainedResultRunDirMode)
	writeFileWithMode(t, service.retainedResultBundlePath(locator), []byte("already retained"), retainedResultBundleFileMode)
	writeOwnershipNormalizationMarker(t, resultDir, ownershipNormalizationMarker{
		SchemaVersion:   ownershipNormalizationMarkerSchemaVersion,
		Status:          ownershipNormalizationMarkerStatus,
		RunID:           "run-deadbeefdeadbeef",
		TargetUID:       intPtr(os.Getuid()),
		TargetGID:       intPtr(os.Getgid()),
		PathsNormalized: append([]string(nil), ownershipNormalizationRequiredPaths...),
		CompletedAt:     "2026-04-25T12:00:00Z",
	}, retainedNormalizationEvidenceFileMode)

	_, err := service.Result(context.Background(), locator.RunID)
	if err == nil || err.Status != http.StatusConflict || err.Code != codeResultUnavailable {
		t.Fatalf("expected invalid preserved normalization evidence to fail closed, got %+v", err)
	}
}

func TestStatusTerminalSuccessWithInvalidNormalizationMarkerSkipsCleanupAndLeavesResultUnavailable(t *testing.T) {
	fixture := newSyntheticNormalizedRunFixture(t, "run-3333333333333333")
	fixture.service.nomadClient = terminalSuccessNomadClient(t, fixture.locator.JobID())
	marker := validOwnershipNormalizationMarker(fixture.locator.RunID)
	marker.CompletedAt = "not-a-timestamp"
	fixture.writeNormalizedRunState(t, &marker)

	status, err := fixture.service.Status(context.Background(), fixture.locator.RunID)
	if err != nil {
		t.Fatalf("status: %+v", err)
	}
	if !status.Terminal || status.Status != executionLifecycleStatusTerminal {
		t.Fatalf("expected terminal success status, got %+v", status)
	}
	requirePathExists(t, fixture.layout.stageRootDir)

	if _, ok, resultErr := fixture.service.readRetainedResultBundle(fixture.locator); resultErr != nil {
		t.Fatalf("read retained result bundle: %+v", resultErr)
	} else if ok {
		t.Fatalf("did not expect retained result bundle with invalid present marker")
	}

	_, resultErr := fixture.service.Result(context.Background(), fixture.locator.RunID)
	if resultErr == nil || resultErr.Status != http.StatusConflict || resultErr.Code != codeResultUnavailable {
		t.Fatalf("expected result_unavailable after invalid marker blocks retention, got %+v", resultErr)
	}
}

func TestStatusTerminalFailureWithValidNormalizationMarkerRetainsStageRootForDebugging(t *testing.T) {
	fixture := newSyntheticNormalizedRunFixture(t, "run-4444444444444444")
	fixture.service.nomadClient = terminalFailedNomadClient(t, fixture.locator.JobID(), 7)
	marker := validOwnershipNormalizationMarker(fixture.locator.RunID)
	fixture.writeNormalizedRunState(t, &marker)

	status, err := fixture.service.Status(context.Background(), fixture.locator.RunID)
	if err != nil {
		t.Fatalf("status: %+v", err)
	}
	if !status.Terminal || status.Status != executionLifecycleStatusTerminal {
		t.Fatalf("expected terminal failure status, got %+v", status)
	}
	if status.ExitCode == nil || *status.ExitCode != 7 {
		t.Fatalf("expected exit code 7, got %+v", status)
	}
	requirePathExists(t, fixture.layout.stageRootDir)

	bundle, ok, resultErr := fixture.service.readRetainedResultBundle(fixture.locator)
	if resultErr != nil {
		t.Fatalf("read retained result bundle: %+v", resultErr)
	}
	if !ok {
		t.Fatalf("expected retained result bundle for failed terminal run with readable normalized result tree")
	}
	entries := readAdmissionResultBundleEntries(t, bundle.Payload)
	if entries["summary.txt"] != "synthetic-ok\n" {
		t.Fatalf("unexpected summary entry %q", entries["summary.txt"])
	}
}

func TestStatusTerminalLostWithValidNormalizationMarkerRetainsStageRootForDebugging(t *testing.T) {
	fixture := newSyntheticNormalizedRunFixture(t, "run-5555555555555555")
	fixture.service.nomadClient = terminalLostNomadClient(t, fixture.locator.JobID(), 137)
	marker := validOwnershipNormalizationMarker(fixture.locator.RunID)
	fixture.writeNormalizedRunState(t, &marker)

	status, err := fixture.service.Status(context.Background(), fixture.locator.RunID)
	if err != nil {
		t.Fatalf("status: %+v", err)
	}
	if !status.Terminal || status.Status != executionLifecycleStatusTerminal {
		t.Fatalf("expected terminal lost status, got %+v", status)
	}
	if status.ExitCode == nil || *status.ExitCode != 137 {
		t.Fatalf("expected exit code 137, got %+v", status)
	}
	requirePathExists(t, fixture.layout.stageRootDir)

	bundle, ok, resultErr := fixture.service.readRetainedResultBundle(fixture.locator)
	if resultErr != nil {
		t.Fatalf("read retained result bundle: %+v", resultErr)
	}
	if !ok {
		t.Fatalf("expected retained result bundle for lost terminal run with readable normalized result tree")
	}
	entries := readAdmissionResultBundleEntries(t, bundle.Payload)
	if entries["summary.txt"] != "synthetic-ok\n" {
		t.Fatalf("unexpected summary entry %q", entries["summary.txt"])
	}
}

func TestStatusTerminalCanceledWithValidNormalizationMarkerRetainsStageRootAndServesRetainedResult(t *testing.T) {
	fixture := newSyntheticNormalizedRunFixture(t, "run-6666666666666666")
	fixture.service.nomadClient = terminalCanceledNomadClient(t, fixture.locator.JobID(), 143)
	marker := validOwnershipNormalizationMarker(fixture.locator.RunID)
	fixture.writeNormalizedRunState(t, &marker)

	status, err := fixture.service.Status(context.Background(), fixture.locator.RunID)
	if err != nil {
		t.Fatalf("status: %+v", err)
	}
	if !status.Terminal || status.Status != executionLifecycleStatusTerminal {
		t.Fatalf("expected terminal canceled status, got %+v", status)
	}
	if status.ExitCode == nil || *status.ExitCode != 143 {
		t.Fatalf("expected exit code 143 for canceled terminal run, got %+v", status)
	}
	requirePathExists(t, fixture.layout.stageRootDir)
	requirePathExists(t, filepath.Join(fixture.layout.resultStageDir, "summary.txt"))

	bundle, ok, resultErr := fixture.service.readRetainedResultBundle(fixture.locator)
	if resultErr != nil {
		t.Fatalf("read retained result bundle: %+v", resultErr)
	}
	if !ok {
		t.Fatalf("expected retained result bundle for canceled terminal run with readable normalized result tree")
	}
	entries := readAdmissionResultBundleEntries(t, bundle.Payload)
	if entries["summary.txt"] != "synthetic-ok\n" {
		t.Fatalf("unexpected summary entry %q", entries["summary.txt"])
	}

	result, resultErr := fixture.service.Result(context.Background(), fixture.locator.RunID)
	if resultErr != nil {
		t.Fatalf("result: %+v", resultErr)
	}
	resultEntries := readAdmissionResultBundleEntries(t, result.Payload)
	if resultEntries["summary.txt"] != "synthetic-ok\n" {
		t.Fatalf("unexpected result entry %q", resultEntries["summary.txt"])
	}
	requirePathExists(t, fixture.layout.stageRootDir)
	requirePathExists(t, filepath.Join(fixture.layout.resultStageDir, "summary.txt"))
}

func TestStatusTerminalCanceledWithInvalidNormalizationMarkerRetainsStageRootAndLeavesResultUnavailable(t *testing.T) {
	fixture := newSyntheticNormalizedRunFixture(t, "run-7777777777777777")
	fixture.service.nomadClient = terminalCanceledNomadClient(t, fixture.locator.JobID(), 143)
	marker := validOwnershipNormalizationMarker(fixture.locator.RunID)
	marker.CompletedAt = "not-a-timestamp"
	fixture.writeNormalizedRunState(t, &marker)

	status, err := fixture.service.Status(context.Background(), fixture.locator.RunID)
	if err != nil {
		t.Fatalf("status: %+v", err)
	}
	if !status.Terminal || status.Status != executionLifecycleStatusTerminal {
		t.Fatalf("expected terminal canceled status, got %+v", status)
	}
	if status.ExitCode == nil || *status.ExitCode != 143 {
		t.Fatalf("expected exit code 143 for canceled terminal run, got %+v", status)
	}
	requirePathExists(t, fixture.layout.stageRootDir)
	requirePathExists(t, filepath.Join(fixture.layout.resultStageDir, "summary.txt"))

	if _, ok, resultErr := fixture.service.readRetainedResultBundle(fixture.locator); resultErr != nil {
		t.Fatalf("read retained result bundle: %+v", resultErr)
	} else if ok {
		t.Fatalf("did not expect retained result bundle with invalid present marker on canceled run")
	}

	_, resultErr := fixture.service.Result(context.Background(), fixture.locator.RunID)
	if resultErr == nil || resultErr.Status != http.StatusConflict || resultErr.Code != codeResultUnavailable {
		t.Fatalf("expected result_unavailable after invalid marker blocks canceled-run retention, got %+v", resultErr)
	}
	requirePathExists(t, fixture.layout.stageRootDir)
	requirePathExists(t, filepath.Join(fixture.layout.resultStageDir, "summary.txt"))
}

func TestRetainTerminalResultFailsClosedWhenResultTreeIsUnreadable(t *testing.T) {
	service, locator, layout := newResultTestService(t)

	mkdirWithMode(t, layout.resultStageDir, 0o700)
	writeFileWithMode(t, filepath.Join(layout.resultStageDir, "summary.txt"), []byte("ok\n"), 0o600)
	requireChmod000ReadDenied(t, layout.resultStageDir)

	retained, err := service.retainTerminalResult(locator)
	if err == nil {
		t.Fatalf("expected unreadable result tree to fail closed")
	}
	if retained {
		t.Fatalf("did not expect retained result bundle on unreadable tree")
	}
	if _, statErr := os.Stat(service.retainedResultBundlePath(locator)); !os.IsNotExist(statErr) {
		t.Fatalf("expected no retained result bundle, got %v", statErr)
	}
}

func TestResultReturnsUnavailableWhenTerminalResultTreeIsUnreadable(t *testing.T) {
	service, locator, layout := newResultTestService(t)

	mkdirWithMode(t, layout.resultStageDir, 0o700)
	writeFileWithMode(t, filepath.Join(layout.resultStageDir, "summary.txt"), []byte("ok\n"), 0o600)
	requireChmod000ReadDenied(t, layout.resultStageDir)

	service.nomadClient = terminalSuccessNomadClient(t, locator.JobID())

	_, err := service.Result(context.Background(), locator.RunID)
	if err == nil || err.Status != http.StatusConflict || err.Code != codeResultUnavailable {
		t.Fatalf("expected result_unavailable for unreadable result tree, got %+v", err)
	}
	requirePathExists(t, layout.stageRootDir)
}

func TestMaybeCleanupSuccessfulStageRootRemovesOwnerOnlyServiceTreeWithoutNormalizationMarker(t *testing.T) {
	stagingRootDir := filepath.Join(t.TempDir(), "stage")
	service := Service{
		cfg: esconfig.Config{
			Execution: esconfig.ExecutionConfig{
				StagingRootDir: stagingRootDir,
				ResultsRootDir: filepath.Join(t.TempDir(), "results"),
			},
		},
	}
	mkdirWithMode(t, service.cfg.Execution.ResultsRootDir, 0o700)
	locator := newExecutionLocatorFromRunID("run-0123456789abcdef")
	layout := newExecutionPackageLayout(service.cfg, locator)

	mkdirWithMode(t, filepath.Join(layout.payloadStageDir), 0o700)
	mkdirWithMode(t, filepath.Join(layout.platformStageDir), 0o700)
	mkdirWithMode(t, filepath.Join(layout.resultStageDir), 0o700)
	mkdirWithMode(t, filepath.Join(layout.mountsStageRootDir, "00", "contents"), 0o700)
	writeFileWithMode(t, filepath.Join(layout.payloadStageDir, executionPayloadArchiveName), []byte("payload"), 0o600)
	writeFileWithMode(t, filepath.Join(layout.platformStageDir, "marker.txt"), []byte("platform"), 0o600)
	writeFileWithMode(t, filepath.Join(layout.resultStageDir, "summary.txt"), []byte("cleanup\n"), 0o600)
	writeFileWithMode(t, filepath.Join(layout.mountsStageRootDir, "00", "contents", "config.env"), []byte("MOUNTED=1\n"), 0o600)

	service.maybeCleanupSuccessfulStageRoot(locator, terminalSuccessAllocation())

	if _, err := os.Stat(layout.stageRootDir); !os.IsNotExist(err) {
		t.Fatalf("expected successful cleanup to remove the stage root, got %v", err)
	}
	bundle, ok, resultErr := service.readRetainedResultBundle(locator)
	if resultErr != nil {
		t.Fatalf("read retained result bundle: %+v", resultErr)
	}
	if !ok {
		t.Fatalf("expected retained result bundle after successful cleanup")
	}
	entries := readAdmissionResultBundleEntries(t, bundle.Payload)
	if entries["summary.txt"] != "cleanup\n" {
		t.Fatalf("unexpected retained result entry %q", entries["summary.txt"])
	}
}

func TestMaybeCleanupSuccessfulStageRootRetainsTreeWhenPresentNormalizationMarkerIsInvalid(t *testing.T) {
	stagingRootDir := filepath.Join(t.TempDir(), "stage")
	resultsRootDir := filepath.Join(t.TempDir(), "results")
	service := Service{
		cfg: esconfig.Config{
			Execution: esconfig.ExecutionConfig{
				StagingRootDir: stagingRootDir,
				ResultsRootDir: resultsRootDir,
			},
		},
	}
	mkdirWithMode(t, service.cfg.Execution.ResultsRootDir, 0o700)
	locator := newExecutionLocatorFromRunID("run-0123456789abcdef")
	layout := newExecutionPackageLayout(service.cfg, locator)

	mkdirWithMode(t, filepath.Join(layout.platformStageDir), 0o700)
	mkdirWithMode(t, filepath.Join(layout.resultStageDir), 0o700)
	mkdirWithMode(t, filepath.Join(layout.runStageDir, "work"), 0o700)
	writeFileWithMode(t, filepath.Join(layout.resultStageDir, "summary.txt"), []byte("cleanup\n"), 0o600)
	writeFileWithMode(t, filepath.Join(layout.stageRootDir, "payload.marker"), []byte("keep"), 0o600)

	bundlePath := service.retainedResultBundlePath(locator)
	writeFileWithMode(t, bundlePath, []byte("already retained"), 0o600)

	marker := validOwnershipNormalizationMarker(locator.RunID)
	marker.CompletedAt = "not-a-timestamp"
	writeOwnershipNormalizationMarker(t, layout.platformStageDir, marker, 0o600)

	service.maybeCleanupSuccessfulStageRoot(locator, terminalSuccessAllocation())

	requirePathExists(t, layout.stageRootDir)
	requirePathExists(t, filepath.Join(layout.stageRootDir, "payload.marker"))
	requirePathExists(t, bundlePath)
}

func TestMaybeCleanupSuccessfulStageRootRetainsUndeletableTreeWithoutPartialRemoval(t *testing.T) {
	stagingRootDir := filepath.Join(t.TempDir(), "stage")
	service := Service{
		cfg: esconfig.Config{
			Execution: esconfig.ExecutionConfig{
				StagingRootDir: stagingRootDir,
				ResultsRootDir: filepath.Join(t.TempDir(), "results"),
			},
		},
	}
	mkdirWithMode(t, service.cfg.Execution.ResultsRootDir, 0o700)
	locator := newExecutionLocatorFromRunID("run-0123456789abcdef")
	layout := newExecutionPackageLayout(service.cfg, locator)

	mkdirWithMode(t, filepath.Join(layout.resultStageDir), 0o700)
	mkdirWithMode(t, filepath.Join(layout.runStageDir, "work", "blocked"), 0o700)
	writeFileWithMode(t, filepath.Join(layout.resultStageDir, "summary.txt"), []byte("cleanup\n"), 0o600)
	writeFileWithMode(t, filepath.Join(layout.stageRootDir, "payload.marker"), []byte("keep"), 0o600)
	requireChmod500DeleteDenied(t, filepath.Join(layout.runStageDir, "work"))

	service.maybeCleanupSuccessfulStageRoot(locator, terminalSuccessAllocation())

	requirePathExists(t, layout.stageRootDir)
	requirePathExists(t, filepath.Join(layout.stageRootDir, "payload.marker"))
	requirePathExists(t, filepath.Join(layout.runStageDir, "work", "blocked"))

	bundle, ok, resultErr := service.readRetainedResultBundle(locator)
	if resultErr != nil {
		t.Fatalf("read retained result bundle: %+v", resultErr)
	}
	if !ok {
		t.Fatalf("expected retained result bundle before cleanup was skipped")
	}
	if len(bundle.Payload) == 0 {
		t.Fatalf("expected retained result payload before cleanup was skipped")
	}
}

func TestValidateOwnershipNormalizationMarkerOptionalTargetUIDGID(t *testing.T) {
	marker := validOwnershipNormalizationMarker("run-0123456789abcdef")

	expectedUID := os.Getuid()
	expectedGID := os.Getgid()
	if err := validateOwnershipNormalizationMarker(marker, ownershipNormalizationMarkerExpectations{
		RunID:       "run-0123456789abcdef",
		ExpectedUID: &expectedUID,
		ExpectedGID: &expectedGID,
	}); err != nil {
		t.Fatalf("expected marker validation to accept matching target uid/gid: %v", err)
	}

	otherUID := expectedUID + 1
	if err := validateOwnershipNormalizationMarker(marker, ownershipNormalizationMarkerExpectations{
		RunID:       "run-0123456789abcdef",
		ExpectedUID: &otherUID,
		ExpectedGID: &expectedGID,
	}); err == nil {
		t.Fatalf("expected marker validation to reject mismatched target uid")
	}
}

func TestPreflightOptionalOwnershipNormalizationMarkerBlocksMissingMarkerInNonRootRequiredMode(t *testing.T) {
	platformDir := filepath.Join(t.TempDir(), "run", "platform")
	mkdirWithMode(t, platformDir, 0o700)

	expectedUID := os.Getuid()
	expectedGID := os.Getgid()
	_, err := preflightOptionalOwnershipNormalizationMarker(platformDir, ownershipNormalizationMarkerExpectations{
		RunID:         "run-0123456789abcdef",
		ExpectedUID:   &expectedUID,
		ExpectedGID:   &expectedGID,
		RequireMarker: true,
	})
	if err == nil {
		t.Fatal("expected missing marker to block in non-root-required mode")
	}
}

func TestPreflightOptionalOwnershipNormalizationMarkerBlocksTargetOwnerMismatchInNonRootRequiredMode(t *testing.T) {
	platformDir := filepath.Join(t.TempDir(), "run", "platform")
	mkdirWithMode(t, platformDir, 0o700)

	marker := validOwnershipNormalizationMarker("run-0123456789abcdef")
	mismatchedUID := os.Getuid() + 1
	marker.TargetUID = &mismatchedUID
	writeOwnershipNormalizationMarker(t, platformDir, marker, 0o600)

	expectedUID := os.Getuid()
	expectedGID := os.Getgid()
	_, err := preflightOptionalOwnershipNormalizationMarker(platformDir, ownershipNormalizationMarkerExpectations{
		RunID:         "run-0123456789abcdef",
		ExpectedUID:   &expectedUID,
		ExpectedGID:   &expectedGID,
		RequireMarker: true,
	})
	if err == nil {
		t.Fatal("expected target-owner mismatch to block in non-root-required mode")
	}
}

func TestPreflightOptionalOwnershipNormalizationMarkerRejectsWorldWritableMarkerAuthorityPath(t *testing.T) {
	platformDir := filepath.Join(t.TempDir(), "run", "platform")
	mkdirWithMode(t, platformDir, 0o755)
	writeOwnershipNormalizationMarker(t, platformDir, validOwnershipNormalizationMarker("run-0123456789abcdef"), 0o600)
	if err := os.Chmod(platformDir, 0o733); err != nil {
		t.Fatalf("chmod platform dir writable: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(platformDir, 0o755)
	})

	if _, err := preflightOptionalOwnershipNormalizationMarker(platformDir, ownershipNormalizationMarkerExpectations{
		RunID: "run-0123456789abcdef",
	}); err == nil {
		t.Fatal("expected workload-writable marker authority path to fail closed")
	}
}

func TestPreflightSuccessfulStageCleanupPassesInNonRootRequiredModeWhenMarkerAndOwnershipMatch(t *testing.T) {
	stagingRootDir := filepath.Join(t.TempDir(), "stage")
	locator := newExecutionLocatorFromRunID("run-0123456789abcdef")
	layout := newExecutionPackageLayout(esconfig.Config{
		Execution: esconfig.ExecutionConfig{
			StagingRootDir: stagingRootDir,
			ResultsRootDir: filepath.Join(t.TempDir(), "results"),
		},
	}, locator)

	mkdirWithMode(t, filepath.Join(layout.payloadStageDir), 0o700)
	mkdirWithMode(t, filepath.Join(layout.platformStageDir), 0o700)
	mkdirWithMode(t, filepath.Join(layout.runStageDir, "work"), 0o700)
	mkdirWithMode(t, filepath.Join(layout.resultStageDir), 0o700)
	writeFileWithMode(t, filepath.Join(layout.payloadStageDir, executionPayloadArchiveName), []byte("payload"), 0o600)
	writeFileWithMode(t, filepath.Join(layout.platformStageDir, "runtime.txt"), []byte("platform"), 0o600)
	writeFileWithMode(t, filepath.Join(layout.runStageDir, "work", "entrypoint"), []byte("#!/bin/sh\n"), 0o700)
	writeFileWithMode(t, filepath.Join(layout.resultStageDir, "summary.txt"), []byte("cleanup\n"), 0o600)
	writeOwnershipNormalizationMarker(t, layout.platformStageDir, validOwnershipNormalizationMarker(locator.RunID), 0o600)

	expectedUID := os.Getuid()
	expectedGID := os.Getgid()
	if err := preflightSuccessfulStageCleanup(layout.stageRootDir, layout.platformStageDir, ownershipNormalizationMarkerExpectations{
		RunID:         locator.RunID,
		ExpectedUID:   &expectedUID,
		ExpectedGID:   &expectedGID,
		RequireMarker: true,
	}); err != nil {
		t.Fatalf("expected non-root-required cleanup preflight to pass, got %v", err)
	}
}

func terminalSuccessNomadClient(t *testing.T, jobID string) *nomadClient {
	t.Helper()
	return terminalNomadClient(t, jobID, "complete", 0)
}

func terminalFailedNomadClient(t *testing.T, jobID string, exitCode int) *nomadClient {
	t.Helper()
	return terminalNomadClient(t, jobID, "failed", exitCode)
}

func terminalLostNomadClient(t *testing.T, jobID string, exitCode int) *nomadClient {
	t.Helper()
	return terminalNomadClient(t, jobID, "lost", exitCode)
}

func terminalCanceledNomadClient(t *testing.T, jobID string, exitCode int) *nomadClient {
	t.Helper()
	// ES currently observes canceled runs as terminal non-success rather than as a
	// distinct public canceled terminal phase.
	return terminalNomadClient(t, jobID, "complete", exitCode)
}

func terminalNomadClient(t *testing.T, jobID string, clientStatus string, exitCode int) *nomadClient {
	t.Helper()

	return newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/job/" + jobID:
			_, _ = w.Write([]byte(`{"ID":"` + jobID + `","Status":"dead"}`))
		case "/v1/job/" + jobID + "/allocations":
			_, _ = w.Write([]byte(`[{"ID":"alloc-1","ModifyIndex":1}]`))
		case "/v1/allocation/alloc-1":
			_, _ = w.Write([]byte(`{"ID":"alloc-1","ClientStatus":"` + clientStatus + `","TaskStates":{"task":{"State":"dead","Events":[{"Type":"Terminated","ExitCode":` + exitCodeString(exitCode) + `}]}}}`))
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
}

func terminalSuccessAllocation() *nomadAllocationDetail {
	return &nomadAllocationDetail{
		ClientStatus: "complete",
		TaskStates: map[string]nomadTaskState{
			nomadTaskName: {
				State: "dead",
				Events: []nomadTaskEvent{
					{Type: "Terminated", ExitCode: 0},
				},
			},
		},
	}
}

func mkdirWithMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()

	if err := os.MkdirAll(path, mode); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
}

func writeFileWithMode(t *testing.T, path string, payload []byte, mode os.FileMode) {
	t.Helper()

	mkdirWithMode(t, filepath.Dir(path), 0o700)
	if err := os.WriteFile(path, payload, mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
}

func requirePathExists(t *testing.T, path string) {
	t.Helper()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected path %s to exist: %v", path, err)
	}
}

func validOwnershipNormalizationMarker(runID string) ownershipNormalizationMarker {
	targetUID := os.Getuid()
	targetGID := os.Getgid()
	return ownershipNormalizationMarker{
		SchemaVersion:   ownershipNormalizationMarkerSchemaVersion,
		Status:          ownershipNormalizationMarkerStatus,
		RunID:           runID,
		TargetUID:       &targetUID,
		TargetGID:       &targetGID,
		PathsNormalized: append([]string(nil), ownershipNormalizationRequiredPaths...),
		CompletedAt:     "2026-04-25T12:00:00Z",
	}
}

func writeOwnershipNormalizationMarker(t *testing.T, platformDir string, marker ownershipNormalizationMarker, mode os.FileMode) {
	t.Helper()

	payload, err := json.Marshal(marker)
	if err != nil {
		t.Fatalf("marshal ownership-normalization marker: %v", err)
	}
	writeFileWithMode(t, filepath.Join(platformDir, ownershipNormalizationMarkerName), append(payload, '\n'), mode)
}

type syntheticNormalizedRunFixture struct {
	service *Service
	locator executionLocator
	layout  executionPackageLayout
}

func newSyntheticNormalizedRunFixture(t *testing.T, runID string) syntheticNormalizedRunFixture {
	t.Helper()

	service := &Service{
		cfg: esconfig.Config{
			Execution: esconfig.ExecutionConfig{
				StagingRootDir: filepath.Join(t.TempDir(), "stage"),
				ResultsRootDir: filepath.Join(t.TempDir(), "results"),
			},
		},
	}
	if err := os.MkdirAll(service.cfg.Execution.ResultsRootDir, 0o700); err != nil {
		t.Fatalf("mkdir results root: %v", err)
	}
	locator := newExecutionLocatorFromRunID(runID)
	return syntheticNormalizedRunFixture{
		service: service,
		locator: locator,
		layout:  newExecutionPackageLayout(service.cfg, locator),
	}
}

func (f syntheticNormalizedRunFixture) writeNormalizedRunState(t *testing.T, marker *ownershipNormalizationMarker) {
	t.Helper()

	mkdirWithMode(t, f.layout.payloadStageDir, 0o700)
	mkdirWithMode(t, f.layout.platformStageDir, 0o700)
	mkdirWithMode(t, filepath.Join(f.layout.runStageDir, "work"), 0o700)
	mkdirWithMode(t, f.layout.resultStageDir, 0o700)
	writeFileWithMode(t, filepath.Join(f.layout.payloadStageDir, executionPayloadArchiveName), []byte("payload"), 0o600)
	writeFileWithMode(t, filepath.Join(f.layout.platformStageDir, "runtime.txt"), []byte("platform"), 0o600)
	writeFileWithMode(t, filepath.Join(f.layout.runStageDir, "work", "entrypoint"), []byte("#!/bin/sh\n"), 0o700)
	writeFileWithMode(t, filepath.Join(f.layout.resultStageDir, "summary.txt"), []byte("synthetic-ok\n"), 0o600)
	if marker != nil {
		writeOwnershipNormalizationMarker(t, f.layout.platformStageDir, *marker, 0o600)
	}
}

func exitCodeString(exitCode int) string {
	return strconv.Itoa(exitCode)
}
