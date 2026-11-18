package admission

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"

	esconfig "execution-substrate/es/config"
	"golang.org/x/sys/unix"
)

func TestTrancheB2GovernedResultRetentionLogsContainOnlyValidatedRunID(t *testing.T) {
	const runID = "run-0123456789abcdef"
	const privateMarker = "private-result-path-uid-9123-env-secret"
	missingResultsRoot := filepath.Join(physicalTestTempDir(t), privateMarker, "missing")
	newService := func() *Service {
		return &Service{
			cfg: esconfig.Config{Execution: esconfig.ExecutionConfig{
				StagingRootDir:     physicalTestTempDir(t),
				ResultsRootDir:     missingResultsRoot,
				RetainedResultAuth: esconfig.RetainedResultAuthConfig{StoreID: "test_store", KeyID: "test_key", KeyFile: "/synthetic/retained-result-key"},
			}},
			resultAuth: syntheticResultAuthenticator(),
			nomadClient: newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				switch request.URL.Path {
				case "/v1/job/exec-" + runID:
					_, _ = w.Write([]byte(`{"ID":"exec-run-0123456789abcdef","Status":"dead","ModifyIndex":1}`))
				case "/v1/job/exec-" + runID + "/allocations":
					_, _ = w.Write([]byte(`[]`))
				default:
					t.Fatalf("unexpected Nomad path %q", request.URL.Path)
				}
			})),
		}
	}

	var captured bytes.Buffer
	previousWriter := log.Writer()
	previousFlags := log.Flags()
	previousPrefix := log.Prefix()
	log.SetOutput(&captured)
	log.SetFlags(0)
	log.SetPrefix("")
	t.Cleanup(func() {
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
		log.SetPrefix(previousPrefix)
	})

	if _, publicErr := newService().Status(context.Background(), runID); publicErr != nil {
		t.Fatalf("status failed before best-effort retention: %+v", publicErr)
	}
	if _, publicErr := newService().Result(context.Background(), runID); publicErr == nil || publicErr.Code != codeResultUnavailable {
		t.Fatalf("result did not preserve unavailable mapping: %+v", publicErr)
	}
	newService().maybeRetainTerminalResult(newExecutionLocatorFromRunID(runID), &nomadAllocationDetail{ClientStatus: "complete"})

	wantLine := "es result retention failed run_id=" + runID
	lines := strings.Split(strings.TrimSpace(captured.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("governed retention log count=%d, want 3: %q", len(lines), captured.String())
	}
	for _, line := range lines {
		if line != wantLine {
			t.Fatalf("governed retention log changed: %q", line)
		}
	}
	if strings.Contains(captured.String(), privateMarker) || strings.Contains(captured.String(), "err=") {
		t.Fatalf("private cause escaped into ordinary logs: %q", captured.String())
	}
}

func TestRetainTerminalResultPackagesResultDirectory(t *testing.T) {
	service, locator, layout := newResultTestService(t)
	if err := os.MkdirAll(filepath.Join(layout.resultStageDir, "nested"), 0o755); err != nil {
		t.Fatalf("mkdir result dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(layout.resultStageDir, "summary.txt"), []byte("ok\n"), 0o644); err != nil {
		t.Fatalf("write result file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(layout.resultStageDir, "nested", "result.json"), []byte(`{"status":"ok"}`+"\n"), 0o644); err != nil {
		t.Fatalf("write nested result file: %v", err)
	}

	retained, err := service.retainTerminalResult(locator)
	if err != nil {
		t.Fatalf("retain terminal result: %v", err)
	}
	if !retained {
		t.Fatalf("expected result retention to report retained bundle")
	}

	bundle, ok, resultErr := service.readRetainedResultBundle(locator)
	if resultErr != nil {
		t.Fatalf("read retained result: %+v", resultErr)
	}
	if !ok {
		t.Fatalf("expected retained bundle to be readable")
	}
	if bundle.OutcomeEvidence.Source != outcomeEvidenceSourceRetainedResultStore ||
		bundle.OutcomeEvidence.Observation != outcomeObservationRetainedResultBundle ||
		bundle.OutcomeEvidence.AccessClass != outcomeAccessClassOpaqueResultBundle {
		t.Fatalf("unexpected retained result outcome evidence %+v", bundle.OutcomeEvidence)
	}

	entries := readAdmissionResultBundleEntries(t, bundle.Payload)
	if entries["summary.txt"] != "ok\n" {
		t.Fatalf("unexpected summary entry %q", entries["summary.txt"])
	}
	if entries["nested/result.json"] != "{\"status\":\"ok\"}\n" {
		t.Fatalf("unexpected nested result entry %q", entries["nested/result.json"])
	}
}

func TestWorkstreamC3RetainedResultBundleRemainsESOwnedOpaqueOutput(t *testing.T) {
	service, locator, layout := newResultTestService(t)
	for _, dir := range []string{
		layout.resultStageDir,
		filepath.Join(layout.resultStageDir, "materialized-workspace"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	for _, file := range []struct {
		path string
		body string
	}{
		{
			path: filepath.Join(layout.resultStageDir, "review.json"),
			body: `{"review":"cp-owned semantic content"}` + "\n",
		},
		{
			path: filepath.Join(layout.resultStageDir, "checkpoint.txt"),
			body: "checkpoint belongs above ES\n",
		},
		{
			path: filepath.Join(layout.resultStageDir, "materialized-workspace", "finalization.txt"),
			body: "finalization remains opaque bundle content\n",
		},
	} {
		if err := os.WriteFile(file.path, []byte(file.body), 0o644); err != nil {
			t.Fatalf("write %s: %v", file.path, err)
		}
	}

	retained, err := service.retainTerminalResult(locator)
	if err != nil {
		t.Fatalf("retain terminal result: %v", err)
	}
	if !retained {
		t.Fatalf("expected result retention to report retained bundle")
	}

	bundlePath := service.retainedResultBundlePath(locator)
	if !strings.HasPrefix(bundlePath, service.cfg.Execution.ResultsRootDir+string(os.PathSeparator)) {
		t.Fatalf("expected retained result under ES results root, got %q", bundlePath)
	}
	if strings.HasPrefix(bundlePath, service.cfg.Execution.StagingRootDir+string(os.PathSeparator)) {
		t.Fatalf("retained result bundle must not live under staging root, got %q", bundlePath)
	}

	bundle, ok, resultErr := service.readRetainedResultBundle(locator)
	if resultErr != nil {
		t.Fatalf("read retained result: %+v", resultErr)
	}
	if !ok {
		t.Fatalf("expected retained result bundle")
	}
	if bundle.MediaType != resultBundleMediaType {
		t.Fatalf("expected result media type %q, got %q", resultBundleMediaType, bundle.MediaType)
	}
	if bundle.OutcomeEvidence.Source != outcomeEvidenceSourceRetainedResultStore ||
		bundle.OutcomeEvidence.Observation != outcomeObservationRetainedResultBundle ||
		bundle.OutcomeEvidence.AccessClass != outcomeAccessClassOpaqueResultBundle {
		t.Fatalf("unexpected retained result outcome evidence %+v", bundle.OutcomeEvidence)
	}

	entries := readAdmissionResultBundleEntries(t, bundle.Payload)
	for _, want := range []string{
		"review.json",
		"checkpoint.txt",
		"materialized-workspace/finalization.txt",
	} {
		if _, ok := entries[want]; !ok {
			t.Fatalf("expected opaque retained result entry %q in %v", want, entries)
		}
	}
	for _, forbiddenSidecar := range []string{
		"authority_handoff.json",
		"retained_result_manifest.json",
		"workflow.json",
		"cp_checkpoint.json",
		"scheduler_truth.json",
	} {
		if _, ok := entries[forbiddenSidecar]; ok {
			t.Fatalf("retained bundle must not synthesize authority sidecar %q", forbiddenSidecar)
		}
	}
}

func TestRetainTerminalResultFailsClosedForSymlinkResultEntry(t *testing.T) {
	service, locator, layout := newResultTestService(t)
	if err := os.MkdirAll(layout.resultStageDir, 0o755); err != nil {
		t.Fatalf("mkdir result dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(layout.resultStageDir, "summary.txt"), []byte("ok\n"), 0o644); err != nil {
		t.Fatalf("write result file: %v", err)
	}
	if err := os.Symlink("summary.txt", filepath.Join(layout.resultStageDir, "summary-link.txt")); err != nil {
		t.Fatalf("create result symlink: %v", err)
	}

	retained, err := service.retainTerminalResult(locator)
	if err == nil || !strings.Contains(err.Error(), "unsupported symbolic link") {
		t.Fatalf("expected symbolic link to fail closed, retained=%v err=%v", retained, err)
	}
	if retained {
		t.Fatalf("did not expect retained result bundle with a symlink entry")
	}
	if _, statErr := os.Stat(service.retainedResultBundlePath(locator)); !os.IsNotExist(statErr) {
		t.Fatalf("expected no retained result bundle, got %v", statErr)
	}
}

func TestRetainTerminalResultFailsClosedForHardLinkedResultFile(t *testing.T) {
	service, locator, layout := newResultTestService(t)
	if err := os.MkdirAll(layout.resultStageDir, 0o755); err != nil {
		t.Fatalf("mkdir result dir: %v", err)
	}
	sourcePath := filepath.Join(layout.resultStageDir, "summary.txt")
	if err := os.WriteFile(sourcePath, []byte("ok\n"), 0o644); err != nil {
		t.Fatalf("write result file: %v", err)
	}
	if err := os.Link(sourcePath, filepath.Join(layout.resultStageDir, "summary-hardlink.txt")); err != nil {
		t.Fatalf("create result hardlink: %v", err)
	}

	retained, err := service.retainTerminalResult(locator)
	if err == nil || !strings.Contains(err.Error(), "unsupported hard link") {
		t.Fatalf("expected hard link to fail closed, retained=%v err=%v", retained, err)
	}
	if retained {
		t.Fatalf("did not expect retained result bundle with a hardlinked file")
	}
	if _, statErr := os.Stat(service.retainedResultBundlePath(locator)); !os.IsNotExist(statErr) {
		t.Fatalf("expected no retained result bundle, got %v", statErr)
	}
}

func TestRetainTerminalResultFailsClosedForSpecialResultFile(t *testing.T) {
	service, locator, layout := newResultTestService(t)
	if err := os.MkdirAll(layout.resultStageDir, 0o755); err != nil {
		t.Fatalf("mkdir result dir: %v", err)
	}
	if err := unix.Mkfifo(filepath.Join(layout.resultStageDir, "stream"), 0o600); err != nil {
		t.Fatalf("create result fifo: %v", err)
	}

	retained, err := service.retainTerminalResult(locator)
	if err == nil || !strings.Contains(err.Error(), "unsupported file mode") {
		t.Fatalf("expected special file to fail closed, retained=%v err=%v", retained, err)
	}
	if retained {
		t.Fatalf("did not expect retained result bundle with a special file")
	}
	if _, statErr := os.Stat(service.retainedResultBundlePath(locator)); !os.IsNotExist(statErr) {
		t.Fatalf("expected no retained result bundle, got %v", statErr)
	}
}

func TestRetainedResultPublicationConcurrentWinnerAndValidatedLoser(t *testing.T) {
	service, locator, layout := newResultTestService(t)
	if err := os.MkdirAll(layout.resultStageDir, 0o755); err != nil {
		t.Fatalf("mkdir result dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(layout.resultStageDir, "summary.txt"), []byte("ok\n"), 0o644); err != nil {
		t.Fatalf("write result file: %v", err)
	}

	type outcome struct {
		retained bool
		err      error
	}
	prepared := make(chan struct{}, 2)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releasePublishers := func() { releaseOnce.Do(func() { close(release) }) }
	defer releasePublishers()
	outcomes := make(chan outcome, 2)
	var workers sync.WaitGroup
	workers.Add(2)
	for index := 0; index < 2; index++ {
		go func() {
			defer workers.Done()
			retained, err := service.retainTerminalResultWithHooks(locator, retainedResultInstallHooks{beforePublish: func() error {
				prepared <- struct{}{}
				<-release
				return nil
			}})
			outcomes <- outcome{retained: retained, err: err}
		}()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-prepared:
		case result := <-outcomes:
			t.Fatalf("publisher failed before both candidates were prepared: %+v", result)
		}
	}
	releasePublishers()
	workers.Wait()
	close(outcomes)

	successes := 0
	for outcome := range outcomes {
		if outcome.err == nil {
			if !outcome.retained {
				t.Fatal("concurrent publisher reported success without retained result")
			}
			successes++
		} else if outcome.retained {
			t.Fatalf("concurrent publisher reported both retention and error: %v", outcome.err)
		}
	}
	if successes == 0 {
		t.Fatal("no concurrent publisher completed the result")
	}
	if bundle, resultErr := service.Result(context.Background(), locator.RunID); resultErr != nil || len(bundle.Payload) == 0 {
		t.Fatalf("concurrent winner left no authenticated public result: bundle=%q err=%+v", bundle.Payload, resultErr)
	}
	info, err := os.Lstat(service.retainedResultBundlePath(locator))
	if err != nil {
		t.Fatalf("stat published result: %v", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != retainedResultBundleFileMode {
		t.Fatal("concurrent publication did not leave one valid final bundle")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Nlink != 1 {
		t.Fatal("concurrent publication left an invalid final link count")
	}
	entries, err := os.ReadDir(service.retainedResultRunDir(locator))
	if err != nil {
		t.Fatalf("read retained result directory: %v", err)
	}
	losers := 0
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".result-") {
			losers++
			loserInfo, err := os.Lstat(filepath.Join(service.retainedResultRunDir(locator), entry.Name()))
			if err != nil || !loserInfo.Mode().IsRegular() || loserInfo.Mode().Perm() != retainedResultBundleFileMode {
				t.Fatalf("retained loser temporary has invalid metadata: info=%v err=%v", loserInfo, err)
			}
		}
	}
	if losers != 1 {
		t.Fatalf("retained loser temporaries = %d, want 1", losers)
	}
}

func TestRetainedResultPublicationValidatesExistingFinal(t *testing.T) {
	tests := []struct {
		name        string
		prepare     func(t *testing.T, fixture *retainedResultPublicationFixture)
		wantError   bool
		wantPublish bool
	}{
		{
			name: "exact idempotent existing winner",
			prepare: func(t *testing.T, fixture *retainedResultPublicationFixture) {
				fixture.writeFinal(t, fixture.payload, retainedResultBundleFileMode)
			},
		},
		{
			name: "existing invalid final digest",
			prepare: func(t *testing.T, fixture *retainedResultPublicationFixture) {
				invalid := bytes.Repeat([]byte{'x'}, len(fixture.payload))
				fixture.writeFinal(t, invalid, retainedResultBundleFileMode)
			},
			wantError: true,
		},
		{
			name: "existing wrong mode",
			prepare: func(t *testing.T, fixture *retainedResultPublicationFixture) {
				fixture.writeFinal(t, fixture.payload, 0o640)
			},
			wantError: true,
		},
		{
			name: "existing wrong link count",
			prepare: func(t *testing.T, fixture *retainedResultPublicationFixture) {
				fixture.writeFinal(t, fixture.payload, retainedResultBundleFileMode)
				if err := os.Link(fixture.finalPath, filepath.Join(fixture.runPath, "second-link")); err != nil {
					t.Fatalf("create existing-final hard link: %v", err)
				}
			},
			wantError: true,
		},
		{
			name: "existing wrong owner policy",
			prepare: func(t *testing.T, fixture *retainedResultPublicationFixture) {
				fixture.writeFinal(t, fixture.payload, retainedResultBundleFileMode)
				fixture.directory.owner.UID++
			},
			wantError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRetainedResultPublicationFixture(t)
			test.prepare(t, fixture)
			published, err := fixture.directory.publishTemporaryBundle(
				fixture.tempName,
				fixture.fingerprint,
				fixture.tempFile,
				retainedResultInstallHooks{},
			)
			if test.wantError {
				if err == nil || published {
					t.Fatal("invalid existing final did not fail closed")
				}
				return
			}
			if err != nil || published != test.wantPublish {
				t.Fatalf("exact existing winner was not idempotent: published=%v err=%v", published, err)
			}
		})
	}
}

func TestRetainedResultPublicationFaultsBeforeCommitAndDuringValidation(t *testing.T) {
	t.Run("winner failure before publication", func(t *testing.T) {
		fixture := newRetainedResultPublicationFixture(t)
		injected := errors.New("injected publication failure")
		published, err := fixture.directory.publishTemporaryBundle(
			fixture.tempName,
			fixture.fingerprint,
			fixture.tempFile,
			retainedResultInstallHooks{beforePublish: func() error { return injected }},
		)
		if !errors.Is(err, injected) || published {
			t.Fatal("pre-publication failure did not fail closed")
		}
		if _, err := os.Stat(fixture.finalPath); !os.IsNotExist(err) {
			t.Fatal("pre-publication failure created a final object")
		}
		if _, err := os.Stat(filepath.Join(fixture.runPath, fixture.tempName)); err != nil {
			t.Fatal("pre-publication failure removed the complete temporary object")
		}
	})

	t.Run("final replacement during validation", func(t *testing.T) {
		fixture := newRetainedResultPublicationFixture(t)
		fixture.writeFinal(t, fixture.payload, retainedResultBundleFileMode)
		displaced := filepath.Join(fixture.runPath, "displaced-final")
		var hookErr error
		published, err := fixture.directory.publishTemporaryBundle(
			fixture.tempName,
			fixture.fingerprint,
			fixture.tempFile,
			retainedResultInstallHooks{afterExistingOpen: func() {
				hookErr = os.Rename(fixture.finalPath, displaced)
				if hookErr == nil {
					hookErr = os.WriteFile(fixture.finalPath, fixture.payload, retainedResultBundleFileMode)
				}
			}},
		)
		if hookErr != nil {
			t.Fatalf("prepare final replacement: %v", hookErr)
		}
		if err == nil || published {
			t.Fatal("final replacement during validation did not fail closed")
		}
	})
}

func TestResultPublicationConflictRetainsStageRoot(t *testing.T) {
	service, locator, _ := newResultTestService(t)
	custody, layout := claimTestStagingCustody(t, service.cfg.Execution.StagingRootDir, locator.RunID)
	if err := custody.ensureDirectory(executionRunStageDirName+"/"+executionResultStageDirName, stableStageDirMode); err != nil {
		t.Fatalf("create staged result directory: %v", err)
	}
	if err := custody.writeFile(executionRunStageDirName+"/"+executionResultStageDirName+"/summary.txt", []byte("ok\n"), stableStageFileMode); err != nil {
		t.Fatalf("write staged result: %v", err)
	}
	if err := custody.close(); err != nil {
		t.Fatalf("close initial custody: %v", err)
	}
	writeRetainedResultBundleBytes(t, service, locator, []byte("invalid final"))

	service.maybeRetainTerminalResult(locator, terminalSuccessAllocation())

	if _, err := os.Stat(layout.stageRootDir); err != nil {
		t.Fatal("invalid existing final changed retained staging")
	}
}

func TestResolvedPlanCustodyRepairCleanupRetainsDisplacedResultTemporary(t *testing.T) {
	for _, replacementKind := range []string{"regular", "symlink"} {
		t.Run(replacementKind, func(t *testing.T) {
			service, locator, _ := newResultTestService(t)
			custody, layout := claimTestStagingCustody(t, service.cfg.Execution.StagingRootDir, locator.RunID)
			if err := custody.writeFile("run/result/summary.txt", []byte("owned result"), stableStageFileMode); err != nil {
				t.Fatal(err)
			}
			if err := custody.close(); err != nil {
				t.Fatal(err)
			}
			runPath := service.retainedResultRunDir(locator)
			injected := errors.New("injected publication fault")
			var replacementPath string
			var replacementBefore os.FileInfo
			retained, err := service.retainTerminalResultWithHooks(locator, retainedResultInstallHooks{beforePublish: func() error {
				entries, err := os.ReadDir(runPath)
				if err != nil {
					return err
				}
				for _, entry := range entries {
					if strings.HasPrefix(entry.Name(), ".result-") {
						replacementPath = filepath.Join(runPath, entry.Name())
						break
					}
				}
				if replacementPath == "" {
					return errors.New("result temporary was not created")
				}
				if err := os.Rename(replacementPath, replacementPath+"-displaced"); err != nil {
					return err
				}
				if replacementKind == "regular" {
					if err := os.WriteFile(replacementPath, []byte("replacement"), 0o600); err != nil {
						return err
					}
				} else if err := os.Symlink(filepath.Base(replacementPath)+"-displaced", replacementPath); err != nil {
					return err
				}
				replacementBefore, err = os.Lstat(replacementPath)
				if err != nil {
					return err
				}
				return injected
			}})
			if retained || !errors.Is(err, injected) {
				t.Fatalf("primary publication fault was hidden: retained=%v err=%v", retained, err)
			}
			after, err := os.Lstat(replacementPath)
			if err != nil || !os.SameFile(replacementBefore, after) || replacementBefore.Mode() != after.Mode() {
				t.Fatalf("replacement temporary changed: before=%v after=%v err=%v", replacementBefore, after, err)
			}
			if replacementKind == "regular" {
				assertFileContent(t, replacementPath, "replacement")
			} else if target, err := os.Readlink(replacementPath); err != nil || target != filepath.Base(replacementPath)+"-displaced" {
				t.Fatalf("replacement symlink changed: target=%q err=%v", target, err)
			}
			if _, err := os.Lstat(layout.stageRootDir); err != nil {
				t.Fatalf("claimed root was removed: %v", err)
			}
			if _, err := os.Lstat(replacementPath + "-displaced"); err != nil {
				t.Fatalf("displaced owned temporary was removed: %v", err)
			}
		})
	}
}

func TestResolvedPlanCustodyRepairPublicationRejectsSubstitutedWinnerBeforePublicRead(t *testing.T) {
	service, locator, _ := newResultTestService(t)
	custody, _ := claimTestStagingCustody(t, service.cfg.Execution.StagingRootDir, locator.RunID)
	if err := custody.writeFile("run/result/summary.txt", []byte("validated result"), stableStageFileMode); err != nil {
		t.Fatal(err)
	}
	if err := custody.close(); err != nil {
		t.Fatal(err)
	}
	runPath := service.retainedResultRunDir(locator)
	var legitimate []byte
	var substituted []byte
	var substituteIdentity os.FileInfo
	retained, err := service.retainTerminalResultWithHooks(locator, retainedResultInstallHooks{beforePublish: func() error {
		entries, err := os.ReadDir(runPath)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), ".result-") {
				continue
			}
			tempPath := filepath.Join(runPath, entry.Name())
			original, err := os.ReadFile(tempPath)
			if err != nil {
				return err
			}
			if len(original) == 0 {
				return errors.New("candidate bundle was empty")
			}
			legitimate = bytes.Clone(original)
			substituted = bytes.Clone(original)
			substituted[len(substituted)-1] ^= 0x01
			if err := os.Rename(tempPath, tempPath+"-validated-displaced"); err != nil {
				return err
			}
			if err := os.WriteFile(tempPath, substituted, retainedResultBundleFileMode); err != nil {
				return err
			}
			substituteIdentity, err = os.Lstat(tempPath)
			return err
		}
		return errors.New("candidate temporary was not found")
	}})
	if len(legitimate) == 0 || len(substituted) == 0 || substituteIdentity == nil {
		t.Fatalf("counterexample fixture was not installed: retained=%v err=%v", retained, err)
	}
	_, statErr := os.Lstat(service.retainedResultBundlePath(locator))
	if statErr != nil && !os.IsNotExist(statErr) {
		t.Fatalf("inspect final after injection: %v", statErr)
	}
	bundle, readErr := service.Result(context.Background(), locator.RunID)
	if readErr == nil {
		if !bytes.Equal(bundle.Payload, legitimate) || bytes.Equal(bundle.Payload, substituted) {
			t.Fatal("successful public result contained bytes other than the writer's candidate")
		}
	} else if len(bundle.Payload) != 0 || readErr.Status != http.StatusConflict || readErr.Code != codeResultUnavailable {
		t.Fatalf("failed public result was not an honest unavailable response: payload=%q err=%+v", bundle.Payload, readErr)
	}
}

func TestRetainedResultAuthReaderWaitsForCommittedPublication(t *testing.T) {
	service, locator, _ := newResultTestService(t)
	custody, _ := claimTestStagingCustody(t, service.cfg.Execution.StagingRootDir, locator.RunID)
	if err := custody.writeFile("run/result/summary.txt", []byte("validated result"), stableStageFileMode); err != nil {
		t.Fatal(err)
	}
	if err := custody.close(); err != nil {
		t.Fatal(err)
	}
	installed := make(chan struct{})
	release := make(chan struct{})
	publication := make(chan error, 1)
	go func() {
		_, err := service.retainTerminalResultWithHooks(locator, retainedResultInstallHooks{afterFinalInstall: func() error {
			close(installed)
			<-release
			return nil
		}})
		publication <- err
	}()
	<-installed
	bundle, readErr := service.Result(context.Background(), locator.RunID)
	if readErr == nil || readErr.Status != http.StatusConflict || readErr.Code != codeResultUnavailable || len(bundle.Payload) != 0 {
		t.Fatalf("reader served final before authenticated record: bundle=%q err=%+v", bundle.Payload, readErr)
	}
	close(release)
	if err := <-publication; err != nil {
		t.Fatalf("complete publication: %v", err)
	}
	bundle, readErr = service.Result(context.Background(), locator.RunID)
	if readErr != nil || len(bundle.Payload) == 0 {
		t.Fatalf("completed publication was unavailable: bundle=%q err=%+v", bundle.Payload, readErr)
	}
}

func TestRetainedResultAuthPublisherErrorsAfterInstallAndCommit(t *testing.T) {
	for _, test := range []struct {
		name          string
		hooks         retainedResultInstallHooks
		wantAvailable bool
	}{
		{"after final before record", retainedResultInstallHooks{afterFinalInstall: func() error { return errors.New("synthetic after-install error") }}, false},
		{"after committed record", retainedResultInstallHooks{afterRecordPublish: func() error { return errors.New("synthetic after-commit error") }}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, locator, _ := newResultTestService(t)
			custody, _ := claimTestStagingCustody(t, service.cfg.Execution.StagingRootDir, locator.RunID)
			if err := custody.writeFile("run/result/summary.txt", []byte("validated result"), stableStageFileMode); err != nil {
				t.Fatal(err)
			}
			if err := custody.close(); err != nil {
				t.Fatal(err)
			}
			if retained, err := service.retainTerminalResultWithHooks(locator, test.hooks); err == nil || retained {
				t.Fatalf("synthetic publisher error not surfaced: retained=%t err=%v", retained, err)
			}
			bundle, readErr := service.Result(context.Background(), locator.RunID)
			if test.wantAvailable {
				if readErr != nil || len(bundle.Payload) == 0 {
					t.Fatalf("committed bytes unavailable after publisher error: bundle=%q err=%+v", bundle.Payload, readErr)
				}
			} else if readErr == nil || readErr.Status != http.StatusConflict || len(bundle.Payload) != 0 {
				t.Fatalf("uncommitted final served after publisher error: bundle=%q err=%+v", bundle.Payload, readErr)
			}
		})
	}
}

func TestRetainedResultAuthRefusesTemporaryInterference(t *testing.T) {
	for _, kind := range []string{"disappearance", "replacement", "in-place mutation"} {
		t.Run(kind, func(t *testing.T) {
			service, locator, _ := newResultTestService(t)
			custody, _ := claimTestStagingCustody(t, service.cfg.Execution.StagingRootDir, locator.RunID)
			if err := custody.writeFile("run/result/summary.txt", []byte("legitimate"), stableStageFileMode); err != nil {
				t.Fatal(err)
			}
			if err := custody.close(); err != nil {
				t.Fatal(err)
			}
			injected := false
			retained, err := service.retainTerminalResultWithHooks(locator, retainedResultInstallHooks{beforePublish: func() error {
				entries, err := os.ReadDir(service.retainedResultRunDir(locator))
				if err != nil {
					return err
				}
				for _, entry := range entries {
					if !strings.HasPrefix(entry.Name(), ".result-") {
						continue
					}
					path := filepath.Join(service.retainedResultRunDir(locator), entry.Name())
					injected = true
					switch kind {
					case "disappearance":
						return os.Remove(path)
					case "replacement":
						original, err := os.ReadFile(path)
						if err != nil {
							return err
						}
						original[len(original)-1] ^= 1
						if err := os.Rename(path, path+".displaced"); err != nil {
							return err
						}
						return os.WriteFile(path, original, retainedResultBundleFileMode)
					case "in-place mutation":
						file, err := os.OpenFile(path, os.O_WRONLY, 0)
						if err != nil {
							return err
						}
						_, writeErr := file.WriteAt([]byte{0xff}, 0)
						return errors.Join(writeErr, file.Close())
					}
				}
				return errors.New("candidate temporary was not found")
			}})
			if !injected || err == nil || retained {
				t.Fatalf("temporary interference was not refused: injected=%t retained=%t err=%v", injected, retained, err)
			}
			bundle, readErr := service.Result(context.Background(), locator.RunID)
			if readErr == nil || len(bundle.Payload) != 0 {
				t.Fatalf("temporary interference produced a successful result: bundle=%q err=%+v", bundle.Payload, readErr)
			}
		})
	}
}

func TestRetainedResultAuthFinalInterferenceBeforeAndAfterRecord(t *testing.T) {
	for _, test := range []struct {
		name         string
		beforeRecord bool
		replace      bool
	}{
		{"mutation before record", true, false},
		{"replacement before record", true, true},
		{"mutation after record", false, false},
		{"replacement after record", false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, locator, _ := newResultTestService(t)
			custody, _ := claimTestStagingCustody(t, service.cfg.Execution.StagingRootDir, locator.RunID)
			if err := custody.writeFile("run/result/summary.txt", []byte("legitimate"), stableStageFileMode); err != nil {
				t.Fatal(err)
			}
			if err := custody.close(); err != nil {
				t.Fatal(err)
			}
			mutated := false
			mutate := func() error {
				path := service.retainedResultBundlePath(locator)
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				if test.replace {
					if err := os.Rename(path, path+".displaced"); err != nil {
						return err
					}
					if err := os.WriteFile(path, data, retainedResultBundleFileMode); err != nil {
						return err
					}
				} else {
					data[len(data)-1] ^= 1
					if err := os.WriteFile(path, data, retainedResultBundleFileMode); err != nil {
						return err
					}
				}
				mutated = true
				return nil
			}
			hooks := retainedResultInstallHooks{}
			if test.beforeRecord {
				hooks.afterFinalInstall = mutate
			} else {
				hooks.afterRecordPublish = mutate
			}
			retained, err := service.retainTerminalResultWithHooks(locator, hooks)
			if !mutated {
				t.Fatalf("final interference did not execute: retained=%t err=%v", retained, err)
			}
			if test.beforeRecord && (err == nil || retained) {
				t.Fatalf("publisher committed changed final: retained=%t err=%v", retained, err)
			}
			bundle, readErr := service.Result(context.Background(), locator.RunID)
			if readErr == nil || readErr.Status != http.StatusConflict || readErr.Code != codeResultUnavailable || len(bundle.Payload) != 0 {
				t.Fatalf("changed final was served: bundle=%q err=%+v", bundle.Payload, readErr)
			}
		})
	}
}

func TestRetainedResultAuthPublisherErrorWhilePublicReaderExecutes(t *testing.T) {
	service, locator, _ := newResultTestService(t)
	custody, _ := claimTestStagingCustody(t, service.cfg.Execution.StagingRootDir, locator.RunID)
	if err := custody.writeFile("run/result/summary.txt", []byte("legitimate"), stableStageFileMode); err != nil {
		t.Fatal(err)
	}
	if err := custody.close(); err != nil {
		t.Fatal(err)
	}
	committed := make(chan struct{})
	release := make(chan struct{})
	injected := errors.New("synthetic error after completed record")
	publication := make(chan error, 1)
	go func() {
		_, err := service.retainTerminalResultWithHooks(locator, retainedResultInstallHooks{afterRecordPublish: func() error {
			close(committed)
			<-release
			return injected
		}})
		publication <- err
	}()
	<-committed
	bundle, readErr := service.Result(context.Background(), locator.RunID)
	if readErr != nil || len(bundle.Payload) == 0 {
		t.Fatalf("completed pair unavailable during publisher error interval: bundle=%q err=%+v", bundle.Payload, readErr)
	}
	close(release)
	if err := <-publication; !errors.Is(err, injected) {
		t.Fatalf("publisher error was lost: %v", err)
	}
}

func TestRetainedResultAuthConflictingPublisherDoesNotOverwrite(t *testing.T) {
	service, locator, _ := newResultTestService(t)
	custody, _ := claimTestStagingCustody(t, service.cfg.Execution.StagingRootDir, locator.RunID)
	if err := custody.writeFile("run/result/summary.txt", []byte("first"), stableStageFileMode); err != nil {
		t.Fatal(err)
	}
	if err := custody.close(); err != nil {
		t.Fatal(err)
	}
	firstPrepared := make(chan struct{})
	secondPrepared := make(chan struct{})
	firstRelease := make(chan struct{})
	secondRelease := make(chan struct{})
	var firstReleaseOnce, secondReleaseOnce sync.Once
	releaseFirst := func() { firstReleaseOnce.Do(func() { close(firstRelease) }) }
	releaseSecond := func() { secondReleaseOnce.Do(func() { close(secondRelease) }) }
	defer releaseFirst()
	defer releaseSecond()
	type publishOutcome struct {
		retained bool
		err      error
	}
	firstOutcome := make(chan publishOutcome, 1)
	go func() {
		retained, err := service.retainTerminalResultWithHooks(locator, retainedResultInstallHooks{beforePublish: func() error {
			close(firstPrepared)
			<-firstRelease
			return nil
		}})
		firstOutcome <- publishOutcome{retained, err}
	}()
	select {
	case <-firstPrepared:
	case outcome := <-firstOutcome:
		t.Fatalf("first publisher failed before candidate preparation: %+v", outcome)
	}
	stagePath := filepath.Join(service.cfg.Execution.StagingRootDir, locator.RunID, "run", "result", "summary.txt")
	if err := os.WriteFile(stagePath, []byte("other"), stableStageFileMode); err != nil {
		t.Fatal(err)
	}
	secondOutcome := make(chan publishOutcome, 1)
	go func() {
		retained, err := service.retainTerminalResultWithHooks(locator, retainedResultInstallHooks{beforePublish: func() error {
			close(secondPrepared)
			<-secondRelease
			return nil
		}})
		secondOutcome <- publishOutcome{retained, err}
	}()
	select {
	case <-secondPrepared:
	case outcome := <-secondOutcome:
		t.Fatalf("second publisher failed before candidate preparation: %+v", outcome)
	}
	releaseFirst()
	if outcome := <-firstOutcome; outcome.err != nil || !outcome.retained {
		t.Fatalf("first prepared candidate failed: %+v", outcome)
	}
	beforeFinal, err := os.ReadFile(service.retainedResultBundlePath(locator))
	if err != nil {
		t.Fatal(err)
	}
	beforeRecord, err := os.ReadFile(filepath.Join(service.retainedResultRunDir(locator), retainedResultRecordFileName))
	if err != nil {
		t.Fatal(err)
	}
	releaseSecond()
	if outcome := <-secondOutcome; outcome.err == nil || outcome.retained {
		t.Fatalf("conflicting prepared publisher reported a win: %+v", outcome)
	}
	afterFinal, err := os.ReadFile(service.retainedResultBundlePath(locator))
	if err != nil || !bytes.Equal(afterFinal, beforeFinal) {
		t.Fatalf("conflicting publisher changed final: err=%v", err)
	}
	afterRecord, err := os.ReadFile(filepath.Join(service.retainedResultRunDir(locator), retainedResultRecordFileName))
	if err != nil || !bytes.Equal(afterRecord, beforeRecord) {
		t.Fatalf("conflicting publisher changed record: err=%v", err)
	}
	if bundle, resultErr := service.Result(context.Background(), locator.RunID); resultErr != nil || !bytes.Equal(bundle.Payload, beforeFinal) {
		t.Fatalf("winner's committed bytes unavailable: err=%+v", resultErr)
	}
}

type retainedResultReviewObject struct {
	mode   os.FileMode
	size   int64
	device uint64
	inode  uint64
	digest [sha256.Size]byte
}

func retainedResultReviewInventory(t *testing.T, path string) map[string]retainedResultReviewObject {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	inventory := make(map[string]retainedResultReviewObject, len(entries))
	for _, entry := range entries {
		objectPath := filepath.Join(path, entry.Name())
		info, err := os.Lstat(objectPath)
		if err != nil {
			t.Fatal(err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			t.Fatalf("missing stat identity for %s", entry.Name())
		}
		var digest [sha256.Size]byte
		if info.Mode().IsRegular() {
			payload, err := os.ReadFile(objectPath)
			if err != nil {
				t.Fatal(err)
			}
			digest = sha256.Sum256(payload)
		}
		inventory[entry.Name()] = retainedResultReviewObject{info.Mode(), info.Size(), uint64(stat.Dev), uint64(stat.Ino), digest}
	}
	return inventory
}

func TestRetainedResultReviewRepeatedTerminalObservationsReuseAuthenticatedPair(t *testing.T) {
	service, locator, _ := newResultTestService(t)
	custody, _ := claimTestStagingCustody(t, service.cfg.Execution.StagingRootDir, locator.RunID)
	if err := custody.writeFile("run/result/summary.txt", []byte("first"), stableStageFileMode); err != nil {
		t.Fatal(err)
	}
	if err := custody.close(); err != nil {
		t.Fatal(err)
	}
	service.nomadClient = newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/job/exec-run-0123456789abcdef":
			_, _ = w.Write([]byte(`{"ID":"exec-run-0123456789abcdef","Status":"dead"}`))
		case "/v1/job/exec-run-0123456789abcdef/allocations":
			_, _ = w.Write([]byte(`[{"ID":"alloc-1","ModifyIndex":1}]`))
		case "/v1/allocation/alloc-1":
			_, _ = w.Write([]byte(`{"ID":"alloc-1","ClientStatus":"complete","TaskStates":{"task":{"State":"dead","Events":[{"Type":"Terminated","ExitCode":0}]}}}`))
		case "/v1/client/fs/logs/alloc-1":
			_, _ = w.Write([]byte("synthetic logs\n"))
		default:
			t.Errorf("unexpected Nomad path %q", r.URL.Path)
		}
	}))
	if status, err := service.Status(context.Background(), locator.RunID); err != nil || !status.Terminal {
		t.Fatalf("initial terminal status: status=%+v err=%+v", status, err)
	}
	initial, resultErr := service.Result(context.Background(), locator.RunID)
	if resultErr != nil || readAdmissionResultBundleEntries(t, initial.Payload)["summary.txt"] != "first" {
		t.Fatalf("initial retained result: err=%+v", resultErr)
	}
	runPath := service.retainedResultRunDir(locator)
	baseline := retainedResultReviewInventory(t, runPath)
	if len(baseline) != 2 {
		t.Fatalf("unexpected initial result inventory: %v", baseline)
	}
	stagePath := filepath.Join(service.cfg.Execution.StagingRootDir, locator.RunID, "run", "result", "summary.txt")
	if err := os.WriteFile(stagePath, []byte("changed"), stableStageFileMode); err != nil {
		t.Fatal(err)
	}
	for phase := 0; phase < 2; phase++ {
		if phase == 1 {
			stageRun := filepath.Join(service.cfg.Execution.StagingRootDir, locator.RunID)
			if err := os.Rename(stageRun, filepath.Join(physicalTestTempDir(t), "moved-run")); err != nil {
				t.Fatal(err)
			}
		}
		for observation := 0; observation < 2; observation++ {
			if status, err := service.Status(context.Background(), locator.RunID); err != nil || !status.Terminal {
				t.Fatalf("repeat status: status=%+v err=%+v", status, err)
			}
			if logs, err := service.Logs(context.Background(), locator.RunID); err != nil || string(logs.Payload) != "synthetic logs\n" {
				t.Fatalf("repeat logs: logs=%q err=%+v", logs.Payload, err)
			}
			if retained, err := service.retainTerminalResult(locator); err != nil || !retained {
				t.Fatalf("repeat retention: retained=%t err=%v", retained, err)
			}
			bundle, err := service.Result(context.Background(), locator.RunID)
			if err != nil || !bytes.Equal(bundle.Payload, initial.Payload) {
				t.Fatalf("repeat result changed selected bytes: err=%+v", err)
			}
			if got := retainedResultReviewInventory(t, runPath); !reflect.DeepEqual(got, baseline) {
				t.Fatalf("repeat terminal observation changed result inventory: got=%v want=%v", got, baseline)
			}
		}
	}
}

func TestRetainedResultReviewInvalidExistingPairCannotRepublish(t *testing.T) {
	for _, damage := range []string{"partial", "invalid"} {
		t.Run(damage, func(t *testing.T) {
			service, locator, _ := newResultTestService(t)
			custody, _ := claimTestStagingCustody(t, service.cfg.Execution.StagingRootDir, locator.RunID)
			if err := custody.writeFile("run/result/summary.txt", []byte("new staged bytes"), stableStageFileMode); err != nil {
				t.Fatal(err)
			}
			if err := custody.close(); err != nil {
				t.Fatal(err)
			}
			writeRetainedResultBundleBytes(t, service, locator, []byte("previous committed bytes"))
			recordPath := filepath.Join(service.retainedResultRunDir(locator), retainedResultRecordFileName)
			if damage == "partial" {
				if err := os.Remove(recordPath); err != nil {
					t.Fatal(err)
				}
			} else {
				data, err := os.ReadFile(recordPath)
				if err != nil {
					t.Fatal(err)
				}
				data[len(data)-2] ^= 1
				if err := os.WriteFile(recordPath, data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			baseline := retainedResultReviewInventory(t, service.retainedResultRunDir(locator))
			if retained, err := service.retainTerminalResult(locator); err == nil || retained {
				t.Fatalf("damaged pair was republished: retained=%t err=%v", retained, err)
			}
			if got := retainedResultReviewInventory(t, service.retainedResultRunDir(locator)); !reflect.DeepEqual(got, baseline) {
				t.Fatalf("damaged pair triggered new result objects: got=%v want=%v", got, baseline)
			}
		})
	}
}

func TestResolvedPlanCustodyRepairCleanupRetainsDisplacedNormalizationEvidence(t *testing.T) {
	for _, replacementKind := range []string{"regular", "symlink"} {
		t.Run(replacementKind, func(t *testing.T) {
			root := physicalTestTempDir(t)
			runID := "run-0123456789abcdef"
			owner := executionPlatformStateOwner{UID: os.Getuid(), GID: os.Getgid()}
			directory, exists, err := openRetainedResultDirectory(root, runID, owner, true)
			if err != nil || !exists {
				t.Fatalf("open result directory: exists=%v err=%v", exists, err)
			}
			t.Cleanup(func() { _ = directory.close() })
			marker := validOwnershipNormalizationMarker(runID)
			markerBytes, err := json.Marshal(marker)
			if err != nil {
				t.Fatal(err)
			}
			markerBytes = append(markerBytes, '\n')
			markerPath := filepath.Join(root, runID, ownershipNormalizationMarkerName)
			injected := errors.New("injected marker fault")
			var replacementBefore os.FileInfo
			err = directory.ensureNormalizationEvidenceWithHook(&marker, markerBytes, ownershipExpectationsForRun(runID, owner, false), func() error {
				if err := os.Rename(markerPath, markerPath+"-displaced"); err != nil {
					return err
				}
				if replacementKind == "regular" {
					if err := os.WriteFile(markerPath, []byte("replacement"), 0o600); err != nil {
						return err
					}
				} else if err := os.Symlink(filepath.Base(markerPath)+"-displaced", markerPath); err != nil {
					return err
				}
				var err error
				replacementBefore, err = os.Lstat(markerPath)
				if err != nil {
					return err
				}
				return injected
			})
			if !errors.Is(err, injected) {
				t.Fatalf("primary marker fault was hidden: %v", err)
			}
			after, err := os.Lstat(markerPath)
			if err != nil || !os.SameFile(replacementBefore, after) || replacementBefore.Mode() != after.Mode() {
				t.Fatalf("replacement marker changed: before=%v after=%v err=%v", replacementBefore, after, err)
			}
			if replacementKind == "regular" {
				assertFileContent(t, markerPath, "replacement")
			} else if target, err := os.Readlink(markerPath); err != nil || target != filepath.Base(markerPath)+"-displaced" {
				t.Fatalf("replacement marker symlink changed: target=%q err=%v", target, err)
			}
			if _, err := os.Lstat(markerPath + "-displaced"); err != nil {
				t.Fatalf("displaced owned marker was removed: %v", err)
			}
		})
	}
}

type retainedResultPublicationFixture struct {
	directory   *retainedResultDirectory
	tempFile    *os.File
	runPath     string
	finalPath   string
	tempName    string
	payload     []byte
	fingerprint retainedResultFingerprint
}

func newRetainedResultPublicationFixture(t *testing.T) *retainedResultPublicationFixture {
	t.Helper()
	root := physicalTestTempDir(t)
	runID := "run-0123456789abcdef"
	owner := executionPlatformStateOwner{UID: os.Getuid(), GID: os.Getgid()}
	directory, exists, err := openRetainedResultDirectory(root, runID, owner, true)
	if err != nil || !exists {
		t.Fatalf("open retained result publication fixture: exists=%v err=%v", exists, err)
	}
	t.Cleanup(func() { _ = directory.close() })
	tempName, file, err := directory.createTempFile()
	if err != nil {
		t.Fatalf("create publication candidate: %v", err)
	}
	payload := []byte("complete candidate\n")
	if _, err := file.Write(payload); err != nil {
		t.Fatalf("write publication candidate: %v", err)
	}
	if err := file.Sync(); err != nil {
		t.Fatalf("sync publication candidate: %v", err)
	}
	fingerprint, err := directory.fingerprintTemporaryFile(tempName, file)
	if err != nil {
		t.Fatalf("fingerprint publication candidate: %v", err)
	}
	t.Cleanup(func() { _ = file.Close() })
	runPath := filepath.Join(root, runID)
	return &retainedResultPublicationFixture{
		directory:   directory,
		tempFile:    file,
		runPath:     runPath,
		finalPath:   filepath.Join(runPath, resultBundleFileName),
		tempName:    tempName,
		payload:     payload,
		fingerprint: fingerprint,
	}
}

func (fixture *retainedResultPublicationFixture) writeFinal(t *testing.T, payload []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(fixture.finalPath, payload, mode); err != nil {
		t.Fatalf("write existing final: %v", err)
	}
	if err := os.Chmod(fixture.finalPath, mode); err != nil {
		t.Fatalf("set existing-final mode: %v", err)
	}
}

func TestResultBundleEntryNameRejectsPathTraversal(t *testing.T) {
	root := filepath.Join(t.TempDir(), "result")
	outside := filepath.Join(filepath.Dir(root), "escape.txt")

	_, err := resultBundleEntryName(root, outside)
	if err == nil || !strings.Contains(err.Error(), "escapes result directory") {
		t.Fatalf("expected path traversal rejection, got %v", err)
	}
}

func TestRetainedResultCustodyRefusesConfiguredRootReplacementBeforeRead(t *testing.T) {
	parent := physicalTestTempDir(t)
	resultsRoot := filepath.Join(parent, "results")
	runID := "run-0123456789abcdef"
	if err := os.MkdirAll(filepath.Join(resultsRoot, runID), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(resultsRoot, runID), retainedResultRunDirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(resultsRoot, runID, resultBundleFileName), []byte("retained"), 0o600); err != nil {
		t.Fatal(err)
	}
	owner, err := executionPlatformStateOwnerFromPath(resultsRoot)
	if err != nil {
		t.Fatal(err)
	}
	directory, exists, err := openRetainedResultDirectory(resultsRoot, runID, owner, false)
	if err != nil || !exists {
		t.Fatalf("open retained result custody: exists=%v err=%v", exists, err)
	}
	defer directory.close()
	displaced := filepath.Join(parent, "results-displaced")
	if err := os.Rename(resultsRoot, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(resultsRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if payload, _, err := directory.readRegularFile(resultBundleFileName); err == nil {
		t.Fatalf("retained-result read accepted replaced configured root: %q", payload)
	}
	if entries, err := os.ReadDir(resultsRoot); err != nil || len(entries) != 0 {
		t.Fatalf("replacement results root was changed: entries=%v err=%v", entries, err)
	}
}

func TestResultReturnsRetainedBundleWithoutRuntimeLookup(t *testing.T) {
	service, locator, _ := newResultTestService(t)
	writeRetainedResultBundleBytes(t, service, locator, []byte("already retained"))

	bundle, err := service.Result(context.Background(), locator.RunID)
	if err != nil {
		t.Fatalf("result should not require runtime when bundle exists: %+v", err)
	}
	if bundle.MediaType != resultBundleMediaType || string(bundle.Payload) != "already retained" {
		t.Fatalf("unexpected retained bundle: %+v", bundle)
	}
	if bundle.OutcomeEvidence.Source != outcomeEvidenceSourceRetainedResultStore ||
		bundle.OutcomeEvidence.Observation != outcomeObservationRetainedResultBundle ||
		bundle.OutcomeEvidence.AccessClass != outcomeAccessClassOpaqueResultBundle {
		t.Fatalf("unexpected retained result outcome evidence %+v", bundle.OutcomeEvidence)
	}
}

func TestResolvedPlanCustodyRepairResultReadRejectsExistingModeWithoutMutation(t *testing.T) {
	service, locator, _ := newResultTestService(t)
	writeRetainedResultBundleBytes(t, service, locator, []byte("existing opaque result"))
	runPath := service.retainedResultRunDir(locator)
	if err := os.Chmod(runPath, 0o755); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(runPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeChange := resultMetadataChangeTime(t, before)
	if _, resultErr := service.Result(context.Background(), locator.RunID); resultErr == nil {
		t.Fatal("existing directory with wrong mode was accepted")
	}
	after, err := os.Lstat(runPath)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode().Perm() != 0o755 || !os.SameFile(before, after) || resultMetadataChangeTime(t, after) != beforeChange {
		t.Fatal("existing result directory was changed during rejected read")
	}
}

func TestResolvedPlanCustodyRepairResultReadValidRepeatHasNoMetadataWrite(t *testing.T) {
	service, locator, _ := newResultTestService(t)
	writeRetainedResultBundleBytes(t, service, locator, []byte("existing opaque result"))
	runPath := service.retainedResultRunDir(locator)
	if err := os.Chmod(runPath, retainedResultRunDirMode); err != nil {
		t.Fatal(err)
	}
	writeOwnershipNormalizationMarker(t, runPath, validOwnershipNormalizationMarker(locator.RunID), retainedNormalizationEvidenceFileMode)
	if err := os.Chmod(runPath, retainedResultRunDirMode); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(runPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeChange := resultMetadataChangeTime(t, before)
	markerPath := filepath.Join(runPath, ownershipNormalizationMarkerName)
	markerBefore, err := os.Lstat(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	markerBeforeChange := resultMetadataChangeTime(t, markerBefore)
	for attempt := 0; attempt < 2; attempt++ {
		bundle, resultErr := service.Result(context.Background(), locator.RunID)
		if resultErr != nil || string(bundle.Payload) != "existing opaque result" {
			t.Fatalf("read %d: bundle=%q err=%v", attempt+1, bundle.Payload, resultErr)
		}
	}
	after, err := os.Lstat(runPath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || resultMetadataChangeTime(t, after) != beforeChange {
		t.Fatal("valid repeat read mutated result directory metadata")
	}
	markerAfter, err := os.Lstat(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(markerBefore, markerAfter) || resultMetadataChangeTime(t, markerAfter) != markerBeforeChange {
		t.Fatal("valid repeat read mutated normalization marker metadata")
	}
}

func TestResolvedPlanCustodyRepairResultReadRejectsBundleLinkAndMarkerModeWithoutMutation(t *testing.T) {
	t.Run("directory owner policy", func(t *testing.T) {
		root := physicalTestTempDir(t)
		runID := "run-0123456789abcdef"
		runPath := filepath.Join(root, runID)
		if err := os.Mkdir(runPath, retainedResultRunDirMode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(runPath, retainedResultRunDirMode); err != nil {
			t.Fatal(err)
		}
		before, err := os.Lstat(runPath)
		if err != nil {
			t.Fatal(err)
		}
		beforeChange := resultMetadataChangeTime(t, before)
		wrongOwner := executionPlatformStateOwner{UID: os.Getuid() + 1, GID: os.Getgid()}
		if directory, exists, err := openRetainedResultDirectory(root, runID, wrongOwner, false); err == nil || exists || directory != nil {
			if directory != nil {
				_ = directory.close()
			}
			t.Fatalf("existing result directory owner mismatch was accepted: exists=%v err=%v", exists, err)
		}
		after, err := os.Lstat(runPath)
		if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || resultMetadataChangeTime(t, after) != beforeChange {
			t.Fatalf("existing owner mismatch was repaired: before=%v after=%v err=%v", before, after, err)
		}
	})
	t.Run("bundle link", func(t *testing.T) {
		service, locator, _ := newResultTestService(t)
		writeRetainedResultBundleBytes(t, service, locator, []byte("opaque"))
		bundlePath := service.retainedResultBundlePath(locator)
		linkPath := bundlePath + "-link"
		if err := os.Link(bundlePath, linkPath); err != nil {
			t.Fatal(err)
		}
		before, err := os.Lstat(bundlePath)
		if err != nil {
			t.Fatal(err)
		}
		if _, resultErr := service.Result(context.Background(), locator.RunID); resultErr == nil {
			t.Fatal("hard-linked retained bundle was accepted")
		}
		after, err := os.Lstat(bundlePath)
		if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
			t.Fatalf("hard-linked bundle changed on read: before=%v after=%v err=%v", before, after, err)
		}
		if _, err := os.Lstat(linkPath); err != nil {
			t.Fatalf("hard link was removed: %v", err)
		}
	})
	t.Run("marker mode", func(t *testing.T) {
		service, locator, _ := newResultTestService(t)
		writeRetainedResultBundleBytes(t, service, locator, []byte("opaque"))
		runPath := service.retainedResultRunDir(locator)
		writeOwnershipNormalizationMarker(t, runPath, validOwnershipNormalizationMarker(locator.RunID), 0o600)
		if err := os.Chmod(runPath, retainedResultRunDirMode); err != nil {
			t.Fatal(err)
		}
		markerPath := filepath.Join(runPath, ownershipNormalizationMarkerName)
		before, err := os.Lstat(markerPath)
		if err != nil {
			t.Fatal(err)
		}
		beforeChange := resultMetadataChangeTime(t, before)
		if _, resultErr := service.Result(context.Background(), locator.RunID); resultErr == nil {
			t.Fatal("wrong-mode existing marker was accepted")
		}
		after, err := os.Lstat(markerPath)
		if err != nil || !os.SameFile(before, after) || after.Mode().Perm() != 0o600 || resultMetadataChangeTime(t, after) != beforeChange {
			t.Fatalf("existing marker was repaired on read: before=%v after=%v err=%v", before, after, err)
		}
	})
}

func resultMetadataChangeTime(t *testing.T, info os.FileInfo) string {
	t.Helper()
	stat := reflect.ValueOf(info.Sys())
	if stat.Kind() != reflect.Ptr || stat.IsNil() {
		t.Fatal("result fixture has no stat metadata")
	}
	stat = stat.Elem()
	change := stat.FieldByName("Ctimespec")
	if !change.IsValid() {
		change = stat.FieldByName("Ctim")
	}
	if !change.IsValid() {
		t.Fatal("result fixture has no metadata change timestamp")
	}
	return fmt.Sprint(change.Interface())
}

func TestRetainedResultRoutesRejectRootOverlapBeforeAnyResultMutation(t *testing.T) {
	root := physicalTestTempDir(t)
	results := filepath.Join(root, "results")
	if err := os.Mkdir(results, 0o755); err != nil {
		t.Fatal(err)
	}
	service := &Service{cfg: esconfig.Config{Execution: esconfig.ExecutionConfig{
		StagingRootDir: root,
		ResultsRootDir: results,
	}}}
	locator := newExecutionLocatorFromRunID("run-0123456789abcdef")
	if retained, err := service.retainTerminalResult(locator); err == nil || retained {
		t.Fatalf("overlapping roots were not refused before retention: retained=%t err=%v", retained, err)
	}
	if _, ok, err := service.readRetainedResultBundle(locator); err == nil || ok {
		t.Fatalf("overlapping roots were not refused before read reconciliation: ok=%t err=%v", ok, err)
	}
	entries, err := os.ReadDir(results)
	if err != nil || len(entries) != 0 {
		t.Fatalf("overlap refusal changed results: entries=%v err=%v", entries, err)
	}
}

func TestResultServesRetainedBundleWhenStagingRootIsAbsentWithoutRuntimeLookup(t *testing.T) {
	service, locator, _ := newResultTestService(t)
	writeRetainedResultBundleBytes(t, service, locator, []byte("retained without staging root"))
	if err := os.Remove(service.cfg.Execution.StagingRootDir); err != nil {
		t.Fatal(err)
	}
	service.nomadClient = newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("retained-first missing-staging lookup reached Nomad: %s %s", r.Method, r.URL.Path)
	}))
	bundle, err := service.Result(context.Background(), locator.RunID)
	if err != nil || string(bundle.Payload) != "retained without staging root" {
		t.Fatalf("retained bundle was not served with absent staging root: bundle=%q err=%v", bundle.Payload, err)
	}
}

func TestResultServesRetainedBundleWhenStagingRunIsAbsentWithoutRuntimeLookup(t *testing.T) {
	service, locator, _ := newResultTestService(t)
	writeRetainedResultBundleBytes(t, service, locator, []byte("retained without staging run"))
	service.nomadClient = newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("retained-first missing-run lookup reached Nomad: %s %s", r.Method, r.URL.Path)
	}))
	bundle, err := service.Result(context.Background(), locator.RunID)
	if err != nil || string(bundle.Payload) != "retained without staging run" {
		t.Fatalf("retained bundle was not served with absent staging run: bundle=%q err=%v", bundle.Payload, err)
	}
}

func TestRetainTerminalResultMissingStageDoesNotCreateResultRun(t *testing.T) {
	service, locator, _ := newResultTestService(t)
	retained, err := service.retainTerminalResult(locator)
	if err != nil || retained {
		t.Fatalf("missing stage should be a clean no-result observation: retained=%t err=%v", retained, err)
	}
	if _, err := os.Stat(service.retainedResultRunDir(locator)); !os.IsNotExist(err) {
		t.Fatalf("missing stage created a results run: %v", err)
	}
}

func TestReadRetainedResultBundleMissingResultsRootDoesNotProvisionIt(t *testing.T) {
	service, locator, _ := newResultTestService(t)
	if err := os.Remove(service.cfg.Execution.ResultsRootDir); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := service.readRetainedResultBundle(locator); err != nil || ok {
		t.Fatalf("missing results root should be a clean absence: ok=%t err=%v", ok, err)
	}
	if _, err := os.Stat(service.cfg.Execution.ResultsRootDir); !os.IsNotExist(err) {
		t.Fatalf("read provisioned a missing results root: %v", err)
	}
}

func TestReadRetainedResultBundleTopologyFailureDoesNotFallThroughToNomad(t *testing.T) {
	root := physicalTestTempDir(t)
	service := &Service{
		cfg: esconfig.Config{Execution: esconfig.ExecutionConfig{StagingRootDir: root, ResultsRootDir: root}},
		nomadClient: newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("topology failure fell through to Nomad: %s %s", r.Method, r.URL.Path)
		})),
	}
	locator := newExecutionLocatorFromRunID("run-0123456789abcdef")
	if _, err := service.Result(context.Background(), locator.RunID); err == nil || err.Code != codeResultUnavailable {
		t.Fatalf("expected fixed result-unavailable topology error, got %+v", err)
	}
}

func TestTopologyAcquisitionOccursPerNamedEffectNotPerStreamWrite(t *testing.T) {
	parent := physicalTestTempDir(t)
	staging := filepath.Join(parent, "staging")
	results := filepath.Join(parent, "results")
	for _, root := range []string{staging, results} {
		if err := os.Mkdir(root, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	ledger := &executionRootAcquisitionLedger{}
	roots, err := qualifyExecutionRoots(staging, results, ledger)
	if err != nil {
		t.Fatal(err)
	}
	defer roots.close()
	owner, err := roots.owner()
	if err != nil {
		t.Fatal(err)
	}
	directory, _, err := openOrCreateRetainedResultDirectory(roots, "run-0123456789abcdef", owner)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.close()
	tempName, tempFile, err := directory.createTempFile()
	if err != nil {
		t.Fatal(err)
	}
	beforeWrites := ledger.Count
	for index := 0; index < 128; index++ {
		if _, err := tempFile.Write([]byte("stream-byte-block")); err != nil {
			t.Fatal(err)
		}
	}
	if ledger.Count != beforeWrites {
		t.Fatalf("stream writes reacquired topology: before=%d after=%d", beforeWrites, ledger.Count)
	}
	if err := tempFile.Sync(); err != nil {
		t.Fatal(err)
	}
	fingerprint, err := directory.fingerprintTemporaryFile(tempName, tempFile)
	if err != nil {
		t.Fatal(err)
	}
	defer tempFile.Close()
	beforePublish := ledger.Count
	installed, err := directory.publishTemporaryBundle(tempName, fingerprint, tempFile, retainedResultInstallHooks{})
	if err != nil || !installed {
		t.Fatalf("publish temp: installed=%t err=%v", installed, err)
	}
	if ledger.Count != beforePublish+1 {
		t.Fatalf("publication did not use exactly one named-boundary acquisition: before=%d after=%d", beforePublish, ledger.Count)
	}
}

func TestResultRetainedBundleLookupIsScopedToRunID(t *testing.T) {
	service, first, _ := newResultTestService(t)
	second := newExecutionLocatorFromRunID("run-fedcba9876543210")
	writeRetainedResultBundleBytes(t, service, first, []byte("first retained bundle"))
	writeRetainedResultBundleBytes(t, service, second, []byte("second retained bundle"))

	firstBundle, err := service.Result(context.Background(), first.RunID)
	if err != nil {
		t.Fatalf("read first retained bundle: %+v", err)
	}
	if string(firstBundle.Payload) != "first retained bundle" {
		t.Fatalf("expected first run bundle only, got %q", string(firstBundle.Payload))
	}

	secondBundle, err := service.Result(context.Background(), second.RunID)
	if err != nil {
		t.Fatalf("read second retained bundle: %+v", err)
	}
	if string(secondBundle.Payload) != "second retained bundle" {
		t.Fatalf("expected second run bundle only, got %q", string(secondBundle.Payload))
	}
}

func TestResultRejectsUnsafeResultReferencesBeforeStorageLookup(t *testing.T) {
	service, locator, _ := newResultTestService(t)
	writeRetainedResultBundleBytes(t, service, locator, []byte("retained bundle"))

	for _, runID := range []string{
		"",
		"not-a-run-id",
		locator.RunID + "/result.tar.gz",
		"../" + locator.RunID,
		"run-0123456789abcdef/../run-fedcba9876543210",
	} {
		_, err := service.Result(context.Background(), runID)
		if err == nil || err.Status != http.StatusBadRequest || err.Code != codeInvalidRunID {
			t.Fatalf("expected invalid_run_id for result reference %q, got %+v", runID, err)
		}
	}

	bundle, err := service.Result(context.Background(), locator.RunID)
	if err != nil {
		t.Fatalf("valid run_id should still retrieve retained bundle: %+v", err)
	}
	if string(bundle.Payload) != "retained bundle" {
		t.Fatalf("unexpected valid retained bundle payload %q", string(bundle.Payload))
	}
}

func TestRetainTerminalResultDoesNotSynthesizeInternalResultSidecars(t *testing.T) {
	service, locator, layout := newResultTestService(t)
	if err := os.MkdirAll(layout.resultStageDir, 0o755); err != nil {
		t.Fatalf("mkdir result dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(layout.resultStageDir, "summary.txt"), []byte("ok\n"), 0o644); err != nil {
		t.Fatalf("write result file: %v", err)
	}

	retained, err := service.retainTerminalResult(locator)
	if err != nil {
		t.Fatalf("retain terminal result: %v", err)
	}
	if !retained {
		t.Fatalf("expected result retention to report retained bundle")
	}

	bundle, ok, resultErr := service.readRetainedResultBundle(locator)
	if resultErr != nil {
		t.Fatalf("read retained result: %+v", resultErr)
	}
	if !ok {
		t.Fatalf("expected retained bundle to be readable")
	}
	entries := readAdmissionResultBundleEntries(t, bundle.Payload)
	if len(entries) != 1 || entries["summary.txt"] != "ok\n" {
		t.Fatalf("expected only workload-authored summary entry, got %#v", entries)
	}
	for _, forbidden := range []string{
		"logs.txt",
		"stdout.log",
		"proof.json",
		"support-bundle.json",
		"retained-internal-metadata.json",
		"credentials.json",
		"endpoint-secrets.json",
		"tls.pem",
		"spiffe.jwt",
		"cp-workflow.json",
		"review.json",
		"checkpoint.json",
		"finalization.json",
		"authority_handoff.json",
		"scheduler_truth.json",
	} {
		if _, ok := entries[forbidden]; ok {
			t.Fatalf("retained bundle must not synthesize internal sidecar %q", forbidden)
		}
	}
}

func TestResultReturnsRuntimeUnavailableWhenRuntimeUnconfiguredAfterNoRetainedBundle(t *testing.T) {
	t.Chdir(t.TempDir())

	locator := newExecutionLocatorFromRunID("run-0123456789abcdea")
	service := &Service{
		nomadClient: newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("runtime-unconfigured result lookup reached Nomad: %s %s", r.Method, r.URL.Path)
		})),
	}

	err := assertResultRuntimeUnavailableNoPanic(t, func() *Error {
		_, err := service.Result(context.Background(), locator.RunID)
		return err
	})
	payload := resultErrorResponsePayload(t, err)
	assertResultPayloadOmitsAll(t, payload,
		"workflow",
		"review",
		"checkpoint",
		"finalization",
		"temporal",
		"approval",
		"intervention",
		"attempt",
		"hold",
		"resume",
		"reject",
		"control_plane",
		"control-plane",
		"run_control",
		"run-control",
	)
}

func TestResultReturnsRuntimeUnavailableWhenConfiguredRuntimeHasNilNomadClientAfterNoRetainedBundle(t *testing.T) {
	service, locator, _ := newResultTestService(t)

	err := assertResultRuntimeUnavailableNoPanic(t, func() *Error {
		_, err := service.Result(context.Background(), locator.RunID)
		return err
	})
	_ = resultErrorResponsePayload(t, err)
}

func TestResultRuntimeUnavailableErrorResponseExcludesCredentialSecurityFields(t *testing.T) {
	service, locator, _ := newResultTestService(t)

	err := assertResultRuntimeUnavailableNoPanic(t, func() *Error {
		_, err := service.Result(context.Background(), locator.RunID)
		return err
	})
	payload := resultErrorResponsePayload(t, err)
	assertResultPayloadOmitsAll(t, payload,
		"vault_token",
		"client_token",
		"root_token",
		"unseal_key",
		"jwt_svid",
		"x509_svid",
		"private_key",
		"api_key",
		"proof_secret",
		"secret_payload",
		"lease_id",
		"lease_duration",
	)
}

func TestResultReturnsNotFoundForTerminalExecutionWithoutOutput(t *testing.T) {
	service, locator, _ := newResultTestService(t)
	service.nomadClient = newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/job/exec-run-0123456789abcdef":
			_, _ = w.Write([]byte(`{"ID":"exec-run-0123456789abcdef","Status":"dead"}`))
		case "/v1/job/exec-run-0123456789abcdef/allocations":
			_, _ = w.Write([]byte(`[{"ID":"alloc-1","ModifyIndex":1}]`))
		case "/v1/allocation/alloc-1":
			_, _ = w.Write([]byte(`{"ID":"alloc-1","ClientStatus":"complete","TaskStates":{"task":{"State":"dead","Events":[{"Type":"Terminated","ExitCode":0}]}}}`))
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))

	_, err := service.Result(context.Background(), locator.RunID)
	if err == nil || err.Status != http.StatusNotFound || err.Code != codeResultNotFound {
		t.Fatalf("expected result_not_found, got %+v", err)
	}
}

func TestResultReturnsConflictBeforeTerminalExecution(t *testing.T) {
	service, locator, _ := newResultTestService(t)
	service.nomadClient = newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/job/exec-run-0123456789abcdef":
			_, _ = w.Write([]byte(`{"ID":"exec-run-0123456789abcdef","Status":"running"}`))
		case "/v1/job/exec-run-0123456789abcdef/allocations":
			_, _ = w.Write([]byte(`[{"ID":"alloc-1","ModifyIndex":1}]`))
		case "/v1/allocation/alloc-1":
			_, _ = w.Write([]byte(`{"ID":"alloc-1","ClientStatus":"running","TaskStates":{"task":{"State":"running"}}}`))
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))

	_, err := service.Result(context.Background(), locator.RunID)
	if err == nil || err.Status != http.StatusConflict || err.Code != codeResultUnavailable {
		t.Fatalf("expected result_unavailable, got %+v", err)
	}
}

func newResultTestService(t *testing.T) (*Service, executionLocator, executionPackageLayout) {
	t.Helper()

	locator := newExecutionLocatorFromRunID("run-0123456789abcdef")
	service := &Service{
		cfg: esconfig.Config{
			Execution: esconfig.ExecutionConfig{
				StagingRootDir:     physicalTestTempDir(t),
				ResultsRootDir:     physicalTestTempDir(t),
				RetainedResultAuth: esconfig.RetainedResultAuthConfig{StoreID: "test_store", KeyID: "test_key", KeyFile: "/synthetic/retained-result-key"},
			},
		},
		resultAuth: syntheticResultAuthenticator(),
	}
	for _, root := range []string{service.cfg.Execution.StagingRootDir, service.cfg.Execution.ResultsRootDir} {
		if err := os.Chown(root, os.Getuid(), os.Getgid()); err != nil {
			t.Fatalf("normalize test root owner: %v", err)
		}
	}
	layout := newExecutionPackageLayout(service.cfg, locator)
	return service, locator, layout
}

func writeRetainedResultBundleBytes(t *testing.T, service *Service, locator executionLocator, payload []byte) {
	t.Helper()

	bundlePath := service.retainedResultBundlePath(locator)
	if err := os.MkdirAll(filepath.Dir(bundlePath), retainedResultRunDirMode); err != nil {
		t.Fatalf("mkdir retained result dir: %v", err)
	}
	if err := os.WriteFile(bundlePath, payload, 0o600); err != nil {
		t.Fatalf("write retained bundle: %v", err)
	}
	directory, exists, err := openRetainedResultDirectory(service.cfg.Execution.ResultsRootDir, locator.RunID, executionPlatformStateOwner{UID: os.Getuid(), GID: os.Getgid()}, false)
	if err != nil || !exists {
		t.Fatalf("open synthetic retained result fixture: exists=%t err=%v", exists, err)
	}
	defer directory.close()
	var finalStat unix.Stat_t
	if err := unix.Fstatat(directory.runFD, resultBundleFileName, &finalStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		t.Fatal(err)
	}
	record := retainedResultRecord{
		storeID: service.resultAuth.storeID,
		keyID:   service.resultAuth.keyID,
		runID:   locator.RunID,
		root:    directory.rootIdentity,
		run:     directory.runIdentity,
		final:   custodyIdentityFromStat(finalStat),
		length:  uint64(len(payload)),
		digest:  sha256.Sum256(payload),
	}
	if err := os.WriteFile(filepath.Join(service.retainedResultRunDir(locator), retainedResultRecordFileName), service.resultAuth.encodeRecord(record), 0o600); err != nil {
		t.Fatalf("write synthetic committed result record: %v", err)
	}
}

func assertResultRuntimeUnavailableNoPanic(t *testing.T, call func() *Error) (err *Error) {
	t.Helper()

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("expected runtime-unavailable error without panic, got panic: %v", recovered)
		}
	}()

	err = call()
	if err == nil {
		t.Fatalf("expected result runtime-unavailable error")
	}
	if err.Status != http.StatusServiceUnavailable || err.Code != codeExecutionRuntimeUnavailable {
		t.Fatalf("expected result runtime-unavailable 503, got %+v", err)
	}
	return err
}

func resultErrorResponsePayload(t *testing.T, err *Error) string {
	t.Helper()

	payload, marshalErr := json.Marshal(ErrorResponse{
		Success: false,
		Error:   err.Message,
		Code:    err.Code,
	})
	if marshalErr != nil {
		t.Fatalf("marshal result error response: %v", marshalErr)
	}

	var fields map[string]json.RawMessage
	if unmarshalErr := json.Unmarshal(payload, &fields); unmarshalErr != nil {
		t.Fatalf("decode result error response: %v", unmarshalErr)
	}
	for _, field := range []string{"success", "error", "code"} {
		if _, ok := fields[field]; !ok {
			t.Fatalf("expected structured result error field %q in %s", field, string(payload))
		}
	}
	if len(fields) != 3 {
		t.Fatalf("expected only structured result error fields, got %s", string(payload))
	}
	return string(payload)
}

func assertResultPayloadOmitsAll(t *testing.T, payload string, forbidden ...string) {
	t.Helper()

	for _, item := range forbidden {
		if strings.Contains(payload, item) {
			t.Fatalf("expected result error response to omit %q, got %s", item, payload)
		}
	}
}

func readAdmissionResultBundleEntries(t *testing.T, payload []byte) map[string]string {
	t.Helper()

	gzipReader, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("open gzip: %v", err)
	}
	defer gzipReader.Close()

	entries := map[string]string{}
	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read tar entry: %v", err)
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			continue
		}
		body, err := io.ReadAll(tarReader)
		if err != nil {
			t.Fatalf("read tar body: %v", err)
		}
		entries[header.Name] = string(body)
	}
	return entries
}

// The invalid-pair refusal is a separate branch from retention attempts: Result
// reads an existing pair before consulting Nomad or reaching a retention logger.
func TestIntegratedAuthenticatedRetentionPrivacyAndNoRepair(t *testing.T) {
	const runID = "run-0123456789abcdef"
	t.Run("invalid_existing_pair_refuses_without_fallback_or_repair", func(t *testing.T) {
		service, locator, _ := newResultTestService(t)
		writeRetainedResultBundleBytes(t, service, locator, []byte("synthetic committed result"))
		finalPath := service.retainedResultBundlePath(locator)
		if err := os.Chmod(finalPath, 0o644); err != nil {
			t.Fatal(err)
		}
		beforeFinal, err := os.Lstat(finalPath)
		if err != nil {
			t.Fatal(err)
		}
		runPath := service.retainedResultRunDir(locator)
		beforeRun, err := os.Lstat(runPath)
		if err != nil {
			t.Fatal(err)
		}
		providerCalls := 0
		service.nomadClient = newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			providerCalls++
			t.Errorf("invalid pair fell through to provider: %s", r.URL.Path)
		}))
		bundle, publicErr := service.Result(context.Background(), runID)
		if publicErr == nil || publicErr.Status != http.StatusConflict || publicErr.Code != codeResultUnavailable || len(bundle.Payload) != 0 || providerCalls != 0 {
			t.Fatalf("invalid pair was served or fell through: payload_len=%d error=%+v provider_calls=%d", len(bundle.Payload), publicErr, providerCalls)
		}
		afterFinal, err := os.Lstat(finalPath)
		if err != nil {
			t.Fatal(err)
		}
		afterRun, err := os.Lstat(runPath)
		if err != nil {
			t.Fatal(err)
		}
		if afterFinal.Mode() != beforeFinal.Mode() || resultMetadataChangeTime(t, afterFinal) != resultMetadataChangeTime(t, beforeFinal) || afterRun.Mode() != beforeRun.Mode() || resultMetadataChangeTime(t, afterRun) != resultMetadataChangeTime(t, beforeRun) {
			t.Fatal("Result repaired existing retained metadata")
		}
	})

	const privateCause = "private-result-path-uid-9123-env-secret"
	for _, tc := range []struct {
		name       string
		allocation bool
		call       string
		wantCalls  int
	}{
		{"terminal_status_without_allocation", false, "status", 2},
		{"terminal_allocation_status", true, "status", 3},
		{"terminal_allocation_logs", true, "logs", 4},
		{"terminal_result_attempt", false, "result", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			missingResultsRoot := filepath.Join(physicalTestTempDir(t), privateCause, "missing")
			calls := []string{}
			service := &Service{
				cfg: esconfig.Config{Execution: esconfig.ExecutionConfig{
					StagingRootDir:     physicalTestTempDir(t),
					ResultsRootDir:     missingResultsRoot,
					RetainedResultAuth: esconfig.RetainedResultAuthConfig{StoreID: "test_store", KeyID: "test_key", KeyFile: "/synthetic/retained-result-key"},
				}},
				resultAuth: syntheticResultAuthenticator(),
				nomadClient: newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls = append(calls, r.URL.Path)
					switch r.URL.Path {
					case "/v1/job/exec-" + runID:
						_, _ = w.Write([]byte(`{"ID":"exec-run-0123456789abcdef","Status":"dead","ModifyIndex":1}`))
					case "/v1/job/exec-" + runID + "/allocations":
						if tc.allocation {
							_, _ = w.Write([]byte(`[{"ID":"alloc-1","ModifyIndex":2}]`))
						} else {
							_, _ = w.Write([]byte(`[]`))
						}
					case "/v1/allocation/alloc-1":
						_, _ = w.Write([]byte(`{"ID":"alloc-1","ClientStatus":"complete","ModifyIndex":2,"TaskStates":{"task":{"State":"dead"}}}`))
					case "/v1/client/fs/logs/alloc-1":
						_, _ = w.Write([]byte("synthetic-log-body"))
					default:
						t.Errorf("unexpected fake provider path %q", r.URL.Path)
						w.WriteHeader(http.StatusNotFound)
					}
				})),
			}
			var captured bytes.Buffer
			previousWriter, previousFlags, previousPrefix := log.Writer(), log.Flags(), log.Prefix()
			log.SetOutput(&captured)
			log.SetFlags(0)
			log.SetPrefix("")
			t.Cleanup(func() { log.SetOutput(previousWriter); log.SetFlags(previousFlags); log.SetPrefix(previousPrefix) })
			switch tc.call {
			case "status":
				got, publicErr := service.Status(context.Background(), runID)
				if publicErr != nil || !got.Terminal {
					t.Fatalf("terminal Status changed: result=%+v err=%+v", got, publicErr)
				}
			case "logs":
				got, publicErr := service.Logs(context.Background(), runID)
				if publicErr != nil || string(got.Payload) != "synthetic-log-body" {
					t.Fatalf("terminal Logs changed: payload=%q err=%+v", got.Payload, publicErr)
				}
			case "result":
				got, publicErr := service.Result(context.Background(), runID)
				if publicErr == nil || publicErr.Status != http.StatusConflict || publicErr.Code != codeResultUnavailable || len(got.Payload) != 0 {
					t.Fatalf("Result failure mapping changed: payload=%q err=%+v", got.Payload, publicErr)
				}
			}
			if len(calls) != tc.wantCalls {
				t.Fatalf("fake provider calls=%v, want %d", calls, tc.wantCalls)
			}
			if got := strings.TrimSpace(captured.String()); got != "es result retention failed run_id="+runID || strings.Contains(got, privateCause) || strings.Contains(got, "err=") {
				t.Fatalf("unsafe or missing retention event %q", captured.String())
			}
		})
	}
}
