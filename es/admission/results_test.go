package admission

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	esconfig "execution-substrate/es/config"
	"golang.org/x/sys/unix"
)

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

func TestResultBundleEntryNameRejectsPathTraversal(t *testing.T) {
	root := filepath.Join(t.TempDir(), "result")
	outside := filepath.Join(filepath.Dir(root), "escape.txt")

	_, err := resultBundleEntryName(root, outside)
	if err == nil || !strings.Contains(err.Error(), "escapes result directory") {
		t.Fatalf("expected path traversal rejection, got %v", err)
	}
}

func TestResultReturnsRetainedBundleWithoutRuntimeLookup(t *testing.T) {
	service, locator, _ := newResultTestService(t)
	bundlePath := service.retainedResultBundlePath(locator)
	if err := os.MkdirAll(filepath.Dir(bundlePath), 0o755); err != nil {
		t.Fatalf("mkdir retained result dir: %v", err)
	}
	if err := os.WriteFile(bundlePath, []byte("already retained"), 0o600); err != nil {
		t.Fatalf("write retained bundle: %v", err)
	}

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
				StagingRootDir: t.TempDir(),
				ResultsRootDir: t.TempDir(),
			},
		},
	}
	if err := os.MkdirAll(service.cfg.Execution.ResultsRootDir, 0o700); err != nil {
		t.Fatalf("mkdir results root: %v", err)
	}
	layout := newExecutionPackageLayout(service.cfg, locator)
	return service, locator, layout
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
