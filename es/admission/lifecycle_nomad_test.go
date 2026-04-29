package admission

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	esconfig "execution-substrate/es/config"
)

var opaqueLifecycleProjectionRevisionPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestStatusReturnsSubmittedWhenNoAllocationExistsYet(t *testing.T) {
	service := Service{
		cfg: minimalLifecycleConfig(t),
		nomadClient: newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/v1/job/exec-run-0123456789abcdef":
				_, _ = w.Write([]byte(`{"ID":"exec-run-0123456789abcdef","Status":"running","ModifyIndex":11}`))
			case "/v1/job/exec-run-0123456789abcdef/allocations":
				_, _ = w.Write([]byte(`[]`))
			default:
				t.Fatalf("unexpected path %q", r.URL.Path)
			}
		})),
	}

	result, err := service.Status(context.Background(), "run-0123456789abcdef")
	if err != nil {
		t.Fatalf("status: %+v", err)
	}
	if result.Status != executionLifecycleStatusSubmitted || result.Terminal {
		t.Fatalf("expected submitted non-terminal result, got %+v", result)
	}
	expectedProjection := lifecycleProjectionFromNomad(11)
	if result.LifecycleProjection != expectedProjection {
		t.Fatalf("expected job-derived lifecycle projection %+v, got %+v", expectedProjection, result.LifecycleProjection)
	}
	assertOpaqueLifecycleProjectionRevision(t, result.LifecycleProjection.Revision)
	if result.OutcomeEvidence.Source != outcomeEvidenceSourceNomad ||
		result.OutcomeEvidence.Observation != outcomeObservationNomadJobProjection ||
		result.OutcomeEvidence.LifecycleProjection == nil ||
		*result.OutcomeEvidence.LifecycleProjection != result.LifecycleProjection ||
		result.OutcomeEvidence.ProviderTerminalObserved == nil ||
		*result.OutcomeEvidence.ProviderTerminalObserved {
		t.Fatalf("unexpected outcome evidence %+v", result.OutcomeEvidence)
	}
}

func TestStatusReturnsTerminalWithExitCodeFromProjectedAllocation(t *testing.T) {
	service := Service{
		cfg: minimalLifecycleConfig(t),
		nomadClient: newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/v1/job/exec-run-0123456789abcdef":
				_, _ = w.Write([]byte(`{"ID":"exec-run-0123456789abcdef","Status":"running","ModifyIndex":10}`))
			case "/v1/job/exec-run-0123456789abcdef/allocations":
				_, _ = w.Write([]byte(`[{"ID":"alloc-old","ModifyIndex":1},{"ID":"alloc-new","ModifyIndex":20}]`))
			case "/v1/allocation/alloc-new":
				_, _ = w.Write([]byte(`{"ID":"alloc-new","ClientStatus":"complete","ModifyIndex":25,"TaskStates":{"task":{"State":"dead","Events":[{"Type":"Started"},{"Type":"Terminated","ExitCode":7}]}}}`))
			default:
				t.Fatalf("unexpected path %q", r.URL.Path)
			}
		})),
	}

	result, err := service.Status(context.Background(), "run-0123456789abcdef")
	if err != nil {
		t.Fatalf("status: %+v", err)
	}
	if result.Status != executionLifecycleStatusTerminal || !result.Terminal || result.ExitCode == nil || *result.ExitCode != 7 {
		t.Fatalf("expected terminal status with exit code, got %+v", result)
	}
	expectedProjection := lifecycleProjectionFromNomad(10, 25)
	if result.LifecycleProjection != expectedProjection {
		t.Fatalf("expected allocation-derived lifecycle projection %+v, got %+v", expectedProjection, result.LifecycleProjection)
	}
	assertOpaqueLifecycleProjectionRevision(t, result.LifecycleProjection.Revision)
	if result.OutcomeEvidence.Source != outcomeEvidenceSourceNomad ||
		result.OutcomeEvidence.Observation != outcomeObservationNomadTaskStateProjection ||
		result.OutcomeEvidence.LifecycleProjection == nil ||
		*result.OutcomeEvidence.LifecycleProjection != result.LifecycleProjection ||
		result.OutcomeEvidence.ProviderTerminalObserved == nil ||
		!*result.OutcomeEvidence.ProviderTerminalObserved {
		t.Fatalf("unexpected outcome evidence %+v", result.OutcomeEvidence)
	}
}

func TestLifecycleProjectionFromNomadIsOpaqueStableAndChangeDetecting(t *testing.T) {
	projection := lifecycleProjectionFromNomad(7, 3, 19, 12)
	if projection.Source != lifecycleProjectionSourceNomad {
		t.Fatalf("expected nomad projection source, got %q", projection.Source)
	}
	assertOpaqueLifecycleProjectionRevision(t, projection.Revision)

	if same := lifecycleProjectionFromNomad(7, 3, 19, 12); projection != same {
		t.Fatalf("expected stable lifecycle projection for identical observation, got %+v and %+v", projection, same)
	}
	if changed := lifecycleProjectionFromNomad(7, 3, 20, 12); projection.Revision == changed.Revision {
		t.Fatalf("expected lifecycle projection revision to change when observation changes: %+v vs %+v", projection, changed)
	}
	if changedShape := lifecycleProjectionFromNomad(19); projection.Revision == changedShape.Revision {
		t.Fatalf("expected lifecycle projection revision to distinguish different observation inputs: %+v vs %+v", projection, changedShape)
	}
}

func TestLogsReturnsTaskStdoutFromNomad(t *testing.T) {
	service := Service{
		cfg: minimalLifecycleConfig(t),
		nomadClient: newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/v1/job/exec-run-0123456789abcdef":
				_, _ = w.Write([]byte(`{"ID":"exec-run-0123456789abcdef","Status":"running"}`))
			case "/v1/job/exec-run-0123456789abcdef/allocations":
				_, _ = w.Write([]byte(`[{"ID":"alloc-1","ModifyIndex":4}]`))
			case "/v1/allocation/alloc-1":
				_, _ = w.Write([]byte(`{"ID":"alloc-1","ClientStatus":"running","TaskStates":{"task":{"State":"running"}}}`))
			case "/v1/client/fs/logs/alloc-1":
				if got := r.URL.Query().Get("task"); got != nomadTaskName {
					t.Fatalf("expected task query %q, got %q", nomadTaskName, got)
				}
				if got := r.URL.Query().Get("plain"); got != "true" {
					t.Fatalf("expected plain logs request, got %q", got)
				}
				_, _ = w.Write([]byte("hello from workload\n"))
			default:
				t.Fatalf("unexpected path %q", r.URL.Path)
			}
		})),
	}

	result, err := service.Logs(context.Background(), "run-0123456789abcdef")
	if err != nil {
		t.Fatalf("logs: %+v", err)
	}
	if string(result.Payload) != "hello from workload\n" {
		t.Fatalf("unexpected logs %q", string(result.Payload))
	}
	if result.OutcomeEvidence.Source != outcomeEvidenceSourceNomad ||
		result.OutcomeEvidence.Observation != outcomeObservationNomadTaskStdout ||
		result.OutcomeEvidence.AccessClass != outcomeAccessClassPlaintextStdout ||
		result.OutcomeEvidence.ProviderTerminalObserved == nil ||
		*result.OutcomeEvidence.ProviderTerminalObserved {
		t.Fatalf("unexpected logs outcome evidence %+v", result.OutcomeEvidence)
	}
}

func TestCancelStopsNomadJobWithoutPurge(t *testing.T) {
	service := Service{
		cfg: minimalLifecycleConfig(t),
		nomadClient: newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodGet && r.URL.Path == "/v1/job/exec-run-0123456789abcdef":
				_, _ = w.Write([]byte(`{"ID":"exec-run-0123456789abcdef","Status":"running"}`))
			case r.Method == http.MethodDelete && r.URL.Path == "/v1/job/exec-run-0123456789abcdef":
				if got := r.URL.Query().Get("purge"); got != "false" {
					t.Fatalf("expected purge=false on cancel, got %q", got)
				}
				_, _ = w.Write([]byte(`{"EvalID":"eval-1"}`))
			default:
				t.Fatalf("unexpected request %s %q", r.Method, r.URL.Path)
			}
		})),
	}

	result, err := service.Cancel(context.Background(), "run-0123456789abcdef")
	if err != nil {
		t.Fatalf("cancel: %+v", err)
	}
	if result.Status != executionLifecycleStatusCancelRequested || result.RunID != "run-0123456789abcdef" {
		t.Fatalf("unexpected cancel result %+v", result)
	}
	if result.OutcomeEvidence.Source != outcomeEvidenceSourceNomad ||
		result.OutcomeEvidence.Observation != outcomeObservationNomadStopAccepted ||
		result.OutcomeEvidence.ProviderTerminalObserved == nil ||
		*result.OutcomeEvidence.ProviderTerminalObserved {
		t.Fatalf("unexpected cancel outcome evidence %+v", result.OutcomeEvidence)
	}
}

func TestFetchJobMapsNotFoundAndFetchTaskLogsMapsConflict(t *testing.T) {
	client := newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/job/missing":
			http.NotFound(w, r)
		case "/v1/client/fs/logs/alloc-1":
			http.NotFound(w, r)
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))

	_, err := client.fetchJob(context.Background(), "missing")
	if err == nil || err.Code != codeExecutionNotFound {
		t.Fatalf("expected execution-not-found mapping, got %+v", err)
	}

	_, err = client.fetchTaskLogs(context.Background(), "alloc-1", nomadTaskName)
	if err == nil || err.Code != codeLogsUnavailable {
		t.Fatalf("expected logs-unavailable mapping, got %+v", err)
	}
}

func newTestNomadClient(t *testing.T, handler http.Handler) *nomadClient {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	baseURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test nomad url: %v", err)
	}
	return &nomadClient{
		baseURL:    baseURL,
		datacenter: "dc1",
		client:     server.Client(),
	}
}

func minimalLifecycleConfig(t *testing.T) esconfig.Config {
	t.Helper()

	return esconfig.Config{
		Execution: esconfig.ExecutionConfig{
			StagingRootDir: t.TempDir(),
			ResultsRootDir: t.TempDir(),
		},
	}
}

func assertOpaqueLifecycleProjectionRevision(t *testing.T, revision string) {
	t.Helper()

	if revision == "" {
		t.Fatal("expected non-empty lifecycle projection revision")
	}
	if !opaqueLifecycleProjectionRevisionPattern.MatchString(revision) {
		t.Fatalf("expected opaque hex lifecycle projection revision, got %q", revision)
	}
	for _, forbidden := range []string{
		"nomad-index",
		"exec-run",
		"alloc-",
		"task",
		":",
		"/",
	} {
		if strings.Contains(revision, forbidden) {
			t.Fatalf("expected lifecycle projection revision to omit %q, got %q", forbidden, revision)
		}
	}
}
