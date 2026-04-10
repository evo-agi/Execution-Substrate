package admission

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	esconfig "execution-substrate/es/config"
)

func TestStatusReturnsSubmittedWhenNoAllocationExistsYet(t *testing.T) {
	service := Service{
		cfg: minimalLifecycleConfig(t),
		nomadClient: newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/v1/job/exec-run-0123456789abcdef":
				_, _ = w.Write([]byte(`{"ID":"exec-run-0123456789abcdef","Status":"running"}`))
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
}

func TestStatusReturnsTerminalWithExitCodeFromProjectedAllocation(t *testing.T) {
	service := Service{
		cfg: minimalLifecycleConfig(t),
		nomadClient: newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/v1/job/exec-run-0123456789abcdef":
				_, _ = w.Write([]byte(`{"ID":"exec-run-0123456789abcdef","Status":"running"}`))
			case "/v1/job/exec-run-0123456789abcdef/allocations":
				_, _ = w.Write([]byte(`[{"ID":"alloc-old","ModifyIndex":1},{"ID":"alloc-new","ModifyIndex":2}]`))
			case "/v1/allocation/alloc-new":
				_, _ = w.Write([]byte(`{"ID":"alloc-new","ClientStatus":"complete","TaskStates":{"task":{"State":"dead","Events":[{"Type":"Started"},{"Type":"Terminated","ExitCode":7}]}}}`))
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

	logs, err := service.Logs(context.Background(), "run-0123456789abcdef")
	if err != nil {
		t.Fatalf("logs: %+v", err)
	}
	if string(logs) != "hello from workload\n" {
		t.Fatalf("unexpected logs %q", string(logs))
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
		},
	}
}
