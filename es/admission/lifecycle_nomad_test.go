package admission

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
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

func TestTrancheB2StopJobConstructsExactNonPurgingDelete(t *testing.T) {
	for _, runID := range []string{"run-0123456789abcdef", "run-fedcba9876543210"} {
		t.Run(runID, func(t *testing.T) {
			jobID := "exec-" + runID
			response := trancheB2Response(http.StatusOK, []byte(`{"EvalID":"ignored"}`), int64(len(`{"EvalID":"ignored"}`)))
			probe := response.Body.(*trancheB2ReadCloseProbe)
			client := trancheB2NomadClientWithResponse(t, func(request *http.Request) *http.Response {
				if request.Method != http.MethodDelete {
					t.Fatalf("cancel method = %s, want DELETE", request.Method)
				}
				wantPath := "/v1/job/" + jobID
				if request.URL.Path != wantPath || request.URL.EscapedPath() != wantPath {
					t.Fatalf("cancel path = %q escaped=%q, want %q", request.URL.Path, request.URL.EscapedPath(), wantPath)
				}
				if request.URL.RawQuery != "namespace="+nomadSubmitNamespace+"&purge=false" {
					t.Fatalf("cancel raw query = %q, want namespace=%s&purge=false", request.URL.RawQuery, nomadSubmitNamespace)
				}
				query := request.URL.Query()
				values, ok := query["purge"]
				if len(query) != 2 || !ok || len(values) != 1 || values[0] != "false" {
					t.Fatalf("cancel parsed query = %#v, want only namespace and purge=[false]", query)
				}
				if request.Body != nil {
					body, err := io.ReadAll(request.Body)
					if err != nil {
						t.Fatal(err)
					}
					if len(body) != 0 {
						t.Fatalf("cancel request body has %d bytes", len(body))
					}
				}
				return response
			})
			if publicErr := client.stopJob(context.Background(), jobID); publicErr != nil {
				t.Fatalf("stop job failed: %+v", publicErr)
			}
			if probe.reads != 0 || !probe.closed {
				t.Fatalf("status-governed cancel body reads=%d closed=%v, want 0/true", probe.reads, probe.closed)
			}
		})
	}
}

func TestTrancheB2StopJobStatusMappingsCloseWithoutReading(t *testing.T) {
	for _, test := range []struct {
		name       string
		status     int
		wantStatus int
		wantCode   string
	}{
		{name: "accepted", status: http.StatusOK},
		{name: "not found", status: http.StatusNotFound, wantStatus: http.StatusNotFound, wantCode: codeExecutionNotFound},
		{name: "provider unavailable", status: http.StatusBadGateway, wantStatus: http.StatusServiceUnavailable, wantCode: codeExecutionRuntimeUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := trancheB2Response(test.status, []byte("private-cancel-provider-body"), int64(len("private-cancel-provider-body")))
			probe := response.Body.(*trancheB2ReadCloseProbe)
			client := trancheB2NomadClientWithResponse(t, func(*http.Request) *http.Response { return response })
			publicErr := client.stopJob(context.Background(), "exec-run-0123456789abcdef")
			if test.wantCode == "" {
				if publicErr != nil {
					t.Fatalf("successful stop returned %+v", publicErr)
				}
			} else if publicErr == nil || publicErr.Status != test.wantStatus || publicErr.Code != test.wantCode {
				t.Fatalf("stop error = %+v, want status=%d code=%q", publicErr, test.wantStatus, test.wantCode)
			}
			if probe.reads != 0 || !probe.closed {
				t.Fatalf("cancel response reads=%d closed=%v, want 0/true", probe.reads, probe.closed)
			}
		})
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

func TestTrancheB2NomadNonSuccessBodiesAreNotReadAndAreClosed(t *testing.T) {
	const marker = "private-nomad-non-success-body"
	for _, test := range []struct {
		name       string
		status     int
		invoke     func(*nomadClient) *Error
		wantStatus int
		wantCode   string
	}{
		{
			name:   "fetch job not found",
			status: http.StatusNotFound,
			invoke: func(client *nomadClient) *Error {
				_, publicErr := client.fetchJob(context.Background(), "missing")
				return publicErr
			},
			wantStatus: http.StatusNotFound,
			wantCode:   codeExecutionNotFound,
		},
		{
			name:   "fetch job provider failure",
			status: http.StatusBadGateway,
			invoke: func(client *nomadClient) *Error {
				_, publicErr := client.fetchJob(context.Background(), "exec-run")
				return publicErr
			},
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   codeExecutionRuntimeUnavailable,
		},
		{
			name:   "task logs not found",
			status: http.StatusNotFound,
			invoke: func(client *nomadClient) *Error {
				_, publicErr := client.fetchTaskLogs(context.Background(), "alloc-1", nomadTaskName)
				return publicErr
			},
			wantStatus: http.StatusConflict,
			wantCode:   codeLogsUnavailable,
		},
		{
			name:   "task logs provider failure",
			status: http.StatusBadGateway,
			invoke: func(client *nomadClient) *Error {
				_, publicErr := client.fetchTaskLogs(context.Background(), "alloc-1", nomadTaskName)
				return publicErr
			},
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   codeExecutionRuntimeUnavailable,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := trancheB2Response(test.status, []byte(marker), int64(len(marker)))
			probe := response.Body.(*trancheB2ReadCloseProbe)
			client := trancheB2NomadClientWithResponse(t, func(*http.Request) *http.Response { return response })
			publicErr := test.invoke(client)
			if publicErr == nil || publicErr.Status != test.wantStatus || publicErr.Code != test.wantCode {
				t.Fatalf("non-success mapping = %+v, want status=%d code=%q", publicErr, test.wantStatus, test.wantCode)
			}
			if strings.Contains(publicErr.Message, marker) {
				t.Fatalf("provider body escaped into public message: %+v", publicErr)
			}
			if probe.reads != 0 || !probe.closed {
				t.Fatalf("non-success body reads=%d closed=%v, want 0/true", probe.reads, probe.closed)
			}
		})
	}
}

func TestTrancheB2LifecycleStructuredNomadReadersEnforceBoundedOneDocument(t *testing.T) {
	t.Run("projected allocation list", func(t *testing.T) {
		exact := trancheB2PaddedJSON(
			`[{"ID":"alloc-1","ModifyIndex":7,"CompatibleUnknown":"`,
			`"}]`,
			int(maxDependencyJSONResponseBytes),
		)
		listResponse := trancheB2Response(http.StatusOK, exact, -1)
		listProbe := listResponse.Body.(*trancheB2ReadCloseProbe)
		detailResponse := trancheB2Response(http.StatusOK, []byte(`{"ID":"alloc-1","ClientStatus":"running","ModifyIndex":8,"TaskStates":{},"CompatibleUnknown":true}`), -1)
		detailProbe := detailResponse.Body.(*trancheB2ReadCloseProbe)
		client := trancheB2NomadClientWithResponse(t, func(request *http.Request) *http.Response {
			switch request.URL.Path {
			case "/v1/job/exec-run/allocations":
				return listResponse
			case "/v1/allocation/alloc-1":
				return detailResponse
			default:
				t.Fatalf("unexpected path %q", request.URL.Path)
				return nil
			}
		})
		allocation, publicErr := client.fetchProjectedAllocation(context.Background(), "exec-run")
		if publicErr != nil || allocation == nil || allocation.ID != "alloc-1" || allocation.ModifyIndex != 8 {
			t.Fatalf("exact-limit compatible list failed: allocation=%+v err=%+v", allocation, publicErr)
		}
		if !listProbe.closed || !detailProbe.closed {
			t.Fatalf("successful allocation response bodies were not closed: list=%v detail=%v", listProbe.closed, detailProbe.closed)
		}

		tooLarge := append(append([]byte(nil), exact...), ' ')
		client = trancheB2NomadClientWithResponse(t, func(*http.Request) *http.Response {
			return trancheB2Response(http.StatusOK, tooLarge, -1)
		})
		if _, publicErr := client.fetchProjectedAllocation(context.Background(), "exec-run"); publicErr == nil {
			t.Fatal("limit-plus-one projected allocation response succeeded")
		}

		client = trancheB2NomadClientWithResponse(t, func(*http.Request) *http.Response {
			return trancheB2Response(http.StatusOK, []byte(`[] {}`), -1)
		})
		if _, publicErr := client.fetchProjectedAllocation(context.Background(), "exec-run"); publicErr == nil {
			t.Fatal("second projected-allocation JSON document succeeded")
		}

		for name, body := range map[string][]byte{
			"malformed":  []byte(`[{"ID":`),
			"wrong type": []byte(`[{"ID":7}]`),
			"trailing":   []byte(`[] trailing`),
		} {
			t.Run(name, func(t *testing.T) {
				client := trancheB2NomadClientWithResponse(t, func(*http.Request) *http.Response {
					return trancheB2Response(http.StatusOK, body, -1)
				})
				if _, publicErr := client.fetchProjectedAllocation(context.Background(), "exec-run"); publicErr == nil {
					t.Fatalf("%s projected-allocation response succeeded", name)
				}
			})
		}
	})

	t.Run("allocation detail", func(t *testing.T) {
		exact := trancheB2PaddedJSON(
			`{"ID":"alloc-1","ClientStatus":"running","ModifyIndex":9,"TaskStates":{},"CompatibleUnknown":"`,
			`"}`,
			int(maxDependencyJSONResponseBytes),
		)
		exactResponse := trancheB2Response(http.StatusOK, exact, -1)
		exactProbe := exactResponse.Body.(*trancheB2ReadCloseProbe)
		client := trancheB2NomadClientWithResponse(t, func(*http.Request) *http.Response {
			return exactResponse
		})
		allocation, publicErr := client.fetchAllocation(context.Background(), "alloc-1")
		if publicErr != nil || allocation.ID != "alloc-1" || allocation.ModifyIndex != 9 {
			t.Fatalf("exact-limit compatible allocation detail failed: allocation=%+v err=%+v", allocation, publicErr)
		}
		if !exactProbe.closed {
			t.Fatal("successful allocation-detail response body was not closed")
		}

		for name, body := range map[string][]byte{
			"limit plus one":  append(append([]byte(nil), exact...), ' '),
			"malformed":       []byte(`{"ID":`),
			"wrong type":      []byte(`{"ID":7}`),
			"trailing":        []byte(`{"ID":"alloc-1"} trailing`),
			"second document": []byte(`{"ID":"alloc-1"} {}`),
		} {
			t.Run(name, func(t *testing.T) {
				client := trancheB2NomadClientWithResponse(t, func(*http.Request) *http.Response {
					return trancheB2Response(http.StatusOK, body, -1)
				})
				if _, publicErr := client.fetchAllocation(context.Background(), "alloc-1"); publicErr == nil {
					t.Fatalf("%s allocation detail succeeded", name)
				}
			})
		}
	})
}

func TestTrancheB2StructuredNomadTransportLengthAndNonSuccessBodies(t *testing.T) {
	const providerMarker = "private-provider-body-path-uid-9123"
	for _, reader := range []struct {
		name   string
		valid  []byte
		invoke func(*nomadClient) *Error
	}{
		{
			name:  "allocation list",
			valid: []byte(`[]`),
			invoke: func(client *nomadClient) *Error {
				_, publicErr := client.fetchProjectedAllocation(context.Background(), "exec-run")
				return publicErr
			},
		},
		{
			name:  "allocation detail",
			valid: []byte(`{"ID":"alloc-1","ClientStatus":"running","TaskStates":{}}`),
			invoke: func(client *nomadClient) *Error {
				_, publicErr := client.fetchAllocation(context.Background(), "alloc-1")
				return publicErr
			},
		},
	} {
		t.Run(reader.name, func(t *testing.T) {
			for _, test := range []struct {
				name          string
				status        int
				contentLength int64
				body          []byte
				wantRead      bool
			}{
				{name: "known oversize", status: http.StatusOK, contentLength: maxDependencyJSONResponseBytes + 1, body: reader.valid},
				{name: "fixed truncation", status: http.StatusOK, contentLength: int64(len(reader.valid) + 1), body: reader.valid, wantRead: true},
				{name: "fixed surplus", status: http.StatusOK, contentLength: int64(len(reader.valid) - 1), body: reader.valid, wantRead: true},
				{name: "non-success body", status: http.StatusBadGateway, contentLength: int64(len(providerMarker)), body: []byte(providerMarker)},
			} {
				t.Run(test.name, func(t *testing.T) {
					probe := &trancheB2ReadCloseProbe{reader: bytes.NewReader(test.body)}
					client := trancheB2NomadClientWithResponse(t, func(*http.Request) *http.Response {
						return &http.Response{StatusCode: test.status, Header: make(http.Header), Body: probe, ContentLength: test.contentLength}
					})
					publicErr := reader.invoke(client)
					if publicErr == nil {
						t.Fatal("invalid transport response succeeded")
					}
					if strings.Contains(publicErr.Message, providerMarker) {
						t.Fatalf("provider body escaped into public error: %+v", publicErr)
					}
					if (probe.reads > 0) != test.wantRead {
						t.Fatalf("body reads=%d, wantRead=%v", probe.reads, test.wantRead)
					}
					if !probe.closed {
						t.Fatal("response body was not closed")
					}
				})
			}
		})
	}
}

func TestTrancheB2FetchJobRemainsUnboundedCompatibleAndOneDocument(t *testing.T) {
	largeValue := strings.Repeat("j", int(maxDependencyJSONResponseBytes)+1)
	body := []byte(fmt.Sprintf(`{"ID":"exec-run","Status":"running","CompatibleUnknown":true,"TaskGroups":[{"Tasks":[{"Name":"task","Env":{"LARGE":"%s"}}]}]}`, largeValue))
	if len(body) <= int(maxDependencyJSONResponseBytes) {
		t.Fatal("oversized job-summary fixture is not oversized")
	}
	largeResponse := trancheB2Response(http.StatusOK, body, -1)
	largeProbe := largeResponse.Body.(*trancheB2ReadCloseProbe)
	client := trancheB2NomadClientWithResponse(t, func(*http.Request) *http.Response {
		return largeResponse
	})
	job, publicErr := client.fetchJob(context.Background(), "exec-run")
	if publicErr != nil || len(job.TaskGroups) != 1 || job.TaskGroups[0].Tasks[0].Env["LARGE"] != largeValue {
		t.Fatalf("valid oversized compatible job summary failed: job=%+v err=%+v", job, publicErr)
	}
	if !largeProbe.closed {
		t.Fatal("successful oversized job-summary body was not closed")
	}

	client = trancheB2NomadClientWithResponse(t, func(*http.Request) *http.Response {
		return trancheB2Response(http.StatusOK, []byte(`{"ID":"exec-run"} {}`), -1)
	})
	if _, publicErr := client.fetchJob(context.Background(), "exec-run"); publicErr == nil {
		t.Fatal("second job-summary JSON document succeeded")
	}
}

func TestTrancheB2SuccessfulPublicTaskLogsRemainOpaqueAndUnbounded(t *testing.T) {
	want := bytes.Repeat([]byte{0x00, 0xff, 'x', '\n'}, int(maxDependencyJSONResponseBytes/4)+1)
	if len(want) <= int(maxDependencyJSONResponseBytes) {
		t.Fatal("public Logs fixture is not above the structured-control limit")
	}
	logsResponse := trancheB2Response(http.StatusOK, want, -1)
	logsProbe := logsResponse.Body.(*trancheB2ReadCloseProbe)
	client := trancheB2NomadClientWithResponse(t, func(*http.Request) *http.Response {
		return logsResponse
	})
	got, publicErr := client.fetchTaskLogs(context.Background(), "alloc-1", nomadTaskName)
	if publicErr != nil {
		t.Fatalf("oversized successful public Logs failed: %+v", publicErr)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("successful public Logs bytes changed")
	}
	if !logsProbe.closed {
		t.Fatal("successful public Logs body was not closed")
	}

	service := Service{
		cfg: minimalLifecycleConfig(t),
		nomadClient: newTestNomadClient(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			switch request.URL.Path {
			case "/v1/job/exec-run-0123456789abcdef":
				_, _ = response.Write([]byte(`{"ID":"exec-run-0123456789abcdef","Status":"running"}`))
			case "/v1/job/exec-run-0123456789abcdef/allocations":
				_, _ = response.Write([]byte(`[{"ID":"alloc-1","ModifyIndex":1}]`))
			case "/v1/allocation/alloc-1":
				_, _ = response.Write([]byte(`{"ID":"alloc-1","ClientStatus":"running","TaskStates":{"task":{"State":"running"}}}`))
			case "/v1/client/fs/logs/alloc-1":
				_, _ = response.Write(want)
			default:
				t.Fatalf("unexpected public Logs path %q", request.URL.Path)
			}
		})),
	}
	result, serviceErr := service.Logs(context.Background(), "run-0123456789abcdef")
	if serviceErr != nil {
		t.Fatalf("oversized successful public Logs service path failed: %+v", serviceErr)
	}
	if !bytes.Equal(result.Payload, want) {
		t.Fatal("successful public Logs service bytes changed")
	}
}

type trancheB2ReadCloseProbe struct {
	reader *bytes.Reader
	reads  int
	closed bool
}

func (p *trancheB2ReadCloseProbe) Read(buffer []byte) (int, error) {
	p.reads++
	return p.reader.Read(buffer)
}

func (p *trancheB2ReadCloseProbe) Close() error {
	p.closed = true
	return nil
}

func trancheB2PaddedJSON(prefix string, suffix string, size int) []byte {
	padding := size - len(prefix) - len(suffix)
	if padding < 0 {
		panic("invalid padded JSON size")
	}
	return []byte(prefix + strings.Repeat("x", padding) + suffix)
}

func trancheB2Response(status int, body []byte, contentLength int64) *http.Response {
	return &http.Response{
		StatusCode:    status,
		Header:        make(http.Header),
		Body:          &trancheB2ReadCloseProbe{reader: bytes.NewReader(body)},
		ContentLength: contentLength,
	}
}

func trancheB2NomadClientWithResponse(t *testing.T, response func(*http.Request) *http.Response) *nomadClient {
	t.Helper()
	baseURL, err := url.Parse("http://nomad.test")
	if err != nil {
		t.Fatal(err)
	}
	return &nomadClient{
		baseURL:    baseURL,
		datacenter: "dc1",
		token:      testNomadToken,
		client: &http.Client{Transport: resolvedPlanRoundTripper(func(request *http.Request) (*http.Response, error) {
			assertNomadJobRequestAuthenticated(t, request)
			return response(request), nil
		})},
	}
}

// newTestNomadClient serves handler behind nomadAccessControlTestHandler, an
// ACL-enabled Nomad stand-in that also checks every job request's token and
// namespace.
func newTestNomadClient(t *testing.T, handler http.Handler) *nomadClient {
	t.Helper()

	return newUnwrappedTestNomadClient(t, nomadAccessControlTestHandler(t, handler))
}

// newUnwrappedTestNomadClient serves handler as the whole Nomad, including
// the access-control endpoints, over HTTPS with a pinned test certificate;
// the client uses ES's own TLS configuration and transport.
func newUnwrappedTestNomadClient(t *testing.T, handler http.Handler) *nomadClient {
	t.Helper()

	pki := newTestNomadPKI(t)
	certificate, pin := pki.serverCert(t, testNomadServerCertOptions{})
	server := startTestNomadTLSServer(t, handler, certificate, 0)
	return newTLSTestNomadClient(t, testNomadTLSConfigFor(server, pki, pin))
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
