package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"execution-substrate/es/admission"
)

func TestLifecycleHeadersExposeOutcomeEvidenceForLogsAndResult(t *testing.T) {
	service := fakeLifecycleService{
		logsResult: admission.ExecutionLogsResult{
			OutcomeEvidence: admission.ExecutionOutcomeEvidence{
				Source:                   "nomad",
				Observation:              "nomad_task_stdout",
				AccessClass:              "plaintext_stdout",
				ProviderTerminalObserved: boolPtr(false),
			},
			Payload: []byte("hello\n"),
		},
		resultBundle: admission.ExecutionResultBundle{
			MediaType: "application/gzip",
			OutcomeEvidence: admission.ExecutionOutcomeEvidence{
				Source:      "es_retained_result_store",
				Observation: "retained_result_bundle",
				AccessClass: "opaque_result_bundle",
			},
			Payload: []byte("bundle"),
		},
	}
	server := NewServer(service, "bootstrap", []string{"operator"}, func() bool { return true })

	logsRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(logsRecorder, authorizedLifecycleRequest(http.MethodGet, "/v1/executions/run-0123456789abcdef/logs"))
	if logsRecorder.Code != http.StatusOK {
		t.Fatalf("expected logs 200, got %d body=%s", logsRecorder.Code, logsRecorder.Body.String())
	}
	assertHeader(t, logsRecorder.Result(), headerOutcomeSource, "nomad")
	assertHeader(t, logsRecorder.Result(), headerOutcomeObservation, "nomad_task_stdout")
	assertHeader(t, logsRecorder.Result(), headerOutcomeAccessClass, "plaintext_stdout")
	assertHeader(t, logsRecorder.Result(), headerProviderTerminalObserved, "false")

	resultRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(resultRecorder, authorizedLifecycleRequest(http.MethodGet, "/v1/executions/run-0123456789abcdef/result"))
	if resultRecorder.Code != http.StatusOK {
		t.Fatalf("expected result 200, got %d body=%s", resultRecorder.Code, resultRecorder.Body.String())
	}
	assertHeader(t, resultRecorder.Result(), headerOutcomeSource, "es_retained_result_store")
	assertHeader(t, resultRecorder.Result(), headerOutcomeObservation, "retained_result_bundle")
	assertHeader(t, resultRecorder.Result(), headerOutcomeAccessClass, "opaque_result_bundle")
}

type fakeLifecycleService struct {
	logsResult   admission.ExecutionLogsResult
	resultBundle admission.ExecutionResultBundle
}

func (f fakeLifecycleService) Health(context.Context) admission.HealthSnapshot {
	return admission.HealthSnapshot{}
}

func (f fakeLifecycleService) Prepare(context.Context, admission.PrepareRequest) (admission.PrepareResult, *admission.Error) {
	return admission.PrepareResult{}, nil
}

func (f fakeLifecycleService) Submit(context.Context, admission.PrepareRequest) (admission.SubmitResult, *admission.Error) {
	return admission.SubmitResult{}, nil
}

func (f fakeLifecycleService) Status(context.Context, string) (admission.ExecutionStatusResult, *admission.Error) {
	return admission.ExecutionStatusResult{}, nil
}

func (f fakeLifecycleService) Logs(context.Context, string) (admission.ExecutionLogsResult, *admission.Error) {
	return f.logsResult, nil
}

func (f fakeLifecycleService) Result(context.Context, string) (admission.ExecutionResultBundle, *admission.Error) {
	return f.resultBundle, nil
}

func (f fakeLifecycleService) Cancel(context.Context, string) (admission.ExecutionCancelResult, *admission.Error) {
	return admission.ExecutionCancelResult{}, nil
}

func authorizedLifecycleRequest(method string, target string) *http.Request {
	request := httptest.NewRequest(method, target, nil)
	spiffeURI, _ := url.Parse("spiffe://execution.internal/operator")
	request.TLS = &tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{
			{
				Issuer: pkix.Name{CommonName: "runtime"},
				URIs:   []*url.URL{spiffeURI},
			},
		}},
	}
	return request
}

func assertHeader(t *testing.T, response *http.Response, key string, want string) {
	t.Helper()

	if got := response.Header.Get(key); got != want {
		t.Fatalf("expected header %s=%q, got %q", key, want, got)
	}
}

func boolPtr(value bool) *bool {
	return &value
}
