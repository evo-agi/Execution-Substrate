package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
	server := NewServer(service, "bootstrap", []string{"operator/local"}, func() bool { return true })

	logsRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(logsRecorder, authorizedLifecycleRequest(http.MethodGet, "/v1/executions/run-0123456789abcdef/logs"))
	if logsRecorder.Code != http.StatusOK {
		t.Fatalf("expected logs 200, got %d body=%s", logsRecorder.Code, logsRecorder.Body.String())
	}
	assertHeader(t, logsRecorder.Result(), "Content-Type", admission.LogsMediaType)
	assertHeader(t, logsRecorder.Result(), headerOutcomeSource, "nomad")
	assertHeader(t, logsRecorder.Result(), headerOutcomeObservation, "nomad_task_stdout")
	assertHeader(t, logsRecorder.Result(), headerOutcomeAccessClass, "plaintext_stdout")
	assertHeader(t, logsRecorder.Result(), headerProviderTerminalObserved, "false")
	if logsRecorder.Body.String() != "hello\n" {
		t.Fatalf("expected logs payload to remain plain text, got %q", logsRecorder.Body.String())
	}

	resultRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(resultRecorder, authorizedLifecycleRequest(http.MethodGet, "/v1/executions/run-0123456789abcdef/result"))
	if resultRecorder.Code != http.StatusOK {
		t.Fatalf("expected result 200, got %d body=%s", resultRecorder.Code, resultRecorder.Body.String())
	}
	assertHeader(t, resultRecorder.Result(), "Content-Type", "application/gzip")
	assertHeader(t, resultRecorder.Result(), headerOutcomeSource, "es_retained_result_store")
	assertHeader(t, resultRecorder.Result(), headerOutcomeObservation, "retained_result_bundle")
	assertHeader(t, resultRecorder.Result(), headerOutcomeAccessClass, "opaque_result_bundle")
	if resultRecorder.Body.String() != "bundle" {
		t.Fatalf("expected result payload bytes unchanged, got %q", resultRecorder.Body.String())
	}
}

func TestProducerContractEndpointRequiresAuthorizedCallerAndReturnsDeclaration(t *testing.T) {
	service := fakeLifecycleService{
		producerContract: admission.ProducerContractDeclaration{
			SchemaVersion: "execution-substrate.producer-contract/v1",
			Service:       "execution",
			GovernedExecution: admission.GovernedExecutionProducerContractDeclaration{
				Contract: "governed-execution-producer/v1",
				Enabled:  true,
			},
		},
	}
	server := NewServer(service, "bootstrap", []string{"operator/local"}, func() bool { return true })

	unauthorizedRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(unauthorizedRecorder, httptest.NewRequest(http.MethodGet, "/v1/executions:contract", nil))
	if unauthorizedRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized contract probe 401, got %d body=%s", unauthorizedRecorder.Code, unauthorizedRecorder.Body.String())
	}

	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, authorizedLifecycleRequest(http.MethodGet, "/v1/executions:contract"))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected contract probe 200, got %d body=%s", recorder.Code, recorder.Body.String())
	}

	var payload admission.ProducerContractDeclaration
	if err := json.NewDecoder(recorder.Result().Body).Decode(&payload); err != nil {
		t.Fatalf("decode contract declaration: %v", err)
	}
	if payload.SchemaVersion != "execution-substrate.producer-contract/v1" ||
		payload.GovernedExecution.Contract != "governed-execution-producer/v1" ||
		!payload.GovernedExecution.Enabled {
		t.Fatalf("unexpected contract declaration %+v", payload)
	}
}

func TestWorkstreamCPrepareRejectsUpstreamAndControlPlaneGrammarFields(t *testing.T) {
	baseInvocation := `"invocation":{"schema_version":"v1","artifact_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","derivation_spec_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","output_id":"runtime"}`
	tests := []struct {
		name string
		body string
	}{
		{
			name: "ARS descriptor tuple",
			body: `{"schema_version":"v1","descriptor_digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",` + baseInvocation + `}`,
		},
		{
			name: "ARS manifest tuple",
			body: `{"schema_version":"v1","manifest":{"digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},` + baseInvocation + `}`,
		},
		{
			name: "ARS index support tuple",
			body: `{"schema_version":"v1","index_entry":{"kind":"manifest"},"supporting":[{"name":"manifest"}],` + baseInvocation + `}`,
		},
		{
			name: "AGS publication fields",
			body: `{"schema_version":"v1","publication":{"builder_service":"artifact-governance","policy_decisions":[{"rule":"allow","result":"applied"}]},` + baseInvocation + `}`,
		},
		{
			name: "CP attempt fields",
			body: `{"schema_version":"v1","attempt":{"provider_run_id":"provider-1","workflow_id":"workflow-1"},` + baseInvocation + `}`,
		},
		{
			name: "CP review checkpoint finalization fields",
			body: `{"schema_version":"v1","review":{"state":"pending"},"checkpoint":{"id":"cp-checkpoint"},"finalization":{"state":"pending"},` + baseInvocation + `}`,
		},
		{
			name: "nested payload digest as public invocation grammar",
			body: `{"schema_version":"v1","invocation":{"schema_version":"v1","artifact_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","payload_digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","derivation_spec_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","output_id":"runtime"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prepareCalls := 0
			server := NewServer(fakeLifecycleService{
				prepareCalls: &prepareCalls,
				prepareResult: admission.PrepareResult{
					Success: true,
				},
			}, "bootstrap", []string{"operator/local"}, func() bool { return true })

			recorder := httptest.NewRecorder()
			server.Handler().ServeHTTP(recorder, authorizedLifecycleRequestWithBody(http.MethodPost, "/v1/executions:prepare", tt.body))
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("expected prepare to reject %s grammar with 400, got %d body=%s", tt.name, recorder.Code, recorder.Body.String())
			}
			if prepareCalls != 0 {
				t.Fatalf("prepare service must not receive rejected %s grammar", tt.name)
			}
			var payload admission.ErrorResponse
			if err := json.NewDecoder(recorder.Result().Body).Decode(&payload); err != nil {
				t.Fatalf("decode error response: %v", err)
			}
			if payload.Code != "invalid_request" {
				t.Fatalf("expected invalid_request for rejected public grammar, got %+v", payload)
			}
		})
	}
}

func TestWorkstreamCExecutionCompatibilityRoutesRemainAvailable(t *testing.T) {
	var prepareRequest admission.PrepareRequest
	var submitRequest admission.PrepareRequest
	service := fakeLifecycleService{
		producerContract: admission.ProducerContractDeclaration{
			SchemaVersion: "execution-substrate.producer-contract/v1",
			Service:       "execution",
			GovernedExecution: admission.GovernedExecutionProducerContractDeclaration{
				Contract: "governed-execution-producer/v1",
				Enabled:  true,
			},
		},
		prepareResult: admission.PrepareResult{
			Success: true,
		},
		submitResult: admission.SubmitResult{
			Success:   true,
			Submitted: true,
			RunID:     "run-0123456789abcdef",
			Status:    "submitted",
		},
		prepareRequestSink: &prepareRequest,
		submitRequestSink:  &submitRequest,
	}
	server := NewServer(service, "bootstrap", []string{"operator/local"}, func() bool { return true })

	contractRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(contractRecorder, authorizedLifecycleRequest(http.MethodGet, "/v1/executions:contract"))
	if contractRecorder.Code != http.StatusOK {
		t.Fatalf("expected contract compatibility route 200, got %d body=%s", contractRecorder.Code, contractRecorder.Body.String())
	}

	body := `{"schema_version":"v1","invocation":{"schema_version":"v1","artifact_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","derivation_spec_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","output_id":"runtime","annotations":{"execution_substrate.runtime_profile":"control-plane-normal-shell/v1"}},"mode":"async"}`
	prepareRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(prepareRecorder, authorizedLifecycleRequestWithBody(http.MethodPost, "/v1/executions:prepare", body))
	if prepareRecorder.Code != http.StatusOK {
		t.Fatalf("expected prepare compatibility route 200, got %d body=%s", prepareRecorder.Code, prepareRecorder.Body.String())
	}
	var preparePayload admission.PrepareResult
	if err := json.NewDecoder(prepareRecorder.Result().Body).Decode(&preparePayload); err != nil {
		t.Fatalf("decode prepare payload: %v", err)
	}
	if !preparePayload.Success {
		t.Fatalf("expected prepare success payload, got %+v", preparePayload)
	}
	if prepareRequest.Invocation.Annotations["execution_substrate.runtime_profile"] != "control-plane-normal-shell/v1" {
		t.Fatalf("expected runtime profile annotation to remain accepted by decode boundary, got %+v", prepareRequest.Invocation.Annotations)
	}

	submitRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(submitRecorder, authorizedLifecycleRequestWithBody(http.MethodPost, "/v1/executions:submit", body))
	if submitRecorder.Code != http.StatusAccepted {
		t.Fatalf("expected submit compatibility route 202, got %d body=%s", submitRecorder.Code, submitRecorder.Body.String())
	}
	var submitPayload admission.SubmitResult
	if err := json.NewDecoder(submitRecorder.Result().Body).Decode(&submitPayload); err != nil {
		t.Fatalf("decode submit payload: %v", err)
	}
	if !submitPayload.Success || !submitPayload.Submitted || submitPayload.Status != "submitted" {
		t.Fatalf("expected bounded submit compatibility receipt, got %+v", submitPayload)
	}
	if submitRequest.Invocation.Annotations["execution_substrate.runtime_profile"] != "control-plane-normal-shell/v1" {
		t.Fatalf("expected runtime profile annotation to remain accepted by submit decode boundary, got %+v", submitRequest.Invocation.Annotations)
	}
}

func TestExecutionCallerAuthorizationMatchesExactOrSubpathOnly(t *testing.T) {
	server := NewServer(fakeLifecycleService{}, "bootstrap", []string{"service/control-plane"}, func() bool { return true })

	tests := []struct {
		name       string
		callerPath string
		wantStatus int
	}{
		{name: "exact match", callerPath: "service/control-plane", wantStatus: http.StatusOK},
		{name: "subpath match", callerPath: "service/control-plane/provider", wantStatus: http.StatusOK},
		{name: "same prefix text without path boundary", callerPath: "service/control-plane-evil", wantStatus: http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			server.Handler().ServeHTTP(recorder, lifecycleRequestWithCaller(http.MethodGet, "/v1/executions:contract", tt.callerPath))
			if recorder.Code != tt.wantStatus {
				t.Fatalf("expected status %d, got %d body=%s", tt.wantStatus, recorder.Code, recorder.Body.String())
			}
		})
	}
}

type fakeLifecycleService struct {
	logsResult         admission.ExecutionLogsResult
	resultBundle       admission.ExecutionResultBundle
	producerContract   admission.ProducerContractDeclaration
	prepareResult      admission.PrepareResult
	submitResult       admission.SubmitResult
	prepareRequestSink *admission.PrepareRequest
	submitRequestSink  *admission.PrepareRequest
	prepareCalls       *int
	submitCalls        *int
}

func (f fakeLifecycleService) Health(context.Context) admission.HealthSnapshot {
	return admission.HealthSnapshot{}
}

func (f fakeLifecycleService) ProducerContract(context.Context) admission.ProducerContractDeclaration {
	return f.producerContract
}

func (f fakeLifecycleService) Prepare(_ context.Context, request admission.PrepareRequest) (admission.PrepareResult, *admission.Error) {
	if f.prepareCalls != nil {
		*f.prepareCalls = *f.prepareCalls + 1
	}
	if f.prepareRequestSink != nil {
		*f.prepareRequestSink = request
	}
	return f.prepareResult, nil
}

func (f fakeLifecycleService) Submit(_ context.Context, request admission.PrepareRequest) (admission.SubmitResult, *admission.Error) {
	if f.submitCalls != nil {
		*f.submitCalls = *f.submitCalls + 1
	}
	if f.submitRequestSink != nil {
		*f.submitRequestSink = request
	}
	return f.submitResult, nil
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
	return lifecycleRequestWithCaller(method, target, "operator/local")
}

func authorizedLifecycleRequestWithBody(method string, target string, body string) *http.Request {
	return lifecycleRequestWithCallerAndBody(method, target, "operator/local", body)
}

func lifecycleRequestWithCaller(method string, target string, callerPath string) *http.Request {
	return lifecycleRequestWithCallerAndBody(method, target, callerPath, "")
}

func lifecycleRequestWithCallerAndBody(method string, target string, callerPath string, body string) *http.Request {
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	request := httptest.NewRequest(method, target, reader)
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	spiffeURI, _ := url.Parse("spiffe://execution.internal/" + callerPath)
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
