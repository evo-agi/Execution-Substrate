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

func TestWorkstreamC2StatusLogsResultCancelCompatibilityShapesStayUnchanged(t *testing.T) {
	service := fakeLifecycleService{
		statusResult: admission.ExecutionStatusResult{
			Success: true,
			RunID:   "run-0123456789abcdef",
			Status:  "running",
			LifecycleProjection: admission.LifecycleProjection{
				Source:   "nomad",
				Revision: "opaque-c2-read-token",
			},
			OutcomeEvidence: admission.ExecutionOutcomeEvidence{
				Source:      "nomad",
				Observation: "nomad_projected_allocation",
				LifecycleProjection: &admission.LifecycleProjection{
					Source:   "nomad",
					Revision: "opaque-c2-read-token",
				},
				ProviderTerminalObserved: boolPtr(false),
			},
		},
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
		cancelResult: admission.ExecutionCancelResult{
			Success: true,
			RunID:   "run-0123456789abcdef",
			Status:  "cancel_requested",
			OutcomeEvidence: admission.ExecutionOutcomeEvidence{
				Source:                   "nomad",
				Observation:              "nomad_stop_request_accepted",
				ProviderTerminalObserved: boolPtr(false),
			},
		},
	}
	server := NewServer(service, "bootstrap", []string{"operator/local"}, func() bool { return true })

	statusRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(statusRecorder, authorizedLifecycleRequest(http.MethodGet, "/v1/executions/run-0123456789abcdef/status"))
	if statusRecorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", statusRecorder.Code, statusRecorder.Body.String())
	}
	assertJSONFieldsExactForAPI(t, statusRecorder.Body.Bytes(),
		"success",
		"run_id",
		"status",
		"lifecycle_projection",
		"outcome_evidence",
		"terminal",
	)
	assertTextOmitsAllForAPI(t, statusRecorder.Body.String(),
		`"job_id"`,
		`"allocation_id"`,
		`"task_id"`,
		`"workflow"`,
		`"checkpoint"`,
		`"finalization"`,
		`"write_guard"`,
		`"retained_result_id"`,
	)

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
		t.Fatalf("expected logs payload unchanged, got %q", logsRecorder.Body.String())
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

	cancelRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(cancelRecorder, authorizedLifecycleRequest(http.MethodPost, "/v1/executions/run-0123456789abcdef:cancel"))
	if cancelRecorder.Code != http.StatusOK {
		t.Fatalf("expected cancel 200, got %d body=%s", cancelRecorder.Code, cancelRecorder.Body.String())
	}
	assertJSONFieldsExactForAPI(t, cancelRecorder.Body.Bytes(), "success", "run_id", "status", "outcome_evidence")
	assertTextOmitsAllForAPI(t, cancelRecorder.Body.String(),
		`"job_id"`,
		`"allocation_id"`,
		`"task_id"`,
		`"workflow"`,
		`"checkpoint"`,
		`"finalization"`,
		`"write_guard"`,
	)
}

func TestWorkstreamC3ResultRouteCompatibilityReturnsOpaqueGzipWithoutRunControlShape(t *testing.T) {
	opaquePayload := []byte(`{"review":"opaque workload content","checkpoint":"not ES grammar","finalization":"not ES grammar"}`)
	service := fakeLifecycleService{
		resultBundle: admission.ExecutionResultBundle{
			MediaType: "application/gzip",
			OutcomeEvidence: admission.ExecutionOutcomeEvidence{
				Source:      "es_retained_result_store",
				Observation: "retained_result_bundle",
				AccessClass: "opaque_result_bundle",
			},
			Payload: opaquePayload,
		},
	}
	server := NewServer(service, "bootstrap", []string{"operator/local"}, func() bool { return true })

	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, authorizedLifecycleRequest(http.MethodGet, "/v1/executions/run-0123456789abcdef/result"))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected result 200, got %d body=%s", recorder.Code, recorder.Body.String())
	}
	assertHeader(t, recorder.Result(), "Content-Type", "application/gzip")
	assertHeader(t, recorder.Result(), headerOutcomeSource, "es_retained_result_store")
	assertHeader(t, recorder.Result(), headerOutcomeObservation, "retained_result_bundle")
	assertHeader(t, recorder.Result(), headerOutcomeAccessClass, "opaque_result_bundle")
	if string(recorder.Body.Bytes()) != string(opaquePayload) {
		t.Fatalf("expected opaque result bytes unchanged, got %q", recorder.Body.String())
	}

	headers := compactHeaderText(recorder.Result().Header)
	assertTextOmitsAllForAPI(t, headers,
		"review",
		"checkpoint",
		"finalization",
		"approval",
		"intervention",
		"hold",
		"resume",
		"reject",
		"Temporal",
		"workflow",
		"scheduler",
		"credential",
		"token",
		"lease",
	)
}

func TestWorkstreamC4PublicRuntimeIdentityVaultResponsesExcludeCredentialLeaseAndRawSPIREMaterial(t *testing.T) {
	handoff := &admission.ExecutionAuthorityHandoff{
		AuthorityPath: "workload_identity_endpoint/workload_vault",
		RuntimeProfile: admission.ExecutionAuthorityRuntimeProfile{
			Name: "control-plane-normal-shell/v1",
		},
		IdentityHandoff: admission.ExecutionAuthorityIdentityHandoff{
			Mode:          "workload_identity_endpoint",
			EndpointEnv:   "EXEC_WORKLOAD_IDENTITY_ENDPOINT",
			EndpointURI:   "unix:///run/es-runtime-identity/run-0123456789abcdef/endpoint",
			JWTSVIDTarget: "workload_vault",
		},
		WorkloadVault: admission.ExecutionAuthorityWorkloadVault{
			AuthMode:    "vault_identity_jwt",
			Address:     "https://vault.internal:8200",
			AuthMount:   "jwt",
			AuthRole:    "service_execution",
			JWTAudience: "vault",
			CACertEnv:   "VAULT_CACERT",
			CACertPath:  "/execution/run/platform/workload-vault-ca.pem",
		},
		RuntimeConfigRefs: admission.ExecutionAuthorityRuntimeConfigRefs{
			WorkloadZoneVaultConfig: admission.ExecutionAuthorityRuntimeConfigRef{
				Digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			},
		},
		CodexCredentialLocation: &admission.ExecutionAuthorityCodexCredential{
			CLIPath:          "/usr/local/bin/codex",
			CredentialSource: "workload_vault",
			VaultSecretPath:  "proof-secrets/data/codex-runtime-profile",
			VaultSecretField: "runtime_profile_key_label",
		},
		Evidence: admission.ExecutionAuthorityEvidence{
			Source:                  "submitted_runtime_spec",
			RuntimeProfile:          "es_selected_runtime_profile",
			IdentityHandoff:         "submitted_runtime_environment",
			WorkloadVault:           "submitted_runtime_environment",
			RuntimeConfigRefs:       "submitted_runtime_metadata",
			CodexCredentialLocation: "submitted_runtime_environment",
		},
	}
	service := fakeLifecycleService{
		submitResult: admission.SubmitResult{
			Success:          true,
			Submitted:        true,
			RunID:            "run-0123456789abcdef",
			Status:           "submitted",
			AuthorityHandoff: handoff,
		},
		statusResult: admission.ExecutionStatusResult{
			Success: true,
			RunID:   "run-0123456789abcdef",
			Status:  "running",
			LifecycleProjection: admission.LifecycleProjection{
				Source:   "nomad",
				Revision: "opaque-c4-read-token",
			},
			OutcomeEvidence: admission.ExecutionOutcomeEvidence{
				Source:      "nomad",
				Observation: "nomad_task_state_projection",
				LifecycleProjection: &admission.LifecycleProjection{
					Source:   "nomad",
					Revision: "opaque-c4-read-token",
				},
				ProviderTerminalObserved: boolPtr(false),
			},
			AuthorityHandoff: handoff,
			Terminal:         false,
		},
	}
	server := NewServer(service, "bootstrap", []string{"operator/local"}, func() bool { return true })
	body := `{"schema_version":"v1","invocation":{"schema_version":"v1","artifact_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","derivation_spec_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","output_id":"runtime"},"mode":"async"}`

	submitRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(submitRecorder, authorizedLifecycleRequestWithBody(http.MethodPost, "/v1/executions:submit", body))
	if submitRecorder.Code != http.StatusAccepted {
		t.Fatalf("expected submit 202, got %d body=%s", submitRecorder.Code, submitRecorder.Body.String())
	}
	assertWorkstreamC4PublicResponseOmitsCredentialLeaseAndRawSPIRE(t, submitRecorder.Body.String())

	statusRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(statusRecorder, authorizedLifecycleRequest(http.MethodGet, "/v1/executions/run-0123456789abcdef/status"))
	if statusRecorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", statusRecorder.Code, statusRecorder.Body.String())
	}
	assertWorkstreamC4PublicResponseOmitsCredentialLeaseAndRawSPIRE(t, statusRecorder.Body.String())
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

func TestWorkstreamC2SubmitRejectsControlPlaneRunControlGrammarBeforeServiceCall(t *testing.T) {
	baseInvocation := `"invocation":{"schema_version":"v1","artifact_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","derivation_spec_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","output_id":"runtime"}`
	tests := []struct {
		name string
		body string
	}{
		{
			name: "CP attempt and provider run id",
			body: `{"schema_version":"v1","attempt":{"provider_run_id":"provider-1"},` + baseInvocation + `}`,
		},
		{
			name: "CP review checkpoint finalization intervention",
			body: `{"schema_version":"v1","review":{"state":"pending"},"checkpoint":{"id":"cp-checkpoint"},"finalization":{"state":"pending"},"intervention":{"state":"open"},` + baseInvocation + `}`,
		},
		{
			name: "CP approval hold resume reject",
			body: `{"schema_version":"v1","approval":{"state":"pending"},"hold":{"reason":"review"},"resume":{"by":"operator"},"reject":{"reason":"policy"},` + baseInvocation + `}`,
		},
		{
			name: "Temporal workflow grammar",
			body: `{"schema_version":"v1","temporal":{"workflow_id":"workflow-1"},"workflow":{"revision":"cp-rev"},"workflow_id":"workflow-1",` + baseInvocation + `}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			submitCalls := 0
			server := NewServer(fakeLifecycleService{
				submitCalls: &submitCalls,
				submitResult: admission.SubmitResult{
					Success:   true,
					Submitted: true,
					RunID:     "run-0123456789abcdef",
					Status:    "submitted",
				},
			}, "bootstrap", []string{"operator/local"}, func() bool { return true })

			recorder := httptest.NewRecorder()
			server.Handler().ServeHTTP(recorder, authorizedLifecycleRequestWithBody(http.MethodPost, "/v1/executions:submit", tt.body))
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("expected submit to reject %s grammar with 400, got %d body=%s", tt.name, recorder.Code, recorder.Body.String())
			}
			if submitCalls != 0 {
				t.Fatalf("submit service must not receive rejected %s grammar", tt.name)
			}
			var payload admission.ErrorResponse
			if err := json.NewDecoder(recorder.Result().Body).Decode(&payload); err != nil {
				t.Fatalf("decode error response: %v", err)
			}
			if payload.Code != "invalid_request" {
				t.Fatalf("expected invalid_request for rejected submit grammar, got %+v", payload)
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
	statusResult       admission.ExecutionStatusResult
	cancelResult       admission.ExecutionCancelResult
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
	return f.statusResult, nil
}

func (f fakeLifecycleService) Logs(context.Context, string) (admission.ExecutionLogsResult, *admission.Error) {
	return f.logsResult, nil
}

func (f fakeLifecycleService) Result(context.Context, string) (admission.ExecutionResultBundle, *admission.Error) {
	return f.resultBundle, nil
}

func (f fakeLifecycleService) Cancel(context.Context, string) (admission.ExecutionCancelResult, *admission.Error) {
	return f.cancelResult, nil
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

func assertJSONFieldsExactForAPI(t *testing.T, data []byte, want ...string) {
	t.Helper()

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatalf("decode json payload: %v", err)
	}
	if len(fields) != len(want) {
		t.Fatalf("expected JSON fields %v, got %s", want, string(data))
	}
	for _, field := range want {
		if _, ok := fields[field]; !ok {
			t.Fatalf("expected JSON field %q in %s", field, string(data))
		}
	}
}

func assertTextOmitsAllForAPI(t *testing.T, text string, forbidden ...string) {
	t.Helper()

	for _, item := range forbidden {
		if strings.Contains(text, item) {
			t.Fatalf("expected text to omit %q, got %s", item, text)
		}
	}
}

func compactHeaderText(header http.Header) string {
	parts := make([]string, 0, len(header))
	for key, values := range header {
		parts = append(parts, key)
		parts = append(parts, values...)
	}
	return strings.Join(parts, " ")
}

func boolPtr(value bool) *bool {
	return &value
}

func assertWorkstreamC4PublicResponseOmitsCredentialLeaseAndRawSPIRE(t *testing.T, text string) {
	t.Helper()

	for _, field := range []string{
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
		"raw_spire_socket",
	} {
		assertTextOmitsAllForAPI(t, text, `"`+field+`":`)
	}
	assertTextOmitsAllForAPI(t, text,
		"/run/spire/sockets/agent.sock",
		"/run/spire/server/private/api.sock",
		"/run/es-runtime-identity/run-0123456789abcdef/internal/spire-agent.sock",
	)
}
