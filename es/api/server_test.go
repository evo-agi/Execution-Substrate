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

func TestWorkstreamCRetainedResultRouteStaysSeparateFromSubmitStatusLogsAndCancel(t *testing.T) {
	submitCalls := 0
	statusCalls := 0
	logsCalls := 0
	resultCalls := 0
	cancelCalls := 0
	resultPayload := []byte("opaque retained bundle")
	service := fakeLifecycleService{
		submitCalls: &submitCalls,
		statusCalls: &statusCalls,
		logsCalls:   &logsCalls,
		resultCalls: &resultCalls,
		cancelCalls: &cancelCalls,
		logsResult: admission.ExecutionLogsResult{
			OutcomeEvidence: admission.ExecutionOutcomeEvidence{
				Source:                   "nomad",
				Observation:              "nomad_task_stdout",
				AccessClass:              "plaintext_stdout",
				ProviderTerminalObserved: boolPtr(true),
			},
			Payload: []byte("raw log payload\n"),
		},
		resultBundle: admission.ExecutionResultBundle{
			MediaType: "application/gzip",
			OutcomeEvidence: admission.ExecutionOutcomeEvidence{
				Source:      "es_retained_result_store",
				Observation: "retained_result_bundle",
				AccessClass: "opaque_result_bundle",
			},
			Payload: resultPayload,
		},
	}
	server := NewServer(service, "bootstrap", []string{"operator/local"}, func() bool { return true })

	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, authorizedLifecycleRequest(http.MethodGet, "/v1/executions/run-0123456789abcdef/result"))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected result 200, got %d body=%s", recorder.Code, recorder.Body.String())
	}
	if resultCalls != 1 || submitCalls != 0 || statusCalls != 0 || logsCalls != 0 || cancelCalls != 0 {
		t.Fatalf("result route must call only result service, got submit=%d status=%d logs=%d result=%d cancel=%d", submitCalls, statusCalls, logsCalls, resultCalls, cancelCalls)
	}
	assertHeader(t, recorder.Result(), "Content-Type", "application/gzip")
	assertHeader(t, recorder.Result(), headerOutcomeSource, "es_retained_result_store")
	assertHeader(t, recorder.Result(), headerOutcomeObservation, "retained_result_bundle")
	assertHeader(t, recorder.Result(), headerOutcomeAccessClass, "opaque_result_bundle")
	assertWorkstreamC5HeaderOmitsRunControlCredentialAndBackendAuthority(t, recorder.Result().Header)
	if string(recorder.Body.Bytes()) != string(resultPayload) {
		t.Fatalf("expected retained result bytes, got %q", recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "raw log payload") {
		t.Fatalf("result route must not expose logs payload through result")
	}
}

func TestWorkstreamCRetainedResultRouteRejectsPathLikeReferencesBeforeService(t *testing.T) {
	resultCalls := 0
	service := fakeLifecycleService{
		resultCalls: &resultCalls,
		resultBundle: admission.ExecutionResultBundle{
			MediaType: "application/gzip",
			Payload:   []byte("bundle"),
		},
	}
	server := NewServer(service, "bootstrap", []string{"operator/local"}, func() bool { return true })

	for _, target := range []string{
		"/v1/executions/run-0123456789abcdef/result.tar.gz/result",
		"/v1/executions/run-0123456789abcdef/retained/run-fedcba9876543210/result",
		"/v1/executions/run-0123456789abcdef/result/extra",
	} {
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, authorizedLifecycleRequest(http.MethodGet, target))
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("expected path-like result reference %q to fail with 404, got %d body=%s", target, recorder.Code, recorder.Body.String())
		}
	}
	if resultCalls != 0 {
		t.Fatalf("path-like result references must not reach result service, got %d calls", resultCalls)
	}
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

func TestWorkstreamC5LifecycleEnvelopesAndHeadersExcludeRunControlAndCredentialFields(t *testing.T) {
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
	logPayload := "raw log payload keeps review/checkpoint/vault_token words as content only\n"
	resultPayload := []byte("raw result bundle bytes keep finalization/private_key words as content only\n")
	service := fakeLifecycleService{
		statusResult: admission.ExecutionStatusResult{
			Success: true,
			RunID:   "run-0123456789abcdef",
			Status:  "running",
			LifecycleProjection: admission.LifecycleProjection{
				Source:   "nomad",
				Revision: "opaque-c5-read-token",
			},
			OutcomeEvidence: admission.ExecutionOutcomeEvidence{
				Source:      "nomad",
				Observation: "nomad_task_state_projection",
				LifecycleProjection: &admission.LifecycleProjection{
					Source:   "nomad",
					Revision: "opaque-c5-read-token",
				},
				ProviderTerminalObserved: boolPtr(false),
			},
			AuthorityHandoff: handoff,
		},
		logsResult: admission.ExecutionLogsResult{
			OutcomeEvidence: admission.ExecutionOutcomeEvidence{
				Source:                   "nomad",
				Observation:              "nomad_task_stdout",
				AccessClass:              "plaintext_stdout",
				ProviderTerminalObserved: boolPtr(false),
			},
			Payload: []byte(logPayload),
		},
		resultBundle: admission.ExecutionResultBundle{
			MediaType: "application/gzip",
			OutcomeEvidence: admission.ExecutionOutcomeEvidence{
				Source:      "es_retained_result_store",
				Observation: "retained_result_bundle",
				AccessClass: "opaque_result_bundle",
			},
			Payload: resultPayload,
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
		"authority_handoff",
		"terminal",
	)
	assertWorkstreamC5EnvelopeOmitsRunControlCredentialAndBackendAuthority(t, statusRecorder.Body.String())

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
	assertWorkstreamC5HeaderOmitsRunControlCredentialAndBackendAuthority(t, logsRecorder.Result().Header)
	if logsRecorder.Body.String() != logPayload {
		t.Fatalf("expected logs payload bytes unchanged, got %q", logsRecorder.Body.String())
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
	assertWorkstreamC5HeaderOmitsRunControlCredentialAndBackendAuthority(t, resultRecorder.Result().Header)
	if string(resultRecorder.Body.Bytes()) != string(resultPayload) {
		t.Fatalf("expected result payload bytes unchanged, got %q", resultRecorder.Body.String())
	}

	cancelRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(cancelRecorder, authorizedLifecycleRequest(http.MethodPost, "/v1/executions/run-0123456789abcdef:cancel"))
	if cancelRecorder.Code != http.StatusOK {
		t.Fatalf("expected cancel 200, got %d body=%s", cancelRecorder.Code, cancelRecorder.Body.String())
	}
	assertJSONFieldsExactForAPI(t, cancelRecorder.Body.Bytes(), "success", "run_id", "status", "outcome_evidence")
	assertWorkstreamC5EnvelopeOmitsRunControlCredentialAndBackendAuthority(t, cancelRecorder.Body.String())
}

func TestWorkstreamCLifecycleProjectionAuthorityLabelsStaySeparatedAtAPIBoundary(t *testing.T) {
	statusCalls := 0
	logsCalls := 0
	resultCalls := 0
	cancelCalls := 0
	logPayload := "raw log payload with workflow/private_key words remains logs body only\n"
	resultPayload := []byte("opaque retained bundle with checkpoint/vault_token words remains result body only\n")
	service := fakeLifecycleService{
		statusCalls: &statusCalls,
		logsCalls:   &logsCalls,
		resultCalls: &resultCalls,
		cancelCalls: &cancelCalls,
		statusResult: admission.ExecutionStatusResult{
			Success: true,
			RunID:   "run-0123456789abcdef",
			Status:  "running",
			LifecycleProjection: admission.LifecycleProjection{
				Source:   "nomad",
				Revision: "opaque-authority-read-token",
			},
			OutcomeEvidence: admission.ExecutionOutcomeEvidence{
				Source:      "nomad",
				Observation: "nomad_task_state_projection",
				LifecycleProjection: &admission.LifecycleProjection{
					Source:   "nomad",
					Revision: "opaque-authority-read-token",
				},
				ProviderTerminalObserved: boolPtr(false),
			},
			Terminal: false,
		},
		logsResult: admission.ExecutionLogsResult{
			OutcomeEvidence: admission.ExecutionOutcomeEvidence{
				Source:                   "nomad",
				Observation:              "nomad_task_stdout",
				AccessClass:              "plaintext_stdout",
				ProviderTerminalObserved: boolPtr(false),
			},
			Payload: []byte(logPayload),
		},
		resultBundle: admission.ExecutionResultBundle{
			MediaType: "application/gzip",
			OutcomeEvidence: admission.ExecutionOutcomeEvidence{
				Source:      "es_retained_result_store",
				Observation: "retained_result_bundle",
				AccessClass: "opaque_result_bundle",
			},
			Payload: resultPayload,
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
	if statusCalls != 1 || logsCalls != 0 || resultCalls != 0 || cancelCalls != 0 {
		t.Fatalf("status route must call only status service, got status=%d logs=%d result=%d cancel=%d", statusCalls, logsCalls, resultCalls, cancelCalls)
	}
	assertJSONFieldsExactForAPI(t, statusRecorder.Body.Bytes(),
		"success",
		"run_id",
		"status",
		"lifecycle_projection",
		"outcome_evidence",
		"terminal",
	)
	var statusPayload admission.ExecutionStatusResult
	if err := json.Unmarshal(statusRecorder.Body.Bytes(), &statusPayload); err != nil {
		t.Fatalf("decode status payload: %v", err)
	}
	if statusPayload.LifecycleProjection.Source != "nomad" ||
		statusPayload.LifecycleProjection.Revision != "opaque-authority-read-token" ||
		statusPayload.OutcomeEvidence.LifecycleProjection == nil ||
		*statusPayload.OutcomeEvidence.LifecycleProjection != statusPayload.LifecycleProjection {
		t.Fatalf("unexpected lifecycle projection authority labels %+v", statusPayload)
	}
	assertWorkstreamCLifecycleAuthorityEnvelopeOmitsForbidden(t, statusRecorder.Body.String())
	assertTextOmitsAllForAPI(t, statusRecorder.Body.String(),
		logPayload,
		string(resultPayload),
		`"retained_result_bundle":`,
		`"raw_logs":`,
		`"result_bundle":`,
	)

	logsRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(logsRecorder, authorizedLifecycleRequest(http.MethodGet, "/v1/executions/run-0123456789abcdef/logs"))
	if logsRecorder.Code != http.StatusOK {
		t.Fatalf("expected logs 200, got %d body=%s", logsRecorder.Code, logsRecorder.Body.String())
	}
	if statusCalls != 1 || logsCalls != 1 || resultCalls != 0 || cancelCalls != 0 {
		t.Fatalf("logs route must call only logs after status, got status=%d logs=%d result=%d cancel=%d", statusCalls, logsCalls, resultCalls, cancelCalls)
	}
	assertHeader(t, logsRecorder.Result(), "Content-Type", admission.LogsMediaType)
	assertHeader(t, logsRecorder.Result(), headerOutcomeSource, "nomad")
	assertHeader(t, logsRecorder.Result(), headerOutcomeObservation, "nomad_task_stdout")
	assertHeader(t, logsRecorder.Result(), headerOutcomeAccessClass, "plaintext_stdout")
	assertWorkstreamCLifecycleAuthorityHeaderOmitsForbidden(t, logsRecorder.Result().Header)
	if logsRecorder.Body.String() != logPayload {
		t.Fatalf("expected logs body to remain separate payload content, got %q", logsRecorder.Body.String())
	}
	assertTextOmitsAllForAPI(t, logsRecorder.Body.String(), string(resultPayload))

	resultRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(resultRecorder, authorizedLifecycleRequest(http.MethodGet, "/v1/executions/run-0123456789abcdef/result"))
	if resultRecorder.Code != http.StatusOK {
		t.Fatalf("expected result 200, got %d body=%s", resultRecorder.Code, resultRecorder.Body.String())
	}
	if statusCalls != 1 || logsCalls != 1 || resultCalls != 1 || cancelCalls != 0 {
		t.Fatalf("result route must call only result after status/logs, got status=%d logs=%d result=%d cancel=%d", statusCalls, logsCalls, resultCalls, cancelCalls)
	}
	assertHeader(t, resultRecorder.Result(), "Content-Type", "application/gzip")
	assertHeader(t, resultRecorder.Result(), headerOutcomeSource, "es_retained_result_store")
	assertHeader(t, resultRecorder.Result(), headerOutcomeObservation, "retained_result_bundle")
	assertHeader(t, resultRecorder.Result(), headerOutcomeAccessClass, "opaque_result_bundle")
	assertWorkstreamCLifecycleAuthorityHeaderOmitsForbidden(t, resultRecorder.Result().Header)
	if string(resultRecorder.Body.Bytes()) != string(resultPayload) {
		t.Fatalf("expected result body to remain separate opaque payload content, got %q", resultRecorder.Body.String())
	}
	assertTextOmitsAllForAPI(t, resultRecorder.Body.String(), logPayload)

	cancelRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(cancelRecorder, authorizedLifecycleRequest(http.MethodPost, "/v1/executions/run-0123456789abcdef:cancel"))
	if cancelRecorder.Code != http.StatusOK {
		t.Fatalf("expected cancel 200, got %d body=%s", cancelRecorder.Code, cancelRecorder.Body.String())
	}
	if statusCalls != 1 || logsCalls != 1 || resultCalls != 1 || cancelCalls != 1 {
		t.Fatalf("cancel route must call only cancel after status/logs/result, got status=%d logs=%d result=%d cancel=%d", statusCalls, logsCalls, resultCalls, cancelCalls)
	}
	assertJSONFieldsExactForAPI(t, cancelRecorder.Body.Bytes(), "success", "run_id", "status", "outcome_evidence")
	var cancelPayload admission.ExecutionCancelResult
	if err := json.Unmarshal(cancelRecorder.Body.Bytes(), &cancelPayload); err != nil {
		t.Fatalf("decode cancel payload: %v", err)
	}
	if cancelPayload.OutcomeEvidence.Source != "nomad" ||
		cancelPayload.OutcomeEvidence.Observation != "nomad_stop_request_accepted" ||
		cancelPayload.OutcomeEvidence.ProviderTerminalObserved == nil ||
		*cancelPayload.OutcomeEvidence.ProviderTerminalObserved {
		t.Fatalf("unexpected cancel authority labels %+v", cancelPayload)
	}
	assertWorkstreamCLifecycleAuthorityEnvelopeOmitsForbidden(t, cancelRecorder.Body.String())
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

func TestWorkstreamCProducerContractEndpointStaysReadOnlyProducerDeclaration(t *testing.T) {
	healthCalls := 0
	contractCalls := 0
	prepareCalls := 0
	submitCalls := 0
	statusCalls := 0
	logsCalls := 0
	resultCalls := 0
	cancelCalls := 0
	service := fakeLifecycleService{
		healthCalls:           &healthCalls,
		producerContractCalls: &contractCalls,
		prepareCalls:          &prepareCalls,
		submitCalls:           &submitCalls,
		statusCalls:           &statusCalls,
		logsCalls:             &logsCalls,
		resultCalls:           &resultCalls,
		cancelCalls:           &cancelCalls,
		producerContract: admission.ProducerContractDeclaration{
			SchemaVersion: "execution-substrate.producer-contract/v1",
			Service:       "execution",
			GovernedExecution: admission.GovernedExecutionProducerContractDeclaration{
				Contract: "governed-execution-producer/v1",
				Enabled:  true,
				RuntimeProfiles: []admission.ProducerRuntimeProfileDeclaration{
					{Name: "static-script/default", Status: "enabled"},
					{Name: "control-plane-normal-shell/v1", Status: "enabled"},
				},
				OutcomeEvidence: admission.ProducerOutcomeEvidenceDeclaration{
					Required: true,
					StatusJSON: admission.ProducerOutcomeEvidenceSurfaceDeclaration{
						Required: true,
						Carrier:  "json_field",
						Field:    "outcome_evidence",
						Source:   "nomad",
					},
					CancelJSON: admission.ProducerOutcomeEvidenceSurfaceDeclaration{
						Required: true,
						Carrier:  "json_field",
						Field:    "outcome_evidence",
						Source:   "nomad",
					},
					LogsHeaders: admission.ProducerOutcomeEvidenceSurfaceDeclaration{
						Required:    true,
						Carrier:     "http_headers",
						MediaType:   admission.LogsMediaType,
						Source:      "nomad",
						AccessClass: "plaintext_stdout",
					},
					ResultHeaders: admission.ProducerOutcomeEvidenceSurfaceDeclaration{
						Required:    true,
						Carrier:     "http_headers",
						MediaType:   "application/gzip",
						Source:      "es_retained_result_store",
						AccessClass: "opaque_result_bundle",
					},
				},
			},
			NonAuthority: []string{
				"not_service_health",
				"not_submit_readiness",
				"not_artifact_admission_proof",
				"not_run_authority",
				"not_run_existence_proof",
				"not_lifecycle_truth",
				"not_lifecycle_write_coordination",
				"not_credential_truth",
				"not_policy_truth",
				"not_scheduler_api",
			},
		},
	}
	server := NewServer(service, "bootstrap", []string{"operator/local"}, func() bool { return true })

	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, authorizedLifecycleRequest(http.MethodGet, "/v1/executions:contract"))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected contract probe 200, got %d body=%s", recorder.Code, recorder.Body.String())
	}
	assertJSONFieldsExactForAPI(t, recorder.Body.Bytes(), "schema_version", "service", "governed_execution", "non_authority")
	if contractCalls != 1 {
		t.Fatalf("expected exactly one producer contract call, got %d", contractCalls)
	}
	for name, calls := range map[string]int{
		"health":  healthCalls,
		"prepare": prepareCalls,
		"submit":  submitCalls,
		"status":  statusCalls,
		"logs":    logsCalls,
		"result":  resultCalls,
		"cancel":  cancelCalls,
	} {
		if calls != 0 {
			t.Fatalf("contract endpoint must not call %s, got %d calls", name, calls)
		}
	}

	body := recorder.Body.String()
	assertTextOmitsAllForAPI(t, body,
		`"ready":`,
		`"health":`,
		`"submit_ready":`,
		`"run_id":`,
		`"status": "running"`,
		`"lifecycle_projection":`,
		`"authority_handoff":`,
		`"nomad_job_id":`,
		`"job_id":`,
		`"allocation_id":`,
		`"task_id":`,
		`"scheduler_id":`,
		`"vault_token":`,
		`"client_token":`,
		`"jwt_svid":`,
		`"x509_svid":`,
		`"private_key":`,
		`"pem_body":`,
		`"raw_cert_body":`,
		`"env":`,
		`"endpoint_secret":`,
		`"raw_payload":`,
		`"raw_logs":`,
		`"support_bundle_payload":`,
		`"proof_payload":`,
		`"host_path":`,
		`"result_path":`,
		`"workflow":`,
		`"checkpoint":`,
		`"finalization":`,
	)
	for _, required := range []string{
		"not_service_health",
		"not_submit_readiness",
		"not_run_existence_proof",
		"not_scheduler_api",
		"control-plane-normal-shell/v1",
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("expected contract declaration to include %q, got %s", required, body)
		}
	}
}

func TestWorkstreamCContractPrepareAndSubmitRemainSeparatedAtAPIBoundary(t *testing.T) {
	contractCalls := 0
	prepareCalls := 0
	submitCalls := 0
	var prepareRequest admission.PrepareRequest
	service := fakeLifecycleService{
		producerContractCalls: &contractCalls,
		prepareCalls:          &prepareCalls,
		submitCalls:           &submitCalls,
		prepareRequestSink:    &prepareRequest,
		producerContract: admission.ProducerContractDeclaration{
			SchemaVersion: "execution-substrate.producer-contract/v1",
			Service:       "execution",
			GovernedExecution: admission.GovernedExecutionProducerContractDeclaration{
				Contract: "governed-execution-producer/v1",
				Enabled:  true,
			},
			NonAuthority: []string{"not_submit_readiness", "not_run_existence_proof"},
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
	}
	server := NewServer(service, "bootstrap", []string{"operator/local"}, func() bool { return true })

	contractRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(contractRecorder, authorizedLifecycleRequest(http.MethodGet, "/v1/executions:contract"))
	if contractRecorder.Code != http.StatusOK {
		t.Fatalf("expected contract 200, got %d body=%s", contractRecorder.Code, contractRecorder.Body.String())
	}
	if contractCalls != 1 || prepareCalls != 0 || submitCalls != 0 {
		t.Fatalf("contract must not imply prepare or submit, got contract=%d prepare=%d submit=%d", contractCalls, prepareCalls, submitCalls)
	}

	body := `{"schema_version":"v1","invocation":{"schema_version":"v1","artifact_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","derivation_spec_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","output_id":"runtime","annotations":{"execution_substrate.runtime_profile":"control-plane-normal-shell/v1"}},"mode":"async"}`
	prepareRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(prepareRecorder, authorizedLifecycleRequestWithBody(http.MethodPost, "/v1/executions:prepare", body))
	if prepareRecorder.Code != http.StatusOK {
		t.Fatalf("expected prepare 200, got %d body=%s", prepareRecorder.Code, prepareRecorder.Body.String())
	}
	if prepareCalls != 1 || submitCalls != 0 {
		t.Fatalf("prepare must not submit, got prepare=%d submit=%d", prepareCalls, submitCalls)
	}
	if prepareRequest.Invocation.Annotations["execution_substrate.runtime_profile"] != "control-plane-normal-shell/v1" {
		t.Fatalf("prepare must preserve runtime-profile annotation, got %+v", prepareRequest.Invocation.Annotations)
	}
	assertJSONFieldsExactForAPI(t, prepareRecorder.Body.Bytes(), "success")
	assertTextOmitsAllForAPI(t, prepareRecorder.Body.String(),
		`"run_id":`,
		`"submitted":`,
		`"status":`,
		`"authority_handoff":`,
		`"lifecycle_projection":`,
		`"outcome_evidence":`,
		`"retained_result_bundle":`,
		`"nomad_job_id":`,
		`"allocation_id":`,
		`"scheduler_id":`,
		`"workflow":`,
		`"checkpoint":`,
		`"finalization":`,
	)
}

func TestWorkstreamCPrepareFailureEnvelopeIsAdmissionBoundaryNotCPRunFailure(t *testing.T) {
	prepareCalls := 0
	submitCalls := 0
	server := NewServer(fakeLifecycleService{
		prepareCalls: &prepareCalls,
		submitCalls:  &submitCalls,
		prepareErr: &admission.Error{
			Status:  http.StatusBadRequest,
			Code:    "unsupported_runtime_profile",
			Message: "unsupported runtime profile",
		},
	}, "bootstrap", []string{"operator/local"}, func() bool { return true })

	body := `{"schema_version":"v1","invocation":{"schema_version":"v1","artifact_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","derivation_spec_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","output_id":"runtime","annotations":{"execution_substrate.runtime_profile":"unsupported/v1"}},"mode":"async"}`
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, authorizedLifecycleRequestWithBody(http.MethodPost, "/v1/executions:prepare", body))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected prepare runtime profile rejection 400, got %d body=%s", recorder.Code, recorder.Body.String())
	}
	if prepareCalls != 1 || submitCalls != 0 {
		t.Fatalf("prepare failure must not submit, got prepare=%d submit=%d", prepareCalls, submitCalls)
	}
	assertJSONFieldsExactForAPI(t, recorder.Body.Bytes(), "success", "error", "code")
	var payload admission.ErrorResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode prepare failure envelope: %v", err)
	}
	if payload.Success || payload.Code != "unsupported_runtime_profile" {
		t.Fatalf("unexpected prepare failure envelope %+v", payload)
	}
	assertTextOmitsAllForAPI(t, recorder.Body.String(),
		`"run_id":`,
		`"status":`,
		`"terminal":`,
		`"exit_code":`,
		`"submitted":`,
		`"authority_handoff":`,
		`"lifecycle_projection":`,
		`"outcome_evidence":`,
		`"provider_run_id":`,
		`"workflow":`,
		`"checkpoint":`,
		`"finalization":`,
		`"review":`,
		`"approval":`,
		`"nomad_job_id":`,
		`"allocation_id":`,
		`"scheduler_id":`,
		`"vault_token":`,
		`"private_key":`,
		`"raw_payload":`,
		`"raw_logs":`,
	)
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

func TestAdmissionPolicyPrepareAndSubmitErrorsUseRedactedEnvelope(t *testing.T) {
	rawFixture := apiPolicyFixtureText()
	body := `{"schema_version":"v1","invocation":{"schema_version":"v1","artifact_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","derivation_spec_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","output_id":"runtime"},"mode":"async"}`
	policyErr := &admission.Error{
		Status:  http.StatusForbidden,
		Code:    "destructive_shell_command_denied",
		Message: "destructive shell command denied by admission policy",
	}
	server := NewServer(fakeLifecycleService{
		prepareErr: policyErr,
		submitErr:  policyErr,
	}, "bootstrap", []string{"operator/local"}, func() bool { return true })

	prepareRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(prepareRecorder, authorizedLifecycleRequestWithBody(http.MethodPost, "/v1/executions:prepare", body))
	if prepareRecorder.Code != http.StatusForbidden {
		t.Fatalf("expected prepare policy denial 403, got %d", prepareRecorder.Code)
	}
	assertJSONFieldsExactForAPI(t, prepareRecorder.Body.Bytes(), "success", "error", "code")
	assertPolicyErrorEnvelopeForAPI(t, prepareRecorder.Body.String(), rawFixture)

	submitRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(submitRecorder, authorizedLifecycleRequestWithBody(http.MethodPost, "/v1/executions:submit", body))
	if submitRecorder.Code != http.StatusForbidden {
		t.Fatalf("expected submit policy denial 403, got %d", submitRecorder.Code)
	}
	assertJSONFieldsExactForAPI(t, submitRecorder.Body.Bytes(), "success", "error", "code")
	assertPolicyErrorEnvelopeForAPI(t, submitRecorder.Body.String(), rawFixture)
}

func TestConfiguredAdmissionPolicyPrepareAndSubmitErrorsUseRedactedEnvelope(t *testing.T) {
	rawFixture := apiConfiguredPolicyFixtureText()
	body := `{"schema_version":"v1","invocation":{"schema_version":"v1","artifact_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","derivation_spec_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","output_id":"runtime"},"mode":"async"}`
	policyErr := &admission.Error{
		Status:  http.StatusForbidden,
		Code:    "configured_static_script_content_denied",
		Message: "static script content denied by admission policy",
	}
	server := NewServer(fakeLifecycleService{
		prepareErr: policyErr,
		submitErr:  policyErr,
	}, "bootstrap", []string{"operator/local"}, func() bool { return true })

	prepareRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(prepareRecorder, authorizedLifecycleRequestWithBody(http.MethodPost, "/v1/executions:prepare", body))
	if prepareRecorder.Code != http.StatusForbidden {
		t.Fatalf("expected prepare configured policy denial 403, got %d", prepareRecorder.Code)
	}
	assertJSONFieldsExactForAPI(t, prepareRecorder.Body.Bytes(), "success", "error", "code")
	assertConfiguredPolicyErrorEnvelopeForAPI(t, prepareRecorder.Body.String(), rawFixture)

	submitRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(submitRecorder, authorizedLifecycleRequestWithBody(http.MethodPost, "/v1/executions:submit", body))
	if submitRecorder.Code != http.StatusForbidden {
		t.Fatalf("expected submit configured policy denial 403, got %d", submitRecorder.Code)
	}
	assertJSONFieldsExactForAPI(t, submitRecorder.Body.Bytes(), "success", "error", "code")
	assertConfiguredPolicyErrorEnvelopeForAPI(t, submitRecorder.Body.String(), rawFixture)
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
	logsResult            admission.ExecutionLogsResult
	resultBundle          admission.ExecutionResultBundle
	statusResult          admission.ExecutionStatusResult
	cancelResult          admission.ExecutionCancelResult
	producerContract      admission.ProducerContractDeclaration
	prepareResult         admission.PrepareResult
	submitResult          admission.SubmitResult
	prepareErr            *admission.Error
	submitErr             *admission.Error
	prepareRequestSink    *admission.PrepareRequest
	submitRequestSink     *admission.PrepareRequest
	healthCalls           *int
	producerContractCalls *int
	prepareCalls          *int
	submitCalls           *int
	statusCalls           *int
	logsCalls             *int
	resultCalls           *int
	cancelCalls           *int
}

func (f fakeLifecycleService) Health(context.Context) admission.HealthSnapshot {
	if f.healthCalls != nil {
		*f.healthCalls = *f.healthCalls + 1
	}
	return admission.HealthSnapshot{}
}

func (f fakeLifecycleService) ProducerContract(context.Context) admission.ProducerContractDeclaration {
	if f.producerContractCalls != nil {
		*f.producerContractCalls = *f.producerContractCalls + 1
	}
	return f.producerContract
}

func (f fakeLifecycleService) Prepare(_ context.Context, request admission.PrepareRequest) (admission.PrepareResult, *admission.Error) {
	if f.prepareCalls != nil {
		*f.prepareCalls = *f.prepareCalls + 1
	}
	if f.prepareRequestSink != nil {
		*f.prepareRequestSink = request
	}
	if f.prepareErr != nil {
		return admission.PrepareResult{}, f.prepareErr
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
	if f.submitErr != nil {
		return admission.SubmitResult{}, f.submitErr
	}
	return f.submitResult, nil
}

func (f fakeLifecycleService) Status(context.Context, string) (admission.ExecutionStatusResult, *admission.Error) {
	if f.statusCalls != nil {
		*f.statusCalls = *f.statusCalls + 1
	}
	return f.statusResult, nil
}

func (f fakeLifecycleService) Logs(context.Context, string) (admission.ExecutionLogsResult, *admission.Error) {
	if f.logsCalls != nil {
		*f.logsCalls = *f.logsCalls + 1
	}
	return f.logsResult, nil
}

func (f fakeLifecycleService) Result(context.Context, string) (admission.ExecutionResultBundle, *admission.Error) {
	if f.resultCalls != nil {
		*f.resultCalls = *f.resultCalls + 1
	}
	return f.resultBundle, nil
}

func (f fakeLifecycleService) Cancel(context.Context, string) (admission.ExecutionCancelResult, *admission.Error) {
	if f.cancelCalls != nil {
		*f.cancelCalls = *f.cancelCalls + 1
	}
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

func assertPolicyErrorEnvelopeForAPI(t *testing.T, body string, rawFixture string) {
	t.Helper()

	var payload admission.ErrorResponse
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("decode policy error envelope: %v", err)
	}
	if payload.Success || payload.Error != "destructive shell command denied by admission policy" || payload.Code != "destructive_shell_command_denied" {
		t.Fatalf("unexpected policy error envelope success=%t code=%q message=%q", payload.Success, payload.Code, payload.Error)
	}
	if strings.Contains(body, rawFixture) {
		t.Fatal("expected policy error envelope to omit raw policy fixture content")
	}
	assertTextOmitsAllForAPI(t, body,
		`"policy_id"`,
		`"matched"`,
		`"prompt"`,
		`"workspace"`,
		`"model_output"`,
		`"logs"`,
		`"result_bundle"`,
		`"support_bundle"`,
	)
}

func assertConfiguredPolicyErrorEnvelopeForAPI(t *testing.T, body string, rawFixture string) {
	t.Helper()

	var payload admission.ErrorResponse
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("decode configured policy error envelope: %v", err)
	}
	if payload.Success || payload.Error != "static script content denied by admission policy" || payload.Code != "configured_static_script_content_denied" {
		t.Fatalf("unexpected configured policy error envelope success=%t code=%q message=%q", payload.Success, payload.Code, payload.Error)
	}
	if strings.Contains(body, rawFixture) {
		t.Fatal("expected configured policy error envelope to omit configured literal content")
	}
	assertTextOmitsAllForAPI(t, body,
		`"policy_id"`,
		`"matched"`,
		`"prompt"`,
		`"workspace"`,
		`"model_output"`,
		`"logs"`,
		`"result_bundle"`,
		`"support_bundle"`,
	)
}

func apiPolicyFixtureText() string {
	return strings.Join([]string{
		"#!/bin/sh",
		strings.Join([]string{"r", "m"}, ""),
		"-rf",
		"/",
		"# inert API redaction fixture; never executed",
	}, "\n")
}

func apiConfiguredPolicyFixtureText() string {
	return "ES_DEMO_LITERAL_MARKER"
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

func assertWorkstreamC5EnvelopeOmitsRunControlCredentialAndBackendAuthority(t *testing.T, text string) {
	t.Helper()

	assertTextOmitsAllForAPI(t, text, workstreamC5ForbiddenEnvelopeTermsForAPI()...)
	assertTextOmitsAllForAPI(t, text,
		"exec-run-0123456789abcdef",
		"alloc-",
		`"nomad_job_id":`,
		`"job_id":`,
		`"allocation_id":`,
		`"task_id":`,
		`"scheduler_id":`,
		`"write_guard":`,
		`"write_precondition":`,
		`"lifecycle_store":`,
		`"retained_result_id":`,
	)
}

func assertWorkstreamC5HeaderOmitsRunControlCredentialAndBackendAuthority(t *testing.T, header http.Header) {
	t.Helper()

	assertTextOmitsAllForAPI(t, compactHeaderText(header), workstreamC5ForbiddenHeaderTermsForAPI()...)
}

func workstreamC5ForbiddenEnvelopeTermsForAPI() []string {
	terms := []string{
		`"review":`,
		`"checkpoint":`,
		`"finalization":`,
		`"intervention":`,
		`"approval":`,
		`"hold":`,
		`"resume":`,
		`"reject":`,
		`"temporal":`,
		`"Temporal":`,
		`"workflow":`,
		`"workflow_id":`,
		`"cp_workflow_id":`,
	}
	for _, field := range workstreamC5ForbiddenCredentialFieldNamesForAPI() {
		terms = append(terms, `"`+field+`":`)
	}
	return terms
}

func workstreamC5ForbiddenHeaderTermsForAPI() []string {
	return append([]string{
		"review",
		"checkpoint",
		"finalization",
		"intervention",
		"approval",
		"hold",
		"resume",
		"reject",
		"Temporal",
		"workflow",
		"nomad_job_id",
		"job_id",
		"allocation_id",
		"task_id",
		"scheduler_id",
		"write_guard",
		"lifecycle_store",
		"retained_result_id",
	}, workstreamC5ForbiddenCredentialFieldNamesForAPI()...)
}

func workstreamC5ForbiddenCredentialFieldNamesForAPI() []string {
	return []string{
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
	}
}

func assertWorkstreamCLifecycleAuthorityEnvelopeOmitsForbidden(t *testing.T, text string) {
	t.Helper()

	assertTextOmitsAllForAPI(t, text, workstreamCLifecycleAuthorityForbiddenJSONTermsForAPI()...)
	assertTextOmitsAllForAPI(t, text,
		"exec-run-0123456789abcdef",
		"alloc-",
		"cp-workflow-version",
		"global_freshness",
		"support payload",
		"proof payload",
	)
}

func assertWorkstreamCLifecycleAuthorityHeaderOmitsForbidden(t *testing.T, header http.Header) {
	t.Helper()

	assertTextOmitsAllForAPI(t, compactHeaderText(header), workstreamCLifecycleAuthorityForbiddenHeaderTermsForAPI()...)
}

func workstreamCLifecycleAuthorityForbiddenJSONTermsForAPI() []string {
	fields := []string{
		"nomad_job_id",
		"job_id",
		"allocation_id",
		"nomad_allocation_id",
		"task_id",
		"scheduler_id",
		"scheduler_revision",
		"lifecycle_store",
		"write_guard",
		"write_precondition",
		"cp_workflow_id",
		"cp_workflow_version",
		"workflow_version",
		"workflow_revision",
		"cp_workflow_revision",
		"global_freshness",
		"freshness_proof",
		"retained_result_id",
		"retained_result_path",
		"retained_bundle_internals",
		"support_payload",
		"proof_payload",
		"env_values",
		"endpoint_secret",
		"pem_body",
		"raw_cert_body",
		"vault_token",
		"client_token",
		"root_token",
		"unseal_key",
		"jwt_svid",
		"x509_svid",
		"private_key",
		"api_key",
	}
	terms := make([]string, 0, len(fields))
	for _, field := range fields {
		terms = append(terms, `"`+field+`":`)
	}
	return terms
}

func workstreamCLifecycleAuthorityForbiddenHeaderTermsForAPI() []string {
	return []string{
		"nomad_job_id",
		"job_id",
		"allocation_id",
		"nomad_allocation_id",
		"task_id",
		"scheduler_id",
		"scheduler_revision",
		"lifecycle_store",
		"write_guard",
		"write_precondition",
		"cp_workflow_id",
		"cp_workflow_version",
		"workflow_version",
		"workflow_revision",
		"cp_workflow_revision",
		"global_freshness",
		"freshness_proof",
		"retained_result_id",
		"retained_result_path",
		"retained_bundle_internals",
		"support_payload",
		"proof_payload",
		"env_values",
		"endpoint_secret",
		"pem_body",
		"raw_cert_body",
		"vault_token",
		"client_token",
		"root_token",
		"unseal_key",
		"jwt_svid",
		"x509_svid",
		"private_key",
		"api_key",
	}
}
