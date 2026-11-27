package admission

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	esconfig "execution-substrate/es/config"
)

func TestProducerContractDeclarationRequiresGovernedOutcomeEvidence(t *testing.T) {
	service := Service{cfg: producerContractSubmitConfig(true)}

	declaration := service.ProducerContract(context.Background())

	if declaration.SchemaVersion != "execution-substrate.producer-contract/v1" {
		t.Fatalf("unexpected schema version %q", declaration.SchemaVersion)
	}
	if declaration.Service != "execution" {
		t.Fatalf("unexpected service %q", declaration.Service)
	}
	if declaration.GovernedExecution.Contract != "governed-execution-producer/v1" {
		t.Fatalf("unexpected contract %q", declaration.GovernedExecution.Contract)
	}
	if !declaration.GovernedExecution.Enabled || declaration.GovernedExecution.DisabledReason != "" {
		t.Fatalf("expected governed execution enabled, got %+v", declaration.GovernedExecution)
	}

	assertRuntimeProfileStatus(t, declaration.GovernedExecution.RuntimeProfiles, runtimeProfileDefaultStaticScript, "enabled")
	assertRuntimeProfileStatus(t, declaration.GovernedExecution.RuntimeProfiles, runtimeProfileControlPlaneNormalShell, "enabled")

	evidence := declaration.GovernedExecution.OutcomeEvidence
	if !evidence.Required {
		t.Fatalf("expected outcome evidence contract to be required")
	}
	assertEvidenceSurface(t, evidence.StatusJSON, "json_field", "outcome_evidence", "", outcomeEvidenceSourceNomad, "", []string{
		outcomeObservationNomadJobProjection,
		outcomeObservationNomadProjectedAllocation,
		outcomeObservationNomadTaskStateProjection,
	})
	assertContainsAll(t, evidence.StatusJSON.RequiredFields, []string{"source", "observation", "lifecycle_projection", "provider_terminal_observed"})
	assertEvidenceSurface(t, evidence.CancelJSON, "json_field", "outcome_evidence", "", outcomeEvidenceSourceNomad, "", []string{
		outcomeObservationNomadStopAccepted,
	})
	assertContainsAll(t, evidence.CancelJSON.RequiredFields, []string{"source", "observation", "provider_terminal_observed"})
	assertEvidenceSurface(t, evidence.LogsHeaders, "http_headers", "", "text/plain; charset=utf-8", outcomeEvidenceSourceNomad, outcomeAccessClassPlaintextStdout, []string{
		outcomeObservationNomadTaskStdout,
	})
	assertContainsAll(t, evidence.LogsHeaders.RequiredHeaders, []string{OutcomeHeaderSource, OutcomeHeaderObservation, OutcomeHeaderAccessClass, OutcomeHeaderProviderTerminalObserved})
	assertEvidenceSurface(t, evidence.ResultHeaders, "http_headers", "", resultBundleMediaType, outcomeEvidenceSourceRetainedResultStore, outcomeAccessClassOpaqueResultBundle, []string{
		outcomeObservationRetainedResultBundle,
	})
	assertContainsAll(t, evidence.ResultHeaders.RequiredHeaders, []string{OutcomeHeaderSource, OutcomeHeaderObservation, OutcomeHeaderAccessClass})

	for _, required := range []string{
		"not_service_health",
		"not_submit_readiness",
		"not_artifact_admission_proof",
		"not_run_authority",
		"not_run_existence_proof",
		"not_lifecycle_truth",
		"not_credential_truth",
		"not_lifecycle_write_coordination",
		"not_policy_truth",
		"not_scheduler_api",
	} {
		if !containsString(declaration.NonAuthority, required) {
			t.Fatalf("expected non_authority to include %q, got %v", required, declaration.NonAuthority)
		}
	}
}

func TestProducerContractOutcomeEvidenceMatchesCurrentResponseEvidence(t *testing.T) {
	declaration := producerOutcomeEvidenceDeclaration()
	projection := LifecycleProjection{
		Source:   lifecycleProjectionSourceNomad,
		Revision: "opaque-same-run-read-token",
	}

	for _, observation := range []string{
		outcomeObservationNomadJobProjection,
		outcomeObservationNomadProjectedAllocation,
		outcomeObservationNomadTaskStateProjection,
	} {
		evidence := statusOutcomeEvidence(observation, projection, observation == outcomeObservationNomadTaskStateProjection)
		assertDeclaredEvidenceMatchesRuntimeEvidence(t, declaration.StatusJSON, evidence)
		if evidence.LifecycleProjection == nil || *evidence.LifecycleProjection != projection {
			t.Fatalf("expected status evidence to carry lifecycle projection, got %+v", evidence)
		}
		assertContainsAll(t, declaration.StatusJSON.RequiredFields, []string{"source", "observation", "lifecycle_projection", "provider_terminal_observed"})
	}

	cancelEvidence := cancelOutcomeEvidence()
	assertDeclaredEvidenceMatchesRuntimeEvidence(t, declaration.CancelJSON, cancelEvidence)
	if cancelEvidence.ProviderTerminalObserved == nil || *cancelEvidence.ProviderTerminalObserved {
		t.Fatalf("expected cancel evidence to avoid terminal-completion claim, got %+v", cancelEvidence)
	}
	assertContainsAll(t, declaration.CancelJSON.RequiredFields, []string{"source", "observation", "provider_terminal_observed"})

	logsEvidence := logsOutcomeEvidence(false)
	assertDeclaredEvidenceMatchesRuntimeEvidence(t, declaration.LogsHeaders, logsEvidence)
	if declaration.LogsHeaders.MediaType != LogsMediaType {
		t.Fatalf("expected logs media type %q, got %q", LogsMediaType, declaration.LogsHeaders.MediaType)
	}
	assertContainsAll(t, declaration.LogsHeaders.RequiredHeaders, []string{
		OutcomeHeaderSource,
		OutcomeHeaderObservation,
		OutcomeHeaderAccessClass,
		OutcomeHeaderProviderTerminalObserved,
	})

	resultEvidence := retainedResultOutcomeEvidence()
	assertDeclaredEvidenceMatchesRuntimeEvidence(t, declaration.ResultHeaders, resultEvidence)
	if declaration.ResultHeaders.MediaType != resultBundleMediaType {
		t.Fatalf("expected result media type %q, got %q", resultBundleMediaType, declaration.ResultHeaders.MediaType)
	}
	assertContainsAll(t, declaration.ResultHeaders.RequiredHeaders, []string{
		OutcomeHeaderSource,
		OutcomeHeaderObservation,
		OutcomeHeaderAccessClass,
	})
}

func TestProducerContractDeclarationDoesNotExposeAuthorityOrSchedulerClaims(t *testing.T) {
	declaration := producerContractDeclaration(producerContractSubmitConfig(true))
	payload, err := json.Marshal(declaration)
	if err != nil {
		t.Fatalf("marshal producer declaration: %v", err)
	}
	text := string(payload)

	for _, forbidden := range []string{
		"nomad_job_id",
		"allocation_id",
		"task_id",
		"scheduler_id",
		"decision_id",
		"vault_token",
		"codex_token",
		"jwt_svid",
		"authority_handoff",
		"runtime_auth_plan",
		"auth_mount",
		"auth_role",
		"jwt_audience",
		"lease",
		"policy_approval",
		"write_precondition",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("producer declaration must not expose %q: %s", forbidden, text)
		}
	}
}

func TestProducerContractDeclarationIsReadOnlyAndDoesNotCreateRunState(t *testing.T) {
	cfg := producerContractSubmitConfig(true)
	root := t.TempDir()
	stagingRoot := root + "/staging"
	resultsRoot := root + "/results"
	cfg.Execution.StagingRootDir = stagingRoot
	cfg.Execution.ResultsRootDir = resultsRoot

	service := Service{
		cfg: cfg,
		arsClient: newArtifactRegistryTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("producer contract must not read ARS, got %s %q", r.Method, r.URL.Path)
		})),
		nomadClient: newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("producer contract must not contact Nomad, got %s %q", r.Method, r.URL.Path)
		})),
	}

	declaration := service.ProducerContract(context.Background())
	if !declaration.GovernedExecution.Enabled {
		t.Fatalf("expected configured producer declaration to stay enabled, got %+v", declaration.GovernedExecution)
	}
	for _, path := range []string{stagingRoot, resultsRoot} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("producer contract must not create execution state directory %s; stat err=%v", path, err)
		}
	}
}

func TestProducerContractSuccessDoesNotImplyPrepareSuccessOrSubmitReadiness(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service := Service{cfg: producerContractSubmitConfig(true)}

	declaration := service.ProducerContract(context.Background())
	if !declaration.GovernedExecution.Enabled ||
		declaration.GovernedExecution.Contract != governedExecutionProducerContract {
		t.Fatalf("expected successful producer declaration, got %+v", declaration)
	}

	_, err := service.Prepare(testCallerContext(), fixture.prepareRequest())
	assertAdmissionError(t, err, http.StatusServiceUnavailable, "trust_model_unavailable")
}

func TestProducerContractPublicDTOStaysNarrowProducerDeclarationOnly(t *testing.T) {
	fieldNames := collectJSONFieldNames(t,
		ProducerContractDeclaration{},
		GovernedExecutionProducerContractDeclaration{},
		ProducerRuntimeProfileDeclaration{},
		ProducerOutcomeEvidenceDeclaration{},
		ProducerOutcomeEvidenceSurfaceDeclaration{},
	)

	// Each compatibility field where the declaration writes it today: another
	// case, a lost tag, another object or a name clash would break a reader.
	compatibilityPaths := []string{
		"schema_version",
		"service",
		"non_authority",
		"governed_execution",
		"governed_execution.contract",
		"governed_execution.enabled",
		"governed_execution.disabled_reason",
		"governed_execution.runtime_profiles",
		"governed_execution.runtime_profiles[].name",
		"governed_execution.runtime_profiles[].status",
		"governed_execution.runtime_profiles[].disabled_reason",
		"governed_execution.outcome_evidence",
		"governed_execution.outcome_evidence.required",
	}
	for _, surface := range []string{"status_json", "cancel_json", "logs_headers", "result_headers"} {
		surfacePath := "governed_execution.outcome_evidence." + surface
		compatibilityPaths = append(compatibilityPaths, surfacePath)
		for _, key := range []string{
			"carrier",
			"field",
			"media_type",
			"required",
			"required_fields",
			"required_headers",
			"source",
			"observations",
			"access_class",
		} {
			compatibilityPaths = append(compatibilityPaths, surfacePath+"."+key)
		}
	}
	assertJSONKeyPathsWritten(t, ProducerContractDeclaration{}, "producer declaration compatibility field", compatibilityPaths...)

	for _, forbidden := range []string{
		"health",
		"ready",
		"readiness",
		"submit_ready",
		"run_id",
		"run_exists",
		"job_id",
		"nomad_job_id",
		"allocation_id",
		"task_id",
		"scheduler_id",
		"provider_run_id",
		"authority_handoff",
		"runtime_auth_plan",
		"credential",
		"credential_material",
		"secret",
		"token",
		"lease",
		"pem_body",
		"raw_cert_body",
		"private_key",
		"env",
		"raw_payload",
		"raw_log",
		"support_bundle",
		"proof_payload",
		"retained_bundle_payload",
		"path",
		"workflow",
		"checkpoint",
		"finalization",
	} {
		if fieldNames.accepts(forbidden) {
			t.Fatalf("producer declaration DTO must not expose authority/readiness/security field %q", forbidden)
		}
	}
}

func TestProducerContractRuntimeProfileMatrixStaysBoundedAndNonSecret(t *testing.T) {
	cfg := producerContractSubmitConfig(true)
	cfg.Execution.RuntimeProfiles.ControlPlaneNormalShell.Image = "execution-substrate/control-plane-normal-shell:supported-local"
	cfg.Execution.RuntimeProfiles.ControlPlaneNormalShell.CodexCLIPath = "/usr/local/bin/codex"
	cfg.Execution.RuntimeProfiles.ControlPlaneNormalShell.CredentialVaultSecretPath = "proof-secrets/data/codex-runtime-profile"
	cfg.Execution.RuntimeProfiles.ControlPlaneNormalShell.CredentialVaultSecretField = "api_key"

	declaration := producerContractDeclaration(cfg)
	profiles := declaration.GovernedExecution.RuntimeProfiles
	if len(profiles) != 2 {
		t.Fatalf("producer contract must declare only the bounded current runtime profiles, got %+v", profiles)
	}
	assertRuntimeProfileStatus(t, profiles, runtimeProfileDefaultStaticScript, "enabled")
	assertRuntimeProfileStatus(t, profiles, runtimeProfileControlPlaneNormalShell, "enabled")

	payload := mustMarshalWorkstreamCTestJSON(t, declaration)
	assertTextOmitsAll(t, payload,
		"execution-substrate/control-plane-normal-shell:supported-local",
		"/usr/local/bin/codex",
		"proof-secrets/data/codex-runtime-profile",
		"api_key",
		`"image":`,
		`"codex_cli_path":`,
		`"credential_vault_secret_path":`,
		`"credential_vault_secret_field":`,
		`"package_kind":`,
		`"runtime_auth_plan":`,
		`"credential_material":`,
		`"secret_material":`,
		`"cp_workflow_id":`,
		`"review":`,
		`"checkpoint":`,
		`"finalization":`,
	)
}

func TestProducerContractDeclarationDoesNotExposeSecretPayloadOrPathMaterial(t *testing.T) {
	cfg := producerContractSubmitConfig(true)
	cfg.Execution.SPIREWorkloadAPISocketPath = "/run/spire/sockets/agent.sock"
	cfg.Execution.RuntimeProfiles.ControlPlaneNormalShell.CredentialVaultSecretPath = "proof-secrets/data/codex-runtime-profile"
	cfg.Execution.RuntimeProfiles.ControlPlaneNormalShell.CredentialVaultSecretField = "api_key"

	payload := mustMarshalWorkstreamCTestJSON(t, producerContractDeclaration(cfg))
	assertTextOmitsAll(t, payload,
		"proof-secrets/data/codex-runtime-profile",
		"api_key",
		"/run/spire/sockets/agent.sock",
		"-----BEGIN",
		"BEGIN CERTIFICATE",
		"BEGIN PRIVATE KEY",
		`"private_key":`,
		`"pem_body":`,
		`"raw_cert_body":`,
		`"env":`,
		`"endpoint_secret":`,
		`"vault_token":`,
		`"client_token":`,
		`"root_token":`,
		`"unseal_key":`,
		`"jwt_svid":`,
		`"x509_svid":`,
		`"lease_id":`,
		`"lease_duration":`,
		`"raw_payload":`,
		`"raw_logs":`,
		`"support_bundle_payload":`,
		`"proof_payload":`,
		`"retained_bundle_payload":`,
		`"host_path":`,
		`"result_path":`,
	)
}

func TestProducerContractDeclarationDoesNotExposeConfiguredAdmissionPolicyLiteral(t *testing.T) {
	cfg := producerContractSubmitConfig(true)
	cfg.AdmissionPolicy = &esconfig.AdmissionPolicyConfig{
		ConfiguredStaticScriptLiteralDeny: &esconfig.ConfiguredStaticScriptLiteralDenyPolicyConfig{
			Mode: esconfig.ConfiguredStaticScriptLiteralDenyModeEnforce,
			Entries: []esconfig.ConfiguredStaticScriptLiteralDenyEntryConfig{
				{
					ID:         "demo-marker",
					InputClass: esconfig.ConfiguredStaticScriptLiteralDenyInputClassStaticScriptPayloadText,
					Literal:    configuredPolicyFixtureMarker(),
				},
			},
		},
	}
	declaration := producerContractDeclaration(cfg)
	payload, err := json.Marshal(declaration)
	if err != nil {
		t.Fatalf("marshal producer declaration: %v", err)
	}
	if strings.Contains(string(payload), configuredPolicyFixtureMarker()) {
		t.Fatalf("producer declaration must not expose configured admission policy literal")
	}
}

func TestProducerContractDeclarationMarksSubmitlessServiceDisabled(t *testing.T) {
	service := Service{cfg: esconfig.Config{}}

	declaration := service.ProducerContract(context.Background())

	if declaration.GovernedExecution.Enabled {
		t.Fatalf("expected governed execution disabled without submit config")
	}
	if declaration.GovernedExecution.DisabledReason != "submit_not_configured" {
		t.Fatalf("unexpected disabled reason %q", declaration.GovernedExecution.DisabledReason)
	}
	assertRuntimeProfileStatus(t, declaration.GovernedExecution.RuntimeProfiles, runtimeProfileDefaultStaticScript, "disabled")
	assertRuntimeProfileStatus(t, declaration.GovernedExecution.RuntimeProfiles, runtimeProfileControlPlaneNormalShell, "disabled")
	assertRuntimeProfileDisabledReason(t, declaration.GovernedExecution.RuntimeProfiles, runtimeProfileDefaultStaticScript, "submit_not_configured")
	assertRuntimeProfileDisabledReason(t, declaration.GovernedExecution.RuntimeProfiles, runtimeProfileControlPlaneNormalShell, "submit_not_configured")
}

func TestProducerContractDeclarationMarksDisabledRuntimeProfileReason(t *testing.T) {
	declaration := producerContractDeclaration(producerContractSubmitConfig(false))

	if !declaration.GovernedExecution.Enabled {
		t.Fatalf("expected governed execution enabled when submit is configured, got %+v", declaration.GovernedExecution)
	}
	assertRuntimeProfileStatus(t, declaration.GovernedExecution.RuntimeProfiles, runtimeProfileDefaultStaticScript, "enabled")
	assertRuntimeProfileStatus(t, declaration.GovernedExecution.RuntimeProfiles, runtimeProfileControlPlaneNormalShell, "disabled")
	assertRuntimeProfileDisabledReason(t, declaration.GovernedExecution.RuntimeProfiles, runtimeProfileControlPlaneNormalShell, "profile_not_enabled")
}

func producerContractSubmitConfig(enableControlPlaneProfile bool) esconfig.Config {
	cfg := esconfig.Config{
		Nomad: esconfig.NomadConfig{
			BaseURL:        "https://127.0.0.1:4646",
			Datacenter:     "dc1",
			TimeoutSeconds: 1,
		},
		Execution: esconfig.ExecutionConfig{
			StagingRootDir:             "/tmp/es-staging",
			ResultsRootDir:             "/tmp/es-results",
			BaseImage:                  "alpine:3.20",
			RuntimeSupportBinary:       "/usr/local/bin/es-runtime-support",
			SPIREWorkloadAPISocketPath: "/run/spire/sockets/agent.sock",
		},
	}
	if enableControlPlaneProfile {
		cfg.Execution.RuntimeProfiles.ControlPlaneNormalShell = esconfig.ControlPlaneNormalShellProfileConfig{
			Enabled:                    true,
			Image:                      "execution-substrate/control-plane-normal-shell:test",
			CodexCLIPath:               "/usr/local/bin/codex",
			CredentialVaultSecretPath:  "secret/data/codex",
			CredentialVaultSecretField: "api_key",
		}
	}
	return cfg
}

func assertRuntimeProfileStatus(t *testing.T, profiles []ProducerRuntimeProfileDeclaration, name string, status string) {
	t.Helper()

	for _, profile := range profiles {
		if profile.Name == name {
			if profile.Status != status {
				t.Fatalf("expected profile %s status %s, got %+v", name, status, profile)
			}
			return
		}
	}
	t.Fatalf("missing runtime profile %q in %+v", name, profiles)
}

func assertRuntimeProfileDisabledReason(t *testing.T, profiles []ProducerRuntimeProfileDeclaration, name string, reason string) {
	t.Helper()

	for _, profile := range profiles {
		if profile.Name == name {
			if profile.DisabledReason != reason {
				t.Fatalf("expected profile %s disabled reason %s, got %+v", name, reason, profile)
			}
			return
		}
	}
	t.Fatalf("missing runtime profile %q in %+v", name, profiles)
}

func assertEvidenceSurface(t *testing.T, surface ProducerOutcomeEvidenceSurfaceDeclaration, carrier string, field string, mediaType string, source string, accessClass string, observations []string) {
	t.Helper()

	if !surface.Required {
		t.Fatalf("expected required surface, got %+v", surface)
	}
	if surface.Carrier != carrier || surface.Field != field || surface.MediaType != mediaType || surface.Source != source || surface.AccessClass != accessClass {
		t.Fatalf("unexpected evidence surface %+v", surface)
	}
	for _, observation := range observations {
		if !containsString(surface.Observations, observation) {
			t.Fatalf("expected observation %q in %+v", observation, surface)
		}
	}
}

func assertDeclaredEvidenceMatchesRuntimeEvidence(t *testing.T, surface ProducerOutcomeEvidenceSurfaceDeclaration, evidence ExecutionOutcomeEvidence) {
	t.Helper()

	if !surface.Required {
		t.Fatalf("expected required evidence surface, got %+v", surface)
	}
	if surface.Source != evidence.Source {
		t.Fatalf("declared source %q does not match runtime evidence %+v", surface.Source, evidence)
	}
	if !containsString(surface.Observations, evidence.Observation) {
		t.Fatalf("declared observations %v do not include runtime evidence %+v", surface.Observations, evidence)
	}
	if surface.AccessClass != evidence.AccessClass {
		t.Fatalf("declared access class %q does not match runtime evidence %+v", surface.AccessClass, evidence)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func assertContainsAll(t *testing.T, values []string, expected []string) {
	t.Helper()

	for _, value := range expected {
		if !containsString(values, value) {
			t.Fatalf("expected %q in %v", value, values)
		}
	}
}
