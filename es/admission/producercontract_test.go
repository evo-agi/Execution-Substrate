package admission

import (
	"context"
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
		"not_run_authority",
		"not_credential_truth",
		"not_lifecycle_write_coordination",
		"not_scheduler_api",
	} {
		if !containsString(declaration.NonAuthority, required) {
			t.Fatalf("expected non_authority to include %q, got %v", required, declaration.NonAuthority)
		}
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
}

func producerContractSubmitConfig(enableControlPlaneProfile bool) esconfig.Config {
	cfg := esconfig.Config{
		Nomad: esconfig.NomadConfig{
			BaseURL:        "http://127.0.0.1:4646",
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
