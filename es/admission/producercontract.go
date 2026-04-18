package admission

import (
	"context"

	esconfig "execution-substrate/es/config"
)

const (
	producerContractSchemaVersion       = "execution-substrate.producer-contract/v1"
	governedExecutionProducerContract   = "governed-execution-producer/v1"
	producerContractStatusEnabled       = "enabled"
	producerContractStatusDisabled      = "disabled"
	producerContractReasonSubmitMissing = "submit_not_configured"
	producerContractReasonProfileOff    = "profile_not_enabled"
)

func (s *Service) ProducerContract(ctx context.Context) ProducerContractDeclaration {
	_ = ctx
	return producerContractDeclaration(s.cfg)
}

func producerContractDeclaration(cfg esconfig.Config) ProducerContractDeclaration {
	submitConfigured := cfg.SubmitConfigured()
	governedExecution := GovernedExecutionProducerContractDeclaration{
		Contract:        governedExecutionProducerContract,
		Enabled:         submitConfigured,
		RuntimeProfiles: producerRuntimeProfileDeclarations(cfg, submitConfigured),
		OutcomeEvidence: producerOutcomeEvidenceDeclaration(),
	}
	if !submitConfigured {
		governedExecution.DisabledReason = producerContractReasonSubmitMissing
	}

	return ProducerContractDeclaration{
		SchemaVersion:     producerContractSchemaVersion,
		Service:           "execution",
		GovernedExecution: governedExecution,
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
	}
}

func producerRuntimeProfileDeclarations(cfg esconfig.Config, submitConfigured bool) []ProducerRuntimeProfileDeclaration {
	return []ProducerRuntimeProfileDeclaration{
		producerRuntimeProfileDeclaration(runtimeProfileDefaultStaticScript, submitConfigured, disabledReasonForProfile(submitConfigured, true)),
		producerRuntimeProfileDeclaration(runtimeProfileControlPlaneNormalShell, submitConfigured && cfg.Execution.RuntimeProfiles.ControlPlaneNormalShell.Enabled, disabledReasonForProfile(submitConfigured, cfg.Execution.RuntimeProfiles.ControlPlaneNormalShell.Enabled)),
	}
}

func producerRuntimeProfileDeclaration(name string, enabled bool, disabledReason string) ProducerRuntimeProfileDeclaration {
	if enabled {
		return ProducerRuntimeProfileDeclaration{
			Name:   name,
			Status: producerContractStatusEnabled,
		}
	}
	return ProducerRuntimeProfileDeclaration{
		Name:           name,
		Status:         producerContractStatusDisabled,
		DisabledReason: disabledReason,
	}
}

func disabledReasonForProfile(submitConfigured bool, profileEnabled bool) string {
	if !submitConfigured {
		return producerContractReasonSubmitMissing
	}
	if !profileEnabled {
		return producerContractReasonProfileOff
	}
	return ""
}

func producerOutcomeEvidenceDeclaration() ProducerOutcomeEvidenceDeclaration {
	return ProducerOutcomeEvidenceDeclaration{
		Required: true,
		StatusJSON: ProducerOutcomeEvidenceSurfaceDeclaration{
			Required: true,
			Carrier:  "json_field",
			Field:    "outcome_evidence",
			RequiredFields: []string{
				"source",
				"observation",
				"lifecycle_projection",
				"provider_terminal_observed",
			},
			Source: outcomeEvidenceSourceNomad,
			Observations: []string{
				outcomeObservationNomadJobProjection,
				outcomeObservationNomadProjectedAllocation,
				outcomeObservationNomadTaskStateProjection,
			},
		},
		CancelJSON: ProducerOutcomeEvidenceSurfaceDeclaration{
			Required: true,
			Carrier:  "json_field",
			Field:    "outcome_evidence",
			RequiredFields: []string{
				"source",
				"observation",
				"provider_terminal_observed",
			},
			Source:       outcomeEvidenceSourceNomad,
			Observations: []string{outcomeObservationNomadStopAccepted},
		},
		LogsHeaders: ProducerOutcomeEvidenceSurfaceDeclaration{
			Required:  true,
			Carrier:   "http_headers",
			MediaType: LogsMediaType,
			RequiredHeaders: []string{
				OutcomeHeaderSource,
				OutcomeHeaderObservation,
				OutcomeHeaderAccessClass,
				OutcomeHeaderProviderTerminalObserved,
			},
			Source:       outcomeEvidenceSourceNomad,
			Observations: []string{outcomeObservationNomadTaskStdout},
			AccessClass:  outcomeAccessClassPlaintextStdout,
		},
		ResultHeaders: ProducerOutcomeEvidenceSurfaceDeclaration{
			Required:  true,
			Carrier:   "http_headers",
			MediaType: resultBundleMediaType,
			RequiredHeaders: []string{
				OutcomeHeaderSource,
				OutcomeHeaderObservation,
				OutcomeHeaderAccessClass,
			},
			Source:       outcomeEvidenceSourceRetainedResultStore,
			Observations: []string{outcomeObservationRetainedResultBundle},
			AccessClass:  outcomeAccessClassOpaqueResultBundle,
		},
	}
}
