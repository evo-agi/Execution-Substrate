package admission

const (
	outcomeEvidenceSourceNomad                 = "nomad"
	outcomeEvidenceSourceRetainedResultStore   = "es_retained_result_store"
	outcomeObservationNomadJobProjection       = "nomad_job_projection"
	outcomeObservationNomadProjectedAllocation = "nomad_projected_allocation"
	outcomeObservationNomadTaskStateProjection = "nomad_task_state_projection"
	outcomeObservationNomadTaskStdout          = "nomad_task_stdout"
	outcomeObservationNomadStopAccepted        = "nomad_stop_request_accepted"
	outcomeObservationRetainedResultBundle     = "retained_result_bundle"
	outcomeAccessClassPlaintextStdout          = "plaintext_stdout"
	outcomeAccessClassOpaqueResultBundle       = "opaque_result_bundle"
)

func statusOutcomeEvidence(observation string, projection LifecycleProjection, terminalObserved bool) ExecutionOutcomeEvidence {
	projectionCopy := projection
	return ExecutionOutcomeEvidence{
		Source:                   outcomeEvidenceSourceNomad,
		Observation:              observation,
		LifecycleProjection:      &projectionCopy,
		ProviderTerminalObserved: boolPointer(terminalObserved),
	}
}

func logsOutcomeEvidence(terminalObserved bool) ExecutionOutcomeEvidence {
	return ExecutionOutcomeEvidence{
		Source:                   outcomeEvidenceSourceNomad,
		Observation:              outcomeObservationNomadTaskStdout,
		AccessClass:              outcomeAccessClassPlaintextStdout,
		ProviderTerminalObserved: boolPointer(terminalObserved),
	}
}

func cancelOutcomeEvidence() ExecutionOutcomeEvidence {
	return ExecutionOutcomeEvidence{
		Source:                   outcomeEvidenceSourceNomad,
		Observation:              outcomeObservationNomadStopAccepted,
		ProviderTerminalObserved: boolPointer(false),
	}
}

func retainedResultOutcomeEvidence() ExecutionOutcomeEvidence {
	return ExecutionOutcomeEvidence{
		Source:      outcomeEvidenceSourceRetainedResultStore,
		Observation: outcomeObservationRetainedResultBundle,
		AccessClass: outcomeAccessClassOpaqueResultBundle,
	}
}

func boolPointer(value bool) *bool {
	return &value
}
