package reliablesubmit

import (
	"context"
	"errors"
	"time"
)

type durableClaimService struct {
	store claimStore
	clock claimClock
}

func newDurableClaimService(store claimStore, clock claimClock) (*durableClaimService, error) {
	if store == nil {
		return nil, errClaimStoreInternal
	}
	if clock == nil {
		clock = systemClaimClock{}
	}
	return &durableClaimService{store: store, clock: clock}, nil
}

type durableClaimOutcomeKind uint8

const (
	durableClaimOutcomeInvalid durableClaimOutcomeKind = iota
	durableClaimOutcomeEstablished
	durableClaimOutcomeExactReplay
	durableClaimOutcomeConflict
	durableClaimOutcomeAssigned
	durableClaimOutcomeEffectIntentRecorded
	durableClaimOutcomeStagingEvidenceRecorded
	durableClaimOutcomeDispatchAttemptRecorded
	durableClaimOutcomeProviderObservationRecorded
	durableClaimOutcomeReconciliationRecorded
	durableClaimOutcomeAccepted
	durableClaimOutcomeProvablyNotAccepted
	durableClaimOutcomeExpiredUnavailable
	durableClaimOutcomeStale
	durableClaimOutcomeUnavailable
)

type durableClaimOutcome struct {
	kind                       durableClaimOutcomeKind
	record                     durableClaimRecord
	hasRecord                  bool
	observationKind            Kind
	underlyingReplayKind       Kind
	runRefDisclosure           RunRefDisclosurePolicy
	acceptedReferenceAvailable bool
}

type establishClaimRequest struct {
	claim        ClaimID
	plan         BoundPlan
	mutation     durableMutationRef
	expiresAt    optionalClaimTime
	initialPhase durablePhaseTag
}

type exactReplayRequest struct {
	claim   ClaimID
	binding PlanBinding
}

type assignRunRequest struct {
	claim            ClaimID
	binding          PlanBinding
	expectedRevision claimRevision
	run              RunRef
	mutation         durableMutationRef
}

type recordProviderEffectIntentRequest struct {
	claim            ClaimID
	binding          PlanBinding
	expectedRevision claimRevision
	intent           durableFactRef
	mutation         durableMutationRef
}

type recordStagingEvidenceRequest struct {
	claim            ClaimID
	binding          PlanBinding
	expectedRevision claimRevision
	staging          durableFactRef
	mutation         durableMutationRef
}

type recordProviderDispatchAttemptRequest struct {
	claim            ClaimID
	binding          PlanBinding
	expectedRevision claimRevision
	dispatch         durableFactRef
	mutation         durableMutationRef
}

type recordProviderCallObservationRequest struct {
	claim            ClaimID
	binding          PlanBinding
	expectedRevision claimRevision
	run              RunRef
	kind             durableProviderObservationKind
	observation      durableFactRef
	mutation         durableMutationRef
}

type recordReconciliationEvidenceRequest struct {
	claim            ClaimID
	binding          PlanBinding
	expectedRevision claimRevision
	run              RunRef
	kind             durableReconciliationKind
	reconciliation   durableFactRef
	mutation         durableMutationRef
}

type acceptWithReceiptRequest struct {
	claim            ClaimID
	binding          PlanBinding
	expectedRevision claimRevision
	receipt          ReceiptRef
	accepted         durableFactRef
	mutation         durableMutationRef
}

type recordProvablyNotAcceptedRequest struct {
	claim            ClaimID
	binding          PlanBinding
	expectedRevision claimRevision
	notAccepted      durableFactRef
	mutation         durableMutationRef
}

type tombstoneClaimRequest struct {
	claim            ClaimID
	binding          PlanBinding
	expectedRevision claimRevision
	state            durableRetentionState
	reason           string
	mutation         durableMutationRef
}

func (s *durableClaimService) establishOrLoadClaim(ctx context.Context, req establishClaimRequest) (durableClaimOutcome, error) {
	now := s.now()
	phase, err := initialClaimPhase(req.claim, req.plan, req.initialPhase)
	if err != nil {
		return durableClaimOutcome{}, err
	}
	initialTag := req.initialPhase
	if initialTag == 0 {
		initialTag = durablePhasePendingBeforeAssignment
	}
	operation, err := deriveDurableOperationDescriptor(
		req.mutation,
		durableOperationEstablishClaim,
		0,
		operationPartUint16(durableOperationPartInitialPhase, uint16(initialTag)),
		operationPartOptionalClaimTime(durableOperationPartExpiresAt, req.expiresAt),
	)
	if err != nil {
		return durableClaimOutcome{}, err
	}
	record, err := newDurableClaimRecord(newDurableClaimRecordInput{
		phase:           phase,
		revision:        initialClaimRevision,
		createdAt:       now,
		updatedAt:       now,
		expiresAt:       req.expiresAt,
		retention:       activeDurableRetention(),
		latestOperation: operation,
	})
	if err != nil {
		return durableClaimOutcome{}, err
	}
	result, err := s.store.establishClaim(ctx, establishClaimCommand{record: record})
	if err != nil {
		if isClaimStoreError(err, claimStoreErrorCommitUnknown) {
			return s.reloadAfterUnknown(ctx, req.claim, req.plan.Binding(), record, durableClaimOutcomeEstablished)
		}
		return durableClaimOutcome{}, err
	}
	if result.created {
		return outcomeForRecord(durableClaimOutcomeEstablished, result.record)
	}
	return s.classifyLoadedRecord(result.record, req.claim, req.plan.Binding())
}

func (s *durableClaimService) exactReplayOrLoad(ctx context.Context, req exactReplayRequest) (durableClaimOutcome, error) {
	record, err := s.store.loadClaim(ctx, loadClaimQuery{claim: req.claim})
	if err != nil {
		return durableClaimOutcome{}, err
	}
	return s.classifyLoadedRecord(record, req.claim, req.binding)
}

func (s *durableClaimService) assignRun(ctx context.Context, req assignRunRequest) (durableClaimOutcome, error) {
	return s.mutate(ctx, mutationRequest{
		claim:            req.claim,
		binding:          req.binding,
		expectedRevision: req.expectedRevision,
		mutation:         req.mutation,
		operationKind:    durableOperationAssignRun,
		operationInput: func() []durableOperationInputPart {
			return []durableOperationInputPart{operationPartRunRef(req.run)}
		},
		successKind: durableClaimOutcomeAssigned,
		apply: func(record durableClaimRecord, nowUTC time.Time, operation durableLatestOperationDescriptor) (durableClaimRecord, error) {
			if record.phase.run.Valid() {
				if record.phase.run.Equal(req.run) {
					return record, nil
				}
				return durableClaimRecord{}, ErrRunAssignmentMismatch
			}
			phase, err := record.phase.hydrate(record.claim, record.plan)
			if err != nil {
				return durableClaimRecord{}, err
			}
			pre, ok := phase.(PreAssignmentPhase)
			if !ok {
				return durableClaimRecord{}, ErrInvalidPhase
			}
			assigned, err := AssignRun(pre, req.run)
			if err != nil {
				return durableClaimRecord{}, err
			}
			return record.withPhaseAndOperation(assigned, operation, nowUTC, someClaimTime(nowUTC), record.effects, record.retention)
		},
	})
}

func (s *durableClaimService) recordProviderEffectIntent(ctx context.Context, req recordProviderEffectIntentRequest) (durableClaimOutcome, error) {
	return s.mutate(ctx, mutationRequest{
		claim:            req.claim,
		binding:          req.binding,
		expectedRevision: req.expectedRevision,
		mutation:         req.mutation,
		operationKind:    durableOperationRecordProviderEffectIntent,
		operationInput: func() []durableOperationInputPart {
			return []durableOperationInputPart{operationPartFactRef(req.intent)}
		},
		successKind: durableClaimOutcomeEffectIntentRecorded,
		apply: func(record durableClaimRecord, nowUTC time.Time, operation durableLatestOperationDescriptor) (durableClaimRecord, error) {
			if !record.phase.run.Valid() {
				return durableClaimRecord{}, ErrInvalidPhase
			}
			if record.effects.intent.present() {
				if record.effects.intent.ref.equal(req.intent) {
					return record, nil
				}
				return durableClaimRecord{}, errInvalidDurableRecord
			}
			effects := record.effects.clone()
			effects.intent = newDurableEffectRefTime(req.intent, nowUTC)
			phase, err := record.hydratePhase()
			if err != nil {
				return durableClaimRecord{}, err
			}
			return record.withPhaseAndOperation(phase, operation, nowUTC, record.assignedAt, effects, record.retention)
		},
	})
}

func (s *durableClaimService) recordStagingEvidence(ctx context.Context, req recordStagingEvidenceRequest) (durableClaimOutcome, error) {
	return s.mutate(ctx, mutationRequest{
		claim:            req.claim,
		binding:          req.binding,
		expectedRevision: req.expectedRevision,
		mutation:         req.mutation,
		operationKind:    durableOperationRecordStagingEvidence,
		operationInput: func() []durableOperationInputPart {
			return []durableOperationInputPart{operationPartFactRef(req.staging)}
		},
		successKind: durableClaimOutcomeStagingEvidenceRecorded,
		apply: func(record durableClaimRecord, nowUTC time.Time, operation durableLatestOperationDescriptor) (durableClaimRecord, error) {
			if !record.effects.intent.present() {
				return durableClaimRecord{}, errInvalidDurableRecord
			}
			if record.effects.staging.present() {
				if record.effects.staging.ref.equal(req.staging) {
					return record, nil
				}
				return durableClaimRecord{}, errInvalidDurableRecord
			}
			effects := record.effects.clone()
			effects.staging = newDurableEffectRefTime(req.staging, nowUTC)
			phase, err := record.hydratePhase()
			if err != nil {
				return durableClaimRecord{}, err
			}
			return record.withPhaseAndOperation(phase, operation, nowUTC, record.assignedAt, effects, record.retention)
		},
	})
}

func (s *durableClaimService) recordProviderDispatchAttempt(ctx context.Context, req recordProviderDispatchAttemptRequest) (durableClaimOutcome, error) {
	return s.mutate(ctx, mutationRequest{
		claim:            req.claim,
		binding:          req.binding,
		expectedRevision: req.expectedRevision,
		mutation:         req.mutation,
		operationKind:    durableOperationRecordProviderDispatchAttempt,
		operationInput: func() []durableOperationInputPart {
			return []durableOperationInputPart{operationPartFactRef(req.dispatch)}
		},
		successKind: durableClaimOutcomeDispatchAttemptRecorded,
		apply: func(record durableClaimRecord, nowUTC time.Time, operation durableLatestOperationDescriptor) (durableClaimRecord, error) {
			if !record.effects.intent.present() {
				return durableClaimRecord{}, errInvalidDurableRecord
			}
			if record.effects.dispatch.present() {
				if record.effects.dispatch.ref.equal(req.dispatch) {
					return record, nil
				}
				return durableClaimRecord{}, errInvalidDurableRecord
			}
			effects := record.effects.clone()
			effects.dispatch = newDurableEffectRefTime(req.dispatch, nowUTC)
			phase, err := record.hydratePhase()
			if err != nil {
				return durableClaimRecord{}, err
			}
			return record.withPhaseAndOperation(phase, operation, nowUTC, record.assignedAt, effects, record.retention)
		},
	})
}

func (s *durableClaimService) recordProviderCallObservation(ctx context.Context, req recordProviderCallObservationRequest) (durableClaimOutcome, error) {
	return s.mutate(ctx, mutationRequest{
		claim:            req.claim,
		binding:          req.binding,
		expectedRevision: req.expectedRevision,
		mutation:         req.mutation,
		operationKind:    durableOperationRecordProviderCallObservation,
		operationInput: func() []durableOperationInputPart {
			return []durableOperationInputPart{
				operationPartRunRef(req.run),
				operationPartUint16(durableOperationPartObservationKind, uint16(req.kind)),
				operationPartFactRef(req.observation),
			}
		},
		successKind: durableClaimOutcomeProviderObservationRecorded,
		apply: func(record durableClaimRecord, nowUTC time.Time, operation durableLatestOperationDescriptor) (durableClaimRecord, error) {
			if err := validateRecordRunRef(record, req.run); err != nil {
				return durableClaimRecord{}, err
			}
			if !record.effects.intent.present() {
				return durableClaimRecord{}, errInvalidDurableRecord
			}
			if !record.effects.dispatch.present() {
				return durableClaimRecord{}, errInvalidDurableRecord
			}
			if req.kind == durableProviderObservationAccepted || req.kind == durableProviderObservationNotAccepted || req.kind == durableProviderObservationInvalid {
				return durableClaimRecord{}, errInvalidDurableRecord
			}
			if !req.observation.valid() {
				return durableClaimRecord{}, errInvalidDurableRecord
			}
			if record.effects.provider.present() {
				if record.effects.provider.kind == req.kind && record.effects.provider.fact.ref.equal(req.observation) {
					return record, nil
				}
				return durableClaimRecord{}, errInvalidDurableRecord
			}
			effects := record.effects.clone()
			effects.provider = durableProviderObservation{kind: req.kind, fact: newDurableEffectRefTime(req.observation, nowUTC)}
			phase, err := phaseForProviderObservation(record, req.kind)
			if err != nil {
				return durableClaimRecord{}, err
			}
			return record.withPhaseAndOperation(phase, operation, nowUTC, record.assignedAt, effects, record.retention)
		},
	})
}

func (s *durableClaimService) recordReconciliationEvidence(ctx context.Context, req recordReconciliationEvidenceRequest) (durableClaimOutcome, error) {
	return s.mutate(ctx, mutationRequest{
		claim:            req.claim,
		binding:          req.binding,
		expectedRevision: req.expectedRevision,
		mutation:         req.mutation,
		operationKind:    durableOperationRecordReconciliationEvidence,
		operationInput: func() []durableOperationInputPart {
			return []durableOperationInputPart{
				operationPartRunRef(req.run),
				operationPartUint16(durableOperationPartReconciliationKind, uint16(req.kind)),
				operationPartFactRef(req.reconciliation),
			}
		},
		successKind: durableClaimOutcomeReconciliationRecorded,
		apply: func(record durableClaimRecord, nowUTC time.Time, operation durableLatestOperationDescriptor) (durableClaimRecord, error) {
			if err := validateRecordRunRef(record, req.run); err != nil {
				return durableClaimRecord{}, err
			}
			if !record.effects.intent.present() {
				return durableClaimRecord{}, errInvalidDurableRecord
			}
			if req.kind == durableReconciliationInvalid {
				return durableClaimRecord{}, errInvalidDurableRecord
			}
			if !req.reconciliation.valid() {
				return durableClaimRecord{}, errInvalidDurableRecord
			}
			if record.effects.reconciliation.present() {
				if record.effects.reconciliation.kind == req.kind && record.effects.reconciliation.fact.ref.equal(req.reconciliation) {
					return record, nil
				}
				return durableClaimRecord{}, errInvalidDurableRecord
			}
			effects := record.effects.clone()
			effects.reconciliation = durableReconciliationFact{kind: req.kind, fact: newDurableEffectRefTime(req.reconciliation, nowUTC)}
			phase, err := phaseForReconciliation(record, req.kind)
			if err != nil {
				return durableClaimRecord{}, err
			}
			return record.withPhaseAndOperation(phase, operation, nowUTC, record.assignedAt, effects, record.retention)
		},
	})
}

func (s *durableClaimService) acceptWithReceipt(ctx context.Context, req acceptWithReceiptRequest) (durableClaimOutcome, error) {
	return s.mutate(ctx, mutationRequest{
		claim:            req.claim,
		binding:          req.binding,
		expectedRevision: req.expectedRevision,
		mutation:         req.mutation,
		operationKind:    durableOperationAcceptWithReceipt,
		operationInput: func() []durableOperationInputPart {
			return []durableOperationInputPart{
				operationPartReceiptRef(req.receipt),
				operationPartFactRef(req.accepted),
			}
		},
		successKind: durableClaimOutcomeAccepted,
		apply: func(record durableClaimRecord, nowUTC time.Time, operation durableLatestOperationDescriptor) (durableClaimRecord, error) {
			if !record.effects.dispatch.present() {
				return durableClaimRecord{}, errInvalidDurableRecord
			}
			current, err := record.hydratePhase()
			if err != nil {
				return durableClaimRecord{}, err
			}
			candidate, ok := current.(ProviderOutcomeCandidatePhase)
			if !ok {
				return durableClaimRecord{}, ErrInvalidProviderOutcomeCandidatePhase
			}
			accepted, err := NewAccepted(candidate, req.receipt)
			if err != nil {
				return durableClaimRecord{}, err
			}
			effects := record.effects.clone()
			effects.provider = durableProviderObservation{
				kind: durableProviderObservationAccepted,
				fact: newDurableEffectRefTime(req.accepted, nowUTC),
			}
			return record.withPhaseAndOperation(accepted, operation, nowUTC, record.assignedAt, effects, record.retention)
		},
	})
}

func (s *durableClaimService) recordProvablyNotAccepted(ctx context.Context, req recordProvablyNotAcceptedRequest) (durableClaimOutcome, error) {
	return s.mutate(ctx, mutationRequest{
		claim:            req.claim,
		binding:          req.binding,
		expectedRevision: req.expectedRevision,
		mutation:         req.mutation,
		operationKind:    durableOperationRecordProvablyNotAccepted,
		operationInput: func() []durableOperationInputPart {
			return []durableOperationInputPart{operationPartFactRef(req.notAccepted)}
		},
		successKind: durableClaimOutcomeProvablyNotAccepted,
		apply: func(record durableClaimRecord, nowUTC time.Time, operation durableLatestOperationDescriptor) (durableClaimRecord, error) {
			if !record.effects.dispatch.present() {
				return durableClaimRecord{}, errInvalidDurableRecord
			}
			current, err := record.hydratePhase()
			if err != nil {
				return durableClaimRecord{}, err
			}
			candidate, ok := current.(ProviderOutcomeCandidatePhase)
			if !ok {
				return durableClaimRecord{}, ErrInvalidProviderOutcomeCandidatePhase
			}
			notAccepted, err := NewProvablyNotAcceptedAfterAssignment(candidate)
			if err != nil {
				return durableClaimRecord{}, err
			}
			effects := record.effects.clone()
			effects.provider = durableProviderObservation{
				kind: durableProviderObservationNotAccepted,
				fact: newDurableEffectRefTime(req.notAccepted, nowUTC),
			}
			return record.withPhaseAndOperation(notAccepted, operation, nowUTC, record.assignedAt, effects, record.retention)
		},
	})
}

func (s *durableClaimService) tombstoneOrExpire(ctx context.Context, req tombstoneClaimRequest) (durableClaimOutcome, error) {
	successKind := durableClaimOutcomeExpiredUnavailable
	return s.mutate(ctx, mutationRequest{
		claim:            req.claim,
		binding:          req.binding,
		expectedRevision: req.expectedRevision,
		mutation:         req.mutation,
		operationKind:    durableOperationTombstoneOrExpire,
		operationInput: func() []durableOperationInputPart {
			return []durableOperationInputPart{
				operationPartUint16(durableOperationPartRetentionState, uint16(req.state)),
				operationPartString(durableOperationPartRetentionReason, req.reason),
			}
		},
		successKind: successKind,
		apply: func(record durableClaimRecord, nowUTC time.Time, operation durableLatestOperationDescriptor) (durableClaimRecord, error) {
			if req.state != durableRetentionExpired && req.state != durableRetentionTombstoned {
				return durableClaimRecord{}, errInvalidDurableRecord
			}
			retention := durableRetentionFact{
				state:         req.state,
				unavailableAt: someClaimTime(nowUTC),
				reason:        req.reason,
			}
			phase, err := record.hydratePhase()
			if err != nil {
				return durableClaimRecord{}, err
			}
			return record.withPhaseAndOperation(phase, operation, nowUTC, record.assignedAt, record.effects, retention)
		},
	})
}

type mutationRequest struct {
	claim            ClaimID
	binding          PlanBinding
	expectedRevision claimRevision
	mutation         durableMutationRef
	operationKind    durableOperationKind
	operationInput   func() []durableOperationInputPart
	successKind      durableClaimOutcomeKind
	apply            func(durableClaimRecord, time.Time, durableLatestOperationDescriptor) (durableClaimRecord, error)
}

func (s *durableClaimService) mutate(ctx context.Context, req mutationRequest) (durableClaimOutcome, error) {
	now := s.now()
	record, err := s.store.loadClaim(ctx, loadClaimQuery{claim: req.claim})
	if err != nil {
		return durableClaimOutcome{}, err
	}
	_, classified, handled, err := s.validateLoadedRecordBinding(record, req.claim, req.binding)
	if err != nil {
		return durableClaimOutcome{}, err
	}
	if handled {
		return classified, nil
	}
	if req.operationInput == nil {
		return durableClaimOutcome{}, errInvalidDurableOperationInputBinding
	}
	operation, err := deriveDurableOperationDescriptor(
		req.mutation,
		req.operationKind,
		req.expectedRevision,
		req.operationInput()...,
	)
	if err != nil {
		return durableClaimOutcome{}, err
	}
	classified, handled, err = s.classifyValidatedRecordForMutation(record, operation, req.successKind)
	if err != nil {
		return durableClaimOutcome{}, err
	}
	if handled {
		return classified, nil
	}
	if record.revision != req.expectedRevision {
		return outcomeForRecord(durableClaimOutcomeStale, record)
	}
	next, err := req.apply(record, now, operation)
	if err != nil {
		return durableClaimOutcome{}, err
	}
	if next.equal(record) {
		return outcomeForRecord(req.successKind, record)
	}
	result, err := s.store.compareAndSwapClaim(ctx, compareAndSwapClaimCommand{
		claim:            req.claim,
		expectedRevision: req.expectedRevision,
		next:             next,
	})
	if err != nil {
		if isClaimStoreError(err, claimStoreErrorCommitUnknown) {
			return s.reloadAfterUnknown(ctx, req.claim, req.binding, next, req.successKind)
		}
		return durableClaimOutcome{}, err
	}
	if result.applied {
		return outcomeForRecord(req.successKind, result.record)
	}
	if result.found {
		classified, handled, classifyErr := s.classifyLoadedRecordForMutation(result.record, req.claim, req.binding, operation, req.successKind)
		if classifyErr != nil {
			return durableClaimOutcome{}, classifyErr
		}
		if handled {
			return classified, nil
		}
		return outcomeForRecord(durableClaimOutcomeStale, result.record)
	}
	return durableClaimOutcome{}, errClaimStoreNotFound
}

func (s *durableClaimService) classifyLoadedRecordForMutation(record durableClaimRecord, claim ClaimID, binding PlanBinding, incoming durableLatestOperationDescriptor, successKind durableClaimOutcomeKind) (durableClaimOutcome, bool, error) {
	if _, classified, handled, err := s.validateLoadedRecordBinding(record, claim, binding); err != nil || handled {
		return classified, handled, err
	}
	return s.classifyValidatedRecordForMutation(record, incoming, successKind)
}

func (s *durableClaimService) classifyValidatedRecordForMutation(record durableClaimRecord, incoming durableLatestOperationDescriptor, successKind durableClaimOutcomeKind) (durableClaimOutcome, bool, error) {
	switch compareDurableLatestOperation(record.latestOperation, incoming) {
	case durableOperationReplayExact:
		replayed, err := outcomeForRecord(successKind, record)
		return replayed, true, err
	case durableOperationReplayConflict:
		conflict, err := mutationConflictOutcome()
		return conflict, true, err
	case durableOperationReplayUnavailable:
		return durableClaimOutcome{kind: durableClaimOutcomeUnavailable}, true, nil
	default:
	}
	if !record.activeAt(s.now()) {
		expired, err := expiredUnavailableOutcome()
		return expired, true, err
	}
	return durableClaimOutcome{}, false, nil
}

func (s *durableClaimService) classifyLoadedRecord(record durableClaimRecord, claim ClaimID, binding PlanBinding) (durableClaimOutcome, error) {
	phase, classified, handled, err := s.validateLoadedRecordBinding(record, claim, binding)
	if err != nil || handled {
		return classified, err
	}
	if !record.activeAt(s.now()) {
		return expiredUnavailableOutcome()
	}
	replay, err := NewExactReplay(phase)
	if err != nil {
		return durableClaimOutcome{}, err
	}
	return durableClaimOutcome{
		kind:                       durableClaimOutcomeExactReplay,
		record:                     record.clone(),
		hasRecord:                  true,
		observationKind:            replay.Kind(),
		underlyingReplayKind:       replay.UnderlyingKind(),
		runRefDisclosure:           replay.SameCallerRunRefDisclosure(),
		acceptedReferenceAvailable: replay.AcceptedSubmissionReferenceAvailable(),
	}, nil
}

func (s *durableClaimService) validateLoadedRecordBinding(record durableClaimRecord, claim ClaimID, binding PlanBinding) (ClaimPhase, durableClaimOutcome, bool, error) {
	if err := record.validate(); err != nil {
		return nil, durableClaimOutcome{}, false, err
	}
	if record.codecVersion == durableClaimCodecVersionSynthetic {
		return nil, durableClaimOutcome{}, false, errClaimStoreUnsupported
	}
	phase, err := record.hydratePhase()
	if err != nil {
		return nil, durableClaimOutcome{}, false, err
	}
	if !record.claim.Equal(claim) {
		return nil, durableClaimOutcome{}, false, errClaimStoreCorrupt
	}
	if err := ValidatePlanBinding(phase, binding); err != nil {
		if errors.Is(err, ErrPlanBindingConflict) {
			conflict, conflictErr := mutationConflictOutcome()
			return nil, conflict, true, conflictErr
		}
		return nil, durableClaimOutcome{}, false, err
	}
	return phase, durableClaimOutcome{}, false, nil
}

func mutationConflictOutcome() (durableClaimOutcome, error) {
	conflict, err := NewConflict()
	if err != nil {
		return durableClaimOutcome{}, err
	}
	return durableClaimOutcome{
		kind:                       durableClaimOutcomeConflict,
		observationKind:            conflict.Kind(),
		runRefDisclosure:           conflict.SameCallerRunRefDisclosure(),
		acceptedReferenceAvailable: conflict.AcceptedSubmissionReferenceAvailable(),
	}, nil
}

func expiredUnavailableOutcome() (durableClaimOutcome, error) {
	expired, err := NewExpiredUnavailable()
	if err != nil {
		return durableClaimOutcome{}, err
	}
	return durableClaimOutcome{
		kind:                       durableClaimOutcomeExpiredUnavailable,
		observationKind:            expired.Kind(),
		runRefDisclosure:           expired.SameCallerRunRefDisclosure(),
		acceptedReferenceAvailable: expired.AcceptedSubmissionReferenceAvailable(),
	}, nil
}

func outcomeForRecord(kind durableClaimOutcomeKind, record durableClaimRecord) (durableClaimOutcome, error) {
	phase, err := record.hydratePhase()
	if err != nil {
		return durableClaimOutcome{}, err
	}
	return durableClaimOutcome{
		kind:                       kind,
		record:                     record.clone(),
		hasRecord:                  true,
		observationKind:            phase.Kind(),
		runRefDisclosure:           phase.SameCallerRunRefDisclosure(),
		acceptedReferenceAvailable: phase.AcceptedSubmissionReferenceAvailable(),
	}, nil
}

func (s *durableClaimService) reloadAfterUnknown(ctx context.Context, claim ClaimID, binding PlanBinding, expected durableClaimRecord, successKind durableClaimOutcomeKind) (durableClaimOutcome, error) {
	reloaded, err := s.store.loadClaim(ctx, loadClaimQuery{claim: claim})
	if err != nil {
		if isClaimStoreError(err, claimStoreErrorNotFound) {
			return durableClaimOutcome{kind: durableClaimOutcomeUnavailable}, errClaimStoreCommitUnknown
		}
		return durableClaimOutcome{}, err
	}
	if reloaded.lastMutation.equal(expected.lastMutation) &&
		reloaded.latestOperation.equal(expected.latestOperation) &&
		reloaded.revision == expected.revision &&
		reloaded.equal(expected) {
		return outcomeForRecord(successKind, reloaded)
	}
	classified, classifyErr := s.classifyLoadedRecord(reloaded, claim, binding)
	if classifyErr != nil {
		return durableClaimOutcome{}, classifyErr
	}
	classified.kind = durableClaimOutcomeUnavailable
	return classified, errClaimStoreCommitUnknown
}

func (s *durableClaimService) now() time.Time {
	return normalizeClaimTime(s.clock.Now())
}

func validateRecordRunRef(record durableClaimRecord, run RunRef) error {
	if !run.Valid() || !record.phase.run.Valid() {
		return ErrInvalidPhase
	}
	if !record.phase.run.Equal(run) {
		return ErrRunAssignmentMismatch
	}
	return nil
}

func phaseForProviderObservation(record durableClaimRecord, kind durableProviderObservationKind) (ClaimPhase, error) {
	current, err := record.hydratePhase()
	if err != nil {
		return nil, err
	}
	candidate, ok := current.(ProviderOutcomeCandidatePhase)
	if !ok {
		return nil, ErrInvalidProviderOutcomeCandidatePhase
	}
	assigned, err := hydrateAssignedPhaseFromCandidate(candidate)
	if err != nil {
		return nil, err
	}
	switch kind {
	case durableProviderObservationPending:
		return NewPendingAfterAssignment(assigned)
	case durableProviderObservationAmbiguous, durableProviderObservationCallUncertain:
		return NewAmbiguousAfterAssignment(assigned)
	default:
		return nil, errInvalidDurableRecord
	}
}

func phaseForReconciliation(record durableClaimRecord, kind durableReconciliationKind) (ClaimPhase, error) {
	current, err := record.hydratePhase()
	if err != nil {
		return nil, err
	}
	switch kind {
	case durableReconciliationNoDispatch:
		if record.effects.dispatch.present() || record.effects.provider.present() || current.Kind() != KindEffectCapableAssigned {
			return nil, errInvalidDurableRecord
		}
		return current, nil
	case durableReconciliationPending:
		if !record.effects.dispatch.present() {
			return nil, errInvalidDurableRecord
		}
		assigned, err := hydrateAssignedPhaseFromCandidate(current)
		if err != nil {
			return nil, err
		}
		return NewPendingAfterAssignment(assigned)
	case durableReconciliationAmbiguous, durableReconciliationInconsistent:
		if !record.effects.dispatch.present() {
			return nil, errInvalidDurableRecord
		}
		assigned, err := hydrateAssignedPhaseFromCandidate(current)
		if err != nil {
			return nil, err
		}
		return NewAmbiguousAfterAssignment(assigned)
	case durableReconciliationAccepted:
		if !record.effects.dispatch.present() || current.Kind() != KindAccepted {
			return nil, errInvalidDurableRecord
		}
		return current, nil
	case durableReconciliationNotAccepted:
		if !record.effects.dispatch.present() {
			return nil, errInvalidDurableRecord
		}
		if current.Kind() == KindProvablyNotAcceptedAfterAssignment {
			return current, nil
		}
		assigned, err := hydrateAssignedPhaseFromCandidate(current)
		if err != nil {
			return nil, err
		}
		return NewProvablyNotAcceptedAfterAssignment(assigned)
	default:
		return nil, errInvalidDurableRecord
	}
}

func hydrateAssignedPhaseFromCandidate(phase ClaimPhase) (EffectCapableAssigned, error) {
	candidate, ok := phase.(ProviderOutcomeCandidatePhase)
	if !ok {
		return EffectCapableAssigned{}, ErrInvalidProviderOutcomeCandidatePhase
	}
	claim, ok := candidate.ClaimID()
	if !ok {
		return EffectCapableAssigned{}, ErrInvalidPhase
	}
	plan, ok := candidate.BoundPlan()
	if !ok {
		return EffectCapableAssigned{}, ErrInvalidPhase
	}
	run, ok := candidate.AssignedRunRef()
	if !ok {
		return EffectCapableAssigned{}, ErrInvalidPhase
	}
	return hydrateAssignedPhase(claim, plan, run)
}

func initialClaimPhase(claim ClaimID, plan BoundPlan, tag durablePhaseTag) (ClaimPhase, error) {
	switch tag {
	case 0, durablePhasePendingBeforeAssignment:
		return NewPendingBeforeAssignment(claim, plan)
	case durablePhaseAmbiguousBeforeAssignment:
		return NewAmbiguousBeforeAssignment(claim, plan)
	default:
		return nil, errInvalidDurableRecord
	}
}

func (r durableClaimRecord) withPhaseAndOperation(phase ClaimPhase, operation durableLatestOperationDescriptor, updatedAt time.Time, assignedAt optionalClaimTime, effects durableEffectFacts, retention durableRetentionFact) (durableClaimRecord, error) {
	if !operation.complete() {
		return durableClaimRecord{}, errInvalidDurableLatestOperation
	}
	return newDurableClaimRecord(newDurableClaimRecordInput{
		phase:           phase,
		revision:        r.revision + 1,
		createdAt:       r.createdAt,
		updatedAt:       updatedAt,
		assignedAt:      assignedAt,
		expiresAt:       r.expiresAt,
		effects:         effects,
		retention:       retention,
		latestOperation: operation,
	})
}
