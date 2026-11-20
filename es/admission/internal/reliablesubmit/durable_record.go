package reliablesubmit

import (
	"bytes"
	"errors"
	"fmt"
	"time"
)

const (
	durableClaimCodecVersionLegacy      uint16 = 1
	durableClaimCodecVersion            uint16 = 2
	durableClaimCodecVersionSynthetic   uint16 = 3
	durableClaimCodecVersionProgress    uint16 = 4
	durableClaimCodecVersionOperational uint16 = 5
)

var (
	errInvalidDurableRecord  = errors.New("reliable submit durable record: invalid")
	errInvalidMutationRef    = errors.New("reliable submit durable record: invalid mutation reference")
	errInvalidDurableFactRef = errors.New("reliable submit durable record: invalid fact reference")
)

type durableMutationRef struct {
	ref opaqueRef
}

func newDurableMutationRef(value []byte) (durableMutationRef, error) {
	ref, err := newOpaqueRef(value, errInvalidMutationRef)
	if err != nil {
		return durableMutationRef{}, err
	}
	return durableMutationRef{ref: ref}, nil
}

func (r durableMutationRef) valid() bool {
	return r.ref.valid()
}

func (r durableMutationRef) equal(other durableMutationRef) bool {
	return r.ref.equal(other.ref)
}

func (r durableMutationRef) clone() durableMutationRef {
	return durableMutationRef{ref: r.ref.clone()}
}

type durableFactRef struct {
	ref opaqueRef
}

func newDurableFactRef(value []byte) (durableFactRef, error) {
	ref, err := newOpaqueRef(value, errInvalidDurableFactRef)
	if err != nil {
		return durableFactRef{}, err
	}
	return durableFactRef{ref: ref}, nil
}

func (r durableFactRef) valid() bool {
	return r.ref.valid()
}

func (r durableFactRef) equal(other durableFactRef) bool {
	return r.ref.equal(other.ref)
}

func (r durableFactRef) clone() durableFactRef {
	return durableFactRef{ref: r.ref.clone()}
}

type durablePhaseTag uint8

const (
	durablePhaseInvalid durablePhaseTag = iota
	durablePhasePendingBeforeAssignment
	durablePhaseAmbiguousBeforeAssignment
	durablePhaseEffectCapableAssigned
	durablePhasePendingAfterAssignment
	durablePhaseAmbiguousAfterAssignment
	durablePhaseAccepted
	durablePhaseProvablyNotAcceptedAfterAssignment
)

type durablePhaseSnapshot struct {
	tag     durablePhaseTag
	run     RunRef
	receipt ReceiptRef
}

func durablePhaseSnapshotFromPhase(phase ClaimPhase) (ClaimID, BoundPlan, durablePhaseSnapshot, error) {
	normalized, err := normalizeClaimPhase(phase, errInvalidDurableRecord)
	if err != nil {
		return ClaimID{}, BoundPlan{}, durablePhaseSnapshot{}, err
	}
	claim, ok := normalized.ClaimID()
	if !ok || !claim.Valid() {
		return ClaimID{}, BoundPlan{}, durablePhaseSnapshot{}, errInvalidDurableRecord
	}
	plan, ok := normalized.BoundPlan()
	if !ok || !plan.Valid() {
		return ClaimID{}, BoundPlan{}, durablePhaseSnapshot{}, errInvalidDurableRecord
	}

	snapshot := durablePhaseSnapshot{}
	switch current := normalized.(type) {
	case PendingBeforeAssignment:
		snapshot.tag = durablePhasePendingBeforeAssignment
	case AmbiguousBeforeAssignment:
		snapshot.tag = durablePhaseAmbiguousBeforeAssignment
	case EffectCapableAssigned:
		run, ok := current.AssignedRunRef()
		if !ok || !run.Valid() {
			return ClaimID{}, BoundPlan{}, durablePhaseSnapshot{}, errInvalidDurableRecord
		}
		snapshot.tag = durablePhaseEffectCapableAssigned
		snapshot.run = run.clone()
	case PendingAfterAssignment:
		run, ok := current.AssignedRunRef()
		if !ok || !run.Valid() {
			return ClaimID{}, BoundPlan{}, durablePhaseSnapshot{}, errInvalidDurableRecord
		}
		snapshot.tag = durablePhasePendingAfterAssignment
		snapshot.run = run.clone()
	case AmbiguousAfterAssignment:
		run, ok := current.AssignedRunRef()
		if !ok || !run.Valid() {
			return ClaimID{}, BoundPlan{}, durablePhaseSnapshot{}, errInvalidDurableRecord
		}
		snapshot.tag = durablePhaseAmbiguousAfterAssignment
		snapshot.run = run.clone()
	case Accepted:
		run, ok := current.AssignedRunRef()
		if !ok || !run.Valid() {
			return ClaimID{}, BoundPlan{}, durablePhaseSnapshot{}, errInvalidDurableRecord
		}
		receipt, ok := current.ReceiptRef()
		if !ok || !receipt.Valid() {
			return ClaimID{}, BoundPlan{}, durablePhaseSnapshot{}, errInvalidDurableRecord
		}
		snapshot.tag = durablePhaseAccepted
		snapshot.run = run.clone()
		snapshot.receipt = receipt.clone()
	case ProvablyNotAcceptedAfterAssignment:
		run, ok := current.AssignedRunRef()
		if !ok || !run.Valid() {
			return ClaimID{}, BoundPlan{}, durablePhaseSnapshot{}, errInvalidDurableRecord
		}
		snapshot.tag = durablePhaseProvablyNotAcceptedAfterAssignment
		snapshot.run = run.clone()
	default:
		return ClaimID{}, BoundPlan{}, durablePhaseSnapshot{}, errInvalidDurableRecord
	}
	if !snapshot.valid() {
		return ClaimID{}, BoundPlan{}, durablePhaseSnapshot{}, errInvalidDurableRecord
	}
	return claim.clone(), plan.clone(), snapshot, nil
}

func (s durablePhaseSnapshot) valid() bool {
	switch s.tag {
	case durablePhasePendingBeforeAssignment, durablePhaseAmbiguousBeforeAssignment:
		return !s.run.Valid() && !s.receipt.Valid()
	case durablePhaseEffectCapableAssigned, durablePhasePendingAfterAssignment,
		durablePhaseAmbiguousAfterAssignment, durablePhaseProvablyNotAcceptedAfterAssignment:
		return s.run.Valid() && !s.receipt.Valid()
	case durablePhaseAccepted:
		return s.run.Valid() && s.receipt.Valid()
	default:
		return false
	}
}

func (s durablePhaseSnapshot) clone() durablePhaseSnapshot {
	return durablePhaseSnapshot{
		tag:     s.tag,
		run:     s.run.clone(),
		receipt: s.receipt.clone(),
	}
}

func (s durablePhaseSnapshot) hydrate(claim ClaimID, plan BoundPlan) (ClaimPhase, error) {
	if !claim.Valid() || !plan.Valid() || !s.valid() {
		return nil, errInvalidDurableRecord
	}
	switch s.tag {
	case durablePhasePendingBeforeAssignment:
		return NewPendingBeforeAssignment(claim, plan)
	case durablePhaseAmbiguousBeforeAssignment:
		return NewAmbiguousBeforeAssignment(claim, plan)
	case durablePhaseEffectCapableAssigned:
		return hydrateAssignedPhase(claim, plan, s.run)
	case durablePhasePendingAfterAssignment:
		assigned, err := hydrateAssignedPhase(claim, plan, s.run)
		if err != nil {
			return nil, err
		}
		return NewPendingAfterAssignment(assigned)
	case durablePhaseAmbiguousAfterAssignment:
		assigned, err := hydrateAssignedPhase(claim, plan, s.run)
		if err != nil {
			return nil, err
		}
		return NewAmbiguousAfterAssignment(assigned)
	case durablePhaseAccepted:
		assigned, err := hydrateAssignedPhase(claim, plan, s.run)
		if err != nil {
			return nil, err
		}
		return NewAccepted(assigned, s.receipt)
	case durablePhaseProvablyNotAcceptedAfterAssignment:
		assigned, err := hydrateAssignedPhase(claim, plan, s.run)
		if err != nil {
			return nil, err
		}
		return NewProvablyNotAcceptedAfterAssignment(assigned)
	default:
		return nil, errInvalidDurableRecord
	}
}

func hydrateAssignedPhase(claim ClaimID, plan BoundPlan, run RunRef) (EffectCapableAssigned, error) {
	before, err := NewPendingBeforeAssignment(claim, plan)
	if err != nil {
		return EffectCapableAssigned{}, err
	}
	return AssignRun(before, run)
}

func (s durablePhaseSnapshot) equal(other durablePhaseSnapshot) bool {
	return s.tag == other.tag &&
		optionalRunRefEqual(s.run, other.run) &&
		optionalReceiptRefEqual(s.receipt, other.receipt)
}

type durableEffectRefTime struct {
	ref durableFactRef
	at  optionalClaimTime
}

func newDurableEffectRefTime(ref durableFactRef, at time.Time) durableEffectRefTime {
	return durableEffectRefTime{ref: ref.clone(), at: someClaimTime(at)}
}

func (f durableEffectRefTime) present() bool {
	return f.ref.valid() || f.at.valid
}

func (f durableEffectRefTime) valid() bool {
	return f.ref.valid() == f.at.valid
}

func (f durableEffectRefTime) clone() durableEffectRefTime {
	return durableEffectRefTime{ref: f.ref.clone(), at: f.at}
}

func (f durableEffectRefTime) equal(other durableEffectRefTime) bool {
	if !f.present() && !other.present() {
		return true
	}
	return f.ref.equal(other.ref) && f.at.equal(other.at)
}

type durableProviderObservationKind uint8

const (
	durableProviderObservationInvalid durableProviderObservationKind = iota
	durableProviderObservationPending
	durableProviderObservationAmbiguous
	durableProviderObservationAccepted
	durableProviderObservationNotAccepted
	durableProviderObservationCallUncertain
)

type durableProviderObservation struct {
	kind durableProviderObservationKind
	fact durableEffectRefTime
}

func (o durableProviderObservation) present() bool {
	return o.kind != durableProviderObservationInvalid || o.fact.present()
}

func (o durableProviderObservation) valid() bool {
	if o.kind == durableProviderObservationInvalid {
		return !o.fact.present()
	}
	return o.fact.valid() && o.fact.present()
}

func (o durableProviderObservation) clone() durableProviderObservation {
	return durableProviderObservation{kind: o.kind, fact: o.fact.clone()}
}

func (o durableProviderObservation) equal(other durableProviderObservation) bool {
	return o.kind == other.kind && o.fact.equal(other.fact)
}

type durableReconciliationKind uint8

const (
	durableReconciliationInvalid durableReconciliationKind = iota
	durableReconciliationNoDispatch
	durableReconciliationPending
	durableReconciliationAmbiguous
	durableReconciliationAccepted
	durableReconciliationNotAccepted
	durableReconciliationInconsistent
)

type durableReconciliationFact struct {
	kind durableReconciliationKind
	fact durableEffectRefTime
}

func (r durableReconciliationFact) present() bool {
	return r.kind != durableReconciliationInvalid || r.fact.present()
}

func (r durableReconciliationFact) valid() bool {
	if r.kind == durableReconciliationInvalid {
		return !r.fact.present()
	}
	return r.fact.valid() && r.fact.present()
}

func (r durableReconciliationFact) clone() durableReconciliationFact {
	return durableReconciliationFact{kind: r.kind, fact: r.fact.clone()}
}

func (r durableReconciliationFact) equal(other durableReconciliationFact) bool {
	return r.kind == other.kind && r.fact.equal(other.fact)
}

type durableEffectFacts struct {
	intent         durableEffectRefTime
	staging        durableEffectRefTime
	dispatch       durableEffectRefTime
	provider       durableProviderObservation
	reconciliation durableReconciliationFact
}

func (f durableEffectFacts) clone() durableEffectFacts {
	return durableEffectFacts{
		intent:         f.intent.clone(),
		staging:        f.staging.clone(),
		dispatch:       f.dispatch.clone(),
		provider:       f.provider.clone(),
		reconciliation: f.reconciliation.clone(),
	}
}

func (f durableEffectFacts) validForPhase(tag durablePhaseTag) bool {
	return f.validForCodecPhase(tag, false)
}

func (f durableEffectFacts) validForCodecPhase(tag durablePhaseTag, progress bool) bool {
	if !f.intent.valid() || !f.staging.valid() || !f.dispatch.valid() ||
		!f.provider.valid() || !f.reconciliation.valid() {
		return false
	}
	if (f.intent.present() || f.staging.present() || f.dispatch.present() ||
		f.provider.present() || f.reconciliation.present()) &&
		!durablePhaseTagHasAssignedRun(tag) {
		return false
	}
	if f.staging.present() && !f.intent.present() {
		return false
	}
	if f.dispatch.present() && !f.intent.present() {
		return false
	}
	if f.provider.present() && !f.dispatch.present() {
		return false
	}
	if f.provider.present() && !providerObservationCompatibleWithPhase(f.provider.kind, tag) {
		return false
	}
	if tag == durablePhaseAccepted && f.provider.kind != durableProviderObservationAccepted {
		return false
	}
	if f.reconciliation.present() && !f.intent.present() {
		return false
	}
	if f.reconciliation.present() {
		if progress {
			if !f.progressReconciliationCompatible(tag) {
				return false
			}
		} else if !reconciliationCompatibleWithPhaseAndFacts(f.reconciliation.kind, tag, f.dispatch.present(), f.provider.present()) {
			return false
		}
	}
	if tag == durablePhaseProvablyNotAcceptedAfterAssignment &&
		f.provider.kind != durableProviderObservationNotAccepted &&
		f.reconciliation.kind != durableReconciliationNotAccepted {
		return false
	}
	return true
}

func (f durableEffectFacts) progressReconciliationCompatible(tag durablePhaseTag) bool {
	at := f.reconciliation.fact.at.value
	if !f.intent.present() || at.Before(f.intent.at.value) {
		return false
	}
	if f.reconciliation.kind == durableReconciliationNoDispatch {
		if f.dispatch.present() {
			return !at.After(f.dispatch.at.value) && tag >= durablePhaseEffectCapableAssigned
		}
		return !f.provider.present() && tag == durablePhaseEffectCapableAssigned
	}
	if !f.dispatch.present() || at.Before(f.dispatch.at.value) {
		return false
	}
	switch f.reconciliation.kind {
	case durableReconciliationPending, durableReconciliationAmbiguous, durableReconciliationInconsistent:
		return tag >= durablePhasePendingAfterAssignment
	case durableReconciliationAccepted:
		return tag == durablePhaseAccepted
	case durableReconciliationNotAccepted:
		return tag == durablePhaseProvablyNotAcceptedAfterAssignment
	default:
		return false
	}
}

func durablePhaseTagHasAssignedRun(tag durablePhaseTag) bool {
	switch tag {
	case durablePhaseEffectCapableAssigned, durablePhasePendingAfterAssignment,
		durablePhaseAmbiguousAfterAssignment, durablePhaseAccepted,
		durablePhaseProvablyNotAcceptedAfterAssignment:
		return true
	default:
		return false
	}
}

func providerObservationCompatibleWithPhase(kind durableProviderObservationKind, tag durablePhaseTag) bool {
	switch kind {
	case durableProviderObservationPending:
		return tag == durablePhasePendingAfterAssignment
	case durableProviderObservationAmbiguous, durableProviderObservationCallUncertain:
		return tag == durablePhaseAmbiguousAfterAssignment
	case durableProviderObservationAccepted:
		return tag == durablePhaseAccepted
	case durableProviderObservationNotAccepted:
		return tag == durablePhaseProvablyNotAcceptedAfterAssignment
	default:
		return false
	}
}

func reconciliationCompatibleWithPhaseAndFacts(kind durableReconciliationKind, tag durablePhaseTag, hasDispatch bool, hasProvider bool) bool {
	switch kind {
	case durableReconciliationNoDispatch:
		return !hasDispatch && !hasProvider && tag == durablePhaseEffectCapableAssigned
	case durableReconciliationPending:
		return hasDispatch && tag == durablePhasePendingAfterAssignment
	case durableReconciliationAmbiguous, durableReconciliationInconsistent:
		return hasDispatch && tag == durablePhaseAmbiguousAfterAssignment
	case durableReconciliationAccepted:
		return hasDispatch && tag == durablePhaseAccepted
	case durableReconciliationNotAccepted:
		return hasDispatch && tag == durablePhaseProvablyNotAcceptedAfterAssignment
	default:
		return false
	}
}

func (f durableEffectFacts) equal(other durableEffectFacts) bool {
	return f.intent.equal(other.intent) &&
		f.staging.equal(other.staging) &&
		f.dispatch.equal(other.dispatch) &&
		f.provider.equal(other.provider) &&
		f.reconciliation.equal(other.reconciliation)
}

type durableRetentionState uint8

const (
	durableRetentionActive durableRetentionState = iota + 1
	durableRetentionExpired
	durableRetentionTombstoned
)

type durableRetentionFact struct {
	state         durableRetentionState
	unavailableAt optionalClaimTime
	reason        string
}

func activeDurableRetention() durableRetentionFact {
	return durableRetentionFact{state: durableRetentionActive}
}

func (r durableRetentionFact) valid() bool {
	switch r.state {
	case durableRetentionActive:
		return !r.unavailableAt.valid && r.reason == ""
	case durableRetentionExpired, durableRetentionTombstoned:
		return r.unavailableAt.valid && r.reason != ""
	default:
		return false
	}
}

func (r durableRetentionFact) equal(other durableRetentionFact) bool {
	return r.state == other.state &&
		r.reason == other.reason &&
		r.unavailableAt.equal(other.unavailableAt)
}

type durableClaimRecord struct {
	progressRowID   int64 // Codecs 4 and 5 retain the physical identity after insertion.
	codecVersion    uint16
	claim           ClaimID
	plan            BoundPlan
	phase           durablePhaseSnapshot
	revision        claimRevision
	effects         durableEffectFacts
	createdAt       time.Time
	updatedAt       time.Time
	assignedAt      optionalClaimTime
	expiresAt       optionalClaimTime
	retention       durableRetentionFact
	lastMutation    durableMutationRef
	latestOperation durableLatestOperationDescriptor
	replay          replayClaimDescriptor
}

type newDurableClaimRecordInput struct {
	phase           ClaimPhase
	revision        claimRevision
	createdAt       time.Time
	updatedAt       time.Time
	assignedAt      optionalClaimTime
	expiresAt       optionalClaimTime
	effects         durableEffectFacts
	retention       durableRetentionFact
	latestOperation durableLatestOperationDescriptor
}

func newDurableClaimRecord(input newDurableClaimRecordInput) (durableClaimRecord, error) {
	claim, plan, snapshot, err := durablePhaseSnapshotFromPhase(input.phase)
	if err != nil {
		return durableClaimRecord{}, err
	}
	record := durableClaimRecord{
		codecVersion:    durableClaimCodecVersion,
		claim:           claim,
		plan:            plan,
		phase:           snapshot,
		revision:        input.revision,
		effects:         input.effects.clone(),
		createdAt:       normalizeClaimTime(input.createdAt),
		updatedAt:       normalizeClaimTime(input.updatedAt),
		assignedAt:      input.assignedAt,
		expiresAt:       input.expiresAt,
		retention:       input.retention,
		lastMutation:    input.latestOperation.mutation.clone(),
		latestOperation: input.latestOperation.clone(),
	}
	if record.retention.state == 0 {
		record.retention = activeDurableRetention()
	}
	if err := record.validate(); err != nil {
		return durableClaimRecord{}, err
	}
	return record, nil
}

func (r durableClaimRecord) validate() error {
	if (r.codecVersion != durableClaimCodecVersion && r.codecVersion != durableClaimCodecVersionLegacy && r.codecVersion != durableClaimCodecVersionSynthetic && r.codecVersion != durableClaimCodecVersionProgress && r.codecVersion != durableClaimCodecVersionOperational) ||
		!r.claim.Valid() ||
		!r.plan.Valid() ||
		!r.phase.valid() ||
		r.revision < initialClaimRevision ||
		r.createdAt.IsZero() ||
		r.updatedAt.IsZero() ||
		r.updatedAt.Before(r.createdAt) ||
		!r.retention.valid() ||
		!r.lastMutation.valid() ||
		!r.latestOperation.validForCodec(r.codecVersion, r.lastMutation) {
		return errInvalidDurableRecord
	}
	if _, err := r.phase.hydrate(r.claim, r.plan); err != nil {
		return errInvalidDurableRecord
	}
	if r.assignedAt.valid {
		if r.assignedAt.value.Before(r.createdAt) || !r.phase.run.Valid() {
			return errInvalidDurableRecord
		}
	}
	if r.phase.run.Valid() && !r.assignedAt.valid {
		return errInvalidDurableRecord
	}
	if !r.effects.validForCodecPhase(r.phase.tag, r.codecVersion == durableClaimCodecVersionProgress) {
		return errInvalidDurableRecord
	}
	if r.codecVersion == durableClaimCodecVersionProgress {
		return r.validateFixtureProgress()
	}
	if r.codecVersion == durableClaimCodecVersionOperational {
		return r.validateOperationalProgress()
	}
	if r.progressRowID != 0 {
		return errInvalidDurableRecord
	}
	if r.codecVersion == durableClaimCodecVersionSynthetic {
		if !r.replay.valid() || r.phase.tag != durablePhasePendingBeforeAssignment ||
			r.revision != initialClaimRevision || r.expiresAt.valid ||
			r.assignedAt.valid || r.retention.state != durableRetentionActive ||
			r.latestOperation.kind != durableOperationEstablishClaim ||
			len(r.claim.caller.ref.value) != 32 || len(r.claim.submitKey.ref.value) != 32 ||
			len(r.plan.binding.ref.value) > 256 {
			return errInvalidDurableRecord
		}
	} else if !r.replay.zero() {
		return errInvalidDurableRecord
	}
	return nil
}

func (r durableClaimRecord) validateFixtureProgress() error {
	if !r.replay.validForScope(2) || len(r.claim.caller.ref.value) != 32 ||
		len(r.claim.submitKey.ref.value) != 32 || len(r.plan.binding.ref.value) > 256 ||
		len(r.lastMutation.ref.value) != 32 || r.expiresAt.valid ||
		r.retention.state != durableRetentionActive || r.createdAt.UnixNano() <= 0 ||
		!time.Unix(0, r.createdAt.UnixNano()).Equal(r.createdAt) ||
		!time.Unix(0, r.updatedAt.UnixNano()).Equal(r.updatedAt) {
		return errInvalidDurableRecord
	}
	if r.revision == initialClaimRevision {
		if r.phase.tag > durablePhaseAmbiguousBeforeAssignment ||
			r.latestOperation.kind != durableOperationEstablishClaim || !r.updatedAt.Equal(r.createdAt) {
			return errInvalidDurableRecord
		}
	} else if r.progressRowID == 0 || r.latestOperation.kind == durableOperationEstablishClaim {
		return errInvalidDurableRecord
	}
	for _, ref := range []opaqueRef{r.phase.run.ref, r.phase.receipt.ref, r.effects.intent.ref.ref,
		r.effects.staging.ref.ref, r.effects.dispatch.ref.ref, r.effects.provider.fact.ref.ref,
		r.effects.reconciliation.fact.ref.ref} {
		if ref.valid() && len(ref.value) != 32 {
			return errInvalidDurableRecord
		}
	}
	for _, at := range []optionalClaimTime{r.assignedAt, r.effects.intent.at, r.effects.staging.at,
		r.effects.dispatch.at, r.effects.provider.fact.at, r.effects.reconciliation.fact.at} {
		if at.valid && (at.value.Before(r.createdAt) || at.value.After(r.updatedAt)) {
			return errInvalidDurableRecord
		}
	}
	if r.effects.provider.present() && r.effects.provider.fact.at.value.Before(r.effects.dispatch.at.value) {
		return errInvalidDurableRecord
	}
	return nil
}

func (r durableClaimRecord) sameProgressOriginal(other durableClaimRecord) bool {
	return r.codecVersion == durableClaimCodecVersionProgress && other.codecVersion == r.codecVersion &&
		r.progressRowID != 0 && r.progressRowID == other.progressRowID && r.claim.Equal(other.claim) &&
		r.plan.EqualBinding(other.plan.Binding()) && witnessEqual(r.plan.Witness(), other.plan.Witness()) &&
		r.createdAt.Equal(other.createdAt) && r.replay.equal(other.replay)
}

func (r durableClaimRecord) hydratePhase() (ClaimPhase, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	return r.phase.hydrate(r.claim, r.plan)
}

func (r durableClaimRecord) clone() durableClaimRecord {
	return durableClaimRecord{
		progressRowID:   r.progressRowID,
		codecVersion:    r.codecVersion,
		claim:           r.claim.clone(),
		plan:            r.plan.clone(),
		phase:           r.phase.clone(),
		revision:        r.revision,
		effects:         r.effects.clone(),
		createdAt:       normalizeClaimTime(r.createdAt),
		updatedAt:       normalizeClaimTime(r.updatedAt),
		assignedAt:      r.assignedAt,
		expiresAt:       r.expiresAt,
		retention:       r.retention,
		lastMutation:    r.lastMutation.clone(),
		latestOperation: r.latestOperation.clone(),
		replay:          r.replay.clone(),
	}
}

func (r durableClaimRecord) activeAt(now time.Time) bool {
	if r.retention.state != durableRetentionActive {
		return false
	}
	if r.expiresAt.valid && !normalizeClaimTime(now).Before(r.expiresAt.value) {
		return false
	}
	return true
}

func (r durableClaimRecord) equal(other durableClaimRecord) bool {
	return r.progressRowID == other.progressRowID && r.codecVersion == other.codecVersion &&
		r.claim.Equal(other.claim) &&
		r.plan.EqualBinding(other.plan.Binding()) &&
		witnessEqual(r.plan.Witness(), other.plan.Witness()) &&
		r.phase.equal(other.phase) &&
		r.revision == other.revision &&
		r.effects.equal(other.effects) &&
		normalizeClaimTime(r.createdAt).Equal(normalizeClaimTime(other.createdAt)) &&
		normalizeClaimTime(r.updatedAt).Equal(normalizeClaimTime(other.updatedAt)) &&
		r.assignedAt.equal(other.assignedAt) &&
		r.expiresAt.equal(other.expiresAt) &&
		r.retention.equal(other.retention) &&
		r.lastMutation.equal(other.lastMutation) &&
		r.latestOperation.equal(other.latestOperation) &&
		r.replay.equal(other.replay)
}

func witnessEqual(left EffectivePlanWitness, right EffectivePlanWitness) bool {
	if !left.Valid() || !right.Valid() {
		return false
	}
	for _, category := range allEffectivePlanCategories {
		leftResolution, err := left.Resolution(category)
		if err != nil {
			return false
		}
		rightResolution, err := right.Resolution(category)
		if err != nil {
			return false
		}
		if leftResolution != rightResolution {
			return false
		}
	}
	return true
}

func opaqueRefBytes(ref opaqueRef) []byte {
	return ref.clone().value
}

func mutationRefBytes(ref durableMutationRef) []byte {
	return opaqueRefBytes(ref.ref)
}

func factRefBytes(ref durableFactRef) []byte {
	return opaqueRefBytes(ref.ref)
}

func bytesToOptionalFactRef(value []byte) (durableFactRef, error) {
	if len(value) == 0 {
		return durableFactRef{}, nil
	}
	return newDurableFactRef(value)
}

func bytesEqual(left []byte, right []byte) bool {
	return bytes.Equal(left, right)
}

func optionalRunRefEqual(left RunRef, right RunRef) bool {
	if !left.Valid() && !right.Valid() {
		return true
	}
	return left.Equal(right)
}

func optionalReceiptRefEqual(left ReceiptRef, right ReceiptRef) bool {
	if !left.Valid() && !right.Valid() {
		return true
	}
	return left.Equal(right)
}

func (t durablePhaseTag) String() string {
	switch t {
	case durablePhasePendingBeforeAssignment:
		return "pending_before_assignment"
	case durablePhaseAmbiguousBeforeAssignment:
		return "ambiguous_before_assignment"
	case durablePhaseEffectCapableAssigned:
		return "effect_capable_assigned"
	case durablePhasePendingAfterAssignment:
		return "pending_after_assignment"
	case durablePhaseAmbiguousAfterAssignment:
		return "ambiguous_after_assignment"
	case durablePhaseAccepted:
		return "accepted"
	case durablePhaseProvablyNotAcceptedAfterAssignment:
		return "provably_not_accepted_after_assignment"
	default:
		return "invalid"
	}
}

func formatDurableOpaque(state fmt.State, typeName string, valid bool) {
	formatOpaque(state, typeName, valid)
}
