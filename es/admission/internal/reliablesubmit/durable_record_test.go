package reliablesubmit

import (
	"errors"
	"testing"
	"time"
)

type durableFixture struct {
	caller      CallerRef
	submitKey   SubmitKeyRef
	claim       ClaimID
	binding     PlanBinding
	otherBind   PlanBinding
	witness     EffectivePlanWitness
	plan        BoundPlan
	run         RunRef
	otherRun    RunRef
	receipt     ReceiptRef
	mutation    durableMutationRef
	nextMut     durableMutationRef
	intent      durableFactRef
	staging     durableFactRef
	dispatch    durableFactRef
	observation durableFactRef
	reconcile   durableFactRef
	now         time.Time
	later       time.Time
}

func newDurableFixture(t *testing.T) durableFixture {
	t.Helper()
	caller := mustPrivateCallerRef(t, []byte("private-caller-reference"))
	submitKey := mustPrivateSubmitKeyRef(t, []byte("private-submit-key-reference"))
	claim := mustPrivateClaimID(t, caller, submitKey)
	binding := mustPrivatePlanBinding(t, []byte("private-plan-binding"))
	otherBind := mustPrivatePlanBinding(t, []byte("private-plan-binding-other"))
	witness := mustPrivateCompleteWitness(t)
	plan := mustPrivateBoundPlan(t, binding, witness)
	run := mustPrivateRunRef(t, []byte("private-run-reference"))
	otherRun := mustPrivateRunRef(t, []byte("private-run-reference-other"))
	receipt := mustPrivateReceiptRef(t, []byte("private-receipt-reference"))
	return durableFixture{
		caller:      caller,
		submitKey:   submitKey,
		claim:       claim,
		binding:     binding,
		otherBind:   otherBind,
		witness:     witness,
		plan:        plan,
		run:         run,
		otherRun:    otherRun,
		receipt:     receipt,
		mutation:    mustPrivateMutationRef(t, []byte("private-mutation-reference")),
		nextMut:     mustPrivateMutationRef(t, []byte("private-mutation-reference-next")),
		intent:      mustPrivateFactRef(t, []byte("private-effect-intent")),
		staging:     mustPrivateFactRef(t, []byte("private-staging-evidence")),
		dispatch:    mustPrivateFactRef(t, []byte("private-dispatch-attempt")),
		observation: mustPrivateFactRef(t, []byte("private-provider-observation")),
		reconcile:   mustPrivateFactRef(t, []byte("private-reconciliation")),
		now:         time.Unix(1730000000, 111).UTC(),
		later:       time.Unix(1730000010, 222).UTC(),
	}
}

func mustPrivateCallerRef(t *testing.T, value []byte) CallerRef {
	t.Helper()
	ref, err := NewCallerRef(value)
	if err != nil {
		t.Fatalf("NewCallerRef: %v", err)
	}
	return ref
}

func mustPrivateSubmitKeyRef(t *testing.T, value []byte) SubmitKeyRef {
	t.Helper()
	ref, err := NewSubmitKeyRef(value)
	if err != nil {
		t.Fatalf("NewSubmitKeyRef: %v", err)
	}
	return ref
}

func mustPrivateClaimID(t *testing.T, caller CallerRef, key SubmitKeyRef) ClaimID {
	t.Helper()
	claim, err := NewClaimID(caller, key)
	if err != nil {
		t.Fatalf("NewClaimID: %v", err)
	}
	return claim
}

func mustPrivatePlanBinding(t *testing.T, value []byte) PlanBinding {
	t.Helper()
	binding, err := NewPlanBinding(value)
	if err != nil {
		t.Fatalf("NewPlanBinding: %v", err)
	}
	return binding
}

func mustPrivateCompleteWitness(t *testing.T) EffectivePlanWitness {
	t.Helper()
	entries := make([]EffectivePlanCategoryCompleteness, 0, len(allEffectivePlanCategories))
	for _, category := range allEffectivePlanCategories {
		entry, err := ResolvedCategory(category)
		if err != nil {
			t.Fatalf("ResolvedCategory: %v", err)
		}
		entries = append(entries, entry)
	}
	witness, err := NewEffectivePlanWitness(entries...)
	if err != nil {
		t.Fatalf("NewEffectivePlanWitness: %v", err)
	}
	return witness
}

func mustPrivateBoundPlan(t *testing.T, binding PlanBinding, witness EffectivePlanWitness) BoundPlan {
	t.Helper()
	plan, err := NewBoundPlan(binding, witness)
	if err != nil {
		t.Fatalf("NewBoundPlan: %v", err)
	}
	return plan
}

func mustPrivateRunRef(t *testing.T, value []byte) RunRef {
	t.Helper()
	ref, err := NewRunRef(value)
	if err != nil {
		t.Fatalf("NewRunRef: %v", err)
	}
	return ref
}

func mustPrivateReceiptRef(t *testing.T, value []byte) ReceiptRef {
	t.Helper()
	ref, err := NewReceiptRef(value)
	if err != nil {
		t.Fatalf("NewReceiptRef: %v", err)
	}
	return ref
}

func mustPrivateMutationRef(t *testing.T, value []byte) durableMutationRef {
	t.Helper()
	ref, err := newDurableMutationRef(value)
	if err != nil {
		t.Fatalf("newDurableMutationRef: %v", err)
	}
	return ref
}

func mustPrivateFactRef(t *testing.T, value []byte) durableFactRef {
	t.Helper()
	ref, err := newDurableFactRef(value)
	if err != nil {
		t.Fatalf("newDurableFactRef: %v", err)
	}
	return ref
}

func mustPrivatePendingBefore(t *testing.T, f durableFixture) PendingBeforeAssignment {
	t.Helper()
	phase, err := NewPendingBeforeAssignment(f.claim, f.plan)
	if err != nil {
		t.Fatalf("NewPendingBeforeAssignment: %v", err)
	}
	return phase
}

func mustPrivateAssigned(t *testing.T, f durableFixture) EffectCapableAssigned {
	t.Helper()
	assigned, err := AssignRun(mustPrivatePendingBefore(t, f), f.run)
	if err != nil {
		t.Fatalf("AssignRun: %v", err)
	}
	return assigned
}

func mustPrivateRecord(t *testing.T, phase ClaimPhase, f durableFixture) durableClaimRecord {
	t.Helper()
	record, err := newDurableClaimRecord(newDurableClaimRecordInput{
		phase:           phase,
		revision:        initialClaimRevision,
		createdAt:       f.now,
		updatedAt:       f.now,
		assignedAt:      assignedAtForPhase(phase, f.now),
		retention:       activeDurableRetention(),
		latestOperation: mustDurableOperationDescriptor(t, f.mutation),
	})
	if err != nil {
		t.Fatalf("newDurableClaimRecord: %v", err)
	}
	return record
}

func mustDurableOperationDescriptor(t *testing.T, mutation durableMutationRef) durableLatestOperationDescriptor {
	t.Helper()
	operation, err := deriveDurableOperationDescriptor(
		mutation,
		durableOperationEstablishClaim,
		0,
		operationPartUint16(durableOperationPartInitialPhase, uint16(durablePhasePendingBeforeAssignment)),
		operationPartOptionalClaimTime(durableOperationPartExpiresAt, noClaimTime()),
	)
	if err != nil {
		t.Fatalf("deriveDurableOperationDescriptor: %v", err)
	}
	return operation
}

func assignedAtForPhase(phase ClaimPhase, at time.Time) optionalClaimTime {
	if phase.HasAssignedRunRef() {
		return someClaimTime(at)
	}
	return noClaimTime()
}

func TestDurablePhaseSnapshotExhaustivelyMapsPersistableModelPhases(t *testing.T) {
	f := newDurableFixture(t)
	assigned := mustPrivateAssigned(t, f)
	pendingAfter, err := NewPendingAfterAssignment(assigned)
	if err != nil {
		t.Fatalf("NewPendingAfterAssignment: %v", err)
	}
	ambiguousBefore, err := NewAmbiguousBeforeAssignment(f.claim, f.plan)
	if err != nil {
		t.Fatalf("NewAmbiguousBeforeAssignment: %v", err)
	}
	ambiguousAfter, err := NewAmbiguousAfterAssignment(assigned)
	if err != nil {
		t.Fatalf("NewAmbiguousAfterAssignment: %v", err)
	}
	accepted, err := NewAccepted(assigned, f.receipt)
	if err != nil {
		t.Fatalf("NewAccepted: %v", err)
	}
	notAccepted, err := NewProvablyNotAcceptedAfterAssignment(assigned)
	if err != nil {
		t.Fatalf("NewProvablyNotAcceptedAfterAssignment: %v", err)
	}

	cases := []struct {
		name string
		in   ClaimPhase
		tag  durablePhaseTag
		kind Kind
	}{
		{name: "pending before", in: mustPrivatePendingBefore(t, f), tag: durablePhasePendingBeforeAssignment, kind: KindPendingBeforeAssignment},
		{name: "ambiguous before", in: ambiguousBefore, tag: durablePhaseAmbiguousBeforeAssignment, kind: KindAmbiguousBeforeAssignment},
		{name: "assigned", in: assigned, tag: durablePhaseEffectCapableAssigned, kind: KindEffectCapableAssigned},
		{name: "pending after", in: pendingAfter, tag: durablePhasePendingAfterAssignment, kind: KindPendingAfterAssignment},
		{name: "ambiguous after", in: ambiguousAfter, tag: durablePhaseAmbiguousAfterAssignment, kind: KindAmbiguousAfterAssignment},
		{name: "accepted", in: accepted, tag: durablePhaseAccepted, kind: KindAccepted},
		{name: "not accepted", in: notAccepted, tag: durablePhaseProvablyNotAcceptedAfterAssignment, kind: KindProvablyNotAcceptedAfterAssignment},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claim, plan, snapshot, err := durablePhaseSnapshotFromPhase(tc.in)
			if err != nil {
				t.Fatalf("durablePhaseSnapshotFromPhase: %v", err)
			}
			if !claim.Equal(f.claim) || !plan.EqualBinding(f.binding) || snapshot.tag != tc.tag {
				t.Fatalf("unexpected snapshot: claim=%v plan=%v tag=%v", claim, plan, snapshot.tag)
			}
			hydrated, err := snapshot.hydrate(claim, plan)
			if err != nil {
				t.Fatalf("hydrate: %v", err)
			}
			if hydrated.Kind() != tc.kind {
				t.Fatalf("hydrated kind = %v, want %v", hydrated.Kind(), tc.kind)
			}
			if err := ValidatePlanBinding(hydrated, f.binding); err != nil {
				t.Fatalf("hydrated binding: %v", err)
			}
		})
	}
}

func TestDurablePhaseSnapshotRejectsDecisionViewsAsStoredPhases(t *testing.T) {
	f := newDurableFixture(t)
	accepted, err := NewAccepted(mustPrivateAssigned(t, f), f.receipt)
	if err != nil {
		t.Fatalf("NewAccepted: %v", err)
	}
	recovered, err := NewRecoveredAccepted(accepted)
	if err != nil {
		t.Fatalf("NewRecoveredAccepted: %v", err)
	}
	replay, err := NewExactReplay(accepted)
	if err != nil {
		t.Fatalf("NewExactReplay: %v", err)
	}
	conflict, err := NewConflict()
	if err != nil {
		t.Fatalf("NewConflict: %v", err)
	}
	unauthorized, err := NewUnauthorized()
	if err != nil {
		t.Fatalf("NewUnauthorized: %v", err)
	}
	expired, err := NewExpiredUnavailable()
	if err != nil {
		t.Fatalf("NewExpiredUnavailable: %v", err)
	}
	for name, decision := range map[string]any{
		"recovered":    recovered,
		"exact replay": replay,
		"conflict":     conflict,
		"unauthorized": unauthorized,
		"expired":      expired,
	} {
		if _, ok := decision.(ClaimPhase); ok {
			t.Fatalf("%s decision unexpectedly implements ClaimPhase", name)
		}
	}
}

func TestDurableClaimRecordCopiesRefsAndStoresUTCTime(t *testing.T) {
	f := newDurableFixture(t)
	callerInput := []byte("copy-caller")
	keyInput := []byte("copy-key")
	bindingInput := []byte("copy-binding")
	mutationInput := []byte("copy-mutation")
	caller := mustPrivateCallerRef(t, callerInput)
	key := mustPrivateSubmitKeyRef(t, keyInput)
	claim := mustPrivateClaimID(t, caller, key)
	binding := mustPrivatePlanBinding(t, bindingInput)
	plan := mustPrivateBoundPlan(t, binding, f.witness)
	mutation := mustPrivateMutationRef(t, mutationInput)
	phase, err := NewPendingBeforeAssignment(claim, plan)
	if err != nil {
		t.Fatalf("NewPendingBeforeAssignment: %v", err)
	}
	record, err := newDurableClaimRecord(newDurableClaimRecordInput{
		phase:           phase,
		revision:        initialClaimRevision,
		createdAt:       time.Now(),
		updatedAt:       time.Now().Add(time.Second),
		retention:       activeDurableRetention(),
		latestOperation: mustDurableOperationDescriptor(t, mutation),
	})
	if err != nil {
		t.Fatalf("newDurableClaimRecord: %v", err)
	}
	callerInput[0] = 'x'
	keyInput[0] = 'x'
	bindingInput[0] = 'x'
	mutationInput[0] = 'x'
	hydrated, err := record.hydratePhase()
	if err != nil {
		t.Fatalf("hydratePhase: %v", err)
	}
	if err := ValidatePlanBinding(hydrated, mustPrivatePlanBinding(t, []byte("copy-binding"))); err != nil {
		t.Fatalf("record did not preserve copied binding: %v", err)
	}
	if !record.lastMutation.equal(mustPrivateMutationRef(t, []byte("copy-mutation"))) {
		t.Fatalf("record did not preserve copied mutation ref")
	}
	if record.createdAt.Location() != time.UTC || record.updatedAt.Location() != time.UTC {
		t.Fatalf("record timestamps are not normalized to UTC")
	}
}

func TestDurableClaimRecordCodecRequiresLatestOperationDescriptor(t *testing.T) {
	f := newDurableFixture(t)
	record := mustPrivateRecord(t, mustPrivatePendingBefore(t, f), f)
	if record.codecVersion != durableClaimCodecVersion || !record.latestOperation.complete() {
		t.Fatalf("new record did not use complete codec v2 descriptor: %+v", record)
	}

	legacy := record.clone()
	legacy.codecVersion = durableClaimCodecVersionLegacy
	var err error
	legacy.latestOperation, err = newLegacyDurableLatestOperationDescriptor(legacy.lastMutation)
	if err != nil {
		t.Fatalf("legacy descriptor: %v", err)
	}
	if err := legacy.validate(); err != nil {
		t.Fatalf("legacy unbound record rejected: %v", err)
	}

	codec2Missing := record.clone()
	codec2Missing.latestOperation = durableLatestOperationDescriptor{mutation: codec2Missing.lastMutation}
	if err := codec2Missing.validate(); !errors.Is(err, errInvalidDurableRecord) {
		t.Fatalf("codec v2 missing descriptor error = %v", err)
	}
	codec1Partial := legacy.clone()
	codec1Partial.latestOperation.kind = durableOperationAssignRun
	if err := codec1Partial.validate(); !errors.Is(err, errInvalidDurableRecord) {
		t.Fatalf("codec v1 partial descriptor error = %v", err)
	}
	mismatch := record.clone()
	mismatch.latestOperation.mutation = f.nextMut
	if err := mismatch.validate(); !errors.Is(err, errInvalidDurableRecord) {
		t.Fatalf("descriptor mutation mismatch error = %v", err)
	}

	otherDescriptor, err := deriveDurableOperationDescriptor(record.lastMutation, durableOperationAssignRun, initialClaimRevision, operationPartRunRef(f.run))
	if err != nil {
		t.Fatalf("derive alternate descriptor: %v", err)
	}
	other := record.clone()
	other.latestOperation = otherDescriptor
	if err := other.validate(); err != nil {
		t.Fatalf("alternate complete descriptor rejected: %v", err)
	}
	if record.equal(other) {
		t.Fatalf("record equality ignored latest-operation descriptor")
	}
}

func TestDurableRecordRejectsContradictoryEffectFacts(t *testing.T) {
	f := newDurableFixture(t)
	assigned := mustPrivateAssigned(t, f)
	effects := durableEffectFacts{
		staging: newDurableEffectRefTime(f.staging, f.now),
	}
	_, err := newDurableClaimRecord(newDurableClaimRecordInput{
		phase:           assigned,
		revision:        initialClaimRevision,
		createdAt:       f.now,
		updatedAt:       f.now,
		assignedAt:      someClaimTime(f.now),
		effects:         effects,
		retention:       activeDurableRetention(),
		latestOperation: mustDurableOperationDescriptor(t, f.mutation),
	})
	if !errors.Is(err, errInvalidDurableRecord) {
		t.Fatalf("expected invalid durable record, got %v", err)
	}
}

func TestDurableRecordRejectsProviderAndReconciliationContradictions(t *testing.T) {
	f := newDurableFixture(t)
	assigned := mustPrivateAssigned(t, f)
	pendingAfter, err := NewPendingAfterAssignment(assigned)
	if err != nil {
		t.Fatalf("NewPendingAfterAssignment: %v", err)
	}
	ambiguousAfter, err := NewAmbiguousAfterAssignment(assigned)
	if err != nil {
		t.Fatalf("NewAmbiguousAfterAssignment: %v", err)
	}
	notAccepted, err := NewProvablyNotAcceptedAfterAssignment(assigned)
	if err != nil {
		t.Fatalf("NewProvablyNotAcceptedAfterAssignment: %v", err)
	}
	intentDispatch := durableEffectFacts{
		intent:   newDurableEffectRefTime(f.intent, f.now),
		dispatch: newDurableEffectRefTime(f.dispatch, f.now),
	}
	for _, tc := range []struct {
		name    string
		phase   ClaimPhase
		effects durableEffectFacts
		wantErr bool
	}{
		{
			name:  "provider pending requires pending phase",
			phase: assigned,
			effects: durableEffectFacts{
				intent:   intentDispatch.intent,
				dispatch: intentDispatch.dispatch,
				provider: durableProviderObservation{kind: durableProviderObservationPending, fact: newDurableEffectRefTime(f.observation, f.now)},
			},
			wantErr: true,
		},
		{
			name:  "provider pending matches pending phase",
			phase: pendingAfter,
			effects: durableEffectFacts{
				intent:   intentDispatch.intent,
				dispatch: intentDispatch.dispatch,
				provider: durableProviderObservation{kind: durableProviderObservationPending, fact: newDurableEffectRefTime(f.observation, f.now)},
			},
		},
		{
			name:  "provider ambiguous rejects pending phase",
			phase: pendingAfter,
			effects: durableEffectFacts{
				intent:   intentDispatch.intent,
				dispatch: intentDispatch.dispatch,
				provider: durableProviderObservation{kind: durableProviderObservationAmbiguous, fact: newDurableEffectRefTime(f.observation, f.now)},
			},
			wantErr: true,
		},
		{
			name:  "validated no dispatch requires no marker",
			phase: assigned,
			effects: durableEffectFacts{
				intent:         intentDispatch.intent,
				reconciliation: durableReconciliationFact{kind: durableReconciliationNoDispatch, fact: newDurableEffectRefTime(f.reconcile, f.now)},
			},
		},
		{
			name:  "validated no dispatch rejects dispatch marker",
			phase: assigned,
			effects: durableEffectFacts{
				intent:         intentDispatch.intent,
				dispatch:       intentDispatch.dispatch,
				reconciliation: durableReconciliationFact{kind: durableReconciliationNoDispatch, fact: newDurableEffectRefTime(f.reconcile, f.now)},
			},
			wantErr: true,
		},
		{
			name:  "reconciliation pending requires marker",
			phase: pendingAfter,
			effects: durableEffectFacts{
				intent:         intentDispatch.intent,
				reconciliation: durableReconciliationFact{kind: durableReconciliationPending, fact: newDurableEffectRefTime(f.reconcile, f.now)},
			},
			wantErr: true,
		},
		{
			name:  "reconciliation ambiguous matches ambiguous phase",
			phase: ambiguousAfter,
			effects: durableEffectFacts{
				intent:         intentDispatch.intent,
				dispatch:       intentDispatch.dispatch,
				reconciliation: durableReconciliationFact{kind: durableReconciliationAmbiguous, fact: newDurableEffectRefTime(f.reconcile, f.now)},
			},
		},
		{
			name:  "reconciliation not accepted proves not accepted phase",
			phase: notAccepted,
			effects: durableEffectFacts{
				intent:         intentDispatch.intent,
				dispatch:       intentDispatch.dispatch,
				reconciliation: durableReconciliationFact{kind: durableReconciliationNotAccepted, fact: newDurableEffectRefTime(f.reconcile, f.now)},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newDurableClaimRecord(newDurableClaimRecordInput{
				phase:           tc.phase,
				revision:        initialClaimRevision,
				createdAt:       f.now,
				updatedAt:       f.now,
				assignedAt:      assignedAtForPhase(tc.phase, f.now),
				effects:         tc.effects,
				retention:       activeDurableRetention(),
				latestOperation: mustDurableOperationDescriptor(t, f.mutation),
			})
			if tc.wantErr && !errors.Is(err, errInvalidDurableRecord) {
				t.Fatalf("expected invalid durable record, got %v", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("newDurableClaimRecord: %v", err)
			}
		})
	}
}

func TestDurableCodecRejectsInvalidTypedNilAndAliases(t *testing.T) {
	if _, _, _, err := durablePhaseSnapshotFromPhase(nil); !errors.Is(err, errInvalidDurableRecord) {
		t.Fatalf("nil phase error = %v", err)
	}
	var typedNil *typedNilClaimPhase
	var phase ClaimPhase = typedNil
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("typed nil phase panicked: %v", r)
			}
		}()
		if _, _, _, err := durablePhaseSnapshotFromPhase(phase); !errors.Is(err, errInvalidDurableRecord) {
			t.Fatalf("typed nil phase error = %v", err)
		}
	}()

	input := []byte("private-fact-alias")
	ref, err := bytesToOptionalFactRef(input)
	if err != nil {
		t.Fatalf("bytesToOptionalFactRef: %v", err)
	}
	input[0] = 'x'
	if !ref.equal(mustPrivateFactRef(t, []byte("private-fact-alias"))) {
		t.Fatalf("durable fact ref aliased caller bytes")
	}
	if _, err := bytesToOptionalFactRef(nil); err != nil {
		t.Fatalf("empty optional fact ref error = %v", err)
	}
}

type typedNilClaimPhase struct{}

func (*typedNilClaimPhase) reliableSubmitObservation() {}
func (*typedNilClaimPhase) reliableSubmitPhase()       {}
func (*typedNilClaimPhase) Kind() Kind                 { return KindInvalid }
func (*typedNilClaimPhase) Valid() bool                { return false }
func (*typedNilClaimPhase) ClaimID() (ClaimID, bool) {
	return ClaimID{}, false
}
func (*typedNilClaimPhase) BoundPlan() (BoundPlan, bool) {
	return BoundPlan{}, false
}
func (*typedNilClaimPhase) HasAssignedRunRef() bool {
	return false
}
func (*typedNilClaimPhase) AssignedRunRef() (RunRef, bool) {
	return RunRef{}, false
}
func (*typedNilClaimPhase) ReceiptRef() (ReceiptRef, bool) {
	return ReceiptRef{}, false
}
func (*typedNilClaimPhase) SameCallerRunRefDisclosure() RunRefDisclosurePolicy {
	return RunRefDisclosureForbidden
}
func (*typedNilClaimPhase) AcceptedSubmissionReferenceAvailable() bool {
	return false
}
