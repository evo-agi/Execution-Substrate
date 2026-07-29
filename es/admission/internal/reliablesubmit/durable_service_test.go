package reliablesubmit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type memoryClaimStore struct {
	mu               sync.Mutex
	records          map[string]durableClaimRecord
	commitUnknownCAS bool
}

func newMemoryClaimStore() *memoryClaimStore {
	return &memoryClaimStore{records: make(map[string]durableClaimRecord)}
}

func (s *memoryClaimStore) establishClaim(ctx context.Context, cmd establishClaimCommand) (establishClaimStoreResult, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	key := claimMapKey(cmd.record.claim)
	if existing, ok := s.records[key]; ok {
		return establishClaimStoreResult{record: existing.clone(), created: false}, nil
	}
	s.records[key] = cmd.record.clone()
	return establishClaimStoreResult{record: cmd.record.clone(), created: true}, nil
}

func (s *memoryClaimStore) loadClaim(ctx context.Context, query loadClaimQuery) (durableClaimRecord, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[claimMapKey(query.claim)]
	if !ok {
		return durableClaimRecord{}, errClaimStoreNotFound
	}
	return record.clone(), nil
}

func (s *memoryClaimStore) compareAndSwapClaim(ctx context.Context, cmd compareAndSwapClaimCommand) (compareAndSwapClaimStoreResult, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	key := claimMapKey(cmd.claim)
	current, ok := s.records[key]
	if !ok {
		return compareAndSwapClaimStoreResult{found: false}, nil
	}
	if current.revision != cmd.expectedRevision || current.retention.state != durableRetentionActive {
		return compareAndSwapClaimStoreResult{record: current.clone(), found: true}, nil
	}
	s.records[key] = cmd.next.clone()
	if s.commitUnknownCAS {
		return compareAndSwapClaimStoreResult{}, errClaimStoreCommitUnknown
	}
	return compareAndSwapClaimStoreResult{record: cmd.next.clone(), applied: true, found: true}, nil
}

func claimMapKey(claim ClaimID) string {
	return string(opaqueRefBytes(claim.caller.ref)) + "\x00" + string(opaqueRefBytes(claim.submitKey.ref))
}

type countingClaimStore struct {
	claimStore
	mu       sync.Mutex
	casCount int
}

func (s *countingClaimStore) compareAndSwapClaim(ctx context.Context, cmd compareAndSwapClaimCommand) (compareAndSwapClaimStoreResult, error) {
	s.mu.Lock()
	s.casCount++
	s.mu.Unlock()
	return s.claimStore.compareAndSwapClaim(ctx, cmd)
}

func (s *countingClaimStore) compareAndSwapCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.casCount
}

type fixedLoadClaimStore struct {
	record   durableClaimRecord
	loadErr  error
	casCount int
}

func (s *fixedLoadClaimStore) establishClaim(ctx context.Context, cmd establishClaimCommand) (establishClaimStoreResult, error) {
	_ = ctx
	_ = cmd
	return establishClaimStoreResult{}, errClaimStoreInternal
}

func (s *fixedLoadClaimStore) loadClaim(ctx context.Context, query loadClaimQuery) (durableClaimRecord, error) {
	_ = ctx
	_ = query
	if s.loadErr != nil {
		return durableClaimRecord{}, s.loadErr
	}
	return s.record.clone(), nil
}

func (s *fixedLoadClaimStore) compareAndSwapClaim(ctx context.Context, cmd compareAndSwapClaimCommand) (compareAndSwapClaimStoreResult, error) {
	_ = ctx
	_ = cmd
	s.casCount++
	return compareAndSwapClaimStoreResult{}, errClaimStoreInternal
}

type scriptedCASLoserStore struct {
	*memoryClaimStore
	casCount int
	after    func(compareAndSwapClaimCommand) durableClaimRecord
}

func (s *scriptedCASLoserStore) compareAndSwapClaim(ctx context.Context, cmd compareAndSwapClaimCommand) (compareAndSwapClaimStoreResult, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	s.casCount++
	key := claimMapKey(cmd.claim)
	current, ok := s.records[key]
	if !ok {
		return compareAndSwapClaimStoreResult{found: false}, nil
	}
	if current.revision != cmd.expectedRevision || current.retention.state != durableRetentionActive {
		return compareAndSwapClaimStoreResult{record: current.clone(), found: true}, nil
	}
	winner := cmd.next.clone()
	if s.after != nil {
		winner = s.after(cmd)
	}
	s.records[key] = winner.clone()
	return compareAndSwapClaimStoreResult{record: winner.clone(), found: true}, nil
}

type manualClaimClock struct {
	now time.Time
}

func (c *manualClaimClock) Now() time.Time {
	return c.now
}

func TestDurableServiceEstablishReplayConflictAndClock(t *testing.T) {
	f := newDurableFixture(t)
	clock := &manualClaimClock{now: f.now}
	service := mustDurableService(t, newMemoryClaimStore(), clock)

	created, err := service.establishOrLoadClaim(context.Background(), establishClaimRequest{
		claim:    f.claim,
		plan:     f.plan,
		mutation: f.mutation,
	})
	if err != nil {
		t.Fatalf("establishOrLoadClaim: %v", err)
	}
	if created.kind != durableClaimOutcomeEstablished || !created.hasRecord {
		t.Fatalf("created outcome = %+v", created)
	}
	if !created.record.createdAt.Equal(f.now) || !created.record.updatedAt.Equal(f.now) {
		t.Fatalf("service did not use injected clock: %+v", created.record)
	}

	replayed, err := service.establishOrLoadClaim(context.Background(), establishClaimRequest{
		claim:    f.claim,
		plan:     f.plan,
		mutation: f.nextMut,
	})
	if err != nil {
		t.Fatalf("establish replay: %v", err)
	}
	if replayed.kind != durableClaimOutcomeExactReplay || replayed.underlyingReplayKind != KindPendingBeforeAssignment {
		t.Fatalf("replay outcome = %+v", replayed)
	}

	conflictPlan := mustPrivateBoundPlan(t, f.otherBind, f.witness)
	conflict, err := service.establishOrLoadClaim(context.Background(), establishClaimRequest{
		claim:    f.claim,
		plan:     conflictPlan,
		mutation: mustPrivateMutationRef(t, []byte("private-conflict-mutation")),
	})
	if err != nil {
		t.Fatalf("establish conflict: %v", err)
	}
	if conflict.kind != durableClaimOutcomeConflict || conflict.hasRecord || conflict.runRefDisclosure != RunRefDisclosureForbidden || conflict.acceptedReferenceAvailable {
		t.Fatalf("conflict disclosed record or accepted reference: %+v", conflict)
	}
}

func TestDurableServiceMutationOrderingAndTombstoneNoReuse(t *testing.T) {
	f := newDurableFixture(t)
	clock := &manualClaimClock{now: f.now}
	store := newMemoryClaimStore()
	service := mustDurableService(t, store, clock)
	created := mustServiceEstablish(t, service, f)

	if _, err := service.recordStagingEvidence(context.Background(), recordStagingEvidenceRequest{
		claim:            f.claim,
		binding:          f.binding,
		expectedRevision: created.record.revision,
		staging:          f.staging,
		mutation:         mustPrivateMutationRef(t, []byte("private-staging-before-intent")),
	}); !errors.Is(err, errInvalidDurableRecord) {
		t.Fatalf("expected staging before intent to fail, got %v", err)
	}

	clock.now = f.later
	assigned, err := service.assignRun(context.Background(), assignRunRequest{
		claim:            f.claim,
		binding:          f.binding,
		expectedRevision: created.record.revision,
		run:              f.run,
		mutation:         f.nextMut,
	})
	if err != nil {
		t.Fatalf("assignRun: %v", err)
	}
	if assigned.kind != durableClaimOutcomeAssigned || assigned.record.revision != created.record.revision+1 {
		t.Fatalf("assigned outcome = %+v", assigned)
	}

	stale, err := service.assignRun(context.Background(), assignRunRequest{
		claim:            f.claim,
		binding:          f.binding,
		expectedRevision: created.record.revision,
		run:              f.run,
		mutation:         mustPrivateMutationRef(t, []byte("private-stale-assignment")),
	})
	if err != nil {
		t.Fatalf("stale assignment: %v", err)
	}
	if stale.kind != durableClaimOutcomeStale {
		t.Fatalf("stale assignment outcome = %+v", stale)
	}

	if _, err := service.assignRun(context.Background(), assignRunRequest{
		claim:            f.claim,
		binding:          f.binding,
		expectedRevision: assigned.record.revision,
		run:              f.otherRun,
		mutation:         mustPrivateMutationRef(t, []byte("private-different-run")),
	}); !errors.Is(err, ErrRunAssignmentMismatch) {
		t.Fatalf("expected different run assignment mismatch, got %v", err)
	}

	intent, err := service.recordProviderEffectIntent(context.Background(), recordProviderEffectIntentRequest{
		claim:            f.claim,
		binding:          f.binding,
		expectedRevision: assigned.record.revision,
		intent:           f.intent,
		mutation:         mustPrivateMutationRef(t, []byte("private-intent-mutation")),
	})
	if err != nil {
		t.Fatalf("recordProviderEffectIntent: %v", err)
	}
	staging, err := service.recordStagingEvidence(context.Background(), recordStagingEvidenceRequest{
		claim:            f.claim,
		binding:          f.binding,
		expectedRevision: intent.record.revision,
		staging:          f.staging,
		mutation:         mustPrivateMutationRef(t, []byte("private-staging-mutation")),
	})
	if err != nil {
		t.Fatalf("recordStagingEvidence: %v", err)
	}
	dispatch, err := service.recordProviderDispatchAttempt(context.Background(), recordProviderDispatchAttemptRequest{
		claim:            f.claim,
		binding:          f.binding,
		expectedRevision: staging.record.revision,
		dispatch:         f.dispatch,
		mutation:         mustPrivateMutationRef(t, []byte("private-dispatch-mutation")),
	})
	if err != nil {
		t.Fatalf("recordProviderDispatchAttempt: %v", err)
	}
	accepted, err := service.acceptWithReceipt(context.Background(), acceptWithReceiptRequest{
		claim:            f.claim,
		binding:          f.binding,
		expectedRevision: dispatch.record.revision,
		receipt:          f.receipt,
		accepted:         f.observation,
		mutation:         mustPrivateMutationRef(t, []byte("private-accepted-mutation")),
	})
	if err != nil {
		t.Fatalf("acceptWithReceipt: %v", err)
	}
	if accepted.kind != durableClaimOutcomeAccepted || !accepted.acceptedReferenceAvailable {
		t.Fatalf("accepted outcome = %+v", accepted)
	}

	tombstoned, err := service.tombstoneOrExpire(context.Background(), tombstoneClaimRequest{
		claim:            f.claim,
		binding:          f.binding,
		expectedRevision: accepted.record.revision,
		state:            durableRetentionTombstoned,
		reason:           "retention elapsed",
		mutation:         mustPrivateMutationRef(t, []byte("private-tombstone-mutation")),
	})
	if err != nil {
		t.Fatalf("tombstoneOrExpire: %v", err)
	}
	if tombstoned.kind != durableClaimOutcomeExpiredUnavailable {
		t.Fatalf("tombstone outcome = %+v", tombstoned)
	}
	reuse, err := service.establishOrLoadClaim(context.Background(), establishClaimRequest{
		claim:    f.claim,
		plan:     f.plan,
		mutation: mustPrivateMutationRef(t, []byte("private-reuse-mutation")),
	})
	if err != nil {
		t.Fatalf("reuse establish: %v", err)
	}
	if reuse.kind != durableClaimOutcomeExpiredUnavailable {
		t.Fatalf("tombstoned claim was reused: %+v", reuse)
	}
}

func TestDurableServiceLatestOperationReplayConflictStaleNoopAndLegacy(t *testing.T) {
	t.Run("assign replay conflict stale and no-op", func(t *testing.T) {
		f := newDurableFixture(t)
		countingStore := &countingClaimStore{claimStore: newMemoryClaimStore()}
		service := mustDurableService(t, countingStore, fixedClaimClock{now: f.now})
		created := mustServiceEstablish(t, service, f)
		assigned, err := service.assignRun(context.Background(), assignRunRequest{
			claim:            f.claim,
			binding:          f.binding,
			expectedRevision: created.record.revision,
			run:              f.run,
			mutation:         f.nextMut,
		})
		if err != nil {
			t.Fatalf("assignRun: %v", err)
		}
		if assigned.kind != durableClaimOutcomeAssigned || countingStore.compareAndSwapCount() != 1 {
			t.Fatalf("initial assignment outcome=%+v cas=%d", assigned, countingStore.compareAndSwapCount())
		}

		replayed, err := service.assignRun(context.Background(), assignRunRequest{
			claim:            f.claim,
			binding:          f.binding,
			expectedRevision: created.record.revision,
			run:              f.run,
			mutation:         f.nextMut,
		})
		if err != nil {
			t.Fatalf("assign replay: %v", err)
		}
		if replayed.kind != durableClaimOutcomeAssigned || !replayed.record.equal(assigned.record) || countingStore.compareAndSwapCount() != 1 {
			t.Fatalf("assignment replay outcome=%+v cas=%d", replayed, countingStore.compareAndSwapCount())
		}

		conflict, err := service.assignRun(context.Background(), assignRunRequest{
			claim:            f.claim,
			binding:          f.binding,
			expectedRevision: created.record.revision,
			run:              f.otherRun,
			mutation:         f.nextMut,
		})
		if err != nil {
			t.Fatalf("same mutation different input conflict: %v", err)
		}
		if conflict.kind != durableClaimOutcomeConflict || conflict.hasRecord || countingStore.compareAndSwapCount() != 1 {
			t.Fatalf("conflict outcome=%+v cas=%d", conflict, countingStore.compareAndSwapCount())
		}

		stale, err := service.assignRun(context.Background(), assignRunRequest{
			claim:            f.claim,
			binding:          f.binding,
			expectedRevision: created.record.revision,
			run:              f.run,
			mutation:         mustPrivateMutationRef(t, []byte("private-stale-after-assign")),
		})
		if err != nil {
			t.Fatalf("stale assignment: %v", err)
		}
		if stale.kind != durableClaimOutcomeStale {
			t.Fatalf("stale assignment outcome = %+v", stale)
		}

		noOp, err := service.assignRun(context.Background(), assignRunRequest{
			claim:            f.claim,
			binding:          f.binding,
			expectedRevision: assigned.record.revision,
			run:              f.run,
			mutation:         mustPrivateMutationRef(t, []byte("private-noop-assignment")),
		})
		if err != nil {
			t.Fatalf("no-op assignment: %v", err)
		}
		if noOp.kind != durableClaimOutcomeAssigned || !noOp.record.latestOperation.equal(assigned.record.latestOperation) || countingStore.compareAndSwapCount() != 1 {
			t.Fatalf("no-op assignment rewrote descriptor or CASed: outcome=%+v cas=%d", noOp, countingStore.compareAndSwapCount())
		}
	})

	t.Run("legacy same mutation unavailable and later mutation upgrades", func(t *testing.T) {
		f := newDurableFixture(t)
		store := newMemoryClaimStore()
		service := mustDurableService(t, store, fixedClaimClock{now: f.now})
		created := mustServiceEstablish(t, service, f)
		legacy := created.record.clone()
		legacy.codecVersion = durableClaimCodecVersionLegacy
		var err error
		legacy.latestOperation, err = newLegacyDurableLatestOperationDescriptor(legacy.lastMutation)
		if err != nil {
			t.Fatalf("legacy descriptor: %v", err)
		}
		store.records[claimMapKey(f.claim)] = legacy.clone()

		unavailable, err := service.assignRun(context.Background(), assignRunRequest{
			claim:            f.claim,
			binding:          f.binding,
			expectedRevision: legacy.revision,
			run:              f.run,
			mutation:         f.mutation,
		})
		if err != nil {
			t.Fatalf("legacy same-mutation replay: %v", err)
		}
		if unavailable.kind != durableClaimOutcomeUnavailable || unavailable.hasRecord {
			t.Fatalf("legacy same-mutation outcome = %+v", unavailable)
		}

		assigned, err := service.assignRun(context.Background(), assignRunRequest{
			claim:            f.claim,
			binding:          f.binding,
			expectedRevision: legacy.revision,
			run:              f.run,
			mutation:         f.nextMut,
		})
		if err != nil {
			t.Fatalf("legacy upgrade assignment: %v", err)
		}
		if assigned.record.codecVersion != durableClaimCodecVersion || !assigned.record.latestOperation.complete() {
			t.Fatalf("legacy row did not upgrade to complete codec v2: %+v", assigned.record)
		}
	})
}

func TestDurableServiceExactLatestOperationReplayCoversMutationKinds(t *testing.T) {
	type replayCase struct {
		name string
		run  func(*testing.T, *durableClaimService, durableFixture)
	}
	for _, tc := range []replayCase{
		{
			name: "assign",
			run: func(t *testing.T, service *durableClaimService, f durableFixture) {
				created := mustServiceEstablish(t, service, f)
				mutation := mustPrivateMutationRef(t, []byte("private-replay-assign"))
				request := assignRunRequest{claim: f.claim, binding: f.binding, expectedRevision: created.record.revision, run: f.run, mutation: mutation}
				first, err := service.assignRun(context.Background(), request)
				if err != nil {
					t.Fatalf("assignRun: %v", err)
				}
				replayed, err := service.assignRun(context.Background(), request)
				assertOperationReplay(t, first, replayed, err)
			},
		},
		{
			name: "intent",
			run: func(t *testing.T, service *durableClaimService, f durableFixture) {
				created := mustServiceEstablish(t, service, f)
				assigned := mustServiceAssign(t, service, f, created.record.revision)
				mutation := mustPrivateMutationRef(t, []byte("private-replay-intent"))
				request := recordProviderEffectIntentRequest{claim: f.claim, binding: f.binding, expectedRevision: assigned.record.revision, intent: f.intent, mutation: mutation}
				first, err := service.recordProviderEffectIntent(context.Background(), request)
				if err != nil {
					t.Fatalf("recordProviderEffectIntent: %v", err)
				}
				replayed, err := service.recordProviderEffectIntent(context.Background(), request)
				assertOperationReplay(t, first, replayed, err)
			},
		},
		{
			name: "staging",
			run: func(t *testing.T, service *durableClaimService, f durableFixture) {
				created := mustServiceEstablish(t, service, f)
				assigned := mustServiceAssign(t, service, f, created.record.revision)
				intent := mustServiceIntent(t, service, f, assigned.record.revision)
				mutation := mustPrivateMutationRef(t, []byte("private-replay-staging"))
				request := recordStagingEvidenceRequest{claim: f.claim, binding: f.binding, expectedRevision: intent.record.revision, staging: f.staging, mutation: mutation}
				first, err := service.recordStagingEvidence(context.Background(), request)
				if err != nil {
					t.Fatalf("recordStagingEvidence: %v", err)
				}
				replayed, err := service.recordStagingEvidence(context.Background(), request)
				assertOperationReplay(t, first, replayed, err)
			},
		},
		{
			name: "dispatch",
			run: func(t *testing.T, service *durableClaimService, f durableFixture) {
				created := mustServiceEstablish(t, service, f)
				assigned := mustServiceAssign(t, service, f, created.record.revision)
				intent := mustServiceIntent(t, service, f, assigned.record.revision)
				mutation := mustPrivateMutationRef(t, []byte("private-replay-dispatch"))
				request := recordProviderDispatchAttemptRequest{claim: f.claim, binding: f.binding, expectedRevision: intent.record.revision, dispatch: f.dispatch, mutation: mutation}
				first, err := service.recordProviderDispatchAttempt(context.Background(), request)
				if err != nil {
					t.Fatalf("recordProviderDispatchAttempt: %v", err)
				}
				replayed, err := service.recordProviderDispatchAttempt(context.Background(), request)
				assertOperationReplay(t, first, replayed, err)
			},
		},
		{
			name: "provider observation",
			run: func(t *testing.T, service *durableClaimService, f durableFixture) {
				created := mustServiceEstablish(t, service, f)
				assigned := mustServiceAssign(t, service, f, created.record.revision)
				intent := mustServiceIntent(t, service, f, assigned.record.revision)
				dispatch := mustServiceDispatch(t, service, f, intent.record.revision)
				mutation := mustPrivateMutationRef(t, []byte("private-replay-provider-observation"))
				request := recordProviderCallObservationRequest{claim: f.claim, binding: f.binding, expectedRevision: dispatch.record.revision, run: f.run, kind: durableProviderObservationPending, observation: f.observation, mutation: mutation}
				first, err := service.recordProviderCallObservation(context.Background(), request)
				if err != nil {
					t.Fatalf("recordProviderCallObservation: %v", err)
				}
				replayed, err := service.recordProviderCallObservation(context.Background(), request)
				assertOperationReplay(t, first, replayed, err)
			},
		},
		{
			name: "reconciliation",
			run: func(t *testing.T, service *durableClaimService, f durableFixture) {
				created := mustServiceEstablish(t, service, f)
				assigned := mustServiceAssign(t, service, f, created.record.revision)
				intent := mustServiceIntent(t, service, f, assigned.record.revision)
				dispatch := mustServiceDispatch(t, service, f, intent.record.revision)
				mutation := mustPrivateMutationRef(t, []byte("private-replay-reconciliation"))
				request := recordReconciliationEvidenceRequest{claim: f.claim, binding: f.binding, expectedRevision: dispatch.record.revision, run: f.run, kind: durableReconciliationPending, reconciliation: f.reconcile, mutation: mutation}
				first, err := service.recordReconciliationEvidence(context.Background(), request)
				if err != nil {
					t.Fatalf("recordReconciliationEvidence: %v", err)
				}
				replayed, err := service.recordReconciliationEvidence(context.Background(), request)
				assertOperationReplay(t, first, replayed, err)
			},
		},
		{
			name: "accepted",
			run: func(t *testing.T, service *durableClaimService, f durableFixture) {
				created := mustServiceEstablish(t, service, f)
				assigned := mustServiceAssign(t, service, f, created.record.revision)
				intent := mustServiceIntent(t, service, f, assigned.record.revision)
				dispatch := mustServiceDispatch(t, service, f, intent.record.revision)
				mutation := mustPrivateMutationRef(t, []byte("private-replay-accepted"))
				request := acceptWithReceiptRequest{claim: f.claim, binding: f.binding, expectedRevision: dispatch.record.revision, receipt: f.receipt, accepted: f.observation, mutation: mutation}
				first, err := service.acceptWithReceipt(context.Background(), request)
				if err != nil {
					t.Fatalf("acceptWithReceipt: %v", err)
				}
				replayed, err := service.acceptWithReceipt(context.Background(), request)
				assertOperationReplay(t, first, replayed, err)
				if !replayed.acceptedReferenceAvailable || !replayed.record.phase.receipt.Equal(f.receipt) {
					t.Fatalf("accepted replay did not retain receipt: %+v", replayed)
				}
			},
		},
		{
			name: "provably not accepted",
			run: func(t *testing.T, service *durableClaimService, f durableFixture) {
				created := mustServiceEstablish(t, service, f)
				assigned := mustServiceAssign(t, service, f, created.record.revision)
				intent := mustServiceIntent(t, service, f, assigned.record.revision)
				dispatch := mustServiceDispatch(t, service, f, intent.record.revision)
				mutation := mustPrivateMutationRef(t, []byte("private-replay-not-accepted"))
				request := recordProvablyNotAcceptedRequest{claim: f.claim, binding: f.binding, expectedRevision: dispatch.record.revision, notAccepted: f.observation, mutation: mutation}
				first, err := service.recordProvablyNotAccepted(context.Background(), request)
				if err != nil {
					t.Fatalf("recordProvablyNotAccepted: %v", err)
				}
				replayed, err := service.recordProvablyNotAccepted(context.Background(), request)
				assertOperationReplay(t, first, replayed, err)
			},
		},
		{
			name: "tombstone expiry",
			run: func(t *testing.T, service *durableClaimService, f durableFixture) {
				created := mustServiceEstablish(t, service, f)
				mutation := mustPrivateMutationRef(t, []byte("private-replay-tombstone"))
				request := tombstoneClaimRequest{claim: f.claim, binding: f.binding, expectedRevision: created.record.revision, state: durableRetentionTombstoned, reason: "retention elapsed", mutation: mutation}
				first, err := service.tombstoneOrExpire(context.Background(), request)
				if err != nil {
					t.Fatalf("tombstoneOrExpire: %v", err)
				}
				replayed, err := service.tombstoneOrExpire(context.Background(), request)
				assertOperationReplay(t, first, replayed, err)
				different, err := service.tombstoneOrExpire(context.Background(), tombstoneClaimRequest{claim: f.claim, binding: f.binding, expectedRevision: first.record.revision, state: durableRetentionTombstoned, reason: "retention elapsed", mutation: mustPrivateMutationRef(t, []byte("private-later-tombstone"))})
				if err != nil {
					t.Fatalf("different tombstone mutation: %v", err)
				}
				if different.kind != durableClaimOutcomeExpiredUnavailable || different.hasRecord {
					t.Fatalf("different inactive mutation outcome = %+v", different)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDurableFixture(t)
			service := mustDurableService(t, newMemoryClaimStore(), fixedClaimClock{now: f.now})
			tc.run(t, service, f)
		})
	}
}

func TestDurableServiceMutationDerivesDescriptorAfterLoadedValidation(t *testing.T) {
	f := newDurableFixture(t)
	valid := mustPrivateRecord(t, mustPrivatePendingBefore(t, f), f)
	corrupt := valid.clone()
	corrupt.codecVersion = durableClaimCodecVersion + 1

	other := newDurableFixture(t)
	other.caller = mustPrivateCallerRef(t, []byte("private-loaded-other-caller"))
	other.claim = mustPrivateClaimID(t, other.caller, other.submitKey)
	other.plan = mustPrivateBoundPlan(t, other.binding, other.witness)
	wrongClaim := mustPrivateRecord(t, mustPrivatePendingBefore(t, other), other)

	tests := []struct {
		name      string
		record    durableClaimRecord
		binding   PlanBinding
		wantErr   error
		wantKind  durableClaimOutcomeKind
		wantNoErr bool
	}{
		{
			name:    "corrupt record before malformed descriptor",
			record:  corrupt,
			binding: f.binding,
			wantErr: errInvalidDurableRecord,
		},
		{
			name:    "loaded claim identity mismatch",
			record:  wrongClaim,
			binding: f.binding,
			wantErr: errClaimStoreCorrupt,
		},
		{
			name:      "plan binding conflict",
			record:    valid,
			binding:   f.otherBind,
			wantKind:  durableClaimOutcomeConflict,
			wantNoErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := &fixedLoadClaimStore{record: tc.record}
			service := mustDurableService(t, store, fixedClaimClock{now: f.now})
			builderCalls := 0
			applyCalls := 0
			outcome, err := service.mutate(context.Background(), mutationRequest{
				claim:            f.claim,
				binding:          tc.binding,
				expectedRevision: initialClaimRevision,
				mutation:         f.nextMut,
				operationKind:    durableOperationInvalid,
				operationInput: func() []durableOperationInputPart {
					builderCalls++
					return []durableOperationInputPart{operationPartRunRef(f.run)}
				},
				successKind: durableClaimOutcomeAssigned,
				apply: func(record durableClaimRecord, nowUTC time.Time, operation durableLatestOperationDescriptor) (durableClaimRecord, error) {
					_ = nowUTC
					_ = operation
					applyCalls++
					return record, nil
				},
			})
			if tc.wantNoErr {
				if err != nil {
					t.Fatalf("mutate returned error: %v", err)
				}
				if outcome.kind != tc.wantKind {
					t.Fatalf("outcome kind = %v, want %v", outcome.kind, tc.wantKind)
				}
			} else if !errors.Is(err, tc.wantErr) {
				t.Fatalf("mutate error = %v, want %v", err, tc.wantErr)
			}
			if builderCalls != 0 || applyCalls != 0 || store.casCount != 0 {
				t.Fatalf("validation failure called builder=%d apply=%d cas=%d", builderCalls, applyCalls, store.casCount)
			}
		})
	}
}

func TestDurableServiceLoadedClaimIdentityMismatchFailsClosedBeforeReplayApplyCAS(t *testing.T) {
	f := newDurableFixture(t)
	other := newDurableFixture(t)
	other.caller = mustPrivateCallerRef(t, []byte("private-loaded-claim-mismatch-caller"))
	other.claim = mustPrivateClaimID(t, other.caller, other.submitKey)
	other.plan = mustPrivateBoundPlan(t, other.binding, other.witness)

	operation, err := deriveDurableOperationDescriptor(f.nextMut, durableOperationAssignRun, initialClaimRevision, operationPartRunRef(f.run))
	if err != nil {
		t.Fatalf("derive would-be replay descriptor: %v", err)
	}
	pending, err := NewPendingBeforeAssignment(other.claim, other.plan)
	if err != nil {
		t.Fatalf("wrong-claim pending phase: %v", err)
	}
	assigned, err := AssignRun(pending, f.run)
	if err != nil {
		t.Fatalf("wrong-claim assignment phase: %v", err)
	}
	wrongClaimRecord, err := newDurableClaimRecord(newDurableClaimRecordInput{
		phase:           assigned,
		revision:        initialClaimRevision + 1,
		createdAt:       f.now,
		updatedAt:       f.later,
		assignedAt:      someClaimTime(f.later),
		retention:       activeDurableRetention(),
		latestOperation: operation,
	})
	if err != nil {
		t.Fatalf("wrong-claim record: %v", err)
	}
	store := &fixedLoadClaimStore{record: wrongClaimRecord}
	service := mustDurableService(t, store, fixedClaimClock{now: f.now})
	builderCalls := 0
	applyCalls := 0
	outcome, err := service.mutate(context.Background(), mutationRequest{
		claim:            f.claim,
		binding:          f.binding,
		expectedRevision: initialClaimRevision,
		mutation:         f.nextMut,
		operationKind:    durableOperationAssignRun,
		operationInput: func() []durableOperationInputPart {
			builderCalls++
			return []durableOperationInputPart{operationPartRunRef(f.run)}
		},
		successKind: durableClaimOutcomeAssigned,
		apply: func(record durableClaimRecord, nowUTC time.Time, operation durableLatestOperationDescriptor) (durableClaimRecord, error) {
			_ = nowUTC
			_ = operation
			applyCalls++
			return record, nil
		},
	})
	if !errors.Is(err, errClaimStoreCorrupt) {
		t.Fatalf("wrong-claim load error = %v", err)
	}
	if outcome.kind == durableClaimOutcomeAssigned || outcome.hasRecord {
		t.Fatalf("wrong-claim load returned replay/apply outcome: %+v", outcome)
	}
	if builderCalls != 0 || applyCalls != 0 || store.casCount != 0 {
		t.Fatalf("wrong-claim load called builder=%d apply=%d cas=%d", builderCalls, applyCalls, store.casCount)
	}
	message := err.Error()
	for _, forbidden := range []string{
		"private-caller-reference",
		"private-loaded-claim-mismatch-caller",
		"private-submit-key-reference",
	} {
		if stringsContains(message, forbidden) {
			t.Fatalf("wrong-claim error disclosed claim material")
		}
	}
}

func TestDurableServiceCASLoserClassifiesLatestOperation(t *testing.T) {
	t.Run("duplicate loser reloads replay", func(t *testing.T) {
		f := newDurableFixture(t)
		store := &scriptedCASLoserStore{memoryClaimStore: newMemoryClaimStore()}
		service := mustDurableService(t, store, fixedClaimClock{now: f.now})
		created := mustServiceEstablish(t, service, f)
		outcome, err := service.assignRun(context.Background(), assignRunRequest{
			claim:            f.claim,
			binding:          f.binding,
			expectedRevision: created.record.revision,
			run:              f.run,
			mutation:         f.nextMut,
		})
		if err != nil {
			t.Fatalf("assign CAS loser: %v", err)
		}
		if outcome.kind != durableClaimOutcomeAssigned || outcome.record.revision != created.record.revision+1 || store.casCount != 1 {
			t.Fatalf("CAS loser replay outcome=%+v cas=%d", outcome, store.casCount)
		}
	})

	t.Run("same mutation different descriptor conflicts", func(t *testing.T) {
		f := newDurableFixture(t)
		store := &scriptedCASLoserStore{
			memoryClaimStore: newMemoryClaimStore(),
			after: func(cmd compareAndSwapClaimCommand) durableClaimRecord {
				winner := cmd.next.clone()
				operation, err := deriveDurableOperationDescriptor(cmd.next.lastMutation, durableOperationAssignRun, cmd.expectedRevision, operationPartRunRef(f.otherRun))
				if err != nil {
					t.Fatalf("derive conflicting winner descriptor: %v", err)
				}
				winner.latestOperation = operation
				return winner
			},
		}
		service := mustDurableService(t, store, fixedClaimClock{now: f.now})
		created := mustServiceEstablish(t, service, f)
		outcome, err := service.assignRun(context.Background(), assignRunRequest{
			claim:            f.claim,
			binding:          f.binding,
			expectedRevision: created.record.revision,
			run:              f.run,
			mutation:         f.nextMut,
		})
		if err != nil {
			t.Fatalf("assign CAS conflict: %v", err)
		}
		if outcome.kind != durableClaimOutcomeConflict || outcome.hasRecord || store.casCount != 1 {
			t.Fatalf("CAS conflict outcome=%+v cas=%d", outcome, store.casCount)
		}
	})

	t.Run("duplicate loser reuses one derived descriptor", func(t *testing.T) {
		f := newDurableFixture(t)
		store := &scriptedCASLoserStore{memoryClaimStore: newMemoryClaimStore()}
		service := mustDurableService(t, store, fixedClaimClock{now: f.now})
		created := mustServiceEstablish(t, service, f)
		builderCalls := 0
		applyCalls := 0
		outcome, err := service.mutate(context.Background(), mutationRequest{
			claim:            f.claim,
			binding:          f.binding,
			expectedRevision: created.record.revision,
			mutation:         f.nextMut,
			operationKind:    durableOperationAssignRun,
			operationInput: func() []durableOperationInputPart {
				builderCalls++
				return []durableOperationInputPart{operationPartRunRef(f.run)}
			},
			successKind: durableClaimOutcomeAssigned,
			apply: func(record durableClaimRecord, nowUTC time.Time, operation durableLatestOperationDescriptor) (durableClaimRecord, error) {
				applyCalls++
				phase, err := record.hydratePhase()
				if err != nil {
					return durableClaimRecord{}, err
				}
				pre, ok := phase.(PreAssignmentPhase)
				if !ok {
					return durableClaimRecord{}, ErrInvalidPhase
				}
				assigned, err := AssignRun(pre, f.run)
				if err != nil {
					return durableClaimRecord{}, err
				}
				return record.withPhaseAndOperation(assigned, operation, nowUTC, someClaimTime(nowUTC), record.effects, record.retention)
			},
		})
		if err != nil {
			t.Fatalf("mutate CAS loser: %v", err)
		}
		if outcome.kind != durableClaimOutcomeAssigned || !outcome.hasRecord {
			t.Fatalf("CAS loser outcome = %+v", outcome)
		}
		if builderCalls != 1 || applyCalls != 1 || store.casCount != 1 {
			t.Fatalf("calls builder=%d apply=%d cas=%d", builderCalls, applyCalls, store.casCount)
		}
	})
}

func TestDurableServiceReloadsAfterCommitOutcomeUnknown(t *testing.T) {
	f := newDurableFixture(t)
	store := newMemoryClaimStore()
	service := mustDurableService(t, store, &manualClaimClock{now: f.now})
	created := mustServiceEstablish(t, service, f)
	store.commitUnknownCAS = true

	assigned, err := service.assignRun(context.Background(), assignRunRequest{
		claim:            f.claim,
		binding:          f.binding,
		expectedRevision: created.record.revision,
		run:              f.run,
		mutation:         f.nextMut,
	})
	if err != nil {
		t.Fatalf("assignRun with commit unknown but committed state: %v", err)
	}
	if assigned.kind != durableClaimOutcomeAssigned || !assigned.record.lastMutation.equal(f.nextMut) {
		t.Fatalf("commit-unknown reload did not prove success: %+v", assigned)
	}
}

func TestDurableServiceProviderObservationRequiresDispatchAndProgressesPhase(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind durableProviderObservationKind
		want Kind
	}{
		{name: "pending", kind: durableProviderObservationPending, want: KindPendingAfterAssignment},
		{name: "ambiguous", kind: durableProviderObservationAmbiguous, want: KindAmbiguousAfterAssignment},
		{name: "call uncertain", kind: durableProviderObservationCallUncertain, want: KindAmbiguousAfterAssignment},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDurableFixture(t)
			service := mustDurableService(t, newMemoryClaimStore(), fixedClaimClock{now: f.now})
			created := mustServiceEstablish(t, service, f)
			assigned := mustServiceAssign(t, service, f, created.record.revision)
			intent := mustServiceIntent(t, service, f, assigned.record.revision)
			dispatch := mustServiceDispatch(t, service, f, intent.record.revision)

			outcome, err := service.recordProviderCallObservation(context.Background(), recordProviderCallObservationRequest{
				claim:            f.claim,
				binding:          f.binding,
				expectedRevision: dispatch.record.revision,
				run:              f.run,
				kind:             tc.kind,
				observation:      f.observation,
				mutation:         mustPrivateMutationRef(t, []byte("private-provider-"+tc.name)),
			})
			if err != nil {
				t.Fatalf("recordProviderCallObservation: %v", err)
			}
			if outcome.kind != durableClaimOutcomeProviderObservationRecorded || outcome.observationKind != tc.want {
				t.Fatalf("provider observation outcome = %+v, want phase %v", outcome, tc.want)
			}
			if outcome.record.phase.tag == durablePhaseEffectCapableAssigned {
				t.Fatalf("provider observation remained effect-capable assigned")
			}
		})
	}

	t.Run("negative preconditions", func(t *testing.T) {
		f := newDurableFixture(t)
		service := mustDurableService(t, newMemoryClaimStore(), fixedClaimClock{now: f.now})
		created := mustServiceEstablish(t, service, f)
		if _, err := service.recordProviderCallObservation(context.Background(), recordProviderCallObservationRequest{
			claim:            f.claim,
			binding:          f.binding,
			expectedRevision: created.record.revision,
			run:              f.run,
			kind:             durableProviderObservationPending,
			observation:      f.observation,
			mutation:         mustPrivateMutationRef(t, []byte("private-provider-before-assignment")),
		}); !errors.Is(err, ErrInvalidPhase) {
			t.Fatalf("provider before assignment error = %v", err)
		}

		assigned := mustServiceAssign(t, service, f, created.record.revision)
		if _, err := service.recordProviderCallObservation(context.Background(), recordProviderCallObservationRequest{
			claim:            f.claim,
			binding:          f.binding,
			expectedRevision: assigned.record.revision,
			run:              f.run,
			kind:             durableProviderObservationPending,
			observation:      f.observation,
			mutation:         mustPrivateMutationRef(t, []byte("private-provider-before-intent")),
		}); !errors.Is(err, errInvalidDurableRecord) {
			t.Fatalf("provider before intent error = %v", err)
		}

		intent := mustServiceIntent(t, service, f, assigned.record.revision)
		dispatch := mustServiceDispatch(t, service, f, intent.record.revision)
		if _, err := service.recordProviderCallObservation(context.Background(), recordProviderCallObservationRequest{
			claim:            f.claim,
			binding:          f.binding,
			expectedRevision: dispatch.record.revision,
			run:              f.otherRun,
			kind:             durableProviderObservationPending,
			observation:      f.observation,
			mutation:         mustPrivateMutationRef(t, []byte("private-provider-wrong-run")),
		}); !errors.Is(err, ErrRunAssignmentMismatch) {
			t.Fatalf("provider wrong run error = %v", err)
		}
		if _, err := service.recordProviderCallObservation(context.Background(), recordProviderCallObservationRequest{
			claim:            f.claim,
			binding:          f.binding,
			expectedRevision: dispatch.record.revision,
			run:              f.run,
			kind:             durableProviderObservationPending,
			observation:      durableFactRef{},
			mutation:         mustPrivateMutationRef(t, []byte("private-provider-empty-fact")),
		}); !errors.Is(err, errInvalidDurableRecord) {
			t.Fatalf("provider empty fact error = %v", err)
		}
	})
}

func TestDurableServiceReconciliationEvidencePreconditionsAndPhase(t *testing.T) {
	t.Run("validated no dispatch evidence", func(t *testing.T) {
		f := newDurableFixture(t)
		service := mustDurableService(t, newMemoryClaimStore(), fixedClaimClock{now: f.now})
		created := mustServiceEstablish(t, service, f)
		assigned := mustServiceAssign(t, service, f, created.record.revision)
		intent := mustServiceIntent(t, service, f, assigned.record.revision)
		outcome, err := service.recordReconciliationEvidence(context.Background(), recordReconciliationEvidenceRequest{
			claim:            f.claim,
			binding:          f.binding,
			expectedRevision: intent.record.revision,
			run:              f.run,
			kind:             durableReconciliationNoDispatch,
			reconciliation:   f.reconcile,
			mutation:         mustPrivateMutationRef(t, []byte("private-reconcile-no-dispatch")),
		})
		if err != nil {
			t.Fatalf("recordReconciliationEvidence no dispatch: %v", err)
		}
		if outcome.kind != durableClaimOutcomeReconciliationRecorded || outcome.observationKind != KindEffectCapableAssigned {
			t.Fatalf("no-dispatch reconciliation outcome = %+v", outcome)
		}
	})

	for _, tc := range []struct {
		name string
		kind durableReconciliationKind
		want Kind
	}{
		{name: "pending", kind: durableReconciliationPending, want: KindPendingAfterAssignment},
		{name: "ambiguous", kind: durableReconciliationAmbiguous, want: KindAmbiguousAfterAssignment},
		{name: "inconsistent", kind: durableReconciliationInconsistent, want: KindAmbiguousAfterAssignment},
		{name: "not accepted", kind: durableReconciliationNotAccepted, want: KindProvablyNotAcceptedAfterAssignment},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDurableFixture(t)
			service := mustDurableService(t, newMemoryClaimStore(), fixedClaimClock{now: f.now})
			created := mustServiceEstablish(t, service, f)
			assigned := mustServiceAssign(t, service, f, created.record.revision)
			intent := mustServiceIntent(t, service, f, assigned.record.revision)
			dispatch := mustServiceDispatch(t, service, f, intent.record.revision)
			outcome, err := service.recordReconciliationEvidence(context.Background(), recordReconciliationEvidenceRequest{
				claim:            f.claim,
				binding:          f.binding,
				expectedRevision: dispatch.record.revision,
				run:              f.run,
				kind:             tc.kind,
				reconciliation:   f.reconcile,
				mutation:         mustPrivateMutationRef(t, []byte("private-reconcile-"+tc.name)),
			})
			if err != nil {
				t.Fatalf("recordReconciliationEvidence: %v", err)
			}
			if outcome.kind != durableClaimOutcomeReconciliationRecorded || outcome.observationKind != tc.want {
				t.Fatalf("reconciliation outcome = %+v, want phase %v", outcome, tc.want)
			}
		})
	}

	t.Run("accepted reconciliation requires accepted phase", func(t *testing.T) {
		f := newDurableFixture(t)
		service := mustDurableService(t, newMemoryClaimStore(), fixedClaimClock{now: f.now})
		created := mustServiceEstablish(t, service, f)
		assigned := mustServiceAssign(t, service, f, created.record.revision)
		intent := mustServiceIntent(t, service, f, assigned.record.revision)
		dispatch := mustServiceDispatch(t, service, f, intent.record.revision)
		if _, err := service.recordReconciliationEvidence(context.Background(), recordReconciliationEvidenceRequest{
			claim:            f.claim,
			binding:          f.binding,
			expectedRevision: dispatch.record.revision,
			run:              f.run,
			kind:             durableReconciliationAccepted,
			reconciliation:   f.reconcile,
			mutation:         mustPrivateMutationRef(t, []byte("private-reconcile-accepted-too-early")),
		}); !errors.Is(err, errInvalidDurableRecord) {
			t.Fatalf("accepted reconciliation before accepted phase error = %v", err)
		}

		accepted, err := service.acceptWithReceipt(context.Background(), acceptWithReceiptRequest{
			claim:            f.claim,
			binding:          f.binding,
			expectedRevision: dispatch.record.revision,
			receipt:          f.receipt,
			accepted:         f.observation,
			mutation:         mustPrivateMutationRef(t, []byte("private-accepted-before-reconcile")),
		})
		if err != nil {
			t.Fatalf("acceptWithReceipt: %v", err)
		}
		outcome, err := service.recordReconciliationEvidence(context.Background(), recordReconciliationEvidenceRequest{
			claim:            f.claim,
			binding:          f.binding,
			expectedRevision: accepted.record.revision,
			run:              f.run,
			kind:             durableReconciliationAccepted,
			reconciliation:   f.reconcile,
			mutation:         mustPrivateMutationRef(t, []byte("private-reconcile-accepted")),
		})
		if err != nil {
			t.Fatalf("record accepted reconciliation: %v", err)
		}
		if outcome.observationKind != KindAccepted {
			t.Fatalf("accepted reconciliation outcome = %+v", outcome)
		}
	})

	t.Run("negative preconditions", func(t *testing.T) {
		f := newDurableFixture(t)
		service := mustDurableService(t, newMemoryClaimStore(), fixedClaimClock{now: f.now})
		created := mustServiceEstablish(t, service, f)
		if _, err := service.recordReconciliationEvidence(context.Background(), recordReconciliationEvidenceRequest{
			claim:            f.claim,
			binding:          f.binding,
			expectedRevision: created.record.revision,
			run:              f.run,
			kind:             durableReconciliationNoDispatch,
			reconciliation:   f.reconcile,
			mutation:         mustPrivateMutationRef(t, []byte("private-reconcile-before-assignment")),
		}); !errors.Is(err, ErrInvalidPhase) {
			t.Fatalf("reconciliation before assignment error = %v", err)
		}

		assigned := mustServiceAssign(t, service, f, created.record.revision)
		if _, err := service.recordReconciliationEvidence(context.Background(), recordReconciliationEvidenceRequest{
			claim:            f.claim,
			binding:          f.binding,
			expectedRevision: assigned.record.revision,
			run:              f.run,
			kind:             durableReconciliationNoDispatch,
			reconciliation:   f.reconcile,
			mutation:         mustPrivateMutationRef(t, []byte("private-reconcile-before-intent")),
		}); !errors.Is(err, errInvalidDurableRecord) {
			t.Fatalf("reconciliation before intent error = %v", err)
		}

		intent := mustServiceIntent(t, service, f, assigned.record.revision)
		dispatch := mustServiceDispatch(t, service, f, intent.record.revision)
		if _, err := service.recordReconciliationEvidence(context.Background(), recordReconciliationEvidenceRequest{
			claim:            f.claim,
			binding:          f.binding,
			expectedRevision: dispatch.record.revision,
			run:              f.run,
			kind:             durableReconciliationNoDispatch,
			reconciliation:   f.reconcile,
			mutation:         mustPrivateMutationRef(t, []byte("private-reconcile-no-dispatch-after-marker")),
		}); !errors.Is(err, errInvalidDurableRecord) {
			t.Fatalf("no-dispatch reconciliation after marker error = %v", err)
		}
		if _, err := service.recordReconciliationEvidence(context.Background(), recordReconciliationEvidenceRequest{
			claim:            f.claim,
			binding:          f.binding,
			expectedRevision: dispatch.record.revision,
			run:              f.run,
			kind:             durableReconciliationPending,
			reconciliation:   durableFactRef{},
			mutation:         mustPrivateMutationRef(t, []byte("private-reconcile-empty-fact")),
		}); !errors.Is(err, errInvalidDurableRecord) {
			t.Fatalf("empty reconciliation fact error = %v", err)
		}
		if _, err := service.recordReconciliationEvidence(context.Background(), recordReconciliationEvidenceRequest{
			claim:            f.claim,
			binding:          f.binding,
			expectedRevision: dispatch.record.revision,
			run:              f.otherRun,
			kind:             durableReconciliationPending,
			reconciliation:   f.reconcile,
			mutation:         mustPrivateMutationRef(t, []byte("private-reconcile-wrong-run")),
		}); !errors.Is(err, ErrRunAssignmentMismatch) {
			t.Fatalf("wrong-run reconciliation error = %v", err)
		}
	})
}

func TestDurableServiceCommitUnknownDoesNotFalsePositive(t *testing.T) {
	for _, tc := range []struct {
		name    string
		loadErr error
		after   func(t *testing.T, f durableFixture, next durableClaimRecord) durableClaimRecord
	}{
		{name: "reload unavailable", loadErr: errClaimStoreUnavailable},
		{name: "reload corrupt", loadErr: errClaimStoreCorrupt},
		{
			name: "mutation differs",
			after: func(t *testing.T, f durableFixture, next durableClaimRecord) durableClaimRecord {
				next.lastMutation = mustPrivateMutationRef(t, []byte("private-other-mutation"))
				return next
			},
		},
		{
			name: "revision differs",
			after: func(t *testing.T, f durableFixture, next durableClaimRecord) durableClaimRecord {
				next.revision++
				return next
			},
		},
		{
			name: "record differs",
			after: func(t *testing.T, f durableFixture, next durableClaimRecord) durableClaimRecord {
				next.effects.intent = newDurableEffectRefTime(f.intent, f.later)
				return next
			},
		},
		{
			name: "descriptor kind differs",
			after: func(t *testing.T, f durableFixture, next durableClaimRecord) durableClaimRecord {
				operation, err := deriveDurableOperationDescriptor(next.lastMutation, durableOperationRecordProviderEffectIntent, initialClaimRevision, operationPartFactRef(f.intent))
				if err != nil {
					t.Fatalf("derive kind-mismatch descriptor: %v", err)
				}
				next.latestOperation = operation
				return next
			},
		},
		{
			name: "descriptor digest differs",
			after: func(t *testing.T, f durableFixture, next durableClaimRecord) durableClaimRecord {
				operation, err := deriveDurableOperationDescriptor(next.lastMutation, durableOperationAssignRun, initialClaimRevision, operationPartRunRef(f.otherRun))
				if err != nil {
					t.Fatalf("derive digest-mismatch descriptor: %v", err)
				}
				next.latestOperation = operation
				return next
			},
		},
		{
			name: "legacy descriptor differs",
			after: func(t *testing.T, f durableFixture, next durableClaimRecord) durableClaimRecord {
				legacy, err := newLegacyDurableLatestOperationDescriptor(next.lastMutation)
				if err != nil {
					t.Fatalf("legacy descriptor: %v", err)
				}
				next.codecVersion = durableClaimCodecVersionLegacy
				next.latestOperation = legacy
				return next
			},
		},
		{
			name: "later unrelated mutation",
			after: func(t *testing.T, f durableFixture, next durableClaimRecord) durableClaimRecord {
				next.revision++
				next.updatedAt = f.later
				next.lastMutation = mustPrivateMutationRef(t, []byte("private-later-unrelated-mutation"))
				return next
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDurableFixture(t)
			initial := mustPrivateRecord(t, mustPrivatePendingBefore(t, f), f)
			store := &scriptedCommitUnknownStore{
				current: initial,
				has:     true,
				loadErr: tc.loadErr,
				after: func(next durableClaimRecord) durableClaimRecord {
					if tc.after == nil {
						return next
					}
					return tc.after(t, f, next)
				},
			}
			service := mustDurableService(t, store, fixedClaimClock{now: f.now})
			outcome, err := service.assignRun(context.Background(), assignRunRequest{
				claim:            f.claim,
				binding:          f.binding,
				expectedRevision: initial.revision,
				run:              f.run,
				mutation:         f.nextMut,
			})
			if err == nil {
				t.Fatalf("commit unknown case returned success: %+v", outcome)
			}
			if outcome.kind == durableClaimOutcomeAssigned {
				t.Fatalf("commit unknown falsely proved assignment: %+v", outcome)
			}
		})
	}
}

type scriptedCommitUnknownStore struct {
	mu       sync.Mutex
	current  durableClaimRecord
	has      bool
	compared bool
	loadErr  error
	after    func(durableClaimRecord) durableClaimRecord
}

func (s *scriptedCommitUnknownStore) establishClaim(ctx context.Context, cmd establishClaimCommand) (establishClaimStoreResult, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.has {
		return establishClaimStoreResult{record: s.current.clone()}, nil
	}
	s.current = cmd.record.clone()
	s.has = true
	return establishClaimStoreResult{record: s.current.clone(), created: true}, nil
}

func (s *scriptedCommitUnknownStore) loadClaim(ctx context.Context, query loadClaimQuery) (durableClaimRecord, error) {
	_ = ctx
	_ = query
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.compared && s.loadErr != nil {
		return durableClaimRecord{}, s.loadErr
	}
	if !s.has {
		return durableClaimRecord{}, errClaimStoreNotFound
	}
	return s.current.clone(), nil
}

func (s *scriptedCommitUnknownStore) compareAndSwapClaim(ctx context.Context, cmd compareAndSwapClaimCommand) (compareAndSwapClaimStoreResult, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.has {
		return compareAndSwapClaimStoreResult{found: false}, nil
	}
	if s.current.revision != cmd.expectedRevision {
		return compareAndSwapClaimStoreResult{record: s.current.clone(), found: true}, nil
	}
	next := cmd.next.clone()
	if s.after != nil {
		next = s.after(next)
	}
	s.current = next
	s.compared = true
	return compareAndSwapClaimStoreResult{}, errClaimStoreCommitUnknown
}

func mustDurableService(t *testing.T, store claimStore, clock claimClock) *durableClaimService {
	t.Helper()
	service, err := newDurableClaimService(store, clock)
	if err != nil {
		t.Fatalf("newDurableClaimService: %v", err)
	}
	return service
}

func mustServiceEstablish(t *testing.T, service *durableClaimService, f durableFixture) durableClaimOutcome {
	t.Helper()
	outcome, err := service.establishOrLoadClaim(context.Background(), establishClaimRequest{
		claim:    f.claim,
		plan:     f.plan,
		mutation: f.mutation,
	})
	if err != nil {
		t.Fatalf("establishOrLoadClaim: %v", err)
	}
	return outcome
}

func assertOperationReplay(t *testing.T, first durableClaimOutcome, replayed durableClaimOutcome, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("operation replay: %v", err)
	}
	if replayed.kind != first.kind {
		t.Fatalf("replay kind = %v, want %v", replayed.kind, first.kind)
	}
	if !replayed.hasRecord || !first.hasRecord || !replayed.record.equal(first.record) {
		t.Fatalf("replay record mismatch: first=%+v replayed=%+v", first, replayed)
	}
	if replayed.observationKind != first.observationKind ||
		replayed.runRefDisclosure != first.runRefDisclosure ||
		replayed.acceptedReferenceAvailable != first.acceptedReferenceAvailable {
		t.Fatalf("replay disclosure changed: first=%+v replayed=%+v", first, replayed)
	}
}
