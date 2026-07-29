package reliablesubmit

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type claimStoreConformanceFactory struct {
	name string
	open func(*testing.T) claimStoreConformanceHandle
}

type claimStoreConformanceHandle struct {
	store  claimStore
	close  func(*testing.T)
	reopen func(*testing.T) claimStoreConformanceHandle
}

func runClaimStoreConformance(t *testing.T, factory claimStoreConformanceFactory) {
	t.Run(factory.name+"/create-reopen-replay-conflict", func(t *testing.T) {
		handle := factory.open(t)
		defer handle.close(t)
		f := newDurableFixture(t)
		service := mustDurableService(t, handle.store, fixedClaimClock{now: f.now})
		created := mustServiceEstablish(t, service, f)
		if created.kind != durableClaimOutcomeEstablished {
			t.Fatalf("establish outcome = %+v", created)
		}
		replayed, err := service.exactReplayOrLoad(context.Background(), exactReplayRequest{claim: f.claim, binding: f.binding})
		if err != nil {
			t.Fatalf("exactReplayOrLoad: %v", err)
		}
		if replayed.kind != durableClaimOutcomeExactReplay || replayed.underlyingReplayKind != KindPendingBeforeAssignment {
			t.Fatalf("replay outcome = %+v", replayed)
		}
		conflict, err := service.exactReplayOrLoad(context.Background(), exactReplayRequest{claim: f.claim, binding: f.otherBind})
		if err != nil {
			t.Fatalf("conflict load: %v", err)
		}
		if conflict.kind != durableClaimOutcomeConflict || conflict.hasRecord {
			t.Fatalf("conflict disclosed record: %+v", conflict)
		}
	})

	t.Run(factory.name+"/concurrent-one-winner", func(t *testing.T) {
		handle := factory.open(t)
		defer handle.close(t)
		f := newDurableFixture(t)
		service := mustDurableService(t, handle.store, fixedClaimClock{now: f.now})
		var wg sync.WaitGroup
		results := make(chan durableClaimOutcomeKind, 8)
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				outcome, err := service.establishOrLoadClaim(context.Background(), establishClaimRequest{
					claim:    f.claim,
					plan:     f.plan,
					mutation: f.mutation,
				})
				if err != nil {
					t.Errorf("establishOrLoadClaim: %v", err)
					return
				}
				results <- outcome.kind
			}()
		}
		wg.Wait()
		close(results)
		created := 0
		replayed := 0
		for result := range results {
			switch result {
			case durableClaimOutcomeEstablished:
				created++
			case durableClaimOutcomeExactReplay:
				replayed++
			default:
				t.Fatalf("unexpected concurrent outcome %v", result)
			}
		}
		if created != 1 || replayed != 7 {
			t.Fatalf("created=%d replayed=%d, want 1/7", created, replayed)
		}
	})

	t.Run(factory.name+"/load-not-found", func(t *testing.T) {
		handle := factory.open(t)
		defer handle.close(t)
		f := newDurableFixture(t)
		_, err := handle.store.loadClaim(context.Background(), loadClaimQuery{claim: f.claim})
		if !errors.Is(err, errClaimStoreNotFound) {
			t.Fatalf("load missing error = %v", err)
		}
	})

	t.Run(factory.name+"/cross-caller-isolation", func(t *testing.T) {
		handle := factory.open(t)
		defer handle.close(t)
		firstFixture := newDurableFixture(t)
		firstService := mustDurableService(t, handle.store, fixedClaimClock{now: firstFixture.now})
		first := mustServiceEstablish(t, firstService, firstFixture)

		secondFixture := firstFixture
		secondFixture.caller = mustPrivateCallerRef(t, []byte("private-caller-reference-other"))
		secondFixture.claim = mustPrivateClaimID(t, secondFixture.caller, secondFixture.submitKey)
		secondFixture.plan = mustPrivateBoundPlan(t, secondFixture.binding, secondFixture.witness)
		secondService := mustDurableService(t, handle.store, fixedClaimClock{now: secondFixture.now})
		second := mustServiceEstablish(t, secondService, secondFixture)
		if second.kind != durableClaimOutcomeEstablished {
			t.Fatalf("second caller outcome = %+v", second)
		}
		loadedFirst, err := handle.store.loadClaim(context.Background(), loadClaimQuery{claim: firstFixture.claim})
		if err != nil {
			t.Fatalf("load first caller: %v", err)
		}
		if !loadedFirst.equal(first.record) {
			t.Fatalf("first caller record changed")
		}
		if loadedFirst.claim.Equal(second.record.claim) {
			t.Fatalf("cross-caller claims collapsed")
		}
	})

	t.Run(factory.name+"/cas-run-immutability-and-effect-order", func(t *testing.T) {
		handle := factory.open(t)
		defer handle.close(t)
		f := newDurableFixture(t)
		service := mustDurableService(t, handle.store, &manualClaimClock{now: f.now})
		created := mustServiceEstablish(t, service, f)
		if _, err := service.recordProviderEffectIntent(context.Background(), recordProviderEffectIntentRequest{
			claim:            f.claim,
			binding:          f.binding,
			expectedRevision: created.record.revision,
			intent:           f.intent,
			mutation:         mustPrivateMutationRef(t, []byte("intent-before-assignment")),
		}); !errors.Is(err, ErrInvalidPhase) {
			t.Fatalf("intent before assignment error = %v", err)
		}
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
		stale, err := service.assignRun(context.Background(), assignRunRequest{
			claim:            f.claim,
			binding:          f.binding,
			expectedRevision: created.record.revision,
			run:              f.run,
			mutation:         mustPrivateMutationRef(t, []byte("stale")),
		})
		if err != nil {
			t.Fatalf("stale same-run assignment: %v", err)
		}
		if stale.kind != durableClaimOutcomeStale {
			t.Fatalf("stale outcome = %+v", stale)
		}
		if _, err := service.assignRun(context.Background(), assignRunRequest{
			claim:            f.claim,
			binding:          f.binding,
			expectedRevision: assigned.record.revision,
			run:              f.otherRun,
			mutation:         mustPrivateMutationRef(t, []byte("different-run")),
		}); !errors.Is(err, ErrRunAssignmentMismatch) {
			t.Fatalf("different run error = %v", err)
		}
		if _, err := service.recordProviderDispatchAttempt(context.Background(), recordProviderDispatchAttemptRequest{
			claim:            f.claim,
			binding:          f.binding,
			expectedRevision: assigned.record.revision,
			dispatch:         f.dispatch,
			mutation:         mustPrivateMutationRef(t, []byte("dispatch-before-intent")),
		}); !errors.Is(err, errInvalidDurableRecord) {
			t.Fatalf("dispatch before intent error = %v", err)
		}
		intent, err := service.recordProviderEffectIntent(context.Background(), recordProviderEffectIntentRequest{
			claim:            f.claim,
			binding:          f.binding,
			expectedRevision: assigned.record.revision,
			intent:           f.intent,
			mutation:         mustPrivateMutationRef(t, []byte("intent")),
		})
		if err != nil {
			t.Fatalf("recordProviderEffectIntent: %v", err)
		}
		dispatch, err := service.recordProviderDispatchAttempt(context.Background(), recordProviderDispatchAttemptRequest{
			claim:            f.claim,
			binding:          f.binding,
			expectedRevision: intent.record.revision,
			dispatch:         f.dispatch,
			mutation:         mustPrivateMutationRef(t, []byte("dispatch")),
		})
		if err != nil {
			t.Fatalf("recordProviderDispatchAttempt: %v", err)
		}
		if _, err := service.acceptWithReceipt(context.Background(), acceptWithReceiptRequest{
			claim:            f.claim,
			binding:          f.binding,
			expectedRevision: dispatch.record.revision,
			receipt:          ReceiptRef{},
			accepted:         f.observation,
			mutation:         mustPrivateMutationRef(t, []byte("accepted-without-receipt")),
		}); !errors.Is(err, ErrInvalidPhase) {
			t.Fatalf("accepted without receipt error = %v", err)
		}
		if _, err := service.recordProviderCallObservation(context.Background(), recordProviderCallObservationRequest{
			claim:            f.claim,
			binding:          f.binding,
			expectedRevision: intent.record.revision,
			run:              f.run,
			kind:             durableProviderObservationAmbiguous,
			observation:      f.observation,
			mutation:         mustPrivateMutationRef(t, []byte("stale-provider-observation")),
		}); err != nil {
			t.Fatalf("stale provider observation returned backend error instead of stale outcome: %v", err)
		}
		provider, err := service.recordProviderCallObservation(context.Background(), recordProviderCallObservationRequest{
			claim:            f.claim,
			binding:          f.binding,
			expectedRevision: dispatch.record.revision,
			run:              f.run,
			kind:             durableProviderObservationAmbiguous,
			observation:      f.observation,
			mutation:         mustPrivateMutationRef(t, []byte("provider-observation")),
		})
		if err != nil {
			t.Fatalf("recordProviderCallObservation: %v", err)
		}
		if provider.kind != durableClaimOutcomeProviderObservationRecorded {
			t.Fatalf("provider observation outcome = %+v", provider)
		}
	})

	t.Run(factory.name+"/latest-operation-replay-conflict-and-cas-loser", func(t *testing.T) {
		handle := factory.open(t)
		defer handle.close(t)
		f := newDurableFixture(t)
		service := mustDurableService(t, handle.store, fixedClaimClock{now: f.now})
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
		if replayed.kind != durableClaimOutcomeAssigned || !replayed.record.equal(assigned.record) {
			t.Fatalf("assign replay outcome = %+v", replayed)
		}
		conflict, err := service.assignRun(context.Background(), assignRunRequest{
			claim:            f.claim,
			binding:          f.binding,
			expectedRevision: created.record.revision,
			run:              f.otherRun,
			mutation:         f.nextMut,
		})
		if err != nil {
			t.Fatalf("same mutation conflict: %v", err)
		}
		if conflict.kind != durableClaimOutcomeConflict || conflict.hasRecord {
			t.Fatalf("same mutation conflict outcome = %+v", conflict)
		}

		other := newDurableFixture(t)
		other.caller = mustPrivateCallerRef(t, []byte("private-caller-reference-cas-loser"))
		other.claim = mustPrivateClaimID(t, other.caller, other.submitKey)
		other.plan = mustPrivateBoundPlan(t, other.binding, other.witness)
		casLoser := &conformanceCASLoserStore{claimStore: handle.store}
		casService := mustDurableService(t, casLoser, fixedClaimClock{now: other.now})
		casCreated := mustServiceEstablish(t, casService, other)
		casAssigned, err := casService.assignRun(context.Background(), assignRunRequest{
			claim:            other.claim,
			binding:          other.binding,
			expectedRevision: casCreated.record.revision,
			run:              other.run,
			mutation:         other.nextMut,
		})
		if err != nil {
			t.Fatalf("CAS-loser assign: %v", err)
		}
		if casAssigned.kind != durableClaimOutcomeAssigned || !casLoser.injected {
			t.Fatalf("CAS-loser replay outcome=%+v injected=%v", casAssigned, casLoser.injected)
		}
	})

	t.Run(factory.name+"/accepted-tombstone-and-no-reuse", func(t *testing.T) {
		handle := factory.open(t)
		defer handle.close(t)
		f := newDurableFixture(t)
		service := mustDurableService(t, handle.store, fixedClaimClock{now: f.now})
		created := mustServiceEstablish(t, service, f)
		assigned := mustServiceAssign(t, service, f, created.record.revision)
		intent := mustServiceIntent(t, service, f, assigned.record.revision)
		dispatch := mustServiceDispatch(t, service, f, intent.record.revision)
		accepted, err := service.acceptWithReceipt(context.Background(), acceptWithReceiptRequest{
			claim:            f.claim,
			binding:          f.binding,
			expectedRevision: dispatch.record.revision,
			receipt:          f.receipt,
			accepted:         f.observation,
			mutation:         mustPrivateMutationRef(t, []byte("accepted")),
		})
		if err != nil {
			t.Fatalf("acceptWithReceipt: %v", err)
		}
		if !accepted.acceptedReferenceAvailable || accepted.observationKind != KindAccepted {
			t.Fatalf("accepted disclosure = %+v", accepted)
		}
		tombstoned, err := service.tombstoneOrExpire(context.Background(), tombstoneClaimRequest{
			claim:            f.claim,
			binding:          f.binding,
			expectedRevision: accepted.record.revision,
			state:            durableRetentionTombstoned,
			reason:           "retained no-reuse marker",
			mutation:         mustPrivateMutationRef(t, []byte("tombstone")),
		})
		if err != nil {
			t.Fatalf("tombstoneOrExpire: %v", err)
		}
		if tombstoned.kind != durableClaimOutcomeExpiredUnavailable {
			t.Fatalf("tombstone outcome = %+v", tombstoned)
		}
		reused, err := service.establishOrLoadClaim(context.Background(), establishClaimRequest{
			claim:    f.claim,
			plan:     f.plan,
			mutation: mustPrivateMutationRef(t, []byte("reuse")),
		})
		if err != nil {
			t.Fatalf("reuse establish: %v", err)
		}
		if reused.kind != durableClaimOutcomeExpiredUnavailable {
			t.Fatalf("tombstoned claim was reused: %+v", reused)
		}
	})

	t.Run(factory.name+"/unsupported-codec-fails-closed", func(t *testing.T) {
		handle := factory.open(t)
		defer handle.close(t)
		f := newDurableFixture(t)
		record := mustPrivateRecord(t, mustPrivatePendingBefore(t, f), f)
		record.codecVersion = durableClaimCodecVersion + 1
		_, err := handle.store.establishClaim(context.Background(), establishClaimCommand{record: record})
		if !errors.Is(err, errClaimStoreCorrupt) {
			t.Fatalf("unsupported codec establish error = %v", err)
		}
	})

	t.Run(factory.name+"/commit-uncertainty-reload-compare", func(t *testing.T) {
		handle := factory.open(t)
		defer handle.close(t)
		f := newDurableFixture(t)
		faulty := &commitUnknownAfterAppliedCASStore{claimStore: handle.store}
		service := mustDurableService(t, faulty, fixedClaimClock{now: f.now})
		created := mustServiceEstablish(t, service, f)
		assigned, err := service.assignRun(context.Background(), assignRunRequest{
			claim:            f.claim,
			binding:          f.binding,
			expectedRevision: created.record.revision,
			run:              f.run,
			mutation:         f.nextMut,
		})
		if err != nil {
			t.Fatalf("assign after injected commit uncertainty: %v", err)
		}
		if assigned.kind != durableClaimOutcomeAssigned || !assigned.record.lastMutation.equal(f.nextMut) {
			t.Fatalf("commit uncertainty was not positively resolved: %+v", assigned)
		}
	})

	t.Run(factory.name+"/sanitized-errors", func(t *testing.T) {
		handle := factory.open(t)
		defer handle.close(t)
		f := newDurableFixture(t)
		_, err := handle.store.loadClaim(context.Background(), loadClaimQuery{claim: f.claim})
		if err == nil {
			t.Fatalf("expected not found")
		}
		for _, secret := range []string{"private-caller-reference", "private-submit-key-reference"} {
			if stringsContains(err.Error(), secret) {
				t.Fatalf("store error leaked private value %q: %v", secret, err)
			}
		}
	})

	t.Run(factory.name+"/reopen", func(t *testing.T) {
		f := newDurableFixture(t)
		handle := factory.open(t)
		service := mustDurableService(t, handle.store, fixedClaimClock{now: f.now})
		created := mustServiceEstablish(t, service, f)
		handle.close(t)
		reopened := handle.reopen(t)
		defer reopened.close(t)
		loaded, err := reopened.store.loadClaim(context.Background(), loadClaimQuery{claim: f.claim})
		if err != nil {
			t.Fatalf("load after reopen: %v", err)
		}
		if !loaded.equal(created.record) {
			t.Fatalf("reopened record mismatch")
		}
	})
}

type commitUnknownAfterAppliedCASStore struct {
	claimStore
	injected bool
}

func (s *commitUnknownAfterAppliedCASStore) compareAndSwapClaim(ctx context.Context, cmd compareAndSwapClaimCommand) (compareAndSwapClaimStoreResult, error) {
	result, err := s.claimStore.compareAndSwapClaim(ctx, cmd)
	if err != nil {
		return result, err
	}
	if result.applied && !s.injected {
		s.injected = true
		return compareAndSwapClaimStoreResult{}, errClaimStoreCommitUnknown
	}
	return result, nil
}

type conformanceCASLoserStore struct {
	claimStore
	injected bool
}

func (s *conformanceCASLoserStore) compareAndSwapClaim(ctx context.Context, cmd compareAndSwapClaimCommand) (compareAndSwapClaimStoreResult, error) {
	result, err := s.claimStore.compareAndSwapClaim(ctx, cmd)
	if err != nil {
		return result, err
	}
	if result.applied && !s.injected {
		s.injected = true
		return compareAndSwapClaimStoreResult{record: result.record, found: true}, nil
	}
	return result, nil
}

func mustServiceAssign(t *testing.T, service *durableClaimService, f durableFixture, revision claimRevision) durableClaimOutcome {
	t.Helper()
	outcome, err := service.assignRun(context.Background(), assignRunRequest{
		claim:            f.claim,
		binding:          f.binding,
		expectedRevision: revision,
		run:              f.run,
		mutation:         mustPrivateMutationRef(t, []byte("assign-"+strconv.FormatInt(int64(revision), 10))),
	})
	if err != nil {
		t.Fatalf("assignRun: %v", err)
	}
	return outcome
}

func mustServiceIntent(t *testing.T, service *durableClaimService, f durableFixture, revision claimRevision) durableClaimOutcome {
	t.Helper()
	outcome, err := service.recordProviderEffectIntent(context.Background(), recordProviderEffectIntentRequest{
		claim:            f.claim,
		binding:          f.binding,
		expectedRevision: revision,
		intent:           f.intent,
		mutation:         mustPrivateMutationRef(t, []byte("intent-"+strconv.FormatInt(int64(revision), 10))),
	})
	if err != nil {
		t.Fatalf("recordProviderEffectIntent: %v", err)
	}
	return outcome
}

func mustServiceDispatch(t *testing.T, service *durableClaimService, f durableFixture, revision claimRevision) durableClaimOutcome {
	t.Helper()
	outcome, err := service.recordProviderDispatchAttempt(context.Background(), recordProviderDispatchAttemptRequest{
		claim:            f.claim,
		binding:          f.binding,
		expectedRevision: revision,
		dispatch:         f.dispatch,
		mutation:         mustPrivateMutationRef(t, []byte("dispatch-"+strconv.FormatInt(int64(revision), 10))),
	})
	if err != nil {
		t.Fatalf("recordProviderDispatchAttempt: %v", err)
	}
	return outcome
}

func stringsContains(s string, substr string) bool {
	return strings.Index(s, substr) >= 0
}
