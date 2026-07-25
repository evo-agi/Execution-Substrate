package reliablesubmit_test

import (
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	rs "execution-substrate/es/admission/internal/reliablesubmit"
)

type modelFixture struct {
	caller    rs.CallerRef
	submitKey rs.SubmitKeyRef
	claim     rs.ClaimID
	binding   rs.PlanBinding
	otherBind rs.PlanBinding
	witness   rs.EffectivePlanWitness
	plan      rs.BoundPlan
	run       rs.RunRef
	otherRun  rs.RunRef
	receipt   rs.ReceiptRef
}

func newModelFixture(t *testing.T) modelFixture {
	t.Helper()

	caller := mustCallerRef(t, []byte("private-caller-reference"))
	submitKey := mustSubmitKeyRef(t, []byte("private-submit-key-reference"))
	claim := mustClaimID(t, caller, submitKey)
	binding := mustPlanBinding(t, []byte("private-plan-binding"))
	otherBinding := mustPlanBinding(t, []byte("private-plan-binding-other"))
	witness := mustCompleteWitness(t)
	plan := mustBoundPlan(t, binding, witness)
	run := mustRunRef(t, []byte("private-run-reference"))
	otherRun := mustRunRef(t, []byte("private-run-reference-other"))
	receipt := mustReceiptRef(t, []byte("private-receipt-reference"))

	return modelFixture{
		caller:    caller,
		submitKey: submitKey,
		claim:     claim,
		binding:   binding,
		otherBind: otherBinding,
		witness:   witness,
		plan:      plan,
		run:       run,
		otherRun:  otherRun,
		receipt:   receipt,
	}
}

func mustCallerRef(t *testing.T, value []byte) rs.CallerRef {
	t.Helper()
	ref, err := rs.NewCallerRef(value)
	if err != nil {
		t.Fatalf("NewCallerRef: %v", err)
	}
	return ref
}

func mustSubmitKeyRef(t *testing.T, value []byte) rs.SubmitKeyRef {
	t.Helper()
	ref, err := rs.NewSubmitKeyRef(value)
	if err != nil {
		t.Fatalf("NewSubmitKeyRef: %v", err)
	}
	return ref
}

func mustClaimID(t *testing.T, caller rs.CallerRef, submitKey rs.SubmitKeyRef) rs.ClaimID {
	t.Helper()
	claim, err := rs.NewClaimID(caller, submitKey)
	if err != nil {
		t.Fatalf("NewClaimID: %v", err)
	}
	return claim
}

func mustPlanBinding(t *testing.T, value []byte) rs.PlanBinding {
	t.Helper()
	binding, err := rs.NewPlanBinding(value)
	if err != nil {
		t.Fatalf("NewPlanBinding: %v", err)
	}
	return binding
}

func mustRunRef(t *testing.T, value []byte) rs.RunRef {
	t.Helper()
	ref, err := rs.NewRunRef(value)
	if err != nil {
		t.Fatalf("NewRunRef: %v", err)
	}
	return ref
}

func mustReceiptRef(t *testing.T, value []byte) rs.ReceiptRef {
	t.Helper()
	ref, err := rs.NewReceiptRef(value)
	if err != nil {
		t.Fatalf("NewReceiptRef: %v", err)
	}
	return ref
}

func mustResolvedCategory(t *testing.T, category rs.EffectivePlanCategory) rs.EffectivePlanCategoryCompleteness {
	t.Helper()
	completeness, err := rs.ResolvedCategory(category)
	if err != nil {
		t.Fatalf("ResolvedCategory(%v): %v", category, err)
	}
	return completeness
}

func completeWitnessEntries(t *testing.T, skip rs.EffectivePlanCategory) []rs.EffectivePlanCategoryCompleteness {
	t.Helper()
	entries := make([]rs.EffectivePlanCategoryCompleteness, 0, len(rs.AllEffectivePlanCategories()))
	for _, category := range rs.AllEffectivePlanCategories() {
		if category == skip {
			continue
		}
		entries = append(entries, mustResolvedCategory(t, category))
	}
	return entries
}

func mustCompleteWitness(t *testing.T) rs.EffectivePlanWitness {
	t.Helper()
	witness, err := rs.NewEffectivePlanWitness(completeWitnessEntries(t, 0)...)
	if err != nil {
		t.Fatalf("NewEffectivePlanWitness: %v", err)
	}
	return witness
}

func mustBoundPlan(t *testing.T, binding rs.PlanBinding, witness rs.EffectivePlanWitness) rs.BoundPlan {
	t.Helper()
	plan, err := rs.NewBoundPlan(binding, witness)
	if err != nil {
		t.Fatalf("NewBoundPlan: %v", err)
	}
	return plan
}

func mustPendingBefore(t *testing.T, fixture modelFixture) rs.PendingBeforeAssignment {
	t.Helper()
	phase, err := rs.NewPendingBeforeAssignment(fixture.claim, fixture.plan)
	if err != nil {
		t.Fatalf("NewPendingBeforeAssignment: %v", err)
	}
	return phase
}

func mustAmbiguousBefore(t *testing.T, fixture modelFixture) rs.AmbiguousBeforeAssignment {
	t.Helper()
	phase, err := rs.NewAmbiguousBeforeAssignment(fixture.claim, fixture.plan)
	if err != nil {
		t.Fatalf("NewAmbiguousBeforeAssignment: %v", err)
	}
	return phase
}

func mustAssigned(t *testing.T, phase rs.PreAssignmentPhase, run rs.RunRef) rs.EffectCapableAssigned {
	t.Helper()
	assigned, err := rs.AssignRun(phase, run)
	if err != nil {
		t.Fatalf("AssignRun: %v", err)
	}
	return assigned
}

func mustPendingAfter(t *testing.T, assigned rs.EffectCapableAssigned) rs.PendingAfterAssignment {
	t.Helper()
	phase, err := rs.NewPendingAfterAssignment(assigned)
	if err != nil {
		t.Fatalf("NewPendingAfterAssignment: %v", err)
	}
	return phase
}

func mustAmbiguousAfter(t *testing.T, assigned rs.EffectCapableAssigned) rs.AmbiguousAfterAssignment {
	t.Helper()
	phase, err := rs.NewAmbiguousAfterAssignment(assigned)
	if err != nil {
		t.Fatalf("NewAmbiguousAfterAssignment: %v", err)
	}
	return phase
}

func mustAccepted(t *testing.T, phase rs.ProviderOutcomeCandidatePhase, receipt rs.ReceiptRef) rs.Accepted {
	t.Helper()
	accepted, err := rs.NewAccepted(phase, receipt)
	if err != nil {
		t.Fatalf("NewAccepted: %v", err)
	}
	return accepted
}

func TestIdentityAndBindingRefsAreOpaqueAndFailClosed(t *testing.T) {
	if _, err := rs.NewCallerRef(nil); !errors.Is(err, rs.ErrInvalidCallerRef) {
		t.Fatalf("empty caller ref error = %v", err)
	}
	if _, err := rs.NewSubmitKeyRef(nil); !errors.Is(err, rs.ErrInvalidSubmitKeyRef) {
		t.Fatalf("empty submit key ref error = %v", err)
	}
	if _, err := rs.NewPlanBinding(nil); !errors.Is(err, rs.ErrInvalidPlanBinding) {
		t.Fatalf("empty plan binding error = %v", err)
	}
	if _, err := rs.NewRunRef(nil); !errors.Is(err, rs.ErrInvalidRunRef) {
		t.Fatalf("empty run ref error = %v", err)
	}
	if _, err := rs.NewReceiptRef(nil); !errors.Is(err, rs.ErrInvalidReceiptRef) {
		t.Fatalf("empty receipt ref error = %v", err)
	}

	callerInput := []byte("caller-private-original")
	submitKeyInput := []byte("submit-key-private-original")
	bindingInput := []byte("plan-binding-private-original")
	runInput := []byte("run-private-original")
	receiptInput := []byte("receipt-private-original")

	caller := mustCallerRef(t, callerInput)
	submitKey := mustSubmitKeyRef(t, submitKeyInput)
	binding := mustPlanBinding(t, bindingInput)
	run := mustRunRef(t, runInput)
	receipt := mustReceiptRef(t, receiptInput)

	callerInput[0] = 'X'
	submitKeyInput[0] = 'X'
	bindingInput[0] = 'X'
	runInput[0] = 'X'
	receiptInput[0] = 'X'

	if !caller.Equal(mustCallerRef(t, []byte("caller-private-original"))) {
		t.Fatalf("caller ref did not defensively copy input")
	}
	if !submitKey.Equal(mustSubmitKeyRef(t, []byte("submit-key-private-original"))) {
		t.Fatalf("submit key ref did not defensively copy input")
	}
	if !binding.Equal(mustPlanBinding(t, []byte("plan-binding-private-original"))) {
		t.Fatalf("plan binding did not defensively copy input")
	}
	if !run.Equal(mustRunRef(t, []byte("run-private-original"))) {
		t.Fatalf("run ref did not defensively copy input")
	}
	if !receipt.Equal(mustReceiptRef(t, []byte("receipt-private-original"))) {
		t.Fatalf("receipt ref did not defensively copy input")
	}

	if caller.Equal(mustCallerRef(t, []byte("caller-private-other"))) {
		t.Fatalf("caller equality matched a different reference")
	}
	if submitKey.Equal(mustSubmitKeyRef(t, []byte("submit-key-private-other"))) {
		t.Fatalf("submit-key equality matched a different reference")
	}
	if binding.Equal(mustPlanBinding(t, []byte("plan-binding-private-other"))) {
		t.Fatalf("plan-binding equality matched a different binding")
	}
	if run.Equal(mustRunRef(t, []byte("run-private-other"))) {
		t.Fatalf("run-ref equality matched a different reference")
	}
	if receipt.Equal(mustReceiptRef(t, []byte("receipt-private-other"))) {
		t.Fatalf("receipt-ref equality matched a different reference")
	}

	claim := mustClaimID(t, caller, submitKey)
	otherClaim := mustClaimID(t, caller, mustSubmitKeyRef(t, []byte("submit-key-private-other")))
	if !claim.Equal(mustClaimID(t, caller, submitKey)) {
		t.Fatalf("claim equality did not match identical safe refs")
	}
	if claim.Equal(otherClaim) {
		t.Fatalf("claim equality matched a different submit key")
	}

	for _, value := range []any{caller, submitKey, claim, binding, run, receipt} {
		if _, ok := value.(fmt.Stringer); ok {
			t.Fatalf("%T must not implement fmt.Stringer", value)
		}
	}

	formatted := fmt.Sprintf("%v %#v %+v", caller, submitKey, claim)
	formatted += fmt.Sprintf(" %v %#v %+v", binding, run, receipt)
	for _, secret := range []string{
		"caller-private-original",
		"submit-key-private-original",
		"plan-binding-private-original",
		"run-private-original",
		"receipt-private-original",
	} {
		if strings.Contains(formatted, secret) {
			t.Fatalf("formatted references exposed private value %q in %q", secret, formatted)
		}
	}
}

func TestModelErrorsDoNotExposePrivateReferenceValues(t *testing.T) {
	fixture := newModelFixture(t)
	pending := mustPendingBefore(t, fixture)
	assigned := mustAssigned(t, pending, fixture.run)

	errs := []error{
		rs.ValidateRunAssignment(assigned, fixture.otherRun),
		rs.ValidatePlanBinding(assigned, fixture.otherBind),
	}
	for _, err := range errs {
		if err == nil {
			t.Fatalf("expected validation error")
		}
		for _, secret := range []string{
			"private-caller-reference",
			"private-submit-key-reference",
			"private-plan-binding",
			"private-run-reference",
			"private-receipt-reference",
		} {
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("error %q exposed private value %q", err.Error(), secret)
			}
		}
	}
}

func requireNoPanicError(t *testing.T, name string, fn func() error) error {
	t.Helper()

	var err error
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("%s panicked: %v", name, recovered)
			}
		}()
		err = fn()
	}()
	return err
}

func requirePrivateModelError(t *testing.T, name string, err error, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s error = %v, want %v", name, err, want)
	}
	for _, secret := range []string{
		"private-caller-reference",
		"private-submit-key-reference",
		"private-plan-binding",
		"private-run-reference",
		"private-receipt-reference",
	} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("%s error %q exposed private value %q", name, err.Error(), secret)
		}
	}
}

func TestPhaseInterfaceOperationsRejectPointerFormsWithoutPanic(t *testing.T) {
	fixture := newModelFixture(t)
	pending := mustPendingBefore(t, fixture)
	ambiguous := mustAmbiguousBefore(t, fixture)
	assigned := mustAssigned(t, pending, fixture.run)
	pendingAfter := mustPendingAfter(t, assigned)
	ambiguousAfter := mustAmbiguousAfter(t, assigned)
	accepted := mustAccepted(t, pendingAfter, fixture.receipt)
	notAccepted, err := rs.NewProvablyNotAcceptedAfterAssignment(ambiguousAfter)
	if err != nil {
		t.Fatalf("NewProvablyNotAcceptedAfterAssignment: %v", err)
	}

	t.Run("AssignRun", func(t *testing.T) {
		var nilPhase rs.PreAssignmentPhase
		var nilPending *rs.PendingBeforeAssignment
		var nilAmbiguous *rs.AmbiguousBeforeAssignment
		for _, tc := range []struct {
			name  string
			phase rs.PreAssignmentPhase
			want  error
			ok    bool
		}{
			{name: "nil interface", phase: nilPhase, want: rs.ErrInvalidPhase},
			{name: "typed nil pending pointer", phase: nilPending, want: rs.ErrInvalidPhase},
			{name: "typed nil ambiguous pointer", phase: nilAmbiguous, want: rs.ErrInvalidPhase},
			{name: "valid pending pointer", phase: &pending, want: rs.ErrInvalidPhase},
			{name: "valid ambiguous pointer", phase: &ambiguous, want: rs.ErrInvalidPhase},
			{name: "zero pending pointer", phase: &rs.PendingBeforeAssignment{}, want: rs.ErrInvalidPhase},
			{name: "zero ambiguous pointer", phase: &rs.AmbiguousBeforeAssignment{}, want: rs.ErrInvalidPhase},
			{name: "zero pending value", phase: rs.PendingBeforeAssignment{}, want: rs.ErrInvalidPhase},
			{name: "zero ambiguous value", phase: rs.AmbiguousBeforeAssignment{}, want: rs.ErrInvalidPhase},
			{name: "valid pending value", phase: pending, ok: true},
			{name: "valid ambiguous value", phase: ambiguous, ok: true},
		} {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				var got rs.EffectCapableAssigned
				err := requireNoPanicError(t, tc.name, func() error {
					var applyErr error
					got, applyErr = rs.AssignRun(tc.phase, fixture.run)
					return applyErr
				})
				if tc.ok {
					if err != nil {
						t.Fatalf("AssignRun valid value error = %v", err)
					}
					if !got.Valid() || !got.HasAssignedRunRef() {
						t.Fatalf("AssignRun valid value did not produce assigned phase")
					}
					return
				}
				requirePrivateModelError(t, tc.name, err, tc.want)
				if got.Valid() || got.HasAssignedRunRef() {
					t.Fatalf("%s fabricated assigned phase from invalid input", tc.name)
				}
			})
		}
	})

	t.Run("ValidateRunAssignment", func(t *testing.T) {
		var nilPhase rs.AssignedRunPhase
		var nilAssigned *rs.EffectCapableAssigned
		var nilPendingAfter *rs.PendingAfterAssignment
		var nilAmbiguousAfter *rs.AmbiguousAfterAssignment
		var nilAccepted *rs.Accepted
		var nilNotAccepted *rs.ProvablyNotAcceptedAfterAssignment
		for _, tc := range []struct {
			name  string
			phase rs.AssignedRunPhase
			want  error
			ok    bool
		}{
			{name: "nil interface", phase: nilPhase, want: rs.ErrInvalidPhase},
			{name: "typed nil assigned pointer", phase: nilAssigned, want: rs.ErrInvalidPhase},
			{name: "typed nil pending-after pointer", phase: nilPendingAfter, want: rs.ErrInvalidPhase},
			{name: "typed nil ambiguous-after pointer", phase: nilAmbiguousAfter, want: rs.ErrInvalidPhase},
			{name: "typed nil accepted pointer", phase: nilAccepted, want: rs.ErrInvalidPhase},
			{name: "typed nil not-accepted pointer", phase: nilNotAccepted, want: rs.ErrInvalidPhase},
			{name: "valid assigned pointer", phase: &assigned, want: rs.ErrInvalidPhase},
			{name: "valid pending-after pointer", phase: &pendingAfter, want: rs.ErrInvalidPhase},
			{name: "valid ambiguous-after pointer", phase: &ambiguousAfter, want: rs.ErrInvalidPhase},
			{name: "valid accepted pointer", phase: &accepted, want: rs.ErrInvalidPhase},
			{name: "valid not-accepted pointer", phase: &notAccepted, want: rs.ErrInvalidPhase},
			{name: "zero assigned pointer", phase: &rs.EffectCapableAssigned{}, want: rs.ErrInvalidPhase},
			{name: "zero pending-after pointer", phase: &rs.PendingAfterAssignment{}, want: rs.ErrInvalidPhase},
			{name: "zero ambiguous-after pointer", phase: &rs.AmbiguousAfterAssignment{}, want: rs.ErrInvalidPhase},
			{name: "zero accepted pointer", phase: &rs.Accepted{}, want: rs.ErrInvalidPhase},
			{name: "zero not-accepted pointer", phase: &rs.ProvablyNotAcceptedAfterAssignment{}, want: rs.ErrInvalidPhase},
			{name: "zero assigned value", phase: rs.EffectCapableAssigned{}, want: rs.ErrInvalidPhase},
			{name: "zero pending-after value", phase: rs.PendingAfterAssignment{}, want: rs.ErrInvalidPhase},
			{name: "zero ambiguous-after value", phase: rs.AmbiguousAfterAssignment{}, want: rs.ErrInvalidPhase},
			{name: "zero accepted value", phase: rs.Accepted{}, want: rs.ErrInvalidPhase},
			{name: "zero not-accepted value", phase: rs.ProvablyNotAcceptedAfterAssignment{}, want: rs.ErrInvalidPhase},
			{name: "valid assigned value", phase: assigned, ok: true},
			{name: "valid pending-after value", phase: pendingAfter, ok: true},
			{name: "valid ambiguous-after value", phase: ambiguousAfter, ok: true},
			{name: "valid accepted value", phase: accepted, ok: true},
			{name: "valid not-accepted value", phase: notAccepted, ok: true},
		} {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				err := requireNoPanicError(t, tc.name, func() error {
					return rs.ValidateRunAssignment(tc.phase, fixture.run)
				})
				if tc.ok {
					if err != nil {
						t.Fatalf("ValidateRunAssignment valid value error = %v", err)
					}
					return
				}
				requirePrivateModelError(t, tc.name, err, tc.want)
			})
		}
	})

	t.Run("ValidatePlanBindingAndReplay", func(t *testing.T) {
		var nilPhase rs.ClaimPhase
		var nilPending *rs.PendingBeforeAssignment
		var nilAmbiguous *rs.AmbiguousBeforeAssignment
		var nilAssigned *rs.EffectCapableAssigned
		var nilPendingAfter *rs.PendingAfterAssignment
		var nilAmbiguousAfter *rs.AmbiguousAfterAssignment
		var nilAccepted *rs.Accepted
		var nilNotAccepted *rs.ProvablyNotAcceptedAfterAssignment
		for _, tc := range []struct {
			name  string
			phase rs.ClaimPhase
			ok    bool
		}{
			{name: "nil interface", phase: nilPhase},
			{name: "typed nil pending pointer", phase: nilPending},
			{name: "typed nil ambiguous pointer", phase: nilAmbiguous},
			{name: "typed nil assigned pointer", phase: nilAssigned},
			{name: "typed nil pending-after pointer", phase: nilPendingAfter},
			{name: "typed nil ambiguous-after pointer", phase: nilAmbiguousAfter},
			{name: "typed nil accepted pointer", phase: nilAccepted},
			{name: "typed nil not-accepted pointer", phase: nilNotAccepted},
			{name: "valid pending pointer", phase: &pending},
			{name: "valid ambiguous pointer", phase: &ambiguous},
			{name: "valid assigned pointer", phase: &assigned},
			{name: "valid pending-after pointer", phase: &pendingAfter},
			{name: "valid ambiguous-after pointer", phase: &ambiguousAfter},
			{name: "valid accepted pointer", phase: &accepted},
			{name: "valid not-accepted pointer", phase: &notAccepted},
			{name: "zero pending pointer", phase: &rs.PendingBeforeAssignment{}},
			{name: "zero ambiguous pointer", phase: &rs.AmbiguousBeforeAssignment{}},
			{name: "zero assigned pointer", phase: &rs.EffectCapableAssigned{}},
			{name: "zero pending-after pointer", phase: &rs.PendingAfterAssignment{}},
			{name: "zero ambiguous-after pointer", phase: &rs.AmbiguousAfterAssignment{}},
			{name: "zero accepted pointer", phase: &rs.Accepted{}},
			{name: "zero not-accepted pointer", phase: &rs.ProvablyNotAcceptedAfterAssignment{}},
			{name: "zero pending value", phase: rs.PendingBeforeAssignment{}},
			{name: "zero ambiguous value", phase: rs.AmbiguousBeforeAssignment{}},
			{name: "zero assigned value", phase: rs.EffectCapableAssigned{}},
			{name: "zero pending-after value", phase: rs.PendingAfterAssignment{}},
			{name: "zero ambiguous-after value", phase: rs.AmbiguousAfterAssignment{}},
			{name: "zero accepted value", phase: rs.Accepted{}},
			{name: "zero not-accepted value", phase: rs.ProvablyNotAcceptedAfterAssignment{}},
			{name: "valid pending value", phase: pending, ok: true},
			{name: "valid ambiguous value", phase: ambiguous, ok: true},
			{name: "valid assigned value", phase: assigned, ok: true},
			{name: "valid pending-after value", phase: pendingAfter, ok: true},
			{name: "valid ambiguous-after value", phase: ambiguousAfter, ok: true},
			{name: "valid accepted value", phase: accepted, ok: true},
			{name: "valid not-accepted value", phase: notAccepted, ok: true},
		} {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				planErr := requireNoPanicError(t, tc.name+" plan", func() error {
					return rs.ValidatePlanBinding(tc.phase, fixture.binding)
				})
				var replay rs.ExactReplay
				replayErr := requireNoPanicError(t, tc.name+" replay", func() error {
					var err error
					replay, err = rs.NewExactReplay(tc.phase)
					return err
				})
				if tc.ok {
					if planErr != nil {
						t.Fatalf("ValidatePlanBinding valid value error = %v", planErr)
					}
					if replayErr != nil {
						t.Fatalf("NewExactReplay valid value error = %v", replayErr)
					}
					if !replay.Valid() || replay.UnderlyingKind() != tc.phase.Kind() {
						t.Fatalf("valid replay did not preserve underlying kind")
					}
					return
				}
				requirePrivateModelError(t, tc.name+" plan", planErr, rs.ErrInvalidPhase)
				requirePrivateModelError(t, tc.name+" replay", replayErr, rs.ErrInvalidReplay)
				if replay.Valid() || replay.UnderlyingKind() != rs.KindInvalid ||
					replay.HasAssignedRunRef() || replay.AcceptedSubmissionReferenceAvailable() {
					t.Fatalf("%s fabricated replay output from invalid input", tc.name)
				}
			})
		}
	})

	t.Run("provider outcome constructors", func(t *testing.T) {
		var nilPhase rs.ProviderOutcomeCandidatePhase
		var nilAssigned *rs.EffectCapableAssigned
		var nilPendingAfter *rs.PendingAfterAssignment
		var nilAmbiguousAfter *rs.AmbiguousAfterAssignment
		for _, tc := range []struct {
			name  string
			phase rs.ProviderOutcomeCandidatePhase
			ok    bool
		}{
			{name: "nil interface", phase: nilPhase},
			{name: "typed nil assigned pointer", phase: nilAssigned},
			{name: "typed nil pending-after pointer", phase: nilPendingAfter},
			{name: "typed nil ambiguous-after pointer", phase: nilAmbiguousAfter},
			{name: "valid assigned pointer", phase: &assigned},
			{name: "valid pending-after pointer", phase: &pendingAfter},
			{name: "valid ambiguous-after pointer", phase: &ambiguousAfter},
			{name: "zero assigned pointer", phase: &rs.EffectCapableAssigned{}},
			{name: "zero pending-after pointer", phase: &rs.PendingAfterAssignment{}},
			{name: "zero ambiguous-after pointer", phase: &rs.AmbiguousAfterAssignment{}},
			{name: "zero assigned value", phase: rs.EffectCapableAssigned{}},
			{name: "zero pending-after value", phase: rs.PendingAfterAssignment{}},
			{name: "zero ambiguous-after value", phase: rs.AmbiguousAfterAssignment{}},
			{name: "valid assigned value", phase: assigned, ok: true},
			{name: "valid pending-after value", phase: pendingAfter, ok: true},
			{name: "valid ambiguous-after value", phase: ambiguousAfter, ok: true},
		} {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				var gotAccepted rs.Accepted
				acceptedErr := requireNoPanicError(t, tc.name+" accepted", func() error {
					var err error
					gotAccepted, err = rs.NewAccepted(tc.phase, fixture.receipt)
					return err
				})
				var gotNotAccepted rs.ProvablyNotAcceptedAfterAssignment
				notAcceptedErr := requireNoPanicError(t, tc.name+" not accepted", func() error {
					var err error
					gotNotAccepted, err = rs.NewProvablyNotAcceptedAfterAssignment(tc.phase)
					return err
				})
				if tc.ok {
					if acceptedErr != nil {
						t.Fatalf("NewAccepted valid value error = %v", acceptedErr)
					}
					if notAcceptedErr != nil {
						t.Fatalf("NewProvablyNotAcceptedAfterAssignment valid value error = %v", notAcceptedErr)
					}
					if !gotAccepted.Valid() || !gotAccepted.AcceptedSubmissionReferenceAvailable() {
						t.Fatalf("valid provider phase did not produce accepted reference")
					}
					if !gotNotAccepted.Valid() || gotNotAccepted.AcceptedSubmissionReferenceAvailable() {
						t.Fatalf("valid provider phase produced invalid not-accepted output")
					}
					return
				}
				requirePrivateModelError(t, tc.name+" accepted", acceptedErr, rs.ErrInvalidProviderOutcomeCandidatePhase)
				requirePrivateModelError(t, tc.name+" not accepted", notAcceptedErr, rs.ErrInvalidProviderOutcomeCandidatePhase)
				if gotAccepted.Valid() || gotAccepted.HasAssignedRunRef() || gotAccepted.AcceptedSubmissionReferenceAvailable() {
					t.Fatalf("%s fabricated accepted output from invalid input", tc.name)
				}
				if gotNotAccepted.Valid() || gotNotAccepted.HasAssignedRunRef() || gotNotAccepted.AcceptedSubmissionReferenceAvailable() {
					t.Fatalf("%s fabricated not-accepted output from invalid input", tc.name)
				}
			})
		}
	})
}

func TestExactReplayStoresImmutableValueSnapshot(t *testing.T) {
	callerInput := []byte("snapshot-caller-private")
	keyInput := []byte("snapshot-key-private")
	bindingInput := []byte("snapshot-plan-binding-private")
	runInput := []byte("snapshot-run-private")
	receiptInput := []byte("snapshot-receipt-private")

	caller := mustCallerRef(t, callerInput)
	submitKey := mustSubmitKeyRef(t, keyInput)
	claim := mustClaimID(t, caller, submitKey)
	binding := mustPlanBinding(t, bindingInput)
	witness := mustCompleteWitness(t)
	plan := mustBoundPlan(t, binding, witness)
	pending := mustPendingBefore(t, modelFixture{claim: claim, plan: plan})
	run := mustRunRef(t, runInput)
	assigned := mustAssigned(t, pending, run)
	receipt := mustReceiptRef(t, receiptInput)
	accepted := mustAccepted(t, assigned, receipt)
	originalRun := mustRunRef(t, []byte("snapshot-run-private"))
	originalReceipt := mustReceiptRef(t, []byte("snapshot-receipt-private"))

	replay, err := rs.NewExactReplay(accepted)
	if err != nil {
		t.Fatalf("NewExactReplay(accepted): %v", err)
	}
	if _, err := rs.NewExactReplay(&accepted); !errors.Is(err, rs.ErrInvalidReplay) {
		t.Fatalf("pointer replay error = %v", err)
	}
	var nilAccepted *rs.Accepted
	if _, err := rs.NewExactReplay(nilAccepted); !errors.Is(err, rs.ErrInvalidReplay) {
		t.Fatalf("typed nil replay error = %v", err)
	}

	callerInput[0] = 'X'
	keyInput[0] = 'X'
	bindingInput[0] = 'X'
	runInput[0] = 'X'
	receiptInput[0] = 'X'
	accepted = mustAccepted(t, mustAssigned(t, pending, mustRunRef(t, []byte("changed-run-private"))), mustReceiptRef(t, []byte("changed-receipt-private")))

	if replay.UnderlyingKind() != rs.KindAccepted || !replay.AcceptedSubmissionReferenceAvailable() {
		t.Fatalf("accepted replay snapshot changed kind or accepted availability")
	}
	gotRun, ok := replay.AssignedRunRef()
	if !ok || !gotRun.Equal(originalRun) {
		t.Fatalf("replay run changed after caller mutation")
	}
	gotReceipt, ok := replay.ReceiptRef()
	if !ok || !gotReceipt.Equal(originalReceipt) {
		t.Fatalf("replay receipt changed after caller mutation")
	}
	if gotRun.Equal(mustRunRef(t, []byte("changed-run-private"))) || gotReceipt.Equal(mustReceiptRef(t, []byte("changed-receipt-private"))) {
		t.Fatalf("replay observed reassigned caller phase")
	}

	fixture := newModelFixture(t)
	pendingReplay, err := rs.NewExactReplay(mustPendingBefore(t, fixture))
	if err != nil {
		t.Fatalf("NewExactReplay(pending): %v", err)
	}
	if pendingReplay.AcceptedSubmissionReferenceAvailable() || pendingReplay.HasAssignedRunRef() {
		t.Fatalf("pending replay must remain non-accepted and runless")
	}
	ambiguousReplay, err := rs.NewExactReplay(mustAmbiguousBefore(t, fixture))
	if err != nil {
		t.Fatalf("NewExactReplay(ambiguous): %v", err)
	}
	if ambiguousReplay.AcceptedSubmissionReferenceAvailable() || ambiguousReplay.HasAssignedRunRef() {
		t.Fatalf("ambiguous-before replay must remain non-accepted and runless")
	}
}

func TestOpaqueReferencesDoNotLeakThroughFormattingOrMarshaling(t *testing.T) {
	caller := mustCallerRef(t, []byte("sentinel-caller-private"))
	submitKey := mustSubmitKeyRef(t, []byte("sentinel-submit-key-private"))
	claim := mustClaimID(t, caller, submitKey)
	binding := mustPlanBinding(t, []byte("sentinel-binding-private"))
	run := mustRunRef(t, []byte("sentinel-run-private"))
	receipt := mustReceiptRef(t, []byte("sentinel-receipt-private"))

	for _, tc := range []struct {
		name     string
		value    any
		sentinel string
	}{
		{name: "CallerRef", value: caller, sentinel: "sentinel-caller-private"},
		{name: "SubmitKeyRef", value: submitKey, sentinel: "sentinel-submit-key-private"},
		{name: "ClaimID caller", value: claim, sentinel: "sentinel-caller-private"},
		{name: "ClaimID key", value: claim, sentinel: "sentinel-submit-key-private"},
		{name: "PlanBinding", value: binding, sentinel: "sentinel-binding-private"},
		{name: "RunRef", value: run, sentinel: "sentinel-run-private"},
		{name: "ReceiptRef", value: receipt, sentinel: "sentinel-receipt-private"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			valueType := reflect.TypeOf(tc.value)
			for _, iface := range []struct {
				name string
				typ  reflect.Type
			}{
				{name: "fmt.Stringer", typ: reflect.TypeOf((*fmt.Stringer)(nil)).Elem()},
				{name: "fmt.GoStringer", typ: reflect.TypeOf((*fmt.GoStringer)(nil)).Elem()},
				{name: "encoding.TextMarshaler", typ: reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem()},
				{name: "json.Marshaler", typ: reflect.TypeOf((*json.Marshaler)(nil)).Elem()},
			} {
				if valueType.Implements(iface.typ) || reflect.PointerTo(valueType).Implements(iface.typ) {
					t.Fatalf("%s must not implement %s", valueType, iface.name)
				}
			}
			for _, formatted := range []string{
				fmt.Sprint(tc.value),
				fmt.Sprintf("%v", tc.value),
				fmt.Sprintf("%+v", tc.value),
				fmt.Sprintf("%#v", tc.value),
				fmt.Sprintf("%s", tc.value),
				fmt.Sprintf("%q", tc.value),
				fmt.Sprintf("%x", tc.value),
				fmt.Sprintf("%X", tc.value),
				fmt.Errorf("ordinary error formatting: %v", tc.value).Error(),
			} {
				if strings.Contains(formatted, tc.sentinel) {
					t.Fatalf("%s leaked sentinel through formatting: %q", tc.name, formatted)
				}
			}
			marshaled, err := json.Marshal(tc.value)
			if err != nil {
				t.Fatalf("json.Marshal(%s): %v", tc.name, err)
			}
			if strings.Contains(string(marshaled), tc.sentinel) {
				t.Fatalf("%s leaked sentinel through JSON: %s", tc.name, string(marshaled))
			}
			for i := 0; i < valueType.NumMethod(); i++ {
				method := valueType.Method(i)
				if method.Type.NumOut() == 1 && method.Type.Out(0).Kind() == reflect.Slice &&
					method.Type.Out(0).Elem().Kind() == reflect.Uint8 {
					t.Fatalf("%s exposes mutable private bytes through %s", valueType, method.Name)
				}
			}
		})
	}
}

func TestEffectivePlanWitnessRequiresExactCategoryCompleteness(t *testing.T) {
	all := rs.AllEffectivePlanCategories()
	if len(all) != 14 {
		t.Fatalf("expected 14 effective-plan categories, got %d", len(all))
	}

	required := map[rs.EffectivePlanCategory]bool{
		rs.EffectivePlanCategoryRequestSchemaOrVersion:        true,
		rs.EffectivePlanCategoryExecutionMode:                 true,
		rs.EffectivePlanCategoryTimeoutSemantics:              true,
		rs.EffectivePlanCategoryCPU:                           true,
		rs.EffectivePlanCategoryMemory:                        true,
		rs.EffectivePlanCategoryRuntimeProfile:                true,
		rs.EffectivePlanCategoryArtifactIdentity:              true,
		rs.EffectivePlanCategoryDerivationSpecIdentity:        true,
		rs.EffectivePlanCategoryOutputIdentity:                true,
		rs.EffectivePlanCategoryCommandAndArgv:                true,
		rs.EffectivePlanCategoryEnvironmentAdditions:          true,
		rs.EffectivePlanCategoryMounts:                        true,
		rs.EffectivePlanCategoryNetworkPosture:                true,
		rs.EffectivePlanCategoryAuthorityHandoffApplicability: true,
	}
	for _, category := range all {
		if !required[category] {
			t.Fatalf("unexpected effective-plan category %v", category)
		}
	}

	witness := mustCompleteWitness(t)
	if !witness.Valid() {
		t.Fatalf("complete witness should be valid")
	}
	if witness.CategoryCount() != 14 {
		t.Fatalf("complete witness category count = %d", witness.CategoryCount())
	}
	for _, category := range []rs.EffectivePlanCategory{
		rs.EffectivePlanCategoryCommandAndArgv,
		rs.EffectivePlanCategoryEnvironmentAdditions,
		rs.EffectivePlanCategoryMounts,
	} {
		resolution, err := witness.Resolution(category)
		if err != nil {
			t.Fatalf("resolution for %v: %v", category, err)
		}
		if resolution != rs.EffectivePlanResolved {
			t.Fatalf("empty collection category %v must be concrete resolved, got %v", category, resolution)
		}
	}

	withDuplicate := append(completeWitnessEntries(t, 0), mustResolvedCategory(t, rs.EffectivePlanCategoryCPU))
	if _, err := rs.NewEffectivePlanWitness(withDuplicate...); !errors.Is(err, rs.ErrDuplicateEffectivePlanCategory) {
		t.Fatalf("duplicate category error = %v", err)
	}

	for _, missing := range []rs.EffectivePlanCategory{
		rs.EffectivePlanCategoryCPU,
		rs.EffectivePlanCategoryMemory,
	} {
		if _, err := rs.NewEffectivePlanWitness(completeWitnessEntries(t, missing)...); !errors.Is(err, rs.ErrMissingEffectivePlanCategory) {
			t.Fatalf("missing %v error = %v", missing, err)
		}
	}

	withUnresolved := completeWitnessEntries(t, 0)
	withUnresolved[0] = rs.EffectivePlanCategoryCompleteness{}
	if _, err := rs.NewEffectivePlanWitness(withUnresolved...); !errors.Is(err, rs.ErrInvalidEffectivePlanWitness) {
		t.Fatalf("unresolved category error = %v", err)
	}

	if _, err := rs.ExplicitlyInapplicableCategory(rs.EffectivePlanCategoryCPU); !errors.Is(err, rs.ErrInapplicableEffectivePlanCategory) {
		t.Fatalf("CPU inapplicable error = %v", err)
	}
	if _, err := rs.ExplicitlyInapplicableCategory(rs.EffectivePlanCategoryMemory); !errors.Is(err, rs.ErrInapplicableEffectivePlanCategory) {
		t.Fatalf("memory inapplicable error = %v", err)
	}
	if _, err := rs.ExplicitlyInapplicableCategory(rs.EffectivePlanCategoryTimeoutSemantics); !errors.Is(err, rs.ErrInapplicableEffectivePlanCategory) {
		t.Fatalf("timeout inapplicable error = %v", err)
	}
	if _, err := rs.ExplicitlyInapplicableCategory(rs.EffectivePlanCategoryRuntimeProfile); !errors.Is(err, rs.ErrInapplicableEffectivePlanCategory) {
		t.Fatalf("runtime-profile inapplicable error = %v", err)
	}
	if _, err := rs.ExplicitlyInapplicableCategory(rs.EffectivePlanCategoryNetworkPosture); !errors.Is(err, rs.ErrInapplicableEffectivePlanCategory) {
		t.Fatalf("network inapplicable error = %v", err)
	}
	if _, err := rs.ExplicitlyInapplicableCategory(rs.EffectivePlanCategoryOutputIdentity); !errors.Is(err, rs.ErrInapplicableEffectivePlanCategory) {
		t.Fatalf("generic output inapplicable error = %v", err)
	}

	outputInapplicable := completeWitnessEntries(t, rs.EffectivePlanCategoryOutputIdentity)
	outputInapplicable = append(outputInapplicable, rs.OutputIdentityExplicitlyInapplicableForPermittedExecutionKind())
	witness, err := rs.NewEffectivePlanWitness(outputInapplicable...)
	if err != nil {
		t.Fatalf("output inapplicable through explicit rule should be accepted: %v", err)
	}
	resolution, err := witness.Resolution(rs.EffectivePlanCategoryOutputIdentity)
	if err != nil {
		t.Fatalf("output resolution: %v", err)
	}
	if resolution != rs.EffectivePlanExplicitlyInapplicable {
		t.Fatalf("output resolution = %v, want explicitly inapplicable", resolution)
	}

	authorityInapplicable := completeWitnessEntries(t, rs.EffectivePlanCategoryAuthorityHandoffApplicability)
	authority, err := rs.ExplicitlyInapplicableCategory(rs.EffectivePlanCategoryAuthorityHandoffApplicability)
	if err != nil {
		t.Fatalf("authority-handoff inapplicable should be constructible: %v", err)
	}
	authorityInapplicable = append(authorityInapplicable, authority)
	if _, err := rs.NewEffectivePlanWitness(authorityInapplicable...); err != nil {
		t.Fatalf("authority-handoff inapplicable witness should be accepted: %v", err)
	}
}

func TestEffectivePlanWitnessZeroValueAndCopiesInputs(t *testing.T) {
	var zero rs.EffectivePlanWitness
	if zero.Valid() {
		t.Fatalf("zero witness must be invalid")
	}
	if zero.CategoryCount() != 0 {
		t.Fatalf("zero witness category count = %d", zero.CategoryCount())
	}
	if _, err := zero.Resolution(rs.EffectivePlanCategoryCPU); !errors.Is(err, rs.ErrInvalidEffectivePlanWitness) {
		t.Fatalf("zero witness resolution error = %v", err)
	}

	categories := rs.AllEffectivePlanCategories()
	categories[0] = 0
	if rs.AllEffectivePlanCategories()[0] == 0 {
		t.Fatalf("AllEffectivePlanCategories returned mutable retained storage")
	}

	entries := completeWitnessEntries(t, 0)
	witness, err := rs.NewEffectivePlanWitness(entries...)
	if err != nil {
		t.Fatalf("NewEffectivePlanWitness: %v", err)
	}
	entries[0] = rs.EffectivePlanCategoryCompleteness{}
	if !witness.Valid() {
		t.Fatalf("witness changed after mutating caller-owned entry slice")
	}
}

func TestPhaseZeroValuesFailClosed(t *testing.T) {
	for _, phase := range []rs.ClaimPhase{
		rs.PendingBeforeAssignment{},
		rs.AmbiguousBeforeAssignment{},
		rs.EffectCapableAssigned{},
		rs.PendingAfterAssignment{},
		rs.AmbiguousAfterAssignment{},
		rs.Accepted{},
		rs.ProvablyNotAcceptedAfterAssignment{},
	} {
		if phase.Valid() {
			t.Fatalf("%T zero value should be invalid", phase)
		}
		if phase.Kind() != rs.KindInvalid {
			t.Fatalf("%T zero kind = %v", phase, phase.Kind())
		}
		if _, ok := phase.ClaimID(); ok {
			t.Fatalf("%T zero value exposed claim", phase)
		}
		if _, ok := phase.BoundPlan(); ok {
			t.Fatalf("%T zero value exposed plan", phase)
		}
		if phase.HasAssignedRunRef() {
			t.Fatalf("%T zero value reported assigned run", phase)
		}
		if _, ok := phase.AssignedRunRef(); ok {
			t.Fatalf("%T zero value exposed run", phase)
		}
		if _, ok := phase.ReceiptRef(); ok {
			t.Fatalf("%T zero value exposed receipt", phase)
		}
		if phase.SameCallerRunRefDisclosure() != rs.RunRefDisclosureForbidden {
			t.Fatalf("%T zero disclosure was not fail-closed", phase)
		}
		if phase.AcceptedSubmissionReferenceAvailable() {
			t.Fatalf("%T zero value reported accepted submission reference", phase)
		}
	}

	for _, decision := range []struct {
		name  string
		valid bool
	}{
		{name: fmt.Sprint(rs.RecoveredAccepted{}), valid: rs.RecoveredAccepted{}.Valid()},
		{name: fmt.Sprint(rs.ExactReplay{}), valid: rs.ExactReplay{}.Valid()},
		{name: fmt.Sprint(rs.Conflict{}), valid: rs.Conflict{}.Valid()},
		{name: fmt.Sprint(rs.Unauthorized{}), valid: rs.Unauthorized{}.Valid()},
		{name: fmt.Sprint(rs.ExpiredUnavailable{}), valid: rs.ExpiredUnavailable{}.Valid()},
	} {
		if decision.valid {
			t.Fatalf("%s zero decision should be invalid", decision.name)
		}
	}
}

func TestAssignmentRunIdentityAndLocalSnapshotLimitation(t *testing.T) {
	fixture := newModelFixture(t)
	pending := mustPendingBefore(t, fixture)
	ambiguous := mustAmbiguousBefore(t, fixture)

	for _, phase := range []rs.ClaimPhase{pending, ambiguous} {
		if phase.HasAssignedRunRef() {
			t.Fatalf("%T before assignment reported run", phase)
		}
		if _, ok := phase.AssignedRunRef(); ok {
			t.Fatalf("%T before assignment exposed run", phase)
		}
		if phase.SameCallerRunRefDisclosure() != rs.RunRefDisclosureForbidden {
			t.Fatalf("%T before assignment disclosure = %v", phase, phase.SameCallerRunRefDisclosure())
		}
		if phase.AcceptedSubmissionReferenceAvailable() {
			t.Fatalf("%T before assignment reported accepted submission reference", phase)
		}
	}

	if _, err := rs.NewPendingBeforeAssignment(rs.ClaimID{}, fixture.plan); !errors.Is(err, rs.ErrInvalidPhase) {
		t.Fatalf("pending without claim error = %v", err)
	}
	if _, err := rs.NewPendingBeforeAssignment(fixture.claim, rs.BoundPlan{}); !errors.Is(err, rs.ErrInvalidPhase) {
		t.Fatalf("pending without bound plan error = %v", err)
	}
	if _, err := rs.AssignRun(pending, rs.RunRef{}); !errors.Is(err, rs.ErrInvalidPhase) {
		t.Fatalf("assignment without run error = %v", err)
	}

	runInput := []byte("assigned-run-is-copied")
	run := mustRunRef(t, runInput)
	runInput[0] = 'X'
	expectedRun := mustRunRef(t, []byte("assigned-run-is-copied"))
	assigned := mustAssigned(t, pending, run)
	gotRun, ok := assigned.AssignedRunRef()
	if !ok || !gotRun.Equal(expectedRun) {
		t.Fatalf("assigned phase did not retain immutable run reference")
	}
	if !assigned.HasAssignedRunRef() {
		t.Fatalf("assigned phase should report internal run")
	}
	if _, ok := assigned.ReceiptRef(); ok {
		t.Fatalf("effect-capable assigned phase must not expose receipt")
	}
	if assigned.AcceptedSubmissionReferenceAvailable() {
		t.Fatalf("effect-capable assignment alone must not expose accepted reference")
	}
	if assigned.SameCallerRunRefDisclosure() != rs.RunRefDisclosureOpenForLaterTransportContract {
		t.Fatalf("effect-capable assignment disclosure = %v", assigned.SameCallerRunRefDisclosure())
	}

	if err := rs.ValidateRunAssignment(assigned, expectedRun); err != nil {
		t.Fatalf("same run reassignment should be idempotent: %v", err)
	}
	if err := rs.ValidateRunAssignment(assigned, fixture.otherRun); !errors.Is(err, rs.ErrRunAssignmentMismatch) {
		t.Fatalf("different run reassignment error = %v", err)
	}

	secondAssigned := mustAssigned(t, pending, fixture.otherRun)
	secondRun, ok := secondAssigned.AssignedRunRef()
	if !ok || !secondRun.Equal(fixture.otherRun) {
		t.Fatalf("second local assignment did not use supplied run")
	}
	if gotRun.Equal(secondRun) {
		t.Fatalf("test needs two different local assignments")
	}
	t.Log("pure model intentionally validates one supplied snapshot; durable persistence/CAS must prevent two stale pre-assignment snapshots from both winning")
}

func TestPendingAmbiguousAcceptedRecoveredAndNotAcceptedPhases(t *testing.T) {
	fixture := newModelFixture(t)
	pendingBefore := mustPendingBefore(t, fixture)
	ambiguousBefore := mustAmbiguousBefore(t, fixture)
	assigned := mustAssigned(t, pendingBefore, fixture.run)
	pendingAfter := mustPendingAfter(t, assigned)
	ambiguousAfter := mustAmbiguousAfter(t, assigned)

	if pendingBefore.Kind() == pendingAfter.Kind() {
		t.Fatalf("pending before/after assignment collapsed to one kind")
	}
	if ambiguousBefore.Kind() == ambiguousAfter.Kind() {
		t.Fatalf("ambiguous before/after assignment collapsed to one kind")
	}

	for _, phase := range []rs.ClaimPhase{pendingAfter, ambiguousAfter} {
		gotRun, ok := phase.AssignedRunRef()
		if !ok || !gotRun.Equal(fixture.run) {
			t.Fatalf("%T did not retain assigned run", phase)
		}
		if _, ok := phase.ReceiptRef(); ok {
			t.Fatalf("%T should not expose accepted receipt", phase)
		}
		if phase.AcceptedSubmissionReferenceAvailable() {
			t.Fatalf("%T must not expose accepted reference before acceptance", phase)
		}
		if phase.SameCallerRunRefDisclosure() != rs.RunRefDisclosureRequiredForSameAuthorizedCaller {
			t.Fatalf("%T disclosure = %v", phase, phase.SameCallerRunRefDisclosure())
		}
	}

	if _, err := rs.NewAccepted(assigned, rs.ReceiptRef{}); !errors.Is(err, rs.ErrInvalidPhase) {
		t.Fatalf("accepted without receipt error = %v", err)
	}
	accepted := mustAccepted(t, pendingAfter, fixture.receipt)
	if accepted.Kind() != rs.KindAccepted {
		t.Fatalf("accepted kind = %v", accepted.Kind())
	}
	if !accepted.AcceptedSubmissionReferenceAvailable() {
		t.Fatalf("accepted must expose accepted submission reference")
	}
	gotRun, ok := accepted.AssignedRunRef()
	if !ok || !gotRun.Equal(fixture.run) {
		t.Fatalf("accepted did not preserve run ref")
	}
	gotReceipt, ok := accepted.ReceiptRef()
	if !ok || !gotReceipt.Equal(fixture.receipt) {
		t.Fatalf("accepted did not preserve receipt ref")
	}

	recovered, err := rs.NewRecoveredAccepted(accepted)
	if err != nil {
		t.Fatalf("NewRecoveredAccepted: %v", err)
	}
	if !recovered.AcceptedSubmissionReferenceAvailable() {
		t.Fatalf("recovered accepted must expose accepted submission reference")
	}
	recoveredRun, ok := recovered.AssignedRunRef()
	if !ok || !recoveredRun.Equal(fixture.run) {
		t.Fatalf("recovered accepted did not preserve run")
	}
	recoveredReceipt, ok := recovered.ReceiptRef()
	if !ok || !recoveredReceipt.Equal(fixture.receipt) {
		t.Fatalf("recovered accepted did not preserve receipt")
	}

	notAccepted, err := rs.NewProvablyNotAcceptedAfterAssignment(ambiguousAfter)
	if err != nil {
		t.Fatalf("NewProvablyNotAcceptedAfterAssignment: %v", err)
	}
	if notAccepted.AcceptedSubmissionReferenceAvailable() {
		t.Fatalf("provably not accepted must not expose accepted reference")
	}
	notAcceptedRun, ok := notAccepted.AssignedRunRef()
	if !ok || !notAcceptedRun.Equal(fixture.run) {
		t.Fatalf("provably not accepted did not retain internal run")
	}
	if _, ok := notAccepted.ReceiptRef(); ok {
		t.Fatalf("provably not accepted must not expose accepted receipt")
	}
	if notAccepted.SameCallerRunRefDisclosure() != rs.RunRefDisclosureOpenForLaterTransportContract {
		t.Fatalf("provably not accepted disclosure = %v", notAccepted.SameCallerRunRefDisclosure())
	}
}

func TestExactReplayConflictUnauthorizedAndExpiredDecisions(t *testing.T) {
	fixture := newModelFixture(t)
	pending := mustPendingBefore(t, fixture)
	assigned := mustAssigned(t, pending, fixture.run)
	accepted := mustAccepted(t, assigned, fixture.receipt)

	pendingReplay, err := rs.NewExactReplay(pending)
	if err != nil {
		t.Fatalf("NewExactReplay(pending): %v", err)
	}
	if pendingReplay.UnderlyingKind() != rs.KindPendingBeforeAssignment {
		t.Fatalf("pending replay underlying kind = %v", pendingReplay.UnderlyingKind())
	}
	if pendingReplay.HasAssignedRunRef() || pendingReplay.AcceptedSubmissionReferenceAvailable() {
		t.Fatalf("pending replay must preserve no-run/no-accepted-reference phase")
	}

	acceptedReplay, err := rs.NewExactReplay(accepted)
	if err != nil {
		t.Fatalf("NewExactReplay(accepted): %v", err)
	}
	if acceptedReplay.UnderlyingKind() != rs.KindAccepted {
		t.Fatalf("accepted replay underlying kind = %v", acceptedReplay.UnderlyingKind())
	}
	if !acceptedReplay.AcceptedSubmissionReferenceAvailable() {
		t.Fatalf("accepted replay must follow accepted reference availability")
	}
	replayRun, ok := acceptedReplay.AssignedRunRef()
	if !ok || !replayRun.Equal(fixture.run) {
		t.Fatalf("accepted replay did not preserve run")
	}
	replayReceipt, ok := acceptedReplay.ReceiptRef()
	if !ok || !replayReceipt.Equal(fixture.receipt) {
		t.Fatalf("accepted replay did not preserve receipt")
	}

	if err := rs.ValidatePlanBinding(accepted, fixture.binding); err != nil {
		t.Fatalf("same plan binding should validate: %v", err)
	}
	if err := rs.ValidatePlanBinding(accepted, fixture.otherBind); !errors.Is(err, rs.ErrPlanBindingConflict) {
		t.Fatalf("plan binding mismatch error = %v", err)
	}

	conflict, err := rs.NewConflict()
	if err != nil {
		t.Fatalf("NewConflict: %v", err)
	}
	unauthorized, err := rs.NewUnauthorized()
	if err != nil {
		t.Fatalf("NewUnauthorized: %v", err)
	}
	expired, err := rs.NewExpiredUnavailable()
	if err != nil {
		t.Fatalf("NewExpiredUnavailable: %v", err)
	}
	for _, decision := range []struct {
		name      string
		claim     func() (rs.ClaimID, bool)
		run       func() (rs.RunRef, bool)
		receipt   func() (rs.ReceiptRef, bool)
		hasRun    func() bool
		available func() bool
		policy    func() rs.RunRefDisclosurePolicy
	}{
		{
			name:      "conflict",
			claim:     conflict.ClaimID,
			run:       conflict.AssignedRunRef,
			receipt:   conflict.ReceiptRef,
			hasRun:    conflict.HasAssignedRunRef,
			available: conflict.AcceptedSubmissionReferenceAvailable,
			policy:    conflict.SameCallerRunRefDisclosure,
		},
		{
			name:      "unauthorized",
			claim:     unauthorized.ClaimID,
			run:       unauthorized.AssignedRunRef,
			receipt:   unauthorized.ReceiptRef,
			hasRun:    unauthorized.HasAssignedRunRef,
			available: unauthorized.AcceptedSubmissionReferenceAvailable,
			policy:    unauthorized.SameCallerRunRefDisclosure,
		},
		{
			name:      "expired unavailable",
			claim:     expired.ClaimID,
			run:       expired.AssignedRunRef,
			receipt:   expired.ReceiptRef,
			hasRun:    expired.HasAssignedRunRef,
			available: expired.AcceptedSubmissionReferenceAvailable,
			policy:    expired.SameCallerRunRefDisclosure,
		},
	} {
		if _, ok := decision.claim(); ok {
			t.Fatalf("%s exposed existing claim identity", decision.name)
		}
		if decision.hasRun() {
			t.Fatalf("%s reported run presence", decision.name)
		}
		if _, ok := decision.run(); ok {
			t.Fatalf("%s exposed run", decision.name)
		}
		if _, ok := decision.receipt(); ok {
			t.Fatalf("%s exposed receipt", decision.name)
		}
		if decision.available() {
			t.Fatalf("%s exposed accepted submission reference", decision.name)
		}
		if decision.policy() != rs.RunRefDisclosureForbidden {
			t.Fatalf("%s disclosure = %v", decision.name, decision.policy())
		}
	}
}

func TestOnlyAcceptedRecoveredAndAcceptedReplayExposeAcceptedSubmissionReference(t *testing.T) {
	fixture := newModelFixture(t)
	pendingBefore := mustPendingBefore(t, fixture)
	ambiguousBefore := mustAmbiguousBefore(t, fixture)
	assigned := mustAssigned(t, pendingBefore, fixture.run)
	pendingAfter := mustPendingAfter(t, assigned)
	ambiguousAfter := mustAmbiguousAfter(t, assigned)
	accepted := mustAccepted(t, assigned, fixture.receipt)
	recovered, err := rs.NewRecoveredAccepted(accepted)
	if err != nil {
		t.Fatalf("NewRecoveredAccepted: %v", err)
	}
	notAccepted, err := rs.NewProvablyNotAcceptedAfterAssignment(assigned)
	if err != nil {
		t.Fatalf("NewProvablyNotAcceptedAfterAssignment: %v", err)
	}
	pendingReplay, err := rs.NewExactReplay(pendingBefore)
	if err != nil {
		t.Fatalf("NewExactReplay(pending): %v", err)
	}
	acceptedReplay, err := rs.NewExactReplay(accepted)
	if err != nil {
		t.Fatalf("NewExactReplay(accepted): %v", err)
	}

	for _, phase := range []rs.ClaimPhase{
		pendingBefore,
		ambiguousBefore,
		assigned,
		pendingAfter,
		ambiguousAfter,
		notAccepted,
	} {
		if phase.AcceptedSubmissionReferenceAvailable() {
			t.Fatalf("%T must not expose accepted submission reference", phase)
		}
	}
	if !accepted.AcceptedSubmissionReferenceAvailable() {
		t.Fatalf("accepted must expose accepted submission reference")
	}
	if !recovered.AcceptedSubmissionReferenceAvailable() {
		t.Fatalf("recovered accepted must expose accepted submission reference")
	}
	if pendingReplay.AcceptedSubmissionReferenceAvailable() {
		t.Fatalf("pending replay must not expose accepted submission reference")
	}
	if !acceptedReplay.AcceptedSubmissionReferenceAvailable() {
		t.Fatalf("accepted replay must follow underlying accepted reference")
	}
}
