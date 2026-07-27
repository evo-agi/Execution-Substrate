package admission

import (
	"errors"
	"os"
	"strings"
	"testing"

	"execution-substrate/es/admission/internal/reliablesubmit"
)

func TestReliableSubmitOutcomeRunDisclosureAndReceiptRules(t *testing.T) {
	run := reliableSubmitTestRunRef(t)
	receipt := reliableSubmitTestReceiptRef(t)

	for _, tc := range []struct {
		kind                 reliableSubmitOutcomeKind
		run                  reliablesubmit.RunRef
		receipt              reliablesubmit.ReceiptRef
		disclosure           reliableSubmitRunRefDisclosure
		hasRun               bool
		hasReceipt           bool
		acceptedRefAvailable bool
	}{
		{kind: reliableSubmitOutcomeAccepted, run: run, receipt: receipt, disclosure: reliableSubmitRunRefDisclosureRequiredForSameAuthorizedCaller, hasRun: true, hasReceipt: true, acceptedRefAvailable: true},
		{kind: reliableSubmitOutcomeAcceptedExactReplay, run: run, receipt: receipt, disclosure: reliableSubmitRunRefDisclosureRequiredForSameAuthorizedCaller, hasRun: true, hasReceipt: true, acceptedRefAvailable: true},
		{kind: reliableSubmitOutcomePendingBeforeAssignment, disclosure: reliableSubmitRunRefDisclosureForbidden},
		{kind: reliableSubmitOutcomePendingAfterAssignment, run: run, disclosure: reliableSubmitRunRefDisclosureRequiredForSameAuthorizedCaller, hasRun: true},
		{kind: reliableSubmitOutcomeAmbiguousBeforeAssignment, disclosure: reliableSubmitRunRefDisclosureForbidden},
		{kind: reliableSubmitOutcomeAmbiguousAfterAssignment, run: run, disclosure: reliableSubmitRunRefDisclosureRequiredForSameAuthorizedCaller, hasRun: true},
		{kind: reliableSubmitOutcomeProvablyNotAccepted, run: run, disclosure: reliableSubmitRunRefDisclosureOpenForLaterTransportContract, hasRun: true},
		{kind: reliableSubmitOutcomeConflictingReuse, disclosure: reliableSubmitRunRefDisclosureForbidden},
		{kind: reliableSubmitOutcomeExpiredUnavailableCorrelation, disclosure: reliableSubmitRunRefDisclosureForbidden},
		{kind: reliableSubmitOutcomeTemporaryStoreUnavailable, disclosure: reliableSubmitRunRefDisclosureForbidden},
		{kind: reliableSubmitOutcomeCorruptUnsupportedStore, disclosure: reliableSubmitRunRefDisclosureForbidden},
		{kind: reliableSubmitOutcomeUnauthorized, disclosure: reliableSubmitRunRefDisclosureForbidden},
	} {
		t.Run(string(tc.kind), func(t *testing.T) {
			outcome, err := newReliableSubmitOutcome(tc.kind, tc.run, tc.receipt)
			if err != nil {
				t.Fatalf("construct outcome: %v", err)
			}
			if outcome.kindValue() != tc.kind {
				t.Fatalf("kind = %q, want %q", outcome.kindValue(), tc.kind)
			}
			if outcome.runRefDisclosureValue() != tc.disclosure {
				t.Fatalf("disclosure = %q, want %q", outcome.runRefDisclosureValue(), tc.disclosure)
			}
			if _, ok := outcome.runRefValue(); ok != tc.hasRun {
				t.Fatalf("run presence = %v, want %v", ok, tc.hasRun)
			}
			if _, ok := outcome.receiptRefValue(); ok != tc.hasReceipt {
				t.Fatalf("receipt presence = %v, want %v", ok, tc.hasReceipt)
			}
			if outcome.acceptedSubmissionReferenceAvailableValue() != tc.acceptedRefAvailable {
				t.Fatalf("accepted reference availability = %v, want %v", outcome.acceptedSubmissionReferenceAvailableValue(), tc.acceptedRefAvailable)
			}
		})
	}
}

func TestReliableSubmitOutcomeProvablyNotAcceptedPreservesOpenDisclosure(t *testing.T) {
	run := reliableSubmitTestRunRef(t)

	outcome, err := newReliableSubmitOutcome(reliableSubmitOutcomeProvablyNotAccepted, run, reliablesubmit.ReceiptRef{})
	if err != nil {
		t.Fatalf("construct provably-not-accepted outcome: %v", err)
	}
	if outcome.runRefDisclosureValue() != reliableSubmitRunRefDisclosureOpenForLaterTransportContract {
		t.Fatalf("provably-not-accepted disclosure = %q, want open", outcome.runRefDisclosureValue())
	}
	if _, ok := outcome.runRefValue(); !ok {
		t.Fatalf("provably-not-accepted must retain internal run ref")
	}
	if _, ok := outcome.receiptRefValue(); ok {
		t.Fatalf("provably-not-accepted must not retain receipt ref")
	}
	if outcome.acceptedSubmissionReferenceAvailableValue() {
		t.Fatalf("provably-not-accepted must not expose accepted reference availability")
	}

	replay, err := newReliableSubmitExactReplayOutcome(outcome)
	if err != nil {
		t.Fatalf("exact replay: %v", err)
	}
	if replay.runRefDisclosureValue() != reliableSubmitRunRefDisclosureOpenForLaterTransportContract {
		t.Fatalf("exact replay disclosure = %q, want underlying open policy", replay.runRefDisclosureValue())
	}
	if replay.acceptedSubmissionReferenceAvailableValue() {
		t.Fatalf("exact replay of provably-not-accepted must not become accepted")
	}
}

func TestReliableSubmitOutcomeRejectsInvalidRunReceiptCombinations(t *testing.T) {
	run := reliableSubmitTestRunRef(t)
	receipt := reliableSubmitTestReceiptRef(t)

	for _, tc := range []struct {
		name    string
		kind    reliableSubmitOutcomeKind
		run     reliablesubmit.RunRef
		receipt reliablesubmit.ReceiptRef
	}{
		{name: "accepted missing receipt", kind: reliableSubmitOutcomeAccepted, run: run},
		{name: "accepted missing run", kind: reliableSubmitOutcomeAccepted, receipt: receipt},
		{name: "pending before with run", kind: reliableSubmitOutcomePendingBeforeAssignment, run: run},
		{name: "pending after without run", kind: reliableSubmitOutcomePendingAfterAssignment},
		{name: "ambiguous before with receipt", kind: reliableSubmitOutcomeAmbiguousBeforeAssignment, receipt: receipt},
		{name: "conflict with run", kind: reliableSubmitOutcomeConflictingReuse, run: run},
		{name: "unauthorized with receipt", kind: reliableSubmitOutcomeUnauthorized, receipt: receipt},
		{name: "unknown kind", kind: reliableSubmitOutcomeKind("unknown")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := newReliableSubmitOutcome(tc.kind, tc.run, tc.receipt); !errors.Is(err, errReliableSubmitInvalidOutcome) {
				t.Fatalf("expected invalid outcome, got %v", err)
			}
		})
	}
}

func TestReliableSubmitOutcomeRetryAndNewKeyRules(t *testing.T) {
	run := reliableSubmitTestRunRef(t)
	receipt := reliableSubmitTestReceiptRef(t)

	for _, tc := range []struct {
		kind      reliableSubmitOutcomeKind
		run       reliablesubmit.RunRef
		receipt   reliablesubmit.ReceiptRef
		retrySafe bool
		newKey    bool
	}{
		{kind: reliableSubmitOutcomeAccepted, run: run, receipt: receipt, retrySafe: true},
		{kind: reliableSubmitOutcomeAcceptedExactReplay, run: run, receipt: receipt, retrySafe: true},
		{kind: reliableSubmitOutcomePendingBeforeAssignment, retrySafe: true},
		{kind: reliableSubmitOutcomePendingAfterAssignment, run: run, retrySafe: true},
		{kind: reliableSubmitOutcomeAmbiguousBeforeAssignment, retrySafe: true},
		{kind: reliableSubmitOutcomeAmbiguousAfterAssignment, run: run, retrySafe: true},
		{kind: reliableSubmitOutcomeProvablyNotAccepted, run: run, retrySafe: true, newKey: true},
		{kind: reliableSubmitOutcomeConflictingReuse, newKey: true},
		{kind: reliableSubmitOutcomeExpiredUnavailableCorrelation, newKey: true},
		{kind: reliableSubmitOutcomeTemporaryStoreUnavailable, retrySafe: true},
		{kind: reliableSubmitOutcomeCorruptUnsupportedStore},
		{kind: reliableSubmitOutcomeUnauthorized},
	} {
		t.Run(string(tc.kind), func(t *testing.T) {
			outcome, err := newReliableSubmitOutcome(tc.kind, tc.run, tc.receipt)
			if err != nil {
				t.Fatalf("construct outcome: %v", err)
			}
			if outcome.exactRetryOfSameRequestSafeValue() != tc.retrySafe {
				t.Fatalf("retry safe = %v, want %v", outcome.exactRetryOfSameRequestSafeValue(), tc.retrySafe)
			}
			if outcome.newKeyRequiredValue() != tc.newKey {
				t.Fatalf("new key required = %v, want %v", outcome.newKeyRequiredValue(), tc.newKey)
			}
		})
	}
}

func TestReliableSubmitOutcomeSourceAvoidsTransportAndConsumerVocabulary(t *testing.T) {
	data, err := os.ReadFile("reliable_submit_outcome.go")
	if err != nil {
		t.Fatalf("read outcome source: %v", err)
	}
	source := string(data)
	for _, forbidden := range []string{
		"HTTP",
		"http",
		"StatusCode",
		"Coordinator",
		"ControlPlane",
		"CP",
		"progression",
		"provider_id",
		"nomad_job_id",
		"allocation_id",
		"EvalID",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("outcome source must avoid %q", forbidden)
		}
	}
}

func reliableSubmitTestRunRef(t *testing.T) reliablesubmit.RunRef {
	t.Helper()
	ref, err := reliablesubmit.NewRunRef([]byte("run-ref"))
	if err != nil {
		t.Fatalf("run ref: %v", err)
	}
	return ref
}

func reliableSubmitTestReceiptRef(t *testing.T) reliablesubmit.ReceiptRef {
	t.Helper()
	ref, err := reliablesubmit.NewReceiptRef([]byte("receipt-ref"))
	if err != nil {
		t.Fatalf("receipt ref: %v", err)
	}
	return ref
}
