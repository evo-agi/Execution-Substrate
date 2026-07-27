package admission

import (
	"errors"

	"execution-substrate/es/admission/internal/reliablesubmit"
)

type reliableSubmitOutcomeKind string

const (
	reliableSubmitOutcomeAccepted                      reliableSubmitOutcomeKind = "accepted"
	reliableSubmitOutcomeAcceptedExactReplay           reliableSubmitOutcomeKind = "accepted_exact_replay"
	reliableSubmitOutcomePendingBeforeAssignment       reliableSubmitOutcomeKind = "pending_before_assignment"
	reliableSubmitOutcomePendingAfterAssignment        reliableSubmitOutcomeKind = "pending_after_assignment"
	reliableSubmitOutcomeAmbiguousBeforeAssignment     reliableSubmitOutcomeKind = "ambiguous_before_assignment"
	reliableSubmitOutcomeAmbiguousAfterAssignment      reliableSubmitOutcomeKind = "ambiguous_after_assignment"
	reliableSubmitOutcomeConflictingReuse              reliableSubmitOutcomeKind = "conflicting_reuse"
	reliableSubmitOutcomeProvablyNotAccepted           reliableSubmitOutcomeKind = "provably_not_accepted"
	reliableSubmitOutcomeExpiredUnavailableCorrelation reliableSubmitOutcomeKind = "expired_unavailable_correlation"
	reliableSubmitOutcomeTemporaryStoreUnavailable     reliableSubmitOutcomeKind = "temporary_store_unavailable"
	reliableSubmitOutcomeCorruptUnsupportedStore       reliableSubmitOutcomeKind = "corrupt_unsupported_store"
	reliableSubmitOutcomeUnauthorized                  reliableSubmitOutcomeKind = "unauthorized"
)

type reliableSubmitRunRefDisclosure string

const (
	reliableSubmitRunRefDisclosureForbidden                       reliableSubmitRunRefDisclosure = "forbidden"
	reliableSubmitRunRefDisclosureRequiredForSameAuthorizedCaller reliableSubmitRunRefDisclosure = "required_for_same_authorized_caller"
	reliableSubmitRunRefDisclosureOpenForLaterTransportContract   reliableSubmitRunRefDisclosure = "open_for_later_transport_contract"
)

var errReliableSubmitInvalidOutcome = errors.New("reliable submit outcome: invalid outcome")

type reliableSubmitOutcome struct {
	kind                                 reliableSubmitOutcomeKind
	runRefDisclosure                     reliableSubmitRunRefDisclosure
	runRef                               reliablesubmit.RunRef
	receiptRef                           reliablesubmit.ReceiptRef
	exactRetryOfSameRequestSafe          bool
	newKeyRequired                       bool
	acceptedSubmissionReferenceAvailable bool
}

func newReliableSubmitOutcome(kind reliableSubmitOutcomeKind, runRef reliablesubmit.RunRef, receiptRef reliablesubmit.ReceiptRef) (reliableSubmitOutcome, error) {
	outcome := reliableSubmitOutcome{kind: kind}
	switch kind {
	case reliableSubmitOutcomeAccepted, reliableSubmitOutcomeAcceptedExactReplay:
		if !runRef.Valid() || !receiptRef.Valid() {
			return reliableSubmitOutcome{}, errReliableSubmitInvalidOutcome
		}
		disclosure, err := reliableSubmitDisclosureFromPureModelPolicy(reliablesubmit.RunRefDisclosureRequiredForSameAuthorizedCaller)
		if err != nil {
			return reliableSubmitOutcome{}, err
		}
		outcome.runRefDisclosure = disclosure
		outcome.runRef = runRef
		outcome.receiptRef = receiptRef
		outcome.exactRetryOfSameRequestSafe = true
		outcome.acceptedSubmissionReferenceAvailable = true
	case reliableSubmitOutcomePendingBeforeAssignment, reliableSubmitOutcomeAmbiguousBeforeAssignment:
		if runRef.Valid() || receiptRef.Valid() {
			return reliableSubmitOutcome{}, errReliableSubmitInvalidOutcome
		}
		disclosure, err := reliableSubmitDisclosureFromPureModelPolicy(reliablesubmit.RunRefDisclosureForbidden)
		if err != nil {
			return reliableSubmitOutcome{}, err
		}
		outcome.runRefDisclosure = disclosure
		outcome.exactRetryOfSameRequestSafe = true
	case reliableSubmitOutcomePendingAfterAssignment, reliableSubmitOutcomeAmbiguousAfterAssignment:
		if !runRef.Valid() || receiptRef.Valid() {
			return reliableSubmitOutcome{}, errReliableSubmitInvalidOutcome
		}
		disclosure, err := reliableSubmitDisclosureFromPureModelPolicy(reliablesubmit.RunRefDisclosureRequiredForSameAuthorizedCaller)
		if err != nil {
			return reliableSubmitOutcome{}, err
		}
		outcome.runRefDisclosure = disclosure
		outcome.runRef = runRef
		outcome.exactRetryOfSameRequestSafe = true
	case reliableSubmitOutcomeProvablyNotAccepted:
		if !runRef.Valid() || receiptRef.Valid() {
			return reliableSubmitOutcome{}, errReliableSubmitInvalidOutcome
		}
		disclosure, err := reliableSubmitDisclosureFromPureModelPolicy(reliablesubmit.RunRefDisclosureOpenForLaterTransportContract)
		if err != nil {
			return reliableSubmitOutcome{}, err
		}
		outcome.runRefDisclosure = disclosure
		outcome.runRef = runRef
		outcome.exactRetryOfSameRequestSafe = true
		outcome.newKeyRequired = true
	case reliableSubmitOutcomeConflictingReuse:
		if runRef.Valid() || receiptRef.Valid() {
			return reliableSubmitOutcome{}, errReliableSubmitInvalidOutcome
		}
		disclosure, err := reliableSubmitDisclosureFromPureModelPolicy(reliablesubmit.RunRefDisclosureForbidden)
		if err != nil {
			return reliableSubmitOutcome{}, err
		}
		outcome.runRefDisclosure = disclosure
		outcome.newKeyRequired = true
	case reliableSubmitOutcomeExpiredUnavailableCorrelation:
		if runRef.Valid() || receiptRef.Valid() {
			return reliableSubmitOutcome{}, errReliableSubmitInvalidOutcome
		}
		disclosure, err := reliableSubmitDisclosureFromPureModelPolicy(reliablesubmit.RunRefDisclosureForbidden)
		if err != nil {
			return reliableSubmitOutcome{}, err
		}
		outcome.runRefDisclosure = disclosure
		outcome.newKeyRequired = true
	case reliableSubmitOutcomeTemporaryStoreUnavailable:
		if runRef.Valid() || receiptRef.Valid() {
			return reliableSubmitOutcome{}, errReliableSubmitInvalidOutcome
		}
		disclosure, err := reliableSubmitDisclosureFromPureModelPolicy(reliablesubmit.RunRefDisclosureForbidden)
		if err != nil {
			return reliableSubmitOutcome{}, err
		}
		outcome.runRefDisclosure = disclosure
		outcome.exactRetryOfSameRequestSafe = true
	case reliableSubmitOutcomeCorruptUnsupportedStore, reliableSubmitOutcomeUnauthorized:
		if runRef.Valid() || receiptRef.Valid() {
			return reliableSubmitOutcome{}, errReliableSubmitInvalidOutcome
		}
		disclosure, err := reliableSubmitDisclosureFromPureModelPolicy(reliablesubmit.RunRefDisclosureForbidden)
		if err != nil {
			return reliableSubmitOutcome{}, err
		}
		outcome.runRefDisclosure = disclosure
	default:
		return reliableSubmitOutcome{}, errReliableSubmitInvalidOutcome
	}
	return outcome, nil
}

func newReliableSubmitExactReplayOutcome(underlying reliableSubmitOutcome) (reliableSubmitOutcome, error) {
	if underlying.kind == reliableSubmitOutcomeAccepted {
		return newReliableSubmitOutcome(reliableSubmitOutcomeAcceptedExactReplay, underlying.runRef, underlying.receiptRef)
	}
	if underlying.kind == "" || !underlying.exactRetryOfSameRequestSafe {
		return reliableSubmitOutcome{}, errReliableSubmitInvalidOutcome
	}
	return underlying, nil
}

func reliableSubmitDisclosureFromPureModelPolicy(policy reliablesubmit.RunRefDisclosurePolicy) (reliableSubmitRunRefDisclosure, error) {
	switch policy {
	case reliablesubmit.RunRefDisclosureForbidden:
		return reliableSubmitRunRefDisclosureForbidden, nil
	case reliablesubmit.RunRefDisclosureRequiredForSameAuthorizedCaller:
		return reliableSubmitRunRefDisclosureRequiredForSameAuthorizedCaller, nil
	case reliablesubmit.RunRefDisclosureOpenForLaterTransportContract:
		return reliableSubmitRunRefDisclosureOpenForLaterTransportContract, nil
	default:
		return "", errReliableSubmitInvalidOutcome
	}
}

func (o reliableSubmitOutcome) kindValue() reliableSubmitOutcomeKind {
	return o.kind
}

func (o reliableSubmitOutcome) runRefDisclosureValue() reliableSubmitRunRefDisclosure {
	return o.runRefDisclosure
}

func (o reliableSubmitOutcome) runRefValue() (reliablesubmit.RunRef, bool) {
	return o.runRef, o.runRef.Valid()
}

func (o reliableSubmitOutcome) receiptRefValue() (reliablesubmit.ReceiptRef, bool) {
	return o.receiptRef, o.receiptRef.Valid()
}

func (o reliableSubmitOutcome) exactRetryOfSameRequestSafeValue() bool {
	return o.exactRetryOfSameRequestSafe
}

func (o reliableSubmitOutcome) newKeyRequiredValue() bool {
	return o.newKeyRequired
}

func (o reliableSubmitOutcome) acceptedSubmissionReferenceAvailableValue() bool {
	return o.acceptedSubmissionReferenceAvailable
}
