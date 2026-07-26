package reliablesubmit

import (
	"context"
	"errors"
)

type claimRevision int64

const initialClaimRevision claimRevision = 1

type claimStore interface {
	establishClaim(context.Context, establishClaimCommand) (establishClaimStoreResult, error)
	loadClaim(context.Context, loadClaimQuery) (durableClaimRecord, error)
	compareAndSwapClaim(context.Context, compareAndSwapClaimCommand) (compareAndSwapClaimStoreResult, error)
}

type establishClaimCommand struct {
	record durableClaimRecord
}

type establishClaimStoreResult struct {
	record  durableClaimRecord
	created bool
}

type loadClaimQuery struct {
	claim ClaimID
}

type compareAndSwapClaimCommand struct {
	claim            ClaimID
	expectedRevision claimRevision
	next             durableClaimRecord
}

type compareAndSwapClaimStoreResult struct {
	record  durableClaimRecord
	applied bool
	found   bool
}

type claimStoreErrorKind uint8

const (
	claimStoreErrorNotFound claimStoreErrorKind = iota + 1
	claimStoreErrorStaleRevision
	claimStoreErrorBusy
	claimStoreErrorUnavailable
	claimStoreErrorUnsupported
	claimStoreErrorCorrupt
	claimStoreErrorCommitUnknown
	claimStoreErrorInternal
)

var (
	errClaimStoreNotFound      = claimStoreError{kind: claimStoreErrorNotFound}
	errClaimStoreStaleRevision = claimStoreError{kind: claimStoreErrorStaleRevision}
	errClaimStoreBusy          = claimStoreError{kind: claimStoreErrorBusy}
	errClaimStoreUnavailable   = claimStoreError{kind: claimStoreErrorUnavailable}
	errClaimStoreUnsupported   = claimStoreError{kind: claimStoreErrorUnsupported}
	errClaimStoreCorrupt       = claimStoreError{kind: claimStoreErrorCorrupt}
	errClaimStoreCommitUnknown = claimStoreError{kind: claimStoreErrorCommitUnknown}
	errClaimStoreInternal      = claimStoreError{kind: claimStoreErrorInternal}
)

type claimStoreError struct {
	kind claimStoreErrorKind
}

func (e claimStoreError) Error() string {
	switch e.kind {
	case claimStoreErrorNotFound:
		return "reliable submit store: claim not found"
	case claimStoreErrorStaleRevision:
		return "reliable submit store: stale revision"
	case claimStoreErrorBusy:
		return "reliable submit store: busy"
	case claimStoreErrorUnavailable:
		return "reliable submit store: temporarily unavailable"
	case claimStoreErrorUnsupported:
		return "reliable submit store: unsupported format"
	case claimStoreErrorCorrupt:
		return "reliable submit store: corrupt or invariant-invalid state"
	case claimStoreErrorCommitUnknown:
		return "reliable submit store: commit outcome unknown"
	default:
		return "reliable submit store: internal persistence failure"
	}
}

func (e claimStoreError) Is(target error) bool {
	var other claimStoreError
	if !errors.As(target, &other) {
		return false
	}
	return e.kind == other.kind
}

func isClaimStoreError(err error, kind claimStoreErrorKind) bool {
	var storeErr claimStoreError
	return errors.As(err, &storeErr) && storeErr.kind == kind
}
