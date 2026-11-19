package reliablesubmit

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

const durableOperationInputBindingLength = sha256.Size
const durableOperationInputBindingDomain = "es/reliable-submit/durable-operation-input/v1"

var (
	errInvalidDurableOperationKind         = errors.New("reliable submit durable operation: invalid kind")
	errInvalidDurableOperationInputBinding = errors.New("reliable submit durable operation: invalid input binding")
	errInvalidDurableLatestOperation       = errors.New("reliable submit durable operation: invalid latest descriptor")
)

type durableOperationKind uint8

const (
	durableOperationInvalid durableOperationKind = iota
	durableOperationEstablishClaim
	durableOperationAssignRun
	durableOperationRecordProviderEffectIntent
	durableOperationRecordStagingEvidence
	durableOperationRecordProviderDispatchAttempt
	durableOperationRecordProviderCallObservation
	durableOperationRecordReconciliationEvidence
	durableOperationAcceptWithReceipt
	durableOperationRecordProvablyNotAccepted
	durableOperationTombstoneOrExpire
)

func (k durableOperationKind) valid() bool {
	return k >= durableOperationEstablishClaim && k <= durableOperationTombstoneOrExpire
}

type durableOperationInputBinding struct {
	value [durableOperationInputBindingLength]byte
	valid bool
}

func newDurableOperationInputBinding(value []byte) (durableOperationInputBinding, error) {
	if len(value) != durableOperationInputBindingLength {
		return durableOperationInputBinding{}, errInvalidDurableOperationInputBinding
	}
	var binding durableOperationInputBinding
	copy(binding.value[:], value)
	binding.valid = true
	return binding, nil
}

func (b durableOperationInputBinding) equal(other durableOperationInputBinding) bool {
	return b.valid == other.valid && b.value == other.value
}

func (b durableOperationInputBinding) clone() durableOperationInputBinding {
	return b
}

func (b durableOperationInputBinding) bytes() []byte {
	if !b.valid {
		return nil
	}
	out := make([]byte, len(b.value))
	copy(out, b.value[:])
	return out
}

func (b durableOperationInputBinding) Format(state fmt.State, verb rune) {
	formatDurableOpaque(state, "durableOperationInputBinding", b.valid)
}

type durableLatestOperationDescriptor struct {
	mutation durableMutationRef
	kind     durableOperationKind
	binding  durableOperationInputBinding
}

func newCompleteDurableLatestOperationDescriptor(mutation durableMutationRef, kind durableOperationKind, binding durableOperationInputBinding) (durableLatestOperationDescriptor, error) {
	descriptor := durableLatestOperationDescriptor{
		mutation: mutation.clone(),
		kind:     kind,
		binding:  binding.clone(),
	}
	if !descriptor.complete() {
		return durableLatestOperationDescriptor{}, errInvalidDurableLatestOperation
	}
	return descriptor, nil
}

func newLegacyDurableLatestOperationDescriptor(mutation durableMutationRef) (durableLatestOperationDescriptor, error) {
	descriptor := durableLatestOperationDescriptor{mutation: mutation.clone()}
	if !descriptor.legacyUnbound() {
		return durableLatestOperationDescriptor{}, errInvalidDurableLatestOperation
	}
	return descriptor, nil
}

func (d durableLatestOperationDescriptor) complete() bool {
	return d.mutation.valid() && d.kind.valid() && d.binding.valid
}

func (d durableLatestOperationDescriptor) legacyUnbound() bool {
	return d.mutation.valid() && d.kind == durableOperationInvalid && !d.binding.valid
}

func (d durableLatestOperationDescriptor) validForCodec(codecVersion uint16, lastMutation durableMutationRef) bool {
	if !d.mutation.valid() || !lastMutation.valid() || !d.mutation.equal(lastMutation) {
		return false
	}
	switch codecVersion {
	case durableClaimCodecVersionLegacy:
		return d.legacyUnbound()
	case durableClaimCodecVersion:
		return d.complete()
	case durableClaimCodecVersionSynthetic:
		return d.complete() && d.kind == durableOperationEstablishClaim
	case durableClaimCodecVersionProgress:
		return d.complete() && d.kind >= durableOperationEstablishClaim && d.kind < durableOperationTombstoneOrExpire
	default:
		return false
	}
}

func (d durableLatestOperationDescriptor) equal(other durableLatestOperationDescriptor) bool {
	return d.mutation.equal(other.mutation) &&
		d.kind == other.kind &&
		d.binding.equal(other.binding)
}

func (d durableLatestOperationDescriptor) clone() durableLatestOperationDescriptor {
	return durableLatestOperationDescriptor{
		mutation: d.mutation.clone(),
		kind:     d.kind,
		binding:  d.binding.clone(),
	}
}

func (d durableLatestOperationDescriptor) Format(state fmt.State, verb rune) {
	formatDurableOpaque(state, "durableLatestOperationDescriptor", d.complete() || d.legacyUnbound())
}

type durableOperationReplayMatch uint8

const (
	durableOperationReplayDifferentMutation durableOperationReplayMatch = iota
	durableOperationReplayExact
	durableOperationReplayConflict
	durableOperationReplayUnavailable
)

func compareDurableLatestOperation(stored durableLatestOperationDescriptor, incoming durableLatestOperationDescriptor) durableOperationReplayMatch {
	if !stored.mutation.equal(incoming.mutation) {
		return durableOperationReplayDifferentMutation
	}
	if stored.complete() && incoming.complete() {
		if stored.kind == incoming.kind && stored.binding.equal(incoming.binding) {
			return durableOperationReplayExact
		}
		return durableOperationReplayConflict
	}
	if stored.legacyUnbound() {
		return durableOperationReplayUnavailable
	}
	return durableOperationReplayConflict
}

type durableOperationInputPart struct {
	tag   uint16
	value []byte
}

const (
	durableOperationPartInitialPhase uint16 = iota + 1
	durableOperationPartExpiresAt
	durableOperationPartRunRef
	durableOperationPartFactRef
	durableOperationPartObservationKind
	durableOperationPartReconciliationKind
	durableOperationPartReceiptRef
	durableOperationPartRetentionState
	durableOperationPartRetentionReason
	durableOperationPartSyntheticDescriptor
)

func deriveDurableOperationDescriptor(mutation durableMutationRef, kind durableOperationKind, predecessor claimRevision, parts ...durableOperationInputPart) (durableLatestOperationDescriptor, error) {
	if !mutation.valid() {
		return durableLatestOperationDescriptor{}, errInvalidMutationRef
	}
	if !kind.valid() {
		return durableLatestOperationDescriptor{}, errInvalidDurableOperationKind
	}
	if kind == durableOperationEstablishClaim {
		if predecessor != 0 {
			return durableLatestOperationDescriptor{}, errInvalidDurableOperationInputBinding
		}
	} else if predecessor < initialClaimRevision {
		return durableLatestOperationDescriptor{}, errInvalidDurableOperationInputBinding
	}
	binding := digestDurableOperationInput(kind, predecessor, parts...)
	return newCompleteDurableLatestOperationDescriptor(mutation, kind, binding)
}

func digestDurableOperationInput(kind durableOperationKind, predecessor claimRevision, parts ...durableOperationInputPart) durableOperationInputBinding {
	encoder := durableOperationInputEncoder{}
	encoder.u16(uint16(kind))
	encoder.i64(int64(predecessor))
	for _, part := range parts {
		encoder.u16(part.tag)
		encoder.bytes(part.value)
	}
	preimage := make([]byte, 0, len(durableOperationInputBindingDomain)+1+len(encoder.buf))
	preimage = append(preimage, durableOperationInputBindingDomain...)
	preimage = append(preimage, 0)
	preimage = append(preimage, encoder.buf...)
	sum := sha256.Sum256(preimage)
	return durableOperationInputBinding{value: sum, valid: true}
}

type durableOperationInputEncoder struct {
	buf []byte
}

func (e *durableOperationInputEncoder) u16(value uint16) {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], value)
	e.buf = append(e.buf, encoded[:]...)
}

func (e *durableOperationInputEncoder) i64(value int64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(value))
	e.buf = append(e.buf, encoded[:]...)
}

func (e *durableOperationInputEncoder) bytes(value []byte) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	e.buf = append(e.buf, length[:]...)
	e.buf = append(e.buf, value...)
}

func operationPartBytes(tag uint16, value []byte) durableOperationInputPart {
	copied := make([]byte, len(value))
	copy(copied, value)
	return durableOperationInputPart{tag: tag, value: copied}
}

func operationPartUint16(tag uint16, value uint16) durableOperationInputPart {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], value)
	return operationPartBytes(tag, encoded[:])
}

func operationPartInt64(tag uint16, value int64) durableOperationInputPart {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(value))
	return operationPartBytes(tag, encoded[:])
}

func operationPartString(tag uint16, value string) durableOperationInputPart {
	return operationPartBytes(tag, []byte(value))
}

func operationPartOptionalClaimTime(tag uint16, value optionalClaimTime) durableOperationInputPart {
	if !value.valid {
		return operationPartBytes(tag, []byte{0})
	}
	var encoded [9]byte
	encoded[0] = 1
	binary.BigEndian.PutUint64(encoded[1:], uint64(value.unixNano()))
	return operationPartBytes(tag, encoded[:])
}

func operationPartRunRef(value RunRef) durableOperationInputPart {
	return operationPartBytes(durableOperationPartRunRef, opaqueRefBytes(value.ref))
}

func operationPartFactRef(value durableFactRef) durableOperationInputPart {
	return operationPartBytes(durableOperationPartFactRef, factRefBytes(value))
}

func operationPartReceiptRef(value ReceiptRef) durableOperationInputPart {
	return operationPartBytes(durableOperationPartReceiptRef, opaqueRefBytes(value.ref))
}
