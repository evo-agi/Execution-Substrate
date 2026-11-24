package reliablesubmit

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"strings"
	"time"
)

// replayClaimDescriptor is the immutable codec-3 extension to the inherited
// durable record. Its ref is a syntax-checked association, never proof that a
// file exists or authenticates. The composite reader supplies that proof.
type replayClaimDescriptor struct {
	privateReplayRedacted
	scope         int64
	intentFormat  int64
	intentMAC     [32]byte
	contextMAC    [32]byte
	wrapperFormat int64
	payloadFormat int64
	algorithm     int64
	ref           string
	size          int64
	fileSHA       [32]byte
	bindingKeyID  string
	bindingKeyFP  [32]byte
	envelopeKeyID string
	envelopeKeyFP [32]byte
}

func (d replayClaimDescriptor) zero() bool                   { return d == (replayClaimDescriptor{}) }
func (d replayClaimDescriptor) clone() replayClaimDescriptor { return d }

func (d replayClaimDescriptor) valid() bool { return d.validForScope(1) }

func (d replayClaimDescriptor) validForScope(scope int64) bool {
	return (scope == 1 || scope == 2 || scope == 3) && d.scope == scope && d.intentFormat == 1 &&
		d.wrapperFormat == scope && d.payloadFormat == scope && d.algorithm == 1 &&
		replayObjectRefValid(d.ref) && d.size >= 29 && d.size <= replaySealedLimit &&
		replayKeyIDValid(d.bindingKeyID) && replayKeyIDValid(d.envelopeKeyID) &&
		d.bindingKeyID != d.envelopeKeyID && d.bindingKeyFP != d.envelopeKeyFP
}

func (d replayClaimDescriptor) equal(other replayClaimDescriptor) bool {
	return d.scope == other.scope && d.intentFormat == other.intentFormat &&
		d.wrapperFormat == other.wrapperFormat && d.payloadFormat == other.payloadFormat &&
		d.algorithm == other.algorithm && d.ref == other.ref && d.size == other.size &&
		d.bindingKeyID == other.bindingKeyID && d.envelopeKeyID == other.envelopeKeyID &&
		subtle.ConstantTimeCompare(d.intentMAC[:], other.intentMAC[:]) == 1 &&
		subtle.ConstantTimeCompare(d.contextMAC[:], other.contextMAC[:]) == 1 &&
		subtle.ConstantTimeCompare(d.fileSHA[:], other.fileSHA[:]) == 1 &&
		subtle.ConstantTimeCompare(d.bindingKeyFP[:], other.bindingKeyFP[:]) == 1 &&
		subtle.ConstantTimeCompare(d.envelopeKeyFP[:], other.envelopeKeyFP[:]) == 1
}

func replayObjectRefValid(ref string) bool {
	if len(ref) != 75 || !strings.HasPrefix(ref, "objects/v1/") {
		return false
	}
	for i := 11; i < len(ref); i++ {
		ch := ref[i]
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			return false
		}
	}
	return true
}

func replayKeyIDValid(id string) bool {
	if len(id) < 1 || len(id) > 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		ch := id[i]
		letter := ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z'
		digit := ch >= '0' && ch <= '9'
		if i == 0 {
			if !letter && !digit {
				return false
			}
		} else if !letter && !digit && ch != '.' && ch != '_' && ch != '-' {
			return false
		}
	}
	return true
}

func newReplayDurableClaimRecord(claim ClaimID, plan BoundPlan, descriptor replayClaimDescriptor, now time.Time) (durableClaimRecord, error) {
	if !claim.Valid() || !plan.Valid() || !descriptor.valid() ||
		len(claim.caller.ref.value) != 32 || len(claim.submitKey.ref.value) != 32 ||
		len(plan.binding.ref.value) > 256 {
		return durableClaimRecord{}, errInvalidDurableRecord
	}
	resolved, inapplicable, err := sqliteWitnessMasks(plan.Witness())
	if err != nil {
		return durableClaimRecord{}, errInvalidDurableRecord
	}
	var randomMutation [32]byte
	if _, err := rand.Read(randomMutation[:]); err != nil {
		return durableClaimRecord{}, errClaimStoreUnavailable
	}
	mutation, err := newDurableMutationRef(randomMutation[:])
	if err != nil {
		return durableClaimRecord{}, errInvalidDurableRecord
	}
	preimage := durableOperationInputEncoder{}
	preimage.bytes(claim.caller.ref.value)
	preimage.bytes(claim.submitKey.ref.value)
	preimage.bytes(plan.binding.ref.value)
	preimage.i64(resolved)
	preimage.i64(inapplicable)
	preimage.i64(1) // pending, revision one, synthetic scope
	preimage.i64(normalizeClaimTime(now).UnixNano())
	preimage.i64(descriptor.scope)
	preimage.i64(descriptor.intentFormat)
	preimage.bytes(descriptor.intentMAC[:])
	preimage.bytes(descriptor.contextMAC[:])
	preimage.i64(descriptor.wrapperFormat)
	preimage.i64(descriptor.payloadFormat)
	preimage.i64(descriptor.algorithm)
	preimage.bytes([]byte(descriptor.ref))
	preimage.i64(descriptor.size)
	preimage.bytes(descriptor.fileSHA[:])
	preimage.bytes([]byte(descriptor.bindingKeyID))
	preimage.bytes(descriptor.bindingKeyFP[:])
	preimage.bytes([]byte(descriptor.envelopeKeyID))
	preimage.bytes(descriptor.envelopeKeyFP[:])
	operation, err := deriveDurableOperationDescriptor(mutation, durableOperationEstablishClaim, 0,
		durableOperationInputPart{tag: durableOperationPartSyntheticDescriptor, value: preimage.buf})
	if err != nil {
		return durableClaimRecord{}, errInvalidDurableRecord
	}
	phase, err := NewPendingBeforeAssignment(claim, plan)
	if err != nil {
		return durableClaimRecord{}, errInvalidDurableRecord
	}
	record, err := newDurableClaimRecord(newDurableClaimRecordInput{
		phase: phase, revision: initialClaimRevision, createdAt: now,
		updatedAt: now, retention: activeDurableRetention(), latestOperation: operation,
	})
	if err != nil {
		return durableClaimRecord{}, err
	}
	record.codecVersion = durableClaimCodecVersionSynthetic
	record.replay = descriptor
	if err := record.validate(); err != nil {
		return durableClaimRecord{}, err
	}
	return record, nil
}

func newProgressInitialClaim(claim ClaimID, plan BoundPlan, tag durablePhaseTag, d replayClaimDescriptor, now time.Time) (durableClaimRecord, error) {
	if !claim.Valid() || !plan.Valid() || !d.validForScope(2) ||
		len(claim.caller.ref.value) != 32 || len(claim.submitKey.ref.value) != 32 ||
		len(plan.binding.ref.value) > 256 ||
		(tag != durablePhasePendingBeforeAssignment && tag != durablePhaseAmbiguousBeforeAssignment) {
		return durableClaimRecord{}, errInvalidDurableRecord
	}
	resolved, inapplicable, err := sqliteWitnessMasks(plan.Witness())
	if err != nil {
		return durableClaimRecord{}, errInvalidDurableRecord
	}
	var randomMutation [32]byte
	if _, err := rand.Read(randomMutation[:]); err != nil {
		return durableClaimRecord{}, errClaimStoreUnavailable
	}
	mutation, err := newDurableMutationRef(randomMutation[:])
	if err != nil {
		return durableClaimRecord{}, err
	}
	now = normalizeClaimTime(now)
	wire := append([]byte("ESRSEST2"), claim.caller.ref.value...)
	wire = append(wire, claim.submitKey.ref.value...)
	wire = binary.BigEndian.AppendUint32(wire, uint32(len(plan.binding.ref.value)))
	wire = append(wire, plan.binding.ref.value...)
	wire = binary.BigEndian.AppendUint16(wire, uint16(resolved))
	wire = binary.BigEndian.AppendUint16(wire, uint16(inapplicable))
	wire = append(wire, byte(tag))
	wire = binary.BigEndian.AppendUint64(wire, uint64(now.UnixNano()))
	wire = binary.BigEndian.AppendUint16(wire, durableClaimCodecVersionProgress)
	wire = append(wire, 2)
	wire = binary.BigEndian.AppendUint16(wire, 1)
	wire = append(wire, d.intentMAC[:]...)
	wire = append(wire, d.contextMAC[:]...)
	wire = binary.BigEndian.AppendUint16(wire, 2)
	wire = binary.BigEndian.AppendUint16(wire, 2)
	wire = binary.BigEndian.AppendUint16(wire, 1)
	wire = append(wire, d.ref...)
	wire = binary.BigEndian.AppendUint32(wire, uint32(d.size))
	wire = append(wire, d.fileSHA[:]...)
	wire = binary.BigEndian.AppendUint16(wire, uint16(len(d.bindingKeyID)))
	wire = append(wire, d.bindingKeyID...)
	wire = append(wire, d.bindingKeyFP[:]...)
	wire = binary.BigEndian.AppendUint16(wire, uint16(len(d.envelopeKeyID)))
	wire = append(wire, d.envelopeKeyID...)
	wire = append(wire, d.envelopeKeyFP[:]...)
	op, err := deriveDurableOperationDescriptor(mutation, durableOperationEstablishClaim, 0,
		durableOperationInputPart{tag: durableOperationPartSyntheticDescriptor, value: wire})
	if err != nil {
		return durableClaimRecord{}, err
	}
	record := durableClaimRecord{
		codecVersion: durableClaimCodecVersionProgress, claim: claim.clone(), plan: plan.clone(),
		phase: durablePhaseSnapshot{tag: tag}, revision: initialClaimRevision, replay: d,
		createdAt: now, updatedAt: now, retention: activeDurableRetention(),
		lastMutation: mutation, latestOperation: op,
	}
	if err := record.validate(); err != nil {
		return durableClaimRecord{}, err
	}
	return record, nil
}
