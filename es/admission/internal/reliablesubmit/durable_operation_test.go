package reliablesubmit

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
)

const manualOperationDigestDomain = "es/reliable-submit/durable-operation-input/v1"

func TestDurableOperationKindClosedRange(t *testing.T) {
	for kind := durableOperationEstablishClaim; kind <= durableOperationTombstoneOrExpire; kind++ {
		if !kind.valid() {
			t.Fatalf("operation kind %d is not valid", kind)
		}
	}
	for _, kind := range []durableOperationKind{durableOperationInvalid, durableOperationTombstoneOrExpire + 1} {
		if kind.valid() {
			t.Fatalf("operation kind %d unexpectedly valid", kind)
		}
		if _, err := deriveDurableOperationDescriptor(
			mustPrivateMutationRef(t, []byte("private-invalid-kind")),
			kind,
			initialClaimRevision,
		); err == nil {
			t.Fatalf("invalid operation kind %d was accepted", kind)
		}
	}
}

func TestDurableOperationInputBindingIsDeterministicAndDomainSeparated(t *testing.T) {
	f := newDurableFixture(t)
	first, err := deriveDurableOperationDescriptor(
		f.nextMut,
		durableOperationAssignRun,
		initialClaimRevision,
		operationPartRunRef(f.run),
	)
	if err != nil {
		t.Fatalf("derive first descriptor: %v", err)
	}
	second, err := deriveDurableOperationDescriptor(
		mustPrivateMutationRef(t, []byte("private-other-mutation-ref")),
		durableOperationAssignRun,
		initialClaimRevision,
		operationPartRunRef(f.run),
	)
	if err != nil {
		t.Fatalf("derive second descriptor: %v", err)
	}
	if !first.binding.equal(second.binding) {
		t.Fatalf("mutation ref changed the operation input digest")
	}
	if first.mutation.equal(second.mutation) {
		t.Fatalf("descriptors collapsed distinct mutation refs")
	}
	if got := len(first.binding.bytes()); got != durableOperationInputBindingLength {
		t.Fatalf("digest length = %d, want %d", got, durableOperationInputBindingLength)
	}

	changedPredecessor := digestDurableOperationInput(durableOperationAssignRun, initialClaimRevision+1, operationPartRunRef(f.run))
	if first.binding.equal(changedPredecessor) {
		t.Fatalf("predecessor revision did not affect operation digest")
	}
	changedKind := digestDurableOperationInput(durableOperationRecordProviderEffectIntent, initialClaimRevision, operationPartRunRef(f.run))
	if first.binding.equal(changedKind) {
		t.Fatalf("operation kind did not affect operation digest")
	}
	changedInput := digestDurableOperationInput(durableOperationAssignRun, initialClaimRevision, operationPartRunRef(f.otherRun))
	if first.binding.equal(changedInput) {
		t.Fatalf("semantic input did not affect operation digest")
	}

	copied := first.binding.bytes()
	copied[0] ^= 0xff
	if first.binding.bytes()[0] == copied[0] {
		t.Fatalf("binding bytes were exposed by alias")
	}
}

func TestDurableOperationInputBindingGoldenPreimage(t *testing.T) {
	part := operationPartBytes(durableOperationPartRunRef, []byte("synthetic-run-ref"))
	preimage := manualOperationDigestPreimage(durableOperationAssignRun, initialClaimRevision, part)
	expected := sha256.Sum256(preimage)
	const expectedHex = "b99d6dd7187c5193bf4e06fd0865d5ada01a742183cb31542f94115e7f36c65d"
	if got := hex.EncodeToString(expected[:]); got != expectedHex {
		t.Fatalf("manual golden digest = %s, want %s", got, expectedHex)
	}

	got := digestDurableOperationInput(durableOperationAssignRun, initialClaimRevision, part)
	if gotHex := hex.EncodeToString(got.bytes()); gotHex != expectedHex {
		t.Fatalf("operation digest = %s, want golden digest", gotHex)
	}

	lengthPrefixedDomain := manualLengthPrefixedDomainDigestPreimage(durableOperationAssignRun, initialClaimRevision, part)
	legacy := sha256.Sum256(lengthPrefixedDomain)
	const legacyHex = "260cfbd8556f43ec88cc9ee4d4e091a0f447dbd7746bf17b32ce7c5b758ebb03"
	if got := hex.EncodeToString(legacy[:]); got != legacyHex {
		t.Fatalf("length-prefixed-domain digest = %s, want pinned alternate", got)
	}
	if legacy == expected {
		t.Fatalf("length-prefixed domain produced the canonical digest")
	}
}

func TestDurableOperationInputBindingMatrixDeterministic(t *testing.T) {
	f := newDurableFixture(t)
	cases := []struct {
		name        string
		kind        durableOperationKind
		predecessor claimRevision
		parts       []durableOperationInputPart
	}{
		{
			name:        "establish",
			kind:        durableOperationEstablishClaim,
			predecessor: 0,
			parts: []durableOperationInputPart{
				operationPartUint16(durableOperationPartInitialPhase, uint16(durablePhasePendingBeforeAssignment)),
				operationPartOptionalClaimTime(durableOperationPartExpiresAt, noClaimTime()),
			},
		},
		{name: "assign", kind: durableOperationAssignRun, predecessor: initialClaimRevision, parts: []durableOperationInputPart{operationPartRunRef(f.run)}},
		{name: "intent", kind: durableOperationRecordProviderEffectIntent, predecessor: initialClaimRevision, parts: []durableOperationInputPart{operationPartFactRef(f.intent)}},
		{name: "staging", kind: durableOperationRecordStagingEvidence, predecessor: initialClaimRevision, parts: []durableOperationInputPart{operationPartFactRef(f.staging)}},
		{name: "dispatch", kind: durableOperationRecordProviderDispatchAttempt, predecessor: initialClaimRevision, parts: []durableOperationInputPart{operationPartFactRef(f.dispatch)}},
		{
			name:        "provider observation",
			kind:        durableOperationRecordProviderCallObservation,
			predecessor: initialClaimRevision,
			parts: []durableOperationInputPart{
				operationPartRunRef(f.run),
				operationPartUint16(durableOperationPartObservationKind, uint16(durableProviderObservationPending)),
				operationPartFactRef(f.observation),
			},
		},
		{
			name:        "reconciliation",
			kind:        durableOperationRecordReconciliationEvidence,
			predecessor: initialClaimRevision,
			parts: []durableOperationInputPart{
				operationPartRunRef(f.run),
				operationPartUint16(durableOperationPartReconciliationKind, uint16(durableReconciliationPending)),
				operationPartFactRef(f.reconcile),
			},
		},
		{
			name:        "accepted",
			kind:        durableOperationAcceptWithReceipt,
			predecessor: initialClaimRevision,
			parts: []durableOperationInputPart{
				operationPartReceiptRef(f.receipt),
				operationPartFactRef(f.observation),
			},
		},
		{name: "not accepted", kind: durableOperationRecordProvablyNotAccepted, predecessor: initialClaimRevision, parts: []durableOperationInputPart{operationPartFactRef(f.observation)}},
		{
			name:        "tombstone",
			kind:        durableOperationTombstoneOrExpire,
			predecessor: initialClaimRevision,
			parts: []durableOperationInputPart{
				operationPartUint16(durableOperationPartRetentionState, uint16(durableRetentionTombstoned)),
				operationPartString(durableOperationPartRetentionReason, "retention elapsed"),
			},
		},
	}
	if len(cases) != int(durableOperationTombstoneOrExpire) {
		t.Fatalf("operation matrix has %d cases, want %d", len(cases), durableOperationTombstoneOrExpire)
	}
	seen := make(map[string]durableOperationKind)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first, err := deriveDurableOperationDescriptor(f.nextMut, tc.kind, tc.predecessor, tc.parts...)
			if err != nil {
				t.Fatalf("derive first descriptor: %v", err)
			}
			second, err := deriveDurableOperationDescriptor(mustPrivateMutationRef(t, []byte("private-matrix-other-mutation")), tc.kind, tc.predecessor, tc.parts...)
			if err != nil {
				t.Fatalf("derive second descriptor: %v", err)
			}
			if !first.complete() || !second.complete() {
				t.Fatalf("matrix descriptor was incomplete")
			}
			if !first.binding.equal(second.binding) {
				t.Fatalf("mutation ref affected %s digest", tc.name)
			}
			repeated := digestDurableOperationInput(tc.kind, tc.predecessor, tc.parts...)
			if !first.binding.equal(repeated) {
				t.Fatalf("%s digest changed across repeated derivation", tc.name)
			}
			key := hex.EncodeToString(first.binding.bytes())
			if previous, ok := seen[key]; ok {
				t.Fatalf("%s digest reused operation kind %d", tc.name, previous)
			}
			seen[key] = tc.kind
		})
	}
}

func TestDurableLatestOperationDescriptorValidationAndComparison(t *testing.T) {
	f := newDurableFixture(t)
	complete := mustDurableOperationDescriptor(t, f.mutation)
	if !complete.complete() || complete.legacyUnbound() {
		t.Fatalf("complete descriptor shape invalid: %#v", complete)
	}
	legacy, err := newLegacyDurableLatestOperationDescriptor(f.mutation)
	if err != nil {
		t.Fatalf("legacy descriptor: %v", err)
	}
	if !legacy.legacyUnbound() || legacy.complete() {
		t.Fatalf("legacy descriptor shape invalid: %#v", legacy)
	}
	if !complete.validForCodec(durableClaimCodecVersion, f.mutation) {
		t.Fatalf("complete descriptor did not validate for codec v2")
	}
	if !legacy.validForCodec(durableClaimCodecVersionLegacy, f.mutation) {
		t.Fatalf("legacy descriptor did not validate for codec v1")
	}
	if complete.validForCodec(durableClaimCodecVersionLegacy, f.mutation) {
		t.Fatalf("complete descriptor validated as legacy codec")
	}
	if legacy.validForCodec(durableClaimCodecVersion, f.mutation) {
		t.Fatalf("legacy descriptor validated as codec v2")
	}

	partial := durableLatestOperationDescriptor{mutation: f.mutation, kind: durableOperationAssignRun}
	if partial.complete() || partial.legacyUnbound() || partial.validForCodec(durableClaimCodecVersion, f.mutation) {
		t.Fatalf("partial descriptor validated")
	}
	if compareDurableLatestOperation(complete, complete.clone()) != durableOperationReplayExact {
		t.Fatalf("matching complete descriptors did not compare exact")
	}
	conflict, err := deriveDurableOperationDescriptor(f.mutation, durableOperationAssignRun, initialClaimRevision, operationPartRunRef(f.run))
	if err != nil {
		t.Fatalf("derive conflicting descriptor: %v", err)
	}
	if compareDurableLatestOperation(complete, conflict) != durableOperationReplayConflict {
		t.Fatalf("same mutation with different descriptor did not conflict")
	}
	if compareDurableLatestOperation(legacy, complete) != durableOperationReplayUnavailable {
		t.Fatalf("legacy same-mutation descriptor did not fail closed as unavailable")
	}
}

func TestDurableOperationFormattingDoesNotExposeRawInput(t *testing.T) {
	f := newDurableFixture(t)
	operation := mustDurableOperationDescriptor(t, f.mutation)
	rendered := fmt.Sprintf("%#v %#v", operation, operation.binding)
	for _, forbidden := range []string{
		"private-mutation-reference",
		"private-plan-binding",
		fmt.Sprintf("%x", operation.binding.bytes()),
	} {
		if stringsContains(rendered, forbidden) {
			t.Fatalf("operation formatter leaked %q in %q", forbidden, rendered)
		}
	}
}

func manualOperationDigestPreimage(kind durableOperationKind, predecessor claimRevision, parts ...durableOperationInputPart) []byte {
	preimage := []byte(manualOperationDigestDomain)
	preimage = append(preimage, 0)
	preimage = manualAppendUint16(preimage, uint16(kind))
	preimage = manualAppendInt64(preimage, int64(predecessor))
	for _, part := range parts {
		preimage = manualAppendUint16(preimage, part.tag)
		preimage = manualAppendBytes(preimage, part.value)
	}
	return preimage
}

func manualLengthPrefixedDomainDigestPreimage(kind durableOperationKind, predecessor claimRevision, parts ...durableOperationInputPart) []byte {
	preimage := manualAppendBytes(nil, []byte(manualOperationDigestDomain))
	preimage = manualAppendUint16(preimage, uint16(kind))
	preimage = manualAppendInt64(preimage, int64(predecessor))
	for _, part := range parts {
		preimage = manualAppendUint16(preimage, part.tag)
		preimage = manualAppendBytes(preimage, part.value)
	}
	return preimage
}

func manualAppendUint16(out []byte, value uint16) []byte {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], value)
	return append(out, encoded[:]...)
}

func manualAppendInt64(out []byte, value int64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(value))
	return append(out, encoded[:]...)
}

func manualAppendBytes(out []byte, value []byte) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	out = append(out, length[:]...)
	return append(out, value...)
}
