package admission

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"execution-substrate/es/admission/internal/reliablesubmit"
)

func TestReliableSubmitClaimRefsUseSpecifiedDerivation(t *testing.T) {
	callerURI := "spiffe://execution.internal/control-plane/prod"
	keyText := reliableSubmitTestKeyString(0x66)
	rawKey, err := decodeCanonicalReliableSubmitKey(keyText)
	if err != nil {
		reliableSubmitPrivacyFail(t, "privacy setup: submit-key decoding failed")
	}

	refs, err := deriveReliableSubmitClaimRefs(callerURI, rawKey)
	if err != nil {
		reliableSubmitPrivacyFail(t, "privacy setup: identity derivation failed")
	}

	callerDigest := sha256.Sum256([]byte(reliableSubmitCallerRefDomain + callerURI))
	expectedCaller, err := reliablesubmit.NewCallerRef(callerDigest[:])
	if err != nil {
		reliableSubmitPrivacyFail(t, "privacy setup: expected caller reference construction failed")
	}

	submitKeyHasher := sha256.New()
	_, _ = submitKeyHasher.Write([]byte(reliableSubmitSubmitKeyRefDomain))
	_, _ = submitKeyHasher.Write(callerDigest[:])
	_, _ = submitKeyHasher.Write(rawKey[:])
	expectedSubmitKey, err := reliablesubmit.NewSubmitKeyRef(submitKeyHasher.Sum(nil))
	if err != nil {
		reliableSubmitPrivacyFail(t, "privacy setup: expected submit-key reference construction failed")
	}
	expectedClaim, err := reliablesubmit.NewClaimID(expectedCaller, expectedSubmitKey)
	if err != nil {
		reliableSubmitPrivacyFail(t, "privacy setup: expected claim identity construction failed")
	}

	if !refs.callerRef.Equal(expectedCaller) {
		reliableSubmitPrivacyFail(t, "privacy identity: caller derivation mismatch")
	}
	if !refs.submitKeyRef.Equal(expectedSubmitKey) {
		reliableSubmitPrivacyFail(t, "privacy identity: submit-key derivation mismatch")
	}
	if !refs.claimID.Equal(expectedClaim) {
		reliableSubmitPrivacyFail(t, "privacy identity: claim identity construction mismatch")
	}
}

func TestReliableSubmitClaimRefsAreDeterministicAndCallerScoped(t *testing.T) {
	keyA, err := decodeCanonicalReliableSubmitKey(reliableSubmitTestKeyString(0x77))
	if err != nil {
		reliableSubmitPrivacyFail(t, "privacy setup: submit-key decoding failed")
	}
	keyB, err := decodeCanonicalReliableSubmitKey(reliableSubmitTestKeyString(0x78))
	if err != nil {
		reliableSubmitPrivacyFail(t, "privacy setup: submit-key decoding failed")
	}

	refsA1, err := deriveReliableSubmitClaimRefs("spiffe://execution.internal/caller/a", keyA)
	if err != nil {
		reliableSubmitPrivacyFail(t, "privacy setup: identity derivation failed")
	}
	refsA2, err := deriveReliableSubmitClaimRefs("spiffe://execution.internal/caller/a", keyA)
	if err != nil {
		reliableSubmitPrivacyFail(t, "privacy setup: identity derivation failed")
	}
	refsDifferentKey, err := deriveReliableSubmitClaimRefs("spiffe://execution.internal/caller/a", keyB)
	if err != nil {
		reliableSubmitPrivacyFail(t, "privacy setup: identity derivation failed")
	}
	refsDifferentCaller, err := deriveReliableSubmitClaimRefs("spiffe://execution.internal/caller/b", keyA)
	if err != nil {
		reliableSubmitPrivacyFail(t, "privacy setup: identity derivation failed")
	}

	if !refsA1.callerRef.Equal(refsA2.callerRef) ||
		!refsA1.submitKeyRef.Equal(refsA2.submitKeyRef) ||
		!refsA1.claimID.Equal(refsA2.claimID) {
		reliableSubmitPrivacyFail(t, "privacy identity: deterministic derivation mismatch")
	}
	if !refsA1.callerRef.Equal(refsDifferentKey.callerRef) {
		reliableSubmitPrivacyFail(t, "privacy identity: caller namespace mismatch")
	}
	if refsA1.submitKeyRef.Equal(refsDifferentKey.submitKeyRef) || refsA1.claimID.Equal(refsDifferentKey.claimID) {
		reliableSubmitPrivacyFail(t, "privacy identity: key isolation mismatch")
	}
	if refsA1.callerRef.Equal(refsDifferentCaller.callerRef) ||
		refsA1.submitKeyRef.Equal(refsDifferentCaller.submitKeyRef) ||
		refsA1.claimID.Equal(refsDifferentCaller.claimID) {
		reliableSubmitPrivacyFail(t, "privacy identity: caller isolation mismatch")
	}
}

func TestReliableSubmitClaimRefDerivationDoesNotRetainMutableInput(t *testing.T) {
	raw := bytes.Repeat([]byte{0x79}, reliableSubmitKeyRawLength)
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	key, err := decodeCanonicalReliableSubmitKey(encoded)
	if err != nil {
		reliableSubmitPrivacyFail(t, "privacy setup: submit-key decoding failed")
	}
	refsBefore, err := deriveReliableSubmitClaimRefs("spiffe://execution.internal/caller/mutable", key)
	if err != nil {
		reliableSubmitPrivacyFail(t, "privacy setup: identity derivation failed")
	}

	for i := range raw {
		raw[i] ^= 0xff
	}

	refsAfter, err := deriveReliableSubmitClaimRefs("spiffe://execution.internal/caller/mutable", key)
	if err != nil {
		reliableSubmitPrivacyFail(t, "privacy setup: identity derivation failed")
	}
	if !refsBefore.callerRef.Equal(refsAfter.callerRef) ||
		!refsBefore.submitKeyRef.Equal(refsAfter.submitKeyRef) ||
		!refsBefore.claimID.Equal(refsAfter.claimID) {
		reliableSubmitPrivacyFail(t, "privacy aliasing: identity invariant failed")
	}
}

func TestReliableSubmitClaimRefDerivationRejectsInvalidCallerWithoutLeak(t *testing.T) {
	badCaller := "spiffe://execution.internal/bad\x00caller"
	key, err := decodeCanonicalReliableSubmitKey(reliableSubmitTestKeyString(0x80))
	if err != nil {
		reliableSubmitPrivacyFail(t, "privacy setup: submit-key decoding failed")
	}

	_, err = deriveReliableSubmitClaimRefs(badCaller, key)
	if !errors.Is(err, errReliableSubmitInvalidCaller) {
		reliableSubmitPrivacyFail(t, "privacy identity: invalid caller classification mismatch")
	}
	if strings.Contains(err.Error(), badCaller) {
		reliableSubmitPrivacyFail(t, "privacy diagnostics: protected material leaked")
	}
}

func TestReliableSubmitClaimRefsFormatOpaque(t *testing.T) {
	callerURI := "spiffe://execution.internal/caller/redacted"
	keyText := reliableSubmitTestKeyString(0x81)
	key, err := decodeCanonicalReliableSubmitKey(keyText)
	if err != nil {
		reliableSubmitPrivacyFail(t, "privacy setup: submit-key decoding failed")
	}
	refs, err := deriveReliableSubmitClaimRefs(callerURI, key)
	if err != nil {
		reliableSubmitPrivacyFail(t, "privacy setup: identity derivation failed")
	}
	formatted := fmt.Sprintf("%v %v %v", refs.callerRef, refs.submitKeyRef, refs.claimID)
	if strings.Contains(formatted, callerURI) || strings.Contains(formatted, keyText) {
		reliableSubmitPrivacyFail(t, "privacy projection: protected material leaked")
	}
}
