package admission

import (
	"crypto/sha256"
	"errors"
	"strings"

	"execution-substrate/es/admission/internal/reliablesubmit"
)

const (
	reliableSubmitCallerRefDomain    = "es/reliable-submit/caller-ref/v1\x00"
	reliableSubmitSubmitKeyRefDomain = "es/reliable-submit/submit-key-ref/v1\x00"
)

var errReliableSubmitInvalidCaller = errors.New("reliable submit identity: invalid caller identity")

type reliableSubmitClaimRefs struct {
	callerRef    reliablesubmit.CallerRef
	submitKeyRef reliablesubmit.SubmitKeyRef
	claimID      reliablesubmit.ClaimID
}

func deriveReliableSubmitClaimRefs(canonicalSPIFFEURI string, rawSubmitKey [reliableSubmitKeyRawLength]byte) (reliableSubmitClaimRefs, error) {
	if !validReliableSubmitCallerURI(canonicalSPIFFEURI) {
		return reliableSubmitClaimRefs{}, errReliableSubmitInvalidCaller
	}

	callerDigest := sha256.Sum256([]byte(reliableSubmitCallerRefDomain + canonicalSPIFFEURI))
	callerRef, err := reliablesubmit.NewCallerRef(callerDigest[:])
	if err != nil {
		return reliableSubmitClaimRefs{}, err
	}

	submitKeyHasher := sha256.New()
	_, _ = submitKeyHasher.Write([]byte(reliableSubmitSubmitKeyRefDomain))
	_, _ = submitKeyHasher.Write(callerDigest[:])
	_, _ = submitKeyHasher.Write(rawSubmitKey[:])
	submitKeyDigest := submitKeyHasher.Sum(nil)

	submitKeyRef, err := reliablesubmit.NewSubmitKeyRef(submitKeyDigest)
	if err != nil {
		return reliableSubmitClaimRefs{}, err
	}
	claimID, err := reliablesubmit.NewClaimID(callerRef, submitKeyRef)
	if err != nil {
		return reliableSubmitClaimRefs{}, err
	}

	return reliableSubmitClaimRefs{
		callerRef:    callerRef,
		submitKeyRef: submitKeyRef,
		claimID:      claimID,
	}, nil
}

func validReliableSubmitCallerURI(canonicalSPIFFEURI string) bool {
	return strings.HasPrefix(canonicalSPIFFEURI, "spiffe://") &&
		!strings.Contains(canonicalSPIFFEURI, "\x00") &&
		strings.TrimSpace(canonicalSPIFFEURI) == canonicalSPIFFEURI &&
		len(canonicalSPIFFEURI) > len("spiffe://")
}
