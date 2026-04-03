package signingv2

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

func NewEnvelope(canonical []byte, keyID string, algorithm string, signatureValue string) Envelope {
	return Envelope{
		CanonicalizationVersion: Version,
		Algorithm:               algorithm,
		KeyID:                   keyID,
		PayloadDigest:           PayloadDigest(canonical),
		SignatureValue:          signatureValue,
	}
}

func VerifyEnvelope(canonical []byte, envelope Envelope, expectedKeyID string, expectedAlgorithm string, publicKey ed25519.PublicKey) error {
	if strings.TrimSpace(envelope.CanonicalizationVersion) != Version {
		return fmt.Errorf("unexpected canonicalization version")
	}
	if strings.TrimSpace(envelope.KeyID) != expectedKeyID {
		return fmt.Errorf("unexpected signing key id")
	}
	if strings.TrimSpace(envelope.Algorithm) != expectedAlgorithm {
		return fmt.Errorf("unexpected signing algorithm")
	}
	if envelope.PayloadDigest != PayloadDigest(canonical) {
		return fmt.Errorf("payload digest mismatch")
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(envelope.SignatureValue))
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(publicKey, canonical, signature) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

func PayloadDigest(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func normalizeStringSet(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	normalized := append([]string(nil), values...)
	sort.Strings(normalized)
	return normalized
}
