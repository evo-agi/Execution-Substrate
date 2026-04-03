package signingv1

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
)

func VerifyDetachedEnvelope(expectedCanonical []byte, envelope DetachedEnvelope, expectedKeyID string, expectedAlgorithm string, publicKey ed25519.PublicKey) error {
	if strings.TrimSpace(envelope.KeyID) != expectedKeyID {
		return fmt.Errorf("unexpected signing key id")
	}
	if strings.TrimSpace(envelope.Algorithm) != expectedAlgorithm {
		return fmt.Errorf("unexpected signing algorithm")
	}
	canonicalFromEnvelope, err := base64.StdEncoding.DecodeString(strings.TrimSpace(envelope.CanonicalSpecB64))
	if err != nil {
		return fmt.Errorf("decode canonical payload: %w", err)
	}
	if !bytes.Equal(canonicalFromEnvelope, expectedCanonical) {
		return fmt.Errorf("canonical payload mismatch")
	}
	if envelope.PayloadDigest != digestBytes(expectedCanonical) {
		return fmt.Errorf("payload digest mismatch")
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(envelope.SignatureValue))
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(publicKey, expectedCanonical, signature) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}
