package evidencev1

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

type ArtifactEvidence struct {
	Claims Claims `json:"claims"`
	Seal   Seal   `json:"seal"`
}

type Seal struct {
	Algorithm     string `json:"algorithm"`
	KeyID         string `json:"key_id"`
	ContentDigest string `json:"content_digest"`
	Signature     string `json:"signature"`
}

func (e ArtifactEvidence) CanonicalBytes() ([]byte, error) {
	return e.Claims.CanonicalBytes()
}

func (e ArtifactEvidence) Validate() error {
	if err := e.Claims.Validate(); err != nil {
		return err
	}
	if err := e.validateSeal(); err != nil {
		return err
	}
	return nil
}

func (e ArtifactEvidence) validateSeal() error {
	requiredStrings := map[string]string{
		"seal.algorithm":      e.Seal.Algorithm,
		"seal.key_id":         e.Seal.KeyID,
		"seal.content_digest": e.Seal.ContentDigest,
		"seal.signature":      e.Seal.Signature,
	}
	for field, value := range requiredStrings {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", field)
		}
	}
	if err := validateDigest(strings.TrimSpace(e.Seal.ContentDigest)); err != nil {
		return fmt.Errorf("seal.content_digest: %w", err)
	}
	return nil
}

func NewSeal(canonical []byte, keyID string, algorithm string, signature string) Seal {
	return Seal{
		Algorithm:     strings.TrimSpace(algorithm),
		KeyID:         strings.TrimSpace(keyID),
		ContentDigest: ContentDigest(canonical),
		Signature:     strings.TrimSpace(signature),
	}
}

func Verify(e ArtifactEvidence, expectedKeyID string, expectedAlgorithm string, publicKey ed25519.PublicKey) error {
	canonical, err := e.CanonicalBytes()
	if err != nil {
		return err
	}
	if strings.TrimSpace(e.Seal.KeyID) != strings.TrimSpace(expectedKeyID) {
		return fmt.Errorf("unexpected signing key id")
	}
	if strings.TrimSpace(e.Seal.Algorithm) != strings.TrimSpace(expectedAlgorithm) {
		return fmt.Errorf("unexpected signing algorithm")
	}
	if strings.TrimSpace(e.Seal.ContentDigest) != ContentDigest(canonical) {
		return fmt.Errorf("content digest mismatch")
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(e.Seal.Signature))
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(publicKey, canonical, signature) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

func ContentDigest(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:])
}
