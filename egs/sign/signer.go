package sign

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"execution-platform/egs/model"
)

type Result struct {
	TrustModel    model.TrustModel `json:"trust_model"`
	Algorithm     string           `json:"algorithm"`
	KeyID         string           `json:"key_id"`
	PayloadDigest string           `json:"payload_digest"`
	Signature     string           `json:"signature"`
	// SourceDigest is advisory metadata only in the current EGS v1 contract.
	// It is excluded from payload_digest and signature, and consumers must not
	// use it for trust decisions. Only payload_digest and signature are
	// authoritative in v1.
	SourceDigest  *string          `json:"source_digest,omitempty"`
}

type Signer interface {
	Sign(trustModel model.TrustModel) (Result, error)
	Algorithm() string
	KeyID() string
}

type Ed25519Signer struct {
	privateKey   ed25519.PrivateKey
	publicKey    ed25519.PublicKey
	keyID        string
	sourceDigest *string
}

func NewEd25519Signer(keyID string, privateKeyHex string, publicKeyHex string, sourceDigest string) (*Ed25519Signer, error) {
	if strings.TrimSpace(keyID) == "" {
		return nil, fmt.Errorf("signer.key_id is required")
	}

	privateKeyBytes, err := hex.DecodeString(strings.TrimSpace(privateKeyHex))
	if err != nil {
		return nil, fmt.Errorf("decode signer.private_key_hex: %w", err)
	}
	var privateKey ed25519.PrivateKey
	switch len(privateKeyBytes) {
	case ed25519.SeedSize:
		privateKey = ed25519.NewKeyFromSeed(privateKeyBytes)
	case ed25519.PrivateKeySize:
		privateKey = ed25519.PrivateKey(privateKeyBytes)
	default:
		return nil, fmt.Errorf("signer.private_key_hex must be a %d-byte seed or %d-byte private key", ed25519.SeedSize, ed25519.PrivateKeySize)
	}

	publicKeyBytes, err := hex.DecodeString(strings.TrimSpace(publicKeyHex))
	if err != nil {
		return nil, fmt.Errorf("decode signer.public_key_hex: %w", err)
	}
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("signer.public_key_hex must be a %d-byte public key", ed25519.PublicKeySize)
	}

	derivedPublicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("derive signer public key: unexpected key type")
	}
	if !bytes.Equal(derivedPublicKey, publicKeyBytes) {
		return nil, fmt.Errorf("signer public key does not match private key")
	}

	var sourceDigestPtr *string
	if trimmed := strings.TrimSpace(sourceDigest); trimmed != "" {
		sourceDigestPtr = &trimmed
	}

	return &Ed25519Signer{
		privateKey:   privateKey,
		publicKey:    ed25519.PublicKey(publicKeyBytes),
		keyID:        strings.TrimSpace(keyID),
		sourceDigest: sourceDigestPtr,
	}, nil
}

func (s *Ed25519Signer) Sign(trustModel model.TrustModel) (Result, error) {
	payloadDigest, err := trustModel.PayloadDigest()
	if err != nil {
		return Result{}, err
	}
	canonical, err := trustModel.CanonicalBytes()
	if err != nil {
		return Result{}, err
	}

	// TODO: Evaluate whether source_digest should become authenticated in a
	// future TrustModel version. If so, include it in the canonical payload,
	// introduce a new trust_model.version contract (for example "v2"), and
	// update ES verification logic accordingly. The current placement and
	// semantics are provisional; consumers must not assume source_digest will
	// remain unsigned forever.
	//
	// trust_model.version is authoritative for signature semantics. In the
	// current EGS v1 contract, the signature covers only canonical TrustModel
	// payload bytes. source_digest remains unsigned advisory metadata. ES and
	// other consumers must ignore source_digest for trust decisions in v1; only
	// payload_digest and signature are authoritative.
	signature := ed25519.Sign(s.privateKey, canonical)
	return Result{
		TrustModel:    trustModel.Normalized(),
		Algorithm:     "ed25519",
		KeyID:         s.keyID,
		PayloadDigest: payloadDigest,
		Signature:     base64.StdEncoding.EncodeToString(signature),
		SourceDigest:  s.sourceDigest,
	}, nil
}

func (s *Ed25519Signer) Algorithm() string {
	return "ed25519"
}

func (s *Ed25519Signer) KeyID() string {
	return s.keyID
}

func (s *Ed25519Signer) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), s.publicKey...)
}
