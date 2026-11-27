package sign

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

type Signer interface {
	SignDetached(canonical []byte) (string, error)
	Algorithm() string
	KeyID() string
}

type Ed25519Signer struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	keyID      string
}

func NewEd25519Signer(keyID string, privateKeyHex string, publicKeyHex string) (*Ed25519Signer, error) {
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
		// A 64-byte key is the seed followed by its public key. Go signs
		// with the seed, hashes the stored public half into every
		// signature, and returns that half from Public without deriving it.
		// A key whose halves do not belong together signs nothing that
		// verifies, and its signatures give the seed away once the same
		// bytes are signed again under the right public key.
		privateKey = ed25519.NewKeyFromSeed(privateKeyBytes[:ed25519.SeedSize])
		if !bytes.Equal(privateKey, privateKeyBytes) {
			return nil, fmt.Errorf("signer.private_key_hex is a %d-byte private key whose second half is not the public key of its first half", ed25519.PrivateKeySize)
		}
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

	return &Ed25519Signer{
		privateKey: privateKey,
		publicKey:  ed25519.PublicKey(publicKeyBytes),
		keyID:      strings.TrimSpace(keyID),
	}, nil
}

func (s *Ed25519Signer) SignDetached(canonical []byte) (string, error) {
	signature := ed25519.Sign(s.privateKey, canonical)
	return base64.StdEncoding.EncodeToString(signature), nil
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
