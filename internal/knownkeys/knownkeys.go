// Package knownkeys names the Ed25519 signing keys whose private halves
// anyone can know, so that AGS, EGS and ES refuse to sign or verify with one.
//
// A known key is one whose 32-byte private seed is a single byte repeated.
// That family holds the two keys this repository has published in its
// example configurations and once wrote into every supported-local install:
// the AGS key, seed 0x11 repeated (public key d04ab232...8737), and
// the EGS key, seed 0x33 repeated (public key 17cb79fb...80ce). Anyone who
// holds such a key can seal artifact evidence for any publisher, or sign an
// EGS trust policy that allows any signer, so a host that trusts one has no
// publisher boundary. The family is closed and small (256 keys), so the
// check needs no list to maintain and also catches the next placeholder of
// the same kind.
//
// Each service owns which keys it configures. This package owns only the
// definition of a known key and the check, so that the three services refuse
// the same keys. The rule is in .docs/system_overview/contracts.md, section
// 3B.
package knownkeys

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"sync"
)

// known maps the public key of every known key to the byte its seed repeats.
var known = sync.OnceValue(func() map[string]byte {
	keys := make(map[string]byte, 256)
	for b := 0; b < 256; b++ {
		seed := bytes.Repeat([]byte{byte(b)}, ed25519.SeedSize)
		public := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		keys[string(public)] = byte(b)
	}
	return keys
})

// Check returns an error naming field when publicKey is the public key of a
// known key, and nil otherwise. It does not check that publicKey is a valid
// Ed25519 public key; the caller's own configuration check does that.
func Check(field string, publicKey []byte) error {
	if b, ok := known()[string(publicKey)]; ok {
		return fmt.Errorf("%s is a known key: its private seed is the byte 0x%02x repeated, like the keys in the repository's example configurations, so anyone can sign with it; give this host its own key (.docs/system_overview/configuration.md, \"Signing keys\")", field, b)
	}
	return nil
}

// CheckPrivate is Check for a private key given as a 32-byte seed or a
// 64-byte Ed25519 private key: it refuses one whose public key is known. It
// returns nil for any other length, which the caller's own configuration
// check refuses.
func CheckPrivate(field string, privateKey []byte) error {
	switch len(privateKey) {
	case ed25519.SeedSize:
		return Check(field, ed25519.NewKeyFromSeed(privateKey).Public().(ed25519.PublicKey))
	case ed25519.PrivateKeySize:
		// A 64-byte Ed25519 private key is the seed followed by the public
		// key. Both halves are checked: Go signs with the seed, and an
		// operator may have pasted a known seed beside another public key.
		if err := Check(field, ed25519.NewKeyFromSeed(privateKey[:ed25519.SeedSize]).Public().(ed25519.PublicKey)); err != nil {
			return err
		}
		return Check(field, privateKey[ed25519.SeedSize:])
	}
	return nil
}
