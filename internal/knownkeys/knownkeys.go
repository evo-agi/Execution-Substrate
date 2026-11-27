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
// Check also refuses the public keys that need no private key at all: the
// 14 values that crypto/ed25519 decodes to a point of small order. For such
// a key anyone can make a signature that ed25519.Verify accepts, and 32 zero
// bytes, the usual placeholder, is one of them.
//
// Each service owns which keys it configures. This package owns only the
// definition of a known key and the check, so that the three services refuse
// the same keys. The rule is in .docs/system_overview/contracts.md, section
// 3B.
package knownkeys

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
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

// smallOrder holds every 32-byte value that crypto/ed25519 decodes to one of
// the eight points of order 1, 2, 4 or 8. A signature under such a public
// key needs no private key: with R the public key of any seed and S that
// seed's scalar, ed25519.Verify accepts (R, S) whenever the challenge hash
// is a multiple of the point's order, one try in eight at worst. The values
// are the canonical encodings of the eight points, the encodings of the two
// points whose x is 0 with the sign bit set, and the encodings with y = p
// and y = p + 1, which crypto/ed25519 reduces to y = 0 and y = 1. The test
// derives the eight points from the curve and checks this list against
// every encoding of them that a forged signature verifies under.
var smallOrder = sync.OnceValue(func() map[string]bool {
	// y as 32 little-endian bytes, with the sign bit of x in the top bit.
	encodings := []string{
		"0000000000000000000000000000000000000000000000000000000000000000", // order 4, y = 0
		"0000000000000000000000000000000000000000000000000000000000000080", // order 4, y = 0, x negative
		"0100000000000000000000000000000000000000000000000000000000000000", // the identity, y = 1
		"0100000000000000000000000000000000000000000000000000000000000080", // the identity, sign bit set
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // order 2, y = p - 1
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // order 2, sign bit set
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // order 4, y = p
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // order 4, y = p, x negative
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // the identity, y = p + 1
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // the identity, y = p + 1, sign bit set
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", // order 8
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", // order 8
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", // order 8
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", // order 8
	}
	keys := make(map[string]bool, len(encodings))
	for _, encoded := range encodings {
		b, err := hex.DecodeString(encoded)
		if err != nil || len(b) != ed25519.PublicKeySize {
			panic("knownkeys: malformed small-order encoding " + encoded)
		}
		keys[string(b)] = true
	}
	return keys
})

// Check returns an error naming field when publicKey is the public key of a
// known key or a point of small order, and nil otherwise. It does not check
// that publicKey is a valid Ed25519 public key; the caller's own
// configuration check does that.
func Check(field string, publicKey []byte) error {
	if b, ok := known()[string(publicKey)]; ok {
		return fmt.Errorf("%s is a known key: its private seed is the byte 0x%02x repeated, like the keys in the repository's example configurations, so anyone can sign with it; give this host its own key (.docs/system_overview/configuration.md, \"Signing keys\")", field, b)
	}
	if smallOrder()[string(publicKey)] {
		return fmt.Errorf("%s is a key anyone can sign for: it is a point of small order (32 zero bytes is one), so a signature under it needs no private key; give this host its own key (.docs/system_overview/configuration.md, \"Signing keys\")", field)
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
