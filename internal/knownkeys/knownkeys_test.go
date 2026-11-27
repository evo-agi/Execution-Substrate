package knownkeys_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"execution-substrate/internal/knownkeys"
)

// The two keys the repository published in its example configurations and
// wrote into every supported-local install before each install generated
// its own.
const (
	publishedAGSPublicKey = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"
	publishedEGSPublicKey = "17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCheckRefusesThePublishedKeys(t *testing.T) {
	for _, test := range []struct {
		public string
		seed   byte
	}{
		{publishedAGSPublicKey, 0x11},
		{publishedEGSPublicKey, 0x33},
	} {
		public := mustHex(t, test.public)
		// The constants are the public halves of the repeated-byte seeds.
		derived := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{test.seed}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
		if !bytes.Equal(derived, public) {
			t.Fatalf("seed 0x%02x repeated does not give %s", test.seed, test.public)
		}
		err := knownkeys.Check("verification.provenance.public_key_hex", public)
		if err == nil {
			t.Fatalf("published key %s accepted", test.public)
		}
		for _, want := range []string{"verification.provenance.public_key_hex", "is a known key", "0x" + hex.EncodeToString([]byte{test.seed}), "give this host its own key"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error %q does not say %q", err, want)
			}
		}
	}
}

func TestEveryRepeatedByteSeedIsKnown(t *testing.T) {
	for b := 0; b < 256; b++ {
		seed := bytes.Repeat([]byte{byte(b)}, ed25519.SeedSize)
		private := ed25519.NewKeyFromSeed(seed)
		if err := knownkeys.Check("k", private.Public().(ed25519.PublicKey)); err == nil {
			t.Fatalf("public key of seed 0x%02x repeated accepted", b)
		}
		if err := knownkeys.CheckPrivate("k", seed); err == nil {
			t.Fatalf("seed 0x%02x repeated accepted", b)
		}
		if err := knownkeys.CheckPrivate("k", private); err == nil {
			t.Fatalf("64-byte private key of seed 0x%02x repeated accepted", b)
		}
	}
}

func TestCheckAcceptsAGeneratedKey(t *testing.T) {
	for i := 0; i < 64; i++ {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if err := knownkeys.Check("k", public); err != nil {
			t.Fatalf("generated key refused: %v", err)
		}
		if err := knownkeys.CheckPrivate("k", private.Seed()); err != nil {
			t.Fatalf("generated seed refused: %v", err)
		}
		if err := knownkeys.CheckPrivate("k", private); err != nil {
			t.Fatalf("generated private key refused: %v", err)
		}
	}
}

// A 64-byte private key carries its public key in its second half; a known
// seed beside another public key, and another seed beside a known public
// key, are both refused.
func TestCheckPrivateChecksBothHalvesOfA64BytePrivateKey(t *testing.T) {
	_, fresh, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	knownSeed := bytes.Repeat([]byte{0x11}, ed25519.SeedSize)
	knownSeedFreshPublic := append(append([]byte{}, knownSeed...), fresh[ed25519.SeedSize:]...)
	if err := knownkeys.CheckPrivate("k", knownSeedFreshPublic); err == nil {
		t.Fatal("known seed with another public half accepted")
	}
	freshSeedKnownPublic := append(append([]byte{}, fresh.Seed()...), mustHex(t, publishedAGSPublicKey)...)
	if err := knownkeys.CheckPrivate("k", freshSeedKnownPublic); err == nil {
		t.Fatal("fresh seed with a known public half accepted")
	}
}

// Lengths that are not an Ed25519 key are left to the caller's own check.
func TestCheckIgnoresOtherLengths(t *testing.T) {
	for _, b := range [][]byte{nil, {}, bytes.Repeat([]byte{0x11}, 31), bytes.Repeat([]byte{0x11}, 33), bytes.Repeat([]byte{0x11}, 63)} {
		if err := knownkeys.Check("k", b); err != nil {
			t.Fatalf("Check(%d bytes) = %v", len(b), err)
		}
		if err := knownkeys.CheckPrivate("k", b); err != nil {
			t.Fatalf("CheckPrivate(%d bytes) = %v", len(b), err)
		}
	}
}
