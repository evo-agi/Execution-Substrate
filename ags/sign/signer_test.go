package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
)

// TestNewEd25519SignerRefusesA64ByteKeyWhoseHalvesDoNotBelongTogether: a
// 64-byte Ed25519 private key is a seed followed by its public key. Go signs
// with the seed and hashes the second half into every signature, and
// PrivateKey.Public returns the second half as it is. A key whose halves do
// not belong together signs nothing that verifies, and its signatures reveal
// the seed as soon as the same bytes are signed again under the right public
// key, so the signer refuses it (red-team RT75-2 of ES PR #75).
func TestNewEd25519SignerRefusesA64ByteKeyWhoseHalvesDoNotBelongTogether(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seedHex := hex.EncodeToString(private.Seed())

	// Both honest spellings of one key are accepted, and sign what verifies
	// under its public key.
	message := []byte("canonical bytes")
	for name, privateHex := range map[string]string{"seed": seedHex, "seed and its public key": hex.EncodeToString(private)} {
		signer, err := NewEd25519Signer("key", privateHex, hex.EncodeToString(public))
		if err != nil {
			t.Fatalf("%s refused: %v", name, err)
		}
		if !ed25519.Verify(public, message, ed25519.Sign(signer.privateKey, message)) {
			t.Fatalf("%s: the signature does not verify under its public key", name)
		}
	}
	// The seed followed by another public key is refused, whichever public
	// key signer.public_key_hex names.
	mismatched := seedHex + hex.EncodeToString(otherPublic)
	for name, publicHex := range map[string]string{"the stored half": hex.EncodeToString(otherPublic), "the seed's own public key": hex.EncodeToString(public)} {
		_, err := NewEd25519Signer("key", mismatched, publicHex)
		if err == nil || !strings.Contains(err.Error(), "second half is not the public key of its first half") {
			t.Errorf("signer.public_key_hex = %s: got %v, want the refusal of a key whose halves do not belong together", name, err)
		}
	}
}
