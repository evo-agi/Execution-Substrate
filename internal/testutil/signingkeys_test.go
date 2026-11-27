package testutil_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"testing"

	"execution-substrate/internal/knownkeys"
	"execution-substrate/internal/testutil"
)

// The keys of the repository's example configurations: seeds 0x11 and 0x33
// repeated.
const (
	exampleAGSPrivate = "1111111111111111111111111111111111111111111111111111111111111111"
	exampleAGSPublic  = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"
	exampleEGSPublic  = "17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce"
)

func signerDoc() map[string]any {
	return map[string]any{
		"signer": map[string]any{
			"algorithm":       "ed25519",
			"key_id":          "ags-key-1",
			"private_key_hex": exampleAGSPrivate,
			"public_key_hex":  exampleAGSPublic,
		},
	}
}

func verificationDoc() map[string]any {
	entry := func(keyID, public string) map[string]any {
		return map[string]any{"algorithm": "ed25519", "key_id": keyID, "public_key_hex": public}
	}
	return map[string]any{
		"verification": map[string]any{
			"trust_model":               entry("egs-key-1", exampleEGSPublic),
			"provenance":                entry("ags-key-1", exampleAGSPublic),
			"derivation_attestation":    entry("ags-key-1", exampleAGSPublic),
			"workload_identity_binding": entry("ags-key-1", exampleAGSPublic),
		},
	}
}

func field(t *testing.T, doc map[string]any, section, name, key string) string {
	t.Helper()
	group := doc[section].(map[string]any)
	if name != "" {
		group = group[name].(map[string]any)
	}
	value, ok := group[key].(string)
	if !ok {
		t.Fatalf("%s.%s.%s is not a string", section, name, key)
	}
	return value
}

func decodeKey(t *testing.T, label, value string) []byte {
	t.Helper()
	key, err := hex.DecodeString(value)
	if err != nil || len(key) != 32 {
		t.Fatalf("%s %q is not 32 bytes of hex", label, value)
	}
	return key
}

// TestWithFreshSigningKeysGivesEachKeyIDOneNewKey checks that the helper
// replaces every key with one no service refuses, keeps the key IDs, gives
// one key ID the same key across configurations within a test, and gives
// another test other keys.
func TestWithFreshSigningKeysGivesEachKeyIDOneNewKey(t *testing.T) {
	var firstProvenance string
	t.Run("one test", func(t *testing.T) {
		signer := testutil.WithFreshSigningKeys(t, signerDoc())
		verification := testutil.WithFreshSigningKeys(t, verificationDoc())

		if got := field(t, signer, "signer", "", "key_id"); got != "ags-key-1" {
			t.Fatalf("signer key_id = %q, want it kept", got)
		}
		seed := decodeKey(t, "signer.private_key_hex", field(t, signer, "signer", "", "private_key_hex"))
		public := decodeKey(t, "signer.public_key_hex", field(t, signer, "signer", "", "public_key_hex"))
		if derived := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey); string(derived) != string(public) {
			t.Fatal("signer.public_key_hex is not the public key of signer.private_key_hex")
		}
		if err := knownkeys.CheckPrivate("signer.private_key_hex", seed); err != nil {
			t.Fatal(err)
		}

		for _, name := range []string{"provenance", "derivation_attestation", "workload_identity_binding"} {
			if got := field(t, verification, "verification", name, "key_id"); got != "ags-key-1" {
				t.Fatalf("verification.%s.key_id = %q, want it kept", name, got)
			}
			if got := field(t, verification, "verification", name, "public_key_hex"); got != hex.EncodeToString(public) {
				t.Fatalf("verification.%s.public_key_hex = %s, want the signer's new public key %x", name, got, public)
			}
		}
		trust := decodeKey(t, "verification.trust_model.public_key_hex", field(t, verification, "verification", "trust_model", "public_key_hex"))
		if string(trust) == string(public) {
			t.Fatal("egs-key-1 got the same key as ags-key-1")
		}
		if got := field(t, verification, "verification", "trust_model", "key_id"); got != "egs-key-1" {
			t.Fatalf("verification.trust_model.key_id = %q, want it kept", got)
		}
		if err := knownkeys.Check("verification.trust_model.public_key_hex", trust); err != nil {
			t.Fatal(err)
		}

		// The same configuration built again in this test gets the same bytes.
		first, err := json.Marshal(verification)
		if err != nil {
			t.Fatal(err)
		}
		again, err := json.Marshal(testutil.WithFreshSigningKeys(t, verificationDoc()))
		if err != nil {
			t.Fatal(err)
		}
		if string(first) != string(again) {
			t.Fatal("building the same configuration twice in one test gave different keys")
		}
		firstProvenance = hex.EncodeToString(public)
	})
	t.Run("another test", func(t *testing.T) {
		verification := testutil.WithFreshSigningKeys(t, verificationDoc())
		if got := field(t, verification, "verification", "provenance", "public_key_hex"); got == firstProvenance {
			t.Fatal("another test got the same key for ags-key-1")
		}
	})
}
