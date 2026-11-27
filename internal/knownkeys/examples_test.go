package knownkeys_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	agsconfig "execution-substrate/ags/config"
	egsconfig "execution-substrate/egs/config"
	esconfig "execution-substrate/es/config"
	"execution-substrate/internal/testutil"
)

// exampleLoaders are the example configurations that carry signing or
// verification keys, with the loader of the service that reads each, and the
// field whose key the loader refuses first.
var exampleLoaders = []struct {
	name  string
	load  func(string) error
	field string
}{
	{"ags.json", func(p string) error { _, err := agsconfig.Load(p); return err }, "signer.private_key_hex"},
	{"ags.operator_and_control_plane.json", func(p string) error { _, err := agsconfig.Load(p); return err }, "signer.private_key_hex"},
	{"egs.json", func(p string) error { _, err := egsconfig.Load(p); return err }, "signer.private_key_hex"},
	{"es.json", func(p string) error { _, err := esconfig.Load(p); return err }, "verification.trust_model.public_key_hex"},
	{"es.operator_and_control_plane.json", func(p string) error { _, err := esconfig.Load(p); return err }, "verification.trust_model.public_key_hex"},
	{"es.configured_literal_policy_demo.json", func(p string) error { _, err := esconfig.Load(p); return err }, "verification.trust_model.public_key_hex"},
}

// TestExampleConfigurationsCarryOnlyKeysTheirServiceRefuses: the example
// configurations are templates. Their keys are known keys, so a host that
// copies one as it is fails at startup with the known-key error and nothing
// else; with fresh keys, each example is a configuration its service
// accepts.
func TestExampleConfigurationsCarryOnlyKeysTheirServiceRefuses(t *testing.T) {
	for _, example := range exampleLoaders {
		t.Run(example.name, func(t *testing.T) {
			raw := testutil.Read(t, filepath.Join(".examples", "config", example.name))
			dir := t.TempDir()

			asIs := filepath.Join(dir, "as-is.json")
			if err := os.WriteFile(asIs, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			err := example.load(asIs)
			if err == nil || !strings.Contains(err.Error(), example.field+" is a known key") {
				t.Fatalf("example as it is: got %v, want the known-key error for %s", err, example.field)
			}

			var doc map[string]any
			if err := json.Unmarshal([]byte(raw), &doc); err != nil {
				t.Fatal(err)
			}
			fresh, err := json.Marshal(testutil.WithFreshSigningKeys(t, doc))
			if err != nil {
				t.Fatal(err)
			}
			freshPath := filepath.Join(dir, "fresh.json")
			if err := os.WriteFile(freshPath, fresh, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := example.load(freshPath); err != nil {
				t.Fatalf("example with fresh keys refused: %v", err)
			}
		})
	}
}

// TestEveryExampleWithKeysIsChecked keeps exampleLoaders complete: an
// example configuration that names a signing or verification key and is not
// in the list fails here.
func TestEveryExampleWithKeysIsChecked(t *testing.T) {
	listed := map[string]bool{}
	for _, example := range exampleLoaders {
		listed[example.name] = true
	}
	entries, err := os.ReadDir(testutil.Path(filepath.Join(".examples", "config")))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		data := testutil.Read(t, filepath.Join(".examples", "config", entry.Name()))
		if strings.Contains(data, "_key_hex") && !listed[entry.Name()] {
			t.Errorf(".examples/config/%s names a key but TestExampleConfigurationsCarryOnlyKeysTheirServiceRefuses does not load it", entry.Name())
		}
	}
}

// TestEachKeyFieldIsChecked puts a known key into one field at a time of an
// example that otherwise has fresh keys, and requires the service to refuse
// that field. A 64-byte private key whose seed is known is refused as well.
func TestEachKeyFieldIsChecked(t *testing.T) {
	const (
		knownSeed   = "1111111111111111111111111111111111111111111111111111111111111111"
		knownPublic = publishedEGSPublicKey
	)
	load := map[string]func(string) error{}
	for _, example := range exampleLoaders {
		load[example.name] = example.load
	}
	cases := []struct {
		example string
		path    []string
		value   string
		field   string
	}{
		{"ags.json", []string{"signer", "private_key_hex"}, knownSeed, "signer.private_key_hex"},
		{"ags.json", []string{"signer", "private_key_hex"}, knownSeed + publishedAGSPublicKey, "signer.private_key_hex"},
		{"ags.json", []string{"signer", "public_key_hex"}, knownPublic, "signer.public_key_hex"},
		{"egs.json", []string{"signer", "private_key_hex"}, knownSeed, "signer.private_key_hex"},
		{"egs.json", []string{"signer", "public_key_hex"}, knownPublic, "signer.public_key_hex"},
		{"es.json", []string{"verification", "trust_model", "public_key_hex"}, knownPublic, "verification.trust_model.public_key_hex"},
		{"es.json", []string{"verification", "provenance", "public_key_hex"}, knownPublic, "verification.provenance.public_key_hex"},
		{"es.json", []string{"verification", "derivation_attestation", "public_key_hex"}, knownPublic, "verification.derivation_attestation.public_key_hex"},
		{"es.json", []string{"verification", "workload_identity_binding", "public_key_hex"}, knownPublic, "verification.workload_identity_binding.public_key_hex"},
	}
	for _, c := range cases {
		t.Run(c.field+"/"+c.example+"/"+hex8(c.value), func(t *testing.T) {
			var doc map[string]any
			if err := json.Unmarshal([]byte(testutil.Read(t, filepath.Join(".examples", "config", c.example))), &doc); err != nil {
				t.Fatal(err)
			}
			testutil.WithFreshSigningKeys(t, doc)
			node := doc
			for _, key := range c.path[:len(c.path)-1] {
				node = node[key].(map[string]any)
			}
			node[c.path[len(c.path)-1]] = c.value
			data, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), c.example)
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			err = load[c.example](path)
			if err == nil || !strings.Contains(err.Error(), c.field+" is a known key") {
				t.Fatalf("got %v, want the known-key error for %s", err, c.field)
			}
		})
	}
}

func hex8(s string) string {
	if len(s) > 8 {
		return s[:8] + "-" + strings.Repeat("x", len(s)/64)
	}
	return s
}
