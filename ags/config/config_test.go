package config

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"execution-substrate/internal/callerauth"
)

func validTestConfig(t *testing.T) Config {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	key := ed25519.NewKeyFromSeed(seed)
	return Config{
		HTTP:          HTTPConfig{BindAddress: "127.0.0.1", Port: 8444, ReadTimeoutSeconds: 5, WriteTimeoutSeconds: 5, ShutdownTimeoutSeconds: 5},
		TLS:           TLSConfig{CertFile: "/etc/ags/tls/server.pem", KeyFile: "/etc/ags/tls/server-key.pem", ClientCAFile: "/etc/ags/tls/client-ca.pem"},
		Security:      SecurityConfig{BootstrapIssuerCommonName: "bootstrap-ca"},
		Authorization: AuthorizationConfig{AllowedSPIFFEPathPrefixes: []string{"operator/local"}},
		Dependencies: DependenciesConfig{ArtifactRegistry: DependencyConfig{
			BaseURL:        "https://ars.internal:8443",
			ServerName:     "server.artifact-registry.internal",
			ClientCertFile: "/etc/ags/tls/client.pem",
			ClientKeyFile:  "/etc/ags/tls/client-key.pem",
			RootCAFile:     "/etc/ags/tls/runtime-ca.pem",
			TimeoutSeconds: 5,
		}},
		Signer: SignerConfig{
			Algorithm:     "ed25519",
			KeyID:         "ags-artifact-fact-signer",
			PrivateKeyHex: hex.EncodeToString(seed),
			PublicKeyHex:  hex.EncodeToString(key.Public().(ed25519.PublicKey)),
		},
	}
}

// security.namespace_issuers binds caller namespaces to client CAs; AGS
// refuses at startup any list the shared caller authentication rule refuses,
// and names the entry.
func TestSecurityNamespaceIssuersAreCheckedAtStartup(t *testing.T) {
	digestA := strings.Repeat("ab", 32)
	digestB := strings.Repeat("cd", 32)
	cfg := validTestConfig(t)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the test config is not valid: %v", err)
	}
	cfg.Security.NamespaceIssuers = []callerauth.NamespaceIssuerConfig{{PathPrefix: "user", IssuerCertificateSHA256: digestA}}
	path := filepath.Join(t.TempDir(), "ags.json")
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"namespace_issuers":[{"path_prefix":"user","issuer_certificate_sha256":"`+digestA+`"}]`) {
		t.Fatalf("security.namespace_issuers is not spelled as documented: %s", encoded)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load refuses a valid namespace_issuers list: %v", err)
	}
	issuers, err := loaded.Security.ParsedNamespaceIssuers()
	if err != nil || len(issuers) != 1 || issuers[0].PathPrefix() != "user" || issuers[0].CASHA256() != digestA {
		t.Fatalf("ParsedNamespaceIssuers = %v, %v", issuers, err)
	}

	cfg.Security.NamespaceIssuers = nil
	if issuers, err := cfg.Security.ParsedNamespaceIssuers(); err != nil || len(issuers) != 0 {
		t.Fatalf("no namespace_issuers: %v, %v", issuers, err)
	}

	for _, tc := range []struct {
		name    string
		entries []callerauth.NamespaceIssuerConfig
		want    string
	}{
		{"empty path", []callerauth.NamespaceIssuerConfig{{PathPrefix: "", IssuerCertificateSHA256: digestA}}, "security.namespace_issuers[0]: path_prefix"},
		{"leading slash", []callerauth.NamespaceIssuerConfig{{PathPrefix: "user", IssuerCertificateSHA256: digestA}, {PathPrefix: "/operator", IssuerCertificateSHA256: digestB}}, "security.namespace_issuers[1]: path_prefix"},
		{"upper-case digest", []callerauth.NamespaceIssuerConfig{{PathPrefix: "user", IssuerCertificateSHA256: strings.ToUpper(digestA)}}, "security.namespace_issuers[0]: issuer_certificate_sha256"},
		{"short digest", []callerauth.NamespaceIssuerConfig{{PathPrefix: "user", IssuerCertificateSHA256: digestA[:62]}}, "security.namespace_issuers[0]: issuer_certificate_sha256"},
		{"one CA for two namespaces", []callerauth.NamespaceIssuerConfig{{PathPrefix: "user", IssuerCertificateSHA256: digestA}, {PathPrefix: "operator", IssuerCertificateSHA256: digestA}}, "security.namespace_issuers: entries 0 and 1 bind the same CA"},
		{"nested namespaces", []callerauth.NamespaceIssuerConfig{{PathPrefix: "user", IssuerCertificateSHA256: digestA}, {PathPrefix: "user/team", IssuerCertificateSHA256: digestB}}, "security.namespace_issuers: entries 0 and 1 bind overlapping namespaces"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validTestConfig(t)
			cfg.Security.NamespaceIssuers = tc.entries
			err := cfg.Validate()
			if err == nil || !strings.HasPrefix(err.Error(), tc.want) {
				t.Fatalf("Validate = %v, want an error starting %q", err, tc.want)
			}
		})
	}

	var raw map[string]any
	if err := json.Unmarshal(encoded, &raw); err != nil {
		t.Fatal(err)
	}
	raw["security"].(map[string]any)["namespace_issuers"] = []any{map[string]any{"path_prefix": "user", "issuer_certificate_sha256": digestA, "issuer": "x"}}
	extra, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, extra, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), `unknown field "issuer"`) {
		t.Fatalf("Load accepts an unknown field in a namespace_issuers entry: %v", err)
	}
}
