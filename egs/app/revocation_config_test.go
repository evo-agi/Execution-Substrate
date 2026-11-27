package app_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"execution-substrate/egs/app"
	"execution-substrate/egs/config"
)

// The revocation runbook (.runbooks/system/Governed Execution ES Revoke An
// Artifact Or Signer.md) says EGS refuses to start on a bad revocation entry or
// an unknown field, and names what its journal shows. cmd/egs/main.go starts
// with config.Load and then app.New, so both must refuse.
func TestEGSRefusesToStartOnEntriesTheRevocationRunbookWarnsAbout(t *testing.T) {
	t.Parallel()

	fixture := newTLSFixture(t)
	cases := []struct {
		name   string
		change func(cfg *config.Config)
		want   string
	}{
		{"unlabeled digest", func(cfg *config.Config) {
			cfg.RuntimeTrust.ArtifactPolicy.RevokedArtifacts = []string{strings.Repeat("a", 64)}
		}, `runtime_trust.artifact_policy.revoked_artifacts must contain labeled sha256 digests in lower-case hex (sha256: and 64 lower-case hex characters); got "` + strings.Repeat("a", 64) + `"`},
		{"upper-case digest", func(cfg *config.Config) {
			cfg.RuntimeTrust.ArtifactPolicy.RevokedArtifacts = []string{"sha256:" + strings.Repeat("A", 64)}
		}, `runtime_trust.artifact_policy.revoked_artifacts must contain labeled sha256 digests in lower-case hex (sha256: and 64 lower-case hex characters); got "sha256:` + strings.Repeat("A", 64) + `"`},
		{"duplicate revoked signer", func(cfg *config.Config) {
			cfg.RuntimeTrust.SignerPolicy.RevokedSigners = []string{"k1", "k1"}
		}, "runtime_trust.signer_policy.revoked_signers cannot contain duplicate values"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := buildConfig(fixture)
			tc.change(&cfg)
			if _, err := config.Load(writeConfig(t, cfg)); err == nil || err.Error() != tc.want {
				t.Fatalf("config.Load() = %v, want %q", err, tc.want)
			}
			if _, err := app.New(cfg); err == nil || err.Error() != tc.want {
				t.Fatalf("app.New() = %v, want %q", err, tc.want)
			}
		})
	}

	t.Run("unknown field", func(t *testing.T) {
		payload, err := json.Marshal(buildConfig(fixture))
		if err != nil {
			t.Fatalf("marshal config: %v", err)
		}
		var doc map[string]any
		if err := json.Unmarshal(payload, &doc); err != nil {
			t.Fatalf("unmarshal config: %v", err)
		}
		doc["runtime_trust"].(map[string]any)["revoked_keys"] = []string{"k1"}
		payload, err = json.Marshal(doc)
		if err != nil {
			t.Fatalf("marshal config: %v", err)
		}
		path := filepath.Join(t.TempDir(), "egs.json")
		if err := os.WriteFile(path, payload, 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		if _, err := config.Load(path); err == nil || !strings.HasPrefix(err.Error(), `decode config: json: unknown field "revoked_keys"`) {
			t.Fatalf("config.Load() = %v, want an unknown-field decode error", err)
		}
	})
}
