package runtimeconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestWorkloadZoneVaultConfigRefValidate(t *testing.T) {
	ref := WorkloadZoneVaultConfigRef{Digest: " sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef "}
	if err := ref.Validate(); err != nil {
		t.Fatalf("expected ref to validate, got %v", err)
	}
	if normalized := ref.Normalized(); normalized.Digest != "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Fatalf("unexpected normalized digest %q", normalized.Digest)
	}
}

func TestWorkloadZoneVaultConfigRefValidateRejectsInvalidDigest(t *testing.T) {
	err := WorkloadZoneVaultConfigRef{Digest: "sha256:not-a-real-digest"}.Validate()
	if err == nil || !strings.Contains(err.Error(), "labeled SHA-256 digest") {
		t.Fatalf("expected labeled digest error, got %v", err)
	}
}

func TestWorkloadZoneVaultConfigBlobJSONRoundTrip(t *testing.T) {
	raw := []byte(`{
  "vault_config": {
    "address": "https://vault.internal:8200",
    "auth_mount": "jwt",
    "auth_role": "service_execution",
    "jwt_audience": "vault"
  }
}`)

	var blob WorkloadZoneVaultConfigBlob
	if err := json.Unmarshal(raw, &blob); err != nil {
		t.Fatalf("decode blob: %v", err)
	}
	if err := blob.Validate(); err != nil {
		t.Fatalf("expected blob to validate, got %v", err)
	}

	if blob.VaultConfig.AuthRole != "service_execution" {
		t.Fatalf("unexpected auth role %q", blob.VaultConfig.AuthRole)
	}
}

func TestWorkloadZoneVaultConfigBlobRejectsMissingRole(t *testing.T) {
	blob := WorkloadZoneVaultConfigBlob{
		VaultConfig: WorkloadZoneVaultConfig{
			Address:     "https://vault.internal:8200",
			AuthMount:   "jwt",
			JWTAudience: "vault",
		},
	}

	err := blob.Validate()
	if err == nil || !strings.Contains(err.Error(), "auth role") {
		t.Fatalf("expected auth role validation error, got %v", err)
	}
}
