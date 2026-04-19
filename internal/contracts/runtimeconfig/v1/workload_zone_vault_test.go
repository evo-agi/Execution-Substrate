package runtimeconfig

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
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
	caBundle := testCertificatePEM(t)
	raw := []byte(`{
  "vault_config": {
    "address": "https://vault.internal:8200",
    "auth_mount": "jwt",
    "auth_role": "service_execution",
    "jwt_audience": "vault",
    "ca_bundle_pem": ` + strconvQuoteForJSON(caBundle) + `
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
	if !strings.Contains(blob.VaultConfig.CABundlePEM, "BEGIN CERTIFICATE") {
		t.Fatalf("expected CA bundle PEM to round trip, got %q", blob.VaultConfig.CABundlePEM)
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

func TestWorkloadZoneVaultConfigBlobRejectsInvalidCABundle(t *testing.T) {
	blob := WorkloadZoneVaultConfigBlob{
		VaultConfig: WorkloadZoneVaultConfig{
			Address:     "https://vault.internal:8200",
			AuthMount:   "jwt",
			AuthRole:    "service_execution",
			JWTAudience: "vault",
			CABundlePEM: "not pem",
		},
	}

	err := blob.Validate()
	if err == nil || !strings.Contains(err.Error(), "ca_bundle_pem") {
		t.Fatalf("expected ca_bundle_pem validation error, got %v", err)
	}
}

func testCertificatePEM(t *testing.T) string {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test CA key: %v", err)
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial number: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "test vault ca",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create test CA certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func strconvQuoteForJSON(value string) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}
