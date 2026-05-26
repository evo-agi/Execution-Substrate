package runtimeconfig

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"reflect"
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

func TestWorkloadZoneVaultConfigBlobCarriesOnlyNonSecretVaultMetadata(t *testing.T) {
	fieldNames := collectRuntimeConfigJSONFieldNames(t, WorkloadZoneVaultConfigRef{}, WorkloadZoneVaultConfigBlob{}, WorkloadZoneVaultConfig{})
	for _, forbidden := range []string{
		"vault_token",
		"client_token",
		"root_token",
		"unseal_key",
		"jwt_svid",
		"x509_svid",
		"private_key",
		"api_key",
		"proof_secret",
		"secret_payload",
		"lease_id",
		"lease_duration",
		"raw_spire_socket",
	} {
		if _, ok := fieldNames[forbidden]; ok {
			t.Fatalf("workload-zone Vault config must not expose token, secret, lease, or raw SPIRE field %q", forbidden)
		}
	}
	for _, required := range []string{
		"digest",
		"vault_config",
		"address",
		"auth_mount",
		"auth_role",
		"jwt_audience",
		"ca_bundle_pem",
	} {
		if _, ok := fieldNames[required]; !ok {
			t.Fatalf("expected non-secret workload-zone Vault metadata field %q", required)
		}
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

func collectRuntimeConfigJSONFieldNames(t *testing.T, values ...any) map[string]struct{} {
	t.Helper()

	names := map[string]struct{}{}
	seen := map[reflect.Type]bool{}
	for _, value := range values {
		collectRuntimeConfigJSONFieldNamesFromType(reflect.TypeOf(value), names, seen)
	}
	return names
}

func collectRuntimeConfigJSONFieldNamesFromType(typ reflect.Type, names map[string]struct{}, seen map[reflect.Type]bool) {
	for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct || seen[typ] {
		return
	}
	seen[typ] = true
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.PkgPath != "" {
			continue
		}
		tagName := strings.Split(field.Tag.Get("json"), ",")[0]
		if tagName != "" && tagName != "-" {
			names[tagName] = struct{}{}
		}
		collectRuntimeConfigJSONFieldNamesFromType(field.Type, names, seen)
	}
}
