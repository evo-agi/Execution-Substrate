package admission

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	egsmodel "execution-substrate/egs/model"
	esconfig "execution-substrate/es/config"
	runtimeconfigv1 "execution-substrate/internal/contracts/runtimeconfig/v1"
)

func TestValidateExecutionRuntimeInputsAcceptsRegularBinaryWithoutLiveSPIRESocketAccess(t *testing.T) {
	rootDir, err := os.MkdirTemp("/tmp", "es-admission-")
	if err != nil {
		t.Fatalf("mkdir temp root: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(rootDir)
	})

	binaryPath := filepath.Join(rootDir, "es-runtime-support")
	if err := os.WriteFile(binaryPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write runtime support binary: %v", err)
	}

	err = validateExecutionRuntimeInputs(esconfig.ExecutionConfig{
		RuntimeSupportBinary:       binaryPath,
		SPIREWorkloadAPISocketPath: filepath.Join(rootDir, "missing-spire.sock"),
	})
	if err != nil {
		t.Fatalf("expected runtime inputs to validate, got %v", err)
	}
}

func TestValidateExecutionRuntimeInputsRejectsNonRegularBinary(t *testing.T) {
	rootDir, err := os.MkdirTemp("/tmp", "es-admission-")
	if err != nil {
		t.Fatalf("mkdir temp root: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(rootDir)
	})

	binaryPath := filepath.Join(rootDir, "runtime-support-dir")
	if err := os.MkdirAll(binaryPath, 0o755); err != nil {
		t.Fatalf("mkdir runtime support dir: %v", err)
	}

	err = validateExecutionRuntimeInputs(esconfig.ExecutionConfig{
		RuntimeSupportBinary:       binaryPath,
		SPIREWorkloadAPISocketPath: filepath.Join(rootDir, "ignored-spire.sock"),
	})
	if err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("expected regular file validation error, got %v", err)
	}
}

func TestValidateExecutionRuntimeInputsRejectsNonAbsoluteSPIRESocketPath(t *testing.T) {
	rootDir, err := os.MkdirTemp("/tmp", "es-admission-")
	if err != nil {
		t.Fatalf("mkdir temp root: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(rootDir)
	})

	binaryPath := filepath.Join(rootDir, "es-runtime-support")
	if err := os.WriteFile(binaryPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write runtime support binary: %v", err)
	}

	err = validateExecutionRuntimeInputs(esconfig.ExecutionConfig{
		RuntimeSupportBinary:       binaryPath,
		SPIREWorkloadAPISocketPath: "relative/spire.sock",
	})
	if err == nil || !strings.Contains(err.Error(), "spire_workload_api_socket_path") {
		t.Fatalf("expected SPIRE path shape validation error, got %v", err)
	}
}

func TestValidatePrepareRequestDefaultsVersionsAndRejectsInvalidInputs(t *testing.T) {
	req := PrepareRequest{
		Invocation: ArtifactInvocation{
			ArtifactDigest:       "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			DerivationSpecDigest: "sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
			OutputID:             "result",
		},
	}
	if err := validatePrepareRequest(&req); err != nil {
		t.Fatalf("expected prepare request to validate, got %v", err)
	}
	if req.SchemaVersion != "v1" || req.Invocation.SchemaVersion != "v1" {
		t.Fatalf("expected schema versions to default to v1, got %+v", req)
	}

	invalid := req
	invalid.Mode = "unsupported"
	err := validatePrepareRequest(&invalid)
	if err == nil || err.Code != codeInvalidRequest || !strings.Contains(err.Message, "mode must be sync or async") {
		t.Fatalf("expected mode validation error, got %+v", err)
	}
}

func TestValidateInvocationAgainstManifestRejectsReservedAndUndeclaredEnv(t *testing.T) {
	manifest := Manifest{
		ArtifactDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		RuntimeInterface: RuntimeInterface{
			EnvironmentVariables: []string{"ALLOWED_ENV"},
		},
	}

	err := validateInvocationAgainstManifest(ArtifactInvocation{
		ArtifactDigest: manifest.ArtifactDigest,
		Env: map[string]string{
			runtimeIdentityEndpointEnvKey: "unix:///tmp/socket",
		},
	}, manifest)
	if err == nil || !strings.Contains(err.Message, "reserved") {
		t.Fatalf("expected reserved env rejection, got %+v", err)
	}

	err = validateInvocationAgainstManifest(ArtifactInvocation{
		ArtifactDigest: manifest.ArtifactDigest,
		Env: map[string]string{
			"NOT_ALLOWED": "1",
		},
	}, manifest)
	if err == nil || !strings.Contains(err.Message, "not allowed by the runtime interface") {
		t.Fatalf("expected undeclared env rejection, got %+v", err)
	}
}

func TestVerifyTrustModelEnvelopeAcceptsSignedCanonicalAndIgnoresPublication(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate ed25519 keypair: %v", err)
	}
	model := egsmodel.RuntimeTrustPolicy{
		SignerPolicy: egsmodel.SignerPolicy{
			AllowedSigners: []string{"ags-signer"},
		},
	}
	canonical, err := model.CanonicalBytes()
	if err != nil {
		t.Fatalf("canonical bytes: %v", err)
	}

	service := Service{
		trustModelVerifier: &ed25519Verifier{
			algorithm: "ed25519",
			keyID:     "egs-signer",
			publicKey: publicKey,
		},
	}
	payload := signedRuntimeTrustResponse{
		RuntimeTrust:  model,
		Algorithm:     "ed25519",
		KeyID:         "egs-signer",
		PayloadDigest: digestBytes(canonical),
		Signature:     base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical)),
		Publication:   json.RawMessage(`{"version":"ignored","update_revision":7}`),
	}

	if err := service.verifyTrustModelEnvelope(payload, canonical); err != nil {
		t.Fatalf("expected trust model envelope verification to succeed, got %v", err)
	}

	payload.PayloadDigest = "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	if err := service.verifyTrustModelEnvelope(payload, canonical); err == nil || !strings.Contains(err.Error(), "payload digest mismatch") {
		t.Fatalf("expected payload digest mismatch, got %v", err)
	}
}

func TestEnforceTrustModelRejectsDisallowedRevokedAndRevokedArtifact(t *testing.T) {
	err := enforceTrustModel(egsmodel.RuntimeTrustPolicy{
		SignerPolicy: egsmodel.SignerPolicy{
			AllowedSigners: []string{"allowed"},
		},
	}, "other", "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err == nil || err.Code != codeSignerNotAllowed {
		t.Fatalf("expected signer-not-allowed error, got %+v", err)
	}

	err = enforceTrustModel(egsmodel.RuntimeTrustPolicy{
		SignerPolicy: egsmodel.SignerPolicy{
			AllowedSigners: []string{"allowed"},
			RevokedSigners: []string{"allowed"},
		},
	}, "allowed", "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err == nil || err.Code != codeSignerRevoked {
		t.Fatalf("expected signer-revoked error, got %+v", err)
	}

	err = enforceTrustModel(egsmodel.RuntimeTrustPolicy{
		SignerPolicy: egsmodel.SignerPolicy{
			AllowedSigners: []string{"allowed"},
		},
		ArtifactPolicy: egsmodel.ArtifactPolicy{
			RevokedArtifacts: []string{"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		},
	}, "allowed", "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err == nil || err.Code != codeArtifactRevoked {
		t.Fatalf("expected artifact-revoked error, got %+v", err)
	}
}

func TestHealthReflectsArtifactRegistryReadinessAndLoadedTrustModel(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"status":"healthy","ready":true}`))
	}))
	defer server.Close()

	baseURL := mustParseURL(t, server.URL)
	service := Service{
		arsClient: &dependencyClient{
			dependencyName: "artifact-registry",
			baseURL:        baseURL,
			client: &http.Client{
				Timeout:   time.Second,
				Transport: server.Client().Transport,
			},
		},
		trustModel: &egsmodel.RuntimeTrustPolicy{},
	}

	health := service.Health(context.Background())
	if !health.ArtifactRegistryHealthy || !health.TrustModelLoaded {
		t.Fatalf("expected health to reflect ready ARS and loaded trust model, got %+v", health)
	}
}

func TestFetchWorkloadZoneVaultConfigDecodesValidBlobAndRejectsInvalidBlob(t *testing.T) {
	var payload string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/blobs/sha256:") || !strings.HasSuffix(r.URL.Path, ":json") {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(payload))
	}))
	defer server.Close()

	service := Service{
		arsClient: &dependencyClient{
			dependencyName: "artifact-registry",
			baseURL:        mustParseURL(t, server.URL),
			client: &http.Client{
				Timeout:   time.Second,
				Transport: server.Client().Transport,
			},
		},
	}
	ref := runtimeconfigv1.WorkloadZoneVaultConfigRef{
		Digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}

	payload = `{"vault_config":{"address":"https://vault.internal:8200","auth_mount":"jwt","auth_role":"execution","jwt_audience":"vault"}}`
	config, err := service.fetchWorkloadZoneVaultConfig(context.Background(), ref)
	if err != nil {
		t.Fatalf("expected workload-zone vault config fetch to succeed, got %+v", err)
	}
	if config.Address != "https://vault.internal:8200" || config.AuthRole != "execution" {
		t.Fatalf("unexpected workload-zone vault config %+v", config)
	}

	payload = `{"vault_config":{"address":"http://bad","auth_mount":"","auth_role":"","jwt_audience":""}}`
	_, err = service.fetchWorkloadZoneVaultConfig(context.Background(), ref)
	if err == nil || err.Code != codeWorkloadZoneVaultUnavailable {
		t.Fatalf("expected invalid workload-zone vault blob to map to unavailable, got %+v", err)
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()

	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url %q: %v", raw, err)
	}
	return parsed
}
