package app_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	acsapp "execution-platform/acs/app"
	acscatalog "execution-platform/acs/catalog"
	acsconfig "execution-platform/acs/config"
	arsapp "execution-platform/ars/app"
	arsconfig "execution-platform/ars/config"
	arsindex "execution-platform/ars/index"
	arsstore "execution-platform/ars/store"
	egsapp "execution-platform/egs/app"
	egsconfig "execution-platform/egs/config"
	egsmodel "execution-platform/egs/model"
	"execution-platform/es/admission"
	esapp "execution-platform/es/app"
	esconfig "execution-platform/es/config"
)

func TestPrepareFlowReturnsAdmissionFacts(t *testing.T) {
	stack := startStack(t, stackOptions{})

	response := doJSONRequest(t, stack.es.Addr(), http.MethodPost, "/v1/executions:prepare", stack.fixture.clientTLSConfig(t, "service/deployment", false), buildPrepareRequestBody(t, stack))
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}

	var payload admission.PrepareResult
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode prepare response: %v", err)
	}

	if !payload.Success {
		t.Fatalf("expected success response")
	}
	if payload.ArtifactDigest != stack.artifactDigest {
		t.Fatalf("unexpected artifact digest: %q", payload.ArtifactDigest)
	}
	if payload.IntentDigest != stack.intentDigest {
		t.Fatalf("unexpected intent digest: %q", payload.IntentDigest)
	}
	if payload.TrustModel.Version != "1.0.0" || payload.TrustModel.UpdateRevision != 7 {
		t.Fatalf("unexpected trust model info: %+v", payload.TrustModel)
	}
	if payload.Provenance.SignerKeyID != stack.fixture.agsKeyID {
		t.Fatalf("unexpected provenance signer: %q", payload.Provenance.SignerKeyID)
	}
	if payload.Workload.WorkloadIdentityID != stack.workloadIdentityID {
		t.Fatalf("unexpected workload identity: %q", payload.Workload.WorkloadIdentityID)
	}
	if payload.WorkloadVault.Digest != stack.workloadZoneVaultDigest {
		t.Fatalf("unexpected workload vault digest: %q", payload.WorkloadVault.Digest)
	}
	if payload.WorkloadVault.AuthMode != string(esconfig.WorkloadVaultAuthModeVaultIdentityJWT) {
		t.Fatalf("unexpected auth mode: %q", payload.WorkloadVault.AuthMode)
	}
	if payload.WorkloadVault.AuthMount != "jwt" || payload.WorkloadVault.AuthRole != "service_execution" || payload.WorkloadVault.JWTAudience != "vault" {
		t.Fatalf("unexpected workload vault plan: %+v", payload.WorkloadVault)
	}
}

func TestPrepareReturns404WhenManifestIsMissing(t *testing.T) {
	stack := startStack(t, stackOptions{MissingManifest: true})
	assertPrepareError(t, stack, http.StatusNotFound, codeManifestNotFound)
}

func TestPrepareReturns404WhenProvenanceIsMissing(t *testing.T) {
	stack := startStack(t, stackOptions{MissingProvenance: true})
	assertPrepareError(t, stack, http.StatusNotFound, codeProvenanceNotFound)
}

func TestPrepareReturns404WhenDerivationMetadataIsMissing(t *testing.T) {
	stack := startStack(t, stackOptions{MissingDerivationMetadata: true})
	assertPrepareError(t, stack, http.StatusNotFound, codeDerivationMetadataNotFound)
}

func TestPrepareReturns404WhenWorkloadIdentityBindingIsMissing(t *testing.T) {
	stack := startStack(t, stackOptions{MissingBinding: true})
	assertPrepareError(t, stack, http.StatusNotFound, codeBindingNotFound)
}

func TestPrepareReturns404WhenDerivationAttestationIsMissing(t *testing.T) {
	stack := startStack(t, stackOptions{MissingAttestation: true})
	assertPrepareError(t, stack, http.StatusNotFound, codeAttestationNotFound)
}

func TestPrepareReturns403WhenSignerIsNotAllowed(t *testing.T) {
	stack := startStack(t, stackOptions{DisallowedSigner: true})
	assertPrepareError(t, stack, http.StatusForbidden, codeSignerNotAllowed)
}

func TestPrepareReturns403WhenSignerIsRevoked(t *testing.T) {
	stack := startStack(t, stackOptions{RevokedSigner: true})
	assertPrepareError(t, stack, http.StatusForbidden, codeSignerRevoked)
}

func TestPrepareReturns403WhenArtifactIsRevoked(t *testing.T) {
	stack := startStack(t, stackOptions{RevokedArtifact: true})
	assertPrepareError(t, stack, http.StatusForbidden, codeArtifactRevoked)
}

func TestPrepareRejectsLegacyAuthModeForThisSlice(t *testing.T) {
	stack := startStack(t, stackOptions{DefaultAuthMode: esconfig.WorkloadVaultAuthModeCGSProofLegacy})
	assertPrepareError(t, stack, http.StatusConflict, codeUnsupportedAuthMode)
}

func TestPrepareReturns503WhenACSIsUnavailable(t *testing.T) {
	stack := startStack(t, stackOptions{})
	stack.shutdownACS(t)
	assertPrepareError(t, stack, http.StatusServiceUnavailable, codeWorkloadZoneVaultUnavailable)
}

func TestPrepareReturns503WhenVaultBlobIsMissing(t *testing.T) {
	stack := startStack(t, stackOptions{MissingVaultBlob: true})
	assertPrepareError(t, stack, http.StatusServiceUnavailable, codeWorkloadZoneVaultUnavailable)
}

func TestPrepareReturns503WhenVaultBlobIsCorrupt(t *testing.T) {
	stack := startStack(t, stackOptions{CorruptVaultBlob: true})
	assertPrepareError(t, stack, http.StatusServiceUnavailable, codeWorkloadZoneVaultUnavailable)
}

func TestPrepareReturns503WhenManifestBlobIsCorrupt(t *testing.T) {
	stack := startStack(t, stackOptions{CorruptManifest: true})
	assertPrepareError(t, stack, http.StatusServiceUnavailable, codeManifestNotFound)
}

func TestPrepareReturns503WhenProvenanceBlobIsCorrupt(t *testing.T) {
	stack := startStack(t, stackOptions{CorruptProvenance: true})
	assertPrepareError(t, stack, http.StatusServiceUnavailable, codeProvenanceNotFound)
}

func TestPrepareReturns503WhenDerivationAttestationBlobIsCorrupt(t *testing.T) {
	stack := startStack(t, stackOptions{CorruptAttestation: true})
	assertPrepareError(t, stack, http.StatusServiceUnavailable, codeAttestationNotFound)
}

func TestStartFailsWhenTrustModelVerificationIsInvalid(t *testing.T) {
	stack := startDependencyStack(t, stackOptions{})
	defer stack.shutdownAll(t)

	cfg := buildESConfig(stack, func(cfg *esconfig.Config) {
		otherPublicKey := make([]byte, ed25519.PublicKeySize)
		if _, err := rand.Read(otherPublicKey); err != nil {
			t.Fatalf("generate wrong trust-model verifier key: %v", err)
		}
		cfg.Verification.TrustModel.PublicKeyHex = hex.EncodeToString(otherPublicKey)
	})

	service, err := esapp.New(cfg)
	if err != nil {
		t.Fatalf("build es app: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := service.Start(ctx); err == nil || !strings.Contains(err.Error(), "verify trust model") {
		t.Fatalf("expected trust-model verification startup failure, got %v", err)
	}
}

func TestPrepareReturns401WhenCallerIdentityIsMissing(t *testing.T) {
	stack := startStack(t, stackOptions{})

	response := doJSONRequest(t, stack.es.Addr(), http.MethodPost, "/v1/executions:prepare", stack.fixture.clientTLSConfig(t, "", false), buildPrepareRequestBody(t, stack))
	defer response.Body.Close()

	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", response.StatusCode)
	}
	if got := strings.TrimSpace(string(mustReadBody(t, response.Body))); got != "Authenticated caller identity required" {
		t.Fatalf("unexpected body: %q", got)
	}
}

func TestPrepareReturns403WhenCallerIsDisallowed(t *testing.T) {
	stack := startStack(t, stackOptions{})

	response := doJSONRequest(t, stack.es.Addr(), http.MethodPost, "/v1/executions:prepare", stack.fixture.clientTLSConfig(t, "service/execution", false), buildPrepareRequestBody(t, stack))
	defer response.Body.Close()

	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", response.StatusCode)
	}
	if got := strings.TrimSpace(string(mustReadBody(t, response.Body))); got != "Caller not authorized for this operation" {
		t.Fatalf("unexpected body: %q", got)
	}
}

func TestPrepareReturns403WhenBootstrapPKICallerIsUsed(t *testing.T) {
	stack := startStack(t, stackOptions{})

	response := doJSONRequest(t, stack.es.Addr(), http.MethodPost, "/v1/executions:prepare", stack.fixture.clientTLSConfig(t, "service/deployment", true), buildPrepareRequestBody(t, stack))
	defer response.Body.Close()

	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", response.StatusCode)
	}
	if got := strings.TrimSpace(string(mustReadBody(t, response.Body))); got != "Bootstrap PKI callers are not accepted; use a SPIRE-issued identity" {
		t.Fatalf("unexpected body: %q", got)
	}
}

func TestPrepareReturns400WhenArtifactDigestIsInvalid(t *testing.T) {
	stack := startStack(t, stackOptions{})

	body := buildPrepareRequest(t, stack, func(request *admission.PrepareRequest) {
		request.Invocation.ArtifactDigest = "not-a-digest"
	})
	assertPrepareErrorForBody(t, stack, body, http.StatusBadRequest, codeInvalidRequest)
}

func TestPrepareReturns400WhenReservedRuntimeEnvKeyIsProvided(t *testing.T) {
	stack := startStack(t, stackOptions{})

	body := buildPrepareRequest(t, stack, func(request *admission.PrepareRequest) {
		request.Invocation.Env["VAULT_ADDR"] = "https://vault.internal:8200"
	})
	assertPrepareErrorForBody(t, stack, body, http.StatusBadRequest, codeInvalidRequest)
}

func TestPrepareReturns400WhenJSONIsMalformed(t *testing.T) {
	stack := startStack(t, stackOptions{})

	response := doJSONRequest(t, stack.es.Addr(), http.MethodPost, "/v1/executions:prepare", stack.fixture.clientTLSConfig(t, "service/deployment", false), []byte(`{"schema_version":"v1"`))
	defer response.Body.Close()

	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", response.StatusCode)
	}
	var payload admission.ErrorResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if payload.Code != codeInvalidRequest || payload.Success {
		t.Fatalf("unexpected malformed-json response: %+v", payload)
	}
}

const (
	codeInvalidRequest               = "invalid_request"
	codeManifestNotFound             = "manifest_not_found"
	codeProvenanceNotFound           = "provenance_not_found"
	codeDerivationMetadataNotFound   = "derivation_metadata_not_found"
	codeBindingNotFound              = "workload_identity_binding_not_found"
	codeAttestationNotFound          = "derivation_attestation_not_found"
	codeSignerNotAllowed             = "signer_not_allowed"
	codeSignerRevoked                = "signer_revoked"
	codeArtifactRevoked              = "artifact_revoked"
	codeUnsupportedAuthMode          = "unsupported_auth_mode"
	codeWorkloadZoneVaultUnavailable = "workload_zone_vault_unavailable"
)

type stackOptions struct {
	MissingManifest           bool
	MissingProvenance         bool
	MissingDerivationMetadata bool
	MissingBinding            bool
	MissingAttestation        bool
	MissingVaultBlob          bool
	CorruptVaultBlob          bool
	CorruptManifest           bool
	CorruptProvenance         bool
	CorruptAttestation        bool
	DisallowedSigner          bool
	RevokedSigner             bool
	RevokedArtifact           bool
	DefaultAuthMode           esconfig.WorkloadVaultAuthMode
}

type testStack struct {
	fixture *tlsFixture

	acs *acsapp.App
	ars *arsapp.App
	egs *egsapp.App
	es  *esapp.App

	acsRunning bool
	arsRunning bool
	egsRunning bool
	esRunning  bool

	artifactDigest          string
	intentDigest            string
	workloadIdentityID      string
	workloadZoneVaultDigest string
}

func startStack(t *testing.T, opts stackOptions) *testStack {
	t.Helper()

	stack := startDependencyStack(t, opts)
	cfg := buildESConfig(stack, func(cfg *esconfig.Config) {
		if opts.DefaultAuthMode != "" {
			cfg.WorkloadVaultAuth.DefaultMode = opts.DefaultAuthMode
		}
	})

	service, err := esapp.New(cfg)
	if err != nil {
		t.Fatalf("build es app: %v", err)
	}
	stack.es = service

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := service.Start(ctx); err != nil {
		t.Fatalf("start es app: %v", err)
	}
	stack.esRunning = true
	t.Cleanup(func() { stack.shutdownAll(t) })

	waitForHealthy(t, service.Addr(), stack.fixture.clientTLSConfig(t, "", false))
	return stack
}

func startDependencyStack(t *testing.T, opts stackOptions) *testStack {
	t.Helper()

	fixture := newTLSFixture(t)
	rootDir := filepath.Join(t.TempDir(), "ars-storage")
	if err := os.MkdirAll(rootDir, 0o755); err != nil {
		t.Fatalf("mkdir ars storage root: %v", err)
	}

	stack := &testStack{
		fixture: fixture,
	}

	artifactDigest := labeledDigest("aa")
	intentDigest := labeledDigest("bb")
	derivationSpecDigest := labeledDigest("cc")
	workloadIdentityID := "spiffe://monolith.internal/service/execution"

	manifestBytes := mustMarshalJSON(t, map[string]any{
		"artifact_digest": artifactDigest,
		"artifact_type":   "static-service",
		"intent_digest":   intentDigest,
		"runtime_interface": map[string]any{
			"parameters":            []string{},
			"environment_variables": []string{"APP_MODE"},
			"required_capabilities": []string{},
		},
	})
	manifestDigest := writeBlobBytes(t, rootDir, manifestBytes)

	provenanceBytes := signedProvenanceJSON(t, fixture, artifactDigest)
	provenanceDigest := writeBlobBytes(t, rootDir, provenanceBytes)

	derivationMetadataBytes := mustMarshalJSON(t, map[string]any{
		"derivation_spec_digest": derivationSpecDigest,
		"output_id":              "runtime",
		"producer_run_id":        "build-run-1",
	})
	derivationMetadataDigest := writeBlobBytes(t, rootDir, derivationMetadataBytes)

	derivationAttestationBytes := signedDerivationAttestationJSON(t, fixture, artifactDigest, derivationSpecDigest)
	derivationAttestationDigest := writeBlobBytes(t, rootDir, derivationAttestationBytes)

	bindingBytes := signedWorkloadIdentityBindingJSON(t, fixture, artifactDigest, derivationSpecDigest, workloadIdentityID)
	bindingDigest := writeBlobBytes(t, rootDir, bindingBytes)

	payloadDigest := writeBlobBytes(t, rootDir, []byte("artifact payload bytes"))

	workloadZoneVaultBytes := mustMarshalJSON(t, map[string]any{
		"vault_config": map[string]any{
			"address":      "https://vault.internal:8200",
			"auth_mount":   "jwt",
			"auth_role":    "service_execution",
			"jwt_audience": "vault",
		},
	})
	workloadZoneVaultDigest := writeBlobBytes(t, rootDir, workloadZoneVaultBytes)

	if opts.MissingManifest {
		removeBlob(t, rootDir, manifestDigest)
	}
	if opts.MissingProvenance {
		removeBlob(t, rootDir, provenanceDigest)
	}
	if opts.MissingDerivationMetadata {
		removeBlob(t, rootDir, derivationMetadataDigest)
	}
	if opts.MissingBinding {
		removeBlob(t, rootDir, bindingDigest)
	}
	if opts.MissingAttestation {
		removeBlob(t, rootDir, derivationAttestationDigest)
	}
	if opts.MissingVaultBlob {
		removeBlob(t, rootDir, workloadZoneVaultDigest)
	}
	if opts.CorruptVaultBlob {
		corruptBlob(t, rootDir, workloadZoneVaultDigest)
	}
	if opts.CorruptManifest {
		corruptBlob(t, rootDir, manifestDigest)
	}
	if opts.CorruptProvenance {
		corruptBlob(t, rootDir, provenanceDigest)
	}
	if opts.CorruptAttestation {
		corruptBlob(t, rootDir, derivationAttestationDigest)
	}

	indexPath := filepath.Join(t.TempDir(), "artifact-index.json")
	indexPayload := map[string]arsindex.Entry{
		artifactDigest: {
			ArtifactDigest:                           artifactDigest,
			ManifestDigest:                           manifestDigest,
			ProvenanceDigest:                         provenanceDigest,
			PayloadDigest:                            payloadDigest,
			DerivationMetadataDigest:                 derivationMetadataDigest,
			DerivationAuthorizationAttestationDigest: derivationAttestationDigest,
			WorkloadIdentityBindingDigest:            bindingDigest,
			CreatedAt:                                "2026-03-31T00:00:00Z",
		},
	}
	if err := os.WriteFile(indexPath, mustMarshalJSON(t, indexPayload), 0o600); err != nil {
		t.Fatalf("write artifact index: %v", err)
	}

	arsCfg := arsconfig.Config{
		HTTP: arsconfig.HTTPConfig{
			BindAddress:            "127.0.0.1",
			Port:                   0,
			ReadTimeoutSeconds:     5,
			WriteTimeoutSeconds:    5,
			ShutdownTimeoutSeconds: 5,
		},
		TLS: arsconfig.TLSConfig{
			CertFile:     fixture.arsServerCertPath,
			KeyFile:      fixture.arsServerKeyPath,
			ClientCAFile: fixture.clientCAPath,
		},
		Authorization: arsconfig.AuthorizationConfig{
			AllowedSPIFFEPathPrefixes: []string{"service/execution"},
		},
		Storage: arsconfig.StorageConfig{
			RootDir:   rootDir,
			IndexFile: indexPath,
		},
	}
	arsService, err := arsapp.New(arsCfg)
	if err != nil {
		t.Fatalf("build ars app: %v", err)
	}
	stack.ars = arsService
	startService(t, arsService.Start, arsService.Addr, fixture.serverTLSConfig(t, fixture.arsServerName))
	stack.arsRunning = true

	acsCfg := acsconfig.Config{
		HTTP: acsconfig.HTTPConfig{
			BindAddress:            "127.0.0.1",
			Port:                   0,
			ReadTimeoutSeconds:     5,
			WriteTimeoutSeconds:    5,
			ShutdownTimeoutSeconds: 5,
		},
		TLS: acsconfig.TLSConfig{
			CertFile:     fixture.acsServerCertPath,
			KeyFile:      fixture.acsServerKeyPath,
			ClientCAFile: fixture.clientCAPath,
		},
		Authorization: acsconfig.AuthorizationConfig{
			AllowedSPIFFEPathPrefixes: []string{"service/execution"},
		},
		Catalog: acsconfig.CatalogConfig{
			SeedArtifactDigests: map[string]acscatalog.AssignmentKey{
				workloadZoneVaultDigest: acscatalog.RequiredWorkloadZoneVault(),
			},
		},
		Audit: acsconfig.AuditConfig{Mode: "noop"},
	}
	acsService, err := acsapp.New(acsCfg)
	if err != nil {
		t.Fatalf("build acs app: %v", err)
	}
	stack.acs = acsService
	startService(t, acsService.Start, acsService.Addr, fixture.serverTLSConfig(t, fixture.acsServerName))
	stack.acsRunning = true

	allowedSigners := []string{fixture.agsKeyID}
	revokedSigners := []string{}
	revokedArtifacts := []string{}
	if opts.DisallowedSigner {
		allowedSigners = []string{"ags-other-key"}
	}
	if opts.RevokedSigner {
		revokedSigners = []string{fixture.agsKeyID}
	}
	if opts.RevokedArtifact {
		revokedArtifacts = []string{artifactDigest}
	}

	egsCfg := egsconfig.Config{
		HTTP: egsconfig.HTTPConfig{
			BindAddress:            "127.0.0.1",
			Port:                   0,
			ReadTimeoutSeconds:     5,
			WriteTimeoutSeconds:    5,
			ShutdownTimeoutSeconds: 5,
		},
		TLS: egsconfig.TLSConfig{
			CertFile:     fixture.egsServerCertPath,
			KeyFile:      fixture.egsServerKeyPath,
			ClientCAFile: fixture.clientCAPath,
		},
		Security: egsconfig.SecurityConfig{
			BootstrapIssuerCommonName: fixture.bootstrapCACN,
		},
		Signer: egsconfig.SignerConfig{
			Algorithm:     "ed25519",
			KeyID:         fixture.egsKeyID,
			PrivateKeyHex: fixture.egsPrivateKeyHex,
			PublicKeyHex:  fixture.egsPublicKeyHex,
			SourceDigest:  labeledDigest("dd"),
		},
		TrustModel: egsmodel.TrustModel{
			SignerPolicy: egsmodel.SignerPolicy{
				AllowedSigners: allowedSigners,
				RevokedSigners: revokedSigners,
			},
			ArtifactPolicy: egsmodel.ArtifactPolicy{
				RevokedArtifacts: revokedArtifacts,
			},
			UpdateRevision: 7,
			Version:        "1.0.0",
		},
	}
	egsService, err := egsapp.New(egsCfg)
	if err != nil {
		t.Fatalf("build egs app: %v", err)
	}
	stack.egs = egsService
	startService(t, egsService.Start, egsService.Addr, fixture.serverTLSConfig(t, fixture.egsServerName))
	stack.egsRunning = true

	stack.artifactDigest = artifactDigest
	stack.intentDigest = intentDigest
	stack.workloadIdentityID = workloadIdentityID
	stack.workloadZoneVaultDigest = workloadZoneVaultDigest

	return stack
}

func buildESConfig(stack *testStack, mutate func(*esconfig.Config)) esconfig.Config {
	defaultMode := esconfig.WorkloadVaultAuthModeVaultIdentityJWT
	if mutate == nil {
		// no-op
	}

	cfg := esconfig.Config{
		HTTP: esconfig.HTTPConfig{
			BindAddress:            "127.0.0.1",
			Port:                   0,
			ReadTimeoutSeconds:     5,
			WriteTimeoutSeconds:    5,
			ShutdownTimeoutSeconds: 5,
		},
		TLS: esconfig.TLSConfig{
			CertFile:     stack.fixture.esServerCertPath,
			KeyFile:      stack.fixture.esServerKeyPath,
			ClientCAFile: stack.fixture.clientCAPath,
		},
		Security: esconfig.SecurityConfig{
			BootstrapIssuerCommonName: stack.fixture.bootstrapCACN,
		},
		Dependencies: esconfig.DependenciesConfig{
			ArtifactCatalog: esconfig.DependencyConfig{
				BaseURL:        "https://" + stack.acs.Addr(),
				ServerName:     stack.fixture.acsServerName,
				ClientCertFile: stack.fixture.executionClientCertPath,
				ClientKeyFile:  stack.fixture.executionClientKeyPath,
				RootCAFile:     stack.fixture.runtimeCAPath,
				TimeoutSeconds: 5,
			},
			ArtifactRegistry: esconfig.DependencyConfig{
				BaseURL:        "https://" + stack.ars.Addr(),
				ServerName:     stack.fixture.arsServerName,
				ClientCertFile: stack.fixture.executionClientCertPath,
				ClientKeyFile:  stack.fixture.executionClientKeyPath,
				RootCAFile:     stack.fixture.runtimeCAPath,
				TimeoutSeconds: 5,
			},
			ExecutionGovernance: esconfig.DependencyConfig{
				BaseURL:        "https://" + stack.egs.Addr(),
				ServerName:     stack.fixture.egsServerName,
				ClientCertFile: stack.fixture.executionClientCertPath,
				ClientKeyFile:  stack.fixture.executionClientKeyPath,
				RootCAFile:     stack.fixture.runtimeCAPath,
				TimeoutSeconds: 5,
			},
		},
		Verification: esconfig.VerificationConfig{
			TrustModel: esconfig.SignerVerifierConfig{
				Algorithm:    "ed25519",
				KeyID:        stack.fixture.egsKeyID,
				PublicKeyHex: stack.fixture.egsPublicKeyHex,
			},
			Provenance: esconfig.SignerVerifierConfig{
				Algorithm:    "ed25519",
				KeyID:        stack.fixture.agsKeyID,
				PublicKeyHex: stack.fixture.agsPublicKeyHex,
			},
			DerivationAttestation: esconfig.SignerVerifierConfig{
				Algorithm:    "ed25519",
				KeyID:        stack.fixture.agsKeyID,
				PublicKeyHex: stack.fixture.agsPublicKeyHex,
			},
			WorkloadIdentityBinding: esconfig.SignerVerifierConfig{
				Algorithm:    "ed25519",
				KeyID:        stack.fixture.agsKeyID,
				PublicKeyHex: stack.fixture.agsPublicKeyHex,
			},
		},
		WorkloadVaultAuth: esconfig.WorkloadVaultAuthConfig{
			DefaultMode: defaultMode,
		},
	}

	if mutate != nil {
		mutate(&cfg)
	}

	return cfg
}

func buildPrepareRequestBody(t *testing.T, stack *testStack) []byte {
	t.Helper()
	return buildPrepareRequest(t, stack, nil)
}

func buildPrepareRequest(t *testing.T, stack *testStack, mutate func(*admission.PrepareRequest)) []byte {
	t.Helper()
	request := admission.PrepareRequest{
		SchemaVersion: "v1",
		Invocation: admission.ArtifactInvocation{
			SchemaVersion:        "v1",
			ArtifactDigest:       stack.artifactDigest,
			DerivationSpecDigest: labeledDigest("cc"),
			OutputID:             "runtime",
			Env: map[string]string{
				"APP_MODE": "test",
			},
		},
		Mode: admission.ExecutionModeAsync,
	}
	if mutate != nil {
		mutate(&request)
	}

	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}
	return payload
}

func assertPrepareError(t *testing.T, stack *testStack, expectedStatus int, expectedCode string) {
	t.Helper()
	assertPrepareErrorForBody(t, stack, buildPrepareRequestBody(t, stack), expectedStatus, expectedCode)
}

func assertPrepareErrorForBody(t *testing.T, stack *testStack, body []byte, expectedStatus int, expectedCode string) {
	t.Helper()

	response := doJSONRequest(t, stack.es.Addr(), http.MethodPost, "/v1/executions:prepare", stack.fixture.clientTLSConfig(t, "service/deployment", false), body)
	defer response.Body.Close()

	if response.StatusCode != expectedStatus {
		t.Fatalf("expected %d, got %d body=%s", expectedStatus, response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}

	var payload admission.ErrorResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if payload.Success {
		t.Fatalf("expected unsuccessful response")
	}
	if payload.Code != expectedCode {
		t.Fatalf("expected code %q, got %q", expectedCode, payload.Code)
	}
}

func (s *testStack) shutdownACS(t *testing.T) {
	t.Helper()
	if !s.acsRunning {
		return
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.acs.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown acs: %v", err)
	}
	s.acsRunning = false
}

func (s *testStack) shutdownAll(t *testing.T) {
	t.Helper()
	for _, step := range []struct {
		running *bool
		name    string
		stop    func(context.Context) error
	}{
		{&s.esRunning, "es", func(ctx context.Context) error { return s.es.Shutdown(ctx) }},
		{&s.egsRunning, "egs", func(ctx context.Context) error { return s.egs.Shutdown(ctx) }},
		{&s.arsRunning, "ars", func(ctx context.Context) error { return s.ars.Shutdown(ctx) }},
		{&s.acsRunning, "acs", func(ctx context.Context) error { return s.acs.Shutdown(ctx) }},
	} {
		if step.running == nil || !*step.running {
			continue
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := step.stop(shutdownCtx)
		cancel()
		if err != nil {
			t.Fatalf("shutdown %s: %v", step.name, err)
		}
		*step.running = false
	}
}

func startService(
	t *testing.T,
	start func(context.Context) (string, error),
	addr func() string,
	tlsConfig *tls.Config,
) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := start(ctx); err != nil {
		t.Fatalf("start service: %v", err)
	}
	waitForHealthy(t, addr(), tlsConfig)
}

func waitForHealthy(t *testing.T, addr string, tlsConfig *tls.Config) {
	t.Helper()

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		response, err := client.Get("https://" + addr + "/health")
		if err == nil {
			var payload struct {
				Ready bool `json:"ready"`
			}
			decodeErr := json.NewDecoder(response.Body).Decode(&payload)
			response.Body.Close()
			if decodeErr == nil && response.StatusCode == http.StatusOK && payload.Ready {
				return
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("service at %s did not become healthy", addr)
}

func doJSONRequest(t *testing.T, addr string, method string, requestPath string, tlsConfig *tls.Config, body []byte) *http.Response {
	t.Helper()

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	request, err := http.NewRequest(method, "https://"+addr+requestPath, strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return response
}

func mustReadBody(t *testing.T, body io.ReadCloser) []byte {
	t.Helper()
	payload, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return payload
}

func mustMarshalJSON(t *testing.T, value any) []byte {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	return payload
}

func writeBlobBytes(t *testing.T, rootDir string, data []byte) string {
	t.Helper()

	digest := arsstore.DigestBytes(data)
	blobPath, err := arsstore.ResolvePath(rootDir, digest)
	if err != nil {
		t.Fatalf("resolve blob path: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(blobPath), 0o755); err != nil {
		t.Fatalf("mkdir blob dir: %v", err)
	}
	if err := os.WriteFile(blobPath, data, 0o600); err != nil {
		t.Fatalf("write blob: %v", err)
	}
	return digest
}

func removeBlob(t *testing.T, rootDir string, digest string) {
	t.Helper()
	blobPath, err := arsstore.ResolvePath(rootDir, digest)
	if err != nil {
		t.Fatalf("resolve blob path: %v", err)
	}
	if err := os.Remove(blobPath); err != nil {
		t.Fatalf("remove blob: %v", err)
	}
}

func corruptBlob(t *testing.T, rootDir string, digest string) {
	t.Helper()
	blobPath, err := arsstore.ResolvePath(rootDir, digest)
	if err != nil {
		t.Fatalf("resolve blob path: %v", err)
	}
	if err := os.WriteFile(blobPath, []byte(`corrupt`), 0o600); err != nil {
		t.Fatalf("corrupt blob: %v", err)
	}
}

func labeledDigest(hexPair string) string {
	return "sha256:" + strings.Repeat(hexPair, 32)
}

type tlsFixture struct {
	runtimeCA      *x509.Certificate
	runtimeCAKey   *rsa.PrivateKey
	bootstrapCA    *x509.Certificate
	bootstrapCAKey *rsa.PrivateKey

	clientCAPath  string
	runtimeCAPath string

	acsServerName     string
	acsServerCertPath string
	acsServerKeyPath  string
	arsServerName     string
	arsServerCertPath string
	arsServerKeyPath  string
	egsServerName     string
	egsServerCertPath string
	egsServerKeyPath  string
	esServerName      string
	esServerCertPath  string
	esServerKeyPath   string
	agsServerName     string
	agsServerCertPath string
	agsServerKeyPath  string

	executionClientCertPath string
	executionClientKeyPath  string
	agsClientCertPath       string
	agsClientKeyPath        string

	egsKeyID         string
	egsPublicKey     ed25519.PublicKey
	egsPublicKeyHex  string
	egsPrivateKeyHex string

	agsKeyID         string
	agsPublicKey     ed25519.PublicKey
	agsPublicKeyHex  string
	agsPrivateKey    ed25519.PrivateKey
	agsPrivateKeyHex string

	bootstrapCACN string
}

func newTLSFixture(t *testing.T) *tlsFixture {
	t.Helper()

	dir := t.TempDir()

	runtimeCA, runtimeCAKey, runtimeCAPEM := createCertificateAuthority(t, "runtime-ca")
	bootstrapCA, bootstrapCAKey, bootstrapCAPEM := createCertificateAuthority(t, "bootstrap-ca")

	clientCAPath := filepath.Join(dir, "client-ca.pem")
	if err := os.WriteFile(clientCAPath, append(append([]byte(nil), runtimeCAPEM...), bootstrapCAPEM...), 0o600); err != nil {
		t.Fatalf("write client ca: %v", err)
	}
	runtimeCAPath := filepath.Join(dir, "runtime-ca.pem")
	if err := os.WriteFile(runtimeCAPath, runtimeCAPEM, 0o600); err != nil {
		t.Fatalf("write runtime ca: %v", err)
	}

	acsServerName := "server.artifact-catalog.internal"
	acsCertPath, acsKeyPath := writeLeafCertificateFiles(t, dir, "acs", runtimeCA, runtimeCAKey, acsServerName, nil)
	arsServerName := "server.artifact-registry.internal"
	arsCertPath, arsKeyPath := writeLeafCertificateFiles(t, dir, "ars", runtimeCA, runtimeCAKey, arsServerName, nil)
	egsServerName := "server.execution-governance.internal"
	egsCertPath, egsKeyPath := writeLeafCertificateFiles(t, dir, "egs", runtimeCA, runtimeCAKey, egsServerName, nil)
	esServerName := "server.execution.internal"
	esCertPath, esKeyPath := writeLeafCertificateFiles(t, dir, "es", runtimeCA, runtimeCAKey, esServerName, nil)
	agsServerName := "server.artifact-governance.internal"
	agsCertPath, agsKeyPath := writeLeafCertificateFiles(t, dir, "ags", runtimeCA, runtimeCAKey, agsServerName, nil)

	executionClientCertPath, executionClientKeyPath := writeLeafCertificateFiles(
		t,
		dir,
		"execution-client",
		runtimeCA,
		runtimeCAKey,
		"client.service.execution",
		[]*url.URL{mustSPIFFEURL(t, "spiffe://monolith.internal/service/execution")},
	)
	agsClientCertPath, agsClientKeyPath := writeLeafCertificateFiles(
		t,
		dir,
		"ags-client",
		runtimeCA,
		runtimeCAKey,
		"client.service.artifact-governance",
		[]*url.URL{mustSPIFFEURL(t, "spiffe://monolith.internal/service/artifact-governance")},
	)

	egsPublicKey, egsPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate egs signing key: %v", err)
	}
	agsPublicKey, agsPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ags signing key: %v", err)
	}

	return &tlsFixture{
		runtimeCA:               runtimeCA,
		runtimeCAKey:            runtimeCAKey,
		bootstrapCA:             bootstrapCA,
		bootstrapCAKey:          bootstrapCAKey,
		clientCAPath:            clientCAPath,
		runtimeCAPath:           runtimeCAPath,
		acsServerName:           acsServerName,
		acsServerCertPath:       acsCertPath,
		acsServerKeyPath:        acsKeyPath,
		arsServerName:           arsServerName,
		arsServerCertPath:       arsCertPath,
		arsServerKeyPath:        arsKeyPath,
		egsServerName:           egsServerName,
		egsServerCertPath:       egsCertPath,
		egsServerKeyPath:        egsKeyPath,
		esServerName:            esServerName,
		esServerCertPath:        esCertPath,
		esServerKeyPath:         esKeyPath,
		agsServerName:           agsServerName,
		agsServerCertPath:       agsCertPath,
		agsServerKeyPath:        agsKeyPath,
		executionClientCertPath: executionClientCertPath,
		executionClientKeyPath:  executionClientKeyPath,
		agsClientCertPath:       agsClientCertPath,
		agsClientKeyPath:        agsClientKeyPath,
		egsKeyID:                "egs-trust-model-signing-v1",
		egsPublicKey:            egsPublicKey,
		egsPublicKeyHex:         hex.EncodeToString(egsPublicKey),
		egsPrivateKeyHex:        hex.EncodeToString(egsPrivateKey),
		agsKeyID:                "ags-provenance-signing-v1",
		agsPublicKey:            agsPublicKey,
		agsPublicKeyHex:         hex.EncodeToString(agsPublicKey),
		agsPrivateKey:           agsPrivateKey,
		agsPrivateKeyHex:        hex.EncodeToString(agsPrivateKey),
		bootstrapCACN:           "bootstrap-ca",
	}
}

func (f *tlsFixture) clientTLSConfig(t *testing.T, spiffePath string, bootstrap bool) *tls.Config {
	t.Helper()

	return f.clientTLSConfigForServer(t, f.esServerName, spiffePath, bootstrap)
}

func (f *tlsFixture) clientTLSConfigForServer(t *testing.T, serverName string, spiffePath string, bootstrap bool) *tls.Config {
	t.Helper()

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(f.runtimeCA)

	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    rootCAs,
		ServerName: serverName,
	}

	if strings.TrimSpace(spiffePath) == "" {
		return cfg
	}

	issuer := f.runtimeCA
	issuerKey := f.runtimeCAKey
	if bootstrap {
		issuer = f.bootstrapCA
		issuerKey = f.bootstrapCAKey
	}

	clientCertPEM, clientKeyPEM := createLeafCertificate(
		t,
		issuer,
		issuerKey,
		"client."+strings.ReplaceAll(strings.Trim(spiffePath, "/"), "/", "."),
		[]*url.URL{mustSPIFFEURL(t, "spiffe://monolith.internal/"+strings.Trim(spiffePath, "/"))},
	)
	certificate, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		t.Fatalf("load client key pair: %v", err)
	}
	cfg.Certificates = []tls.Certificate{certificate}
	return cfg
}

func (f *tlsFixture) serverTLSConfig(t *testing.T, serverName string) *tls.Config {
	t.Helper()

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(f.runtimeCA)

	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    rootCAs,
		ServerName: serverName,
	}
}

func signedProvenanceJSON(t *testing.T, fixture *tlsFixture, artifactDigest string) []byte {
	t.Helper()

	payload := struct {
		ArtifactDigest      string `json:"artifact_digest"`
		BuilderService      string `json:"builder_service"`
		InvokerService      string `json:"invoker_service"`
		InvokerPrincipal    string `json:"invoker_principal"`
		PolicyDecisionsHash string `json:"policy_decisions_hash"`
		BuildLogDigest      string `json:"build_log_digest"`
	}{
		ArtifactDigest:      artifactDigest,
		BuilderService:      "artifact-governance",
		InvokerService:      "deployment",
		InvokerPrincipal:    "spiffe://monolith.internal/service/deployment",
		PolicyDecisionsHash: digestBytes([]byte("allow:applied")),
		BuildLogDigest:      labeledDigest("ee"),
	}
	canonical := mustMarshalJSON(t, payload)
	signature := ed25519.Sign(fixture.agsPrivateKey, canonical)

	return mustMarshalJSON(t, map[string]any{
		"artifact_digest": artifactDigest,
		"builder_service": "artifact-governance",
		"invoker": map[string]any{
			"service":   "deployment",
			"principal": "spiffe://monolith.internal/service/deployment",
		},
		"policy_decisions": []map[string]any{
			{"rule": "allow", "result": "applied"},
		},
		"build_log_digest": labeledDigest("ee"),
		"signature": map[string]any{
			"alg":    "ed25519",
			"key_id": fixture.agsKeyID,
			"value":  base64.StdEncoding.EncodeToString(signature),
		},
	})
}

func signedDerivationAttestationJSON(t *testing.T, fixture *tlsFixture, artifactDigest string, derivationSpecDigest string) []byte {
	t.Helper()

	constraints := admission.DerivationSpecConstraintsInfo{
		AllowedToolchains:      []string{},
		ForbiddenToolchains:    []string{},
		OS:                     "linux",
		Arch:                   "amd64",
		NetworkAccess:          false,
		WritablePaths:          []string{},
		ForbiddenPaths:         []string{},
		DeterminismExpectation: "deterministic",
	}

	canonical := mustMarshalJSON(t, struct {
		ArtifactDigest       string                                  `json:"artifact_digest"`
		DerivationSpecDigest string                                  `json:"derivation_spec_digest"`
		OutputID             string                                  `json:"output_id"`
		Constraints          admission.DerivationSpecConstraintsInfo `json:"constraints"`
		PolicyVersion        string                                  `json:"policy_version"`
		ExpectedArtifactType string                                  `json:"expected_artifact_type,omitempty"`
	}{
		ArtifactDigest:       artifactDigest,
		DerivationSpecDigest: derivationSpecDigest,
		OutputID:             "runtime",
		Constraints:          constraints,
		PolicyVersion:        "2026-03-31",
		ExpectedArtifactType: "static-service",
	})
	signature := ed25519.Sign(fixture.agsPrivateKey, canonical)

	return mustMarshalJSON(t, map[string]any{
		"artifact_digest":        artifactDigest,
		"derivation_spec_digest": derivationSpecDigest,
		"output_id":              "runtime",
		"constraints":            constraints,
		"policy_version":         "2026-03-31",
		"expected_artifact_type": "static-service",
		"signature_info": map[string]any{
			"payload_digest":     digestBytes(canonical),
			"canonical_spec_b64": base64.StdEncoding.EncodeToString(canonical),
			"signature_value":    base64.StdEncoding.EncodeToString(signature),
			"key_id":             fixture.agsKeyID,
			"algorithm":          "ed25519",
		},
	})
}

func signedWorkloadIdentityBindingJSON(t *testing.T, fixture *tlsFixture, artifactDigest string, derivationSpecDigest string, workloadIdentityID string) []byte {
	t.Helper()

	canonical := mustMarshalJSON(t, struct {
		ArtifactClass        string `json:"artifact_class"`
		ArtifactDigest       string `json:"artifact_digest"`
		DerivationSpecDigest string `json:"derivation_spec_digest"`
		Description          string `json:"description,omitempty"`
		ModulePath           string `json:"module_path"`
		OutputID             string `json:"output_id"`
		PolicyVersion        string `json:"policy_version"`
		ServiceName          string `json:"service_name,omitempty"`
		TargetPlatform       string `json:"target_platform,omitempty"`
		WorkloadIdentityID   string `json:"workload_identity_id,omitempty"`
		WorkloadType         string `json:"workload_type"`
	}{
		ArtifactClass:        "service",
		ArtifactDigest:       artifactDigest,
		DerivationSpecDigest: derivationSpecDigest,
		Description:          "Execution workload",
		ModulePath:           "services.execution.ExecutionServer",
		OutputID:             "runtime",
		PolicyVersion:        "2026-03-31",
		ServiceName:          "execution",
		TargetPlatform:       "docker",
		WorkloadIdentityID:   workloadIdentityID,
		WorkloadType:         "service",
	})
	signature := ed25519.Sign(fixture.agsPrivateKey, canonical)

	return mustMarshalJSON(t, map[string]any{
		"workload_type":          "service",
		"module_path":            "services.execution.ExecutionServer",
		"derivation_spec_digest": derivationSpecDigest,
		"output_id":              "runtime",
		"artifact_digest":        artifactDigest,
		"artifact_class":         "service",
		"policy_version":         "2026-03-31",
		"service_name":           "execution",
		"target_platform":        "docker",
		"description":            "Execution workload",
		"workload_identity_id":   workloadIdentityID,
		"signature_info": map[string]any{
			"payload_digest":     digestBytes(canonical),
			"canonical_spec_b64": base64.StdEncoding.EncodeToString(canonical),
			"signature_value":    base64.StdEncoding.EncodeToString(signature),
			"key_id":             fixture.agsKeyID,
			"algorithm":          "ed25519",
		},
	})
}

func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func createCertificateAuthority(t *testing.T, commonName string) (*x509.Certificate, *rsa.PrivateKey, []byte) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: randomSerialNumber(t),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create ca certificate: %v", err)
	}

	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca certificate: %v", err)
	}

	return certificate, privateKey, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func writeLeafCertificateFiles(t *testing.T, dir string, prefix string, issuer *x509.Certificate, issuerKey *rsa.PrivateKey, commonName string, uris []*url.URL) (string, string) {
	t.Helper()

	certPEM, keyPEM := createLeafCertificate(t, issuer, issuerKey, commonName, uris)
	certPath := filepath.Join(dir, prefix+"-cert.pem")
	keyPath := filepath.Join(dir, prefix+"-key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

func createLeafCertificate(t *testing.T, issuer *x509.Certificate, issuerKey *rsa.PrivateKey, commonName string, uris []*url.URL) ([]byte, []byte) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: randomSerialNumber(t),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:    []string{commonName},
		URIs:        uris,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &privateKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	return certPEM, keyPEM
}

func randomSerialNumber(t *testing.T) *big.Int {
	t.Helper()
	value, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial number: %v", err)
	}
	return value
}

func mustSPIFFEURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse SPIFFE URL: %v", err)
	}
	return parsed
}
