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

	arsapi "execution-substrate/ars/api"
	arsapp "execution-substrate/ars/app"
	arsconfig "execution-substrate/ars/config"
	arsindex "execution-substrate/ars/index"
	arsstore "execution-substrate/ars/store"
	egsapp "execution-substrate/egs/app"
	egsconfig "execution-substrate/egs/config"
	egsmodel "execution-substrate/egs/model"
	"execution-substrate/es/admission"
	esapp "execution-substrate/es/app"
	esconfig "execution-substrate/es/config"
	evidencev1 "execution-substrate/internal/contracts/evidence/v1"
	runtimeconfigv1 "execution-substrate/internal/contracts/runtimeconfig/v1"
)

func TestPrepareFlowReturnsBoundedPreflightSuccess(t *testing.T) {
	stack := startStack(t, stackOptions{})

	response := doJSONRequest(t, stack.es.Addr(), http.MethodPost, "/v1/executions:prepare", stack.fixture.clientTLSConfig(t, "operator", false), buildPrepareRequestBody(t, stack))
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}

	body := mustReadBody(t, response.Body)
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("decode raw prepare response: %v", err)
	}
	if _, ok := raw["trust_model"]; ok {
		t.Fatalf("did not expect trust_model metadata in prepare response: %s", strings.TrimSpace(string(body)))
	}
	for _, key := range []string{
		"artifact_digest",
		"derivation_spec_digest",
		"output_id",
		"intent_digest",
		"artifact_type",
		"provenance",
		"workload",
		"workload_vault",
	} {
		if _, ok := raw[key]; ok {
			t.Fatalf("did not expect internal admission detail %q in bounded prepare response: %s", key, strings.TrimSpace(string(body)))
		}
	}

	var payload admission.PrepareResult
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode prepare response: %v", err)
	}

	if !payload.Success {
		t.Fatalf("expected success response")
	}
}

func TestPrepareIgnoresMissingManifestWhenEvidenceIsPresent(t *testing.T) {
	stack := startStack(t, stackOptions{MissingManifest: true})
	assertPrepareSuccess(t, stack)
}

func TestPrepareReturns404WhenEvidenceIsMissing(t *testing.T) {
	stack := startStack(t, stackOptions{MissingEvidence: true})
	assertPrepareError(t, stack, http.StatusNotFound, codeArtifactEvidenceNotFound)
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

func TestPrepareReturns503WhenVaultBlobIsMissing(t *testing.T) {
	stack := startStack(t, stackOptions{MissingVaultBlob: true})
	assertPrepareError(t, stack, http.StatusServiceUnavailable, codeWorkloadZoneVaultUnavailable)
}

func TestPrepareReturns503WhenVaultBlobIsCorrupt(t *testing.T) {
	stack := startStack(t, stackOptions{CorruptVaultBlob: true})
	assertPrepareError(t, stack, http.StatusServiceUnavailable, codeWorkloadZoneVaultUnavailable)
}

func TestPrepareReturns503WhenVaultBlobShapeIsInvalid(t *testing.T) {
	stack := startStack(t, stackOptions{InvalidVaultBlobShape: true})
	assertPrepareError(t, stack, http.StatusServiceUnavailable, codeWorkloadZoneVaultUnavailable)
}

func TestPrepareIgnoresCorruptManifestWhenEvidenceIsPresent(t *testing.T) {
	stack := startStack(t, stackOptions{CorruptManifest: true})
	assertPrepareSuccess(t, stack)
}

func TestPrepareReturns503WhenEvidenceBlobIsCorrupt(t *testing.T) {
	stack := startStack(t, stackOptions{CorruptEvidence: true})
	assertPrepareError(t, stack, http.StatusServiceUnavailable, codeArtifactEvidenceUnavailable)
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

func TestNewFailsWhenWorkloadZoneVaultConfigRefIsMissing(t *testing.T) {
	stack := startDependencyStack(t, stackOptions{})
	defer stack.shutdownAll(t)

	cfg := buildESConfig(stack, func(cfg *esconfig.Config) {
		cfg.RuntimeConfig.WorkloadZoneVaultConfigRef = runtimeconfigv1.WorkloadZoneVaultConfigRef{}
	})

	if _, err := esapp.New(cfg); err == nil || !strings.Contains(err.Error(), "runtime_config.workload_zone_vault_config_ref") {
		t.Fatalf("expected missing workload-zone vault config ref startup failure, got %v", err)
	}
}

func TestNewFailsWhenWorkloadZoneVaultConfigRefIsInvalid(t *testing.T) {
	stack := startDependencyStack(t, stackOptions{})
	defer stack.shutdownAll(t)

	cfg := buildESConfig(stack, func(cfg *esconfig.Config) {
		cfg.RuntimeConfig.WorkloadZoneVaultConfigRef = runtimeconfigv1.WorkloadZoneVaultConfigRef{
			Digest: "sha256:not-a-real-digest",
		}
	})

	if _, err := esapp.New(cfg); err == nil || !strings.Contains(err.Error(), "runtime_config.workload_zone_vault_config_ref") {
		t.Fatalf("expected invalid workload-zone vault config ref startup failure, got %v", err)
	}
}

func TestPrepareWithoutClientCertFailsTLSHandshake(t *testing.T) {
	stack := startStack(t, stackOptions{})

	_, err := doJSONRequestWithError(stack.es.Addr(), http.MethodPost, "/v1/executions:prepare", stack.fixture.clientTLSConfig(t, "", false), buildPrepareRequestBody(t, stack))
	if err == nil {
		t.Fatalf("expected tls handshake failure without client certificate")
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

func TestPrepareAllowsConfiguredControlPlaneCaller(t *testing.T) {
	stack := startStack(t, stackOptions{
		AllowedExecutionCallerPrefixes: []string{"service/control-plane"},
	})

	response := doJSONRequest(t, stack.es.Addr(), http.MethodPost, "/v1/executions:prepare", stack.fixture.clientTLSConfig(t, "service/control-plane", false), buildPrepareRequestBody(t, stack))
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}
}

func TestPrepareReturns403WhenDeploymentCallerIsUsed(t *testing.T) {
	stack := startStack(t, stackOptions{})

	response := doJSONRequest(t, stack.es.Addr(), http.MethodPost, "/v1/executions:prepare", stack.fixture.clientTLSConfig(t, "service/deployment", false), buildPrepareRequestBody(t, stack))
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

	response := doJSONRequest(t, stack.es.Addr(), http.MethodPost, "/v1/executions:prepare", stack.fixture.clientTLSConfig(t, "operator", true), buildPrepareRequestBody(t, stack))
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

	response := doJSONRequest(t, stack.es.Addr(), http.MethodPost, "/v1/executions:prepare", stack.fixture.clientTLSConfig(t, "operator", false), []byte(`{"schema_version":"v1"`))
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
	codeArtifactEvidenceNotFound     = "artifact_evidence_not_found"
	codeArtifactEvidenceUnavailable  = "artifact_evidence_unavailable"
	codeManifestNotFound             = "manifest_not_found"
	codeProvenanceNotFound           = "provenance_not_found"
	codeDerivationMetadataNotFound   = "derivation_metadata_not_found"
	codeBindingNotFound              = "workload_identity_binding_not_found"
	codeAttestationNotFound          = "derivation_attestation_not_found"
	codeSignerNotAllowed             = "signer_not_allowed"
	codeSignerRevoked                = "signer_revoked"
	codeArtifactRevoked              = "artifact_revoked"
	codeWorkloadZoneVaultUnavailable = "workload_zone_vault_unavailable"
)

type stackOptions struct {
	MissingManifest                bool
	MissingEvidence                bool
	MissingVaultBlob               bool
	CorruptVaultBlob               bool
	InvalidVaultBlobShape          bool
	CorruptManifest                bool
	CorruptEvidence                bool
	DisallowedSigner               bool
	RevokedSigner                  bool
	RevokedArtifact                bool
	DefaultAuthMode                esconfig.WorkloadVaultAuthMode
	AllowedExecutionCallerPrefixes []string
}

type testStack struct {
	fixture *tlsFixture

	ars *arsapp.App
	egs *egsapp.App
	es  *esapp.App

	arsRunning bool
	egsRunning bool
	esRunning  bool

	artifactDigest          string
	intentDigest            string
	workloadZoneVaultDigest string
}

func startStack(t *testing.T, opts stackOptions) *testStack {
	t.Helper()

	stack := startDependencyStack(t, opts)
	cfg := buildESConfig(stack, func(cfg *esconfig.Config) {
		if opts.DefaultAuthMode != "" {
			cfg.WorkloadVaultAuth.DefaultMode = opts.DefaultAuthMode
		}
		if len(opts.AllowedExecutionCallerPrefixes) > 0 {
			cfg.Authorization.AllowedSPIFFEPathPrefixes = append([]string(nil), opts.AllowedExecutionCallerPrefixes...)
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

	waitForHealthy(t, service.Addr(), stack.fixture.clientTLSConfig(t, "operator", false))
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

	intentDigest := labeledDigest("bb")
	derivationSpecDigest := labeledDigest("cc")
	payloadBytes := []byte("artifact payload bytes")
	payloadDigest := arsstore.DigestBytes(payloadBytes)
	identity, err := evidencev1.NewArtifactIdentity(payloadDigest, "static-service", intentDigest)
	if err != nil {
		t.Fatalf("derive artifact identity: %v", err)
	}
	artifactDigest := identity.ArtifactDigest

	manifestBytes := mustMarshalJSON(t, map[string]any{
		"artifact_digest": artifactDigest,
		"artifact_type":   "static-service",
		"intent_digest":   intentDigest,
		"runtime_interface": map[string]any{
			"environment_variables": []string{"APP_MODE"},
			"required_capabilities": []string{},
		},
	})
	manifestDigest := writeBlobBytes(t, rootDir, manifestBytes)

	writeBlobBytes(t, rootDir, payloadBytes)
	evidenceBytes := signedArtifactEvidenceJSON(t, fixture, artifactDigest, payloadDigest, intentDigest, derivationSpecDigest)
	evidenceDigest := writeBlobBytes(t, rootDir, evidenceBytes)
	discoveryBytes := artifactDiscoveryJSON(t, artifactDigest, "static-service", intentDigest, evidenceDigest, payloadDigest)
	discoveryDigest := writeBlobBytes(t, rootDir, discoveryBytes)
	descriptorBytes := artifactDescriptorJSON(t, artifactDigest, "static-service", intentDigest, evidenceDigest, payloadDigest, manifestDigest)
	descriptorDigest := writeBlobBytes(t, rootDir, descriptorBytes)

	workloadZoneVaultBytes := mustMarshalJSON(t, map[string]any{
		"vault_config": map[string]any{
			"address":      "https://vault.internal:8200",
			"auth_mount":   "jwt",
			"auth_role":    "service_execution",
			"jwt_audience": "vault",
		},
	})
	if opts.InvalidVaultBlobShape {
		workloadZoneVaultBytes = mustMarshalJSON(t, map[string]any{
			"vault_config": map[string]any{
				"address":      "https://vault.internal:8200",
				"auth_mount":   "jwt",
				"jwt_audience": "vault",
			},
		})
	}
	workloadZoneVaultDigest := writeBlobBytes(t, rootDir, workloadZoneVaultBytes)

	if opts.MissingManifest {
		removeBlob(t, rootDir, manifestDigest)
	}
	if opts.MissingEvidence {
		removeBlob(t, rootDir, evidenceDigest)
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
	if opts.CorruptEvidence {
		corruptBlob(t, rootDir, evidenceDigest)
	}

	indexPath := filepath.Join(t.TempDir(), "artifact-index.json")
	indexPayload := map[string]arsindex.Entry{
		artifactDigest: {
			ArtifactDigest:   artifactDigest,
			DiscoveryDigest:  discoveryDigest,
			DescriptorDigest: descriptorDigest,
			CreatedAt:        "2026-03-31T00:00:00Z",
		},
	}
	if opts.MissingEvidence {
		delete(indexPayload, artifactDigest)
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
		Security: arsconfig.SecurityConfig{
			BootstrapIssuerCommonName: fixture.bootstrapCACN,
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
	startService(t, arsService.Start, arsService.Addr, fixture.clientTLSConfigForServer(t, fixture.arsServerName, "service/execution", false))
	stack.arsRunning = true

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
		},
		RuntimeTrust: egsmodel.RuntimeTrustPolicy{
			SignerPolicy: egsmodel.SignerPolicy{
				AllowedSigners: allowedSigners,
				RevokedSigners: revokedSigners,
			},
			ArtifactPolicy: egsmodel.ArtifactPolicy{
				RevokedArtifacts: revokedArtifacts,
			},
		},
		Publication: egsmodel.PublicationMetadata{
			UpdateRevision: 7,
			Version:        "1.0.0",
		},
	}
	egsService, err := egsapp.New(egsCfg)
	if err != nil {
		t.Fatalf("build egs app: %v", err)
	}
	stack.egs = egsService
	startService(t, egsService.Start, egsService.Addr, fixture.clientTLSConfigForServer(t, fixture.egsServerName, "service/execution", false))
	stack.egsRunning = true

	stack.artifactDigest = artifactDigest
	stack.intentDigest = intentDigest
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
		Authorization: esconfig.AuthorizationConfig{
			AllowedSPIFFEPathPrefixes: []string{"operator"},
		},
		Dependencies: esconfig.DependenciesConfig{
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
		RuntimeConfig: esconfig.RuntimeConfigConfig{
			WorkloadZoneVaultConfigRef: runtimeconfigv1.WorkloadZoneVaultConfigRef{
				Digest: stack.workloadZoneVaultDigest,
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

func assertPrepareSuccess(t *testing.T, stack *testStack) {
	t.Helper()

	response := doJSONRequest(t, stack.es.Addr(), http.MethodPost, "/v1/executions:prepare", stack.fixture.clientTLSConfig(t, "operator", false), buildPrepareRequestBody(t, stack))
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}

	var payload admission.PrepareResult
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode prepare response: %v", err)
	}
	if !payload.Success {
		t.Fatalf("expected successful prepare response: %+v", payload)
	}
}

func assertPrepareErrorForBody(t *testing.T, stack *testStack, body []byte, expectedStatus int, expectedCode string) {
	t.Helper()

	response := doJSONRequest(t, stack.es.Addr(), http.MethodPost, "/v1/executions:prepare", stack.fixture.clientTLSConfig(t, "operator", false), body)
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

func doJSONRequestWithError(addr string, method string, requestPath string, tlsConfig *tls.Config, body []byte) (*http.Response, error) {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	request, err := http.NewRequest(method, "https://"+addr+requestPath, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")

	return client.Do(request)
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

func overwriteBlobBytes(t *testing.T, rootDir string, digest string, data []byte) {
	t.Helper()

	blobPath, err := arsstore.ResolvePath(rootDir, digest)
	if err != nil {
		t.Fatalf("resolve blob path: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(blobPath), 0o755); err != nil {
		t.Fatalf("mkdir blob dir: %v", err)
	}
	if err := os.WriteFile(blobPath, data, 0o600); err != nil {
		t.Fatalf("overwrite blob: %v", err)
	}
}

func readJSONBlob(t *testing.T, rootDir string, digest string, target any) {
	t.Helper()

	blobPath, err := arsstore.ResolvePath(rootDir, digest)
	if err != nil {
		t.Fatalf("resolve blob path: %v", err)
	}
	data, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatalf("read blob: %v", err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("decode blob: %v", err)
	}
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
		[]*url.URL{mustSPIFFEURL(t, "spiffe://execution.internal/service/execution")},
	)
	agsClientCertPath, agsClientKeyPath := writeLeafCertificateFiles(
		t,
		dir,
		"ags-client",
		runtimeCA,
		runtimeCAKey,
		"client.service.artifact-governance",
		[]*url.URL{mustSPIFFEURL(t, "spiffe://execution.internal/service/artifact-governance")},
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
		egsKeyID:                "egs-trust-model-signer",
		egsPublicKey:            egsPublicKey,
		egsPublicKeyHex:         hex.EncodeToString(egsPublicKey),
		egsPrivateKeyHex:        hex.EncodeToString(egsPrivateKey),
		agsKeyID:                "ags-artifact-fact-signer",
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
		[]*url.URL{mustSPIFFEURL(t, "spiffe://execution.internal/"+strings.Trim(spiffePath, "/"))},
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

func signedArtifactEvidenceJSON(
	t *testing.T,
	fixture *tlsFixture,
	artifactDigest string,
	payloadDigest string,
	intentDigest string,
	derivationSpecDigest string,
) []byte {
	t.Helper()

	record := evidencev1.ArtifactEvidence{
		Claims: evidencev1.Claims{
			SchemaVersion: evidencev1.Version,
			Package: evidencev1.PackageClaims{
				Identity: evidencev1.ArtifactIdentity{
					ArtifactDigest: artifactDigest,
					PayloadDigest:  payloadDigest,
					ArtifactType:   "static-service",
					IntentDigest:   intentDigest,
				},
				Publication: evidencev1.Publication{
					BuilderService: "artifact-governance",
					Invoker: evidencev1.Invoker{
						Service:   "operator",
						Principal: "spiffe://execution.internal/operator",
					},
					PolicyDecisions: []evidencev1.PolicyDecision{
						{Rule: "allow", Result: "applied"},
					},
					BuildLogDigest: labeledDigest("ee"),
				},
			},
			Admission: evidencev1.AdmissionClaims{
				Authorization: evidencev1.AuthorizationClaims{
					Derivation: evidencev1.DerivationAuthorization{
						DerivationSpecDigest: derivationSpecDigest,
						OutputID:             "runtime",
					},
				},
				Execution: evidencev1.ExecutionClaims{
					Runtime: evidencev1.ExecutionRuntime{
						EnvironmentVariables: []string{"APP_MODE"},
						RequiredCapabilities: []string{},
					},
					Workload: evidencev1.ExecutionWorkload{
						TargetPlatform: "docker",
					},
					Access: evidencev1.ExecutionAccess{
						NetworkAccess: false,
					},
				},
			},
		},
	}

	canonical, err := record.CanonicalBytes()
	if err != nil {
		t.Fatalf("canonicalize artifact evidence: %v", err)
	}
	record.Seal = evidencev1.NewSeal(canonical, fixture.agsKeyID, "ed25519", base64.StdEncoding.EncodeToString(ed25519.Sign(fixture.agsPrivateKey, canonical)))
	return mustMarshalJSON(t, record)
}

func artifactDescriptorJSON(
	t *testing.T,
	artifactDigest string,
	artifactType string,
	intentDigest string,
	evidenceDigest string,
	payloadDigest string,
	manifestDigest string,
) []byte {
	t.Helper()

	return mustMarshalJSON(t, arsapi.ArtifactDescriptor{
		SchemaVersion: arsapi.ArtifactDescriptorSchemaVersion,
		Artifact: arsapi.ArtifactIdentity{
			ArtifactDigest: artifactDigest,
			ArtifactType:   artifactType,
			IntentDigest:   intentDigest,
		},
		Package: arsapi.ArtifactPackage{
			Evidence: arsapi.ArtifactBlobRef{
				Digest:    evidenceDigest,
				MediaType: "application/json",
			},
			Payload: arsapi.ArtifactBlobRef{
				Digest:    payloadDigest,
				MediaType: "application/octet-stream",
			},
			Supporting: []arsapi.ArtifactSupportRef{
				{
					Name:      "manifest",
					Digest:    manifestDigest,
					MediaType: "application/json",
				},
			},
		},
	})
}

func artifactDiscoveryJSON(
	t *testing.T,
	artifactDigest string,
	artifactType string,
	intentDigest string,
	evidenceDigest string,
	payloadDigest string,
) []byte {
	t.Helper()

	return mustMarshalJSON(t, arsapi.ArtifactDiscovery{
		SchemaVersion: arsapi.ArtifactDiscoverySchemaVersion,
		Artifact: arsapi.ArtifactIdentity{
			ArtifactDigest: artifactDigest,
			ArtifactType:   artifactType,
			IntentDigest:   intentDigest,
		},
		Evidence: arsapi.ArtifactBlobRef{
			Digest:    evidenceDigest,
			MediaType: "application/json",
		},
		Payload: arsapi.ArtifactBlobRef{
			Digest:    payloadDigest,
			MediaType: "application/octet-stream",
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
