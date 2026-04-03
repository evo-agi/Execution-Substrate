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
	agsapp "execution-platform/ags/app"
	agsconfig "execution-platform/ags/config"
	arsapp "execution-platform/ars/app"
	arsconfig "execution-platform/ars/config"
	arsindex "execution-platform/ars/index"
	arsstore "execution-platform/ars/store"
	signingv2 "execution-platform/contracts/signing/v2"
	egsapp "execution-platform/egs/app"
	egsconfig "execution-platform/egs/config"
	egsmodel "execution-platform/egs/model"
	"execution-platform/es/admission"
	esapp "execution-platform/es/app"
	esconfig "execution-platform/es/config"
)

func TestPublishFlowProducesArtifactESAccepts(t *testing.T) {
	stack := startPublishedStack(t)
	defer stack.shutdownAll(t)

	response := doJSONRequest(t, stack.es.Addr(), http.MethodPost, "/v1/executions:prepare", stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "service/deployment", false), buildPrepareRequestBody(t, stack))
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}

	var payload admission.PrepareResult
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode prepare response: %v", err)
	}
	if !payload.Success {
		t.Fatalf("expected successful prepare response")
	}
	if payload.ArtifactDigest != stack.publishResponse.ArtifactDigest {
		t.Fatalf("unexpected artifact digest: %q", payload.ArtifactDigest)
	}
	if payload.Provenance.SignerKeyID != stack.fixture.agsKeyID {
		t.Fatalf("unexpected provenance signer key: %q", payload.Provenance.SignerKeyID)
	}
}

func TestPublishValidDeploymentCallerSucceeds(t *testing.T) {
	stack := startDependencyStack(t)
	defer stack.shutdownAll(t)

	response := publishArtifactRequest(t, stack, "service/deployment", false, nil)
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}

	var payload publishResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode publish response: %v", err)
	}
	if !payload.Published {
		t.Fatalf("expected published response")
	}
}

func TestPublishValidOperatorCallerSucceeds(t *testing.T) {
	stack := startDependencyStack(t)
	defer stack.shutdownAll(t)

	response := publishArtifactRequest(t, stack, "operator", false, func(body map[string]any) {
		provenance := body["provenance"].(map[string]any)
		invoker := provenance["invoker"].(map[string]any)
		invoker["service"] = "operator"
		invoker["principal"] = "spiffe://monolith.internal/operator"
	})
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}
}

func TestPublishRejectsUnauthorizedCaller(t *testing.T) {
	stack := startDependencyStack(t)
	defer stack.shutdownAll(t)

	response := publishArtifactRequest(t, stack, "service/execution", false, nil)
	defer response.Body.Close()

	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}
}

func TestPublishRejectsBootstrapPKICaller(t *testing.T) {
	stack := startDependencyStack(t)
	defer stack.shutdownAll(t)

	response := publishArtifactRequest(t, stack, "service/deployment", true, nil)
	defer response.Body.Close()

	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}
}

func TestPublishIgnoresCallerSuppliedBuilderServiceAndESAccepts(t *testing.T) {
	stack := startDependencyStack(t)
	defer stack.shutdownAll(t)

	response := publishArtifactRequest(t, stack, "service/deployment", false, func(body map[string]any) {
		provenance := body["provenance"].(map[string]any)
		provenance["builder_service"] = "caller-controlled-builder"
	})
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}

	if err := json.NewDecoder(response.Body).Decode(&stack.publishResponse); err != nil {
		t.Fatalf("decode publish response: %v", err)
	}

	entry := stack.loadIndexEntry(t)
	var provenance map[string]any
	readJSONBlob(t, stack.rootDir, entry.ProvenanceDigest, &provenance)
	if got := provenance["payload"].(map[string]any)["claims"].(map[string]any)["builder_service"]; got != "artifact-governance" {
		t.Fatalf("expected builder_service artifact-governance, got %v", got)
	}

	startES(t, stack)
	response = doJSONRequest(t, stack.es.Addr(), http.MethodPost, "/v1/executions:prepare", stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "service/deployment", false), buildPrepareRequestBody(t, stack))
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 prepare, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}
}

func TestPublishRejectsDeploymentCallerMismatchedInvokerService(t *testing.T) {
	stack := startDependencyStack(t)
	defer stack.shutdownAll(t)

	response := publishArtifactRequest(t, stack, "service/deployment", false, func(body map[string]any) {
		provenance := body["provenance"].(map[string]any)
		invoker := provenance["invoker"].(map[string]any)
		invoker["service"] = "operator"
	})
	defer response.Body.Close()

	assertPublishError(t, response, http.StatusForbidden, "publish_forbidden")
}

func TestPublishRejectsDeploymentCallerMismatchedInvokerPrincipal(t *testing.T) {
	stack := startDependencyStack(t)
	defer stack.shutdownAll(t)

	response := publishArtifactRequest(t, stack, "service/deployment", false, func(body map[string]any) {
		provenance := body["provenance"].(map[string]any)
		invoker := provenance["invoker"].(map[string]any)
		invoker["principal"] = "spiffe://monolith.internal/service/other"
	})
	defer response.Body.Close()

	assertPublishError(t, response, http.StatusForbidden, "publish_forbidden")
}

func TestPublishRejectsOperatorCallerMismatchedInvokerFields(t *testing.T) {
	stack := startDependencyStack(t)
	defer stack.shutdownAll(t)

	response := publishArtifactRequest(t, stack, "operator", false, func(body map[string]any) {
		provenance := body["provenance"].(map[string]any)
		invoker := provenance["invoker"].(map[string]any)
		invoker["service"] = "deployment"
		invoker["principal"] = "spiffe://monolith.internal/service/deployment"
	})
	defer response.Body.Close()

	assertPublishError(t, response, http.StatusForbidden, "publish_forbidden")
}

func TestPublishRejectsInvalidWorkloadIdentityID(t *testing.T) {
	stack := startDependencyStack(t)
	defer stack.shutdownAll(t)

	response := publishArtifactRequest(t, stack, "service/deployment", false, func(body map[string]any) {
		binding := body["workload_identity_binding"].(map[string]any)
		binding["workload_identity_id"] = "not-a-spiffe-uri"
	})
	defer response.Body.Close()

	assertPublishError(t, response, http.StatusBadRequest, "invalid_request")
}

func TestPublishRejectsWorkloadIdentityIDServiceNameConflict(t *testing.T) {
	stack := startDependencyStack(t)
	defer stack.shutdownAll(t)

	response := publishArtifactRequest(t, stack, "service/deployment", false, func(body map[string]any) {
		binding := body["workload_identity_binding"].(map[string]any)
		binding["service_name"] = "payments"
	})
	defer response.Body.Close()

	assertPublishError(t, response, http.StatusConflict, "artifact_fact_conflict")
}

func TestPublishRejectsPolicyVersionConflict(t *testing.T) {
	stack := startDependencyStack(t)
	defer stack.shutdownAll(t)

	response := publishArtifactRequest(t, stack, "service/deployment", false, func(body map[string]any) {
		binding := body["workload_identity_binding"].(map[string]any)
		binding["policy_version"] = "different-policy-version"
	})
	defer response.Body.Close()

	assertPublishError(t, response, http.StatusConflict, "artifact_fact_conflict")
}

func TestPublishRejectsExpectedArtifactTypeConflict(t *testing.T) {
	stack := startDependencyStack(t)
	defer stack.shutdownAll(t)

	response := publishArtifactRequest(t, stack, "service/deployment", false, func(body map[string]any) {
		attestation := body["derivation_attestation"].(map[string]any)
		attestation["expected_artifact_type"] = "other-artifact-type"
	})
	defer response.Body.Close()

	assertPublishError(t, response, http.StatusConflict, "artifact_fact_conflict")
}

func TestPublishRejectsServiceWorkloadMissingServiceName(t *testing.T) {
	stack := startDependencyStack(t)
	defer stack.shutdownAll(t)

	response := publishArtifactRequest(t, stack, "service/deployment", false, func(body map[string]any) {
		binding := body["workload_identity_binding"].(map[string]any)
		delete(binding, "service_name")
	})
	defer response.Body.Close()

	assertPublishError(t, response, http.StatusConflict, "artifact_fact_conflict")
}

func TestPrepareRejectsTamperedPayloadAfterPublish(t *testing.T) {
	stack := startPublishOnlyStack(t)
	defer stack.shutdownAll(t)

	entry := stack.loadIndexEntry(t)
	var attestation map[string]any
	readJSONBlob(t, stack.rootDir, entry.DerivationAuthorizationAttestationDigest, &attestation)
	payload := attestation["payload"].(map[string]any)
	policy := payload["claims"].(map[string]any)["policy"].(map[string]any)
	policy["version"] = "tampered"
	stack.replaceIndexedBlobAndRestartARS(t, func(entry *arsindex.Entry) {
		entry.DerivationAuthorizationAttestationDigest = stack.writeJSONBlob(t, attestation)
	})

	startES(t, stack)
	assertPrepareError(t, stack, http.StatusForbidden, "derivation_attestation_invalid")
}

func TestPrepareRejectsTamperedSignatureAfterPublish(t *testing.T) {
	stack := startPublishOnlyStack(t)
	defer stack.shutdownAll(t)

	entry := stack.loadIndexEntry(t)
	var provenance map[string]any
	readJSONBlob(t, stack.rootDir, entry.ProvenanceDigest, &provenance)
	signature := provenance["signature"].(map[string]any)
	signature["signature_value"] = base64.StdEncoding.EncodeToString([]byte("invalid-signature"))
	stack.replaceIndexedBlobAndRestartARS(t, func(entry *arsindex.Entry) {
		entry.ProvenanceDigest = stack.writeJSONBlob(t, provenance)
	})

	startES(t, stack)
	assertPrepareError(t, stack, http.StatusForbidden, "provenance_invalid")
}

func TestPrepareRejectsCrossFactMismatchAfterPublish(t *testing.T) {
	stack := startPublishOnlyStack(t)
	defer stack.shutdownAll(t)

	entry := stack.loadIndexEntry(t)
	mismatchedBinding := signedWorkloadIdentityBindingJSON(
		t,
		stack.fixture,
		stack.publishResponse.ArtifactDigest,
		labeledDigest("99"),
		stack.workloadIdentityID,
		stack.outputID,
	)
	mismatchedBindingDigest := writeBlobBytes(t, stack.rootDir, mismatchedBinding)

	stack.replaceIndexedBlobAndRestartARS(t, func(entry *arsindex.Entry) {
		entry.WorkloadIdentityBindingDigest = mismatchedBindingDigest
	})

	_ = entry
	startES(t, stack)
	assertPrepareError(t, stack, http.StatusForbidden, "workload_identity_binding_invalid")
}

func TestPrepareRejectsMissingReferencedBlobAfterPublish(t *testing.T) {
	stack := startPublishOnlyStack(t)
	defer stack.shutdownAll(t)

	entry := stack.loadIndexEntry(t)
	removeBlob(t, stack.rootDir, entry.ManifestDigest)
	stack.restartARS(t)

	startES(t, stack)
	assertPrepareError(t, stack, http.StatusNotFound, "manifest_not_found")
}

type publishedStack struct {
	fixture *tlsFixture

	rootDir   string
	indexPath string

	acs *acsapp.App
	ars *arsapp.App
	egs *egsapp.App
	ags *agsapp.App
	es  *esapp.App

	acsRunning bool
	arsRunning bool
	egsRunning bool
	agsRunning bool
	esRunning  bool

	publishResponse publishResponse

	intentDigest            string
	derivationSpecDigest    string
	outputID                string
	workloadIdentityID      string
	workloadZoneVaultDigest string
}

type publishResponse struct {
	Published                                bool   `json:"published"`
	ArtifactDigest                           string `json:"artifact_digest"`
	ManifestDigest                           string `json:"manifest_digest"`
	ProvenanceDigest                         string `json:"provenance_digest"`
	PayloadDigest                            string `json:"payload_digest"`
	DerivationMetadataDigest                 string `json:"derivation_metadata_digest"`
	DerivationAuthorizationAttestationDigest string `json:"derivation_authorization_attestation_digest"`
	WorkloadIdentityBindingDigest            string `json:"workload_identity_binding_digest"`
}

func startPublishedStack(t *testing.T) *publishedStack {
	t.Helper()

	stack := startPublishOnlyStack(t)
	startES(t, stack)
	return stack
}

func startPublishOnlyStack(t *testing.T) *publishedStack {
	t.Helper()

	stack := startDependencyStack(t)
	publishArtifact(t, stack)
	return stack
}

func startDependencyStack(t *testing.T) *publishedStack {
	t.Helper()

	fixture := newTLSFixture(t)
	rootDir := filepath.Join(t.TempDir(), "ars-storage")
	if err := os.MkdirAll(rootDir, 0o755); err != nil {
		t.Fatalf("mkdir ars storage root: %v", err)
	}
	indexPath := filepath.Join(t.TempDir(), "artifact-index.json")
	if err := os.WriteFile(indexPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write empty artifact index: %v", err)
	}

	workloadZoneVaultBytes := mustMarshalJSON(t, map[string]any{
		"vault_config": map[string]any{
			"address":      "https://vault.internal:8200",
			"auth_mount":   "jwt",
			"auth_role":    "service_execution",
			"jwt_audience": "vault",
		},
	})
	workloadZoneVaultDigest := writeBlobBytes(t, rootDir, workloadZoneVaultBytes)

	stack := &publishedStack{
		fixture:                 fixture,
		rootDir:                 rootDir,
		indexPath:               indexPath,
		intentDigest:            labeledDigest("aa"),
		derivationSpecDigest:    labeledDigest("bb"),
		outputID:                "runtime",
		workloadIdentityID:      "spiffe://monolith.internal/service/execution",
		workloadZoneVaultDigest: workloadZoneVaultDigest,
	}

	arsService, err := arsapp.New(buildARSConfig(stack))
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
				AllowedSigners: []string{fixture.agsKeyID},
				RevokedSigners: []string{},
			},
			ArtifactPolicy: egsmodel.ArtifactPolicy{
				RevokedArtifacts: []string{},
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

	agsCfg := agsconfig.Config{
		HTTP: agsconfig.HTTPConfig{
			BindAddress:            "127.0.0.1",
			Port:                   0,
			ReadTimeoutSeconds:     5,
			WriteTimeoutSeconds:    5,
			ShutdownTimeoutSeconds: 5,
		},
		TLS: agsconfig.TLSConfig{
			CertFile:     fixture.agsServerCertPath,
			KeyFile:      fixture.agsServerKeyPath,
			ClientCAFile: fixture.clientCAPath,
		},
		Security: agsconfig.SecurityConfig{
			BootstrapIssuerCommonName: fixture.bootstrapCACN,
		},
		Dependencies: agsconfig.DependenciesConfig{
			ArtifactRegistry: agsconfig.DependencyConfig{
				BaseURL:        "https://" + stack.ars.Addr(),
				ServerName:     fixture.arsServerName,
				ClientCertFile: fixture.agsClientCertPath,
				ClientKeyFile:  fixture.agsClientKeyPath,
				RootCAFile:     fixture.runtimeCAPath,
				TimeoutSeconds: 5,
			},
		},
		Signer: agsconfig.SignerConfig{
			Algorithm:     "ed25519",
			KeyID:         fixture.agsKeyID,
			PrivateKeyHex: fixture.agsPrivateKeyHex,
			PublicKeyHex:  fixture.agsPublicKeyHex,
		},
	}
	agsService, err := agsapp.New(agsCfg)
	if err != nil {
		t.Fatalf("build ags app: %v", err)
	}
	stack.ags = agsService
	startService(t, agsService.Start, agsService.Addr, fixture.serverTLSConfig(t, fixture.agsServerName))
	stack.agsRunning = true

	return stack
}

func startES(t *testing.T, stack *publishedStack) {
	t.Helper()

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
			DefaultMode: esconfig.WorkloadVaultAuthModeVaultIdentityJWT,
		},
	}

	service, err := esapp.New(cfg)
	if err != nil {
		t.Fatalf("build es app: %v", err)
	}
	stack.es = service
	startService(t, service.Start, service.Addr, stack.fixture.serverTLSConfig(t, stack.fixture.esServerName))
	stack.esRunning = true
}

func publishArtifact(t *testing.T, stack *publishedStack) {
	t.Helper()

	response := publishArtifactRequest(t, stack, "service/deployment", false, nil)
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}

	if err := json.NewDecoder(response.Body).Decode(&stack.publishResponse); err != nil {
		t.Fatalf("decode publish response: %v", err)
	}
	if !stack.publishResponse.Published {
		t.Fatalf("expected published response")
	}
}

func publishArtifactRequest(t *testing.T, stack *publishedStack, callerPath string, bootstrap bool, mutate func(map[string]any)) *http.Response {
	t.Helper()

	requestBody := buildPublishRequestBody(t, stack)
	if mutate != nil {
		mutate(requestBody)
	}

	return doJSONRequest(
		t,
		stack.ags.Addr(),
		http.MethodPost,
		"/v1/artifacts:publish",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.agsServerName, callerPath, bootstrap),
		mustMarshalJSON(t, requestBody),
	)
}

func buildPublishRequestBody(t *testing.T, stack *publishedStack) map[string]any {
	t.Helper()

	return map[string]any{
		"artifact_payload_b64": base64.StdEncoding.EncodeToString([]byte("artifact payload bytes")),
		"manifest": map[string]any{
			"artifact_type": "static-service",
			"intent_digest": stack.intentDigest,
			"runtime_interface": map[string]any{
				"parameters":            []string{},
				"environment_variables": []string{"APP_MODE"},
				"required_capabilities": []string{},
			},
		},
		"provenance": map[string]any{
			"builder_service": "artifact-governance",
			"invoker": map[string]any{
				"service":   "deployment",
				"principal": "spiffe://monolith.internal/service/deployment",
			},
			"policy_decisions": []map[string]any{
				{"rule": "allow", "result": "applied"},
			},
			"build_log_digest": labeledDigest("ee"),
		},
		"derivation_metadata": map[string]any{
			"derivation_spec_digest": stack.derivationSpecDigest,
			"output_id":              stack.outputID,
			"producer_run_id":        "build-run-1",
		},
		"derivation_attestation": map[string]any{
			"constraints": map[string]any{
				"allowed_toolchains":      []string{},
				"forbidden_toolchains":    []string{},
				"os":                      "linux",
				"arch":                    "amd64",
				"network_access":          false,
				"writable_paths":          []string{},
				"forbidden_paths":         []string{},
				"determinism_expectation": "deterministic",
			},
			"policy_version":         "2026-03-31",
			"expected_artifact_type": "static-service",
		},
		"workload_identity_binding": map[string]any{
			"artifact_class":       "service",
			"workload_type":        "service",
			"module_path":          "services.execution.ExecutionServer",
			"policy_version":       "2026-03-31",
			"service_name":         "execution",
			"target_platform":      "docker",
			"description":          "Execution workload",
			"workload_identity_id": stack.workloadIdentityID,
		},
	}
}

func assertPublishError(t *testing.T, response *http.Response, expectedStatus int, expectedCode string) {
	t.Helper()

	if response.StatusCode != expectedStatus {
		t.Fatalf("expected %d, got %d body=%s", expectedStatus, response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}

	var payload map[string]any
	if strings.Contains(response.Header.Get("Content-Type"), "application/json") {
		if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
			t.Fatalf("decode publish error response: %v", err)
		}
		if payload["success"] != false {
			t.Fatalf("expected success=false, got %v", payload["success"])
		}
		if expectedCode != "" && payload["code"] != expectedCode {
			t.Fatalf("expected code %q, got %v", expectedCode, payload["code"])
		}
	}
}

func buildARSConfig(stack *publishedStack) arsconfig.Config {
	return arsconfig.Config{
		HTTP: arsconfig.HTTPConfig{
			BindAddress:            "127.0.0.1",
			Port:                   0,
			ReadTimeoutSeconds:     5,
			WriteTimeoutSeconds:    5,
			ShutdownTimeoutSeconds: 5,
		},
		TLS: arsconfig.TLSConfig{
			CertFile:     stack.fixture.arsServerCertPath,
			KeyFile:      stack.fixture.arsServerKeyPath,
			ClientCAFile: stack.fixture.clientCAPath,
		},
		Authorization: arsconfig.AuthorizationConfig{
			AllowedSPIFFEPathPrefixes: []string{"service/execution"},
		},
		Storage: arsconfig.StorageConfig{
			RootDir:   stack.rootDir,
			IndexFile: stack.indexPath,
		},
	}
}

func buildPrepareRequestBody(t *testing.T, stack *publishedStack) []byte {
	t.Helper()
	return mustMarshalJSON(t, admission.PrepareRequest{
		SchemaVersion: "v1",
		Invocation: admission.ArtifactInvocation{
			SchemaVersion:        "v1",
			ArtifactDigest:       stack.publishResponse.ArtifactDigest,
			DerivationSpecDigest: stack.derivationSpecDigest,
			OutputID:             stack.outputID,
			Env: map[string]string{
				"APP_MODE": "test",
			},
		},
		Mode: admission.ExecutionModeAsync,
	})
}

func assertPrepareError(t *testing.T, stack *publishedStack, expectedStatus int, expectedCode string) {
	t.Helper()

	response := doJSONRequest(t, stack.es.Addr(), http.MethodPost, "/v1/executions:prepare", stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "service/deployment", false), buildPrepareRequestBody(t, stack))
	defer response.Body.Close()

	if response.StatusCode != expectedStatus {
		t.Fatalf("expected %d, got %d body=%s", expectedStatus, response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}

	var payload admission.ErrorResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if payload.Code != expectedCode {
		t.Fatalf("expected code %q, got %q", expectedCode, payload.Code)
	}
}

func (s *publishedStack) shutdownAll(t *testing.T) {
	t.Helper()
	for _, step := range []struct {
		running *bool
		name    string
		stop    func(context.Context) error
	}{
		{&s.esRunning, "es", func(ctx context.Context) error { return s.es.Shutdown(ctx) }},
		{&s.agsRunning, "ags", func(ctx context.Context) error { return s.ags.Shutdown(ctx) }},
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

func (s *publishedStack) restartARS(t *testing.T) {
	t.Helper()
	if s.arsRunning {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := s.ars.Shutdown(shutdownCtx)
		cancel()
		if err != nil {
			t.Fatalf("shutdown ars: %v", err)
		}
		s.arsRunning = false
	}

	arsService, err := arsapp.New(buildARSConfig(s))
	if err != nil {
		t.Fatalf("rebuild ars app: %v", err)
	}
	s.ars = arsService
	startService(t, arsService.Start, arsService.Addr, s.fixture.serverTLSConfig(t, s.fixture.arsServerName))
	s.arsRunning = true
}

func (s *publishedStack) loadIndexEntry(t *testing.T) arsindex.Entry {
	t.Helper()
	data, err := os.ReadFile(s.indexPath)
	if err != nil {
		t.Fatalf("read artifact index: %v", err)
	}
	var entries map[string]arsindex.Entry
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatalf("decode artifact index: %v", err)
	}
	entry, ok := entries[s.publishResponse.ArtifactDigest]
	if !ok {
		t.Fatalf("missing artifact index entry for %s", s.publishResponse.ArtifactDigest)
	}
	return entry
}

func (s *publishedStack) replaceIndexedBlobAndRestartARS(t *testing.T, mutate func(*arsindex.Entry)) {
	t.Helper()

	if s.arsRunning {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := s.ars.Shutdown(shutdownCtx)
		cancel()
		if err != nil {
			t.Fatalf("shutdown ars: %v", err)
		}
		s.arsRunning = false
	}

	data, err := os.ReadFile(s.indexPath)
	if err != nil {
		t.Fatalf("read artifact index: %v", err)
	}
	var entries map[string]arsindex.Entry
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatalf("decode artifact index: %v", err)
	}
	entry := entries[s.publishResponse.ArtifactDigest]
	mutate(&entry)
	entries[s.publishResponse.ArtifactDigest] = entry

	if err := os.WriteFile(s.indexPath, append(mustMarshalJSON(t, entries), '\n'), 0o600); err != nil {
		t.Fatalf("write mutated artifact index: %v", err)
	}

	s.restartARS(t)
}

func (s *publishedStack) writeJSONBlob(t *testing.T, value any) string {
	t.Helper()
	return writeBlobBytes(t, s.rootDir, mustMarshalJSON(t, value))
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
	egsPublicKeyHex  string
	egsPrivateKeyHex string

	agsKeyID         string
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
		t, dir, "execution-client", runtimeCA, runtimeCAKey, "client.service.execution",
		[]*url.URL{mustSPIFFEURL(t, "spiffe://monolith.internal/service/execution")},
	)
	agsClientCertPath, agsClientKeyPath := writeLeafCertificateFiles(
		t, dir, "ags-client", runtimeCA, runtimeCAKey, "client.service.artifact-governance",
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
		egsKeyID:                "egs-trust-model-signer",
		egsPublicKeyHex:         hex.EncodeToString(egsPublicKey),
		egsPrivateKeyHex:        hex.EncodeToString(egsPrivateKey),
		agsKeyID:                "ags-artifact-fact-signer",
		agsPublicKeyHex:         hex.EncodeToString(agsPublicKey),
		agsPrivateKey:           agsPrivateKey,
		agsPrivateKeyHex:        hex.EncodeToString(agsPrivateKey),
		bootstrapCACN:           "bootstrap-ca",
	}
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

func signedWorkloadIdentityBindingJSON(t *testing.T, fixture *tlsFixture, artifactDigest string, derivationSpecDigest string, workloadIdentityID string, outputID string) []byte {
	t.Helper()

	payload := signingv2.WorkloadIdentityBindingPayload{
		Kind: signingv2.KindWorkloadIdentityBinding,
		Subject: signingv2.WorkloadIdentitySubject{
			ArtifactClass:        "service",
			ArtifactDigest:       artifactDigest,
			DerivationSpecDigest: derivationSpecDigest,
			OutputID:             outputID,
		},
		Claims: signingv2.WorkloadIdentityBindingClaims{
			Descriptor: signingv2.WorkloadDescriptor{
				WorkloadType:       "service",
				ModulePath:         "services.execution.ExecutionServer",
				ServiceName:        "execution",
				TargetPlatform:     "docker",
				Description:        "Execution workload",
				WorkloadIdentityID: workloadIdentityID,
			},
			Policy: signingv2.WorkloadPolicy{
				Version: "2026-03-31",
			},
		},
	}
	canonical, err := signingv2.CanonicalWorkloadIdentityBindingPayload(payload)
	if err != nil {
		t.Fatalf("canonicalize workload identity binding: %v", err)
	}
	signature := signingv2.NewEnvelope(canonical, fixture.agsKeyID, "ed25519", base64.StdEncoding.EncodeToString(ed25519.Sign(fixture.agsPrivateKey, canonical)))

	return mustMarshalJSON(t, map[string]any{
		"payload":   payload,
		"signature": signature,
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
