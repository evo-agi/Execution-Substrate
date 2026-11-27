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

	agsapp "execution-substrate/ags/app"
	agsconfig "execution-substrate/ags/config"
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
	"execution-substrate/internal/callerauth"
	evidencev1 "execution-substrate/internal/contracts/evidence/v1"
	runtimeconfigv1 "execution-substrate/internal/contracts/runtimeconfig/v1"
)

const (
	operatorCallerPath = "operator/local"
	operatorSPIFFEID   = "spiffe://execution.internal/" + operatorCallerPath
)

func TestPublishFlowProducesArtifactESAccepts(t *testing.T) {
	stack := startPublishedStack(t)
	defer stack.shutdownAll(t)

	response := doJSONRequest(t, stack.es.Addr(), http.MethodPost, "/v1/executions:prepare", stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, operatorCallerPath, false), buildPrepareRequestBody(t, stack))
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
	if strings.TrimSpace(stack.publishResponse.DiscoveryDigest) == "" {
		t.Fatalf("expected discovery digest in publish response")
	}
	entry, discovery := stack.loadDiscovery(t)
	if entry.DiscoveryDigest != stack.publishResponse.DiscoveryDigest {
		t.Fatalf("expected index discovery digest %q, got %q", stack.publishResponse.DiscoveryDigest, entry.DiscoveryDigest)
	}
	var evidence evidencev1.ArtifactEvidence
	readJSONBlob(t, stack.rootDir, discovery.Evidence.Digest, &evidence)
	if evidence.Claims.Package.Identity.ArtifactDigest != stack.publishResponse.ArtifactDigest {
		t.Fatalf("unexpected evidence artifact digest: %q", evidence.Claims.Package.Identity.ArtifactDigest)
	}
	if stack.publishResponse.ArtifactDigest == stack.publishResponse.PayloadDigest {
		t.Fatalf("expected artifact and payload digests to differ, both were %q", stack.publishResponse.ArtifactDigest)
	}
	if discovery.Payload.Digest != stack.publishResponse.PayloadDigest {
		t.Fatalf("expected discovery payload digest %q, got %q", stack.publishResponse.PayloadDigest, discovery.Payload.Digest)
	}
	if evidence.Claims.Package.Identity.PayloadDigest != stack.publishResponse.PayloadDigest {
		t.Fatalf("expected evidence payload digest %q, got %q", stack.publishResponse.PayloadDigest, evidence.Claims.Package.Identity.PayloadDigest)
	}
}

func TestPublishDerivesArtifactIdentityDistinctFromPayloadIdentity(t *testing.T) {
	stack := startPublishOnlyStack(t)
	defer stack.shutdownAll(t)

	if stack.publishResponse.ArtifactDigest == stack.publishResponse.PayloadDigest {
		t.Fatalf("expected artifact identity to differ from payload identity, both were %q", stack.publishResponse.ArtifactDigest)
	}

	entry, discovery := stack.loadDiscovery(t)
	if entry.ArtifactDigest != stack.publishResponse.ArtifactDigest {
		t.Fatalf("expected index artifact digest %q, got %q", stack.publishResponse.ArtifactDigest, entry.ArtifactDigest)
	}
	if discovery.Payload.Digest != stack.publishResponse.PayloadDigest {
		t.Fatalf("expected discovery payload digest %q, got %q", stack.publishResponse.PayloadDigest, discovery.Payload.Digest)
	}
}

func TestPublishRejectsDeploymentCaller(t *testing.T) {
	stack := startDependencyStack(t)
	defer stack.shutdownAll(t)

	response := publishArtifactRequest(t, stack, "service/deployment", false, nil)
	defer response.Body.Close()

	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}
}

func TestPublishValidOperatorCallerSucceeds(t *testing.T) {
	stack := startDependencyStack(t)
	defer stack.shutdownAll(t)

	response := publishArtifactRequest(t, stack, operatorCallerPath, false, nil)
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}
}

func TestPublishAllowsConfiguredControlPlaneCaller(t *testing.T) {
	stack := startDependencyStackWithAGSAllowedCallers(t, []string{"service/control-plane"})
	defer stack.shutdownAll(t)

	response := publishArtifactRequest(t, stack, "service/control-plane", false, nil)
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}

	if err := json.NewDecoder(response.Body).Decode(&stack.publishResponse); err != nil {
		t.Fatalf("decode publish response: %v", err)
	}

	_, discovery := stack.loadDiscovery(t)
	var evidence map[string]any
	readJSONBlob(t, stack.rootDir, discovery.Evidence.Digest, &evidence)
	publication := evidence["claims"].(map[string]any)["package"].(map[string]any)["publication"].(map[string]any)
	invoker := publication["invoker"].(map[string]any)
	if got := invoker["service"]; got != "service/control-plane" {
		t.Fatalf("expected invoker service derived from configured caller path, got %v", got)
	}
	if got := invoker["principal"]; got != "spiffe://execution.internal/service/control-plane" {
		t.Fatalf("expected invoker principal derived from configured caller identity, got %v", got)
	}
}

// AGS applies security.namespace_issuers from its configuration: a CA bound
// to a namespace vouches for no path outside it, and a path in a bound
// namespace needs that namespace's CA. Both callers below are allowed and
// their certificates come from the same client CA, so only the binding
// tells them apart.
func TestPublishAppliesConfiguredNamespaceIssuers(t *testing.T) {
	for _, tc := range []struct {
		name      string
		boundToCA bool
		operator  int
		user      int
	}{
		{name: "user_bound_to_the_client_CA", boundToCA: true, operator: http.StatusUnauthorized, user: http.StatusOK},
		{name: "user_bound_to_another_CA", boundToCA: false, operator: http.StatusOK, user: http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stack := startDependencyStackWithAGSConfig(t, []string{operatorCallerPath, "user/claude"}, func(fixture *tlsFixture) []callerauth.NamespaceIssuerConfig {
				digest := sha256.Sum256(fixture.runtimeCA.Raw)
				if !tc.boundToCA {
					digest = sha256.Sum256(fixture.bootstrapCA.Raw)
				}
				return []callerauth.NamespaceIssuerConfig{{PathPrefix: "user", IssuerCertificateSHA256: hex.EncodeToString(digest[:])}}
			})
			defer stack.shutdownAll(t)
			for _, caller := range []struct {
				path string
				want int
			}{{operatorCallerPath, tc.operator}, {"user/claude", tc.user}} {
				response := publishArtifactRequest(t, stack, caller.path, false, nil)
				body := strings.TrimSpace(string(mustReadBody(t, response.Body)))
				response.Body.Close()
				if response.StatusCode != caller.want {
					t.Fatalf("publish as %s: want %d, got %d body=%s", caller.path, caller.want, response.StatusCode, body)
				}
				if caller.want == http.StatusUnauthorized && body != "Authenticated caller identity required" {
					t.Fatalf("publish as %s: unexpected body %q", caller.path, body)
				}
			}
		})
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

	response := publishArtifactRequest(t, stack, operatorCallerPath, true, nil)
	defer response.Body.Close()

	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}
}

func TestPublishDerivesBuilderServiceAndCallerBindingInEvidence(t *testing.T) {
	stack := startDependencyStack(t)
	defer stack.shutdownAll(t)

	response := publishArtifactRequest(t, stack, operatorCallerPath, false, nil)
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}

	if err := json.NewDecoder(response.Body).Decode(&stack.publishResponse); err != nil {
		t.Fatalf("decode publish response: %v", err)
	}

	_, discovery := stack.loadDiscovery(t)
	var evidence map[string]any
	readJSONBlob(t, stack.rootDir, discovery.Evidence.Digest, &evidence)
	claims := evidence["claims"].(map[string]any)
	pkg := claims["package"].(map[string]any)
	publication := pkg["publication"].(map[string]any)
	if got := publication["builder_service"]; got != "artifact-governance" {
		t.Fatalf("expected builder_service artifact-governance, got %v", got)
	}
	invoker := publication["invoker"].(map[string]any)
	if got := invoker["service"]; got != operatorCallerPath {
		t.Fatalf("expected invoker service %s, got %v", operatorCallerPath, got)
	}
	if got := invoker["principal"]; got != operatorSPIFFEID {
		t.Fatalf("expected invoker principal derived from caller, got %v", got)
	}
	admission := claims["admission"].(map[string]any)
	authorization := admission["authorization"].(map[string]any)
	execution := admission["execution"].(map[string]any)
	if _, ok := admission["runtime"]; ok {
		t.Fatalf("expected evidence admission claims to omit the old mixed runtime field, got %v", admission["runtime"])
	}
	derivation := authorization["derivation"].(map[string]any)
	if got := derivation["derivation_spec_digest"]; got != stack.derivationSpecDigest {
		t.Fatalf("expected derivation_spec_digest %q, got %v", stack.derivationSpecDigest, got)
	}
	if got := derivation["output_id"]; got != stack.outputID {
		t.Fatalf("expected output_id %q, got %v", stack.outputID, got)
	}
	if _, ok := authorization["workload_binding"]; ok {
		t.Fatalf("expected workload_binding to be absent from authorization claims, got %v", authorization["workload_binding"])
	}
	if _, ok := derivation["producer_run_id"]; ok {
		t.Fatalf("expected producer_run_id to be absent from authorization derivation claims, got %v", derivation["producer_run_id"])
	}
	if _, ok := derivation["policy_version"]; ok {
		t.Fatalf("expected policy_version to be absent from authorization derivation claims, got %v", derivation["policy_version"])
	}
	if _, ok := derivation["expected_artifact_type"]; ok {
		t.Fatalf("expected expected_artifact_type to be absent from authorization derivation claims, got %v", derivation["expected_artifact_type"])
	}
	if _, ok := derivation["constraints"]; ok {
		t.Fatalf("expected constraints to be absent from authorization derivation claims, got %v", derivation["constraints"])
	}
	if got := execution["access"].(map[string]any)["network_access"]; got != false {
		t.Fatalf("expected execution access network_access false, got %v", got)
	}
	workload := execution["workload"].(map[string]any)
	if got := workload["target_platform"]; got != "docker" {
		t.Fatalf("expected execution workload target_platform docker, got %v", got)
	}
	for _, removed := range []string{"artifact_class", "workload_type", "service_name", "workload_identity_id", "description"} {
		if _, ok := workload[removed]; ok {
			t.Fatalf("did not expect removed execution workload field %q in evidence, got %v", removed, workload)
		}
	}
	runtime := execution["runtime"].(map[string]any)
	if _, ok := runtime["parameters"]; ok {
		t.Fatalf("did not expect removed execution runtime field parameters in evidence, got %v", runtime)
	}

	startES(t, stack)
	response = doJSONRequest(t, stack.es.Addr(), http.MethodPost, "/v1/executions:prepare", stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, operatorCallerPath, false), buildPrepareRequestBody(t, stack))
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 prepare, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}
}

func TestPublishResponseAndIndexAreEvidenceOnly(t *testing.T) {
	stack := startPublishOnlyStack(t)
	defer stack.shutdownAll(t)

	if strings.Contains(string(stack.publishResponseBody), `"compatibility"`) || strings.Contains(string(stack.publishResponseBody), `"legacy_signing_v2"`) {
		t.Fatalf("expected publish response to omit legacy compatibility inventory, got %s", strings.TrimSpace(string(stack.publishResponseBody)))
	}
	if !strings.Contains(string(stack.publishResponseBody), `"discovery_digest"`) {
		t.Fatalf("expected publish response to expose discovery digest, got %s", strings.TrimSpace(string(stack.publishResponseBody)))
	}

	indexBytes, err := os.ReadFile(stack.indexPath)
	if err != nil {
		t.Fatalf("read artifact index: %v", err)
	}
	if strings.Contains(string(indexBytes), `"compatibility"`) || strings.Contains(string(indexBytes), `"legacy_signing_v2"`) {
		t.Fatalf("expected artifact index to omit legacy compatibility inventory, got %s", strings.TrimSpace(string(indexBytes)))
	}
	if !strings.Contains(string(indexBytes), `"discovery_digest"`) {
		t.Fatalf("expected artifact index to expose primary discovery digest, got %s", strings.TrimSpace(string(indexBytes)))
	}
}

func TestPublishArtifactIdentityIgnoresAdmissionOnlyChanges(t *testing.T) {
	first := startPublishOnlyStack(t)
	defer first.shutdownAll(t)

	second := startDependencyStack(t)
	defer second.shutdownAll(t)

	response := publishArtifactRequest(t, second, operatorCallerPath, false, func(body map[string]any) {
		admissionBody := body["admission"].(map[string]any)
		runtime := admissionBody["runtime"].(map[string]any)
		runtime["environment_variables"] = []string{"APP_MODE", "EXTRA_FLAG"}

		workload := admissionBody["workload"].(map[string]any)
		workload["target_platform"] = "docker"
	})
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}

	var payload publishResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode publish response: %v", err)
	}

	if payload.ArtifactDigest != first.publishResponse.ArtifactDigest {
		t.Fatalf("expected admission-only changes to preserve artifact identity: first=%q second=%q", first.publishResponse.ArtifactDigest, payload.ArtifactDigest)
	}
	if payload.DiscoveryDigest == first.publishResponse.DiscoveryDigest {
		t.Fatalf("expected admission-only changes to alter primary discovery, both were %q", payload.DiscoveryDigest)
	}
}

func TestPublishRejectsLegacyPublicationBuilderField(t *testing.T) {
	stack := startDependencyStack(t)
	defer stack.shutdownAll(t)

	response := publishArtifactRequest(t, stack, operatorCallerPath, false, func(body map[string]any) {
		publication := body["publication"].(map[string]any)
		publication["builder_service"] = "caller-controlled-builder"
	})
	defer response.Body.Close()

	assertPublishError(t, response, http.StatusBadRequest, "invalid_request")
}

func TestPublishRejectsLegacyPublicationInvokerField(t *testing.T) {
	stack := startDependencyStack(t)
	defer stack.shutdownAll(t)

	response := publishArtifactRequest(t, stack, operatorCallerPath, false, func(body map[string]any) {
		publication := body["publication"].(map[string]any)
		publication["invoker"] = map[string]any{
			"service":   operatorCallerPath,
			"principal": operatorSPIFFEID,
		}
	})
	defer response.Body.Close()

	assertPublishError(t, response, http.StatusBadRequest, "invalid_request")
}

func TestPublishRejectsRemovedWorkloadIdentityIDField(t *testing.T) {
	stack := startDependencyStack(t)
	defer stack.shutdownAll(t)

	response := publishArtifactRequest(t, stack, operatorCallerPath, false, func(body map[string]any) {
		admissionBody := body["admission"].(map[string]any)
		binding := admissionBody["workload"].(map[string]any)
		binding["workload_identity_id"] = "not-a-spiffe-uri"
	})
	defer response.Body.Close()

	assertPublishError(t, response, http.StatusBadRequest, "invalid_request")
}

func TestPublishRejectsRemovedServiceNameField(t *testing.T) {
	stack := startDependencyStack(t)
	defer stack.shutdownAll(t)

	response := publishArtifactRequest(t, stack, operatorCallerPath, false, func(body map[string]any) {
		admissionBody := body["admission"].(map[string]any)
		binding := admissionBody["workload"].(map[string]any)
		binding["service_name"] = "payments"
	})
	defer response.Body.Close()

	assertPublishError(t, response, http.StatusBadRequest, "invalid_request")
}

func TestPublishRejectsRemovedDerivationPolicyVersionField(t *testing.T) {
	stack := startDependencyStack(t)
	defer stack.shutdownAll(t)

	response := publishArtifactRequest(t, stack, operatorCallerPath, false, func(body map[string]any) {
		admissionBody := body["admission"].(map[string]any)
		derivation := admissionBody["derivation"].(map[string]any)
		derivation["policy_version"] = "2026-03-31"
	})
	defer response.Body.Close()

	assertPublishError(t, response, http.StatusBadRequest, "invalid_request")
}

func TestPublishRejectsRemovedWorkloadBindingFields(t *testing.T) {
	stack := startDependencyStack(t)
	defer stack.shutdownAll(t)

	response := publishArtifactRequest(t, stack, operatorCallerPath, false, func(body map[string]any) {
		admissionBody := body["admission"].(map[string]any)
		workload := admissionBody["workload"].(map[string]any)
		workload["module_path"] = "services.execution.ExecutionServer"
		workload["policy_version"] = "2026-03-31"
	})
	defer response.Body.Close()

	assertPublishError(t, response, http.StatusBadRequest, "invalid_request")
}

func TestWorkstreamBPublishRejectsControlPlaneProofGrammar(t *testing.T) {
	for _, field := range []string{
		"attempt_manifest",
		"retained_result_manifest",
		"review",
		"checkpoint",
		"finalization",
	} {
		t.Run(field, func(t *testing.T) {
			stack := startDependencyStack(t)
			defer stack.shutdownAll(t)

			response := publishArtifactRequest(t, stack, operatorCallerPath, false, func(body map[string]any) {
				body[field] = map[string]any{"source": "cp-proof-example"}
			})
			defer response.Body.Close()

			assertPublishError(t, response, http.StatusBadRequest, "invalid_request")
		})
	}
}

func TestPrepareRejectsTamperedEvidenceAfterPublish(t *testing.T) {
	stack := startPublishOnlyStack(t)
	defer stack.shutdownAll(t)

	_, discovery := stack.loadDiscovery(t)
	var evidence map[string]any
	readJSONBlob(t, stack.rootDir, discovery.Evidence.Digest, &evidence)
	claims := evidence["claims"].(map[string]any)
	admissionPayload := claims["admission"].(map[string]any)
	execution := admissionPayload["execution"].(map[string]any)
	workload := execution["workload"].(map[string]any)
	workload["target_platform"] = "not-docker"
	stack.mutateDiscoveryAndRestartARS(t, func(discovery *arsapi.ArtifactDiscovery) {
		discovery.Evidence.Digest = stack.writeJSONBlob(t, evidence)
	})

	startES(t, stack)
	assertPrepareError(t, stack, http.StatusForbidden, "artifact_evidence_invalid")
}

func TestPrepareRejectsMissingEvidenceBlobAfterPublish(t *testing.T) {
	stack := startPublishOnlyStack(t)
	defer stack.shutdownAll(t)

	_, discovery := stack.loadDiscovery(t)
	removeBlob(t, stack.rootDir, discovery.Evidence.Digest)
	stack.restartARS(t)

	startES(t, stack)
	assertPrepareError(t, stack, http.StatusServiceUnavailable, "artifact_evidence_unavailable")
}

type publishedStack struct {
	fixture *tlsFixture

	rootDir   string
	indexPath string

	ars *arsapp.App
	egs *egsapp.App
	ags *agsapp.App
	es  *esapp.App

	arsRunning bool
	egsRunning bool
	agsRunning bool
	esRunning  bool

	publishResponse     publishResponse
	publishResponseBody []byte

	intentDigest            string
	derivationSpecDigest    string
	outputID                string
	workloadZoneVaultDigest string
}

type publishResponse struct {
	Published        bool   `json:"published"`
	ArtifactDigest   string `json:"artifact_digest"`
	DiscoveryDigest  string `json:"discovery_digest"`
	DescriptorDigest string `json:"descriptor_digest"`
	EvidenceDigest   string `json:"evidence_digest"`
	ManifestDigest   string `json:"manifest_digest"`
	PayloadDigest    string `json:"payload_digest"`
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
	return startDependencyStackWithAGSAllowedCallers(t, []string{operatorCallerPath})
}

func startDependencyStackWithAGSAllowedCallers(t *testing.T, allowedPrefixes []string) *publishedStack {
	t.Helper()
	return startDependencyStackWithAGSConfig(t, allowedPrefixes, nil)
}

// startDependencyStackWithAGSConfig starts the stack with AGS allowing
// allowedPrefixes and, when namespaceIssuers is set, with the
// security.namespace_issuers it returns for the stack's TLS fixture.
func startDependencyStackWithAGSConfig(t *testing.T, allowedPrefixes []string, namespaceIssuers func(*tlsFixture) []callerauth.NamespaceIssuerConfig) *publishedStack {
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
		workloadZoneVaultDigest: workloadZoneVaultDigest,
	}

	arsService, err := arsapp.New(buildARSConfig(stack))
	if err != nil {
		t.Fatalf("build ars app: %v", err)
	}
	stack.ars = arsService
	startService(t, arsService.Start, arsService.Addr, fixture.clientTLSConfigForServer(t, fixture.arsServerName, "service/execution", false))
	stack.arsRunning = true

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
				AllowedSigners: []string{fixture.agsKeyID},
				RevokedSigners: []string{},
			},
			ArtifactPolicy: egsmodel.ArtifactPolicy{
				RevokedArtifacts: []string{},
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
		Authorization: agsconfig.AuthorizationConfig{
			AllowedSPIFFEPathPrefixes: append([]string(nil), allowedPrefixes...),
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
	if namespaceIssuers != nil {
		agsCfg.Security.NamespaceIssuers = namespaceIssuers(fixture)
	}
	agsService, err := agsapp.New(agsCfg)
	if err != nil {
		t.Fatalf("build ags app: %v", err)
	}
	stack.ags = agsService
	startService(t, agsService.Start, agsService.Addr, fixture.clientTLSConfigForServer(t, fixture.agsServerName, operatorCallerPath, false))
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
		Authorization: esconfig.AuthorizationConfig{
			AllowedSPIFFEPathPrefixes: []string{operatorCallerPath},
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
			DefaultMode: esconfig.WorkloadVaultAuthModeVaultIdentityJWT,
		},
	}

	service, err := esapp.New(cfg)
	if err != nil {
		t.Fatalf("build es app: %v", err)
	}
	stack.es = service
	startService(t, service.Start, service.Addr, stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, operatorCallerPath, false))
	stack.esRunning = true
}

func publishArtifact(t *testing.T, stack *publishedStack) {
	t.Helper()

	response := publishArtifactRequest(t, stack, operatorCallerPath, false, nil)
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
	}

	stack.publishResponseBody = mustReadBody(t, response.Body)
	if err := json.Unmarshal(stack.publishResponseBody, &stack.publishResponse); err != nil {
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
		"artifact": map[string]any{
			"artifact_type": "static-service",
			"intent_digest": stack.intentDigest,
		},
		"publication": map[string]any{
			"policy_decisions": []map[string]any{
				{"rule": "allow", "result": "applied"},
			},
			"build_log_digest": labeledDigest("ee"),
		},
		"admission": map[string]any{
			"runtime": map[string]any{
				"environment_variables": []string{"APP_MODE"},
				"required_capabilities": []string{},
			},
			"access": map[string]any{
				"network_access": false,
			},
			"derivation": map[string]any{
				"derivation_spec_digest": stack.derivationSpecDigest,
				"output_id":              stack.outputID,
			},
			"workload": map[string]any{
				"target_platform": "docker",
			},
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
		Security: arsconfig.SecurityConfig{
			BootstrapIssuerCommonName: stack.fixture.bootstrapCACN,
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

	response := doJSONRequest(t, stack.es.Addr(), http.MethodPost, "/v1/executions:prepare", stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, operatorCallerPath, false), buildPrepareRequestBody(t, stack))
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

func assertPrepareSuccess(t *testing.T, stack *publishedStack) {
	t.Helper()

	response := doJSONRequest(t, stack.es.Addr(), http.MethodPost, "/v1/executions:prepare", stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, operatorCallerPath, false), buildPrepareRequestBody(t, stack))
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
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
	startService(t, arsService.Start, arsService.Addr, s.fixture.clientTLSConfigForServer(t, s.fixture.arsServerName, "service/execution", false))
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

func (s *publishedStack) loadDescriptor(t *testing.T) (arsindex.Entry, arsapi.ArtifactDescriptor) {
	t.Helper()

	entry := s.loadIndexEntry(t)
	var descriptor arsapi.ArtifactDescriptor
	readJSONBlob(t, s.rootDir, entry.DescriptorDigest, &descriptor)
	return entry, descriptor
}

func (s *publishedStack) loadDiscovery(t *testing.T) (arsindex.Entry, arsapi.ArtifactDiscovery) {
	t.Helper()

	entry := s.loadIndexEntry(t)
	var discovery arsapi.ArtifactDiscovery
	readJSONBlob(t, s.rootDir, entry.DiscoveryDigest, &discovery)
	return entry, discovery
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

func (s *publishedStack) mutateDescriptorAndRestartARS(t *testing.T, mutate func(*arsapi.ArtifactDescriptor)) {
	t.Helper()

	entry, descriptor := s.loadDescriptor(t)
	mutate(&descriptor)
	updatedDescriptorDigest := s.writeJSONBlob(t, descriptor)
	s.replaceIndexedBlobAndRestartARS(t, func(entry *arsindex.Entry) {
		entry.DescriptorDigest = updatedDescriptorDigest
	})
	if s.publishResponse.DescriptorDigest == entry.DescriptorDigest {
		s.publishResponse.DescriptorDigest = updatedDescriptorDigest
	}
}

func (s *publishedStack) mutateDiscoveryAndRestartARS(t *testing.T, mutate func(*arsapi.ArtifactDiscovery)) {
	t.Helper()

	entry, discovery := s.loadDiscovery(t)
	mutate(&discovery)
	updatedDiscoveryDigest := s.writeJSONBlob(t, discovery)
	s.replaceIndexedBlobAndRestartARS(t, func(entry *arsindex.Entry) {
		entry.DiscoveryDigest = updatedDiscoveryDigest
	})
	if s.publishResponse.DiscoveryDigest == entry.DiscoveryDigest {
		s.publishResponse.DiscoveryDigest = updatedDiscoveryDigest
	}
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
		[]*url.URL{mustSPIFFEURL(t, "spiffe://execution.internal/service/execution")},
	)
	agsClientCertPath, agsClientKeyPath := writeLeafCertificateFiles(
		t, dir, "ags-client", runtimeCA, runtimeCAKey, "client.service.artifact-governance",
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
