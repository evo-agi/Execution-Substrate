package admission

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	arsapi "execution-substrate/ars/api"
	egsmodel "execution-substrate/egs/model"
	"execution-substrate/es/admission/internal/admissionstate"
	esconfig "execution-substrate/es/config"
	evidencev1 "execution-substrate/internal/contracts/evidence/v1"
	runtimeconfigv1 "execution-substrate/internal/contracts/runtimeconfig/v1"
	"execution-substrate/internal/observability"

	"golang.org/x/text/unicode/norm"
	"golang.org/x/text/unicode/rangetable"
)

const (
	codeInvalidRequest                  = "invalid_request"
	codeArtifactEvidenceNotFound        = "artifact_evidence_not_found"
	codeManifestNotFound                = "manifest_not_found"
	codeArtifactEvidenceInvalid         = "artifact_evidence_invalid"
	codeArtifactEvidenceUnavailable     = "artifact_evidence_unavailable"
	codeProvenanceNotFound              = "provenance_not_found"
	codeDerivationMetadataNotFound      = "derivation_metadata_not_found"
	codeDerivationAttestationNotFound   = "derivation_attestation_not_found"
	codeWorkloadIdentityBindingNotFound = "workload_identity_binding_not_found"
	codeProvenanceInvalid               = "provenance_invalid"
	codeDerivationAttestationInvalid    = "derivation_attestation_invalid"
	codeWorkloadIdentityBindingInvalid  = "workload_identity_binding_invalid"
	codeSignerNotAllowed                = "signer_not_allowed"
	codeSignerRevoked                   = "signer_revoked"
	codeArtifactRevoked                 = "artifact_revoked"
	codeWorkloadZoneVaultUnavailable    = "workload_zone_vault_unavailable"
	codeExecutionRuntimeUnavailable     = "execution_runtime_unavailable"
	codeUnsupportedExecutionMode        = "unsupported_execution_mode"
	codeUnsupportedArtifactType         = "unsupported_artifact_type"
	codeUnsupportedCapabilities         = "unsupported_capabilities"
	codeUnsupportedRuntimeProfile       = "unsupported_runtime_profile"
	codePayloadUnavailable              = "payload_unavailable"
	codeSubmissionFailed                = "submission_failed"
	codeInvalidRunID                    = "invalid_run_id"
	codeExecutionNotFound               = "execution_not_found"
	codeLogsUnavailable                 = "logs_unavailable"
	codeResultUnavailable               = "result_unavailable"
	codeResultNotFound                  = "result_not_found"
	codeMountConflict                   = "mount_conflict"
	codeMountArtifactInvalid            = "mount_artifact_invalid"
)

var (
	labeledSHA256DigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	reservedRuntimeEnvKeys     = map[string]struct{}{
		"PROJECT_NAME":                {},
		"ENVIRONMENT":                 {},
		"PLATFORM":                    {},
		"GUID":                        {},
		"SERVICE_ID":                  {},
		"SESSION_ID":                  {},
		"PARENT_SESSION_ID":           {},
		"traceparent":                 {},
		"EXEC_SVID_PATH":              {},
		"VAULT_AGENT_TOKEN_PATH":      {},
		"VAULT_ADDR":                  {},
		"VAULT_CACERT":                {},
		"VAULT_NAMESPACE":             {},
		"SSL_CERT_FILE":               {},
		runtimeIdentityEndpointEnvKey: {},
	}
	reservedRuntimeEnvPrefixes = []string{
		"EXEC_",
		"EXEC_WORKLOAD_VAULT_",
	}
)

type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	return e.Message
}

type Service struct {
	cfg        esconfig.Config
	resultAuth *retainedResultAuthenticator

	workloadZoneVaultConfigRef runtimeconfigv1.WorkloadZoneVaultConfigRef
	arsClient                  *dependencyClient
	egsClient                  *dependencyClient

	trustModelVerifier       *ed25519Verifier
	provenanceVerifier       *ed25519Verifier
	nomadClient              *nomadClient
	admissionPolicyEvaluator AdmissionPolicyEvaluator

	mu         sync.RWMutex
	trustModel *egsmodel.RuntimeTrustPolicy
	// Private operational authority is commissioned only by the unwired handoff.
	// trustModelVerified and trustModelOwner say that this Service loaded and
	// verified its trust model itself; Service.mu protects them.
	trustModelVerified bool
	trustModelOwner    *Service
	// operational is the handle of the admission state: the installed view,
	// the withdrawal and supersession latches and the confirmation time. The
	// state lives in the package admissionstate behind its own lock, and
	// NewService sets the handle once. A Service made without NewService holds
	// the zero handle, which is closed.
	operational      admissionstate.State
	operationalProof *operationalAdmissionProofHooks
}

type dependencyClient struct {
	dependencyName string
	baseURL        *url.URL
	client         *http.Client
}

type ed25519Verifier struct {
	algorithm string
	keyID     string
	publicKey ed25519.PublicKey
}

// TODO: ARS publishes richer health payloads today, but ES must not grow an
//
//	implicit shared health-schema dependency around those additional fields.
//	Revisit only if the platform adopts an explicit shared readiness contract.
//
// healthResponse is intentionally minimal. ES only depends on dependency
type healthResponse struct {
	Status string `json:"status"`
	Ready  bool   `json:"ready"`
}

type signedRuntimeTrustResponse struct {
	RuntimeTrust  egsmodel.RuntimeTrustPolicy `json:"runtime_trust"`
	Algorithm     string                      `json:"algorithm"`
	KeyID         string                      `json:"key_id"`
	PayloadDigest string                      `json:"payload_digest"`
	Signature     string                      `json:"signature"`
	Publication   json.RawMessage             `json:"publication,omitempty"`
}

type artifactRegistryErrorResponse struct {
	Error string `json:"error"`
}

type discoveredArtifact struct {
	discovery arsapi.ArtifactDiscovery
	evidence  evidencev1.ArtifactEvidence
}

type preparedArtifact struct {
	privateExecutionValue
	manifest       Manifest
	payloadDigest  string
	targetPlatform string
	networkAccess  bool
	// Owned full signed record from the same successful artifact admission.
	provenanceRecord string
}

type preparedAdmission struct {
	privateExecutionValue
	admittedRequest             PrepareRequest
	result                      PrepareResult
	artifact                    preparedArtifact
	workloadVaultPlan           esconfig.ResolvedWorkloadVaultAuthPlan
	workloadZoneVaultConfigRef  runtimeconfigv1.WorkloadZoneVaultConfigRef
	trustModel                  egsmodel.RuntimeTrustPolicy
	policyPayloadBytes          []byte
	policyPayloadBytesAvailable bool
}

type admissionIntent uint8

const (
	admissionIntentPrepare admissionIntent = iota
	admissionIntentSubmit
)

func NewService(cfg esconfig.Config) (*Service, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	workloadZoneVaultConfigRef := cfg.RuntimeConfig.WorkloadZoneVaultConfigRef.Normalized()
	arsClient, err := newDependencyClient(cfg.Dependencies.ArtifactRegistry, "artifact-registry")
	if err != nil {
		return nil, fmt.Errorf("build artifact registry client: %w", err)
	}
	egsClient, err := newDependencyClient(cfg.Dependencies.ExecutionGovernance, "execution-governance")
	if err != nil {
		return nil, fmt.Errorf("build execution governance client: %w", err)
	}

	trustModelVerifier, err := newEd25519Verifier(cfg.Verification.TrustModel)
	if err != nil {
		return nil, err
	}
	provenanceVerifier, err := newEd25519Verifier(cfg.Verification.Provenance)
	if err != nil {
		return nil, err
	}
	if _, err := newEd25519Verifier(cfg.Verification.DerivationAttestation); err != nil {
		return nil, err
	}
	if _, err := newEd25519Verifier(cfg.Verification.WorkloadIdentityBinding); err != nil {
		return nil, err
	}

	var nomadClient *nomadClient
	var resultAuth *retainedResultAuthenticator
	if cfg.SubmitConfigured() {
		resultAuth, err = loadRetainedResultAuthenticator(cfg.Execution)
		if err != nil {
			return nil, err
		}
		roots, err := provisionExecutionRoots(cfg.Execution.StagingRootDir, cfg.Execution.ResultsRootDir, nil)
		if err != nil {
			return nil, err
		}
		owner, err := roots.owner()
		if err != nil {
			_ = roots.close()
			return nil, err
		}
		if err := roots.probeCapabilities(owner); err != nil {
			_ = roots.close()
			return nil, fmt.Errorf("validate execution root capabilities: %w", err)
		}
		if err := roots.reobserve(); err != nil {
			_ = roots.close()
			return nil, fmt.Errorf("requalify execution roots after capability probes: %w", err)
		}
		if err := roots.close(); err != nil {
			return nil, fmt.Errorf("close qualified execution roots: %w", err)
		}
		if err := validateExecutionRuntimeInputs(cfg.Execution); err != nil {
			return nil, err
		}
		nomadClient, err = newNomadClient(cfg.Nomad)
		if err != nil {
			return nil, fmt.Errorf("build nomad client: %w", err)
		}
	}

	service := &Service{
		cfg:                        cfg,
		resultAuth:                 resultAuth,
		workloadZoneVaultConfigRef: workloadZoneVaultConfigRef,
		arsClient:                  arsClient,
		egsClient:                  egsClient,
		trustModelVerifier:         trustModelVerifier,
		provenanceVerifier:         provenanceVerifier,
		nomadClient:                nomadClient,
		admissionPolicyEvaluator:   admissionPolicyEvaluatorFromConfig(cfg.AdmissionPolicy),
	}
	service.operational = admissionstate.New(service)
	return service, nil
}

func validateExecutionRuntimeInputs(cfg esconfig.ExecutionConfig) error {
	if err := validateSPIREWorkloadAPISocketPathConfigShape(cfg.SPIREWorkloadAPISocketPath); err != nil {
		return err
	}
	if err := validateBoundedRegularFile(cfg.RuntimeSupportBinary, maxRuntimeSupportBytes); err != nil {
		return fmt.Errorf("validate execution.runtime_support_binary: %w", err)
	}
	return nil
}

func validateSPIREWorkloadAPISocketPathConfigShape(path string) error {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return fmt.Errorf("validate execution.spire_workload_api_socket_path: path is required")
	}
	if !filepath.IsAbs(trimmed) {
		return fmt.Errorf("validate execution.spire_workload_api_socket_path: path must be absolute")
	}
	return nil
}

func (s *Service) Initialize(ctx context.Context) error {
	if s.operational.Commissioned() {
		return fmt.Errorf("private operational authority is already commissioned or withdrawn")
	}
	normalized, err := s.fetchVerifiedTrustModel(ctx)
	if err != nil {
		return err
	}

	// Service.mu is held across this question and the write below. An install
	// holds it too, so no view is installed between the two.
	s.mu.Lock()
	if s.operational.Commissioned() {
		s.mu.Unlock()
		return fmt.Errorf("private operational authority was commissioned during trust load")
	}
	s.trustModel = &normalized
	s.trustModelVerified = true
	s.trustModelOwner = s
	s.mu.Unlock()

	return nil
}

// fetchVerifiedTrustModel requests the signed runtime trust model from EGS,
// verifies its envelope and returns the normalized policy. It reads and
// changes no Service state; Initialize and the private operational
// confirmation are its only callers.
func (s *Service) fetchVerifiedTrustModel(ctx context.Context) (egsmodel.RuntimeTrustPolicy, error) {
	requestCtx, cancel := context.WithTimeout(ctx, s.egsClient.client.Timeout)
	defer cancel()

	response, err := s.egsClient.get(requestCtx, "/v1/trust-model")
	if err != nil {
		return egsmodel.RuntimeTrustPolicy{}, fmt.Errorf("fetch trust model: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return egsmodel.RuntimeTrustPolicy{}, fmt.Errorf("fetch trust model: unexpected status %d", response.StatusCode)
	}

	var payload signedRuntimeTrustResponse
	if err := decodeBoundedJSONResponse(response, &payload); err != nil {
		return egsmodel.RuntimeTrustPolicy{}, fmt.Errorf("decode trust model response: %w", err)
	}
	if err := payload.RuntimeTrust.Validate(); err != nil {
		return egsmodel.RuntimeTrustPolicy{}, fmt.Errorf("validate trust model: %w", err)
	}

	canonical, err := payload.RuntimeTrust.CanonicalBytes()
	if err != nil {
		return egsmodel.RuntimeTrustPolicy{}, fmt.Errorf("canonicalize trust model: %w", err)
	}
	if err := s.verifyTrustModelEnvelope(payload, canonical); err != nil {
		return egsmodel.RuntimeTrustPolicy{}, fmt.Errorf("verify trust model: %w", err)
	}

	return payload.RuntimeTrust.Normalized(), nil
}

func (s *Service) Health(ctx context.Context) HealthSnapshot {
	// TODO: This milestone slice fetches TrustModel only at startup and does not
	// 		 treat live EGS reachability as a runtime readiness dependency afterward.
	// 		 If a later slice introduces background TrustModel refresh or LKG behavior,
	// 		 revisit ES /health semantics explicitly instead of expanding them by drift.
	type result struct {
		ok bool
	}

	arsCh := make(chan result, 1)

	go func() {
		arsCh <- result{ok: s.arsClient.checkReady(ctx)}
	}()

	arsResult := <-arsCh

	s.mu.RLock()
	loaded := s.trustModel != nil
	s.mu.RUnlock()

	return HealthSnapshot{
		ArtifactRegistryHealthy: arsResult.ok,
		TrustModelLoaded:        loaded,
	}
}

func (s *Service) Prepare(ctx context.Context, req PrepareRequest) (PrepareResult, *Error) {
	prepared, err := s.prepareAdmission(ctx, req, admissionIntentPrepare)
	if err != nil {
		return PrepareResult{}, err
	}
	if err := s.validateRuntimeProfileForPrepare(prepared.admittedRequest, prepared); err != nil {
		return PrepareResult{}, err
	}
	return prepared.result, nil
}

func (s *Service) prepareAdmission(ctx context.Context, req PrepareRequest, intent admissionIntent) (preparedAdmission, *Error) {
	req = snapshotAdmissionRequest(req)
	switch intent {
	case admissionIntentPrepare:
	case admissionIntentSubmit:
		if req.Mode == "" {
			req.Mode = ExecutionModeAsync
		}
		if req.Mode != ExecutionModeAsync {
			return preparedAdmission{}, &Error{
				Status:  http.StatusBadRequest,
				Code:    codeUnsupportedExecutionMode,
				Message: "only async submission is supported in this execution slice",
			}
		}
	default:
		panic("unknown private admission intent")
	}
	if err := validatePrepareRequest(&req); err != nil {
		return preparedAdmission{}, err
	}

	trustModel := s.currentTrustModel()
	if trustModel == nil {
		return preparedAdmission{}, &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    "trust_model_unavailable",
			Message: "trust model is unavailable",
		}
	}

	artifact, err := s.prepareArtifact(ctx, req, *trustModel)
	if err != nil {
		return preparedAdmission{}, err
	}

	workloadVaultRef := s.workloadZoneVaultConfigRef
	workloadVaultConfig, err := s.fetchWorkloadZoneVaultConfig(ctx, workloadVaultRef)
	if err != nil {
		return preparedAdmission{}, err
	}

	plan, resolveErr := s.cfg.WorkloadVaultAuth.Resolve(workloadVaultConfig)
	if resolveErr != nil {
		return preparedAdmission{}, &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    codeWorkloadZoneVaultUnavailable,
			Message: "workload-zone vault configuration is invalid",
		}
	}

	policyPayloadBytes, policyPayloadBytesAvailable, policyErr := s.enforceAdmissionPolicy(ctx, req, artifact)
	if policyErr != nil {
		return preparedAdmission{}, policyErr
	}

	return preparedAdmission{
		admittedRequest: snapshotAdmissionRequest(req),
		result: PrepareResult{
			Success: true,
		},
		artifact:                    artifact,
		workloadVaultPlan:           plan,
		workloadZoneVaultConfigRef:  workloadVaultRef,
		trustModel:                  snapshotRuntimeTrustModel(*trustModel),
		policyPayloadBytes:          policyPayloadBytes,
		policyPayloadBytesAvailable: policyPayloadBytesAvailable,
	}, nil
}

func (s *Service) prepareArtifact(ctx context.Context, req PrepareRequest, trustModel egsmodel.RuntimeTrustPolicy) (preparedArtifact, *Error) {
	discovery, err := s.fetchArtifactDiscovery(ctx, req.Invocation.ArtifactDigest)
	if err != nil {
		return preparedArtifact{}, err
	}
	artifact, err := s.prepareArtifactFromDiscovery(req, trustModel, discovery)
	if err != nil {
		return preparedArtifact{}, err
	}
	// The successful ordinary resolution owns the exact typed record it used.
	// This carrier is inert for ordinary Submit and never enters its plan. A
	// record that cannot be represented leaves the carrier empty: ordinary
	// Prepare and Submit proceed, and the private builder refuses an empty one.
	if fullRecord, marshalErr := json.Marshal(discovery.evidence); marshalErr == nil {
		artifact.provenanceRecord = string(fullRecord)
	}
	return artifact, nil
}

func (s *Service) currentTrustModel() *egsmodel.RuntimeTrustPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.trustModel == nil {
		return nil
	}
	snapshot := snapshotRuntimeTrustModel(*s.trustModel)
	return &snapshot
}

func (s *Service) fetchArtifactDiscovery(ctx context.Context, artifactDigest string) (discoveredArtifact, *Error) {
	discovery, err := s.fetchArtifactDiscoveryRecord(ctx, artifactDigest)
	if err != nil {
		return discoveredArtifact{}, err
	}
	evidence, err := s.fetchArtifactEvidenceBlob(ctx, artifactDigest, discovery.Evidence.Digest)
	if err != nil {
		return discoveredArtifact{}, err
	}
	return discoveredArtifact{
		discovery: discovery,
		evidence:  evidence,
	}, nil
}

func (s *Service) fetchArtifactDiscoveryRecord(ctx context.Context, artifactDigest string) (arsapi.ArtifactDiscovery, *Error) {
	response, err := s.arsClient.get(ctx, "/v1/artifacts/"+artifactDigest+"/discovery")
	if err != nil {
		return arsapi.ArtifactDiscovery{}, &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    codeArtifactEvidenceUnavailable,
			Message: "artifact discovery read failed",
		}
	}
	defer response.Body.Close()

	switch response.StatusCode {
	case http.StatusOK:
		var payload arsapi.ArtifactDiscovery
		if err := decodeBoundedJSONResponse(response, &payload); err != nil {
			return arsapi.ArtifactDiscovery{}, &Error{
				Status:  http.StatusServiceUnavailable,
				Code:    codeArtifactEvidenceUnavailable,
				Message: "artifact discovery payload was invalid",
			}
		}
		return payload, nil
	case http.StatusNotFound:
		var payload artifactRegistryErrorResponse
		if err := decodeBoundedCompatibleJSONResponse(response, &payload); err == nil {
			switch strings.TrimSpace(payload.Error) {
			case "artifact not found", "artifact data not registered":
				return arsapi.ArtifactDiscovery{}, &Error{
					Status:  http.StatusNotFound,
					Code:    codeArtifactEvidenceNotFound,
					Message: "artifact evidence not found",
				}
			}
		}
		return arsapi.ArtifactDiscovery{}, &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    codeArtifactEvidenceUnavailable,
			Message: "artifact evidence is unavailable",
		}
	default:
		return arsapi.ArtifactDiscovery{}, &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    codeArtifactEvidenceUnavailable,
			Message: "artifact evidence is unavailable",
		}
	}
}

func (s *Service) fetchArtifactEvidenceBlob(ctx context.Context, artifactDigest string, evidenceDigest string) (evidencev1.ArtifactEvidence, *Error) {
	unavailable := func(message string) *Error {
		return &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    codeArtifactEvidenceUnavailable,
			Message: message,
		}
	}
	evidenceBytes, fetchErr := s.fetchVerifiedARSBlob(ctx, evidenceDigest, arsBlobViewJSON, maxDependencyJSONResponseBytes)
	if fetchErr != nil {
		switch fetchErr.failure {
		case arsBlobRequestFailed:
			return evidencev1.ArtifactEvidence{}, unavailable("artifact evidence read failed")
		case arsBlobReadFailed:
			return evidencev1.ArtifactEvidence{}, unavailable("artifact evidence payload was invalid")
		case arsBlobDigestMismatch:
			return evidencev1.ArtifactEvidence{}, unavailable(artifactEvidenceDigestMismatchMessage)
		default:
			return evidencev1.ArtifactEvidence{}, unavailable("artifact evidence is unavailable")
		}
	}
	var payload evidencev1.ArtifactEvidence
	if err := decodeJSON(bytes.NewReader(evidenceBytes), &payload); err != nil {
		return evidencev1.ArtifactEvidence{}, unavailable("artifact evidence payload was invalid")
	}
	return payload, nil
}

func (s *Service) prepareArtifactFromDiscovery(req PrepareRequest, trustModel egsmodel.RuntimeTrustPolicy, discovery discoveredArtifact) (preparedArtifact, *Error) {
	discoveryRecord := discovery.discovery
	evidence := discovery.evidence
	authorization := evidence.Claims.Admission.Authorization
	if discoveryRecord.Artifact.ArtifactDigest != req.Invocation.ArtifactDigest {
		return preparedArtifact{}, &Error{
			Status:  http.StatusBadRequest,
			Code:    codeInvalidRequest,
			Message: "artifact digest mismatch between request and artifact discovery",
		}
	}
	if evidence.Claims.Package.Identity.ArtifactDigest != req.Invocation.ArtifactDigest {
		return preparedArtifact{}, &Error{
			Status:  http.StatusBadRequest,
			Code:    codeInvalidRequest,
			Message: "artifact digest mismatch between request and artifact evidence",
		}
	}
	if authorization.Derivation.DerivationSpecDigest != req.Invocation.DerivationSpecDigest {
		return preparedArtifact{}, &Error{
			Status:  http.StatusBadRequest,
			Code:    codeInvalidRequest,
			Message: "derivation_spec_digest does not match artifact evidence",
		}
	}
	if authorization.Derivation.OutputID != req.Invocation.OutputID {
		return preparedArtifact{}, &Error{
			Status:  http.StatusBadRequest,
			Code:    codeInvalidRequest,
			Message: "output_id does not match artifact evidence",
		}
	}
	artifact, err := s.prepareArtifactFromEvidenceRecord(trustModel, discoveryRecord, evidence)
	if err != nil {
		return preparedArtifact{}, err
	}
	if err := validateInvocationAgainstManifest(req.Invocation, artifact.manifest); err != nil {
		return preparedArtifact{}, err
	}
	return artifact, nil
}

func (s *Service) prepareArtifactFromEvidenceRecord(trustModel egsmodel.RuntimeTrustPolicy, discovery arsapi.ArtifactDiscovery, evidence evidencev1.ArtifactEvidence) (preparedArtifact, *Error) {
	artifactDigest := strings.TrimSpace(discovery.Artifact.ArtifactDigest)
	execution := evidence.Claims.Admission.Execution
	if evidence.Claims.Package.Identity.ArtifactDigest != artifactDigest {
		return preparedArtifact{}, &Error{
			Status:  http.StatusForbidden,
			Code:    codeArtifactEvidenceInvalid,
			Message: "artifact evidence does not match the requested artifact digest",
		}
	}
	if err := evidence.Validate(); err != nil {
		return preparedArtifact{}, &Error{
			Status:  http.StatusForbidden,
			Code:    codeArtifactEvidenceInvalid,
			Message: "artifact evidence is structurally invalid",
		}
	}
	if evidence.Claims.Package.Identity.PayloadDigest != strings.TrimSpace(discovery.Payload.Digest) {
		return preparedArtifact{}, &Error{
			Status:  http.StatusForbidden,
			Code:    codeArtifactEvidenceInvalid,
			Message: "artifact discovery payload reference does not match artifact evidence",
		}
	}
	if evidence.Claims.Package.Identity.ArtifactType != strings.TrimSpace(discovery.Artifact.ArtifactType) {
		return preparedArtifact{}, &Error{
			Status:  http.StatusForbidden,
			Code:    codeArtifactEvidenceInvalid,
			Message: "artifact discovery artifact type does not match artifact evidence",
		}
	}
	if evidence.Claims.Package.Identity.IntentDigest != strings.TrimSpace(discovery.Artifact.IntentDigest) {
		return preparedArtifact{}, &Error{
			Status:  http.StatusForbidden,
			Code:    codeArtifactEvidenceInvalid,
			Message: "artifact discovery intent digest does not match artifact evidence",
		}
	}
	if err := evidencev1.Verify(evidence, s.provenanceVerifier.keyID, s.provenanceVerifier.algorithm, s.provenanceVerifier.publicKey); err != nil {
		return preparedArtifact{}, &Error{
			Status:  http.StatusForbidden,
			Code:    codeArtifactEvidenceInvalid,
			Message: "artifact evidence signature verification failed",
		}
	}
	if err := enforceTrustModel(trustModel, evidence.Seal.KeyID, artifactDigest); err != nil {
		return preparedArtifact{}, err
	}
	return preparedArtifact{
		manifest:       manifestFromEvidence(evidence),
		payloadDigest:  strings.TrimSpace(discovery.Payload.Digest),
		targetPlatform: execution.Workload.TargetPlatform,
		networkAccess:  execution.Access.NetworkAccess,
	}, nil
}

func manifestFromEvidence(evidence evidencev1.ArtifactEvidence) Manifest {
	runtime := evidence.Claims.Admission.Execution.Runtime
	return Manifest{
		ArtifactDigest: evidence.Claims.Package.Identity.ArtifactDigest,
		ArtifactType:   evidence.Claims.Package.Identity.ArtifactType,
		IntentDigest:   evidence.Claims.Package.Identity.IntentDigest,
		RuntimeInterface: RuntimeInterface{
			EnvironmentVariables: append([]string(nil), runtime.EnvironmentVariables...),
			RequiredCapabilities: append([]string(nil), runtime.RequiredCapabilities...),
		},
	}
}

func (s *Service) fetchWorkloadZoneVaultConfig(ctx context.Context, ref runtimeconfigv1.WorkloadZoneVaultConfigRef) (runtimeconfigv1.WorkloadZoneVaultConfig, *Error) {
	unavailable := func(message string) *Error {
		return &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    codeWorkloadZoneVaultUnavailable,
			Message: message,
		}
	}
	blobBytes, fetchErr := s.fetchVerifiedARSBlob(ctx, ref.Digest, arsBlobViewJSON, maxDependencyJSONResponseBytes)
	if fetchErr != nil {
		switch fetchErr.failure {
		case arsBlobRequestFailed:
			return runtimeconfigv1.WorkloadZoneVaultConfig{}, unavailable("artifact registry workload-zone vault blob read failed")
		case arsBlobReadFailed:
			return runtimeconfigv1.WorkloadZoneVaultConfig{}, unavailable("artifact registry workload-zone vault blob was invalid")
		case arsBlobDigestMismatch:
			return runtimeconfigv1.WorkloadZoneVaultConfig{}, unavailable(workloadZoneVaultBlobDigestMismatchMessage)
		default:
			return runtimeconfigv1.WorkloadZoneVaultConfig{}, unavailable("artifact registry workload-zone vault blob is unavailable")
		}
	}

	var payload runtimeconfigv1.WorkloadZoneVaultConfigBlob
	if err := decodeJSON(bytes.NewReader(blobBytes), &payload); err != nil {
		return runtimeconfigv1.WorkloadZoneVaultConfig{}, unavailable("artifact registry workload-zone vault blob was invalid")
	}
	if err := payload.Validate(); err != nil {
		return runtimeconfigv1.WorkloadZoneVaultConfig{}, &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    codeWorkloadZoneVaultUnavailable,
			Message: "artifact registry workload-zone vault blob was invalid",
		}
	}
	return payload.Normalized().VaultConfig, nil
}

func (s *Service) verifyTrustModelEnvelope(payload signedRuntimeTrustResponse, canonical []byte) error {
	if strings.TrimSpace(payload.Algorithm) != s.trustModelVerifier.algorithm {
		return fmt.Errorf("trust model algorithm mismatch")
	}
	if strings.TrimSpace(payload.KeyID) != s.trustModelVerifier.keyID {
		return fmt.Errorf("trust model key_id mismatch")
	}
	expectedDigest := digestBytes(canonical)
	if payload.PayloadDigest != expectedDigest {
		return fmt.Errorf("trust model payload digest mismatch")
	}
	// publication metadata is intentionally outside the signed runtime trust
	// payload and is ignored for trust decisions here.
	if err := s.trustModelVerifier.verifyDetached(canonical, payload.KeyID, payload.Algorithm, payload.Signature); err != nil {
		return err
	}
	return nil
}

func enforceTrustModel(trustModel egsmodel.RuntimeTrustPolicy, signerKeyID string, artifactDigest string) *Error {
	for _, allowed := range trustModel.SignerPolicy.AllowedSigners {
		if allowed == signerKeyID {
			goto allowed
		}
	}
	return &Error{
		Status:  http.StatusForbidden,
		Code:    codeSignerNotAllowed,
		Message: "provenance signer is not allowed by the TrustModel",
	}

allowed:
	for _, revoked := range trustModel.SignerPolicy.RevokedSigners {
		if revoked == signerKeyID {
			return &Error{
				Status:  http.StatusForbidden,
				Code:    codeSignerRevoked,
				Message: "provenance signer is revoked by the TrustModel",
			}
		}
	}
	for _, revokedArtifact := range trustModel.ArtifactPolicy.RevokedArtifacts {
		if revokedArtifact == artifactDigest {
			return &Error{
				Status:  http.StatusForbidden,
				Code:    codeArtifactRevoked,
				Message: "artifact is revoked by the TrustModel",
			}
		}
	}
	return nil
}

func validatePrepareRequest(req *PrepareRequest) *Error {
	if req == nil {
		return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "request body is required"}
	}
	if strings.TrimSpace(req.SchemaVersion) == "" {
		req.SchemaVersion = "v1"
	}
	if strings.TrimSpace(req.Invocation.SchemaVersion) == "" {
		req.Invocation.SchemaVersion = "v1"
	}
	if req.Mode != "" && req.Mode != ExecutionModeAsync && req.Mode != ExecutionModeSync {
		return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "mode must be sync or async"}
	}
	if req.TimeoutSeconds < 0 {
		return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "timeout_seconds must be non-negative"}
	}
	if req.Resources != nil {
		if req.Resources.CPU <= 0 {
			return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "resources.cpu must be greater than 0"}
		}
		if req.Resources.MemoryMB < nomadMinimumMemoryMB {
			return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: fmt.Sprintf("resources.memory_mb must be at least %d, the least memory Nomad registers a task with", nomadMinimumMemoryMB)}
		}
	}

	invocation := req.Invocation
	if !isLabeledSHA256Digest(invocation.ArtifactDigest) {
		return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "invocation.artifact_digest must be a labeled sha256 digest"}
	}
	if !isLabeledSHA256Digest(invocation.DerivationSpecDigest) {
		return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "invocation.derivation_spec_digest must be a labeled sha256 digest"}
	}
	if strings.TrimSpace(invocation.OutputID) == "" {
		return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "invocation.output_id is required"}
	}
	return nil
}

// nomadPassesAsWritten reports whether Nomad hands s to the workload exactly
// as written. Nomad's client evaluates "${...}" and "%{...}" in every string of
// a task's driver configuration (the arguments and the mounts) as an HCL
// template, with the node's attributes and metadata, the task's environment
// and a set of functions, and rewrites the escapes "$${" and "%%{". It replaces
// "${name}" in every environment and meta value with a node attribute or an
// environment value. A NUL byte cannot reach a process at all. So a request
// string that ES places in a Nomad job holds none of these, or the workload
// would run with values that ES never admitted, or never start once ES has
// accepted it.
func nomadPassesAsWritten(s string) bool {
	return !strings.Contains(s, "${") && !strings.Contains(s, "%{") && strings.IndexByte(s, 0) < 0
}

const nomadEvaluatedText = `must not contain "${", "%{" or a NUL byte, which Nomad would not pass on as written`

// nomadKeepsDriverString reports whether Nomad's client leaves s, a string of a
// task's driver configuration (an argument or a mount target), unchanged on
// its way to the workload, apart from the templates nomadPassesAsWritten
// refuses. The client parses each such string with HCL, whose template
// scanner drops a byte order mark (U+FEFF) at its start, and holds the result
// as a cty string, which is rewritten to Unicode Normalization Form C. So s
// must not begin with U+FEFF and must be in NFC. ES judges NFC by its own
// tables, of Unicode version norm.Version. A Nomad built with tables of a
// later version could normalize a code point that ES's tables do not know, so
// s also holds only code points assigned in norm.Version. Unicode's
// normalization stability policy then keeps s unchanged by every later
// version. Nomad leaves environment keys and values and meta values as they
// are, so this applies to the driver configuration only.
func nomadKeepsDriverString(s string) bool {
	if strings.HasPrefix(s, "\ufeff") || !norm.NFC.IsNormalString(s) {
		return false
	}
	for _, r := range s {
		if r >= utf8.RuneSelf && (nomadNormalizationAssigned == nil || !unicode.Is(nomadNormalizationAssigned, r)) {
			return false
		}
	}
	return true
}

// nomadNormalizationAssigned holds the code points assigned in the Unicode
// version of ES's normalization tables. If x/text has no table of assigned
// code points for that version it is nil, and nomadKeepsDriverString then
// refuses every string that is not ASCII.
var nomadNormalizationAssigned = rangetable.Assigned(norm.Version)

const nomadRewrittenText = "must be in Unicode Normalization Form C, use only code points assigned in Unicode " + norm.Version + " and not begin with a byte order mark, or Nomad would not pass it on as written"

// nomadMinimumMemoryMB is the least memory Nomad registers a task with
// (Nomad v2.1.1, structs.MinResources and Resources.MeetsMinResources). A
// request below it would be accepted, claimed and staged, and then refused by
// Nomad for good.
const nomadMinimumMemoryMB = 10

func validateInvocationAgainstManifest(invocation ArtifactInvocation, manifest Manifest) *Error {
	if manifest.ArtifactDigest != invocation.ArtifactDigest {
		return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "artifact digest mismatch between request and manifest"}
	}
	if len(invocation.Argv) > 100 {
		return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "invocation.argv exceeds the maximum supported count"}
	}
	if !nomadPassesAsWritten(invocation.OutputID) {
		return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "invocation.output_id " + nomadEvaluatedText}
	}
	for _, arg := range invocation.Argv {
		if !nomadPassesAsWritten(arg) {
			return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "invocation.argv " + nomadEvaluatedText}
		}
		if !nomadKeepsDriverString(arg) {
			return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "invocation.argv " + nomadRewrittenText}
		}
	}
	allowedEnv := make(map[string]struct{}, len(manifest.RuntimeInterface.EnvironmentVariables))
	for _, key := range manifest.RuntimeInterface.EnvironmentVariables {
		allowedEnv[strings.TrimSpace(key)] = struct{}{}
	}
	for key, value := range invocation.Env {
		if !nomadPassesAsWritten(key) || !nomadPassesAsWritten(value) {
			return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "invocation.env " + nomadEvaluatedText}
		}
		if isReservedRuntimeEnvKey(key) {
			return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: fmt.Sprintf("environment key is reserved for runtime identity or control-plane use: %s", key)}
		}
		if len(allowedEnv) > 0 {
			if _, ok := allowedEnv[key]; !ok {
				return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: fmt.Sprintf("environment key is not allowed by the runtime interface: %s", key)}
			}
		}
	}
	if err := validateRuntimeMounts(invocation.Mounts); err != nil {
		return err
	}
	return nil
}

func newDependencyClient(cfg esconfig.DependencyConfig, dependencyName string) (*dependencyClient, error) {
	certificate, err := tls.LoadX509KeyPair(cfg.ClientCertFile, cfg.ClientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load client certificate: %w", err)
	}

	rootPEM, err := os.ReadFile(cfg.RootCAFile)
	if err != nil {
		return nil, fmt.Errorf("read root ca: %w", err)
	}
	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(rootPEM) {
		return nil, fmt.Errorf("append root ca: no valid certificates found")
	}

	baseURL, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse base url: %w", err)
	}

	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      rootCAs,
		ServerName:   cfg.ServerName,
		Certificates: []tls.Certificate{certificate},
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return &dependencyClient{
		dependencyName: strings.TrimSpace(dependencyName),
		baseURL:        baseURL,
		client: &http.Client{
			Timeout:   time.Duration(cfg.TimeoutSeconds) * time.Second,
			Transport: observability.WrapRoundTripper("execution", strings.TrimSpace(dependencyName), true, transport),
			// A redirect is the dependency's answer, never an instruction:
			// following one would let a compromised ARS or EGS make ES send
			// requests to any origin it can reach, including over cleartext.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (c *dependencyClient) get(ctx context.Context, endpoint string) (*http.Response, error) {
	requestURL := c.baseURL.ResolveReference(&url.URL{Path: path.Clean(endpoint)})
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return nil, err
	}
	return c.client.Do(request)
}

func (c *dependencyClient) checkReady(ctx context.Context) bool {
	requestCtx, cancel := context.WithTimeout(ctx, c.client.Timeout)
	defer cancel()

	response, err := c.get(requestCtx, "/health")
	if err != nil {
		return false
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return false
	}

	var payload healthResponse
	// Dependency health payloads have historically been extension-tolerant.
	// Bound their acquisition without silently converting that compatibility
	// behavior into the strict decoding used by admission-owned contracts.
	if err := decodeBoundedCompatibleJSONResponse(response, &payload); err != nil {
		return false
	}
	return payload.Status == "healthy" && payload.Ready
}

func newEd25519Verifier(cfg esconfig.SignerVerifierConfig) (*ed25519Verifier, error) {
	publicKeyBytes, err := hex.DecodeString(strings.TrimSpace(cfg.PublicKeyHex))
	if err != nil {
		return nil, fmt.Errorf("decode %s public key: %w", cfg.KeyID, err)
	}
	return &ed25519Verifier{
		algorithm: "ed25519",
		keyID:     strings.TrimSpace(cfg.KeyID),
		publicKey: ed25519.PublicKey(publicKeyBytes),
	}, nil
}

func (v *ed25519Verifier) verifyDetached(canonical []byte, keyID string, algorithm string, signatureB64 string) error {
	if strings.TrimSpace(keyID) != v.keyID {
		return fmt.Errorf("unexpected signing key id")
	}
	if strings.TrimSpace(algorithm) != v.algorithm {
		return fmt.Errorf("unexpected signing algorithm")
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(signatureB64))
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(v.publicKey, canonical, signature) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

func decodeJSON(reader io.Reader, target any) error {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("trailing data after first JSON document")
	}
	return nil
}

func decodeBoundedJSONResponse(response *http.Response, target any) error {
	payload, err := readBoundedResponseBody(response, maxDependencyJSONResponseBytes)
	if err != nil {
		return err
	}
	return decodeJSON(bytes.NewReader(payload), target)
}

func decodeBoundedCompatibleJSONResponse(response *http.Response, target any) error {
	payload, err := readBoundedResponseBody(response, maxDependencyJSONResponseBytes)
	if err != nil {
		return err
	}
	return json.NewDecoder(bytes.NewReader(payload)).Decode(target)
}

func decodeCompatibleJSONDocument(reader io.Reader, target any) error {
	decoder := json.NewDecoder(reader)
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("trailing data after first JSON document")
	}
	return nil
}

func decodeBoundedCompatibleJSONDocumentResponse(response *http.Response, target any) error {
	payload, err := readBoundedResponseBody(response, maxDependencyJSONResponseBytes)
	if err != nil {
		return err
	}
	return decodeCompatibleJSONDocument(bytes.NewReader(payload), target)
}

func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func isLabeledSHA256Digest(value string) bool {
	return labeledSHA256DigestPattern.MatchString(strings.TrimSpace(value))
}

func isReservedRuntimeEnvKey(key string) bool {
	normalized := strings.TrimSpace(key)
	if normalized == "" {
		return false
	}
	if _, ok := reservedRuntimeEnvKeys[normalized]; ok {
		return true
	}
	for _, prefix := range reservedRuntimeEnvPrefixes {
		if strings.HasPrefix(normalized, prefix) {
			return true
		}
	}
	return false
}
