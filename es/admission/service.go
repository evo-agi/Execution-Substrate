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
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	egsmodel "execution-platform/egs/model"
	esconfig "execution-platform/es/config"
	"execution-platform/observability"
)

const (
	codeInvalidRequest                  = "invalid_request"
	codeManifestNotFound                = "manifest_not_found"
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
	codeUnsupportedAuthMode             = "unsupported_auth_mode"
	codeExecutionRuntimeUnavailable     = "execution_runtime_unavailable"
	codeUnsupportedExecutionMode        = "unsupported_execution_mode"
	codeUnsupportedArtifactType         = "unsupported_artifact_type"
	codeUnsupportedCapabilities         = "unsupported_capabilities"
	codeUnsupportedMounts               = "unsupported_mounts"
	codeUnsupportedNetworkAccess        = "unsupported_network_access"
	codePayloadUnavailable              = "payload_unavailable"
	codeSubmissionFailed                = "submission_failed"
	codeInvalidRunID                    = "invalid_run_id"
	codeExecutionNotFound               = "execution_not_found"
	codeLogsUnavailable                 = "logs_unavailable"
)

var (
	labeledSHA256DigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	validTargetSubpathPattern  = regexp.MustCompile(`^[a-zA-Z0-9_\-][a-zA-Z0-9_\-/]*$`)
	reservedRuntimeEnvKeys     = map[string]struct{}{
		"PROJECT_NAME":           {},
		"ENVIRONMENT":            {},
		"PLATFORM":               {},
		"GUID":                   {},
		"SERVICE_ID":             {},
		"SESSION_ID":             {},
		"PARENT_SESSION_ID":      {},
		"traceparent":            {},
		"MONOLITH_SVID_PATH":     {},
		"VAULT_AGENT_TOKEN_PATH": {},
		"VAULT_ADDR":             {},
		"VAULT_NAMESPACE":        {},
	}
	reservedRuntimeEnvPrefixes = []string{
		"EXEC_",
		"MONOLITH_WORKLOAD_VAULT_",
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
	cfg esconfig.Config

	acsClient *dependencyClient
	arsClient *dependencyClient
	egsClient *dependencyClient

	trustModelVerifier              *ed25519Verifier
	provenanceVerifier              *ed25519Verifier
	derivationAttestationVerifier   *ed25519Verifier
	workloadIdentityBindingVerifier *ed25519Verifier
	nomadClient                     *nomadClient

	mu         sync.RWMutex
	trustModel *egsmodel.TrustModel
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

// healthResponse is intentionally minimal. ES only depends on dependency
// /health responses exposing top-level status and ready signals in this slice.
// TODO: ACS and ARS publish richer health payloads today, but ES must not grow
// an implicit shared health-schema dependency around their additional fields.
// Revisit only if the platform adopts an explicit shared readiness contract.
type healthResponse struct {
	Status string `json:"status"`
	Ready  bool   `json:"ready"`
}

type signedTrustModelResponse struct {
	TrustModel    egsmodel.TrustModel `json:"trust_model"`
	Algorithm     string              `json:"algorithm"`
	KeyID         string              `json:"key_id"`
	PayloadDigest string              `json:"payload_digest"`
	Signature     string              `json:"signature"`
	SourceDigest  *string             `json:"source_digest,omitempty"`
}

// acsLookupResponse intentionally models only the frozen ACS fields that ES
// currently needs on the admission path.
// TODO: assignment and catalog_snapshot_digest are advisory for this slice and
// must not become hidden execution inputs unless the ACS->ES boundary is
// explicitly expanded and documented.
type acsLookupResponse struct {
	Success               bool            `json:"success"`
	Digest                *string         `json:"digest"`
	Assignment            json.RawMessage `json:"assignment,omitempty"`
	CatalogSnapshotDigest *string         `json:"catalog_snapshot_digest,omitempty"`
	Error                 *string         `json:"error,omitempty"`
}

type workloadZoneVaultBlob struct {
	VaultConfig struct {
		Address     string `json:"address"`
		AuthMount   string `json:"auth_mount"`
		AuthRole    string `json:"auth_role"`
		JWTAudience string `json:"jwt_audience"`
	} `json:"vault_config"`
}

func NewService(cfg esconfig.Config) (*Service, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	acsClient, err := newDependencyClient(cfg.Dependencies.ArtifactCatalog, "artifact-catalog")
	if err != nil {
		return nil, fmt.Errorf("build artifact catalog client: %w", err)
	}
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
	derivationVerifier, err := newEd25519Verifier(cfg.Verification.DerivationAttestation)
	if err != nil {
		return nil, err
	}
	bindingVerifier, err := newEd25519Verifier(cfg.Verification.WorkloadIdentityBinding)
	if err != nil {
		return nil, err
	}

	var nomadClient *nomadClient
	if cfg.SubmitConfigured() {
		if err := os.MkdirAll(cfg.Execution.StagingRootDir, 0o755); err != nil {
			return nil, fmt.Errorf("create execution staging root: %w", err)
		}
		nomadClient, err = newNomadClient(cfg.Nomad)
		if err != nil {
			return nil, fmt.Errorf("build nomad client: %w", err)
		}
	}

	return &Service{
		cfg:                             cfg,
		acsClient:                       acsClient,
		arsClient:                       arsClient,
		egsClient:                       egsClient,
		trustModelVerifier:              trustModelVerifier,
		provenanceVerifier:              provenanceVerifier,
		derivationAttestationVerifier:   derivationVerifier,
		workloadIdentityBindingVerifier: bindingVerifier,
		nomadClient:                     nomadClient,
	}, nil
}

func (s *Service) Initialize(ctx context.Context) error {
	requestCtx, cancel := context.WithTimeout(ctx, s.egsClient.client.Timeout)
	defer cancel()

	response, err := s.egsClient.get(requestCtx, "/v1/trust-model")
	if err != nil {
		return fmt.Errorf("fetch trust model: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch trust model: unexpected status %d", response.StatusCode)
	}

	var payload signedTrustModelResponse
	if err := decodeJSON(response.Body, &payload); err != nil {
		return fmt.Errorf("decode trust model response: %w", err)
	}
	if err := payload.TrustModel.Validate(); err != nil {
		return fmt.Errorf("validate trust model: %w", err)
	}

	canonical, err := payload.TrustModel.CanonicalBytes()
	if err != nil {
		return fmt.Errorf("canonicalize trust model: %w", err)
	}
	if err := s.verifyTrustModelEnvelope(payload, canonical); err != nil {
		return fmt.Errorf("verify trust model: %w", err)
	}

	normalized := payload.TrustModel.Normalized()

	s.mu.Lock()
	s.trustModel = &normalized
	s.mu.Unlock()
	return nil
}

func (s *Service) Health(ctx context.Context) HealthSnapshot {
	// TODO: This milestone slice fetches TrustModel only at startup and does not
	// treat live EGS reachability as a runtime readiness dependency afterward.
	// If a later slice introduces background TrustModel refresh or LKG behavior,
	// revisit ES /health semantics explicitly instead of expanding them by drift.
	type result struct {
		ok bool
	}

	acsCh := make(chan result, 1)
	arsCh := make(chan result, 1)

	go func() {
		acsCh <- result{ok: s.acsClient.checkReady(ctx)}
	}()
	go func() {
		arsCh <- result{ok: s.arsClient.checkReady(ctx)}
	}()

	acsResult := <-acsCh
	arsResult := <-arsCh

	s.mu.RLock()
	loaded := s.trustModel != nil
	s.mu.RUnlock()

	return HealthSnapshot{
		ArtifactCatalogHealthy:  acsResult.ok,
		ArtifactRegistryHealthy: arsResult.ok,
		TrustModelLoaded:        loaded,
	}
}

func (s *Service) Prepare(ctx context.Context, req PrepareRequest) (PrepareResult, *Error) {
	if err := validatePrepareRequest(&req); err != nil {
		return PrepareResult{}, err
	}

	trustModel := s.currentTrustModel()
	if trustModel == nil {
		return PrepareResult{}, &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    "trust_model_unavailable",
			Message: "trust model is unavailable",
		}
	}

	manifest, err := s.fetchManifest(ctx, req.Invocation.ArtifactDigest)
	if err != nil {
		return PrepareResult{}, err
	}
	if err := validateInvocationAgainstManifest(req.Invocation, manifest); err != nil {
		return PrepareResult{}, err
	}

	provenance, err := s.fetchProvenance(ctx, req.Invocation.ArtifactDigest)
	if err != nil {
		return PrepareResult{}, err
	}
	if err := s.verifyProvenance(provenance, req.Invocation.ArtifactDigest); err != nil {
		return PrepareResult{}, err
	}

	metadata, err := s.fetchDerivationMetadata(ctx, req.Invocation.ArtifactDigest)
	if err != nil {
		return PrepareResult{}, err
	}
	if metadata.DerivationSpecDigest != req.Invocation.DerivationSpecDigest {
		return PrepareResult{}, &Error{
			Status:  http.StatusBadRequest,
			Code:    codeInvalidRequest,
			Message: "derivation_spec_digest does not match artifact metadata",
		}
	}
	if metadata.OutputID != req.Invocation.OutputID {
		return PrepareResult{}, &Error{
			Status:  http.StatusBadRequest,
			Code:    codeInvalidRequest,
			Message: "output_id does not match artifact metadata",
		}
	}

	attestation, err := s.fetchDerivationAttestation(ctx, req.Invocation.ArtifactDigest)
	if err != nil {
		return PrepareResult{}, err
	}
	if err := s.verifyDerivationAttestation(attestation, req.Invocation.ArtifactDigest, metadata); err != nil {
		return PrepareResult{}, err
	}

	binding, err := s.fetchWorkloadIdentityBinding(ctx, req.Invocation.ArtifactDigest)
	if err != nil {
		return PrepareResult{}, err
	}
	if err := s.verifyWorkloadIdentityBinding(binding, req.Invocation.ArtifactDigest, metadata); err != nil {
		return PrepareResult{}, err
	}

	if err := enforceTrustModel(*trustModel, provenance.Signature.KeyID, req.Invocation.ArtifactDigest); err != nil {
		return PrepareResult{}, err
	}

	workloadVaultDigest, err := s.fetchWorkloadZoneVaultDigest(ctx)
	if err != nil {
		return PrepareResult{}, err
	}

	workloadVaultConfig, err := s.fetchWorkloadZoneVaultConfig(ctx, workloadVaultDigest)
	if err != nil {
		return PrepareResult{}, err
	}

	plan, resolveErr := s.cfg.WorkloadVaultAuth.Resolve(
		esconfig.WorkloadIdentityAttributes{
			ArtifactClass:      binding.ArtifactClass,
			WorkloadType:       binding.WorkloadType,
			ServiceName:        binding.ServiceName,
			WorkloadIdentityID: binding.WorkloadIdentityID,
		},
		esconfig.VaultRuntimeFields{
			Address:     workloadVaultConfig.VaultConfig.Address,
			AuthMount:   workloadVaultConfig.VaultConfig.AuthMount,
			AuthRole:    workloadVaultConfig.VaultConfig.AuthRole,
			JWTAudience: workloadVaultConfig.VaultConfig.JWTAudience,
		},
	)
	if resolveErr != nil {
		return PrepareResult{}, &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    codeWorkloadZoneVaultUnavailable,
			Message: resolveErr.Error(),
		}
	}
	if plan.Mode != esconfig.WorkloadVaultAuthModeVaultIdentityJWT {
		return PrepareResult{}, &Error{
			Status:  http.StatusConflict,
			Code:    codeUnsupportedAuthMode,
			Message: "only vault_identity_jwt is supported in the prepare milestone slice",
		}
	}

	return PrepareResult{
		Success:              true,
		ArtifactDigest:       req.Invocation.ArtifactDigest,
		DerivationSpecDigest: req.Invocation.DerivationSpecDigest,
		OutputID:             req.Invocation.OutputID,
		IntentDigest:         manifest.IntentDigest,
		ArtifactType:         manifest.ArtifactType,
		TrustModel: TrustModelInfo{
			Version:        trustModel.Version,
			UpdateRevision: trustModel.UpdateRevision,
		},
		Provenance: ProvenanceInfo{
			SignerKeyID: provenance.Signature.KeyID,
		},
		Workload: WorkloadInfo{
			Type:               binding.WorkloadType,
			ServiceName:        binding.ServiceName,
			WorkloadIdentityID: binding.WorkloadIdentityID,
		},
		WorkloadVault: WorkloadVaultInfo{
			Digest:      workloadVaultDigest,
			Address:     plan.Address,
			AuthMode:    string(plan.Mode),
			AuthMount:   plan.AuthMount,
			AuthRole:    plan.AuthRole,
			JWTAudience: plan.JWTAudience,
		},
	}, nil
}

func (s *Service) currentTrustModel() *egsmodel.TrustModel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.trustModel == nil {
		return nil
	}
	copy := *s.trustModel
	return &copy
}

func (s *Service) fetchManifest(ctx context.Context, artifactDigest string) (Manifest, *Error) {
	return fetchArtifactJSON[Manifest](ctx, s.arsClient, "/v1/artifacts/"+artifactDigest+"/manifest", codeManifestNotFound, "manifest not found")
}

func (s *Service) fetchProvenance(ctx context.Context, artifactDigest string) (Provenance, *Error) {
	return fetchArtifactJSON[Provenance](ctx, s.arsClient, "/v1/artifacts/"+artifactDigest+"/provenance", codeProvenanceNotFound, "provenance not found")
}

func (s *Service) fetchDerivationMetadata(ctx context.Context, artifactDigest string) (DerivationMetadata, *Error) {
	return fetchArtifactJSON[DerivationMetadata](ctx, s.arsClient, "/v1/artifacts/"+artifactDigest+"/derivation-metadata", codeDerivationMetadataNotFound, "derivation metadata not found")
}

func (s *Service) fetchDerivationAttestation(ctx context.Context, artifactDigest string) (DerivationAttestation, *Error) {
	return fetchArtifactJSON[DerivationAttestation](ctx, s.arsClient, "/v1/artifacts/"+artifactDigest+"/derivation-authorization-attestation", codeDerivationAttestationNotFound, "derivation authorization attestation not found")
}

func (s *Service) fetchWorkloadIdentityBinding(ctx context.Context, artifactDigest string) (WorkloadIdentityBinding, *Error) {
	return fetchArtifactJSON[WorkloadIdentityBinding](ctx, s.arsClient, "/v1/artifacts/"+artifactDigest+"/workload-identity-binding", codeWorkloadIdentityBindingNotFound, "workload identity binding not found")
}

func (s *Service) fetchWorkloadZoneVaultDigest(ctx context.Context) (string, *Error) {
	response, err := s.acsClient.get(ctx, "/v1/configuration/workload-zone/vault")
	if err != nil {
		return "", &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    codeWorkloadZoneVaultUnavailable,
			Message: "artifact catalog lookup failed",
		}
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return "", &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    codeWorkloadZoneVaultUnavailable,
			Message: "artifact catalog lookup failed",
		}
	}

	var payload acsLookupResponse
	if err := decodeJSON(response.Body, &payload); err != nil {
		return "", &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    codeWorkloadZoneVaultUnavailable,
			Message: "artifact catalog response was invalid",
		}
	}
	if !payload.Success || payload.Digest == nil || strings.TrimSpace(*payload.Digest) == "" {
		return "", &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    codeWorkloadZoneVaultUnavailable,
			Message: "artifact catalog did not return a workload-zone vault digest",
		}
	}
	return strings.TrimSpace(*payload.Digest), nil
}

func (s *Service) fetchWorkloadZoneVaultConfig(ctx context.Context, digest string) (workloadZoneVaultBlob, *Error) {
	response, err := s.arsClient.get(ctx, "/v1/blobs/"+digest+":json")
	if err != nil {
		return workloadZoneVaultBlob{}, &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    codeWorkloadZoneVaultUnavailable,
			Message: "artifact registry workload-zone vault blob read failed",
		}
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return workloadZoneVaultBlob{}, &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    codeWorkloadZoneVaultUnavailable,
			Message: "artifact registry workload-zone vault blob is unavailable",
		}
	}

	var payload workloadZoneVaultBlob
	if err := decodeJSON(response.Body, &payload); err != nil {
		return workloadZoneVaultBlob{}, &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    codeWorkloadZoneVaultUnavailable,
			Message: "artifact registry workload-zone vault blob was invalid",
		}
	}

	// TODO: ES intentionally parses only the minimal vault_config fields needed
	// for vault_identity_jwt preparation in this milestone slice: address,
	// auth_mount, auth_role, and jwt_audience. It does not own the broader
	// workload-zone Vault schema and should not absorb unrelated configuration
	// semantics here. Namespace and any future Vault fields remain upstream
	// concerns until a dedicated runtime-auth config boundary exists.
	return payload, nil
}

func (s *Service) verifyTrustModelEnvelope(payload signedTrustModelResponse, canonical []byte) error {
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
	// source_digest is advisory metadata in EGS v1 and is intentionally ignored
	// for trust decisions here. Only payload_digest and signature are
	// authoritative in the current versioned contract.
	if err := s.trustModelVerifier.verifyDetached(canonical, payload.KeyID, payload.Algorithm, payload.Signature); err != nil {
		return err
	}
	return nil
}

func (s *Service) verifyProvenance(provenance Provenance, artifactDigest string) *Error {
	if provenance.ArtifactDigest != artifactDigest {
		return &Error{
			Status:  http.StatusBadRequest,
			Code:    codeInvalidRequest,
			Message: "artifact digest mismatch between request and provenance",
		}
	}

	canonical := canonicalProvenanceBytes(provenance)
	if err := s.provenanceVerifier.verifyDetached(canonical, provenance.Signature.KeyID, provenance.Signature.Alg, provenance.Signature.Value); err != nil {
		return &Error{
			Status:  http.StatusForbidden,
			Code:    codeProvenanceInvalid,
			Message: "provenance signature verification failed",
		}
	}
	return nil
}

func (s *Service) verifyDerivationAttestation(attestation DerivationAttestation, artifactDigest string, metadata DerivationMetadata) *Error {
	if attestation.ArtifactDigest != artifactDigest ||
		attestation.DerivationSpecDigest != metadata.DerivationSpecDigest ||
		attestation.OutputID != metadata.OutputID {
		return &Error{
			Status:  http.StatusForbidden,
			Code:    codeDerivationAttestationInvalid,
			Message: "derivation authorization attestation does not match artifact metadata",
		}
	}

	canonical := canonicalDerivationAttestationBytes(attestation)
	if err := s.derivationAttestationVerifier.verifyEnvelope(canonical, attestation.SignatureInfo); err != nil {
		return &Error{
			Status:  http.StatusForbidden,
			Code:    codeDerivationAttestationInvalid,
			Message: "derivation authorization attestation signature verification failed",
		}
	}
	return nil
}

func (s *Service) verifyWorkloadIdentityBinding(binding WorkloadIdentityBinding, artifactDigest string, metadata DerivationMetadata) *Error {
	if binding.ArtifactDigest != artifactDigest ||
		binding.DerivationSpecDigest != metadata.DerivationSpecDigest ||
		binding.OutputID != metadata.OutputID {
		return &Error{
			Status:  http.StatusForbidden,
			Code:    codeWorkloadIdentityBindingInvalid,
			Message: "workload identity binding does not match artifact metadata",
		}
	}
	if strings.TrimSpace(binding.WorkloadIdentityID) == "" {
		return &Error{
			Status:  http.StatusForbidden,
			Code:    codeWorkloadIdentityBindingInvalid,
			Message: "workload identity binding is missing workload_identity_id",
		}
	}

	canonical := canonicalWorkloadIdentityBindingBytes(binding)
	if err := s.workloadIdentityBindingVerifier.verifyEnvelope(canonical, binding.SignatureInfo); err != nil {
		return &Error{
			Status:  http.StatusForbidden,
			Code:    codeWorkloadIdentityBindingInvalid,
			Message: "workload identity binding signature verification failed",
		}
	}
	return nil
}

func enforceTrustModel(trustModel egsmodel.TrustModel, signerKeyID string, artifactDigest string) *Error {
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
		if req.Resources.MemoryMB <= 0 {
			return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "resources.memory_mb must be greater than 0"}
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

func validateInvocationAgainstManifest(invocation ArtifactInvocation, manifest Manifest) *Error {
	if manifest.ArtifactDigest != invocation.ArtifactDigest {
		return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "artifact digest mismatch between request and manifest"}
	}
	if len(invocation.Argv) > 100 {
		return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "invocation.argv exceeds the maximum supported count"}
	}
	allowedEnv := make(map[string]struct{}, len(manifest.RuntimeInterface.EnvironmentVariables))
	for _, key := range manifest.RuntimeInterface.EnvironmentVariables {
		allowedEnv[strings.TrimSpace(key)] = struct{}{}
	}
	for key := range invocation.Env {
		if isReservedRuntimeEnvKey(key) {
			return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: fmt.Sprintf("environment key is reserved for runtime identity or control-plane use: %s", key)}
		}
		if len(allowedEnv) > 0 {
			if _, ok := allowedEnv[key]; !ok {
				return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: fmt.Sprintf("environment key is not allowed by the runtime interface: %s", key)}
			}
		}
	}
	for _, mount := range invocation.Mounts {
		if strings.TrimSpace(mount.Name) == "" {
			return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "mount name is required"}
		}
		if mount.Source.Type != "artifact" {
			return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "mount source.type must be artifact"}
		}
		if !isLabeledSHA256Digest(mount.Source.Digest) {
			return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: fmt.Sprintf("mount source digest must be a labeled sha256 digest: %s", mount.Name)}
		}
		if strings.HasPrefix(mount.TargetSubpath, "/") || strings.Contains(mount.TargetSubpath, "..") || !validTargetSubpathPattern.MatchString(mount.TargetSubpath) {
			return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: fmt.Sprintf("mount target_subpath must be workspace-relative: %s", mount.Name)}
		}
	}
	return nil
}

func fetchArtifactJSON[T any](ctx context.Context, client *dependencyClient, endpoint string, notFoundCode string, notFoundMessage string) (T, *Error) {
	var zero T

	response, err := client.get(ctx, endpoint)
	if err != nil {
		return zero, &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    notFoundCode,
			Message: fmt.Sprintf("%s: dependency request failed", notFoundMessage),
		}
	}
	defer response.Body.Close()

	switch response.StatusCode {
	case http.StatusOK:
		var payload T
		if err := decodeJSON(response.Body, &payload); err != nil {
			return zero, &Error{
				Status:  http.StatusServiceUnavailable,
				Code:    notFoundCode,
				Message: fmt.Sprintf("%s: dependency payload was invalid", notFoundMessage),
			}
		}
		return payload, nil
	case http.StatusNotFound:
		return zero, &Error{
			Status:  http.StatusNotFound,
			Code:    notFoundCode,
			Message: notFoundMessage,
		}
	default:
		return zero, &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    notFoundCode,
			Message: fmt.Sprintf("%s: dependency returned status %d", notFoundMessage, response.StatusCode),
		}
	}
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
	decoder := json.NewDecoder(response.Body)
	if err := decoder.Decode(&payload); err != nil {
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

func (v *ed25519Verifier) verifyEnvelope(expectedCanonical []byte, info SignatureInfo) error {
	// TODO: ES reconstructs canonical bytes from parsed ARS artifact facts
	// before verifying AGS signatures. That works for this slice, but it assumes
	// AGS signed the same canonical structure ES rebuilds here. When the AGS
	// producer slice lands, freeze this canonical producer/consumer contract
	// explicitly before widening artifact fact schemas.
	// Detached-envelope rules in this slice:
	// 1. signature_info.key_id and signature_info.algorithm identify the signer
	// 2. signature_info.canonical_spec_b64 must contain the exact canonical
	//    payload bytes that ES reconstructs for the artifact fact
	// 3. signature_info.payload_digest must equal sha256(canonical payload)
	// 4. signature_info.signature_value signs only the canonical payload bytes;
	//    the signature_info wrapper itself is not signed
	if strings.TrimSpace(info.KeyID) != v.keyID {
		return fmt.Errorf("unexpected signing key id")
	}
	if strings.TrimSpace(info.Algorithm) != v.algorithm {
		return fmt.Errorf("unexpected signing algorithm")
	}
	canonicalFromEnvelope, err := base64.StdEncoding.DecodeString(strings.TrimSpace(info.CanonicalSpecB64))
	if err != nil {
		return fmt.Errorf("decode canonical payload: %w", err)
	}
	if !bytes.Equal(canonicalFromEnvelope, expectedCanonical) {
		return fmt.Errorf("canonical payload mismatch")
	}
	if info.PayloadDigest != digestBytes(expectedCanonical) {
		return fmt.Errorf("payload digest mismatch")
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(info.SignatureValue))
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(v.publicKey, expectedCanonical, signature) {
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

func canonicalProvenanceBytes(provenance Provenance) []byte {
	// Provenance canonicalization contract for the current ES slice:
	// 1. policy_decisions are normalized by sorting ascending on (rule, result)
	// 2. policy_decisions_hash = sha256("rule:result|...") over that sorted list
	// 3. the signed JSON payload is marshaled with fields in this exact order:
	//    artifact_digest, builder_service, invoker_service, invoker_principal,
	//    policy_decisions_hash, build_log_digest
	// 4. the outer policy_decisions array and signature wrapper are NOT signed;
	//    they are transport fields only
	// TODO: This producer/consumer contract is provisional until AGS exists in
	// Go. AGS must either sign exactly this canonical payload or explicitly
	// redefine the provenance signing contract and update ES accordingly.
	policyDecisions := append([]PolicyDecision(nil), provenance.PolicyDecisions...)
	sort.Slice(policyDecisions, func(i, j int) bool {
		if policyDecisions[i].Rule == policyDecisions[j].Rule {
			return policyDecisions[i].Result < policyDecisions[j].Result
		}
		return policyDecisions[i].Rule < policyDecisions[j].Rule
	})

	parts := make([]string, 0, len(policyDecisions))
	for _, decision := range policyDecisions {
		parts = append(parts, decision.Rule+":"+decision.Result)
	}
	policyDecisionHash := digestBytes([]byte(strings.Join(parts, "|")))

	payload := struct {
		ArtifactDigest      string `json:"artifact_digest"`
		BuilderService      string `json:"builder_service"`
		InvokerService      string `json:"invoker_service"`
		InvokerPrincipal    string `json:"invoker_principal"`
		PolicyDecisionsHash string `json:"policy_decisions_hash"`
		BuildLogDigest      string `json:"build_log_digest"`
	}{
		ArtifactDigest:      provenance.ArtifactDigest,
		BuilderService:      provenance.BuilderService,
		InvokerService:      provenance.Invoker.Service,
		InvokerPrincipal:    provenance.Invoker.Principal,
		PolicyDecisionsHash: policyDecisionHash,
		BuildLogDigest:      provenance.BuildLogDigest,
	}
	encoded, _ := json.Marshal(payload)
	return encoded
}

func canonicalDerivationAttestationBytes(attestation DerivationAttestation) []byte {
	// Derivation attestation canonicalization contract for the current ES slice:
	// 1. the signed JSON payload is marshaled with fields in this exact order:
	//    artifact_digest, derivation_spec_digest, output_id, constraints,
	//    policy_version, expected_artifact_type
	// 2. constraints are serialized in the struct field order:
	//    allowed_toolchains, forbidden_toolchains, os, arch, network_access,
	//    writable_paths, forbidden_paths, determinism_expectation
	// 3. signature_info is NOT part of the signed payload; it carries detached
	//    signature metadata for verification only
	// TODO: This producer/consumer contract is provisional until AGS exists in
	// Go. AGS must either sign exactly this canonical payload or explicitly
	// redefine the attestation signing contract and update ES accordingly.
	payload := struct {
		ArtifactDigest       string                        `json:"artifact_digest"`
		DerivationSpecDigest string                        `json:"derivation_spec_digest"`
		OutputID             string                        `json:"output_id"`
		Constraints          DerivationSpecConstraintsInfo `json:"constraints"`
		PolicyVersion        string                        `json:"policy_version"`
		ExpectedArtifactType string                        `json:"expected_artifact_type,omitempty"`
	}{
		ArtifactDigest:       attestation.ArtifactDigest,
		DerivationSpecDigest: attestation.DerivationSpecDigest,
		OutputID:             attestation.OutputID,
		Constraints:          attestation.Constraints,
		PolicyVersion:        attestation.PolicyVersion,
		ExpectedArtifactType: attestation.ExpectedArtifactType,
	}
	encoded, _ := json.Marshal(payload)
	return encoded
}

func canonicalWorkloadIdentityBindingBytes(binding WorkloadIdentityBinding) []byte {
	// Workload identity binding canonicalization contract for the current ES
	// slice:
	// 1. the signed JSON payload is marshaled with fields in this exact order:
	//    artifact_class, artifact_digest, derivation_spec_digest, description,
	//    module_path, output_id, policy_version, service_name, target_platform,
	//    workload_identity_id, workload_type
	// 2. omitempty fields participate only when present in the binding payload
	// 3. signature_info is NOT part of the signed payload; it carries detached
	//    signature metadata for verification only
	// TODO: This producer/consumer contract is provisional until AGS exists in
	// Go. AGS must either sign exactly this canonical payload or explicitly
	// redefine the binding signing contract and update ES accordingly.
	payload := struct {
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
		ArtifactClass:        binding.ArtifactClass,
		ArtifactDigest:       binding.ArtifactDigest,
		DerivationSpecDigest: binding.DerivationSpecDigest,
		Description:          binding.Description,
		ModulePath:           binding.ModulePath,
		OutputID:             binding.OutputID,
		PolicyVersion:        binding.PolicyVersion,
		ServiceName:          binding.ServiceName,
		TargetPlatform:       binding.TargetPlatform,
		WorkloadIdentityID:   binding.WorkloadIdentityID,
		WorkloadType:         binding.WorkloadType,
	}
	encoded, _ := json.Marshal(payload)
	return encoded
}
