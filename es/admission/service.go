package admission

import (
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
	"strings"
	"sync"
	"time"

	evidencev1 "execution-platform/contracts/evidence/v1"
	egsmodel "execution-platform/egs/model"
	esconfig "execution-platform/es/config"
	"execution-platform/observability"
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
	codePayloadUnavailable              = "payload_unavailable"
	codeSubmissionFailed                = "submission_failed"
	codeInvalidRunID                    = "invalid_run_id"
	codeExecutionNotFound               = "execution_not_found"
	codeLogsUnavailable                 = "logs_unavailable"
	codeMountConflict                   = "mount_conflict"
	codeMountArtifactInvalid            = "mount_artifact_invalid"
)

// TODO: Do not mention "monolith"
var (
	labeledSHA256DigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	reservedRuntimeEnvKeys     = map[string]struct{}{
		"PROJECT_NAME":                        {},
		"ENVIRONMENT":                         {},
		"PLATFORM":                            {},
		"GUID":                                {},
		"SERVICE_ID":                          {},
		"SESSION_ID":                          {},
		"PARENT_SESSION_ID":                   {},
		"traceparent":                         {},
		"MONOLITH_SVID_PATH":                  {},
		"VAULT_AGENT_TOKEN_PATH":              {},
		"VAULT_ADDR":                          {},
		"VAULT_NAMESPACE":                     {},
		"MONOLITH_WORKLOAD_IDENTITY_ENDPOINT": {},
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

	trustModelVerifier *ed25519Verifier
	provenanceVerifier *ed25519Verifier
	nomadClient        *nomadClient

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

type artifactRegistryErrorResponse struct {
	Error string `json:"error"`
}

type artifactRegistryDescriptor struct {
	SchemaVersion string                             `json:"schema_version"`
	Artifact      artifactRegistryDescriptorIdentity `json:"artifact"`
	Package       artifactRegistryDescriptorPackage  `json:"package"`
}

type artifactRegistryDescriptorIdentity struct {
	ArtifactDigest string `json:"artifact_digest"`
	ArtifactType   string `json:"artifact_type"`
	IntentDigest   string `json:"intent_digest"`
}

type artifactRegistryDescriptorPackage struct {
	Evidence   artifactRegistryBlobRef         `json:"evidence"`
	Payload    artifactRegistryBlobRef         `json:"payload"`
	Supporting []artifactRegistrySupportingRef `json:"supporting,omitempty"`
}

type artifactRegistryBlobRef struct {
	Digest    string `json:"digest"`
	MediaType string `json:"media_type,omitempty"`
}

type artifactRegistrySupportingRef struct {
	Name      string `json:"name"`
	Digest    string `json:"digest"`
	MediaType string `json:"media_type,omitempty"`
}

type discoveredArtifact struct {
	descriptor artifactRegistryDescriptor
	evidence   evidencev1.ArtifactEvidence
}

type preparedArtifact struct {
	manifest       Manifest
	payloadDigest  string
	signerKeyID    string
	workload       WorkloadInfo
	workloadAttrs  esconfig.WorkloadIdentityAttributes
	targetPlatform string
	networkAccess  bool
}

type preparedAdmission struct {
	result     PrepareResult
	artifact   preparedArtifact
	trustModel egsmodel.TrustModel
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
	if _, err := newEd25519Verifier(cfg.Verification.DerivationAttestation); err != nil {
		return nil, err
	}
	if _, err := newEd25519Verifier(cfg.Verification.WorkloadIdentityBinding); err != nil {
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
		cfg:                cfg,
		acsClient:          acsClient,
		arsClient:          arsClient,
		egsClient:          egsClient,
		trustModelVerifier: trustModelVerifier,
		provenanceVerifier: provenanceVerifier,
		nomadClient:        nomadClient,
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
	prepared, err := s.prepareAdmission(ctx, req)
	if err != nil {
		return PrepareResult{}, err
	}
	return prepared.result, nil
}

func (s *Service) prepareAdmission(ctx context.Context, req PrepareRequest) (preparedAdmission, *Error) {
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

	workloadVaultDigest, err := s.fetchWorkloadZoneVaultDigest(ctx)
	if err != nil {
		return preparedAdmission{}, err
	}

	workloadVaultConfig, err := s.fetchWorkloadZoneVaultConfig(ctx, workloadVaultDigest)
	if err != nil {
		return preparedAdmission{}, err
	}

	plan, resolveErr := s.cfg.WorkloadVaultAuth.Resolve(
		artifact.workloadAttrs,
		esconfig.VaultRuntimeFields{
			Address:     workloadVaultConfig.VaultConfig.Address,
			AuthMount:   workloadVaultConfig.VaultConfig.AuthMount,
			AuthRole:    workloadVaultConfig.VaultConfig.AuthRole,
			JWTAudience: workloadVaultConfig.VaultConfig.JWTAudience,
		},
	)
	if resolveErr != nil {
		return preparedAdmission{}, &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    codeWorkloadZoneVaultUnavailable,
			Message: resolveErr.Error(),
		}
	}

	return preparedAdmission{
		result: PrepareResult{
			Success:              true,
			ArtifactDigest:       req.Invocation.ArtifactDigest,
			DerivationSpecDigest: req.Invocation.DerivationSpecDigest,
			OutputID:             req.Invocation.OutputID,
			IntentDigest:         artifact.manifest.IntentDigest,
			ArtifactType:         artifact.manifest.ArtifactType,
			TrustModel: TrustModelInfo{
				Version:        trustModel.Version,
				UpdateRevision: trustModel.UpdateRevision,
			},
			Provenance: ProvenanceInfo{
				SignerKeyID: artifact.signerKeyID,
			},
			Workload: artifact.workload,
			WorkloadVault: WorkloadVaultInfo{
				Digest:      workloadVaultDigest,
				Address:     plan.Address,
				AuthMode:    string(plan.Mode),
				AuthMount:   plan.AuthMount,
				AuthRole:    plan.AuthRole,
				JWTAudience: plan.JWTAudience,
			},
		},
		artifact:   artifact,
		trustModel: *trustModel,
	}, nil
}

func (s *Service) prepareArtifact(ctx context.Context, req PrepareRequest, trustModel egsmodel.TrustModel) (preparedArtifact, *Error) {
	discovery, err := s.fetchArtifactDiscovery(ctx, req.Invocation.ArtifactDigest)
	if err != nil {
		return preparedArtifact{}, err
	}
	return s.prepareArtifactFromDiscovery(req, trustModel, discovery)
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

func (s *Service) fetchArtifactDiscovery(ctx context.Context, artifactDigest string) (discoveredArtifact, *Error) {
	descriptor, err := s.fetchArtifactDescriptor(ctx, artifactDigest)
	if err != nil {
		return discoveredArtifact{}, err
	}
	evidence, err := s.fetchArtifactEvidenceBlob(ctx, artifactDigest, descriptor.Package.Evidence.Digest)
	if err != nil {
		return discoveredArtifact{}, err
	}
	return discoveredArtifact{
		descriptor: descriptor,
		evidence:   evidence,
	}, nil
}

func (s *Service) fetchArtifactDescriptor(ctx context.Context, artifactDigest string) (artifactRegistryDescriptor, *Error) {
	response, err := s.arsClient.get(ctx, "/v1/artifacts/"+artifactDigest+"/descriptor")
	if err != nil {
		return artifactRegistryDescriptor{}, &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    codeArtifactEvidenceUnavailable,
			Message: "artifact descriptor read failed",
		}
	}
	defer response.Body.Close()

	switch response.StatusCode {
		case http.StatusOK:
			var payload artifactRegistryDescriptor
			if err := decodeJSON(response.Body, &payload); err != nil {
				return artifactRegistryDescriptor{}, &Error{
					Status:  http.StatusServiceUnavailable,
					Code:    codeArtifactEvidenceUnavailable,
					Message: "artifact descriptor payload was invalid",
				}
			}
			return payload, nil
		case http.StatusNotFound:
			var payload artifactRegistryErrorResponse
			if err := json.NewDecoder(response.Body).Decode(&payload); err == nil {
				switch strings.TrimSpace(payload.Error) {
					case "artifact not found", "artifact data not registered":
						return artifactRegistryDescriptor{}, &Error{
							Status:  http.StatusNotFound,
							Code:    codeArtifactEvidenceNotFound,
							Message: "artifact evidence not found",
						}
				}
			}
			return artifactRegistryDescriptor{}, &Error{
				Status:  http.StatusServiceUnavailable,
				Code:    codeArtifactEvidenceUnavailable,
				Message: "artifact evidence is unavailable",
			}
		default:
			return artifactRegistryDescriptor{}, &Error{
				Status:  http.StatusServiceUnavailable,
				Code:    codeArtifactEvidenceUnavailable,
				Message: "artifact evidence is unavailable",
			}
	}
}

func (s *Service) fetchArtifactEvidenceBlob(ctx context.Context, artifactDigest string, evidenceDigest string) (evidencev1.ArtifactEvidence, *Error) {
	response, err := s.arsClient.get(ctx, "/v1/blobs/"+evidenceDigest+":json")
	if err != nil {
		return evidencev1.ArtifactEvidence{}, &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    codeArtifactEvidenceUnavailable,
			Message: "artifact evidence read failed",
		}
	}
	defer response.Body.Close()

	switch response.StatusCode {
		case http.StatusOK:
			var payload evidencev1.ArtifactEvidence
			if err := decodeJSON(response.Body, &payload); err != nil {
				return evidencev1.ArtifactEvidence{}, &Error{
					Status:  http.StatusServiceUnavailable,
					Code:    codeArtifactEvidenceUnavailable,
					Message: "artifact evidence payload was invalid",
				}
			}
			return payload, nil
		case http.StatusNotFound:
			return evidencev1.ArtifactEvidence{}, &Error{
				Status:  http.StatusServiceUnavailable,
				Code:    codeArtifactEvidenceUnavailable,
				Message: "artifact evidence is unavailable",
			}
		default:
			return evidencev1.ArtifactEvidence{}, &Error{
				Status:  http.StatusServiceUnavailable,
				Code:    codeArtifactEvidenceUnavailable,
				Message: "artifact evidence is unavailable",
			}
	}
}

func (s *Service) prepareArtifactFromDiscovery(req PrepareRequest, trustModel egsmodel.TrustModel, discovery discoveredArtifact) (preparedArtifact, *Error) {
	descriptor := discovery.descriptor
	evidence := discovery.evidence
	if descriptor.Artifact.ArtifactDigest != req.Invocation.ArtifactDigest {
		return preparedArtifact{}, &Error{
			Status:  http.StatusBadRequest,
			Code:    codeInvalidRequest,
			Message: "artifact digest mismatch between request and artifact descriptor",
		}
	}
	if evidence.Claims.Artifact.ArtifactDigest != req.Invocation.ArtifactDigest {
		return preparedArtifact{}, &Error{
			Status:  http.StatusBadRequest,
			Code:    codeInvalidRequest,
			Message: "artifact digest mismatch between request and artifact evidence",
		}
	}
	if evidence.Claims.Admission.Derivation.DerivationSpecDigest != req.Invocation.DerivationSpecDigest {
		return preparedArtifact{}, &Error{
			Status:  http.StatusBadRequest,
			Code:    codeInvalidRequest,
			Message: "derivation_spec_digest does not match artifact evidence",
		}
	}
	if evidence.Claims.Admission.Derivation.OutputID != req.Invocation.OutputID {
		return preparedArtifact{}, &Error{
			Status:  http.StatusBadRequest,
			Code:    codeInvalidRequest,
			Message: "output_id does not match artifact evidence",
		}
	}
	artifact, err := s.prepareArtifactFromEvidenceRecord(trustModel, descriptor, evidence)
	if err != nil {
		return preparedArtifact{}, err
	}
	if err := validateInvocationAgainstManifest(req.Invocation, artifact.manifest); err != nil {
		return preparedArtifact{}, err
	}
	return artifact, nil
}

func (s *Service) prepareArtifactFromEvidenceRecord(trustModel egsmodel.TrustModel, descriptor artifactRegistryDescriptor, evidence evidencev1.ArtifactEvidence) (preparedArtifact, *Error) {
	artifactDigest := strings.TrimSpace(descriptor.Artifact.ArtifactDigest)
	if evidence.Claims.Artifact.ArtifactDigest != artifactDigest {
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
	if evidence.Claims.Artifact.PayloadDigest != strings.TrimSpace(descriptor.Package.Payload.Digest) {
		return preparedArtifact{}, &Error{
			Status:  http.StatusForbidden,
			Code:    codeArtifactEvidenceInvalid,
			Message: "artifact descriptor payload reference does not match artifact evidence",
		}
	}
	if evidence.Claims.Artifact.ArtifactType != strings.TrimSpace(descriptor.Artifact.ArtifactType) {
		return preparedArtifact{}, &Error{
			Status:  http.StatusForbidden,
			Code:    codeArtifactEvidenceInvalid,
			Message: "artifact descriptor artifact type does not match artifact evidence",
		}
	}
	if evidence.Claims.Artifact.IntentDigest != strings.TrimSpace(descriptor.Artifact.IntentDigest) {
		return preparedArtifact{}, &Error{
			Status:  http.StatusForbidden,
			Code:    codeArtifactEvidenceInvalid,
			Message: "artifact descriptor intent digest does not match artifact evidence",
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
		manifest:      manifestFromEvidence(evidence),
		payloadDigest: strings.TrimSpace(descriptor.Package.Payload.Digest),
		signerKeyID:   evidence.Seal.KeyID,
		workload: WorkloadInfo{
			Type:               evidence.Claims.Admission.Workload.WorkloadType,
			ServiceName:        evidence.Claims.Admission.Workload.ServiceName,
			WorkloadIdentityID: evidence.Claims.Admission.Workload.WorkloadIdentityID,
		},
		workloadAttrs: esconfig.WorkloadIdentityAttributes{
			ArtifactClass:      evidence.Claims.Admission.Workload.ArtifactClass,
			WorkloadType:       evidence.Claims.Admission.Workload.WorkloadType,
			ServiceName:        evidence.Claims.Admission.Workload.ServiceName,
			WorkloadIdentityID: evidence.Claims.Admission.Workload.WorkloadIdentityID,
		},
		targetPlatform: evidence.Claims.Admission.Workload.TargetPlatform,
		networkAccess:  evidence.Claims.Admission.Derivation.Constraints.NetworkAccess,
	}, nil
}

func manifestFromEvidence(evidence evidencev1.ArtifactEvidence) Manifest {
	return Manifest{
		ArtifactDigest: evidence.Claims.Artifact.ArtifactDigest,
		ArtifactType:   evidence.Claims.Artifact.ArtifactType,
		IntentDigest:   evidence.Claims.Artifact.IntentDigest,
		RuntimeInterface: RuntimeInterface{
			Parameters:           append([]string(nil), evidence.Claims.Admission.Runtime.Parameters...),
			EnvironmentVariables: append([]string(nil), evidence.Claims.Admission.Runtime.EnvironmentVariables...),
			RequiredCapabilities: append([]string(nil), evidence.Claims.Admission.Runtime.RequiredCapabilities...),
		},
	}
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
