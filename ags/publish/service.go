package publish

import (
	"bytes"
	"context"
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
	"regexp"
	"sort"
	"strings"
	"time"

	"execution-platform/ags/config"
	"execution-platform/ags/sign"
	evidencev1 "execution-platform/contracts/evidence/v1"
	"execution-platform/observability"
)

const (
	codeInvalidRequest   = "invalid_request"
	codePublishFailed    = "publish_failed"
	codeDependencyError  = "artifact_registry_unavailable"
	codePublishForbidden = "publish_forbidden"
	codeArtifactConflict = "artifact_fact_conflict"
	builderServiceName   = "artifact-governance"
)

var labeledSHA256DigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type Service struct {
	cfg       config.Config
	arsClient *dependencyClient
	signer    sign.Signer
}

type dependencyClient struct {
	baseURL *url.URL
	client  *http.Client
}

type registerArtifactRequest struct {
	DescriptorDigest string `json:"descriptor_digest"`
}

type artifactDescriptor struct {
	SchemaVersion string           `json:"schema_version"`
	Artifact      artifactIdentity `json:"artifact"`
	Package       artifactPackage  `json:"package"`
}

type artifactIdentity struct {
	ArtifactDigest string `json:"artifact_digest"`
	ArtifactType   string `json:"artifact_type"`
	IntentDigest   string `json:"intent_digest"`
}

type artifactPackage struct {
	Evidence   artifactBlobRef      `json:"evidence"`
	Payload    artifactBlobRef      `json:"payload"`
	Supporting []artifactSupportRef `json:"supporting,omitempty"`
}

type artifactBlobRef struct {
	Digest    string `json:"digest"`
	MediaType string `json:"media_type,omitempty"`
}

type artifactSupportRef struct {
	Name      string `json:"name"`
	Digest    string `json:"digest"`
	MediaType string `json:"media_type,omitempty"`
}

type dependencyHealthResponse struct {
	Status string `json:"status"`
	Ready  bool   `json:"ready"`
}

type blobUpload struct {
	digest string
	data   []byte
}

func NewService(cfg config.Config) (*Service, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	arsClient, err := newDependencyClient(cfg.Dependencies.ArtifactRegistry)
	if err != nil {
		return nil, fmt.Errorf("build artifact registry client: %w", err)
	}

	signer, err := sign.NewEd25519Signer(cfg.Signer.KeyID, cfg.Signer.PrivateKeyHex, cfg.Signer.PublicKeyHex)
	if err != nil {
		return nil, err
	}

	return &Service{
		cfg:       cfg,
		arsClient: arsClient,
		signer:    signer,
	}, nil
}

func (s *Service) Health(ctx context.Context) HealthSnapshot {
	return HealthSnapshot{
		ArtifactRegistryHealthy: s.arsClient.checkReady(ctx),
		SignerReady:             s.signer != nil,
	}
}

func (s *Service) Publish(ctx context.Context, caller CallerIdentity, req PublishRequest) (PublishResult, *Error) {
	validation, validationErr := validatePublishRequest(caller, &req)
	if validationErr != nil {
		return PublishResult{}, validationErr
	}

	payloadDigest := digestBytes(validation.payloadBytes)
	artifactDigest, err := deriveArtifactDigest(payloadDigest, req)
	if err != nil {
		return PublishResult{}, &Error{Status: http.StatusInternalServerError, Code: codePublishFailed, Message: "derive artifact identity failed"}
	}

	manifest := Manifest{
		ArtifactDigest:   artifactDigest,
		ArtifactType:     strings.TrimSpace(req.Artifact.ArtifactType),
		IntentDigest:     strings.TrimSpace(req.Artifact.IntentDigest),
		RuntimeInterface: req.Admission.Runtime,
	}

	metadata := DerivationMetadata{
		DerivationSpecDigest: strings.TrimSpace(req.Admission.Derivation.DerivationSpecDigest),
		OutputID:             strings.TrimSpace(req.Admission.Derivation.OutputID),
		ProducerRunID:        strings.TrimSpace(req.Admission.Derivation.ProducerRunID),
	}

	evidence, err := s.buildArtifactEvidence(payloadDigest, manifest, metadata, req, validation.invoker)
	if err != nil {
		return PublishResult{}, &Error{Status: http.StatusInternalServerError, Code: codePublishFailed, Message: err.Error()}
	}

	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return PublishResult{}, &Error{Status: http.StatusInternalServerError, Code: codePublishFailed, Message: "marshal manifest failed"}
	}
	evidenceBytes, err := json.Marshal(evidence)
	if err != nil {
		return PublishResult{}, &Error{Status: http.StatusInternalServerError, Code: codePublishFailed, Message: "marshal artifact evidence failed"}
	}
	evidenceDigest := digestBytes(evidenceBytes)
	manifestDigest := digestBytes(manifestBytes)
	descriptor := artifactDescriptor{
		SchemaVersion: "v1",
		Artifact: artifactIdentity{
			ArtifactDigest: artifactDigest,
			ArtifactType:   manifest.ArtifactType,
			IntentDigest:   manifest.IntentDigest,
		},
		Package: artifactPackage{
			Evidence: artifactBlobRef{
				Digest:    evidenceDigest,
				MediaType: "application/json",
			},
			Payload: artifactBlobRef{
				Digest:    payloadDigest,
				MediaType: "application/octet-stream",
			},
			Supporting: []artifactSupportRef{
				{
					Name:      "manifest",
					Digest:    manifestDigest,
					MediaType: "application/json",
				},
			},
		},
	}
	descriptorBytes, err := json.Marshal(descriptor)
	if err != nil {
		return PublishResult{}, &Error{Status: http.StatusInternalServerError, Code: codePublishFailed, Message: "marshal artifact descriptor failed"}
	}
	descriptorDigest := digestBytes(descriptorBytes)

	uploads := []blobUpload{
		{digest: payloadDigest, data: validation.payloadBytes},
		{digest: evidenceDigest, data: evidenceBytes},
		{digest: manifestDigest, data: manifestBytes},
		{digest: descriptorDigest, data: descriptorBytes},
	}

	for _, upload := range uploads {
		if err := s.arsClient.putBlob(ctx, upload.digest, upload.data); err != nil {
			return PublishResult{}, &Error{Status: http.StatusServiceUnavailable, Code: codeDependencyError, Message: err.Error()}
		}
	}

	if err := s.arsClient.registerArtifact(ctx, registerArtifactRequest{
		DescriptorDigest: descriptorDigest,
	}); err != nil {
		return PublishResult{}, &Error{Status: http.StatusServiceUnavailable, Code: codeDependencyError, Message: err.Error()}
	}

	return PublishResult{
		Published:        true,
		ArtifactDigest:   artifactDigest,
		DescriptorDigest: descriptorDigest,
		EvidenceDigest:   evidenceDigest,
		ManifestDigest:   manifestDigest,
		PayloadDigest:    payloadDigest,
	}, nil
}

func (s *Service) buildArtifactEvidence(
	payloadDigest string,
	manifest Manifest,
	metadata DerivationMetadata,
	req PublishRequest,
	invoker InvokerInfo,
) (evidencev1.ArtifactEvidence, error) {
	record := evidencev1.ArtifactEvidence{
		Claims: evidencev1.Claims{
			SchemaVersion: evidencev1.Version,
			Artifact: evidencev1.Artifact{
				ArtifactDigest: manifest.ArtifactDigest,
				PayloadDigest:  payloadDigest,
				ArtifactType:   manifest.ArtifactType,
				IntentDigest:   manifest.IntentDigest,
			},
			Publication: evidencev1.Publication{
				BuilderService: builderServiceName,
				Invoker: evidencev1.Invoker{
					Service:   invoker.Service,
					Principal: invoker.Principal,
				},
				PolicyDecisions: toEvidencePolicyDecisions(normalizePolicyDecisions(req.Publication.PolicyDecisions)),
				BuildLogDigest:  strings.TrimSpace(req.Publication.BuildLogDigest),
			},
			Admission: evidencev1.Admission{
				Runtime: evidencev1.Runtime{
					Parameters:           cloneStringsPreserveShape(manifest.RuntimeInterface.Parameters),
					EnvironmentVariables: cloneStringsPreserveShape(manifest.RuntimeInterface.EnvironmentVariables),
					RequiredCapabilities: cloneStringsPreserveShape(manifest.RuntimeInterface.RequiredCapabilities),
				},
				Derivation: evidencev1.Derivation{
					DerivationSpecDigest: metadata.DerivationSpecDigest,
					OutputID:             metadata.OutputID,
					ProducerRunID:        metadata.ProducerRunID,
					PolicyVersion:        strings.TrimSpace(req.Admission.Derivation.PolicyVersion),
					ExpectedArtifactType: strings.TrimSpace(req.Admission.Derivation.ExpectedArtifactType),
					Constraints: evidencev1.Constraints{
						AllowedToolchains:      cloneStringsPreserveShape(req.Admission.Derivation.Constraints.AllowedToolchains),
						ForbiddenToolchains:    cloneStringsPreserveShape(req.Admission.Derivation.Constraints.ForbiddenToolchains),
						OS:                     req.Admission.Derivation.Constraints.OS,
						Arch:                   req.Admission.Derivation.Constraints.Arch,
						NetworkAccess:          req.Admission.Derivation.Constraints.NetworkAccess,
						WritablePaths:          cloneStringsPreserveShape(req.Admission.Derivation.Constraints.WritablePaths),
						ForbiddenPaths:         cloneStringsPreserveShape(req.Admission.Derivation.Constraints.ForbiddenPaths),
						DeterminismExpectation: req.Admission.Derivation.Constraints.DeterminismExpectation,
					},
				},
				Workload: evidencev1.Workload{
					ArtifactClass:      strings.TrimSpace(req.Admission.Workload.ArtifactClass),
					WorkloadType:       strings.TrimSpace(req.Admission.Workload.WorkloadType),
					ModulePath:         strings.TrimSpace(req.Admission.Workload.ModulePath),
					ServiceName:        strings.TrimSpace(req.Admission.Workload.ServiceName),
					TargetPlatform:     strings.TrimSpace(req.Admission.Workload.TargetPlatform),
					Description:        strings.TrimSpace(req.Admission.Workload.Description),
					WorkloadIdentityID: strings.TrimSpace(req.Admission.Workload.WorkloadIdentityID),
					PolicyVersion:      strings.TrimSpace(req.Admission.Workload.PolicyVersion),
				},
			},
		},
	}

	canonical, err := record.CanonicalBytes()
	if err != nil {
		return evidencev1.ArtifactEvidence{}, err
	}
	signature, err := s.signer.SignDetached(canonical)
	if err != nil {
		return evidencev1.ArtifactEvidence{}, err
	}
	record.Seal = evidencev1.NewSeal(canonical, s.signer.KeyID(), s.signer.Algorithm(), signature)
	return record, nil
}

type publishValidation struct {
	payloadBytes []byte
	invoker      InvokerInfo
}

func validatePublishRequest(caller CallerIdentity, req *PublishRequest) (publishValidation, *Error) {
	if req == nil {
		return publishValidation{}, &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "request body is required"}
	}

	invoker, authErr := expectedInvokerForCaller(caller)
	if authErr != nil {
		return publishValidation{}, authErr
	}

	payloadBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.ArtifactPayloadB64))
	if err != nil {
		return publishValidation{}, &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "artifact_payload_b64 must be valid base64"}
	}
	if strings.TrimSpace(req.Artifact.ArtifactType) == "" {
		return publishValidation{}, &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "artifact.artifact_type is required"}
	}
	if !isLabeledSHA256Digest(req.Artifact.IntentDigest) {
		return publishValidation{}, &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "artifact.intent_digest must be a labeled sha256 digest"}
	}
	if !isLabeledSHA256Digest(req.Publication.BuildLogDigest) {
		return publishValidation{}, &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "publication.build_log_digest must be a labeled sha256 digest"}
	}
	if !isLabeledSHA256Digest(req.Admission.Derivation.DerivationSpecDigest) {
		return publishValidation{}, &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "admission.derivation.derivation_spec_digest must be a labeled sha256 digest"}
	}
	if strings.TrimSpace(req.Admission.Derivation.OutputID) == "" {
		return publishValidation{}, &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "admission.derivation.output_id is required"}
	}
	if strings.TrimSpace(req.Admission.Derivation.ProducerRunID) == "" {
		return publishValidation{}, &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "admission.derivation.producer_run_id is required"}
	}
	if strings.TrimSpace(req.Admission.Derivation.PolicyVersion) == "" {
		return publishValidation{}, &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "admission.derivation.policy_version is required"}
	}
	if strings.TrimSpace(req.Admission.Workload.ArtifactClass) == "" {
		return publishValidation{}, &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "admission.workload.artifact_class is required"}
	}
	if strings.TrimSpace(req.Admission.Workload.WorkloadType) == "" {
		return publishValidation{}, &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "admission.workload.workload_type is required"}
	}
	if strings.TrimSpace(req.Admission.Workload.ModulePath) == "" {
		return publishValidation{}, &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "admission.workload.module_path is required"}
	}
	if strings.TrimSpace(req.Admission.Workload.PolicyVersion) == "" {
		return publishValidation{}, &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "admission.workload.policy_version is required"}
	}
	if strings.TrimSpace(req.Admission.Workload.WorkloadIdentityID) == "" {
		return publishValidation{}, &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "admission.workload.workload_identity_id is required"}
	}
	workloadIdentityID := strings.TrimSpace(req.Admission.Workload.WorkloadIdentityID)
	if !isValidSPIFFEURI(workloadIdentityID) {
		return publishValidation{}, &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "admission.workload.workload_identity_id must be a valid SPIFFE URI"}
	}
	serviceName := strings.TrimSpace(req.Admission.Workload.ServiceName)
	if strings.TrimSpace(req.Admission.Workload.WorkloadType) == "service" && serviceName == "" {
		return publishValidation{}, &Error{Status: http.StatusConflict, Code: codeArtifactConflict, Message: "admission.workload.service_name is required for service workloads"}
	}
	if strings.TrimSpace(req.Admission.Derivation.PolicyVersion) != strings.TrimSpace(req.Admission.Workload.PolicyVersion) {
		return publishValidation{}, &Error{Status: http.StatusConflict, Code: codeArtifactConflict, Message: "admission.derivation.policy_version must match admission.workload.policy_version"}
	}
	expectedArtifactType := strings.TrimSpace(req.Admission.Derivation.ExpectedArtifactType)
	if expectedArtifactType != "" && expectedArtifactType != strings.TrimSpace(req.Artifact.ArtifactType) {
		return publishValidation{}, &Error{Status: http.StatusConflict, Code: codeArtifactConflict, Message: "admission.derivation.expected_artifact_type must match artifact.artifact_type"}
	}
	if serviceName != "" {
		derivedServiceName, ok := spiffeServiceName(workloadIdentityID)
		if !ok || derivedServiceName != serviceName {
			return publishValidation{}, &Error{Status: http.StatusConflict, Code: codeArtifactConflict, Message: "admission.workload.service_name conflicts with admission.workload.workload_identity_id"}
		}
	}

	return publishValidation{
		payloadBytes: payloadBytes,
		invoker:      invoker,
	}, nil
}

func expectedInvokerForCaller(caller CallerIdentity) (InvokerInfo, *Error) {
	// TODO: Do not mention "monolith"
	switch caller.Path {
		case "service/deployment":
			return InvokerInfo{
				Service:   "deployment",
				Principal: "spiffe://monolith.internal/service/deployment",
			}, nil
		case "operator":
			return InvokerInfo{
				Service:   "operator",
				Principal: "spiffe://monolith.internal/operator",
			}, nil
		default:
			return InvokerInfo{}, &Error{Status: http.StatusForbidden, Code: codePublishForbidden, Message: "caller not authorized for artifact publication"}
	}
}

func isValidSPIFFEURI(value string) bool {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return false
	}
	if parsed.Scheme != "spiffe" || parsed.Host == "" {
		return false
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	return strings.TrimSpace(parsed.Path) != ""
}

func spiffeServiceName(value string) (string, bool) {
	if !isValidSPIFFEURI(value) {
		return "", false
	}

	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return "", false
	}

	trimmedPath := strings.Trim(parsed.Path, "/")
	segments := strings.Split(trimmedPath, "/")
	if len(segments) != 2 || segments[0] != "service" || strings.TrimSpace(segments[1]) == "" {
		return "", false
	}
	return segments[1], true
}

func newDependencyClient(cfg config.DependencyConfig) (*dependencyClient, error) {
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
		return nil, fmt.Errorf("parse dependency url: %w", err)
	}

	client := &http.Client{
		Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second,
		Transport: observability.WrapRoundTripper(builderServiceName, "artifact-registry", true, &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{certificate},
				RootCAs:      rootCAs,
				ServerName:   cfg.ServerName,
			},
		}),
	}

	return &dependencyClient{
		baseURL: baseURL,
		client:  client,
	}, nil
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
	var payload dependencyHealthResponse
	decoder := json.NewDecoder(response.Body)
	if err := decoder.Decode(&payload); err != nil {
		return false
	}
	return payload.Status == "healthy" && payload.Ready
}

func (c *dependencyClient) putBlob(ctx context.Context, digest string, data []byte) error {
	requestURL := c.baseURL.ResolveReference(&url.URL{Path: "/v1/blobs/" + digest})
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, requestURL.String(), bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build blob upload request: %w", err)
	}

	response, err := c.client.Do(request)
	if err != nil {
		return fmt.Errorf("upload blob %s: %w", digest, err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		return fmt.Errorf("upload blob %s: unexpected status %d body=%s", digest, response.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (c *dependencyClient) registerArtifact(ctx context.Context, requestBody registerArtifactRequest) error {
	payload, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("marshal register request: %w", err)
	}

	requestURL := c.baseURL.ResolveReference(&url.URL{Path: "/v1/artifacts:register"})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL.String(), strings.NewReader(string(payload)))
	if err != nil {
		return fmt.Errorf("build register request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := c.client.Do(request)
	if err != nil {
		return fmt.Errorf("register descriptor %s: %w", requestBody.DescriptorDigest, err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		return fmt.Errorf("register descriptor %s: unexpected status %d body=%s", requestBody.DescriptorDigest, response.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (c *dependencyClient) get(ctx context.Context, path string) (*http.Response, error) {
	requestURL := c.baseURL.ResolveReference(&url.URL{Path: path})
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return nil, err
	}
	return c.client.Do(request)
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

func deriveArtifactDigest(payloadDigest string, req PublishRequest) (string, error) {
	type identityArtifact struct {
		PayloadDigest string `json:"payload_digest"`
		ArtifactType  string `json:"artifact_type"`
		IntentDigest  string `json:"intent_digest"`
	}
	type identityRuntime struct {
		Parameters           []string `json:"parameters"`
		EnvironmentVariables []string `json:"environment_variables"`
		RequiredCapabilities []string `json:"required_capabilities"`
	}
	type identityConstraints struct {
		AllowedToolchains      []string `json:"allowed_toolchains"`
		ForbiddenToolchains    []string `json:"forbidden_toolchains"`
		OS                     string   `json:"os"`
		Arch                   string   `json:"arch"`
		NetworkAccess          bool     `json:"network_access"`
		WritablePaths          []string `json:"writable_paths"`
		ForbiddenPaths         []string `json:"forbidden_paths"`
		DeterminismExpectation string   `json:"determinism_expectation"`
	}
	type identityDerivation struct {
		DerivationSpecDigest string              `json:"derivation_spec_digest"`
		OutputID             string              `json:"output_id"`
		ExpectedArtifactType string              `json:"expected_artifact_type,omitempty"`
		Constraints          identityConstraints `json:"constraints"`
	}
	type identityWorkload struct {
		ArtifactClass      string `json:"artifact_class"`
		WorkloadType       string `json:"workload_type"`
		ModulePath         string `json:"module_path"`
		ServiceName        string `json:"service_name,omitempty"`
		TargetPlatform     string `json:"target_platform,omitempty"`
		Description        string `json:"description,omitempty"`
		WorkloadIdentityID string `json:"workload_identity_id"`
	}
	type artifactIdentity struct {
		SchemaVersion string             `json:"schema_version"`
		Artifact      identityArtifact   `json:"artifact"`
		Runtime       identityRuntime    `json:"runtime"`
		Derivation    identityDerivation `json:"derivation"`
		Workload      identityWorkload   `json:"workload"`
	}

	identity := artifactIdentity{
		SchemaVersion: "v1",
		Artifact: identityArtifact{
			PayloadDigest: strings.TrimSpace(payloadDigest),
			ArtifactType:  strings.TrimSpace(req.Artifact.ArtifactType),
			IntentDigest:  strings.TrimSpace(req.Artifact.IntentDigest),
		},
		Runtime: identityRuntime{
			Parameters:           normalizeStringSet(req.Admission.Runtime.Parameters),
			EnvironmentVariables: normalizeStringSet(req.Admission.Runtime.EnvironmentVariables),
			RequiredCapabilities: normalizeStringSet(req.Admission.Runtime.RequiredCapabilities),
		},
		Derivation: identityDerivation{
			DerivationSpecDigest: strings.TrimSpace(req.Admission.Derivation.DerivationSpecDigest),
			OutputID:             strings.TrimSpace(req.Admission.Derivation.OutputID),
			ExpectedArtifactType: strings.TrimSpace(req.Admission.Derivation.ExpectedArtifactType),
			Constraints: identityConstraints{
				AllowedToolchains:      normalizeStringSet(req.Admission.Derivation.Constraints.AllowedToolchains),
				ForbiddenToolchains:    normalizeStringSet(req.Admission.Derivation.Constraints.ForbiddenToolchains),
				OS:                     strings.TrimSpace(req.Admission.Derivation.Constraints.OS),
				Arch:                   strings.TrimSpace(req.Admission.Derivation.Constraints.Arch),
				NetworkAccess:          req.Admission.Derivation.Constraints.NetworkAccess,
				WritablePaths:          normalizeStringSet(req.Admission.Derivation.Constraints.WritablePaths),
				ForbiddenPaths:         normalizeStringSet(req.Admission.Derivation.Constraints.ForbiddenPaths),
				DeterminismExpectation: strings.TrimSpace(req.Admission.Derivation.Constraints.DeterminismExpectation),
			},
		},
		Workload: identityWorkload{
			ArtifactClass:      strings.TrimSpace(req.Admission.Workload.ArtifactClass),
			WorkloadType:       strings.TrimSpace(req.Admission.Workload.WorkloadType),
			ModulePath:         strings.TrimSpace(req.Admission.Workload.ModulePath),
			ServiceName:        strings.TrimSpace(req.Admission.Workload.ServiceName),
			TargetPlatform:     strings.TrimSpace(req.Admission.Workload.TargetPlatform),
			Description:        strings.TrimSpace(req.Admission.Workload.Description),
			WorkloadIdentityID: strings.TrimSpace(req.Admission.Workload.WorkloadIdentityID),
		},
	}

	canonical, err := json.Marshal(identity)
	if err != nil {
		return "", err
	}
	return digestBytes(canonical), nil
}

func normalizePolicyDecisions(decisions []PolicyDecision) []PolicyDecision {
	normalized := append([]PolicyDecision(nil), decisions...)
	sort.Slice(normalized, func(i, j int) bool {
		if normalized[i].Rule == normalized[j].Rule {
			return normalized[i].Result < normalized[j].Result
		}
		return normalized[i].Rule < normalized[j].Rule
	})
	return normalized
}

func normalizeStringSet(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	normalized := append([]string(nil), values...)
	for i := range normalized {
		normalized[i] = strings.TrimSpace(normalized[i])
	}
	sort.Strings(normalized)
	return normalized
}

func cloneStringsPreserveShape(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string{}, values...)
}

func toEvidencePolicyDecisions(decisions []PolicyDecision) []evidencev1.PolicyDecision {
	normalized := make([]evidencev1.PolicyDecision, 0, len(decisions))
	for _, decision := range decisions {
		normalized = append(normalized, evidencev1.PolicyDecision{
			Rule:   decision.Rule,
			Result: decision.Result,
		})
	}
	return normalized
}

func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func isLabeledSHA256Digest(value string) bool {
	return labeledSHA256DigestPattern.MatchString(strings.TrimSpace(value))
}
