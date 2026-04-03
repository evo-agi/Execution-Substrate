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
	signingv2 "execution-platform/contracts/signing/v2"
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
	ArtifactDigest                           string `json:"artifact_digest"`
	ManifestDigest                           string `json:"manifest_digest"`
	ProvenanceDigest                         string `json:"provenance_digest"`
	PayloadDigest                            string `json:"payload_digest"`
	DerivationMetadataDigest                 string `json:"derivation_metadata_digest"`
	DerivationAuthorizationAttestationDigest string `json:"derivation_authorization_attestation_digest"`
	WorkloadIdentityBindingDigest            string `json:"workload_identity_binding_digest"`
}

type dependencyHealthResponse struct {
	Status string `json:"status"`
	Ready  bool   `json:"ready"`
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

	artifactDigest := digestBytes(validation.payloadBytes)

	manifest := Manifest{
		ArtifactDigest:   artifactDigest,
		ArtifactType:     strings.TrimSpace(req.Manifest.ArtifactType),
		IntentDigest:     strings.TrimSpace(req.Manifest.IntentDigest),
		RuntimeInterface: req.Manifest.RuntimeInterface,
	}

	provenance, err := s.buildProvenance(artifactDigest, req.Provenance, validation.invoker)
	if err != nil {
		return PublishResult{}, &Error{Status: http.StatusInternalServerError, Code: codePublishFailed, Message: err.Error()}
	}

	metadata := DerivationMetadata{
		DerivationSpecDigest: strings.TrimSpace(req.DerivationMetadata.DerivationSpecDigest),
		OutputID:             strings.TrimSpace(req.DerivationMetadata.OutputID),
		ProducerRunID:        strings.TrimSpace(req.DerivationMetadata.ProducerRunID),
	}

	attestation, err := s.buildDerivationAttestation(artifactDigest, metadata, req.DerivationAttestation)
	if err != nil {
		return PublishResult{}, &Error{Status: http.StatusInternalServerError, Code: codePublishFailed, Message: err.Error()}
	}

	binding, err := s.buildWorkloadIdentityBinding(artifactDigest, metadata, req.WorkloadIdentityBinding)
	if err != nil {
		return PublishResult{}, &Error{Status: http.StatusInternalServerError, Code: codePublishFailed, Message: err.Error()}
	}

	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return PublishResult{}, &Error{Status: http.StatusInternalServerError, Code: codePublishFailed, Message: "marshal manifest failed"}
	}
	provenanceBytes, err := json.Marshal(provenance)
	if err != nil {
		return PublishResult{}, &Error{Status: http.StatusInternalServerError, Code: codePublishFailed, Message: "marshal provenance failed"}
	}
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return PublishResult{}, &Error{Status: http.StatusInternalServerError, Code: codePublishFailed, Message: "marshal derivation metadata failed"}
	}
	attestationBytes, err := json.Marshal(attestation)
	if err != nil {
		return PublishResult{}, &Error{Status: http.StatusInternalServerError, Code: codePublishFailed, Message: "marshal derivation attestation failed"}
	}
	bindingBytes, err := json.Marshal(binding)
	if err != nil {
		return PublishResult{}, &Error{Status: http.StatusInternalServerError, Code: codePublishFailed, Message: "marshal workload identity binding failed"}
	}

	manifestDigest := digestBytes(manifestBytes)
	provenanceDigest := digestBytes(provenanceBytes)
	payloadDigest := artifactDigest
	metadataDigest := digestBytes(metadataBytes)
	attestationDigest := digestBytes(attestationBytes)
	bindingDigest := digestBytes(bindingBytes)

	uploads := []struct {
		digest string
		data   []byte
	}{
		{digest: payloadDigest, data: validation.payloadBytes},
		{digest: manifestDigest, data: manifestBytes},
		{digest: provenanceDigest, data: provenanceBytes},
		{digest: metadataDigest, data: metadataBytes},
		{digest: attestationDigest, data: attestationBytes},
		{digest: bindingDigest, data: bindingBytes},
	}
	for _, upload := range uploads {
		if err := s.arsClient.putBlob(ctx, upload.digest, upload.data); err != nil {
			return PublishResult{}, &Error{Status: http.StatusServiceUnavailable, Code: codeDependencyError, Message: err.Error()}
		}
	}

	if err := s.arsClient.registerArtifact(ctx, registerArtifactRequest{
		ArtifactDigest:                           artifactDigest,
		ManifestDigest:                           manifestDigest,
		ProvenanceDigest:                         provenanceDigest,
		PayloadDigest:                            payloadDigest,
		DerivationMetadataDigest:                 metadataDigest,
		DerivationAuthorizationAttestationDigest: attestationDigest,
		WorkloadIdentityBindingDigest:            bindingDigest,
	}); err != nil {
		return PublishResult{}, &Error{Status: http.StatusServiceUnavailable, Code: codeDependencyError, Message: err.Error()}
	}

	return PublishResult{
		Published:                                true,
		ArtifactDigest:                           artifactDigest,
		ManifestDigest:                           manifestDigest,
		ProvenanceDigest:                         provenanceDigest,
		PayloadDigest:                            payloadDigest,
		DerivationMetadataDigest:                 metadataDigest,
		DerivationAuthorizationAttestationDigest: attestationDigest,
		WorkloadIdentityBindingDigest:            bindingDigest,
	}, nil
}

func (s *Service) buildProvenance(artifactDigest string, input ProvenanceInput, invoker InvokerInfo) (Provenance, error) {
	provenance := Provenance{
		Payload: signingv2.ProvenancePayload{
			Kind: signingv2.KindProvenance,
			Subject: signingv2.ProvenanceSubject{
				ArtifactDigest: artifactDigest,
			},
			Claims: signingv2.ProvenanceClaims{
				BuilderService: builderServiceName,
				Invoker: signingv2.ProvenanceInvoker{
					Service:   invoker.Service,
					Principal: invoker.Principal,
				},
				PolicyDecisions: toSigningPolicyDecisions(normalizePolicyDecisions(input.PolicyDecisions)),
				BuildLogDigest:  strings.TrimSpace(input.BuildLogDigest),
			},
		},
	}

	canonical, err := signingv2.CanonicalProvenancePayload(provenance.Payload)
	if err != nil {
		return Provenance{}, err
	}
	signature, err := s.signer.SignDetached(canonical)
	if err != nil {
		return Provenance{}, err
	}
	provenance.Signature = signingv2.NewEnvelope(canonical, s.signer.KeyID(), s.signer.Algorithm(), signature)
	return provenance, nil
}

func (s *Service) buildDerivationAttestation(artifactDigest string, metadata DerivationMetadata, input DerivationAttestationInput) (DerivationAttestation, error) {
	attestation := DerivationAttestation{
		Payload: signingv2.DerivationAttestationPayload{
			Kind: signingv2.KindDerivationAttestation,
			Subject: signingv2.DerivationSubject{
				ArtifactDigest:       artifactDigest,
				DerivationSpecDigest: metadata.DerivationSpecDigest,
				OutputID:             metadata.OutputID,
			},
			Claims: signingv2.DerivationAttestationClaims{
				Constraints: signingv2.DerivationConstraints{
					AllowedToolchains:      cloneStringsPreserveShape(input.Constraints.AllowedToolchains),
					ForbiddenToolchains:    cloneStringsPreserveShape(input.Constraints.ForbiddenToolchains),
					OS:                     input.Constraints.OS,
					Arch:                   input.Constraints.Arch,
					NetworkAccess:          input.Constraints.NetworkAccess,
					WritablePaths:          cloneStringsPreserveShape(input.Constraints.WritablePaths),
					ForbiddenPaths:         cloneStringsPreserveShape(input.Constraints.ForbiddenPaths),
					DeterminismExpectation: input.Constraints.DeterminismExpectation,
				},
				Policy: signingv2.DerivationPolicy{
					Version:              strings.TrimSpace(input.PolicyVersion),
					ExpectedArtifactType: strings.TrimSpace(input.ExpectedArtifactType),
				},
			},
		},
	}

	canonical, err := signingv2.CanonicalDerivationAttestationPayload(attestation.Payload)
	if err != nil {
		return DerivationAttestation{}, err
	}
	signature, err := s.signer.SignDetached(canonical)
	if err != nil {
		return DerivationAttestation{}, err
	}
	attestation.Signature = signingv2.NewEnvelope(canonical, s.signer.KeyID(), s.signer.Algorithm(), signature)
	return attestation, nil
}

func (s *Service) buildWorkloadIdentityBinding(artifactDigest string, metadata DerivationMetadata, input WorkloadIdentityBindingInput) (WorkloadIdentityBinding, error) {
	binding := WorkloadIdentityBinding{
		Payload: signingv2.WorkloadIdentityBindingPayload{
			Kind: signingv2.KindWorkloadIdentityBinding,
			Subject: signingv2.WorkloadIdentitySubject{
				ArtifactClass:        strings.TrimSpace(input.ArtifactClass),
				ArtifactDigest:       artifactDigest,
				DerivationSpecDigest: metadata.DerivationSpecDigest,
				OutputID:             metadata.OutputID,
			},
			Claims: signingv2.WorkloadIdentityBindingClaims{
				Descriptor: signingv2.WorkloadDescriptor{
					WorkloadType:       strings.TrimSpace(input.WorkloadType),
					ModulePath:         strings.TrimSpace(input.ModulePath),
					ServiceName:        strings.TrimSpace(input.ServiceName),
					TargetPlatform:     strings.TrimSpace(input.TargetPlatform),
					Description:        strings.TrimSpace(input.Description),
					WorkloadIdentityID: strings.TrimSpace(input.WorkloadIdentityID),
				},
				Policy: signingv2.WorkloadPolicy{
					Version: strings.TrimSpace(input.PolicyVersion),
				},
			},
		},
	}

	canonical, err := signingv2.CanonicalWorkloadIdentityBindingPayload(binding.Payload)
	if err != nil {
		return WorkloadIdentityBinding{}, err
	}
	signature, err := s.signer.SignDetached(canonical)
	if err != nil {
		return WorkloadIdentityBinding{}, err
	}
	binding.Signature = signingv2.NewEnvelope(canonical, s.signer.KeyID(), s.signer.Algorithm(), signature)
	return binding, nil
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
	if strings.TrimSpace(req.Manifest.ArtifactType) == "" {
		return publishValidation{}, &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "manifest.artifact_type is required"}
	}
	if !isLabeledSHA256Digest(req.Manifest.IntentDigest) {
		return publishValidation{}, &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "manifest.intent_digest must be a labeled sha256 digest"}
	}
	if strings.TrimSpace(req.Provenance.Invoker.Service) == "" {
		return publishValidation{}, &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "provenance.invoker.service is required"}
	}
	if strings.TrimSpace(req.Provenance.Invoker.Principal) == "" {
		return publishValidation{}, &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "provenance.invoker.principal is required"}
	}
	if !isLabeledSHA256Digest(req.Provenance.BuildLogDigest) {
		return publishValidation{}, &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "provenance.build_log_digest must be a labeled sha256 digest"}
	}
	if !isLabeledSHA256Digest(req.DerivationMetadata.DerivationSpecDigest) {
		return publishValidation{}, &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "derivation_metadata.derivation_spec_digest must be a labeled sha256 digest"}
	}
	if strings.TrimSpace(req.DerivationMetadata.OutputID) == "" {
		return publishValidation{}, &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "derivation_metadata.output_id is required"}
	}
	if strings.TrimSpace(req.DerivationMetadata.ProducerRunID) == "" {
		return publishValidation{}, &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "derivation_metadata.producer_run_id is required"}
	}
	if strings.TrimSpace(req.DerivationAttestation.PolicyVersion) == "" {
		return publishValidation{}, &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "derivation_attestation.policy_version is required"}
	}
	if strings.TrimSpace(req.WorkloadIdentityBinding.ArtifactClass) == "" {
		return publishValidation{}, &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "workload_identity_binding.artifact_class is required"}
	}
	if strings.TrimSpace(req.WorkloadIdentityBinding.WorkloadType) == "" {
		return publishValidation{}, &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "workload_identity_binding.workload_type is required"}
	}
	if strings.TrimSpace(req.WorkloadIdentityBinding.ModulePath) == "" {
		return publishValidation{}, &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "workload_identity_binding.module_path is required"}
	}
	if strings.TrimSpace(req.WorkloadIdentityBinding.PolicyVersion) == "" {
		return publishValidation{}, &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "workload_identity_binding.policy_version is required"}
	}
	if strings.TrimSpace(req.WorkloadIdentityBinding.WorkloadIdentityID) == "" {
		return publishValidation{}, &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "workload_identity_binding.workload_identity_id is required"}
	}
	if strings.TrimSpace(req.Provenance.Invoker.Service) != invoker.Service {
		return publishValidation{}, &Error{Status: http.StatusForbidden, Code: codePublishForbidden, Message: "provenance.invoker.service does not match authenticated caller"}
	}
	if strings.TrimSpace(req.Provenance.Invoker.Principal) != invoker.Principal {
		return publishValidation{}, &Error{Status: http.StatusForbidden, Code: codePublishForbidden, Message: "provenance.invoker.principal does not match authenticated caller"}
	}
	workloadIdentityID := strings.TrimSpace(req.WorkloadIdentityBinding.WorkloadIdentityID)
	if !isValidSPIFFEURI(workloadIdentityID) {
		return publishValidation{}, &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "workload_identity_binding.workload_identity_id must be a valid SPIFFE URI"}
	}
	serviceName := strings.TrimSpace(req.WorkloadIdentityBinding.ServiceName)
	if strings.TrimSpace(req.WorkloadIdentityBinding.WorkloadType) == "service" && serviceName == "" {
		return publishValidation{}, &Error{Status: http.StatusConflict, Code: codeArtifactConflict, Message: "workload_identity_binding.service_name is required for service workloads"}
	}
	if strings.TrimSpace(req.DerivationAttestation.PolicyVersion) != strings.TrimSpace(req.WorkloadIdentityBinding.PolicyVersion) {
		return publishValidation{}, &Error{Status: http.StatusConflict, Code: codeArtifactConflict, Message: "derivation_attestation.policy_version must match workload_identity_binding.policy_version"}
	}
	expectedArtifactType := strings.TrimSpace(req.DerivationAttestation.ExpectedArtifactType)
	if expectedArtifactType != "" && expectedArtifactType != strings.TrimSpace(req.Manifest.ArtifactType) {
		return publishValidation{}, &Error{Status: http.StatusConflict, Code: codeArtifactConflict, Message: "derivation_attestation.expected_artifact_type must match manifest.artifact_type"}
	}
	if serviceName != "" {
		derivedServiceName, ok := spiffeServiceName(workloadIdentityID)
		if !ok || derivedServiceName != serviceName {
			return publishValidation{}, &Error{Status: http.StatusConflict, Code: codeArtifactConflict, Message: "workload_identity_binding.service_name conflicts with workload_identity_binding.workload_identity_id"}
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
		return fmt.Errorf("register artifact %s: %w", requestBody.ArtifactDigest, err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		return fmt.Errorf("register artifact %s: unexpected status %d body=%s", requestBody.ArtifactDigest, response.StatusCode, strings.TrimSpace(string(body)))
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

func cloneStringsPreserveShape(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string{}, values...)
}

func toSigningPolicyDecisions(decisions []PolicyDecision) []signingv2.PolicyDecision {
	normalized := make([]signingv2.PolicyDecision, 0, len(decisions))
	for _, decision := range decisions {
		normalized = append(normalized, signingv2.PolicyDecision{
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
