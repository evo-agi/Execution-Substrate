package api

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"execution-platform/cgs/config"
	"execution-platform/cgs/policy"
	"execution-platform/cgs/proof"
)

const serviceName = "credential-governance"

type Server struct {
	policies            *policy.Set
	vaultRuntime        config.VaultRuntimeConfig
	bootstrapIssuerCN   string
	proofMinter         proof.Minter
	policyDigest        string
	workloadVaultDigest string
	workloadVaultSource string
}

func NewServer(
	policies *policy.Set,
	vaultRuntime config.VaultRuntimeConfig,
	bootstrapIssuerCN string,
	proofMinter proof.Minter,
	policyDigest string,
	workloadVaultDigest string,
	workloadVaultSource string,
) *Server {
	return &Server{
		policies:            policies,
		vaultRuntime:        vaultRuntime,
		bootstrapIssuerCN:   strings.TrimSpace(bootstrapIssuerCN),
		proofMinter:         proofMinter,
		policyDigest:        policyDigest,
		workloadVaultDigest: workloadVaultDigest,
		workloadVaultSource: workloadVaultSource,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/credential/authorize", s.handleAuthorize)
	return mux
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	callerIdentity, issuerCommonName, ok := authenticatedCallerIdentity(r)
	if !ok {
		writeText(w, http.StatusUnauthorized, "Authenticated caller identity required")
		return
	}
	if s.bootstrapIssuerCN != "" && issuerCommonName == s.bootstrapIssuerCN {
		writeText(w, http.StatusForbidden, "Bootstrap PKI callers are not accepted; use a SPIRE-issued identity")
		return
	}

	var request AuthorizeRequest
	if err := decodeJSONBody(r.Body, &request); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	if err := validateRequestShape(request); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	workload := policy.Workload{
		Type:               request.Workload.Type,
		ServiceName:        request.Workload.ServiceName,
		WorkloadIdentityID: request.Workload.WorkloadIdentityID,
		ModulePath:         request.Workload.ModulePath,
		FilePath:           request.Workload.FilePath,
		TargetPlatform:     request.Workload.TargetPlatform,
		Description:        request.Workload.Description,
		Ephemeral:          request.Workload.Ephemeral,
	}
	if err := s.policies.ValidateWorkload(workload); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	if callerIdentity != request.Workload.WorkloadIdentityID {
		writeText(w, http.StatusForbidden, "Authenticated caller does not match requested workload principal")
		return
	}
	callerSubjectType, callerSubjectID, ok := subjectFromSPIFFEID(callerIdentity)
	if !ok {
		writeText(w, http.StatusForbidden, "Authenticated caller does not match requested workload principal")
		return
	}
	derivedSubjectType, derivedSubjectID, ok := s.policies.SubjectFromWorkload(workload)
	if ok && (derivedSubjectType != callerSubjectType || derivedSubjectID != callerSubjectID) {
		writeText(w, http.StatusForbidden, "Authenticated caller does not match workload descriptor subject")
		return
	}

	requestID := newID("req")
	decisionID := newID("dec")

	// requested_by is accepted for wire compatibility, but CGS v1 does not trust
	// it as an authorization input. The authenticated SPIFFE caller and local
	// policy determine the decision boundary for this slice.
	evaluation := s.policies.Evaluate(decisionID, policy.RequestedBy{
		Component: request.RequestedBy.Component,
		Platform:  request.RequestedBy.Platform,
		User:      request.RequestedBy.User,
	}, workload)

	response := AuthorizeResponse{
		Allowed:    evaluation.Allowed,
		RequestID:  requestID,
		DecisionID: decisionID,
		Audit: AuthorizationAudit{
			DecisionID:     evaluation.Audit.DecisionID,
			Reasons:        evaluation.Audit.Reasons,
			PolicyVersion:  evaluation.Audit.PolicyVersion,
			EvaluatedRules: evaluation.Audit.EvaluatedRules,
		},
		CredentialPolicyDigest: s.policyDigest,
		WorkloadVaultDigest:    s.workloadVaultDigest,
		WorkloadVaultSource:    s.workloadVaultSource,
	}

	if !evaluation.Allowed {
		response.Reason = &ReasonResponse{
			Code:    evaluation.Reason.Code,
			Message: evaluation.Reason.Message,
		}
		writeJSON(w, http.StatusOK, response)
		return
	}

	mintedProof, err := s.proofMinter.MintRecordProof(proof.Input{
		DecisionID:         decisionID,
		CallerIdentityID:   callerIdentity,
		WorkloadIdentityID: request.Workload.WorkloadIdentityID,
		RunID:              contextString(request.Context, "run_id"),
		AllocationID:       firstContextString(request.Context, "allocation_id", "alloc_id", "nomad_allocation_id", "nomad_alloc_id"),
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{
			Success: false,
			Error:   "failed to mint record proof",
		})
		return
	}

	response.Credential = &AuthorizedCredential{
		Role:       evaluation.Role,
		AuthMethod: "spiffe",
		AuthPlan: VaultAuthPlan{
			WorkloadIdentityID: request.Workload.WorkloadIdentityID,
			VaultAddress:       s.vaultRuntime.Address,
			AuthMount:          s.vaultRuntime.AuthMount,
			AuthRole:           s.vaultRuntime.AuthRole,
			JWTAudience:        s.vaultRuntime.JWTAudience,
		},
		TokenConstraints: TokenConstraints{
			TTLSeconds: 900,
			Renewable:  true,
		},
	}
	if evaluation.Constraints != nil {
		response.Constraints = &CredentialConstraints{
			ForbiddenStages: append([]string(nil), evaluation.Constraints.ForbiddenStages...),
			ExpiresAt:       evaluation.Constraints.ExpiresAt,
		}
	}
	response.RecordProof = mintedProof.Token
	response.RecordProofExpiresAt = &mintedProof.ExpiresAt

	writeJSON(w, http.StatusOK, response)
}

func validateRequestShape(request AuthorizeRequest) error {
	if strings.TrimSpace(request.RequestedBy.Component) == "" {
		return fmt.Errorf("requested_by.component is required")
	}
	if strings.TrimSpace(request.RequestedBy.Platform) == "" {
		return fmt.Errorf("requested_by.platform is required")
	}
	if strings.TrimSpace(request.RequestedBy.User) == "" {
		return fmt.Errorf("requested_by.user is required")
	}
	if strings.TrimSpace(request.Workload.WorkloadIdentityID) == "" {
		return fmt.Errorf("workload.workload_identity_id is required")
	}
	for _, capability := range request.RequestedCapabilities {
		if strings.TrimSpace(capability) == "" {
			return fmt.Errorf("requested_capabilities cannot contain empty values")
		}
		if capability != "vault:read" {
			return fmt.Errorf("requested_capabilities contains unsupported capability: %s", capability)
		}
	}
	if request.Context == nil {
		return fmt.Errorf("context must be an object")
	}
	return nil
}

func decodeJSONBody(reader io.ReadCloser, target any) error {
	defer reader.Close()

	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		if err == io.EOF {
			return fmt.Errorf("request body is required")
		}
		return fmt.Errorf("malformed JSON request body")
	}

	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("malformed JSON request body")
	}

	return nil
}

func authenticatedCallerIdentity(r *http.Request) (identityID string, issuerCommonName string, ok bool) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return "", "", false
	}

	cert := r.TLS.VerifiedChains[0][0]
	if cert == nil {
		return "", "", false
	}

	identityID, ok = spiffeIdentityFromCertificate(cert)
	if !ok {
		return "", "", false
	}

	return identityID, cert.Issuer.CommonName, true
}

func spiffeIdentityFromCertificate(cert *x509.Certificate) (string, bool) {
	for _, uri := range cert.URIs {
		if uri != nil && uri.Scheme == "spiffe" && uri.Host != "" {
			return uri.String(), true
		}
	}
	return "", false
}

func subjectFromSPIFFEID(identityID string) (string, string, bool) {
	parsed, err := url.Parse(identityID)
	if err != nil || parsed.Scheme != "spiffe" || parsed.Host == "" {
		return "", "", false
	}

	segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(segments) != 2 {
		return "", "", false
	}
	if segments[0] != "service" && segments[0] != "script" {
		return "", "", false
	}
	if strings.TrimSpace(segments[1]) == "" {
		return "", "", false
	}

	return segments[0], segments[1], true
}

func contextString(context map[string]any, key string) string {
	if context == nil {
		return ""
	}
	value, ok := context[key]
	if !ok {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	return ""
}

func firstContextString(context map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := contextString(context, key); value != "" {
			return value
		}
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeText(w http.ResponseWriter, status int, value string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, value)
}
