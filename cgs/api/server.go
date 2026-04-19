package api

import (
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"strings"

	"execution-substrate/cgs/policy"
	"execution-substrate/internal/httpx"
	"execution-substrate/internal/observability"
)

const serviceName = "credential-governance"

type Server struct {
	policies          *policy.Set
	bootstrapIssuerCN string
}

func NewServer(policies *policy.Set, bootstrapIssuerCN string) *Server {
	return &Server{
		policies:          policies,
		bootstrapIssuerCN: strings.TrimSpace(bootstrapIssuerCN),
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/credential/authorize", s.handleAuthorize)
	return observability.WrapHandler(serviceName, mux)
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
		httpx.WriteJSON(w, http.StatusBadRequest, ErrorResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	if err := validateRequestShape(request); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, ErrorResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	workload := policy.Workload{
		Type:               request.Workload.Type,
		WorkloadIdentityID: request.Workload.WorkloadIdentityID,
	}
	if err := s.policies.ValidateWorkload(workload); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, ErrorResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	if callerIdentity != request.Workload.WorkloadIdentityID {
		writeText(w, http.StatusForbidden, "Authenticated caller does not match requested workload principal")
		return
	}
	callerSubjectType, callerSubjectID, ok := policy.SubjectFromSPIFFEID(callerIdentity)
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

	evaluation := s.policies.Evaluate(decisionID, workload)

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
	}

	if !evaluation.Allowed {
		response.Reason = &ReasonResponse{
			Code:    evaluation.Reason.Code,
			Message: evaluation.Reason.Message,
		}
		httpx.WriteJSON(w, http.StatusOK, response)
		return
	}

	response.Decision = &AuthorizationDecision{Role: evaluation.Role}
	if evaluation.Constraints != nil {
		response.Decision.Constraints = &AuthorizationConstraints{
			ForbiddenStages: append([]string(nil), evaluation.Constraints.ForbiddenStages...),
			ExpiresAt:       evaluation.Constraints.ExpiresAt,
		}
	}

	httpx.WriteJSON(w, http.StatusOK, response)
}

func validateRequestShape(request AuthorizeRequest) error {
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
	return nil
}

func decodeJSONBody(reader io.ReadCloser, target any) error {
	if err := httpx.DecodeStrictJSONAndClose(reader, target); err != nil {
		if err == io.EOF {
			return fmt.Errorf("request body is required")
		}
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

func writeText(w http.ResponseWriter, status int, value string) {
	httpx.WriteText(w, status, value)
}
