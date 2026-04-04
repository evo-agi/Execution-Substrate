package api

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"execution-platform/ags/publish"
	"execution-platform/observability"
)

const serviceName = "artifact-governance"

type publishingService interface {
	Health(ctx context.Context) publish.HealthSnapshot
	Publish(ctx context.Context, caller publish.CallerIdentity, req publish.PublishRequest) (publish.PublishResult, *publish.Error)
}

type Server struct {
	service           publishingService
	bootstrapIssuerCN string
	isStarted         func() bool
}

func NewServer(service publishingService, bootstrapIssuerCN string, isStarted func() bool) *Server {
	return &Server{
		service:           service,
		bootstrapIssuerCN: strings.TrimSpace(bootstrapIssuerCN),
		isStarted:         isStarted,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("POST /v1/artifacts:publish", s.handlePublish)
	return observability.WrapHandler(serviceName, mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	_ = r

	started := false
	if s.isStarted != nil {
		started = s.isStarted()
	}

	snapshot := s.service.Health(r.Context())
	ready := started && snapshot.SignerReady && snapshot.ArtifactRegistryHealthy
	status := "unhealthy"
	if ready {
		status = "healthy"
	}

	writeJSON(w, http.StatusOK, HealthResponse{
		Status:  status,
		Ready:   ready,
		Service: serviceName,
		AdditionalProperties: HealthAdditionalProperties{
			Dependencies: HealthDependencies{
				ArtifactRegistry: label(snapshot.ArtifactRegistryHealthy, "healthy", "unhealthy"),
			},
			Readiness: HealthReadiness{
				ServerStarted: label(started, "started", "not_started"),
				Signer:        label(snapshot.SignerReady, "initialized", "missing"),
			},
		},
	})
}

func (s *Server) handlePublish(w http.ResponseWriter, r *http.Request) {
	caller, issuerCommonName, ok := authenticatedCallerIdentity(r)
	if !ok {
		writeText(w, http.StatusUnauthorized, "Authenticated caller identity required")
		return
	}
	if issuerCommonName == s.bootstrapIssuerCN {
		writeText(w, http.StatusForbidden, "Bootstrap PKI callers are not accepted; use a SPIRE-issued identity")
		return
	}
	if caller.Path != "service/deployment" && caller.Path != "operator" {
		writeText(w, http.StatusForbidden, "Caller not authorized for this operation")
		return
	}

	var request publish.PublishRequest
	if err := decodeJSON(r.Body, &request); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{
			Success: false,
			Error:   "invalid request body",
			Code:    "invalid_request",
		})
		return
	}

	result, err := s.service.Publish(r.Context(), caller, request)
	if err != nil {
		writeJSON(w, err.Status, ErrorResponse{
			Success: false,
			Error:   err.Message,
			Code:    err.Code,
		})
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func authenticatedCallerIdentity(r *http.Request) (caller publish.CallerIdentity, issuerCommonName string, ok bool) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return publish.CallerIdentity{}, "", false
	}

	cert := r.TLS.VerifiedChains[0][0]
	if cert == nil {
		return publish.CallerIdentity{}, "", false
	}

	caller, ok = callerIdentityFromCertificate(cert)
	if !ok {
		return publish.CallerIdentity{}, "", false
	}
	return caller, cert.Issuer.CommonName, true
}

func callerIdentityFromCertificate(cert *x509.Certificate) (publish.CallerIdentity, bool) {
	const prefix = "spiffe://execution.internal/"

	for _, uri := range cert.URIs {
		value := uri.String()
		if strings.HasPrefix(value, prefix) {
			return publish.CallerIdentity{
				Path:     strings.TrimPrefix(value, prefix),
				SPIFFEID: value,
			}, true
		}
	}

	return publish.CallerIdentity{}, false
}

func decodeJSON(body io.ReadCloser, target any) error {
	defer body.Close()

	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return err
	}
	return nil
}

func label(ok bool, healthy string, unhealthy string) string {
	if ok {
		return healthy
	}
	return unhealthy
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeText(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}
