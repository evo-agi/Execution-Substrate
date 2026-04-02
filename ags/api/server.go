package api

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"execution-platform/ags/publish"
)

const serviceName = "artifact-governance"

type publishingService interface {
	Health(ctx context.Context) publish.HealthSnapshot
	Publish(ctx context.Context, req publish.PublishRequest) (publish.PublishResult, *publish.Error)
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
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	_ = r

	started := false
	if s.isStarted != nil {
		started = s.isStarted()
	}

	snapshot := s.service.Health(context.Background())
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
	callerPath, issuerCommonName, ok := authenticatedCallerIdentity(r)
	if !ok {
		writeText(w, http.StatusUnauthorized, "Authenticated caller identity required")
		return
	}
	if issuerCommonName == s.bootstrapIssuerCN {
		writeText(w, http.StatusForbidden, "Bootstrap PKI callers are not accepted; use a SPIRE-issued identity")
		return
	}
	if callerPath != "service/deployment" && callerPath != "operator" {
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

	result, err := s.service.Publish(r.Context(), request)
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

func authenticatedCallerIdentity(r *http.Request) (callerPath string, issuerCommonName string, ok bool) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return "", "", false
	}

	cert := r.TLS.VerifiedChains[0][0]
	if cert == nil {
		return "", "", false
	}

	callerPath, ok = spiffePathFromCertificate(cert)
	if !ok {
		return "", "", false
	}
	return callerPath, cert.Issuer.CommonName, true
}

func spiffePathFromCertificate(cert *x509.Certificate) (string, bool) {
	// TODO: Do not mention "monolith" or "internal"
	const prefix = "spiffe://monolith.internal/"

	for _, uri := range cert.URIs {
		value := uri.String()
		if strings.HasPrefix(value, prefix) {
			return strings.TrimPrefix(value, prefix), true
		}
	}

	return "", false
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
