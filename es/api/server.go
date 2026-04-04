package api

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"execution-platform/es/admission"
	"execution-platform/observability"
)

const serviceName = "execution"

type preparationService interface {
	Health(ctx context.Context) admission.HealthSnapshot
	Prepare(ctx context.Context, req admission.PrepareRequest) (admission.PrepareResult, *admission.Error)
	Submit(ctx context.Context, req admission.PrepareRequest) (admission.SubmitResult, *admission.Error)
	Status(ctx context.Context, runID string) (admission.ExecutionStatusResult, *admission.Error)
	Logs(ctx context.Context, runID string) ([]byte, *admission.Error)
	Cancel(ctx context.Context, runID string) (admission.ExecutionCancelResult, *admission.Error)
}

type Server struct {
	service           preparationService
	bootstrapIssuerCN string
	isStarted         func() bool
}

func NewServer(service preparationService, bootstrapIssuerCN string, isStarted func() bool) *Server {
	return &Server{
		service:           service,
		bootstrapIssuerCN: strings.TrimSpace(bootstrapIssuerCN),
		isStarted:         isStarted,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	// TODO: /v1/executions:prepare is a bounded milestone surface for the
	// 		 admission/preparation slice. It is not yet a permanent long-term public
	// 		 execution API and must not accumulate run IDs, scheduler metadata, or
	// 		 proto-execution state.
	mux.HandleFunc("POST /v1/executions:prepare", s.handlePrepare)

	// TODO: /v1/executions:submit is the minimal real execution surface for the
	// 		 first Nomad/Docker slice. It is intentionally async-only and returns a
	// 		 bounded submission receipt, not a durable execution lifecycle API.
	mux.HandleFunc("POST /v1/executions:submit", s.handleSubmit)

	mux.HandleFunc("GET /v1/executions/", s.handleLifecycleGet)
	mux.HandleFunc("POST /v1/executions/", s.handleLifecyclePost)
	return observability.WrapHandler(serviceName, mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	started := false
	if s.isStarted != nil {
		started = s.isStarted()
	}

	snapshot := s.service.Health(r.Context())
	ready := started && snapshot.TrustModelLoaded && snapshot.ArtifactRegistryHealthy
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
				TrustModel:    label(snapshot.TrustModelLoaded, "loaded", "missing"),
			},
		},
	})
}

func (s *Server) handlePrepare(w http.ResponseWriter, r *http.Request) {
	request, ok := s.decodeAuthorizedExecutionRequest(w, r)
	if !ok {
		return
	}

	result, err := s.service.Prepare(r.Context(), request)
	if err != nil {
		writeJSON(w, err.Status, admission.ErrorResponse{
			Success: false,
			Error:   err.Message,
			Code:    err.Code,
		})
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleSubmit(w http.ResponseWriter, r *http.Request) {
	request, ok := s.decodeAuthorizedExecutionRequest(w, r)
	if !ok {
		return
	}

	result, err := s.service.Submit(r.Context(), request)
	if err != nil {
		writeJSON(w, err.Status, admission.ErrorResponse{
			Success: false,
			Error:   err.Message,
			Code:    err.Code,
		})
		return
	}

	writeJSON(w, http.StatusAccepted, result)
}

func (s *Server) handleLifecycleGet(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeExecutionCaller(w, r) {
		return
	}

	runID, action, ok := parseLifecycleRequest(r.URL.Path)
	if !ok || (action != "status" && action != "logs") {
		http.NotFound(w, r)
		return
	}

	switch action {
		case "status":
			result, err := s.service.Status(r.Context(), runID)
			if err != nil {
				writeJSON(w, err.Status, admission.ErrorResponse{
					Success: false,
					Error:   err.Message,
					Code:    err.Code,
				})
				return
			}
			writeJSON(w, http.StatusOK, result)
		case "logs":
			payload, err := s.service.Logs(r.Context(), runID)
			if err != nil {
				writeJSON(w, err.Status, admission.ErrorResponse{
					Success: false,
					Error:   err.Message,
					Code:    err.Code,
				})
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(payload)
	}
}

func (s *Server) handleLifecyclePost(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeExecutionCaller(w, r) {
		return
	}

	runID, action, ok := parseLifecycleRequest(r.URL.Path)
	if !ok || action != "cancel" {
		http.NotFound(w, r)
		return
	}

	result, err := s.service.Cancel(r.Context(), runID)
	if err != nil {
		writeJSON(w, err.Status, admission.ErrorResponse{
			Success: false,
			Error:   err.Message,
			Code:    err.Code,
		})
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func (s *Server) decodeAuthorizedExecutionRequest(w http.ResponseWriter, r *http.Request) (admission.PrepareRequest, bool) {
	if !s.authorizeExecutionCaller(w, r) {
		return admission.PrepareRequest{}, false
	}

	var request admission.PrepareRequest
	if err := decodeJSON(r.Body, &request); err != nil {
		writeJSON(w, http.StatusBadRequest, admission.ErrorResponse{
			Success: false,
			Error:   "invalid request body",
			Code:    "invalid_request",
		})
		return admission.PrepareRequest{}, false
	}
	return request, true
}

func (s *Server) authorizeExecutionCaller(w http.ResponseWriter, r *http.Request) bool {
	callerPath, issuerCommonName, ok := authenticatedCallerIdentity(r)
	if !ok {
		writeText(w, http.StatusUnauthorized, "Authenticated caller identity required")
		return false
	}
	if issuerCommonName == s.bootstrapIssuerCN {
		writeText(w, http.StatusForbidden, "Bootstrap PKI callers are not accepted; use a SPIRE-issued identity")
		return false
	}
	if callerPath != "service/deployment" && callerPath != "operator" {
		writeText(w, http.StatusForbidden, "Caller not authorized for this operation")
		return false
	}
	return true
}

func parseLifecycleRequest(requestPath string) (runID string, action string, ok bool) {
	const prefix = "/v1/executions/"
	if !strings.HasPrefix(requestPath, prefix) {
		return "", "", false
	}

	trimmed := strings.TrimPrefix(requestPath, prefix)
	switch {
		case strings.HasSuffix(trimmed, "/status"):
			runID = strings.TrimSuffix(trimmed, "/status")
			action = "status"
		case strings.HasSuffix(trimmed, "/logs"):
			runID = strings.TrimSuffix(trimmed, "/logs")
			action = "logs"
		case strings.HasSuffix(trimmed, ":cancel"):
			runID = strings.TrimSuffix(trimmed, ":cancel")
			action = "cancel"
		default:
			return "", "", false
	}

	if runID == "" || strings.Contains(runID, "/") {
		return "", "", false
	}
	return runID, action, true
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
	const prefix = "spiffe://execution.internal/"

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
