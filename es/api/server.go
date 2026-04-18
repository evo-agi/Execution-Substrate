package api

import (
	"context"
	"crypto/x509"
	"net/http"
	"strconv"
	"strings"

	"execution-substrate/es/admission"
	"execution-substrate/internal/httpx"
	"execution-substrate/internal/observability"
)

const serviceName = "execution"

type preparationService interface {
	Health(ctx context.Context) admission.HealthSnapshot
	Prepare(ctx context.Context, req admission.PrepareRequest) (admission.PrepareResult, *admission.Error)
	Submit(ctx context.Context, req admission.PrepareRequest) (admission.SubmitResult, *admission.Error)
	Status(ctx context.Context, runID string) (admission.ExecutionStatusResult, *admission.Error)
	Logs(ctx context.Context, runID string) (admission.ExecutionLogsResult, *admission.Error)
	Result(ctx context.Context, runID string) (admission.ExecutionResultBundle, *admission.Error)
	Cancel(ctx context.Context, runID string) (admission.ExecutionCancelResult, *admission.Error)
}

const (
	headerOutcomeSource             = "Execution-Substrate-Outcome-Source"
	headerOutcomeObservation        = "Execution-Substrate-Outcome-Observation"
	headerOutcomeAccessClass        = "Execution-Substrate-Outcome-Access-Class"
	headerProviderTerminalObserved  = "Execution-Substrate-Provider-Terminal-Observed"
	headerLifecycleProjectionSource = "Execution-Substrate-Lifecycle-Projection-Source"
	headerLifecycleProjectionRev    = "Execution-Substrate-Lifecycle-Projection-Revision"
)

type Server struct {
	service             preparationService
	bootstrapIssuerCN   string
	allowedPathPrefixes []string
	isStarted           func() bool
}

func NewServer(service preparationService, bootstrapIssuerCN string, allowedPathPrefixes []string, isStarted func() bool) *Server {
	return &Server{
		service:             service,
		bootstrapIssuerCN:   strings.TrimSpace(bootstrapIssuerCN),
		allowedPathPrefixes: append([]string(nil), allowedPathPrefixes...),
		isStarted:           isStarted,
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

	httpx.WriteJSON(w, http.StatusOK, HealthResponse{
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
		httpx.WriteJSON(w, err.Status, admission.ErrorResponse{
			Success: false,
			Error:   err.Message,
			Code:    err.Code,
		})
		return
	}

	httpx.WriteJSON(w, http.StatusOK, result)
}

func (s *Server) handleSubmit(w http.ResponseWriter, r *http.Request) {
	request, ok := s.decodeAuthorizedExecutionRequest(w, r)
	if !ok {
		return
	}

	result, err := s.service.Submit(r.Context(), request)
	if err != nil {
		httpx.WriteJSON(w, err.Status, admission.ErrorResponse{
			Success: false,
			Error:   err.Message,
			Code:    err.Code,
		})
		return
	}

	httpx.WriteJSON(w, http.StatusAccepted, result)
}

func (s *Server) handleLifecycleGet(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeExecutionCaller(w, r) {
		return
	}

	runID, action, ok := parseLifecycleRequest(r.URL.Path)
	if !ok || (action != "status" && action != "logs" && action != "result") {
		http.NotFound(w, r)
		return
	}

	switch action {
	case "status":
		result, err := s.service.Status(r.Context(), runID)
		if err != nil {
			httpx.WriteJSON(w, err.Status, admission.ErrorResponse{
				Success: false,
				Error:   err.Message,
				Code:    err.Code,
			})
			return
		}
		httpx.WriteJSON(w, http.StatusOK, result)
	case "logs":
		result, err := s.service.Logs(r.Context(), runID)
		if err != nil {
			httpx.WriteJSON(w, err.Status, admission.ErrorResponse{
				Success: false,
				Error:   err.Message,
				Code:    err.Code,
			})
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writeOutcomeEvidenceHeaders(w.Header(), result.OutcomeEvidence)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(result.Payload)
	case "result":
		bundle, err := s.service.Result(r.Context(), runID)
		if err != nil {
			httpx.WriteJSON(w, err.Status, admission.ErrorResponse{
				Success: false,
				Error:   err.Message,
				Code:    err.Code,
			})
			return
		}
		w.Header().Set("Content-Type", bundle.MediaType)
		writeOutcomeEvidenceHeaders(w.Header(), bundle.OutcomeEvidence)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bundle.Payload)
	}
}

func writeOutcomeEvidenceHeaders(header http.Header, evidence admission.ExecutionOutcomeEvidence) {
	if strings.TrimSpace(evidence.Source) != "" {
		header.Set(headerOutcomeSource, evidence.Source)
	}
	if strings.TrimSpace(evidence.Observation) != "" {
		header.Set(headerOutcomeObservation, evidence.Observation)
	}
	if strings.TrimSpace(evidence.AccessClass) != "" {
		header.Set(headerOutcomeAccessClass, evidence.AccessClass)
	}
	if evidence.ProviderTerminalObserved != nil {
		header.Set(headerProviderTerminalObserved, strconv.FormatBool(*evidence.ProviderTerminalObserved))
	}
	if evidence.LifecycleProjection != nil {
		if strings.TrimSpace(evidence.LifecycleProjection.Source) != "" {
			header.Set(headerLifecycleProjectionSource, evidence.LifecycleProjection.Source)
		}
		if strings.TrimSpace(evidence.LifecycleProjection.Revision) != "" {
			header.Set(headerLifecycleProjectionRev, evidence.LifecycleProjection.Revision)
		}
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
		httpx.WriteJSON(w, err.Status, admission.ErrorResponse{
			Success: false,
			Error:   err.Message,
			Code:    err.Code,
		})
		return
	}

	httpx.WriteJSON(w, http.StatusOK, result)
}

func (s *Server) decodeAuthorizedExecutionRequest(w http.ResponseWriter, r *http.Request) (admission.PrepareRequest, bool) {
	if !s.authorizeExecutionCaller(w, r) {
		return admission.PrepareRequest{}, false
	}

	var request admission.PrepareRequest
	if err := httpx.DecodeStrictJSONAndClose(r.Body, &request); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, admission.ErrorResponse{
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
		httpx.WriteText(w, http.StatusUnauthorized, "Authenticated caller identity required")
		return false
	}
	if issuerCommonName == s.bootstrapIssuerCN {
		httpx.WriteText(w, http.StatusForbidden, "Bootstrap PKI callers are not accepted; use a SPIRE-issued identity")
		return false
	}
	authorized := false
	for _, prefix := range s.allowedPathPrefixes {
		if matchesAuthorizedPathPrefix(callerPath, prefix) {
			authorized = true
			break
		}
	}
	if !authorized {
		httpx.WriteText(w, http.StatusForbidden, "Caller not authorized for this operation")
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
	case strings.HasSuffix(trimmed, "/result"):
		runID = strings.TrimSuffix(trimmed, "/result")
		action = "result"
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

func matchesAuthorizedPathPrefix(path string, prefix string) bool {
	normalizedPath := strings.Trim(path, "/")
	normalizedPrefix := strings.Trim(prefix, "/")

	if normalizedPath == "" || normalizedPrefix == "" {
		return false
	}

	return normalizedPath == normalizedPrefix || strings.HasPrefix(normalizedPath, normalizedPrefix+"/")
}

func label(ok bool, healthy string, unhealthy string) string {
	if ok {
		return healthy
	}
	return unhealthy
}
