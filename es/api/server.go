package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"execution-substrate/es/admission"
	"execution-substrate/internal/callerallowlist"
	"execution-substrate/internal/callerauth"
	"execution-substrate/internal/httpx"
	"execution-substrate/internal/observability"
)

const serviceName = "execution"

type preparationService interface {
	Health(ctx context.Context) admission.HealthSnapshot
	ProducerContract(ctx context.Context) admission.ProducerContractDeclaration
	Prepare(ctx context.Context, req admission.PrepareRequest) (admission.PrepareResult, *admission.Error)
	Submit(ctx context.Context, req admission.PrepareRequest) (admission.SubmitResult, *admission.Error)
	Status(ctx context.Context, runID string) (admission.ExecutionStatusResult, *admission.Error)
	Logs(ctx context.Context, runID string) (admission.ExecutionLogsResult, *admission.Error)
	Result(ctx context.Context, runID string) (admission.ExecutionResultBundle, *admission.Error)
	Cancel(ctx context.Context, runID string) (admission.ExecutionCancelResult, *admission.Error)
}

const (
	headerOutcomeSource             = admission.OutcomeHeaderSource
	headerOutcomeObservation        = admission.OutcomeHeaderObservation
	headerOutcomeAccessClass        = admission.OutcomeHeaderAccessClass
	headerProviderTerminalObserved  = admission.OutcomeHeaderProviderTerminalObserved
	headerLifecycleProjectionSource = admission.OutcomeHeaderLifecycleProjectionSource
	headerLifecycleProjectionRev    = admission.OutcomeHeaderLifecycleProjectionRev
)

type Server struct {
	service             preparationService
	callers             callerauth.Authenticator
	allowedPathPrefixes []string
	isStarted           func() bool
}

func NewServer(service preparationService, bootstrapIssuerCN string, allowedPathPrefixes []string, isStarted func() bool) *Server {
	return &Server{
		service:             service,
		callers:             callerauth.NewAuthenticator(bootstrapIssuerCN),
		allowedPathPrefixes: append([]string(nil), allowedPathPrefixes...),
		isStarted:           isStarted,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /v1/executions:contract", s.handleProducerContract)
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

func (s *Server) handleProducerContract(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeExecutionCaller(w, r) {
		return
	}

	httpx.WriteJSON(w, http.StatusOK, s.service.ProducerContract(r.Context()))
}

func (s *Server) handlePrepare(w http.ResponseWriter, r *http.Request) {
	ctx, request, ok := s.decodeAuthorizedExecutionRequest(w, r)
	if !ok {
		return
	}

	result, err := s.service.Prepare(ctx, request)
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
	ctx, request, ok := s.decodeAuthorizedExecutionRequest(w, r)
	if !ok {
		return
	}

	result, err := s.service.Submit(ctx, request)
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
		w.Header().Set("Content-Type", admission.LogsMediaType)
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

// decodeAuthorizedExecutionRequest authorizes the caller and decodes the
// request. The returned context carries the caller the connection
// authenticated, which ES admission matches workload grants on: the caller
// identity comes from the mTLS connection only, never from the body.
func (s *Server) decodeAuthorizedExecutionRequest(w http.ResponseWriter, r *http.Request) (context.Context, admission.PrepareRequest, bool) {
	caller, ok := s.authorizedExecutionCaller(w, r)
	if !ok {
		return nil, admission.PrepareRequest{}, false
	}

	var request admission.PrepareRequest
	if err := httpx.DecodeStrictJSONAndClose(r.Body, &request); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, admission.ErrorResponse{
			Success: false,
			Error:   "invalid request body",
			Code:    "invalid_request",
		})
		return nil, admission.PrepareRequest{}, false
	}
	return admission.WithAuthenticatedCaller(r.Context(), caller), request, true
}

func (s *Server) authorizeExecutionCaller(w http.ResponseWriter, r *http.Request) bool {
	_, ok := s.authorizedExecutionCaller(w, r)
	return ok
}

// authorizedExecutionCaller authenticates the caller from the TLS connection
// the request arrived on, which ES's server accepts through
// callerauth.NewListener and hands callerauth through its ConnContext hook
// (es/app), and checks it against the allowlist.
func (s *Server) authorizedExecutionCaller(w http.ResponseWriter, r *http.Request) (callerauth.ConnectionCaller, bool) {
	caller, ok := s.callers.AuthenticateConnection(w, r)
	if !ok {
		return callerauth.ConnectionCaller{}, false
	}
	if !callerallowlist.MatchesAny(caller.ID(), s.allowedPathPrefixes) {
		httpx.WriteText(w, http.StatusForbidden, "Caller not authorized for this operation")
		return callerauth.ConnectionCaller{}, false
	}
	return caller, true
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

func label(ok bool, healthy string, unhealthy string) string {
	if ok {
		return healthy
	}
	return unhealthy
}
