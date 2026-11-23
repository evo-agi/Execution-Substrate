package api

import (
	"context"
	"net/http"
	"strings"

	"execution-substrate/ags/publish"
	"execution-substrate/internal/callerauth"
	"execution-substrate/internal/httpx"
	"execution-substrate/internal/observability"
)

const serviceName = "artifact-governance"

type publishingService interface {
	Health(ctx context.Context) publish.HealthSnapshot
	Publish(ctx context.Context, caller publish.CallerIdentity, req publish.PublishRequest) (publish.PublishResult, *publish.Error)
}

type Server struct {
	service             publishingService
	callers             callerauth.Authenticator
	allowedPathPrefixes []string
	isStarted           func() bool
}

func NewServer(service publishingService, bootstrapIssuerCN string, allowedPathPrefixes []string, isStarted func() bool) *Server {
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
				Signer:        label(snapshot.SignerReady, "initialized", "missing"),
			},
		},
	})
}

func (s *Server) handlePublish(w http.ResponseWriter, r *http.Request) {
	authenticated, ok := s.callers.Authenticate(w, r)
	if !ok {
		return
	}
	caller := publish.CallerIdentity{
		Path:     authenticated.ID().Path(),
		SPIFFEID: authenticated.ID().String(),
	}
	authorized := false
	for _, prefix := range s.allowedPathPrefixes {
		if matchesAuthorizedPathPrefix(caller.Path, prefix) {
			authorized = true
			break
		}
	}
	if !authorized {
		httpx.WriteText(w, http.StatusForbidden, "Caller not authorized for this operation")
		return
	}

	var request publish.PublishRequest
	if err := httpx.DecodeStrictJSONAndClose(r.Body, &request); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, ErrorResponse{
			Success: false,
			Error:   "invalid request body",
			Code:    "invalid_request",
		})
		return
	}

	result, err := s.service.Publish(r.Context(), caller, request)
	if err != nil {
		httpx.WriteJSON(w, err.Status, ErrorResponse{
			Success: false,
			Error:   err.Message,
			Code:    err.Code,
		})
		return
	}

	httpx.WriteJSON(w, http.StatusOK, result)
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
