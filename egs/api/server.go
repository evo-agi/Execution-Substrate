package api

import (
	"net/http"

	"execution-substrate/egs/contract"
	"execution-substrate/egs/sign"
	"execution-substrate/internal/callerauth"
	"execution-substrate/internal/httpx"
	"execution-substrate/internal/observability"
)

const serviceName = "execution-governance"

type Server struct {
	runtimeTrust contract.RuntimeTrustPolicy
	publication  contract.PublicationMetadata
	signer       sign.Signer
	callers      callerauth.Authenticator
	isStarted    func() bool
}

func NewServer(
	runtimeTrust contract.RuntimeTrustPolicy,
	publication contract.PublicationMetadata,
	signer sign.Signer,
	bootstrapIssuerCN string,
	isStarted func() bool,
) *Server {
	return &Server{
		runtimeTrust: runtimeTrust.Normalized(),
		publication:  publication.Normalized(),
		signer:       signer,
		callers:      callerauth.NewAuthenticator(bootstrapIssuerCN),
		isStarted:    isStarted,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /v1/trust-model", s.handleTrustModel)
	return observability.WrapHandler(serviceName, mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	_ = r

	started := false
	if s.isStarted != nil {
		started = s.isStarted()
	}
	signerReady := s.signer != nil
	trustModelReady := s.runtimeTrust.Validate() == nil
	ready := started && signerReady && trustModelReady

	status := "unhealthy"
	if ready {
		status = "healthy"
	}

	httpx.WriteJSON(w, http.StatusOK, HealthResponse{
		Status:  status,
		Ready:   ready,
		Service: serviceName,
		AdditionalProperties: HealthAdditionalProperties{
			Readiness: HealthReadiness{
				Signer:     readinessLabel(signerReady, "initialized", "missing"),
				TrustModel: readinessLabel(trustModelReady, "loaded", "missing"),
			},
		},
	})
}

func (s *Server) handleTrustModel(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.callers.Authenticate(w, r)
	if !ok {
		return
	}
	if !authorizedTrustModelCaller(caller.ID().Path()) {
		httpx.WriteText(w, http.StatusForbidden, "Caller not authorized for this operation")
		return
	}

	result, err := s.signer.Sign(s.runtimeTrust)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, ErrorResponse{
			Error: "failed to sign trust model",
		})
		return
	}

	httpx.WriteJSON(w, http.StatusOK, SignedRuntimeTrustResponse{
		RuntimeTrust:  result.RuntimeTrust,
		Algorithm:     result.Algorithm,
		KeyID:         result.KeyID,
		PayloadDigest: result.PayloadDigest,
		Signature:     result.Signature,
		Publication:   s.publication,
	})
}

func authorizedTrustModelCaller(callerPath string) bool {
	switch callerPath {
	case "service/execution", "operator/local":
		return true
	default:
		return false
	}
}

func readinessLabel(ok bool, readyValue string, notReadyValue string) string {
	if ok {
		return readyValue
	}
	return notReadyValue
}
