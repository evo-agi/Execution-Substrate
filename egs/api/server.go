package api

import (
	"crypto/x509"
	"net/http"
	"strings"

	"execution-substrate/egs/model"
	"execution-substrate/egs/sign"
	"execution-substrate/internal/httpx"
	"execution-substrate/internal/observability"
)

const serviceName = "execution-governance"

type Server struct {
	runtimeTrust      model.RuntimeTrustPolicy
	publication       model.PublicationMetadata
	signer            sign.Signer
	bootstrapIssuerCN string
	isStarted         func() bool
}

func NewServer(
	runtimeTrust model.RuntimeTrustPolicy,
	publication model.PublicationMetadata,
	signer sign.Signer,
	bootstrapIssuerCN string,
	isStarted func() bool,
) *Server {
	return &Server{
		runtimeTrust:      runtimeTrust.Normalized(),
		publication:       publication.Normalized(),
		signer:            signer,
		bootstrapIssuerCN: strings.TrimSpace(bootstrapIssuerCN),
		isStarted:         isStarted,
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
	callerPath, issuerCommonName, ok := authenticatedCallerIdentity(r)
	if !ok {
		httpx.WriteText(w, http.StatusUnauthorized, "Authenticated caller identity required")
		return
	}
	if issuerCommonName == s.bootstrapIssuerCN {
		httpx.WriteText(w, http.StatusForbidden, "Bootstrap PKI callers are not accepted; use a SPIRE-issued identity")
		return
	}
	if !authorizedTrustModelCaller(callerPath) {
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

func readinessLabel(ok bool, readyValue string, notReadyValue string) string {
	if ok {
		return readyValue
	}
	return notReadyValue
}
