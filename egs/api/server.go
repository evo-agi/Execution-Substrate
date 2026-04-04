package api

import (
	"crypto/x509"
	"encoding/json"
	"net/http"
	"strings"

	"execution-platform/egs/model"
	"execution-platform/egs/sign"
	"execution-platform/observability"
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

	writeJSON(w, http.StatusOK, HealthResponse{
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
		writeText(w, http.StatusUnauthorized, "Authenticated caller identity required")
		return
	}
	if issuerCommonName == s.bootstrapIssuerCN {
		writeText(w, http.StatusForbidden, "Bootstrap PKI callers are not accepted; use a SPIRE-issued identity")
		return
	}
	if callerPath != "service/execution" && callerPath != "operator" {
		writeText(w, http.StatusForbidden, "Caller not authorized for this operation")
		return
	}

	result, err := s.signer.Sign(s.runtimeTrust)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{
			Error: "failed to sign trust model",
		})
		return
	}

	writeJSON(w, http.StatusOK, SignedRuntimeTrustResponse{
		RuntimeTrust:  result.RuntimeTrust,
		Algorithm:     result.Algorithm,
		KeyID:         result.KeyID,
		PayloadDigest: result.PayloadDigest,
		Signature:     result.Signature,
		Publication:   s.publication,
	})
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

func readinessLabel(ok bool, readyValue string, notReadyValue string) string {
	if ok {
		return readyValue
	}
	return notReadyValue
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
