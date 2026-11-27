package api_test

import (
	"net/http"
	"sync"
	"testing"

	"execution-substrate/egs/api"
	"execution-substrate/egs/contract"
	"execution-substrate/egs/sign"
	"execution-substrate/internal/callerauth/callerauthtest"
)

const testBootstrapIssuer = "bootstrap-ca"

type countingSigner struct {
	mu    sync.Mutex
	calls int
}

func (s *countingSigner) Sign(contract.RuntimeTrustPolicy) (sign.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	return sign.Result{}, nil
}

func (s *countingSigner) Algorithm() string { return "test" }
func (s *countingSigner) KeyID() string     { return "test" }

func (s *countingSigner) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func TestEGSTrustModelAppliesTheSharedCallerAuthenticationRule(t *testing.T) {
	signer := &countingSigner{}
	server := api.NewServer(contract.RuntimeTrustPolicy{}, contract.PublicationMetadata{}, signer, testBootstrapIssuer, func() bool { return true })
	for _, path := range []string{"service/execution", "operator/local"} {
		callerauthtest.CheckRoute(t, server.Handler(), callerauthtest.Route{
			Name:        "trust_model_as_" + map[string]string{"service/execution": "execution", "operator/local": "operator"}[path],
			Method:      http.MethodGet,
			Target:      "/v1/trust-model",
			AllowedPath: path,
		}, testBootstrapIssuer, signer.count)
	}
}

func TestEGSAuthorizationStaysLocalAfterAuthentication(t *testing.T) {
	signer := &countingSigner{}
	server := api.NewServer(contract.RuntimeTrustPolicy{}, contract.PublicationMetadata{}, signer, testBootstrapIssuer, func() bool { return true })
	for _, path := range []string{"operator", "service/execution/sub", "service/deployment"} {
		state := callerauthtest.State(callerauthtest.Certificate(t, callerauthtest.RuntimeIssuer, callerauthtest.SPIFFEID(path)))
		response := callerauthtest.Serve(t, server.Handler(), http.MethodGet, "/v1/trust-model", "", state)
		if response.Code != http.StatusForbidden || response.Body.String() != "Caller not authorized for this operation" {
			t.Errorf("%s: %d %q", path, response.Code, response.Body.String())
		}
	}
	if signer.count() != 0 {
		t.Fatalf("unauthorized callers reached the signer %d times", signer.count())
	}
}
