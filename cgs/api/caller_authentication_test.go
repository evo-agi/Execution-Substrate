package api_test

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"execution-substrate/cgs/api"
	"execution-substrate/cgs/policy"
	"execution-substrate/internal/callerauth/callerauthtest"
)

const (
	testBootstrapIssuer = "bootstrap-ca"
	testIDConf          = `
subject "execution" {
  type: "service"
  principal: "spiffe://execution.internal/service/execution"
  role: "worker"
}
`
)

func loadTestPolicy(t *testing.T) *policy.Set {
	t.Helper()
	path := filepath.Join(t.TempDir(), "id.conf")
	if err := os.WriteFile(path, []byte(testIDConf), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := policy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func authorizeBody(workloadIdentityID string) string {
	body, _ := json.Marshal(api.AuthorizeRequest{
		Workload:              api.WorkloadDescriptor{Type: "service", WorkloadIdentityID: workloadIdentityID},
		RequestedCapabilities: []string{"vault:read"},
	})
	return string(body)
}

// jsonCounter counts the responses that CGS writes after authentication:
// every such response is JSON, and both authentication refusals are plain
// text.
type jsonCounter struct {
	mu      sync.Mutex
	handler http.Handler
	calls   int
}

func (c *jsonCounter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.handler.ServeHTTP(w, r)
	if strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		c.mu.Lock()
		c.calls++
		c.mu.Unlock()
	}
}

func (c *jsonCounter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func TestCGSAuthorizeAppliesTheSharedCallerAuthenticationRule(t *testing.T) {
	counter := &jsonCounter{handler: api.NewServer(loadTestPolicy(t), testBootstrapIssuer).Handler()}
	callerauthtest.CheckRoute(t, counter, callerauthtest.Route{
		Name:        "authorize",
		Method:      http.MethodPost,
		Target:      "/v1/credential/authorize",
		Body:        authorizeBody("spiffe://execution.internal/service/execution"),
		AllowedPath: "service/execution",
	}, testBootstrapIssuer, counter.count)
}

// CGS used to accept a caller identity from any SPIFFE trust domain. A
// caller from another trust domain that names itself as the workload is now
// refused at authentication, before any policy evaluation.
func TestCGSRefusesACallerFromAnotherTrustDomainThatNamesItself(t *testing.T) {
	handler := api.NewServer(loadTestPolicy(t), testBootstrapIssuer).Handler()
	for _, id := range []string{
		"spiffe://other.internal/service/execution",
		"spiffe://execution.internal.evil/service/execution",
		"spiffe://evil.execution.internal/service/execution",
	} {
		state := callerauthtest.State(callerauthtest.Certificate(t, callerauthtest.RuntimeIssuer, id))
		response := callerauthtest.Serve(t, handler, http.MethodPost, "/v1/credential/authorize", authorizeBody(id), state)
		if response.Code != http.StatusUnauthorized || response.Body.String() != callerauthtest.UnauthenticatedBody {
			t.Errorf("%s: %d %q", id, response.Code, response.Body.String())
		}
	}
}

func TestCGSAuthorizeAllowsTheMatchingCallerAndRefusesAMismatch(t *testing.T) {
	handler := api.NewServer(loadTestPolicy(t), testBootstrapIssuer).Handler()
	state := callerauthtest.State(callerauthtest.Certificate(t, callerauthtest.RuntimeIssuer, "spiffe://execution.internal/service/execution"))

	response := callerauthtest.Serve(t, handler, http.MethodPost, "/v1/credential/authorize", authorizeBody("spiffe://execution.internal/service/execution"), state)
	var decoded api.AuthorizeResponse
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &decoded) != nil || !decoded.Allowed {
		t.Fatalf("matching caller: %d %q", response.Code, response.Body.String())
	}

	response = callerauthtest.Serve(t, handler, http.MethodPost, "/v1/credential/authorize", authorizeBody("spiffe://execution.internal/service/other"), state)
	if response.Code != http.StatusForbidden || response.Body.String() != "Authenticated caller does not match requested workload principal" {
		t.Fatalf("mismatched caller: %d %q", response.Code, response.Body.String())
	}
}
