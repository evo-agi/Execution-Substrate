package api_test

import (
	"errors"
	"net/http"
	"sync"
	"testing"

	"execution-substrate/ars/api"
	"execution-substrate/ars/index"
	"execution-substrate/internal/callerauth/callerauthtest"
)

const (
	testDigest          = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	testBootstrapIssuer = "bootstrap-ca"
)

// countingStore and countingIndex count every call, so a test can tell
// whether a request got past caller authentication.
type counter struct {
	mu    sync.Mutex
	calls int
}

func (c *counter) hit() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
}

func (c *counter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

type countingStore struct{ calls *counter }

func (s countingStore) RootDir() string { return "/nonexistent" }
func (s countingStore) Exists(string) (bool, error) {
	s.calls.hit()
	return false, nil
}
func (s countingStore) Read(string) ([]byte, error) {
	s.calls.hit()
	return nil, errors.New("countingStore: no blobs")
}
func (s countingStore) Write(string, []byte) (bool, error) {
	s.calls.hit()
	return false, errors.New("countingStore: read only")
}

type countingIndex struct{ calls *counter }

func (i countingIndex) Path() string { return "/nonexistent" }
func (i countingIndex) Count() int   { return 0 }
func (i countingIndex) Lookup(string) (index.Entry, bool, error) {
	i.calls.hit()
	return index.Entry{}, false, nil
}
func (i countingIndex) Register(index.Entry) (bool, error) {
	i.calls.hit()
	return false, errors.New("countingIndex: read only")
}

// Every ARS route that authenticates its caller, read routes and writer
// routes alike, applies the shared caller authentication rule.
func TestARSRoutesApplyTheSharedCallerAuthenticationRule(t *testing.T) {
	calls := &counter{}
	server := api.NewServer(countingStore{calls}, countingIndex{calls}, []string{"service/execution"}, testBootstrapIssuer, func() bool { return true })
	handler := server.Handler()

	for _, route := range []callerauthtest.Route{
		{Name: "blob_bytes", Method: http.MethodGet, Target: "/v1/blobs/" + testDigest + ":bytes", AllowedPath: "service/execution"},
		{Name: "blob_json", Method: http.MethodGet, Target: "/v1/blobs/" + testDigest + ":json", AllowedPath: "service/execution"},
		{Name: "blob_head", Method: http.MethodHead, Target: "/v1/blobs/" + testDigest, AllowedPath: "service/execution"},
		{Name: "artifact_read", Method: http.MethodGet, Target: "/v1/artifacts/" + testDigest + "/discovery", AllowedPath: "service/execution"},
		{Name: "blob_put", Method: http.MethodPut, Target: "/v1/blobs/" + testDigest, Body: "x", AllowedPath: "service/artifact-governance"},
		{Name: "artifact_register", Method: http.MethodPost, Target: "/v1/artifacts:register", Body: `{"discovery_digest":"` + testDigest + `"}`, AllowedPath: "service/artifact-governance"},
	} {
		callerauthtest.CheckRoute(t, handler, route, testBootstrapIssuer, calls.count)
	}
}

// Authorization stays ARS's own: an authenticated caller outside the read
// allowlist, or other than the writer, gets 403.
func TestARSAuthorizationStaysLocalAfterAuthentication(t *testing.T) {
	calls := &counter{}
	server := api.NewServer(countingStore{calls}, countingIndex{calls}, []string{"service/execution"}, testBootstrapIssuer, func() bool { return true })
	handler := server.Handler()

	for _, tc := range []struct {
		method, target, body, callerPath string
	}{
		{http.MethodGet, "/v1/blobs/" + testDigest + ":bytes", "", "service/deployment"},
		{http.MethodGet, "/v1/blobs/" + testDigest + ":bytes", "", "service/execution-evil"},
		{http.MethodPut, "/v1/blobs/" + testDigest, "x", "service/execution"},
		{http.MethodPost, "/v1/artifacts:register", `{"discovery_digest":"` + testDigest + `"}`, "service/execution"},
	} {
		state := callerauthtest.State(callerauthtest.Certificate(t, callerauthtest.RuntimeIssuer, callerauthtest.SPIFFEID(tc.callerPath)))
		response := callerauthtest.Serve(t, handler, tc.method, tc.target, tc.body, state)
		if response.Code != http.StatusForbidden || response.Body.String() != "Caller not authorized for this operation" {
			t.Errorf("%s %s as %s: %d %q", tc.method, tc.target, tc.callerPath, response.Code, response.Body.String())
		}
	}
	if calls.count() != 0 {
		t.Fatalf("unauthorized callers reached the store or index %d times", calls.count())
	}
}
