package app_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// The exclusive-writer check asks Nomad itself: a policy or role counts as a
// grant when a short-lived token holding only it can plan a job in the ES
// namespace, however its rules are written. Auth methods are refused
// outright, because their binding rules can issue tokens with any policy.
func TestNomadACLToolAsksNomadWhichGrantsCanSubmit(t *testing.T) {
	harness := startACLTestNomad(t, nomadHarnessOptions{})
	aclDir := filepath.Dir(harness.esTokenFile)
	management := filepath.Join(aclDir, "management-token")
	owner := strconv.Itoa(os.Geteuid()) + ":" + strconv.Itoa(os.Getegid())
	provision := func() (string, error) {
		return runNomadACLTool(t, "provision", "--addr", harness.addr,
			"--management-token-file", management,
			"--es-token-file", harness.esTokenFile, "--es-token-owner", owner,
			"--observer-token-file", harness.observerTokenFile, "--observer-token-owner", owner)
	}
	check := func() (string, error) {
		return runNomadACLTool(t, "check", "--addr", harness.addr, "--es-token-file", harness.esTokenFile,
			"--observer-token-file", harness.observerTokenFile, "--management-token-file", management)
	}
	write := func(method string, path string, body any) string {
		t.Helper()
		var payload []byte
		if body != nil {
			payload = mustMarshalJSON(t, body)
		}
		status, response := nomadRawRequest(t, method, harness.addr+path, harness.managementToken, payload)
		if status != http.StatusOK {
			t.Fatalf("%s %s: HTTP %d %s", method, path, status, response)
		}
		return response
	}
	refusedBoth := func(label string, want string) {
		t.Helper()
		if output, err := provision(); err == nil || !strings.Contains(output, want) {
			t.Fatalf("provision accepted %s: %v output=%s", label, err, output)
		}
		if output, err := check(); err == nil || !strings.Contains(output, want) {
			t.Fatalf("check accepted %s: %v output=%s", label, err, output)
		}
	}

	if output, err := check(); err != nil || !strings.Contains(output, "no other grant can submit there") {
		t.Fatalf("check with the management token failed on the provisioned Nomad: %v output=%s", err, output)
	}

	for _, form := range []struct{ name, rules string }{
		{"hcl-glob", `namespace "*" { policy = "write" }`},
		{"json", `{"namespace": {"es-submit-v1": {"capabilities": ["submit-job"]}}}`},
		{"escaped", `namespace "es-submit-v1" { policy = "write" }`},
		{"partial-glob", `namespace "es-*" { capabilities = ["submit-job"] }`},
		{"json-glob", `{"namespace": {"*": {"policy": "write"}}}`},
	} {
		write(http.MethodPost, "/v1/acl/policy/"+form.name, map[string]string{"Name": form.name, "Rules": form.rules})
		refusedBoth("the "+form.name+" policy", "other ACL grants can submit jobs in es-submit-v1 (policy "+form.name+")")
		write(http.MethodDelete, "/v1/acl/policy/"+form.name, nil)
	}

	var role struct {
		ID string `json:"ID"`
	}
	if err := json.Unmarshal([]byte(write(http.MethodPost, "/v1/acl/role", map[string]any{"Name": "es-copy", "Policies": []map[string]string{{"Name": "es-submit-v1"}}})), &role); err != nil || role.ID == "" {
		t.Fatalf("create role: %v", err)
	}
	refusedBoth("a role holding the ES policy", "other ACL grants can submit jobs in es-submit-v1 (role es-copy)")
	write(http.MethodDelete, "/v1/acl/role/"+role.ID, nil)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	write(http.MethodPost, "/v1/acl/auth-method", map[string]any{
		"Name": "es-probe-jwt", "Type": "JWT", "TokenLocality": "local", "MaxTokenTTL": "1h",
		"Config": map[string]any{"JWTValidationPubKeys": []string{string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}},
	})
	refusedBoth("an auth method", "nomad has ACL auth methods (es-probe-jwt)")
	write(http.MethodDelete, "/v1/acl/auth-method/es-probe-jwt", nil)

	write(http.MethodPost, "/v1/acl/policy/readers", map[string]string{"Name": "readers", "Rules": `namespace "default" { policy = "read" }`})
	if output, err := provision(); err != nil {
		t.Fatalf("provision refused a policy that cannot submit in es-submit-v1: %v output=%s", err, output)
	}
	if output, err := check(); err != nil {
		t.Fatalf("check refused a policy that cannot submit in es-submit-v1: %v output=%s", err, output)
	}

	var tokens []struct {
		Name string `json:"Name"`
	}
	if err := json.Unmarshal([]byte(write(http.MethodGet, "/v1/acl/tokens", nil)), &tokens); err != nil {
		t.Fatal(err)
	}
	for _, token := range tokens {
		if token.Name == "es-acl-probe" {
			t.Fatal("a probe token outlived its probe")
		}
	}
}

// fakeNomadForACLCheck answers the requests of nomad_acl.py check like a
// locked Nomad. deviate changes one answer; it returns true when it wrote one.
type fakeNomadForACLCheck struct {
	mu      sync.Mutex
	deviate func(w http.ResponseWriter, r *http.Request, token string) bool
	tokens  map[string]string // probe secret -> granted policy or role
}

const (
	fakeACLManagementToken = "7b712e3f-4d5c-4e6f-a0b1-c2d3e4f5a6b7"
	fakeACLProbeSecret     = "8c823f40-5e6d-4f70-b1c2-d3e4f5a6b7c8"
)

func (f *fakeNomadForACLCheck) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Nomad-Token")
	w.Header().Set("Content-Type", "application/json")
	if f.deviate != nil && f.deviate(w, r, token) {
		return
	}
	writeJSON := func(value any) { _ = json.NewEncoder(w).Encode(value) }
	planPath := "/v1/job/es-acl-probe/plan"
	namespace := r.URL.Query().Get("namespace")
	switch {
	case r.URL.Path == "/v1/acl/token/self":
		switch token {
		case "":
			writeJSON(map[string]any{"AccessorID": "anonymous", "Type": "client"})
		case testESNomadToken:
			writeJSON(map[string]any{"AccessorID": "es", "SecretID": testESNomadToken, "Type": "client", "Policies": []string{"es-submit-v1"}})
		case testObserverNomadToken:
			writeJSON(map[string]any{"AccessorID": "observer", "SecretID": testObserverNomadToken, "Type": "client", "Policies": []string{"es-observer-v1"}})
		case fakeACLManagementToken:
			writeJSON(map[string]any{"AccessorID": "management", "SecretID": fakeACLManagementToken, "Type": "management"})
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	case r.URL.Path == "/v1/acl/policy/anonymous":
		w.WriteHeader(http.StatusNotFound)
	case r.URL.Path == planPath:
		_, _ = io.Copy(io.Discard, r.Body)
		if token == testESNomadToken && namespace == "es-submit-v1" {
			writeJSON(map[string]any{"Index": 1})
			return
		}
		w.WriteHeader(http.StatusForbidden)
	case r.URL.Path == "/v1/nodes":
		if token == testObserverNomadToken {
			writeJSON([]any{})
			return
		}
		w.WriteHeader(http.StatusForbidden)
	case r.URL.Path == "/v1/acl/policies" && token == fakeACLManagementToken:
		writeJSON([]map[string]string{{"Name": "es-submit-v1"}, {"Name": "es-observer-v1"}})
	case r.URL.Path == "/v1/acl/roles" && token == fakeACLManagementToken:
		writeJSON([]any{})
	case r.URL.Path == "/v1/acl/auth-methods" && token == fakeACLManagementToken:
		writeJSON([]any{})
	case r.URL.Path == "/v1/acl/token" && r.Method == http.MethodPost && token == fakeACLManagementToken:
		writeJSON(map[string]any{"AccessorID": "probe", "SecretID": fakeACLProbeSecret})
	case r.URL.Path == "/v1/acl/token/probe" && r.Method == http.MethodDelete && token == fakeACLManagementToken:
		writeJSON(true)
	default:
		w.WriteHeader(http.StatusForbidden)
	}
}

// Each probe and policy check of nomad_acl.py check refuses on its own: the
// fake answers like a locked Nomad except for one deviation per case.
func TestNomadACLToolCheckRefusesEachDeviation(t *testing.T) {
	dir := t.TempDir()
	esTokenFile, err := writeNomadTokenFileAt(dir, "es-token", testESNomadToken)
	if err != nil {
		t.Fatal(err)
	}
	observerTokenFile, err := writeNomadTokenFileAt(dir, "observer-token", testObserverNomadToken)
	if err != nil {
		t.Fatal(err)
	}
	managementFile := filepath.Join(filepath.Dir(esTokenFile), "management-token")
	if err := os.WriteFile(managementFile, []byte(fakeACLManagementToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(deviate func(http.ResponseWriter, *http.Request, string) bool) (string, error) {
		server := httptest.NewServer(&fakeNomadForACLCheck{deviate: deviate})
		defer server.Close()
		return runNomadACLTool(t, "check", "--addr", server.URL, "--es-token-file", esTokenFile,
			"--observer-token-file", observerTokenFile, "--management-token-file", managementFile)
	}
	if output, err := run(nil); err != nil || !strings.Contains(output, "no other grant can submit there") {
		t.Fatalf("check refused the locked fake: %v output=%s", err, output)
	}
	answer := func(path string, token string, status int, body any) func(http.ResponseWriter, *http.Request, string) bool {
		return func(w http.ResponseWriter, r *http.Request, got string) bool {
			if r.URL.Path != path || got != token {
				return false
			}
			w.WriteHeader(status)
			if body != nil {
				_ = json.NewEncoder(w).Encode(body)
			}
			return true
		}
	}
	plan := func(token string, namespace string, status int) func(http.ResponseWriter, *http.Request, string) bool {
		return func(w http.ResponseWriter, r *http.Request, got string) bool {
			if r.URL.Path != "/v1/job/es-acl-probe/plan" || got != token || r.URL.Query().Get("namespace") != namespace {
				return false
			}
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"Index":1}`))
			return true
		}
	}
	for _, test := range []struct {
		name    string
		deviate func(http.ResponseWriter, *http.Request, string) bool
		want    string
	}{
		{"ACLs disabled", answer("/v1/acl/token/self", "", http.StatusOK, map[string]any{"AccessorID": "acls-disabled"}), "nomad ACLs are disabled"},
		{"anonymous policy", answer("/v1/acl/policy/anonymous", "", http.StatusOK, map[string]any{"Name": "anonymous"}), "has an `anonymous` ACL policy"},
		{"ES token has another policy too", answer("/v1/acl/token/self", testESNomadToken, http.StatusOK,
			map[string]any{"SecretID": testESNomadToken, "Type": "client", "Policies": []string{"es-submit-v1", "wider"}}), "does not hold the ES client token"},
		{"ES token file holds a management token", answer("/v1/acl/token/self", testESNomadToken, http.StatusOK,
			map[string]any{"SecretID": testESNomadToken, "Type": "management", "Policies": []string{"es-submit-v1"}}), "does not hold the ES client token"},
		{"ES token answers for another secret", answer("/v1/acl/token/self", testESNomadToken, http.StatusOK,
			map[string]any{"SecretID": testObserverNomadToken, "Type": "client", "Policies": []string{"es-submit-v1"}}), "does not hold the ES client token"},
		{"plan without a token allowed", plan("", "es-submit-v1", http.StatusOK), "a plan without a token in es-submit-v1 returned HTTP 200"},
		{"ES token cannot plan in its namespace", plan(testESNomadToken, "es-submit-v1", http.StatusForbidden), "a plan with the ES token in es-submit-v1 returned HTTP 403"},
		{"ES token can plan in default", plan(testESNomadToken, "default", http.StatusOK), "a plan with the ES token in namespace default returned HTTP 200"},
		{"ES token can read nodes", answer("/v1/nodes", testESNomadToken, http.StatusOK, []any{}), "the ES token could read nodes"},
		{"observer token has another policy", answer("/v1/acl/token/self", testObserverNomadToken, http.StatusOK,
			map[string]any{"SecretID": testObserverNomadToken, "Type": "client", "Policies": []string{"es-submit-v1"}}), "does not hold the observer token"},
		{"observer token can plan", plan(testObserverNomadToken, "es-submit-v1", http.StatusOK), "the observer token could plan jobs in es-submit-v1"},
		{"management token is not one", answer("/v1/acl/token/self", fakeACLManagementToken, http.StatusOK,
			map[string]any{"SecretID": fakeACLManagementToken, "Type": "client"}), "does not hold a working Nomad management token"},
		{"auth method present", answer("/v1/acl/auth-methods", fakeACLManagementToken, http.StatusOK, []map[string]string{{"Name": "sso"}}), "nomad has ACL auth methods (sso)"},
		{"another policy can submit", plan(fakeACLProbeSecret, "es-submit-v1", http.StatusOK), "other ACL grants can submit jobs in es-submit-v1 (policy es-observer-v1)"},
	} {
		t.Run(test.name, func(t *testing.T) {
			output, err := run(test.deviate)
			if err == nil || !strings.Contains(output, test.want) {
				t.Fatalf("check did not refuse with %q: %v output=%s", test.want, err, output)
			}
		})
	}
}
