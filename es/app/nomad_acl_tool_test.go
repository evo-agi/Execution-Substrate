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
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// The exclusive-writer check asks Nomad itself: a policy or role counts as a
// grant when a short-lived token holding only it can read the ES namespace
// (Nomad allows that for any job capability there) or plan a job in it,
// however its rules are written and whatever job capability they give. Auth
// methods are refused outright, because their binding rules can issue tokens
// with any policy. check also refuses a second token with ES's or the
// observer's policy, either policy with rules other than the tool's or with a
// job ACL, and an ES or observer token with a role.
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

	if output, err := check(); err != nil || !strings.Contains(output, "no other grant holds capabilities there") {
		t.Fatalf("check with the management token failed on the provisioned Nomad: %v output=%s", err, output)
	}

	for _, form := range []struct{ name, rules string }{
		{"hcl-glob", `namespace "*" { policy = "write" }`},
		{"json", `{"namespace": {"es-submit-v1": {"capabilities": ["submit-job"]}}}`},
		{"escaped", `namespace "es\u002dsubmit-v1" { policy = "write" }`},
		{"json-escaped", `{"namespace": {"es\u002dsubmit\u002dv1": {"policy": "write"}}}`},
		{"partial-glob", `namespace "es-*" { capabilities = ["submit-job"] }`},
		{"json-glob", `{"namespace": {"*": {"policy": "write"}}}`},
		// Grants that cannot submit but can change, rerun, stop, enter or
		// read ES's jobs.
		{"scale-only", `namespace "es-submit-v1" { capabilities = ["scale-job"] }`},
		{"lifecycle-json", `{"namespace": {"es-submit-v1": {"capabilities": ["read-job", "alloc-lifecycle"]}}}`},
		{"exec-glob", `namespace "*" { capabilities = ["read-job", "alloc-exec"] }`},
		{"dispatch-only", `namespace "es-submit-v1" { capabilities = ["dispatch-job"] }`},
		{"another-reader", `namespace "es-submit-v1" { capabilities = ["read-job"] }`},
	} {
		write(http.MethodPost, "/v1/acl/policy/"+form.name, map[string]string{"Name": form.name, "Rules": form.rules})
		refusedBoth("the "+form.name+" policy", "other ACL grants hold capabilities in es-submit-v1 (policy "+form.name+")")
		write(http.MethodDelete, "/v1/acl/policy/"+form.name, nil)
	}

	var role struct {
		ID string `json:"ID"`
	}
	if err := json.Unmarshal([]byte(write(http.MethodPost, "/v1/acl/role", map[string]any{"Name": "es-copy", "Policies": []map[string]string{{"Name": "es-submit-v1"}}})), &role); err != nil || role.ID == "" {
		t.Fatalf("create role: %v", err)
	}
	refusedBoth("a role holding the ES policy", "other ACL grants hold capabilities in es-submit-v1 (role es-copy)")
	write(http.MethodDelete, "/v1/acl/role/"+role.ID, nil)

	// Every management token can submit anywhere, so a second live one
	// breaks the lock. An expired one does not.
	var extraManagement struct {
		AccessorID string `json:"AccessorID"`
	}
	if err := json.Unmarshal([]byte(write(http.MethodPost, "/v1/acl/token", map[string]any{"Name": "extra-management", "Type": "management"})), &extraManagement); err != nil || extraManagement.AccessorID == "" {
		t.Fatalf("create a second management token: %v", err)
	}
	refusedBoth("a second management token", "nomad has other management tokens (accessors "+extraManagement.AccessorID+")")
	write(http.MethodDelete, "/v1/acl/token/"+extraManagement.AccessorID, nil)

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

	// Grants that hold nothing in es-submit-v1 pass: one limited to the
	// default namespace, and a glob write that a deny on es-submit-v1
	// shadows.
	write(http.MethodPost, "/v1/acl/policy/readers", map[string]string{"Name": "readers", "Rules": `namespace "default" { policy = "read" }`})
	write(http.MethodPost, "/v1/acl/policy/shadowed", map[string]string{"Name": "shadowed",
		"Rules": "namespace \"*\" { policy = \"write\" }\nnamespace \"es-submit-v1\" { policy = \"deny\" }\n"})
	if output, err := provision(); err != nil {
		t.Fatalf("provision refused policies that hold nothing in es-submit-v1: %v output=%s", err, output)
	}
	if output, err := check(); err != nil {
		t.Fatalf("check refused policies that hold nothing in es-submit-v1: %v output=%s", err, output)
	}
	write(http.MethodDelete, "/v1/acl/policy/shadowed", nil)

	// A second token with ES's policy, and widened ES or observer policies:
	// check refuses each, and provision deletes the token or restores the
	// rules.
	var second struct {
		AccessorID string `json:"AccessorID"`
	}
	if err := json.Unmarshal([]byte(write(http.MethodPost, "/v1/acl/token", map[string]any{
		"Name": "not-es", "Type": "client", "Policies": []string{"es-submit-v1"},
	})), &second); err != nil || second.AccessorID == "" {
		t.Fatalf("create a second ES-policy token: %v", err)
	}
	if output, err := check(); err == nil || !strings.Contains(output, "live tokens holding the es-submit-v1 policy are") ||
		!strings.Contains(output, second.AccessorID) {
		t.Fatalf("check accepted a second token with the ES policy: %v output=%s", err, output)
	}
	if output, err := provision(); err != nil || !strings.Contains(output, "deleted the stale es-submit-v1 token (accessor "+second.AccessorID+")") {
		t.Fatalf("provision did not delete a second token with the ES policy: %v output=%s", err, output)
	}
	// The observer policy is exempt from the probes only while its rules are
	// the tool's: a provision that does not write it (no observer token
	// file) judges a widened copy like any other grant.
	write(http.MethodPost, "/v1/acl/policy/es-observer-v1", map[string]string{"Name": "es-observer-v1",
		"Rules": "namespace \"es-submit-v1\" {\n  capabilities = [\"read-job\", \"alloc-lifecycle\"]\n}\n"})
	if output, err := runNomadACLTool(t, "provision", "--addr", harness.addr, "--management-token-file", management,
		"--es-token-file", harness.esTokenFile, "--es-token-owner", owner); err == nil ||
		!strings.Contains(output, "other ACL grants hold capabilities in es-submit-v1 (policy es-observer-v1)") {
		t.Fatalf("provision without the observer accepted a widened observer policy: %v output=%s", err, output)
	}
	for _, widened := range []struct{ policy, rules string }{
		{"es-observer-v1", "agent {\n  policy = \"read\"\n}\nnode {\n  policy = \"read\"\n}\n" +
			"namespace \"es-submit-v1\" {\n  capabilities = [\"read-job\", \"read-logs\", \"scale-job\", \"alloc-exec\", \"alloc-lifecycle\"]\n}\n"},
		{"es-submit-v1", "namespace \"es-submit-v1\" {\n  capabilities = [\"submit-job\", \"read-job\", \"read-logs\", \"alloc-exec\", \"alloc-node-exec\"]\n}\n" +
			"host_volume \"*\" {\n  policy = \"write\"\n}\n"},
	} {
		write(http.MethodPost, "/v1/acl/policy/"+widened.policy, map[string]string{"Name": widened.policy, "Rules": widened.rules})
		if output, err := check(); err == nil || !strings.Contains(output, "the "+widened.policy+" policy's rules differ") {
			t.Fatalf("check accepted a widened %s policy: %v output=%s", widened.policy, err, output)
		}
		if output, err := provision(); err != nil {
			t.Fatalf("provision did not restore the %s policy: %v output=%s", widened.policy, err, output)
		}
		if output, err := check(); err != nil {
			t.Fatalf("check failed after provision restored the %s policy: %v output=%s", widened.policy, err, output)
		}
	}

	// Provision keeps an existing ES token only when Nomad reports it as the
	// ES client token with exactly ES's policy. A wider token in the ES token
	// file is replaced, and deleted in Nomad.
	var wider struct {
		AccessorID string `json:"AccessorID"`
		SecretID   string `json:"SecretID"`
	}
	if err := json.Unmarshal([]byte(write(http.MethodPost, "/v1/acl/token", map[string]any{
		"Name": "es-submit-v1", "Type": "client", "Policies": []string{"es-submit-v1", "readers"},
	})), &wider); err != nil || wider.AccessorID == "" || wider.SecretID == "" {
		t.Fatalf("create a wider ES token: %v", err)
	}
	replaceNomadTokenFileContent(t, harness.esTokenFile, wider.SecretID)
	output, err := provision()
	if err != nil || !strings.Contains(output, "wrote a new es-submit-v1 token") ||
		!strings.Contains(output, "deleted the stale es-submit-v1 token (accessor "+wider.AccessorID+")") {
		t.Fatalf("provision did not replace a wider ES token: %v output=%s", err, output)
	}
	if readNomadTokenFile(t, harness.esTokenFile) == wider.SecretID {
		t.Fatal("provision kept an ES token with a wider policy set")
	}
	if status, _ := nomadRawRequest(t, http.MethodGet, harness.addr+"/v1/acl/token/self", wider.SecretID, nil); status == http.StatusOK {
		t.Fatal("the replaced wider ES token still works")
	}

	// A job ACL on ES's or the observer's policy gives the policy's
	// capabilities to the workloads of the job it names (for ES's policy, a
	// second writer in es-submit-v1). check refuses it and provision clears it.
	jobACL := map[string]string{"Namespace": "es-submit-v1", "JobID": "es-jobacl-victim"}
	policyJobACL := func(name string) any {
		t.Helper()
		var stored struct {
			JobACL any `json:"JobACL"`
		}
		if err := json.Unmarshal([]byte(write(http.MethodGet, "/v1/acl/policy/"+name, nil)), &stored); err != nil {
			t.Fatal(err)
		}
		return stored.JobACL
	}
	for _, policy := range []struct{ name, rules string }{
		{"es-submit-v1", toolESPolicyRules},
		{"es-observer-v1", toolObserverPolicyRules},
	} {
		write(http.MethodPost, "/v1/acl/policy/"+policy.name, map[string]any{"Name": policy.name, "Rules": policy.rules, "JobACL": jobACL})
		if policyJobACL(policy.name) == nil {
			t.Fatalf("nomad did not store the job ACL on the %s policy", policy.name)
		}
		if output, err := check(); err == nil || !strings.Contains(output, "the "+policy.name+" policy has a job ACL") {
			t.Fatalf("check accepted a job ACL on the %s policy: %v output=%s", policy.name, err, output)
		}
		if output, err := provision(); err != nil {
			t.Fatalf("provision refused while clearing the job ACL on the %s policy: %v output=%s", policy.name, err, output)
		}
		if got := policyJobACL(policy.name); got != nil {
			t.Fatalf("provision left the job ACL on the %s policy: %v", policy.name, got)
		}
		if output, err := check(); err != nil {
			t.Fatalf("check failed after provision cleared the job ACL on the %s policy: %v output=%s", policy.name, err, output)
		}
	}
	// With a job ACL, the observer policy is not exempt from the probes either:
	// a provision that does not write it judges it like any other grant.
	write(http.MethodPost, "/v1/acl/policy/es-observer-v1", map[string]any{"Name": "es-observer-v1", "Rules": toolObserverPolicyRules, "JobACL": jobACL})
	if output, err := runNomadACLTool(t, "provision", "--addr", harness.addr, "--management-token-file", management,
		"--es-token-file", harness.esTokenFile, "--es-token-owner", owner); err == nil ||
		!strings.Contains(output, "other ACL grants hold capabilities in es-submit-v1 (policy es-observer-v1)") {
		t.Fatalf("provision without the observer exempted an observer policy with a job ACL: %v output=%s", err, output)
	}
	if output, err := provision(); err != nil || policyJobACL("es-observer-v1") != nil {
		t.Fatalf("provision did not restore the observer policy: %v output=%s", err, output)
	}

	// A role on the ES or observer token widens it while its Policies still
	// list only the designed policy. check refuses such a token, and provision
	// replaces it (and deletes it in Nomad).
	write(http.MethodPost, "/v1/acl/policy/es-acl-test-default-writer", map[string]string{"Name": "es-acl-test-default-writer",
		"Rules": "namespace \"default\" {\n  policy = \"write\"\n}\n"})
	var wideRole struct {
		ID string `json:"ID"`
	}
	if err := json.Unmarshal([]byte(write(http.MethodPost, "/v1/acl/role", map[string]any{
		"Name": "es-acl-test-wider", "Policies": []map[string]string{{"Name": "es-acl-test-default-writer"}},
	})), &wideRole); err != nil || wideRole.ID == "" {
		t.Fatalf("create a role: %v", err)
	}
	for _, held := range []struct{ name, file, label string }{
		{"es-submit-v1", harness.esTokenFile, "the ES client token with only the es-submit-v1 policy and no roles"},
		{"es-observer-v1", harness.observerTokenFile, "the observer client token with only the es-observer-v1 policy and no roles"},
	} {
		secret := readNomadTokenFile(t, held.file)
		status, body := nomadRawRequest(t, http.MethodGet, harness.addr+"/v1/acl/token/self", secret, nil)
		var self struct {
			AccessorID string `json:"AccessorID"`
		}
		if status != http.StatusOK || json.Unmarshal([]byte(body), &self) != nil || self.AccessorID == "" {
			t.Fatalf("read the %s token: HTTP %d", held.name, status)
		}
		write(http.MethodPost, "/v1/acl/token/"+self.AccessorID, map[string]any{"AccessorID": self.AccessorID, "Name": held.name,
			"Type": "client", "Policies": []string{held.name}, "Roles": []map[string]string{{"ID": wideRole.ID}}})
		if output, err := check(); err == nil || !strings.Contains(output, "does not hold "+held.label) {
			t.Fatalf("check accepted the %s token with a role: %v output=%s", held.name, err, output)
		}
		output, err := provision()
		if err != nil || !strings.Contains(output, "wrote a new "+held.name+" token") ||
			!strings.Contains(output, "deleted the stale "+held.name+" token (accessor "+self.AccessorID+")") {
			t.Fatalf("provision did not replace the %s token with a role: %v output=%s", held.name, err, output)
		}
		if readNomadTokenFile(t, held.file) == secret {
			t.Fatalf("provision kept the %s token with a role", held.name)
		}
		if output, err := check(); err != nil {
			t.Fatalf("check failed after provision replaced the %s token: %v output=%s", held.name, err, output)
		}
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

// replaceNomadTokenFileContent puts token into an existing 0400 token file,
// keeping its owner and mode.
func replaceNomadTokenFileContent(t *testing.T, path string, token string) {
	t.Helper()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
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
	// The rules nomad_acl.py writes for ES's and the observer's policies.
	toolESPolicyRules       = "namespace \"es-submit-v1\" {\n  capabilities = [\"submit-job\", \"read-job\", \"read-logs\"]\n}\n"
	toolObserverPolicyRules = "agent {\n  policy = \"read\"\n}\nnode {\n  policy = \"read\"\n}\n" +
		"namespace \"es-submit-v1\" {\n  capabilities = [\"read-job\", \"read-logs\"]\n}\n"
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
	case r.URL.Path == "/v1/acl/policy/es-submit-v1" && (token == testESNomadToken || token == fakeACLManagementToken):
		writeJSON(map[string]any{"Name": "es-submit-v1", "Rules": toolESPolicyRules, "JobACL": nil})
	case r.URL.Path == "/v1/acl/policy/es-observer-v1" && (token == testObserverNomadToken || token == fakeACLManagementToken):
		writeJSON(map[string]any{"Name": "es-observer-v1", "Rules": toolObserverPolicyRules, "JobACL": nil})
	case r.URL.Path == "/v1/namespace/es-submit-v1":
		// Only the probe token for the default-readers policy asks.
		w.WriteHeader(http.StatusForbidden)
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
		writeJSON([]map[string]string{{"Name": "es-submit-v1"}, {"Name": "es-observer-v1"}, {"Name": "default-readers"}})
	case r.URL.Path == "/v1/acl/roles" && token == fakeACLManagementToken:
		writeJSON([]any{})
	case r.URL.Path == "/v1/acl/auth-methods" && token == fakeACLManagementToken:
		writeJSON([]any{})
	case r.URL.Path == "/v1/acl/tokens" && token == fakeACLManagementToken:
		writeJSON([]map[string]any{
			{"AccessorID": "management", "Type": "management"},
			{"AccessorID": "es", "Type": "client", "Policies": []string{"es-submit-v1"}},
			{"AccessorID": "observer", "Type": "client", "Policies": []string{"es-observer-v1"}},
			{"AccessorID": "expired-management", "Type": "management", "ExpirationTime": "2020-01-01T00:00:00.123456789Z"},
			{"AccessorID": "expired-es", "Type": "client", "Policies": []string{"es-submit-v1"}, "ExpirationTime": "2020-01-01T00:00:00Z"},
		})
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
	if output, err := run(nil); err != nil || !strings.Contains(output, "no other grant holds capabilities there") {
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
	// The tool sends tokens straight to the Nomad address: it follows no
	// redirect and ignores proxy settings in its environment.
	startElsewhere := func(t *testing.T) (*httptest.Server, *atomic.Int32) {
		var requests atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"AccessorID":"anonymous","Type":"client"}`))
		}))
		t.Cleanup(server.Close)
		return server, &requests
	}
	t.Run("redirect is not followed", func(t *testing.T) {
		elsewhere, requests := startElsewhere(t)
		output, err := run(func(w http.ResponseWriter, r *http.Request, _ string) bool {
			http.Redirect(w, r, elsewhere.URL+r.URL.RequestURI(), http.StatusTemporaryRedirect)
			return true
		})
		if err == nil {
			t.Fatalf("check passed through a redirecting Nomad address: output=%s", output)
		}
		if got := requests.Load(); got != 0 {
			t.Fatalf("the redirect target received %d request(s)", got)
		}
	})
	t.Run("proxy settings are ignored", func(t *testing.T) {
		proxy, requests := startElsewhere(t)
		server := httptest.NewServer(&fakeNomadForACLCheck{})
		defer server.Close()
		command := exec.Command("python3", "-I", nomadACLToolPath(), "check", "--addr", server.URL,
			"--es-token-file", esTokenFile, "--observer-token-file", observerTokenFile, "--management-token-file", managementFile)
		command.Env = append(os.Environ(), "http_proxy="+proxy.URL, "HTTP_PROXY="+proxy.URL, "all_proxy="+proxy.URL, "no_proxy=", "NO_PROXY=")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("check with proxy settings failed: %v output=%s", err, output)
		}
		if got := requests.Load(); got != 0 {
			t.Fatalf("the proxy received %d request(s)", got)
		}
	})

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
			map[string]any{"SecretID": testObserverNomadToken, "Type": "client", "Policies": []string{"es-submit-v1"}}), "does not hold the observer client token"},
		{"ES token has a role", answer("/v1/acl/token/self", testESNomadToken, http.StatusOK,
			map[string]any{"SecretID": testESNomadToken, "Type": "client", "Policies": []string{"es-submit-v1"},
				"Roles": []map[string]string{{"ID": "role-id", "Name": "wider"}}}), "does not hold the ES client token with only the es-submit-v1 policy and no roles"},
		{"observer token has a role", answer("/v1/acl/token/self", testObserverNomadToken, http.StatusOK,
			map[string]any{"SecretID": testObserverNomadToken, "Type": "client", "Policies": []string{"es-observer-v1"},
				"Roles": []map[string]string{{"ID": "role-id", "Name": "wider"}}}), "does not hold the observer client token with only the es-observer-v1 policy and no roles"},
		{"observer token file holds a management token", answer("/v1/acl/token/self", testObserverNomadToken, http.StatusOK,
			map[string]any{"SecretID": testObserverNomadToken, "Type": "management", "Policies": []string{"es-observer-v1"}}), "does not hold the observer client token"},
		{"observer token can plan", plan(testObserverNomadToken, "es-submit-v1", http.StatusOK), "the observer token could plan jobs in es-submit-v1"},
		{"management token is not one", answer("/v1/acl/token/self", fakeACLManagementToken, http.StatusOK,
			map[string]any{"SecretID": fakeACLManagementToken, "Type": "client"}), "does not hold a working Nomad management token"},
		{"auth method present", answer("/v1/acl/auth-methods", fakeACLManagementToken, http.StatusOK, []map[string]string{{"Name": "sso"}}), "nomad has ACL auth methods (sso)"},
		{"another live management token", answer("/v1/acl/tokens", fakeACLManagementToken, http.StatusOK, []map[string]any{
			{"AccessorID": "management", "Type": "management"},
			{"AccessorID": "es", "Type": "client", "Policies": []string{"es-submit-v1"}},
			{"AccessorID": "observer", "Type": "client", "Policies": []string{"es-observer-v1"}},
			{"AccessorID": "second", "Type": "management", "ExpirationTime": "0001-01-01T00:00:00Z"},
			{"AccessorID": "third", "Type": "management", "ExpirationTime": "2999-01-01T00:00:00Z"},
		}), "nomad has other management tokens (accessors second, third)"},
		{"another policy can submit", plan(fakeACLProbeSecret, "es-submit-v1", http.StatusOK), "other ACL grants hold capabilities in es-submit-v1 (policy default-readers)"},
		{"another policy holds some capability", answer("/v1/namespace/es-submit-v1", fakeACLProbeSecret, http.StatusOK, map[string]any{"Name": "es-submit-v1"}),
			"other ACL grants hold capabilities in es-submit-v1 (policy default-readers)"},
		{"probe answer is not a refusal", answer("/v1/namespace/es-submit-v1", fakeACLProbeSecret, http.StatusInternalServerError, nil),
			"other ACL grants hold capabilities in es-submit-v1 (policy default-readers)"},
		{"ES policy widened", answer("/v1/acl/policy/es-submit-v1", testESNomadToken, http.StatusOK,
			map[string]any{"Name": "es-submit-v1", "Rules": strings.Replace(toolESPolicyRules, `"read-logs"`, `"read-logs", "alloc-exec"`, 1)}),
			"the es-submit-v1 policy's rules differ"},
		{"observer policy widened", answer("/v1/acl/policy/es-observer-v1", testObserverNomadToken, http.StatusOK,
			map[string]any{"Name": "es-observer-v1", "Rules": strings.Replace(toolObserverPolicyRules, `"read-logs"`, `"read-logs", "scale-job"`, 1)}),
			"the es-observer-v1 policy's rules differ"},
		{"observer policy widened, as the management token reads it", answer("/v1/acl/policy/es-observer-v1", fakeACLManagementToken, http.StatusOK,
			map[string]any{"Name": "es-observer-v1", "Rules": toolObserverPolicyRules + "operator {\n  policy = \"write\"\n}\n"}),
			"the es-observer-v1 policy's rules differ"},
		{"ES policy missing", answer("/v1/acl/policy/es-submit-v1", testESNomadToken, http.StatusNotFound, nil), "the es-submit-v1 policy's rules differ"},
		{"ES policy has a job ACL", answer("/v1/acl/policy/es-submit-v1", testESNomadToken, http.StatusOK,
			map[string]any{"Name": "es-submit-v1", "Rules": toolESPolicyRules, "JobACL": map[string]string{"Namespace": "es-submit-v1", "JobID": "victim"}}),
			"the es-submit-v1 policy has a job ACL"},
		{"observer policy has a job ACL", answer("/v1/acl/policy/es-observer-v1", testObserverNomadToken, http.StatusOK,
			map[string]any{"Name": "es-observer-v1", "Rules": toolObserverPolicyRules, "JobACL": map[string]string{"Namespace": "es-submit-v1", "JobID": "victim"}}),
			"the es-observer-v1 policy has a job ACL"},
		{"observer policy has a job ACL, as the management token reads it", answer("/v1/acl/policy/es-observer-v1", fakeACLManagementToken, http.StatusOK,
			map[string]any{"Name": "es-observer-v1", "Rules": toolObserverPolicyRules, "JobACL": map[string]string{"Namespace": "es-submit-v1", "JobID": "victim"}}),
			"the es-observer-v1 policy has a job ACL"},
		{"another management token whose expiry is unreadable", answer("/v1/acl/tokens", fakeACLManagementToken, http.StatusOK, []map[string]any{
			{"AccessorID": "management", "Type": "management"},
			{"AccessorID": "es", "Type": "client", "Policies": []string{"es-submit-v1"}},
			{"AccessorID": "observer", "Type": "client", "Policies": []string{"es-observer-v1"}},
			{"AccessorID": "unreadable-expiry", "Type": "management", "ExpirationTime": "next Tuesday"},
		}), "nomad has other management tokens (accessors unreadable-expiry)"},
		{"second token with the ES policy", answer("/v1/acl/tokens", fakeACLManagementToken, http.StatusOK, []map[string]any{
			{"AccessorID": "management", "Type": "management"},
			{"AccessorID": "es", "Type": "client", "Policies": []string{"es-submit-v1"}},
			{"AccessorID": "not-es", "Type": "client", "Policies": []string{"es-submit-v1"}},
			{"AccessorID": "observer", "Type": "client", "Policies": []string{"es-observer-v1"}},
		}), "live tokens holding the es-submit-v1 policy are (accessors es, not-es)"},
		{"second token with the observer policy", answer("/v1/acl/tokens", fakeACLManagementToken, http.StatusOK, []map[string]any{
			{"AccessorID": "management", "Type": "management"},
			{"AccessorID": "es", "Type": "client", "Policies": []string{"es-submit-v1"}},
			{"AccessorID": "observer", "Type": "client", "Policies": []string{"es-observer-v1"}},
			{"AccessorID": "observer-copy", "Type": "client", "Policies": []string{"es-observer-v1", "default-readers"}},
		}), "live tokens holding the es-observer-v1 policy are (accessors observer, observer-copy)"},
	} {
		t.Run(test.name, func(t *testing.T) {
			output, err := run(test.deviate)
			if err == nil || !strings.Contains(output, test.want) {
				t.Fatalf("check did not refuse with %q: %v output=%s", test.want, err, output)
			}
		})
	}
}
