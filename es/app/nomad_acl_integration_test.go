package app_test

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Nomad access control in the es/app fixtures.
//
// Every real Nomad these tests start enforces ACLs and is provisioned with
// scripts/internal/nomad_acl.py, the same tool operators run. ES gets only
// its least-privilege token file; the harness reads and cleans up with the
// management token. Fake Nomad servers answer ES's access-control check like
// an ACL-enforcing Nomad with no anonymous policy.

const (
	nomadACLNamespace = "es-submit-v1"
	// testESNomadToken is ES's token in fake-Nomad fixtures.
	testESNomadToken = "5e5f0c1d-2b3a-4c4d-8e9f-a0b1c2d3e4f5"
	// testObserverNomadToken is the operator's read token in fake-Nomad fixtures.
	testObserverNomadToken               = "6f601d2e-3c4b-4d5e-9fa0-b1c2d3e4f5a6"
	nomadAccessControlCheckFailedMessage = "execution runtime access control check failed"
)

func writeNomadTokenFileAt(rootDir string, name string, token string) (string, error) {
	dir := filepath.Join(rootDir, "nomad-es-token")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, name)
	if existing, err := os.ReadFile(path); err == nil {
		if strings.TrimSpace(string(existing)) != token {
			return "", fmt.Errorf("%s already holds another token", path)
		}
		return path, nil
	}
	if err := os.WriteFile(path, []byte(token+"\n"), 0o400); err != nil {
		return "", err
	}
	return path, nil
}

// writeFakeNomadTokenFile writes ES's fake-Nomad token where ES's config
// names it, with the custody ES requires.
func writeFakeNomadTokenFile(t *testing.T, rootDir string) string {
	t.Helper()
	path, err := writeNomadTokenFileAt(rootDir, "es-token", testESNomadToken)
	if err != nil {
		t.Fatalf("write fake nomad token file: %v", err)
	}
	return path
}

func writeFakeNomadObserverTokenFile(t *testing.T, rootDir string) string {
	t.Helper()
	path, err := writeNomadTokenFileAt(rootDir, "observer-token", testObserverNomadToken)
	if err != nil {
		t.Fatalf("write fake nomad observer token file: %v", err)
	}
	return path
}

// writeUnissuedNomadTokenFile writes a well-formed token that no Nomad
// issued, for a Nomad started without ACLs.
func writeUnissuedNomadTokenFile(rootDir string) (string, error) {
	return writeNomadTokenFileAt(rootDir, "es-token", newRandomNomadToken())
}

func newRandomNomadToken() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		panic(err)
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	hex := fmt.Sprintf("%x", raw[:])
	return hex[0:8] + "-" + hex[8:12] + "-" + hex[12:16] + "-" + hex[16:20] + "-" + hex[20:32]
}

// lockedFakeNomadHandler answers the two requests of ES's access-control
// check like an ACL-enforcing Nomad that knows ES's token and holds no
// anonymous policy, and passes every other request to next.
func lockedFakeNomadHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/acl/token/self":
			if r.Header.Get("X-Nomad-Token") != testESNomadToken {
				http.Error(w, "Permission denied", http.StatusForbidden)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"AccessorID": "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
				"SecretID":   testESNomadToken,
				"Name":       "es-submit-v1",
				"Type":       "client",
				"Policies":   []string{"es-submit-v1"},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/acl/policy/anonymous":
			http.Error(w, "ACL policy not found", http.StatusNotFound)
		default:
			next.ServeHTTP(w, r)
		}
	})
}

func executionPlatformRepoRootPath() string {
	_, currentFile, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
}

func nomadACLToolPath() string {
	return filepath.Join(executionPlatformRepoRootPath(), "scripts", "internal", "nomad_acl.py")
}

// waitLeaderResult waits for a Nomad leader; /v1/status/leader needs no token.
func (n *nomadHarness) waitLeaderResult(timeout time.Duration) string {
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		response, err := client.Get(n.addr + "/v1/status/leader")
		if err == nil {
			var leader string
			decodeErr := json.NewDecoder(response.Body).Decode(&leader)
			response.Body.Close()
			if decodeErr == nil && strings.TrimSpace(leader) != "" {
				return ""
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	output, _ := os.ReadFile(n.outputPath)
	return fmt.Sprintf("nomad leader did not appear; logs=%s", strings.TrimSpace(string(output)))
}

// provisionACL bootstraps the harness Nomad's ACLs with the operator tool.
func (n *nomadHarness) provisionACL(rootDir string) string {
	aclDir := filepath.Join(rootDir, "nomad-acl")
	if err := os.MkdirAll(aclDir, 0o700); err != nil {
		return fmt.Sprintf("create nomad acl dir: %v", err)
	}
	if err := os.Chmod(aclDir, 0o700); err != nil {
		return fmt.Sprintf("chmod nomad acl dir: %v", err)
	}
	owner := strconv.Itoa(os.Geteuid()) + ":" + strconv.Itoa(os.Getegid())
	managementFile := filepath.Join(aclDir, "management-token")
	esTokenFile := filepath.Join(aclDir, "es-token")
	observerTokenFile := filepath.Join(aclDir, "observer-token")
	command := exec.Command("python3", "-I", nomadACLToolPath(), "provision",
		"--addr", n.addr,
		"--management-token-file", managementFile,
		"--es-token-file", esTokenFile,
		"--es-token-owner", owner,
		"--observer-token-file", observerTokenFile,
		"--observer-token-owner", owner,
	)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Sprintf("provision nomad acl: %v output=%s", err, strings.TrimSpace(string(output)))
	}
	management, err := os.ReadFile(managementFile)
	if err != nil {
		return fmt.Sprintf("read nomad management token: %v", err)
	}
	n.managementToken = strings.TrimSpace(string(management))
	n.esTokenFile = esTokenFile
	n.observerTokenFile = observerTokenFile
	return ""
}

// nomadHarnessTransport sends the harness's management token, and the ES
// namespace unless a request names one.
type nomadHarnessTransport struct {
	token string
	base  http.RoundTripper
}

func (transport nomadHarnessTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	if transport.token != "" {
		clone.Header.Set("X-Nomad-Token", transport.token)
	}
	query := clone.URL.Query()
	if query.Get("namespace") == "" {
		query.Set("namespace", nomadACLNamespace)
		clone.URL.RawQuery = query.Encode()
	}
	return transport.base.RoundTrip(clone)
}

func (n *nomadHarness) httpClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: nomadHarnessTransport{token: n.managementToken, base: http.DefaultTransport}}
}

// cliEnv is the environment for a nomad CLI call as the test operator.
func (n *nomadHarness) cliEnv() []string {
	env := []string{"NOMAD_ADDR=" + n.addr, "NOMAD_NAMESPACE=" + nomadACLNamespace}
	if n.managementToken != "" {
		env = append(env, "NOMAD_TOKEN="+n.managementToken)
	}
	return env
}

func nomadCLIEnv(t *testing.T, addr string, tokenFile string) []string {
	t.Helper()
	token, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatalf("read nomad token file: %v", err)
	}
	return []string{"NOMAD_ADDR=" + addr, "NOMAD_NAMESPACE=" + nomadACLNamespace, "NOMAD_TOKEN=" + strings.TrimSpace(string(token))}
}

func assertNomadTokenFileCustody(t *testing.T, label string, path string, wantMode os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != wantMode || int(stat.Uid) != os.Geteuid() || stat.Nlink != 1 {
		t.Fatalf("%s custody: mode=%v uid=%v links=%v, want regular %v owned by %d with one link", label, info.Mode(), stat.Uid, stat.Nlink, wantMode, os.Geteuid())
	}
}

// assertBringupNomadACLMaterial checks what bring-up left for its managed
// local Nomad: an owner-only management token, a read-only observer token,
// and ES's token where ES's config names it.
func assertBringupNomadACLMaterial(t *testing.T, bringupDir string, esTokenFile string) {
	t.Helper()
	aclDir := filepath.Join(bringupDir, "nomad-acl")
	info, err := os.Stat(aclDir)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("bring-up nomad acl dir: info=%v err=%v", info, err)
	}
	assertNomadTokenFileCustody(t, "management token", filepath.Join(aclDir, "management-token"), 0o600)
	assertNomadTokenFileCustody(t, "observer token", filepath.Join(aclDir, "observer-token"), 0o400)
	assertNomadTokenFileCustody(t, "ES token", esTokenFile, 0o400)
}

func requireNomadBinary(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("nomad"); err != nil {
		t.Skipf("nomad binary lookup failed: %v", err)
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skipf("python3 lookup failed: %v", err)
	}
}

func startACLTestNomad(t *testing.T, opts nomadHarnessOptions) *nomadHarness {
	t.Helper()
	requireNomadBinary(t)
	rootDir := newExecutionWorkspaceTempDir(t, "nomad-acl-")
	opts.leaderOnly = true
	harness := startNomadHarnessWithOptions(t, rootDir, opts)
	t.Cleanup(harness.stop)
	return harness
}

func readNomadTokenFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read token file: %v", err)
	}
	return strings.TrimSpace(string(data))
}

// nomadACLProbeJob is a registrable batch job. Nomad validates a job before
// it checks access, so only a valid job shows what access decides.
func nomadACLProbeJob(t *testing.T, id string, namespace string) []byte {
	t.Helper()
	return mustMarshalJSON(t, map[string]any{
		"Job": map[string]any{
			"ID":          id,
			"Name":        id,
			"Type":        "batch",
			"Namespace":   namespace,
			"Datacenters": []string{"dc1"},
			"TaskGroups": []map[string]any{{
				"Name":  "probe",
				"Count": 1,
				"Tasks": []map[string]any{{
					"Name":   "probe",
					"Driver": "docker",
					"Config": map[string]any{"image": "alpine:3.20", "command": "/bin/true"},
				}},
			}},
		},
	})
}

func nomadRawRequest(t *testing.T, method string, url string, token string, body []byte) (int, string) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatalf("build nomad request: %v", err)
	}
	if token != "" {
		request.Header.Set("X-Nomad-Token", token)
	}
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer response.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	return response.StatusCode, strings.TrimSpace(string(payload))
}

func nomadJobIDsInEveryNamespace(t *testing.T, harness *nomadHarness) []string {
	t.Helper()
	status, body := nomadRawRequest(t, http.MethodGet, harness.addr+"/v1/jobs?namespace=*", harness.managementToken, nil)
	if status != http.StatusOK {
		t.Fatalf("list jobs in every namespace: HTTP %d %s", status, body)
	}
	var jobs []struct {
		ID        string `json:"ID"`
		Namespace string `json:"Namespace"`
	}
	if err := json.Unmarshal([]byte(body), &jobs); err != nil {
		t.Fatalf("decode job list: %v", err)
	}
	ids := make([]string, 0, len(jobs))
	for _, job := range jobs {
		ids = append(ids, job.Namespace+"/"+job.ID)
	}
	return ids
}

// TestRealNomadRefusesJobsWithoutTheESToken is the brief's core claim, run on
// a real Nomad provisioned by the operator tool: a caller without ES's token
// cannot submit a job, and ES's own token can submit only in ES's namespace.
func TestRealNomadRefusesJobsWithoutTheESToken(t *testing.T) {
	harness := startACLTestNomad(t, nomadHarnessOptions{})
	esToken := readNomadTokenFile(t, harness.esTokenFile)
	observerToken := readNomadTokenFile(t, harness.observerTokenFile)
	unknownToken := newRandomNomadToken()

	refused := []struct {
		name      string
		token     string
		namespace string
	}{
		{"no token in the ES namespace", "", nomadACLNamespace},
		{"no token in the default namespace", "", "default"},
		{"unknown token in the ES namespace", unknownToken, nomadACLNamespace},
		{"observer token in the ES namespace", observerToken, nomadACLNamespace},
		{"ES token in the default namespace", esToken, "default"},
	}
	for index, test := range refused {
		jobID := fmt.Sprintf("acl-refused-%d", index)
		status, body := nomadRawRequest(t, http.MethodPost, harness.addr+"/v1/jobs?namespace="+test.namespace, test.token, nomadACLProbeJob(t, jobID, test.namespace))
		if status != http.StatusForbidden {
			t.Errorf("%s: register returned HTTP %d %s, want 403", test.name, status, body)
		}
	}

	for _, request := range []struct {
		name   string
		method string
		path   string
		body   []byte
	}{
		{"read nodes", http.MethodGet, "/v1/nodes", nil},
		{"read the agent", http.MethodGet, "/v1/agent/self", nil},
		{"create a namespace", http.MethodPost, "/v1/namespace/es-other", mustMarshalJSON(t, map[string]string{"Name": "es-other"})},
		{"write a policy", http.MethodPost, "/v1/acl/policy/es-wider", mustMarshalJSON(t, map[string]string{"Name": "es-wider", "Rules": `namespace "*" { policy = "write" }`})},
		{"create a token", http.MethodPost, "/v1/acl/token", mustMarshalJSON(t, map[string]any{"Name": "es-copy", "Type": "client", "Policies": []string{"es-submit-v1"}})},
	} {
		status, body := nomadRawRequest(t, request.method, harness.addr+request.path, esToken, request.body)
		if status != http.StatusForbidden {
			t.Errorf("ES token could %s: HTTP %d %s", request.name, status, body)
		}
	}

	if status, body := nomadRawRequest(t, http.MethodGet, harness.addr+"/v1/nodes", observerToken, nil); status != http.StatusOK {
		t.Errorf("observer token could not read nodes: HTTP %d %s", status, body)
	}

	// Positive control: the same job with ES's token in ES's namespace.
	status, body := nomadRawRequest(t, http.MethodPost, harness.addr+"/v1/jobs?namespace="+nomadACLNamespace, esToken, nomadACLProbeJob(t, "acl-accepted", nomadACLNamespace))
	if status != http.StatusOK {
		t.Fatalf("ES token could not register in %s: HTTP %d %s", nomadACLNamespace, status, body)
	}
	if got := strings.Join(nomadJobIDsInEveryNamespace(t, harness), ","); got != nomadACLNamespace+"/acl-accepted" {
		t.Fatalf("jobs in every namespace = %q, want only the ES-registered job", got)
	}
	status, body = nomadRawRequest(t, http.MethodDelete, harness.addr+"/v1/job/acl-accepted?namespace="+nomadACLNamespace+"&purge=true", esToken, nil)
	if status != http.StatusOK {
		t.Fatalf("ES token could not stop its job: HTTP %d %s", status, body)
	}

	check := exec.Command("python3", "-I", nomadACLToolPath(), "check", "--addr", harness.addr, "--es-token-file", harness.esTokenFile, "--observer-token-file", harness.observerTokenFile)
	if output, err := check.CombinedOutput(); err != nil {
		t.Fatalf("nomad_acl.py check failed on the provisioned Nomad: %v output=%s", err, output)
	}
}

func runNomadACLTool(t *testing.T, args ...string) (string, error) {
	t.Helper()
	command := exec.Command("python3", append([]string{"-I", nomadACLToolPath()}, args...)...)
	output, err := command.CombinedOutput()
	return string(output), err
}

func nomadTokenSelfAccessor(t *testing.T, harness *nomadHarness, token string) (int, string) {
	t.Helper()
	status, body := nomadRawRequest(t, http.MethodGet, harness.addr+"/v1/acl/token/self", token, nil)
	if status != http.StatusOK {
		return status, ""
	}
	var self struct {
		AccessorID string `json:"AccessorID"`
	}
	if err := json.Unmarshal([]byte(body), &self); err != nil {
		t.Fatalf("decode token self: %v", err)
	}
	return status, self.AccessorID
}

func TestNomadACLToolKeepsRotatesAndRefusesUnsafeStates(t *testing.T) {
	harness := startACLTestNomad(t, nomadHarnessOptions{})
	aclDir := filepath.Dir(harness.esTokenFile)
	owner := strconv.Itoa(os.Geteuid()) + ":" + strconv.Itoa(os.Getegid())
	provision := func(extra ...string) (string, error) {
		args := append([]string{"provision", "--addr", harness.addr,
			"--management-token-file", filepath.Join(aclDir, "management-token"),
			"--es-token-file", harness.esTokenFile, "--es-token-owner", owner,
			"--observer-token-file", harness.observerTokenFile, "--observer-token-owner", owner,
		}, extra...)
		return runNomadACLTool(t, args...)
	}
	check := func() (string, error) {
		return runNomadACLTool(t, "check", "--addr", harness.addr, "--es-token-file", harness.esTokenFile)
	}

	firstToken := readNomadTokenFile(t, harness.esTokenFile)
	if output, err := provision(); err != nil || !strings.Contains(output, "kept the working es-submit-v1 token") {
		t.Fatalf("second provision did not keep the token: %v output=%s", err, output)
	}
	if got := readNomadTokenFile(t, harness.esTokenFile); got != firstToken {
		t.Fatal("second provision changed the ES token")
	}

	if output, err := provision("--rotate"); err != nil || !strings.Contains(output, "deleted the stale es-submit-v1 token") {
		t.Fatalf("rotate did not replace the token: %v output=%s", err, output)
	}
	rotated := readNomadTokenFile(t, harness.esTokenFile)
	if rotated == firstToken {
		t.Fatal("rotate kept the old ES token")
	}
	if status, _ := nomadTokenSelfAccessor(t, harness, firstToken); status != http.StatusForbidden {
		t.Fatalf("the rotated-out token still works: HTTP %d", status)
	}
	assertNomadTokenFileCustody(t, "rotated ES token", harness.esTokenFile, 0o400)

	// A token file others could read is treated as exposed: check refuses
	// it and provision replaces the token.
	if err := os.Chmod(harness.esTokenFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if output, err := check(); err == nil || !strings.Contains(output, "mode 0400 or 0600") {
		t.Fatalf("check accepted a readable token file: %v output=%s", err, output)
	}
	if output, err := provision(); err != nil || !strings.Contains(output, "wrote a new es-submit-v1 token") {
		t.Fatalf("provision did not replace an exposed token: %v output=%s", err, output)
	}
	if status, _ := nomadTokenSelfAccessor(t, harness, rotated); status != http.StatusForbidden {
		t.Fatalf("the exposed token still works: HTTP %d", status)
	}

	for _, policy := range []struct {
		name  string
		rules string
		want  string
	}{
		{"anonymous", `namespace "default" { policy = "read" }`, "has an `anonymous` ACL policy"},
		{"operations", `namespace "*" { policy = "write" }`, "other ACL grants can submit jobs in es-submit-v1 (policy operations)"},
	} {
		status, body := nomadRawRequest(t, http.MethodPost, harness.addr+"/v1/acl/policy/"+policy.name, harness.managementToken, mustMarshalJSON(t, map[string]string{"Name": policy.name, "Rules": policy.rules}))
		if status != http.StatusOK {
			t.Fatalf("create %s policy: HTTP %d %s", policy.name, status, body)
		}
		if output, err := provision(); err == nil || !strings.Contains(output, policy.want) {
			t.Fatalf("provision accepted the %s policy: %v output=%s", policy.name, err, output)
		}
		if policy.name == "anonymous" {
			if output, err := check(); err == nil || !strings.Contains(output, policy.want) {
				t.Fatalf("check accepted the anonymous policy: %v output=%s", err, output)
			}
		}
		status, body = nomadRawRequest(t, http.MethodDelete, harness.addr+"/v1/acl/policy/"+policy.name, harness.managementToken, nil)
		if status != http.StatusOK {
			t.Fatalf("delete %s policy: HTTP %d %s", policy.name, status, body)
		}
	}
	if output, err := check(); err != nil {
		t.Fatalf("check failed after the unsafe policies were removed: %v output=%s", err, output)
	}

	// A lost management token file is never silently replaced.
	management := filepath.Join(aclDir, "management-token")
	if err := os.Rename(management, management+".kept"); err != nil {
		t.Fatal(err)
	}
	if output, err := provision(); err == nil || !strings.Contains(output, "already bootstrapped") {
		t.Fatalf("provision did not refuse a missing management token on a bootstrapped Nomad: %v output=%s", err, output)
	}
	if _, err := os.Lstat(management); !os.IsNotExist(err) {
		t.Fatalf("refused provision left a management token file: %v", err)
	}
}

func TestNomadACLToolRefusesANomadWithoutACLs(t *testing.T) {
	harness := startACLTestNomad(t, nomadHarnessOptions{aclDisabled: true})
	aclDir := filepath.Join(filepath.Dir(harness.esTokenFile), "acl")
	if err := os.Mkdir(aclDir, 0o700); err != nil {
		t.Fatal(err)
	}
	owner := strconv.Itoa(os.Geteuid()) + ":" + strconv.Itoa(os.Getegid())
	output, err := runNomadACLTool(t, "provision", "--addr", harness.addr,
		"--management-token-file", filepath.Join(aclDir, "management-token"),
		"--es-token-file", filepath.Join(aclDir, "es-token"), "--es-token-owner", owner)
	if err == nil || !strings.Contains(output, "nomad ACLs are disabled") {
		t.Fatalf("provision accepted a Nomad without ACLs: %v output=%s", err, output)
	}
	if entries, readErr := os.ReadDir(aclDir); readErr != nil || len(entries) != 0 {
		t.Fatalf("refused provision wrote files: entries=%v err=%v", entries, readErr)
	}
	output, err = runNomadACLTool(t, "check", "--addr", harness.addr, "--es-token-file", harness.esTokenFile)
	if err == nil || !strings.Contains(output, "nomad ACLs are disabled") {
		t.Fatalf("check accepted a Nomad without ACLs: %v output=%s", err, output)
	}
}

func submitExecutionExpectingRefusal(t *testing.T, stack *submitStack) (int, map[string]any) {
	t.Helper()
	response := doJSONRequest(
		t,
		stack.es.Addr(),
		http.MethodPost,
		"/v1/executions:submit",
		stack.fixture.clientTLSConfigForServer(t, stack.fixture.esServerName, "operator/local", false),
		buildSubmitRequestBody(t, stack),
	)
	defer response.Body.Close()
	var payload map[string]any
	_ = json.NewDecoder(response.Body).Decode(&payload)
	return response.StatusCode, payload
}

func assertESAccessControlRefusal(t *testing.T, label string, status int, payload map[string]any) {
	t.Helper()
	if status != http.StatusServiceUnavailable || payload["code"] != "execution_runtime_unavailable" || payload["error"] != nomadAccessControlCheckFailedMessage {
		t.Fatalf("%s: submit returned HTTP %d %v, want 503 execution_runtime_unavailable %q", label, status, payload, nomadAccessControlCheckFailedMessage)
	}
}

// TestSubmitRefusesANomadThatDoesNotEnforceACLs runs ES against real Nomads:
// one with an anonymous policy and one without ACLs. ES refuses both before
// it registers anything, and submits once the anonymous policy is gone.
func TestSubmitRefusesANomadThatDoesNotEnforceACLs(t *testing.T) {
	t.Run("anonymous policy", func(t *testing.T) {
		stack := startRuntimeIdentitySubmitStack(t)
		status, body := nomadRawRequest(t, http.MethodPost, stack.nomad.addr+"/v1/acl/policy/anonymous", stack.nomad.managementToken,
			mustMarshalJSON(t, map[string]string{"Name": "anonymous", "Rules": `namespace "default" { policy = "read" }`}))
		if status != http.StatusOK {
			t.Fatalf("create anonymous policy: HTTP %d %s", status, body)
		}
		refusedStatus, payload := submitExecutionExpectingRefusal(t, stack)
		assertESAccessControlRefusal(t, "anonymous policy", refusedStatus, payload)
		if jobs := nomadJobIDsInEveryNamespace(t, stack.nomad); len(jobs) != 0 {
			t.Fatalf("refused submit registered jobs: %v", jobs)
		}

		status, body = nomadRawRequest(t, http.MethodDelete, stack.nomad.addr+"/v1/acl/policy/anonymous", stack.nomad.managementToken, nil)
		if status != http.StatusOK {
			t.Fatalf("delete anonymous policy: HTTP %d %s", status, body)
		}
		submitted := submitExecution(t, stack, 10, 128)
		stack.nomad.waitForExecutionJob(t, submitted.RunID)
	})

	t.Run("ACLs disabled", func(t *testing.T) {
		stack := startRuntimeIdentitySubmitStackWithOptions(t, submitStackOptions{nomadACLDisabled: true})
		refusedStatus, payload := submitExecutionExpectingRefusal(t, stack)
		assertESAccessControlRefusal(t, "ACLs disabled", refusedStatus, payload)
		if jobs := nomadJobIDsInEveryNamespace(t, stack.nomad); len(jobs) != 0 {
			t.Fatalf("refused submit registered jobs: %v", jobs)
		}
	})
}

// Supported-local setup refuses, before it changes anything, a Nomad that does
// not enforce access control and a token directory placed inside the proof's
// scopes. On a locked Nomad it keeps or issues the tokens through the root
// wrapper, with ES's token owned by root (ES runs as root in that profile) and
// the observer token owned by the user who runs setup.
func TestSupportedLocalSetupLocksNomadBeforeProofEffects(t *testing.T) {
	repo := executionPlatformRepoRoot(t)
	script := filepath.Join(repo, "scripts", "72_supported_local_setup.sh")
	const fakes = `
require_command() { :; }
require_supported_go_toolchain() { :; }
uname() { printf 'Linux\n'; }
preflight_supported_local_setup_execution_roots() { :; }
preflight_supported_local_setup_spire_pin() { :; }
provision_supported_local_execution_roots() { :; }
stop_background_process() { :; }
stop_vault_dev_listener() { :; }
curl() {
  local url
  for url do :; done
  case "${url}" in
    */v1/acl/token/self) printf '{"AccessorID":"%s"}\n' "${ROOT_ACCESSOR}" ;;
    */v1/acl/policy/anonymous) printf '%s' "${ROOT_ANONYMOUS_STATUS}" ;;
    *) printf 'unexpected curl %s\n' "${url}" >> "$ROOT_EVENTS"; return 97 ;;
  esac
}
sudo() {
  if [[ "$1" == -n && "$2" == true ]]; then return 0; fi
  printf 'sudo %s\n' "$*" >> "$ROOT_EVENTS"
  return "${ROOT_PROVISION_STATUS:-0}"
}
nomad_api_get() {
  [[ "$1" == /v1/agent/self && "${NOMAD_TOKEN_FILE}" == "${SUPPORTED_LOCAL_NOMAD_ACL_DIR}/observer-token" ]] || return 97
  printf '%s\n' "${ROOT_AGENT_SELF}" > "$2"
}
build_codex_runtime_profile_image() { printf 'first proof effect\n' >> "$ROOT_EVENTS"; exit 97; }
setup`
	type result struct {
		workspace, proof, events, output string
	}
	run := func(t *testing.T, overrides ...string) result {
		t.Helper()
		workspace := t.TempDir()
		proof := filepath.Join(workspace, "proof")
		events := filepath.Join(workspace, "events")
		if err := os.WriteFile(events, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		output, _ := auditScriptSource(t, script, fakes, append([]string{
			"EXECUTION_SUBSTRATE_REPO_ROOT=" + repo,
			"SUPPORTED_LOCAL_PROOF_DIR=" + proof,
			"SUPPORTED_LOCAL_PROOF_ID=fixture-proof",
			"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_STORE_ID=test_store",
			"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_ID=test_key",
			"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_FILE=" + filepath.Join(workspace, "external", "key"),
			"SUPPORTED_LOCAL_NOMAD_ACL_DIR=" + filepath.Join(workspace, "nomad-acl"),
			"SUPPORTED_LOCAL_VAULT_PUBLIC_HOST=127.0.0.1",
			"SUPPORTED_LOCAL_VAULT_ROOT_TOKEN=synthetic-token",
			"SUPPORTED_LOCAL_VAULT_SECRET_VALUE=synthetic-value",
			"SUPPORTED_LOCAL_CODEX_CREDENTIAL_VALUE=synthetic-value",
			"ROOT_EVENTS=" + events,
			"ROOT_ACCESSOR=anonymous",
			"ROOT_ANONYMOUS_STATUS=404",
			"ROOT_AGENT_SELF=" + string(mustMarshalJSON(t, map[string]any{"config": map[string]any{
				"Client":  map[string]any{"Options": map[string]any{"driver.allowlist": "docker"}},
				"Plugins": supportedNomadDockerPluginAgentConfig(),
			}})),
		}, overrides...)...)
		recorded, err := os.ReadFile(events)
		if err != nil {
			t.Fatal(err)
		}
		return result{workspace: workspace, proof: proof, events: string(recorded), output: string(output)}
	}
	refusedBeforeEffects := func(t *testing.T, r result, message string) {
		t.Helper()
		if !strings.Contains(r.output, message) || r.events != "" {
			t.Fatalf("setup did not refuse before its first effect: output=%q events=%q", r.output, r.events)
		}
		if _, err := os.Lstat(r.proof); !os.IsNotExist(err) {
			t.Fatalf("refused setup created its proof root: %v", err)
		}
	}

	t.Run("ACLs disabled", func(t *testing.T) {
		r := run(t, "ROOT_ACCESSOR=acls-disabled")
		refusedBeforeEffects(t, r, "supported-local Nomad does not enforce access control")
	})
	t.Run("anonymous policy present", func(t *testing.T) {
		r := run(t, "ROOT_ANONYMOUS_STATUS=200")
		refusedBeforeEffects(t, r, "supported-local Nomad does not enforce access control")
	})
	t.Run("token directory inside the proof directory", func(t *testing.T) {
		workspace := t.TempDir()
		r := run(t, "SUPPORTED_LOCAL_PROOF_DIR="+filepath.Join(workspace, "proof"),
			"SUPPORTED_LOCAL_NOMAD_ACL_DIR="+filepath.Join(workspace, "proof", "nomad-acl"),
			"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_FILE="+filepath.Join(workspace, "external", "key"))
		if !strings.Contains(r.output, "outside the proof, staging, results and SPIRE socket directories") || r.events != "" {
			t.Fatalf("token directory inside the proof was accepted: output=%q events=%q", r.output, r.events)
		}
	})
	t.Run("provisioning failure stops setup", func(t *testing.T) {
		r := run(t, "ROOT_PROVISION_STATUS=1")
		if !strings.Contains(r.output, "supported-local Nomad access control provisioning failed") ||
			strings.Contains(r.events, "first proof effect") {
			t.Fatalf("setup continued after failed provisioning: output=%q events=%q", r.output, r.events)
		}
	})
	t.Run("Docker driver not limited", func(t *testing.T) {
		plugins := supportedNomadDockerPluginAgentConfig()
		plugins[0]["Config"].(map[string]any)["allow_privileged"] = true
		r := run(t, "ROOT_AGENT_SELF="+string(mustMarshalJSON(t, map[string]any{"config": map[string]any{
			"Client":  map[string]any{"Options": map[string]any{"driver.allowlist": "docker"}},
			"Plugins": plugins,
		}})))
		if !strings.Contains(r.output, "the Docker plugin must refuse privileged containers") ||
			!strings.Contains(r.output, "supported-local Nomad does not limit its drivers the supported way") ||
			strings.Contains(r.events, "first proof effect") {
			t.Fatalf("setup continued on a Nomad without the Docker limits: output=%q events=%q", r.output, r.events)
		}
	})
	t.Run("locked Nomad", func(t *testing.T) {
		r := run(t)
		current, err := exec.Command("id", "-un").Output()
		if err != nil {
			t.Fatal(err)
		}
		want := "sudo -n env NOMAD_ADDR=http://127.0.0.1:4646 NOMAD_ACL_DIR=" + filepath.Join(r.workspace, "nomad-acl") +
			" ES_USER=root OBSERVER_USER=" + strings.TrimSpace(string(current)) +
			" bash " + filepath.Join(repo, "scripts", "nomad_acl_setup.sh") + " provision\n"
		if os.Geteuid() == 0 {
			want = ""
		}
		if want != "" && r.events != want+"first proof effect\n" {
			t.Fatalf("setup did not provision Nomad tokens through the root wrapper before its proof effects: output=%q events=%q", r.output, r.events)
		}
	})
}

// The supported-local proof reads node details from an ACL-enforcing Nomad
// with the read-only observer token named by NOMAD_TOKEN_FILE. The token goes
// only in the request header, never into evidence or output, and a token file
// that is a symbolic link is refused before any request.
func TestSupportedLocalProofNodeDetailsSendTheObserverToken(t *testing.T) {
	const nodeID = "01234567-89ab-cdef-0123-456789abcdef"
	var requests, refused atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("X-Nomad-Token") != testObserverNomadToken {
			refused.Add(1)
			http.Error(w, "Permission denied", http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case "/v1/nodes":
			fmt.Fprintf(w, `[{"ID":%q}]`, nodeID)
		case "/v1/node/" + nodeID:
			fmt.Fprint(w, `{"Attributes":{"cpu.totalcompute":"2000"},"Drivers":{"docker":{"Healthy":true}}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	workspace := t.TempDir()
	tokenFile := writeFakeNomadObserverTokenFile(t, workspace)
	project := func(tokenEnv string) (string, []byte, error) {
		path := filepath.Join(t.TempDir(), "node-details-safe.json")
		command := exec.Command("python3", filepath.Join(executionPlatformRepoRoot(t), "scripts", "internal", "supported_local_proof_projection.py"),
			"fetch-node-details", server.URL, path)
		command.Env = []string{"PATH=" + os.Getenv("PATH"), "PYTHONDONTWRITEBYTECODE=1"}
		if tokenEnv != "" {
			command.Env = append(command.Env, "NOMAD_TOKEN_FILE="+tokenEnv)
		}
		output, err := command.CombinedOutput()
		return path, output, err
	}

	path, output, err := project(tokenFile)
	if err != nil {
		t.Fatalf("node details with the observer token failed: %v output=%q", err, output)
	}
	evidence, err := os.ReadFile(path)
	if err != nil || bytes.Contains(evidence, []byte(testObserverNomadToken)) || bytes.Contains(output, []byte(testObserverNomadToken)) {
		t.Fatalf("observer token entered evidence or output: err=%v", err)
	}
	if refused.Load() != 0 {
		t.Fatalf("a request went out without the observer token: %d", refused.Load())
	}

	path, output, err = project("")
	if err == nil || refused.Load() == 0 {
		t.Fatalf("node details without a token were not refused by the ACL Nomad: err=%v output=%q", err, output)
	}
	if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
		t.Fatal("refused node fetch published output")
	}

	link := filepath.Join(workspace, "observer-link")
	if err := os.Symlink(tokenFile, link); err != nil {
		t.Fatal(err)
	}
	before := requests.Load()
	if _, output, err := project(link); err == nil || bytes.Contains(output, []byte(testObserverNomadToken)) {
		t.Fatalf("symbolic-link token file was accepted: err=%v output=%q", err, output)
	}
	if requests.Load() != before {
		t.Fatal("a symbolic-link token file reached Nomad")
	}
}
