package admission

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	esconfig "execution-substrate/es/config"
)

// testNomadToken is a synthetic Nomad ACL secret ID used only by these tests.
const testNomadToken = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"

// nomadAccessControlTestHandler stands in for an ACL-enabled Nomad in front
// of a test's own job handler. It answers the two access-control requests
// that precede every submission as a correctly locked Nomad would, and it
// fails the test if any job, allocation or client request lacks ES's token or
// leaves nomadSubmitNamespace. The wrapped handler never sees the two
// access-control requests.
func nomadAccessControlTestHandler(t *testing.T, next http.Handler) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if served := serveNomadAccessControlRequest(t, w, request); served {
			return
		}
		assertNomadJobRequestAuthenticated(t, request)
		next.ServeHTTP(w, request)
	})
}

func serveNomadAccessControlRequest(t *testing.T, w http.ResponseWriter, request *http.Request) bool {
	t.Helper()
	switch request.URL.Path {
	case "/v1/acl/token/self":
		if request.Method != http.MethodGet || request.Header.Get(nomadTokenHeader) != testNomadToken {
			t.Errorf("token self request method=%s carried the wrong token", request.Method)
			w.WriteHeader(http.StatusForbidden)
			return true
		}
		writeJSONResponse(t, w, http.StatusOK, map[string]any{
			"AccessorID": "a1b2c3d4-0000-4000-8000-000000000001",
			"SecretID":   testNomadToken,
			"Name":       "execution-substrate-es",
			"Type":       "client",
			"Policies":   []string{"es-submit"},
		})
		return true
	case "/v1/acl/policy/" + nomadAnonymousPolicyName:
		if request.Method != http.MethodGet || len(request.Header.Values(nomadTokenHeader)) != 0 {
			t.Errorf("anonymous policy request method=%s carried a token", request.Method)
		}
		http.Error(w, "ACL policy not found", http.StatusNotFound)
		return true
	}
	return false
}

func assertNomadJobRequestAuthenticated(t *testing.T, request *http.Request) {
	t.Helper()
	if values := request.Header.Values(nomadTokenHeader); len(values) != 1 || values[0] != testNomadToken {
		t.Errorf("Nomad %s %s carried %d token header(s) or the wrong token", request.Method, request.URL.Path, len(values))
	}
	if values := request.URL.Query()["namespace"]; len(values) != 1 || values[0] != nomadSubmitNamespace {
		t.Errorf("Nomad %s %s namespace query = %q, want exactly [%s]", request.Method, request.URL.Path, values, nomadSubmitNamespace)
	}
}

func writeNomadTokenFile(t *testing.T, dir string, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, "es-token")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func privateNomadTokenDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "nomad-acl")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestLoadNomadTokenAcceptsOnlyAPrivateCanonicalSecretID(t *testing.T) {
	for _, test := range []struct {
		name    string
		content string
		mode    os.FileMode
	}{
		{name: "exact 0400", content: testNomadToken, mode: 0o400},
		{name: "exact 0600", content: testNomadToken, mode: 0o600},
		{name: "one trailing line feed", content: testNomadToken + "\n", mode: 0o400},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := writeNomadTokenFile(t, privateNomadTokenDir(t), test.content, test.mode)
			token, err := loadNomadToken(path)
			if err != nil || token != testNomadToken {
				t.Fatalf("private canonical token refused: err=%v", err)
			}
		})
	}
}

func TestLoadNomadTokenRefusesUnsafeOrMalformedFiles(t *testing.T) {
	for _, test := range []struct {
		name    string
		content string
		mode    os.FileMode
		want    string
	}{
		{name: "group readable", content: testNomadToken, mode: 0o440, want: "unsafe identity, access or length"},
		{name: "world readable", content: testNomadToken, mode: 0o644, want: "unsafe identity, access or length"},
		{name: "owner executable", content: testNomadToken, mode: 0o700, want: "unsafe identity, access or length"},
		{name: "empty", content: "", mode: 0o600, want: "unsafe identity, access or length"},
		{name: "upper-case hex", content: strings.ToUpper(testNomadToken), mode: 0o600, want: "exactly one Nomad ACL token secret ID"},
		{name: "carriage return line ending", content: testNomadToken[:35] + "\r\n", mode: 0o600, want: "exactly one Nomad ACL token secret ID"},
		{name: "two line feeds", content: testNomadToken + "\n\n", mode: 0o600, want: "unsafe identity, access or length"},
		{name: "leading space", content: " " + testNomadToken, mode: 0o600, want: "exactly one Nomad ACL token secret ID"},
		{name: "trailing space", content: testNomadToken + " ", mode: 0o600, want: "exactly one Nomad ACL token secret ID"},
		{name: "hyphen moved", content: testNomadToken[:7] + "-" + testNomadToken[7:8] + testNomadToken[9:], mode: 0o600, want: "exactly one Nomad ACL token secret ID"},
		{name: "non-hex digit", content: "g" + testNomadToken[1:], mode: 0o600, want: "exactly one Nomad ACL token secret ID"},
		{name: "jwt-like text", content: strings.Repeat("a", 36), mode: 0o600, want: "exactly one Nomad ACL token secret ID"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := writeNomadTokenFile(t, privateNomadTokenDir(t), test.content, test.mode)
			token, err := loadNomadToken(path)
			if err == nil || token != "" || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("unsafe or malformed token file accepted or misreported: token=%q err=%v", token, err)
			}
			if strings.Contains(err.Error(), testNomadToken) || strings.Contains(err.Error(), test.content) && test.content != "" {
				t.Fatalf("token file error echoed file content: %v", err)
			}
		})
	}
}

func TestLoadNomadTokenRefusesLinksAndUnsafeParents(t *testing.T) {
	t.Run("symbolic link", func(t *testing.T) {
		dir := privateNomadTokenDir(t)
		target := writeNomadTokenFile(t, dir, testNomadToken, 0o400)
		link := filepath.Join(dir, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := loadNomadToken(link); err == nil {
			t.Fatal("symbolic link to a token file accepted")
		}
	})
	t.Run("second hard link", func(t *testing.T) {
		dir := privateNomadTokenDir(t)
		target := writeNomadTokenFile(t, dir, testNomadToken, 0o400)
		if err := os.Link(target, filepath.Join(dir, "other")); err != nil {
			t.Fatal(err)
		}
		if _, err := loadNomadToken(target); err == nil || !strings.Contains(err.Error(), "unsafe identity") {
			t.Fatalf("token file with a second hard link accepted: %v", err)
		}
	})
	t.Run("directory", func(t *testing.T) {
		dir := privateNomadTokenDir(t)
		path := filepath.Join(dir, "es-token")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := loadNomadToken(path); err == nil {
			t.Fatal("directory accepted as token file")
		}
	})
	t.Run("missing", func(t *testing.T) {
		if _, err := loadNomadToken(filepath.Join(privateNomadTokenDir(t), "absent")); err == nil || !strings.Contains(err.Error(), "unavailable") {
			t.Fatalf("missing token file not refused as unavailable: %v", err)
		}
	})
	for _, mode := range []os.FileMode{0o770, 0o757, 0o1777} {
		t.Run("writable parent "+mode.String(), func(t *testing.T) {
			dir := privateNomadTokenDir(t)
			path := writeNomadTokenFile(t, dir, testNomadToken, 0o400)
			if err := os.Chmod(dir, mode); err != nil {
				t.Fatal(err)
			}
			if _, err := loadNomadToken(path); err == nil || !strings.Contains(err.Error(), "parent is unsafe") {
				t.Fatalf("token file under a group- or world-writable parent accepted: %v", err)
			}
		})
	}
	t.Run("symbolic link in parent path", func(t *testing.T) {
		dir := privateNomadTokenDir(t)
		writeNomadTokenFile(t, dir, testNomadToken, 0o400)
		alias := filepath.Join(t.TempDir(), "alias")
		if err := os.Symlink(dir, alias); err != nil {
			t.Fatal(err)
		}
		if _, err := loadNomadToken(filepath.Join(alias, "es-token")); err == nil {
			t.Fatal("token file reached through a symbolic link in its parent path accepted")
		}
	})
	for _, path := range []string{"", "relative/es-token", "/tmp/x/../es-token"} {
		t.Run("unclean path "+path, func(t *testing.T) {
			if _, err := loadNomadToken(path); err == nil || !strings.Contains(err.Error(), "clean absolute path") {
				t.Fatalf("unclean token path %q accepted: %v", path, err)
			}
		})
	}
}

// continueNomadTokenTestAsRoot reports whether the calling test may go on in
// this process. As root it may. Otherwise the same test runs again as root
// through passwordless sudo, as on the CI runner, and this run reports that
// result; without passwordless sudo the test skips itself.
func continueNomadTokenTestAsRoot(t *testing.T) bool {
	t.Helper()
	if os.Geteuid() == 0 {
		return true
	}
	if output, err := exec.Command("sudo", "-n", "true").CombinedOutput(); err != nil {
		t.Skipf("needs root or passwordless sudo to give a path another owner: %v: %s", err, strings.TrimSpace(string(output)))
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("sudo", "-n", self, "-test.run", "^"+t.Name()+"$", "-test.v", "-test.count=1").CombinedOutput()
	t.Logf("the same test as root:\n%s", output)
	if err != nil {
		t.Fatalf("the test failed as root: %v", err)
	}
	if !strings.Contains(string(output), "--- PASS: "+t.Name()) {
		t.Fatal("the test did not run as root")
	}
	return false
}

func TestLoadNomadTokenRefusesAFileOwnedByAnotherUser(t *testing.T) {
	if !continueNomadTokenTestAsRoot(t) {
		return
	}
	dir := privateNomadTokenDir(t)
	path := writeNomadTokenFile(t, dir, testNomadToken, 0o400)
	if err := os.Chown(path, 4242, 4242); err != nil {
		t.Fatal(err)
	}
	if _, err := loadNomadToken(path); err == nil || !strings.Contains(err.Error(), "unsafe identity") {
		t.Fatalf("token file owned by another user accepted: %v", err)
	}
}

func TestLoadNomadTokenRefusesAParentOwnedByAnotherUser(t *testing.T) {
	if !continueNomadTokenTestAsRoot(t) {
		return
	}
	dir := privateNomadTokenDir(t)
	path := writeNomadTokenFile(t, dir, testNomadToken, 0o400)
	if err := os.Chown(dir, 4242, 4242); err != nil {
		t.Fatal(err)
	}
	if _, err := loadNomadToken(path); err == nil || !strings.Contains(err.Error(), "parent is unsafe") {
		t.Fatalf("token file under a parent owned by another non-root user accepted: %v", err)
	}
}

func minimalNomadConfigForTest(tokenFile string) esconfig.NomadConfig {
	return esconfig.NomadConfig{BaseURL: "http://127.0.0.1:4646", Datacenter: "dc1", TimeoutSeconds: 5, TokenFile: tokenFile}
}

func TestNewNomadClientLoadsTheTokenOrRefusesToBuild(t *testing.T) {
	path := writeNomadTokenFile(t, privateNomadTokenDir(t), testNomadToken, 0o400)
	cfg := minimalNomadConfigForTest(path)
	client, err := newNomadClient(cfg)
	if err != nil || client.token != testNomadToken {
		t.Fatalf("client did not load the token: err=%v", err)
	}
	cfg.TokenFile = filepath.Join(filepath.Dir(path), "absent")
	if client, err := newNomadClient(cfg); err == nil || client != nil {
		t.Fatal("client built without a readable token file")
	}
}

// ES's Nomad client keeps a redirect answer instead of following it, so its
// token never reaches the host a redirect names, and it uses no proxy.
func TestNomadClientNeverFollowsARedirectOrUsesAProxy(t *testing.T) {
	var elsewhere sync.Mutex
	elsewhereRequests := 0
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		elsewhere.Lock()
		elsewhereRequests++
		elsewhere.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"EvalID":"redirected"}`))
	}))
	defer other.Close()
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		http.Redirect(w, request, other.URL+request.URL.RequestURI(), http.StatusTemporaryRedirect)
	}))
	defer redirecting.Close()

	cfg := minimalNomadConfigForTest(writeNomadTokenFile(t, privateNomadTokenDir(t), testNomadToken, 0o400))
	cfg.BaseURL = redirecting.URL
	client, err := newNomadClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if accessErr := client.verifyAccessControl(context.Background()); accessErr == nil {
		t.Fatal("access control check passed on a redirect")
	}
	if _, err := client.submitJob(context.Background(), map[string]any{"Job": map[string]any{"ID": "redirect-probe"}}); err == nil {
		t.Fatal("submit succeeded on a redirect")
	}
	elsewhere.Lock()
	defer elsewhere.Unlock()
	if elsewhereRequests != 0 {
		t.Fatalf("the client followed %d redirect(s)", elsewhereRequests)
	}
	if newNomadTransport().Proxy != nil {
		t.Fatal("the Nomad transport uses a proxy")
	}
	if client.client.CheckRedirect == nil || client.client.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("the Nomad client follows redirects")
	}
}

// recordingNomad records every request the client makes and answers job
// requests with fixed bodies.
type recordingNomad struct {
	mu       sync.Mutex
	requests []*http.Request
}

func (n *recordingNomad) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	n.mu.Lock()
	n.requests = append(n.requests, request.Clone(context.Background()))
	n.mu.Unlock()
	switch {
	case request.Method == http.MethodPost && request.URL.Path == "/v1/jobs":
		_, _ = io.Copy(io.Discard, request.Body)
		_, _ = w.Write([]byte(`{"EvalID":"eval-1"}`))
	case request.Method == http.MethodGet && request.URL.Path == "/v1/job/exec-run-0123456789abcdef":
		_, _ = w.Write([]byte(`{"ID":"exec-run-0123456789abcdef","Status":"running","ModifyIndex":3}`))
	case request.Method == http.MethodGet && request.URL.Path == "/v1/job/exec-run-0123456789abcdef/allocations":
		_, _ = w.Write([]byte(`[{"ID":"alloc-1","ClientStatus":"running","ModifyIndex":4}]`))
	case request.Method == http.MethodGet && request.URL.Path == "/v1/allocation/alloc-1":
		_, _ = w.Write([]byte(`{"ID":"alloc-1","ClientStatus":"running","ModifyIndex":4,"TaskStates":{}}`))
	case request.Method == http.MethodGet && request.URL.Path == "/v1/client/fs/logs/alloc-1":
		_, _ = w.Write([]byte("log"))
	case request.Method == http.MethodDelete && request.URL.Path == "/v1/job/exec-run-0123456789abcdef":
		_, _ = w.Write([]byte(`{"EvalID":"eval-2"}`))
	default:
		http.NotFound(w, request)
	}
}

func TestEveryNomadJobRequestCarriesTheTokenAndTheSubmitNamespace(t *testing.T) {
	recorder := &recordingNomad{}
	client := newTestNomadClient(t, recorder)
	ctx := context.Background()
	if _, err := client.submitJob(ctx, map[string]any{"Job": map[string]any{"ID": "exec-run-0123456789abcdef", "Namespace": nomadSubmitNamespace}}); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if _, err := client.fetchJob(ctx, "exec-run-0123456789abcdef"); err != nil {
		t.Fatalf("fetch job: %v", err)
	}
	if _, err := client.fetchProjectedAllocation(ctx, "exec-run-0123456789abcdef"); err != nil {
		t.Fatalf("fetch allocation: %v", err)
	}
	if _, err := client.fetchTaskLogs(ctx, "alloc-1", nomadTaskName); err != nil {
		t.Fatalf("fetch logs: %v", err)
	}
	if err := client.stopJob(ctx, "exec-run-0123456789abcdef"); err != nil {
		t.Fatalf("stop job: %v", err)
	}

	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	seen := map[string]bool{}
	for _, request := range recorder.requests {
		seen[request.Method+" "+request.URL.Path] = true
		if values := request.Header.Values(nomadTokenHeader); len(values) != 1 || values[0] != testNomadToken {
			t.Errorf("%s %s carried %d token header(s) or the wrong token", request.Method, request.URL.Path, len(values))
		}
		if values := request.URL.Query()["namespace"]; len(values) != 1 || values[0] != nomadSubmitNamespace {
			t.Errorf("%s %s namespace = %q", request.Method, request.URL.Path, values)
		}
		if strings.Contains(request.URL.RawQuery, testNomadToken) || strings.Contains(request.URL.Path, testNomadToken) {
			t.Errorf("%s %s put the token into the URL", request.Method, request.URL.Path)
		}
	}
	for _, want := range []string{
		"POST /v1/jobs",
		"GET /v1/job/exec-run-0123456789abcdef",
		"GET /v1/job/exec-run-0123456789abcdef/allocations",
		"GET /v1/allocation/alloc-1",
		"GET /v1/client/fs/logs/alloc-1",
		"DELETE /v1/job/exec-run-0123456789abcdef",
	} {
		if !seen[want] {
			t.Errorf("request %s was not made; saw %v", want, seen)
		}
	}
}

func TestNomadJobSpecNamesTheSubmitNamespace(t *testing.T) {
	spec := buildNomadJobSpec(resolvedNomadJobProjection{jobID: "exec-run-0123456789abcdef"})
	job, ok := spec["Job"].(map[string]any)
	if !ok || job["Namespace"] != nomadSubmitNamespace {
		t.Fatalf("job spec namespace = %#v, want %q", job["Namespace"], nomadSubmitNamespace)
	}
}

type accessControlScenario struct {
	selfStatus      int
	selfBody        string
	anonymousStatus int
	anonymousBody   string
}

func newAccessControlScenarioClient(t *testing.T, scenario accessControlScenario, jobRequests *int) *nomadClient {
	t.Helper()
	return newUnwrappedTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/acl/token/self":
			w.WriteHeader(scenario.selfStatus)
			_, _ = w.Write([]byte(scenario.selfBody))
		case "/v1/acl/policy/anonymous":
			w.WriteHeader(scenario.anonymousStatus)
			_, _ = w.Write([]byte(scenario.anonymousBody))
		default:
			if jobRequests != nil {
				*jobRequests++
			}
			http.NotFound(w, request)
		}
	}))
}

func clientTokenSelfBody(secret string, tokenType string, accessor string) string {
	body, _ := json.Marshal(map[string]any{"AccessorID": accessor, "SecretID": secret, "Type": tokenType, "Policies": []string{"es-submit"}})
	return string(body)
}

func TestVerifyAccessControlPassesOnlyOnALockedNomad(t *testing.T) {
	locked := accessControlScenario{
		selfStatus:      http.StatusOK,
		selfBody:        clientTokenSelfBody(testNomadToken, "client", "a1b2c3d4-0000-4000-8000-000000000001"),
		anonymousStatus: http.StatusNotFound,
		anonymousBody:   "ACL policy not found",
	}
	if err := newAccessControlScenarioClient(t, locked, nil).verifyAccessControl(context.Background()); err != nil {
		t.Fatalf("locked Nomad refused: %+v", err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*accessControlScenario)
	}{
		{name: "ACL system disabled", mutate: func(s *accessControlScenario) {
			s.selfBody = `{"AccessorID":"acls-disabled","SecretID":"","Name":"ACLs disabled token","Type":"client","Policies":null}`
		}},
		{name: "ACL system disabled echoing nothing back", mutate: func(s *accessControlScenario) {
			s.selfBody = `{"AccessorID":"acls-disabled","Type":"client"}`
		}},
		{name: "token resolved as anonymous", mutate: func(s *accessControlScenario) {
			s.selfBody = clientTokenSelfBody("", "client", "anonymous")
		}},
		{name: "token unknown to Nomad", mutate: func(s *accessControlScenario) {
			s.selfStatus, s.selfBody = http.StatusForbidden, "Permission denied"
		}},
		{name: "management token", mutate: func(s *accessControlScenario) {
			s.selfBody = clientTokenSelfBody(testNomadToken, "management", "a1b2c3d4-0000-4000-8000-000000000001")
		}},
		{name: "another token's secret", mutate: func(s *accessControlScenario) {
			s.selfBody = clientTokenSelfBody("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f1", "client", "a1b2c3d4-0000-4000-8000-000000000001")
		}},
		{name: "secret with a prefix of ours", mutate: func(s *accessControlScenario) {
			s.selfBody = clientTokenSelfBody(testNomadToken[:35], "client", "a1b2c3d4-0000-4000-8000-000000000001")
		}},
		{name: "empty accessor", mutate: func(s *accessControlScenario) {
			s.selfBody = clientTokenSelfBody(testNomadToken, "client", "")
		}},
		{name: "malformed token self body", mutate: func(s *accessControlScenario) { s.selfBody = `{"SecretID":` }},
		{name: "trailing document after token self", mutate: func(s *accessControlScenario) {
			s.selfBody = clientTokenSelfBody(testNomadToken, "client", "a1b2c3d4-0000-4000-8000-000000000001") + "{}"
		}},
		{name: "oversized token self body", mutate: func(s *accessControlScenario) {
			s.selfBody = `{"AccessorID":"a","SecretID":"` + testNomadToken + `","Type":"client","Pad":"` + strings.Repeat("x", int(maxDependencyJSONResponseBytes)) + `"}`
		}},
		{name: "anonymous policy present", mutate: func(s *accessControlScenario) {
			s.anonymousStatus, s.anonymousBody = http.StatusOK, `{"Name":"anonymous","Rules":"namespace \"default\" { policy = \"read\" }"}`
		}},
		{name: "anonymous policy lookup refused by a disabled ACL system", mutate: func(s *accessControlScenario) {
			s.anonymousStatus, s.anonymousBody = http.StatusBadRequest, "ACL support disabled"
		}},
		{name: "anonymous policy lookup forbidden", mutate: func(s *accessControlScenario) {
			s.anonymousStatus, s.anonymousBody = http.StatusForbidden, "Permission denied"
		}},
		{name: "anonymous policy lookup server error", mutate: func(s *accessControlScenario) {
			s.anonymousStatus, s.anonymousBody = http.StatusInternalServerError, "boom"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			scenario := locked
			test.mutate(&scenario)
			jobRequests := 0
			err := newAccessControlScenarioClient(t, scenario, &jobRequests).verifyAccessControl(context.Background())
			if err == nil {
				t.Fatal("unlocked or unverifiable Nomad accepted")
			}
			if err.Status != http.StatusServiceUnavailable || err.Code != codeExecutionRuntimeUnavailable || err.Message != nomadAccessControlCheckFailedMessage {
				t.Fatalf("refusal = %+v, want 503 %s %q", err, codeExecutionRuntimeUnavailable, nomadAccessControlCheckFailedMessage)
			}
			if strings.Contains(err.Message, testNomadToken) {
				t.Fatal("refusal message names the token")
			}
			if jobRequests != 0 {
				t.Fatalf("access-control check made %d job request(s)", jobRequests)
			}
		})
	}
}

func TestVerifyAccessControlSendsTheTokenOnlyToTokenSelf(t *testing.T) {
	var mu sync.Mutex
	headers := map[string][]string{}
	client := newUnwrappedTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		mu.Lock()
		headers[request.URL.Path] = request.Header.Values(nomadTokenHeader)
		mu.Unlock()
		if !serveNomadAccessControlRequest(t, w, request) {
			http.NotFound(w, request)
		}
	}))
	if err := client.verifyAccessControl(context.Background()); err != nil {
		t.Fatalf("locked Nomad refused: %+v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if got := headers["/v1/acl/token/self"]; len(got) != 1 || got[0] != testNomadToken {
		t.Fatalf("token self request carried %d token header(s) or the wrong token", len(got))
	}
	if got, ok := headers["/v1/acl/policy/anonymous"]; !ok || len(got) != 0 {
		t.Fatalf("anonymous policy request seen=%v carried %d token header(s)", ok, len(got))
	}
}

func TestVerifyAccessControlReportsAnUnreachableNomadAsUnavailable(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	baseURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	server.Close()
	client := &nomadClient{baseURL: baseURL, token: testNomadToken, client: &http.Client{}}
	accessErr := client.verifyAccessControl(context.Background())
	if accessErr == nil || accessErr.Status != http.StatusServiceUnavailable || accessErr.Code != codeExecutionRuntimeUnavailable ||
		accessErr.Message != "execution runtime is unavailable" {
		t.Fatalf("unreachable Nomad = %+v", accessErr)
	}
}

func TestNomadTokenIsAStartupPrerequisiteBeforeAnyRootIsProvisioned(t *testing.T) {
	workspace := physicalTestTempDir(t)
	stage := filepath.Join(workspace, "stage")
	results := filepath.Join(workspace, "results")
	// The staging root exists and the results root does not, so a configured
	// startup that gets past the token provisions the results root.
	if err := os.Mkdir(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := newExecutionRootStartupTestConfig(t, stage, results)
	tokenPath := cfg.Nomad.TokenFile
	assertRefusedBeforeEffects := func(label string, want string) {
		t.Helper()
		service, err := NewService(cfg)
		if err == nil || service != nil || !strings.Contains(err.Error(), want) ||
			strings.Contains(err.Error(), tokenPath) || strings.Contains(err.Error(), testNomadToken) {
			t.Fatalf("%s: startup did not refuse safely: service=%v err=%v", label, service != nil, err)
		}
		if _, err := os.Lstat(results); !os.IsNotExist(err) {
			t.Fatalf("%s: token prerequisite failure provisioned %s: %v", label, results, err)
		}
		if entries, err := os.ReadDir(stage); err != nil || len(entries) != 0 {
			t.Fatalf("%s: token prerequisite failure left staging effects: entries=%v err=%v", label, entries, err)
		}
	}

	if err := os.Remove(tokenPath); err != nil {
		t.Fatal(err)
	}
	assertRefusedBeforeEffects("absent token", "nomad token file is unavailable")

	if err := os.WriteFile(tokenPath, []byte(testNomadToken), 0o644); err != nil {
		t.Fatal(err)
	}
	assertRefusedBeforeEffects("readable by others", "nomad token file has unsafe identity, access or length")

	if err := os.Chmod(tokenPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if service, err := NewService(cfg); err != nil || service == nil || service.nomadClient == nil ||
		service.nomadClient.token != testNomadToken {
		t.Fatalf("startup with a private token did not load it: service=%v err=%v", service != nil, err)
	}
	if info, err := os.Lstat(results); err != nil || !info.IsDir() {
		t.Fatalf("startup with a private token did not provision %s: %v", results, err)
	}
}

func TestSubmitRefusesBeforeRunAssignmentWhenNomadAccessControlFails(t *testing.T) {
	cases := []struct {
		name      string
		scenario  accessControlScenario
		wantError string
	}{
		{
			name: "ACL system disabled",
			scenario: accessControlScenario{
				selfStatus:      http.StatusOK,
				selfBody:        `{"AccessorID":"acls-disabled","SecretID":"","Type":"","Name":"ACLs disabled"}`,
				anonymousStatus: http.StatusBadRequest,
				anonymousBody:   "ACL support disabled",
			},
			wantError: nomadAccessControlCheckFailedMessage,
		},
		{
			name: "anonymous policy present",
			scenario: accessControlScenario{
				selfStatus:      http.StatusOK,
				selfBody:        clientTokenSelfBody(testNomadToken, "client", "a1b2c3d4-0000-4000-8000-000000000001"),
				anonymousStatus: http.StatusOK,
				anonymousBody:   `{"Name":"anonymous","Rules":"namespace \"*\" { policy = \"write\" }"}`,
			},
			wantError: nomadAccessControlCheckFailedMessage,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newPreparedArtifactFixture(t)
			service, stagingRoot, _ := newWorkstreamCTestService(t, fixture)
			policyPayload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
				staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
			})
			service.arsClient = newResolvedPlanDependencyClient(t, resolvedPlanArtifactHandler(t, fixture, policyPayload, nil))
			jobRequests := 0
			service.nomadClient = newAccessControlScenarioClient(t, tc.scenario, &jobRequests)

			result, publicErr := service.Submit(context.Background(), fixture.prepareRequest())
			if publicErr == nil || publicErr.Status != http.StatusServiceUnavailable ||
				publicErr.Code != codeExecutionRuntimeUnavailable || publicErr.Message != tc.wantError {
				t.Fatalf("unexpected access-control refusal: %+v", publicErr)
			}
			if result != (SubmitResult{}) {
				t.Fatalf("access-control refusal returned a result: %+v", result)
			}
			if jobRequests != 0 {
				t.Fatalf("access-control refusal reached %d job endpoint request(s)", jobRequests)
			}
			entries, err := os.ReadDir(stagingRoot)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("access-control refusal claimed a staging run: %v", entries)
			}
		})
	}
}
