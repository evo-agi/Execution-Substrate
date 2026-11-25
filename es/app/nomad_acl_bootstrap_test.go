package app_test

import (
	"crypto/tls"
	"encoding/json"
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

// An ACL bootstrap can fail before Nomad installs the secret that was saved
// for it: Nomad has no leader yet, or the response is lost. These tests pin
// that both bootstrap paths (the setup script's and the operator tool's) wait
// for a named leader or can be rerun to finish such a bootstrap, and that
// neither reuses a saved secret on a Nomad someone else bootstrapped.

// runSetupNomadACLBootstrap runs the setup script's bootstrap_nomad_acl on its
// own, with sudo running its command as the test user, whose uid the test
// Nomads run as. aclDir must exist.
func runSetupNomadACLBootstrap(t *testing.T, addr string, caFile string, aclDir string, leaderWaitSeconds int) (string, error) {
	t.Helper()
	return runSetupNomadACLSnippet(t, addr, caFile, aclDir, leaderWaitSeconds, os.Geteuid(), `bootstrap_nomad_acl
if [[ "${NOMAD_QUALIFY_TOKEN}" == "$(cat "${NOMAD_ACL_MANAGEMENT_TOKEN_FILE}")" ]]; then
  echo "qualify token is the saved management token"
fi`)
}

// runSetupNomadACLSnippet runs a snippet with the setup script's
// nomad_acl_bootstrap functions and its CPU visibility diagnostics defined,
// expecting Nomad's listener to belong to nomadUID and its certificate to
// come from caFile's CA.
func runSetupNomadACLSnippet(t *testing.T, addr string, caFile string, aclDir string, leaderWaitSeconds int, nomadUID int, call string) (string, error) {
	t.Helper()
	setup := filepath.Join(executionPlatformRepoRootPath(), "scripts", "70_linux_setup.sh")
	snippet := `set -euo pipefail
sudo() { "$@"; }
cleanup_tempfiles() { rm -f "$@"; }
eval "$(sed -n '/^# BEGIN nomad_acl_bootstrap/,/^# END nomad_acl_bootstrap/p' "$1")"
eval "$(sed -n '/^# BEGIN nomad_cpu_visibility_diagnostics/,/^# END nomad_cpu_visibility_diagnostics/p' "$1")"
` + call
	command := exec.Command("bash", "-c", snippet, "bash", setup)
	command.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"NOMAD_HTTP_ADDR=" + addr,
		"NOMAD_CACERT=" + caFile,
		"NOMAD_ACL_DIR=" + aclDir,
		"NOMAD_ACL_MANAGEMENT_TOKEN_FILE=" + filepath.Join(aclDir, "management-token"),
		"NOMAD_LEADER_WAIT_SECONDS=" + strconv.Itoa(leaderWaitSeconds),
		"NOMAD_SERVICE_UID=" + strconv.Itoa(nomadUID),
	}
	output, err := command.CombinedOutput()
	return string(output), err
}

func newNomadACLDir(t *testing.T) string {
	t.Helper()
	aclDir := filepath.Join(t.TempDir(), "nomad-acl")
	if err := os.Mkdir(aclDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return aclDir
}

// writeUnissuedManagementToken leaves what a bootstrap that never took effect
// leaves: a saved secret that Nomad does not know.
func writeUnissuedManagementToken(t *testing.T, aclDir string) string {
	t.Helper()
	secret := newRandomNomadToken()
	if err := os.WriteFile(filepath.Join(aclDir, "management-token"), []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return secret
}

func requireNomadManagementToken(t *testing.T, label string, harness *nomadHarness, token string) {
	t.Helper()
	status, body := nomadRawRequest(t, http.MethodGet, harness.addr+"/v1/acl/token/self", token, nil)
	var self struct {
		Type string `json:"Type"`
	}
	if status != http.StatusOK || json.Unmarshal([]byte(body), &self) != nil || self.Type != "management" {
		t.Fatalf("%s: the saved secret is not Nomad's management token: HTTP %d %s", label, status, body)
	}
}

// TestLinuxSetupBootstrapsNomadACLOnlyOnceNomadNamesALeader: Nomad answers
// /v1/status/leader with "" while it elects a leader. The setup script must
// not take that for a leader: it waits, and bootstraps only after Nomad
// names one.
func TestLinuxSetupBootstrapsNomadACLOnlyOnceNomadNamesALeader(t *testing.T) {
	var mu sync.Mutex
	var log []string
	leaderAnswers := 0
	namedAfter := -1 // -1: never name a leader
	var bootstrapSecret string
	server, material := startNomadTLSStandIn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/status/leader":
			leaderAnswers++
			if namedAfter >= 0 && leaderAnswers > namedAfter {
				log = append(log, "leader named")
				_ = json.NewEncoder(w).Encode("127.0.0.1:4647")
				return
			}
			log = append(log, "leader empty")
			_ = json.NewEncoder(w).Encode("")
		case "/v1/acl/token/self":
			log = append(log, "token/self")
			http.Error(w, "ACL token not found", http.StatusForbidden)
		case "/v1/acl/bootstrap":
			log = append(log, "bootstrap")
			var request struct {
				BootstrapSecret string `json:"BootstrapSecret"`
			}
			_ = json.NewDecoder(r.Body).Decode(&request)
			bootstrapSecret = request.BootstrapSecret
			_ = json.NewEncoder(w).Encode(map[string]any{"SecretID": request.BootstrapSecret, "Type": "management"})
		default:
			log = append(log, "unexpected "+r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	snapshot := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), log...)
	}

	// Nomad never names a leader: the bounded wait gives up and nothing else
	// happens.
	aclDir := newNomadACLDir(t)
	output, err := runSetupNomadACLBootstrap(t, server.URL, material.caFile, aclDir, 2)
	if err == nil || !strings.Contains(output, "nomad: no leader within 2s, so ACLs cannot be bootstrapped") {
		t.Fatalf("bootstrap went on without a named leader: %v output=%s", err, output)
	}
	for _, entry := range snapshot() {
		if entry != "leader empty" {
			t.Fatalf("bootstrap sent more than leader requests to a Nomad without a leader: %v", snapshot())
		}
	}
	if _, err := os.Lstat(filepath.Join(aclDir, "management-token")); !os.IsNotExist(err) {
		t.Fatalf("bootstrap saved a management token without a leader: %v", err)
	}

	// Nomad names a leader on the third answer: bootstrap waits for it, then
	// bootstraps with the secret it saved.
	mu.Lock()
	log, leaderAnswers, namedAfter = nil, 0, 2
	mu.Unlock()
	output, err = runSetupNomadACLBootstrap(t, server.URL, material.caFile, aclDir, 10)
	if err != nil || !strings.Contains(output, "nomad acl: bootstrapped") || !strings.Contains(output, "qualify token is the saved management token") {
		t.Fatalf("bootstrap failed once Nomad named a leader: %v output=%s", err, output)
	}
	if got, want := strings.Join(snapshot(), ", "), "leader empty, leader empty, leader named, token/self, bootstrap"; got != want {
		t.Fatalf("bootstrap requests were %q, want %q", got, want)
	}
	saved, err := os.ReadFile(filepath.Join(aclDir, "management-token"))
	if err != nil || strings.TrimSpace(string(saved)) != bootstrapSecret {
		t.Fatalf("bootstrap did not send the secret it saved: %v", err)
	}
}

// TestLinuxSetupBootstrapFinishesWithItsSavedSecret runs the setup script's
// bootstrap against a real Nomad that a failed attempt left unbootstrapped
// with a saved secret, and against one bootstrapped by someone else.
func TestLinuxSetupBootstrapFinishesWithItsSavedSecret(t *testing.T) {
	harness := startNomadHarnessWithOptions(t, newExecutionWorkspaceTempDir(t, "nomad-acl-bootstrap-"), nomadHarnessOptions{aclUnbootstrapped: true, leaderOnly: true})
	t.Cleanup(harness.stop)
	aclDir := newNomadACLDir(t)
	secret := writeUnissuedManagementToken(t, aclDir)

	output, err := runSetupNomadACLBootstrap(t, harness.addr, harness.tls.caFile, aclDir, 30)
	if err != nil || !strings.Contains(output, "nomad acl: bootstrapped") || !strings.Contains(output, "qualify token is the saved management token") {
		t.Fatalf("bootstrap did not finish with the saved secret: %v output=%s", err, output)
	}
	requireNomadManagementToken(t, "setup bootstrap", harness, secret)
	output, err = runSetupNomadACLBootstrap(t, harness.addr, harness.tls.caFile, aclDir, 30)
	if err != nil || !strings.Contains(output, "nomad acl: enforced") {
		t.Fatalf("a rerun did not keep the management token: %v output=%s", err, output)
	}

	stranger := writeUnissuedManagementToken(t, aclDir)
	output, err = runSetupNomadACLBootstrap(t, harness.addr, harness.tls.caFile, aclDir, 30)
	if err == nil || !strings.Contains(output, "ACLs were bootstrapped before") {
		t.Fatalf("bootstrap accepted a saved secret on a Nomad bootstrapped with another: %v output=%s", err, output)
	}
	if kept, err := os.ReadFile(filepath.Join(aclDir, "management-token")); err != nil || strings.TrimSpace(string(kept)) != stranger {
		t.Fatalf("refused bootstrap changed the operator's management token file: %v", err)
	}
}

// TestNomadACLToolRetriesABootstrapThatNeverTookEffect: the operator tool
// saves its secret before it bootstraps. If that bootstrap never took effect,
// a rerun offers the saved secret again and finishes; on a Nomad that someone
// else bootstrapped it refuses and keeps the file.
func TestNomadACLToolRetriesABootstrapThatNeverTookEffect(t *testing.T) {
	harness := startNomadHarnessWithOptions(t, newExecutionWorkspaceTempDir(t, "nomad-acl-bootstrap-"), nomadHarnessOptions{aclUnbootstrapped: true, leaderOnly: true})
	t.Cleanup(harness.stop)
	aclDir := newNomadACLDir(t)
	secret := writeUnissuedManagementToken(t, aclDir)
	owner := strconv.Itoa(os.Geteuid()) + ":" + strconv.Itoa(os.Getegid())
	provision := func() (string, error) {
		return runNomadACLTool(t, "provision", "--addr", harness.addr, "--ca-file", harness.tls.caFile,
			"--management-token-file", filepath.Join(aclDir, "management-token"),
			"--es-token-file", filepath.Join(aclDir, "es-token"), "--es-token-owner", owner)
	}

	output, err := provision()
	if err != nil || !strings.Contains(output, "nomad acl: bootstrapped") {
		t.Fatalf("provision did not finish the bootstrap with the saved secret: %v output=%s", err, output)
	}
	requireNomadManagementToken(t, "tool bootstrap", harness, secret)
	if kept, err := os.ReadFile(filepath.Join(aclDir, "management-token")); err != nil || strings.TrimSpace(string(kept)) != secret {
		t.Fatalf("provision replaced the saved management token: %v", err)
	}

	stranger := writeUnissuedManagementToken(t, aclDir)
	output, err = provision()
	if err == nil || !strings.Contains(output, "does not hold a working Nomad management token and nomad ACLs were already bootstrapped") {
		t.Fatalf("provision accepted a saved secret on a Nomad bootstrapped with another: %v output=%s", err, output)
	}
	if kept, err := os.ReadFile(filepath.Join(aclDir, "management-token")); err != nil || strings.TrimSpace(string(kept)) != stranger {
		t.Fatalf("refused provision changed the operator's management token file: %v", err)
	}
	requireNomadManagementToken(t, "after the refusal", harness, secret)

	// A token Nomad knows but that is not a management token (here ES's own)
	// is not taken for one.
	esToken := readNomadTokenFile(t, filepath.Join(aclDir, "es-token"))
	if err := os.WriteFile(filepath.Join(aclDir, "management-token"), []byte(esToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err = provision()
	if err == nil || !strings.Contains(output, "does not hold a working Nomad management token and nomad ACLs were already bootstrapped") {
		t.Fatalf("provision took a client token for the management token: %v output=%s", err, output)
	}
	if kept, err := os.ReadFile(filepath.Join(aclDir, "management-token")); err != nil || strings.TrimSpace(string(kept)) != esToken {
		t.Fatalf("refused provision changed the management token file holding a client token: %v", err)
	}
}

// recordingNomadStandIn is a TLS 1.3 stand-in on loopback with a certificate
// from fresh Nomad TLS material, run by the test's own user. answer handles
// each request after it is logged; the log keeps every request's path, token
// header and body. hellos counts the TLS handshakes clients began.
type recordingNomadStandIn struct {
	*httptest.Server
	material nomadTLSMaterial
	mu       sync.Mutex
	log      []string
	hellos   atomic.Int32
}

func startRecordingNomadStandIn(t *testing.T, answer func(w http.ResponseWriter, r *http.Request, seen int)) *recordingNomadStandIn {
	t.Helper()
	material, err := issueNomadTLSMaterial(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.LoadX509KeyPair(material.certFile, material.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	standIn := &recordingNomadStandIn{material: material}
	standIn.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		standIn.mu.Lock()
		standIn.log = append(standIn.log, r.Method+" "+r.URL.Path+" token="+r.Header.Get("X-Nomad-Token")+" body="+string(body))
		seen := len(standIn.log)
		standIn.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		answer(w, r, seen)
	}))
	standIn.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			standIn.hellos.Add(1)
			return nil, nil
		},
	}
	standIn.StartTLS()
	t.Cleanup(standIn.Close)
	return standIn
}

func (s *recordingNomadStandIn) requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.log...)
}

func (s *recordingNomadStandIn) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.log = nil
	s.hellos.Store(0)
}

// TestNomadACLToolSendsNothingToAPortHolder: while Nomad is down any local
// account can listen on its port. TLS keeps a holder without Nomad's server
// key from passing for Nomad; as a second guard the tool asks the kernel who
// owns the socket that accepted its connection and sends nothing unless that
// is Nomad's user: no management token, no bootstrap secret, not even a TLS
// handshake. This stand-in holds a certificate from the CA the tool trusts, so
// only the owner check stops it.
func TestNomadACLToolSendsNothingToAPortHolder(t *testing.T) {
	standIn := startRecordingNomadStandIn(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		switch r.URL.Path {
		case "/v1/status/leader":
			_ = json.NewEncoder(w).Encode("127.0.0.1:4647")
		case "/v1/acl/token/self":
			_ = json.NewEncoder(w).Encode(map[string]any{"AccessorID": "anonymous", "Type": "client"})
		default:
			http.Error(w, "Permission denied", http.StatusForbidden)
		}
	})
	notNomads := strconv.Itoa(os.Geteuid() + 1)
	owner := strconv.Itoa(os.Geteuid()) + ":" + strconv.Itoa(os.Getegid())
	aclDir := newNomadACLDir(t)
	management := filepath.Join(aclDir, "management-token")
	provision := func(nomadUID string) (string, error) {
		return runNomadACLTool(t, "provision", "--nomad-uid", nomadUID, "--addr", standIn.URL, "--ca-file", standIn.material.caFile, "--leader-wait-seconds", "1",
			"--management-token-file", management,
			"--es-token-file", filepath.Join(aclDir, "es-token"), "--es-token-owner", owner)
	}
	refused := func(label string, output string, err error) {
		t.Helper()
		if err == nil || !strings.Contains(output, "not Nomad's uid "+notNomads) || !strings.Contains(output, "nothing was sent") {
			t.Fatalf("%s: the tool did not refuse a listener another user owns: %v output=%s", label, err, output)
		}
		if got := standIn.requests(); len(got) != 0 {
			t.Fatalf("%s: the port holder received %q", label, got)
		}
		if got := standIn.hellos.Load(); got != 0 {
			t.Fatalf("%s: the port holder saw %d TLS handshake(s)", label, got)
		}
	}

	// First run: no bootstrap secret is generated, saved or sent.
	output, err := provision(notNomads)
	refused("first run", output, err)
	if _, err := os.Lstat(management); !os.IsNotExist(err) {
		t.Fatalf("first run saved a management token for a listener that is not Nomad's: %v", err)
	}

	// A saved management token is not sent, by provision or by check.
	saved := writeUnissuedManagementToken(t, aclDir)
	output, err = provision(notNomads)
	refused("provision with a saved token", output, err)
	esToken := writeFakeNomadTokenFile(t, t.TempDir())
	output, err = runNomadACLTool(t, "check", "--nomad-uid", notNomads, "--addr", standIn.URL, "--ca-file", standIn.material.caFile,
		"--es-token-file", esToken, "--management-token-file", management)
	refused("check", output, err)

	// The case as it happens on a host: root runs the tool with its default
	// (Nomad runs as root) while another account holds the port. Here the
	// holder is the test's user and root comes from passwordless sudo.
	if os.Geteuid() != 0 && exec.Command("sudo", "-n", "true").Run() == nil {
		output, err := exec.Command("sudo", "-n", "python3", "-I", nomadACLToolPath(), "provision",
			"--addr", standIn.URL, "--ca-file", standIn.material.caFile, "--leader-wait-seconds", "1",
			"--management-token-file", filepath.Join(aclDir, "root-management-token"),
			"--es-token-file", filepath.Join(aclDir, "root-es-token"), "--es-token-owner", "0:0").CombinedOutput()
		if err == nil || !strings.Contains(string(output), "runs as uid "+strconv.Itoa(os.Geteuid())+", not Nomad's uid 0") {
			t.Fatalf("root's run did not refuse a port the test's user holds: %v output=%s", err, output)
		}
		if got := standIn.requests(); len(got) != 0 || standIn.hellos.Load() != 0 {
			t.Fatalf("root's run sent the port holder %q (%d TLS handshake(s))", got, standIn.hellos.Load())
		}
		if _, err := os.Lstat(filepath.Join(aclDir, "root-management-token")); !os.IsNotExist(err) {
			t.Fatalf("root's run saved a management token for a listener that is not Nomad's: %v", err)
		}
	} else {
		t.Log("root and another account cannot both be had here; the case with root as the caller is not run")
	}

	// Control: with the listener's real owner named, the same stand-in gets
	// the tool's requests, so the refusals above came from the owner check.
	output, err = provision(strconv.Itoa(os.Geteuid()))
	if got := standIn.requests(); len(got) == 0 || !strings.Contains(strings.Join(got, "\n"), "token="+saved) {
		t.Fatalf("control: the tool did not reach a listener the named user owns: %v output=%s requests=%q", err, output, got)
	}
}

// TestLinuxSetupBootstrapSendsNoSecretToAPortHolder: the setup script's
// bootstrap and every token-bearing request it makes check that Nomad's user
// (root on a host) owns the listener first.
// TestLinuxSetupChecksNomadsListenerBeforeEveryTokenSend pins where the
// checks sit.
func TestLinuxSetupBootstrapSendsNoSecretToAPortHolder(t *testing.T) {
	standIn := startRecordingNomadStandIn(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		if r.URL.Path == "/v1/status/leader" {
			_ = json.NewEncoder(w).Encode("127.0.0.1:4647")
			return
		}
		http.Error(w, "ACL token not found", http.StatusForbidden)
	})
	notNomads := os.Geteuid() + 1
	aclDir := newNomadACLDir(t)
	output, err := runSetupNomadACLSnippet(t, standIn.URL, standIn.material.caFile, aclDir, 5, notNomads, "bootstrap_nomad_acl")
	if err == nil || !strings.Contains(output, "not owned by Nomad's user (uid "+strconv.Itoa(notNomads)+")") {
		t.Fatalf("bootstrap did not refuse a listener another user owns: %v output=%s", err, output)
	}
	for _, request := range standIn.requests() {
		if !strings.HasPrefix(request, "GET /v1/status/leader token= ") {
			t.Fatalf("the port holder received more than leader questions: %q", standIn.requests())
		}
	}
	if _, err := os.Lstat(filepath.Join(aclDir, "management-token")); !os.IsNotExist(err) {
		t.Fatalf("bootstrap saved a secret for a listener that is not Nomad's: %v", err)
	}

	// The qualification requests send the management token through
	// nomad_token_curl, which checks too.
	standIn.reset()
	output, err = runSetupNomadACLSnippet(t, standIn.URL, standIn.material.caFile, aclDir, 5, notNomads,
		`nomad_token_curl "$(cat /proc/sys/kernel/random/uuid)" --silent "${NOMAD_HTTP_ADDR}/v1/agent/self"`)
	if err == nil || !strings.Contains(output, "not owned by Nomad's user") || len(standIn.requests()) != 0 {
		t.Fatalf("nomad_token_curl sent a token to a listener another user owns: %v output=%s requests=%q", err, output, standIn.requests())
	}
	output, err = runSetupNomadACLSnippet(t, standIn.URL, standIn.material.caFile, aclDir, 5, os.Geteuid(),
		`nomad_token_curl "$(cat /proc/sys/kernel/random/uuid)" --silent "${NOMAD_HTTP_ADDR}/v1/agent/self"`)
	if err != nil || len(standIn.requests()) != 1 {
		t.Fatalf("control: nomad_token_curl did not reach a listener Nomad's user owns: %v output=%s requests=%q", err, output, standIn.requests())
	}

	// Setup runs the CPU visibility diagnostics when qualification fails,
	// which can happen after the bootstrap set the management token, for
	// example because Nomad stopped. They ask Nomad for its nodes with that
	// token, so they check the listener too. The call is the script's own:
	// report_nomad_cpu_visibility_diagnostics || true.
	qualifyToken := newRandomNomadToken()
	if err := os.WriteFile(filepath.Join(aclDir, "qualify-token"), []byte(qualifyToken), 0o600); err != nil {
		t.Fatal(err)
	}
	diagnostics := `NOMAD_QUALIFY_TOKEN="$(cat "${NOMAD_ACL_DIR}/qualify-token")"
report_nomad_cpu_visibility_diagnostics || true`
	standIn.reset()
	output, err = runSetupNomadACLSnippet(t, standIn.URL, standIn.material.caFile, aclDir, 5, notNomads, diagnostics)
	if err != nil || !strings.Contains(output, "not owned by Nomad's user (uid "+strconv.Itoa(notNomads)+")") || len(standIn.requests()) != 0 {
		t.Fatalf("the diagnostics sent the management token to a listener another user owns: %v output=%s requests=%q", err, output, standIn.requests())
	}
	output, err = runSetupNomadACLSnippet(t, standIn.URL, standIn.material.caFile, aclDir, 5, os.Geteuid(), diagnostics)
	if got := standIn.requests(); err != nil || len(got) == 0 || got[0] != "GET /v1/nodes token="+qualifyToken+" body=" {
		t.Fatalf("control: the diagnostics did not ask a listener Nomad's user owns for its nodes: %v output=%s requests=%q", err, output, got)
	}
}

// TestNomadACLToolWaitsForANamedLeader: provision waits for Nomad to name a
// leader before it bootstraps, and a refusal quotes Nomad's own answer.
func TestNomadACLToolWaitsForANamedLeader(t *testing.T) {
	var mode atomic.Int32
	standIn := startRecordingNomadStandIn(t, func(w http.ResponseWriter, r *http.Request, seen int) {
		switch {
		case r.URL.Path == "/v1/status/leader" && mode.Load() == 0:
			http.Error(w, "No cluster leader", http.StatusInternalServerError)
		case r.URL.Path == "/v1/status/leader" && mode.Load() == 1 && seen <= 2:
			_ = json.NewEncoder(w).Encode("")
		case r.URL.Path == "/v1/status/leader":
			_ = json.NewEncoder(w).Encode("127.0.0.1:4647")
		case r.URL.Path == "/v1/acl/token/self" && mode.Load() == 1:
			_ = json.NewEncoder(w).Encode(map[string]any{"AccessorID": "acls-disabled"})
		case r.URL.Path == "/v1/acl/token/self":
			http.Error(w, "No cluster leader", http.StatusInternalServerError)
		default:
			http.Error(w, "unexpected", http.StatusTeapot)
		}
	})
	owner := strconv.Itoa(os.Geteuid()) + ":" + strconv.Itoa(os.Getegid())
	aclDir := newNomadACLDir(t)
	management := filepath.Join(aclDir, "management-token")
	provision := func() (string, error) {
		return runNomadACLTool(t, "provision", "--addr", standIn.URL, "--ca-file", standIn.material.caFile, "--leader-wait-seconds", "2",
			"--management-token-file", management,
			"--es-token-file", filepath.Join(aclDir, "es-token"), "--es-token-owner", owner)
	}
	paths := func() string {
		var out []string
		for _, request := range standIn.requests() {
			out = append(out, strings.Fields(request)[1])
		}
		return strings.Join(out, ", ")
	}

	// No leader at all: the bounded wait refuses with Nomad's answer, after
	// asking only for the leader, and saves no secret.
	output, err := provision()
	if err == nil || !strings.Contains(output, "nomad has no leader after 2s (GET /v1/status/leader returned HTTP 500: No cluster leader)") {
		t.Fatalf("provision did not refuse a Nomad without a leader: %v output=%s", err, output)
	}
	if got := paths(); strings.Trim(strings.ReplaceAll(got, "/v1/status/leader", ""), ", ") != "" {
		t.Fatalf("provision asked more than the leader of a Nomad without one: %s", got)
	}
	if _, err := os.Lstat(management); !os.IsNotExist(err) {
		t.Fatalf("provision saved a secret without a leader: %v", err)
	}

	// "" while electing, then a named leader: provision waits for the name.
	standIn.reset()
	mode.Store(1)
	output, err = provision()
	if err == nil || !strings.Contains(output, "nomad ACLs are disabled") {
		t.Fatalf("provision did not go on once Nomad named a leader: %v output=%s", err, output)
	}
	if got, want := paths(), "/v1/status/leader, /v1/status/leader, /v1/status/leader, /v1/acl/token/self"; got != want {
		t.Fatalf("provision requests were %q, want %q", got, want)
	}

	// An error from the ACL question is quoted, not reported as ACLs being off.
	standIn.reset()
	mode.Store(2)
	output, err = provision()
	if err == nil || !strings.Contains(output, "GET /v1/acl/token/self returned HTTP 500: No cluster leader") {
		t.Fatalf("provision did not quote Nomad's error: %v output=%s", err, output)
	}
}
