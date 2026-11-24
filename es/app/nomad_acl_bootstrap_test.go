package app_test

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// An ACL bootstrap can fail before Nomad installs the secret that was saved
// for it: Nomad has no leader yet, or the response is lost. These tests pin
// that both bootstrap paths (the setup script's and the operator tool's) wait
// for a named leader or can be rerun to finish such a bootstrap, and that
// neither reuses a saved secret on a Nomad someone else bootstrapped.

// runSetupNomadACLBootstrap runs the setup script's bootstrap_nomad_acl on its
// own, with sudo running its command as the test user. aclDir must exist.
func runSetupNomadACLBootstrap(t *testing.T, addr string, caFile string, aclDir string, leaderWaitSeconds int) (string, error) {
	t.Helper()
	setup := filepath.Join(executionPlatformRepoRootPath(), "scripts", "70_linux_setup.sh")
	snippet := `set -euo pipefail
sudo() { "$@"; }
cleanup_tempfiles() { rm -f "$@"; }
eval "$(sed -n '/^# BEGIN nomad_acl_bootstrap/,/^# END nomad_acl_bootstrap/p' "$1")"
bootstrap_nomad_acl
if [[ "${NOMAD_QUALIFY_TOKEN}" == "$(cat "${NOMAD_ACL_MANAGEMENT_TOKEN_FILE}")" ]]; then
  echo "qualify token is the saved management token"
fi`
	command := exec.Command("bash", "-c", snippet, "bash", setup)
	command.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"NOMAD_HTTP_ADDR=" + addr,
		"NOMAD_CACERT=" + caFile,
		"NOMAD_ACL_DIR=" + aclDir,
		"NOMAD_ACL_MANAGEMENT_TOKEN_FILE=" + filepath.Join(aclDir, "management-token"),
		"NOMAD_LEADER_WAIT_SECONDS=" + strconv.Itoa(leaderWaitSeconds),
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
}
