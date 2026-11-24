package app_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// continueTestAsRoot returns true when the test already runs as root. Else it
// runs the same test again as root through passwordless sudo, requires that
// run to pass, and returns false so the caller stops.
func continueTestAsRoot(t *testing.T, why string) bool {
	t.Helper()
	if os.Geteuid() == 0 {
		return true
	}
	if output, err := exec.Command("sudo", "-n", "true").CombinedOutput(); err != nil {
		t.Skipf("needs root or passwordless sudo %s: %v: %s", why, err, strings.TrimSpace(string(output)))
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

// Every check the setup wrapper runs, on its own and after provision or
// rotate, hands the tool the management token file, so the operator's check
// always includes the exclusive-writer probes and the token and policy
// checks that need it.
func TestNomadACLSetupWrapperChecksWithTheManagementToken(t *testing.T) {
	if !continueTestAsRoot(t, "to run the root-only setup wrapper") {
		return
	}
	repo := executionPlatformRepoRoot(t)
	root := t.TempDir()
	internal := filepath.Join(root, "scripts", "internal")
	if err := os.MkdirAll(internal, 0o755); err != nil {
		t.Fatal(err)
	}
	wrapper, err := os.ReadFile(filepath.Join(repo, "scripts", "nomad_acl_setup.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "scripts", "nomad_acl_setup.sh"), wrapper, 0o755); err != nil {
		t.Fatal(err)
	}
	// The stand-in tool records each invocation's arguments, one per line.
	if err := os.WriteFile(filepath.Join(internal, "nomad_acl.py"), []byte(
		"import os, sys\nwith open(os.environ['FAKE_TOOL_LOG'], 'a') as f:\n    f.write('\\x1f'.join(sys.argv[1:]) + '\\n')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	aclDir := filepath.Join(root, "acl")
	run := func(t *testing.T, args ...string) [][]string {
		t.Helper()
		log := filepath.Join(t.TempDir(), "tool.log")
		command := exec.Command("bash", append([]string{filepath.Join(root, "scripts", "nomad_acl_setup.sh")}, args...)...)
		command.Env = []string{"PATH=" + os.Getenv("PATH"), "NOMAD_ACL_DIR=" + aclDir, "ES_USER=root", "OBSERVER_USER=root", "FAKE_TOOL_LOG=" + log}
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("setup wrapper %v failed: %v output=%s", args, err, output)
		}
		data, err := os.ReadFile(log)
		if err != nil {
			t.Fatal(err)
		}
		var calls [][]string
		for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
			calls = append(calls, strings.Split(line, "\x1f"))
		}
		return calls
	}
	hasPair := func(call []string, flag string, value string) bool {
		for i := 0; i+1 < len(call); i++ {
			if call[i] == flag && call[i+1] == value {
				return true
			}
		}
		return false
	}
	management := filepath.Join(aclDir, "management-token")
	for _, test := range []struct {
		name    string
		args    []string
		actions []string
	}{
		{"check", []string{"check"}, []string{"check"}},
		{"provision", nil, []string{"provision", "check"}},
		{"rotate", []string{"rotate"}, []string{"provision", "check"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := run(t, test.args...)
			if len(calls) != len(test.actions) {
				t.Fatalf("wrapper ran the tool %d time(s), want %v: %q", len(calls), test.actions, calls)
			}
			for i, call := range calls {
				if call[0] != test.actions[i] || !hasPair(call, "--management-token-file", management) ||
					!hasPair(call, "--observer-token-file", filepath.Join(aclDir, "observer-token")) ||
					!hasPair(call, "--nomad-uid", "0") {
					t.Fatalf("tool call %d = %q, want %s with the management and observer token files and Nomad's uid 0", i, call, test.actions[i])
				}
			}
		})
	}
}

// The shell helpers that send a token to Nomad ignore proxy settings: with
// every proxy variable pointing at a listener and a Nomad address that does
// not resolve, the request fails without reaching the listener.
func TestNomadACLShellHelpersIgnoreProxySettings(t *testing.T) {
	repo := executionPlatformRepoRoot(t)
	var requests atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"AccessorID":"anonymous","Type":"client"}`))
	}))
	defer proxy.Close()
	tokenFile := writeFakeNomadObserverTokenFile(t, t.TempDir())
	for _, call := range []string{
		`nomad_api_get /v1/agent/self "$OUT"`,
		`nomad_acl_state_check`,
	} {
		t.Run(strings.Fields(call)[0], func(t *testing.T) {
			before := requests.Load()
			command := exec.Command("bash", "-c", `source "$1"; `+call, "bash", filepath.Join(repo, "scripts", "internal", "nomad_acl.sh"))
			command.Env = []string{
				"PATH=" + os.Getenv("PATH"),
				"NOMAD_ADDR=http://nomad-proxy-probe.invalid:4646",
				"NOMAD_TOKEN_FILE=" + tokenFile,
				"OUT=" + filepath.Join(t.TempDir(), "out.json"),
				"http_proxy=" + proxy.URL, "HTTP_PROXY=" + proxy.URL,
				"https_proxy=" + proxy.URL, "HTTPS_PROXY=" + proxy.URL,
				"all_proxy=" + proxy.URL, "ALL_PROXY=" + proxy.URL,
				"no_proxy=", "NO_PROXY=",
			}
			output, err := command.CombinedOutput()
			if err == nil {
				t.Fatalf("%s reached an unresolvable Nomad address: output=%s", call, output)
			}
			if got := requests.Load() - before; got != 0 {
				t.Fatalf("%s sent %d request(s) to the proxy: output=%s", call, got, output)
			}
		})
	}
}

// The token directory check refuses a directory inside, equal to or above
// any one of the scopes it is given, each on its own.
func TestNomadACLDirPlacementRefusesEveryScope(t *testing.T) {
	repo := executionPlatformRepoRoot(t)
	scopes := []string{"/srv/proof", "/srv/staging", "/srv/results", "/run/spire/sockets"}
	check := func(aclDir string) (string, error) {
		command := exec.Command("bash", "-c", `source "$1"; shift; nomad_acl_validate_dir_placement "$@"`, "bash",
			filepath.Join(repo, "scripts", "internal", "nomad_acl.sh"), aclDir, scopes[0], scopes[1], scopes[2], scopes[3])
		command.Env = []string{"PATH=" + os.Getenv("PATH")}
		output, err := command.CombinedOutput()
		return string(output), err
	}
	if output, err := check("/etc/execution-substrate/nomad-acl"); err != nil {
		t.Fatalf("a token directory outside every scope was refused: %v output=%s", err, output)
	}
	for _, scope := range scopes {
		for _, aclDir := range []string{scope, scope + "/nomad-acl", filepath.Dir(scope)} {
			if output, err := check(aclDir); err == nil || !strings.Contains(output, "outside the proof, staging, results and SPIRE socket directories") {
				t.Fatalf("token directory %s overlapping scope %s accepted: %v output=%s", aclDir, scope, err, output)
			}
		}
	}
}
