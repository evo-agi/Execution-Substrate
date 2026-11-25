package app_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
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
	run := func(t *testing.T, env []string, args ...string) [][]string {
		t.Helper()
		log := filepath.Join(t.TempDir(), "tool.log")
		command := exec.Command("bash", append([]string{filepath.Join(root, "scripts", "nomad_acl_setup.sh")}, args...)...)
		command.Env = append([]string{"PATH=" + os.Getenv("PATH"), "NOMAD_ACL_DIR=" + aclDir, "ES_USER=root", "OBSERVER_USER=root", "FAKE_TOOL_LOG=" + log}, env...)
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
			calls := run(t, nil, test.args...)
			if len(calls) != len(test.actions) {
				t.Fatalf("wrapper ran the tool %d time(s), want %v: %q", len(calls), test.actions, calls)
			}
			for i, call := range calls {
				if call[0] != test.actions[i] || !hasPair(call, "--management-token-file", management) ||
					!hasPair(call, "--observer-token-file", filepath.Join(aclDir, "observer-token")) ||
					!hasPair(call, "--nomad-uid", "0") || !hasPair(call, "--addr", "https://127.0.0.1:4646") ||
					!hasPair(call, "--ca-file", "/etc/nomad.d/tls/ca.pem") {
					t.Fatalf("tool call %d = %q, want %s with the management and observer token files, Nomad's uid 0, its default HTTPS address and CA", i, call, test.actions[i])
				}
			}
		})
	}
	// placement reads node state with the observer token and plans with ES's
	// token; it never gets the management token. ES's config and the time of
	// the latest Nomad start come from the environment.
	for _, test := range []struct {
		name string
		env  []string
		want [][2]string
	}{
		{"placement", nil, [][2]string{{"--addr", "https://127.0.0.1:4646"}, {"--ca-file", "/etc/nomad.d/tls/ca.pem"},
			{"--es-config", "/etc/execution-substrate/es.json"}, {"--fresh-after", "0"}, {"--wait-seconds", "60"}}},
		{"placement after a start", []string{"ES_CONFIG=/srv/es/es.json", "NOMAD_STARTED_AT=1764022640", "NOMAD_PLACEMENT_WAIT_SECONDS=120",
			"NOMAD_ADDR=https://[::1]:4747", "NOMAD_CACERT=/srv/nomad/tls/ca.pem"},
			[][2]string{{"--addr", "https://[::1]:4747"}, {"--ca-file", "/srv/nomad/tls/ca.pem"},
				{"--es-config", "/srv/es/es.json"}, {"--fresh-after", "1764022640"}, {"--wait-seconds", "120"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := run(t, test.env, "placement")
			if len(calls) != 1 || calls[0][0] != "placement" || slices.Contains(calls[0], "--management-token-file") ||
				!hasPair(calls[0], "--es-token-file", filepath.Join(aclDir, "es-token")) ||
				!hasPair(calls[0], "--observer-token-file", filepath.Join(aclDir, "observer-token")) ||
				!hasPair(calls[0], "--nomad-uid", "0") {
				t.Fatalf("wrapper placement ran %q, want one placement call with the ES and observer token files only", calls)
			}
			for _, pair := range test.want {
				if !hasPair(calls[0], pair[0], pair[1]) {
					t.Fatalf("wrapper placement call %q lacks %s %s", calls[0], pair[0], pair[1])
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
	nomadTLS, err := issueNomadTLSMaterial(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	caFile := nomadTLS.caFile
	for _, call := range []string{
		`nomad_api_get /v1/agent/self "$OUT"`,
		`nomad_acl_state_check`,
	} {
		t.Run(strings.Fields(call)[0], func(t *testing.T) {
			before := requests.Load()
			command := exec.Command("bash", "-c", `source "$1"; `+call, "bash", filepath.Join(repo, "scripts", "internal", "nomad_acl.sh"))
			command.Env = []string{
				"PATH=" + os.Getenv("PATH"),
				"NOMAD_ADDR=https://nomad-proxy-probe.invalid:4646",
				"NOMAD_CACERT=" + caFile,
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

// The shell helpers send requests to Nomad only over TLS 1.3, trusting only
// NOMAD_CACERT. They refuse a plain-HTTP NOMAD_ADDR and a CA file that is
// missing or a symbolic link before any request; a Nomad whose certificate
// another CA signed, or that offers only TLS 1.2, fails the handshake, so no
// request (and no token) reaches it. With Nomad's own CA the token arrives.
func TestNomadShellHelpersTrustOnlyNomadsCA(t *testing.T) {
	repo := executionPlatformRepoRoot(t)
	tokenFile := writeFakeNomadObserverTokenFile(t, t.TempDir())
	var requests atomic.Int32
	var authorized atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("X-Nomad-Token") == testObserverNomadToken {
			authorized.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"config":{}}`))
	})
	server, nomadTLS := startNomadTLSStandIn(t, handler)
	plain := httptest.NewServer(handler)
	defer plain.Close()
	tls12 := httptestTLS12Server(t, nomadTLS, handler)
	other, err := issueNomadTLSMaterial(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.Symlink(nomadTLS.caFile, link); err != nil {
		t.Fatal(err)
	}
	get := func(addr string, caFile string) (string, error) {
		command := exec.Command("bash", "-c", `source "$1"; nomad_api_get /v1/agent/self "$OUT"`, "bash",
			filepath.Join(repo, "scripts", "internal", "nomad_acl.sh"))
		command.Env = []string{
			"PATH=" + os.Getenv("PATH"),
			"NOMAD_ADDR=" + addr,
			"NOMAD_CACERT=" + caFile,
			"NOMAD_TOKEN_FILE=" + tokenFile,
			"OUT=" + filepath.Join(t.TempDir(), "out.json"),
		}
		output, err := command.CombinedOutput()
		return string(output), err
	}

	if output, err := get(server.URL, nomadTLS.caFile); err != nil || authorized.Load() != 1 {
		t.Fatalf("nomad_api_get with Nomad's CA failed: %v authorized=%d output=%s", err, authorized.Load(), output)
	}
	for _, test := range []struct {
		name, addr, caFile, want string
	}{
		{"plain HTTP address", plain.URL, nomadTLS.caFile, "NOMAD_ADDR must be Nomad's https:// address"},
		{"no CA file", server.URL, "", "NOMAD_CACERT must name Nomad's CA certificate file"},
		{"CA file missing", server.URL, filepath.Join(t.TempDir(), "missing.pem"), "NOMAD_CACERT must name Nomad's CA certificate file"},
		{"CA file is a symbolic link", server.URL, link, "NOMAD_CACERT must name Nomad's CA certificate file"},
		{"certificate from another CA", server.URL, other.caFile, ""},
		{"Nomad offers only TLS 1.2", tls12.URL, nomadTLS.caFile, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			requests.Store(0)
			output, err := get(test.addr, test.caFile)
			if err == nil || !strings.Contains(output, test.want) {
				t.Fatalf("nomad_api_get did not refuse with %q: %v output=%s", test.want, err, output)
			}
			if got := requests.Load(); got != 0 {
				t.Fatalf("refused nomad_api_get sent %d request(s)", got)
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

// TestLinuxSetupChecksNomadsListenerBeforeEveryTokenSend: the setup script
// sends Nomad a token or a bootstrap secret only right after it checked that
// Nomad's user owns the listener (require_nomad_listener).
// TestLinuxSetupBootstrapSendsNoSecretToAPortHolder shows that the checks
// work; this test keeps each send next to one, including a send that a later
// check covers today, so a send cannot be added or moved away from its check.
//
// A send is a command, outside a heredoc and outside a comment, that hands
// NOMAD_TOKEN to a program, names X-Nomad-Token, or carries BootstrapSecret.
// Its check is one of:
//   - "require_nomad_listener ||" earlier in the same command;
//   - the statement just before it: "require_nomad_listener || return 1";
//   - the block just before it: "if ! require_nomad_listener; then", a body
//     that ends in "return 1", then "fi".
func TestLinuxSetupChecksNomadsListenerBeforeEveryTokenSend(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(executionPlatformRepoRoot(t), "scripts", "70_linux_setup.sh"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	send := regexp.MustCompile(`\bNOMAD_TOKEN=|X-Nomad-Token|BootstrapSecret`)
	heredoc := regexp.MustCompile(`<<-?'?([A-Za-z_][A-Za-z0-9_]*)'?`)
	function := regexp.MustCompile(`^([a-z_][a-z0-9_]*)\(\) \{$`)
	indent := func(line string) int { return len(line) - len(strings.TrimLeft(line, " ")) }
	previousStatement := func(i int) int {
		for i--; i >= 0 && strings.TrimSpace(lines[i]) == ""; i-- {
		}
		return i
	}
	checked := func(start int, at int, column int) bool {
		for i := start; i <= at; i++ {
			if index := strings.Index(lines[i], "require_nomad_listener ||"); index >= 0 && (i < at || index < column) {
				return true
			}
		}
		before := previousStatement(start)
		if before < 0 {
			return false
		}
		switch strings.TrimSpace(lines[before]) {
		case "require_nomad_listener || return 1":
			return true
		case "fi":
			body := previousStatement(before)
			if body < 0 || strings.TrimSpace(lines[body]) != "return 1" {
				return false
			}
			for i := body - 1; i >= 0; i-- {
				if strings.TrimSpace(lines[i]) != "" && indent(lines[i]) <= indent(lines[before]) {
					return indent(lines[i]) == indent(lines[before]) && strings.TrimSpace(lines[i]) == "if ! require_nomad_listener; then"
				}
			}
		}
		return false
	}

	inFunctions := map[string]bool{}
	current := ""
	terminator := ""
	for i, line := range lines {
		if terminator != "" {
			if strings.TrimSpace(line) == terminator {
				terminator = ""
			}
			continue
		}
		if m := function.FindStringSubmatch(line); m != nil {
			current = m[1]
		}
		where := current
		if where == "" {
			where = "main body"
		}
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			if location := send.FindStringIndex(line); location != nil {
				start := i
				for start > 0 && strings.HasSuffix(strings.TrimRight(lines[start-1], " "), "\\") {
					start--
				}
				if !checked(start, i, location[0]) {
					t.Errorf("70_linux_setup.sh:%d (%s) sends a token without checking Nomad's listener just before: %s", i+1, where, strings.TrimSpace(line))
				}
				inFunctions[current] = true
			}
		}
		if m := heredoc.FindStringSubmatch(line); m != nil {
			terminator = m[1]
		}
		if line == "}" {
			current = "" // a function ends at a closing brace in column 0
		}
	}
	// The sends this test must at least find, so it cannot pass by finding none.
	for _, name := range []string{"nomad_token_curl", "bootstrap_nomad_acl", "report_nomad_cpu_visibility_diagnostics", "qualify_supported_substrate"} {
		if !inFunctions[name] {
			t.Errorf("found no token send in %s; the scan no longer recognises the script's sends", name)
		}
	}
}
