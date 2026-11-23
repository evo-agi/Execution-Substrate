package app_test

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestSupportedLocalExecutionRootSyntheticFixtures(t *testing.T) {
	repo := executionPlatformRepoRoot(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatalf("resolve Python fixture interpreter: %v", err)
	}
	command := exec.Command(python, "-B", filepath.Join(repo, "scripts", "internal", "test_supported_local_execution_roots.py"))
	command.Dir = repo
	command.Env = auditControlledScriptEnv(t, "TMPDIR="+t.TempDir(), "PYTHONDONTWRITEBYTECODE=1")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("synthetic owner fixture failed: %v output=%s", err, output)
	}
	if !strings.Contains(string(output), "Ran 11 tests") || !strings.Contains(string(output), "OK") {
		t.Fatalf("synthetic owner fixture did not report its exact selection: %s", output)
	}
}

// fullReadinessFixture replaces only external transports and the privileged
// owner observation. The real root helper's ownership rules are exercised by
// TestSupportedLocalExecutionRootSyntheticFixtures; no test performs chown.
type fullReadinessFixture struct {
	t       *testing.T
	repo    string
	proof   string
	config  string
	state   string
	bin     string
	events  string
	server  *httptest.Server
	initial []byte
	roots   map[string]os.FileInfo
	// observerToken is the read-only Nomad token file readiness reads with.
	observerToken string
}

func newFullReadinessFixture(t *testing.T) *fullReadinessFixture {
	t.Helper()
	repo := executionPlatformRepoRoot(t)
	workspace := t.TempDir()
	proof := filepath.Join(workspace, "proof")
	state := filepath.Join(workspace, "state")
	bin := filepath.Join(workspace, "bin")
	for _, path := range []string{proof, state, bin} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"es-staging", "es-results"} {
		if err := os.Mkdir(filepath.Join(proof, name), 0o555); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"Dockerfile", "ca.pem", "cert.pem", "key.pem", "runtime-support"} {
		if err := os.WriteFile(filepath.Join(proof, name), []byte("synthetic fixture\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The socket is test-owned; the checker only inspects its local type.
	socketRoot, err := os.MkdirTemp("/tmp", "r16-socket-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketRoot) })
	socketPath := filepath.Join(socketRoot, "spire.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/node/node-1" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"Attributes":{"cpu.totalcompute":"4000"},"Drivers":{"docker":{"Healthy":true}}}`))
	}))
	t.Cleanup(server.Close)
	config := filepath.Join(proof, "es.json")
	esTokenFile := writeFakeNomadTokenFile(t, workspace)
	observerTokenFile := writeFakeNomadObserverTokenFile(t, workspace)
	data, err := json.Marshal(map[string]any{
		"nomad":          map[string]any{"base_url": server.URL, "datacenter": "dc1", "token_file": esTokenFile},
		"runtime_config": map[string]any{"workload_zone_vault_config_ref": map[string]any{"digest": "fixture-digest"}},
		"execution": map[string]any{
			"staging_root_dir": filepath.Join(proof, "es-staging"), "results_root_dir": filepath.Join(proof, "es-results"),
			"base_image": "fixture-base:local", "runtime_support_binary": filepath.Join(proof, "runtime-support"),
			"spire_workload_api_socket_path": socketPath,
			"runtime_profiles":               map[string]any{"control_plane_normal_shell": map[string]any{"enabled": true, "image": "fixture-runtime:local"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "staging-invariant.json"), []byte("unchanged sentinel\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proof, ".supported-local-es-root-binding-v1"), []byte("synthetic marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fullReadinessFixture{t: t, repo: repo, proof: proof, config: config, state: state, bin: bin,
		events: filepath.Join(workspace, "events"), server: server, initial: data, roots: map[string]os.FileInfo{},
		observerToken: observerTokenFile}
	for _, name := range []string{"es-staging", "es-results"} {
		info, err := os.Stat(filepath.Join(proof, name))
		if err != nil {
			t.Fatal(err)
		}
		f.roots[name] = info
	}
	for name, body := range map[string]string{
		"python3": `#!/bin/sh
if [ "${1:-}" = "$ROOT_REPO/scripts/internal/supported_local_execution_roots.py" ]; then
  printf 'root-check %s\n' "$2" >> "$ROOT_EVENTS"
  [ "$2" = check ] && [ "${ROOT_HELPER_RESULT:-ok}" = ok ] && exit 0
  exit 83
fi
exec "$ROOT_REAL_PYTHON" "$@"
`,
		"curl": `#!/bin/sh
for arg do url=$arg; done
printf 'curl %s\n' "$url" >> "$ROOT_EVENTS"
case "$url" in
  "$ROOT_SERVER_URL"/ars/health|"$ROOT_SERVER_URL"/egs/health|"$ROOT_SERVER_URL"/ags/health|"$ROOT_SERVER_URL"/es/health)
    printf '{"ready":true}\n' ;;
  "$ROOT_SERVER_URL"/ars/v1/blobs/fixture-digest:json)
    printf '{"vault_config":{"address":"https://vault.example.invalid","auth_mount":"jwt","auth_role":"fixture","jwt_audience":"fixture"}}\n' ;;
  "$ROOT_SERVER_URL"/v1/status/leader)
    printf '"127.0.0.1:4647"\n' ;;
  "$ROOT_SERVER_URL"/v1/acl/token/self)
    printf '{"AccessorID":"anonymous","Type":"client","Policies":[]}\n' ;;
  "$ROOT_SERVER_URL"/v1/acl/policy/anonymous)
    printf '404' ;;
  "$ROOT_SERVER_URL"/v1/agent/self)
    printf '{"config":{"DevMode":false,"Client":{"Options":{"driver.allowlist":"docker"}},"Plugins":[{"Name":"docker","Config":{"allow_privileged":false,"allow_caps":["chown","dac_override","fowner","kill","setgid","setuid","setpcap"],"volumes":{"enabled":true},"gc":{"image":false}}}]}}\n' ;;
  "$ROOT_SERVER_URL"/v1/nodes)
    printf '[{"ID":"node-1","Name":"fixture","Status":"ready"}]\n' ;;
  *) printf 'unexpected curl URL\n' >> "$ROOT_EVENTS"; exit 97 ;;
esac
`,
		"docker": `#!/bin/sh
printf 'docker %s\n' "$*" >> "$ROOT_EVENTS"
case "$1 $2" in
  "info ") exit 0 ;;
  "image inspect") [ "${ROOT_IMAGE_PRESENT:-1}" = 1 ] && exit 0; exit 83 ;;
esac
printf 'unexpected docker operation\n' >> "$ROOT_EVENTS"
exit 97
`,
		"sudo":    "#!/bin/sh\nprintf 'unexpected sudo\\n' >> \"$ROOT_EVENTS\"\nexit 97\n",
		"nomad":   "#!/bin/sh\nprintf 'unexpected nomad\\n' >> \"$ROOT_EVENTS\"\nexit 97\n",
		"limactl": "#!/bin/sh\nprintf 'unexpected limactl\\n' >> \"$ROOT_EVENTS\"\nexit 97\n",
		"vault":   "#!/bin/sh\nprintf 'unexpected vault\\n' >> \"$ROOT_EVENTS\"\nexit 97\n",
		"ssh":     "#!/bin/sh\nprintf 'unexpected ssh\\n' >> \"$ROOT_EVENTS\"\nexit 97\n",
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (f *fullReadinessFixture) env(overrides ...string) []string {
	f.t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		f.t.Fatal(err)
	}
	base := []string{
		"PATH=" + f.bin + string(os.PathListSeparator) + auditSafeScriptPath(f.t),
		"ROOT_REPO=" + f.repo, "ROOT_REAL_PYTHON=" + python, "ROOT_EVENTS=" + f.events,
		"ROOT_SERVER_URL=" + f.server.URL, "ROOT_CONFIG=" + f.config,
		"SUPPORTED_LOCAL_ES_ROOTS_PROFILE=service-root-v1", "SUPPORTED_LOCAL_PROOF_DIR=" + f.proof,
		"SUPPORTED_LOCAL_PROOF_ID=fixture-proof", "CONTROL_PLANE_IMAGE=execution-substrate/control-plane:supported-local",
		"CONTROL_PLANE_DOCKERFILE=" + filepath.Join(f.proof, "Dockerfile"),
		"BRINGUP_PROFILE=full", "BRINGUP_DIR=" + f.state,
		"ES_CONFIG=" + f.config, "NOMAD_ADDR=" + f.server.URL, "NOMAD_TOKEN_FILE=" + f.observerToken,
		"ARS_URL=" + f.server.URL + "/ars", "EGS_URL=" + f.server.URL + "/egs",
		"AGS_URL=" + f.server.URL + "/ags", "ES_URL=" + f.server.URL + "/es",
		"CA_CERT=" + filepath.Join(f.proof, "ca.pem"),
		"OPERATOR_CERT=" + filepath.Join(f.proof, "cert.pem"), "OPERATOR_KEY=" + filepath.Join(f.proof, "key.pem"),
	}
	return auditControlledScriptEnv(f.t, append(base, overrides...)...)
}

func (f *fullReadinessFixture) runChecker(overrides ...string) (string, error) {
	f.t.Helper()
	command := exec.Command("/bin/bash", "-c", `source "$1"; check_es_submit_config_once "$ROOT_CONFIG"`,
		"bash", filepath.Join(f.repo, "scripts", "internal", "bringup.sh"))
	command.Env = f.env(overrides...)
	output, err := command.CombinedOutput()
	return string(output), err
}

func (f *fullReadinessFixture) runScript(script string, args []string, overrides ...string) (string, error) {
	f.t.Helper()
	command := exec.Command("/bin/bash", append([]string{filepath.Join(f.repo, "scripts", script)}, args...)...)
	command.Env = f.env(overrides...)
	output, err := command.CombinedOutput()
	return string(output), err
}

func (f *fullReadinessFixture) eventText() string {
	f.t.Helper()
	data, err := os.ReadFile(f.events)
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		f.t.Fatal(err)
	}
	return string(data)
}

func (f *fullReadinessFixture) assertNoReadinessMutation() {
	f.t.Helper()
	data, err := os.ReadFile(f.config)
	if err != nil || string(data) != string(f.initial) {
		f.t.Fatalf("readiness rewrote ES config: %v", err)
	}
	data, err = os.ReadFile(filepath.Join(f.state, "staging-invariant.json"))
	if err != nil || string(data) != "unchanged sentinel\n" {
		f.t.Fatalf("readiness rewrote staging invariant: %v %q", err, data)
	}
	data, err = os.ReadFile(filepath.Join(f.proof, ".supported-local-es-root-binding-v1"))
	if err != nil || string(data) != "synthetic marker\n" {
		f.t.Fatalf("readiness rewrote proof binding: %v %q", err, data)
	}
	for _, name := range []string{"es-staging", "es-results"} {
		info, err := os.Stat(filepath.Join(f.proof, name))
		if err != nil || !os.SameFile(info, f.roots[name]) || info.Mode() != f.roots[name].Mode() ||
			!info.ModTime().Equal(f.roots[name].ModTime()) ||
			info.Sys().(*syscall.Stat_t).Uid != f.roots[name].Sys().(*syscall.Stat_t).Uid ||
			info.Sys().(*syscall.Stat_t).Gid != f.roots[name].Sys().(*syscall.Stat_t).Gid {
			f.t.Fatalf("readiness changed fixture root metadata %s: %v %v", name, info, err)
		}
	}
	if strings.Contains(f.eventText(), "unexpected ") {
		f.t.Fatalf("readiness attempted forbidden external operation: %q", f.eventText())
	}
}

func TestSupportedLocalFullReadinessUsesServiceRootProfile(t *testing.T) {
	f := newFullReadinessFixture(t)
	if os.Geteuid() == 0 {
		t.Skip("caller-writability contrast requires a non-root operator")
	}
	for _, name := range []string{"es-staging", "es-results"} {
		if err := exec.Command("/bin/bash", "-c", `[[ -w "$1" ]]`, "bash", filepath.Join(f.proof, name)).Run(); err == nil {
			t.Fatal("fixture root is writable by the operator")
		}
	}
	output, err := f.runChecker()
	if err != nil || !strings.Contains(output, "ready=true") || strings.Count(f.eventText(), "root-check check\n") != 1 {
		t.Fatalf("validated service-root readiness failed: %v %q events=%q", err, output, f.eventText())
	}
	f.assertNoReadinessMutation()
}

func TestSupportedLocalFullReadinessRejectsInvalidServiceRootProfile(t *testing.T) {
	for _, tc := range []struct{ name, override, message string }{
		{"unknown", "SUPPORTED_LOCAL_ES_ROOTS_PROFILE=unknown", "unsupported supported-local roots profile"},
		{"missing proof binding", "SUPPORTED_LOCAL_PROOF_ID=", "supported-local proof config or roots are mismatched"},
		{"wrong config", "ROOT_CONFIG=/missing/es.json", "supported-local proof config or roots are mismatched"},
		{"wrong image", "CONTROL_PLANE_IMAGE=other:local", "supported-local service image is incompatible"},
		{"wrong Dockerfile", "CONTROL_PLANE_DOCKERFILE=/missing/Dockerfile", "supported-local service Dockerfile is incompatible"},
		{"owner mode or identity refusal", "ROOT_HELPER_RESULT=fail", "supported-local root owner, mode, or identity is invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFullReadinessFixture(t)
			output, err := f.runChecker(tc.override)
			if err == nil || !strings.Contains(output, tc.message) || strings.Contains(output, "ready=true") {
				t.Fatalf("invalid profile accepted: %v %q", err, output)
			}
			f.assertNoReadinessMutation()
		})
	}
	t.Run("wrong same-path mount", func(t *testing.T) {
		f := newFullReadinessFixture(t)
		var cfg map[string]any
		if err := json.Unmarshal(f.initial, &cfg); err != nil {
			t.Fatal(err)
		}
		otherRoot := filepath.Join(f.proof, "other-results")
		if err := os.Mkdir(otherRoot, 0o555); err != nil {
			t.Fatal(err)
		}
		cfg["execution"].(map[string]any)["results_root_dir"] = otherRoot
		data, _ := json.Marshal(cfg)
		if err := os.WriteFile(f.config, data, 0o600); err != nil {
			t.Fatal(err)
		}
		f.initial = data
		output, err := f.runChecker()
		if err == nil || !strings.Contains(output, "not mounted") || strings.Contains(output, "ready=true") {
			t.Fatalf("wrong same-path mount accepted: %v %q", err, output)
		}
		f.assertNoReadinessMutation()
	})
}

func TestSupportedLocalFullReadinessPreservesGenericRootWritability(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mode   os.FileMode
		wantOK bool
	}{
		{"writable", 0o755, true}, {"not writable", 0o555, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if os.Geteuid() == 0 && !tc.wantOK {
				t.Skip("non-writable contrast requires a non-root caller")
			}
			f := newFullReadinessFixture(t)
			for _, name := range []string{"es-staging", "es-results"} {
				if err := os.Chmod(filepath.Join(f.proof, name), tc.mode); err != nil {
					t.Fatal(err)
				}
			}
			output, err := f.runChecker("SUPPORTED_LOCAL_ES_ROOTS_PROFILE=")
			if (err == nil) != tc.wantOK || strings.Contains(f.eventText(), "root-check") {
				t.Fatalf("generic caller-writability changed: %v %q events=%q", err, output, f.eventText())
			}
		})
	}
	t.Run("missing roots stay absent", func(t *testing.T) {
		f := newFullReadinessFixture(t)
		if err := os.Remove(filepath.Join(f.proof, "es-staging")); err != nil {
			t.Fatal(err)
		}
		output, err := f.runChecker("SUPPORTED_LOCAL_ES_ROOTS_PROFILE=")
		if err == nil || !strings.Contains(output, "does not exist") {
			t.Fatalf("missing generic root accepted: %v %q", err, output)
		}
		if _, err := os.Lstat(filepath.Join(f.proof, "es-staging")); !os.IsNotExist(err) {
			t.Fatalf("generic readiness created root: %v", err)
		}
	})
}

func TestSupportedLocalFullReadinessActualEntrypoints(t *testing.T) {
	for _, script := range []string{"01_bringup.sh", "10_health_check.sh"} {
		t.Run(script, func(t *testing.T) {
			f := newFullReadinessFixture(t)
			var args []string
			if script == "01_bringup.sh" {
				args = []string{"check"}
			}
			output, err := f.runScript(script, args)
			if err != nil || !strings.Contains(output, "submit-ready: true") ||
				strings.Count(f.eventText(), "root-check check\n") != 1 ||
				!strings.Contains(f.eventText(), "docker image inspect fixture-runtime:local") {
				t.Fatalf("full entrypoint did not complete synthetic readiness: %v %q events=%q", err, output, f.eventText())
			}
			f.assertNoReadinessMutation()
		})
	}
	// Diagnostics sources only bringup.sh; its shared checker must be complete
	// without executing the collector, whose top-level dispatcher writes a bundle.
	f := newFullReadinessFixture(t)
	diagnostics, err := os.ReadFile(filepath.Join(f.repo, "scripts", "70_diagnostics.sh"))
	if err != nil || !strings.Contains(string(diagnostics), `source "${SCRIPT_DIR}/internal/bringup.sh"`) ||
		!strings.Contains(string(diagnostics), `check_es_submit_config_once "${ES_CONFIG}"`) {
		t.Fatalf("diagnostics consumer no longer sources the shared checker: %v", err)
	}
	output, err := f.runChecker()
	if err != nil || !strings.Contains(output, "ready=true") {
		t.Fatalf("diagnostics-sourced checker unavailable: %v %q", err, output)
	}
}

func TestSupportedLocalFullReadinessStillChecksSubmitPrerequisites(t *testing.T) {
	f := newFullReadinessFixture(t)
	output, err := f.runScript("10_health_check.sh", nil, "ROOT_IMAGE_PRESENT=0")
	if err == nil || !strings.Contains(output, "runtime profile image: missing") ||
		strings.Contains(output, "submit-ready: true") || strings.Count(f.eventText(), "root-check check\n") != 1 ||
		!strings.Contains(f.eventText(), "docker image inspect fixture-runtime:local") {
		t.Fatalf("downstream image refusal was bypassed: %v %q events=%q", err, output, f.eventText())
	}
	f.assertNoReadinessMutation()
}

func TestSupportedLocalExecutionRootFailedProvisionEmitsNoEvidence(t *testing.T) {
	repo := executionPlatformRepoRoot(t)
	workspace := t.TempDir()
	proof := filepath.Join(workspace, "proof")
	events := filepath.Join(workspace, "events")
	script := filepath.Join(repo, "scripts", "72_supported_local_setup.sh")
	body := `
require_command() { :; }
require_supported_go_toolchain() { :; }
uname() { printf 'Linux\n'; }
sudo() {
  printf 'sudo %s\n' "$*" >> "$ROOT_EVENTS"
  if [[ "$1" == -n && "$2" == true ]]; then return 0; fi
  if [[ "$1" == -n && "$2" == python3 && "$4" == provision ]]; then return 1; fi
  return 97
}
docker() { printf 'unexpected docker\n' >> "$ROOT_EVENTS"; return 97; }
nomad() { printf 'unexpected nomad\n' >> "$ROOT_EVENTS"; return 97; }
vault() { printf 'unexpected vault\n' >> "$ROOT_EVENTS"; return 97; }
limactl() { printf 'unexpected limactl\n' >> "$ROOT_EVENTS"; return 97; }
curl() { printf 'unexpected curl\n' >> "$ROOT_EVENTS"; return 97; }
nomad_acl_state_check() { :; }
ss() { printf 'unexpected ss\n' >> "$ROOT_EVENTS"; return 97; }
stop_background_process() { :; }
stop_vault_dev_listener() { :; }
build_codex_runtime_profile_image() { printf 'unexpected build\n' >> "$ROOT_EVENTS"; return 97; }
setup`
	output, err := auditScriptSource(t, script, body,
		"EXECUTION_SUBSTRATE_REPO_ROOT="+repo,
		"SUPPORTED_LOCAL_PROOF_DIR="+proof,
		"SUPPORTED_LOCAL_PROOF_ID=fixture-proof",
		"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_STORE_ID=test_store",
		"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_ID=test_key",
		"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_FILE="+filepath.Join(workspace, "external", "key"),
		"SUPPORTED_LOCAL_VAULT_PUBLIC_HOST=127.0.0.1",
		"SUPPORTED_LOCAL_VAULT_ROOT_TOKEN=synthetic-token",
		"SUPPORTED_LOCAL_VAULT_SECRET_VALUE=synthetic-value",
		"SUPPORTED_LOCAL_CODEX_CREDENTIAL_VALUE=synthetic-value",
		"ROOT_EVENTS="+events,
	)
	if err == nil || string(output) != "supported-local execution roots invalid\n" {
		t.Fatalf("failed provisioning continued or changed its safe error: err=%v output=%q", err, output)
	}
	for _, name := range []string{"execution-roots-setup-safe.json", "env.sh", "es-staging", "es-results"} {
		if _, err := os.Lstat(filepath.Join(proof, name)); !os.IsNotExist(err) {
			t.Fatalf("failed provisioning emitted or adopted %s: %v", name, err)
		}
	}
	data, err := os.ReadFile(events)
	if err != nil || !strings.Contains(string(data), "sudo -n true\n") ||
		!strings.Contains(string(data), "sudo -n python3 "+filepath.Join(repo, "scripts", "internal", "supported_local_execution_roots.py")+" provision "+proof+" fixture-proof ") ||
		strings.Contains(string(data), "unexpected ") {
		t.Fatalf("failed provisioning escaped the fake privilege boundary: err=%v events=%q", err, data)
	}
}

func TestSupportedLocalExecutionRootPrivilegeGateBeforeMutation(t *testing.T) {
	repo := executionPlatformRepoRoot(t)
	workspace := t.TempDir()
	proof := filepath.Join(workspace, "proof")
	events := filepath.Join(workspace, "events")
	script := filepath.Join(repo, "scripts", "72_supported_local_setup.sh")
	body := `
require_command() { :; }
require_supported_go_toolchain() { printf 'go\n' >> "$ROOT_EVENTS"; }
uname() { printf 'Linux\n'; }
sudo() { printf 'sudo %s\n' "$*" >> "$ROOT_EVENTS"; return 1; }
detect_docker_bridge_gateway() { printf 'unexpected bridge lookup\n' >&2; return 97; }
setup`
	output, err := auditScriptSource(t, script, body,
		"EXECUTION_SUBSTRATE_REPO_ROOT="+repo,
		"SUPPORTED_LOCAL_PROOF_DIR="+proof,
		"SUPPORTED_LOCAL_PROOF_ID=fixture-proof",
		"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_STORE_ID=test_store",
		"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_ID=test_key",
		"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_FILE="+filepath.Join(workspace, "external", "key"),
		"ROOT_EVENTS="+events,
	)
	if err == nil || string(output) != "supported-local execution-root privilege is unavailable\n" {
		t.Fatalf("missing privilege passed setup gate or disclosed details: err=%v output=%q", err, output)
	}
	if _, err := os.Lstat(proof); !os.IsNotExist(err) {
		t.Fatalf("privilege refusal changed proof workspace: %v", err)
	}
	data, err := os.ReadFile(events)
	if err != nil || string(data) != "go\nsudo -n true\n" {
		t.Fatalf("privilege gate order changed: err=%v events=%q", err, data)
	}
}

func TestSupportedLocalExecutionRootNarrowPrivilegeTransport(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("unprivileged transport fixture requires a non-root caller")
	}
	repo := executionPlatformRepoRoot(t)
	workspace := t.TempDir()
	proof := filepath.Join(workspace, "proof")
	events := filepath.Join(workspace, "events")
	setup := filepath.Join(repo, "scripts", "72_supported_local_setup.sh")
	body := `
python3() {
  printf 'bind %s\n' "$*" >> "$ROOT_EVENTS"
  printf '1:2:3\n'
}
sudo() {
  printf 'sudo %s\n' "$*" >> "$ROOT_EVENTS"
}
provision_supported_local_execution_roots`
	output, err := auditScriptSource(t, setup, body,
		"EXECUTION_SUBSTRATE_REPO_ROOT="+repo,
		"SUPPORTED_LOCAL_PROOF_DIR="+proof,
		"SUPPORTED_LOCAL_PROOF_ID=fixture-proof",
		"ROOT_EVENTS="+events,
	)
	if err != nil || len(output) != 0 {
		t.Fatalf("narrow privilege transport failed: err=%v output=%q", err, output)
	}
	got, err := os.ReadFile(events)
	want := "bind " + filepath.Join(repo, "scripts", "internal", "supported_local_execution_roots.py") +
		" bind " + proof + " fixture-proof\n" +
		"sudo -n python3 " + filepath.Join(repo, "scripts", "internal", "supported_local_execution_roots.py") +
		" provision " + proof + " fixture-proof 1:2:3\n"
	if err != nil || string(got) != want {
		t.Fatalf("privilege transport widened: err=%v got=%q want=%q", err, got, want)
	}
}

func TestSupportedLocalExecutionRootSharedPreflightProfileAndGeneric(t *testing.T) {
	repo := executionPlatformRepoRoot(t)
	workspace := t.TempDir()
	proof := filepath.Join(workspace, "proof")
	if err := os.Mkdir(proof, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"es-staging", "es-results"} {
		if err := os.Mkdir(filepath.Join(proof, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	configPath := filepath.Join(proof, "es.json")
	config := map[string]any{"execution": map[string]any{
		"staging_root_dir": filepath.Join(proof, "es-staging"),
		"results_root_dir": filepath.Join(proof, "es-results"),
	}}
	data, _ := json.Marshal(config)
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	// The unprivileged fixture cannot create root-owned directories. Its
	// synthetic helper response stands for the 0:0/0755 static check, while
	// these real 0555 directories make a caller -w gate fail if reintroduced.
	for _, name := range []string{"es-staging", "es-results"} {
		root := filepath.Join(proof, name)
		if err := os.Chmod(root, 0o555); err != nil {
			t.Fatal(err)
		}
		if err := exec.Command("/bin/bash", "-c", `[[ -w "$1" ]]`, "bash", root).Run(); err == nil {
			t.Fatal("fixture root remained writable to the invoking shell")
		}
	}
	helperCalls := filepath.Join(workspace, "helper-calls")
	shared := filepath.Join(repo, "scripts", "internal", "control_plane.sh")
	body := `
bringup_repo_root() { printf '%s\n' "$ROOT_REPO"; }
python3() {
  if [[ "${1:-}" == "$ROOT_REPO/scripts/internal/supported_local_execution_roots.py" ]]; then
    printf '%s\n' "$*" >> "$ROOT_HELPER_CALLS"
    return 0
  fi
  command python3 "$@"
}

verify_es_staging_invariant "$ROOT_CONFIG"`
	base := []string{
		"ROOT_REPO=" + repo,
		"ROOT_CONFIG=" + configPath,
		"ROOT_HELPER_CALLS=" + helperCalls,
		"BRINGUP_DIR=" + filepath.Join(workspace, "state"),
		"SUPPORTED_LOCAL_PROOF_DIR=" + proof,
		"SUPPORTED_LOCAL_PROOF_ID=fixture-proof",
		"CONTROL_PLANE_IMAGE=execution-substrate/control-plane:supported-local",
		"CONTROL_PLANE_DOCKERFILE=" + filepath.Join(proof, "Dockerfile"),
	}
	profileEnv := append(append([]string{}, base...), "SUPPORTED_LOCAL_ES_ROOTS_PROFILE=service-root-v1")
	output, err := auditScriptSource(t, shared, body, profileEnv...)
	if err != nil || len(output) != 0 {
		t.Fatalf("selected static profile was not routed through the shared check: err=%v output=%q", err, output)
	}
	calls, err := os.ReadFile(helperCalls)
	if err != nil || !strings.Contains(string(calls), " check "+proof+" fixture-proof "+configPath) {
		t.Fatalf("shared profile helper invocation mismatch: err=%v calls=%q", err, calls)
	}
	if _, err := os.Stat(filepath.Join(workspace, "state", "staging-invariant.json")); err != nil {
		t.Fatalf("selected static profile did not preserve mount evidence: %v", err)
	}

	for _, test := range []struct{ name, value, want string }{
		{"unsupported profile", "SUPPORTED_LOCAL_ES_ROOTS_PROFILE=other", "unsupported supported-local roots profile"},
		{"incompatible image", "CONTROL_PLANE_IMAGE=other/image:local", "supported-local service image is incompatible"},
		{"mismatched config", "SUPPORTED_LOCAL_PROOF_DIR=" + filepath.Join(workspace, "other"), "supported-local proof config or roots are mismatched"},
	} {
		t.Run(test.name, func(t *testing.T) {
			env := append(append([]string{}, base...), "SUPPORTED_LOCAL_ES_ROOTS_PROFILE=service-root-v1", test.value)
			out, err := auditScriptSource(t, shared, body, env...)
			if err == nil || !strings.Contains(string(out), test.want) {
				t.Fatalf("unsafe selected profile accepted: err=%v output=%q", err, out)
			}
		})
	}
	overlapData, _ := json.Marshal(map[string]any{"execution": map[string]any{
		"staging_root_dir": filepath.Join(proof, "es-staging"),
		"results_root_dir": filepath.Join(proof, "es-staging"),
	}})
	if err := os.WriteFile(configPath, overlapData, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := auditScriptSource(t, shared, body, profileEnv...); err == nil ||
		!strings.Contains(string(out), "execution.results_root_dir must be separate from execution.staging_root_dir") {
		t.Fatalf("overlapping selected-profile roots accepted: err=%v output=%q", err, out)
	}
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	genericProof := filepath.Join(workspace, "generic")
	if err := os.Mkdir(genericProof, 0o755); err != nil {
		t.Fatal(err)
	}
	genericConfig := filepath.Join(genericProof, "es.json")
	genericData, _ := json.Marshal(map[string]any{"execution": map[string]any{
		"staging_root_dir": filepath.Join(genericProof, "staging"),
		"results_root_dir": filepath.Join(genericProof, "results"),
	}})
	if err := os.WriteFile(genericConfig, genericData, 0o600); err != nil {
		t.Fatal(err)
	}
	genericEnv := append(append([]string{}, base...), "ROOT_CONFIG="+genericConfig, "BRINGUP_DIR="+filepath.Join(workspace, "generic-state"))
	if out, err := auditScriptSource(t, shared, body, genericEnv...); err != nil || len(out) != 0 {
		t.Fatalf("generic caller-writable path changed: err=%v output=%q", err, out)
	}
	for _, name := range []string{"staging", "results"} {
		if _, err := os.Stat(filepath.Join(genericProof, name)); err != nil {
			t.Fatalf("generic path no longer creates missing root %s: %v", name, err)
		}
	}
}

func TestSupportedLocalExecutionRootSetupAndProofOrdering(t *testing.T) {
	repo := executionPlatformRepoRoot(t)
	setupBytes, err := os.ReadFile(filepath.Join(repo, "scripts", "72_supported_local_setup.sh"))
	if err != nil {
		t.Fatal(err)
	}
	setup := string(setupBytes)
	for _, forbidden := range []string{"staging_root.mkdir(parents=True", "results_root.mkdir(parents=True", "\"${PROOF_DIR}/es-staging\" \"${PROOF_DIR}/bin\""} {
		if strings.Contains(setup, forbidden) {
			t.Fatalf("setup retains a second root creator: %q", forbidden)
		}
	}
	for _, required := range []string{
		"preflight_supported_local_setup_execution_roots",
		"provision_supported_local_execution_roots",
		"write_supported_local_execution_root_evidence",
		"execution-roots-setup-safe.json",
		`export SUPPORTED_LOCAL_ES_ROOTS_PROFILE="${ES_ROOTS_PROFILE}"`,
		`python3 "${ES_ROOTS_HELPER}" check "${PROOF_DIR}" "${PROOF_ID}" "${PROOF_DIR}/es.json"`,
	} {
		if !strings.Contains(setup, required) {
			t.Fatalf("setup missing root profile boundary %q", required)
		}
	}
	preflight := strings.Index(setup, "preflight_supported_local_setup_execution_roots\n")
	fresh := strings.Index(setup, `mkdir -- "${PROOF_DIR}"`)
	provision := strings.Index(setup, "  provision_supported_local_execution_roots\n")
	build := strings.Index(setup, "  build_codex_runtime_profile_image\n")
	if preflight < 0 || fresh < preflight || provision < fresh || build < provision {
		t.Fatalf("setup privilege/fresh-root/provision/build ordering changed")
	}
	checked := strings.Index(setup, `python3 "${ES_ROOTS_HELPER}" check "${PROOF_DIR}" "${PROOF_ID}" "${PROOF_DIR}/es.json"`)
	emitted := strings.Index(setup, `  write_supported_local_execution_root_evidence "${PROOF_DIR}"`)
	if checked < build || emitted < checked {
		t.Fatal("safe setup projection is not after root/config check")
	}

	proofBytes, err := os.ReadFile(filepath.Join(repo, "scripts", "73_supported_local_proof.sh"))
	if err != nil {
		t.Fatal(err)
	}
	proof := string(proofBytes)
	bootstrapStart := strings.Index(proof, "prepare_guest_bootstrap_dir() {")
	bootstrapEnd := strings.Index(proof, "copy_repo_snapshot_to_guest() {")
	if bootstrapStart < 0 || bootstrapEnd <= bootstrapStart {
		t.Fatal("proof bootstrap function missing")
	}
	bootstrap := proof[bootstrapStart:bootstrapEnd]
	if strings.Contains(bootstrap, `"${GUEST_PROOF_DIR}" "$(dirname`) {
		t.Fatal("proof bootstrap still precreates the fresh setup root")
	}
	if !strings.Contains(proof, `"${GUEST_BOOTSTRAP_DIR}/guest-repo-snapshot.sha256"`) ||
		!strings.Contains(proof, `cp -- "${GUEST_BOOTSTRAP_DIR}/guest-repo-snapshot.sha256"`) ||
		strings.Index(proof, "run_phase guest-setup setup_guest_environment") >= strings.Index(proof, "run_phase input-transfer copy_inputs_to_guest") {
		t.Fatal("snapshot metadata transfer is not after exclusive setup")
	}
}

func TestSupportedLocalExecutionRootFixedSafeEvidence(t *testing.T) {
	repo := executionPlatformRepoRoot(t)
	proof := t.TempDir()
	script := filepath.Join(repo, "scripts", "72_supported_local_setup.sh")
	body := `write_supported_local_execution_root_evidence "$ROOT_PROOF"`
	output, err := auditScriptSource(t, script, body,
		"EXECUTION_SUBSTRATE_REPO_ROOT="+repo, "ROOT_PROOF="+proof,
		"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_FILE="+filepath.Join(proof, "synthetic-key-path-canary"))
	if err != nil || len(output) != 0 {
		t.Fatalf("fixed setup projection failed: err=%v output=%q", err, output)
	}
	path := filepath.Join(proof, "execution-roots-setup-safe.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("fixed setup projection metadata invalid: info=%v err=%v", info, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil || len(fields) != 8 ||
		fields["schema"] != "supported-local-execution-roots-setup-safe-v1" ||
		fields["profile"] != "service-root-v1" ||
		fields["configured_root_mode"] != "0755" ||
		fields["static_root_owner_mode_checked"] != true ||
		fields["container_identity_or_behavioral_capability_proved"] != false ||
		strings.Contains(string(data), proof) || strings.Contains(string(data), "synthetic-key-path-canary") {
		t.Fatalf("fixed setup projection disclosed path or changed schema: fields=%v err=%v", fields, err)
	}
	if output, err := auditScriptSource(t, script, body,
		"EXECUTION_SUBSTRATE_REPO_ROOT="+repo, "ROOT_PROOF="+proof); err == nil ||
		string(output) != "supported-local execution roots invalid\n" {
		t.Fatalf("existing safe projection was adopted or disclosed: err=%v output=%q", err, output)
	}
}

func TestSupportedLocalProofStagingPresenceMetadataOnly(t *testing.T) {
	repo := executionPlatformRepoRoot(t)
	body, err := os.ReadFile(filepath.Join(repo, "scripts", "73_supported_local_proof.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	startMarker := "staging_state=\"$(python3 - <<'PY' \"$GUEST_PROOF_DIR/es.json\" \"${run_id}\"\n"
	start := strings.Index(text, startMarker)
	if start < 0 {
		t.Fatal("source-owned metadata staging observation missing")
	}
	start += len(startMarker)
	end := strings.Index(text[start:], "\nPY\n)\"")
	if end < 0 {
		t.Fatal("source-owned staging observation delimiter missing")
	}
	pythonBody := text[start : start+end]
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	proof := t.TempDir()
	staging := filepath.Join(proof, "es-staging")
	if err := os.Mkdir(staging, 0o755); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(proof, "es.json")
	data, _ := json.Marshal(map[string]any{"execution": map[string]any{"staging_root_dir": staging}})
	if err := os.WriteFile(config, data, 0o600); err != nil {
		t.Fatal(err)
	}
	runID := "run-0123456789abcdef"
	run := func() (string, error) {
		command := exec.Command(python, "-B", "-c", pythonBody, config, runID)
		command.Env = auditControlledScriptEnv(t, "TMPDIR="+t.TempDir(), "PYTHONDONTWRITEBYTECODE=1")
		result, err := command.CombinedOutput()
		return string(result), err
	}
	if output, err := run(); err != nil || output != "absent\n" {
		t.Fatalf("missing run directory misreported: err=%v output=%q", err, output)
	}
	runRoot := filepath.Join(staging, runID)
	if err := os.Mkdir(runRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	if output, err := run(); err != nil || output != "present\n" {
		t.Fatalf("private run directory was not observed by metadata: err=%v output=%q", err, output)
	}
	if err := os.Chmod(staging, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(staging, 0o755) })
	if os.Geteuid() != 0 {
		if output, err := run(); err == nil || output != "proof staging observation invalid\n" {
			t.Fatalf("access refusal was reported as absence: err=%v output=%q", err, output)
		}
	}
}

func TestSupportedLocalExecutionRootBothCallersReachProfileCheck(t *testing.T) {
	repo := executionPlatformRepoRoot(t)
	workspace := t.TempDir()
	proof := filepath.Join(workspace, "proof")
	if err := os.Mkdir(proof, 0o755); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(proof, "es.json")
	data, _ := json.Marshal(map[string]any{"execution": map[string]any{
		"staging_root_dir": filepath.Join(proof, "es-staging"),
		"results_root_dir": filepath.Join(proof, "es-results"),
	}})
	if err := os.WriteFile(config, data, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Dockerfile", "ca.pem", "operator.pem", "operator-key.pem"} {
		if err := os.WriteFile(filepath.Join(proof, name), []byte("synthetic fixture\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bin := filepath.Join(workspace, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"docker": `#!/bin/sh
printf 'docker %s\n' "$*" >> "$ROOT_EVENTS"
case "$1 $2" in
  "info "|"image inspect") exit 0 ;;
  "run --rm") printf 'slice0-host-loopback-ok\n'; exit 0 ;;
esac
exit 97
`,
		"python3": `#!/bin/sh
if [ "$1" = "$ROOT_REPO/scripts/internal/supported_local_execution_roots.py" ]; then
  printf 'root-check %s\n' "$2" >> "$ROOT_EVENTS"
  exit 83
fi
if [ "$1 $2" = "-m http.server" ]; then
  printf 'fake-http-server\n' >> "$ROOT_EVENTS"
  exit 0
fi
exec "$ROOT_REAL_PYTHON" "$@"
`,
		"sleep":   "#!/bin/sh\nexit 0\n",
		"sudo":    "#!/bin/sh\nprintf 'unexpected sudo\\n' >> \"$ROOT_EVENTS\"\nexit 97\n",
		"nomad":   "#!/bin/sh\nprintf 'unexpected nomad\\n' >> \"$ROOT_EVENTS\"\nexit 97\n",
		"vault":   "#!/bin/sh\nprintf 'unexpected vault\\n' >> \"$ROOT_EVENTS\"\nexit 97\n",
		"limactl": "#!/bin/sh\nprintf 'unexpected limactl\\n' >> \"$ROOT_EVENTS\"\nexit 97\n",
		"ss":      "#!/bin/sh\nprintf 'unexpected ss\\n' >> \"$ROOT_EVENTS\"\nexit 97\n",
		"curl":    "#!/bin/sh\nprintf 'unexpected curl\\n' >> \"$ROOT_EVENTS\"\nexit 97\n",
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	realPython, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, script string
		args         []string
	}{
		{"prepare-only bringup", "01_bringup.sh", []string{"up"}},
		{"ES launcher", "05_start_es.sh", nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			events := filepath.Join(t.TempDir(), "events")
			command := exec.Command("/bin/bash", append([]string{filepath.Join(repo, "scripts", test.script)}, test.args...)...)
			command.Env = auditControlledScriptEnv(t,
				"PATH="+bin+string(os.PathListSeparator)+auditSafeScriptPath(t),
				"ROOT_REPO="+repo, "ROOT_REAL_PYTHON="+realPython, "ROOT_EVENTS="+events,
				"SUPPORTED_LOCAL_PROOF_DIR="+proof, "SUPPORTED_LOCAL_PROOF_ID=fixture-proof",
				"SUPPORTED_LOCAL_ES_ROOTS_PROFILE=service-root-v1",
				"BRINGUP_PROFILE=prepare-only", "BRINGUP_DIR="+filepath.Join(workspace, "bringup"),
				"CONTROL_PLANE_IMAGE=execution-substrate/control-plane:supported-local",
				"CONTROL_PLANE_IMAGE_BUILD=never", "CONTROL_PLANE_TARGETARCH=arm64",
				"CONTROL_PLANE_DOCKERFILE="+filepath.Join(proof, "Dockerfile"),
				"ARS_CONFIG="+config, "EGS_CONFIG="+config, "AGS_CONFIG="+config, "ES_CONFIG="+config,
				"ARS_URL=https://127.0.0.1:1", "EGS_URL=https://127.0.0.1:2",
				"AGS_URL=https://127.0.0.1:3", "ES_URL=https://127.0.0.1:4",
				"CA_CERT="+filepath.Join(proof, "ca.pem"),
				"OPERATOR_CERT="+filepath.Join(proof, "operator.pem"),
				"OPERATOR_KEY="+filepath.Join(proof, "operator-key.pem"),
			)
			output, err := command.CombinedOutput()
			if err == nil || !strings.Contains(string(output), "ES staging invariant failed: supported-local root owner, mode, or identity is invalid") {
				t.Fatalf("%s did not refuse at the shared profile check: err=%v output=%q", test.name, err, output)
			}
			eventBytes, err := os.ReadFile(events)
			if err != nil || strings.Count(string(eventBytes), "root-check check\n") != 1 ||
				strings.Contains(string(eventBytes), "docker rm") || strings.Contains(string(eventBytes), "docker run --rm --name") ||
				strings.Contains(string(eventBytes), "unexpected ") {
				t.Fatalf("%s bypassed the static profile check or started ES: err=%v events=%q", test.name, err, eventBytes)
			}
		})
	}
}
