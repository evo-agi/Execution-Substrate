package scripts_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

// boxNomadHCL is the box's /etc/nomad.d/nomad.hcl as the read-only
// preflight of 2026-11-24 printed it: 529 bytes, Remote Alpha 0.7's
// one-host config.
const boxNomadHCL = `# Remote Alpha 0.7 one-host substrate config.
data_dir = "/opt/nomad/data"
bind_addr = "127.0.0.1"

addresses {
  http = "127.0.0.1"
  rpc  = "127.0.0.1"
  serf = "127.0.0.1"
}

advertise {
  http = "127.0.0.1:4646"
  rpc  = "127.0.0.1:4647"
  serf = "127.0.0.1:4648"
}

server {
  enabled = true
  bootstrap_expect = 1
}

client {
  enabled = true
  servers = ["127.0.0.1"]
  network_interface = "enp1s0"
  cni_path = "/opt/cni/bin"
  options = {
    "docker.cleanup.image" = "false"
    "docker.volumes.enabled" = "true"
  }
}
`

// boxNomadHCLLocked is what the lock makes of it: the legacy Docker
// options become the driver allowlist, and the acl block and the Docker
// plugin block of scripts/70_linux_setup.sh are added.
const boxNomadHCLLocked = `# Remote Alpha 0.7 one-host substrate config.
data_dir = "/opt/nomad/data"
bind_addr = "127.0.0.1"

addresses {
  http = "127.0.0.1"
  rpc  = "127.0.0.1"
  serf = "127.0.0.1"
}

advertise {
  http = "127.0.0.1:4646"
  rpc  = "127.0.0.1:4647"
  serf = "127.0.0.1:4648"
}

server {
  enabled = true
  bootstrap_expect = 1
}

client {
  enabled = true
  servers = ["127.0.0.1"]
  network_interface = "enp1s0"
  cni_path = "/opt/cni/bin"
  options = {
    "driver.allowlist" = "docker"
  }
}

acl {
  enabled = true
}

# ES runs every task through its runtime helper on the Docker driver, so only
# that driver is enabled and the Docker plugin is limited (audit INF-02): no
# privileged containers, and only the capabilities the helper uses to prepare
# a run and drop to the workload user. ES's bind mounts need volumes enabled.
# Runtime profile images must survive image garbage collection.
plugin "docker" {
  config {
    allow_privileged = false
    allow_caps       = ["chown", "dac_override", "fowner", "kill", "setgid", "setuid", "setpcap"]

    volumes {
      enabled = true
    }

    gc {
      image = false
    }
  }
}
`

const upgradeTestCommit = "0123456789abcdef0123456789abcdef01234567"

// The fakes stand in for the host's systemctl, curl and nomad, and for
// scripts/nomad_acl_setup.sh. They log every call to calls.log in the state
// directory and act on its marker files. Starting nomad reads the host's
// nomad.hcl: with an acl block, Nomad is "locked" and refuses anonymous job
// requests, as the real one does.
const fakeSystemctl = `#!/usr/bin/env bash
set -u
s="$FAKE_STATE"
echo "systemctl $*" >> "$s/calls.log"
case "$1" in
  is-active)
    shift
    for u in "$@"; do if [[ -e "$s/inactive-$u" ]]; then echo inactive; else echo active; fi; done ;;
  show)
    printf 'User=%s\n' "$(cat "$s/es-user" 2>/dev/null || echo es)"
    printf 'ExecStart={ path=/usr/local/lib/execution-substrate/bin/es ; argv[]=%s ; ignore_errors=no }\n' \
      "$(cat "$s/es-argv" 2>/dev/null || echo '/usr/local/lib/execution-substrate/bin/es -config /etc/execution-substrate/es.json')" ;;
  stop)
    # fail-stop-<unit> holds how many stops still succeed; after those, the
    # stop fails and the unit keeps running.
    if [[ -e "$s/fail-stop-$2" ]]; then
      n="$(cat "$s/fail-stop-$2")"
      if (( n <= 0 )); then echo "Failed to stop $2.service" >&2; exit 1; fi
      echo $((n - 1)) > "$s/fail-stop-$2"
    fi
    touch "$s/inactive-$2" ;;
  start)
    if [[ -e "$s/fail-start-$2-once" ]]; then rm -f "$s/fail-start-$2-once"; echo "Job for $2.service failed" >&2; exit 1; fi
    if [[ "$2" == nomad ]]; then
      if grep -q '^acl {' "$FAKE_HOST_ROOT/etc/nomad.d/nomad.hcl"; then touch "$s/locked"; else rm -f "$s/locked"; fi
      # leader-starts holds how many Nomad starts still elect a leader.
      if [[ -e "$s/leader-starts" ]]; then
        n="$(cat "$s/leader-starts")"
        if (( n <= 0 )); then touch "$s/no-leader"; else echo $((n - 1)) > "$s/leader-starts"; rm -f "$s/no-leader"; fi
      fi
    fi
    rm -f "$s/inactive-$2" ;;
  *)
    echo "fake systemctl: unexpected $*" >&2; exit 2 ;;
esac
`

const fakeCurl = `#!/usr/bin/env bash
set -u
s="$FAKE_STATE"
url="${@: -1}"
echo "curl $url" >> "$s/calls.log"
body_wanted=1
for a in "$@"; do [[ "$a" == /dev/null ]] && body_wanted=0; done
code=200
body=''
refuse() { echo "curl: (7) Failed to connect" >&2; exit 7; }
case "$url" in
  */v1/status/leader)
    [[ -e "$s/inactive-nomad" ]] && refuse
    if [[ -e "$s/no-leader" ]]; then code=500; body='No cluster leader'; else body='"127.0.0.1:4647"'; fi ;;
  */v1/jobs\?namespace=\*)
    [[ -e "$s/inactive-nomad" ]] && refuse
    if [[ -e "$s/locked" ]]; then code=403; body='Permission denied'; else body="$(cat "$s/jobs.json" 2>/dev/null || echo '[]')"; fi ;;
  */v1/jobs)
    [[ -e "$s/inactive-nomad" ]] && refuse
    if [[ -e "$s/locked" ]]; then code=403; fi ;;
  https://127.0.0.1:8445/*)
    { [[ -e "$s/inactive-es" ]] || [[ -e "$s/unhealthy" ]]; } && refuse ;;
  https://127.0.0.1:8444/*)
    [[ -e "$s/unhealthy" ]] && refuse ;;
  *)
    echo "fake curl: unexpected $url" >&2; exit 2 ;;
esac
if [[ $body_wanted == 1 ]]; then printf '%s\n%s' "$body" "$code"; else printf '%s' "$code"; fi
`

const fakeNomad = `#!/usr/bin/env bash
set -u
s="$FAKE_STATE"
echo "nomad $*" >> "$s/calls.log"
[[ "$1 $2" == "config validate" ]] || exit 2
if [[ -e "$s/slow-validate" ]]; then touch "$s/validating"; sleep 20; fi
[[ -e "$s/nomad-invalid" ]] && { echo "invalid config" >&2; exit 1; }
grep -q '^acl {' "$3/nomad.hcl"
`

const fakeACLSetup = `#!/usr/bin/env bash
set -u
s="$FAKE_STATE"
echo "acl-setup $1 ES_USER=$ES_USER OBSERVER_USER=$OBSERVER_USER NOMAD_USER=$NOMAD_USER NOMAD_ADDR=$NOMAD_ADDR" >> "$s/calls.log"
[[ -e "$s/locked" ]] || { echo "nomad acl setup: Nomad does not enforce ACLs" >&2; exit 1; }
case "$1" in
  provision)
    if [[ -e "$s/slow-acl" ]]; then
      # A grandchild that would write after its parent is gone.
      ( sleep 2; touch "$s/grandchild-wrote" ) &
      touch "$s/acl-running"
      sleep 20
    fi
    mkdir -p "$NOMAD_ACL_DIR"
    chmod 0755 "$NOMAD_ACL_DIR"
    if [[ ! -e "$NOMAD_ACL_DIR/es-token" ]]; then
      (umask 077; echo 01234567-89ab-cdef-0123-456789abcdef > "$NOMAD_ACL_DIR/es-token")
      chmod 0400 "$NOMAD_ACL_DIR/es-token"
    fi ;;
  check)
    [[ -e "$s/acl-check-fails" ]] && { echo "nomad acl check: failed" >&2; exit 1; }
    [[ -e "$NOMAD_ACL_DIR/es-token" ]] ;;
  *) exit 2 ;;
esac
`

type upgradeHost struct {
	t       *testing.T
	root    string
	state   string
	bin     string
	payload string
	helper  string
}

func (h *upgradeHost) path(rel string) string { return filepath.Join(h.root, filepath.FromSlash(rel)) }

func (h *upgradeHost) write(rel string, data string, mode os.FileMode) {
	h.t.Helper()
	path := h.path(rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), mode); err != nil {
		h.t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		h.t.Fatal(err)
	}
}

func (h *upgradeHost) mkdir(rel string, mode os.FileMode) {
	h.t.Helper()
	if err := os.MkdirAll(h.path(rel), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.Chmod(h.path(rel), mode); err != nil {
		h.t.Fatal(err)
	}
}

func (h *upgradeHost) mark(name string, content string) {
	h.t.Helper()
	if err := os.WriteFile(filepath.Join(h.state, name), []byte(content), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h *upgradeHost) marked(name string) bool {
	_, err := os.Stat(filepath.Join(h.state, name))
	return err == nil
}

// boxShapedESConfig is the operator and control-plane example without the
// two keys the box's ES build predates: the box's es.json key set.
func boxShapedESConfig(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(repoPath(".examples/config/es.operator_and_control_plane.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	delete(doc["nomad"].(map[string]any), "token_file")
	delete(doc["execution"].(map[string]any), "retained_result_auth")
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// newUpgradeHost lays out a host root shaped like the box, a payload built
// from upgradeTestCommit, and the fakes.
func newUpgradeHost(t *testing.T, helper string) *upgradeHost {
	t.Helper()
	h := &upgradeHost{t: t, root: t.TempDir(), state: t.TempDir(), bin: t.TempDir(), payload: filepath.Join(t.TempDir(), "payload"), helper: helper}
	if err := os.WriteFile(filepath.Join(h.state, "calls.log"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	h.mkdir("etc/execution-substrate", 0o755)
	h.write("etc/execution-substrate/es.json", string(boxShapedESConfig(t)), 0o640)
	h.write("etc/execution-substrate/ags.json", `{"http": {"bind_address": "127.0.0.1", "port": 8444}}`+"\n", 0o640)
	h.write("etc/execution-substrate/healthcheck.env", "CA_CERT=/etc/execution-substrate/tls/ca.pem\nOPERATOR_CERT=\"/etc/x/operator.pem\"\nOPERATOR_KEY=/etc/x/operator-key.pem\n", 0o640)
	h.write("etc/systemd/system/es.service", "[Service]\nExecStart=/usr/local/lib/execution-substrate/bin/es -config /etc/execution-substrate/es.json\n", 0o644)
	h.write("etc/systemd/system/es.service.d/10-account.conf", "[Service]\nUser=es\nGroup=es\nUMask=0027\n", 0o644)
	h.write("usr/local/lib/execution-substrate/bin/es", "old es build\n", 0o755)
	h.write("usr/local/bin/es-runtime-support", "old runtime support build\n", 0o755)
	h.mkdir("etc/nomad.d", 0o755)
	h.write("etc/nomad.d/nomad.hcl", boxNomadHCL, 0o644)
	h.write("etc/nomad.d/nomad.env", "", 0o644)
	h.write("etc/nomad.d/nomad.hcl.pre-alpha0.7.20260422213553", "# an older config Nomad does not load\n", 0o644)
	h.mkdir("opt/nomad", 0o755)
	h.mkdir("opt/nomad/data", 0o755)
	h.write("opt/nomad/data/server/raft/raft.db", "raft state\n", 0o600)
	h.mkdir("var/backups", 0o755)

	if err := os.Mkdir(h.payload, 0o755); err != nil {
		t.Fatal(err)
	}
	helperBytes, err := os.ReadFile(helper)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"es": []byte("new es build\n"), "es-runtime-support": []byte("new runtime support build\n"), "esconfigcheck": helperBytes}
	sums := map[string]string{}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(h.payload, name), data, 0o755); err != nil {
			t.Fatal(err)
		}
		sums[name] = sha256Hex(data)
	}
	writeJSONFile(t, filepath.Join(h.payload, "provenance.json"), map[string]any{
		"commit": upgradeTestCommit, "go_version": "go1.26.5", "vcs_modified": false, "sha256": sums,
	})

	for name, script := range map[string]string{"systemctl": fakeSystemctl, "curl": fakeCurl, "nomad": fakeNomad, "acl-setup": fakeACLSetup} {
		if err := os.WriteFile(filepath.Join(h.bin, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

func (h *upgradeHost) command(args ...string) *exec.Cmd {
	cmd := exec.Command("python3", append([]string{"-I", repoPath(upgradeESPython), "--host-root", h.root}, args...)...)
	cmd.Env = append(os.Environ(),
		"PATH="+h.bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAKE_STATE="+h.state,
		"FAKE_HOST_ROOT="+h.root,
		"ES_UPGRADE_TEST_ACL_SETUP="+filepath.Join(h.bin, "acl-setup"),
		"ES_UPGRADE_TEST_WAIT_SECONDS=1",
	)
	return cmd
}

func (h *upgradeHost) run(args ...string) (string, string, int) {
	h.t.Helper()
	cmd := h.command(args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			h.t.Fatalf("run %v: %v", args, err)
		}
		code = exitErr.ExitCode()
	}
	return stdout.String(), stderr.String(), code
}

func (h *upgradeHost) check() (map[string]any, string, int) {
	h.t.Helper()
	stdout, stderr, code := h.run("check", "--payload", h.payload, "--commit", upgradeTestCommit)
	var report map[string]any
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		h.t.Fatalf("check printed no JSON report (exit %d): %v\nstdout %s\nstderr %s", code, err, stdout, stderr)
	}
	return report, stderr, code
}

func (h *upgradeHost) apply() (string, string, int) {
	h.t.Helper()
	return h.run("apply", "--payload", h.payload, "--commit", upgradeTestCommit)
}

func (h *upgradeHost) calls(prefix string) []string {
	h.t.Helper()
	data, err := os.ReadFile(filepath.Join(h.state, "calls.log"))
	if err != nil {
		h.t.Fatal(err)
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.HasPrefix(line, prefix) {
			out = append(out, line)
		}
	}
	return out
}

func (h *upgradeHost) clearCalls() {
	h.t.Helper()
	if err := os.WriteFile(filepath.Join(h.state, "calls.log"), nil, 0o644); err != nil {
		h.t.Fatal(err)
	}
}

// snapshot maps every path under the host root to its type, mode and,
// for a file, the SHA-256 of its content.
func (h *upgradeHost) snapshot() map[string]string {
	h.t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(h.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(h.root, path)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		entry := info.Mode().String()
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			entry += " " + sha256Hex(data)
		}
		out[filepath.ToSlash(rel)] = entry
		return nil
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return out
}

// upgradeLeftovers are the paths an apply leaves on the host even after a
// rollback: the retained-result key, the Nomad ACL token files and the
// backups. The old config names none of them.
var upgradeLeftovers = regexp.MustCompile(`^(etc/execution-substrate/retained-result-auth|etc/execution-substrate/nomad-acl|var/backups/execution-substrate-es-upgrade)(/|$)`)

func assertRestored(t *testing.T, before, after map[string]string) {
	t.Helper()
	for path, entry := range before {
		if after[path] != entry {
			t.Errorf("%s: before %q, after %q", path, entry, after[path])
		}
	}
	for path := range after {
		if _, ok := before[path]; !ok && !upgradeLeftovers.MatchString(path) {
			t.Errorf("%s is new after the rollback", path)
		}
	}
}

func readSummary(t *testing.T, h *upgradeHost) (string, map[string]any) {
	t.Helper()
	dirs, err := filepath.Glob(h.path("var/backups/execution-substrate-es-upgrade/*"))
	if err != nil || len(dirs) != 1 {
		t.Fatalf("want one backup directory, found %v (%v)", dirs, err)
	}
	if !regexp.MustCompile(`/\d{8}T\d{6}Z-` + upgradeTestCommit[:12] + `$`).MatchString(dirs[0]) {
		t.Fatalf("backup directory %s is not named <UTC time>-<commit>", dirs[0])
	}
	if st, err := os.Lstat(dirs[0]); err != nil || st.Mode().Perm() != 0o700 || !st.IsDir() {
		t.Fatalf("backup directory mode: %v %v", st, err)
	}
	if st, err := os.Lstat(filepath.Dir(dirs[0])); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("backup root mode: %v %v", st, err)
	}
	data, err := os.ReadFile(filepath.Join(dirs[0], "summary.json"))
	if err != nil {
		t.Fatal(err)
	}
	var summary map[string]any
	if err := json.Unmarshal(data, &summary); err != nil {
		t.Fatal(err)
	}
	return dirs[0], summary
}

func modeOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

func TestRemoteAlphaUpgradeESNomadLockMatchesSupportedConfig(t *testing.T) {
	if len(boxNomadHCL) != 529 {
		t.Fatalf("the box's nomad.hcl fixture is %d bytes; the preflight read 529", len(boxNomadHCL))
	}
	code := `import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("upgrade", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
new, state = m.plan_nomad_hcl(sys.stdin.read())
print(json.dumps({"locked": new, "state": state, "box_sha256": m.NOMAD_HCL_BOX_SHA256,
                  "fragments": [m.NOMAD_LOCKED_OPTIONS, m.NOMAD_ACL_BLOCK, m.NOMAD_PLUGIN_BLOCK]}))`
	cmd := exec.Command("python3", "-I", "-c", code, repoPath(upgradeESPython))
	cmd.Stdin = strings.NewReader(boxNomadHCL)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("plan_nomad_hcl: %v", err)
	}
	var got struct {
		Locked    string   `json:"locked"`
		State     string   `json:"state"`
		BoxSHA256 string   `json:"box_sha256"`
		Fragments []string `json:"fragments"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got.BoxSHA256 != sha256Hex([]byte(boxNomadHCL)) {
		t.Fatalf("NOMAD_HCL_BOX_SHA256 %s is not the fixture's %s", got.BoxSHA256, sha256Hex([]byte(boxNomadHCL)))
	}
	if got.State != "apply" || got.Locked != boxNomadHCLLocked {
		t.Fatalf("the lock of the box's nomad.hcl (%s):\n%s", got.State, got.Locked)
	}
	// Every piece the lock adds is the supported config's own text.
	setup := mustRead(t, repoPath("scripts/70_linux_setup.sh"))
	for _, fragment := range got.Fragments {
		if !strings.Contains(setup, fragment) {
			t.Errorf("scripts/70_linux_setup.sh's Nomad config does not hold the lock's fragment:\n%s", fragment)
		}
	}
}

func TestRemoteAlphaUpgradeESCheckChangesNothing(t *testing.T) {
	h := newUpgradeHost(t, buildESConfigCheck(t))
	before := h.snapshot()
	report, stderr, code := h.check()
	if code != 0 {
		t.Fatalf("check exited %d: %s\n%v", code, stderr, report["blockers"])
	}
	if blockers := report["blockers"].([]any); len(blockers) != 0 {
		t.Fatalf("blockers on a box-shaped host: %v", blockers)
	}
	esConfig := report["es_config"].(map[string]any)
	if fmt.Sprint(esConfig["changes"]) != "[nomad.token_file execution.retained_result_auth]" || esConfig["new_es_accepts_migrated_config"] != true {
		t.Fatalf("es_config report: %v", esConfig)
	}
	if lock := report["nomad_hcl"].(map[string]any)["lock"]; lock != "apply" {
		t.Fatalf("nomad_hcl lock state %v", lock)
	}
	if report["retained_result_key"] != "would create" {
		t.Fatalf("retained_result_key %v", report["retained_result_key"])
	}
	health := report["health"].(map[string]any)
	for _, url := range []string{"https://127.0.0.1:8445/health", "https://127.0.0.1:8445/v1/executions:contract", "https://127.0.0.1:8444/health"} {
		if health[url] != "200" {
			t.Fatalf("health %v", health)
		}
	}
	assertRestored(t, before, h.snapshot())
	if len(before) != len(h.snapshot()) {
		t.Fatalf("check created files")
	}
	for _, call := range h.calls("systemctl") {
		if !strings.HasPrefix(call, "systemctl is-active") && !strings.HasPrefix(call, "systemctl show") {
			t.Fatalf("check ran %q", call)
		}
	}
	if calls := h.calls("acl-setup"); len(calls) != 0 {
		t.Fatalf("check ran the ACL setup: %v", calls)
	}
}

func TestRemoteAlphaUpgradeESCheckRefusesWhatItWasNotWrittenFor(t *testing.T) {
	helper := buildESConfigCheck(t)
	cases := []struct {
		name   string
		break_ func(h *upgradeHost)
		scope  string
		says   string
	}{
		{"es.json has a key the box's build lacks", func(h *upgradeHost) {
			var doc map[string]any
			_ = json.Unmarshal(boxShapedESConfig(t), &doc)
			doc["http"].(map[string]any)["idle_timeout_seconds"] = 5
			data, _ := json.Marshal(doc)
			h.write("etc/execution-substrate/es.json", string(data), 0o640)
		}, "es_config", "differ from the build this upgrade was written for"},
		{"es.json is world-readable", func(h *upgradeHost) {
			_ = os.Chmod(h.path("etc/execution-substrate/es.json"), 0o644)
		}, "es_config", "not root:es 0640"},
		{"nomad.hcl is not the preflight's", func(h *upgradeHost) {
			h.write("etc/nomad.d/nomad.hcl", strings.Replace(boxNomadHCL, `bootstrap_expect = 1`, `bootstrap_expect = 3`, 1), 0o644)
		}, "nomad_hcl", "not the file the preflight read"},
		{"Nomad is already locked", func(h *upgradeHost) {
			h.write("etc/nomad.d/nomad.hcl", boxNomadHCLLocked, 0o644)
		}, "nomad_hcl", "already been applied"},
		{"Nomad would load another config", func(h *upgradeHost) {
			h.write("etc/nomad.d/tls.hcl", "tls {}\n", 0o644)
		}, "nomad_hcl", "would also load ['tls.hcl']"},
		{"a service is down", func(h *upgradeHost) { h.mark("inactive-vault", "") }, "services", "not every service is active"},
		{"es.service runs ES as root", func(h *upgradeHost) { h.mark("es-user", "root") }, "es_unit", "runs as 'root'"},
		{"es.service starts another binary", func(h *upgradeHost) {
			h.mark("es-argv", "/opt/es -config /etc/execution-substrate/es.json")
		}, "es_unit", "does not start"},
		{"ES is not healthy", func(h *upgradeHost) { h.mark("unhealthy", "") }, "health", "do not all answer 200"},
		{"a Nomad job is running", func(h *upgradeHost) {
			h.mark("jobs.json", `[{"ID": "es-run-1", "Status": "running"}]`)
		}, "nomad", "pending or running: ['es-run-1']"},
		{"the payload is from another commit", func(h *upgradeHost) {
			writeJSONFile(t, filepath.Join(h.payload, "provenance.json"), map[string]any{"commit": strings.Repeat("a", 40), "go_version": "go1.26.5", "vcs_modified": false})
		}, "payload", "not the named commit"},
		{"a payload binary changed", func(h *upgradeHost) {
			_ = os.WriteFile(filepath.Join(h.payload, "es"), []byte("tampered\n"), 0o755)
		}, "payload", "does not match its provenance"},
		{"the payload directory is group-writable", func(h *upgradeHost) {
			_ = os.Chmod(h.payload, 0o775)
		}, "payload", "group and others cannot write"},
		{"a retained-result key of the wrong size exists", func(h *upgradeHost) {
			h.write("etc/execution-substrate/retained-result-auth/es.key", "short", 0o400)
		}, "retained_result_key", "exactly 32 bytes"},
		{"Nomad's data directory is a link", func(h *upgradeHost) {
			_ = os.RemoveAll(h.path("opt/nomad/data"))
			_ = os.Symlink(h.path("var/backups"), h.path("opt/nomad/data"))
		}, "nomad_dirs", "/opt/nomad/data is not a directory"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newUpgradeHost(t, helper)
			tc.break_(h)
			before := h.snapshot()
			report, stderr, code := h.check()
			if code != 1 || !strings.Contains(stderr, "blocker(s); nothing was changed") {
				t.Fatalf("check exited %d: %s", code, stderr)
			}
			found := false
			for _, b := range report["blockers"].([]any) {
				blocker := b.(map[string]any)
				if blocker["scope"] == tc.scope && strings.Contains(blocker["summary"].(string), tc.says) {
					found = true
				}
			}
			if !found {
				t.Fatalf("no %s blocker saying %q in %v", tc.scope, tc.says, report["blockers"])
			}
			assertRestored(t, before, h.snapshot())

			// apply refuses the same host before it changes anything.
			h.clearCalls()
			_, stderr, code = h.apply()
			if code != 1 || !strings.Contains(stderr, "nothing was changed") {
				t.Fatalf("apply exited %d: %s", code, stderr)
			}
			assertRestored(t, before, h.snapshot())
			if _, err := os.Lstat(h.path("var/backups/execution-substrate-es-upgrade")); err == nil {
				t.Fatalf("a refused apply wrote a backup")
			}
			for _, call := range h.calls("systemctl") {
				if !strings.HasPrefix(call, "systemctl is-active") && !strings.HasPrefix(call, "systemctl show") {
					t.Fatalf("a refused apply ran %q", call)
				}
			}
		})
	}
}

func TestRemoteAlphaUpgradeESApply(t *testing.T) {
	helper := buildESConfigCheck(t)
	h := newUpgradeHost(t, helper)
	before := h.snapshot()
	stdout, stderr, code := h.apply()
	if code != 0 {
		t.Fatalf("apply exited %d\nstdout %s\nstderr %s", code, stdout, stderr)
	}

	// ES's own config loader accepts the migrated es.json, which carries the
	// token file and retained-result auth, with its old owner and mode.
	if out, err := exec.Command(helper, h.path("etc/execution-substrate/es.json")).CombinedOutput(); err != nil {
		t.Fatalf("ES refuses the installed es.json: %v %s", err, out)
	}
	var esConfig map[string]any
	if err := json.Unmarshal([]byte(mustRead(t, h.path("etc/execution-substrate/es.json"))), &esConfig); err != nil {
		t.Fatal(err)
	}
	if got := esConfig["nomad"].(map[string]any)["token_file"]; got != "/etc/execution-substrate/nomad-acl/es-token" {
		t.Fatalf("token_file %v", got)
	}
	if got := fmt.Sprint(esConfig["execution"].(map[string]any)["retained_result_auth"]); got != "map[key_file:/etc/execution-substrate/retained-result-auth/es.key key_id:k1 store_id:remote-alpha]" {
		t.Fatalf("retained_result_auth %s", got)
	}
	for path, want := range map[string]os.FileMode{
		"etc/execution-substrate/es.json":                     0o640,
		"usr/local/lib/execution-substrate/bin/es":            0o755,
		"usr/local/bin/es-runtime-support":                    0o755,
		"etc/nomad.d/nomad.hcl":                               0o640,
		"etc/nomad.d/nomad.env":                               0o640,
		"etc/nomad.d":                                         0o755,
		"opt/nomad":                                           0o755,
		"opt/nomad/data":                                      0o700,
		"etc/execution-substrate/retained-result-auth":        0o755,
		"etc/execution-substrate/retained-result-auth/es.key": 0o400,
	} {
		if got := modeOf(t, h.path(path)); got != want {
			t.Errorf("%s mode %04o, want %04o", path, got, want)
		}
	}
	if got := mustRead(t, h.path("usr/local/lib/execution-substrate/bin/es")); got != "new es build\n" {
		t.Fatalf("es binary %q", got)
	}
	if got := mustRead(t, h.path("usr/local/bin/es-runtime-support")); got != "new runtime support build\n" {
		t.Fatalf("runtime support binary %q", got)
	}
	if got := mustRead(t, h.path("etc/nomad.d/nomad.hcl")); got != boxNomadHCLLocked {
		t.Fatalf("nomad.hcl after the lock:\n%s", got)
	}
	if key, err := os.ReadFile(h.path("etc/execution-substrate/retained-result-auth/es.key")); err != nil || len(key) != 32 {
		t.Fatalf("retained-result key: %d bytes, %v", len(key), err)
	}
	if strings.Contains(stdout+stderr, "01234567-89ab-cdef") {
		t.Fatalf("apply printed the Nomad token")
	}
	// Files the upgrade does not own stay as they were.
	for _, path := range []string{"etc/execution-substrate/ags.json", "etc/execution-substrate/healthcheck.env", "etc/systemd/system/es.service",
		"etc/systemd/system/es.service.d/10-account.conf", "etc/nomad.d/nomad.hcl.pre-alpha0.7.20260422213553", "opt/nomad/data/server/raft/raft.db"} {
		if after := h.snapshot()[path]; after != before[path] {
			t.Errorf("%s changed: %q -> %q", path, before[path], after)
		}
	}

	// The order: ES stops first, Nomad is validated, stopped, locked and
	// started, its ACLs are provisioned, then ES starts and is verified.
	if got, want := strings.Join(h.calls("systemctl st"), " | "), "systemctl stop es | systemctl stop nomad | systemctl start nomad | systemctl start es"; got != want {
		t.Fatalf("service calls %q, want %q", got, want)
	}
	if got, want := strings.Join(h.calls("acl-setup"), " | "),
		"acl-setup provision ES_USER=es OBSERVER_USER=root NOMAD_USER=root NOMAD_ADDR=http://127.0.0.1:4646 | "+
			"acl-setup check ES_USER=es OBSERVER_USER=root NOMAD_USER=root NOMAD_ADDR=http://127.0.0.1:4646"; got != want {
		t.Fatalf("ACL setup calls %q", got)
	}
	log := mustRead(t, filepath.Join(h.state, "calls.log"))
	if strings.Index(log, "nomad config validate") > strings.Index(log, "systemctl stop nomad") {
		t.Fatalf("Nomad was stopped before its new config was validated:\n%s", log)
	}

	backupDir, summary := readSummary(t, h)
	if summary["result"] != "applied" {
		t.Fatalf("summary result %v", summary["result"])
	}
	for _, name := range []string{"manifest.json", "directories.json", "ownership.json", "payload/es", "payload/es-runtime-support", "payload/esconfigcheck"} {
		if _, err := os.Lstat(filepath.Join(backupDir, name)); err != nil {
			t.Errorf("backup lacks %s: %v", name, err)
		}
	}

	// A second check sees an applied upgrade and refuses.
	report, _, code := h.check()
	if code != 1 || !strings.Contains(fmt.Sprint(report["blockers"]), "already been applied") {
		t.Fatalf("check after apply: exit %d, %v", code, report["blockers"])
	}

	// rollback puts the host back exactly, and Nomad, read again, is unlocked.
	h.clearCalls()
	stdout, stderr, code = h.run("rollback", "--backup-dir", backupDir)
	if code != 0 {
		t.Fatalf("rollback exited %d\nstdout %s\nstderr %s", code, stdout, stderr)
	}
	assertRestored(t, before, h.snapshot())
	if h.marked("locked") || h.marked("inactive-es") || h.marked("inactive-nomad") {
		t.Fatalf("after the rollback: locked %v, es down %v, nomad down %v", h.marked("locked"), h.marked("inactive-es"), h.marked("inactive-nomad"))
	}
	if got, want := strings.Join(h.calls("systemctl st"), " | "), "systemctl stop es | systemctl stop nomad | systemctl start nomad | systemctl start es"; got != want {
		t.Fatalf("rollback service calls %q, want %q", got, want)
	}

	// After the rollback the host checks clean again, and a second apply
	// reuses the key and the ACL tokens the first one left.
	if report, stderr, code := h.check(); code != 0 {
		t.Fatalf("check after rollback exited %d: %s %v", code, stderr, report["blockers"])
	} else if report["retained_result_key"] != "exists" {
		t.Fatalf("retained_result_key after rollback %v", report["retained_result_key"])
	}
}

func TestRemoteAlphaUpgradeESApplyRollsBackOnFailure(t *testing.T) {
	helper := buildESConfigCheck(t)
	cases := []struct {
		name    string
		marker  string
		failure string
	}{
		{"the locked Nomad config does not validate", "nomad-invalid", "nomad config validate"},
		{"ES does not start", "fail-start-es-once", "systemctl start es"},
		{"the ACL check fails after ES starts", "acl-check-fails", "acl-setup check"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newUpgradeHost(t, helper)
			before := h.snapshot()
			h.mark(tc.marker, "")
			stdout, stderr, code := h.apply()
			if code != 1 || !strings.Contains(stderr, "apply failed; result rolled_back;") {
				t.Fatalf("apply exited %d\nstdout %s\nstderr %s", code, stdout, stderr)
			}
			assertRestored(t, before, h.snapshot())
			if h.marked("locked") || h.marked("inactive-es") || h.marked("inactive-nomad") {
				t.Fatalf("after the rollback: locked %v, es down %v, nomad down %v", h.marked("locked"), h.marked("inactive-es"), h.marked("inactive-nomad"))
			}
			_, summary := readSummary(t, h)
			if summary["result"] != "rolled_back" || !strings.Contains(fmt.Sprint(summary["failure"]), tc.failure) {
				t.Fatalf("summary result %v, failure %v", summary["result"], summary["failure"])
			}
			calls := h.calls("systemctl st")
			if len(calls) < 2 || calls[len(calls)-2] != "systemctl start nomad" || calls[len(calls)-1] != "systemctl start es" {
				t.Fatalf("the rollback did not end by starting Nomad and ES: %v", calls)
			}
		})
	}
}

// An interruption while a command runs ends that command's whole process
// group, grandchildren included, before the rollback starts.
func TestRemoteAlphaUpgradeESApplyRollsBackWhenInterrupted(t *testing.T) {
	helper := buildESConfigCheck(t)
	cases := []struct {
		name, slow, reached string
	}{
		{"during the Nomad config validation", "slow-validate", "validating"},
		{"during the ACL setup", "slow-acl", "acl-running"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newUpgradeHost(t, helper)
			before := h.snapshot()
			h.mark(tc.slow, "")
			cmd := h.command("apply", "--payload", h.payload, "--commit", upgradeTestCommit)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(30 * time.Second)
			for !h.marked(tc.reached) {
				if time.Now().After(deadline) {
					_ = cmd.Process.Kill()
					t.Fatalf("apply never reached %s\n%s\n%s", tc.reached, stdout.String(), stderr.String())
				}
				time.Sleep(50 * time.Millisecond)
			}
			if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			err := cmd.Wait()
			exitErr, ok := err.(*exec.ExitError)
			if !ok || exitErr.ExitCode() != 1 || !strings.Contains(stderr.String(), "result rolled_back") {
				t.Fatalf("interrupted apply: %v\nstdout %s\nstderr %s", err, stdout.String(), stderr.String())
			}
			assertRestored(t, before, h.snapshot())
			_, summary := readSummary(t, h)
			if summary["result"] != "rolled_back" || !strings.Contains(fmt.Sprint(summary["failure"]), "Interrupted") {
				t.Fatalf("summary result %v, failure %v", summary["result"], summary["failure"])
			}
			if h.marked("inactive-es") || h.marked("inactive-nomad") {
				t.Fatalf("ES or Nomad left stopped")
			}
			time.Sleep(3 * time.Second)
			if h.marked("grandchild-wrote") {
				t.Fatalf("a grandchild of the interrupted command kept running after the rollback")
			}
		})
	}
}

func TestRemoteAlphaUpgradeESRollbackFailuresAreReported(t *testing.T) {
	helper := buildESConfigCheck(t)

	t.Run("nothing is restored under an ES that will not stop", func(t *testing.T) {
		h := newUpgradeHost(t, helper)
		h.mark("acl-check-fails", "")
		h.mark("fail-stop-es", "1") // apply's own stop works; the rollback's fails
		_, stderr, code := h.apply()
		if code != 1 || !strings.Contains(stderr, "result rollback_failed") {
			t.Fatalf("apply exited %d: %s", code, stderr)
		}
		_, summary := readSummary(t, h)
		if !strings.Contains(fmt.Sprint(summary["rollback_failure"]), "Failed to stop es") {
			t.Fatalf("rollback_failure %v", summary["rollback_failure"])
		}
		if got := mustRead(t, h.path("usr/local/lib/execution-substrate/bin/es")); got != "new es build\n" {
			t.Fatalf("files were restored under a running ES: es binary %q", got)
		}
	})

	t.Run("a Nomad without a leader after the restore fails it", func(t *testing.T) {
		h := newUpgradeHost(t, helper)
		before := h.snapshot()
		h.mark("acl-check-fails", "")
		h.mark("leader-starts", "1") // the lock's start elects a leader; the restore's does not
		_, stderr, code := h.apply()
		if code != 1 || !strings.Contains(stderr, "result rollback_failed") {
			t.Fatalf("apply exited %d: %s", code, stderr)
		}
		_, summary := readSummary(t, h)
		if !strings.Contains(fmt.Sprint(summary["rollback_failure"]), "named no leader") {
			t.Fatalf("rollback_failure %v", summary["rollback_failure"])
		}
		assertRestored(t, before, h.snapshot())
		if h.marked("inactive-es") || h.marked("inactive-nomad") {
			t.Fatalf("the failed restore left ES or Nomad stopped")
		}
	})

	t.Run("rollback exits 1 when Nomad names no leader", func(t *testing.T) {
		h := newUpgradeHost(t, helper)
		if _, stderr, code := h.apply(); code != 0 {
			t.Fatalf("apply exited %d: %s", code, stderr)
		}
		backupDir, _ := readSummary(t, h)
		h.mark("leader-starts", "0")
		_, stderr, code := h.run("rollback", "--backup-dir", backupDir)
		if code != 1 || !strings.Contains(stderr, "named no leader") {
			t.Fatalf("rollback exited %d: %s", code, stderr)
		}
	})
}

func TestRemoteAlphaUpgradeESBuildRefusals(t *testing.T) {
	cases := []struct {
		args []string
		says string
	}{
		{[]string{"build", "--out", repoPath("scripts/payload"), "--commit", upgradeTestCommit}, "outside the checkout"},
		{[]string{"build", "--out", filepath.Join(t.TempDir(), "payload"), "--commit", "cacf5c1"}, "full lower-case 40-character SHA-1"},
	}
	for _, tc := range cases {
		_, stderr, code := runUpgradeESPython(t, tc.args...)
		if code != 1 || !strings.Contains(stderr, tc.says) {
			t.Errorf("%v: exit %d, stderr %q", tc.args, code, stderr)
		}
	}
	if _, err := os.Lstat(repoPath("scripts/payload")); err == nil {
		t.Fatalf("a refused build wrote into the checkout")
	}
}
