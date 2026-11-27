package scripts_test

// Regression tests for the SPIRE agent helper's bundle refresh timer and
// refresh mode: the checks pin makes before it installs a root-run copy of
// itself, what status says about the installed timer and the definition
// systemd runs, the helper lock, and the bounds on the server bundle. Each
// subtest removes the need for one guard to be trusted untested. The helper
// runs against fake systemctl, setpriv, spire-server and spire-agent;
// openssl runs for real. No SPIRE binaries are needed.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const spireAgentGuardDriver = `import fcntl, importlib.util, json, os, stat, sys
spec = importlib.util.spec_from_file_location("ra_spire_agent_guard", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)
case, root = sys.argv[2], sys.argv[3]
cfg = json.load(open(os.path.join(root, "layout.json")))
L = mod.Layout(**{k: tuple(v) if isinstance(v, list) else v for k, v in cfg.items()})
rep = mod.Report(case, True)
r = mod.Runner(L, rep)
def seed(copy_mode):
    for d in L.installed_helper_dirs:
        os.makedirs(d, exist_ok=True)
        os.chmod(d, 0o755)
    files = {L.installed_helper_path: open(mod.HELPER_SOURCE, "rb").read()}
    files.update(mod.refresh_unit_texts(L))
    for path, data in files.items():
        with open(path, "wb") as fh:
            fh.write(data)
        os.chmod(path, copy_mode if path == L.installed_helper_path else 0o644)
out = {}
try:
    if case == "inspect":
        mod.TimerInstall(r, rep).inspect()
        out = {"ok": True, "plan": rep.plan}
    elif case == "inspect-seeded":
        seed(0o644)
        mod.TimerInstall(r, rep).inspect()
        out = {"ok": True, "plan": rep.plan}
    elif case == "install":
        ti = mod.TimerInstall(r, rep)
        ti.inspect()
        ti.apply()
        out = {"ok": True}
    elif case.startswith("timer-check-"):
        seed(int(case.rsplit("-", 1)[1], 8))
        mod.check_refresh_timer(r, rep)
        out = {"ok": True}
    elif case == "timer-check":
        mod.check_refresh_timer(r, rep)
        out = {"ok": True}
    elif case == "refresh-locked":
        os.makedirs(os.path.dirname(L.lock_path), mode=0o700, exist_ok=True)
        fd = os.open(L.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        sys.exit(mod.main(["--json", "refresh", "--apply"], L))
    elif case == "refresh":
        sys.exit(mod.main(["--json", "refresh", "--apply"], L))
    elif case == "write-then-unreadable":
        # The bundle is written, then reading it back is refused: the run
        # must say that the file was written, never "nothing was changed".
        bundle = mod.ServerBundle(open(os.path.join(root, "server-bundle.pem"), "rb").read(), 1)
        def refuse(*args, **kwargs):
            raise mod.Refusal("cannot open it")
        real_atomic_write = mod.atomic_write
        def write_then_refuse(*args, **kwargs):
            real_atomic_write(*args, **kwargs)
            mod.read_regular_file = refuse
        mod.atomic_write = write_then_refuse
        mod.write_bundle(r, rep, bundle)
        out = {"ok": True}
    elif case == "write-checks":
        # write_bundle's own checks, past the reply checks: the size bound,
        # and the bytes read back after the write.
        out = {"ok": True}
        for name, pem in (("empty", b""), ("oversized", b"A" * (L.bundle_max_bytes + 1))):
            try:
                mod.write_bundle(r, rep, mod.ServerBundle(pem, 1))
                out[name] = "written"
            except mod.Failure as exc:
                out[name] = "failed: " + str(exc)
            out[name + "_file"] = os.path.lexists(L.bundle_path)
        real_atomic_write = mod.atomic_write
        def write_other(path, data, *args):
            real_atomic_write(path, data + b"#", *args)
        mod.atomic_write = write_other
        try:
            mod.write_bundle(r, rep, mod.ServerBundle(b"AAAA\n", 1))
            out["readback"] = "written"
        except mod.Failure as exc:
            out["readback"] = "failed: " + str(exc)
    elif case == "agent":
        out = {"ok": True, "agent": mod.read_local_agent(r)}
    elif case == "root-parse":
        # The parsers of SPIRE's data, called in root's process.
        out = {"ok": True}
        for name, call in (("pem", lambda: mod.parse_pem_certificates(open(os.path.join(root, "server-bundle.pem")).read())),
                           ("openssl", lambda: mod.openssl_cert_fields(r, b"", der=True))):
            try:
                call()
                out[name] = "ran"
            except AssertionError as exc:
                out[name] = "refused: " + str(exc)
    elif case == "check-replies":
        # Root's checks of replies from the SPIRE data check, one per entry
        # of replies.json.
        results = []
        for item in json.load(open(os.path.join(root, "replies.json"))):
            try:
                if item["kind"] == "bundle":
                    server, file_state = mod.check_bundle_reply(L, item["reply"], item["fetch_server"], item["sent_file"])
                    if "bundle" in server:
                        server = dict(server, bundle={"pem": server["bundle"].pem.decode("ascii"), "count": server["bundle"].count})
                    results.append({"ok": True, "server": server, "file": file_state})
                else:
                    results.append({"ok": True, "agent": mod.check_agent_reply(L, item["reply"])})
            except mod.CommandError as exc:
                results.append({"ok": False, "reason": str(exc)})
        out = {"ok": True, "results": results}
    elif case == "list-agents":
        try:
            out = {"ok": True, "agents": mod.list_agents(r)}
        except mod.CommandError as exc:
            out = {"ok": False, "kind": "CommandError", "reason": str(exc)}
    elif case == "render":
        rep.check("quoted", "info", "a\x1b[2Jb\x07c\x9bd\x7fe\tf\ng")
        out = {"ok": True, "text": rep.render_text()}
    elif case == "view-other-account":
        # The SPIRE data check started for an account it is not running as
        # (the fake setpriv runs it as the test user).
        import dataclasses
        other = "nobody" if os.geteuid() == 0 else "root"
        try:
            mod.agent_view(mod.Runner(dataclasses.replace(L, spire_user=other), rep), b"{}")
            out = {"ok": True}
        except mod.CommandError as exc:
            out = {"ok": False, "kind": "CommandError", "reason": str(exc)}
except (mod.Refusal, mod.Failure) as exc:
    out = {"ok": False, "kind": type(exc).__name__, "reason": str(exc)}
out["checks"] = rep.checks
out["actions"] = rep.actions
print(json.dumps(out))
`

// The fake systemctl keeps unit properties in systemd.json. enable --now and
// disable --now set UnitFileState and ActiveState; daemon-reload appends a
// byte to "reload_mutates" when it names a file, and merges "on_reload" into
// the units' properties.
const spireAgentGuardSystemctl = `import json, os, sys
STATE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "systemd.json")
st = json.load(open(STATE))
with open(STATE + ".log", "a") as log:
    log.write(json.dumps(sys.argv[1:]) + "\n")
args = sys.argv[1:]
units = st.setdefault("units", {})
if args == ["daemon-reload"]:
    if st.get("reload_mutates"):
        with open(st["reload_mutates"], "ab") as fh:
            fh.write(b"#")
    for name, props in (st.get("on_reload") or {}).items():
        units.setdefault(name, {}).update(props)
    json.dump(st, open(STATE, "w"))
    sys.exit(0)
if len(args) == 3 and args[1] == "--now" and args[0] in ("enable", "disable"):
    u = units.setdefault(args[2], {})
    u["UnitFileState"], u["ActiveState"] = ("enabled", "active") if args[0] == "enable" else ("disabled", "inactive")
    json.dump(st, open(STATE, "w"))
    sys.exit(0)
if args[0] == "show":
    props = args[2].split("=", 1)[1].split(",")
    u = units.get(args[1], {})
    for p in props:
        print(p + "=" + str(u.get(p, "")))
    sys.exit(0)
sys.exit(1)
`

// The fake setpriv logs the first two words of each command it runs.
const spireAgentGuardSetpriv = `import json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
i = sys.argv.index("--")
with open(os.path.join(ROOT, "setpriv.log"), "a") as log:
    log.write(json.dumps(sys.argv[i + 1:i + 3]) + "\n")
os.execv(sys.argv[i + 1], sys.argv[i + 1:])
`

const spireAgentGuardServer = `import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if sys.argv[1:3] == ["bundle", "show"]:
    sys.stdout.write(open(os.path.join(ROOT, "server-bundle.pem")).read())
    sys.exit(0)
if sys.argv[1:3] == ["agent", "list"] and os.path.exists(os.path.join(ROOT, "agent-list.json")):
    sys.stdout.write(open(os.path.join(ROOT, "agent-list.json")).read())
    sys.exit(0)
sys.exit(1)
`

const spireAgentGuardAgent = `import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if sys.argv[1:2] == ["validate"]:
    sys.exit(int(open(os.path.join(ROOT, "validate-rc")).read()))
sys.exit(1)
`

type spireAgentGuardRoot struct {
	t      *testing.T
	root   string
	python string
	module string
	layout map[string]any
	units  map[string]map[string]string
	extra  map[string]any
}

func newSPIREAgentGuardRoot(t *testing.T, python, openssl string) *spireAgentGuardRoot {
	t.Helper()
	root, err := os.MkdirTemp("", "raa")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	cur, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	grp, err := user.LookupGroupId(cur.Gid)
	if err != nil {
		t.Fatal(err)
	}
	a := &spireAgentGuardRoot{t: t, root: root, python: python, units: map[string]map[string]string{}, extra: map[string]any{}}
	for _, d := range []string{"bin", "mod", "usr/local", "etc/systemd/system", "etc/spire/agent", "run/s"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{"usr", "usr/local", "etc", "etc/systemd", "etc/systemd/system", "etc/spire", "etc/spire/agent", "run"} {
		a.chmod(filepath.Join(root, d), 0o755)
	}
	a.chmod(filepath.Join(root, "run/s"), 0o700)
	a.module = filepath.Join(root, "mod", "remote_alpha_spire_agent.py")
	a.write(a.module, string(spireAgentHelperRead(t, spireAgentHelperModule)), 0o644)
	for name, body := range map[string]string{"systemctl": spireAgentGuardSystemctl, "setpriv": spireAgentGuardSetpriv, "spire-server": spireAgentGuardServer, "spire-agent": spireAgentGuardAgent, "tmpfiles": "import sys\nsys.exit(0)\n"} {
		a.write(filepath.Join(root, "bin", name), "#!"+python+" -I\n"+body, 0o755)
	}
	sock := filepath.Join(root, "run/s/api.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen %s: %v", sock, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	a.chmod(sock, 0o600)
	bundle := filepath.Join(root, "etc/spire/agent/bootstrap-bundle.pem")
	a.layout = map[string]any{
		"spire_user": cur.Username, "spire_group": grp.Name, "file_owner": cur.Username, "file_group": grp.Name,
		"required_euid": os.Geteuid(), "server_socket": sock, "runtime_dir_root": filepath.Join(root, "run"),
		"agent_config": filepath.Join(root, "etc/spire/agent/agent.conf"), "bundle_path": bundle,
		"systemd_unit_dir":      filepath.Join(root, "etc/systemd/system"),
		"installed_helper_path": filepath.Join(root, "usr/local/libexec/es/remote_alpha_spire_agent.py"),
		"installed_helper_dirs": []string{filepath.Join(root, "usr/local/libexec"), filepath.Join(root, "usr/local/libexec/es")},
		"lock_path":             filepath.Join(root, "run/es-lock/lock"),
		"spire_server_bin":      filepath.Join(root, "bin/spire-server"), "spire_agent_bin": filepath.Join(root, "bin/spire-agent"),
		"systemctl_bin": filepath.Join(root, "bin/systemctl"), "setpriv_bin": filepath.Join(root, "bin/setpriv"),
		"openssl_bin": openssl, "tmpfiles_bin": filepath.Join(root, "bin/tmpfiles"),
		"command_path_env": filepath.Dir(python) + ":/usr/bin:/bin",
		"python_argv":      []string{python, "-I", "-B", "-S"},
	}
	a.setAgentConf(bundle)
	a.write(filepath.Join(root, "validate-rc"), "0", 0o644)
	ca := spireAgentHelperTestCert(t, true, "spiffe://"+spireAgentHelperTrustDomain, time.Now().Add(time.Hour))
	a.write(filepath.Join(root, "server-bundle.pem"), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca})), 0o644)
	a.units["spire-server.service"] = map[string]string{"ActiveState": "active", "LoadState": "loaded"}
	a.units[spireAgentHelperRefreshUnit+".service"] = map[string]string{"LoadState": "loaded", "Result": "success", "FragmentPath": a.unitPath(".service")}
	a.units[spireAgentHelperRefreshUnit+".timer"] = map[string]string{"LoadState": "loaded", "UnitFileState": "disabled", "ActiveState": "inactive", "FragmentPath": a.unitPath(".timer")}
	return a
}

func (a *spireAgentGuardRoot) unitPath(suffix string) string {
	return filepath.Join(a.root, "etc/systemd/system", spireAgentHelperRefreshUnit+suffix)
}

// enabledTimer marks the timer enabled and active, as after an install.
func (a *spireAgentGuardRoot) enabledTimer() {
	a.units[spireAgentHelperRefreshUnit+".timer"]["UnitFileState"] = "enabled"
	a.units[spireAgentHelperRefreshUnit+".timer"]["ActiveState"] = "active"
}

func (a *spireAgentGuardRoot) chmod(path string, mode os.FileMode) {
	a.t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		a.t.Fatal(err)
	}
}

func (a *spireAgentGuardRoot) write(path, content string, mode os.FileMode) {
	a.t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		a.t.Fatal(err)
	}
	a.chmod(path, mode)
}

func (a *spireAgentGuardRoot) setAgentConf(bundle string) {
	a.t.Helper()
	conf := a.layout["agent_config"].(string)
	a.write(conf, "agent {\n    data_dir = \"/nonexistent\"\n    trust_domain = \""+spireAgentHelperTrustDomain+"\"\n    trust_bundle_path = \""+bundle+"\"\n}\n", 0o644)
}

func (a *spireAgentGuardRoot) state() map[string]any {
	a.t.Helper()
	data, err := os.ReadFile(filepath.Join(a.root, "systemd.json"))
	if err != nil {
		a.t.Fatal(err)
	}
	var st map[string]any
	if err := json.Unmarshal(data, &st); err != nil {
		a.t.Fatal(err)
	}
	return st
}

func (a *spireAgentGuardRoot) run(c string) (int, map[string]any) {
	a.t.Helper()
	for path, value := range map[string]any{"layout.json": a.layout, "systemd.json": map[string]any{"units": a.units, "reload_mutates": a.extra["reload_mutates"], "on_reload": a.extra["on_reload"]}} {
		data, err := json.Marshal(value)
		if err != nil {
			a.t.Fatal(err)
		}
		a.write(filepath.Join(a.root, path), string(data), 0o644)
	}
	driver := filepath.Join(a.root, "driver.py")
	a.write(driver, spireAgentGuardDriver, 0o644)
	cmd := exec.Command(a.python, "-I", "-B", driver, a.module, c, a.root)
	cmd.Dir = executionSubstrateRepoRoot
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		a.t.Fatalf("driver %s: %v", c, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		a.t.Fatalf("driver %s printed %q (stderr %q): %v", c, out, stderr.String(), err)
	}
	return code, doc
}

func spireAgentGuardCheck(doc map[string]any, name string) (string, string) {
	checks, _ := doc["checks"].([]any)
	for _, c := range checks {
		m := c.(map[string]any)
		if m["name"] == name {
			return m["state"].(string), m["detail"].(string)
		}
	}
	return "", ""
}

// TestRemoteAlphaSPIREAgentPinRefusesACopyDirectoryAnotherAccountOwns runs
// pin as root, as on the box, against a copy directory that another account
// owns. Only root can give a directory another owner, so the test skips
// itself without root. .github/ci/environment-only-tests.txt lists it, and
// the step "Listed tests pass as root" of go.yml runs it as root;
// .github/ci/environment-only-tests-macos.txt lists it for the macOS runner.
// Without root, TestRemoteAlphaSPIREAgentTimerInstallChecks covers the same
// check by expecting root as the owner of directories the test user owns.
func TestRemoteAlphaSPIREAgentPinRefusesACopyDirectoryAnotherAccountOwns(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to give the directory another owner")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatalf("needs python3: %v", err)
	}
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Fatalf("needs openssl: %v", err)
	}
	a := newSPIREAgentGuardRoot(t, python, openssl)
	d := filepath.Join(a.root, "usr/local/libexec")
	if err := os.Mkdir(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(d, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	_, doc := a.run("inspect")
	if doc["ok"] != false || !strings.Contains(doc["reason"].(string), d+" is ") {
		t.Fatalf("want a refusal naming %q, got %v", d, doc)
	}
}

func TestRemoteAlphaSPIREAgentTimerAndRefreshGuards(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("needs python3: %v", err)
	}
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skipf("needs openssl: %v", err)
	}
	refusal := func(t *testing.T, doc map[string]any, want string) {
		t.Helper()
		if doc["ok"] != false || !strings.Contains(doc["reason"].(string), want) {
			t.Fatalf("want a refusal naming %q, got %v", want, doc)
		}
	}

	t.Run("inspect_plans_an_install", func(t *testing.T) {
		a := newSPIREAgentGuardRoot(t, python, openssl)
		_, doc := a.run("inspect")
		if doc["ok"] != true || !strings.Contains(strings.Join(func() []string {
			var s []string
			for _, p := range doc["plan"].([]any) {
				s = append(s, p.(string))
			}
			return s
		}(), " "), "install the bundle refresh timer") {
			t.Fatalf("inspect: %v", doc)
		}
	})
	t.Run("pin_refuses_its_own_file_when_group_writable", func(t *testing.T) {
		a := newSPIREAgentGuardRoot(t, python, openssl)
		a.chmod(a.module, 0o664)
		_, doc := a.run("inspect")
		refusal(t, doc, "pin installs a copy of it for the refresh timer only when")
	})
	t.Run("pin_refuses_a_copy_directory_others_can_write", func(t *testing.T) {
		a := newSPIREAgentGuardRoot(t, python, openssl)
		d := filepath.Join(a.root, "usr/local/libexec")
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
		a.chmod(d, 0o775)
		_, doc := a.run("inspect")
		refusal(t, doc, d+" is ")
	})
	t.Run("pin_refuses_when_the_parent_of_the_copy_directories_is_writable", func(t *testing.T) {
		a := newSPIREAgentGuardRoot(t, python, openssl)
		a.chmod(filepath.Join(a.root, "usr/local"), 0o775)
		_, doc := a.run("inspect")
		refusal(t, doc, filepath.Join(a.root, "usr/local")+" is ")
	})
	t.Run("status_flags_a_copy_others_can_write", func(t *testing.T) {
		a := newSPIREAgentGuardRoot(t, python, openssl)
		a.enabledTimer()
		_, doc := a.run("timer-check-0666")
		if state, detail := spireAgentGuardCheck(doc, "refresh timer"); state != "attention" || !strings.Contains(detail, "remote_alpha_spire_agent.py is not as pin writes it") {
			t.Fatalf("status accepted a world-writable copy: %s %s", state, detail)
		}
	})
	t.Run("timer_check_ok", func(t *testing.T) {
		a := newSPIREAgentGuardRoot(t, python, openssl)
		a.enabledTimer()
		_, doc := a.run("timer-check-0644")
		if state, detail := spireAgentGuardCheck(doc, "refresh timer"); state != "ok" {
			t.Fatalf("status on an installed timer: %s %s", state, detail)
		}
	})
	t.Run("status_flags_a_disabled_timer", func(t *testing.T) {
		a := newSPIREAgentGuardRoot(t, python, openssl)
		_, doc := a.run("timer-check-0644")
		if state, detail := spireAgentGuardCheck(doc, "refresh timer"); state != "attention" || !strings.Contains(detail, "is disabled and inactive") {
			t.Fatalf("status accepted a disabled timer: %s %s", state, detail)
		}
	})
	t.Run("status_flags_a_stopped_timer", func(t *testing.T) {
		a := newSPIREAgentGuardRoot(t, python, openssl)
		a.units[spireAgentHelperRefreshUnit+".timer"]["UnitFileState"] = "enabled"
		_, doc := a.run("timer-check-0644")
		if state, detail := spireAgentGuardCheck(doc, "refresh timer"); state != "attention" || !strings.Contains(detail, "is enabled and inactive") {
			t.Fatalf("status accepted a stopped timer: %s %s", state, detail)
		}
	})
	t.Run("install_that_systemd_does_not_load_is_rolled_back_and_disabled", func(t *testing.T) {
		a := newSPIREAgentGuardRoot(t, python, openssl)
		a.units[spireAgentHelperRefreshUnit+".service"] = map[string]string{"LoadState": "not-found"}
		_, doc := a.run("install")
		if doc["ok"] != false || doc["kind"] != "Failure" || !strings.Contains(doc["reason"].(string), "its files were put back as they were") ||
			!strings.Contains(doc["reason"].(string), "systemd reports "+spireAgentHelperRefreshUnit+".service as not-found, not loaded") {
			t.Fatalf("an install whose service did not load was not a failure naming its load state: %v", doc)
		}
		timer := a.state()["units"].(map[string]any)[spireAgentHelperRefreshUnit+".timer"].(map[string]any)
		if timer["UnitFileState"] != "disabled" || timer["ActiveState"] != "inactive" {
			t.Fatalf("rollback left the timer %v", timer)
		}
		for _, p := range []string{"usr/local/libexec", "etc/systemd/system/" + spireAgentHelperRefreshUnit + ".service"} {
			if _, err := os.Lstat(filepath.Join(a.root, p)); !os.IsNotExist(err) {
				t.Fatalf("rollback left %s (%v)", p, err)
			}
		}
	})
	t.Run("install_whose_files_change_before_the_check_fails", func(t *testing.T) {
		a := newSPIREAgentGuardRoot(t, python, openssl)
		a.extra["reload_mutates"] = filepath.Join(a.root, "etc/systemd/system", spireAgentHelperRefreshUnit+".service")
		_, doc := a.run("install")
		if doc["ok"] != false || !strings.Contains(doc["reason"].(string), spireAgentHelperRefreshUnit+".service is not as pin writes it") {
			t.Fatalf("an install whose unit file changed was accepted: %v", doc)
		}
	})
	refreshDoc := func(t *testing.T, a *spireAgentGuardRoot, c string) (int, string, string) {
		t.Helper()
		code, doc := a.run(c)
		res, _ := doc["result"].(string)
		msg, _ := doc["message"].(string)
		return code, res, msg
	}
	t.Run("refresh_writes_the_server_bundle", func(t *testing.T) {
		a := newSPIREAgentGuardRoot(t, python, openssl)
		code, res, msg := refreshDoc(t, a, "refresh")
		if code != 0 || res != "ok" || !strings.HasPrefix(msg, "refreshed") {
			t.Fatalf("refresh: %d %s %s", code, res, msg)
		}
		if got, want := spireAgentHelperRead(t, a.layout["bundle_path"].(string)), spireAgentHelperRead(t, filepath.Join(a.root, "server-bundle.pem")); string(got) != string(want) {
			t.Fatalf("bundle file %q, want %q", got, want)
		}
	})
	t.Run("refresh_waits_for_no_one_holding_the_lock", func(t *testing.T) {
		a := newSPIREAgentGuardRoot(t, python, openssl)
		code, res, msg := refreshDoc(t, a, "refresh-locked")
		if code != 1 || res != "refused" || !strings.Contains(msg, "another run of this helper holds the lock") {
			t.Fatalf("refresh with the lock held: %d %s %s", code, res, msg)
		}
		if _, err := os.Lstat(a.layout["bundle_path"].(string)); !os.IsNotExist(err) {
			t.Fatalf("refresh with the lock held wrote the bundle file")
		}
	})
	t.Run("refresh_refuses_a_config_spire_does_not_confirm", func(t *testing.T) {
		a := newSPIREAgentGuardRoot(t, python, openssl)
		a.write(filepath.Join(a.root, "validate-rc"), "1", 0o644)
		code, res, msg := refreshDoc(t, a, "refresh")
		if code != 1 || res != "refused" || !strings.Contains(msg, "SPIRE's own parser does not confirm it") {
			t.Fatalf("refresh with spire-agent validate refusing: %d %s %s", code, res, msg)
		}
	})
	t.Run("refresh_refuses_a_bundle_path_that_is_a_symlink", func(t *testing.T) {
		a := newSPIREAgentGuardRoot(t, python, openssl)
		target := filepath.Join(a.root, "elsewhere.pem")
		a.write(target, "", 0o644)
		bundle := a.layout["bundle_path"].(string)
		if err := os.Symlink(target, bundle); err != nil {
			t.Fatal(err)
		}
		code, res, msg := refreshDoc(t, a, "refresh")
		if code != 1 || res != "refused" || !strings.Contains(msg, "is not a regular file") {
			t.Fatalf("refresh over a symlink: %d %s %s", code, res, msg)
		}
		if st, err := os.Lstat(bundle); err != nil || st.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("refresh replaced the symlink (%v)", err)
		}
	})
	t.Run("refresh_refuses_a_missing_bundle_directory", func(t *testing.T) {
		a := newSPIREAgentGuardRoot(t, python, openssl)
		bundle := filepath.Join(a.root, "etc/spire/missing/bootstrap-bundle.pem")
		a.layout["bundle_path"] = bundle
		a.setAgentConf(bundle)
		code, res, msg := refreshDoc(t, a, "refresh")
		if code != 1 || res != "refused" || !strings.Contains(msg, "is not a directory") {
			t.Fatalf("refresh with no bundle directory: %d %s %s", code, res, msg)
		}
	})

	// systemd must run the unit files pin wrote, and nothing else.
	t.Run("status_flags_a_drop_in", func(t *testing.T) {
		a := newSPIREAgentGuardRoot(t, python, openssl)
		a.enabledTimer()
		dropin := a.unitPath(".service") + ".d/override.conf"
		a.units[spireAgentHelperRefreshUnit+".service"]["DropInPaths"] = dropin
		_, doc := a.run("timer-check-0644")
		if state, detail := spireAgentGuardCheck(doc, "refresh timer"); state != "attention" || !strings.Contains(detail, spireAgentHelperRefreshUnit+".service has drop-ins that change it: "+dropin) {
			t.Fatalf("status accepted a drop-in: %s %s", state, detail)
		}
	})
	t.Run("status_flags_a_unit_systemd_loads_from_elsewhere", func(t *testing.T) {
		a := newSPIREAgentGuardRoot(t, python, openssl)
		a.enabledTimer()
		elsewhere := filepath.Join(a.root, "run/systemd/system", spireAgentHelperRefreshUnit+".timer")
		a.units[spireAgentHelperRefreshUnit+".timer"]["FragmentPath"] = elsewhere
		_, doc := a.run("timer-check-0644")
		if state, detail := spireAgentGuardCheck(doc, "refresh timer"); state != "attention" || !strings.Contains(detail, "systemd loads "+spireAgentHelperRefreshUnit+".timer from "+elsewhere+", not "+a.unitPath(".timer")) {
			t.Fatalf("status accepted a unit loaded from elsewhere: %s %s", state, detail)
		}
	})
	t.Run("status_flags_a_unit_systemd_has_not_reloaded", func(t *testing.T) {
		a := newSPIREAgentGuardRoot(t, python, openssl)
		a.enabledTimer()
		a.units[spireAgentHelperRefreshUnit+".service"]["NeedDaemonReload"] = "yes"
		_, doc := a.run("timer-check-0644")
		if state, detail := spireAgentGuardCheck(doc, "refresh timer"); state != "attention" || !strings.Contains(detail, spireAgentHelperRefreshUnit+".service changed on disk since systemd last loaded it") {
			t.Fatalf("status accepted a unit systemd has not reloaded: %s %s", state, detail)
		}
	})
	t.Run("pin_refuses_to_install_around_a_drop_in", func(t *testing.T) {
		a := newSPIREAgentGuardRoot(t, python, openssl)
		a.units[spireAgentHelperRefreshUnit+".timer"]["DropInPaths"] = a.unitPath(".timer") + ".d/x.conf"
		_, doc := a.run("inspect")
		refusal(t, doc, spireAgentHelperRefreshUnit+".timer has drop-ins")
	})
	t.Run("pin_refuses_a_unit_systemd_loads_from_elsewhere", func(t *testing.T) {
		a := newSPIREAgentGuardRoot(t, python, openssl)
		a.units[spireAgentHelperRefreshUnit+".service"]["FragmentPath"] = filepath.Join(a.root, "run/systemd/transient", spireAgentHelperRefreshUnit+".service")
		_, doc := a.run("inspect")
		refusal(t, doc, "which pin does not manage")
	})
	t.Run("pin_reloads_systemd_when_it_has_not_loaded_the_files", func(t *testing.T) {
		a := newSPIREAgentGuardRoot(t, python, openssl)
		a.enabledTimer()
		_, doc := a.run("inspect-seeded")
		if doc["ok"] != true || len(doc["plan"].([]any)) != 0 {
			t.Fatalf("an installed timer was not left alone: %v", doc)
		}
		a.units[spireAgentHelperRefreshUnit+".timer"]["NeedDaemonReload"] = "yes"
		_, doc = a.run("inspect-seeded")
		if doc["ok"] != true || len(doc["plan"].([]any)) != 1 || !strings.Contains(doc["plan"].([]any)[0].(string), "run systemctl daemon-reload") {
			t.Fatalf("pin did not plan a daemon-reload for a unit systemd has not loaded: %v", doc)
		}
	})
	t.Run("install_whose_unit_gains_a_drop_in_is_rolled_back", func(t *testing.T) {
		a := newSPIREAgentGuardRoot(t, python, openssl)
		a.extra["on_reload"] = map[string]any{spireAgentHelperRefreshUnit + ".service": map[string]string{"DropInPaths": "/run/systemd/system/x.service.d/y.conf"}}
		_, doc := a.run("install")
		if doc["ok"] != false || doc["kind"] != "Failure" || !strings.Contains(doc["reason"].(string), "has drop-ins that change it") || !strings.Contains(doc["reason"].(string), "its files were put back as they were") {
			t.Fatalf("an install whose unit gained a drop-in was accepted: %v", doc)
		}
		if _, err := os.Lstat(a.unitPath(".service")); !os.IsNotExist(err) {
			t.Fatalf("rollback left the service unit (%v)", err)
		}
		if timer := a.state()["units"].(map[string]any)[spireAgentHelperRefreshUnit+".timer"].(map[string]any); timer["UnitFileState"] != "disabled" {
			t.Fatalf("rollback left the timer %v", timer)
		}
	})
	t.Run("install_that_systemd_has_not_loaded_fails", func(t *testing.T) {
		a := newSPIREAgentGuardRoot(t, python, openssl)
		a.extra["on_reload"] = map[string]any{spireAgentHelperRefreshUnit + ".timer": map[string]string{"NeedDaemonReload": "yes"}}
		_, doc := a.run("install")
		if doc["ok"] != false || !strings.Contains(doc["reason"].(string), spireAgentHelperRefreshUnit+".timer changed on disk since systemd last loaded it") {
			t.Fatalf("an install systemd had not loaded was accepted: %v", doc)
		}
	})
	// Whoever can write a directory that holds the copy can replace the file
	// root runs: status flags each one, as pin refuses it.
	for _, rel := range []string{"usr/local", "usr/local/libexec", "usr/local/libexec/es"} {
		t.Run("status_flags_a_writable_helper_directory_"+strings.ReplaceAll(rel, "/", "_"), func(t *testing.T) {
			a := newSPIREAgentGuardRoot(t, python, openssl)
			a.enabledTimer()
			if _, doc := a.run("timer-check-0644"); func() string { s, _ := spireAgentGuardCheck(doc, "refresh timer"); return s }() != "ok" {
				t.Fatalf("status on an installed timer: %v", doc)
			}
			d := filepath.Join(a.root, rel)
			a.chmod(d, 0o775)
			_, doc := a.run("timer-check")
			if state, detail := spireAgentGuardCheck(doc, "refresh timer"); state != "attention" || !strings.Contains(detail, d+" is ") || !strings.Contains(detail, "needs directories owned by") {
				t.Fatalf("status accepted a writable %s: %s %s", rel, state, detail)
			}
		})
	}
	// The lock lives in a directory of its own (the refresh unit's
	// RuntimeDirectory=): refresh creates it 0700 and refuses one that is
	// not this user's or that others can write.
	t.Run("refresh_creates_its_lock_directory", func(t *testing.T) {
		a := newSPIREAgentGuardRoot(t, python, openssl)
		if code, res, msg := refreshDoc(t, a, "refresh"); code != 0 || res != "ok" {
			t.Fatalf("refresh: %d %s %s", code, res, msg)
		}
		st, err := os.Lstat(filepath.Join(a.root, "run/es-lock"))
		if err != nil || !st.IsDir() || st.Mode().Perm() != 0o700 {
			t.Fatalf("lock directory after refresh: %v %v", st, err)
		}
	})
	t.Run("refresh_refuses_a_lock_directory_others_can_write", func(t *testing.T) {
		a := newSPIREAgentGuardRoot(t, python, openssl)
		d := filepath.Join(a.root, "run/es-lock")
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		a.chmod(d, 0o770)
		code, res, msg := refreshDoc(t, a, "refresh")
		if code != 1 || res != "refused" || !strings.Contains(msg, "lock directory "+d+" is ") {
			t.Fatalf("refresh with a group-writable lock directory: %d %s %s", code, res, msg)
		}
		if _, err := os.Lstat(a.layout["bundle_path"].(string)); !os.IsNotExist(err) {
			t.Fatalf("refresh wrote the bundle file without its lock")
		}
	})
	t.Run("refresh_refuses_a_lock_directory_that_is_a_symlink", func(t *testing.T) {
		a := newSPIREAgentGuardRoot(t, python, openssl)
		target := filepath.Join(a.root, "elsewhere-dir")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(a.root, "run/es-lock")); err != nil {
			t.Fatal(err)
		}
		code, res, msg := refreshDoc(t, a, "refresh")
		if code != 1 || res != "refused" || !strings.Contains(msg, "lock directory") {
			t.Fatalf("refresh with a symlinked lock directory: %d %s %s", code, res, msg)
		}
		if entries, _ := os.ReadDir(target); len(entries) != 0 {
			t.Fatalf("refresh created %v through the symlink", entries)
		}
	})
	t.Run("a_bundle_file_written_but_unreadable_is_a_failure_that_says_so", func(t *testing.T) {
		a := newSPIREAgentGuardRoot(t, python, openssl)
		_, doc := a.run("write-then-unreadable")
		if doc["ok"] != false || doc["kind"] != "Failure" || !strings.Contains(doc["reason"].(string), "was written but does not read back as the server bundle (cannot open it)") {
			t.Fatalf("a write that does not read back: %v", doc)
		}
	})
	// The bundle file: an oversized one is replaced, not a reason to refuse.
	t.Run("refresh_replaces_an_oversized_bundle_file", func(t *testing.T) {
		a := newSPIREAgentGuardRoot(t, python, openssl)
		bundle := a.layout["bundle_path"].(string)
		a.write(bundle, strings.Repeat("#", 1<<20+1), 0o644)
		if code, res, msg := refreshDoc(t, a, "refresh"); code != 0 || res != "ok" {
			t.Fatalf("refresh over an oversized file: %d %s %s", code, res, msg)
		}
		if got, want := spireAgentHelperRead(t, bundle), spireAgentHelperRead(t, filepath.Join(a.root, "server-bundle.pem")); string(got) != string(want) {
			t.Fatalf("bundle file after refresh is %d bytes, want the server bundle", len(got))
		}
	})
	t.Run("refresh_refuses_more_certificates_than_it_accepts", func(t *testing.T) {
		a := newSPIREAgentGuardRoot(t, python, openssl)
		var b strings.Builder
		for i := 0; i < 17; i++ {
			der := spireAgentHelperTestCert(t, true, "spiffe://"+spireAgentHelperTrustDomain, time.Now().Add(time.Hour))
			b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		}
		a.write(filepath.Join(a.root, "server-bundle.pem"), b.String(), 0o644)
		code, res, msg := refreshDoc(t, a, "refresh")
		if code != 1 || res != "refused" || !strings.Contains(msg, "holds 17 certificates, more than the 16") {
			t.Fatalf("refresh with 17 server certificates: %d %s %s", code, res, msg)
		}
		if _, err := os.Lstat(a.layout["bundle_path"].(string)); !os.IsNotExist(err) {
			t.Fatalf("refresh wrote a bundle of 17 certificates")
		}
	})
}

// What a process answering the server's admin socket as spire can make
// refresh, which the timer runs as root, do with a huge server bundle: it
// is refused before anything is parsed or written, and the next run with a
// normal bundle succeeds.
func TestRemoteAlphaSPIREAgentServerBundleIsBounded(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("needs python3: %v", err)
	}
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skipf("needs openssl: %v", err)
	}
	a := newSPIREAgentGuardRoot(t, python, openssl)
	// What a process answering the server's admin socket as spire could
	// print: many distinct CA certificates for the trust domain.
	const n = 2000
	var b strings.Builder
	for i := 0; i < n; i++ {
		der := spireAgentHelperTestCert(t, true, "spiffe://"+spireAgentHelperTrustDomain, time.Now().Add(time.Hour))
		b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	a.write(filepath.Join(a.root, "server-bundle.pem"), b.String(), 0o644)
	start := time.Now()
	code, doc := a.run("refresh")
	took := time.Since(start)
	res, _ := doc["result"].(string)
	msg, _ := doc["message"].(string)
	t.Logf("server bundle of %d CA certificates (%d bytes): exit %d, result %q, message %q, %s", n, b.Len(), code, res, msg, took.Round(time.Millisecond))
	st, err := os.Lstat(a.layout["bundle_path"].(string))
	if err == nil {
		t.Errorf("refresh wrote a %d-byte bootstrap bundle from a %d-certificate server bundle; want a refusal before any write", st.Size(), n)
		if strings.Contains(msg, "nothing was changed") {
			t.Errorf("the run reports %q although it replaced the bundle file", msg)
		}
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if code != 1 || res != "refused" {
		t.Errorf("want exit 1 and result refused, got %d %q", code, res)
	}
	// The server answers normally again: the next timer run should put a
	// current bundle back.
	one := spireAgentHelperTestCert(t, true, "spiffe://"+spireAgentHelperTrustDomain, time.Now().Add(time.Hour))
	a.write(filepath.Join(a.root, "server-bundle.pem"), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: one})), 0o644)
	code, doc = a.run("refresh")
	res, _ = doc["result"].(string)
	msg, _ = doc["message"].(string)
	t.Logf("next run with a one-certificate server bundle: exit %d, result %q, message %q", code, res, msg)
	if code != 0 || res != "ok" {
		t.Errorf("the next refresh does not recover: exit %d, result %q, message %q", code, res, msg)
	}
}

// The output bound holds on its own: a server bundle of one certificate
// followed by more than 1 MiB of blank lines (which the PEM parser would
// accept) is refused while it is read, before anything is written.
func TestRemoteAlphaSPIREAgentServerBundleOutputIsBounded(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("needs python3: %v", err)
	}
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skipf("needs openssl: %v", err)
	}
	a := newSPIREAgentGuardRoot(t, python, openssl)
	der := spireAgentHelperTestCert(t, true, "spiffe://"+spireAgentHelperTrustDomain, time.Now().Add(time.Hour))
	a.write(filepath.Join(a.root, "server-bundle.pem"), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))+strings.Repeat("\n", 1<<20), 0o644)
	code, doc := a.run("refresh")
	if res, msg := doc["result"], doc["message"]; code != 1 || res != "refused" || !strings.Contains(msg.(string), "spire-server bundle show printed more than 1048576 bytes") {
		t.Fatalf("refresh with 1 MiB of server output: %d %v %v", code, res, msg)
	}
	if _, err := os.Lstat(a.layout["bundle_path"].(string)); !os.IsNotExist(err) {
		t.Fatalf("refresh wrote the bundle file")
	}
}

// The size of the file refresh would write is checked before writing. The
// server prints CA certificates with single-line base64 bodies, under the
// output bound; written in 64-character lines they would exceed the 1 MiB
// that the helper reads back, so refresh refuses and writes nothing.
func TestRemoteAlphaSPIREAgentBundleFileSizeIsCheckedBeforeWriting(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("needs python3: %v", err)
	}
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skipf("needs openssl: %v", err)
	}
	a := newSPIREAgentGuardRoot(t, python, openssl)
	const limit = 1 << 20
	var printed strings.Builder
	rewritten := 0
	for i := 0; i < 12; i++ {
		body := base64.StdEncoding.EncodeToString(spireAgentGuardBigCACert(t, 64900))
		printed.WriteString("-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----\n")
		rewritten += len("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n") + len(body) + (len(body)+63)/64
	}
	if printed.Len() > limit || rewritten <= limit {
		t.Fatalf("test bundle sizes: printed %d, rewritten %d; want printed <= %d < rewritten", printed.Len(), rewritten, limit)
	}
	a.write(filepath.Join(a.root, "server-bundle.pem"), printed.String(), 0o644)
	code, doc := a.run("refresh")
	if res, msg := doc["result"], doc["message"]; code != 1 || res != "refused" || !strings.Contains(msg.(string), "the server bundle is larger than 1048576 bytes as a PEM file") {
		t.Fatalf("refresh with a bundle that grows past 1 MiB when written: %d %v %v", code, res, msg)
	}
	if _, err := os.Lstat(a.layout["bundle_path"].(string)); !os.IsNotExist(err) {
		t.Fatalf("refresh wrote the bundle file")
	}
}

// spireAgentGuardBigCACert is a CA certificate for the trust domain that
// carries a private extension of padding bytes, to reach a given size.
func spireAgentGuardBigCACert(t *testing.T, padding int) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse("spiffe://" + spireAgentHelperTrustDomain)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		URIs:                  []*url.URL{u},
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtraExtensions:       []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1}, Value: make([]byte, padding)}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// status must not call the refresh timer ok when systemd could not load
// one of its units or has it masked: a drop-in that clears the timer's
// OnCalendar= leaves it LoadState=bad-setting, active, with no next run.
// (Re-check 26, S26-2, and re-check 25, N25-1.)
func TestRemoteAlphaSPIREAgentStatusFlagsAUnitSystemdDoesNotLoad(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("needs python3: %v", err)
	}
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skipf("needs openssl: %v", err)
	}
	for _, suffix := range []string{".service", ".timer"} {
		for _, load := range []string{"bad-setting", "error", "masked"} {
			t.Run(suffix[1:]+"_"+load, func(t *testing.T) {
				a := newSPIREAgentGuardRoot(t, python, openssl)
				a.enabledTimer()
				a.units[spireAgentHelperRefreshUnit+suffix]["LoadState"] = load
				a.units[spireAgentHelperRefreshUnit+suffix]["DropInPaths"] = a.unitPath(suffix) + ".d/o.conf"
				_, doc := a.run("timer-check-0644")
				state, detail := spireAgentGuardCheck(doc, "refresh timer")
				if state != "attention" || !strings.Contains(detail, load) {
					t.Fatalf("status calls a %s unit that systemd reports as %s: %s %s", suffix, load, state, detail)
				}
			})
		}
	}
}
