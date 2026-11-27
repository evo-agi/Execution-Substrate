package scripts_test

// Pins the checks that decide whether pin may install a root-run copy of the
// SPIRE agent helper and two systemd units, how a failed install is put
// back, and what status says about the installed timer. Each scenario runs
// a Python driver against the helper with a fake systemctl and temporary
// directories under the test's own; no SPIRE binaries are needed.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"
)

const spireAgentInstallerDriver = `
import contextlib, grp, importlib.util, io, json, os, pwd, shutil, stat, sys, tempfile, fcntl

spec = importlib.util.spec_from_file_location("ra_spire_agent", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
sys.modules["ra_spire_agent"] = mod
spec.loader.exec_module(mod)
tempfile.tempdir = sys.argv[2]
OWN = mod.read_own_helper(mod.Layout(), for_install=False)
mod.read_own_helper = lambda L, *, for_install: OWN  # the file mode of this checkout is not under test here

USER = pwd.getpwuid(os.geteuid()).pw_name
GROUP = grp.getgrgid(os.getegid()).gr_name
FAKE = '''#!%(py)s
import json, os, sys
S = %(state)r
U = %(units)r
args = sys.argv[1:]
open(os.path.join(S, "log"), "a").write(json.dumps(args) + "\\n")
def flag(n): return os.path.exists(os.path.join(S, n))
if args == ["daemon-reload"]:
    sys.exit(0)
if args[:2] in (["enable", "--now"], ["disable", "--now"]):
    if args[0] == "enable":
        if flag("fail-enable"): sys.exit(1)
        open(os.path.join(S, "enabled"), "w").close()
    elif flag("enabled"):
        os.unlink(os.path.join(S, "enabled"))
    sys.exit(0)
unit = args[1]
loaded = os.path.exists(os.path.join(U, unit))
timer = unit.endswith(".timer")
vals = {"LoadState": "loaded" if loaded else "not-found",
        "FragmentPath": os.path.join(U, unit) if loaded else "", "DropInPaths": "", "NeedDaemonReload": "no",
        "UnitFileState": "enabled" if (timer and flag("enabled")) else "disabled",
        "ActiveState": "active" if (timer and flag("enabled") and not flag("stopped") and not flag("no-activate")) else "inactive",
        "Result": "success", "ExecMainStartTimestamp": "", "ExecMainStatus": "0"}
for p in args[2].split("=", 1)[1].split(","):
    print(p + "=" + vals.get(p, ""))
'''

def world(layout_overrides=None, make_dirs=True, file_owner=None):
    root = tempfile.mkdtemp(prefix="inst-")
    local = os.path.join(root, "usr/local"); lib = os.path.join(local, "libexec"); lib2 = os.path.join(lib, "execution-substrate")
    units = os.path.join(root, "units"); state = os.path.join(root, "state"); lock = os.path.join(root, "lock")
    for d in (local, units, state):
        os.makedirs(d); os.chmod(d, 0o755)
    if make_dirs:
        for d in (lib, lib2):
            os.mkdir(d); os.chmod(d, 0o755)
    fake = os.path.join(root, "systemctl")
    open(fake, "w").write(FAKE % {"py": sys.executable, "state": state, "units": units}); os.chmod(fake, 0o755)
    # a stub of its own for the commands these scenarios never run (macOS has no /bin/true)
    true = os.path.join(root, "true")
    open(true, "w").write("#!/bin/sh\nexit 0\n"); os.chmod(true, 0o755)
    kw = dict(file_owner=file_owner or USER, file_group=GROUP, required_euid=os.geteuid(), systemd_unit_dir=units,
              installed_helper_path=os.path.join(lib2, "remote_alpha_spire_agent.py"), installed_helper_dirs=(lib, lib2),
              systemctl_bin=fake, lock_path=lock, spire_server_bin=true, spire_agent_bin=true,
              setpriv_bin=true, openssl_bin=true, tmpfiles_bin=true)
    kw.update(layout_overrides or {})
    L = mod.Layout(**kw)
    rep = mod.Report("pin", True); r = mod.Runner(L, rep)
    return dict(root=root, local=local, lib=lib, lib2=lib2, units=units, state=state, L=L, rep=rep, r=r, TI=mod.TimerInstall(r, rep))

def flagfile(w, name): open(os.path.join(w["state"], name), "w").close()
def log(w):
    p = os.path.join(w["state"], "log")
    return [json.loads(x) for x in open(p)] if os.path.exists(p) else []
def inspect_refusal(w):
    try:
        w["TI"].inspect(); return None
    except mod.Refusal as exc:
        return str(exc)
def installed(**kw):
    w = world(**kw); w["TI"].inspect(); assert w["TI"].apply() is True; return w
def status_state(w):
    rep = mod.Report("status", False); mod.check_refresh_timer(mod.Runner(w["L"], rep), rep); return rep.checks[0]

R = {}
def rec(name, ok, detail=""): R[name] = {"ok": bool(ok), "detail": detail}

# directory checks of the helper copy (pin refuses before it changes anything)
for name, key, mode in (("copy_dir_group_writable", "lib2", 0o775), ("copy_dir_world_writable", "lib2", 0o777),
                        ("libexec_group_writable", "lib", 0o775), ("usr_local_group_writable", "local", 0o775)):
    w = world(); os.chmod(w[key], mode); msg = inspect_refusal(w)
    rec(name, msg is not None and w[key] in msg and "no one else can write" in msg, str(msg))
w = world(); shutil.rmtree(w["lib2"]); open(w["lib2"], "w").close(); os.chmod(w["lib2"], 0o644); msg = inspect_refusal(w)
rec("copy_dir_is_a_file", msg is not None and w["lib2"] in msg, str(msg))
if os.geteuid() != 0:
    w = world(file_owner=pwd.getpwuid(0).pw_name, layout_overrides=dict(file_group=grp.getgrgid(0).gr_name))
    msg = inspect_refusal(w)
    rec("copy_dir_owned_by_another_user", msg is not None and w["local"] in msg and "owned by" in msg, str(msg))
w = world(); other = os.path.join(w["lib"], "remote_alpha_spire_agent.py")
w2 = world(layout_overrides=dict(installed_helper_path=os.path.join(w["lib"], "other.py")))
msg = inspect_refusal(w2); rec("copy_path_not_directly_in_last_dir", msg is not None and "is not directly in" in msg, str(msg))
w = world(); shutil.rmtree(w["units"]); msg = inspect_refusal(w)
rec("unit_dir_missing", msg is not None and "is not a directory" in msg, str(msg))
w = world(); svc = os.path.join(w["units"], w["L"].refresh_unit_name + ".service")
open(svc, "w").write("[Service]\nExecStart=/bin/true\n"); msg = inspect_refusal(w)
rec("foreign_service_unit_refused", msg is not None and "was not written by" in msg and svc in msg, str(msg))

# a full install, then what status sees
w = installed(); st = status_state(w); rec("installed_status_ok", st["state"] == "ok", st["detail"][:120])
os.chmod(w["L"].installed_helper_path, 0o666); st = status_state(w)
rec("status_flags_copy_mode_0666", st["state"] == "attention" and "is not as pin writes it" in st["detail"], st["detail"][:120])
w = installed(); flagfile(w, "stopped"); st = status_state(w)
rec("status_flags_enabled_but_inactive_timer", st["state"] == "attention" and "inactive" in st["detail"], st["detail"][:120])

# failed installs put everything back
w = world(make_dirs=False); flagfile(w, "fail-enable"); w["TI"].inspect()
try: w["TI"].apply(); err = None
except mod.Failure as exc: err = str(exc)
cmds = [c[0] for c in log(w)]
rec("failed_enable_rolls_back_and_reloads", err is not None and not os.listdir(w["units"]) and not os.path.exists(w["lib"]) and cmds[-1] == "daemon-reload" and "disable" in cmds, f"{err} {cmds}")
w = world(make_dirs=False); flagfile(w, "no-activate"); w["TI"].inspect()
try: w["TI"].apply(); err = None
except mod.Failure as exc: err = str(exc)
rec("timer_that_does_not_start_is_a_failure", err is not None, str(err))
rec("failed_install_disables_the_timer_it_enabled", not os.path.exists(os.path.join(w["state"], "enabled")) and not os.listdir(w["units"]) and not os.path.exists(w["lib"]), str(os.listdir(w["state"])))
# an upgrade that fails restores the previous files
w = installed(); old = {}
for p in list(mod.refresh_unit_texts(w["L"])) + [w["L"].installed_helper_path]:
    open(p, "ab").write(b"\n# older version\n"); old[p] = open(p, "rb").read()
os.unlink(os.path.join(w["state"], "enabled")); flagfile(w, "fail-enable")
ti = mod.TimerInstall(w["r"], w["rep"]); ti.inspect()
try: ti.apply(); err = None
except mod.Failure as exc: err = str(exc)
same = all(open(p, "rb").read() == b for p, b in old.items())
rec("failed_upgrade_restores_previous_files", err is not None and same, str(err))

# refresh takes the helper's lock (last: main() sets umask and signal handlers)
w = world(); fd = os.open(w["L"].lock_path, os.O_RDWR | os.O_CREAT, 0o600); fcntl.flock(fd, fcntl.LOCK_EX)
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    code = mod.main(["refresh", "--json"], w["L"])
msg = json.loads(buf.getvalue())["message"]
rec("refresh_refused_while_another_run_holds_the_lock", code == 1 and "holds the lock" in msg, msg)
print(json.dumps(R, sort_keys=True))
`

func TestRemoteAlphaSPIREAgentTimerInstallChecks(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("needs python3: %v", err)
	}
	dir := t.TempDir()
	driver := filepath.Join(dir, "installer_driver.py")
	if err := os.WriteFile(driver, []byte(spireAgentInstallerDriver), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(python, "-I", "-B", driver, spireAgentHelperModule, t.TempDir())
	cmd.Dir = executionSubstrateRepoRoot
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if exitErr, ok := err.(*exec.ExitError); ok {
			stderr = string(exitErr.Stderr)
		}
		t.Fatalf("driver: %v\n%s", err, stderr)
	}
	var got map[string]struct {
		OK     bool   `json:"ok"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("driver output %q: %v", out, err)
	}
	names := make([]string, 0, len(got))
	for name := range got {
		names = append(names, name)
	}
	sort.Strings(names)
	want := []string{
		"copy_dir_group_writable", "copy_dir_is_a_file", "copy_dir_world_writable", "copy_path_not_directly_in_last_dir",
		"failed_enable_rolls_back_and_reloads", "failed_install_disables_the_timer_it_enabled", "failed_upgrade_restores_previous_files",
		"foreign_service_unit_refused", "installed_status_ok", "libexec_group_writable", "refresh_refused_while_another_run_holds_the_lock",
		"status_flags_copy_mode_0666", "status_flags_enabled_but_inactive_timer", "timer_that_does_not_start_is_a_failure",
		"unit_dir_missing", "usr_local_group_writable",
	}
	if os.Geteuid() != 0 {
		want = append(want, "copy_dir_owned_by_another_user")
		sort.Strings(want)
	}
	if len(names) != len(want) {
		t.Fatalf("driver ran %v, want %v", names, want)
	}
	for i, name := range names {
		if name != want[i] {
			t.Fatalf("driver ran %v, want %v", names, want)
		}
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			if !got[name].OK {
				t.Fatalf("%s: %s", name, got[name].Detail)
			}
		})
	}
}
