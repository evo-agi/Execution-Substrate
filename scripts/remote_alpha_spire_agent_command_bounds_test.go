package scripts_test

// Bounds on what the SPIRE agent helper runs (collect_output, Runner.run)
// and the owner check on its lock directory. Each check here fails when its
// guard is removed: the command timeout and the kill of a command the run
// stops waiting for, the 4 MiB output cap on every command, the cap on
// stderr, the exact limit, a stop signal, and a lock directory that another
// account owns. Adopted from the re-checks of PR #82 (reports 25 and 26).

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestRemoteAlphaSPIREAgentCommandTimeoutOutputCapAndLockOwner runs
// Runner.run against real child processes, and take_lock against a lock
// directory this user does not own (as root, one it gives to 65534; without
// root, /usr).
const spireAgentCommandBoundsDriver = `
import importlib.util, json, os, sys, time
spec = importlib.util.spec_from_file_location("ra_spire_agent", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
sys.modules["ra_spire_agent"] = mod
spec.loader.exec_module(mod)
tmp = sys.argv[2]
R = {}
def rec(name, ok, detail): R[name] = {"ok": bool(ok), "detail": str(detail)}

# 1. A command that outlives command_timeout_seconds is stopped and killed.
L = mod.Layout(command_timeout_seconds=1)
r = mod.Runner(L, mod.Report("status", False))
pidfile = os.path.join(tmp, "pid")
t0 = time.monotonic()
try:
    r.run([sys.executable, "-I", "-S", "-c", "import os,sys,time; open(sys.argv[1],'w').write(str(os.getpid())); time.sleep(20)", pidfile])
    rec("timeout_stops_the_command", False, "returned after %.1fs" % (time.monotonic() - t0))
except mod.CommandError as exc:
    rec("timeout_stops_the_command", "timed out" in str(exc) and time.monotonic() - t0 < 10, "%s after %.1fs" % (exc, time.monotonic() - t0))
pid = int(open(pidfile).read())
try:
    os.kill(pid, 0)
    alive = True
except ProcessLookupError:
    alive = False
rec("timed_out_command_is_killed", not alive, "pid %d alive=%s" % (pid, alive))
if alive:
    os.kill(pid, 9)

# 2. The general output cap applies to every command, not only bundle show.
L = mod.Layout(command_output_max_bytes=65536)
r = mod.Runner(L, mod.Report("status", False))
try:
    r.run([sys.executable, "-I", "-S", "-c", "import sys; sys.stdout.write('x' * 200000)"])
    rec("general_output_cap", False, "no refusal")
except mod.OutputTooLarge as exc:
    rec("general_output_cap", True, exc)

# 3. take_lock refuses a lock directory this user does not own.
if os.geteuid() == 0:
    d = os.path.join(tmp, "lockdir"); os.mkdir(d, 0o700); os.chown(d, 65534, 65534)
    lock = os.path.join(d, "lock")
else:
    lock = "/usr/es-spire-agent-test-lock"   # /usr exists and belongs to root; nothing is created
try:
    fd = mod.take_lock(mod.Layout(lock_path=lock))
    os.close(fd)
    rec("lock_dir_of_another_owner_refused", False, "lock taken")
except mod.Refusal as exc:
    rec("lock_dir_of_another_owner_refused", "lock directory" in str(exc), exc)
except OSError as exc:
    rec("lock_dir_of_another_owner_refused", False, "OSError instead of a refusal: %s" % exc)
print(json.dumps(R, sort_keys=True))
`

func TestRemoteAlphaSPIREAgentCommandTimeoutOutputCapAndLockOwner(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("needs python3: %v", err)
	}
	dir := t.TempDir()
	driver := filepath.Join(dir, "command_bounds_driver.py")
	if err := os.WriteFile(driver, []byte(spireAgentCommandBoundsDriver), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(python, "-I", "-B", driver, spireAgentHelperModule, t.TempDir())
	cmd.Dir = executionSubstrateRepoRoot
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("driver: %v", err)
	}
	var got map[string]struct {
		OK     bool   `json:"ok"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("driver output %q: %v", out, err)
	}
	for _, name := range []string{"timeout_stops_the_command", "timed_out_command_is_killed", "general_output_cap", "lock_dir_of_another_owner_refused"} {
		t.Run(name, func(t *testing.T) {
			res, ok := got[name]
			if !ok {
				t.Fatalf("driver did not run %s", name)
			}
			if !res.OK {
				t.Fatalf("%s: %s", name, res.Detail)
			}
		})
	}
}

// TestRemoteAlphaSPIREAgentCollectOutputStopsWhatRunsPastItsLimits loads
// the helper's own collect_output and runs each scenario against a real
// child process: a command that hangs, floods stdout or stderr, prints
// exactly the limit or one byte more, echoes its stdin, or outlives a stop
// signal.
const spireAgentCollectDriver = `
import importlib.util, json, signal, subprocess, sys, time
spec = importlib.util.spec_from_file_location("h", sys.argv[1])
h = importlib.util.module_from_spec(spec)
sys.modules["h"] = h
spec.loader.exec_module(h)

def start(code):
    return subprocess.Popen([sys.executable, "-I", "-c", code], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

out = {}
SLEEP = "import time; time.sleep(15)"

def attempt(name, code, limit, timeout, stdin=None):
    p = start(code)
    began = time.monotonic()
    try:
        so, se = h.collect_output(p, stdin, limit, timeout)
        out[name] = {"result": "ok", "stdout": len(so), "stderr": len(se)}
    except subprocess.TimeoutExpired:
        out[name] = {"result": "timeout"}
    except h.OutputTooLarge:
        out[name] = {"result": "too_large"}
    out[name]["seconds"] = round(time.monotonic() - began, 1)
    out[name]["child_gone"] = p.poll() is not None
    if p.poll() is None:
        p.kill(); p.wait()

attempt("hangs", SLEEP, 1 << 20, 1.0)
attempt("stdout_flood", "import sys, time; sys.stdout.write('x' * 9000000); sys.stdout.flush(); " + SLEEP, 1 << 20, 5.0)
attempt("stderr_flood", "import sys, time; sys.stderr.write('x' * 9000000); sys.stderr.flush(); " + SLEEP, 1 << 20, 5.0)
attempt("at_the_limit", "import sys; sys.stdout.write('x' * 1000)", 1000, 30.0)
attempt("one_over_the_limit", "import sys; sys.stdout.write('x' * 1001)", 1000, 30.0)
attempt("stdin_echo", "import sys; sys.stdout.write(sys.stdin.read())", 1 << 20, 30.0, stdin=b"y" * 300000)

class Stop(Exception):
    pass
def stop(*_):
    raise Stop()
signal.signal(signal.SIGALRM, stop)
signal.alarm(1)
p = start(SLEEP)
began = time.monotonic()
try:
    h.collect_output(p, None, 1 << 20, 5.0)
    out["stop_signal"] = {"result": "ok"}
except Stop:
    out["stop_signal"] = {"result": "stopped"}
out["stop_signal"]["seconds"] = round(time.monotonic() - began, 1)
out["stop_signal"]["child_gone"] = p.poll() is not None
if p.poll() is None:
    p.kill(); p.wait()
print(json.dumps(out))
`

func TestRemoteAlphaSPIREAgentCollectOutputStopsWhatRunsPastItsLimits(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("needs python3: %v", err)
	}
	driver := filepath.Join(t.TempDir(), "driver.py")
	if err := os.WriteFile(driver, []byte(spireAgentCollectDriver), 0o644); err != nil {
		t.Fatal(err)
	}
	// A collect_output that never enforces its deadline would hang here.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "-I", "-B", driver, spireAgentHelperModule)
	cmd.Dir = executionSubstrateRepoRoot
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("collect_output scenarios did not finish: %v", err)
	}
	var got map[string]struct {
		Result    string  `json:"result"`
		Stdout    int     `json:"stdout"`
		Stderr    int     `json:"stderr"`
		Seconds   float64 `json:"seconds"`
		ChildGone bool    `json:"child_gone"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	for name, want := range map[string]string{
		"hangs": "timeout", "stdout_flood": "too_large", "stderr_flood": "too_large",
		"at_the_limit": "ok", "one_over_the_limit": "too_large", "stdin_echo": "ok", "stop_signal": "stopped",
	} {
		if got[name].Result != want {
			t.Errorf("%s: %s, want %s (%+v)", name, got[name].Result, want, got[name])
		}
	}
	for _, name := range []string{"hangs", "stdout_flood", "stderr_flood", "stop_signal"} {
		if !got[name].ChildGone {
			t.Errorf("%s: the command was left running (%+v)", name, got[name])
		}
		if got[name].Seconds > 10 {
			t.Errorf("%s: took %.1f s, well past its limit (%+v)", name, got[name].Seconds, got[name])
		}
	}
	if got["stdin_echo"].Stdout != 300000 {
		t.Errorf("stdin_echo: the command's stdin was not fed whole (%+v)", got["stdin_echo"])
	}
}
