package scripts_test

// Tests for scripts/remote_alpha_spire_agent.sh and its Python core
// scripts/internal/remote_alpha_spire_agent.py.
//
// The two flow tests drive the helper against real SPIRE 1.14.4 binaries:
// the release tarball named by SUPPORTED_LOCAL_TEST_SPIRE_TARBALL (CI sets
// it), checked against scripts/internal/spire_release.sha256. The server and
// agent configurations copy the box's (join token attestation, disk key
// managers, unix workload attestor, the same alias and workload entries)
// with a short CA lifetime and a 60 s (pin test) or 15 s (recover test) SVID
// lifetime. systemd is replaced by a small fake systemctl
// that runs the real binaries and follows the box units' Requires= chain
// (es.service -> spire-agent.service -> spire-server.service), and setpriv by
// a fake that checks its arguments and runs the command as the test user.
// So these tests do not prove systemd's or setpriv's own behaviour; the box
// run does.

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	spireAgentHelperTrustDomain = "execution.internal"
	spireAgentHelperAlias       = "spiffe://execution.internal/spire-agent"
	spireAgentHelperWorkload    = "spiffe://execution.internal/workload"
)

var spireAgentHelperModule = filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_spire_agent.py")

// spireAgentHelperDriver imports the helper module from its path and runs
// main with a Layout built from a JSON file of overrides, or prints the
// default Layout, or classifies an agent.conf, or runs the SPIRE-side
// pinned check with a Layout from a JSON file, or runs the server bundle
// checks on a PEM file standing in for "spire-server bundle show" output
// (only the spire-server call is replaced; openssl runs for real). It is
// test code only.
const spireAgentHelperDriver = `import dataclasses, importlib.util, json, sys
spec = importlib.util.spec_from_file_location("ra_spire_agent", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)
if sys.argv[2] == "--dump-layout":
    print(json.dumps(dataclasses.asdict(mod.Layout()), sort_keys=True))
    sys.exit(0)
if sys.argv[2] == "--group-members":
    print(json.dumps(sorted(mod.group_members(sys.argv[3]))))
    sys.exit(0)
if sys.argv[2] == "--analyze-config":
    print(json.dumps(mod.analyze_agent_config(open(sys.argv[3], newline="").read(), sys.argv[4]), sort_keys=True))
    sys.exit(0)
if sys.argv[2] == "--confirm-pinned":
    overrides = json.load(open(sys.argv[3]))
    for key, value in list(overrides.items()):
        if isinstance(value, list):
            overrides[key] = tuple(value)
    ok, detail = mod.spire_confirms_pinned(mod.Runner(mod.Layout(**overrides), mod.Report("status", False)))
    print(json.dumps({"ok": ok, "detail": detail}))
    sys.exit(0)
if sys.argv[2] == "--export-bundle":
    pem = open(sys.argv[3], newline="").read()
    real_text = mod.Runner.text
    def fake_text(self, argv, **kwargs):
        if argv[0] == self.L.spire_server_bin:
            return pem
        return real_text(self, argv, **kwargs)
    mod.Runner.text = fake_text
    layout = mod.Layout(openssl_bin=sys.argv[4])
    try:
        ders = mod.export_server_bundle(mod.Runner(layout, mod.Report("status", False)))
        print(json.dumps({"ok": True, "count": len(ders)}))
    except mod.Refusal as exc:
        print(json.dumps({"ok": False, "reason": str(exc)}))
    sys.exit(0)
overrides = json.load(open(sys.argv[2]))
for key, value in list(overrides.items()):
    if isinstance(value, list):
        overrides[key] = tuple(value)
sys.exit(mod.main(sys.argv[3:], mod.Layout(**overrides)))
`

// The fake systemctl keeps one pid file per unit and follows the box units'
// Requires= chain: start pulls required units up first, stop takes
// dependents down first, restart restarts active dependents too. A unit with
// a socket waits up to 5 s for it and sets mode 0600, like the box units'
// ExecStartPost, and fails when it does not appear. A file
// <unit>.fail-next-start in the state directory makes the next start of
// that unit fail once. While a file hold-restart exists there, a restart
// stops the unit, adds a line to held-restarts and waits before it starts
// the unit again, so a test can signal the helper inside a restart.
const spireAgentHelperFakeSystemctl = `import json, os, signal, stat, subprocess, sys, time
STATE = %q
cfg = json.load(open(os.path.join(STATE, "units.json")))
with open(os.path.join(STATE, "systemctl.log"), "a") as fh:
    fh.write(json.dumps(sys.argv[1:]) + "\n")

def pidfile(u):
    return os.path.join(STATE, u + ".pid")

def alive(pid):
    try:
        with open("/proc/%%d/stat" %% pid) as fh:
            return fh.read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False

def pid_of(u):
    try:
        pid = int(open(pidfile(u)).read())
    except (OSError, ValueError):
        return 0
    return pid if alive(pid) else 0

def dependents(u):
    return [x for x in cfg if u in cfg[x]["requires"]]

def start(u):
    if pid_of(u):
        return 0
    marker = os.path.join(STATE, u + ".fail-next-start")
    if os.path.exists(marker):
        os.unlink(marker)
        return 1
    for dep in cfg[u]["requires"]:
        if start(dep) != 0:
            return 1
    sock = cfg[u].get("socket")
    if sock and os.path.lexists(sock):
        os.unlink(sock)
    with open(os.path.join(STATE, u + ".log"), "ab") as log:
        p = subprocess.Popen(cfg[u]["argv"], stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True, cwd="/")
    open(pidfile(u), "w").write(str(p.pid))
    if sock:
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                if stat.S_ISSOCK(os.lstat(sock).st_mode):
                    os.chmod(sock, 0o600)
                    return 0
            except OSError:
                pass
            time.sleep(0.1)
        stop(u)
        return 1
    return 0

def stop(u):
    for d in dependents(u):
        stop(d)
    pid = pid_of(u)
    if pid:
        os.kill(pid, signal.SIGTERM)
        deadline = time.time() + 10
        while alive(pid) and time.time() < deadline:
            time.sleep(0.05)
        if alive(pid):
            os.kill(pid, signal.SIGKILL)
    try:
        os.unlink(pidfile(u))
    except OSError:
        pass
    return 0

def active_dependents(u):
    out = []
    for d in dependents(u):
        if pid_of(d):
            out.append(d)
        out.extend(active_dependents(d))
    return out

cmd, unit = sys.argv[1], sys.argv[2]
if unit not in cfg:
    sys.exit(5)
if cmd == "show":
    props = sys.argv[3].split("=", 1)[1].split(",")
    pid = pid_of(unit)
    values = {"ActiveState": "active" if pid else "inactive", "SubState": "running" if pid else "dead",
              "MainPID": str(pid), "NRestarts": "0", "RuntimeDirectory": cfg[unit].get("runtime_directory", ""),
              "LoadState": "loaded"}
    for p in props:
        print(p + "=" + values.get(p, ""))
    sys.exit(0)
if cmd == "start":
    sys.exit(start(unit))
if cmd == "stop":
    sys.exit(stop(unit))
if cmd == "restart":
    deps = active_dependents(unit)
    stop(unit)
    hold = os.path.join(STATE, "hold-restart")
    if os.path.exists(hold):
        with open(os.path.join(STATE, "held-restarts"), "a") as fh:
            fh.write(unit + "\n")
        while os.path.exists(hold):
            time.sleep(0.05)
    rc = start(unit)
    for d in deps:
        rc = rc or start(d)
    sys.exit(rc)
sys.exit(1)
`

// The fake setpriv accepts exactly the argument form the helper uses, for
// the expected account, logs it and runs the command as the test user.
const spireAgentHelperFakeSetpriv = `import json, os, sys
LOG, USER, GROUP = %q, %q, %q
args = sys.argv[1:]
expected = ["--reuid=" + USER, "--regid=" + GROUP, "--init-groups", "--reset-env", "--"]
if args[:5] != expected or len(args) < 6:
    sys.stderr.write("fake setpriv: unexpected arguments %%r\n" %% (args,))
    sys.exit(97)
with open(LOG, "a") as fh:
    fh.write(json.dumps({"tool": "setpriv", "argv": args}) + "\n")
os.execve(args[5], args[5:], {"PATH": "/usr/local/bin:/bin:/usr/bin", "HOME": "/", "USER": USER, "LOGNAME": USER})
`

// A shim in front of a real SPIRE binary logs its argv, and for
// -joinTokenFile the file's mode and owner and which stop signals arrive
// blocked, then runs the real binary.
// While a marker file exists, "validate" fails, or a "run" with a join token
// (in a file or, which the helper must never do, on the command line) exits
// at once, so the tests can reach the helper's failure paths. Two more
// markers hold an attesting run or a "validate" at its start, so a test can
// signal the helper at that point.
const spireAgentHelperShim = `import json, os, sys, time
LOG, REAL, FAIL_VALIDATE, FAIL_ATTEST, HOLD_ATTEST, HOLD_VALIDATE, LINGER, LINGERING = %q, %q, %q, %q, %q, %q, %q, %q
args = sys.argv[1:]
entry = {"tool": os.path.basename(REAL), "argv": args}
if "-joinTokenFile" in args:
    path = args[args.index("-joinTokenFile") + 1]
    st = os.lstat(path)
    entry["token_file"] = {"path": path, "mode": oct(st.st_mode & 0o7777), "uid": st.st_uid, "size": st.st_size,
                           "dir_mode": oct(os.lstat(os.path.dirname(path)).st_mode & 0o7777)}
    if "-config" in args:
        conf = open(args[args.index("-config") + 1]).read().lower()
        entry["config_names_insecure_bootstrap"] = "insecure_bootstrap" in conf
    blocked = int(next(l for l in open("/proc/self/status") if l.startswith("SigBlk:")).split()[1], 16)
    entry["stop_signals_blocked"] = [s for s in (1, 2, 15) if blocked >> (s - 1) & 1]
with open(LOG, "a") as fh:
    fh.write(json.dumps(entry) + "\n")
if LINGER and args[:1] == ["run"] and ("-joinTokenFile" in args or "-joinToken" in args) and os.path.exists(LINGER):
    # An attesting agent that takes its time to exit on SIGTERM: it says
    # so in LINGERING and stays until the LINGER marker is gone.
    import signal
    def linger(signum, frame):
        open(LINGERING, "w").close()
        deadline = time.time() + 30
        while os.path.exists(LINGER) and time.time() < deadline:
            time.sleep(0.05)
        sys.exit(0)
    signal.signal(signal.SIGTERM, linger)
while HOLD_ATTEST and args[:1] == ["run"] and ("-joinTokenFile" in args or "-joinToken" in args) and os.path.exists(HOLD_ATTEST):
    time.sleep(0.05)
while HOLD_VALIDATE and args[:1] == ["validate"] and os.path.exists(HOLD_VALIDATE):
    time.sleep(0.05)
if FAIL_VALIDATE and args[:1] == ["validate"] and os.path.exists(FAIL_VALIDATE):
    print("SPIRE agent configuration file is invalid: injected by the test")
    sys.exit(1)
if FAIL_ATTEST and args[:1] == ["run"] and ("-joinTokenFile" in args or "-joinToken" in args) and os.path.exists(FAIL_ATTEST):
    # The real token first, placed so that cutting this log to its last
    # 1500 bytes splits it in half (the helper must redact before it cuts),
    # then SPIRE's own success line with a quoted agent ID.
    if "-joinTokenFile" in args:
        token = open(args[args.index("-joinTokenFile") + 1]).read()
    else:
        token = args[args.index("-joinToken") + 1]
    rest = ('\ntime="2026-01-01T00:00:00Z" level=info msg="Node attestation was successful" spiffe_id="spiffe://execution.internal/spire/agent/join_token/0f0f0f0f-1e1e-4d4d-8c8c-7b7b7b7b7b7b" subsystem_name=attestor'
            "\nagent crashed: injected by the test\n")
    sys.stdout.write("join token " + token + "." * (1500 - len(token) // 2 - len(rest)) + rest)
    sys.exit(3)
os.execv(REAL, [REAL] + args)
`

type spireAgentHelperBox struct {
	t           *testing.T
	root        string
	python      string
	realServer  string
	realAgent   string
	systemctl   string
	stateDir    string
	logsDir     string
	shimLog     string
	failMarker  string
	failAttest  string
	holdAttest  string
	holdValid   string
	linger      string
	lingering   string
	port        int
	serverConf  string
	agentConf   string
	dataDir     string
	serverSock  string
	agentSock   string
	bundlePath  string
	tmpfilesDir string
	scratch     string
	layoutPath  string
	user        string
	group       string
	uid         int
}

func spireAgentHelperRequireTools(t *testing.T) (tarball, python, tmpfiles string) {
	t.Helper()
	tarball = strings.TrimSpace(os.Getenv("SUPPORTED_LOCAL_TEST_SPIRE_TARBALL"))
	if tarball == "" {
		t.Skip("needs SUPPORTED_LOCAL_TEST_SPIRE_TARBALL: the pinned SPIRE 1.14.4 linux musl release tarball (CI sets it)")
	}
	var err error
	if python, err = exec.LookPath("python3"); err != nil {
		t.Skipf("needs python3: %v", err)
	}
	if tmpfiles, err = exec.LookPath("systemd-tmpfiles"); err != nil {
		t.Skipf("needs systemd-tmpfiles: %v", err)
	}
	if _, err = exec.LookPath("openssl"); err != nil {
		t.Skipf("needs openssl: %v", err)
	}
	return tarball, python, tmpfiles
}

// spireAgentHelperExtract checks the tarball against the repo's SPIRE pin
// file and extracts the two binaries.
func spireAgentHelperExtract(t *testing.T, tarball, dest string) (server, agent string) {
	t.Helper()
	data, err := os.ReadFile(tarball)
	if err != nil {
		t.Fatalf("read SPIRE tarball: %v", err)
	}
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	pins, err := os.ReadFile(filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "spire_release.sha256"))
	if err != nil {
		t.Fatalf("read SPIRE pin file: %v", err)
	}
	pinned := ""
	for _, line := range strings.Split(string(pins), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == got {
			pinned = fields[1]
		}
	}
	if !regexp.MustCompile(`^spire-1\.14\.4-linux-[a-z0-9]+-musl\.tar\.gz$`).MatchString(pinned) {
		t.Fatalf("SPIRE tarball sha256 %s is not pinned for SPIRE 1.14.4 in scripts/internal/spire_release.sha256", got)
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("open SPIRE tarball: %v", err)
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read SPIRE tarball: %v", err)
		}
		name := filepath.Base(hdr.Name)
		if hdr.Typeflag != tar.TypeReg || filepath.Base(filepath.Dir(hdr.Name)) != "bin" || (name != "spire-server" && name != "spire-agent") {
			continue
		}
		out := filepath.Join(dest, name)
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read %s from SPIRE tarball: %v", name, err)
		}
		if err := os.WriteFile(out, body, 0o755); err != nil {
			t.Fatalf("write %s: %v", out, err)
		}
		if name == "spire-server" {
			server = out
		} else {
			agent = out
		}
	}
	if server == "" || agent == "" {
		t.Fatalf("SPIRE tarball lacks bin/spire-server or bin/spire-agent")
	}
	return server, agent
}

func spireAgentHelperFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func spireAgentHelperServerConf(dir, sock string, port int, svidTTL string) string {
	return fmt.Sprintf(`server {
    bind_address = "127.0.0.1"
    bind_port = "%d"
    socket_path = "%s"
    trust_domain = "%s"
    data_dir = "%s"
    log_level = "INFO"
    ca_ttl = "1h"
    default_x509_svid_ttl = "%s"
    default_jwt_svid_ttl = "1m"
    jwt_key_type = "rsa-2048"
    jwt_issuer = "spiffe://%s"
}

plugins {
    DataStore "sql" {
        plugin_data {
            database_type = "sqlite3"
            connection_string = "%s/datastore.sqlite3"
        }
    }

    KeyManager "disk" {
        plugin_data {
            keys_path = "%s/keys.json"
        }
    }

    NodeAttestor "join_token" {
        plugin_data {}
    }
}
`, port, sock, spireAgentHelperTrustDomain, dir, svidTTL, spireAgentHelperTrustDomain, dir, dir)
}

// spireAgentHelperAgentConf has the box agent.conf's shape, including its
// line `    insecure_bootstrap = true`.
func spireAgentHelperAgentConf(dataDir, sock string, port int) string {
	return fmt.Sprintf(`agent {
    data_dir = "%s"
    log_level = "INFO"
    trust_domain = "%s"
    server_address = "127.0.0.1"
    server_port = "%d"
    socket_path = "%s"
    insecure_bootstrap = true
}

plugins {
    KeyManager "disk" {
        plugin_data {
            directory = "%s"
        }
    }

    NodeAttestor "join_token" {
        plugin_data {}
    }

    WorkloadAttestor "unix" {
        plugin_data {}
    }
}
`, dataDir, spireAgentHelperTrustDomain, port, sock, dataDir)
}

// newSPIREAgentHelperBox builds the box shape under a temporary root. The
// agent SVID lives svidTTL (the box: 48h).
func newSPIREAgentHelperBox(t *testing.T, svidTTL string) *spireAgentHelperBox {
	t.Helper()
	tarball, python, tmpfiles := spireAgentHelperRequireTools(t)
	// A short root keeps Unix socket paths far below the 108-byte limit.
	root, err := os.MkdirTemp("", "rasa")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	b := &spireAgentHelperBox{t: t, root: root, python: python}
	t.Cleanup(func() {
		b.stopAll()
		_ = os.RemoveAll(root)
	})
	cur, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	grpEntry, err := user.LookupGroupId(cur.Gid)
	if err != nil {
		t.Fatalf("current group: %v", err)
	}
	b.user, b.group = cur.Username, grpEntry.Name
	b.uid, _ = strconv.Atoi(cur.Uid)
	for _, d := range []string{"bin", "real", "state", "logs", "etc/spire/agent", "etc/spire/server", "tmpfiles/etc/tmpfiles.d", "var/lib/spire/server", "var/lib/spire/agent", "run/spire/server/private", "run/spire/sockets", "scratch"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	// Box modes: data and socket directories are not world readable.
	for d, mode := range map[string]os.FileMode{"var/lib/spire/server": 0o750, "var/lib/spire/agent": 0o750, "run/spire/server/private": 0o700, "run/spire/sockets": 0o750} {
		if err := os.Chmod(filepath.Join(root, d), mode); err != nil {
			t.Fatalf("chmod %s: %v", d, err)
		}
	}
	b.realServer, b.realAgent = spireAgentHelperExtract(t, tarball, filepath.Join(root, "real"))
	b.stateDir = filepath.Join(root, "state")
	b.logsDir = filepath.Join(root, "logs")
	b.shimLog = filepath.Join(b.logsDir, "commands.jsonl")
	b.failMarker = filepath.Join(root, "fail-validate")
	b.failAttest = filepath.Join(root, "fail-attest")
	b.holdAttest = filepath.Join(root, "hold-attest")
	b.holdValid = filepath.Join(root, "hold-validate")
	b.linger = filepath.Join(root, "linger-attest")
	b.lingering = filepath.Join(root, "lingering")
	b.port = spireAgentHelperFreePort(t)
	b.serverSock = filepath.Join(root, "run/spire/server/private/api.sock")
	b.agentSock = filepath.Join(root, "run/spire/sockets/agent.sock")
	b.serverConf = filepath.Join(root, "etc/spire/server/server.conf")
	b.agentConf = filepath.Join(root, "etc/spire/agent/agent.conf")
	b.dataDir = filepath.Join(root, "var/lib/spire/agent")
	b.bundlePath = filepath.Join(root, "etc/spire/agent/bootstrap-bundle.pem")
	b.tmpfilesDir = filepath.Join(root, "tmpfiles")
	b.scratch = filepath.Join(root, "scratch")
	b.write(b.serverConf, spireAgentHelperServerConf(filepath.Join(root, "var/lib/spire/server"), b.serverSock, b.port, svidTTL), 0o644)
	b.write(b.agentConf, spireAgentHelperAgentConf(b.dataDir, b.agentSock, b.port), 0o644)

	b.systemctl = filepath.Join(root, "bin", "systemctl")
	b.write(b.systemctl, "#!"+python+"\n"+fmt.Sprintf(spireAgentHelperFakeSystemctl, b.stateDir), 0o755)
	sleepBin, err := exec.LookPath("sleep")
	if err != nil {
		t.Fatalf("sleep: %v", err)
	}
	units := map[string]any{
		"spire-server.service": map[string]any{"argv": []string{b.realServer, "run", "-config", b.serverConf}, "requires": []string{}, "socket": b.serverSock},
		"spire-agent.service":  map[string]any{"argv": []string{b.realAgent, "run", "-config", b.agentConf}, "requires": []string{"spire-server.service"}, "socket": b.agentSock},
		"es.service":           map[string]any{"argv": []string{sleepBin, "100000"}, "requires": []string{"spire-agent.service"}},
	}
	b.writeJSON(filepath.Join(b.stateDir, "units.json"), units)
	setpriv := filepath.Join(root, "bin", "setpriv")
	b.write(setpriv, "#!"+python+"\n"+fmt.Sprintf(spireAgentHelperFakeSetpriv, b.shimLog, b.user, b.group), 0o755)
	shimServer := filepath.Join(root, "bin", "spire-server")
	shimAgent := filepath.Join(root, "bin", "spire-agent")
	b.write(shimServer, "#!"+python+"\n"+fmt.Sprintf(spireAgentHelperShim, b.shimLog, b.realServer, "", "", "", "", "", ""), 0o755)
	b.write(shimAgent, "#!"+python+"\n"+fmt.Sprintf(spireAgentHelperShim, b.shimLog, b.realAgent, b.failMarker, b.failAttest, b.holdAttest, b.holdValid, b.linger, b.lingering), 0o755)
	openssl, _ := exec.LookPath("openssl")

	layout := map[string]any{
		"spire_user":       b.user,
		"spire_group":      b.group,
		"file_owner":       b.user,
		"file_group":       b.group,
		"required_euid":    os.Geteuid(),
		"server_socket":    b.serverSock,
		"agent_socket":     b.agentSock,
		"agent_config":     b.agentConf,
		"bundle_path":      b.bundlePath,
		"agent_data_dir":   b.dataDir,
		"runtime_dirs":     []string{filepath.Join(root, "run/spire"), filepath.Join(root, "run/spire/server"), filepath.Join(root, "run/spire/server/private"), filepath.Join(root, "run/spire/sockets")},
		"runtime_dir_root": filepath.Join(root, "run"),
		"tmpfiles_root":    b.tmpfilesDir,
		"tmpfiles_path":    filepath.Join(b.tmpfilesDir, "etc/tmpfiles.d/spire.conf"),
		"scratch_parent":   b.scratch,
		"lock_path":        filepath.Join(root, "helper.lock"),
		"spire_server_bin": shimServer,
		"spire_agent_bin":  shimAgent,
		"systemctl_bin":    b.systemctl,
		"setpriv_bin":      setpriv,
		"openssl_bin":      openssl,
		"tmpfiles_bin":     tmpfiles,
		"command_path_env": filepath.Dir(python) + ":/usr/sbin:/usr/bin:/sbin:/bin",
		// The agent renews at about half of a 15 s or 60 s life, so a
		// threshold above 0 would make "attention" depend on timing.
		"svid_attention_seconds":         0,
		"agent_health_timeout_seconds":   30,
		"attestation_timeout_seconds":    30,
		"workload_svid_timeout_seconds":  45,
		"dependent_unit_timeout_seconds": 20,
		"poll_interval_seconds":          0.3,
	}
	b.layoutPath = filepath.Join(root, "layout.json")
	b.writeJSON(b.layoutPath, layout)
	return b
}

func (b *spireAgentHelperBox) write(path, content string, mode os.FileMode) {
	b.t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		b.t.Fatalf("write %s: %v", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		b.t.Fatalf("chmod %s: %v", path, err)
	}
}

func (b *spireAgentHelperBox) writeJSON(path string, v any) {
	b.t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		b.t.Fatalf("marshal %s: %v", path, err)
	}
	b.write(path, string(data), 0o644)
}

func (b *spireAgentHelperBox) ctl(args ...string) {
	b.t.Helper()
	cmd := exec.Command(b.systemctl, args...)
	cmd.Dir = executionSubstrateRepoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		b.t.Fatalf("fake systemctl %v: %v %s", args, err, out)
	}
}

func (b *spireAgentHelperBox) pid(unit string) int {
	data, err := os.ReadFile(filepath.Join(b.stateDir, unit+".pid"))
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil || strings.Fields(string(stat[bytes.LastIndexByte(stat, ')')+1:]))[0] == "Z" {
		return 0
	}
	return pid
}

func (b *spireAgentHelperBox) stopAll() {
	stop := exec.Command(b.systemctl, "stop", "spire-server.service")
	stop.Dir = executionSubstrateRepoRoot
	_ = stop.Run()
	entries, _ := os.ReadDir(b.stateDir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".pid") {
			data, _ := os.ReadFile(filepath.Join(b.stateDir, e.Name()))
			if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 0 {
				if p, err := os.FindProcess(pid); err == nil {
					_ = p.Kill()
				}
			}
		}
	}
}

func (b *spireAgentHelperBox) server(args ...string) []byte {
	b.t.Helper()
	full := append(append([]string{}, args...), "-socketPath", b.serverSock)
	cmd := exec.Command(b.realServer, full...)
	cmd.Dir = executionSubstrateRepoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		b.t.Fatalf("spire-server %v: %v %s", args, err, out)
	}
	return out
}

type spireAgentHelperAgentRecord struct {
	ID        string
	ExpiresAt int64
}

func (b *spireAgentHelperBox) agents() []spireAgentHelperAgentRecord {
	b.t.Helper()
	var doc struct {
		Agents []struct {
			ID struct {
				TrustDomain string `json:"trust_domain"`
				Path        string `json:"path"`
			} `json:"id"`
			ExpiresAt string `json:"x509svid_expires_at"`
		} `json:"agents"`
	}
	if err := json.Unmarshal(b.server("agent", "list", "-output", "json"), &doc); err != nil {
		b.t.Fatalf("parse agent list: %v", err)
	}
	var out []spireAgentHelperAgentRecord
	for _, a := range doc.Agents {
		exp, _ := strconv.ParseInt(a.ExpiresAt, 10, 64)
		out = append(out, spireAgentHelperAgentRecord{ID: "spiffe://" + a.ID.TrustDomain + a.ID.Path, ExpiresAt: exp})
	}
	return out
}

type spireAgentHelperEntry struct {
	ID       string
	SPIFFEID string
	ParentID string
}

func (b *spireAgentHelperBox) entries() []spireAgentHelperEntry {
	b.t.Helper()
	type tdPath struct {
		TrustDomain string `json:"trust_domain"`
		Path        string `json:"path"`
	}
	var doc struct {
		Entries []struct {
			ID       string `json:"id"`
			SPIFFEID tdPath `json:"spiffe_id"`
			ParentID tdPath `json:"parent_id"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(b.server("entry", "show", "-output", "json"), &doc); err != nil {
		b.t.Fatalf("parse entry show: %v", err)
	}
	var out []spireAgentHelperEntry
	for _, e := range doc.Entries {
		out = append(out, spireAgentHelperEntry{ID: e.ID, SPIFFEID: "spiffe://" + e.SPIFFEID.TrustDomain + e.SPIFFEID.Path, ParentID: "spiffe://" + e.ParentID.TrustDomain + e.ParentID.Path})
	}
	return out
}

// localAgentID reads the agent's own SVID from its data directory with Go's
// x509 parser, independently of the helper.
func (b *spireAgentHelperBox) localAgentID(dataDir string) (string, time.Time) {
	b.t.Helper()
	raw, err := os.ReadFile(filepath.Join(dataDir, "agent-data.json"))
	if err != nil {
		return "", time.Time{}
	}
	var doc struct {
		SVID []string `json:"svid"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.SVID) == 0 {
		return "", time.Time{}
	}
	pemBytes, err := base64.StdEncoding.DecodeString(doc.SVID[0])
	if err != nil {
		b.t.Fatalf("decode agent SVID: %v", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		b.t.Fatalf("agent SVID is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || len(cert.URIs) != 1 {
		b.t.Fatalf("parse agent SVID: %v", err)
	}
	return cert.URIs[0].String(), cert.NotAfter
}

func (b *spireAgentHelperBox) waitFor(what string, timeout time.Duration, cond func() bool) {
	b.t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			b.t.Fatalf("timed out after %s waiting for %s", timeout, what)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// bootstrapLikeTheBox starts the server, registers the box's alias and
// workload entries (the workload selector is the test user's UID, since the
// helper's Workload API check runs as the helper's own user), attests the
// agent once with insecure_bootstrap and a join token, then starts
// es.service, which starts the agent unit from its cached SVID.
func (b *spireAgentHelperBox) bootstrapLikeTheBox() {
	b.t.Helper()
	b.ctl("start", "spire-server.service")
	var tok struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(b.server("token", "generate", "-spiffeID", spireAgentHelperAlias, "-ttl", "600", "-output", "json"), &tok); err != nil || tok.Value == "" {
		b.t.Fatalf("token generate: %v", err)
	}
	b.server("entry", "create", "-parentID", spireAgentHelperAlias, "-spiffeID", spireAgentHelperWorkload, "-selector", "unix:uid:"+strconv.Itoa(b.uid))
	tokFile := filepath.Join(b.root, "bootstrap-token")
	b.write(tokFile, tok.Value, 0o600)
	cmd := exec.Command(b.realAgent, "run", "-config", b.agentConf, "-joinTokenFile", tokFile)
	cmd.Dir = executionSubstrateRepoRoot
	logf, err := os.Create(filepath.Join(b.logsDir, "bootstrap-agent.log"))
	if err != nil {
		b.t.Fatalf("create log: %v", err)
	}
	defer logf.Close()
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		b.t.Fatalf("start bootstrap agent: %v", err)
	}
	b.waitFor("the first attestation", 30*time.Second, func() bool {
		id, _ := b.localAgentID(b.dataDir)
		return id != ""
	})
	_ = cmd.Process.Signal(os.Interrupt)
	_, _ = cmd.Process.Wait()
	_ = os.Remove(tokFile)
	b.ctl("start", "es.service")
	if b.pid("spire-agent.service") == 0 || b.pid("es.service") == 0 {
		b.t.Fatalf("agent or es unit did not start")
	}
}

type spireAgentHelperRun struct {
	code   int
	stdout string
	stderr string
	report map[string]any
}

func (b *spireAgentHelperBox) helper(args ...string) spireAgentHelperRun {
	b.t.Helper()
	driver := filepath.Join(b.root, "driver.py")
	if _, err := os.Stat(driver); err != nil {
		b.write(driver, spireAgentHelperDriver, 0o644)
	}
	full := append([]string{"-I", "-B", driver, spireAgentHelperModule, b.layoutPath}, args...)
	full = append(full, "--json")
	cmd := exec.Command(b.python, full...)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	run := spireAgentHelperRun{stdout: stdout.String(), stderr: stderr.String()}
	if exitErr, ok := err.(*exec.ExitError); ok {
		run.code = exitErr.ExitCode()
	} else if err != nil {
		b.t.Fatalf("run helper %v: %v", args, err)
	}
	if err := json.Unmarshal(stdout.Bytes(), &run.report); err != nil {
		b.t.Fatalf("helper %v printed no JSON report: %v\nstdout=%s\nstderr=%s", args, err, run.stdout, run.stderr)
	}
	return run
}

// startHelper runs the helper in the background, for a test that signals it.
func (b *spireAgentHelperBox) startHelper(args ...string) (*exec.Cmd, *bytes.Buffer) {
	b.t.Helper()
	driver := filepath.Join(b.root, "driver.py")
	if _, err := os.Stat(driver); err != nil {
		b.write(driver, spireAgentHelperDriver, 0o644)
	}
	cmd := exec.Command(b.python, append([]string{"-I", "-B", driver, spireAgentHelperModule, b.layoutPath}, append(args, "--json")...)...)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Start(); err != nil {
		b.t.Fatal(err)
	}
	return cmd, &out
}

// attestingRuns counts the logged spire-agent runs with a join token, in a
// file or (which the helper must never do) on the command line.
func (b *spireAgentHelperBox) attestingRuns() int {
	n := 0
	sc := bufio.NewScanner(strings.NewReader(b.commandLog()))
	for sc.Scan() {
		var entry struct {
			Tool string   `json:"tool"`
			Argv []string `json:"argv"`
		}
		if json.Unmarshal(sc.Bytes(), &entry) != nil || entry.Tool != "spire-agent" || len(entry.Argv) == 0 || entry.Argv[0] != "run" {
			continue
		}
		for _, arg := range entry.Argv {
			if arg == "-joinTokenFile" || arg == "-joinToken" {
				n++
				break
			}
		}
	}
	return n
}

// confirmPinned runs the helper's SPIRE-side check (spire-agent validate,
// plain and with -trustBundle, as the SPIRE account) on the config at path.
func (b *spireAgentHelperBox) confirmPinned(path string) (bool, string) {
	b.t.Helper()
	var layout map[string]any
	if err := json.Unmarshal(spireAgentHelperRead(b.t, b.layoutPath), &layout); err != nil {
		b.t.Fatal(err)
	}
	layout["agent_config"] = path
	alt := filepath.Join(b.root, "layout-confirm.json")
	b.writeJSON(alt, layout)
	code, out, stderr := spireAgentHelperDriverRun(b.t, "--confirm-pinned", alt)
	if code != 0 {
		b.t.Fatalf("confirm-pinned driver exited %d: %s", code, stderr)
	}
	var got struct {
		OK     bool   `json:"ok"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		b.t.Fatalf("confirm-pinned output %q: %v", out, err)
	}
	return got.OK, got.Detail
}

func (r spireAgentHelperRun) check(name string) map[string]any {
	checks, _ := r.report["checks"].([]any)
	for _, c := range checks {
		m, _ := c.(map[string]any)
		if m["name"] == name {
			return m
		}
	}
	return nil
}

func (r spireAgentHelperRun) String() string {
	data, _ := json.MarshalIndent(r.report, "", "  ")
	return fmt.Sprintf("exit %d\n%s\nstderr: %s", r.code, data, r.stderr)
}

func (r spireAgentHelperRun) expect(t *testing.T, code int, result string) {
	t.Helper()
	if r.code != code || r.report["result"] != result {
		t.Fatalf("expected exit %d result %q, got:\n%s", code, result, r)
	}
}

func spireAgentHelperRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func spireAgentHelperCertSet(t *testing.T, data []byte) []string {
	t.Helper()
	var out []string
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			t.Fatalf("unexpected PEM block %q", block.Type)
		}
		sum := sha256.Sum256(block.Bytes)
		out = append(out, hex.EncodeToString(sum[:]))
	}
	if len(bytes.TrimSpace(data)) != 0 {
		t.Fatalf("trailing bytes after PEM blocks")
	}
	sort.Strings(out)
	return out
}

func spireAgentHelperGlob(t *testing.T, pattern string) []string {
	t.Helper()
	matches, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("glob %s: %v", pattern, err)
	}
	sort.Strings(matches)
	return matches
}

func spireAgentHelperMode(t *testing.T, path string) (os.FileMode, string) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("stat %s: no owner information", path)
	}
	u, err := user.LookupId(strconv.FormatUint(uint64(st.Uid), 10))
	if err != nil {
		t.Fatalf("owner of %s: %v", path, err)
	}
	g, err := user.LookupGroupId(strconv.FormatUint(uint64(st.Gid), 10))
	if err != nil {
		t.Fatalf("group of %s: %v", path, err)
	}
	return fi.Mode().Perm() | fi.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky), u.Username + ":" + g.Name
}

// deriveConf rewrites only the data directory, key manager directory and
// socket lines of an agent.conf, so a fresh agent bootstraps with exactly
// the given file's bootstrap and server lines.
func spireAgentHelperDeriveConf(t *testing.T, conf []byte, oldDataDir, oldSock, newDataDir, newSock string) string {
	t.Helper()
	text := string(conf)
	derived := strings.ReplaceAll(text, `"`+oldDataDir+`"`, `"`+newDataDir+`"`)
	derived = strings.ReplaceAll(derived, `"`+oldSock+`"`, `"`+newSock+`"`)
	keep := func(s string) []string {
		var lines []string
		for _, l := range strings.Split(s, "\n") {
			if !strings.Contains(l, newDataDir) && !strings.Contains(l, oldDataDir) && !strings.Contains(l, newSock) && !strings.Contains(l, oldSock) {
				lines = append(lines, l)
			}
		}
		return lines
	}
	if strings.Join(keep(text), "\n") != strings.Join(keep(derived), "\n") || strings.Count(derived, newDataDir) != 2 || strings.Count(derived, newSock) != 1 {
		t.Fatalf("derived agent.conf changed more than its data, key and socket paths")
	}
	return derived
}

// runFreshAgent bootstraps a new agent from conf with a join token file and
// reports whether it attested (its socket appeared) within the wait.
func (b *spireAgentHelperBox) runFreshAgent(name, conf, sock, token string, wait time.Duration) (bool, string) {
	b.t.Helper()
	confPath := filepath.Join(b.root, name+".conf")
	b.write(confPath, conf, 0o644)
	if err := os.MkdirAll(filepath.Join(b.root, name), 0o750); err != nil {
		b.t.Fatalf("mkdir %s: %v", name, err)
	}
	tokFile := filepath.Join(b.root, name+".token")
	b.write(tokFile, token, 0o600)
	logPath := filepath.Join(b.logsDir, name+".log")
	logf, err := os.Create(logPath)
	if err != nil {
		b.t.Fatalf("create %s: %v", logPath, err)
	}
	cmd := exec.Command(b.realAgent, "run", "-config", confPath, "-joinTokenFile", tokFile)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		b.t.Fatalf("start %s: %v", name, err)
	}
	attested := false
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		if fi, err := os.Lstat(sock); err == nil && fi.Mode()&os.ModeSocket != 0 {
			attested = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
	logf.Close()
	return attested, string(spireAgentHelperRead(b.t, logPath))
}

func TestRemoteAlphaSPIREAgentPinAgainstRealSPIRE(t *testing.T) {
	t.Parallel()
	// 60 s: the agent stays stopped for the impostor episode below and must
	// restart from its cached SVID afterwards.
	b := newSPIREAgentHelperBox(t, "60s")
	b.bootstrapLikeTheBox()
	original := spireAgentHelperRead(t, b.agentConf)
	agentID, _ := b.localAgentID(b.dataDir)
	if !strings.HasPrefix(agentID, "spiffe://execution.internal/spire/agent/join_token/") {
		t.Fatalf("unexpected bootstrap agent ID %q", agentID)
	}
	tokenPart := strings.TrimPrefix(agentID, "spiffe://execution.internal/spire/agent/join_token/")

	// status on the box's current shape: insecure bootstrap, no bundle file,
	// no boot rule for the runtime directories.
	status := b.helper("status")
	status.expect(t, 1, "attention")
	if c := status.check("bootstrap"); c == nil || c["state"] != "attention" {
		t.Fatalf("status did not flag insecure_bootstrap:\n%s", status)
	}
	if c := status.check("reboot readiness"); c == nil || c["state"] != "attention" {
		t.Fatalf("status did not flag missing boot rules:\n%s", status)
	}
	if c := status.check("agent identity"); c == nil || c["state"] != "ok" || !strings.Contains(c["detail"].(string), "join_token/<redacted>") {
		t.Fatalf("status agent identity is not ok and redacted:\n%s", status)
	}
	if c := status.check("agent health"); c == nil || c["state"] != "ok" {
		t.Fatalf("status agent health:\n%s", status)
	}
	if strings.Contains(status.stdout, tokenPart) {
		t.Fatalf("status printed the join token part of the agent ID")
	}

	// The bundle is trusted because only root and the SPIRE account can
	// answer on the admin socket: a socket directory others can write, or a
	// socket others can use, is refused before anything changes.
	privateDir := filepath.Dir(b.serverSock)
	for _, bad := range []struct {
		path string
		mode os.FileMode
	}{{privateDir, 0o777}, {filepath.Dir(privateDir), 0o777}, {b.serverSock, 0o666}} {
		fi, err := os.Lstat(bad.path)
		if err != nil {
			t.Fatal(err)
		}
		good := fi.Mode().Perm()
		if err := os.Chmod(bad.path, bad.mode); err != nil {
			t.Fatal(err)
		}
		st := b.helper("status")
		if c := st.check("server admin socket"); c == nil || c["state"] != "fail" {
			t.Fatalf("status accepted %s at %o:\n%s", bad.path, bad.mode, st)
		}
		refusedPin := b.helper("pin", "--apply")
		refusedPin.expect(t, 1, "refused")
		if err := os.Chmod(bad.path, good); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(spireAgentHelperRead(t, b.agentConf), original) || len(spireAgentHelperGlob(t, b.bundlePath)) != 0 {
			t.Fatalf("a refused pin changed a file")
		}
	}

	// pin without --apply changes nothing.
	agentPid, esPid := b.pid("spire-agent.service"), b.pid("es.service")
	plan := b.helper("pin")
	plan.expect(t, 0, "planned")
	if steps, _ := plan.report["plan"].([]any); len(steps) != 4 {
		t.Fatalf("expected 4 planned steps (bundle, boot rule, config, restart):\n%s", plan)
	}
	if !bytes.Equal(spireAgentHelperRead(t, b.agentConf), original) || len(spireAgentHelperGlob(t, b.bundlePath)) != 0 || len(spireAgentHelperGlob(t, filepath.Join(b.tmpfilesDir, "etc/tmpfiles.d/*"))) != 0 {
		t.Fatalf("pin without --apply changed a file")
	}
	if b.pid("spire-agent.service") != agentPid {
		t.Fatalf("pin without --apply restarted the agent")
	}

	// A validate failure after the edit restores the original config.
	b.write(b.failMarker, "", 0o644)
	failed := b.helper("pin", "--apply")
	failed.expect(t, 1, "failed")
	if !strings.Contains(failed.report["message"].(string), "validate refused") || !strings.Contains(failed.report["message"].(string), "restored") {
		t.Fatalf("validate failure not reported as restored:\n%s", failed)
	}
	if !bytes.Equal(spireAgentHelperRead(t, b.agentConf), original) {
		t.Fatalf("agent.conf was not restored after the validate failure")
	}
	backups := spireAgentHelperGlob(t, b.agentConf+".bak-*")
	if len(backups) != 1 || !bytes.Equal(spireAgentHelperRead(t, backups[0]), original) {
		t.Fatalf("expected one backup with the original bytes, got %v", backups)
	}
	if b.pid("spire-agent.service") != agentPid {
		t.Fatalf("a failed pin restarted the agent")
	}
	if err := os.Remove(b.failMarker); err != nil {
		t.Fatal(err)
	}

	// A failed restart after the edit restores the original config, starts
	// the agent and es.service again, and reports the rollback.
	if err := os.Rename(backups[0], filepath.Join(b.root, "validate-failure-backup")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(b.bundlePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(b.tmpfilesDir, "etc/tmpfiles.d/spire.conf")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	b.write(filepath.Join(b.stateDir, "spire-agent.service.fail-next-start"), "", 0o644)
	rolledBack := b.helper("pin", "--apply")
	rolledBack.expect(t, 1, "failed")
	if !strings.Contains(rolledBack.report["message"].(string), "rolled back") {
		t.Fatalf("restart failure not reported as rolled back:\n%s", rolledBack)
	}
	if !bytes.Equal(spireAgentHelperRead(t, b.agentConf), original) {
		t.Fatalf("agent.conf was not restored after the failed restart")
	}
	if b.pid("spire-agent.service") == 0 || b.pid("es.service") == 0 {
		t.Fatalf("the rollback did not bring the agent and es.service back")
	}
	if id, _ := b.localAgentID(b.dataDir); id != agentID {
		t.Fatalf("agent identity changed across the rollback")
	}
	backups = spireAgentHelperGlob(t, b.agentConf+".bak-*")
	if len(backups) != 1 || !bytes.Equal(spireAgentHelperRead(t, backups[0]), original) {
		t.Fatalf("expected one backup with the original bytes after the rollback, got %v", backups)
	}
	agentPid, esPid = b.pid("spire-agent.service"), b.pid("es.service")
	// Remove what the failed run wrote, so the real run below writes all of
	// it again. The backup is renamed so the next one is the only match.
	if err := os.Remove(b.bundlePath); err != nil {
		t.Fatalf("the failed run should have written the bundle before the config: %v", err)
	}
	if err := os.Remove(filepath.Join(b.tmpfilesDir, "etc/tmpfiles.d/spire.conf")); err != nil {
		t.Fatalf("the failed run should have written the boot rule before the config: %v", err)
	}
	if err := os.Rename(backups[0], filepath.Join(b.root, "first-backup")); err != nil {
		t.Fatal(err)
	}
	// The backup name has one-second resolution; make sure it differs.
	time.Sleep(1100 * time.Millisecond)

	// A SIGTERM (or an SSH hangup) while spire-agent validate checks the
	// edited config: the helper restores the original config, leaves the
	// agent running untouched, and still prints its report.
	b.write(b.holdValid, "", 0o644)
	validatesBefore := strings.Count(b.commandLog(), `"argv": ["validate"`)
	sigPin, sigPinOut := b.startHelper("pin", "--apply")
	b.waitFor("the held validate", 60*time.Second, func() bool {
		return strings.Count(b.commandLog(), `"argv": ["validate"`) > validatesBefore
	})
	_ = sigPin.Process.Signal(syscall.SIGTERM)
	_ = sigPin.Wait()
	if err := os.Remove(b.holdValid); err != nil {
		t.Fatal(err)
	}
	var sigPinReport map[string]any
	if err := json.Unmarshal(sigPinOut.Bytes(), &sigPinReport); err != nil || sigPinReport["result"] != "failed" || !strings.Contains(fmt.Sprint(sigPinReport["message"]), "SIGTERM") {
		t.Fatalf("a SIGTERM during validate gave no failure report (%v): %s", err, sigPinOut.String())
	}
	if !bytes.Equal(spireAgentHelperRead(t, b.agentConf), original) || !strings.Contains(fmt.Sprint(sigPinReport["actions"]), "restored the original") {
		t.Fatalf("a SIGTERM during validate did not restore agent.conf: %s", sigPinOut.String())
	}
	if b.pid("spire-agent.service") != agentPid || b.pid("es.service") != esPid {
		t.Fatalf("a SIGTERM during validate restarted the agent or es.service")
	}
	if procs, _ := filepath.Glob("/proc/[0-9]*/cmdline"); len(procs) > 0 {
		for _, p := range procs {
			if data, err := os.ReadFile(p); err == nil && strings.Contains(string(data), "validate") && strings.Contains(string(data), b.agentConf) {
				t.Fatalf("a held validate outlived the SIGTERM: %q", strings.ReplaceAll(string(data), "\x00", " "))
			}
		}
	}
	for _, path := range []string{b.bundlePath, filepath.Join(b.tmpfilesDir, "etc/tmpfiles.d/spire.conf")} {
		if err := os.Remove(path); err != nil {
			t.Fatalf("the interrupted run should have written %s before the config: %v", path, err)
		}
	}
	backups = spireAgentHelperGlob(t, b.agentConf+".bak-*")
	if len(backups) != 1 || !bytes.Equal(spireAgentHelperRead(t, backups[0]), original) {
		t.Fatalf("expected one backup with the original bytes after the interrupted run, got %v", backups)
	}
	if err := os.Rename(backups[0], filepath.Join(b.root, "interrupted-backup")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)

	// Two stop signals (an SSH hangup, then a kill, say): the first while
	// pin's restart is held after its stop, the second while the rollback's
	// restart is held. The first starts the rollback and makes the helper
	// ignore further stop signals, so the rollback finishes: the original
	// config is back and the agent and es.service run with the old identity.
	holdRestart := filepath.Join(b.stateDir, "hold-restart")
	heldRestarts := filepath.Join(b.stateDir, "held-restarts")
	held := func() int {
		data, err := os.ReadFile(heldRestarts)
		if err != nil {
			return 0
		}
		return strings.Count(string(data), "\n")
	}
	b.write(holdRestart, "", 0o644)
	twoSig, twoSigOut := b.startHelper("pin", "--apply")
	b.waitFor("pin's held restart", 60*time.Second, func() bool { return held() == 1 })
	_ = twoSig.Process.Signal(syscall.SIGTERM)
	b.waitFor("the rollback's held restart", 60*time.Second, func() bool { return held() == 2 })
	_ = twoSig.Process.Signal(syscall.SIGTERM)
	time.Sleep(500 * time.Millisecond)
	if err := os.Remove(holdRestart); err != nil {
		t.Fatal(err)
	}
	_ = twoSig.Wait()
	if err := os.Remove(heldRestarts); err != nil {
		t.Fatal(err)
	}
	var twoSigReport map[string]any
	if err := json.Unmarshal(twoSigOut.Bytes(), &twoSigReport); err != nil || twoSigReport["result"] != "failed" ||
		!strings.Contains(fmt.Sprint(twoSigReport["message"]), "rolled back: stopped by SIGTERM") || strings.Contains(fmt.Sprint(twoSigReport["message"]), "rollback failed") {
		t.Fatalf("two SIGTERMs during pin's restart and its rollback did not end in a finished rollback (%v): %s", err, twoSigOut.String())
	}
	if !bytes.Equal(spireAgentHelperRead(t, b.agentConf), original) || b.pid("spire-agent.service") == 0 || b.pid("es.service") == 0 {
		t.Fatalf("after two SIGTERMs the original config is not back, or the agent or es.service is down: %s", twoSigOut.String())
	}
	if id, _ := b.localAgentID(b.dataDir); id != agentID {
		t.Fatalf("agent identity changed across the interrupted rollback")
	}
	for _, path := range []string{b.bundlePath, filepath.Join(b.tmpfilesDir, "etc/tmpfiles.d/spire.conf")} {
		if err := os.Remove(path); err != nil {
			t.Fatalf("the twice-interrupted run should have written %s before the config: %v", path, err)
		}
	}
	backups = spireAgentHelperGlob(t, b.agentConf+".bak-*")
	if len(backups) != 1 || !bytes.Equal(spireAgentHelperRead(t, backups[0]), original) {
		t.Fatalf("expected one backup with the original bytes after the twice-interrupted run, got %v", backups)
	}
	if err := os.Rename(backups[0], filepath.Join(b.root, "twice-interrupted-backup")); err != nil {
		t.Fatal(err)
	}
	agentPid, esPid = b.pid("spire-agent.service"), b.pid("es.service")
	time.Sleep(1100 * time.Millisecond)

	pinned := b.helper("pin", "--apply")
	pinned.expect(t, 0, "ok")
	after := spireAgentHelperRead(t, b.agentConf)
	wantConf := strings.Replace(string(original), "    insecure_bootstrap = true\n", "    trust_bundle_path = \""+b.bundlePath+"\"\n", 1)
	if string(after) != wantConf {
		t.Fatalf("pin changed more or less than the insecure_bootstrap line:\n%s", after)
	}
	backups = spireAgentHelperGlob(t, b.agentConf+".bak-*")
	if len(backups) != 1 || !bytes.Equal(spireAgentHelperRead(t, backups[0]), original) {
		t.Fatalf("pin --apply left no backup with the original bytes: %v", backups)
	}
	if mode, owner := spireAgentHelperMode(t, b.bundlePath); mode != 0o644 || owner != b.user+":"+b.group {
		t.Fatalf("bundle file is %o %s, want 0644 %s:%s", mode, owner, b.user, b.group)
	}
	if got, want := spireAgentHelperCertSet(t, spireAgentHelperRead(t, b.bundlePath)), spireAgentHelperCertSet(t, b.server("bundle", "show", "-format", "pem")); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("bundle file differs from the server bundle")
	}
	// The boot rule copies each runtime directory's owner and mode, and the
	// real systemd-tmpfiles applies it that way under an empty root.
	rule := string(spireAgentHelperRead(t, filepath.Join(b.tmpfilesDir, "etc/tmpfiles.d/spire.conf")))
	sandbox := filepath.Join(b.root, "tmpfiles-sandbox")
	for _, d := range []string{"etc"} {
		if err := os.MkdirAll(filepath.Join(sandbox, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"passwd", "group"} {
		b.write(filepath.Join(sandbox, "etc", f), string(spireAgentHelperRead(t, "/etc/"+f)), 0o644)
	}
	ruleCopy := filepath.Join(b.root, "rule-copy.conf")
	b.write(ruleCopy, rule, 0o644)
	tmpfiles := exec.Command("systemd-tmpfiles", "--root="+sandbox, "--create", ruleCopy)
	tmpfiles.Dir = executionSubstrateRepoRoot
	if out, err := tmpfiles.CombinedOutput(); err != nil {
		t.Fatalf("systemd-tmpfiles refused the written rule: %v %s", err, out)
	}
	for _, d := range []string{"run/spire", "run/spire/server", "run/spire/server/private", "run/spire/sockets"} {
		real := filepath.Join(b.root, d)
		wantMode, wantOwner := spireAgentHelperMode(t, real)
		line := fmt.Sprintf("d %s %04o %s -\n", real, wantMode, strings.Replace(wantOwner, ":", " ", 1))
		if !strings.Contains(rule, line) {
			t.Fatalf("boot rule lacks %q:\n%s", line, rule)
		}
		if gotMode, gotOwner := spireAgentHelperMode(t, sandbox+real); gotMode != wantMode || gotOwner != wantOwner {
			t.Fatalf("systemd-tmpfiles created %s as %o %s, want %o %s", d, gotMode, gotOwner, wantMode, wantOwner)
		}
	}
	// The agent restarted with its original identity, and es.service with it.
	if b.pid("spire-agent.service") == agentPid || b.pid("spire-agent.service") == 0 {
		t.Fatalf("pin --apply did not restart the agent")
	}
	if b.pid("es.service") == esPid || b.pid("es.service") == 0 {
		t.Fatalf("es.service was not restarted with the agent")
	}
	if id, _ := b.localAgentID(b.dataDir); id != agentID {
		t.Fatalf("agent identity changed across pin")
	}
	if actions := fmt.Sprint(pinned.report["actions"]); !strings.Contains(actions, "Workload API served "+spireAgentHelperWorkload) || !strings.Contains(actions, "es.service active") {
		t.Fatalf("pin did not check the workload SVID and es.service:\n%s", pinned)
	}

	healthy := b.helper("status")
	healthy.expect(t, 0, "ok")

	// pin is idempotent.
	agentPid, esPid = b.pid("spire-agent.service"), b.pid("es.service")
	again := b.helper("pin", "--apply")
	again.expect(t, 0, "ok")
	if again.report["message"] != "nothing to change" || len(spireAgentHelperGlob(t, b.agentConf+".bak-*")) != 1 || !bytes.Equal(spireAgentHelperRead(t, b.agentConf), after) || b.pid("spire-agent.service") != agentPid || b.pid("es.service") != esPid {
		t.Fatalf("second pin --apply was not a no-op:\n%s", again)
	}

	// SPIRE's own reading decides whether a config counts as pinned. The
	// pinned file passes. The original, and a heredoc that hides an
	// insecure_bootstrap from a line scan, fail validate -trustBundle; a
	// heredoc that hides the trust_bundle_path line fails plain validate.
	if ok, detail := b.confirmPinned(b.agentConf); !ok {
		t.Fatalf("SPIRE did not confirm the pinned agent.conf: %s", detail)
	}
	pathLine := "    trust_bundle_path = \"" + b.bundlePath + "\"\n"
	hidden := filepath.Join(b.root, "heredoc-agent.conf")
	b.write(hidden, strings.Replace(string(after), pathLine, "    admin_socket_path = <<EOT\n"+pathLine+"EOT\n    Insecure_Bootstrap = true\n", 1), 0o644)
	insecureCopy := filepath.Join(b.root, "insecure-agent.conf")
	b.write(insecureCopy, string(original), 0o644)
	hiddenPath := filepath.Join(b.root, "heredoc-path-agent.conf")
	b.write(hiddenPath, strings.Replace(string(after), pathLine, "    join_token = <<EOT\n"+pathLine+"EOT\n", 1), 0o644)
	for path, want := range map[string]string{
		hidden:       "with -trustBundle: SPIRE agent configuration file is invalid: only one of insecure_bootstrap or trust_bundle_path",
		insecureCopy: "with -trustBundle: SPIRE agent configuration file is invalid: only one of insecure_bootstrap or trust_bundle_path",
		hiddenPath:   "plain: SPIRE agent configuration file is invalid: trust_bundle_path or trust_bundle_url must be configured",
	} {
		if ok, detail := b.confirmPinned(path); ok || !strings.Contains(detail, want) {
			t.Fatalf("SPIRE confirmed %s as pinned (%v), or for another reason: %s", filepath.Base(path), ok, detail)
		}
	}
	// A config the line scan calls pinned but SPIRE refuses is flagged by
	// status and refused by pin, and nothing changes.
	b.write(b.agentConf, strings.Replace(string(after), "    trust_domain = \""+spireAgentHelperTrustDomain+"\"\n", "", 1), 0o644)
	disagree := b.helper("status")
	if c := disagree.check("bootstrap"); c == nil || c["state"] != "attention" || !strings.Contains(fmt.Sprint(c["detail"]), "SPIRE's own parser does not confirm it") {
		t.Fatalf("status did not flag a config SPIRE refuses:\n%s", disagree)
	}
	refusedDisagree := b.helper("pin", "--apply")
	refusedDisagree.expect(t, 1, "refused")
	if !strings.Contains(refusedDisagree.report["message"].(string), "SPIRE's own parser does not confirm it") || b.pid("spire-agent.service") != agentPid {
		t.Fatalf("pin did not refuse a config SPIRE refuses:\n%s", refusedDisagree)
	}
	b.write(b.agentConf, string(after), 0o644)

	// The security proof (INF-14). With the real server down, an impostor
	// server holds its port. A fresh bootstrap with the pinned agent.conf
	// refuses it; the same bootstrap with the original insecure agent.conf
	// attests to it, which shows the impostor is a working server.
	b.ctl("stop", "spire-server.service")
	if b.pid("spire-agent.service") != 0 || b.pid("es.service") != 0 {
		t.Fatalf("stopping the server did not stop its dependents")
	}
	impDir := filepath.Join(b.root, "impostor")
	impSock := filepath.Join(impDir, "api.sock")
	if err := os.MkdirAll(impDir, 0o700); err != nil {
		t.Fatal(err)
	}
	impConf := filepath.Join(impDir, "server.conf")
	b.write(impConf, spireAgentHelperServerConf(impDir, impSock, b.port, "60s"), 0o644)
	imp := exec.Command(b.realServer, "run", "-config", impConf)
	imp.Dir = executionSubstrateRepoRoot
	impLog, _ := os.Create(filepath.Join(b.logsDir, "impostor.log"))
	imp.Stdout, imp.Stderr = impLog, impLog
	if err := imp.Start(); err != nil {
		t.Fatalf("start impostor: %v", err)
	}
	defer func() { _ = imp.Process.Kill(); _, _ = imp.Process.Wait(); impLog.Close() }()
	b.waitFor("the impostor's admin socket", 20*time.Second, func() bool { _, err := os.Lstat(impSock); return err == nil })
	impToken := func() string {
		var tok struct {
			Value string `json:"value"`
		}
		gen := exec.Command(b.realServer, "token", "generate", "-socketPath", impSock, "-spiffeID", spireAgentHelperAlias, "-output", "json")
		gen.Dir = executionSubstrateRepoRoot
		out, err := gen.CombinedOutput()
		if err != nil || json.Unmarshal(out, &tok) != nil || tok.Value == "" {
			t.Fatalf("impostor token: %v %s", err, out)
		}
		return tok.Value
	}
	freshData := filepath.Join(b.root, "fresh-pinned")
	freshSock := filepath.Join(b.root, "fp.sock")
	pinnedFresh := spireAgentHelperDeriveConf(t, after, b.dataDir, b.agentSock, freshData, freshSock)
	ok, log := b.runFreshAgent("fresh-pinned", pinnedFresh, freshSock, impToken(), 8*time.Second)
	if ok || !strings.Contains(log, "certificate signed by unknown authority") {
		t.Fatalf("a pinned fresh bootstrap did not refuse the impostor (attested=%v):\n%s", ok, log)
	}
	if id, _ := b.localAgentID(freshData); id != "" {
		t.Fatalf("a pinned fresh bootstrap stored an identity from the impostor")
	}
	insecureData := filepath.Join(b.root, "fresh-insecure")
	insecureSock := filepath.Join(b.root, "fi.sock")
	insecureFresh := spireAgentHelperDeriveConf(t, original, b.dataDir, b.agentSock, insecureData, insecureSock)
	if ok, log := b.runFreshAgent("fresh-insecure", insecureFresh, insecureSock, impToken(), 15*time.Second); !ok {
		t.Fatalf("control: an insecure fresh bootstrap did not attest to the impostor:\n%s", log)
	}
	_ = imp.Process.Kill()
	_, _ = imp.Process.Wait()

	// The real server comes back and the agent restarts from its cache.
	b.ctl("start", "es.service")
	back := b.helper("status")
	back.expect(t, 0, "ok")
	if id, _ := b.localAgentID(b.dataDir); id != agentID {
		t.Fatalf("agent identity changed across the impostor episode")
	}
}

// spireAgentHelperProcWatch records every command line seen in /proc while
// it runs.
type spireAgentHelperProcWatch struct {
	mu    sync.Mutex
	lines map[string]bool
	stop  chan struct{}
	done  chan struct{}
}

func startSPIREAgentHelperProcWatch() *spireAgentHelperProcWatch {
	w := &spireAgentHelperProcWatch{lines: map[string]bool{}, stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(w.done)
		for {
			select {
			case <-w.stop:
				return
			default:
			}
			entries, _ := os.ReadDir("/proc")
			for _, e := range entries {
				if _, err := strconv.Atoi(e.Name()); err != nil {
					continue
				}
				data, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
				if err == nil && len(data) > 0 {
					w.mu.Lock()
					w.lines[string(data)] = true
					w.mu.Unlock()
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	return w
}

func (w *spireAgentHelperProcWatch) finish() map[string]bool {
	close(w.stop)
	<-w.done
	return w.lines
}

// expireAgent stops the agent unit and waits until its SVID has expired.
// The agent's own SVID can be newer than the server's record: SPIRE
// promotes a renewed SVID in the record only when the agent first presents
// it, so an agent stopped right after a renewal leaves the record behind.
func (b *spireAgentHelperBox) expireAgent() string {
	b.t.Helper()
	b.ctl("stop", "spire-agent.service")
	if b.pid("es.service") != 0 {
		b.t.Fatalf("stopping the agent did not stop es.service")
	}
	id, notAfter := b.localAgentID(b.dataDir)
	exp := notAfter.Unix()
	found := false
	for _, a := range b.agents() {
		if a.ID == id {
			found = true
			if a.ExpiresAt > exp {
				exp = a.ExpiresAt
			}
		}
	}
	if id == "" || !found {
		b.t.Fatalf("no local agent identity with a server record")
	}
	b.waitFor("the agent SVID to expire", 75*time.Second, func() bool { return time.Now().Unix() > exp+1 })
	return id
}

func (b *spireAgentHelperBox) commandLog() string {
	data, _ := os.ReadFile(b.shimLog)
	ctl, _ := os.ReadFile(filepath.Join(b.stateDir, "systemctl.log"))
	return string(data) + string(ctl)
}

func TestRemoteAlphaSPIREAgentRecoverAgainstRealSPIRE(t *testing.T) {
	t.Parallel()
	// 15 s: each expiry below waits out one SVID lifetime.
	b := newSPIREAgentHelperBox(t, "15s")
	b.bootstrapLikeTheBox()
	original := spireAgentHelperRead(t, b.agentConf)

	refused := b.helper("recover", "--apply")
	refused.expect(t, 1, "refused")
	if !strings.Contains(refused.report["message"].(string), "valid until") {
		t.Fatalf("recover on a healthy agent was not refused for its valid SVID:\n%s", refused)
	}
	if !bytes.Equal(spireAgentHelperRead(t, b.agentConf), original) || len(spireAgentHelperGlob(t, b.dataDir+".recover-*")) != 0 {
		t.Fatalf("a refused recover changed something")
	}

	// The box was off longer than the agent SVID's life.
	oldID := b.expireAgent()
	expired := b.helper("status")
	expired.expect(t, 1, "attention")
	if c := expired.check("agent identity"); c == nil || c["state"] != "fail" || !strings.Contains(c["detail"].(string), "EXPIRED") {
		t.Fatalf("status did not report the expired SVID:\n%s", expired)
	}
	oldData := spireAgentHelperRead(t, filepath.Join(b.dataDir, "agent-data.json"))

	// With no registration entry under the alias, a new agent would serve
	// nothing: recover refuses before any change.
	for _, e := range b.entries() {
		if e.ParentID == spireAgentHelperAlias {
			b.server("entry", "delete", "-entryID", e.ID)
		}
	}
	noChildren := b.helper("recover", "--apply")
	noChildren.expect(t, 1, "refused")
	if !strings.Contains(noChildren.report["message"].(string), "no registration entry names") || !bytes.Equal(spireAgentHelperRead(t, b.agentConf), original) || len(spireAgentHelperGlob(t, b.bundlePath)) != 0 {
		t.Fatalf("recover without workload entries was not refused before any change:\n%s", noChildren)
	}
	b.server("entry", "create", "-parentID", spireAgentHelperAlias, "-spiffeID", spireAgentHelperWorkload, "-selector", "unix:uid:"+strconv.Itoa(b.uid))

	plan := b.helper("recover")
	plan.expect(t, 0, "planned")
	if !bytes.Equal(spireAgentHelperRead(t, b.agentConf), original) || !bytes.Equal(spireAgentHelperRead(t, filepath.Join(b.dataDir, "agent-data.json")), oldData) || len(spireAgentHelperGlob(t, b.bundlePath)) != 0 {
		t.Fatalf("recover without --apply changed something")
	}

	// An attestation that fails puts the old data directory back and leaves
	// the units stopped.
	b.write(b.failAttest, "", 0o644)
	crashed := b.helper("recover", "--apply")
	crashed.expect(t, 1, "failed")
	if !strings.Contains(crashed.report["message"].(string), "the attesting agent exited") {
		t.Fatalf("attestation failure not reported:\n%s", crashed)
	}
	if strings.Contains(crashed.stdout, "0f0f0f0f-1e1e-4d4d-8c8c-7b7b7b7b7b7b") || !strings.Contains(crashed.report["message"].(string), "join_token/<redacted>") {
		t.Fatalf("the agent log tail in the failure report was not redacted:\n%s", crashed)
	}
	// The shim printed the token where a cut before redaction would leave
	// its second half in the tail.
	if !strings.Contains(crashed.report["message"].(string), "<redacted>"+strings.Repeat(".", 100)) || regexp.MustCompile(`[0-9a-f-]{8}\.{100}`).MatchString(crashed.stdout) {
		t.Fatalf("part of the join token reached the failure report:\n%s", crashed)
	}
	if !bytes.Equal(spireAgentHelperRead(t, filepath.Join(b.dataDir, "agent-data.json")), oldData) || len(spireAgentHelperGlob(t, b.dataDir+".failed-*")) != 1 || len(spireAgentHelperGlob(t, b.dataDir+".recover-*")) != 0 {
		t.Fatalf("a failed attestation did not put the old data directory back")
	}
	if left := spireAgentHelperGlob(t, filepath.Join(b.scratch, "*")); len(left) != 0 {
		t.Fatalf("a failed recover left scratch entries: %v", left)
	}
	if b.pid("spire-agent.service") != 0 || b.pid("es.service") != 0 {
		t.Fatalf("a failed recover started units")
	}
	if err := os.Remove(b.failAttest); err != nil {
		t.Fatal(err)
	}
	// The backup name has one-second resolution; make sure it differs.
	time.Sleep(1100 * time.Millisecond)

	// An OS error after the swap (here the token directory cannot be
	// created, as with a full /run) also puts the old data directory back.
	if err := os.Rename(b.scratch, b.scratch+".away"); err != nil {
		t.Fatal(err)
	}
	osErr := b.helper("recover", "--apply")
	if err := os.Rename(b.scratch+".away", b.scratch); err != nil {
		t.Fatal(err)
	}
	osErr.expect(t, 1, "failed")
	if !strings.Contains(osErr.report["message"].(string), "attestation failed") {
		t.Fatalf("an OS error during the swap was not reported as a failed attestation:\n%s", osErr)
	}
	if !bytes.Equal(spireAgentHelperRead(t, filepath.Join(b.dataDir, "agent-data.json")), oldData) || len(spireAgentHelperGlob(t, b.dataDir+".failed-*")) != 2 || len(spireAgentHelperGlob(t, b.dataDir+".recover-*")) != 0 {
		t.Fatalf("an OS error during the swap did not put the old data directory back:\n%s", osErr)
	}
	time.Sleep(1100 * time.Millisecond)

	// A SIGTERM (or an SSH hangup) while the token file exists: the helper
	// stops the attesting agent, removes the token file and puts the old data
	// directory back, and still prints its report. The shim holds the
	// attesting run at its start, so the signal lands during attestation.
	b.write(b.holdAttest, "", 0o644)
	driver := filepath.Join(b.root, "driver.py")
	sigCmd := exec.Command(b.python, "-I", "-B", driver, spireAgentHelperModule, b.layoutPath, "recover", "--apply", "--json")
	sigCmd.Dir = executionSubstrateRepoRoot
	sigCmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	var sigOut bytes.Buffer
	sigCmd.Stdout = &sigOut
	if err := sigCmd.Start(); err != nil {
		t.Fatal(err)
	}
	b.waitFor("the held attesting run", 60*time.Second, func() bool {
		return b.attestingRuns() == 2
	})
	_ = sigCmd.Process.Signal(syscall.SIGTERM)
	_ = sigCmd.Wait()
	if err := os.Remove(b.holdAttest); err != nil {
		t.Fatal(err)
	}
	var sigReport map[string]any
	if err := json.Unmarshal(sigOut.Bytes(), &sigReport); err != nil || sigReport["result"] != "failed" || !strings.Contains(fmt.Sprint(sigReport["message"]), "SIGTERM") {
		t.Fatalf("a SIGTERM during attestation gave no failure report (%v): %s", err, sigOut.String())
	}
	if left := spireAgentHelperGlob(t, filepath.Join(b.scratch, "*")); len(left) != 0 {
		t.Fatalf("a SIGTERM during attestation left scratch entries: %v", left)
	}
	if !bytes.Equal(spireAgentHelperRead(t, filepath.Join(b.dataDir, "agent-data.json")), oldData) || len(spireAgentHelperGlob(t, b.dataDir+".recover-*")) != 0 {
		t.Fatalf("a SIGTERM during attestation did not put the old data directory back")
	}
	procs, _ := filepath.Glob("/proc/[0-9]*/cmdline")
	for _, p := range procs {
		if data, err := os.ReadFile(p); err == nil && strings.Contains(string(data), b.scratch) {
			t.Fatalf("an attesting agent outlived the SIGTERM: %q", strings.ReplaceAll(string(data), "\x00", " "))
		}
	}
	time.Sleep(1100 * time.Millisecond)

	// A first stop signal while the helper cleans up after an ordinary
	// failure is held until the cleanup ends. Here attestation times out (the
	// shim holds the run, and this layout allows 2 s), and the attesting
	// agent takes its time to exit on the helper's SIGTERM. The test signals
	// the helper while it waits for that agent.
	var short map[string]any
	if err := json.Unmarshal(spireAgentHelperRead(t, b.layoutPath), &short); err != nil {
		t.Fatal(err)
	}
	short["attestation_timeout_seconds"] = 2
	shortLayout := filepath.Join(b.root, "layout-short-attest.json")
	b.writeJSON(shortLayout, short)
	b.write(b.holdAttest, "", 0o644)
	b.write(b.linger, "", 0o644)
	cleanCmd := exec.Command(b.python, "-I", "-B", driver, spireAgentHelperModule, shortLayout, "recover", "--apply", "--json")
	cleanCmd.Dir = executionSubstrateRepoRoot
	cleanCmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	var cleanOut bytes.Buffer
	cleanCmd.Stdout = &cleanOut
	if err := cleanCmd.Start(); err != nil {
		t.Fatal(err)
	}
	b.waitFor("the attesting agent's SIGTERM from the helper's cleanup", 60*time.Second, func() bool {
		_, err := os.Stat(b.lingering)
		return err == nil
	})
	_ = cleanCmd.Process.Signal(syscall.SIGTERM)
	time.Sleep(500 * time.Millisecond)
	for _, p := range []string{b.linger, b.holdAttest} {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
	_ = cleanCmd.Wait()
	_ = os.Remove(b.lingering)
	var cleanReport map[string]any
	if err := json.Unmarshal(cleanOut.Bytes(), &cleanReport); err != nil || cleanReport["result"] != "failed" {
		t.Fatalf("a SIGTERM during cleanup gave no failure report (%v): %s", err, cleanOut.String())
	}
	if left := spireAgentHelperGlob(t, filepath.Join(b.scratch, "*")); len(left) != 0 {
		t.Fatalf("a SIGTERM during cleanup cut it short: scratch entries left: %v", left)
	}
	if !bytes.Equal(spireAgentHelperRead(t, filepath.Join(b.dataDir, "agent-data.json")), oldData) || len(spireAgentHelperGlob(t, b.dataDir+".recover-*")) != 0 {
		t.Fatalf("a SIGTERM during cleanup did not put the old data directory back")
	}
	time.Sleep(1100 * time.Millisecond)

	entriesBefore := len(b.entries())
	watch := startSPIREAgentHelperProcWatch()
	recovered := b.helper("recover", "--apply")
	seen := watch.finish()
	recovered.expect(t, 0, "ok")

	newID, notAfter := b.localAgentID(b.dataDir)
	if newID == "" || newID == oldID || time.Until(notAfter) <= 0 {
		t.Fatalf("recover left no new valid agent identity")
	}
	token := strings.TrimPrefix(newID, "spiffe://execution.internal/spire/agent/join_token/")
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(token) {
		t.Fatalf("new agent ID does not end in a join token: %q", newID)
	}
	// The join token never reached the helper's output, any command line
	// (logged by the shims, the fake setpriv and the fake systemctl, and
	// polled from /proc), and its file is gone.
	if strings.Contains(recovered.stdout+recovered.stderr, token) {
		t.Fatalf("recover printed the join token")
	}
	if strings.Contains(b.commandLog(), token) {
		t.Fatalf("the join token appeared in a logged command line")
	}
	for line := range seen {
		if strings.Contains(line, token) {
			t.Fatalf("the join token appeared in a process command line: %q", strings.ReplaceAll(line, "\x00", " "))
		}
	}
	// Four runs had a join token file: the injected crash, the SIGTERM
	// step, the SIGTERM-during-cleanup step and the recovery.
	var tokenFiles []map[string]any
	sc := bufio.NewScanner(strings.NewReader(b.commandLog()))
	for sc.Scan() {
		var entry map[string]any
		if json.Unmarshal(sc.Bytes(), &entry) == nil && entry["token_file"] != nil {
			tokenFiles = append(tokenFiles, entry["token_file"].(map[string]any))
		}
	}
	if len(tokenFiles) != 4 {
		t.Fatalf("expected 4 runs with a join token file (crash, SIGTERM, SIGTERM during cleanup, recovery), got %d", len(tokenFiles))
	}
	var attestRuns, setprivTokens, setprivRuns int
	sc = bufio.NewScanner(strings.NewReader(b.commandLog()))
	for sc.Scan() {
		var entry struct {
			Tool     string   `json:"tool"`
			Argv     []string `json:"argv"`
			Insecure *bool    `json:"config_names_insecure_bootstrap"`
			Blocked  *[]int   `json:"stop_signals_blocked"`
		}
		if json.Unmarshal(sc.Bytes(), &entry) != nil {
			continue
		}
		argv := strings.Join(entry.Argv, " ")
		switch {
		case entry.Tool == "spire-agent" && strings.Contains(argv, "-joinTokenFile"):
			attestRuns++
			if entry.Insecure == nil || *entry.Insecure || !strings.Contains(argv, "-trustBundle "+b.bundlePath+" -trustBundleFormat pem ") {
				t.Fatalf("an attesting run did not use the pinned bundle: %s (config names insecure_bootstrap: %v)", argv, entry.Insecure)
			}
			// The helper holds stop signals while it starts the agent; the
			// agent must not inherit that, or it could not be stopped.
			if entry.Blocked == nil || len(*entry.Blocked) != 0 {
				t.Fatalf("an attesting run started with stop signals blocked: %v", entry.Blocked)
			}
		case entry.Tool == "setpriv" && strings.Contains(argv, " token generate ") && strings.Contains(argv, " -ttl 120 "):
			setprivTokens++
		case entry.Tool == "setpriv" && strings.Contains(argv, " run -config ") && strings.Contains(argv, "-joinTokenFile"):
			setprivRuns++
		}
	}
	if attestRuns != 4 || setprivTokens != 4 || setprivRuns != 4 {
		t.Fatalf("attesting runs %d, token generations as the SPIRE account with -ttl 120: %d, attesting runs as the SPIRE account: %d; want 4 each", attestRuns, setprivTokens, setprivRuns)
	}
	for _, tf := range tokenFiles {
		if tf["mode"] != "0o600" || tf["dir_mode"] != "0o700" || int(tf["uid"].(float64)) != b.uid || !strings.HasPrefix(tf["path"].(string), b.scratch+"/") {
			t.Fatalf("join token file was not a 0600 file of the SPIRE account under the scratch parent: %v", tf)
		}
	}
	if left := spireAgentHelperGlob(t, filepath.Join(b.scratch, "*")); len(left) != 0 {
		t.Fatalf("recover left scratch entries: %v", left)
	}
	// The old data directory was kept, the config pinned, the units are up.
	moved := spireAgentHelperGlob(t, b.dataDir+".recover-*")
	if len(moved) != 1 || !bytes.Equal(spireAgentHelperRead(t, filepath.Join(moved[0], "agent-data.json")), oldData) {
		t.Fatalf("recover did not keep the old data directory: %v", moved)
	}
	if mode, _ := spireAgentHelperMode(t, b.dataDir); mode != 0o750 {
		t.Fatalf("new data directory mode %o, want the old 0750", mode)
	}
	if !strings.Contains(string(spireAgentHelperRead(t, b.agentConf)), "trust_bundle_path = \""+b.bundlePath+"\"") || len(spireAgentHelperGlob(t, b.agentConf+".bak-*")) != 1 {
		t.Fatalf("recover did not pin agent.conf before attesting")
	}
	if b.pid("spire-agent.service") == 0 || b.pid("es.service") == 0 {
		t.Fatalf("recover did not bring the agent and es.service back")
	}
	if actions := fmt.Sprint(recovered.report["actions"]); !strings.Contains(actions, "Workload API served "+spireAgentHelperWorkload) {
		t.Fatalf("recover did not check the workload SVID:\n%s", recovered)
	}
	// Without --evict-old-agent the expired record and its alias stay.
	var oldPresent bool
	for _, a := range b.agents() {
		oldPresent = oldPresent || a.ID == oldID
	}
	if !oldPresent || len(b.entries()) != entriesBefore+1 {
		t.Fatalf("recover without --evict-old-agent removed something (old record present=%v, entries %d -> %d)", oldPresent, entriesBefore, len(b.entries()))
	}
	healthy := b.helper("status")
	healthy.expect(t, 0, "ok")
	again := b.helper("recover", "--apply")
	again.expect(t, 1, "refused")

	// A second expiry, recovered with --evict-old-agent, removes exactly the
	// replaced agent's record and alias entry.
	secondOld := b.expireAgent()
	entriesBeforeEvict := len(b.entries())
	evicted := b.helper("recover", "--apply", "--evict-old-agent")
	evicted.expect(t, 0, "ok")
	var firstStill, secondStill bool
	for _, a := range b.agents() {
		firstStill = firstStill || a.ID == oldID
		secondStill = secondStill || a.ID == secondOld
	}
	if !firstStill || secondStill {
		t.Fatalf("--evict-old-agent evicted the wrong records (first present=%v, second present=%v)", firstStill, secondStill)
	}
	workloads := 0
	for _, e := range b.entries() {
		if e.ParentID == secondOld {
			t.Fatalf("--evict-old-agent left the replaced agent's alias entry")
		}
		if e.SPIFFEID == spireAgentHelperWorkload {
			workloads++
		}
	}
	// One alias entry added for the new agent, one removed for the old.
	if got := len(b.entries()); got != entriesBeforeEvict || workloads != 1 {
		t.Fatalf("--evict-old-agent deleted more than the replaced agent's alias entry (entries %d -> %d, workload entries %d)", entriesBeforeEvict, got, workloads)
	}
	final := b.helper("status")
	final.expect(t, 0, "ok")
}

func spireAgentHelperDriverRun(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("needs python3: %v", err)
	}
	dir := t.TempDir()
	driver := filepath.Join(dir, "driver.py")
	if err := os.WriteFile(driver, []byte(spireAgentHelperDriver), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(python, append([]string{"-I", "-B", driver, spireAgentHelperModule}, args...)...)
	cmd.Dir = executionSubstrateRepoRoot
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("run driver: %v", err)
	}
	return code, stdout.String(), stderr.String()
}

func TestRemoteAlphaSPIREAgentLayoutPinsBoxValues(t *testing.T) {
	code, out, stderr := spireAgentHelperDriverRun(t, "--dump-layout")
	if code != 0 {
		t.Fatalf("dump layout: %d %s", code, stderr)
	}
	var layout map[string]any
	if err := json.Unmarshal([]byte(out), &layout); err != nil {
		t.Fatalf("parse layout: %v", err)
	}
	// Box values from the read-only box checks of 2026-11-23 (units, paths,
	// accounts) and the INF-14 plan (bundle file, boot rule path).
	want := map[string]any{
		"trust_domain":           "execution.internal",
		"agent_alias_path":       "/spire-agent",
		"workload_spiffe_id":     "spiffe://execution.internal/workload",
		"server_unit":            "spire-server.service",
		"agent_unit":             "spire-agent.service",
		"dependent_units":        []any{"es.service"},
		"spire_user":             "spire",
		"spire_group":            "spire",
		"file_owner":             "root",
		"file_group":             "root",
		"required_euid":          float64(0),
		"server_socket":          "/run/spire/server/private/api.sock",
		"agent_socket":           "/run/spire/sockets/agent.sock",
		"agent_config":           "/etc/spire/agent/agent.conf",
		"bundle_path":            "/etc/spire/agent/bootstrap-bundle.pem",
		"agent_data_dir":         "/var/lib/spire/agent",
		"agent_data_dir_mode":    float64(0o750),
		"runtime_dirs":           []any{"/run/spire", "/run/spire/server", "/run/spire/server/private", "/run/spire/sockets"},
		"runtime_dir_root":       "/run",
		"tmpfiles_root":          "/",
		"tmpfiles_path":          "/etc/tmpfiles.d/spire.conf",
		"account_db_dir":         "/etc",
		"scratch_parent":         "/run",
		"lock_path":              "/run/execution-substrate-remote-alpha-spire-agent.lock",
		"spire_server_bin":       "/usr/local/bin/spire-server",
		"spire_agent_bin":        "/usr/local/bin/spire-agent",
		"systemctl_bin":          "/usr/bin/systemctl",
		"setpriv_bin":            "/usr/bin/setpriv",
		"openssl_bin":            "/usr/bin/openssl",
		"tmpfiles_bin":           "/usr/bin/systemd-tmpfiles",
		"command_path_env":       "/usr/sbin:/usr/bin:/sbin:/bin",
		"join_token_ttl_seconds": float64(120),
		"svid_attention_seconds": float64(12 * 3600),
	}
	for key, value := range want {
		if fmt.Sprint(layout[key]) != fmt.Sprint(value) {
			t.Errorf("Layout().%s = %v, want %v", key, layout[key], value)
		}
	}
	// The entry point uses Layout() unchanged and reads no environment.
	source := string(spireAgentHelperRead(t, spireAgentHelperModule))
	for _, forbidden := range []string{"os.environ", "getenv", "putenv", "environb"} {
		if strings.Contains(source, forbidden) {
			t.Errorf("helper source mentions %q; its paths must not come from the environment", forbidden)
		}
	}
	if !strings.Contains(source, "sys.exit(main(sys.argv[1:], Layout()))") {
		t.Errorf("helper entry point does not run main with the default Layout")
	}
	wrapper := string(spireAgentHelperRead(t, filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_spire_agent.sh")))
	if !strings.Contains(wrapper, `exec /usr/bin/python3 -I -B "${SCRIPT_DIR}/internal/remote_alpha_spire_agent.py" "$@"`) {
		t.Errorf("wrapper does not exec the isolated Python core")
	}
}

// The admin socket check counts an account whose primary group is the SPIRE
// group as a member of it, though /etc/group lists only the others. The
// test's own account has its primary group and is usually not listed there.
func TestRemoteAlphaSPIREAgentGroupMembersCountPrimaryGroup(t *testing.T) {
	cur, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	g, err := user.LookupGroupId(cur.Gid)
	if err != nil {
		t.Fatal(err)
	}
	code, out, stderr := spireAgentHelperDriverRun(t, "--group-members", g.Name)
	if code != 0 {
		t.Fatalf("group members: %d %s", code, stderr)
	}
	var members []string
	if err := json.Unmarshal([]byte(out), &members); err != nil {
		t.Fatal(err)
	}
	for _, m := range members {
		if m == cur.Username {
			return
		}
	}
	t.Fatalf("members of %s %v leave out %s, whose primary group it is", g.Name, members, cur.Username)
}

func TestRemoteAlphaSPIREAgentConfigAnalysis(t *testing.T) {
	bundle := "/etc/spire/agent/bootstrap-bundle.pem"
	box := spireAgentHelperAgentConf("/var/lib/spire/agent", "/run/spire/sockets/agent.sock", 8081)
	pinned := strings.Replace(box, "insecure_bootstrap = true", `trust_bundle_path = "`+bundle+`"`, 1)
	pinLine := `    trust_bundle_path = "` + bundle + "\"\n"
	cases := []struct {
		name, conf, state string
	}{
		{"box_insecure", box, "insecure"},
		{"pinned", pinned, "pinned"},
		{"pinned_with_pem_format", strings.Replace(pinned, "agent {\n", "agent {\n    trust_bundle_format = \"pem\"\n", 1), "pinned"},
		{"pinned_other_path", strings.Replace(pinned, bundle, "/tmp/other.pem", 1), "unrecognized"},
		{"spiffe_format", strings.Replace(pinned, "agent {\n", "agent {\n    trust_bundle_format = \"spiffe\"\n", 1), "unrecognized"},
		{"both", strings.Replace(box, "agent {\n", "agent {\n    trust_bundle_path = \""+bundle+"\"\n", 1), "unrecognized"},
		{"neither", strings.Replace(box, "    insecure_bootstrap = true\n", "", 1), "unrecognized"},
		{"insecure_false", strings.Replace(box, "= true", "= false", 1), "unrecognized"},
		{"insecure_twice", strings.Replace(box, "agent {\n", "agent {\n    insecure_bootstrap = true\n", 1), "unrecognized"},
		{"url", strings.Replace(box, "agent {\n", "agent {\n    trust_bundle_url = \"https://x\"\n", 1), "unrecognized"},
		{"commented_key", strings.Replace(box, "agent {\n", "agent {\n    # insecure_bootstrap = true\n", 1), "unrecognized"},
		{"block_comment", "/* x */\n" + box, "unrecognized"},
		{"outside_block", strings.Replace(box, "    insecure_bootstrap = true\n", "", 1) + "insecure_bootstrap = true\n", "unrecognized"},
		{"one_line_block", "agent { insecure_bootstrap = true }\n", "unrecognized"},
		{"crlf", strings.ReplaceAll(box, "\n", "\r\n"), "unrecognized"},
		{"two_agent_blocks", box + box, "unrecognized"},
		// SPIRE 1.14.4 reads each of these as insecure_bootstrap = true.
		{"pinned_plus_case_variant", strings.Replace(pinned, "agent {\n", "agent {\n    Insecure_Bootstrap = true\n", 1), "unrecognized"},
		{"pinned_plus_escaped_quoted_key", strings.Replace(pinned, "agent {\n", "agent {\n    \"insecure\\u005fbootstrap\" = true\n", 1), "unrecognized"},
		{"heredoc_hides_path", strings.Replace(box, "    insecure_bootstrap = true\n", "    admin_socket_path = <<EOT\n    trust_bundle_path = \""+bundle+"\"\nEOT\n    Insecure_Bootstrap = true\n", 1), "unrecognized"},
		// SPIRE 1.14.4 reads no trust_bundle_path here: the heredoc is the
		// join_token value. Only the heredoc rule tells the scan.
		{"heredoc_swallows_path", strings.Replace(box, "    insecure_bootstrap = true\n", "    join_token = <<EOT\n    trust_bundle_path = \""+bundle+"\"\nEOT\n", 1), "unrecognized"},
		// SPIRE 1.14.4 reads trust_bundle_path = "/tmp/other.pem" in each of
		// these (a later key wins, and a second agent block merges into the
		// first), and spire-agent validate accepts them plain and with
		// -trustBundle, so only the scan can tell.
		{"pinned_plus_second_block_escaped_path", pinned + "agent { \"trust\\u005fbundle\\u005fpath\" = \"/tmp/other.pem\" }\n", "unrecognized"},
		{"pinned_plus_same_line_escaped_path", strings.Replace(pinned, pinLine, pinLine+"    log_level = \"INFO\", \"trust\\u005fbundle\\u005fpath\" = \"/tmp/other.pem\"\n", 1), "unrecognized"},
		{"pinned_plus_long_s_path", strings.Replace(pinned, pinLine, pinLine+"    tru\u017ft_bundle_path = \"/tmp/other.pem\"\n", 1), "unrecognized"},
	}
	dir := t.TempDir()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name+".conf")
			if err := os.WriteFile(path, []byte(tc.conf), 0o644); err != nil {
				t.Fatal(err)
			}
			code, out, stderr := spireAgentHelperDriverRun(t, "--analyze-config", path, bundle)
			if code != 0 {
				t.Fatalf("analyze: %d %s", code, stderr)
			}
			var got map[string]any
			if err := json.Unmarshal([]byte(out), &got); err != nil {
				t.Fatal(err)
			}
			if got["state"] != tc.state {
				t.Fatalf("state %v, want %s (%v)", got["state"], tc.state, got)
			}
		})
	}
}

// spireAgentHelperTestCert returns a self-signed certificate (DER) with one
// URI SAN, as a CA or a leaf, that expires at notAfter.
func spireAgentHelperTestCert(t *testing.T, isCA bool, uri string, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(uri)
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
		NotBefore:             notAfter.Add(-2 * time.Hour),
		NotAfter:              notAfter,
		URIs:                  []*url.URL{u},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// The bundle the helper writes for the agent is what the agent will trust at
// its next bootstrap, so the checks on "spire-server bundle show" output are
// tested directly: only CA certificates for the trust domain, at least one
// unexpired, no repeats, and nothing in the text besides CERTIFICATE blocks.
func TestRemoteAlphaSPIREAgentBundleExportChecks(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skipf("needs openssl: %v", err)
	}
	td := "spiffe://" + spireAgentHelperTrustDomain
	now := time.Now()
	current := spireAgentHelperTestCert(t, true, td, now.Add(time.Hour))
	expired := spireAgentHelperTestCert(t, true, td, now.Add(-time.Hour))
	pemOf := func(ders ...[]byte) string {
		var buf bytes.Buffer
		for _, der := range ders {
			if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
				t.Fatal(err)
			}
		}
		return buf.String()
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("not a real key")}))
	cases := []struct {
		name   string
		pem    string
		count  int
		reason string
	}{
		{"one_current_ca", pemOf(current), 1, ""},
		{"expired_and_current_ca", pemOf(expired, current), 2, ""},
		{"leaf_certificate", pemOf(spireAgentHelperTestCert(t, false, td, now.Add(time.Hour))), 0, "not a CA certificate"},
		{"other_trust_domain", pemOf(spireAgentHelperTestCert(t, true, "spiffe://other.internal", now.Add(time.Hour))), 0, "not a CA certificate"},
		{"workload_uri", pemOf(spireAgentHelperTestCert(t, true, spireAgentHelperWorkload, now.Add(time.Hour))), 0, "not a CA certificate"},
		{"current_plus_leaf", pemOf(current, spireAgentHelperTestCert(t, false, td, now.Add(time.Hour))), 0, "not a CA certificate"},
		{"only_expired_ca", pemOf(expired), 0, "no unexpired CA certificate"},
		{"trailing_text", pemOf(current) + "junk\n", 0, "not a PEM bundle"},
		{"private_key_block", pemOf(current) + keyPEM, 0, "not a PEM bundle"},
		{"crlf", strings.ReplaceAll(pemOf(current), "\n", "\r\n"), 0, "not a PEM bundle"},
		{"empty", "", 0, "not a PEM bundle"},
		{"repeated", pemOf(current, current), 0, "repeats a certificate"},
	}
	dir := t.TempDir()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name+".pem")
			if err := os.WriteFile(path, []byte(tc.pem), 0o600); err != nil {
				t.Fatal(err)
			}
			code, out, stderr := spireAgentHelperDriverRun(t, "--export-bundle", path, openssl)
			if code != 0 {
				t.Fatalf("driver exited %d: %s", code, stderr)
			}
			var got struct {
				OK     bool   `json:"ok"`
				Count  int    `json:"count"`
				Reason string `json:"reason"`
			}
			if err := json.Unmarshal([]byte(out), &got); err != nil {
				t.Fatalf("driver output %q: %v", out, err)
			}
			if tc.reason == "" {
				if !got.OK || got.Count != tc.count {
					t.Fatalf("want accepted with %d certificates, got %+v", tc.count, got)
				}
				return
			}
			if got.OK || !strings.Contains(got.Reason, tc.reason) {
				t.Fatalf("want refusal containing %q, got %+v", tc.reason, got)
			}
		})
	}
}

func TestRemoteAlphaSPIREAgentUsageAndRootRefusal(t *testing.T) {
	dir := t.TempDir()
	layout := filepath.Join(dir, "layout.json")
	if err := os.WriteFile(layout, []byte(fmt.Sprintf(`{"required_euid": %d}`, os.Geteuid()+1)), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := spireAgentHelperDriverRun(t, layout, "status")
	if code != 2 || !strings.Contains(stderr, "must run as root") || out != "" {
		t.Fatalf("expected a root refusal with exit 2, got %d %q %q", code, out, stderr)
	}
	for _, args := range [][]string{{"status", "--apply"}, {"pin", "--evict-old-agent"}, {"bogus"}, {}} {
		code, _, _ := spireAgentHelperDriverRun(t, append([]string{layout}, args...)...)
		if code != 2 {
			t.Fatalf("args %v: exit %d, want 2", args, code)
		}
	}
	cmd := exec.Command(filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_spire_agent.sh"), "--help")
	cmd.Dir = executionSubstrateRepoRoot
	out2, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out2), "{status,pin,recover}") {
		t.Fatalf("wrapper --help: %v %s", err, out2)
	}
}

func TestRemoteAlphaSPIREAgentHelperIsDocumented(t *testing.T) {
	plans := compactText(mustRead(t, "PLANS.md"))
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	if !strings.Contains(plans, "`scripts/remote_alpha_spire_agent.sh`") {
		t.Fatalf("PLANS.md does not name the SPIRE agent helper")
	}
	for _, required := range []string{
		"Remote SPIRE Agent Bootstrap Trust And Recovery Helper",
		"`sudo scripts/remote_alpha_spire_agent.sh status`",
		"`sudo scripts/remote_alpha_spire_agent.sh pin --apply`",
		"`sudo scripts/remote_alpha_spire_agent.sh recover --apply`",
		"`--evict-old-agent`",
		"`execution-substrate.remote-alpha.spire-agent.v1`",
		"`/etc/spire/agent/bootstrap-bundle.pem`",
		"`/etc/tmpfiles.d/spire.conf`",
		"If the box or `spire-server.service` has been off for more than a day",
		"-trustBundle /etc/spire/agent/bootstrap-bundle.pem -trustBundleFormat pem -joinTokenFile <file>",
		"a stop signal (`SIGINT`, `SIGHUP` from an SSH drop, `SIGTERM`)",
	} {
		if !strings.Contains(remote, compactText(required)) {
			t.Fatalf("remote alpha doc missing %q", required)
		}
	}
}
