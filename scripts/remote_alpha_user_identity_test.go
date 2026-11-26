package scripts_test

// Tests for scripts/remote_alpha_user_identity.sh and its Python core
// scripts/internal/remote_alpha_user_identity.py.
//
// The box is a temporary directory tree with the box's file layout, owned
// by the test user; systemd is a small fake systemctl that records every call
// and can be told to fail a restart; openssl is the host's real openssl. The
// end-to-end test serves the minted identity through the real ES and AGS API
// handlers (es/api, ags/api) and through internal/callerauth, behind TLS
// configurations built the way es/app and ags/app build theirs, from the
// configs the helper edited and loaded with es/config and ags/config.
//
// Box modes need OpenSSL 3, as on the box; on a host whose /usr/bin/openssl
// is something else (macOS LibreSSL) those tests skip and say so. The caller
// request test runs everywhere, so running it on the Mac checks the caller
// side against LibreSSL. REMOTE_ALPHA_USER_IDENTITY_CALLER_PYTHON names
// another interpreter for the caller modes (for example a Python 3.9, the
// Mac's version); the default is /usr/bin/python3.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	agsapi "execution-substrate/ags/api"
	agsconfig "execution-substrate/ags/config"
	"execution-substrate/ags/publish"
	"execution-substrate/es/admission"
	esapi "execution-substrate/es/api"
	esconfig "execution-substrate/es/config"
	"execution-substrate/internal/callerauth"
)

var userIdentityModule = filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_user_identity.py")

const userIdentityBootstrapCN = "Bootstrap Root CA Example"

// userIdentityDriver imports the helper from its path and runs main with a
// Layout built from a JSON file, prints the default Layout, or applies one
// allowlist change to a config file and prints the edited text. Test code
// only.
const userIdentityDriver = `import dataclasses, importlib.util, json, os, sys
spec = importlib.util.spec_from_file_location("ra_user_identity", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)
if sys.argv[2] == "--dump-layout":
    print(json.dumps(dataclasses.asdict(mod.Layout()), sort_keys=True))
    sys.exit(0)
if sys.argv[2] == "--render-with-key":
    # A report that would carry private key text, rendered as text and as
    # JSON. No mode puts a key in a report; this reaches the last guard.
    rep = mod.Report("status", False)
    label = "PRIVATE " + "KEY"
    rep.facts["leak"] = "-----BEGIN %s-----\nMIIB\n-----END %s-----" % (label, label)
    rep.result = "ok"
    print(json.dumps([rep.render(False), rep.render(True)]))
    sys.exit(0)
if sys.argv[2] == "--set-prefixes-tampered":
    # A faulty array edit: the real one, then one more replacement in its
    # result, so the checks after the edit have something to catch.
    for fname in ("array_with_added", "array_with_removed"):
        def tampered(*args, _real=getattr(mod, fname)):
            return _real(*args).replace(sys.argv[5], sys.argv[6], 1)
        setattr(mod, fname, tampered)
    sys.argv[2] = "--set-prefixes"
if sys.argv[2] == "--set-prefixes":
    data = open(sys.argv[3], "rb").read()
    try:
        config = mod.ServiceConfig("T", mod.FileState(sys.argv[3], data, os.stat(sys.argv[3])))
        config.set_prefixes(json.loads(sys.argv[4]))
        print(json.dumps({"ok": True, "text": config.file.new.decode("utf-8")}))
    except (mod.Refusal, mod.Failure) as exc:
        print(json.dumps({"ok": False, "reason": str(exc)}))
    sys.exit(0)
sys.exit(mod.main(sys.argv[3:], mod.Layout(**json.load(open(sys.argv[2])))))
`

// The fake systemctl logs each call. show prints a running unit with the PID
// in <unit>.pid (100 at first); restart moves to a new PID. Markers in its
// directory: <unit>.fail-next-restart makes the next restart exit 1 once;
// <unit>.dead-after-next-restart makes the next restart succeed but leave
// the unit failed, once; <unit>.fail-restarts makes every restart exit 1;
// <unit>.flapping gives the unit a new PID at every show.
const userIdentityFakeSystemctl = `#!/usr/bin/python3
import json, os, sys
STATE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(STATE, "systemctl.log"), "a") as fh:
    fh.write(json.dumps(sys.argv[1:]) + "\n")
cmd, unit = sys.argv[1], sys.argv[2]
pidfile = os.path.join(STATE, unit + ".pid")
pid = int(open(pidfile).read()) if os.path.exists(pidfile) else 100
def marker(name):
    return os.path.join(STATE, unit + "." + name)
def take(name):
    if os.path.exists(marker(name)):
        os.unlink(marker(name))
        return True
    return False
if cmd == "restart":
    if take("fail-next-restart") or os.path.exists(marker("fail-restarts")):
        open(pidfile, "w").write("0")
        sys.exit(1)
    if take("dead-after-next-restart"):
        open(pidfile, "w").write("0")
        sys.exit(0)
    open(pidfile, "w").write(str(max(pid, 100) + 1))
    sys.exit(0)
if cmd == "show":
    if pid and os.path.exists(marker("flapping")):
        pid += 1
        open(pidfile, "w").write(str(pid))
    if pid == 0:
        print("ActiveState=failed\nSubState=failed\nMainPID=0\nLoadState=loaded")
    else:
        print("ActiveState=active\nSubState=running\nMainPID=%d\nLoadState=loaded" % pid)
    sys.exit(0)
sys.exit(3)
`

type userIdentityBox struct {
	t         *testing.T
	root      string
	etc       string
	agsConfig string
	esConfig  string
	agsCA     string
	esCA      string
	userCADir string
	units     string
	layout    string
	callers   string
	lock      string
	extCAPEM  []byte
	python    string
}

func requireUserIdentityOpenSSL3(t *testing.T) {
	t.Helper()
	cmd := exec.Command("/usr/bin/openssl", "version")
	cmd.Dir = t.TempDir()
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("/usr/bin/openssl version: %v", err)
	}
	if !strings.HasPrefix(string(out), "OpenSSL 3.") {
		t.Skipf("box modes need OpenSSL 3 as on the box; /usr/bin/openssl is %s", strings.TrimSpace(string(out)))
	}
}

func userIdentityCallerPython() string {
	if p := os.Getenv("REMOTE_ALPHA_USER_IDENTITY_CALLER_PYTHON"); p != "" {
		return p
	}
	return "/usr/bin/python3"
}

// newUserIdentityBox builds a box tree: an external client CA installed in
// both client CA files, and AGS and ES configs from the repository examples
// pointing at them, with the box's allowlists.
func newUserIdentityBox(t *testing.T) *userIdentityBox {
	t.Helper()
	root := t.TempDir()
	etc := filepath.Join(root, "etc", "execution-substrate")
	b := &userIdentityBox{
		t:         t,
		root:      root,
		etc:       etc,
		agsConfig: filepath.Join(etc, "ags.json"),
		esConfig:  filepath.Join(etc, "es.json"),
		agsCA:     filepath.Join(etc, "tls", "external-client-auth-ca.pem"),
		esCA:      filepath.Join(etc, "es-tls", "server-client-ca.pem"),
		userCADir: filepath.Join(etc, "user-ca"),
		units:     filepath.Join(root, "units"),
		layout:    filepath.Join(root, "layout.json"),
		callers:   filepath.Join(root, "callers"),
		lock:      filepath.Join(root, "user-identity.lock"),
		python:    userIdentityCallerPython(),
	}
	for _, dir := range []string{filepath.Join(etc, "tls"), filepath.Join(etc, "es-tls"), b.units} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{filepath.Join(root, "etc"), etc} {
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	_, _, b.extCAPEM = userIdentityTestCA(t, "Remote Alpha External Client Auth CA")
	writeUserIdentityFile(t, b.agsCA, b.extCAPEM, 0o640)
	writeUserIdentityFile(t, b.esCA, b.extCAPEM, 0o640)
	// The box's AGS, an older build, still lists the one-segment "operator";
	// AGS and ES from ES PR #38 on refuse such a prefix at startup, and the flow
	// test loads these configs into today's AGS and ES, so the fixture uses two
	// segments. The helper leaves every other entry as it is either way.
	b.writeConfig("ags", b.agsConfig, b.agsCA, []string{"operator/local", "service/control-plane"})
	b.writeConfig("es", b.esConfig, b.esCA, []string{"operator/local", "service/control-plane"})
	writeUserIdentityFile(t, filepath.Join(b.units, "systemctl"), []byte(userIdentityFakeSystemctl), 0o755)
	refused := 0
	if os.Geteuid() == 0 {
		refused = -1
	}
	b.writeLayout(map[string]any{
		"required_euid":       os.Geteuid(),
		"box_owner_uid":       os.Geteuid(),
		"ags_config":          b.agsConfig,
		"es_config":           b.esConfig,
		"ags_client_ca":       b.agsCA,
		"es_client_ca":        b.esCA,
		"user_ca_dir":         b.userCADir,
		"lock_path":           b.lock,
		"systemctl_bin":       filepath.Join(b.units, "systemctl"),
		"settle_seconds":      0.05,
		"caller_root":         b.callers,
		"refused_caller_euid": refused,
	})
	return b
}

func (b *userIdentityBox) writeLayout(fields map[string]any) {
	data, err := json.Marshal(fields)
	if err != nil {
		b.t.Fatal(err)
	}
	writeUserIdentityFile(b.t, b.layout, data, 0o600)
}

func (b *userIdentityBox) layoutFields() map[string]any {
	var fields map[string]any
	if err := json.Unmarshal(mustReadUserIdentityFile(b.t, b.layout), &fields); err != nil {
		b.t.Fatal(err)
	}
	return fields
}

func (b *userIdentityBox) writeConfig(example, path, clientCA string, prefixes []string) {
	b.t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(mustReadUserIdentityFile(b.t, filepath.Join(executionSubstrateRepoRoot, ".examples", "config", example+".json")), &doc); err != nil {
		b.t.Fatal(err)
	}
	doc["tls"].(map[string]any)["client_ca_file"] = clientCA
	doc["authorization"].(map[string]any)["allowed_spiffe_path_prefixes"] = prefixes
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		b.t.Fatal(err)
	}
	writeUserIdentityFile(b.t, path, append(data, '\n'), 0o640)
}

type userIdentityRun struct {
	code   int
	stdout string
	stderr string
	doc    map[string]any
}

func (r userIdentityRun) result() string {
	if r.doc == nil {
		return ""
	}
	s, _ := r.doc["result"].(string)
	return s
}

func (r userIdentityRun) message() string {
	if r.doc == nil {
		return ""
	}
	s, _ := r.doc["message"].(string)
	return s
}

func (r userIdentityRun) fact(name string) string {
	if r.doc == nil {
		return ""
	}
	facts, _ := r.doc["facts"].(map[string]any)
	s, _ := facts[name].(string)
	return s
}

func (r userIdentityRun) String() string {
	return fmt.Sprintf("exit %d\nstdout:\n%s\nstderr:\n%s", r.code, r.stdout, r.stderr)
}

func (b *userIdentityBox) runWith(python string, args ...string) userIdentityRun {
	b.t.Helper()
	argv := append([]string{"-I", "-B", "-c", userIdentityDriver, userIdentityModule, b.layout}, args...)
	cmd := exec.Command(python, argv...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	cmd.Dir = b.root
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	run := userIdentityRun{stdout: stdout.String(), stderr: stderr.String()}
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			b.t.Fatalf("run %v: %v", args, err)
		}
		run.code = exitErr.ExitCode()
	}
	if strings.Contains(run.stdout+run.stderr, "PRIVATE KEY") {
		b.t.Fatalf("helper output carries private key text:\n%s", run)
	}
	for _, arg := range args {
		if arg == "--json" && !(run.code == 2 && run.stdout == "") {
			var doc map[string]any
			if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
				b.t.Fatalf("run %v printed no JSON report: %v\n%s", args, err, run)
			}
			run.doc = doc
		}
	}
	return run
}

// box runs a box mode with /usr/bin/python3, the box's interpreter.
func (b *userIdentityBox) box(args ...string) userIdentityRun {
	b.t.Helper()
	return b.runWith("/usr/bin/python3", append(args, "--json")...)
}

// caller runs a caller mode with the caller interpreter.
func (b *userIdentityBox) caller(args ...string) userIdentityRun {
	b.t.Helper()
	return b.runWith(b.python, append(args, "--json")...)
}

func (b *userIdentityBox) mustOK(run userIdentityRun, what string) userIdentityRun {
	b.t.Helper()
	if run.code != 0 || (run.result() != "ok" && run.result() != "planned") {
		b.t.Fatalf("%s: want ok\n%s", what, run)
	}
	return run
}

func (b *userIdentityBox) callerDir(name string) string {
	return filepath.Join(b.callers, name)
}

// mint runs init-ca (if needed), request, issue and install for name and
// returns the issued certificate path on the "box".
func (b *userIdentityBox) mint(name string) string {
	b.t.Helper()
	if _, err := os.Lstat(b.userCADir); os.IsNotExist(err) {
		b.mustOK(b.box("init-ca", "--apply"), "init-ca")
	}
	b.mustOK(b.caller("request", "--name", name), "request")
	csr := filepath.Join(b.root, name+".csr")
	writeUserIdentityFile(b.t, csr, mustReadUserIdentityFile(b.t, filepath.Join(b.callerDir(name), "request.csr")), 0o644)
	out := filepath.Join(b.root, name+".crt")
	b.mustOK(b.box("issue", "--name", name, "--csr", csr, "--out", out, "--apply"), "issue")
	return out
}

func (b *userIdentityBox) systemctlCalls() []string {
	data, err := os.ReadFile(filepath.Join(b.units, "systemctl.log"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		b.t.Fatal(err)
	}
	var calls []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var argv []string
		if err := json.Unmarshal([]byte(line), &argv); err != nil {
			b.t.Fatal(err)
		}
		calls = append(calls, strings.Join(argv[:2], " "))
	}
	return calls
}

func (b *userIdentityBox) restarts() []string {
	var out []string
	for _, call := range b.systemctlCalls() {
		if strings.HasPrefix(call, "restart ") {
			out = append(out, strings.TrimPrefix(call, "restart "))
		}
	}
	return out
}

func (b *userIdentityBox) clearSystemctlLog() {
	_ = os.Remove(filepath.Join(b.units, "systemctl.log"))
}

func (b *userIdentityBox) marker(unit, name string) {
	writeUserIdentityFile(b.t, filepath.Join(b.units, unit+"."+name), nil, 0o644)
}

// snapshot records every entry under the box's /etc/execution-substrate:
// type, mode, owner and content digest.
func (b *userIdentityBox) snapshot() map[string]string {
	b.t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(b.etc, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		st := info.Sys().(*syscall.Stat_t)
		value := fmt.Sprintf("%v %d:%d", info.Mode(), st.Uid, st.Gid)
		if info.Mode().IsRegular() {
			sum := sha256.Sum256(mustReadUserIdentityFile(b.t, path))
			value += " " + hex.EncodeToString(sum[:])
		}
		rel, _ := filepath.Rel(b.etc, path)
		out[rel] = value
		return nil
	})
	if err != nil {
		b.t.Fatal(err)
	}
	return out
}

func requireSameUserIdentitySnapshot(t *testing.T, before, after map[string]string, what string) {
	t.Helper()
	var diffs []string
	for path, value := range before {
		if after[path] != value {
			diffs = append(diffs, fmt.Sprintf("%s: %q -> %q", path, value, after[path]))
		}
	}
	for path, value := range after {
		if _, ok := before[path]; !ok {
			diffs = append(diffs, fmt.Sprintf("%s: new %q", path, value))
		}
	}
	sort.Strings(diffs)
	if len(diffs) > 0 {
		t.Fatalf("%s changed the box:\n%s", what, strings.Join(diffs, "\n"))
	}
}

// withoutUserIdentityBackups drops the entries inside user-ca/backups.
func withoutUserIdentityBackups(snapshot map[string]string) map[string]string {
	out := map[string]string{}
	prefix := filepath.Join("user-ca", "backups") + string(filepath.Separator)
	for path, value := range snapshot {
		if !strings.HasPrefix(path, prefix) {
			out[path] = value
		}
	}
	return out
}

func writeUserIdentityFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func mustReadUserIdentityFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func userIdentityTestCA(t *testing.T, cn string) (*x509.Certificate, *rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func userIdentityServerCert(t *testing.T, ca *x509.Certificate, caKey *rsa.PrivateKey) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "server.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func parseUserIdentityPEMCert(t *testing.T, data []byte) *x509.Certificate {
	t.Helper()
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("not exactly one PEM certificate:\n%s", data)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// ---------------------------------------------------------------------------
// Real ES and AGS handlers behind the box's TLS shape

type userIdentityESStub struct {
	t *testing.T
}

func (s userIdentityESStub) Health(context.Context) admission.HealthSnapshot {
	return admission.HealthSnapshot{}
}

func (s userIdentityESStub) ProducerContract(context.Context) admission.ProducerContractDeclaration {
	return admission.ProducerContractDeclaration{}
}

func (s userIdentityESStub) unexpected(op string) *admission.Error {
	s.t.Errorf("ES %s must not be reached by the identity check", op)
	return &admission.Error{Status: http.StatusInternalServerError, Code: "unexpected", Message: op}
}

func (s userIdentityESStub) Prepare(context.Context, admission.PrepareRequest) (admission.PrepareResult, *admission.Error) {
	return admission.PrepareResult{}, s.unexpected("prepare")
}

func (s userIdentityESStub) Submit(context.Context, admission.PrepareRequest) (admission.SubmitResult, *admission.Error) {
	return admission.SubmitResult{}, s.unexpected("submit")
}

func (s userIdentityESStub) Status(context.Context, string) (admission.ExecutionStatusResult, *admission.Error) {
	return admission.ExecutionStatusResult{}, s.unexpected("status")
}

func (s userIdentityESStub) Logs(context.Context, string) (admission.ExecutionLogsResult, *admission.Error) {
	return admission.ExecutionLogsResult{}, s.unexpected("logs")
}

func (s userIdentityESStub) Result(context.Context, string) (admission.ExecutionResultBundle, *admission.Error) {
	return admission.ExecutionResultBundle{}, s.unexpected("result")
}

func (s userIdentityESStub) Cancel(context.Context, string) (admission.ExecutionCancelResult, *admission.Error) {
	return admission.ExecutionCancelResult{}, s.unexpected("cancel")
}

type userIdentityAGSStub struct {
	publishCalls *atomic.Int32
}

func (s userIdentityAGSStub) Health(context.Context) publish.HealthSnapshot {
	return publish.HealthSnapshot{}
}

func (s userIdentityAGSStub) Publish(context.Context, publish.CallerIdentity, publish.PublishRequest) (publish.PublishResult, *publish.Error) {
	s.publishCalls.Add(1)
	return publish.PublishResult{}, &publish.Error{Status: http.StatusInternalServerError, Code: "unexpected", Message: "publish reached"}
}

type userIdentityServers struct {
	es           *httptest.Server
	ags          *httptest.Server
	whoami       *httptest.Server
	publishCalls atomic.Int32
}

func (s *userIdentityServers) Close() {
	s.es.Close()
	s.ags.Close()
	s.whoami.Close()
}

// serverTLS is the TLS configuration es/app and ags/app build: the client
// CA file read once, verified client certificates required.
func userIdentityServerTLS(t *testing.T, cert tls.Certificate, clientCAFile string) *tls.Config {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(mustReadUserIdentityFile(t, clientCAFile)) {
		t.Fatalf("no certificates in %s", clientCAFile)
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}
}

// startUserIdentityServers loads the box configs with the services' own
// loaders, as a restart would, and serves the real handlers.
func startUserIdentityServers(t *testing.T, b *userIdentityBox, cert tls.Certificate) *userIdentityServers {
	t.Helper()
	esCfg, err := esconfig.Load(b.esConfig)
	if err != nil {
		t.Fatalf("es/config refuses the edited es.json: %v", err)
	}
	agsCfg, err := agsconfig.Load(b.agsConfig)
	if err != nil {
		t.Fatalf("ags/config refuses the edited ags.json: %v", err)
	}
	s := &userIdentityServers{}
	started := func() bool { return true }
	s.es = httptest.NewUnstartedServer(esapi.NewServer(userIdentityESStub{t: t}, esCfg.Security.BootstrapIssuerCommonName, esCfg.Authorization.AllowedSPIFFEPathPrefixes, started).Handler())
	s.es.TLS = userIdentityServerTLS(t, cert, esCfg.TLS.ClientCAFile)
	s.es.StartTLS()
	s.ags = httptest.NewUnstartedServer(agsapi.NewServer(userIdentityAGSStub{publishCalls: &s.publishCalls}, agsCfg.Security.BootstrapIssuerCommonName, agsCfg.Authorization.AllowedSPIFFEPathPrefixes, started).Handler())
	s.ags.TLS = userIdentityServerTLS(t, cert, agsCfg.TLS.ClientCAFile)
	s.ags.StartTLS()
	authenticator := callerauth.NewAuthenticator(esCfg.Security.BootstrapIssuerCommonName)
	s.whoami = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if caller, ok := authenticator.Authenticate(w, r); ok {
			_, _ = io.WriteString(w, caller.ID().String())
		}
	}))
	s.whoami.TLS = userIdentityServerTLS(t, cert, esCfg.TLS.ClientCAFile)
	s.whoami.StartTLS()
	return s
}

// whoami calls the callerauth server with a Go client holding the caller's
// key and certificate.
func userIdentityWhoami(t *testing.T, s *userIdentityServers, serverCA []byte, certFile, keyFile string) (string, error) {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("Go cannot load the caller key pair: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(serverCA)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{pair}}}, Timeout: 10 * time.Second}
	defer client.CloseIdleConnections()
	resp, err := client.Get(s.whoami.URL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return fmt.Sprintf("%d %s", resp.StatusCode, body), nil
}

func (b *userIdentityBox) checkOutcome(name, service, serverURL string) userIdentityRun {
	b.t.Helper()
	return b.caller("check", "--name", name, "--url", serverURL, "--service", service)
}

// ---------------------------------------------------------------------------
// Tests

// TestUserIdentityFlowThroughRealESAndAGSHandlers mints user/claude, allows
// it, and calls the real ES and AGS handlers with it; then revokes it and
// removes the user CA, and checks each step's effect on those handlers.
func TestUserIdentityFlowThroughRealESAndAGSHandlers(t *testing.T) {
	requireUserIdentityOpenSSL3(t)
	b := newUserIdentityBox(t)
	originalAGS := mustReadUserIdentityFile(t, b.agsConfig)
	originalES := mustReadUserIdentityFile(t, b.esConfig)

	serverCA, serverCAKey, serverCAPEM := userIdentityTestCA(t, "Remote Alpha Server CA")
	serverCert := userIdentityServerCert(t, serverCA, serverCAKey)
	serverCAFile := filepath.Join(b.root, "server-ca.pem")
	writeUserIdentityFile(t, serverCAFile, serverCAPEM, 0o644)

	issued := b.mint("claude")
	before := b.snapshot()
	install := b.mustOK(b.caller("install", "--name", "claude", "--cert", issued, "--server-ca", serverCAFile), "install")
	if install.fact("spiffe_id") != "spiffe://execution.internal/user/claude" {
		t.Fatalf("install reports %q", install.fact("spiffe_id"))
	}
	requireSameUserIdentitySnapshot(t, before, b.snapshot(), "install (a caller mode)")
	certFile := filepath.Join(b.callerDir("claude"), "cert.pem")
	keyFile := filepath.Join(b.callerDir("claude"), "key.pem")

	// Before allow: the services do not trust the user CA at all.
	servers := startUserIdentityServers(t, b, serverCert)
	for _, service := range []struct{ name, url string }{{"es", servers.es.URL}, {"ags", servers.ags.URL}} {
		run := b.checkOutcome("claude", service.name, service.url)
		if run.code != 1 || run.fact("outcome") != "client_certificate_refused" {
			t.Fatalf("check %s before allow: want client_certificate_refused\n%s", service.name, run)
		}
	}
	if got, err := userIdentityWhoami(t, servers, serverCAPEM, certFile, keyFile); err == nil {
		t.Fatalf("callerauth server accepted the user certificate before allow: %s", got)
	}
	servers.Close()

	// allow without --apply changes nothing.
	before = b.snapshot()
	plan := b.mustOK(b.box("allow", "--name", "claude"), "allow plan")
	if plan.result() != "planned" {
		t.Fatalf("allow without --apply: %s", plan)
	}
	requireSameUserIdentitySnapshot(t, before, b.snapshot(), "allow without --apply")
	if len(b.restarts()) != 0 {
		t.Fatalf("allow without --apply restarted %v", b.restarts())
	}

	b.mustOK(b.box("allow", "--name", "claude", "--apply"), "allow")
	if got := strings.Join(b.restarts(), ","); got != "ags.service,es.service" {
		t.Fatalf("allow restarted %q, want ags.service then es.service", got)
	}
	agsCA := mustReadUserIdentityFile(t, b.agsCA)
	if !bytes.Equal(agsCA, mustReadUserIdentityFile(t, b.esCA)) {
		t.Fatal("allow left the two client CA files different")
	}
	userCAPEM := mustReadUserIdentityFile(t, filepath.Join(b.userCADir, "ca-cert.pem"))
	if !bytes.Equal(agsCA, append(append([]byte(nil), b.extCAPEM...), userCAPEM...)) {
		t.Fatal("allow did not append exactly the user CA after the external client CA")
	}
	for _, f := range []struct {
		path string
		mode os.FileMode
	}{{b.agsCA, 0o640}, {b.esCA, 0o640}, {b.agsConfig, 0o640}, {b.esConfig, 0o640}} {
		info, err := os.Stat(f.path)
		if err != nil || info.Mode().Perm() != f.mode {
			t.Fatalf("%s mode after allow: %v %v", f.path, info.Mode(), err)
		}
	}
	for _, f := range []struct {
		path     string
		original []byte
		last     string
	}{{b.agsConfig, originalAGS, `"service/control-plane"`}, {b.esConfig, originalES, `"service/control-plane"`}} {
		want := strings.Replace(string(f.original), "      "+f.last+"\n", "      "+f.last+",\n      \"user/claude\"\n", 1)
		if got := string(mustReadUserIdentityFile(t, f.path)); got != want {
			t.Fatalf("%s after allow is not the original with one added line:\n%s", f.path, got)
		}
	}
	// A second allow has nothing to do.
	b.clearSystemctlLog()
	again := b.mustOK(b.box("allow", "--name", "claude", "--apply"), "second allow")
	if !strings.Contains(again.message(), "nothing to do") || len(b.restarts()) != 0 {
		t.Fatalf("second allow: %s, restarts %v", again, b.restarts())
	}

	servers = startUserIdentityServers(t, b, serverCert)
	es := b.checkOutcome("claude", "es", servers.es.URL)
	if es.code != 0 || es.fact("outcome") != "authorized" {
		t.Fatalf("check es after allow:\n%s", es)
	}
	ags := b.checkOutcome("claude", "ags", servers.ags.URL)
	if ags.code != 0 || ags.fact("outcome") != "authorized" {
		t.Fatalf("check ags after allow:\n%s", ags)
	}
	if n := servers.publishCalls.Load(); n != 0 {
		t.Fatalf("the AGS check reached the publish service %d times; it must stop at the body decode", n)
	}
	got, err := userIdentityWhoami(t, servers, serverCAPEM, certFile, keyFile)
	if err != nil || got != "200 spiffe://execution.internal/user/claude" {
		t.Fatalf("callerauth identity after allow: %q %v", got, err)
	}
	servers.Close()

	// revoke: authenticated but no longer allowed.
	b.mustOK(b.box("revoke", "--name", "claude", "--apply"), "revoke")
	servers = startUserIdentityServers(t, b, serverCert)
	for _, service := range []struct{ name, url string }{{"es", servers.es.URL}, {"ags", servers.ags.URL}} {
		run := b.checkOutcome("claude", service.name, service.url)
		if run.code != 1 || run.fact("outcome") != "not_allowed" {
			t.Fatalf("check %s after revoke: want not_allowed\n%s", service.name, run)
		}
	}
	servers.Close()
	if !bytes.Equal(mustReadUserIdentityFile(t, b.agsConfig), originalAGS) || !bytes.Equal(mustReadUserIdentityFile(t, b.esConfig), originalES) {
		t.Fatal("revoke did not restore the original config bytes")
	}

	// revoke --remove-ca: back to the external client CA alone.
	b.mustOK(b.box("revoke", "--name", "claude", "--remove-ca", "--apply"), "revoke --remove-ca")
	if !bytes.Equal(mustReadUserIdentityFile(t, b.agsCA), b.extCAPEM) || !bytes.Equal(mustReadUserIdentityFile(t, b.esCA), b.extCAPEM) {
		t.Fatal("revoke --remove-ca did not restore the external client CA bytes")
	}
	servers = startUserIdentityServers(t, b, serverCert)
	defer servers.Close()
	run := b.checkOutcome("claude", "es", servers.es.URL)
	if run.fact("outcome") != "client_certificate_refused" {
		t.Fatalf("check after --remove-ca: %s", run)
	}

	// A revoked name is never issued or allowed again.
	b.mustOK(b.caller("request", "--name", "claude", "--renew"), "request --renew")
	csr := filepath.Join(b.root, "claude-again.csr")
	writeUserIdentityFile(t, csr, mustReadUserIdentityFile(t, filepath.Join(b.callerDir("claude"), "pending", "request.csr")), 0o644)
	for _, args := range [][]string{
		{"issue", "--name", "claude", "--csr", csr, "--out", filepath.Join(b.root, "again.crt"), "--apply"},
		{"allow", "--name", "claude", "--apply"},
	} {
		run := b.box(args...)
		if run.code != 1 || run.result() != "refused" || !strings.Contains(run.message(), "revoked") {
			t.Fatalf("%v on a revoked name: %s", args, run)
		}
	}

	var registry map[string]any
	if err := json.Unmarshal(mustReadUserIdentityFile(t, filepath.Join(b.userCADir, "registry.json")), &registry); err != nil {
		t.Fatal(err)
	}
	entry := registry["names"].(map[string]any)["claude"].(map[string]any)
	if entry["state"] != "revoked" || entry["spiffe_id"] != "spiffe://execution.internal/user/claude" {
		t.Fatalf("registry entry: %v", entry)
	}
	var modes []string
	for _, e := range registry["events"].([]any) {
		modes = append(modes, e.(map[string]any)["mode"].(string))
	}
	if got := strings.Join(modes, ","); got != "init-ca,issue,allow,revoke,revoke" {
		t.Fatalf("registry events %q", got)
	}
}

// TestUserIdentityCertificatesMeetTheProfileInGo reads the user CA and a
// leaf with Go's x509 package, verifies the leaf for client auth the way the
// services do, and proves the CA's name constraint binds: a certificate the
// same CA key signs for another trust domain fails verification.
func TestUserIdentityCertificatesMeetTheProfileInGo(t *testing.T) {
	requireUserIdentityOpenSSL3(t)
	b := newUserIdentityBox(t)
	issued := b.mint("claude")
	ca := parseUserIdentityPEMCert(t, mustReadUserIdentityFile(t, filepath.Join(b.userCADir, "ca-cert.pem")))
	leaf := parseUserIdentityPEMCert(t, mustReadUserIdentityFile(t, issued))

	if !ca.IsCA || !ca.BasicConstraintsValid || ca.MaxPathLen != 0 || !ca.MaxPathLenZero {
		t.Fatalf("CA constraints: IsCA %v pathlen %d zero %v", ca.IsCA, ca.MaxPathLen, ca.MaxPathLenZero)
	}
	if ca.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign || len(ca.ExtKeyUsage) != 0 {
		t.Fatalf("CA usages: %v %v", ca.KeyUsage, ca.ExtKeyUsage)
	}
	if !ca.PermittedDNSDomainsCritical || strings.Join(ca.PermittedURIDomains, ",") != "execution.internal" ||
		len(ca.PermittedDNSDomains)+len(ca.ExcludedURIDomains)+len(ca.PermittedEmailAddresses)+len(ca.PermittedIPRanges) != 0 {
		t.Fatalf("CA name constraints: critical %v URIs %v", ca.PermittedDNSDomainsCritical, ca.PermittedURIDomains)
	}
	if ca.Subject.CommonName != "Execution Substrate Remote Alpha User CA" || ca.Subject.CommonName == userIdentityBootstrapCN {
		t.Fatalf("CA subject %v", ca.Subject)
	}
	if key, ok := ca.PublicKey.(*rsa.PublicKey); !ok || key.N.BitLen() != 3072 {
		t.Fatal("CA key is not RSA-3072")
	}
	if ca.SignatureAlgorithm != x509.SHA256WithRSA {
		t.Fatalf("CA signature %v", ca.SignatureAlgorithm)
	}
	if lifetime := ca.NotAfter.Sub(ca.NotBefore); lifetime != 400*24*time.Hour {
		t.Fatalf("CA lifetime %v", lifetime)
	}

	if leaf.IsCA || !leaf.BasicConstraintsValid || leaf.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Fatalf("leaf constraints: IsCA %v usage %v", leaf.IsCA, leaf.KeyUsage)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(leaf.UnknownExtKeyUsage) != 0 {
		t.Fatalf("leaf EKU %v", leaf.ExtKeyUsage)
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != "spiffe://execution.internal/user/claude" ||
		len(leaf.DNSNames)+len(leaf.EmailAddresses)+len(leaf.IPAddresses) != 0 {
		t.Fatalf("leaf SANs: %v %v %v %v", leaf.URIs, leaf.DNSNames, leaf.EmailAddresses, leaf.IPAddresses)
	}
	if leaf.Subject.String() != "CN=claude" || !bytes.Equal(leaf.RawIssuer, ca.RawSubject) {
		t.Fatalf("leaf subject %v issuer %v", leaf.Subject, leaf.Issuer)
	}
	if lifetime := leaf.NotAfter.Sub(leaf.NotBefore); lifetime != 90*24*time.Hour {
		t.Fatalf("leaf lifetime %v", lifetime)
	}
	if leaf.SerialNumber.BitLen() != 127 {
		t.Fatalf("leaf serial has %d bits, want 127", leaf.SerialNumber.BitLen())
	}
	if !bytes.Equal(leaf.AuthorityKeyId, ca.SubjectKeyId) || len(leaf.SubjectKeyId) == 0 {
		t.Fatal("leaf key identifiers do not chain to the CA")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("Go does not verify the leaf for client auth: %v", err)
	}
	caller, err := callerauth.CallerFromConnectionState(&tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf, ca}}}, time.Now())
	if err != nil || caller.ID().String() != "spiffe://execution.internal/user/claude" {
		t.Fatalf("callerauth reads %v, %v", caller.ID(), err)
	}

	// The same CA key signing an ID in another trust domain: Go refuses it.
	keyBlock, _ := pem.Decode(mustReadUserIdentityFile(t, filepath.Join(b.userCADir, "ca-key.pem")))
	caKeyAny, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	foreignKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	foreignURI, _ := url.Parse("spiffe://other.example/user/claude")
	foreignDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "claude"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true, URIs: []*url.URL{foreignURI},
	}, ca, &foreignKey.PublicKey, caKeyAny)
	if err != nil {
		t.Fatal(err)
	}
	foreign, _ := x509.ParseCertificate(foreignDER)
	if _, err := foreign.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Fatal("the user CA's name constraint did not stop a certificate for another trust domain")
	}
}

// TestUserIdentityApplyRollsBackToTheExactBytes makes each restart step fail
// in turn and requires the four service files, their modes and the registry
// to come back exactly, with the units that were restarted restarted again.
func TestUserIdentityApplyRollsBackToTheExactBytes(t *testing.T) {
	requireUserIdentityOpenSSL3(t)
	cases := []struct {
		name         string
		unit, marker string
		wantRestarts string
		wantResult   string
		wantMessage  string
	}{
		{"AGS restart fails", "ags.service", "fail-next-restart", "ags.service,ags.service", "failed", "rolled back"},
		{"AGS dies after restart", "ags.service", "dead-after-next-restart", "ags.service,ags.service", "failed", "rolled back"},
		{"ES restart fails", "es.service", "fail-next-restart", "ags.service,es.service,ags.service,es.service", "failed", "rolled back"},
		{"ES dies after restart", "es.service", "dead-after-next-restart", "ags.service,es.service,ags.service,es.service", "failed", "rolled back"},
		{"ES keeps changing PID", "es.service", "flapping", "ags.service,es.service,ags.service,es.service", "failed", "rollback incomplete"},
		{"ES never restarts", "es.service", "fail-restarts", "ags.service,es.service,ags.service,es.service", "failed", "rollback incomplete"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b := newUserIdentityBox(t)
			b.mint("claude")
			before := b.snapshot()
			b.clearSystemctlLog()
			b.marker(tc.unit, tc.marker)
			run := b.box("allow", "--name", "claude", "--apply")
			if run.code != 1 || run.result() != tc.wantResult || !strings.Contains(run.message(), tc.wantMessage) {
				t.Fatalf("want %s with %q\n%s", tc.wantResult, tc.wantMessage, run)
			}
			if got := strings.Join(b.restarts(), ","); got != tc.wantRestarts {
				t.Fatalf("restarts %q, want %q", got, tc.wantRestarts)
			}
			// The only new entries are the backup directory and its files.
			requireSameUserIdentitySnapshot(t, withoutUserIdentityBackups(before), withoutUserIdentityBackups(b.snapshot()), "a rolled-back allow")
		})
	}

	t.Run("revoke that fails says the name may still be allowed", func(t *testing.T) {
		t.Parallel()
		b := newUserIdentityBox(t)
		b.mint("claude")
		b.mustOK(b.box("allow", "--name", "claude", "--apply"), "allow")
		before := b.snapshot()
		b.marker("es.service", "dead-after-next-restart")
		run := b.box("revoke", "--name", "claude", "--apply")
		if run.code != 1 || !strings.Contains(run.message(), "did not take effect") {
			t.Fatalf("failed revoke: %s", run)
		}
		requireSameUserIdentitySnapshot(t, withoutUserIdentityBackups(before), withoutUserIdentityBackups(b.snapshot()), "a rolled-back revoke")
	})
}

// TestUserIdentityRefusesAndChangesNothing covers every refusal: each leaves
// the box tree byte-for-byte unchanged and restarts nothing.
func TestUserIdentityRefusesAndChangesNothing(t *testing.T) {
	requireUserIdentityOpenSSL3(t)

	type setup func(t *testing.T, b *userIdentityBox) []string
	edit := func(path string, change func(string) string) func(t *testing.T, b *userIdentityBox) {
		return func(t *testing.T, b *userIdentityBox) {
			info, _ := os.Stat(path)
			writeUserIdentityFile(t, path, []byte(change(string(mustReadUserIdentityFile(t, path)))), info.Mode().Perm())
		}
	}
	minted := func(t *testing.T, b *userIdentityBox) { b.mint("claude") }
	cases := []struct {
		name    string
		prepare setup
		code    int
		want    string
	}{
		{"issue before init-ca", func(t *testing.T, b *userIdentityBox) []string {
			return []string{"issue", "--name", "claude", "--csr", "/nonexistent.csr", "--out", "/nonexistent.crt"}
		}, 1, "run init-ca first"},
		{"init-ca twice", func(t *testing.T, b *userIdentityBox) []string {
			b.mustOK(b.box("init-ca", "--apply"), "init-ca")
			return []string{"init-ca", "--apply"}
		}, 1, "created once"},
		{"allow before issue", func(t *testing.T, b *userIdentityBox) []string {
			b.mustOK(b.box("init-ca", "--apply"), "init-ca")
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "run issue first"},
		{"AGS client CA path differs", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			b.writeConfig("ags", b.agsConfig, filepath.Join(b.etc, "tls", "combined-service-ca-bundle.pem"), []string{"operator/local", "service/control-plane"})
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "AGS tls.client_ca_file"},
		{"client CA files differ", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			_, _, other := userIdentityTestCA(t, "Other CA")
			writeUserIdentityFile(t, b.esCA, other, 0o640)
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "differ"},
		{"a bare user prefix already covers the name", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			b.writeConfig("ags", b.agsConfig, b.agsCA, []string{"operator/local", "service/control-plane", "user"})
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "already authorizes user/claude"},
		{"a trailing-slash entry already covers the name", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			b.writeConfig("es", b.esConfig, b.esCA, []string{"operator/local", "service/control-plane", "user/claude/"})
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "already authorizes user/claude"},
		{"duplicate JSON key", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			edit(b.esConfig, func(s string) string {
				return strings.Replace(s, `"authorization": {`, `"authorization": {"allowed_spiffe_path_prefixes": ["operator/local"],`, 1)
			})(t, b)
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "duplicate key"},
		{"a case variant of a key Go would fold together", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			edit(b.agsConfig, func(s string) string {
				return strings.Replace(s, "{\n", "{\n  \"Authorization\": {\"allowed_spiffe_path_prefixes\": [\"user\"]},\n", 1)
			})(t, b)
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "only lower-case ASCII keys"},
		{"a Kelvin-sign key Go would fold to k", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			edit(b.esConfig, func(s string) string {
				return strings.Replace(s, "{\n", "{\n  \"tlsK\": 1,\n", 1)
			})(t, b)
			return []string{"revoke", "--name", "claude", "--apply"}
		}, 1, "only lower-case ASCII keys"},
		{"a non-certificate block in a client CA file", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			junk := append(append([]byte(nil), b.extCAPEM...), []byte("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n")...)
			writeUserIdentityFile(t, b.agsCA, junk, 0o640)
			writeUserIdentityFile(t, b.esCA, junk, 0o640)
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "PUBLIC KEY block"},
		{"text outside PEM blocks in a client CA file", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			junk := append([]byte("subject=CN = x\n"), b.extCAPEM...)
			writeUserIdentityFile(t, b.agsCA, junk, 0o640)
			writeUserIdentityFile(t, b.esCA, junk, 0o640)
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "outside PEM blocks"},
		{"user CA already present but not last", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			userCA := mustReadUserIdentityFile(t, filepath.Join(b.userCADir, "ca-cert.pem"))
			_, _, other := userIdentityTestCA(t, "Later CA")
			data := bytes.Join([][]byte{b.extCAPEM, userCA, other}, nil)
			writeUserIdentityFile(t, b.agsCA, data, 0o640)
			writeUserIdentityFile(t, b.esCA, data, 0o640)
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "not as its byte-exact final block"},
		{"user CA first in the client CA files", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			userCA := mustReadUserIdentityFile(t, filepath.Join(b.userCADir, "ca-cert.pem"))
			writeUserIdentityFile(t, b.agsCA, userCA, 0o640)
			writeUserIdentityFile(t, b.esCA, userCA, 0o640)
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "first certificate"},
		{"user CA twice at the end of the client CA files", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			userCA := mustReadUserIdentityFile(t, filepath.Join(b.userCADir, "ca-cert.pem"))
			data := bytes.Join([][]byte{b.extCAPEM, userCA, userCA}, nil)
			writeUserIdentityFile(t, b.agsCA, data, 0o640)
			writeUserIdentityFile(t, b.esCA, data, 0o640)
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "more than once"},
		{"client CA file without a final newline", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			data := bytes.TrimRight(b.extCAPEM, "\n")
			writeUserIdentityFile(t, b.agsCA, data, 0o640)
			writeUserIdentityFile(t, b.esCA, data, 0o640)
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "newline"},
		{"group-writable config", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			if err := os.Chmod(b.esConfig, 0o660); err != nil {
				t.Fatal(err)
			}
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "not writable by group or others"},
		{"symlinked config", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			moved := filepath.Join(b.root, "ags.json.real")
			if err := os.Rename(b.agsConfig, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(moved, b.agsConfig); err != nil {
				t.Fatal(err)
			}
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "cannot open"},
		{"group-writable config directory", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			if err := os.Chmod(filepath.Join(b.etc, "es-tls"), 0o775); err != nil {
				t.Fatal(err)
			}
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "not writable by group or others"},
		{"CA key readable by others", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			if err := os.Chmod(filepath.Join(b.userCADir, "ca-key.pem"), 0o644); err != nil {
				t.Fatal(err)
			}
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "mode 0600"},
		{"registry for another CA", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			path := filepath.Join(b.userCADir, "registry.json")
			edit(path, func(s string) string {
				var doc map[string]any
				_ = json.Unmarshal([]byte(s), &doc)
				doc["ca"].(map[string]any)["sha256"] = strings.Repeat("0", 64)
				out, _ := json.Marshal(doc)
				return string(out)
			})(t, b)
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "does not match"},
		{"--remove-ca while another name is active", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			b.mint("second")
			b.mustOK(b.box("allow", "--name", "claude", "--apply"), "allow")
			return []string{"revoke", "--name", "claude", "--remove-ca", "--apply"}
		}, 1, "other names are active: second"},
		{"--remove-ca while other user entries remain", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			b.mustOK(b.box("allow", "--name", "claude", "--apply"), "allow")
			b.writeConfig("ags", b.agsConfig, b.agsCA, []string{"operator/local", "service/control-plane", "user/claude", "user/ghost"})
			return []string{"revoke", "--name", "claude", "--remove-ca", "--apply"}
		}, 1, "user entries remain in the allowlists: user/ghost"},
		{"a CA that ends before a 90-day certificate", func(t *testing.T, b *userIdentityBox) []string {
			fields := b.layoutFields()
			fields["ca_days"] = 60
			b.writeLayout(fields)
			b.mustOK(b.box("init-ca", "--apply"), "init-ca")
			b.mustOK(b.caller("request", "--name", "claude"), "request")
			return []string{"issue", "--name", "claude", "--csr", filepath.Join(b.callerDir("claude"), "request.csr"), "--out", filepath.Join(b.root, "short.crt"), "--apply"}
		}, 1, "before a 90-day certificate would"},
		{"revoke of an unknown name", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			return []string{"revoke", "--name", "nobody", "--apply"}
		}, 1, "not in the registry"},
		{"removing the only allowlist entry", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			b.mustOK(b.box("allow", "--name", "claude", "--apply"), "allow")
			b.writeConfig("ags", b.agsConfig, b.agsCA, []string{"user/claude"})
			return []string{"revoke", "--name", "claude", "--apply"}
		}, 1, "would become empty"},
		{"lock held by another run", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			fd, err := syscall.Open(b.lock, syscall.O_RDWR|syscall.O_CREAT, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { syscall.Close(fd) })
			if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
				t.Fatal(err)
			}
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "holds the lock"},
		{"box mode as another user", func(t *testing.T, b *userIdentityBox) []string {
			fields := b.layoutFields()
			fields["required_euid"] = os.Geteuid() + 1
			b.writeLayout(fields)
			return []string{"init-ca", "--apply"}
		}, 2, ""},
		{"caller mode as root", func(t *testing.T, b *userIdentityBox) []string {
			fields := b.layoutFields()
			fields["refused_caller_euid"] = os.Geteuid()
			b.writeLayout(fields)
			return []string{"request", "--name", "claude"}
		}, 2, ""},
	}
	for _, name := range []string{"Claude", "1claude", "claude-", "-claude", "cl.aude", "cl/aude", "cl_aude", strings.Repeat("a", 33), ""} {
		name := name
		cases = append(cases, struct {
			name    string
			prepare setup
			code    int
			want    string
		}{"bad name " + fmt.Sprintf("%q", name), func(t *testing.T, b *userIdentityBox) []string {
			return []string{"allow", "--name", name, "--apply"}
		}, 2, ""})
	}
	for _, args := range [][]string{
		{"status", "--apply"},
		{"allow", "--name", "claude", "--csr", "/x"},
		{"issue", "--name", "claude", "--csr", "/x"},
		{"request", "--name", "claude", "--apply"},
		{"check", "--name", "claude", "--service", "ags"},
		{"revoke", "--name", "claude", "--renew"},
		{"issue", "--name", "claude", "--csr", "relative.csr", "--out", "/x.crt"},
	} {
		args := args
		cases = append(cases, struct {
			name    string
			prepare setup
			code    int
			want    string
		}{"usage " + strings.Join(args, " "), func(t *testing.T, b *userIdentityBox) []string {
			if args[0] == "issue" {
				b.mustOK(b.box("init-ca", "--apply"), "init-ca")
			}
			return args
		}, 2, ""})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b := newUserIdentityBox(t)
			args := tc.prepare(t, b)
			before := b.snapshot()
			b.clearSystemctlLog()
			run := b.runWith("/usr/bin/python3", append(args, "--json")...)
			if run.code != tc.code {
				t.Fatalf("want exit %d\n%s", tc.code, run)
			}
			if tc.want != "" && (run.doc == nil || run.result() != "refused" || !strings.Contains(run.message(), tc.want)) {
				t.Fatalf("want refused with %q\n%s", tc.want, run)
			}
			requireSameUserIdentitySnapshot(t, before, b.snapshot(), "a refused run")
			if r := b.restarts(); len(r) != 0 {
				t.Fatalf("a refused run restarted %v", r)
			}
		})
	}
}

// TestUserIdentityIssueChecksTheCSR covers what issue accepts and refuses in
// a CSR. CSRs made in Go stand in for other tools.
func TestUserIdentityIssueChecksTheCSR(t *testing.T) {
	requireUserIdentityOpenSSL3(t)
	makeCSR := func(t *testing.T, key any, subject pkix.Name, extra []pkix.Extension) []byte {
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: subject, ExtraExtensions: extra}, key)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	}
	rsaKey := func(bits int) *rsa.PrivateKey {
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	ecKey := func(curve elliptic.Curve) *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	key3072 := rsaKey(3072)
	good := makeCSR(t, key3072, pkix.Name{CommonName: "claude"}, nil)
	tampered := func() []byte {
		block, _ := pem.Decode(makeCSR(t, rsaKey(3072), pkix.Name{CommonName: "claude"}, nil))
		der := append([]byte(nil), block.Bytes...)
		der[len(der)-5] ^= 0x01
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	}()
	sanExt := pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: []byte{0x30, 0x00}}

	cases := []struct {
		name string
		csr  []byte
		want string // "" = accepted
	}{
		{"RSA-3072", good, ""},
		{"EC P-256", makeCSR(t, ecKey(elliptic.P256()), pkix.Name{CommonName: "claude"}, nil), ""},
		{"EC P-384", makeCSR(t, ecKey(elliptic.P384()), pkix.Name{CommonName: "claude"}, nil), ""},
		{"RSA-2048", makeCSR(t, rsaKey(2048), pkix.Name{CommonName: "claude"}, nil), "3072 to 8192 bits"},
		{"EC P-521", makeCSR(t, ecKey(elliptic.P521()), pkix.Name{CommonName: "claude"}, nil), "P-256 or P-384"},
		{"another name", makeCSR(t, rsaKey(3072), pkix.Name{CommonName: "other"}, nil), "want exactly CN=claude"},
		{"extra subject attribute", makeCSR(t, rsaKey(3072), pkix.Name{CommonName: "claude", Organization: []string{"x"}}, nil), "want exactly CN=claude"},
		{"requested extensions", makeCSR(t, rsaKey(3072), pkix.Name{CommonName: "claude"}, []pkix.Extension{sanExt}), "requested extensions"},
		{"bad self-signature", tampered, "self-signature does not verify"},
		{"two blocks", append(append([]byte(nil), good...), good...), "exactly one CERTIFICATE REQUEST"},
		{"a certificate instead", nil, "exactly one CERTIFICATE REQUEST"},
	}
	b := newUserIdentityBox(t)
	b.mustOK(b.box("init-ca", "--apply"), "init-ca")
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			csr := tc.csr
			if csr == nil {
				csr = b.extCAPEM
			}
			csrPath := filepath.Join(b.root, fmt.Sprintf("case%d.csr", i))
			out := filepath.Join(b.root, fmt.Sprintf("case%d.crt", i))
			writeUserIdentityFile(t, csrPath, csr, 0o644)
			before := b.snapshot()
			// Every case gets its own name for the accepted ones, so key reuse
			// is not what is tested here.
			run := b.box("issue", "--name", "claude", "--csr", csrPath, "--out", out, "--apply")
			if tc.want == "" {
				b.mustOK(run, "issue")
				leaf := parseUserIdentityPEMCert(t, mustReadUserIdentityFile(t, out))
				if leaf.URIs[0].String() != "spiffe://execution.internal/user/claude" {
					t.Fatalf("leaf URI %v", leaf.URIs)
				}
				return
			}
			if run.code != 1 || run.result() != "refused" || !strings.Contains(run.message(), tc.want) {
				t.Fatalf("want refused with %q\n%s", tc.want, run)
			}
			requireSameUserIdentitySnapshot(t, before, b.snapshot(), "a refused issue")
			if _, err := os.Lstat(out); !os.IsNotExist(err) {
				t.Fatalf("a refused issue wrote %s", out)
			}
		})
	}

	t.Run("the same key twice", func(t *testing.T) {
		csrPath := filepath.Join(b.root, "again.csr")
		writeUserIdentityFile(t, csrPath, good, 0o644)
		run := b.box("issue", "--name", "claude", "--csr", csrPath, "--out", filepath.Join(b.root, "again.crt"), "--apply")
		if run.code != 1 || !strings.Contains(run.message(), "already used") {
			t.Fatalf("key reuse: %s", run)
		}
	})
	t.Run("an existing output file", func(t *testing.T) {
		csrPath := filepath.Join(b.root, "fresh.csr")
		writeUserIdentityFile(t, csrPath, makeCSR(t, rsaKey(3072), pkix.Name{CommonName: "claude"}, nil), 0o644)
		out := filepath.Join(b.root, "exists.crt")
		writeUserIdentityFile(t, out, []byte("keep"), 0o644)
		run := b.box("issue", "--name", "claude", "--csr", csrPath, "--out", out, "--apply")
		if run.code != 1 || !strings.Contains(run.message(), "already exists") || string(mustReadUserIdentityFile(t, out)) != "keep" {
			t.Fatalf("existing --out: %s", run)
		}
	})
	t.Run("issue without --apply", func(t *testing.T) {
		csrPath := filepath.Join(b.root, "plan.csr")
		writeUserIdentityFile(t, csrPath, makeCSR(t, rsaKey(3072), pkix.Name{CommonName: "claude"}, nil), 0o644)
		before := b.snapshot()
		run := b.mustOK(b.box("issue", "--name", "claude", "--csr", csrPath, "--out", filepath.Join(b.root, "plan.crt")), "issue plan")
		if run.result() != "planned" || run.fact("csr_public_key_sha256") == "" {
			t.Fatalf("issue plan: %s", run)
		}
		requireSameUserIdentitySnapshot(t, before, b.snapshot(), "issue without --apply")
	})
}

// TestUserIdentityAllowlistEditKeepsEveryOtherByte pins the in-place array
// edit on several layouts, and that the edited example configs still load.
func TestUserIdentityAllowlistEditKeepsEveryOtherByte(t *testing.T) {
	dir := t.TempDir()
	editWith := func(t *testing.T, text string, prefixes []string, tamper ...string) (bool, string) {
		t.Helper()
		path := filepath.Join(dir, "config.json")
		writeUserIdentityFile(t, path, []byte(text), 0o600)
		list, _ := json.Marshal(prefixes)
		args := []string{"-I", "-B", "-c", userIdentityDriver, userIdentityModule, "--set-prefixes", path, string(list)}
		if len(tamper) == 2 {
			args[5] = "--set-prefixes-tampered"
			args = append(args, tamper...)
		}
		cmd := exec.Command("/usr/bin/python3", args...)
		cmd.Dir = t.TempDir()
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("driver: %v", err)
		}
		var result struct {
			OK     bool   `json:"ok"`
			Text   string `json:"text"`
			Reason string `json:"reason"`
		}
		if err := json.Unmarshal(out, &result); err != nil {
			t.Fatalf("driver output %q: %v", out, err)
		}
		if result.OK {
			return true, result.Text
		}
		return false, result.Reason
	}
	edit := func(t *testing.T, text string, prefixes []string) (bool, string) {
		t.Helper()
		return editWith(t, text, prefixes)
	}
	const multi = "{\n  \"tls\": {\"client_ca_file\": \"/x\"},\n  \"authorization\": {\n    \"allowed_spiffe_path_prefixes\": [\n      \"operator/local\",\n      \"service/control-plane\"\n    ]\n  },\n  \"note\": \"caf\\u00e9 \\/ slash\"\n}\n"
	cases := []struct {
		name, text string
		prefixes   []string
		want       string
	}{
		{"add, multi-line", multi, []string{"operator/local", "service/control-plane", "user/claude"},
			strings.Replace(multi, "\"service/control-plane\"\n", "\"service/control-plane\",\n      \"user/claude\"\n", 1)},
		{"remove last, multi-line", strings.Replace(multi, "\"service/control-plane\"\n", "\"service/control-plane\",\n      \"user/claude\"\n", 1),
			[]string{"operator/local", "service/control-plane"}, multi},
		{"remove first, multi-line", multi, []string{"service/control-plane"},
			strings.Replace(multi, "\"operator/local\",\n      ", "", 1)},
		{"add, compact", `{"authorization":{"allowed_spiffe_path_prefixes":["a/b","c/d"]},"z":1}`, []string{"a/b", "c/d", "user/claude"},
			`{"authorization":{"allowed_spiffe_path_prefixes":["a/b","c/d","user/claude"]},"z":1}`},
		{"add to one element, one line", `{"authorization": {"allowed_spiffe_path_prefixes": ["a/b"]}}`, []string{"a/b", "user/claude"},
			`{"authorization": {"allowed_spiffe_path_prefixes": ["a/b", "user/claude"]}}`},
		{"add to one element, tabs", "{\n\t\"authorization\": {\n\t\t\"allowed_spiffe_path_prefixes\": [\n\t\t\t\"a/b\"\n\t\t]\n\t}\n}\n", []string{"a/b", "user/claude"},
			"{\n\t\"authorization\": {\n\t\t\"allowed_spiffe_path_prefixes\": [\n\t\t\t\"a/b\",\n\t\t\t\"user/claude\"\n\t\t]\n\t}\n}\n"},
		{"same key elsewhere is left alone", `{"allowed_spiffe_path_prefixes":["x/y"],"authorization":{"other":{"allowed_spiffe_path_prefixes":["q/r"]},"allowed_spiffe_path_prefixes":["a/b","c/d"]}}`,
			[]string{"a/b", "c/d", "user/claude"},
			`{"allowed_spiffe_path_prefixes":["x/y"],"authorization":{"other":{"allowed_spiffe_path_prefixes":["q/r"]},"allowed_spiffe_path_prefixes":["a/b","c/d","user/claude"]}}`},
		{"escaped existing entries keep their bytes", `{"authorization":{"allowed_spiffe_path_prefixes":["a\/b","c/d"]}}`, []string{"a/b", "c/d", "user/claude"},
			`{"authorization":{"allowed_spiffe_path_prefixes":["a\/b","c/d","user/claude"]}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, got := edit(t, tc.text, tc.prefixes)
			if !ok || got != tc.want {
				t.Fatalf("edit:\n got %v %q\nwant %q", ok, got, tc.want)
			}
		})
	}
	for _, tc := range []struct{ name, text, want string }{
		{"duplicate key", `{"authorization":{"allowed_spiffe_path_prefixes":["a/b"],"allowed_spiffe_path_prefixes":["c/d","e/f"]}}`, "duplicate key"},
		{"duplicate key off the edited path", `{"x":{"y":1,"y":2},"authorization":{"allowed_spiffe_path_prefixes":["a/b","c/d"]}}`, "duplicate key"},
		{"NaN", `{"authorization":{"allowed_spiffe_path_prefixes":["a/b","c/d"]},"x":NaN}`, "not JSON"},
		{"trailing data", `{"authorization":{"allowed_spiffe_path_prefixes":["a/b","c/d"]}} {}`, "not strict JSON"},
		{"not a list of strings", `{"authorization":{"allowed_spiffe_path_prefixes":["a/b",1]}}`, "non-empty list of strings"},
		{"upper-case key", `{"Tls":{},"authorization":{"allowed_spiffe_path_prefixes":["a/b","c/d"]}}`, "lower-case ASCII"},
	} {
		t.Run("refuses "+tc.name, func(t *testing.T) {
			ok, reason := edit(t, tc.text, []string{"a/b", "c/d", "user/claude"})
			if ok || !strings.Contains(reason, tc.want) {
				t.Fatalf("want refusal with %q, got %v %q", tc.want, ok, reason)
			}
		})
	}

	// A faulty array edit is caught after it runs, whether it changes what
	// the document means or only bytes outside the array, adding or removing.
	added := []string{"operator/local", "service/control-plane", "user/claude"}
	withUser := strings.Replace(multi, "\"service/control-plane\"\n", "\"service/control-plane\",\n      \"user/claude\"\n", 1)
	for _, tc := range []struct {
		name, text string
		prefixes   []string
		old, new   string
		want       string
	}{
		{"meaning after the array", multi, added, "slash", "slosh", "allowlist edit check failed"},
		{"meaning after the array, removing", withUser, added[:2], "slash", "slosh", "allowlist edit check failed"},
		{"bytes before the array", multi, added, `{"client_ca_file": "/x"}`, `{"client_ca_file":"/x"}`, "changed bytes before the array"},
		{"bytes after the array", multi, added, `"note": `, `"note" : `, "changed bytes after the array"},
		{"bytes after the array, removing", withUser, added[:2], "\n}\n", "\n}\n\n", "changed bytes after the array"},
	} {
		t.Run("catches a faulty edit: "+tc.name, func(t *testing.T) {
			ok, reason := editWith(t, tc.text, tc.prefixes, tc.old, tc.new)
			if ok || !strings.Contains(reason, tc.want) {
				t.Fatalf("want failure with %q, got %v %q", tc.want, ok, reason)
			}
		})
	}

	// The repository's example configs, edited both ways, still load in the
	// services' own config loaders with exactly the expected allowlist.
	for _, example := range []string{"ags", "es"} {
		t.Run("example "+example, func(t *testing.T) {
			text := string(mustReadUserIdentityFile(t, filepath.Join(executionSubstrateRepoRoot, ".examples", "config", example+".json")))
			var doc struct {
				Authorization struct {
					Prefixes []string `json:"allowed_spiffe_path_prefixes"`
				} `json:"authorization"`
			}
			if err := json.Unmarshal([]byte(text), &doc); err != nil {
				t.Fatal(err)
			}
			want := append(append([]string(nil), doc.Authorization.Prefixes...), "user/claude")
			ok, edited := edit(t, text, want)
			if !ok {
				t.Fatalf("edit refused: %s", edited)
			}
			path := filepath.Join(dir, example+".json")
			writeUserIdentityFile(t, path, []byte(edited), 0o600)
			var got []string
			if example == "es" {
				cfg, err := esconfig.Load(path)
				if err != nil {
					t.Fatalf("es/config refuses the edited example: %v", err)
				}
				got = cfg.Authorization.AllowedSPIFFEPathPrefixes
			} else {
				cfg, err := agsconfig.Load(path)
				if err != nil {
					t.Fatalf("ags/config refuses the edited example: %v", err)
				}
				got = cfg.Authorization.AllowedSPIFFEPathPrefixes
			}
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Fatalf("loaded allowlist %v, want %v", got, want)
			}
			ok, back := edit(t, edited, doc.Authorization.Prefixes)
			if !ok || back != text {
				t.Fatalf("removing the entry did not restore the example bytes: %v %q", ok, back)
			}
		})
	}
}

// TestUserIdentityRequestMakesAPrivateKeyAndAMatchingCSR is the caller side
// alone. It needs no OpenSSL 3, so on the Mac it checks LibreSSL.
func TestUserIdentityRequestMakesAPrivateKeyAndAMatchingCSR(t *testing.T) {
	b := newUserIdentityBox(t)
	run := b.mustOK(b.caller("request", "--name", "claude"), "request")
	dir := b.callerDir("claude")
	for _, d := range []string{b.callers, dir} {
		info, err := os.Lstat(d)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
			t.Fatalf("%s: %v %v", d, info.Mode(), err)
		}
	}
	info, err := os.Lstat(filepath.Join(dir, "key.pem"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key.pem mode: %v %v", info.Mode(), err)
	}
	csrPEM := mustReadUserIdentityFile(t, filepath.Join(dir, "request.csr"))
	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature: %v", err)
	}
	if csr.Subject.String() != "CN=claude" || len(csr.Extensions) != 0 || len(csr.URIs) != 0 {
		t.Fatalf("CSR subject %v extensions %v", csr.Subject, csr.Extensions)
	}
	if key, ok := csr.PublicKey.(*rsa.PublicKey); !ok || key.N.BitLen() != 3072 {
		t.Fatal("CSR key is not RSA-3072")
	}
	spki := sha256.Sum256(csr.RawSubjectPublicKeyInfo)
	if run.fact("public_key_sha256") != hex.EncodeToString(spki[:]) {
		t.Fatalf("request reports public key sha256 %q, CSR has %x", run.fact("public_key_sha256"), spki)
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, "request.csr"), filepath.Join(dir, "key.pem"))
	_ = pair
	if err == nil {
		t.Fatal("a CSR loaded as a certificate")
	}
	keyBlock, _ := pem.Decode(mustReadUserIdentityFile(t, filepath.Join(dir, "key.pem")))
	if keyBlock == nil || !strings.HasSuffix(keyBlock.Type, "PRIVATE KEY") {
		t.Fatal("key.pem is not a PEM private key")
	}

	again := b.caller("request", "--name", "claude")
	if again.code != 1 || !strings.Contains(again.message(), "use --renew") {
		t.Fatalf("second request: %s", again)
	}
	renew := b.caller("request", "--name", "claude", "--renew")
	if renew.code != 1 || !strings.Contains(renew.message(), "installed key and certificate") {
		t.Fatalf("renew before install: %s", renew)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	open := b.caller("request", "--name", "other")
	if open.code != 0 {
		t.Fatalf("a second name: %s", open)
	}
	loose := b.caller("check", "--name", "claude")
	if loose.code != 1 || !strings.Contains(loose.message(), "chmod 700") {
		t.Fatalf("check with a group-readable key directory: %s", loose)
	}
}

// TestUserIdentityRenewalPromotesTheNewKey installs a renewal: the pending
// key becomes the key, the old pair moves to previous/, and both old and new
// certificates stay in the registry.
func TestUserIdentityRenewalPromotesTheNewKey(t *testing.T) {
	requireUserIdentityOpenSSL3(t)
	b := newUserIdentityBox(t)
	first := b.mint("claude")
	b.mustOK(b.caller("install", "--name", "claude", "--cert", first), "install")
	dir := b.callerDir("claude")
	oldKey := mustReadUserIdentityFile(t, filepath.Join(dir, "key.pem"))

	b.mustOK(b.caller("request", "--name", "claude", "--renew"), "request --renew")
	if _, err := os.Lstat(filepath.Join(dir, "pending", "key.pem")); err != nil {
		t.Fatal(err)
	}
	csr := filepath.Join(b.root, "renew.csr")
	writeUserIdentityFile(t, csr, mustReadUserIdentityFile(t, filepath.Join(dir, "pending", "request.csr")), 0o644)
	second := filepath.Join(b.root, "renew.crt")
	b.mustOK(b.box("issue", "--name", "claude", "--csr", csr, "--out", second, "--apply"), "second issue")

	// A certificate for another name is refused and changes nothing.
	b.mint("other")
	wrong := b.caller("install", "--name", "claude", "--cert", filepath.Join(b.root, "other.crt"))
	if wrong.code != 1 || !strings.Contains(wrong.message(), "subject alternative names") {
		t.Fatalf("install of another name's certificate: %s", wrong)
	}

	b.mustOK(b.caller("install", "--name", "claude", "--cert", second), "install renewal")
	// The first certificate's key now lives in previous/: installing it again
	// is refused.
	stale := b.caller("install", "--name", "claude", "--cert", first)
	if stale.code != 1 || !strings.Contains(stale.message(), "does not match the local key") {
		t.Fatalf("install of the replaced certificate: %s", stale)
	}
	if !bytes.Equal(mustReadUserIdentityFile(t, filepath.Join(dir, "previous", "key.pem")), oldKey) {
		t.Fatal("the old key did not move to previous/")
	}
	if _, err := os.Lstat(filepath.Join(dir, "pending")); !os.IsNotExist(err) {
		t.Fatal("pending/ still exists after the renewal install")
	}
	check := b.mustOK(b.caller("check", "--name", "claude"), "check")
	if check.fact("certificate_sha256") == "" {
		t.Fatalf("check: %s", check)
	}
	cert := parseUserIdentityPEMCert(t, mustReadUserIdentityFile(t, filepath.Join(dir, "cert.pem")))
	if !bytes.Equal(cert.Raw, parseUserIdentityPEMCert(t, mustReadUserIdentityFile(t, second)).Raw) {
		t.Fatal("cert.pem is not the renewed certificate")
	}
	var registry struct {
		Names map[string]struct {
			Certificates []map[string]any `json:"certificates"`
		} `json:"names"`
	}
	if err := json.Unmarshal(mustReadUserIdentityFile(t, filepath.Join(b.userCADir, "registry.json")), &registry); err != nil {
		t.Fatal(err)
	}
	if n := len(registry.Names["claude"].Certificates); n != 2 {
		t.Fatalf("registry holds %d certificates for claude, want 2", n)
	}
	status := b.box("status")
	if status.code != 0 || status.result() != "ok" {
		t.Fatalf("status: %s", status)
	}
}

// TestUserIdentityStatusFlagsDrift reports an allowlist entry the registry
// does not know and an entry present in one service only.
func TestUserIdentityStatusFlagsDrift(t *testing.T) {
	requireUserIdentityOpenSSL3(t)
	b := newUserIdentityBox(t)
	b.mint("claude")
	b.mustOK(b.box("allow", "--name", "claude", "--apply"), "allow")
	if run := b.box("status"); run.code != 0 || run.result() != "ok" {
		t.Fatalf("status after allow: %s", run)
	}
	b.writeConfig("es", b.esConfig, b.esCA, []string{"operator/local", "service/control-plane", "user/claude", "user/ghost"})
	run := b.box("status")
	if run.code != 1 || run.result() != "attention" {
		t.Fatalf("status with drift: %s", run)
	}
	var details []string
	for _, c := range run.doc["checks"].([]any) {
		check := c.(map[string]any)
		if check["state"] != "ok" {
			details = append(details, fmt.Sprintf("%s: %s", check["name"], check["detail"]))
		}
	}
	got := strings.Join(details, "\n")
	if !strings.Contains(got, "allowlist user/ghost: in ES but not an active registry name") {
		t.Fatalf("status attention:\n%s", got)
	}
	before := b.snapshot()
	b.box("status")
	requireSameUserIdentitySnapshot(t, before, b.snapshot(), "status")
}

// TestUserIdentityDefaultLayoutIsTheBox pins the box values in Layout and
// the wrapper's interpreter flags.
func TestUserIdentityDefaultLayoutIsTheBox(t *testing.T) {
	cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-c", userIdentityDriver, userIdentityModule, "--dump-layout")
	cmd.Dir = t.TempDir()
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	var layout map[string]any
	if err := json.Unmarshal(out, &layout); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"trust_domain":        "execution.internal",
		"path_namespace":      "user",
		"required_euid":       float64(0),
		"box_owner_uid":       float64(0),
		"refused_caller_euid": float64(0),
		"ags_config":          "/etc/execution-substrate/ags.json",
		"es_config":           "/etc/execution-substrate/es.json",
		"ags_client_ca":       "/etc/execution-substrate/tls/external-client-auth-ca.pem",
		"es_client_ca":        "/etc/execution-substrate/es-tls/server-client-ca.pem",
		"user_ca_dir":         "/etc/execution-substrate/user-ca",
		"ags_unit":            "ags.service",
		"es_unit":             "es.service",
		"openssl_bin":         "/usr/bin/openssl",
		"systemctl_bin":       "/usr/bin/systemctl",
		"ca_common_name":      "Execution Substrate Remote Alpha User CA",
		"ca_days":             float64(400),
		"ca_key_bits":         float64(3072),
		"leaf_days":           float64(90),
		"caller_root":         "",
		"caller_key_bits":     float64(3072),
	}
	for key, value := range want {
		if layout[key] != value {
			t.Errorf("Layout.%s = %v, want %v", key, layout[key], value)
		}
	}
	wrapper := string(mustReadUserIdentityFile(t, filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_user_identity.sh")))
	if !strings.Contains(wrapper, `exec /usr/bin/python3 -I -B "${SCRIPT_DIR}/internal/remote_alpha_user_identity.py" "$@"`) {
		t.Fatal("the wrapper no longer runs the module with /usr/bin/python3 -I -B")
	}
	info, err := os.Stat(filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_user_identity.sh"))
	if err != nil || info.Mode().Perm()&0o111 == 0 {
		t.Fatal("the wrapper is not executable")
	}
}

// userIdentityDirDigest names every entry under dir with its mode and, for a
// regular file, its SHA-256, so a refused run can be shown to change nothing.
func userIdentityDirDigest(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		value := info.Mode().String()
		if info.Mode().IsRegular() {
			sum := sha256.Sum256(mustReadUserIdentityFile(t, path))
			value += " " + hex.EncodeToString(sum[:])
		}
		rel, _ := filepath.Rel(dir, path)
		out[rel] = value
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func userIdentityPrivateKey(t *testing.T, path string) *rsa.PrivateKey {
	t.Helper()
	block, _ := pem.Decode(mustReadUserIdentityFile(t, path))
	if block == nil {
		t.Fatalf("%s holds no PEM block", path)
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey
		}
		t.Fatalf("%s is not an RSA key", path)
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return key
}

// TestUserIdentityInstallRefusesCertificatesOffTheProfile signs, with the
// user CA's own key, certificates that each break one rule of the leaf
// profile. install refuses each with its reason and leaves the caller
// directory as it was, and check flags such a certificate once it is in
// place. A certificate on the profile, made the same way, is installed.
func TestUserIdentityInstallRefusesCertificatesOffTheProfile(t *testing.T) {
	requireUserIdentityOpenSSL3(t)
	b := newUserIdentityBox(t)
	b.mint("claude")
	dir := b.callerDir("claude")
	ca := parseUserIdentityPEMCert(t, mustReadUserIdentityFile(t, filepath.Join(b.userCADir, "ca-cert.pem")))
	caKey := userIdentityPrivateKey(t, filepath.Join(b.userCADir, "ca-key.pem"))
	callerPub := userIdentityPrivateKey(t, filepath.Join(dir, "key.pem")).Public()
	id, _ := url.Parse("spiffe://execution.internal/user/claude")
	other, _ := url.Parse("spiffe://execution.internal/user/other")
	serial := int64(1000)
	sign := func(t *testing.T, edit func(*x509.Certificate), pub any) string {
		t.Helper()
		serial++
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: "claude"},
			NotBefore:             time.Now().Add(-time.Minute),
			NotAfter:              time.Now().Add(60 * 24 * time.Hour), // past check's 14-day warning
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			BasicConstraintsValid: true,
			URIs:                  []*url.URL{id},
		}
		if edit != nil {
			edit(template)
		}
		if pub == nil {
			pub = callerPub
		}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, pub, caKey)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(b.root, fmt.Sprintf("profile-%d.crt", serial))
		writeUserIdentityFile(t, path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
		return path
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*x509.Certificate)
		pub  any
		want string
	}{
		{"serverAuth instead of clientAuth", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }, nil,
			"extended key usage is not exactly clientAuth"},
		{"clientAuth and serverAuth", func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		}, nil, "extended key usage is not exactly clientAuth"},
		{"no extended key usage", func(c *x509.Certificate) { c.ExtKeyUsage = nil }, nil, "extended key usage missing"},
		{"CA:TRUE", func(c *x509.Certificate) { c.IsCA = true }, nil, "basic constraints are not CA:FALSE"},
		{"no basic constraints", func(c *x509.Certificate) { c.BasicConstraintsValid = false }, nil, "basic constraints missing or not critical"},
		{"keyEncipherment too", func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageKeyEncipherment }, nil,
			"key usage is not exactly digitalSignature"},
		{"no key usage", func(c *x509.Certificate) { c.KeyUsage = 0 }, nil, "key usage missing or not critical"},
		{"an organization in the subject", func(c *x509.Certificate) { c.Subject.Organization = []string{"x"} }, nil, "subject is"},
		{"another name in the subject", func(c *x509.Certificate) { c.Subject.CommonName = "other" }, nil, "subject is"},
		{"a second URI", func(c *x509.Certificate) { c.URIs = []*url.URL{id, other} }, nil, "subject alternative names are not exactly"},
		{"a DNS name too", func(c *x509.Certificate) { c.DNSNames = []string{"claude.example"} }, nil, "subject alternative names are not exactly"},
		{"no subject alternative name", func(c *x509.Certificate) { c.URIs = nil }, nil, "subject alternative name missing"},
		{"an extra extension", func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, Value: []byte{0x05, 0x00}}}
		}, nil, "unexpected extensions"},
		{"expired", func(c *x509.Certificate) {
			c.NotBefore, c.NotAfter = time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour)
		}, nil, "not valid now"},
		{"not yet valid", func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Hour) }, nil, "not valid now"},
		{"another key", nil, &otherKey.PublicKey, "does not match the local key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := sign(t, tc.edit, tc.pub)
			before := userIdentityDirDigest(t, dir)
			run := b.caller("install", "--name", "claude", "--cert", path)
			if run.code != 1 || run.result() != "refused" || !strings.Contains(run.message(), tc.want) {
				t.Fatalf("install: want refused with %q\n%s", tc.want, run)
			}
			requireSameUserIdentitySnapshot(t, before, userIdentityDirDigest(t, dir), "refused install")
		})
	}

	// check judges the installed certificate by the same profile.
	good := sign(t, nil, nil)
	b.mustOK(b.caller("install", "--name", "claude", "--cert", good), "install of a certificate on the profile")
	b.mustOK(b.caller("check", "--name", "claude"), "check")
	writeUserIdentityFile(t, filepath.Join(dir, "cert.pem"),
		mustReadUserIdentityFile(t, sign(t, func(c *x509.Certificate) { c.IsCA = true }, nil)), 0o644)
	run := b.caller("check", "--name", "claude")
	var detail string
	if run.doc != nil {
		for _, c := range run.doc["checks"].([]any) {
			if check := c.(map[string]any); check["name"] == "certificate" && check["state"] == "fail" {
				detail, _ = check["detail"].(string)
			}
		}
	}
	if run.code != 1 || !strings.Contains(detail, "basic constraints are not CA:FALSE") {
		t.Fatalf("check of a CA:TRUE certificate: %s", run)
	}
}

// TestUserIdentityRefusesACAOffTheProfile replaces the user CA certificate
// with one made from the same key but without the right name constraint,
// and updates the registry to name it, so only the CA profile check can stop
// it. Every box mode that reads the CA refuses, and nothing changes.
func TestUserIdentityRefusesACAOffTheProfile(t *testing.T) {
	requireUserIdentityOpenSSL3(t)
	for _, tc := range []struct {
		name string
		edit func(*x509.Certificate)
		want string
	}{
		{"no name constraints", func(c *x509.Certificate) {}, "name constraints missing or not critical"},
		{"another trust domain", func(c *x509.Certificate) {
			c.PermittedURIDomains = []string{"other.example"}
			c.PermittedDNSDomainsCritical = true
		}, "name constraints do not permit exactly URI:execution.internal"},
		{"pathlen 1", func(c *x509.Certificate) {
			c.MaxPathLen, c.MaxPathLenZero = 1, false
			c.PermittedURIDomains = []string{"execution.internal"}
			c.PermittedDNSDomainsCritical = true
		}, "basic constraints are not CA:TRUE, pathlen:0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newUserIdentityBox(t)
			b.mint("claude")
			certPath := filepath.Join(b.userCADir, "ca-cert.pem")
			old := parseUserIdentityPEMCert(t, mustReadUserIdentityFile(t, certPath))
			caKey := userIdentityPrivateKey(t, filepath.Join(b.userCADir, "ca-key.pem"))
			template := &x509.Certificate{
				SerialNumber:          big.NewInt(4242),
				Subject:               old.Subject,
				NotBefore:             old.NotBefore,
				NotAfter:              old.NotAfter,
				IsCA:                  true,
				BasicConstraintsValid: true,
				MaxPathLenZero:        true,
				KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
				SubjectKeyId:          old.SubjectKeyId,
			}
			tc.edit(template)
			der, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(certPath)
			if err != nil {
				t.Fatal(err)
			}
			writeUserIdentityFile(t, certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), info.Mode().Perm())
			registryPath := filepath.Join(b.userCADir, "registry.json")
			var registry map[string]any
			if err := json.Unmarshal(mustReadUserIdentityFile(t, registryPath), &registry); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(der)
			registry["ca"].(map[string]any)["sha256"] = hex.EncodeToString(sum[:])
			data, err := json.MarshalIndent(registry, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			writeUserIdentityFile(t, registryPath, append(data, '\n'), 0o600)

			before := b.snapshot()
			csr := filepath.Join(b.root, "claude.csr")
			for _, args := range [][]string{
				{"allow", "--name", "claude", "--apply"},
				{"issue", "--name", "claude", "--csr", csr, "--out", filepath.Join(b.root, "again.crt"), "--apply"},
				{"revoke", "--name", "claude", "--apply"},
			} {
				run := b.box(args...)
				if run.code != 1 || run.result() != "refused" || !strings.Contains(run.message(), tc.want) {
					t.Fatalf("%v: want refused with %q\n%s", args, tc.want, run)
				}
			}
			requireSameUserIdentitySnapshot(t, before, b.snapshot(), "refused modes")
			if status := b.box("status"); status.code != 1 || !strings.Contains(status.stdout, tc.want) {
				t.Fatalf("status: want %q\n%s", tc.want, status)
			}
		})
	}
}

// TestUserIdentityCheckNamesEachOutcome serves fixed answers on the box's
// TLS shape and checks how check reads each one. Only ES 200, or AGS 400
// with the JSON code invalid_request (AGS's refusal of the empty publish
// body, which comes after authorization), counts as authorized.
func TestUserIdentityCheckNamesEachOutcome(t *testing.T) {
	requireUserIdentityOpenSSL3(t)
	b := newUserIdentityBox(t)
	serverCA, serverCAKey, serverCAPEM := userIdentityTestCA(t, "Remote Alpha Server CA")
	serverCert := userIdentityServerCert(t, serverCA, serverCAKey)
	serverCAFile := filepath.Join(b.root, "server-ca.pem")
	writeUserIdentityFile(t, serverCAFile, serverCAPEM, 0o644)
	b.mustOK(b.caller("install", "--name", "claude", "--cert", b.mint("claude"), "--server-ca", serverCAFile), "install")

	const plain = "text/plain; charset=utf-8"
	for _, tc := range []struct {
		name, service, contentType, body, want string
		status                                 int
	}{
		{"ES returns its contract", "es", "application/json", `{}`, "authorized", 200},
		{"AGS refuses the empty body", "ags", "application/json", `{"code":"invalid_request","message":"empty body"}`, "authorized", 400},
		{"AGS 400 with another code", "ags", "application/json", `{"code":"payload_too_large"}`, "unexpected", 400},
		{"AGS 400 invalid_request not sent as JSON", "ags", plain, `{"code":"invalid_request"}`, "unexpected", 400},
		{"AGS 400 with no body", "ags", "", "", "unexpected", 400},
		{"ES 400 invalid_request", "es", "application/json", `{"code":"invalid_request"}`, "unexpected", 400},
		{"AGS 200", "ags", "application/json", `{}`, "unexpected", 200},
		{"not authenticated", "es", plain, "Unauthorized\n", "not_authenticated", 401},
		{"not on the allowlist", "ags", plain, "Caller not authorized for this operation\n", "not_allowed", 403},
		{"another refusal", "es", plain, "Forbidden\n", "refused", 403},
		{"server error", "es", plain, "internal error\n", "unexpected", 500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wantMethod, wantPath := http.MethodGet, "/v1/executions:contract"
			if tc.service == "ags" {
				wantMethod, wantPath = http.MethodPost, "/v1/artifacts:publish"
			}
			var requests atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				body, _ := io.ReadAll(r.Body)
				if r.Method != wantMethod || r.URL.Path != wantPath || len(body) != 0 || len(r.TLS.PeerCertificates) != 1 {
					t.Errorf("check sent %s %s with %d body bytes and %d client certificates", r.Method, r.URL.Path, len(body), len(r.TLS.PeerCertificates))
				}
				if tc.contentType != "" {
					w.Header().Set("Content-Type", tc.contentType)
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAnyClientCert}
			server.StartTLS()
			defer server.Close()

			run := b.checkOutcome("claude", tc.service, server.URL)
			wantCode := 1
			if tc.want == "authorized" {
				wantCode = 0
			}
			var status float64
			if facts, ok := run.doc["facts"].(map[string]any); ok {
				status, _ = facts["http_status"].(float64)
			}
			if run.code != wantCode || run.fact("outcome") != tc.want || int(status) != tc.status {
				t.Fatalf("want outcome %s, exit %d, HTTP %d\n%s", tc.want, wantCode, tc.status, run)
			}
			if n := requests.Load(); n != 1 {
				t.Fatalf("check made %d requests, want 1", n)
			}
		})
	}
}

// TestUserIdentityReportNeverCarriesAPrivateKey hands the report renderer a
// report that holds private key text. As text and as JSON it comes out as
// the suppression notice instead. No mode puts a key in a report; this is
// the last guard behind that.
func TestUserIdentityReportNeverCarriesAPrivateKey(t *testing.T) {
	cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-c", userIdentityDriver, userIdentityModule, "--render-with-key")
	cmd.Dir = t.TempDir()
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("PRIVATE KEY")) {
		t.Fatalf("a rendered report carries private key text:\n%s", out)
	}
	var rendered []string
	if err := json.Unmarshal(out, &rendered); err != nil || len(rendered) != 2 {
		t.Fatalf("driver output %q: %v", out, err)
	}
	for i, text := range rendered {
		var doc map[string]any
		if err := json.Unmarshal([]byte(text), &doc); err != nil {
			t.Fatalf("rendering %d is not the JSON suppression notice: %v\n%s", i, err, text)
		}
		if doc["result"] != "failed" || doc["message"] != "report suppressed: it contained private key text" || doc["mode"] != "status" {
			t.Fatalf("rendering %d: %v", i, doc)
		}
		if _, ok := doc["facts"]; ok {
			t.Fatalf("rendering %d kept the facts: %v", i, doc)
		}
	}
}

// The fake openssl runs /usr/bin/openssl, except that when openssl.tamper
// sits next to it, it changes one thing in the signing call (x509 -req), so
// the certificate issue gets back is not the one it asked for.
const userIdentityTamperingOpenSSL = `#!/usr/bin/python3
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
args = sys.argv[1:]
marker = os.path.join(HERE, "openssl.tamper")
if args[:2] == ["x509", "-req"] and os.path.exists(marker):
    tamper = open(marker).read().strip()
    if tamper == "days":
        args[args.index("-days") + 1] = "500"
    elif tamper == "serial":
        args[args.index("-set_serial") + 1] = "0x1234"
    elif tamper == "digest":
        args[args.index("-sha256")] = "-sha384"
    elif tamper == "server-auth":
        i = args.index("-extfile") + 1
        text = open(args[i]).read().replace("extendedKeyUsage = clientAuth", "extendedKeyUsage = clientAuth, serverAuth")
        args[i] = os.path.join(HERE, "tampered.cnf")
        open(args[i], "w").write(text)
    else:
        sys.exit("unknown tamper " + tamper)
os.execv("/usr/bin/openssl", ["/usr/bin/openssl"] + args)
`

// TestUserIdentityIssueChecksWhatOpenSSLSigned makes openssl sign something
// other than what issue asked for, one change at a time. issue reads the
// result back, refuses to record it, and leaves every box file as it was.
// The same fake openssl with no change gives a certificate issue records.
func TestUserIdentityIssueChecksWhatOpenSSLSigned(t *testing.T) {
	requireUserIdentityOpenSSL3(t)
	b := newUserIdentityBox(t)
	b.mustOK(b.box("init-ca", "--apply"), "init-ca")
	b.mustOK(b.caller("request", "--name", "claude"), "request")
	csr := filepath.Join(b.root, "claude.csr")
	writeUserIdentityFile(t, csr, mustReadUserIdentityFile(t, filepath.Join(b.callerDir("claude"), "request.csr")), 0o644)
	fake := filepath.Join(b.root, "fake-openssl")
	if err := os.Mkdir(fake, 0o755); err != nil {
		t.Fatal(err)
	}
	writeUserIdentityFile(t, filepath.Join(fake, "openssl"), []byte(userIdentityTamperingOpenSSL), 0o755)
	fields := b.layoutFields()
	fields["openssl_bin"] = filepath.Join(fake, "openssl")
	b.writeLayout(fields)
	out := filepath.Join(b.root, "claude.crt")

	for _, tc := range []struct{ tamper, want string }{
		{"days", "outlasts the CA"},
		{"days", "validity is not the expected window"},
		{"serial", "serial differs from the one requested"},
		{"digest", "not signed with sha256WithRSAEncryption"},
		{"server-auth", "extended key usage is not exactly clientAuth"},
	} {
		t.Run(tc.tamper+": "+tc.want, func(t *testing.T) {
			writeUserIdentityFile(t, filepath.Join(fake, "openssl.tamper"), []byte(tc.tamper), 0o644)
			before := b.snapshot()
			run := b.box("issue", "--name", "claude", "--csr", csr, "--out", out, "--apply")
			if run.code != 1 || run.result() != "failed" ||
				!strings.Contains(run.message(), "signed certificate check failed, nothing recorded") || !strings.Contains(run.message(), tc.want) {
				t.Fatalf("issue with openssl changing %s: want failed with %q\n%s", tc.tamper, tc.want, run)
			}
			requireSameUserIdentitySnapshot(t, before, b.snapshot(), "issue of a tampered certificate")
			if _, err := os.Lstat(out); !os.IsNotExist(err) {
				t.Fatalf("issue wrote %s: %v", out, err)
			}
		})
	}

	if err := os.Remove(filepath.Join(fake, "openssl.tamper")); err != nil {
		t.Fatal(err)
	}
	b.mustOK(b.box("issue", "--name", "claude", "--csr", csr, "--out", out, "--apply"), "issue through the fake openssl with no change")
	b.mustOK(b.caller("install", "--name", "claude", "--cert", out), "install")
}

// TestUserIdentityDocsTrackWorkloadGrants keeps the user identity docs in
// step with network grants. While ES has no admission_policy.workload_grants,
// the docs section and the runbook must say that grants are not in this
// build. Once ES has them, this fails until both say how the box owner grants
// a user identity network access, allow names that step, and the sentence
// goes.
func TestUserIdentityDocsTrackWorkloadGrants(t *testing.T) {
	const notYet = "Network grants are not in this build"
	grants := false
	policy := reflect.TypeOf(esconfig.AdmissionPolicyConfig{})
	for i := 0; i < policy.NumField(); i++ {
		if name, _, _ := strings.Cut(policy.Field(i).Tag.Get("json"), ","); name == "workload_grants" {
			grants = true
		}
	}
	for _, rel := range []string{
		".docs/system_overview/remote_supported_host_alpha.md",
		".runbooks/system/Governed Execution ES Remote Alpha User Identity.md",
	} {
		says := strings.Contains(string(mustReadUserIdentityFile(t, filepath.Join(executionSubstrateRepoRoot, filepath.FromSlash(rel)))), notYet)
		switch {
		case grants && says:
			t.Errorf("%s still says %q, but es/config now has admission_policy.workload_grants: say how the box owner "+
				"grants a user/<name> caller network access, make allow name that step without adding a grant, and drop the sentence", rel, notYet)
		case !grants && !says:
			t.Errorf("%s no longer says %q, but es/config has no admission_policy.workload_grants", rel, notYet)
		}
	}
}
