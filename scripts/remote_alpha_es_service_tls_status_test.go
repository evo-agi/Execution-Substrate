package scripts_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

func remoteAlphaESServiceTLSStatusCollectorPath() string {
	return filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_es_tls_status.py")
}

// The standard local boundary of the collector's process cleanup, as Python
// lines for a fixture that has loaded the collector as "module". The lines
// import what they use under names of their own, so they need nothing else
// of the fixture, and in particular no import of os.
//
// The cleanup reaches the target's process table through three functions:
// scan_group_members lists /proc, signal_same_group_members uses pidfd_open
// and pidfd_send_signal, and read_proc_identity reads /proc/<pid>/stat and
// confirms absence with pidfd_open. A local fixture replaces all three
// together with the probe that would have proved them. Replacing only some of
// them leaves the rest reading the real host: beside invented identities
// where /proc exists, and without an end where neither /proc nor pidfd_open
// exists, because a listed process can then never be confirmed absent.
//
// With the stand-in scan, the only caller of read_proc_identity is the
// absence check after the reap, where the true answer is that no listed
// process is still present.
//
// Two further lines make a broken fixture fail instead of misleading or
// hanging. The two readers below read_proc_identity are target-only and
// unreachable here; a fixture that reaches one ends itself with status 97. A
// fixture that is still running after LOCAL_FIXTURE_BOUND seconds, 120 unless
// the fixture set the name before these lines, prints the stack of every
// thread and ends itself with status 98. The bound uses the real-time timer
// and SIGALRM, which the collector does not use, and no thread.
//
// TestRemoteAlphaESServiceTLSStatusLocalBoundary... hold these properties.
const remoteAlphaESStatusLocalProcessBoundary = `# Local generated fixtures inject the target-only process capability boundary.
import faulthandler as _faulthandler,os as _os,signal as _signal
module.validate_process_capability=lambda: None
module.PROCESS_CAPABILITY_READY=True
module.scan_group_members=lambda pgid: [(pgid,0)]
module.signal_same_group_members=lambda pgid,signum: _os.kill(pgid,signum)
module.read_proc_identity=lambda pid: None
def _target_only(name):
    def reached(*_args,**_kwargs):
        _os.write(2,("local fixture reached the target-only host path: "+name+"\n").encode());_os._exit(97)
    return reached
module.read_proc_stat_identity=_target_only("read_proc_stat_identity")
module.process_absent=_target_only("process_absent")
def _fixture_overdue(_signum,_frame):
    _os.write(2,b"local fixture exceeded its bound\n");_faulthandler.dump_traceback(all_threads=True);_os._exit(98)
_signal.signal(_signal.SIGALRM,_fixture_overdue)
_signal.setitimer(_signal.ITIMER_REAL,globals().get("LOCAL_FIXTURE_BOUND",120.0))
`

// This helper runs only a non-main parser fixture in a local Python child.
// It never invokes the collector entry point or a real OpenSSL child.
func runRemoteAlphaESServiceTLSStatusX509TextFixture(t *testing.T, probe string, stdin []byte, paths ...string) map[string]bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	args := append([]string{"-I", "-B", "-c", probe, remoteAlphaESServiceTLSStatusCollectorPath()}, paths...)
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", args...)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	cmd.Stdin = bytes.NewReader(stdin)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("local x509 text fixture timed out: %v", ctx.Err())
	}
	if err != nil {
		t.Fatalf("local x509 text fixture: %v\n%s", err, output)
	}
	var result map[string]bool
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("local x509 text fixture JSON: %v\n%s", err, output)
	}
	return result
}

func TestRemoteAlphaESServiceTLSStatusCollectorSourceBoundary(t *testing.T) {
	source := mustRead(t, remoteAlphaESServiceTLSStatusCollectorPath())
	assertContainsAll(t, "dedicated status collector", source,
		"artifact-registry", "execution-governance",
		"es-service-tls-status-summary.json", "es-governance-tls-status-summary.json",
		"es-service-tls-status-summary.v1", "es-governance-tls-status-summary.v1",
		"finalized", "os.replace", "os._exit(0)",
	)
	assertContainsNone(t, "dedicated status collector forbidden renewal path", source,
		"remote_alpha_es_service_tls_renew", "--execute-renew", "systemctl", "curl",
		"private-backups", "shell=True", "subprocess.run(", "tempfile", "mkstemp", "/var/tmp/",
	)
}

func TestRemoteAlphaESServiceTLSStatusRejectsUnsupportedCLI(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"--scope", "unknown"},
		{"--scope", "artifact-registry", "--execute-renew"},
		{"--scope", "execution-governance", "--summary-path", "/tmp/x"},
		{"--scope", "artifact-registry", "--config-path", "/tmp/x"},
	} {
		cmd := exec.Command("/usr/bin/python3", append([]string{"-I", "-B", remoteAlphaESServiceTLSStatusCollectorPath()}, args...)...)
		cmd.Dir = executionSubstrateRepoRoot
		cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
		output, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("unsupported args %q unexpectedly succeeded: %s", args, output)
		}
		if strings.Contains(string(output), "/tmp/x") {
			t.Fatalf("unsupported args echoed override path: %s", output)
		}
	}
}

func TestRemoteAlphaESServiceTLSStatusInputFIFORefusal(t *testing.T) {
	const probe = `
import importlib.util,json,os,pathlib,stat,sys
source,path,kind,previous=sys.argv[1:]
spec=importlib.util.spec_from_file_location("status_fifo",source)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
` + remoteAlphaESStatusLocalProcessBoundary + `module.check_extended=lambda _fd: None
module.check_input_ancestor=lambda info: None if stat.S_ISDIR(info.st_mode) else (_ for _ in ()).throw(module.Incomplete("ancestor"))
module.run_fixed=lambda *_a,**_k: (_ for _ in ()).throw(AssertionError("child started for FIFO"))
prior=pathlib.Path(previous).read_bytes()
try:
    if kind in ("required_config","optional_config"):
        module.CONFIG["fixture"]=path
        module.read_config("fixture",kind=="required_config")
    elif kind=="key":
        module.key_pair("fixture",{"public_key_sha256":"a"*64},path)
    else:
        module.cert_role(("fixture",path,"ca" if kind=="anchor" else "server",None,None))
    refused=False
except module.Incomplete:
    refused=True
print(json.dumps({"refused":refused,"previous_unchanged":pathlib.Path(previous).read_bytes()==prior,
                  "no_lock_or_pipe":not list(pathlib.Path(previous).parent.glob("*.lock")) and not list(pathlib.Path(previous).parent.glob("*.pipe"))}))
`
	for _, scope := range []string{"artifact-registry", "execution-governance"} {
		t.Run(scope, func(t *testing.T) {
			var f *remoteAlphaESServiceTLSFixture
			if scope == "artifact-registry" {
				f = setupRemoteAlphaESServiceTLSFixture(t, false)
			} else {
				f = setupRemoteAlphaESGovernanceTLSFixture(t, false)
			}
			base := f.arsTLSDir
			required, optional, cert, key := f.arsConfig, f.egsConfig, "ars-server-cert.pem", "ars-server-key.pem"
			if scope == "execution-governance" {
				base = f.egsTLSDir
				required, optional, cert, key = f.egsConfig, f.arsConfig, "egs-server-cert.pem", "egs-server-key.pem"
			}
			previous := filepath.Join(f.root, "previous-generation.json")
			writeFile(t, previous, []byte("previous generation\n"), 0o600)
			for _, tc := range []struct{ kind, path string }{
				{"required_config", required}, {"optional_config", optional},
				{"certificate", filepath.Join(base, cert)}, {"key", filepath.Join(base, key)},
				{"anchor", filepath.Join(base, "runtime-ca.pem")},
			} {
				t.Run(tc.kind, func(t *testing.T) {
					original, err := os.ReadFile(tc.path)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.Remove(tc.path); err != nil {
						t.Fatal(err)
					}
					if err := syscall.Mkfifo(tc.path, 0o600); err != nil {
						t.Fatal(err)
					}
					defer func() {
						_ = os.Remove(tc.path)
						_ = os.WriteFile(tc.path, original, 0o600)
					}()
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					cmd := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-B", "-c", probe,
						remoteAlphaESServiceTLSStatusCollectorPath(), tc.path, tc.kind, previous)
					cmd.Dir = executionSubstrateRepoRoot
					cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
					output, err := cmd.CombinedOutput()
					if ctx.Err() != nil {
						t.Fatalf("FIFO leaf blocked without a writer: %v", ctx.Err())
					}
					if err != nil {
						t.Fatalf("FIFO probe: %v\n%s", err, output)
					}
					var result map[string]bool
					if err := json.Unmarshal(output, &result); err != nil {
						t.Fatalf("FIFO result: %v\n%s", err, output)
					}
					for label, ok := range result {
						if !ok {
							t.Errorf("%s false", label)
						}
					}
				})
			}
		})
	}
}

func TestRemoteAlphaESServiceTLSStatusLeafSwapToFIFORefusal(t *testing.T) {
	f := setupRemoteAlphaESServiceTLSFixture(t, false)
	const probe = `
import importlib.util,json,os,pathlib,stat,sys
source,path=sys.argv[1:]
spec=importlib.util.spec_from_file_location("status_fifo_swap",source)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
` + remoteAlphaESStatusLocalProcessBoundary + `module.check_extended=lambda _fd: None
module.check_input_ancestor=lambda info: None if stat.S_ISDIR(info.st_mode) else (_ for _ in ()).throw(module.Incomplete("ancestor"))
path=pathlib.Path(path);original=path.read_bytes();real_open=os.open;swapped=[False]
def swap_before_open(name,flags,*args,**kwargs):
    if name==path.name and flags & os.O_NONBLOCK and not swapped[0]:
        swapped[0]=True;path.unlink();os.mkfifo(path,0o600)
    return real_open(name,flags,*args,**kwargs)
module.os.open=swap_before_open
try:
    try: module.open_fixed_regular(str(path),module.MAX_INPUT);refused=False
    except module.Incomplete: refused=True
finally:
    module.os.open=real_open
    if path.exists(): path.unlink()
    path.write_bytes(original)
print(json.dumps({"swapped":swapped[0],"refused":refused,"restored":path.read_bytes()==original}))
`
	for _, path := range []string{f.arsConfig, filepath.Join(f.arsTLSDir, "runtime-ca.pem")} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-B", "-c", probe,
				remoteAlphaESServiceTLSStatusCollectorPath(), path)
			cmd.Dir = executionSubstrateRepoRoot
			cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
			output, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("swapped FIFO blocked without writer: %v", ctx.Err())
			}
			if err != nil {
				t.Fatalf("swapped FIFO probe: %v\n%s", err, output)
			}
			var result map[string]bool
			if err := json.Unmarshal(output, &result); err != nil {
				t.Fatalf("swapped FIFO result: %v\n%s", err, output)
			}
			for label, ok := range result {
				if !ok {
					t.Errorf("%s false", label)
				}
			}
		})
	}
}

// The generated fixture redirects only source-controlled fixed paths inside a
// private test tree. The production CLI has no fixture or path override.
func runRemoteAlphaESTLSFixture(t *testing.T, f *remoteAlphaESServiceTLSFixture, scope string, previous ...string) map[string]any {
	t.Helper()
	const harness = `
import datetime, importlib.util, json, os, pathlib, re, stat, sys
source, root, scope, previous = sys.argv[1:]
spec = importlib.util.spec_from_file_location("status_fixture", source)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
` + remoteAlphaESStatusLocalProcessBoundary + `root = pathlib.Path(root).resolve()
fixed = {
    "/etc/execution-substrate/ars-tls": str(root / "etc/execution-substrate/ars-tls"),
    "/etc/execution-substrate/egs-tls": str(root / "etc/execution-substrate/egs-tls"),
    "/etc/execution-substrate/es-tls": str(root / "etc/execution-substrate/es-tls"),
    "/etc/execution-substrate/tls": str(root / "etc/execution-substrate/tls"),
    "/etc/execution-substrate/": str(root / "etc/execution-substrate") + "/",
}
def relocate(value):
    if isinstance(value, str):
        for old, new in fixed.items():
            if value.startswith(old): return new + value[len(old):]
        return value
    if isinstance(value, tuple): return tuple(relocate(item) for item in value)
    if isinstance(value, dict): return {key: relocate(item) for key, item in value.items()}
    return value
module.SCOPES = relocate(module.SCOPES)
module.CONFIG = relocate(module.CONFIG)
module.check_extended = lambda _fd: None  # generated local fixture has no fd-xattr API
def fixture_ancestor(info):
    if not stat.S_ISDIR(info.st_mode): raise module.Incomplete("fixture_ancestor_unsafe")
    if info.st_uid not in (0, os.getuid()): raise module.Incomplete("fixture_ancestor_owner")
module.check_input_ancestor = fixture_ancestor
original_run_fixed = module.run_fixed
expected_ca = (root / "etc/execution-substrate" / ("ars-tls" if scope == "artifact-registry" else "egs-tls") / "runtime-ca.pem").read_bytes()
def fixture_run_fixed(argv, input_bytes=None, anchor_bytes=None):
    if len(argv) > 2 and argv[1] == "verify":
        expected = [module.OPENSSL, "verify", "-trusted", module.TRUST_FD_OPERAND, "-purpose"]
        assert list(argv[:5]) == expected and argv[-1] == "/dev/stdin"
        assert argv[5] in ("sslclient", "sslserver")
        assert (list(argv[6:-1]) == [] if argv[5] == "sslclient" else
                list(argv[6:-1]) == ["-verify_hostname", "server.artifact-registry.internal" if scope == "artifact-registry" else "server.execution-governance.internal"])
        assert isinstance(input_bytes, bytes) and isinstance(anchor_bytes, bytes)
        code, metadata, error = original_run_fixed((module.OPENSSL,"x509","-in","/dev/stdin","-noout","-subject","-issuer","-dates","-nameopt","RFC2253"), input_bytes)
        assert code == 0 and not error
        fields = metadata.decode().splitlines()
        subject = fields[0].split("CN=", 1)[1]
        before = module.parse_openssl_time(fields[2].split("=", 1)[1])
        after = module.parse_openssl_time(fields[3].split("=", 1)[1])
        now = datetime.datetime.now(datetime.timezone.utc)
        before_dt = datetime.datetime.strptime(before, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
        after_dt = datetime.datetime.strptime(after, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
        if now > after_dt:
            root_error = "CN = Remote Alpha Internal Runtime Root CA\nerror 10 at 1 depth lookup:certificate has expired\n"
            leaf_error = "CN = " + subject + "\nerror 10 at 0 depth lookup:certificate has expired\n"
            return 2, ((root_error * 3) + leaf_error + "/dev/stdin: verification failed: 10 (certificate has expired)\n").encode(), b""
        if now < before_dt:
            return 2, ("CN = " + subject + "\nerror 9 at 0 depth lookup:certificate is not yet valid\n/dev/stdin: verification failed: 9 (certificate is not yet valid)\n").encode(), b""
        if anchor_bytes != expected_ca:
            return 2, ("CN = " + subject + "\nerror 20 at 0 depth lookup:unable to get local issuer certificate\n/dev/stdin: verification failed: 20 (unable to get local issuer certificate)\n").encode(), b""
        if argv[5] == "sslserver":
            code, text, error = original_run_fixed((module.OPENSSL,"x509","-in","/dev/stdin","-noout","-text"), input_bytes)
            assert code == 0 and not error
            san = re.search(rb"X509v3 Subject Alternative Name:\s*\n\s*([^\n]+)", text)
            if san is None or argv[7].encode() not in san.group(1):
                return 2, b"", ("CN=" + subject + "\nerror 62 at 0 depth lookup: hostname mismatch\nerror /dev/stdin: verification failed\n").encode()
        return 0, b"/dev/stdin: OK\n", b""
    return original_run_fixed(argv, input_bytes, anchor_bytes)
module.run_fixed = fixture_run_fixed
if previous:
    original_token_hex=module.secrets.token_hex
    sequence=iter((previous,"f"*32))
    module.secrets.token_hex=lambda n: next(sequence) if n==16 else original_token_hex(n)
record = module.collect(scope, previous or None)
print(module.encode_document(record, scope).decode(), end="")
`
	prior := ""
	if len(previous) > 0 {
		prior = previous[0]
	}
	cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-c", harness,
		remoteAlphaESServiceTLSStatusCollectorPath(), f.root, scope, prior)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("status fixture %s failed: %v\n%s", scope, err, output)
	}
	var record map[string]any
	if err := json.Unmarshal(output, &record); err != nil {
		t.Fatalf("status fixture JSON: %v\n%s", err, output)
	}
	return record
}

func statusFixtureCodes(t *testing.T, record map[string]any) []string {
	t.Helper()
	items, ok := record["blockers"].([]any)
	if !ok {
		t.Fatalf("missing blocker array: %#v", record["blockers"])
	}
	codes := make([]string, 0, len(items))
	for _, item := range items {
		code, ok := item.(string)
		if !ok {
			t.Fatalf("non-string blocker: %#v", item)
		}
		codes = append(codes, code)
	}
	return codes
}

func TestRemoteAlphaESServiceTLSStatusCollectionArtifactRegistry(t *testing.T) {
	f := setupRemoteAlphaESServiceTLSFixture(t, false)
	record := runRemoteAlphaESTLSFixture(t, f, "artifact-registry")
	assertJSONPathEquals(t, record, "result.status", "pass")
	assertJSONPathEquals(t, record, "result.ok", true)
	assertJSONPathEquals(t, record, "finalized", true)
	assertJSONPathEquals(t, record, "scope", "artifact-registry")
	assertJSONPathEquals(t, record, "route", "es-service-tls-status")
	assertJSONPathEquals(t, record, "schema_version", "execution-substrate.remote-alpha.es-service-tls-status-summary.v1")
	assertJSONPathEquals(t, record, "collector_contract", "execution-substrate.remote-alpha.es-tls-status-collector/v1")
	if got := len(record["certificates"].([]any)); got != 6 {
		t.Fatalf("P0s cert role count %d", got)
	}
	if got := len(record["key_pairs"].([]any)); got != 3 {
		t.Fatalf("P0s key pair count %d", got)
	}
	if got := len(record["verification"].([]any)); got != 4 {
		t.Fatalf("P0s chain check count %d", got)
	}
	if len(statusFixtureCodes(t, record)) != 0 {
		t.Fatalf("valid P0s fixture blocked: %v", statusFixtureCodes(t, record))
	}
	roles := []string{}
	for _, item := range record["certificates"].([]any) {
		roles = append(roles, item.(map[string]any)["label"].(string))
	}
	wantRoles := []string{"ars_trusted_runtime_client_ca", "ars_server", "ags_artifact_registry_client", "ags_artifact_registry_root_ca", "es_artifact_registry_client", "es_artifact_registry_root_ca"}
	if !slices.Equal(roles, wantRoles) {
		t.Fatalf("P0s role labels %v", roles)
	}
	wantPaths := []string{filepath.Join(f.arsTLSDir, "runtime-ca.pem"), filepath.Join(f.arsTLSDir, "ars-server-cert.pem"), filepath.Join(f.agsTLSDir, "ags-client-cert.pem"), filepath.Join(f.agsTLSDir, "runtime-ca.pem"), filepath.Join(f.esTLSDir, "artifact-registry-client-cert.pem"), filepath.Join(f.esTLSDir, "artifact-registry-root-ca.pem")}
	for i, item := range record["certificates"].([]any) {
		if got := item.(map[string]any)["path"]; got != wantPaths[i] {
			t.Fatalf("P0s role path %d = %v, want %s", i, got, wantPaths[i])
		}
	}
	for _, item := range record["verification"].([]any) {
		check := item.(map[string]any)
		if check["purpose"] == "sslserver" && check["hostname"] != "server.artifact-registry.internal" {
			t.Fatalf("P0s server verification hostname %v", check["hostname"])
		}
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	assertContainsNone(t, "bounded status metadata", string(encoded), "-----BEGIN", "PRIVATE KEY", "BEGIN CERTIFICATE", "secret payload")
}

func TestRemoteAlphaESServiceTLSStatusCollectionExecutionGovernance(t *testing.T) {
	f := setupRemoteAlphaESGovernanceTLSFixture(t, false)
	record := runRemoteAlphaESTLSFixture(t, f, "execution-governance")
	assertJSONPathEquals(t, record, "result.status", "pass")
	assertJSONPathEquals(t, record, "result.ok", true)
	assertJSONPathEquals(t, record, "scope", "execution-governance")
	assertJSONPathEquals(t, record, "route", "es-governance-tls-status")
	assertJSONPathEquals(t, record, "schema_version", "execution-substrate.remote-alpha.es-governance-tls-status-summary.v1")
	if got := len(record["certificates"].([]any)); got != 4 {
		t.Fatalf("P0t cert role count %d", got)
	}
	if got := len(record["key_pairs"].([]any)); got != 2 {
		t.Fatalf("P0t key pair count %d", got)
	}
	if got := len(record["verification"].([]any)); got != 2 {
		t.Fatalf("P0t chain check count %d", got)
	}
	if len(statusFixtureCodes(t, record)) != 0 {
		t.Fatalf("valid P0t fixture blocked: %v", statusFixtureCodes(t, record))
	}
	roles := []string{}
	for _, item := range record["certificates"].([]any) {
		roles = append(roles, item.(map[string]any)["label"].(string))
	}
	wantRoles := []string{"egs_trusted_runtime_client_ca", "egs_server", "es_execution_governance_client", "es_execution_governance_root_ca"}
	if !slices.Equal(roles, wantRoles) {
		t.Fatalf("P0t role labels %v", roles)
	}
	wantPaths := []string{filepath.Join(f.egsTLSDir, "runtime-ca.pem"), filepath.Join(f.egsTLSDir, "egs-server-cert.pem"), filepath.Join(f.esTLSDir, "execution-governance-client-cert.pem"), filepath.Join(f.esTLSDir, "execution-governance-root-ca.pem")}
	for i, item := range record["certificates"].([]any) {
		if got := item.(map[string]any)["path"]; got != wantPaths[i] {
			t.Fatalf("P0t role path %d = %v, want %s", i, got, wantPaths[i])
		}
	}
	for _, item := range record["verification"].([]any) {
		check := item.(map[string]any)
		if check["purpose"] == "sslserver" && check["hostname"] != "server.execution-governance.internal" {
			t.Fatalf("P0t server verification hostname %v", check["hostname"])
		}
	}
}

func TestRemoteAlphaESServiceTLSStatusCollectionTypedFailures(t *testing.T) {
	for _, tc := range []struct {
		name        string
		scope       string
		makeFixture func(*testing.T) *remoteAlphaESServiceTLSFixture
		mutate      func(*testing.T, *remoteAlphaESServiceTLSFixture)
		code        string
	}{
		{"expired", "artifact-registry", func(t *testing.T) *remoteAlphaESServiceTLSFixture {
			return setupRemoteAlphaESServiceTLSFixture(t, true)
		}, nil, "certificate_expired"},
		{"missing cert", "artifact-registry", func(t *testing.T) *remoteAlphaESServiceTLSFixture {
			return setupRemoteAlphaESServiceTLSFixture(t, false)
		}, func(t *testing.T, f *remoteAlphaESServiceTLSFixture) {
			if err := os.Remove(filepath.Join(f.arsTLSDir, "ars-server-cert.pem")); err != nil {
				t.Fatal(err)
			}
		}, "certificate_missing"},
		{"malformed cert", "artifact-registry", func(t *testing.T) *remoteAlphaESServiceTLSFixture {
			return setupRemoteAlphaESServiceTLSFixture(t, false)
		}, func(t *testing.T, f *remoteAlphaESServiceTLSFixture) {
			writeFile(t, filepath.Join(f.arsTLSDir, "ars-server-cert.pem"), []byte("bad cert"), 0o640)
		}, "certificate_malformed"},
		{"missing key", "artifact-registry", func(t *testing.T) *remoteAlphaESServiceTLSFixture {
			return setupRemoteAlphaESServiceTLSFixture(t, false)
		}, func(t *testing.T, f *remoteAlphaESServiceTLSFixture) {
			if err := os.Remove(filepath.Join(f.arsTLSDir, "ars-server-key.pem")); err != nil {
				t.Fatal(err)
			}
		}, "key_missing"},
		{"key mismatch", "artifact-registry", func(t *testing.T) *remoteAlphaESServiceTLSFixture {
			return setupRemoteAlphaESServiceTLSFixture(t, false)
		}, func(t *testing.T, f *remoteAlphaESServiceTLSFixture) {
			data, err := os.ReadFile(filepath.Join(f.agsTLSDir, "ags-client-key.pem"))
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(f.arsTLSDir, "ars-server-key.pem"), data, 0o640)
		}, "key_mismatch"},
		{"malformed config", "artifact-registry", func(t *testing.T) *remoteAlphaESServiceTLSFixture {
			return setupRemoteAlphaESServiceTLSFixture(t, false)
		}, func(t *testing.T, f *remoteAlphaESServiceTLSFixture) { writeFile(t, f.arsConfig, []byte("{"), 0o600) }, "config_malformed"},
		{"topology mismatch", "artifact-registry", func(t *testing.T) *remoteAlphaESServiceTLSFixture {
			return setupRemoteAlphaESServiceTLSFixture(t, false)
		}, func(t *testing.T, f *remoteAlphaESServiceTLSFixture) {
			writeFile(t, f.arsConfig, []byte(`{"tls":{"cert_file":"/wrong"}}`), 0o600)
		}, "topology_mismatch"},
		{"AGS exclusion", "execution-governance", func(t *testing.T) *remoteAlphaESServiceTLSFixture {
			return setupRemoteAlphaESGovernanceTLSFixture(t, false)
		}, func(t *testing.T, f *remoteAlphaESServiceTLSFixture) {
			writeFile(t, f.agsConfig, []byte(`{"dependencies":{"execution_governance":{}}}`), 0o600)
		}, "ags_scope_present"},
		{"wrong CA", "artifact-registry", func(t *testing.T) *remoteAlphaESServiceTLSFixture {
			return setupRemoteAlphaESServiceTLSFixture(t, false)
		}, func(t *testing.T, f *remoteAlphaESServiceTLSFixture) {
			now := time.Now().UTC()
			ca, _, _ := remoteAlphaGenerateCA(t, now.Add(-time.Hour), now.Add(24*time.Hour))
			writeFile(t, filepath.Join(f.agsTLSDir, "runtime-ca.pem"), ca, 0o640)
		}, "chain_failed"},
		{"hostname mismatch", "artifact-registry", func(t *testing.T) *remoteAlphaESServiceTLSFixture {
			return setupRemoteAlphaESServiceTLSFixture(t, false)
		}, func(t *testing.T, f *remoteAlphaESServiceTLSFixture) {
			now := time.Now().UTC()
			ca, key, _ := remoteAlphaGenerateCA(t, now.Add(-time.Hour), now.Add(24*time.Hour))
			cert, private := remoteAlphaGenerateLeaf(t, ca, key, "wrong.internal", x509.ExtKeyUsageServerAuth, now.Add(-time.Hour), now.Add(24*time.Hour))
			writeFile(t, filepath.Join(f.arsTLSDir, "runtime-ca.pem"), ca, 0o640)
			writeFile(t, filepath.Join(f.agsTLSDir, "runtime-ca.pem"), ca, 0o640)
			writeFile(t, filepath.Join(f.esTLSDir, "artifact-registry-root-ca.pem"), ca, 0o640)
			writeFile(t, filepath.Join(f.arsTLSDir, "ars-server-cert.pem"), cert, 0o640)
			writeFile(t, filepath.Join(f.arsTLSDir, "ars-server-key.pem"), private, 0o640)
		}, "san_mismatch"},
		{"not yet valid", "artifact-registry", func(t *testing.T) *remoteAlphaESServiceTLSFixture {
			return setupRemoteAlphaESServiceTLSFixture(t, false)
		}, func(t *testing.T, f *remoteAlphaESServiceTLSFixture) {
			now := time.Now().UTC()
			ca, key, _ := remoteAlphaGenerateCA(t, now.Add(-time.Hour), now.Add(48*time.Hour))
			cert, private := remoteAlphaGenerateLeaf(t, ca, key, "server.artifact-registry.internal", x509.ExtKeyUsageServerAuth, now.Add(12*time.Hour), now.Add(48*time.Hour))
			writeFile(t, filepath.Join(f.arsTLSDir, "runtime-ca.pem"), ca, 0o640)
			writeFile(t, filepath.Join(f.agsTLSDir, "runtime-ca.pem"), ca, 0o640)
			writeFile(t, filepath.Join(f.esTLSDir, "artifact-registry-root-ca.pem"), ca, 0o640)
			writeFile(t, filepath.Join(f.arsTLSDir, "ars-server-cert.pem"), cert, 0o640)
			writeFile(t, filepath.Join(f.arsTLSDir, "ars-server-key.pem"), private, 0o640)
		}, "certificate_not_yet_valid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.makeFixture(t)
			if tc.mutate != nil {
				tc.mutate(t, f)
			}
			record := runRemoteAlphaESTLSFixture(t, f, tc.scope)
			assertJSONPathEquals(t, record, "result.status", "fail")
			assertJSONPathEquals(t, record, "result.ok", false)
			if !slices.Contains(statusFixtureCodes(t, record), tc.code) {
				t.Fatalf("missing %s blocker: %v", tc.code, statusFixtureCodes(t, record))
			}
			if tc.name == "hostname mismatch" && !slices.Contains(statusFixtureCodes(t, record), "chain_failed") {
				t.Fatalf("exact hostname verification failure was not typed: %v", statusFixtureCodes(t, record))
			}
		})
	}
}

func validateRemoteAlphaESTLSStatusDocument(t *testing.T, record map[string]any, scope, previous, root string) error {
	t.Helper()
	const probe = `
import importlib.util, json, sys
spec=importlib.util.spec_from_file_location("status_reader", sys.argv[1])
module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
` + remoteAlphaESStatusLocalProcessBoundary + `root=sys.argv[4]
prefix="/etc/execution-substrate/"
def relocate(value):
    if isinstance(value,str) and value.startswith(prefix): return root+"/etc/execution-substrate/"+value[len(prefix):]
    if isinstance(value,tuple): return tuple(relocate(item) for item in value)
    if isinstance(value,dict): return {key:relocate(item) for key,item in value.items()}
    return value
module.SCOPES=relocate(module.SCOPES)
try:
    record=json.loads(sys.stdin.read(), object_pairs_hook=module._unique_pairs)
    module.validate_document(record, sys.argv[2], sys.argv[3] or None)
except Exception as exc:
    print(type(exc).__name__)
    sys.exit(1)
`
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-c", probe,
		remoteAlphaESServiceTLSStatusCollectorPath(), scope, previous, root)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	cmd.Stdin = strings.NewReader(string(encoded))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, output)
	}
	return nil
}

func copyRemoteAlphaESTLSRecord(t *testing.T, source map[string]any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestRemoteAlphaESServiceTLSStatusReaderDocumentAcceptance(t *testing.T) {
	passFixture := setupRemoteAlphaESServiceTLSFixture(t, false)
	failFixture := setupRemoteAlphaESServiceTLSFixture(t, true)
	pass := runRemoteAlphaESTLSFixture(t, passFixture, "artifact-registry")
	fail := runRemoteAlphaESTLSFixture(t, failFixture, "artifact-registry")
	if err := validateRemoteAlphaESTLSStatusDocument(t, pass, "artifact-registry", "", passFixture.root); err != nil {
		t.Fatalf("fresh pass refused: %v", err)
	}
	if err := validateRemoteAlphaESTLSStatusDocument(t, fail, "artifact-registry", "", failFixture.root); err != nil {
		t.Fatalf("fresh completed fail refused: %v", err)
	}
	cases := []struct {
		name     string
		mutate   func(map[string]any)
		scope    string
		previous string
	}{
		{"finalized missing", func(r map[string]any) { delete(r, "finalized") }, "artifact-registry", ""},
		{"finalized false", func(r map[string]any) { r["finalized"] = false }, "artifact-registry", ""},
		{"old generation", nil, "artifact-registry", pass["generation"].(string)},
		{"stale timestamp", func(r map[string]any) {
			r["checked_at"] = time.Now().UTC().Add(-6 * time.Minute).Format("2006-01-02T15:04:05Z")
		}, "artifact-registry", ""},
		{"future timestamp", func(r map[string]any) {
			r["checked_at"] = time.Now().UTC().Add(2 * time.Minute).Format("2006-01-02T15:04:05Z")
		}, "artifact-registry", ""},
		{"wrong schema", func(r map[string]any) { r["schema_version"] = "legacy" }, "artifact-registry", ""},
		{"wrong route", func(r map[string]any) { r["route"] = "es-governance-tls-status" }, "artifact-registry", ""},
		{"wrong scope", nil, "execution-governance", ""},
		{"unknown field", func(r map[string]any) { r["extra"] = true }, "artifact-registry", ""},
		{"wrong role cardinality", func(r map[string]any) { r["certificates"] = r["certificates"].([]any)[:5] }, "artifact-registry", ""},
		{"wrong role label", func(r map[string]any) { r["certificates"].([]any)[0].(map[string]any)["label"] = "legacy" }, "artifact-registry", ""},
		{"unknown code", func(r map[string]any) { r["topology"].([]any)[0].(map[string]any)["code"] = "unknown" }, "artifact-registry", ""},
		{"inconsistent result", func(r map[string]any) { r["result"].(map[string]any)["ok"] = false }, "artifact-registry", ""},
		{"renewal effect", func(r map[string]any) { r["non_effects"].(map[string]any)["renewal_attempted"] = true }, "artifact-registry", ""},
		{"raw output flag", func(r map[string]any) { r["security"].(map[string]any)["raw_openssl_output_included"] = true }, "artifact-registry", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			record := copyRemoteAlphaESTLSRecord(t, pass)
			if tc.mutate != nil {
				tc.mutate(record)
			}
			if err := validateRemoteAlphaESTLSStatusDocument(t, record, tc.scope, tc.previous, passFixture.root); err == nil {
				t.Fatalf("unsafe record accepted")
			}
		})
	}
}

func TestRemoteAlphaESServiceTLSStatusReaderSemanticConsistency(t *testing.T) {
	ars := setupRemoteAlphaESServiceTLSFixture(t, false)
	egs := setupRemoteAlphaESGovernanceTLSFixture(t, false)
	expired := setupRemoteAlphaESServiceTLSFixture(t, true)
	missing := setupRemoteAlphaESServiceTLSFixture(t, false)
	if err := os.Remove(filepath.Join(missing.arsTLSDir, "ars-server-cert.pem")); err != nil {
		t.Fatal(err)
	}
	arsPass := runRemoteAlphaESTLSFixture(t, ars, "artifact-registry")
	egsPass := runRemoteAlphaESTLSFixture(t, egs, "execution-governance")
	arsExpired := runRemoteAlphaESTLSFixture(t, expired, "artifact-registry")
	arsMissing := runRemoteAlphaESTLSFixture(t, missing, "artifact-registry")
	for _, tc := range []struct {
		name, scope, root string
		record            map[string]any
	}{
		{"P0s emitted pass", "artifact-registry", ars.root, arsPass},
		{"P0t emitted pass", "execution-governance", egs.root, egsPass},
		{"P0s emitted completed fail", "artifact-registry", expired.root, arsExpired},
		{"P0s emitted missing cert", "artifact-registry", missing.root, arsMissing},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateRemoteAlphaESTLSStatusDocument(t, tc.record, tc.scope, "", tc.root); err != nil {
				t.Fatalf("collector-emitted record rejected: %v", err)
			}
		})
	}
	stamp := arsPass["checked_at"].(string)
	equality := copyRemoteAlphaESTLSRecord(t, arsPass)
	ca := equality["certificates"].([]any)[0].(map[string]any)
	ca["not_before"], ca["not_after"] = stamp, stamp
	if err := validateRemoteAlphaESTLSStatusDocument(t, equality, "artifact-registry", "", ars.root); err != nil {
		t.Fatalf("validity equality at checked_at refused: %v", err)
	}
	setFailure := func(record map[string]any, item map[string]any, code string) {
		item["status"], item["code"] = "fail", code
		record["blockers"] = []any{code}
		record["result"] = map[string]any{"status": "fail", "ok": false}
	}
	cases := []struct {
		name   string
		base   map[string]any
		root   string
		mutate func(map[string]any)
	}{
		{"expired date with false flag and aggregate pass", arsPass, ars.root, func(r map[string]any) {
			r["certificates"].([]any)[0].(map[string]any)["not_after"] = "2000-01-01T00:00:00Z"
		}},
		{"future not before with false flag", arsPass, ars.root, func(r map[string]any) {
			cert := r["certificates"].([]any)[0].(map[string]any)
			cert["not_before"], cert["not_after"] = "2099-01-01T00:00:00Z", "2100-01-01T00:00:00Z"
		}},
		{"inverted interval", arsPass, ars.root, func(r map[string]any) {
			cert := r["certificates"].([]any)[0].(map[string]any)
			cert["not_before"], cert["not_after"] = "2099-01-01T00:00:00Z", "2000-01-01T00:00:00Z"
		}},
		{"fixed label wrong role", arsPass, ars.root, func(r map[string]any) {
			r["certificates"].([]any)[0].(map[string]any)["role"] = "server"
		}},
		{"certificate with key code", arsPass, ars.root, func(r map[string]any) {
			setFailure(r, r["certificates"].([]any)[0].(map[string]any), "key_malformed")
		}},
		{"trust anchor mismatch with reported metadata", arsPass, ars.root, func(r map[string]any) {
			setFailure(r, r["certificates"].([]any)[0].(map[string]any), "trust_anchor_count_mismatch")
		}},
		{"trust anchor mismatch on non CA role", arsPass, ars.root, func(r map[string]any) {
			setFailure(r, r["certificates"].([]any)[1].(map[string]any), "trust_anchor_count_mismatch")
		}},
		{"trust anchor mismatch with verification pass", arsPass, ars.root, func(r map[string]any) {
			cert := r["certificates"].([]any)[0].(map[string]any)
			setFailure(r, cert, "trust_anchor_count_mismatch")
			for _, key := range []string{"not_before", "not_after", "expired", "not_yet_valid", "sha256", "fingerprint_sha256", "public_key_sha256", "subject_sha256", "issuer_sha256", "san_match", "eku_match"} {
				cert[key] = nil
			}
		}},
		{"P0t only code in P0s disjoint check", arsPass, ars.root, func(r map[string]any) {
			for _, item := range r["topology"].([]any) {
				if check := item.(map[string]any); check["id"] == "related_service_tls_disjoint" {
					setFailure(r, check, "ags_scope_present")
					return
				}
			}
			t.Fatal("missing disjoint check")
		}},
		{"disjoint malformed with valid related config", arsPass, ars.root, func(r map[string]any) {
			for _, item := range r["topology"].([]any) {
				if check := item.(map[string]any); check["id"] == "related_service_tls_disjoint" {
					setFailure(r, check, "related_config_malformed")
					return
				}
			}
			t.Fatal("missing disjoint check")
		}},
		{"disjoint missing with all required configs present", arsPass, ars.root, func(r map[string]any) {
			for _, item := range r["topology"].([]any) {
				if check := item.(map[string]any); check["id"] == "related_service_tls_disjoint" {
					setFailure(r, check, "config_missing")
					return
				}
			}
			t.Fatal("missing disjoint check")
		}},
		{"pass with failed child", arsExpired, expired.root, func(r map[string]any) {
			r["blockers"] = []any{}
			r["result"] = map[string]any{"status": "pass", "ok": true}
		}},
		{"fail with missing blockers", arsExpired, expired.root, func(r map[string]any) {
			r["blockers"] = []any{}
		}},
		{"fail with inconsistent blockers", arsExpired, expired.root, func(r map[string]any) {
			r["blockers"] = []any{"key_mismatch"}
		}},
		{"unknown nested certificate field", arsPass, ars.root, func(r map[string]any) {
			r["certificates"].([]any)[0].(map[string]any)["unexpected"] = true
		}},
		{"invented exists field", arsMissing, missing.root, func(r map[string]any) {
			r["certificates"].([]any)[1].(map[string]any)["exists"] = false
		}},
		{"missing certificate with digest", arsMissing, missing.root, func(r map[string]any) {
			r["certificates"].([]any)[1].(map[string]any)["sha256"] = strings.Repeat("a", 64)
		}},
		{"pair unavailable with available cert", arsPass, ars.root, func(r map[string]any) {
			pair := r["key_pairs"].([]any)[0].(map[string]any)
			setFailure(r, pair, "certificate_unavailable")
			pair["matches"] = false
		}},
		{"chain unavailable with available certs", arsPass, ars.root, func(r map[string]any) {
			setFailure(r, r["verification"].([]any)[0].(map[string]any), "certificate_unavailable")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			record := copyRemoteAlphaESTLSRecord(t, tc.base)
			tc.mutate(record)
			if err := validateRemoteAlphaESTLSStatusDocument(t, record, "artifact-registry", "", tc.root); err == nil {
				t.Fatal("contradictory record accepted")
			}
		})
	}
}

func TestRemoteAlphaESServiceTLSStatusBoundedChildRunner(t *testing.T) {
	const probe = `
import importlib.util, json, os, pathlib, signal, sys, threading
source, root = sys.argv[1:]
spec=importlib.util.spec_from_file_location("status_runner", source)
module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
` + remoteAlphaESStatusLocalProcessBoundary + `root=pathlib.Path(root)
child=root/"fake_openssl"
child.write_text('''#!/usr/bin/python3
import os, sys, time
mode=sys.argv[1]
if mode in ("timeout", "signal"):
    open(sys.argv[2], "w").write(str(os.getpid()))
    time.sleep(10)
elif mode == "stdout": sys.stdout.buffer.write(b"x"*70000)
elif mode == "stderr": sys.stderr.buffer.write(b"x"*9000)
elif mode == "checkfd":
    fd,dev,ino=map(int,sys.argv[2:5])
    try:
        info=os.fstat(fd)
        inherited=(info.st_dev,info.st_ino)==(dev,ino)
    except OSError: inherited=False
    sys.stdout.write("inherited" if inherited else "closed")
''')
child.chmod(0o700)
module.OPENSSL=str(child); module.CHILD_TIMEOUT=0.25; module.CHILD_GRACE=0.25
spawned=threading.Event(); processes=[]; original_popen=module.subprocess.Popen
def track_popen(*args, **kwargs):
    proc=original_popen(*args, **kwargs); processes.append(proc); spawned.set(); return proc
module.subprocess.Popen=track_popen
def interrupt_when_spawned():
    if spawned.wait(5):
        threading.Event().wait(0.05)
        os.kill(os.getpid(),signal.SIGTERM)
results={}
for mode in ("timeout", "stdout", "stderr", "signal"):
    module.CHILD_TIMEOUT=5.0 if mode in ("stdout", "stderr") else 0.25
    spawned.clear()
    pidfile=root/(mode+".pid")
    if mode == "signal":
        signal.signal(signal.SIGTERM,module._latch)
        timer=threading.Thread(target=interrupt_when_spawned); timer.start()
    try: module.run_fixed((str(child),mode,str(pidfile)))
    except module.Incomplete as exc: results[mode]=str(exc)
    else: results[mode]="unexpected_success"
    if mode == "signal": timer.join(); module.LATCHED_SIGNAL=None
    if mode in ("timeout", "signal"):
        pid=processes[-1].pid
        try: os.waitpid(pid,os.WNOHANG); results[mode+"_reaped"]=False
        except ChildProcessError: results[mode+"_reaped"]=True
lock=root/"lock"; lock.write_text("")
fd=os.open(lock,os.O_RDONLY); os.set_inheritable(fd,True)
info=os.fstat(fd)
module.CHILD_TIMEOUT=2.0
code,out,_error=module.run_fixed((str(child),"checkfd",str(fd),str(info.st_dev),str(info.st_ino)))
results["lock_fd_closed"]=(code==0 and out==b"closed")
os.close(fd)
module.open_fixed_regular=lambda *_args,**_kwargs: b"fixture"
module.run_fixed=lambda *_args,**_kwargs: (0,b"unexpected grammar",b"")
try: module.cert_metadata("/fixed/public-cert.pem"); results["unexpected_grammar_refused"]=False
except module.Incomplete: results["unexpected_grammar_refused"]=True
print(json.dumps(results,sort_keys=True))
`
	cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-c", probe,
		remoteAlphaESServiceTLSStatusCollectorPath(), t.TempDir())
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bounded runner probe: %v\n%s", err, output)
	}
	var result map[string]any
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("runner result: %v\n%s", err, output)
	}
	for key, want := range map[string]string{"timeout": "child_timeout", "stdout": "child_output_overflow", "stderr": "child_output_overflow", "signal": "child_interrupted"} {
		if result[key] != want {
			t.Fatalf("%s = %v, want %s", key, result[key], want)
		}
	}
	for _, key := range []string{"timeout_reaped", "signal_reaped", "lock_fd_closed", "unexpected_grammar_refused"} {
		if result[key] != true {
			t.Fatalf("%s = %v", key, result[key])
		}
	}
}

func TestRemoteAlphaESServiceTLSStatusOpenSSLGrammar(t *testing.T) {
	const probe = `
import importlib.util, json, os, pathlib, sys
source, root = sys.argv[1:]
spec=importlib.util.spec_from_file_location("status_grammar", source)
module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
` + remoteAlphaESStatusLocalProcessBoundary + `root=pathlib.Path(root)
cert=root/"bad-cert.pem"; cert.write_bytes(b"bad cert")
key=root/"bad-key.pem"; key.write_bytes(b"bad key")
module.open_fixed_regular=lambda path,limit,read_content=True: pathlib.Path(path).read_bytes() if read_content else None
results={}
cert_argv=(module.OPENSSL,"x509","-in","/dev/stdin","-noout","-subject","-issuer","-dates","-fingerprint","-sha256","-nameopt","RFC2253")
key_argv=(module.OPENSSL,"pkey","-in","/dev/stdin","-pubout","-outform","DER")
cert_tuple=module.run_fixed(cert_argv,b"bad cert"); key_tuple=module.run_fixed(key_argv,b"bad key")
results["exact_malformed_certificate"]=(module.cert_metadata(str(cert))[0]["code"]=="certificate_malformed")
results["exact_malformed_key"]=(module.key_pair("fixture",{"public_key_sha256":"a"*64},str(key))["code"]=="key_malformed")
original=module.run_fixed
def incomplete(call):
    try: call(); return False
    except module.Incomplete: return True
for label, response in (
    ("unknown_nonzero_cert",(1,b"",b"unrecognized failure\n")),
    ("malformed_cert_plus_noise",(cert_tuple[0],cert_tuple[1],cert_tuple[2]+b"warning\n")),
    ("zero_cert_unexpected_output",(0,b"unexpected success\n",b"")),
    ("signal_cert",(-15,b"",b"")),
):
    module.run_fixed=lambda *_args, response=response, **_kwargs: response
    results[label]=incomplete(lambda:module.cert_metadata(str(cert)))
for label, response in (
    ("unknown_nonzero_key",(1,b"",b"unrecognized failure\n")),
    ("malformed_key_plus_noise",(key_tuple[0],key_tuple[1],key_tuple[2]+b"warning\n")),
    ("zero_key_unexpected_output",(0,b"unexpected success\n",b"")),
    ("signal_key",(-15,b"",b"")),
):
    module.run_fixed=lambda *_args, response=response, **_kwargs: response
    results[label]=incomplete(lambda:module.key_pair("fixture",{"public_key_sha256":"a"*64},str(key)))
ca={"sha256":"a"*64}; leaf={"sha256":"b"*64}
def verify(): return module.verify_chain("fixture",ca,leaf,b"selected anchor",b"leaf", "sslserver","fixture.internal")
success=(0,b"/dev/stdin: OK\n",b"")
failure=(2,b"CN = fixture.internal\nerror 20 at 0 depth lookup:unable to get local issuer certificate\n/dev/stdin: verification failed: 20 (unable to get local issuer certificate)\n",b"")
hostname=(2,b"",b"CN=fixture.internal\nerror 62 at 0 depth lookup: hostname mismatch\nerror /dev/stdin: verification failed\n")
module.run_fixed=lambda *_args, **_kwargs: success
results["verify_exact_success"]=(verify()["code"]=="pass")
module.run_fixed=lambda *_args, **_kwargs: failure
results["verify_exact_failure"]=(verify()["code"]=="chain_failed")
module.run_fixed=lambda *_args, **_kwargs: hostname
results["verify_hostname_mismatch"]=(verify()["code"]=="chain_failed")
for label, response in (
    ("verify_failure_plus_noise",(failure[0],failure[1]+b"warning\n",failure[2])),
    ("verify_unknown_nonzero",(2,b"unrelated error 20 at 0 depth lookup\n",b"")),
    ("verify_zero_extra_line",(0,success[1]+b"extra\n",b"")),
    ("verify_zero_stderr",(0,success[1],b"warning\n")),
    ("verify_hostname_warning",(hostname[0],hostname[1],hostname[2]+b"warning\n")),
    ("verify_usage",(1,b"",b"usage: verify\n")),
    ("verify_signal",(-15,b"",b"")),
):
    module.run_fixed=lambda *_args, response=response, **_kwargs: response
    results[label]=incomplete(verify)
module.run_fixed=original
overflow=root/"overflow-openssl"
overflow.write_text('#!/usr/bin/python3\nimport sys\nsys.stdout.buffer.write(b"x"*70000)\n')
overflow.chmod(0o700)
module.OPENSSL=str(overflow)
results["output_limit"]=(incomplete(lambda:module.run_fixed((str(overflow),))) )
print(json.dumps(results,sort_keys=True))
`
	cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-c", probe,
		remoteAlphaESServiceTLSStatusCollectorPath(), t.TempDir())
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("OpenSSL grammar probe: %v\n%s", err, output)
	}
	var results map[string]bool
	if err := json.Unmarshal(output, &results); err != nil {
		t.Fatalf("OpenSSL grammar result: %v\n%s", err, output)
	}
	if len(results) != 21 {
		t.Fatalf("OpenSSL grammar checks missing: %v", results)
	}
	for name, ok := range results {
		if !ok {
			t.Errorf("OpenSSL grammar check %s failed", name)
		}
	}
}

func TestRemoteAlphaESServiceTLSStatusX509TextSignatureTails(t *testing.T) {
	const probe = `
import importlib.util,json,sys
spec=importlib.util.spec_from_file_location("status_x509_tail_fixture",sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
prefix=b"Certificate:\n    Data:\n"
algorithm=b"    Signature Algorithm: sha256WithRSAEncryption\n"
old=prefix+algorithm+b"         01:ab:ff\n"
new=prefix+algorithm+b"    Signature Value:\n        01:ab:ff\n"
cases={
 "legacy":old,
 "legacy_multiple":prefix+algorithm+b"         01:ab:\n         cd:ef\n",
 "openssl3":new,
 "openssl3_multiple":prefix+algorithm+b"    Signature Value:\n        01:ab:\n        cd:ef\n",
 "wrong_heading":prefix+algorithm+b"    Signature Values:\n        01:ab\n",
 "repeated_heading":prefix+algorithm+b"    Signature Value:\n    Signature Value:\n        01:ab\n",
 "heading_plus_nine":prefix+algorithm+b"    Signature Value:\n         01:ab\n",
 "no_heading_eight":prefix+algorithm+b"        01:ab\n",
 "mixed_indentation":prefix+algorithm+b"    Signature Value:\n        01:ab\n         cd:ef\n",
 "zero_rows":prefix+algorithm+b"    Signature Value:\n",
 "malformed_truncated_hex":prefix+algorithm+b"    Signature Value:\n        01:ab:f\n",
 "extra_trailing":new+b"extra\n",
 "carriage_return":new.replace(b"\n",b"\r\n"),
 "nul_control":new+b"\x00",
 "bad_prefix":b"Not a certificate:\n    Data:\n"+algorithm+b"    Signature Value:\n        01:ab\n",
 "uppercase_hex":prefix+algorithm+b"    Signature Value:\n        AB:CD\n",
}
print(json.dumps({name:module._valid_x509_text(value) for name,value in cases.items()},sort_keys=True))
`
	got := runRemoteAlphaESServiceTLSStatusX509TextFixture(t, probe, nil)
	want := map[string]bool{
		"legacy": true, "legacy_multiple": true,
		"openssl3": true, "openssl3_multiple": true,
		"wrong_heading": false, "repeated_heading": false,
		"heading_plus_nine": false, "no_heading_eight": false,
		"mixed_indentation": false, "zero_rows": false,
		"malformed_truncated_hex": false, "extra_trailing": false,
		"carriage_return": false, "nul_control": false,
		"bad_prefix": false, "uppercase_hex": false,
	}
	if len(got) != len(want) {
		t.Fatalf("signature-tail case count = %d, want %d: %v", len(got), len(want), got)
	}
	for label, expected := range want {
		actual, present := got[label]
		if !present || actual != expected {
			t.Errorf("signature-tail %s = %t (present %t), want %t", label, actual, present, expected)
		}
	}
}

func TestRemoteAlphaESServiceTLSStatusX509TextNativeOpenSSL3Response(t *testing.T) {
	root := filepath.Join(executionSubstrateRepoRoot, "testdata", "remote_alpha_es_tls_status")
	text, err := os.ReadFile(filepath.Join(root, "openssl3_x509_text.stdout"))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := os.ReadFile(filepath.Join(root, "openssl3_public_cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if len(text) != 3059 || fmt.Sprintf("%x", sha256.Sum256(text)) != "b9b4211e036dee8819e68711e5d254db289abc20c6ae5bfbb2683fe4085087e4" {
		t.Fatal("retained synthetic OpenSSL 3 text identity changed")
	}
	if len(cert) != 1172 || fmt.Sprintf("%x", sha256.Sum256(cert)) != "a6f1256b5d7ce3485eeadd59e974637e49e3857b4aa159923a1bd0dd0a367c55" {
		t.Fatal("retained synthetic public certificate identity changed")
	}
	if !bytes.Contains(text, []byte("\n    Signature Value:\n        ")) ||
		!bytes.HasPrefix(cert, []byte("-----BEGIN CERTIFICATE-----\n")) {
		t.Fatal("retained synthetic fixture shape changed")
	}
	const probe = `
import importlib.util,json,sys
spec=importlib.util.spec_from_file_location("status_x509_native_fixture",sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
raw=sys.stdin.buffer.read(3060)
print(json.dumps({"accepted":module._valid_x509_text(raw),"input_bound":len(raw)==3059}))
`
	got := runRemoteAlphaESServiceTLSStatusX509TextFixture(t, probe, text)
	if len(got) != 2 || !got["accepted"] || !got["input_bound"] {
		t.Fatalf("retained synthetic OpenSSL 3 response was not admitted unchanged: %v", got)
	}
}

func TestRemoteAlphaESServiceTLSStatusX509TextRoleCompatibility(t *testing.T) {
	root := filepath.Join(executionSubstrateRepoRoot, "testdata", "remote_alpha_es_tls_status")
	textPath := filepath.Join(root, "openssl3_x509_text.stdout")
	certPath := filepath.Join(root, "openssl3_public_cert.pem")
	text, err := os.ReadFile(textPath)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(text)) != "b9b4211e036dee8819e68711e5d254db289abc20c6ae5bfbb2683fe4085087e4" ||
		fmt.Sprintf("%x", sha256.Sum256(cert)) != "a6f1256b5d7ce3485eeadd59e974637e49e3857b4aa159923a1bd0dd0a367c55" {
		t.Fatal("synthetic role witness fixture identity changed")
	}
	const probe = `
import datetime,importlib.util,json,os,pathlib,sys
source,text_path,cert_path=sys.argv[1:]
spec=importlib.util.spec_from_file_location("status_x509_role_fixture",source)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
native=pathlib.Path(text_path).read_bytes()
cert=pathlib.Path(cert_path).read_bytes()
now=datetime.datetime(2026,11,4,0,0,0,tzinfo=datetime.timezone.utc)
expected_argv=(module.OPENSSL,"x509","-in","/dev/stdin","-noout","-text")
results={}
def text_for(item,san_mode="ok",eku_mode="ok"):
    _label,_path,role,hostname,eku=item
    body=b"Certificate:\n    Data:\n"
    if hostname is not None and san_mode!="missing":
        name=hostname if san_mode=="ok" else "wrong.ge-p0t-parser-fixture.invalid"
        body+=b"            X509v3 Subject Alternative Name:\n                DNS:"+name.encode()+b"\n"
    if eku_mode!="missing":
        wanted="TLS Web Server Authentication" if eku=="server" else "TLS Web Client Authentication"
        if eku_mode=="wrong":
            wanted="TLS Web Client Authentication" if eku=="server" else "TLS Web Server Authentication"
        body+=b"            X509v3 Extended Key Usage:\n                "+wanted.encode()+b"\n"
    return body+b"    Signature Algorithm: sha256WithRSAEncryption\n    Signature Value:\n        01:ab:ff\n"
def invoke(item,text,response=None,status="pass",code="pass"):
    calls=[]
    def metadata(path,observed_at=None,single_trust_anchor=False):
        assert path==item[1] and observed_at==now
        assert single_trust_anchor==(item[2]=="ca")
        return {"status":status,"code":code,"not_before":"2026-11-03T00:00:00Z",
                "not_after":"2026-11-05T00:00:00Z","expired":code=="certificate_expired",
                "not_yet_valid":code=="certificate_not_yet_valid","sha256":"a"*64,
                "fingerprint_sha256":"b"*64,"public_key_sha256":"c"*64,
                "subject_sha256":"d"*64,"issuer_sha256":"e"*64},cert
    def fixed(argv,input_bytes=None,anchor_bytes=None):
        calls.append((tuple(argv),input_bytes,anchor_bytes))
        assert tuple(argv)==expected_argv and input_bytes==cert and anchor_bytes is None
        return response if response is not None else (0,text,b"")
    module.cert_metadata=metadata
    module.run_fixed=fixed
    try:
        record,returned=module.cert_role(item,now)
    except module.Incomplete as exc:
        return None,calls,str(exc)
    assert returned==cert
    return record,calls,None
counts={}
all_roles_pass=True
ca_no_child=True
argv_and_bytes_bound=True
for scope in ("artifact-registry","execution-governance"):
    counts[scope]={"ca":0,"non_ca":0}
    for item in module.SCOPES[scope]["certs"]:
        record,calls,error=invoke(item,text_for(item))
        if item[2]=="ca":
            counts[scope]["ca"]+=1
            ca_no_child=ca_no_child and error is None and calls==[] and record["san_match"] is None and record["eku_match"] is None
        else:
            counts[scope]["non_ca"]+=1
            all_roles_pass=all_roles_pass and error is None and record["status"]=="pass" and record["code"]=="pass"
            all_roles_pass=all_roles_pass and record["eku_match"] is True
            if item[3] is not None: all_roles_pass=all_roles_pass and record["san_match"] is True
            argv_and_bytes_bound=argv_and_bytes_bound and len(calls)==1 and calls[0]==(expected_argv,cert,None)
results["p0s_role_counts"]=counts["artifact-registry"]=={"ca":3,"non_ca":3}
results["p0t_role_counts"]=counts["execution-governance"]=={"ca":2,"non_ca":2}
results["both_scopes_non_ca_role_handling"]=all_roles_pass
results["ca_behavior_unchanged"]=ca_no_child
results["exact_argv_and_input_bytes"]=argv_and_bytes_bound
server=next(item for item in module.SCOPES["artifact-registry"]["certs"] if item[2]=="server")
client=next(item for item in module.SCOPES["execution-governance"]["certs"] if item[2]=="client")
record,_,error=invoke(server,text_for(server,san_mode="missing"))
results["san_missing"]=error is None and record["code"]=="san_missing"
record,_,error=invoke(server,text_for(server,san_mode="wrong"))
results["san_mismatch"]=error is None and record["code"]=="san_mismatch"
record,_,error=invoke(client,text_for(client,eku_mode="missing"))
results["eku_missing"]=error is None and record["code"]=="eku_missing"
record,_,error=invoke(client,text_for(client,eku_mode="wrong"))
results["eku_mismatch"]=error is None and record["code"]=="eku_mismatch"
record,_,error=invoke(server,text_for(server,san_mode="missing",eku_mode="missing"),status="fail",code="certificate_expired")
results["expired_precedence"]=error is None and record["code"]=="certificate_expired"
record,_,error=invoke(client,text_for(client,eku_mode="missing"),status="fail",code="certificate_not_yet_valid")
results["not_yet_valid_precedence"]=error is None and record["code"]=="certificate_not_yet_valid"
record,_,error=invoke(client,text_for(client),response=(1,b"",b""))
results["wrong_exit_incomplete"]=record is None and error=="unexpected_openssl_grammar"
record,_,error=invoke(client,text_for(client),response=(0,text_for(client),b"warning\n"))
results["nonempty_stderr_incomplete"]=record is None and error=="unexpected_openssl_grammar"
record,_,error=invoke(client,native)
results["native_text_reaches_role_checks"]=error is None and record["code"]=="eku_missing"
# The following pipeline fixture injects local /dev/null descriptors and a
# rejected cert-role response. It proves no encode/publish call on this path,
# not root custody, process capability, lock behavior, or live publication.
module.ES_TLS_STATUS_BOOTSTRAP_VERIFIED=True
module.ES_TLS_STATUS_BOOTSTRAP_INTERRUPTED=[False]
module.open_status_dir=lambda:os.open(os.devnull,os.O_RDONLY)
module.open_scope_lock=lambda _status,_name:os.open(os.devnull,os.O_RDONLY)
module.validate_process_capability=lambda:None
module.preexisting_generation=lambda _status,_scope:module._PriorSummarySnapshot(module._PriorSummaryState.ABSENT)
module.encode_document=lambda *_args:(_ for _ in ()).throw(AssertionError("encode reached"))
module.publish=lambda *_args:(_ for _ in ()).throw(AssertionError("publish reached"))
def failing_collect(_scope,_previous):
    record,calls,error=invoke(client,text_for(client),response=(0,b"unknown grammar\n",b""))
    if error is not None:raise module.Incomplete(error)
    return record
module.collect=failing_collect
results["rejected_tuple_no_publication"]=module.main(["--scope","execution-governance"])==1
print(json.dumps(results,sort_keys=True))
`
	got := runRemoteAlphaESServiceTLSStatusX509TextFixture(t, probe, nil, textPath, certPath)
	want := []string{
		"p0s_role_counts", "p0t_role_counts", "both_scopes_non_ca_role_handling",
		"ca_behavior_unchanged", "exact_argv_and_input_bytes",
		"san_missing", "san_mismatch", "eku_missing", "eku_mismatch",
		"expired_precedence", "not_yet_valid_precedence",
		"wrong_exit_incomplete", "nonempty_stderr_incomplete",
		"native_text_reaches_role_checks", "rejected_tuple_no_publication",
	}
	if len(got) != len(want) {
		t.Fatalf("x509 role witness count = %d, want %d: %v", len(got), len(want), got)
	}
	for _, label := range want {
		if !got[label] {
			t.Errorf("x509 role witness %s false or missing", label)
		}
	}
}

func TestRemoteAlphaESServiceTLSStatusChildSetupFailureReaps(t *testing.T) {
	const probe = `
import importlib.util,json,os,pathlib,sys
source,root,mode=sys.argv[1:]
spec=importlib.util.spec_from_file_location("status_setup",source)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
` + remoteAlphaESStatusLocalProcessBoundary + `root=pathlib.Path(root)
child=root/"fixture-openssl"
child.write_text('#!/usr/bin/python3\nimport time\ntime.sleep(10)\n')
child.chmod(0o700)
module.OPENSSL=str(child);module.CHILD_GRACE=0.5
canonical=root/"es-service-tls-status-summary.json";canonical.write_bytes(b"old_generation\n")
spawned=[];original_popen=module.subprocess.Popen;original_set_blocking=module.os.set_blocking
def track_popen(*args,**kwargs):
    proc=original_popen(*args,**kwargs);spawned.append(proc)
    if mode=="nonblocking":module.os.set_blocking=lambda *_args:(_ for _ in ()).throw(OSError("fixture set_blocking failure"))
    return proc
module.subprocess.Popen=track_popen
if mode=="construct":
    module.selectors.DefaultSelector=lambda:(_ for _ in ()).throw(OSError("fixture selector construction failure"))
elif mode=="register":
    original_selector=module.selectors.DefaultSelector
    class FailingSelector:
        def __init__(self):self.inner=original_selector()
        def register(self,*_args,**_kwargs):raise OSError("fixture selector registration failure")
        def close(self):self.inner.close()
    module.selectors.DefaultSelector=FailingSelector
called=[]
module.ES_TLS_STATUS_BOOTSTRAP_VERIFIED=True
module.ES_TLS_STATUS_BOOTSTRAP_INTERRUPTED=[False]
module.open_status_dir=lambda:os.open(root,os.O_RDONLY|os.O_DIRECTORY)
module.open_scope_lock=lambda _fd,_name:os.open(root/"fixture-lock",os.O_RDONLY|os.O_CREAT,0o600)
module.preexisting_generation=lambda _fd,_scope:module._PriorSummarySnapshot(module._PriorSummaryState.VALID,"0"*32)
module.collect=lambda _scope,_previous:module.run_fixed((str(child),))
module.publish=lambda *_args:called.append(True)
try:result=module.main(["--scope","artifact-registry"])
finally:module.os.set_blocking=original_set_blocking
reaped=False;gone=False
if spawned:
    proc=spawned[0]
    try:os.waitpid(proc.pid,os.WNOHANG)
    except ChildProcessError:reaped=True
    try:os.kill(proc.pid,0)
    except ProcessLookupError:gone=True
print(json.dumps({"exit_incomplete":result==1,"spawned_once":len(spawned)==1,"reaped":reaped,"gone":gone,"no_publication":not called and canonical.read_bytes()==b"old_generation\n","no_scratch":not any(p.suffix==".tmp" for p in root.iterdir())},sort_keys=True))
`
	for _, mode := range []string{"construct", "register", "nonblocking"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-c", probe,
				remoteAlphaESServiceTLSStatusCollectorPath(), t.TempDir(), mode)
			cmd.Dir = executionSubstrateRepoRoot
			cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("child setup probe: %v\n%s", err, output)
			}
			var result map[string]bool
			if err := json.Unmarshal(output, &result); err != nil {
				t.Fatalf("child setup result: %v\n%s", err, output)
			}
			if len(result) != 6 {
				t.Fatalf("child setup checks missing: %v", result)
			}
			for name, ok := range result {
				if !ok {
					t.Errorf("child setup check %s failed", name)
				}
			}
		})
	}
}

func TestRemoteAlphaESServiceTLSStatusRelatedConfigHandling(t *testing.T) {
	for _, tc := range []struct {
		name, scope, relatedID string
		fixture                func(*testing.T) *remoteAlphaESServiceTLSFixture
		optional               func(*remoteAlphaESServiceTLSFixture) string
		covered                func(*remoteAlphaESServiceTLSFixture) string
	}{
		{"P0s related EGS", "artifact-registry", "egs_related_config", func(t *testing.T) *remoteAlphaESServiceTLSFixture {
			return setupRemoteAlphaESServiceTLSFixture(t, false)
		}, func(f *remoteAlphaESServiceTLSFixture) string { return f.egsConfig }, func(f *remoteAlphaESServiceTLSFixture) string {
			return filepath.Join(f.arsTLSDir, "ars-server-cert.pem")
		}},
		{"P0t related ARS", "execution-governance", "ars_related_config", func(t *testing.T) *remoteAlphaESServiceTLSFixture {
			return setupRemoteAlphaESGovernanceTLSFixture(t, false)
		}, func(f *remoteAlphaESServiceTLSFixture) string { return f.arsConfig }, func(f *remoteAlphaESServiceTLSFixture) string {
			return filepath.Join(f.egsTLSDir, "egs-server-cert.pem")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			find := func(t *testing.T, record map[string]any, id string) map[string]any {
				t.Helper()
				for _, item := range record["topology"].([]any) {
					check := item.(map[string]any)
					if check["id"] == id {
						return check
					}
				}
				t.Fatalf("missing topology check %s", id)
				return nil
			}
			t.Run("valid disjoint", func(t *testing.T) {
				f := tc.fixture(t)
				r := runRemoteAlphaESTLSFixture(t, f, tc.scope)
				if r["result"].(map[string]any)["status"] != "pass" || find(t, r, tc.relatedID)["code"] != "pass" || find(t, r, "related_service_tls_disjoint")["code"] != "pass" {
					t.Fatalf("valid related config did not pass: %v", r["topology"])
				}
			})
			t.Run("absent", func(t *testing.T) {
				f := tc.fixture(t)
				if err := os.Remove(tc.optional(f)); err != nil {
					t.Fatal(err)
				}
				r := runRemoteAlphaESTLSFixture(t, f, tc.scope)
				if r["result"].(map[string]any)["status"] != "pass" || find(t, r, tc.relatedID)["code"] != "absent" {
					t.Fatalf("safe absence not explicit and passing: %v", r["topology"])
				}
			})
			for _, malformed := range []struct{ name, content string }{{"syntax malformed", "{"}, {"structure malformed", `{"tls":[]}`}, {"null tls", `{"tls":null}`}, {"null dependencies", `{"dependencies":null}`}} {
				t.Run(malformed.name, func(t *testing.T) {
					f := tc.fixture(t)
					writeFile(t, tc.optional(f), []byte(malformed.content), 0o600)
					r := runRemoteAlphaESTLSFixture(t, f, tc.scope)
					if r["result"].(map[string]any)["status"] != "fail" || find(t, r, tc.relatedID)["code"] != "related_config_malformed" || find(t, r, "related_service_tls_disjoint")["status"] != "fail" || !slices.Contains(statusFixtureCodes(t, r), "related_config_malformed") {
						t.Fatalf("malformed related config was downgraded: %v", r["topology"])
					}
				})
			}
			t.Run("valid overlap", func(t *testing.T) {
				f := tc.fixture(t)
				writeFile(t, tc.optional(f), []byte(fmt.Sprintf(`{"tls":{"cert_file":%q}}`, tc.covered(f))), 0o600)
				r := runRemoteAlphaESTLSFixture(t, f, tc.scope)
				if r["result"].(map[string]any)["status"] != "fail" || find(t, r, tc.relatedID)["code"] != "pass" || find(t, r, "related_service_tls_disjoint")["code"] != "topology_overlap" {
					t.Fatalf("related overlap was not typed: %v", r["topology"])
				}
			})
			t.Run("unsafe symlink incomplete", func(t *testing.T) {
				f := tc.fixture(t)
				optional := tc.optional(f)
				bytes, err := os.ReadFile(optional)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(optional); err != nil {
					t.Fatal(err)
				}
				target := optional + ".fixture-target"
				writeFile(t, target, bytes, 0o600)
				if err := os.Symlink(target, optional); err != nil {
					t.Fatal(err)
				}
				const probe = `
import importlib.util, os, pathlib, stat, sys
source, root, scope = sys.argv[1:]
spec=importlib.util.spec_from_file_location("related_config",source)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
` + remoteAlphaESStatusLocalProcessBoundary + `module.CONFIG={name:str(pathlib.Path(root)/"etc/execution-substrate"/(name+".json")) for name in module.CONFIG}
def fixture_read(path,limit,read_content=True):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size>limit: raise module.Incomplete("fixture_unsafe")
        if not read_content:return None
        return os.read(fd,limit+1)
    finally:os.close(fd)
module.open_fixed_regular=fixture_read
try:module.collect_topology(module.SCOPES[scope]);sys.exit(1)
except module.Incomplete:sys.exit(0)
`
				cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-c", probe, remoteAlphaESServiceTLSStatusCollectorPath(), f.root, tc.scope)
				cmd.Dir = executionSubstrateRepoRoot
				cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("unsafe related config did not fail incomplete: %v\n%s", err, output)
				}
			})
		})
	}
}

func TestRemoteAlphaESServiceTLSStatusPublicationBoundary(t *testing.T) {
	const probe = `
import importlib.util, os, pathlib, signal, stat, sys
source, root, mode = sys.argv[1:]
spec=importlib.util.spec_from_file_location("status_publish", source)
module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
` + remoteAlphaESStatusLocalProcessBoundary + `root=pathlib.Path(root); canonical=root/"es-service-tls-status-summary.json"
canonical.write_bytes(b"old_generation\n"); canonical.chmod(0o644)
module.check_extended=lambda _fd: None  # macOS test Python lacks os.listxattr(fd)
def root_meta(info):
    return os.stat_result((info.st_mode,info.st_ino,info.st_dev,info.st_nlink,0,0,
                           info.st_size,info.st_atime,info.st_mtime,info.st_ctime))
real_stat=os.stat
def root_stat(path,*args,**kwargs):
    info=real_stat(path,*args,**kwargs)
    return root_meta(info) if str(path)==canonical.name else info
module.os.stat=root_stat
def fixture_protected_file(fd, expected):
    info=os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_gid!=os.stat(root).st_gid or stat.S_IMODE(info.st_mode)!=expected or info.st_nlink!=1:
        raise module.Incomplete("fixture_unsafe_file")
    module.check_extended(fd)
    return root_meta(info)
module.check_protected_file=fixture_protected_file
if mode == "write":
    def fail_write(*_args,**_kwargs): raise OSError("write blocked")
    module.os.write=fail_write
elif mode == "fsync":
    def fail_fsync(*_args,**_kwargs): raise OSError("fsync blocked")
    module.os.fsync=fail_fsync
elif mode == "chmod":
    def fail_chmod(*_args,**_kwargs): raise OSError("chmod blocked")
    module.os.fchmod=fail_chmod
elif mode == "precommit":
    def fail_existing(*_args,**_kwargs): raise module.Incomplete("precommit validation blocked")
    module.check_existing=fail_existing
elif mode == "replace":
    def fail_replace(*_args,**_kwargs): raise OSError("replace blocked")
    module.os.replace=fail_replace
elif mode == "latched": module.LATCHED_SIGNAL=signal.SIGTERM
elif mode == "pending":
    signal.pthread_sigmask(signal.SIG_BLOCK,module.SIGNALS)
    os.kill(os.getpid(),signal.SIGTERM)
fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
try:
    module.publish(fd,"artifact-registry",b"new_generation\n")
    (root/"postreplace_callback").write_text("unexpected")
except (module.Incomplete,OSError) as exc:
    if mode == "pass": print(type(exc).__name__, str(exc))
    sys.exit(1)
finally:
    os.close(fd)
`
	for _, mode := range []string{"pass", "write", "fsync", "chmod", "precommit", "replace", "latched", "pending"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-c", probe,
				remoteAlphaESServiceTLSStatusCollectorPath(), root, mode)
			cmd.Dir = executionSubstrateRepoRoot
			cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
			output, err := cmd.CombinedOutput()
			if mode == "pass" && err != nil {
				t.Fatalf("publication failed: %v\n%s", err, output)
			}
			if mode != "pass" && err == nil {
				t.Fatalf("incomplete publication succeeded: %s", output)
			}
			if len(output) != 0 {
				t.Fatalf("publication emitted output: %q", output)
			}
			canonical := filepath.Join(root, "es-service-tls-status-summary.json")
			data, err := os.ReadFile(canonical)
			if err != nil {
				t.Fatal(err)
			}
			want := "old_generation\n"
			if mode == "pass" {
				want = "new_generation\n"
			}
			if string(data) != want {
				t.Fatalf("canonical bytes = %q, want %q", data, want)
			}
			entries, err := os.ReadDir(root)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].Name() != "es-service-tls-status-summary.json" {
				t.Fatalf("publication left scratch or callback: %v", entries)
			}
		})
	}
}

func TestRemoteAlphaESServiceTLSStatusPublicationSetupFailure(t *testing.T) {
	const probe = `
import importlib.util,json,os,pathlib,stat,sys
source,root,mode=sys.argv[1:]
spec=importlib.util.spec_from_file_location("status_publish_setup",source)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
` + remoteAlphaESStatusLocalProcessBoundary + `root=pathlib.Path(root);canonical=root/"es-service-tls-status-summary.json"
canonical.write_bytes(b"old_generation\n");canonical.chmod(0o644)
module.check_extended=lambda _fd:None
real_fstat=os.fstat
def fixture_protected_file(fd,expected):
    info=real_fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=expected or info.st_nlink!=1:
        raise module.Incomplete("fixture_unsafe_file")
    return info
module.check_protected_file=fixture_protected_file
injected=[False]
def fail_first_fstat(fd):
    if not injected[0]:
        injected[0]=True
        if mode=="substitute":
            temps=[p for p in root.iterdir() if p.name.endswith(".tmp")]
            if len(temps)!=1:raise RuntimeError("temporary not created")
            temps[0].unlink();temps[0].write_bytes(b"substitute\n");temps[0].chmod(0o600)
        raise OSError("fixture initial fstat failure")
    if mode=="unprovable":raise OSError("fixture identity unprovable")
    return real_fstat(fd)
module.os.fstat=fail_first_fstat
status_fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
try:
    try:module.publish(status_fd,"artifact-registry",b"new_generation\n");failed=False
    except (module.Incomplete,OSError):failed=True
finally:
    os.close(status_fd);module.os.fstat=real_fstat
temps=[p for p in root.iterdir() if p.name.endswith(".tmp")]
owned_removed=(mode=="initial_fstat" and not temps)
substitute_kept=(mode=="substitute" and len(temps)==1 and temps[0].read_bytes()==b"substitute\n")
diagnostic_kept=(mode=="unprovable" and len(temps)==1 and stat.S_IMODE(temps[0].stat().st_mode)==0o600)
print(json.dumps({"failed":failed,"injected":injected[0],"canonical_unchanged":canonical.read_bytes()==b"old_generation\n","owned_removed":owned_removed,"substitute_kept":substitute_kept,"diagnostic_kept":diagnostic_kept,"temporary_count":len(temps)},sort_keys=True))
`
	for _, mode := range []string{"initial_fstat", "substitute", "unprovable"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-c", probe,
				remoteAlphaESServiceTLSStatusCollectorPath(), t.TempDir(), mode)
			cmd.Dir = executionSubstrateRepoRoot
			cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("publication setup probe: %v\n%s", err, output)
			}
			var result map[string]any
			if err := json.Unmarshal(output, &result); err != nil {
				t.Fatalf("publication setup result: %v\n%s", err, output)
			}
			for _, name := range []string{"failed", "injected", "canonical_unchanged"} {
				if result[name] != true {
					t.Errorf("%s = %v", name, result[name])
				}
			}
			wantCount := float64(0)
			wantFlag := "owned_removed"
			if mode == "substitute" {
				wantCount, wantFlag = 1, "substitute_kept"
			} else if mode == "unprovable" {
				wantCount, wantFlag = 1, "diagnostic_kept"
			}
			if result[wantFlag] != true || result["temporary_count"] != wantCount {
				t.Errorf("temporary disposition = %v", result)
			}
		})
	}
}

func runRemoteAlphaESStatusBootstrapCase(t *testing.T, mode string) map[string]bool {
	t.Helper()
	const probe = `
import hashlib,json,os,pathlib,pwd,re,secrets,shutil,subprocess,sys
source,root,mode=sys.argv[1:]
root=pathlib.Path(root)
parent=pathlib.Path("/private/tmp") if mode=="private_tmp" else root/"stage-parent"
if parent!=pathlib.Path("/private/tmp"):parent.mkdir();parent.chmod(0o1777)
assert parent.stat().st_mode & 0o7777 == 0o1777
shell=pathlib.Path(source).read_text()
marker="IFS= read -r -d '' bootstrap <<'REMOTE_ALPHA_ES_TLS_STATUS_BOOTSTRAP' || true\n"
start=shell.index(marker)+len(marker)
end=shell.index("\nREMOTE_ALPHA_ES_TLS_STATUS_BOOTSTRAP\n",start)
bootstrap=shell[start:end]
def replace_once(old,new):
    global bootstrap
    if bootstrap.count(old)!=1: raise RuntimeError("bootstrap fixture source drift: "+old)
    bootstrap=bootstrap.replace(old,new)
replace_once('r"/tmp/\\.es','r"'+re.escape(str(parent))+r'/\.es')
replace_once('os.open("/tmp",','os.open('+repr(str(parent))+',')
replace_once('parent.st_uid != 0 or parent.st_gid != 0',
             'parent.st_uid != '+str(parent.stat().st_uid)+' or parent.st_gid != '+str(parent.stat().st_gid))
replace_once('os.geteuid() != 0','os.geteuid() != os.getuid()')
replace_once('os.fchown(dir_fd, 0, 0)','os.fchmod(dir_fd, 0o700)')
replace_once('os.fstat(dir_fd).st_uid != 0','os.fstat(dir_fd).st_uid != operator_uid')
replace_once('os.fstat(dir_fd).st_gid != 0','os.fstat(dir_fd).st_gid != operator_gid')
replace_once('if any(attr not in ("security.selinux", "com.apple.provenance") for attr in os.listxattr(fd)):',
             'if False:')
name=".es-tls-status-"+secrets.token_hex(16)
stage=parent/name;stage.mkdir(mode=0o700);stage.chmod(0o700)
os.chown(stage,os.getuid(),os.getgid())
assert stage.stat().st_uid==os.getuid() and stage.stat().st_gid==os.getgid()
leaf=stage/"remote_alpha_es_tls_status.py"
payload=("import json,os,sys\n"
         "assert globals().get('ES_TLS_STATUS_BOOTSTRAP_VERIFIED') is True\n"
         "assert globals().get('ES_TLS_STATUS_BOOTSTRAP_INTERRUPTED') == [False]\n"
         "assert not os.path.exists("+repr(str(stage))+")\n"
         "print(json.dumps({'ran':'expected','scope':sys.argv[2]}))\n"
         "raise SystemExit(0)\n").encode()
alternate=payload.replace(b"expected",b"replaced")
assert len(payload)==len(alternate)
digest=hashlib.sha256(payload).hexdigest()
if mode in ("regular_swap","same_size","fifo","symlink"):
    leaf.write_bytes(payload);leaf.chmod(0o644)
    mode_marker="<<'REMOTE_ALPHA_ES_TLS_STATUS_MODE'\n"
    mode_start=shell.index(mode_marker)+len(mode_marker)
    mode_end=shell.index("\nREMOTE_ALPHA_ES_TLS_STATUS_MODE\n",mode_start)
    directory=stage.stat()
    verified=subprocess.run([sys.executable,"-I","-B","-",str(leaf),
                             str(directory.st_dev)+":"+str(directory.st_ino)],
                            input=shell[mode_start:mode_end].encode(),capture_output=True,timeout=2)
    if verified.returncode!=0:raise RuntimeError("pre-root stage verification failed")
    leaf.unlink()
if mode in ("fifo","safe"):
    replace_once('        entry = os.stat(basename, dir_fd=dir_fd, follow_symlinks=False)',
                 '        print("STAGED_LEAF_CHECK_REACHED",file=sys.stderr)\n'
                 '        entry = os.stat(basename, dir_fd=dir_fd, follow_symlinks=False)')
if mode=="fifo": os.mkfifo(leaf,0o600)
elif mode=="symlink":
    target=root/"alternate.py";target.write_bytes(alternate);leaf.symlink_to(target)
else:
    leaf.write_bytes(alternate if mode in ("regular_swap","same_size") else payload)
    leaf.chmod(0o600)
if leaf.is_file() and not leaf.is_symlink():
    os.chown(leaf,os.getuid(),os.getgid())
    assert leaf.stat().st_uid==os.getuid() and leaf.stat().st_gid==os.getgid()
if mode=="extra": (stage/"extra").write_bytes(b"unexpected")
if mode=="digest": digest=hashlib.sha256(alternate).hexdigest()
if mode=="post_open_swap":
    target=root/"replacement.py";target.write_bytes(alternate)
    old='            current = os.stat(basename, dir_fd=dir_fd, follow_symlinks=False)\n            if (os.fstat(dir_fd)'
    new=('            os.unlink(basename, dir_fd=dir_fd)\n'
         '            os.symlink('+repr(str(target))+', basename, dir_fd=dir_fd)\n'
         '            current = os.stat(basename, dir_fd=dir_fd, follow_symlinks=False)\n'
         '            if (os.fstat(dir_fd)')
    replace_once(old,new)
if mode=="cleanup_failure":
    replace_once('            os.unlink(basename, dir_fd=dir_fd)\n',
                 '            raise OSError("injected exact cleanup failure")\n')
info=stage.stat()
original=root/"renamed-original-stage"
def replace_stage():
    stage.rename(original)
    stage.mkdir(mode=0o700)
    os.chown(stage,os.getuid(),os.getgid())
    (stage/leaf.name).write_bytes(payload)
    (stage/leaf.name).chmod(0o600)
    os.chown(stage/leaf.name,os.getuid(),os.getgid())
if mode in ("stage_replace","stage_renamed"):
    replace_stage()
if mode=="stage_after_open_replace":
    old='        directory = os.fstat(dir_fd)\n        entry_dir = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)'
    new=('        directory = os.fstat(dir_fd)\n'
         '        os.rename('+repr(str(stage))+','+repr(str(original))+')\n'
         '        os.mkdir('+repr(str(stage))+',0o700)\n'
         '        open('+repr(str(leaf))+',"wb").write('+repr(payload)+')\n'
         '        os.chmod('+repr(str(leaf))+',0o600)\n'
         '        entry_dir = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)')
    replace_once(old,new)
if mode=="stage_before_remove_replace":
    old='            os.fchmod(dir_fd, 0o700)\n            current_dir = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)'
    new=('            os.fchmod(dir_fd, 0o700)\n'
         '            os.rename('+repr(str(stage))+','+repr(str(original))+')\n'
         '            os.mkdir('+repr(str(stage))+',0o700)\n'
         '            open('+repr(str(leaf))+',"wb").write('+repr(payload)+')\n'
         '            os.chmod('+repr(str(leaf))+',0o600)\n'
         '            current_dir = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)')
    replace_once(old,new)
env=os.environ.copy();env.update(SUDO_USER="ds",SUDO_UID=str(os.getuid()),
                                 SUDO_GID=str(os.getgid()),PYTHONDONTWRITEBYTECODE="1")
expected_dev=str(info.st_dev)
expected_ino=str(info.st_ino)
if mode=="device_mismatch":expected_dev=str(info.st_dev+1)
if mode=="inode_mismatch":expected_ino=str(info.st_ino+1)
if mode=="invalid_device":expected_dev="invalid"
if mode=="overflow_inode":expected_ino=str(2**64)
if mode=="gid_mismatch":env["SUDO_GID"]=str(os.getgid()+1)
try:
    try:
        child=subprocess.run([sys.executable,"-I","-B","-c",bootstrap,str(stage),leaf.name,digest,
                              "artifact-registry",expected_dev,expected_ino],
                             env=env,capture_output=True,timeout=2)
        bounded=True
        ran=b'"ran": "expected"' in child.stdout
        accepted=child.returncode==0
    except subprocess.TimeoutExpired:
        bounded=False;ran=False;accepted=False
    result={"bounded":bounded,"correct":(accepted and ran and not stage.exists()) if mode in ("safe","private_tmp") else
            (not accepted and not ran and stage.exists() and
             (original.exists() if mode.startswith("stage_") else True))}
    if mode in ("fifo","safe"):
        result["staged_leaf_check_reached"]=b"STAGED_LEAF_CHECK_REACHED" in child.stderr
    print(json.dumps(result,sort_keys=True))
finally:
    if stage.exists() or stage.is_symlink(): shutil.rmtree(stage)
    if original.exists():shutil.rmtree(original)
`
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-B", "-c", probe,
		remoteAlphaOperatorScriptPath(), t.TempDir(), mode)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("bootstrap %s timed out: %v", mode, ctx.Err())
	}
	if err != nil {
		t.Fatalf("bootstrap %s probe: %v\n%s", mode, err, output)
	}
	var result map[string]bool
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("bootstrap %s result: %v\n%s", mode, err, output)
	}
	return result
}

func TestRemoteAlphaESServiceTLSStatusRootLoadedStageCustody(t *testing.T) {
	for _, mode := range []string{"safe", "private_tmp", "digest", "extra", "post_open_swap", "cleanup_failure", "device_mismatch", "inode_mismatch", "invalid_device", "overflow_inode", "gid_mismatch", "stage_replace", "stage_renamed", "stage_after_open_replace", "stage_before_remove_replace"} {
		t.Run(mode, func(t *testing.T) {
			for label, ok := range runRemoteAlphaESStatusBootstrapCase(t, mode) {
				if !ok {
					t.Errorf("%s failed", label)
				}
			}
		})
	}
}

func TestRemoteAlphaESServiceTLSStatusStageRegularScriptSubstitution(t *testing.T) {
	for _, mode := range []string{"regular_swap", "same_size", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			for label, ok := range runRemoteAlphaESStatusBootstrapCase(t, mode) {
				if !ok {
					t.Errorf("%s failed", label)
				}
			}
		})
	}
}

func TestRemoteAlphaESServiceTLSStatusStageFIFOSubstitution(t *testing.T) {
	for label, ok := range runRemoteAlphaESStatusBootstrapCase(t, "fifo") {
		if !ok {
			t.Errorf("%s failed", label)
		}
	}
}

func TestRemoteAlphaESServiceTLSStatusDirectPathInvocationRefusal(t *testing.T) {
	cmd := exec.Command("/usr/bin/python3", "-I", "-B", remoteAlphaESServiceTLSStatusCollectorPath(),
		"--scope", "artifact-registry")
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	if output, err := cmd.CombinedOutput(); err == nil || len(output) != 0 {
		t.Fatalf("direct collector path did not refuse quietly: err=%v output=%q", err, output)
	}
}

func TestRemoteAlphaESServiceTLSStatusProtectedCustodyAndLocks(t *testing.T) {
	const probe = `
import importlib.util, json, os, pathlib, stat, sys
source, root = sys.argv[1:]
spec=importlib.util.spec_from_file_location("status_custody", source)
module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
` + remoteAlphaESStatusLocalProcessBoundary + `root=pathlib.Path(root); status=root/"status"; status.mkdir(mode=0o755); status.chmod(0o755)
module.check_extended=lambda _fd: None  # descriptor xattr API absent on test macOS
real_fstat=os.fstat
wrong_owner_fd=os.open(status,os.O_RDONLY|os.O_DIRECTORY)
try:
    try: module.check_protected_dir(wrong_owner_fd,0o755); wrong_owner_refused=False
    except module.Incomplete: wrong_owner_refused=True
finally: os.close(wrong_owner_fd)
def root_metadata(fd):
    s=real_fstat(fd)
    return os.stat_result((s.st_mode,s.st_ino,s.st_dev,s.st_nlink,0,0,s.st_size,s.st_atime,s.st_mtime,s.st_ctime))
module.os.fstat=root_metadata
real_stat=os.stat
def root_stat(path,*args,**kwargs):
    s=real_stat(path,*args,**kwargs)
    if str(path)!="es-service-tls-status-summary.json": return s
    return os.stat_result((s.st_mode,s.st_ino,s.st_dev,s.st_nlink,0,0,s.st_size,s.st_atime,s.st_mtime,s.st_ctime))
module.os.stat=root_stat
results={}
results["wrong_owner_refused"]=wrong_owner_refused
symlink=root/"status-link"; symlink.symlink_to(status)
try: os.open(symlink,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW); results["symlink_ancestor_refused"]=False
except OSError: results["symlink_ancestor_refused"]=True
try: os.open(root/"missing-status",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW); results["missing_dir_refused"]=False
except FileNotFoundError: results["missing_dir_refused"]=True
fd=os.open(status,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
    module.check_protected_dir(fd,0o755); results["safe_dir"]=True
    lock=module.open_scope_lock(fd,".es-service-tls-status.lock")
    try:
        try: module.open_scope_lock(fd,".es-service-tls-status.lock"); results["same_scope_contended"]=False
        except module.Incomplete: results["same_scope_contended"]=True
        other=module.open_scope_lock(fd,".es-governance-tls-status.lock")
        results["different_scope_lock"]=True
        os.close(other)
    finally: os.close(lock)
    lock_path=status/".es-service-tls-status.lock"; lock_path.unlink(); lock_path.symlink_to(root/"missing-lock")
    try: module.open_scope_lock(fd,lock_path.name); results["unsafe_lock_refused"]=False
    except module.Incomplete: results["unsafe_lock_refused"]=True
    lock_path.unlink()
    target=status/"es-service-tls-status-summary.json"; target.write_text("fixture"); target.chmod(0o644)
    module.check_existing(fd,target.name); results["safe_target"]=True
    target.chmod(0o666)
    try: module.check_existing(fd,target.name); results["unsafe_mode_refused"]=False
    except module.Incomplete: results["unsafe_mode_refused"]=True
    target.chmod(0o644)
    link=root/"extra-link"; os.link(target,link)
    try: module.check_existing(fd,target.name); results["multiple_links_refused"]=False
    except module.Incomplete: results["multiple_links_refused"]=True
    link.unlink(); target.unlink(); target.symlink_to(root/"missing")
    try: module.check_existing(fd,target.name); results["symlink_target_refused"]=False
    except module.Incomplete: results["symlink_target_refused"]=True
    target.unlink()
    status.chmod(0o775)
    try: module.check_protected_dir(fd,0o755); results["writable_dir_refused"]=False
    except module.Incomplete: results["writable_dir_refused"]=True
    status.chmod(0o755)
    module.check_extended=lambda _fd: (_ for _ in ()).throw(module.Incomplete("unknown_acl"))
    try: module.check_protected_dir(fd,0o755); results["unproved_acl_refused"]=False
    except module.Incomplete: results["unproved_acl_refused"]=True
finally: os.close(fd)
print(json.dumps(results,sort_keys=True))
`
	cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-c", probe,
		remoteAlphaESServiceTLSStatusCollectorPath(), t.TempDir())
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("custody probe: %v\n%s", err, output)
	}
	var results map[string]bool
	if err := json.Unmarshal(output, &results); err != nil {
		t.Fatalf("custody result: %v\n%s", err, output)
	}
	for key, ok := range results {
		if !ok {
			t.Fatalf("custody check %s failed", key)
		}
	}
	if len(results) != 13 {
		t.Fatalf("custody probe skipped checks: %v", results)
	}
}

func TestRemoteAlphaESServiceTLSStatusGenerationDiffersFromPreRun(t *testing.T) {
	f := setupRemoteAlphaESServiceTLSFixture(t, false)
	first := runRemoteAlphaESTLSFixture(t, f, "artifact-registry")
	prior := first["generation"].(string)
	second := runRemoteAlphaESTLSFixture(t, f, "artifact-registry", prior)
	if second["generation"] == prior || second["generation"] != strings.Repeat("f", 32) {
		t.Fatalf("new generation was not chosen after forced prior collision")
	}
}

func runRemoteAlphaCanonicalSummaryCase(t *testing.T, scope, which, mode string) map[string]bool {
	t.Helper()
	const probe = `
import importlib.util,json,os,pathlib,stat,sys
source,root,scope,which,mode=sys.argv[1:]
spec=importlib.util.spec_from_file_location("canonical_summary_probe",source)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
root=pathlib.Path(root);status=root/"status";status.mkdir(mode=0o755)
name=module.SCOPES[scope]["canonical"];target=status/name
raw=json.dumps({"schema_version":module.SCOPES[scope]["schema"],"collector_contract":module.CONTRACT,
                "finalized":True,"generation":"a"*32,"scope":scope,"route":module.SCOPES[scope]["route"]}).encode()
target.write_bytes(raw);target.chmod(0o644)
module.check_extended=lambda _fd: None
module.open_status_dir=lambda:os.open(status,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
module.validate_document=lambda _document,_scope,_prior,_now: None
real_fstat=os.fstat;real_stat=os.stat;real_open=os.open;real_read=os.read
def root_meta(s):
    return os.stat_result((s.st_mode,s.st_ino,s.st_dev,s.st_nlink,0,0,s.st_size,s.st_atime,s.st_mtime,s.st_ctime))
def root_fstat(fd):return root_meta(real_fstat(fd))
def root_stat(path,*args,**kwargs):
    s=real_stat(path,*args,**kwargs)
    return root_meta(s) if str(path)==name else s
module.os.fstat=root_fstat;module.os.stat=root_stat
if which=="publish":
    def protected_file(fd,mode):
        info=root_fstat(fd)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=mode or info.st_nlink!=1:
            raise module.Incomplete("unsafe_fixture_file")
        return info
    module.check_protected_file=protected_file
if mode=="fifo":
    target.unlink();os.mkfifo(target,0o600)
if mode=="absent": target.unlink()
swapped=[False]
def swapping_open(path,flags,*args,**kwargs):
    if str(path)==name and flags & os.O_NONBLOCK and not swapped[0]:
        if mode in ("swap_fifo","swap_symlink","swap_regular"):
            swapped[0]=True;target.unlink()
            if mode=="swap_fifo": os.mkfifo(target,0o600)
            elif mode=="swap_symlink": target.symlink_to(root/"other")
            else: target.write_bytes(json.dumps({"generation":"b"*32}).encode());target.chmod(0o644)
    return real_open(path,flags,*args,**kwargs)
module.os.open=swapping_open
changed=[False]
def changing_read(fd,count):
    block=real_read(fd,count)
    if block and not changed[0] and mode in ("short","size","inode"):
        changed[0]=True
        if mode=="short":return block[:len(block)//2]
        if mode=="size":target.write_bytes(raw+b" ")
        if mode=="inode":target.unlink();target.write_bytes(raw);target.chmod(0o644)
    return block
module.os.read=changing_read
fd=real_open(status,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
    try:
        if which=="check_existing": result=module.check_existing(fd,name)
        elif which=="preexisting_generation": result=module.preexisting_generation(fd,scope)
        elif which=="read_accepted_status": result=module.read_accepted_status(scope,"0"*32)
        elif which=="publish": result=module.publish(fd,scope,b"fresh generation\n")
        else: raise AssertionError("unknown function")
        accepted=True
    except (module.Incomplete,OSError,ValueError):
        accepted=False;result=None
finally:
    os.close(fd);module.os.open=real_open;module.os.read=real_read
expected=(accepted and (which!="preexisting_generation" or
          (result.state is module._PriorSummaryState.VALID and result.generation=="a"*32))) if mode=="valid" else (
    ((not accepted) if which=="read_accepted_status" else
     (accepted and (result.state is module._PriorSummaryState.ABSENT if which=="preexisting_generation" else result is None)))
     if mode=="absent" else not accepted)
print(json.dumps({"expected":expected,"swap_exercised":(swapped[0] if mode.startswith("swap_") else True),
                  "read_exercised":(changed[0] if mode in ("short","size","inode") else True),
                  "publication_preserved":((not target.is_file() or target.read_bytes()!=b"fresh generation\n") and
                    not list(status.glob("*.tmp"))) if which=="publish" else True},sort_keys=True))
`
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-B", "-c", probe,
		remoteAlphaESServiceTLSStatusCollectorPath(), t.TempDir(), scope, which, mode)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("canonical %s %s %s blocked: %v", scope, which, mode, ctx.Err())
	}
	if err != nil {
		t.Fatalf("canonical %s %s %s: %v\n%s", scope, which, mode, err, output)
	}
	var result map[string]bool
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("canonical result: %v\n%s", err, output)
	}
	return result
}

func TestRemoteAlphaESServiceTLSStatusPublicationExistingTargetNonblockingSafety(t *testing.T) {
	for _, scope := range []string{"artifact-registry", "execution-governance"} {
		for _, mode := range []string{"fifo", "swap_fifo", "swap_symlink", "swap_regular", "short", "size", "inode"} {
			t.Run(scope+"/"+mode, func(t *testing.T) {
				for label, ok := range runRemoteAlphaCanonicalSummaryCase(t, scope, "publish", mode) {
					if !ok {
						t.Errorf("%s failed", label)
					}
				}
			})
		}
	}
}

func TestRemoteAlphaESServiceTLSStatusCanonicalSummaryFIFORefusal(t *testing.T) {
	for _, scope := range []string{"artifact-registry", "execution-governance"} {
		for _, which := range []string{"check_existing", "preexisting_generation", "read_accepted_status"} {
			t.Run(scope+"/"+which, func(t *testing.T) {
				for label, ok := range runRemoteAlphaCanonicalSummaryCase(t, scope, which, "fifo") {
					if !ok {
						t.Errorf("%s failed", label)
					}
				}
			})
		}
	}
}

func TestRemoteAlphaESServiceTLSStatusCanonicalSummarySubstitutionRefusal(t *testing.T) {
	for _, scope := range []string{"artifact-registry", "execution-governance"} {
		for _, which := range []string{"check_existing", "preexisting_generation", "read_accepted_status"} {
			for _, mode := range []string{"swap_fifo", "swap_symlink", "swap_regular", "short", "size", "inode"} {
				t.Run(scope+"/"+which+"/"+mode, func(t *testing.T) {
					for label, ok := range runRemoteAlphaCanonicalSummaryCase(t, scope, which, mode) {
						if !ok {
							t.Errorf("%s failed", label)
						}
					}
				})
			}
		}
	}
}

func TestRemoteAlphaESServiceTLSStatusPreRunGenerationSnapshotSafety(t *testing.T) {
	for _, scope := range []string{"artifact-registry", "execution-governance"} {
		for _, mode := range []string{"valid", "absent"} {
			t.Run(scope+"/"+mode, func(t *testing.T) {
				for label, ok := range runRemoteAlphaCanonicalSummaryCase(t, scope, "preexisting_generation", mode) {
					if !ok {
						t.Errorf("%s failed", label)
					}
				}
			})
		}
	}
}

func TestRemoteAlphaESServiceTLSStatusProtectedReaderNonblockingSafety(t *testing.T) {
	for _, scope := range []string{"artifact-registry", "execution-governance"} {
		for _, mode := range []string{"valid", "absent"} {
			t.Run(scope+"/"+mode, func(t *testing.T) {
				for label, ok := range runRemoteAlphaCanonicalSummaryCase(t, scope, "read_accepted_status", mode) {
					if !ok {
						t.Errorf("%s failed", label)
					}
				}
			})
		}
	}
}

func TestRemoteAlphaESServiceTLSStatusReaderProtectedFile(t *testing.T) {
	f := setupRemoteAlphaESServiceTLSFixture(t, false)
	record := runRemoteAlphaESTLSFixture(t, f, "artifact-registry")
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	const probe = `
import importlib.util,json,os,pathlib,stat,sys
source,root,fixture=sys.argv[1:]
spec=importlib.util.spec_from_file_location("status_reader_file",source)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
` + remoteAlphaESStatusLocalProcessBoundary + `prefix="/etc/execution-substrate/"
def relocate(value):
    if isinstance(value,str) and value.startswith(prefix): return fixture+"/etc/execution-substrate/"+value[len(prefix):]
    if isinstance(value,tuple): return tuple(relocate(item) for item in value)
    if isinstance(value,dict): return {key:relocate(item) for key,item in value.items()}
    return value
module.SCOPES=relocate(module.SCOPES)
root=pathlib.Path(root);status=root/"status";status.mkdir(mode=0o755)
name=module.SCOPES["artifact-registry"]["canonical"]
target=status/name
record=json.loads(sys.stdin.read())
target.write_text(json.dumps(record));target.chmod(0o644)
module.check_extended=lambda _fd: None
real_fstat=os.fstat
def root_fstat(fd):
    s=real_fstat(fd)
    return os.stat_result((s.st_mode,s.st_ino,s.st_dev,s.st_nlink,0,0,s.st_size,s.st_atime,s.st_mtime,s.st_ctime))
module.os.fstat=root_fstat
real_stat=os.stat
def root_stat(path,*args,**kwargs):
    s=real_stat(path,*args,**kwargs)
    if str(path)!=name: return s
    return os.stat_result((s.st_mode,s.st_ino,s.st_dev,s.st_nlink,0,0,s.st_size,s.st_atime,s.st_mtime,s.st_ctime))
module.os.stat=root_stat
module.open_status_dir=lambda:os.open(status,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
results={}
def accepted():
    try: module.read_accepted_status("artifact-registry","0"*32);return True
    except (module.Incomplete,OSError,ValueError):return False
results["fresh_pass"]=accepted()
original_bytes=target.read_bytes();target.write_bytes(original_bytes+b" "*64)
real_read=os.read
def short_read(fd,count):return real_read(fd,count)[:len(original_bytes)]
module.os.read=short_read
results["short_read_refused"]=not accepted()
module.os.read=real_read;target.write_bytes(original_bytes)
target.chmod(0o666);results["unsafe_mode_refused"]=not accepted();target.chmod(0o644)
link=root/"hardlink";os.link(target,link);results["multiple_links_refused"]=not accepted();link.unlink()
module.check_extended=lambda _fd: (_ for _ in ()).throw(module.Incomplete("acl_unproved"))
results["acl_refused"]=not accepted();module.check_extended=lambda _fd: None
module.open_status_dir=lambda: (_ for _ in ()).throw(module.Incomplete("unsafe_ancestry"))
results["unsafe_ancestry_refused"]=not accepted()
module.open_status_dir=lambda:os.open(status,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
target.unlink();target.symlink_to(root/"legacy")
results["symlink_refused"]=not accepted();target.unlink()
(root/"legacy").write_text(json.dumps(record))
results["legacy_fallback_absent"]=not accepted()
print(json.dumps(results,sort_keys=True))
`
	cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-c", probe,
		remoteAlphaESServiceTLSStatusCollectorPath(), t.TempDir(), f.root)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	cmd.Stdin = strings.NewReader(string(encoded))
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("protected reader probe: %v\n%s", err, output)
	}
	var result map[string]bool
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("protected reader result: %v\n%s", err, output)
	}
	for key, ok := range result {
		if !ok {
			t.Fatalf("protected reader check %s failed", key)
		}
	}
	if len(result) != 8 {
		t.Fatalf("protected reader skipped checks: %v", result)
	}
}

func TestRemoteAlphaESServiceTLSStatusStrictJSONAndCanonicalPaths(t *testing.T) {
	for _, tc := range []struct{ scope, required, optional string }{
		{"artifact-registry", "ars", "egs"},
		{"execution-governance", "egs", "ars"},
	} {
		t.Run(tc.scope, func(t *testing.T) {
			var f *remoteAlphaESServiceTLSFixture
			if tc.scope == "artifact-registry" {
				f = setupRemoteAlphaESServiceTLSFixture(t, false)
			} else {
				f = setupRemoteAlphaESGovernanceTLSFixture(t, false)
			}
			const probe = `
import importlib.util,json,os,pathlib,stat,sys
source,root,scope,required,optional=sys.argv[1:]
spec=importlib.util.spec_from_file_location("status_strict",source)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
` + remoteAlphaESStatusLocalProcessBoundary + `root=pathlib.Path(root)
module.CONFIG={name:str(root/"etc/execution-substrate"/(name+".json")) for name in module.CONFIG}
module.check_extended=lambda _fd: None
module.check_input_ancestor=lambda info: None if stat.S_ISDIR(info.st_mode) else (_ for _ in ()).throw(module.Incomplete("ancestor"))
results={}
for name in (required,optional):
    path=pathlib.Path(module.CONFIG[name]); original=path.read_bytes()
    expected="config_malformed" if name==required else "related_config_malformed"
    for label,payload in (
        ("nan",b'{"ignored":NaN}'),("infinity",b'{"ignored":Infinity}'),
        ("negative_infinity",b'{"ignored":-Infinity}'),
        ("overflow",b'{"ignored":1e10000}'),
        ("negative_overflow",b'{"ignored":-1e10000}'),
        ("nested_overflow",b'{"ignored":{"deep":[0,{"value":1e10000}]}}'),
        ("duplicate",b'{"tls":{},"tls":{}}'),("array",b'[]'),
        ("invalid_utf8",b'{"x":"\xff"}'),("trailing",b'{} {}')):
        path.write_bytes(payload)
        results[name+"_"+label]=(module.read_config(name,name==required)[1]==expected)
    document=json.loads(original)
    document["finite_control"]={"integer":42,"decimal":1.25}
    path.write_text(json.dumps(document))
    results[name+"_finite_controls"]=(module.read_config(name,name==required)[1]=="pass")
    path.write_bytes(original)
    document=json.loads(original)
    section="tls"
    key="cert_file"
    base=document[section][key]
    aliases=(base.replace("/","/./",1),base.replace("/","/../",1),
             base.replace("/","//",1),base+"/",base+"\x00")
    for index,alias in enumerate(aliases):
        document[section][key]=alias
        path.write_text(json.dumps(document))
        results[name+"_alias_"+str(index)]=(module.read_config(name,name==required)[1]==expected)
    path.write_bytes(original)
optional_path=pathlib.Path(module.CONFIG[optional]);original=optional_path.read_bytes()
covered=module.SCOPES[scope]["certs"][0][1]
optional_path.write_text(json.dumps({"tls":{"cert_file":covered.replace("/etc/","/etc/./",1)}}))
topology=module.collect_topology(module.SCOPES[scope])
results["covered_alias_disjoint"]=next(item for item in topology if item["id"]=="related_service_tls_disjoint")["code"]=="related_config_malformed"
if scope=="execution-governance":
    optional_path.write_text(json.dumps({"dependencies":{"artifact_registry":{"client_cert_file":covered.replace("/etc/","/etc/./",1)}}}))
    topology=module.collect_topology(module.SCOPES[scope])
    results["covered_dependency_alias_disjoint"]=next(item for item in topology if item["id"]=="related_dependency_tls_disjoint")["code"]=="related_config_malformed"
optional_path.write_bytes(original)
print(json.dumps(results,sort_keys=True))
`
			cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-c", probe,
				remoteAlphaESServiceTLSStatusCollectorPath(), f.root, tc.scope, tc.required, tc.optional)
			cmd.Dir = executionSubstrateRepoRoot
			cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("strict JSON and paths probe: %v\n%s", err, output)
			}
			var results map[string]bool
			if err := json.Unmarshal(output, &results); err != nil {
				t.Fatalf("strict JSON and paths result: %v\n%s", err, output)
			}
			want := 33
			if tc.scope == "execution-governance" {
				want = 34
			}
			if len(results) != want {
				t.Fatalf("missing strict cases: %v", results)
			}
			for label, ok := range results {
				if !ok {
					t.Errorf("%s accepted malformed input", label)
				}
			}
		})
	}
}

func TestRemoteAlphaESServiceTLSStatusStrictJSONDepthPolicy(t *testing.T) {
	const probe = `
import importlib.util,json,os,pathlib,stat,sys
source,root,mode,scope,valid_path=sys.argv[1:]
spec=importlib.util.spec_from_file_location("status_depth",source)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
root=pathlib.Path(root);results={}
def nested(depth,kind):
    value="0"
    for index in range(depth):
        container=kind if kind!="mixed" else ("object" if index%2 else "array")
        value='{"x":'+value+'}' if container=="object" else '['+value+']'
    return value.encode()
def depth_rejected(raw):
    try: module.strict_json(raw)
    except module.StrictJSONDepthRejected: return True
    return False
def json_rejected(raw):
    try: module.strict_json(raw)
    except module.StrictJSONRejected: return True
    return False
if mode=="boundary":
    results["constant"]=(module.MAX_JSON_CONTAINER_DEPTH==64)
    for kind in ("object","array","mixed"):
        results[kind+"64"]=not depth_rejected(nested(64,kind))
        results[kind+"65"]=depth_rejected(nested(65,kind))
    results["nested994"]=depth_rejected(nested(994,"array"))
    results["nested3000"]=depth_rejected(nested(3000,"array"))
    results["shallow"]=(module.strict_json(b'{"tls":{}}')=={"tls":{}})
    results["finite_int_decimal"]=(module.strict_json(b'{"integer":42,"decimal":1.25}')=={"integer":42,"decimal":1.25})
    controls={
      "overflow_pos":b'{"x":1e10000}',"overflow_neg":b'{"x":-1e10000}',
      "nested_overflow":b'{"x":{"y":[1e10000]}}',
      "nan":b'{"x":NaN}',"inf":b'{"x":Infinity}',"neg_inf":b'{"x":-Infinity}',
      "duplicate":b'{"x":0,"x":1}',"invalid_utf8":b'{"x":"\xff"}',
      "trailing":b'{} {}'}
    for label,raw in controls.items(): results[label]=json_rejected(raw)
    module.open_fixed_regular=lambda path,limit:b'[]'
    results["nonobject_config"]=(module.read_config("ags",True)[1]=="config_malformed")
elif mode=="config":
    chosen=module.SCOPES[scope]
    configs={name:{} for name in module.CONFIG}
    def put(name,keys,value):
        node=configs[name]
        for key in keys[:-1]: node=node.setdefault(key,{})
        node[keys[-1]]=value
    for _label,name,keys,value in chosen["bindings"]: put(name,keys,value)
    for _label,name,keys,port in chosen["urls"]: put(name,keys,"https://127.0.0.1:"+str(port))
    payloads={name:json.dumps(config).encode() for name,config in configs.items()}
    names={path:name for name,path in module.CONFIG.items()}
    module.open_fixed_regular=lambda path,limit:payloads[names[path]]
    baseline=module.collect_topology(chosen)
    results["baseline"]=all(item["status"]=="pass" for item in baseline)
    required="ags"
    payloads[required]=nested(65,"object")
    results["required_code"]=(module.read_config(required,True)[1]=="config_malformed")
    checks={item["id"]:item for item in module.collect_topology(chosen)}
    results["required_record"]=(checks[required+"_config"]["status"]=="fail" and checks[required+"_config"]["code"]=="config_malformed")
    results["required_dependent"]=(checks["related_service_tls_disjoint"]["code"]=="related_config_malformed")
    blockers={item["code"] for item in checks.values() if item["status"]=="fail"}
    results["required_blockers"]=("config_malformed" in blockers and "related_config_malformed" in blockers)
    results["required_no_pass"]=bool(blockers)
    payloads[required]=json.dumps(configs[required]).encode()
    optional=next(name for name in module.CONFIG if name not in chosen["required_config"])
    payloads[optional]=nested(65,"array")
    results["optional_code"]=(module.read_config(optional,False)[1]=="related_config_malformed")
    checks={item["id"]:item for item in module.collect_topology(chosen)}
    related=checks[optional+"_related_config"]
    results["optional_record"]=(related["status"]=="fail" and related["code"]=="related_config_malformed")
    results["optional_dependent"]=(checks["related_service_tls_disjoint"]["code"]=="related_config_malformed")
    results["optional_not_absent"]=(related["code"]!="absent")
    results["optional_no_pass"]=any(item["status"]=="fail" for item in checks.values())
    results["optional_dependency"]=(scope!="execution-governance" or checks["related_dependency_tls_disjoint"]["code"]=="related_config_malformed")
elif mode=="summary":
    status=root/"status";status.mkdir(mode=0o755)
    name=module.SCOPES[scope]["canonical"];target=status/name
    old_generation="a"*32
    old=b'{"generation":"'+old_generation.encode()+b'","padding":'+nested(64,"array")+b'}'
    target.write_bytes(old);target.chmod(0o644)
    old_inode=target.stat().st_ino
    module.check_extended=lambda fd:None
    real_fstat=os.fstat;real_stat=os.stat;real_open=os.open
    def root_meta(info):
        return os.stat_result((info.st_mode,info.st_ino,info.st_dev,info.st_nlink,0,0,info.st_size,info.st_atime,info.st_mtime,info.st_ctime))
    def root_fstat(fd):return root_meta(real_fstat(fd))
    def root_stat(path,*args,**kwargs):
        info=real_stat(path,*args,**kwargs)
        return root_meta(info) if str(path)==name else info
    module.os.fstat=root_fstat;module.os.stat=root_stat
    module.open_status_dir=lambda:real_open(status,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    module.open_scope_lock=lambda fd,name:real_open(status,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    module.validate_process_capability=lambda:None
    module.collect=lambda *args:(_ for _ in ()).throw(AssertionError("collection after depth rejection"))
    module.publish=lambda *args:(_ for _ in ()).throw(AssertionError("publication after depth rejection"))
    module.ES_TLS_STATUS_BOOTSTRAP_VERIFIED=True
    module.ES_TLS_STATUS_BOOTSTRAP_INTERRUPTED=[False]
    fd=real_open(status,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        snapshot=module.preexisting_generation(fd,scope)
        results["prior_rejected"]=(snapshot.state is module._PriorSummaryState.INVALID_OR_UNACCEPTED)
    finally: os.close(fd)
    results["main_incomplete"]=(module.main(["--scope",scope])==1)
    results["prior_bytes"]=(target.read_bytes()==old)
    results["prior_inode"]=(target.stat().st_ino==old_inode)
    results["no_replacement"]=(sorted(path.name for path in status.iterdir())==[name])
    try: module.read_accepted_status(scope,"0"*32);results["reader_rejected"]=False
    except module.Incomplete: results["reader_rejected"]=True
    # The exact production schema has no field that can carry 64 containers.
    # Isolate the protected reader's JSON layer, then restore semantic validation.
    depth64=b'{"generation":"'+old_generation.encode()+b'","padding":'+nested(63,"array")+b'}'
    target.write_bytes(depth64)
    real_validate=module.validate_document
    module.validate_document=lambda *args:None
    try:
        decoded=module.read_accepted_status(scope,"0"*32)
        results["reader_depth64_json_layer"]=(decoded["generation"]==old_generation and "padding" in decoded)
    finally: module.validate_document=real_validate
    fixture_root=pathlib.Path(valid_path).parent
    fixed={
      "/etc/execution-substrate/ars-tls":str(fixture_root/"etc/execution-substrate/ars-tls"),
      "/etc/execution-substrate/egs-tls":str(fixture_root/"etc/execution-substrate/egs-tls"),
      "/etc/execution-substrate/es-tls":str(fixture_root/"etc/execution-substrate/es-tls"),
      "/etc/execution-substrate/tls":str(fixture_root/"etc/execution-substrate/tls"),
      "/etc/execution-substrate/":str(fixture_root/"etc/execution-substrate")+"/"}
    def relocate(value):
        if isinstance(value,str):
            for old,new in fixed.items():
                if value.startswith(old):return new+value[len(old):]
            return value
        if isinstance(value,tuple):return tuple(relocate(item) for item in value)
        if isinstance(value,dict):return {key:relocate(item) for key,item in value.items()}
        return value
    module.SCOPES=relocate(module.SCOPES)
    valid=pathlib.Path(valid_path).read_bytes()
    target.write_bytes(valid)
    fd=real_open(status,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        snapshot=module.preexisting_generation(fd,scope)
        results["valid_snapshot"]=(snapshot.state is module._PriorSummaryState.VALID and
                                   snapshot.generation==json.loads(valid)["generation"])
    finally: os.close(fd)
    accepted=module.read_accepted_status(scope,"0"*32)
    results["valid_reader"]=(accepted["generation"]==json.loads(valid)["generation"])
    results["valid_schema"]=(accepted["schema_version"]==module.SCOPES[scope]["schema"])
    module.os.fstat=real_fstat;module.os.stat=real_stat
else: raise AssertionError("unknown mode")
print(json.dumps(results,sort_keys=True))
`
	run := func(t *testing.T, mode, scope, validPath string, expected []string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-B", "-c", probe,
			remoteAlphaESServiceTLSStatusCollectorPath(), t.TempDir(), mode, scope, validPath)
		cmd.Dir = executionSubstrateRepoRoot
		cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
		output, err := cmd.CombinedOutput()
		if ctx.Err() != nil {
			t.Fatalf("%s %s exceeded bounded completion: %v", mode, scope, ctx.Err())
		}
		if err != nil || strings.Contains(string(output), "Traceback") || strings.Contains(string(output), "RecursionError") {
			t.Fatalf("%s %s leaked or failed: %v\n%s", mode, scope, err, output)
		}
		var results map[string]bool
		if err := json.Unmarshal(output, &results); err != nil {
			t.Fatalf("%s %s result: %v\n%s", mode, scope, err, output)
		}
		if len(results) != len(expected) {
			t.Fatalf("%s %s skipped checks: %v", mode, scope, results)
		}
		for _, key := range expected {
			t.Run(key, func(t *testing.T) {
				if !results[key] {
					t.Errorf("%s %s %s failed", mode, scope, key)
				}
			})
		}
	}
	t.Run("boundary", func(t *testing.T) {
		run(t, "boundary", "-", "-", []string{
			"constant", "object64", "object65", "array64", "array65", "mixed64", "mixed65",
			"nested994", "nested3000", "shallow", "finite_int_decimal", "overflow_pos",
			"overflow_neg", "nested_overflow", "nan", "inf", "neg_inf", "duplicate",
			"invalid_utf8", "trailing", "nonobject_config",
		})
	})
	for _, scope := range []string{"artifact-registry", "execution-governance"} {
		t.Run(scope, func(t *testing.T) {
			t.Run("config", func(t *testing.T) {
				run(t, "config", scope, "-", []string{
					"baseline", "required_code", "required_record", "required_dependent",
					"required_blockers", "required_no_pass", "optional_code",
					"optional_record", "optional_dependent", "optional_not_absent",
					"optional_no_pass", "optional_dependency",
				})
			})
			t.Run("summary", func(t *testing.T) {
				var f *remoteAlphaESServiceTLSFixture
				if scope == "artifact-registry" {
					f = setupRemoteAlphaESServiceTLSFixture(t, false)
				} else {
					f = setupRemoteAlphaESGovernanceTLSFixture(t, false)
				}
				record := runRemoteAlphaESTLSFixture(t, f, scope)
				valid, err := json.Marshal(record)
				if err != nil {
					t.Fatal(err)
				}
				validPath := filepath.Join(f.root, "valid-summary.json")
				if err := os.WriteFile(validPath, valid, 0o600); err != nil {
					t.Fatal(err)
				}
				run(t, "summary", scope, validPath, []string{
					"prior_rejected", "main_incomplete", "prior_bytes", "prior_inode",
					"no_replacement", "reader_rejected", "reader_depth64_json_layer", "valid_snapshot",
					"valid_reader", "valid_schema",
				})
			})
		})
	}
}

func TestRemoteAlphaESServiceTLSStatusPriorSummaryInvalidPrecedence(t *testing.T) {
	const probe = `
import copy,datetime as dt,importlib.util,json,os,pathlib,stat,sys
source,root,scope_name=sys.argv[1:]
spec=importlib.util.spec_from_file_location("prior_precedence_fixture",source)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
root=pathlib.Path(root);status=root/"status";status.mkdir(mode=0o755)
scope=module.SCOPES[scope_name];name=scope["canonical"];target=status/name
old_generation="a"*32;new_generation="b"*32;hash64="c"*64
module.check_extended=lambda _fd:None
real_fstat=os.fstat;real_stat=os.stat;real_open=os.open
def root_meta(info):
    return os.stat_result((info.st_mode,info.st_ino,info.st_dev,info.st_nlink,0,0,
                           info.st_size,info.st_atime,info.st_mtime,info.st_ctime))
module.os.fstat=lambda fd:root_meta(real_fstat(fd))
def root_stat(path,*args,**kwargs):
    info=real_stat(path,*args,**kwargs)
    return root_meta(info) if str(path)==name else info
module.os.stat=root_stat
module.open_status_dir=lambda:real_open(status,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
module.open_scope_lock=lambda _fd,_name:real_open(status,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
module.validate_process_capability=lambda:None
module.ES_TLS_STATUS_BOOTSTRAP_VERIFIED=True
module.ES_TLS_STATUS_BOOTSTRAP_INTERRUPTED=[False]
module.collect_topology=lambda chosen:[{"id":identifier,"status":"pass","code":"pass"}
                                       for identifier in module.expected_topology_ids(chosen)]
def valid_cert(item,observed):
    label,path,role,_,_=item
    before=(observed-dt.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    after=(observed+dt.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return ({"label":label,"path":path,"role":role,"status":"pass","code":"pass",
             "not_before":before,"not_after":after,"expired":False,"not_yet_valid":False,
             "sha256":hash64,"fingerprint_sha256":hash64,"public_key_sha256":hash64,
             "subject_sha256":hash64,"issuer_sha256":hash64,
             "san_match":True if role=="server" else None,
             "eku_match":None if role=="ca" else True},b"fixture")
def missing_cert(item,_observed):
    label,path,role,_,_=item
    record={"label":label,"path":path,"role":role,"status":"fail","code":"certificate_missing"}
    record.update({field:None for field in
                   ("not_before","not_after","expired","not_yet_valid","sha256",
                    "fingerprint_sha256","public_key_sha256","subject_sha256",
                    "issuer_sha256","san_match","eku_match")})
    return record,None
module.cert_role=valid_cert
module.key_pair=lambda label,_cert,_path:{"label":label,"status":"pass","code":"pass","matches":True}
module.verify_chain=lambda label,_ca,_cert,_cab,_certb,purpose,hostname:{
    "label":label,"status":"pass","code":"pass","purpose":purpose,"hostname":hostname}
module.secrets.token_hex=lambda _n:old_generation
pass_record=module.collect(scope_name)
pass_raw=module.encode_document(pass_record,scope_name)
module.cert_role=missing_cert
module.key_pair=lambda label,_cert,_path:{"label":label,"status":"fail","code":"certificate_unavailable","matches":False}
module.verify_chain=lambda label,_ca,_cert,_cab,_certb,purpose,hostname:{
    "label":label,"status":"fail","code":"certificate_unavailable","purpose":purpose,"hostname":hostname}
fail_record=module.collect(scope_name)
fail_raw=module.encode_document(fail_record,scope_name)
module.cert_role=valid_cert
module.key_pair=lambda label,_cert,_path:{"label":label,"status":"pass","code":"pass","matches":True}
module.verify_chain=lambda label,_ca,_cert,_cab,_certb,purpose,hostname:{
    "label":label,"status":"pass","code":"pass","purpose":purpose,"hostname":hostname}
def changed(**fields):
    record=copy.deepcopy(pass_record);record.update(fields)
    return json.dumps(record,sort_keys=True,separators=(",",":")).encode()
def extra(raw,*fields):
    return raw.rstrip()[:-1]+b","+b",".join(fields)+b"}"
deep=b"["*64+b"0"+b"]"*64
decoder_deep=b"["*3000+b"0"+b"]"*3000
stale=changed(checked_at="2020-01-01T00:00:00Z")
missing_generation=copy.deepcopy(pass_record);del missing_generation["generation"]
missing_generation=json.dumps(missing_generation,sort_keys=True,separators=(",",":")).encode()
wrong_schema=changed(schema_version="wrong.schema")
cases=[
    ("absent",None,"ABSENT"),
    ("valid",pass_raw,"VALID"),
    ("stale",stale,"VALID"),
    ("completed_fail",fail_raw,"VALID"),
    ("depth65",extra(pass_raw,b'"deep":'+deep),"INVALID_OR_UNACCEPTED"),
    ("overflow_positive",extra(pass_raw,b'"overflow":1e10000'),"INVALID_OR_UNACCEPTED"),
    ("overflow_negative",extra(pass_raw,b'"overflow":-1e10000'),"INVALID_OR_UNACCEPTED"),
    ("literal_nan",extra(pass_raw,b'"constant":NaN'),"INVALID_OR_UNACCEPTED"),
    ("literal_infinity",extra(pass_raw,b'"constant":Infinity'),"INVALID_OR_UNACCEPTED"),
    ("literal_negative_infinity",extra(pass_raw,b'"constant":-Infinity'),"INVALID_OR_UNACCEPTED"),
    ("duplicate",extra(pass_raw,b'"duplicate":0',b'"duplicate":1'),"INVALID_OR_UNACCEPTED"),
    ("invalid_utf8",extra(pass_raw,b'"bad":"\xff"'),"INVALID_OR_UNACCEPTED"),
    ("trailing",pass_raw+b" {}","INVALID_OR_UNACCEPTED"),
    ("nonobject",b"[]","INVALID_OR_UNACCEPTED"),
    ("decoder_exhaustion",extra(pass_raw,b'"deep":'+decoder_deep),"INVALID_OR_UNACCEPTED"),
    ("missing_generation",missing_generation,"INVALID_OR_UNACCEPTED"),
    ("malformed_generation",changed(generation=42),"INVALID_OR_UNACCEPTED"),
    ("wrong_schema",wrong_schema,"INVALID_OR_UNACCEPTED"),
    ("wrong_scope",changed(scope="wrong-scope"),"INVALID_OR_UNACCEPTED"),
    ("wrong_collector",changed(collector_contract="wrong-collector"),"INVALID_OR_UNACCEPTED"),
    ("wrong_route",changed(route="wrong-route"),"INVALID_OR_UNACCEPTED"),
    ("not_finalized",changed(finalized=False),"INVALID_OR_UNACCEPTED"),
    ("depth_then_overflow",extra(pass_raw,b'"deep":'+deep,b'"overflow":1e10000'),"INVALID_OR_UNACCEPTED"),
    ("overflow_then_depth",extra(pass_raw,b'"overflow":1e10000',b'"deep":'+deep),"INVALID_OR_UNACCEPTED"),
    ("duplicate_before_depth",extra(pass_raw,b'"duplicate":0',b'"duplicate":1',b'"deep":'+deep),"INVALID_OR_UNACCEPTED"),
    ("duplicate_after_depth",extra(pass_raw,b'"deep":'+deep,b'"duplicate":0',b'"duplicate":1'),"INVALID_OR_UNACCEPTED"),
    ("depth_then_trailing",extra(pass_raw,b'"deep":'+deep)+b" {}","INVALID_OR_UNACCEPTED"),
    ("overflow_bad_generation",extra(changed(generation="z"*32),b'"overflow":1e10000'),"INVALID_OR_UNACCEPTED"),
    ("wrong_schema_depth",extra(wrong_schema,b'"deep":'+deep),"INVALID_OR_UNACCEPTED"),
]
real_collect=module.collect
module.subprocess.Popen=lambda *_args,**_kwargs:(_ for _ in ()).throw(AssertionError("OpenSSL spawn"))
results={}
for label,raw,expected_state in cases:
    if target.exists():target.unlink()
    if raw is not None:
        target.write_bytes(raw);target.chmod(0o644)
        before=target.stat()
    else:before=None
    fd=real_open(status,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:snapshot=module.preexisting_generation(fd,scope_name)
    finally:os.close(fd)
    state_ok=(snapshot.state.name==expected_state and
              snapshot.generation==(old_generation if expected_state=="VALID" else None))
    if expected_state=="INVALID_OR_UNACCEPTED":
        state_ok=state_ok and bool(snapshot.reason_class)
    events=[];published=[]
    def track_collect(name,previous):
        events.append(("collect",previous))
        if expected_state=="INVALID_OR_UNACCEPTED":
            raise AssertionError("real collection entry reached after invalid prior summary")
        return real_collect(name,previous)
    def track_publish(_fd,_name,payload):
        events.append(("publish",None));published.append(json.loads(payload))
    module.collect=track_collect;module.publish=track_publish
    tokens=iter((old_generation,new_generation))
    module.secrets.token_hex=lambda _n:next(tokens)
    exit_code=module.main(["--scope",scope_name])
    after=target.stat() if target.exists() else None
    unchanged=(before is None and after is None) or (
        before is not None and after is not None and target.read_bytes()==raw and
        (before.st_dev,before.st_ino,before.st_mode,before.st_size,before.st_mtime_ns)==
        (after.st_dev,after.st_ino,after.st_mode,after.st_size,after.st_mtime_ns))
    no_temporary=not any(path.name.endswith(".tmp") for path in status.iterdir())
    if expected_state=="INVALID_OR_UNACCEPTED":
        lifecycle=(not events and not published)
    else:
        prior=old_generation if expected_state=="VALID" else None
        lifecycle=(events==[("collect",prior),("publish",None)] and len(published)==1 and
                   published[0]["generation"]!=prior)
    results[label]=(state_ok and exit_code==1 and unchanged and no_temporary and lifecycle)
    module.collect=real_collect
print(json.dumps(results,sort_keys=True))
`
	expected := []string{
		"absent", "valid", "stale", "completed_fail",
		"depth65", "overflow_positive", "overflow_negative", "literal_nan",
		"literal_infinity", "literal_negative_infinity", "duplicate", "invalid_utf8",
		"trailing", "nonobject", "decoder_exhaustion", "missing_generation",
		"malformed_generation", "wrong_schema", "wrong_scope", "wrong_collector",
		"wrong_route", "not_finalized", "depth_then_overflow", "overflow_then_depth",
		"duplicate_before_depth", "duplicate_after_depth", "depth_then_trailing",
		"overflow_bad_generation", "wrong_schema_depth",
	}
	for _, scope := range []string{"artifact-registry", "execution-governance"} {
		t.Run(scope, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-B", "-c", probe,
				remoteAlphaESServiceTLSStatusCollectorPath(), t.TempDir(), scope)
			cmd.Dir = executionSubstrateRepoRoot
			cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
			output, err := cmd.CombinedOutput()
			if ctx.Err() != nil || err != nil || strings.Contains(string(output), "Traceback") ||
				strings.Contains(string(output), "RecursionError") {
				t.Fatalf("%s prior-summary precedence probe failed: %v %v\n%s", scope, ctx.Err(), err, output)
			}
			var results map[string]bool
			if err := json.Unmarshal(output, &results); err != nil {
				t.Fatalf("%s prior-summary precedence result: %v\n%s", scope, err, output)
			}
			if len(results) != len(expected) {
				t.Fatalf("%s prior-summary precedence omitted cases: %v", scope, results)
			}
			for _, label := range expected {
				t.Run(label, func(t *testing.T) {
					if !results[label] {
						t.Errorf("%s prior-summary precedence failed", label)
					}
				})
			}
		})
	}
}

func TestRemoteAlphaESServiceTLSStatusSafeAbsenceUnsafeAncestry(t *testing.T) {
	const probe = `
import importlib.util,json,os,pathlib,stat,sys
source,root=sys.argv[1:]
spec=importlib.util.spec_from_file_location("status_ancestry",source)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
` + remoteAlphaESStatusLocalProcessBoundary + `root=pathlib.Path(root);safe=root/"safe";safe.mkdir();(safe/"good.pem").write_bytes(b"fixture")
module.check_extended=lambda _fd: None
module.check_input_ancestor=lambda info: None if stat.S_ISDIR(info.st_mode) else (_ for _ in ()).throw(module.Incomplete("ancestor"))
def result(path):
    try: module.open_fixed_regular(str(path),module.MAX_INPUT);return "read"
    except module._VerifiedFinalLeafAbsent:return "missing"
    except module.Incomplete:return "incomplete"
    except OSError:return "incomplete"
results={"safe_leaf_absent":result(safe/"absent.pem")=="missing"}
(safe/"leaf-link.pem").symlink_to(safe/"good.pem")
results["symlink_leaf"]=result(safe/"leaf-link.pem")=="incomplete"
(root/"ancestor-link").symlink_to(safe)
results["symlink_ancestor"]=result(root/"ancestor-link"/"absent.pem")=="incomplete"
(root/"not-directory").write_bytes(b"x")
results["non_directory_ancestor"]=result(root/"not-directory"/"absent.pem")=="incomplete"
original=module.check_input_ancestor
module.check_input_ancestor=lambda _info: (_ for _ in ()).throw(module.Incomplete("metadata"))
results["metadata_failure"]=result(safe/"good.pem")=="incomplete"
module.check_input_ancestor=original
original_same=module.same_entry
module.same_entry=lambda *_args: (_ for _ in ()).throw(module.Incomplete("race"))
results["race"]=result(safe/"good.pem")=="incomplete"
print(json.dumps(results,sort_keys=True))
`
	cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-c", probe,
		remoteAlphaESServiceTLSStatusCollectorPath(), t.TempDir())
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("safe absence probe: %v\n%s", err, output)
	}
	var results map[string]bool
	if err := json.Unmarshal(output, &results); err != nil {
		t.Fatalf("safe absence result: %v\n%s", err, output)
	}
	if len(results) != 6 {
		t.Fatalf("missing safe absence cases: %v", results)
	}
	for label, ok := range results {
		if !ok {
			t.Errorf("%s had wrong absence semantics", label)
		}
	}
}

func TestRemoteAlphaESServiceTLSStatusExactOpenSSLArgvAndSelectedAnchor(t *testing.T) {
	const probe = `
import importlib.util,json,os,pathlib,sys
source,root=sys.argv[1:]
spec=importlib.util.spec_from_file_location("status_exact_verify",source)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
` + remoteAlphaESStatusLocalProcessBoundary + `root=pathlib.Path(root);child=root/"fake-openssl";log=root/"child.json"
child.write_text('''#!/usr/bin/python3
import json,os,sys
argv=sys.argv[1:]
ca=open(argv[2],"rb").read(); leaf=sys.stdin.buffer.read()
with open('''+repr(str(log))+''',"w") as output:
    json.dump({"argv":argv,"env":dict(os.environ),"ca":ca.decode(),"leaf":leaf.decode()},output)
if ca == b"selected CA" and leaf == b"selected leaf":
    sys.stdout.write("/dev/stdin: OK\\n")
else:
    sys.stderr.write("CN=fixture.internal\\nerror 20 at 0 depth lookup: unable to get local issuer certificate\\nerror /dev/stdin: verification failed\\n")
    sys.exit(2)
''')
child.chmod(0o700)
module.OPENSSL=str(child)
os.environ["SSL_CERT_FILE"]="/hostile/default/ca.pem";os.environ["SSL_CERT_DIR"]="/hostile/default/ca-dir"
os.environ["OPENSSL_MODULES"]="/hostile/modules";os.environ["OPENSSL_ENGINES"]="/hostile/engines"
original_popen=module.subprocess.Popen;spawn_env=[]
def capture_popen(*args,**kwargs):
    spawn_env.append(dict(kwargs["env"]))
    return original_popen(*args,**kwargs)
module.subprocess.Popen=capture_popen
ca={"sha256":"a"*64};leaf={"sha256":"b"*64}
good=module.verify_chain("fixture",ca,leaf,b"selected CA",b"selected leaf","sslserver","fixture.internal")
seen=json.loads(log.read_text())
expected=["verify","-trusted",seen["argv"][2],"-purpose","sslserver","-verify_hostname","fixture.internal","/dev/stdin"]
results={"exact_argv":seen["argv"]==expected and seen["argv"][2].startswith("/dev/fd/"),
         "exact_bytes":seen["ca"]=="selected CA" and seen["leaf"]=="selected leaf",
         "fixed_environment":spawn_env==[module.CHILD_ENV],
         "ambient_excluded":not any(key in seen["env"] for key in ("SSL_CERT_FILE","SSL_CERT_DIR","OPENSSL_MODULES","OPENSSL_ENGINES")),
         "selected_success":good["code"]=="pass"}
wrong=module.verify_chain("fixture",ca,leaf,b"wrong CA",b"selected leaf","sslserver","fixture.internal")
results["wrong_selected_anchor_fails"]=wrong["code"]=="chain_failed" and spawn_env==[module.CHILD_ENV,module.CHILD_ENV]
print(json.dumps(results,sort_keys=True))
`
	cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-c", probe,
		remoteAlphaESServiceTLSStatusCollectorPath(), t.TempDir())
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("exact OpenSSL argv probe: %v\n%s", err, output)
	}
	var results map[string]bool
	if err := json.Unmarshal(output, &results); err != nil {
		t.Fatalf("exact OpenSSL argv result: %v\n%s", err, output)
	}
	if len(results) != 6 {
		t.Fatalf("missing exact OpenSSL checks: %v", results)
	}
	for label, ok := range results {
		if !ok {
			t.Errorf("%s failed", label)
		}
	}
}

func TestRemoteAlphaESServiceTLSStatusMaterialByteBinding(t *testing.T) {
	f := setupRemoteAlphaESServiceTLSFixture(t, false)
	const probe = `
import hashlib,importlib.util,json,os,pathlib,stat,sys
source,root=sys.argv[1:]
spec=importlib.util.spec_from_file_location("status_binding",source)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
` + remoteAlphaESStatusLocalProcessBoundary + `root=pathlib.Path(root);ars=root/"etc/execution-substrate/ars-tls";ags=root/"etc/execution-substrate/tls"
module.check_extended=lambda _fd: None
cert=ars/"ars-server-cert.pem";key=ars/"ars-server-key.pem"
old_cert=cert.read_bytes();new_cert=(ags/"ags-client-cert.pem").read_bytes()
old_key=key.read_bytes();new_key=(ags/"ags-client-key.pem").read_bytes()
module.check_input_ancestor=lambda info: None if stat.S_ISDIR(info.st_mode) else (_ for _ in ()).throw(module.Incomplete("ancestor"))
original=module.open_fixed_regular;swapped=set()
def read_then_swap(path,limit,read_content=True):
    raw=original(path,limit,read_content)
    if path==str(cert) and path not in swapped:
        cert.write_bytes(new_cert);swapped.add(path)
    if path==str(key) and path not in swapped:
        key.write_bytes(new_key);swapped.add(path)
    return raw
module.open_fixed_regular=read_then_swap
record,raw=module.cert_role(("ars_server",str(cert),"server","server.artifact-registry.internal","server"))
pair=module.key_pair("ars_server",record,str(key))
results={"certificate_swapped":cert.read_bytes()==new_cert,
         "hash_bound":record["sha256"]==hashlib.sha256(old_cert).hexdigest() and raw==old_cert,
         "role_bound":record["san_match"] is True and record["eku_match"] is True,
         "key_swapped":key.read_bytes()==new_key,
         "key_bound":pair["code"]=="pass"}
print(json.dumps(results,sort_keys=True))
`
	cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-c", probe,
		remoteAlphaESServiceTLSStatusCollectorPath(), f.root)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("byte binding probe: %v\n%s", err, output)
	}
	var results map[string]bool
	if err := json.Unmarshal(output, &results); err != nil {
		t.Fatalf("byte binding result: %v\n%s", err, output)
	}
	if len(results) != 5 {
		t.Fatalf("missing byte binding checks: %v", results)
	}
	for label, ok := range results {
		if !ok {
			t.Errorf("%s failed", label)
		}
	}
}

// The fixed child of this fixture exits at once and leaves one descendant in
// its process group. The collector's cleanup holds until no process of that
// group is visible, and a killed process stays visible until its parent reaps
// it. So the descendant keeps a parent of its own: a keeper that leaves the
// group before the cleanup can start, because it holds the child's output
// pipes until then. As an orphan the descendant would wait for whatever
// process adopts orphans on the host, and a host that reaps them on a slow
// timer would decide the result.
// The descendant ignores SIGTERM before it closes those pipes, so that the
// cleanup always has to go on to SIGKILL.
//
// The keeper reaps the killed descendant only when the fixture lets it: it
// waits until the fixture closes its end of a FIFO. Until then the killed
// descendant stays in the group, where the host shows a dead process that has
// not been reaped. The fixture lets go once it has seen the cleanup wait for
// that process. Three things must have happened in this order: a SIGKILL was
// delivered to the descendant; the cleanup left the bounded wait behind that
// SIGKILL, which shows when it delivers a further signal or reaps the fixed
// child; and the cleanup then read the descendant's identity twice and found
// it in the group both times. The reads inside the bounded wait do not count,
// because a cleanup that trusts a delivered SIGKILL makes them too and stops
// waiting right after them. When the fixture lets go, the cleanup must not
// have returned and must still hold its lock. A cleanup that returns sooner
// leaves the descendant held and in the group, which fails the case, so no
// result depends on how long a step takes. Where the host does not show such
// a process, the cleanup has nothing to wait for and the case runs as it
// would with a keeper that reaps at once. In either case the fixture checks
// that the keeper still held the descendant when it let go.
func runRemoteAlphaESStatusGroupFailureCase(t *testing.T, mode string) map[string]bool {
	t.Helper()
	const probe = `
import fcntl,importlib.util,json,os,pathlib,signal,subprocess,sys,threading,time
source,root,mode=sys.argv[1:]
spec=importlib.util.spec_from_file_location("group_failure_fixture",source)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
root=pathlib.Path(root);child=root/"fixed-openssl";pidfile=root/"desc.pid";canonical=root/"canonical.json"
canonical.write_bytes(b"previous generation\n")
child.write_text("#!/usr/bin/python3\nimport os,signal,sys,time\n"
                 "def close_std():\n    for fd in (0,1,2):\n        try:os.close(fd)\n        except OSError:pass\n"
                 "if os.fork()==0:\n    pid=os.fork()\n    if pid==0:\n"
                 "        signal.signal(signal.SIGTERM,signal.SIG_IGN);close_std();time.sleep(3);os._exit(0)\n"
                 "    os.setpgid(0,0);hold=os.open(sys.argv[1]+'.release',os.O_RDONLY|os.O_NONBLOCK);os.set_blocking(hold,True)\n"
                 "    open(sys.argv[1],'w').write(str(pid));close_std()\n"
                 "    try:os.read(hold,1)\n    except OSError:pass\n"
                 "    try:os.waitpid(pid,0)\n    except OSError:pass\n"
                 "    os._exit(0)\n")
child.chmod(0o700);module.OPENSSL=str(child);module.CHILD_TIMEOUT=2.5;module.CHILD_GRACE=.15
module.validate_process_capability=lambda: None
module.PROCESS_CAPABILITY_READY=True
real_popen=module.subprocess.Popen;real_killpg=os.killpg;real_listdir=os.listdir
unrelated=real_popen([sys.executable,"-I","-B","-c","import time;time.sleep(3)"],start_new_session=True)
spawned=[];signaled=[];pins={};post_reap=[False];gate=threading.Event();transient=[False];identity_reads=[0];poll_faults=[0]
stage=[0];looks=[0];waiting=[False];early=[False];kept=[None];released=[False];seen=threading.Event();release_lock=threading.Lock()
release_path=str(pidfile)+".release";os.mkfifo(release_path,0o600)
reader=os.open(release_path,os.O_RDONLY|os.O_NONBLOCK);release_fd=os.open(release_path,os.O_WRONLY);os.close(reader)
if mode=="poll_hold":
    class FaultTime:
        monotonic=staticmethod(time.monotonic)
        @staticmethod
        def sleep(seconds):
            if not gate.is_set():
                poll_faults[0]+=1
                raise RuntimeError("persistent cleanup polling failure")
            time.sleep(seconds)
    module.time=FaultTime
def track(*args,**kwargs):
    proc=real_popen(*args,**kwargs);spawned.append(proc);return proc
module.subprocess.Popen=track
def descendant():return int(pidfile.read_text()) if pidfile.exists() else -1
def identity(pid):
    if mode=="identity_once" and pid==descendant():
        identity_reads[0]+=1
        if identity_reads[0]==2:raise RuntimeError("one-shot identity revalidation failure")
    if spawned and pid==spawned[0].pid and not getattr(spawned[0],"_status_reaped",False):
        return spawned[0].pid,1  # WNOWAIT reserves the fixture leader
    try:return os.getpgid(pid),1
    except ProcessLookupError:return None
def in_group(pid):
    try:return pid>0 and bool(spawned) and os.getpgid(pid)==spawned[0].pid
    except ProcessLookupError:return False
def unreaped(pid):
    if pid<=0:return False
    try:os.kill(pid,0)
    except OSError:return False
    return True
def release():
    with release_lock:
        if not released[0]:
            kept[0]=unreaped(descendant());released[0]=True;os.close(release_fd)
def delivered(signum):
    # 0: no SIGKILL delivered yet. 1: the first one was. 2: the cleanup has
    # left the bounded wait behind it.
    if stage[0]>=1:stage[0]=2
    elif signum==signal.SIGKILL:stage[0]=1
def collector_identity(pid):
    result=identity(pid)
    if stage[0]==1 and spawned and getattr(spawned[0],"_status_reaped",False):stage[0]=2
    if pid==descendant() and stage[0]==2 and not released[0] and spawned and result==(spawned[0].pid,1):
        looks[0]+=1
        if looks[0]>=2:waiting[0]=True;seen.set()
    return result
module.read_proc_identity=collector_identity
def listdir(path):
    if path=="/proc":
        if mode in ("scan_once","scan_plain_once") and not transient[0]:
            transient[0]=True;raise RuntimeError("one-shot membership scan failure")
        if mode=="post_reap_scan_once" and spawned and getattr(spawned[0],"_status_reaped",False) and not transient[0]:
            transient[0]=True;raise RuntimeError("one-shot post-reap membership scan failure")
        if mode=="scan_hold" and not gate.is_set():
            raise RuntimeError("persistent membership scan failure")
        if not spawned:return []
        if mode=="member_error_continue":return [str(spawned[0].pid),str(descendant()),str(unrelated.pid)]
        return [str(descendant()),str(spawned[0].pid),str(unrelated.pid)]
    return real_listdir(path)
module.os.listdir=listdir
def pidfd_open(pid,flags=0):
    if mode=="pidfd_once" and pid==descendant() and not transient[0]:
        transient[0]=True;raise RuntimeError("one-shot pidfd acquisition failure")
    if identity(pid) is None:raise ProcessLookupError()
    fd=os.open("/dev/null",os.O_RDONLY|os.O_CLOEXEC);pins[fd]=(pid,identity(pid));return fd
def pidfd_signal(fd,signum,_info=None,_flags=0):
    pid,observed=pins[fd]
    if identity(pid)!=observed:raise ProcessLookupError()
    if spawned and getattr(spawned[0],"_status_reaped",False):post_reap[0]=True
    if pid==spawned[0].pid and module.leader_terminal(spawned[0]):
        if mode=="member_error_continue":raise OSError("terminal leader pidfd signal error")
        raise ProcessLookupError()
    if mode in ("hold","poll_hold") and not gate.is_set():raise OSError("member signal unavailable")
    if mode=="transient" and not transient[0]:transient[0]=True;raise OSError("transient member failure")
    signaled.append(pid);os.kill(pid,signum)
    if pid==descendant():delivered(signum)
module.os.pidfd_open=pidfd_open;module.signal.pidfd_send_signal=pidfd_signal
real_prove_absent=module.prove_group_absent
def prove_absent(pgid):
    if mode=="report_once" and not transient[0]:
        transient[0]=True;raise RuntimeError("one-shot cleanup-state reporting failure")
    return real_prove_absent(pgid)
module.prove_group_absent=prove_absent
def killpg(pgid,signum):
    if signum in (signal.SIGTERM,signal.SIGKILL):
        if spawned and getattr(spawned[0],"_status_reaped",False):post_reap[0]=True
        if mode=="term" and signum==signal.SIGTERM:raise OSError("group TERM failure")
        if mode in ("both","transient","hold","poll_hold","member_error_continue","scan_once","scan_hold","pidfd_once","identity_once","report_once"):raise OSError("group signal failure")
    result=real_killpg(pgid,signum)
    delivered(signum)
    return result
module.os.killpg=killpg
outcome=[None]
lock_path=root/"scope.lock"
def run():
    lock_fd=os.open(lock_path,os.O_RDWR|os.O_CREAT,0o600)
    fcntl.flock(lock_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    try:
        try:module.run_fixed((str(child),str(pidfile)));outcome[0]="complete"
        except module.Incomplete:outcome[0]="incomplete"
        except BaseException as exc:outcome[0]=type(exc).__name__
        with release_lock:early[0]=not released[0] and in_group(descendant())
    finally:os.close(lock_fd);seen.set()
thread=threading.Thread(target=run,daemon=True)
try:
    thread.start();deadline=time.monotonic()+2
    while not pidfile.exists() and time.monotonic()<deadline:time.sleep(.01)
    if not pidfile.exists():raise RuntimeError("descendant did not spawn; outcome="+str(outcome[0])+" spawned="+str(len(spawned)))
    if mode in ("hold","scan_hold","poll_hold"):
        time.sleep(.35);held=thread.is_alive() and outcome[0] is None and canonical.read_bytes()==b"previous generation\n"
        observer=os.open(lock_path,os.O_RDWR)
        try:
            try:fcntl.flock(observer,fcntl.LOCK_EX|fcntl.LOCK_NB);lock_held=False
            except BlockingIOError:lock_held=True
        finally:os.close(observer)
        gate.set()
    else:held=True;lock_held=True
    seen.wait(2);still=locked=True
    if waiting[0]:
        still=thread.is_alive() and outcome[0] is None
        observer=os.open(lock_path,os.O_RDWR)
        try:
            try:fcntl.flock(observer,fcntl.LOCK_EX|fcntl.LOCK_NB);locked=False
            except BlockingIOError:locked=True
        finally:os.close(observer)
        release()
    thread.join(2)
    pid=descendant()
    # A briefly reparented zombie can answer kill(pid, 0) after its fixed
    # process group is gone. Check the identity-backed group disposition.
    remaining=identity(pid)
    gone=remaining is None or remaining[0]!=spawned[0].pid
    release()
    try:os.waitpid(spawned[0].pid,os.WNOHANG);reaped=False
    except ChildProcessError:reaped=True
    print(json.dumps({"returned":not thread.is_alive() and outcome[0]=="incomplete", "held":held,
        "lock_held":lock_held,
        "descendant_gone":gone,"leader_reaped":reaped,
        "keeper_held_descendant":kept[0] is True,
        "no_return_while_member_visible":not early[0] and (not waiting[0] or (still and locked)),
        "member_fallback":(pid in signaled)==(mode not in ("scan_plain_once","post_reap_scan_once")),
        "only_same_group":unrelated.pid not in signaled,"no_post_reap_signal":not post_reap[0],
        "prior_unchanged":canonical.read_bytes()==b"previous generation\n",
        "bounded_fault_retries":poll_faults[0]<30},sort_keys=True))
finally:
    gate.set()
    if pidfile.exists() and spawned:
        try:
            pid=descendant()
            if os.getpgid(pid)==spawned[0].pid:os.kill(pid,signal.SIGKILL)
        except ProcessLookupError:pass
    release()
    unrelated.terminate();unrelated.wait(timeout=2)
`
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-B", "-c", probe,
		remoteAlphaESServiceTLSStatusCollectorPath(), t.TempDir(), mode)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("group %s fixture timed out: %v", mode, ctx.Err())
	}
	if err != nil {
		t.Fatalf("group %s fixture: %v\n%s", mode, err, output)
	}
	var result map[string]bool
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("group %s result: %v\n%s", mode, err, output)
	}
	return result
}

func TestRemoteAlphaESServiceTLSStatusCombinedGroupSignalFailureLiveDescendant(t *testing.T) {
	for _, mode := range []string{"term", "both", "transient", "member_error_continue"} {
		t.Run(mode, func(t *testing.T) {
			for label, ok := range runRemoteAlphaESStatusGroupFailureCase(t, mode) {
				if !ok {
					t.Errorf("%s failed", label)
				}
			}
		})
	}
}

func TestRemoteAlphaESServiceTLSStatusUnresolvedCleanupHold(t *testing.T) {
	for _, mode := range []string{"hold", "scan_hold", "poll_hold"} {
		t.Run(mode, func(t *testing.T) {
			for label, ok := range runRemoteAlphaESStatusGroupFailureCase(t, mode) {
				if !ok {
					t.Errorf("%s failed", label)
				}
			}
		})
	}
}

func TestRemoteAlphaESServiceTLSStatusCleanupRuntimeExceptionHold(t *testing.T) {
	for _, mode := range []string{"scan_once", "scan_plain_once", "pidfd_once", "identity_once", "report_once", "post_reap_scan_once"} {
		t.Run(mode, func(t *testing.T) {
			for label, ok := range runRemoteAlphaESStatusGroupFailureCase(t, mode) {
				if !ok {
					t.Errorf("%s failed", label)
				}
			}
		})
	}
}

func TestRemoteAlphaESServiceTLSStatusProcessCapabilityUnavailableBeforeSpawn(t *testing.T) {
	const probe = `
import importlib.util,json,sys
spec=importlib.util.spec_from_file_location("status_capability",sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
spawned=[False]
module.validate_process_capability=lambda: (_ for _ in ()).throw(module.Incomplete("capability_unavailable"))
module.subprocess.Popen=lambda *_a,**_k: spawned.__setitem__(0,True)
try:module.run_fixed((module.OPENSSL,"version"));refused=False
except module.Incomplete:refused=True
print(json.dumps({"refused":refused,"not_spawned":not spawned[0]}))
`
	cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-c", probe,
		remoteAlphaESServiceTLSStatusCollectorPath())
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("capability probe: %v\n%s", err, output)
	}
	var result map[string]bool
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("capability result: %v\n%s", err, output)
	}
	for label, ok := range result {
		if !ok {
			t.Errorf("%s failed", label)
		}
	}
}

func TestRemoteAlphaESServiceTLSStatusFixedCapabilityProbe(t *testing.T) {
	const probe = `
import importlib.util,json,os,signal,sys
spec=importlib.util.spec_from_file_location("status_capability_backend",sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class Backend:
    def __init__(self,mode):
        self.mode=mode;self.pid=123456;self.live=False;self.reaped=False
        self.forked=0;self.waited=0;self.nonreaping=0;self.signaled=0
        self.wnowait=None if mode=="missing_wnowait" else 0x1000000
        self.p_pid=1;self.wexited=4;self.wnohang=1
        self.pidfd_open=None if mode=="missing_pidfd" else self.open_pidfd
        self.pidfd_send_signal=self.send_pidfd
        self.terminal=None if mode=="missing_waitid" else self.waitid_terminal
    def pipe(self):return (10,11)
    def close(self,fd):pass
    def write(self,fd,raw):return len(raw)
    def fork(self):self.forked+=1;self.live=True;return self.pid
    def open_pidfd(self,pid,flags=0):
        assert pid==self.pid and self.live
        return 12
    def send_pidfd(self,fd,signum,info=None,flags=0):
        assert fd==12 and signum in (0,signal.SIGKILL)
        self.signaled+=1
        if signum==signal.SIGKILL:self.live=False
    def read_identity(self,pid):
        assert pid==self.pid
        return (7,9) if self.live else None
    def scan_members(self,pgid):
        assert pgid==7
        return [(self.pid,9)] if self.live else []
    def waitid_terminal(self,pid):
        assert pid==self.pid
        self.nonreaping+=1
        if self.mode=="broken_nonreaping":self.live=False
        return True
    def waitpid(self,pid,flags):
        assert pid==self.pid
        self.waited+=1
        if self.mode=="broken_nonreaping":raise ChildProcessError()
        if self.mode=="reap_failure" and self.waited==1:raise RuntimeError("first reap failed")
        self.live=False;self.reaped=True
        return (pid,0)
    def kill(self,pid,signum):
        assert pid==self.pid and signum==signal.SIGKILL
        self.signaled+=1
        self.live=False
results={}
for mode in ("success","missing_waitid","missing_wnowait","missing_pidfd",
             "broken_nonreaping","reap_failure"):
    backend=Backend(mode)
    try:module.validate_process_capability(backend);accepted=True
    except module.Incomplete:accepted=False
    results[mode]=(accepted==(mode=="success") and
                   (backend.reaped or not backend.forked or mode=="broken_nonreaping") and
                   (backend.nonreaping>0 if mode=="success" else True) and
                   (backend.signaled>0 if mode=="success" else True))
    if mode=="missing_pidfd":
        original=module.validate_process_capability
        module.validate_process_capability=lambda: original(backend)
        spawned=[False]
        module.subprocess.Popen=lambda *_a,**_k: spawned.__setitem__(0,True)
        try:module.run_fixed((module.OPENSSL,"version"));results["failed_preflight_no_openssl"]=False
        except module.Incomplete:results["failed_preflight_no_openssl"]=not spawned[0]
        module.validate_process_capability=original
print(json.dumps(results,sort_keys=True))
`
	cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-c", probe,
		remoteAlphaESServiceTLSStatusCollectorPath())
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fixed capability probe: %v\n%s", err, output)
	}
	var results map[string]bool
	if err := json.Unmarshal(output, &results); err != nil {
		t.Fatalf("fixed capability result: %v\n%s", err, output)
	}
	if len(results) != 7 {
		t.Fatalf("missing capability cases: %v", results)
	}
	for label, ok := range results {
		if !ok {
			t.Errorf("%s failed", label)
		}
	}
}

func TestRemoteAlphaESServiceTLSStatusInvocationCapabilityPreflightCardinality(t *testing.T) {
	const probe = `
import importlib.util,json,os,pathlib,sys
source,root=sys.argv[1:]
spec=importlib.util.spec_from_file_location("status_invocation_probe",source)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
module.ES_TLS_STATUS_BOOTSTRAP_VERIFIED=True
module.ES_TLS_STATUS_BOOTSTRAP_INTERRUPTED=[False]
module.open_status_dir=lambda:os.open(root,os.O_RDONLY|os.O_DIRECTORY)
module.open_scope_lock=lambda _fd,_name:os.open(os.devnull,os.O_RDONLY)
events=[]
module.preexisting_generation=lambda _fd,_scope:(events.append("summary_read") or module._PriorSummarySnapshot(module._PriorSummaryState.ABSENT))
module.encode_document=lambda _record,_scope:b"{}"
module.publish=lambda *_args:(_ for _ in ()).throw(module.Incomplete("fixture_stop_before_publication"))
original_run_fixed=module.run_fixed
spawns=[]
module.subprocess.Popen=lambda *_a,**_k:spawns.append(True)
results={}
try:original_run_fixed((module.OPENSSL,"version"));results["guard_without_state"]=False
except module.Incomplete:results["guard_without_state"]=not spawns
for scope in ("artifact-registry","execution-governance"):
    for mode in ("success","failure"):
        events.clear();spawns.clear();probes=[0]
        def validate():
            probes[0]+=1;events.append("probe")
            if mode=="failure":raise module.Incomplete("probe_failed")
        def fixed(_argv,*_args):
            if not module.PROCESS_CAPABILITY_READY:raise AssertionError("missing invocation state")
            events.append("openssl")
            return 0,b"",b""
        module.validate_process_capability=validate
        module.run_fixed=fixed
        module.collect=lambda _scope,_previous:(module.run_fixed((module.OPENSSL,"one")),module.run_fixed((module.OPENSSL,"two")),{})[-1]
        before=len(os.listdir("/dev/fd"))
        status=module.main(["--scope",scope])
        after=len(os.listdir("/dev/fd"))
        key=scope+"_"+mode
        if mode=="success":
            results[key]=(status==1 and events==["probe","summary_read","openssl","openssl"] and probes==[1] and not module.PROCESS_CAPABILITY_READY and not spawns and before==after)
        else:
            results[key]=(status==1 and events==["probe"] and probes==[1] and not module.PROCESS_CAPABILITY_READY and not spawns and before==after)
print(json.dumps(results,sort_keys=True))
`
	cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-c", probe,
		remoteAlphaESServiceTLSStatusCollectorPath(), t.TempDir())
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("invocation preflight fixture: %v\n%s", err, output)
	}
	var results map[string]bool
	if err := json.Unmarshal(output, &results); err != nil {
		t.Fatalf("preflight result: %v\n%s", err, output)
	}
	if len(results) != 5 {
		t.Fatalf("missing preflight scenarios: %v", results)
	}
	for label, ok := range results {
		if !ok {
			t.Errorf("%s failed", label)
		}
	}
}

func TestRemoteAlphaESServiceTLSStatusSignalingWaitFailureCleanup(t *testing.T) {
	const probe = `
import importlib.util,json,os,pathlib,signal,subprocess,sys
source,root,mode=sys.argv[1:]
spec=importlib.util.spec_from_file_location("status_signaling",source)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
` + remoteAlphaESStatusLocalProcessBoundary + `root=pathlib.Path(root);child=root/"sleep-openssl";canonical=root/"canonical.json"
canonical.write_bytes(b"old generation\n")
child.write_text('#!/usr/bin/python3\nimport signal,time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\ntime.sleep(10)\n')
child.chmod(0o700);module.OPENSSL=str(child);module.CHILD_TIMEOUT=0.2;module.CHILD_GRACE=0.2
spawned=[];original_popen=module.subprocess.Popen;original_killpg=module.os.killpg
post_reap_signal=[False]
def track(*args,**kwargs):
    proc=original_popen(*args,**kwargs);spawned.append(proc)
    if mode=="wait":
        original=proc.wait;seen=[False]
        def bad_wait(*a,**k):
            if not seen[0]:seen[0]=True;raise OSError("injected wait")
            return original(*a,**k)
        proc.wait=bad_wait
    if mode=="poll":proc.poll=lambda: (_ for _ in ()).throw(OSError("injected poll"))
    return proc
module.subprocess.Popen=track
def tracked_killpg(pid,sig):
    if sig in (signal.SIGTERM,signal.SIGKILL) and spawned and spawned[0].returncode is not None:
        post_reap_signal[0]=True
    if mode in ("term","kill") and sig==(signal.SIGTERM if mode=="term" else signal.SIGKILL):
        raise OSError("injected signal")
    return original_killpg(pid,sig)
module.os.killpg=tracked_killpg
try:
    try:module.run_fixed((str(child),));incomplete=False
    except module.Incomplete:incomplete=True
finally:module.os.killpg=original_killpg
reaped=False;gone=False;group_gone=False
if spawned:
    proc=spawned[0]
    try:os.waitpid(proc.pid,os.WNOHANG)
    except ChildProcessError:reaped=True
    try:os.kill(proc.pid,0)
    except ProcessLookupError:gone=True
    try:os.killpg(proc.pid,0)
    except ProcessLookupError:group_gone=True
print(json.dumps({"incomplete":incomplete,"spawned_once":len(spawned)==1,"reaped":reaped,"gone":gone,"group_gone":group_gone,"no_post_reap_signal":not post_reap_signal[0],"previous_generation":canonical.read_bytes()==b"old generation\n"},sort_keys=True))
`
	for _, mode := range []string{"term", "kill", "wait", "poll"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-c", probe,
				remoteAlphaESServiceTLSStatusCollectorPath(), t.TempDir(), mode)
			cmd.Dir = executionSubstrateRepoRoot
			cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("signaling cleanup probe: %v\n%s", err, output)
			}
			var results map[string]bool
			if err := json.Unmarshal(output, &results); err != nil {
				t.Fatalf("signaling cleanup result: %v\n%s", err, output)
			}
			for label, ok := range results {
				if !ok {
					t.Errorf("%s failed", label)
				}
			}
		})
	}
}

func TestRemoteAlphaESServiceTLSStatusPostExitDescendantContainment(t *testing.T) {
	const probe = `
import importlib.util,json,os,pathlib,signal,subprocess,sys,time
source,root,mode=sys.argv[1:]
spec=importlib.util.spec_from_file_location("status_descendant",source)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
# Local generated fixtures inject the target-only process capability boundary.
module.validate_process_capability=lambda: None
module.PROCESS_CAPABILITY_READY=True
module.signal_same_group_members=lambda pgid,signum: os.kill(pgid,signum)
root=pathlib.Path(root);child=root/"fake-openssl";descendant=root/"descendant.pid";canonical=root/"canonical.json"
canonical.write_bytes(b"previous generation\n")
def fixture_identity(pid):
    if spawned and pid==spawned[0].pid:
        return (pid,1) if not getattr(spawned[0],"_status_reaped",False) else None
    try:group=os.getpgid(pid)
    except ProcessLookupError:return None
    if spawned and pid!=spawned[0].pid:
        state=subprocess.run(["/bin/ps","-o","stat=","-p",str(pid)],
                             capture_output=True,timeout=1).stdout.strip()
        if not state or state.startswith(b"Z"):return None
    return group,1
def fixture_members(pgid):
    pids=[pgid]
    if descendant.exists():pids.append(int(descendant.read_text()))
    return [(pid,1) for pid in pids if fixture_identity(pid)==(pgid,1)]
module.read_proc_identity=fixture_identity
module.scan_group_members=fixture_members
child.write_text('''#!/usr/bin/python3
import os,sys,time
pid=os.fork()
if pid==0:
    for fd in (0,1,2):
        try: os.close(fd)
        except OSError: pass
    time.sleep(2)
    os._exit(0)
open(sys.argv[1],"w").write(str(pid))
''')
child.chmod(0o700);module.OPENSSL=str(child);module.CHILD_TIMEOUT=1;module.CHILD_GRACE=.3
spawned=[];calls=[];injected=[False];post_reap_signal=[False]
original_popen=module.subprocess.Popen;original_killpg=module.os.killpg
def track_popen(*args,**kwargs):
    proc=original_popen(*args,**kwargs);spawned.append(proc);return proc
module.subprocess.Popen=track_popen
original_terminal=module.leader_terminal
def fail_after_exit(proc):
    terminal=original_terminal(proc)
    if mode=="post_exit" and terminal and not injected[0]:
        injected[0]=True
        proc.returncode=0  # observed terminal status must not skip group disposition
        raise OSError("injected post-exit lifecycle failure")
    return terminal
module.leader_terminal=fail_after_exit
original_reap=module.reap_child
def fail_after_reap(proc):
    code=original_reap(proc)
    if mode=="post_reap" and not injected[0]:
        injected[0]=True
        raise OSError("injected post-reap wait failure")
    return code
module.reap_child=fail_after_reap
def track_group(pgid,signum):
    calls.append((pgid,signum))
    if not spawned or pgid!=spawned[0].pid:
        raise AssertionError("nonfixture process group targeted")
    if signum in (signal.SIGTERM,signal.SIGKILL) and getattr(spawned[0],"_status_reaped",False):
        post_reap_signal[0]=True
    return original_killpg(pgid,signum)
module.os.killpg=track_group
try:
    try: module.run_fixed((str(child),str(descendant)));incomplete=False
    except module.Incomplete: incomplete=True
finally:
    module.os.killpg=original_killpg
pid=int(descendant.read_text())
gone=fixture_identity(pid)!=(spawned[0].pid,1)
if not gone:
    os.kill(pid,signal.SIGKILL)  # only the fixture-owned descendant
reaped=False
try: os.waitpid(spawned[0].pid,os.WNOHANG)
except ChildProcessError: reaped=True
print(json.dumps({"incomplete":incomplete,"injected":injected[0],"only_fixture_group":all(p==spawned[0].pid for p,_ in calls),
                  "group_disposition_attempted":any(s in (signal.SIGTERM,signal.SIGKILL) for _,s in calls),
                  "descendant_gone":gone,"leader_reaped":reaped,"no_post_reap_signal":not post_reap_signal[0],
                  "previous_unchanged":canonical.read_bytes()==b"previous generation\n"},sort_keys=True))
`
	for _, mode := range []string{"post_exit", "post_reap"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-B", "-c", probe,
				remoteAlphaESServiceTLSStatusCollectorPath(), t.TempDir(), mode)
			cmd.Dir = executionSubstrateRepoRoot
			cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
			output, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("descendant fixture timed out: %v", ctx.Err())
			}
			if err != nil {
				t.Fatalf("descendant fixture: %v\n%s", err, output)
			}
			var result map[string]bool
			if err := json.Unmarshal(output, &result); err != nil {
				t.Fatalf("descendant result: %v\n%s", err, output)
			}
			for label, ok := range result {
				if !ok {
					t.Errorf("%s false", label)
				}
			}
		})
	}
}

func TestRemoteAlphaESServiceTLSStatusZombieLeaderGroupDisposition(t *testing.T) {
	const probe = `
import importlib.util,json,os,pathlib,signal,sys
source,root=sys.argv[1:]
spec=importlib.util.spec_from_file_location("status_zombie_group",source)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
` + remoteAlphaESStatusLocalProcessBoundary + `child=pathlib.Path(root)/"fake-openssl"
child.write_text('#!/usr/bin/python3\nimport sys\nsys.stdout.write("fixed output")\n')
child.chmod(0o700);module.OPENSSL=str(child);module.CHILD_GRACE=.2
spawned=[];signals=[];original_popen=module.subprocess.Popen;original_killpg=module.os.killpg
def track_popen(*args,**kwargs):
    proc=original_popen(*args,**kwargs);spawned.append(proc);return proc
module.subprocess.Popen=track_popen
def zombie_visible(pgid,signum):
    if not spawned or pgid!=spawned[0].pid: raise AssertionError("wrong group")
    if signum==0 and spawned[0].returncode is None:
        return None  # fixture for a kernel that reports the zombie leader as a group member
    if signum in (signal.SIGTERM,signal.SIGKILL):
        signals.append(spawned[0].returncode is None)
    return original_killpg(pgid,signum)
module.os.killpg=zombie_visible
try:
    code,out,err=module.run_fixed((str(child),))
finally:
    module.os.killpg=original_killpg
print(json.dumps({"completed":(code,out,err)==(0,b"fixed output",b""),
                  "signals_before_reap":bool(signals) and all(signals),
                  "leader_reaped":spawned[0].returncode==0},sort_keys=True))
`
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-B", "-c", probe,
		remoteAlphaESServiceTLSStatusCollectorPath(), t.TempDir())
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("zombie group fixture timed out: %v", ctx.Err())
	}
	if err != nil {
		t.Fatalf("zombie group fixture: %v\n%s", err, output)
	}
	var result map[string]bool
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("zombie group result: %v\n%s", err, output)
	}
	for label, ok := range result {
		if !ok {
			t.Errorf("%s false", label)
		}
	}
}

func TestRemoteAlphaESServiceTLSStatusSelectedAnchorOnlyTrust(t *testing.T) {
	f := setupRemoteAlphaESServiceTLSFixture(t, false)
	now := time.Now().UTC()
	wrongCA, _, _ := remoteAlphaGenerateCA(t, now.Add(-time.Hour), now.Add(24*time.Hour))
	wrongPath := filepath.Join(f.root, "wrong-selected-ca.pem")
	writeFile(t, wrongPath, wrongCA, 0o600)
	const probe = `
import importlib.util,json,os,pathlib,sys
source,root,wrong=sys.argv[1:]
spec=importlib.util.spec_from_file_location("status_trust",source)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
` + remoteAlphaESStatusLocalProcessBoundary + `root=pathlib.Path(root)
correct=(root/"etc/execution-substrate/ars-tls/runtime-ca.pem").read_bytes()
client=(root/"etc/execution-substrate/tls/ags-client-cert.pem").read_bytes()
wrong=pathlib.Path(wrong).read_bytes()
argv=(module.OPENSSL,"verify","-trusted",module.TRUST_FD_OPERAND,"-purpose","sslclient","/dev/stdin")
os.environ["SSL_CERT_FILE"]=str(root/"etc/execution-substrate/ars-tls/runtime-ca.pem")
os.environ["SSL_CERT_DIR"]=str(root/"etc/execution-substrate/ars-tls")
good=module.run_fixed(argv,client,correct)
bad=module.run_fixed(argv,client,wrong)
module.CHILD_ENV=module.CHILD_ENV | {"SSL_CERT_FILE":os.environ["SSL_CERT_FILE"],"SSL_CERT_DIR":os.environ["SSL_CERT_DIR"]}
ambient=module.run_fixed(argv,client,wrong)
print(json.dumps({"good_selected_anchor":good==(0,b"/dev/stdin: OK\n",b""),
                  "wrong_selected_anchor":bad[0]!=0 and b"/dev/stdin: OK" not in bad[1],
                  "hostile_ambient_cannot_rescue":ambient[0]!=0 and b"/dev/stdin: OK" not in ambient[1]},sort_keys=True))
`
	cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-c", probe,
		remoteAlphaESServiceTLSStatusCollectorPath(), f.root, wrongPath)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("selected-anchor trust probe: %v\n%s", err, output)
	}
	var results map[string]bool
	if err := json.Unmarshal(output, &results); err != nil {
		t.Fatalf("selected-anchor trust result: %v\n%s", err, output)
	}
	if len(results) != 3 {
		t.Fatalf("missing trust checks: %v", results)
	}
	for label, ok := range results {
		if !ok {
			t.Errorf("%s failed", label)
		}
	}
}

func TestRemoteAlphaESServiceTLSStatusSingleSelectedTrustAnchorCardinality(t *testing.T) {
	const probe = `
import importlib.util,json,os,pathlib,stat,sys
source,selected,wrong,key,leaf=sys.argv[1:]
spec=importlib.util.spec_from_file_location("status_single_anchor",source)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
` + remoteAlphaESStatusLocalProcessBoundary + `module.check_extended=lambda _fd: None
module.check_input_ancestor=lambda info: None if stat.S_ISDIR(info.st_mode) else (_ for _ in ()).throw(module.Incomplete("ancestor"))
selected=pathlib.Path(selected);correct=selected.read_bytes();wrong=pathlib.Path(wrong).read_bytes();key=pathlib.Path(key).read_bytes()
cases={"single":correct,"surrounding_whitespace":b" \t\r\n"+correct+b"\v\f ",
       "first_wrong_second_correct":wrong+correct,"first_correct_second_wrong":correct+wrong,
       "duplicate":correct+correct,"certificate_plus_key":correct+key,
       "trailing_text":correct+b"not whitespace", "zero_anchor":b" \t\n"}
results={}
for name,content in cases.items():
    selected.write_bytes(content)
    record,raw=module.cert_role(("fixture",str(selected),"ca",None,None))
    if name in ("single","surrounding_whitespace"):
        results[name]=record["code"]=="pass" and raw==content and record["sha256"] is not None
    else:
        results[name]=(record["code"]=="trust_anchor_count_mismatch" and record["status"]=="fail" and
                       raw is None and all(record[k] is None for k in ("sha256","fingerprint_sha256","public_key_sha256","not_before","not_after")))
selected.write_bytes(correct)
print(json.dumps(results,sort_keys=True))
`
	for _, scope := range []string{"artifact-registry", "execution-governance"} {
		t.Run(scope, func(t *testing.T) {
			var f *remoteAlphaESServiceTLSFixture
			base, leaf := "ars-tls", "tls/ags-client-cert.pem"
			if scope == "artifact-registry" {
				f = setupRemoteAlphaESServiceTLSFixture(t, false)
			} else {
				f = setupRemoteAlphaESGovernanceTLSFixture(t, false)
				base, leaf = "egs-tls", "es-tls/execution-governance-client-cert.pem"
			}
			selected := filepath.Join(f.root, "etc", "execution-substrate", base, "runtime-ca.pem")
			correct, err := os.ReadFile(selected)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			wrong, _, _ := remoteAlphaGenerateCA(t, now.Add(-time.Hour), now.Add(24*time.Hour))
			wrongPath := filepath.Join(f.root, "wrong-ca.pem")
			keyPath := filepath.Join(f.root, "etc", "execution-substrate", base, strings.TrimSuffix(strings.ReplaceAll(base, "-tls", ""), "")+"-server-key.pem")
			if scope == "execution-governance" {
				keyPath = filepath.Join(f.egsTLSDir, "egs-server-key.pem")
			}
			writeFile(t, wrongPath, wrong, 0o600)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-B", "-c", probe,
				remoteAlphaESServiceTLSStatusCollectorPath(), selected, wrongPath, keyPath,
				filepath.Join(f.root, "etc", "execution-substrate", leaf))
			cmd.Dir = executionSubstrateRepoRoot
			cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
			output, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("anchor probe timed out: %v", ctx.Err())
			}
			if err != nil {
				t.Fatalf("anchor probe: %v\n%s", err, output)
			}
			var results map[string]bool
			if err := json.Unmarshal(output, &results); err != nil {
				t.Fatalf("anchor result: %v\n%s", err, output)
			}
			if len(results) != 8 {
				t.Fatalf("anchor case count %d: %v", len(results), results)
			}
			for label, ok := range results {
				if !ok {
					t.Errorf("%s failed", label)
				}
			}
			writeFile(t, selected, append(append([]byte{}, wrong...), correct...), 0o600)
			record := runRemoteAlphaESTLSFixture(t, f, scope)
			if !slices.Contains(statusFixtureCodes(t, record), "trust_anchor_count_mismatch") {
				t.Fatalf("missing cardinality blocker: %v", statusFixtureCodes(t, record))
			}
			if record["result"].(map[string]any)["ok"] != false {
				t.Fatalf("multi-anchor collection passed: %v", record["result"])
			}
			if record["certificates"].([]any)[0].(map[string]any)["sha256"] != nil ||
				record["verification"].([]any)[0].(map[string]any)["code"] != "certificate_unavailable" {
				t.Fatalf("multi-anchor verification or metadata accepted")
			}
			writeFile(t, selected, correct, 0o600)
		})
	}
}

func TestRemoteAlphaESServiceTLSStatusUnsupportedExactCommand(t *testing.T) {
	const probe = `
import importlib.util,json,pathlib,sys
source,root=sys.argv[1:]
spec=importlib.util.spec_from_file_location("status_unsupported",source)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
root=pathlib.Path(root)
canonical=root/"canonical.json";canonical.write_bytes(b"previous generation\n")
ca=b"fixed selected anchor";leaf=b"fixed leaf"
metadata={"sha256":"a"*64}
seen=[]
def fake_unsupported(argv,input_bytes=None,anchor_bytes=None):
    seen.append((argv,input_bytes,anchor_bytes))
    return (1,b"",b"usage: verify: unsupported option\n")
module.run_fixed=fake_unsupported
try:
    module.verify_chain("fixture",metadata,metadata,ca,leaf,"sslserver","server.artifact-registry.internal")
    incomplete=False
except module.Incomplete:
    incomplete=True
expected=(module.OPENSSL,"verify","-trusted",module.TRUST_FD_OPERAND,"-purpose",
          "sslserver","-verify_hostname","server.artifact-registry.internal","/dev/stdin")
print(json.dumps({"unsupported_exact_server_command_is_incomplete":incomplete,
                  "exact_argv":len(seen)==1 and seen[0][0]==expected,
                  "selected_bytes":len(seen)==1 and seen[0][1:]==(leaf,ca),
                  "previous_generation_unchanged":canonical.read_bytes()==b"previous generation\n"}))
`
	cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-c", probe,
		remoteAlphaESServiceTLSStatusCollectorPath(), t.TempDir())
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("unsupported exact command probe: %v\n%s", err, output)
	}
	var results map[string]bool
	if err := json.Unmarshal(output, &results); err != nil {
		t.Fatalf("unsupported exact command result: %v\n%s", err, output)
	}
	if len(results) != 4 {
		t.Fatalf("missing deterministic unsupported-command checks: %v", results)
	}
	for label, ok := range results {
		if !ok {
			t.Errorf("%s failed", label)
		}
	}
}
