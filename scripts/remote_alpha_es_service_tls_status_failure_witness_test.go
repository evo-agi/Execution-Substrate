package scripts_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// These Python children import only the source-controlled collector and extract
// the fixed bootstrap as data. Every status fd, child, and terminal is injected;
// they never run an operator route or contact a target.
func runRemoteAlphaESFailureWitnessProbeRaw(t *testing.T, probe string, args ...string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	argv := append([]string{"-I", "-B", "-c", probe,
		remoteAlphaESServiceTLSStatusCollectorPath(), remoteAlphaOperatorScriptPath()}, args...)
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", argv...)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("contained witness probe timed out: %v", ctx.Err())
	}
	return output, err
}

func runRemoteAlphaESFailureWitnessProbe(t *testing.T, probe string, args ...string) map[string]any {
	t.Helper()
	output, err := runRemoteAlphaESFailureWitnessProbeRaw(t, probe, args...)
	if err != nil {
		t.Fatalf("contained witness probe: %v\n%s", err, output)
	}
	var result map[string]any
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("contained witness probe JSON: %v\n%s", err, output)
	}
	return result
}

func TestRemoteAlphaESServiceTLSStatusFailureWitnessCoupledVocabulary(t *testing.T) {
	const probe = `
import ast, importlib.util, json, pathlib, re, sys
source, shell = sys.argv[1:]
spec = importlib.util.spec_from_file_location("witness_collector", source)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
text = pathlib.Path(shell).read_text()
start = text.index("IFS= read -r -d '' bootstrap <<'REMOTE_ALPHA_ES_TLS_STATUS_BOOTSTRAP' || true\n")
start += len("IFS= read -r -d '' bootstrap <<'REMOTE_ALPHA_ES_TLS_STATUS_BOOTSTRAP' || true\n")
end = text.index("\nREMOTE_ALPHA_ES_TLS_STATUS_BOOTSTRAP\n", start)
tree = ast.parse(text[start:end])
selected = [node for node in tree.body if
            (isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "_FAILURE_WITNESS_COUPLINGS" for target in node.targets)) or
            (isinstance(node, ast.FunctionDef) and node.name == "format_failure_witness")]
assert len(selected) == 2
env = {"re": re}
exec(compile(ast.Module(body=selected, type_ignores=[]), "<fixed-bootstrap-functions>", "exec"), env)
fmt = env["format_failure_witness"]
digest = "a" * 64
cases = [
  ("bootstrap", "bootstrap_entry", "caller_identity_unproved"),
  ("bootstrap", "stage_custody", "source_unproved"),
  ("bootstrap", "stage_disposition", "stage_disposition_unproved"),
  ("bootstrap", "collector_load", "collector_load_unproved"),
  ("collector", "collector_entry", "invocation_unproved"),
  ("collector", "protected_ancestry", "protected_state_unproved"),
  ("collector", "scope_lock", "lock_acquisition_unproved"),
  ("collector", "process_capability", "process_capability_unproved"),
  ("collector", "prior_snapshot", "prior_read_unproved"),
  ("collector", "collection", "openssl_grammar_unaccepted"),
  ("collector", "record_encoding", "record_unaccepted"),
  ("collector", "publication_precommit", "publication_unproved"),
]
ok = True
for origin, phase, reason in cases:
    source_kind = "unverified" if phase == "bootstrap_entry" else "verified"
    source_digest = "none" if phase == "bootstrap_entry" else digest
    line = fmt("artifact-registry", origin, source_kind, source_digest, phase, reason)
    expected = ("ES_TLS_STATUS_FAILURE_V1 scope=artifact-registry origin=" + origin +
                " source=" + source_kind + " collector_sha256=" + source_digest + " phase=" + phase +
                " reason=" + reason + "\n").encode("ascii")
    ok &= line == expected and len(line) <= 512
for phase, reasons in env["_FAILURE_WITNESS_COUPLINGS"].items():
    for reason in reasons:
        origin = "bootstrap" if phase.startswith("bootstrap_") or phase in ("stage_custody", "stage_disposition", "collector_load") else "collector"
        source_kind = "unverified" if phase == "bootstrap_entry" else "verified"
        source_digest = "none" if phase == "bootstrap_entry" else digest
        ok &= fmt("execution-governance", origin, source_kind, source_digest, phase, reason) is not None
        ok &= fmt("execution-governance", origin, source_kind, source_digest, phase, "interrupted") is not None
        ok &= fmt("execution-governance", origin, source_kind, source_digest, phase, "unknown") is not None
bad = [
  ("artifact-registry", "collector", "unverified", "none", "collection", "unknown"),
  ("artifact-registry", "collector", "verified", "none", "collection", "unknown"),
  ("artifact-registry", "collector", "verified", "A"*64, "collection", "unknown"),
  ("unknown", "collector", "verified", digest, "collection", "unknown"),
  ("unknown", "bootstrap", "unverified", "none", "stage_custody", "unknown"),
  ("artifact-registry", "bootstrap", "verified", digest, "scope_lock", "lock_state_unproved"),
  ("artifact-registry", "collector", "verified", digest, "collection", "lock_state_unproved"),
  ("artifact-registry", "collector", "verified", digest, "collection", "x\nsecret"),
  ("artifact-registry", "collector", "verified", digest, "collection", "\x1b[31m"),
  ("artifact-registry", "bootstrap", "verified", digest, "bootstrap_entry", "unknown"),
  ("artifact-registry", "bootstrap", "unverified", "none", "stage_disposition", "unknown"),
  ("artifact-registry", "bootstrap", "unverified", "none", "collector_load", "unknown"),
]
ok &= all(fmt(*item) is None for item in bad)
ok &= fmt("unknown", "bootstrap", "unverified", "none", "bootstrap_entry", "invocation_unproved") is not None
ok &= fmt("artifact-registry", "bootstrap", "unverified", "none", "stage_custody", "source_unproved") is not None
class Hostile:
    def __str__(self): raise AssertionError("secret-looking sentinel")
    def __repr__(self): raise AssertionError("secret-looking sentinel")
ok &= fmt("artifact-registry", "collector", "verified", digest, "collection", Hostile()) is None
mapping = [
  ("protected_ancestry", "unsafe_protected_ancestor", "protected_state_unproved"),
  ("scope_lock", "unsafe_lock", "lock_state_unproved"),
  ("scope_lock", "same_scope_lock_contended", "lock_acquisition_unproved"),
  ("process_capability", "process_capability_unavailable", "process_capability_unproved"),
  ("prior_snapshot", "prior_summary_unaccepted", "prior_summary_unaccepted"),
  ("prior_snapshot", "summary_leaf_changed", "prior_read_unproved"),
  ("collection", "unsafe_fixed_input", "fixed_input_unproved"),
  ("collection", "invalid_fixed_command", "fixed_command_unproved"),
  ("collection", "child_run_unproved", "openssl_child_unproved"),
  ("collection", "unexpected_openssl_grammar", "openssl_grammar_unaccepted"),
  ("record_encoding", "record_encoding", "record_unaccepted"),
  ("publication_precommit", "summary_write", "publication_unproved"),
]
ok &= all(m._failure_reason(phase, m.Incomplete(literal)) == expected for phase,literal,expected in mapping)
ok &= m._failure_reason("collection", m.Incomplete("child_interrupted")) == "interrupted"
ok &= m._failure_reason("collection", m.Incomplete(Hostile())) == "unknown"
ok &= m._failure_reason("collection", RuntimeError(Hostile())) == "unknown"
print(json.dumps({"closed_and_exact": bool(ok), "specific_cases": len(cases)}))
`
	result := runRemoteAlphaESFailureWitnessProbe(t, probe)
	if result["closed_and_exact"] != true || result["specific_cases"] != float64(12) {
		t.Fatalf("failure witness vocabulary/source binding: %v", result)
	}
}

func TestRemoteAlphaESServiceTLSStatusFailureWitnessCollectorCloseout(t *testing.T) {
	const probe = `
import importlib.util,json,os,sys
source,_shell,scope,mode=sys.argv[1:]
spec=importlib.util.spec_from_file_location("witness_main",source)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.ES_TLS_STATUS_BOOTSTRAP_VERIFIED=True
m.ES_TLS_STATUS_BOOTSTRAP_INTERRUPTED=[False]
closed=[]
def close(fd):
    closed.append(fd)
    if mode=="close_fault" and fd==302: raise OSError("injected close fault")
m.os.close=close
m.open_status_dir=lambda:301
m.open_scope_lock=lambda _fd,_name:302
m.validate_process_capability=lambda:None
m.preexisting_generation=lambda _fd,_scope:m._PriorSummarySnapshot(m._PriorSummaryState.ABSENT)
m.collect=lambda _scope,_previous:{}
m.check_signal=lambda:None
m.encode_document=lambda _record,_scope:b"{}"
def fail(reason): raise m.Incomplete(reason)
if mode=="ancestry":m.open_status_dir=lambda:fail("unsafe_protected_ancestor")
elif mode=="lock":m.open_scope_lock=lambda _fd,_name:fail("same_scope_lock_contended")
elif mode in ("process","close_fault","uncertain"):
    def process():
        if mode=="uncertain":m.WITNESS_DISPOSITION_UNPROVED=True
        fail("process_capability_unavailable")
    m.validate_process_capability=process
elif mode=="prior":m.preexisting_generation=lambda _fd,_scope:fail("summary_leaf_changed")
elif mode=="collection":m.collect=lambda _scope,_previous:fail("unexpected_openssl_grammar")
elif mode=="encoding":m.encode_document=lambda _record,_scope:fail("record_encoding")
elif mode=="hostile":
    class Hostile:
        def __str__(self):raise AssertionError("secret-looking sentinel")
        def __repr__(self):raise AssertionError("secret-looking sentinel")
    m.collect=lambda _scope,_previous:fail(Hostile())
elif mode=="unexpected":m.collect=lambda _scope,_previous:(_ for _ in ()).throw(RuntimeError("secret-looking sentinel"))
else:m.publish=lambda _fd,_scope,_payload:fail("summary_write")
escaped=False
try:rc=m.main(["--scope",scope])
except BaseException:rc=1;escaped=True
print(json.dumps({"rc":rc,"closed":closed,"selection":m.WITNESS_SELECTION,
                  "proved":m.WITNESS_CLOSEOUT_PROVED,"escaped":escaped}))
`
	for _, scope := range []string{"artifact-registry", "execution-governance"} {
		for _, tc := range []struct {
			mode, phase, reason string
			closed              []any
			proved              bool
		}{
			{"ancestry", "protected_ancestry", "protected_state_unproved", []any{}, true},
			{"lock", "scope_lock", "lock_acquisition_unproved", []any{float64(301)}, true},
			{"process", "process_capability", "process_capability_unproved", []any{float64(302), float64(301)}, true},
			{"prior", "prior_snapshot", "prior_read_unproved", []any{float64(302), float64(301)}, true},
			{"collection", "collection", "openssl_grammar_unaccepted", []any{float64(302), float64(301)}, true},
			{"encoding", "record_encoding", "record_unaccepted", []any{float64(302), float64(301)}, true},
			{"publication", "publication_precommit", "publication_unproved", []any{float64(302), float64(301)}, true},
			{"hostile", "collection", "unknown", []any{float64(302), float64(301)}, true},
			{"uncertain", "process_capability", "process_capability_unproved", []any{float64(302), float64(301)}, false},
			{"close_fault", "process_capability", "process_capability_unproved", []any{float64(302), float64(301)}, false},
			{"unexpected", "", "", []any{float64(302), float64(301)}, false},
		} {
			t.Run(scope+"/"+tc.mode, func(t *testing.T) {
				got := runRemoteAlphaESFailureWitnessProbe(t, probe, scope, tc.mode)
				if got["rc"] != float64(1) || got["proved"] != tc.proved {
					t.Fatalf("return or closeout: %v", got)
				}
				closed, ok := got["closed"].([]any)
				if !ok || !sameFailureWitnessSequence(closed, tc.closed) {
					t.Fatalf("close sequence: %v", got)
				}
				if tc.phase == "" {
					if got["selection"] != nil || got["escaped"] != true {
						t.Fatalf("unexpected exception selected witness: %v", got)
					}
					return
				}
				selection, ok := got["selection"].([]any)
				if !ok || len(selection) != 2 || selection[0] != tc.phase || selection[1] != tc.reason {
					t.Fatalf("wrong phase/reason: %v", got)
				}
			})
		}
	}
}

func TestRemoteAlphaESServiceTLSStatusFailureWitnessFixedInputCloseout(t *testing.T) {
	const probe = `
import ast,importlib.util,json,os,pathlib,re,stat,sys
source,shell,root_arg,scope,consumer,mode=sys.argv[1:]
root=pathlib.Path(root_arg)
path=root/"fixed-input"
prior=root/"prior-summary"
prior.write_bytes(b"prior generation retained")
if mode=="settled":path.symlink_to("missing")
else:path.write_bytes(b"{}")
text=pathlib.Path(shell).read_text()
mark="IFS= read -r -d '' bootstrap <<'REMOTE_ALPHA_ES_TLS_STATUS_BOOTSTRAP' || true\n"
start=text.index(mark)+len(mark);end=text.index("\nREMOTE_ALPHA_ES_TLS_STATUS_BOOTSTRAP\n",start)
tree=ast.parse(text[start:end])
selected=[node for node in tree.body if
          (isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id=="_FAILURE_WITNESS_COUPLINGS" for target in node.targets)) or
          (isinstance(node,ast.FunctionDef) and node.name in ("format_failure_witness","emit_failure_witness"))]
assert len(selected)==3
spec=importlib.util.spec_from_file_location("witness_fixed_input",source)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.CONFIG["ars"]=str(path)
# Test-owned input bypasses root-only metadata checks; the primitive and consumers remain real.
m.check_input_ancestor=lambda _info:None
m.check_extended=lambda _fd:None
m.same_entry=lambda *_args:None
m.same_leaf=lambda *_args:None
m.ES_TLS_STATUS_BOOTSTRAP_VERIFIED=True
m.ES_TLS_STATUS_BOOTSTRAP_INTERRUPTED=[False]
m.open_status_dir=lambda:100000
m.open_scope_lock=lambda _fd,_name:100001
m.validate_process_capability=lambda:None
m.preexisting_generation=lambda _fd,_scope:m._PriorSummarySnapshot(m._PriorSummaryState.ABSENT)
m.check_signal=lambda:None
published=[]
m.publish=lambda *_args:published.append(True)
if consumer=="config":m.collect=lambda _scope,_previous:m.read_config("ars",True)
elif consumer=="certificate":m.collect=lambda _scope,_previous:m.cert_metadata(str(path))
else:m.collect=lambda _scope,_previous:m.key_pair("fixture",{"public_key_sha256":"0"*64},str(path))
real_open=os.open;real_close=os.close
opened=set();faulted=[];attempts={};closes=[]
def tracked_open(*args,**kwargs):
    fd=real_open(*args,**kwargs);opened.add(fd);return fd
def close_once(fd):
    attempts[fd]=attempts.get(fd,0)+1
    if fd in (100000,100001):
        closes.append("status" if fd==100000 else "lock")
        return
    is_directory=stat.S_ISDIR(os.fstat(fd).st_mode)
    if not faulted and ((mode=="leaf" and not is_directory) or (mode=="ancestry" and is_directory)):
        closes.append("input_close_fault")
        faulted.append(fd)
        raise OSError("secret-looking sentinel\x1b[31m")
    closes.append("input_close")
    real_close(fd);opened.discard(fd)
os.open=tracked_open;os.close=close_once
try:
    rc=m.main(["--scope",scope])
    lines=[]
    env=dict(re=re,uncaught=[False],owned_fds={"parent":False,"directory":False,"file":False},
             collector_started=True,stage_closeout=True,collector_failure_exit=True,
             collector_namespace=dict(WITNESS_SELECTION=m.WITNESS_SELECTION,
                 WITNESS_CLOSEOUT_PROVED=m.WITNESS_CLOSEOUT_PROVED,
                 WITNESS_DISPOSITION_UNPROVED=m.WITNESS_DISPOSITION_UNPROVED),
             scope_value=scope,verified_digest="a"*64,write_failure_witness=lines.append)
    exec(compile(ast.Module(body=selected,type_ignores=[]),"<exact-bootstrap-gate>","exec"),env)
    env["emit_failure_witness"]()
    result=dict(rc=rc,selection=m.WITNESS_SELECTION,proved=m.WITNESS_CLOSEOUT_PROVED,
                uncertain=m.WITNESS_DISPOSITION_UNPROVED,emitted=len(lines),
                witness_exact=lines==[("ES_TLS_STATUS_FAILURE_V1 scope="+scope+
                    " origin=collector source=verified collector_sha256="+"a"*64+
                    " phase=collection reason=fixed_input_unproved\n").encode("ascii")],
                hostile_leak=any(b"secret-looking sentinel" in line or b"\x1b" in line for line in lines),
                close_order=closes[-2:],fault_attempts=attempts.get(faulted[0],0) if faulted else 0,
                prior_preserved=prior.read_bytes()==b"prior generation retained",published=len(published))
finally:
    os.open=real_open;os.close=real_close
    # Emergency fixture cleanup follows all production closeout/sink observations.
    for fd in sorted(opened):real_close(fd)
print(json.dumps(result,sort_keys=True))
`
	for _, scope := range []string{"artifact-registry", "execution-governance"} {
		for _, consumer := range []string{"config", "certificate", "key"} {
			for _, mode := range []string{"leaf", "ancestry"} {
				t.Run(scope+"/"+consumer+"/"+mode, func(t *testing.T) {
					got := runRemoteAlphaESFailureWitnessProbe(t, probe, t.TempDir(), scope, consumer, mode)
					if got["rc"] != float64(1) || got["published"] != float64(0) || got["prior_preserved"] != true ||
						got["hostile_leak"] != false || got["fault_attempts"] != float64(1) ||
						got["uncertain"] != true || got["proved"] != false || got["emitted"] != float64(0) {
						t.Fatalf("fixed-input close uncertainty earned output eligibility: %v", got)
					}
					selection, ok := got["selection"].([]any)
					if !ok || !sameFailureWitnessSequence(selection, []any{"collection", "fixed_input_unproved"}) ||
						!sameFailureWitnessSequence(got["close_order"].([]any), []any{"lock", "status"}) {
						t.Fatalf("fixed-input failure changed selection or lock/status order: %v", got)
					}
				})
			}
		}
	}
	for _, scope := range []string{"artifact-registry", "execution-governance"} {
		t.Run(scope+"/settled", func(t *testing.T) {
			got := runRemoteAlphaESFailureWitnessProbe(t, probe, t.TempDir(), scope, "config", "settled")
			if got["rc"] != float64(1) || got["published"] != float64(0) || got["prior_preserved"] != true ||
				got["uncertain"] != false || got["proved"] != true || got["emitted"] != float64(1) ||
				got["witness_exact"] != true || got["hostile_leak"] != false ||
				!sameFailureWitnessSequence(got["close_order"].([]any), []any{"lock", "status"}) {
				t.Fatalf("settled fixed-input refusal lost exact witness: %v", got)
			}
		})
	}
}

func TestRemoteAlphaESServiceTLSStatusFailureWitnessTemporaryDisposition(t *testing.T) {
	const probe = `
import importlib.util,json,os,stat,sys,types
source,_shell,scope,mode=sys.argv[1:]
spec=importlib.util.spec_from_file_location("witness_temporary",source)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.ES_TLS_STATUS_BOOTSTRAP_VERIFIED=True
m.ES_TLS_STATUS_BOOTSTRAP_INTERRUPTED=[False]
m.open_status_dir=lambda:301
m.open_scope_lock=lambda _fd,_name:302
m.validate_process_capability=lambda:None
m.preexisting_generation=lambda _fd,_scope:m._PriorSummarySnapshot(m._PriorSummaryState.ABSENT)
m.collect=lambda _scope,_previous:{}
m.check_signal=lambda:None
m.encode_document=lambda _record,_scope:b"bounded record"
m.secrets.token_hex=lambda n:"a"*32
owned=types.SimpleNamespace(st_dev=7,st_ino=8,st_mode=stat.S_IFREG|0o600,st_nlink=1)
foreign=types.SimpleNamespace(st_dev=7,st_ino=9,st_mode=stat.S_IFREG|0o600,st_nlink=1)
events=[]
m.os.open=lambda name,flags,*a,**k:303
m.os.fstat=lambda fd:owned
m.check_protected_file=lambda fd,permission:owned
def write(fd,data):
    events.append("write")
    if mode=="generic_write":raise OSError("secret-looking sentinel")
    return 0
m.os.write=write
def temporary_stat(name,**kw):
    events.append("stat")
    if mode=="stat_fault":raise OSError("secret-looking sentinel")
    return foreign if mode=="foreign" else owned
m.os.stat=temporary_stat
m.os.unlink=lambda name,**kw:events.append("unlink")
m.os.close=lambda fd:events.append("close:"+str(fd))
m.os.replace=lambda *a,**kw:(_ for _ in ()).throw(AssertionError("publication reached"))
m.os._exit=lambda code:(_ for _ in ()).throw(AssertionError("exit reached"))
rc=m.main(["--scope",scope])
print(json.dumps({"rc":rc,"events":events,"selection":m.WITNESS_SELECTION,
                  "proved":m.WITNESS_CLOSEOUT_PROVED,"uncertain":m.WITNESS_DISPOSITION_UNPROVED}))
`
	for _, scope := range []string{"artifact-registry", "execution-governance"} {
		for _, tc := range []struct {
			mode, reason string
			proved       bool
			unlink       bool
		}{
			{"clean", "publication_unproved", true, true},
			{"stat_fault", "publication_unproved", false, false},
			{"foreign", "publication_unproved", false, false},
			{"generic_write", "unknown", false, true},
		} {
			t.Run(scope+"/"+tc.mode, func(t *testing.T) {
				got := runRemoteAlphaESFailureWitnessProbe(t, probe, scope, tc.mode)
				if got["rc"] != float64(1) || got["proved"] != tc.proved || got["uncertain"] == tc.proved {
					t.Fatalf("temporary closeout classification: %v", got)
				}
				selection, ok := got["selection"].([]any)
				if !ok || len(selection) != 2 || selection[0] != "publication_precommit" || selection[1] != tc.reason {
					t.Fatalf("temporary phase/reason: %v", got)
				}
				events, ok := got["events"].([]any)
				if !ok || len(events) < 4 || events[len(events)-3] != "close:303" ||
					events[len(events)-2] != "close:302" || events[len(events)-1] != "close:301" {
					t.Fatalf("temporary and lock/status descriptors did not close before output eligibility: %v", got)
				}
				count := 0
				for _, event := range events {
					if event == "unlink" {
						count++
					}
				}
				if (count == 1) != tc.unlink || count > 1 {
					t.Fatalf("unexpected temporary cleanup: %v", got)
				}
			})
		}
	}
}

func TestRemoteAlphaESServiceTLSStatusFailureWitnessNoDirectOrStaleState(t *testing.T) {
	const probe = `
import importlib.util,json,sys
source,_shell=sys.argv[1:]
spec=importlib.util.spec_from_file_location("witness_stale",source)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
direct=m.main(["--scope","artifact-registry"])
direct_clean=m.WITNESS_SELECTION is None and m.WITNESS_CLOSEOUT_PROVED is False
m.ES_TLS_STATUS_BOOTSTRAP_VERIFIED=True
m.ES_TLS_STATUS_BOOTSTRAP_INTERRUPTED=[False]
m.open_status_dir=lambda:(_ for _ in ()).throw(m.Incomplete("unsafe_protected_ancestor"))
failed=m.main(["--scope","artifact-registry"])
first=m.WITNESS_SELECTION==("protected_ancestry","protected_state_unproved") and m.WITNESS_CLOSEOUT_PROVED is True
unsupported=m.main(["--scope","unsupported"])
reset=m.WITNESS_SELECTION is None and m.WITNESS_CLOSEOUT_PROVED is False
m.ES_TLS_STATUS_BOOTSTRAP_INTERRUPTED=[1]
contradictory=m.main(["--scope","artifact-registry"])
contradictory_clean=m.WITNESS_SELECTION is None and m.WITNESS_CLOSEOUT_PROVED is False
m.ES_TLS_STATUS_BOOTSTRAP_INTERRUPTED=[True]
interrupted=m.main(["--scope","artifact-registry"])
reached=m.WITNESS_SELECTION==("collector_entry","interrupted") and m.WITNESS_CLOSEOUT_PROVED is True
print(json.dumps({"direct":direct,"direct_clean":direct_clean,"failed":failed,
                  "first":first,"unsupported":unsupported,"reset":reset,
                  "contradictory":contradictory,"contradictory_clean":contradictory_clean,
                  "interrupted":interrupted,"reached":reached}))
`
	got := runRemoteAlphaESFailureWitnessProbe(t, probe)
	if got["direct"] != float64(2) || got["direct_clean"] != true ||
		got["failed"] != float64(1) || got["first"] != true ||
		got["unsupported"] != float64(2) || got["reset"] != true ||
		got["contradictory"] != float64(1) || got["contradictory_clean"] != true ||
		got["interrupted"] != float64(1) || got["reached"] != true {
		t.Fatalf("direct or stale state could become privileged witness: %v", got)
	}
}

func sameFailureWitnessSequence(a, b []any) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestRemoteAlphaESServiceTLSStatusFailureWitnessTerminalBestEffort(t *testing.T) {
	const probe = `
import ast,json,pathlib,sys,types
_source,shell=sys.argv[1:]
text=pathlib.Path(shell).read_text()
mark="IFS= read -r -d '' bootstrap <<'REMOTE_ALPHA_ES_TLS_STATUS_BOOTSTRAP' || true\n"
start=text.index(mark)+len(mark);end=text.index("\nREMOTE_ALPHA_ES_TLS_STATUS_BOOTSTRAP\n",start)
tree=ast.parse(text[start:end])
node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=="write_failure_witness")
events=[]
class FakeOS:
    O_WRONLY=1;O_NONBLOCK=2;O_NOCTTY=4;O_CLOEXEC=8
    def __init__(self,mode):self.mode=mode
    def open(self,path,flags):
        events.append(("open",path,flags))
        if self.mode=="unavailable":raise OSError()
        return 77
    def isatty(self,fd):events.append(("isatty",fd));return self.mode!="not_tty"
    def write(self,fd,data):
        events.append(("write",fd,len(data)))
        if self.mode=="blocked":raise BlockingIOError()
        if self.mode=="broken":raise BrokenPipeError()
        return len(data)-1 if self.mode=="short" else len(data)
    def close(self,fd):
        events.append(("close",fd))
        if self.mode=="close_fault":raise OSError()
ok=True
for mode in ("normal","unavailable","not_tty","blocked","broken","short","close_fault"):
    events.clear();fake=FakeOS(mode)
    env={"os":fake}
    exec(compile(ast.Module(body=[node],type_ignores=[]),"<fixed-terminal-write>","exec"),env)
    env["write_failure_witness"](b"fixed witness\n")
    opens=[e for e in events if e[0]=="open"]
    writes=[e for e in events if e[0]=="write"]
    closes=[e for e in events if e[0]=="close"]
    ok &= len(opens)==1 and opens[0]==("open","/dev/tty",15)
    ok &= len(writes)==(0 if mode in ("unavailable","not_tty") else 1)
    ok &= len(closes)==(0 if mode=="unavailable" else 1)
print(json.dumps({"nonblocking_one_write":bool(ok)}))
`
	got := runRemoteAlphaESFailureWitnessProbe(t, probe)
	if got["nonblocking_one_write"] != true {
		t.Fatalf("terminal delivery introduced fallback, retry or inherited fd use: %v", got)
	}
}

func TestRemoteAlphaESServiceTLSStatusFailureWitnessBootstrapOwnedTerminal(t *testing.T) {
	const probe = `
import fcntl,hashlib,json,os,pathlib,pty,pwd,re,secrets,select,shutil,subprocess,sys,termios,time
_source,shell,root_arg,scope,mode=sys.argv[1:]
root=pathlib.Path(root_arg);parent=root/"stage-parent";parent.mkdir();parent.chmod(0o1777)
text=pathlib.Path(shell).read_text()
mark="IFS= read -r -d '' bootstrap <<'REMOTE_ALPHA_ES_TLS_STATUS_BOOTSTRAP' || true\n"
start=text.index(mark)+len(mark);end=text.index("\nREMOTE_ALPHA_ES_TLS_STATUS_BOOTSTRAP\n",start)
bootstrap=text[start:end]
def replace_once(old,new):
    global bootstrap
    assert bootstrap.count(old)==1,old
    bootstrap=bootstrap.replace(old,new)
replace_once('r"/tmp/\\.es','r"'+re.escape(str(parent))+r'/\.es')
replace_once('os.open("/tmp",','os.open('+repr(str(parent))+',')
replace_once('parent.st_uid != 0 or parent.st_gid != 0',
             'parent.st_uid != '+str(parent.stat().st_uid)+' or parent.st_gid != '+str(parent.stat().st_gid))
replace_once('os.geteuid() != 0','os.geteuid() != os.getuid()')
replace_once('os.fchown(dir_fd, 0, 0)','os.fchmod(dir_fd, 0o700)')
replace_once('os.fstat(dir_fd).st_uid != 0','os.fstat(dir_fd).st_uid != operator_uid')
replace_once('os.fstat(dir_fd).st_gid != 0','os.fstat(dir_fd).st_gid != operator_gid')
replace_once('if any(attr not in ("security.selinux", "com.apple.provenance") for attr in os.listxattr(fd)):', 'if False:')
if mode=="stage_cleanup":
    replace_once('            os.unlink(basename, dir_fd=dir_fd)\n',
                 '            raise SystemExit(1)  # named owned-stage cleanup fault\n')
name=".es-tls-status-"+secrets.token_hex(16)
stage=parent/name;stage.mkdir(mode=0o700);stage.chmod(0o700)
os.chown(stage,os.getuid(),os.getgid())
leaf=stage/"remote_alpha_es_tls_status.py"
payload=("import sys\n"
         "WITNESS_SELECTION=None\n"
         "WITNESS_CLOSEOUT_PROVED=False\n"
         "WITNESS_DISPOSITION_UNPROVED=False\n"
         "def main(argv):\n"
         "    global WITNESS_SELECTION,WITNESS_CLOSEOUT_PROVED,WITNESS_DISPOSITION_UNPROVED\n"
         "    assert argv == ['--scope',"+repr(scope)+"]\n"
         "    if "+repr(mode)+" == 'unhandled': raise RuntimeError('secret-looking sentinel\\x1b[31m')\n"
         "    if "+repr(mode)+" == 'hostile_exit': raise SystemExit('secret-looking sentinel\\x1b[31m')\n"
         "    if "+repr(mode)+" == 'success': return 0\n"
         "    if "+repr(mode)+" == 'fixture_read_fault':\n"
         "        import time; time.sleep(10)\n"
         "    WITNESS_SELECTION=('collection','openssl_grammar_unaccepted')\n"
         "    WITNESS_CLOSEOUT_PROVED=True\n"
         "    WITNESS_DISPOSITION_UNPROVED="+repr(mode=="collector_uncertain")+"\n"
         "    return 1\n"
         "if __name__ == '__main__':\n"
         "    if "+repr(mode)+" == 'normal_return': main(sys.argv[1:])\n"
         "    else: sys.exit(main(sys.argv[1:]))\n").encode()
leaf.write_bytes(payload);leaf.chmod(0o600)
os.chown(leaf,os.getuid(),os.getgid())
digest=hashlib.sha256(payload).hexdigest()
if mode=="source_mismatch":digest="b"*64 if digest!="b"*64 else "c"*64
if mode=="stage_extra":(stage/"unexpected").write_bytes(b"owned fixture")
env=os.environ.copy();env.update(SUDO_USER="ds",SUDO_UID=str(os.getuid()),
                                 SUDO_GID=str(os.getgid()),PYTHONDONTWRITEBYTECODE="1")
if mode=="identity":env["SUDO_GID"]=str(os.getgid()+1)
info=stage.stat()
master,slave=pty.openpty()
def setup_ctty():
    os.setsid()
    fcntl.ioctl(slave,termios.TIOCSCTTY,0)
child=None
try:
    child=subprocess.Popen([sys.executable,"-I","-B","-c",bootstrap,str(stage),leaf.name,digest,
                            scope,str(info.st_dev),str(info.st_ino)],
                           stdin=slave,stdout=slave,stderr=slave,env=env,close_fds=True,preexec_fn=setup_ctty)
    os.close(slave);slave=-1
    if mode=="fixture_read_fault":raise RuntimeError("injected fixture read fault")
    output=bytearray();deadline=time.monotonic()+3
    while time.monotonic()<deadline:
        ready,_,_=select.select([master],[],[],0.05)
        if ready:
            try:piece=os.read(master,4096)
            except OSError:piece=b""
            if not piece:break
            output.extend(piece)
            assert len(output)<8192
        if child.poll() is not None and not ready:break
    child.wait(timeout=1)
    normalized=bytes(output).replace(b"\r\n",b"\n").decode("ascii","replace")
    print(json.dumps({"exit":child.returncode,"output":normalized,"stage_remains":stage.exists(),
                      "digest":hashlib.sha256(payload).hexdigest()}))
finally:
    original_failure=sys.exc_info()[0] is not None
    cleanup_unproved=[]
    terminated=False
    if child is not None:
        try:
            if child.poll() is None:
                try:child.terminate();terminated=True
                except ProcessLookupError:pass
            try:child.wait(timeout=1)
            except subprocess.TimeoutExpired:
                try:child.kill()
                except ProcessLookupError:pass
                child.wait(timeout=1)
        except BaseException:
            cleanup_unproved.append("exact_child")
        if child.returncode is None:cleanup_unproved.append("reap")
    for label,fd in (("master_pty",master),("slave_pty",slave)):
        if fd>=0:
            try:os.close(fd)
            except BaseException:cleanup_unproved.append(label)
    stage_removed=False
    try:
        if stage.exists():shutil.rmtree(stage)
        stage_removed=not stage.exists()
    except BaseException:cleanup_unproved.append("owned_stage")
    if mode=="fixture_read_fault":
        print("FIXTURE_CLEANUP child_reaped="+str(child is not None and child.returncode is not None).lower()+
              " terminated="+str(terminated).lower()+" stage_removed="+str(stage_removed).lower()+
              " uncertain="+str(bool(cleanup_unproved)).lower(),file=sys.stderr)
    if cleanup_unproved:
        print("FIXTURE_CLEANUP_UNPROVED "+",".join(cleanup_unproved),file=sys.stderr)
        if not original_failure:raise RuntimeError("fixture cleanup unproved")
`
	for _, scope := range []string{"artifact-registry", "execution-governance"} {
		for _, tc := range []struct {
			mode, fragment string
			remains        bool
		}{
			{"identity", "origin=bootstrap source=unverified collector_sha256=none phase=bootstrap_entry reason=caller_identity_unproved", true},
			{"stage_extra", "origin=bootstrap source=unverified collector_sha256=none phase=stage_custody reason=stage_custody_unproved", true},
			{"source_mismatch", "origin=bootstrap source=unverified collector_sha256=none phase=stage_custody reason=source_unproved", true},
			{"stage_cleanup", "origin=bootstrap source=verified collector_sha256=", true},
			{"collector", "origin=collector source=verified collector_sha256=", false},
			{"collector_uncertain", "", false},
			{"unhandled", "", false},
			{"hostile_exit", "", false},
			{"normal_return", "", false},
			{"success", "", false},
		} {
			t.Run(scope+"/"+tc.mode, func(t *testing.T) {
				got := runRemoteAlphaESFailureWitnessProbe(t, probe, t.TempDir(), scope, tc.mode)
				if got["stage_remains"] != tc.remains {
					t.Fatalf("owned stage disposition: %v", got)
				}
				output, _ := got["output"].(string)
				if tc.fragment == "" {
					if output != "" {
						t.Fatalf("uncertain or successful path emitted: %v", got)
					}
				} else {
					if !strings.HasPrefix(output, "ES_TLS_STATUS_FAILURE_V1 scope="+scope+" ") ||
						!strings.Contains(output, tc.fragment) || strings.Count(output, "ES_TLS_STATUS_FAILURE_V1") != 1 ||
						!strings.HasSuffix(output, "\n") || len(output) > 512 {
						t.Fatalf("root-owned witness incomplete or invalid: %v", got)
					}
					if tc.mode == "collector" || tc.mode == "stage_cleanup" {
						if !strings.Contains(output, got["digest"].(string)) {
							t.Fatalf("verified source digest not bound to exact payload: %v", got)
						}
					}
				}
				if strings.Contains(output, "secret-looking sentinel") || strings.Contains(output, "\x1b") {
					t.Fatalf("hostile exception escaped into terminal: %v", got)
				}
				if tc.mode == "success" && got["exit"] != float64(0) {
					t.Fatalf("synthetic completed success did not exit zero: %v", got)
				}
			})
		}
	}
	for _, scope := range []string{"artifact-registry", "execution-governance"} {
		t.Run(scope+"/fixture_read_fault", func(t *testing.T) {
			root := t.TempDir()
			output, err := runRemoteAlphaESFailureWitnessProbeRaw(t, probe, root, scope, "fixture_read_fault")
			if err == nil || !bytes.Contains(output, []byte("injected fixture read fault")) ||
				!bytes.Contains(output, []byte("FIXTURE_CLEANUP child_reaped=true terminated=true stage_removed=true uncertain=false")) ||
				bytes.Contains(output, []byte("FIXTURE_CLEANUP_UNPROVED")) {
				t.Fatalf("exceptional PTY fixture cleanup did not preserve failure and reap exact child: %v\n%s", err, output)
			}
			entries, err := os.ReadDir(root + "/stage-parent")
			if err != nil || len(entries) != 0 {
				t.Fatalf("exceptional PTY fixture retained owned stage: %v %v", entries, err)
			}
		})
	}
}

func TestRemoteAlphaESServiceTLSStatusFailureWitnessSourceBoundary(t *testing.T) {
	collector := mustRead(t, remoteAlphaESServiceTLSStatusCollectorPath())
	facade := mustRead(t, remoteAlphaOperatorScriptPath())
	if strings.Contains(collector, "/dev/tty") || strings.Contains(collector, "ES_TLS_STATUS_FAILURE_V1") {
		t.Fatal("collector acquired terminal witness ownership")
	}
	if !bytes.Contains([]byte(collector), []byte("os.replace(temporary, name, src_dir_fd=status_fd, dst_dir_fd=status_fd)\n        os._exit(0)")) {
		t.Fatal("successful publication no longer immediately exits")
	}
	for _, required := range []string{
		"ES_TLS_STATUS_FAILURE_V1", "write_failure_witness", "format_failure_witness",
		"remote phase unproved", `ssh -tt "${ssh_target}" "${remote_command}"`,
	} {
		if !strings.Contains(facade, required) {
			t.Fatalf("missing fixed facade/terminal boundary %q", required)
		}
	}
	statusSection := docSection(t, facade, "remote_alpha_es_tls_status_shell_quote() {", "\nrecovery_session_es_service_tls() {")
	if strings.Contains(statusSection, "tee /dev/tty") || strings.Contains(statusSection, "sudo -n") {
		t.Fatal("status route changed visible sudo/terminal discipline")
	}
}

func TestRemoteAlphaESServiceTLSStatusFailureWitnessDocumentsContract(t *testing.T) {
	for _, path := range []string{
		"PLANS.md",
		".docs/system_overview/remote_supported_host_alpha.md",
		".docs/system_overview/remote_alpha_access_contract.md",
		".docs/system_overview/artifact_hygiene.md",
	} {
		source := mustRead(t, executionSubstrateRepoRoot+"/"+path)
		for _, required := range []string{"failure witness", "terminal", "source", "closeout", "protected"} {
			if !strings.Contains(strings.ToLower(source), required) {
				t.Fatalf("%s does not state %s boundary", path, required)
			}
		}
	}
	owner := mustRead(t, executionSubstrateRepoRoot+"/.docs/system_overview/remote_supported_host_alpha.md")
	for _, required := range []string{
		"ES_TLS_STATUS_FAILURE_V1 scope=<scope> origin=<origin> source=<source> collector_sha256=<digest> phase=<phase> reason=<reason>",
		"lock_acquisition_unproved", "openssl_grammar_unaccepted", "publication_precommit",
		"at most 512 bytes", "completed", "remote phase", "unproved",
	} {
		if !strings.Contains(owner, required) {
			t.Fatalf("owning status contract omitted %q", required)
		}
	}
}

func TestRemoteAlphaESServiceTLSStatusFailureWitnessResourceCloseout(t *testing.T) {
	const probe = `
import ast,importlib.util,json,os,pathlib,re,selectors,signal,sys,types
source,shell,root_arg,scope,mode=sys.argv[1:]
root=pathlib.Path(root_arg)
prior=root/"prior-summary";prior.write_bytes(b"prior generation retained")
text=pathlib.Path(shell).read_text()
mark="IFS= read -r -d '' bootstrap <<'REMOTE_ALPHA_ES_TLS_STATUS_BOOTSTRAP' || true\n"
start=text.index(mark)+len(mark);end=text.index("\nREMOTE_ALPHA_ES_TLS_STATUS_BOOTSTRAP\n",start)
tree=ast.parse(text[start:end])
selected=[node for node in tree.body if
 (isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="_FAILURE_WITNESS_COUPLINGS" for t in node.targets)) or
 (isinstance(node,ast.FunctionDef) and node.name in ("format_failure_witness","emit_failure_witness"))]
assert len(selected)==3
spec=importlib.util.spec_from_file_location("resource_closeout_collector",source)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
module=m
` + remoteAlphaESStatusLocalChildNamespace + `m.ES_TLS_STATUS_BOOTSTRAP_VERIFIED=True;m.ES_TLS_STATUS_BOOTSTRAP_INTERRUPTED=[False]
m.SIGNALS=();m.LATCHED_SIGNAL=None
class Hostile:
 def __str__(self):raise AssertionError("hostile close payload rendered")
 def __repr__(self):raise AssertionError("hostile close payload rendered")
class FakeOS:
 def __init__(self):
  self.closed=[];self.attempts={};self.sentinel_touched=False;self.target={
   "cap_read":10,"cap_write":11,"cap_proc":701,"cap_pidfd":12,
   "proc_scan":701,"member_pidfd":77,"anchor_read":50,"anchor_write":51,
   "status_ancestry":201}.get(mode)
 def __getattr__(self,name):return getattr(os,name)
 def open(self,path,flags,*args,**kwargs):
  if path=="/proc/4242/stat" and mode in ("cap_proc","proc_scan"):return 701
  if mode=="status_ancestry" and path=="/":return 201
  if mode=="status_ancestry" and path=="var" and kwargs.get("dir_fd")==201:return 202
  raise AssertionError("unexpected fake open")
 def read(self,fd,n):
  if fd==701:return b"4242 (probe) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1\n"
  if fd in (402,403):return b""
  raise AssertionError("unexpected fake read")
 def close(self,fd):
  self.closed.append(fd);self.attempts[fd]=self.attempts.get(fd,0)+1
  if fd not in (301,302,201,202,10,11,12,50,51,701,77):raise AssertionError("unexpected fake close")
  if fd==self.target:
   if self.attempts[fd]==1:raise OSError(Hostile())
   self.sentinel_touched=True
 def pipe(self):
  if mode.startswith("anchor_"):return (50,51)
  raise AssertionError("unexpected fake pipe")
 def set_blocking(self,fd,flag):
  if fd not in (401,402,403,51):raise AssertionError("unexpected fake set_blocking")
 def write(self,fd,data):
  if fd in (401,51):return len(data)
  raise AssertionError("unexpected fake write")
 def listdir(self,path):
  if mode=="proc_scan" and path=="/proc":return ["4242"]
  raise AssertionError("unexpected fake listdir")
 def pidfd_open(self,pid,flags):
  if mode=="member_pidfd" and pid==4242:return 77
  raise AssertionError("unexpected fake pidfd_open")
proxy=FakeOS();m.os=proxy
class FakeBackend:
 wnowait=1;p_pid=1;wexited=1;wnohang=1
 def __init__(self):self.killed=[];self.reaped=[];self.opened_pidfd=False
 def pipe(self):return (10,11)
 def fork(self):return 4242
 def close(self,fd):proxy.close(fd)
 def read_identity(self,pid):
  return m.read_proc_identity(pid) if mode=="cap_proc" else (42,1)
 def pidfd_open(self,pid,flags):self.opened_pidfd=True;return 12
 def pidfd_send_signal(self,*args):return None
 def terminal(self,pid):return True
 def scan_members(self,pgid):return [(4242,1)]
 def write(self,fd,data):return len(data)
 def kill(self,pid,sig):self.killed.append(pid)
 def waitpid(self,pid,options):self.reaped.append(pid);return (pid,0)
backend=FakeBackend()
class FakeStream:
 def __init__(self,name,fd):self.name=name;self.fd=fd;self.state=False;self.attempts=0;self.retry=False
 def fileno(self):return self.fd
 @property
 def closed(self):
  if mode=="stream_state_getter" and self.name=="stdin":raise OSError(Hostile())
  return self.state
 def close(self):
  self.attempts+=1
  if mode.startswith("stream_") and self.name in mode and mode!="stream_state_getter":
   if self.attempts==1:
    if mode.endswith("after"):self.state=True
    raise OSError(Hostile())
   self.retry=True
  self.state=True
class FakeProc:
 def __init__(self):
  self.pid=9001;self.returncode=0
  self.stdin=FakeStream("stdin",401);self.stdout=FakeStream("stdout",402);self.stderr=FakeStream("stderr",403)
proc=FakeProc()
class FakeSelector:
 def __init__(self):self.keys=[];self.close_attempts=0
 def register(self,obj,events,data):self.keys.append(types.SimpleNamespace(fileobj=obj,data=data))
 def unregister(self,obj):self.keys=[k for k in self.keys if k.fileobj is not obj]
 def get_map(self):return self.keys
 def select(self,timeout):
  wanted=("stdin" if mode.startswith("stream_inloop_stdin") else
          "out" if mode.startswith("stream_inloop_stdout") else
          "err" if mode.startswith("stream_inloop_stderr") else
          "anchor" if mode=="anchor_write" else None)
  keys=[k for k in self.keys if k.data[1]==wanted] if wanted else self.keys
  return [(keys[0],0)] if keys else []
 def close(self):
  self.close_attempts+=1
  if mode=="selector_close":raise OSError(Hostile())
selector=FakeSelector()
m.open_status_dir=(m.open_status_dir if mode=="status_ancestry" else lambda:301)
if mode=="status_ancestry":
 m.check_protected_dir=lambda _fd,_mode=None:types.SimpleNamespace()
 m.same_entry=lambda *_args:None
m.open_scope_lock=lambda _fd,_name:302
m.check_signal=lambda:None
m.preexisting_generation=lambda _fd,_scope:m._PriorSummarySnapshot(m._PriorSummaryState.ABSENT)
m.encode_document=lambda _record,_scope:b"{}"
published=[];m.publish=lambda *_args:published.append(True)
child_owned=[];m.own_child_until_proved=lambda child:child_owned.append(child.pid) or False
m.leader_terminal=lambda child:True
if mode.startswith("cap_"):
 original=m.validate_process_capability
 m.validate_process_capability=lambda:original(backend)
else:
 m.validate_process_capability=lambda:None
if mode.startswith(("stream_","anchor_")) or mode=="selector_close":
 m.subprocess.Popen=lambda *args,**kwargs:proc
 if mode.startswith("stream_final") or mode=="stream_state_getter":
  m.selectors.DefaultSelector=lambda:(_ for _ in ()).throw(m.Incomplete("child_run_unproved"))
 else:m.selectors.DefaultSelector=lambda:selector
 def collect(_scope,_previous):
  return m.run_fixed((m.OPENSSL,m.TRUST_FD_OPERAND) if mode.startswith("anchor_") else (m.OPENSSL,),
                     input_bytes=b"",anchor_bytes=b"x" if mode.startswith("anchor_") else None)
 m.collect=collect
elif mode=="proc_scan":m.collect=lambda _scope,_previous:m.scan_group_members(42)
elif mode=="member_pidfd":
 m.scan_group_members=lambda _pgid:[(4242,1)]
 m.read_proc_identity=lambda _pid:(42,1)
 m.signal=types.SimpleNamespace(pidfd_send_signal=lambda *_args:None)
 m.collect=lambda _scope,_previous:m.signal_same_group_members(42,15)
else:
 def settled(_scope,_previous):raise m.Incomplete("unexpected_openssl_grammar")
 m.collect=settled
rc=m.main(["--scope",scope])
first=dict(rc=rc,selection=m.WITNESS_SELECTION,uncertain=m.WITNESS_DISPOSITION_UNPROVED,
           proved=m.WITNESS_CLOSEOUT_PROVED,published=len(published),
           close_order=proxy.closed[-2:] if mode!="status_ancestry" else [],
           target_attempts=proxy.attempts.get(proxy.target,0) if proxy.target is not None else 0,
           child_close_attempts=proxy.attempts.get(202,0),sentinel_touched=proxy.sentinel_touched,
           stream_attempts={s.name:s.attempts for s in (proc.stdin,proc.stdout,proc.stderr)},
           stream_retry=any(s.retry for s in (proc.stdin,proc.stdout,proc.stderr)),
           selector_close_attempts=selector.close_attempts,
           child_owner_calls=len(child_owned),probe_reaped=backend.reaped==[4242],
           prior_preserved=prior.read_bytes()==b"prior generation retained")
def emit():
 lines=[]
 env=dict(re=re,uncaught=[False],owned_fds={"parent":False,"directory":False,"file":False},
          collector_started=True,stage_closeout=True,collector_failure_exit=True,
          collector_namespace=dict(WITNESS_SELECTION=m.WITNESS_SELECTION,
           WITNESS_CLOSEOUT_PROVED=m.WITNESS_CLOSEOUT_PROVED,
           WITNESS_DISPOSITION_UNPROVED=m.WITNESS_DISPOSITION_UNPROVED),
          scope_value=scope,verified_digest="a"*64,write_failure_witness=lines.append)
 exec(compile(ast.Module(body=selected,type_ignores=[]),"<exact-bootstrap-gate>","exec"),env)
 env["emit_failure_witness"]()
 return lines
lines=emit()
first["sink_attempts"]=len(lines)
first["hostile_leak"]=any(b"hostile close payload" in line or b"\x1b" in line for line in lines)
first["line_exact"]=lines==[("ES_TLS_STATUS_FAILURE_V1 scope="+scope+
 " origin=collector source=verified collector_sha256="+"a"*64+
 " phase=collection reason="+("openssl_child_unproved" if mode=="stream_state_getter" else "openssl_grammar_unaccepted")+"\n").encode("ascii")]
if mode=="cap_proc":
 m.validate_process_capability=lambda:None
 def settled_again(_scope,_previous):raise m.Incomplete("unexpected_openssl_grammar")
 m.collect=settled_again
 second_rc=m.main(["--scope",scope]);second_lines=emit()
 first["next_invocation_reset"]=(second_rc==1 and m.WITNESS_DISPOSITION_UNPROVED is False and
  m.WITNESS_CLOSEOUT_PROVED is True and m.WITNESS_SELECTION==("collection","openssl_grammar_unaccepted") and
  len(second_lines)==1)
print(json.dumps(first,sort_keys=True))
`
	modes := []string{
		"stream_inloop_stdin_before", "stream_inloop_stdin_after",
		"stream_inloop_stdout_before", "stream_inloop_stdout_after",
		"stream_inloop_stderr_before", "stream_inloop_stderr_after",
		"stream_final_stdin_before", "stream_final_stdin_after",
		"stream_final_stdout_before", "stream_final_stdout_after",
		"stream_final_stderr_before", "stream_final_stderr_after",
		"stream_state_getter", "anchor_read", "anchor_write", "selector_close",
		"cap_read", "cap_write", "cap_proc", "cap_pidfd", "proc_scan", "member_pidfd",
		"status_ancestry", "settled",
	}
	for _, scope := range []string{"artifact-registry", "execution-governance"} {
		for _, mode := range modes {
			t.Run(scope+"/"+mode, func(t *testing.T) {
				got := runRemoteAlphaESFailureWitnessProbe(t, probe, t.TempDir(), scope, mode)
				phase, reason := "collection", "openssl_child_unproved"
				if strings.HasPrefix(mode, "cap_") {
					phase, reason = "process_capability", "process_capability_unproved"
				} else if mode == "status_ancestry" {
					phase, reason = "protected_ancestry", "unknown"
				} else if mode == "proc_scan" {
					reason = "unknown"
				} else if mode == "settled" {
					reason = "openssl_grammar_unaccepted"
				}
				selection, ok := got["selection"].([]any)
				if got["rc"] != float64(1) || !ok || !sameFailureWitnessSequence(selection, []any{phase, reason}) ||
					got["published"] != float64(0) || got["prior_preserved"] != true || got["hostile_leak"] != false {
					t.Fatalf("resource failure changed public outcome or disclosed payload: %v", got)
				}
				if mode == "status_ancestry" {
					if got["target_attempts"] != float64(1) || got["child_close_attempts"] != float64(1) ||
						got["sentinel_touched"] != false || len(got["close_order"].([]any)) != 0 {
						t.Fatalf("protected ancestry retried ambiguous parent or abandoned child: %v", got)
					}
				} else if !sameFailureWitnessSequence(got["close_order"].([]any), []any{float64(302), float64(301)}) {
					t.Fatalf("main lock/status close order changed: %v", got)
				}
				if strings.HasPrefix(mode, "stream_") && mode != "stream_state_getter" {
					name := "stdin"
					if strings.Contains(mode, "stdout") {
						name = "stdout"
					}
					if strings.Contains(mode, "stderr") {
						name = "stderr"
					}
					attempts := got["stream_attempts"].(map[string]any)
					if attempts[name] != float64(1) || got["stream_retry"] != false {
						t.Fatalf("failed stream received a second close attempt: %v", got)
					}
				} else if mode == "stream_state_getter" {
					attempts := got["stream_attempts"].(map[string]any)
					for _, name := range []string{"stdin", "stdout", "stderr"} {
						if attempts[name] != float64(1) {
							t.Fatalf("private close tokens did not settle all streams: %v", got)
						}
					}
				} else if mode == "selector_close" {
					if got["selector_close_attempts"] != float64(1) {
						t.Fatalf("selector close attempt changed: %v", got)
					}
				} else if mode != "settled" {
					if got["target_attempts"] != float64(1) || got["sentinel_touched"] != false {
						t.Fatalf("numeric close retried or touched synthetic reused number: %v", got)
					}
				}
				if strings.HasPrefix(mode, "cap_") && got["probe_reaped"] != true {
					t.Fatalf("synthetic capability child was not reaped: %v", got)
				}
				if strings.HasPrefix(mode, "stream_") || strings.HasPrefix(mode, "anchor_") || mode == "selector_close" {
					if got["child_owner_calls"].(float64) < 1 {
						t.Fatalf("fake child owner was bypassed: %v", got)
					}
				}
				settled := mode == "settled" || mode == "stream_state_getter"
				if settled {
					if got["uncertain"] != false || got["proved"] != true || got["sink_attempts"] != float64(1) || got["line_exact"] != true {
						t.Fatalf("settled failure lost exact eligible witness: %v", got)
					}
				} else if got["uncertain"] != true || got["proved"] != false || got["sink_attempts"] != float64(0) {
					t.Fatalf("unproved resource close earned witness sink: %v", got)
				}
				if mode == "cap_proc" && got["next_invocation_reset"] != true {
					t.Fatalf("next invocation inherited stale uncertainty: %v", got)
				}
			})
		}
	}
}

// These finite matrices exercise the actual collector functions through local
// fake descriptor lifetimes. The F3 owner fixture controls group observations
// while retaining run_fixed, terminate_child, reap_child, and the owner loop.
func TestRemoteAlphaESServiceTLSStatusFailureWitnessPendingFixedInputCloseout(t *testing.T) {
	const probe = `
import ast,importlib.util,json,os,pathlib,re,stat,sys,types
source,shell,root_arg,scope,consumer,mode=sys.argv[1:]
root=pathlib.Path(root_arg);prior=root/'prior-summary';prior.write_bytes(b'prior generation retained')
spec=importlib.util.spec_from_file_location('pending_f1_collector',source)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
text=pathlib.Path(shell).read_text();mark="IFS= read -r -d '' bootstrap <<'REMOTE_ALPHA_ES_TLS_STATUS_BOOTSTRAP' || true\n"
start=text.index(mark)+len(mark);end=text.index('\nREMOTE_ALPHA_ES_TLS_STATUS_BOOTSTRAP\n',start)
tree=ast.parse(text[start:end]);nodes=[n for n in tree.body if (isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='_FAILURE_WITNESS_COUPLINGS' for t in n.targets)) or (isinstance(n,ast.FunctionDef) and n.name in ('format_failure_witness','emit_failure_witness'))]
assert len(nodes)==3
class FakeOS:
 def __init__(self):
  self.attempts=[];self.counts={};self.reads=0;self.retry=False
 def __getattr__(self,name):return getattr(os,name)
 def open(self,name,flags,*args,**kwargs):
  key=(name,kwargs.get('dir_fd'));mapping={('/',None):10,('a',10):11,('b',11):12,('c',12):13,('file',13):14}
  assert key in mapping,key
  return mapping[key]
 def fstat(self,fd):
  assert fd in (10,11,12,13,14),fd
  return types.SimpleNamespace(st_mode=(stat.S_IFREG|0o600) if fd==14 else (stat.S_IFDIR|0o700),st_uid=0,st_gid=0,st_nlink=1,st_size=2 if fd==14 else 0,st_dev=1,st_ino=fd)
 def stat(self,name,*args,**kwargs):
  assert name=='file' and kwargs.get('dir_fd')==13
  return self.fstat(14)
 def read(self,fd,n):
  assert fd==14
  self.reads+=1
  return b'{}' if self.reads==1 else b''
 def close(self,fd):
  self.attempts.append(fd);self.counts[fd]=self.counts.get(fd,0)+1
  faults={'leaf':{14},'ancestor_last':{13},'ancestor_middle':{12},'ancestor_first':{11},'ancestor_root':{10},'leaf_and_middle':{14,12},'invalid_child_and_middle':{13,12}}.get(mode,set())
  if fd in faults:
   if self.counts[fd]==1:raise OSError('synthetic close fault')
   self.retry=True
  assert fd in (10,11,12,13,14,30,31),fd
fake=FakeOS();m.os=fake
m.check_input_ancestor=lambda info: (_ for _ in ()).throw(OSError('invalid child')) if mode=='invalid_child_and_middle' and info.st_ino==13 else None
m.check_extended=lambda fd:None;m.same_entry=lambda *args:None;m.same_leaf=lambda *args:None
m.file_identity=lambda info:info.st_ino;m.leaf_identity=lambda info:info.st_ino
m.CONFIG['ars']='/a/b/c/file'
m.ES_TLS_STATUS_BOOTSTRAP_VERIFIED=True;m.ES_TLS_STATUS_BOOTSTRAP_INTERRUPTED=[False];m.SIGNALS=();m.LATCHED_SIGNAL=None
m.open_status_dir=lambda:30;m.open_scope_lock=lambda *args:31;m.validate_process_capability=lambda:None
m.preexisting_generation=lambda *args:m._PriorSummarySnapshot(m._PriorSummaryState.ABSENT)
m.check_signal=lambda:None
published=[];m.publish=lambda *args:published.append(True)
m.run_fixed=lambda *args,**kwargs:(_ for _ in ()).throw(m.Incomplete('unexpected_openssl_grammar'))
def collect(scope_name,previous):
 if consumer=='config':m.read_config('ars',True)
 elif consumer=='certificate':m.cert_metadata('/a/b/c/file')
 else:m.key_pair('fixture',{'public_key_sha256':'0'*64},'/a/b/c/file')
 raise m.Incomplete('unexpected_openssl_grammar')
m.collect=collect
rc=m.main(['--scope',scope])
lines=[];env=dict(re=re,uncaught=[False],owned_fds={'parent':False,'directory':False,'file':False},collector_started=True,stage_closeout=True,collector_failure_exit=True,collector_namespace=dict(WITNESS_SELECTION=m.WITNESS_SELECTION,WITNESS_CLOSEOUT_PROVED=m.WITNESS_CLOSEOUT_PROVED,WITNESS_DISPOSITION_UNPROVED=m.WITNESS_DISPOSITION_UNPROVED),scope_value=scope,verified_digest='a'*64,write_failure_witness=lines.append)
exec(compile(ast.Module(body=nodes,type_ignores=[]),'<exact-bootstrap-gate>','exec'),env);env['emit_failure_witness']()
expected_input=[13,12,11,10] if mode=='invalid_child_and_middle' else [14,13,12,11,10]
input_attempts=[fd for fd in fake.attempts if fd not in (30,31)]
settled=mode=='settled'
result={'scope':scope,'consumer':consumer,'mode':mode,'rc':rc,'input_attempts':input_attempts,'expected_input_attempts':expected_input,'all_once':all(n==1 for n in fake.counts.values()),'retry':fake.retry,'main_close_order':fake.attempts[-2:],'uncertain':m.WITNESS_DISPOSITION_UNPROVED,'proved':m.WITNESS_CLOSEOUT_PROVED,'sink_attempts':len(lines),'prior_preserved':prior.read_bytes()==b'prior generation retained','published':len(published),'selection':m.WITNESS_SELECTION}
print(json.dumps(result,sort_keys=True),flush=True)
assert input_attempts==expected_input and result['all_once'] and not result['retry']
assert rc==1 and result['main_close_order']==[31,30] and result['prior_preserved'] and result['published']==0
assert result['uncertain']==(not settled) and result['proved']==settled and result['sink_attempts']==(1 if settled else 0)
assert m.WITNESS_SELECTION==('collection','openssl_grammar_unaccepted' if settled else 'fixed_input_unproved')
`
	for _, scope := range []string{"artifact-registry", "execution-governance"} {
		for _, consumer := range []string{"config", "certificate", "key"} {
			for _, mode := range []string{"settled", "leaf", "ancestor_last", "ancestor_middle", "ancestor_first", "ancestor_root", "leaf_and_middle", "invalid_child_and_middle"} {
				t.Run(scope+"/"+consumer+"/"+mode, func(t *testing.T) {
					got := runRemoteAlphaESFailureWitnessProbe(t, probe, t.TempDir(), scope, consumer, mode)
					if got["scope"] != scope || got["consumer"] != consumer || got["mode"] != mode {
						t.Fatalf("wrong finite fixed-input fixture result: %v", got)
					}
				})
			}
		}
	}
}

func TestRemoteAlphaESServiceTLSStatusFailureWitnessPendingMainCloseout(t *testing.T) {
	const probe = `
import ast,importlib.util,json,os,pathlib,re,sys,threading,types
source,shell,root_arg,scope,mode=sys.argv[1:]
root=pathlib.Path(root_arg);prior=root/'prior-summary';prior.write_bytes(b'prior generation retained')
spec=importlib.util.spec_from_file_location('pending_f2_collector',source);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
text=pathlib.Path(shell).read_text();mark="IFS= read -r -d '' bootstrap <<'REMOTE_ALPHA_ES_TLS_STATUS_BOOTSTRAP' || true\n"
start=text.index(mark)+len(mark);end=text.index('\nREMOTE_ALPHA_ES_TLS_STATUS_BOOTSTRAP\n',start)
tree=ast.parse(text[start:end]);nodes=[n for n in tree.body if (isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='_FAILURE_WITNESS_COUPLINGS' for t in n.targets)) or (isinstance(n,ast.FunctionDef) and n.name in ('format_failure_witness','emit_failure_witness'))]
assert len(nodes)==3
class FakeOS:
 def __init__(self):self.attempts=[];self.counts={};self.retry=False
 def __getattr__(self,name):return getattr(os,name)
 def close(self,fd):
  assert fd in (30,31),fd
  self.attempts.append(fd);self.counts[fd]=self.counts.get(fd,0)+1
  faults={'lock':{31},'status':{30},'both':{31,30},'prelock_status':{30},'lock_interrupt':{31},'status_interrupt':{30}}.get(mode,set())
  if fd in faults:
   if self.counts[fd]==1:
    if mode.endswith('_interrupt'):raise KeyboardInterrupt()
    raise OSError('synthetic close fault')
   self.retry=True
fake=FakeOS();m.os=fake
m.ES_TLS_STATUS_BOOTSTRAP_VERIFIED=True;m.ES_TLS_STATUS_BOOTSTRAP_INTERRUPTED=[False];m.SIGNALS=();m.LATCHED_SIGNAL=None
m.open_status_dir=lambda:30
m.open_scope_lock=lambda *args:(_ for _ in ()).throw(m.Incomplete('same_scope_lock_contended')) if mode.startswith('prelock') else 31
m.validate_process_capability=lambda:None;m.preexisting_generation=lambda *args:m._PriorSummarySnapshot(m._PriorSummaryState.ABSENT)
m.check_signal=lambda:None
published=[];m.publish=lambda *args:published.append(True)
entered=threading.Event();release=threading.Event();before=[]
if mode=='unresolved_owner':
 proc=types.SimpleNamespace(_status_reaped=False)
 def controlled_terminate(_proc):
  entered.set();assert release.wait(2),'owner release missing';return False
 m.terminate_child=controlled_terminate
 def collect(*args):
  m.own_child_until_proved(proc)
  raise m.Incomplete('unexpected_openssl_grammar')
else:
 def collect(*args):raise m.Incomplete('unexpected_openssl_grammar')
m.collect=collect
outcome={}
def run_main():
 try:outcome['rc']=m.main(['--scope',scope])
 except BaseException as e:outcome['error']=type(e).__name__
if mode=='unresolved_owner':
 thread=threading.Thread(target=run_main);thread.start();assert entered.wait(2),'owner did not enter'
 before=[list(fake.attempts),m.WITNESS_CLOSEOUT_PROVED];release.set();thread.join(2);assert not thread.is_alive(),'owner did not finish'
else:run_main()
lines=[];env=dict(re=re,uncaught=['error' in outcome],owned_fds={'parent':False,'directory':False,'file':False},collector_started=True,stage_closeout=True,collector_failure_exit=True,collector_namespace=dict(WITNESS_SELECTION=m.WITNESS_SELECTION,WITNESS_CLOSEOUT_PROVED=m.WITNESS_CLOSEOUT_PROVED,WITNESS_DISPOSITION_UNPROVED=m.WITNESS_DISPOSITION_UNPROVED),scope_value=scope,verified_digest='a'*64,write_failure_witness=lines.append)
exec(compile(ast.Module(body=nodes,type_ignores=[]),'<exact-bootstrap-gate>','exec'),env);env['emit_failure_witness']()
expected=[30] if mode.startswith('prelock') else [31,30]
fault=mode in ('lock','status','both','prelock_status','lock_interrupt','status_interrupt')
interrupted=mode.endswith('_interrupt')
result={'scope':scope,'mode':mode,'rc':outcome.get('rc'),'error':outcome.get('error'),'attempts':fake.attempts,'expected':expected,'all_once':all(x==1 for x in fake.counts.values()),'retry':fake.retry,'uncertain':m.WITNESS_DISPOSITION_UNPROVED,'proved':m.WITNESS_CLOSEOUT_PROVED,'sink_attempts':len(lines),'published':len(published),'prior_preserved':prior.read_bytes()==b'prior generation retained','selection':m.WITNESS_SELECTION,'before_owner_release':before}
print(json.dumps(result,sort_keys=True),flush=True)
assert fake.attempts==expected and result['all_once'] and not result['retry']
assert (result['rc'] is None and result['error']=='KeyboardInterrupt') if interrupted else (result['rc']==1 and result['error'] is None)
assert result['uncertain']==fault and result['proved']==(not fault) and result['sink_attempts']==(0 if fault else 1)
assert result['published']==0 and result['prior_preserved']
if mode=='unresolved_owner':assert before==[[],False]
if mode.startswith('prelock'):assert m.WITNESS_SELECTION==('scope_lock','lock_acquisition_unproved')
else:assert m.WITNESS_SELECTION==('collection','openssl_grammar_unaccepted')
`
	for _, scope := range []string{"artifact-registry", "execution-governance"} {
		for _, mode := range []string{"settled", "lock", "status", "both", "prelock", "prelock_status", "lock_interrupt", "status_interrupt", "unresolved_owner"} {
			t.Run(scope+"/"+mode, func(t *testing.T) {
				got := runRemoteAlphaESFailureWitnessProbe(t, probe, t.TempDir(), scope, mode)
				if got["scope"] != scope || got["mode"] != mode {
					t.Fatalf("wrong finite main closeout fixture result: %v", got)
				}
			})
		}
	}
}

func TestRemoteAlphaESServiceTLSStatusFailureWitnessPendingMemberCloseout(t *testing.T) {
	const probe = `
import importlib.util,json,os,signal,sys,types
source,_shell,scope,mode=sys.argv[1:]
spec=importlib.util.spec_from_file_location('pending_f3_members',source);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class FakeOS:
 def __init__(self):self.opened=[];self.closed=[];self.lifetimes={};self.attempts={};self.retry=False;self.proc_attempts=0
 def __getattr__(self,name):return getattr(os,name)
 def pidfd_open(self,pid,flags):
  if mode=='acquire_first' and pid==101:raise OSError('synthetic acquisition fault')
  if mode=='acquire_gone' and pid==101:raise ProcessLookupError('synthetic gone')
  fd=41 if pid==101 or (mode=='reuse_number' and pid==102) else 42 if pid==102 else 43
  life=len(self.opened)+1;self.opened.append([pid,fd,life]);self.lifetimes[fd]=(pid,fd,life);return fd
 def open(self,path,flags,*args,**kwargs):
  assert mode=='identity_proc_close' and path=='/proc/101/stat',path
  return 701
 def read(self,fd,n):
  assert fd==701
  return b'101 (fixture) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1\n'
 def close(self,fd):
  if fd==701:
   self.proc_attempts+=1
   assert self.proc_attempts==1
   raise OSError('synthetic proc close fault')
  life=self.lifetimes[fd];self.closed.append(list(life));self.attempts[life]=self.attempts.get(life,0)+1
  faults={'close_first':{101},'close_second':{102},'close_third':{103},'close_pair':{101,103},'reuse_number':{101},'signal_and_close':{101}}.get(mode,set())
  if life[0] in faults and self.attempts[life]==1:raise OSError('synthetic member close fault')
  if self.attempts[life]>1:self.retry=True
fake=FakeOS();m.os=fake
m.scan_group_members=lambda pgid:[(101,1),(102,2),(103,3)]
checks=[];original_read=m.read_proc_identity
def read_identity(pid):
 checks.append(pid)
 if mode=='identity_proc_close' and pid==101:return original_read(pid)
 return (42,999 if pid==103 else 1 if pid==101 else 2)
m.read_proc_identity=read_identity
signals=[]
def send(fd,signum,*args):
 pid=fake.lifetimes[fd][0];signals.append(pid)
 if mode in ('signal_first','signal_and_close') and pid==101:raise OSError('synthetic signal fault')
 if mode=='signal_gone' and pid==101:raise ProcessLookupError('synthetic gone')
m.signal=types.SimpleNamespace(pidfd_send_signal=send)
error=None;reason=None
try:m.signal_same_group_members(42,signal.SIGTERM)
except Exception as exc:error=type(exc).__name__;reason=exc.args[0] if type(exc) is m.Incomplete and exc.args else None
unproved=mode in ('close_first','close_second','close_third','close_pair','reuse_number','acquire_first','signal_first','signal_and_close','identity_proc_close')
sticky=mode in ('close_first','close_second','close_third','close_pair','reuse_number','signal_and_close','identity_proc_close')
expected_open=[102,103] if mode in ('acquire_first','acquire_gone') else [101,102,103]
expected_signal=[102] if mode in ('acquire_first','acquire_gone','identity_proc_close') else [101,102]
expected_checks=[102,103] if mode in ('acquire_first','acquire_gone') else [101,102,103]
result={'scope':scope,'mode':mode,'error':error,'reason':reason,'opened':fake.opened,'closed':fake.closed,'checks':checks,'signals':signals,'proc_close_attempts':fake.proc_attempts,'retry':fake.retry,'sticky':m.WITNESS_DISPOSITION_UNPROVED}
print(json.dumps(result,sort_keys=True),flush=True)
assert [x[0] for x in fake.opened]==expected_open
assert [x[0] for x in fake.closed]==expected_open and all(x==1 for x in fake.attempts.values()) and not fake.retry
assert checks==expected_checks and signals==expected_signal
assert (error=='Incomplete' and reason=='process_member_signal_unproved') if unproved else error is None
assert m.WITNESS_DISPOSITION_UNPROVED==sticky
if mode=='reuse_number':assert fake.opened[0][1]==fake.opened[1][1] and fake.closed[0][2]!=fake.closed[1][2]
`
	for _, scope := range []string{"artifact-registry", "execution-governance"} {
		for _, mode := range []string{"settled", "close_first", "close_second", "close_third", "close_pair", "reuse_number", "acquire_first", "acquire_gone", "signal_first", "signal_gone", "signal_and_close", "identity_proc_close"} {
			t.Run(scope+"/"+mode, func(t *testing.T) {
				got := runRemoteAlphaESFailureWitnessProbe(t, probe, scope, mode)
				if got["scope"] != scope || got["mode"] != mode {
					t.Fatalf("wrong finite member closeout fixture result: %v", got)
				}
			})
		}
	}
}

func TestRemoteAlphaESServiceTLSStatusFailureWitnessPendingOwnerComposition(t *testing.T) {
	const probe = `
import ast,importlib.util,json,os,pathlib,re,selectors,signal,sys,types
source,shell,root_arg,scope=sys.argv[1:]
root=pathlib.Path(root_arg);prior=root/'prior-summary';prior.write_bytes(b'prior generation retained')
spec=importlib.util.spec_from_file_location('pending_f3_owner',source);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
module=m
` + remoteAlphaESStatusLocalChildNamespace + `text=pathlib.Path(shell).read_text();mark="IFS= read -r -d '' bootstrap <<'REMOTE_ALPHA_ES_TLS_STATUS_BOOTSTRAP' || true\n"
start=text.index(mark)+len(mark);end=text.index('\nREMOTE_ALPHA_ES_TLS_STATUS_BOOTSTRAP\n',start)
tree=ast.parse(text[start:end]);nodes=[n for n in tree.body if (isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='_FAILURE_WITNESS_COUPLINGS' for t in n.targets)) or (isinstance(n,ast.FunctionDef) and n.name in ('format_failure_witness','emit_failure_witness'))]
assert len(nodes)==3
events=[];alive={9002,9003};scan_round=[0];first_helper_round=[None];reap_count=[0]
class FakeStream:
 def __init__(self,name):self.name=name;self.count=0
 def close(self):self.count+=1;events.append(['stream_close',self.name])
class FakeProc:
 pid=9001;returncode=None;stdin=None
 def __init__(self):self.stdout=FakeStream('stdout');self.stderr=FakeStream('stderr');self._status_reaped=False
proc=FakeProc()
class FakeOS:
 def __init__(self):self.counts={}
 def __getattr__(self,name):return getattr(os,name)
 def killpg(self,pgid,signum):
  assert pgid==9001;events.append(['group_signal_denied',int(signum)]);raise PermissionError('controlled group denial')
 def pidfd_open(self,pid,flags):
  assert pid in (9001,9002,9003);fd={9001:51,9002:52,9003:53}[pid]
  if first_helper_round[0] is None:first_helper_round[0]=scan_round[0]
  events.append(['pin',pid,scan_round[0]]);return fd
 def close(self,fd):
  if fd in (30,31):events.append(['main_close',fd]);return
  assert fd in (51,52,53),fd
  self.counts[fd]=self.counts.get(fd,0)+1;events.append(['pidfd_close',fd,scan_round[0]])
  if fd==52 and self.counts[fd]==1:raise OSError('synthetic first member close fault')
 def waitpid(self,pid,options):
  assert pid==9001 and options==os.WNOHANG
  reap_count[0]+=1;events.append(['reap',pid]);return pid,0
fake=FakeOS();m.os=fake

def scan(pgid):
 assert pgid==9001
 scan_round[0]+=1
 if proc._status_reaped:
  events.append(['absence_scan',scan_round[0]]);return []
 members=[(9001,1)]+[(pid,pid-9000) for pid in sorted(alive)]
 events.append(['scan',scan_round[0],[pid for pid,_ in members]])
 return members
m.scan_group_members=scan
m.read_proc_identity=lambda pid:(9001,1 if pid==9001 else pid-9000)
m.leader_terminal=lambda observed:observed is proc

def send(fd,signum,*args):
 pid={51:9001,52:9002,53:9003}[fd]
 events.append(['member_signal',pid,scan_round[0],int(signum)])
 if pid in alive:alive.remove(pid)
m.signal=types.SimpleNamespace(SIGTERM=signal.SIGTERM,SIGKILL=signal.SIGKILL,pidfd_send_signal=send)
m.CHILD_GRACE=0.05
m.ES_TLS_STATUS_BOOTSTRAP_VERIFIED=True;m.ES_TLS_STATUS_BOOTSTRAP_INTERRUPTED=[False];m.SIGNALS=();m.LATCHED_SIGNAL=None
m.open_status_dir=lambda:30;m.open_scope_lock=lambda *args:31;m.validate_process_capability=lambda:None
m.preexisting_generation=lambda *args:m._PriorSummarySnapshot(m._PriorSummaryState.ABSENT)
m.check_signal=lambda:None
published=[];m.publish=lambda *args:published.append(True)
m.subprocess.Popen=lambda *args,**kwargs:proc
m.selectors.DefaultSelector=lambda:(_ for _ in ()).throw(m.Incomplete('child_run_unproved'))
m.collect=lambda *args:m.run_fixed((m.OPENSSL,))
rc=m.main(['--scope',scope])
lines=[];env=dict(re=re,uncaught=[False],owned_fds={'parent':False,'directory':False,'file':False},collector_started=True,stage_closeout=True,collector_failure_exit=True,collector_namespace=dict(WITNESS_SELECTION=m.WITNESS_SELECTION,WITNESS_CLOSEOUT_PROVED=m.WITNESS_CLOSEOUT_PROVED,WITNESS_DISPOSITION_UNPROVED=m.WITNESS_DISPOSITION_UNPROVED),scope_value=scope,verified_digest='a'*64,write_failure_witness=lines.append)
exec(compile(ast.Module(body=nodes,type_ignores=[]),'<exact-bootstrap-gate>','exec'),env);env['emit_failure_witness']()
first=first_helper_round[0]
same_scan_later=any(e[0]=='member_signal' and e[1]==9003 and e[2]==first for e in events)
reap_index=next((i for i,e in enumerate(events) if e[0]=='reap'),-1)
absence_index=next((i for i,e in enumerate(events) if e[0]=='absence_scan'),-1)
main_indices=[i for i,e in enumerate(events) if e[0]=='main_close']
result={'scope':scope,'rc':rc,'first_helper_round':first,'later_member_signaled_same_scan':same_scan_later,'alive_at_return':sorted(alive),'reap_count':reap_count[0],'reaped':proc._status_reaped,'main_close_order':[events[i][1] for i in main_indices],'main_close_after_reap_absence':bool(main_indices) and min(main_indices)>max(reap_index,absence_index),'pidfd_counts':fake.counts,'events':events,'uncertain':m.WITNESS_DISPOSITION_UNPROVED,'proved':m.WITNESS_CLOSEOUT_PROVED,'sink_attempts':len(lines),'published':len(published),'prior_preserved':prior.read_bytes()==b'prior generation retained','selection':m.WITNESS_SELECTION,'fake_observations':True}
print(json.dumps(result,sort_keys=True),flush=True)
assert rc==1 and same_scan_later and not alive and reap_count==[1] and proc._status_reaped
assert result['main_close_order']==[31,30] and result['main_close_after_reap_absence']
assert fake.counts=={51:1,52:1,53:1} and proc.stdout.count==1 and proc.stderr.count==1
assert m.WITNESS_DISPOSITION_UNPROVED and not m.WITNESS_CLOSEOUT_PROVED and len(lines)==0 and not published and result['prior_preserved']
assert m.WITNESS_SELECTION==('collection','openssl_child_unproved')
`
	for _, scope := range []string{"artifact-registry", "execution-governance"} {
		t.Run(scope, func(t *testing.T) {
			got := runRemoteAlphaESFailureWitnessProbe(t, probe, t.TempDir(), scope)
			if got["scope"] != scope || got["fake_observations"] != true {
				t.Fatalf("wrong composed owner fixture result: %v", got)
			}
		})
	}
}

// This fixture calls the real fixed-input primitive and each consumer. All input
// descriptors and metadata are controlled local observations, with no host input.
func TestRemoteAlphaESServiceTLSStatusFailureWitnessInputAbsencePrecedence(t *testing.T) {
	const probe = `
import ast,datetime as dt,importlib.util,json,os,pathlib,re,stat,sys,types
source,shell,scope,consumer,mode,kind=sys.argv[1:]
spec=importlib.util.spec_from_file_location('absence_precedence_collector',source)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
assert scope in m.SCOPES and kind in ('direct','composed')
real_os=os
present=mode.startswith('present_') or mode=='read_fault_plus_close'
configs={name:{} for name in m.CONFIG}
chosen=m.SCOPES[scope]
def put(name,keys,value):
 node=configs[name]
 for key in keys[:-1]:node=node.setdefault(key,{})
 node[keys[-1]]=value
for _label,name,keys,value in chosen['bindings']:put(name,keys,value)
for _label,name,keys,port in chosen['urls']:put(name,keys,'https://127.0.0.1:'+str(port))
payloads={name:json.dumps(data).encode() for name,data in configs.items()}
optional=next(name for name in m.CONFIG if name not in chosen['required_config'])
file_numbers={name:20+i for i,name in enumerate(m.CONFIG)}
class HostileClose(OSError):
 def __str__(self):raise AssertionError('hostile close text was formatted')
 def __repr__(self):raise AssertionError('hostile close repr was formatted')
class FakeOS:
 def __init__(self):
  self.invocation=0;self.target=None;self.opened=[];self.closes=[];self.counts={};self.reads={};self.retry=False
 def __getattr__(self,name):return getattr(real_os,name)
 def open(self,name,flags,*args,**kwargs):
  parent=kwargs.get('dir_fd')
  if name=='/' and parent is None:self.invocation+=1;fd=10
  elif name=='a' and parent==10:fd=11
  elif name=='b' and parent==11:fd=12
  elif name=='c' and parent==12:fd=13
  elif parent==13 and name in (('file',) if kind=='direct' else tuple(m.CONFIG)):
   fd=14 if kind=='direct' else file_numbers[name]
  else:raise AssertionError(('unexpected open',name,parent))
  if kind=='direct' and name=='file' and not present:raise AssertionError('opened missing leaf')
  if kind=='composed' and name==optional:raise AssertionError('opened missing optional leaf')
  self.opened.append([self.invocation,fd,name]);return fd
 def fstat(self,fd):
  is_file=fd==14 or fd in file_numbers.values()
  size=2 if kind=='direct' else next((len(payloads[name]) for name,value in file_numbers.items() if value==fd),0)
  return types.SimpleNamespace(st_mode=(stat.S_IFREG|0o600) if is_file else (stat.S_IFDIR|0o700),st_uid=0,st_gid=0,st_nlink=1,st_size=size if is_file else 0,st_dev=1,st_ino=fd)
 def stat(self,name,*args,**kwargs):
  if kwargs.get('dir_fd')!=13:raise AssertionError(('unexpected stat',name,kwargs))
  if (kind=='direct' and name=='file' and not present) or (kind=='composed' and name==optional):
   self.target=self.invocation
   raise FileNotFoundError('synthetic missing final entry')
  if kind=='direct' and name!='file':raise AssertionError(('unexpected direct leaf',name))
  if kind=='composed' and name not in m.CONFIG:raise AssertionError(('unexpected config leaf',name))
  return self.fstat(14 if kind=='direct' else file_numbers[name])
 def read(self,fd,n):
  if kind=='direct' and mode=='read_fault_plus_close' and fd==14:raise OSError('synthetic read fault')
  key=(self.invocation,fd);self.reads[key]=self.reads.get(key,0)+1
  if kind=='direct':return b'{}' if self.reads[key]==1 else b''
  name=next(name for name,value in file_numbers.items() if value==fd)
  return payloads[name] if self.reads[key]==1 else b''
 def close(self,fd):
  key=(self.invocation,fd);self.closes.append([self.invocation,fd]);self.counts[key]=self.counts.get(key,0)+1
  if self.counts[key]>1:self.retry=True
  if fd in (30,31):return
  faults={'absent_close_last':{13},'absent_close_middle':{12},'absent_close_first':{11},'absent_close_root':{10},
          'absent_close_multi':{13,11},'absent_close_notfound':{12},'absent_close_hostile':{12},'absent_close_interrupt':{12},
          'absent_prior_incomplete_plus_close':{12},'present_leaf_close_notfound':{14},
          'present_root_close_notfound':{10},'present_ancestor_close_notfound':{12},
          'present_close_multi':{14,12},'invalid_child_close_notfound':{13},
          'root_validation_close_notfound':{10},'read_fault_plus_close':{12}}.get(mode,set())
  if kind=='composed' and self.invocation!=self.target:return
  if fd in faults and self.counts[key]==1:
   if mode=='absent_close_interrupt':raise KeyboardInterrupt()
   if mode.endswith('_hostile'):raise HostileClose()
   if mode.endswith('_notfound'):raise FileNotFoundError('synthetic close fault')
   raise OSError('synthetic close fault')
fake=FakeOS();m.os=fake
m.check_extended=lambda fd:None;m.same_entry=lambda *args:None;m.same_leaf=lambda *args:None
m.file_identity=lambda info:(info.st_dev,info.st_ino);m.leaf_identity=lambda info:(info.st_dev,info.st_ino)
root_checks=[0]
def check_ancestor(info):
 if mode=='root_validation_close_notfound' and info.st_ino==10:raise OSError('synthetic root validation fault')
 if mode=='invalid_child_close_notfound' and info.st_ino==13:raise OSError('synthetic invalid child')
 if mode=='absent_prior_incomplete_plus_close' and info.st_ino==10:
  root_checks[0]+=1
  if root_checks[0]>1:raise m.Incomplete('unsafe_input_ancestor')
m.check_input_ancestor=check_ancestor
if kind=='direct':
 m.CONFIG['ars']='/a/b/c/file'
 try:
  if consumer=='required_config':value=m.read_config('ars',True);completed=value[1]
  elif consumer=='optional_config':value=m.read_config('ars',False);completed=value[1]
  elif consumer=='certificate':value=m.cert_metadata('/a/b/c/file');completed=value[0]['code']
  elif consumer=='key':value=m.key_pair('fixture',{'public_key_sha256':'0'*64},'/a/b/c/file');completed=value['code']
  else:raise AssertionError('unknown consumer')
  error=None;literal=None
 except BaseException as exc:
  error=type(exc).__name__;literal=exc.args[0] if type(exc) is m.Incomplete and exc.args else None;completed=None
 target=fake.invocation
 expected=[10] if mode=='root_validation_close_notfound' else [13,12,11,10] if mode=='invalid_child_close_notfound' or not present else [14,13,12,11,10]
 attempts=[fd for invocation,fd in fake.closes if invocation==target]
 settled=mode=='absent_settled'
 expected_completed={'required_config':'config_missing','optional_config':'absent','certificate':'certificate_missing','key':'key_missing'}[consumer]
 result={'kind':kind,'scope':scope,'consumer':consumer,'mode':mode,'completed':completed,'error':error,'literal':literal,'attempts':attempts,'expected_attempts':expected,'sticky':m.WITNESS_DISPOSITION_UNPROVED,'retry':fake.retry,'all_once':all(n==1 for n in fake.counts.values()),'failure_reason':m._failure_reason('collection',m.Incomplete('fixed_input_close_unproved'))}
 print(json.dumps(result,sort_keys=True),flush=True)
 assert attempts==expected and result['all_once'] and not fake.retry
 if settled:assert completed==expected_completed and error is None and not result['sticky']
 elif mode=='absent_close_interrupt':assert error=='KeyboardInterrupt' and completed is None and result['sticky']
 elif mode=='absent_prior_incomplete_plus_close':assert error=='Incomplete' and literal=='unsafe_input_ancestor' and result['sticky']
 else:assert error=='Incomplete' and literal=='fixed_input_close_unproved' and completed is None and result['sticky']
 if not settled:assert result['failure_reason']=='fixed_input_unproved'
else:
 assert consumer=='optional_config'
 m.CONFIG={name:'/a/b/c/'+name for name in m.CONFIG}
 def cert_role(item,observed_at):
  label,path,role=item[:3]
  record={'label':label,'path':path,'role':role,'status':'pass','code':'pass','not_before':'2020-01-01T00:00:00Z','not_after':'2035-01-01T00:00:00Z','expired':False,'not_yet_valid':False,'sha256':'a'*64,'fingerprint_sha256':'b'*64,'public_key_sha256':'c'*64,'subject_sha256':'d'*64,'issuer_sha256':'e'*64,'san_match':True if role=='server' else None,'eku_match':None if role=='ca' else True}
  return record,b'fixture-cert'
 m.cert_role=cert_role
 m.key_pair=lambda label,cert,path:{'label':label,'status':'pass','code':'pass','matches':True}
 m.verify_chain=lambda *args:{'label':args[0],'status':'pass','code':'pass','purpose':args[-2],'hostname':args[-1]}
 m.ES_TLS_STATUS_BOOTSTRAP_VERIFIED=True;m.ES_TLS_STATUS_BOOTSTRAP_INTERRUPTED=[False];m.SIGNALS=();m.LATCHED_SIGNAL=None
 m.open_status_dir=lambda:30;m.open_scope_lock=lambda *args:31;m.validate_process_capability=lambda:None
 m.preexisting_generation=lambda *args:m._PriorSummarySnapshot(m._PriorSummaryState.ABSENT)
 m.check_signal=lambda:None
 original_encode=m.encode_document;encoded=[];published=[]
 def tracked_encode(record,scope_name):
  payload=original_encode(record,scope_name);encoded.append((record,payload));return payload
 m.encode_document=tracked_encode
 m.publish=lambda status_fd,scope_name,payload:published.append((status_fd,scope_name,payload))
 rc=m.main(['--scope',scope])
 text=pathlib.Path(shell).read_text();mark="IFS= read -r -d '' bootstrap <<'REMOTE_ALPHA_ES_TLS_STATUS_BOOTSTRAP' || true\n"
 start=text.index(mark)+len(mark);end=text.index('\nREMOTE_ALPHA_ES_TLS_STATUS_BOOTSTRAP\n',start)
 tree=ast.parse(text[start:end]);nodes=[n for n in tree.body if (isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='_FAILURE_WITNESS_COUPLINGS' for t in n.targets)) or (isinstance(n,ast.FunctionDef) and n.name in ('format_failure_witness','emit_failure_witness'))]
 assert len(nodes)==3
 lines=[];env=dict(re=re,uncaught=[False],owned_fds={'parent':False,'directory':False,'file':False},collector_started=True,stage_closeout=True,collector_failure_exit=True,collector_namespace=dict(WITNESS_SELECTION=m.WITNESS_SELECTION,WITNESS_CLOSEOUT_PROVED=m.WITNESS_CLOSEOUT_PROVED,WITNESS_DISPOSITION_UNPROVED=m.WITNESS_DISPOSITION_UNPROVED),scope_value=scope,verified_digest='a'*64,write_failure_witness=lines.append)
 exec(compile(ast.Module(body=nodes,type_ignores=[]),'<exact-bootstrap-gate>','exec'),env);env['emit_failure_witness']()
 target=fake.target
 assert target is not None
 attempts=[fd for invocation,fd in fake.closes if invocation==target and fd not in (30,31)]
 close_main=[fd for invocation,fd in fake.closes if fd in (30,31)]
 related=next((r for r in encoded[0][0]['topology'] if r['id']==optional+'_related_config'),None) if encoded else None
 result={'kind':kind,'scope':scope,'consumer':consumer,'mode':mode,'rc':rc,'target_invocation':target,'attempts':attempts,'main_closes':close_main,'encoded':len(encoded),'published_sink':len(published),'record_result':encoded[0][0]['result']['status'] if encoded else None,'related_code':related['code'] if related else None,'selection':m.WITNESS_SELECTION,'sticky':m.WITNESS_DISPOSITION_UNPROVED,'proved':m.WITNESS_CLOSEOUT_PROVED,'witness_sink':len(lines),'retry':fake.retry,'all_once':all(n==1 for n in fake.counts.values()),'sink_kind':'source-bound in-memory recorder; not protected publication'}
 print(json.dumps(result,sort_keys=True),flush=True)
 assert rc==1 and attempts==[13,12,11,10] and close_main==[31,30] and result['all_once'] and not fake.retry
 if mode=='absent_settled':
  assert len(encoded)==len(published)==1 and related['code']=='absent' and encoded[0][0]['result']=={'status':'pass','ok':True}
  assert not result['sticky'] and result['proved'] and len(lines)==1
 else:
  assert not encoded and not published and result['sticky'] and not result['proved'] and not lines
  assert m.WITNESS_SELECTION==('collection','fixed_input_unproved')
`
	for _, scope := range []string{"artifact-registry", "execution-governance"} {
		for _, consumer := range []string{"required_config", "optional_config", "certificate", "key"} {
			for _, mode := range []string{
				"absent_settled", "absent_close_last", "absent_close_middle", "absent_close_first",
				"absent_close_root", "absent_close_multi", "absent_close_notfound", "absent_close_hostile",
				"absent_close_interrupt", "absent_prior_incomplete_plus_close",
				"present_leaf_close_notfound", "present_root_close_notfound",
				"present_ancestor_close_notfound", "present_close_multi",
				"invalid_child_close_notfound", "root_validation_close_notfound",
				"read_fault_plus_close",
			} {
				t.Run(scope+"/"+consumer+"/"+mode, func(t *testing.T) {
					got := runRemoteAlphaESFailureWitnessProbe(t, probe, scope, consumer, mode, "direct")
					if got["scope"] != scope || got["consumer"] != consumer || got["mode"] != mode ||
						got["all_once"] != true || got["retry"] != false {
						t.Fatalf("fixed-input absence/cleanup case: %v", got)
					}
				})
			}
		}
	}
}

// Main, collect_topology, collect, and encode_document remain real here. The
// publication receiver is a labeled in-memory sink; no protected file is written.
func TestRemoteAlphaESServiceTLSStatusFailureWitnessOptionalAbsenceComposition(t *testing.T) {
	const probe = `
import ast,datetime as dt,importlib.util,json,os,pathlib,re,stat,sys,types
source,shell,scope,consumer,mode,kind=sys.argv[1:]
spec=importlib.util.spec_from_file_location('absence_precedence_collector',source)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
assert scope in m.SCOPES and kind in ('direct','composed')
real_os=os
present=mode.startswith('present_') or mode=='read_fault_plus_close'
configs={name:{} for name in m.CONFIG}
chosen=m.SCOPES[scope]
def put(name,keys,value):
 node=configs[name]
 for key in keys[:-1]:node=node.setdefault(key,{})
 node[keys[-1]]=value
for _label,name,keys,value in chosen['bindings']:put(name,keys,value)
for _label,name,keys,port in chosen['urls']:put(name,keys,'https://127.0.0.1:'+str(port))
payloads={name:json.dumps(data).encode() for name,data in configs.items()}
optional=next(name for name in m.CONFIG if name not in chosen['required_config'])
file_numbers={name:20+i for i,name in enumerate(m.CONFIG)}
class HostileClose(OSError):
 def __str__(self):raise AssertionError('hostile close text was formatted')
 def __repr__(self):raise AssertionError('hostile close repr was formatted')
class FakeOS:
 def __init__(self):
  self.invocation=0;self.target=None;self.opened=[];self.closes=[];self.counts={};self.reads={};self.retry=False
 def __getattr__(self,name):return getattr(real_os,name)
 def open(self,name,flags,*args,**kwargs):
  parent=kwargs.get('dir_fd')
  if name=='/' and parent is None:self.invocation+=1;fd=10
  elif name=='a' and parent==10:fd=11
  elif name=='b' and parent==11:fd=12
  elif name=='c' and parent==12:fd=13
  elif parent==13 and name in (('file',) if kind=='direct' else tuple(m.CONFIG)):
   fd=14 if kind=='direct' else file_numbers[name]
  else:raise AssertionError(('unexpected open',name,parent))
  if kind=='direct' and name=='file' and not present:raise AssertionError('opened missing leaf')
  if kind=='composed' and name==optional:raise AssertionError('opened missing optional leaf')
  self.opened.append([self.invocation,fd,name]);return fd
 def fstat(self,fd):
  is_file=fd==14 or fd in file_numbers.values()
  size=2 if kind=='direct' else next((len(payloads[name]) for name,value in file_numbers.items() if value==fd),0)
  return types.SimpleNamespace(st_mode=(stat.S_IFREG|0o600) if is_file else (stat.S_IFDIR|0o700),st_uid=0,st_gid=0,st_nlink=1,st_size=size if is_file else 0,st_dev=1,st_ino=fd)
 def stat(self,name,*args,**kwargs):
  if kwargs.get('dir_fd')!=13:raise AssertionError(('unexpected stat',name,kwargs))
  if (kind=='direct' and name=='file' and not present) or (kind=='composed' and name==optional):
   self.target=self.invocation
   raise FileNotFoundError('synthetic missing final entry')
  if kind=='direct' and name!='file':raise AssertionError(('unexpected direct leaf',name))
  if kind=='composed' and name not in m.CONFIG:raise AssertionError(('unexpected config leaf',name))
  return self.fstat(14 if kind=='direct' else file_numbers[name])
 def read(self,fd,n):
  if kind=='direct' and mode=='read_fault_plus_close' and fd==14:raise OSError('synthetic read fault')
  key=(self.invocation,fd);self.reads[key]=self.reads.get(key,0)+1
  if kind=='direct':return b'{}' if self.reads[key]==1 else b''
  name=next(name for name,value in file_numbers.items() if value==fd)
  return payloads[name] if self.reads[key]==1 else b''
 def close(self,fd):
  key=(self.invocation,fd);self.closes.append([self.invocation,fd]);self.counts[key]=self.counts.get(key,0)+1
  if self.counts[key]>1:self.retry=True
  if fd in (30,31):return
  faults={'absent_close_last':{13},'absent_close_middle':{12},'absent_close_first':{11},'absent_close_root':{10},
          'absent_close_multi':{13,11},'absent_close_notfound':{12},'absent_close_hostile':{12},'absent_close_interrupt':{12},
          'absent_prior_incomplete_plus_close':{12},'present_leaf_close_notfound':{14},
          'present_root_close_notfound':{10},'present_ancestor_close_notfound':{12},
          'present_close_multi':{14,12},'invalid_child_close_notfound':{13},
          'root_validation_close_notfound':{10},'read_fault_plus_close':{12}}.get(mode,set())
  if kind=='composed' and self.invocation!=self.target:return
  if fd in faults and self.counts[key]==1:
   if mode=='absent_close_interrupt':raise KeyboardInterrupt()
   if mode.endswith('_hostile'):raise HostileClose()
   if mode.endswith('_notfound'):raise FileNotFoundError('synthetic close fault')
   raise OSError('synthetic close fault')
fake=FakeOS();m.os=fake
m.check_extended=lambda fd:None;m.same_entry=lambda *args:None;m.same_leaf=lambda *args:None
m.file_identity=lambda info:(info.st_dev,info.st_ino);m.leaf_identity=lambda info:(info.st_dev,info.st_ino)
root_checks=[0]
def check_ancestor(info):
 if mode=='root_validation_close_notfound' and info.st_ino==10:raise OSError('synthetic root validation fault')
 if mode=='invalid_child_close_notfound' and info.st_ino==13:raise OSError('synthetic invalid child')
 if mode=='absent_prior_incomplete_plus_close' and info.st_ino==10:
  root_checks[0]+=1
  if root_checks[0]>1:raise m.Incomplete('unsafe_input_ancestor')
m.check_input_ancestor=check_ancestor
if kind=='direct':
 m.CONFIG['ars']='/a/b/c/file'
 try:
  if consumer=='required_config':value=m.read_config('ars',True);completed=value[1]
  elif consumer=='optional_config':value=m.read_config('ars',False);completed=value[1]
  elif consumer=='certificate':value=m.cert_metadata('/a/b/c/file');completed=value[0]['code']
  elif consumer=='key':value=m.key_pair('fixture',{'public_key_sha256':'0'*64},'/a/b/c/file');completed=value['code']
  else:raise AssertionError('unknown consumer')
  error=None;literal=None
 except BaseException as exc:
  error=type(exc).__name__;literal=exc.args[0] if type(exc) is m.Incomplete and exc.args else None;completed=None
 target=fake.invocation
 expected=[10] if mode=='root_validation_close_notfound' else [13,12,11,10] if mode=='invalid_child_close_notfound' or not present else [14,13,12,11,10]
 attempts=[fd for invocation,fd in fake.closes if invocation==target]
 settled=mode=='absent_settled'
 expected_completed={'required_config':'config_missing','optional_config':'absent','certificate':'certificate_missing','key':'key_missing'}[consumer]
 result={'kind':kind,'scope':scope,'consumer':consumer,'mode':mode,'completed':completed,'error':error,'literal':literal,'attempts':attempts,'expected_attempts':expected,'sticky':m.WITNESS_DISPOSITION_UNPROVED,'retry':fake.retry,'all_once':all(n==1 for n in fake.counts.values()),'failure_reason':m._failure_reason('collection',m.Incomplete('fixed_input_close_unproved'))}
 print(json.dumps(result,sort_keys=True),flush=True)
 assert attempts==expected and result['all_once'] and not fake.retry
 if settled:assert completed==expected_completed and error is None and not result['sticky']
 elif mode=='absent_close_interrupt':assert error=='KeyboardInterrupt' and completed is None and result['sticky']
 elif mode=='absent_prior_incomplete_plus_close':assert error=='Incomplete' and literal=='unsafe_input_ancestor' and result['sticky']
 else:assert error=='Incomplete' and literal=='fixed_input_close_unproved' and completed is None and result['sticky']
 if not settled:assert result['failure_reason']=='fixed_input_unproved'
else:
 assert consumer=='optional_config'
 m.CONFIG={name:'/a/b/c/'+name for name in m.CONFIG}
 def cert_role(item,observed_at):
  label,path,role=item[:3]
  record={'label':label,'path':path,'role':role,'status':'pass','code':'pass','not_before':'2020-01-01T00:00:00Z','not_after':'2035-01-01T00:00:00Z','expired':False,'not_yet_valid':False,'sha256':'a'*64,'fingerprint_sha256':'b'*64,'public_key_sha256':'c'*64,'subject_sha256':'d'*64,'issuer_sha256':'e'*64,'san_match':True if role=='server' else None,'eku_match':None if role=='ca' else True}
  return record,b'fixture-cert'
 m.cert_role=cert_role
 m.key_pair=lambda label,cert,path:{'label':label,'status':'pass','code':'pass','matches':True}
 m.verify_chain=lambda *args:{'label':args[0],'status':'pass','code':'pass','purpose':args[-2],'hostname':args[-1]}
 m.ES_TLS_STATUS_BOOTSTRAP_VERIFIED=True;m.ES_TLS_STATUS_BOOTSTRAP_INTERRUPTED=[False];m.SIGNALS=();m.LATCHED_SIGNAL=None
 m.open_status_dir=lambda:30;m.open_scope_lock=lambda *args:31;m.validate_process_capability=lambda:None
 m.preexisting_generation=lambda *args:m._PriorSummarySnapshot(m._PriorSummaryState.ABSENT)
 m.check_signal=lambda:None
 original_encode=m.encode_document;encoded=[];published=[]
 def tracked_encode(record,scope_name):
  payload=original_encode(record,scope_name);encoded.append((record,payload));return payload
 m.encode_document=tracked_encode
 m.publish=lambda status_fd,scope_name,payload:published.append((status_fd,scope_name,payload))
 rc=m.main(['--scope',scope])
 text=pathlib.Path(shell).read_text();mark="IFS= read -r -d '' bootstrap <<'REMOTE_ALPHA_ES_TLS_STATUS_BOOTSTRAP' || true\n"
 start=text.index(mark)+len(mark);end=text.index('\nREMOTE_ALPHA_ES_TLS_STATUS_BOOTSTRAP\n',start)
 tree=ast.parse(text[start:end]);nodes=[n for n in tree.body if (isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='_FAILURE_WITNESS_COUPLINGS' for t in n.targets)) or (isinstance(n,ast.FunctionDef) and n.name in ('format_failure_witness','emit_failure_witness'))]
 assert len(nodes)==3
 lines=[];env=dict(re=re,uncaught=[False],owned_fds={'parent':False,'directory':False,'file':False},collector_started=True,stage_closeout=True,collector_failure_exit=True,collector_namespace=dict(WITNESS_SELECTION=m.WITNESS_SELECTION,WITNESS_CLOSEOUT_PROVED=m.WITNESS_CLOSEOUT_PROVED,WITNESS_DISPOSITION_UNPROVED=m.WITNESS_DISPOSITION_UNPROVED),scope_value=scope,verified_digest='a'*64,write_failure_witness=lines.append)
 exec(compile(ast.Module(body=nodes,type_ignores=[]),'<exact-bootstrap-gate>','exec'),env);env['emit_failure_witness']()
 target=fake.target
 assert target is not None
 attempts=[fd for invocation,fd in fake.closes if invocation==target and fd not in (30,31)]
 close_main=[fd for invocation,fd in fake.closes if fd in (30,31)]
 related=next((r for r in encoded[0][0]['topology'] if r['id']==optional+'_related_config'),None) if encoded else None
 result={'kind':kind,'scope':scope,'consumer':consumer,'mode':mode,'rc':rc,'target_invocation':target,'attempts':attempts,'main_closes':close_main,'encoded':len(encoded),'published_sink':len(published),'record_result':encoded[0][0]['result']['status'] if encoded else None,'related_code':related['code'] if related else None,'selection':m.WITNESS_SELECTION,'sticky':m.WITNESS_DISPOSITION_UNPROVED,'proved':m.WITNESS_CLOSEOUT_PROVED,'witness_sink':len(lines),'retry':fake.retry,'all_once':all(n==1 for n in fake.counts.values()),'sink_kind':'source-bound in-memory recorder; not protected publication'}
 print(json.dumps(result,sort_keys=True),flush=True)
 assert rc==1 and attempts==[13,12,11,10] and close_main==[31,30] and result['all_once'] and not fake.retry
 if mode=='absent_settled':
  assert len(encoded)==len(published)==1 and related['code']=='absent' and encoded[0][0]['result']=={'status':'pass','ok':True}
  assert not result['sticky'] and result['proved'] and len(lines)==1
 else:
  assert not encoded and not published and result['sticky'] and not result['proved'] and not lines
  assert m.WITNESS_SELECTION==('collection','fixed_input_unproved')
`
	for _, scope := range []string{"artifact-registry", "execution-governance"} {
		for _, mode := range []string{"absent_settled", "absent_close_middle", "absent_close_multi", "absent_close_notfound", "absent_close_hostile"} {
			t.Run(scope+"/"+mode, func(t *testing.T) {
				got := runRemoteAlphaESFailureWitnessProbe(t, probe, scope, "optional_config", mode, "composed")
				if got["scope"] != scope || got["mode"] != mode || got["all_once"] != true ||
					got["retry"] != false || got["sink_kind"] != "source-bound in-memory recorder; not protected publication" {
					t.Fatalf("optional absence composition: %v", got)
				}
			})
		}
	}
}

// This source is generated from an independently authored local fixture before
// the collector repair. It uses the actual fixed-input primitive and consumers.
const verifiedInputOriginProbe = `
import ast
from collections import Counter
import importlib.util
import json
import os
import pathlib
import re
import stat
import sys

source, shell, mode, consumer, scope, root = sys.argv[1:]
root = pathlib.Path(root)
spec = importlib.util.spec_from_file_location('origin_matrix_collector', source)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
REAL = os

# The local fixture is not a root-owned target. Preserve real descriptor and
# name operations; substitute only target ownership and extended metadata.
def check_input_ancestor(info):
    if mode=='root_validation' and (info.st_dev,info.st_ino)==(REAL.stat('/').st_dev,REAL.stat('/').st_ino):
        raise FileNotFoundError('root validation')
    if mode=='ancestor_validation' and (info.st_dev,info.st_ino)==(REAL.stat(root/'safe').st_dev,REAL.stat(root/'safe').st_ino):
        raise FileNotFoundError('ancestor validation')
    if not stat.S_ISDIR(info.st_mode):raise m.Incomplete('unsafe_input_ancestor')
m.check_input_ancestor = check_input_ancestor
m.check_extended = lambda _fd: None

class HostileFileNotFound(FileNotFoundError):
    def __str__(self): raise AssertionError('hostile error was formatted')
    def __repr__(self): raise AssertionError('hostile error was represented')

class FaultOS:
    def __init__(self, target, parent):
        self.target=target; self.parent=parent
        self.active={}; self.opens={}; self.closes={}; self.serial=0; self.current=0
        self.target_call=None; self.leaf_fd=None; self.seen_target=False
        self.leaf_stats=0; self.leaf_fstats=0; self.leaf_reads=0; self.root_fstats={}
        self.injected=False
    def __getattr__(self, key): return getattr(REAL,key)
    def open(self,name,flags,*args,**kw):
        if name=='/' and kw.get('dir_fd') is None:
            self.serial+=1;self.current=self.serial
            if mode=='root_open' and consumer!='composed':
                self.injected=True;raise FileNotFoundError('root acquisition')
        if mode=='ancestor_open' and name==self.parent and consumer!='composed':
            self.injected=True;raise FileNotFoundError('ancestor acquisition')
        if mode=='leaf_open' and name==self.target and kw.get('dir_fd') is not None:
            self.injected=True;raise FileNotFoundError('present leaf vanished at open')
        fd=REAL.open(name,flags,*args,**kw)
        self.active[fd]=(self.current,name)
        self.opens.setdefault(self.current,[]).append(name)
        if name==self.target and kw.get('dir_fd') is not None:
            self.target_call=self.current;self.leaf_fd=fd
        return fd
    def fstat(self,fd):
        call,name=self.active.get(fd,(None,None))
        if name=='/':
            count=self.root_fstats.get(call,0)+1;self.root_fstats[call]=count
            if consumer!='composed' and ((mode=='root_fstat' and count==1) or (mode in ('absent_revalidation','final_revalidation') and count==2)):
                self.injected=True;raise FileNotFoundError('root metadata')
        if name==self.parent and mode=='ancestor_fstat' and consumer!='composed':
            self.injected=True;raise FileNotFoundError('ancestor metadata')
        if name==self.target:
            self.leaf_fstats+=1
            if (mode=='initial_leaf_fstat' and self.leaf_fstats==1) or (mode=='final_leaf_fstat' and self.leaf_fstats==2):
                self.injected=True;raise FileNotFoundError('leaf metadata')
        return REAL.fstat(fd)
    def stat(self,name,*args,**kw):
        if name==self.parent and mode=='ancestor_recheck' and consumer!='composed':
            self.injected=True;raise FileNotFoundError('ancestor name recheck')
        if name==self.target and kw.get('dir_fd') is not None:
            self.seen_target=True;self.target_call=self.current;self.leaf_stats+=1
            if (mode=='initial_leaf_recheck' and self.leaf_stats==2) or (mode=='final_leaf_recheck' and self.leaf_stats==3):
                self.injected=True;raise FileNotFoundError('present leaf name recheck')
        return REAL.stat(name,*args,**kw)
    def read(self,fd,size):
        if fd==self.leaf_fd:
            self.leaf_reads+=1
            if mode in ('read_first','read_hostile') and self.leaf_reads==1:
                self.injected=True
                if mode=='read_hostile':raise HostileFileNotFound()
                raise FileNotFoundError('present leaf first read')
            if mode=='read_late':
                if self.leaf_reads==1:return REAL.read(fd,1)
                if self.leaf_reads==2:
                    self.injected=True;raise FileNotFoundError('present leaf later read')
        return REAL.read(fd,size)
    def close(self,fd):
        call,name=self.active.pop(fd,(None,None))
        if call is not None:self.closes.setdefault(call,[]).append(name)
        REAL.close(fd)
        if not self.injected and ((mode=='close_leaf' and name==self.target) or (mode=='close_parent' and name==self.parent and self.seen_target and call==self.target_call)):
            self.injected=True;raise FileNotFoundError('synthetic close uncertainty')

def outcome(fn):
    try:
        value=fn()
        return {'return':value if isinstance(value,(str,int,type(None))) else 'bytes' if isinstance(value,bytes) else value}
    except BaseException as exc:
        literal=exc.args[0] if type(exc) is m.Incomplete and len(exc.args)==1 and type(exc.args[0]) is str else None
        return {'exception':type(exc).__name__,'literal':literal}

def bootstrap_sink():
    text=pathlib.Path(shell).read_text()
    mark="IFS= read -r -d '' bootstrap <<'REMOTE_ALPHA_ES_TLS_STATUS_BOOTSTRAP' || true\n"
    a=text.index(mark)+len(mark);b=text.index('\nREMOTE_ALPHA_ES_TLS_STATUS_BOOTSTRAP\n',a)
    tree=ast.parse(text[a:b])
    selected=[n for n in tree.body if
        (isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='_FAILURE_WITNESS_COUPLINGS' for t in n.targets)) or
        (isinstance(n,ast.FunctionDef) and n.name in ('format_failure_witness','emit_failure_witness'))]
    assert len(selected)==3
    lines=[]
    env={'re':re,'uncaught':[False], 'owned_fds':{'parent':False,'directory':False,'file':False},
         'collector_started':True,'stage_closeout':True,'collector_failure_exit':True,
         'collector_namespace':{'WITNESS_SELECTION':m.WITNESS_SELECTION,'WITNESS_CLOSEOUT_PROVED':m.WITNESS_CLOSEOUT_PROVED,'WITNESS_DISPOSITION_UNPROVED':m.WITNESS_DISPOSITION_UNPROVED},
         'scope_value':scope,'verified_digest':'a'*64,'write_failure_witness':lines.append}
    exec(compile(ast.Module(body=selected,type_ignores=[]),'<source-bound-bootstrap>','exec'),env)
    env['emit_failure_witness']()
    return len(lines)

if consumer=='composed':
    chosen=m.SCOPES[scope]
    cfg={name:{} for name in m.CONFIG}
    def put(name,keys,value):
        node=cfg[name]
        for key in keys[:-1]:node=node.setdefault(key,{})
        node[keys[-1]]=value
    for _label,name,keys,value in chosen['bindings']:put(name,keys,value)
    for _label,name,keys,port in chosen['urls']:put(name,keys,'https://127.0.0.1:'+str(port))
    optional=next(name for name in cfg if name not in chosen['required_config'])
    target=optional
    m.CONFIG={name:str(root/name) for name in cfg}
    for name,data in cfg.items():
        if name==optional and mode in ('absent','close_parent'):continue
        p=pathlib.Path(m.CONFIG[name]);p.write_bytes(json.dumps(data).encode());p.chmod(0o600)
    fault=FaultOS(target,root.name);m.os=fault
    lock=root/'fixture.lock';lock.write_bytes(b'')
    m.ES_TLS_STATUS_BOOTSTRAP_VERIFIED=True;m.ES_TLS_STATUS_BOOTSTRAP_INTERRUPTED=[False]
    m.SIGNALS=();m.LATCHED_SIGNAL=None
    m.open_status_dir=lambda:REAL.open(root,REAL.O_RDONLY)
    m.open_scope_lock=lambda *_a:REAL.open(lock,REAL.O_RDONLY)
    m.validate_process_capability=lambda:None
    prior_generation='f'*64
    m.preexisting_generation=lambda *_a:m._PriorSummarySnapshot(m._PriorSummaryState.VALID,prior_generation)
    m.check_signal=lambda:None
    def cert_role(item,_when):
        label,path,role=item[:3]
        return ({'label':label,'path':path,'role':role,'status':'pass','code':'pass','not_before':'2020-01-01T00:00:00Z','not_after':'2035-01-01T00:00:00Z','expired':False,'not_yet_valid':False,'sha256':'a'*64,'fingerprint_sha256':'b'*64,'public_key_sha256':'c'*64,'subject_sha256':'d'*64,'issuer_sha256':'e'*64,'san_match':True if role=='server' else None,'eku_match':None if role=='ca' else True},b'fixture-cert')
    m.cert_role=cert_role
    m.key_pair=lambda label,cert,path:{'label':label,'status':'pass','code':'pass','matches':True}
    m.verify_chain=lambda label,*args:{'label':label,'status':'pass','code':'pass','purpose':args[-2],'hostname':args[-1]}
    encoded=[];published=[];original=m.encode_document
    def encode(record,name):
        payload=original(record,name);encoded.append(record);return payload
    m.encode_document=encode
    m.publish=lambda *args:published.append(args)
    rc=m.main(['--scope',scope])
    related=next((x for x in encoded[0]['topology'] if x['id']==optional+'_related_config'),None) if encoded else None
    calls=fault.target_call
    row={'mode':mode,'consumer':consumer,'scope':scope,'rc':rc,'optional_present':pathlib.Path(m.CONFIG[optional]).exists(),'injected':fault.injected,'target_opens':fault.opens.get(calls,[]),'target_closes':fault.closes.get(calls,[]),'encoded':len(encoded),'published_recorder':len(published),'related_code':related['code'] if related else None,'record_result':encoded[0]['result'] if encoded else None,'selection':m.WITNESS_SELECTION,'sticky':m.WITNESS_DISPOSITION_UNPROVED,'proved':m.WITNESS_CLOSEOUT_PROVED,'bootstrap_sink':bootstrap_sink(),'sink_label':'in-memory publication recorder returns; no protected publication','prior_sentinel':prior_generation,'prior_label':'in-memory prior snapshot; no protected prior file read'}
else:
    safe=root/'safe';safe.mkdir()
    target='leaf';path=safe/target
    if mode not in ('absent','metadata_absent','absent_revalidation','close_parent'):
        path.write_bytes(b'{"x":1}');path.chmod(0o600)
    fault=FaultOS(target,safe.name);m.os=fault
    def check_extended(fd):
        _call,name=fault.active.get(fd,(None,None))
        matching=(mode=='root_extended' and name=='/') or (mode=='ancestor_extended' and name==safe.name) or (mode=='leaf_extended' and name==target and fault.leaf_fstats==1) or (mode=='final_leaf_extended' and name==target and fault.leaf_fstats==2)
        if matching:
            fault.injected=True;raise FileNotFoundError('extended metadata')
    m.check_extended=check_extended
    if consumer in ('required','optional'):m.CONFIG['ars']=str(path)
    if consumer=='repeat':
        results=[]
        for action in ('fault','present','absent','present_again'):
            if action=='absent':path.unlink()
            if action=='present_again':path.write_bytes(b'{"x":1}');path.chmod(0o600)
            result=outcome(lambda:m.open_fixed_regular(str(path),m.MAX_INPUT))
            call=fault.current
            results.append({'action':action,'result':result,'opens':fault.opens.get(call,[]),'closes':fault.closes.get(call,[])})
        print(json.dumps({'mode':mode,'consumer':consumer,'results':results,'leaf_present':path.exists(),'sticky':m.WITNESS_DISPOSITION_UNPROVED},sort_keys=True))
        sys.exit(0)
    if mode=='raw_primitive_error':
        m.open_fixed_regular=lambda *_a,**_k:(_ for _ in ()).throw(FileNotFoundError('substituted primitive; consumer boundary only'))
    if consumer=='primitive':
        primitive_path=str(safe/'..'/'leaf') if mode=='invalid_path' else str(path)
        got=outcome(lambda:m.open_fixed_regular(primitive_path,m.MAX_INPUT,mode not in ('metadata_absent','metadata_valid')))
    elif consumer in ('required','optional'):
        got=outcome(lambda:m.read_config('ars',consumer=='required')[1])
    elif consumer=='certificate':got=outcome(lambda:m.cert_metadata(str(path))[0]['code'])
    elif consumer=='key':got=outcome(lambda:m.key_pair('k',{'public_key_sha256':'a'*64},str(path))['code'])
    else:raise AssertionError(consumer)
    calls=fault.target_call if fault.target_call is not None else fault.current
    row={'mode':mode,'consumer':consumer,'scope':scope,'result':got,'leaf_present':path.exists(),'injected':fault.injected,'opens':fault.opens.get(calls,[]),'closes':fault.closes.get(calls,[]),'sticky':m.WITNESS_DISPOSITION_UNPROVED,'leaf_reads':fault.leaf_reads,'leaf_stats':fault.leaf_stats}
    if mode=='raw_primitive_error':row['substitution']='primitive deliberately raises raw FileNotFoundError to test consumer fallback only'

print(json.dumps(row,sort_keys=True))
`

func assertRemoteAlphaInputOriginCloseOrder(t *testing.T, got map[string]any, opensKey, closesKey string) {
	t.Helper()
	opens, okOpen := got[opensKey].([]any)
	closes, okClose := got[closesKey].([]any)
	if !okOpen || !okClose || len(opens) != len(closes) {
		t.Fatalf("input close count differs from acquisitions: %v", got)
	}
	for i := range opens {
		if closes[i] != opens[len(opens)-1-i] {
			t.Fatalf("input close order is not leaf-before-reverse-ancestry: %v", got)
		}
	}
}

func TestRemoteAlphaESServiceTLSStatusFailureWitnessVerifiedInputOriginMatrix(t *testing.T) {
	for _, tc := range []struct {
		mode, wantException, wantLiteral, wantReturn string
		sticky                                       bool
	}{
		{"invalid_path", "Incomplete", "invalid_fixed_path", "", false},
		{"root_open", "Incomplete", "fixed_input_read_unproved", "", false},
		{"root_fstat", "Incomplete", "fixed_input_read_unproved", "", false},
		{"root_validation", "Incomplete", "fixed_input_read_unproved", "", false},
		{"root_extended", "Incomplete", "fixed_input_read_unproved", "", false},
		{"ancestor_open", "Incomplete", "unsafe_input_ancestor", "", false},
		{"ancestor_fstat", "Incomplete", "unsafe_input_ancestor", "", false},
		{"ancestor_validation", "Incomplete", "unsafe_input_ancestor", "", false},
		{"ancestor_extended", "Incomplete", "unsafe_input_ancestor", "", false},
		{"ancestor_recheck", "Incomplete", "unsafe_input_ancestor", "", false},
		{"absent_revalidation", "Incomplete", "input_ancestor_changed", "", false},
		{"leaf_open", "Incomplete", "fixed_input_changed", "", false},
		{"initial_leaf_fstat", "Incomplete", "fixed_input_read_unproved", "", false},
		{"leaf_extended", "Incomplete", "fixed_input_read_unproved", "", false},
		{"initial_leaf_recheck", "Incomplete", "fixed_input_changed", "", false},
		{"read_first", "Incomplete", "fixed_input_read_unproved", "", false},
		{"read_late", "Incomplete", "fixed_input_read_unproved", "", false},
		{"read_hostile", "Incomplete", "fixed_input_read_unproved", "", false},
		{"final_leaf_fstat", "Incomplete", "fixed_input_read_unproved", "", false},
		{"final_leaf_extended", "Incomplete", "fixed_input_read_unproved", "", false},
		{"final_leaf_recheck", "Incomplete", "fixed_input_changed", "", false},
		{"final_revalidation", "Incomplete", "input_ancestor_changed", "", false},
		{"close_leaf", "Incomplete", "fixed_input_close_unproved", "", true},
		{"close_parent", "Incomplete", "fixed_input_close_unproved", "", true},
		{"absent", "_VerifiedFinalLeafAbsent", "", "", false},
		{"metadata_absent", "_VerifiedFinalLeafAbsent", "", "", false},
		{"normal", "", "", "bytes", false},
		{"metadata_valid", "", "", "none", false},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			got := runRemoteAlphaESFailureWitnessProbe(t, verifiedInputOriginProbe,
				tc.mode, "primitive", "artifact-registry", t.TempDir())
			result, ok := got["result"].(map[string]any)
			if !ok || got["mode"] != tc.mode || got["sticky"] != tc.sticky {
				t.Fatalf("primitive origin result shape: %v", got)
			}
			if tc.wantException != "" {
				if result["exception"] != tc.wantException || (tc.wantLiteral != "" && result["literal"] != tc.wantLiteral) {
					t.Fatalf("primitive origin misclassified: %v", got)
				}
			} else if tc.wantReturn == "none" {
				if _, exists := result["exception"]; exists || result["return"] != nil {
					t.Fatalf("metadata-only success changed: %v", got)
				}
			} else if result["return"] != tc.wantReturn {
				t.Fatalf("regular-byte success changed: %v", got)
			}
			assertRemoteAlphaInputOriginCloseOrder(t, got, "opens", "closes")
			if tc.mode == "read_late" && got["leaf_reads"] != float64(2) {
				t.Fatalf("late read fault was not reached after a prefix: %v", got)
			}
		})
	}
	for _, consumer := range []string{"required", "optional", "certificate", "key"} {
		for _, mode := range []string{"absent", "read_first", "read_late", "raw_primitive_error"} {
			t.Run(consumer+"/"+mode, func(t *testing.T) {
				got := runRemoteAlphaESFailureWitnessProbe(t, verifiedInputOriginProbe,
					mode, consumer, "artifact-registry", t.TempDir())
				result, ok := got["result"].(map[string]any)
				if !ok || got["sticky"] != false {
					t.Fatalf("consumer origin result shape: %v", got)
				}
				if mode == "absent" {
					want := map[string]string{"required": "config_missing", "optional": "absent", "certificate": "certificate_missing", "key": "key_missing"}[consumer]
					if result["return"] != want || got["leaf_present"] != false {
						t.Fatalf("verified final absence lost its completed code: %v", got)
					}
				} else {
					want := "fixed_input_read_unproved"
					if mode == "raw_primitive_error" {
						want = map[string]string{"required": "config_read_unproved", "optional": "config_read_unproved", "certificate": "certificate_read_unproved", "key": "key_read_unproved"}[consumer]
					}
					if result["exception"] != "Incomplete" || result["literal"] != want {
						t.Fatalf("non-final or raw exception became completed missing: %v", got)
					}
				}
				assertRemoteAlphaInputOriginCloseOrder(t, got, "opens", "closes")
			})
		}
	}
}

func TestRemoteAlphaESServiceTLSStatusFailureWitnessVerifiedInputOriginComposition(t *testing.T) {
	for _, scope := range []string{"artifact-registry", "execution-governance"} {
		for _, mode := range []string{"read_first", "read_late", "initial_leaf_fstat", "final_leaf_fstat", "absent", "close_parent", "normal"} {
			t.Run(scope+"/"+mode, func(t *testing.T) {
				got := runRemoteAlphaESFailureWitnessProbe(t, verifiedInputOriginProbe,
					mode, "composed", scope, t.TempDir())
				if got["scope"] != scope || got["mode"] != mode || got["rc"] != float64(1) ||
					got["sink_label"] != "in-memory publication recorder returns; no protected publication" ||
					got["prior_sentinel"] != strings.Repeat("f", 64) ||
					got["prior_label"] != "in-memory prior snapshot; no protected prior file read" {
					t.Fatalf("composed origin result shape: %v", got)
				}
				assertRemoteAlphaInputOriginCloseOrder(t, got, "target_opens", "target_closes")
				switch mode {
				case "absent", "normal":
					want := "absent"
					if mode == "normal" {
						want = "pass"
					}
					result, ok := got["record_result"].(map[string]any)
					if !ok || result["status"] != "pass" || result["ok"] != true ||
						got["related_code"] != want || got["encoded"] != float64(1) ||
						got["published_recorder"] != float64(1) {
						t.Fatalf("settled control failed to reach record formation: %v", got)
					}
				case "close_parent":
					if got["encoded"] != float64(0) || got["published_recorder"] != float64(0) ||
						got["sticky"] != true || got["proved"] != false || got["bootstrap_sink"] != float64(0) {
						t.Fatalf("close uncertainty did not suppress record and witness: %v", got)
					}
				default:
					selection, ok := got["selection"].([]any)
					if !ok || len(selection) != 2 || selection[0] != "collection" || selection[1] != "fixed_input_unproved" ||
						got["encoded"] != float64(0) || got["published_recorder"] != float64(0) ||
						got["sticky"] != false || got["proved"] != true || got["bootstrap_sink"] != float64(1) {
						t.Fatalf("settled non-final failure was not incomplete with advisory selection: %v", got)
					}
				}
			})
		}
	}
}

func TestRemoteAlphaESServiceTLSStatusFailureWitnessVerifiedInputOriginFreshInvocations(t *testing.T) {
	got := runRemoteAlphaESFailureWitnessProbe(t, verifiedInputOriginProbe,
		"read_first", "repeat", "artifact-registry", t.TempDir())
	rows, ok := got["results"].([]any)
	if !ok || len(rows) != 4 || got["leaf_present"] != true || got["sticky"] != false {
		t.Fatalf("fresh input invocation shape: %v", got)
	}
	for i, want := range []struct {
		action, exception, literal, returned string
	}{
		{"fault", "Incomplete", "fixed_input_read_unproved", ""},
		{"present", "", "", "bytes"},
		{"absent", "_VerifiedFinalLeafAbsent", "", ""},
		{"present_again", "", "", "bytes"},
	} {
		row, ok := rows[i].(map[string]any)
		if !ok || row["action"] != want.action {
			t.Fatalf("fresh invocation order: %v", got)
		}
		result, ok := row["result"].(map[string]any)
		if !ok || (want.exception != "" && (result["exception"] != want.exception ||
			want.literal != "" && result["literal"] != want.literal)) ||
			(want.returned != "" && result["return"] != want.returned) {
			t.Fatalf("input origin state leaked across calls: %v", got)
		}
		assertRemoteAlphaInputOriginCloseOrder(t, row, "opens", "closes")
	}
}

func TestRemoteAlphaESServiceTLSStatusFailureWitnessVerifiedInputOriginSourceBoundary(t *testing.T) {
	const probe = `
import ast,importlib.util,json,pathlib,sys
source=sys.argv[1]
tree=ast.parse(pathlib.Path(source).read_bytes())
classes=[n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='_VerifiedFinalLeafAbsent']
functions={n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)}
producers=[]
for name,fn in functions.items():
 for n in ast.walk(fn):
  if isinstance(n,ast.Raise) and isinstance(n.exc,ast.Call) and isinstance(n.exc.func,ast.Name) and n.exc.func.id=='_VerifiedFinalLeafAbsent':producers.append(name)
consumers={}
for name in ('read_config','cert_metadata','key_pair'):
 handlers=[n for n in ast.walk(functions[name]) if isinstance(n,ast.ExceptHandler)]
 consumers[name]=[n.type.id for n in handlers if isinstance(n.type,ast.Name)]
spec=importlib.util.spec_from_file_location('origin_source_boundary',source);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
print(json.dumps({'direct_exception':len(classes)==1 and len(classes[0].bases)==1 and isinstance(classes[0].bases[0],ast.Name) and classes[0].bases[0].id=='Exception',
'single_producer':producers==['open_fixed_regular'],
'three_consumers':all('_VerifiedFinalLeafAbsent' in consumers[name] and 'FileNotFoundError' not in consumers[name] for name in consumers),
'private_reason':m._FAILURE_REASON_LITERALS['collection'].get('fixed_input_read_unproved')=='fixed_input_unproved'},sort_keys=True))
`
	got := runRemoteAlphaESFailureWitnessProbe(t, probe)
	for _, key := range []string{"direct_exception", "single_producer", "three_consumers", "private_reason"} {
		if got[key] != true {
			t.Fatalf("verified absence source boundary %s: %v", key, got)
		}
	}
}
