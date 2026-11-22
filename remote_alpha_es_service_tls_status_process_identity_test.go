package executionsubstrate_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
	"time"
)

// These Python children import only the source-controlled collector. They
// never run its entry point, an operator route, or a real OpenSSL child. The
// live probes start only their own short-lived children, read the local
// /proc, and write nothing outside t.TempDir().
func runRemoteAlphaESProcessIdentityProbe(t *testing.T, probe string, args ...string) map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	argv := append([]string{"-I", "-B", "-c", probe, remoteAlphaESServiceTLSStatusCollectorPath()}, args...)
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", argv...)
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	cmd.WaitDelay = 10 * time.Second
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("process identity probe timed out: %v\n%s", ctx.Err(), output)
	}
	if err != nil {
		t.Fatalf("process identity probe: %v\n%s", err, output)
	}
	var result map[string]any
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("process identity probe JSON: %v\n%s", err, output)
	}
	return result
}

func assertRemoteAlphaESProcessIdentityCases(t *testing.T, result map[string]any, want ...string) {
	t.Helper()
	cases, ok := result["cases"].(map[string]any)
	if !ok {
		t.Fatalf("process identity probe returned no cases: %v", result)
	}
	detail, _ := result["detail"].(map[string]any)
	for _, label := range want {
		if cases[label] != true {
			t.Errorf("%s failed: %v", label, detail[label])
		}
	}
	if len(cases) != len(want) {
		t.Errorf("process identity probe returned %d cases, want %d: %v", len(cases), len(want), cases)
	}
}

// The live probes need a readable Linux-format /proc/self/stat. That is
// decided by attempting the read, never by an OS label. Only the probe's
// explicit refusal skips; any other shape of answer is a failure.
func requireRemoteAlphaESLiveProcStat(t *testing.T, result map[string]any) {
	t.Helper()
	switch result["capability"] {
	case true:
	case false:
		reason, ok := result["reason"].(string)
		if !ok || reason == "" {
			t.Fatalf("live proc stat probe refused without a reason: %v", result)
		}
		t.Skipf("skipping live proc stat fixture: %s", reason)
	default:
		t.Fatalf("live proc stat probe did not state its capability: %v", result)
	}
}

const remoteAlphaESProcessIdentityLoader = `
import errno,importlib.util,json,os,pathlib,signal,sys,threading,time
spec=importlib.util.spec_from_file_location("status_process_identity",sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
cases={};detail={}
def record(label,passed,seen):
    cases[label]=bool(passed)
    if not passed:detail[label]=repr(seen)
`

// The live prelude decides the capability by behavior and gives the probes
// real processes whose names the kernel reports unescaped in /proc/<pid>/stat.
// Every fixture process is a direct child that this probe ends and reaps; it
// also ends by itself when the probe disappears.
const remoteAlphaESProcessIdentityLivePrelude = remoteAlphaESProcessIdentityLoader + `
def unavailable():
    try:fd=os.open("/proc/self/stat",os.O_RDONLY)
    except OSError as exc:
        return "cannot open /proc/self/stat: "+errno.errorcode.get(exc.errno,str(exc.errno))
    try:raw=os.read(fd,4097)
    finally:os.close(fd)
    if not raw.startswith(b"%d ("%os.getpid()):
        return "/proc/self/stat does not start with this process ID and a name"
    return None
reason=unavailable()
if reason is not None:
    print(json.dumps({"capability":False,"reason":reason}));sys.exit(0)
# The grace bound of the cleanup owner is not under test here: a loaded test
# host must not turn one late scheduling of a fixture child into a failure.
module.CHILD_GRACE=30.0
held=[]
def start(name,stay=True):
    ready_r,ready_w=os.pipe();hold_r,hold_w=os.pipe()
    pid=os.fork()
    if pid==0:
        code=1
        try:
            for fd in [ready_r,hold_w]+held:os.close(fd)
            os.setsid()
            fd=os.open("/proc/self/comm",os.O_WRONLY)
            try:os.write(fd,name)
            finally:os.close(fd)
            os.write(ready_w,b"r");os.close(ready_w)
            if stay:os.read(hold_r,1)
            code=0
        except BaseException:pass
        os._exit(code)
    os.close(ready_w);os.close(hold_r);held.append(hold_w)
    ready=os.read(ready_r,1)==b"r";os.close(ready_r)
    if not ready:
        stop(pid);raise RuntimeError("fixture process did not start")
    return pid
def stop(pid):
    # Only for a child that this probe has not reaped yet: its PID is reserved.
    os.kill(pid,signal.SIGKILL);os.waitpid(pid,0)
def name_of(pid):
    with open("/proc/%d/comm"%pid,"rb") as handle:return handle.read()
def start_time_of(pid):
    # Independent of the collector: its own bytes parse of the same file.
    with open("/proc/%d/stat"%pid,"rb") as handle:raw=handle.read()
    return int(raw[raw.rindex(b")")+1:].split()[19])
`

// The process name in a proc stat line is chosen by its own process. This
// fixture feeds the reader exact stat bytes through an injected os facade, so
// it runs on every host: any name byte must leave the identity readable, a
// forged tail inside a name must not be parsed, a process that ended at open
// or read is absent, and every other fault stays unproved.
func TestRemoteAlphaESServiceTLSStatusProcessIdentityOpaqueNameBytes(t *testing.T) {
	const probe = remoteAlphaESProcessIdentityLoader + `
PID=4242;PGID=777;START=123456789
FIELDS=[b"S",b"1",b"777",b"778",b"0",b"-1",b"4194560",b"10",b"0",b"0",b"0",b"1",b"2",
        b"0",b"0",b"20",b"0",b"1",b"0",b"123456789",b"1000",b"100",b"18446744073709551615"]
def line(name,fields=FIELDS,head=b"4242 (",close=b") "):
    return head+name+close+b" ".join(fields)+b"\n"
def swap(index,value):
    fields=list(FIELDS);fields[index]=value;return fields
def fault(code):return OSError(code,os.strerror(code))
class FakeOS:
    def __init__(self,raw=b"",open_error=None,read_error=None,close_error=None):
        self.raw=raw;self.open_error=open_error;self.read_error=read_error
        self.close_error=close_error;self.opened=0;self.closed=0
    def __getattr__(self,name):return getattr(os,name)
    def open(self,path,flags,*args,**kwargs):
        if path!="/proc/4242/stat" or args or kwargs:raise AssertionError("unexpected fake open")
        self.opened+=1
        if self.open_error is not None:raise self.open_error
        return 900
    def read(self,fd,n):
        if fd!=900:raise AssertionError("unexpected fake read")
        if self.read_error is not None:raise self.read_error
        return self.raw[:n]
    def close(self,fd):
        if fd!=900:raise AssertionError("unexpected fake close")
        self.closed+=1
        if self.close_error is not None:raise self.close_error
def outcome(fake,pid=PID):
    module.os=fake
    try:value=module.read_proc_identity(pid)
    except module.Incomplete as exc:kind=("incomplete",str(exc))
    except BaseException as exc:kind=("raised",type(exc).__name__)
    else:kind=("value",value)
    finally:module.os=os
    return kind,fake.opened,fake.closed
PRESENT=("value",(PGID,START));ABSENT=("value",None)
UNPROVED=("incomplete","process_identity_unproved")
def expect(label,fake,want,pid=PID):
    got=outcome(fake,pid);record(label,got==want,got)

names={
    "name_ascii":b"sleep",
    "name_utf8":b"sl\xc3\xa9\xc3\xa9p",
    "name_invalid_utf8":b"\xff\xfe\xfd",
    "name_high_bytes":bytes(range(0xf1,0x100)),
    "name_forged_tail":b"x) R 1 4242 4242 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 99999 1 1",
    "name_parens":b"((a)(",
    "name_close_paren":b")",
    "name_newline":b"new\nline",
    "name_whitespace":b" \t ",
    "name_empty":b"",
    "name_worker_64":b"\xe9"*64,
}
for label,name in names.items():expect(label,FakeOS(line(name)),(PRESENT,1,1))
refused=[value for value in range(256)
         if outcome(FakeOS(line(b"a"+bytes([value])+b"z")))!=(PRESENT,1,1)]
record("name_every_byte_value",not refused,refused[:8])

body=line(b"sleep")[:-1]
def padded(size):
    room=size-1-len(body)
    return body+(b" 00" if room%2 else b"")+b" 0"*((room-(3 if room%2 else 0))//2)+b"\n"
record("line_4096_fixture",len(padded(4096))==4096 and len(padded(4097))==4097,
       (len(padded(4096)),len(padded(4097))))
expect("line_4096_accepted",FakeOS(padded(4096)),(PRESENT,1,1))
unproved={
    "line_over_4096":padded(4097),
    "line_other_pid":line(b"sleep",head=b"4243 ("),
    "line_longer_pid":line(b"sleep",head=b"14242 ("),
    "line_pid_with_more_digits":line(b"sleep",head=b"42421 ("),
    "line_no_space_before_name":line(b"sleep",head=b"4242("),
    "line_no_close_paren":line(b"sleep",close=b" "),
    "line_nineteen_fields":line(b"sleep",FIELDS[:19]),
    "line_group_not_numeric":line(b"sleep",swap(2,b"x77")),
    "line_start_not_numeric":line(b"sleep",swap(19,b"1x")),
    "line_group_non_ascii_digits":line(b"sleep",swap(2,b"\xd9\xa7\xd9\xa7\xd9\xa7")),
    "line_group_non_ascii_space":line(b"sleep",swap(2,b"777\xa0")),
    "line_start_non_ascii_digit":line(b"sleep",swap(19,b"\xb2")),
    "line_empty":b"",
}
for label,raw in unproved.items():expect(label,FakeOS(raw),(UNPROVED,1,1))
expect("pid_zero",FakeOS(line(b"sleep")),(UNPROVED,0,0),0)
expect("pid_negative",FakeOS(line(b"sleep")),(UNPROVED,0,0),-4242)

# Only a process that no longer exists is absent. Nothing else is.
expect("open_enoent",FakeOS(open_error=fault(errno.ENOENT)),(ABSENT,1,0))
expect("open_esrch",FakeOS(open_error=fault(errno.ESRCH)),(ABSENT,1,0))
for code in (errno.EACCES,errno.EPERM,errno.EMFILE,errno.ENFILE,errno.ENOMEM,
             errno.EIO,errno.ELOOP,errno.ENOTDIR,errno.EINTR):
    expect("open_"+errno.errorcode[code].lower(),FakeOS(open_error=fault(code)),(UNPROVED,1,0))
expect("read_esrch",FakeOS(read_error=fault(errno.ESRCH)),(ABSENT,1,1))
for code in (errno.ENOENT,errno.EACCES,errno.EPERM,errno.ENOMEM,errno.EIO,errno.EINTR):
    got=outcome(FakeOS(read_error=fault(code)))
    record("read_"+errno.errorcode[code].lower(),
           got[0][0] in ("incomplete","raised") and got[1:]==(1,1),got)
module.WITNESS_DISPOSITION_UNPROVED=False
got=outcome(FakeOS(read_error=fault(errno.ESRCH),close_error=fault(errno.EIO)))
record("read_esrch_close_failure_stays_unproved",
       got==(("raised","OSError"),1,1) and module.WITNESS_DISPOSITION_UNPROVED is True,
       (got,module.WITNESS_DISPOSITION_UNPROVED))
module.WITNESS_DISPOSITION_UNPROVED=False

class FakeProc:
    def __init__(self,table):self.table=table;self.fds={};self.last=900;self.closed=0
    def __getattr__(self,name):return getattr(os,name)
    def listdir(self,path):
        if path!="/proc":raise AssertionError("unexpected fake listdir")
        return ["self","1","4242","thread-self","4300","4400","4500","uptime"]
    def open(self,path,flags,*args,**kwargs):
        kind,value=self.table[path]
        if kind=="open_error":raise value
        self.last+=1;self.fds[self.last]=(kind,value);return self.last
    def read(self,fd,n):
        kind,value=self.fds[fd]
        if kind=="read_error":raise value
        return value[:n]
    def close(self,fd):
        del self.fds[fd];self.closed+=1
def scan(table):
    fake=FakeProc(table);module.os=fake
    try:kind=("value",module.scan_group_members(PGID))
    except module.Incomplete as exc:kind=("incomplete",str(exc))
    except BaseException as exc:kind=("raised",type(exc).__name__)
    finally:module.os=os
    return kind,fake.closed,len(fake.fds)
table={
    "/proc/1/stat":("open_error",fault(errno.ENOENT)),
    "/proc/4242/stat":("raw",line(b"sl\xc3\xa9\xc3\xa9p")),
    "/proc/4300/stat":("raw",line(b"\xff\xfe",swap(2,b"555"),head=b"4300 (")),
    "/proc/4400/stat":("read_error",fault(errno.ESRCH)),
    "/proc/4500/stat":("open_error",fault(errno.ESRCH)),
}
got=scan(table)
record("scan_passes_foreign_names_and_ended_processes",got==(("value",[(PID,START)]),3,0),got)
hidden=dict(table);hidden["/proc/4300/stat"]=("open_error",fault(errno.EACCES))
got=scan(hidden)
record("scan_unreadable_process_stays_unproved",got==(UNPROVED,1,0),got)
print(json.dumps({"cases":cases,"detail":detail},sort_keys=True))
`
	result := runRemoteAlphaESProcessIdentityProbe(t, probe)
	assertRemoteAlphaESProcessIdentityCases(t, result,
		"name_ascii", "name_utf8", "name_invalid_utf8", "name_high_bytes",
		"name_forged_tail", "name_parens", "name_close_paren", "name_newline",
		"name_whitespace", "name_empty", "name_worker_64", "name_every_byte_value",
		"line_4096_fixture", "line_4096_accepted", "line_over_4096",
		"line_other_pid", "line_longer_pid", "line_pid_with_more_digits",
		"line_no_space_before_name",
		"line_no_close_paren", "line_nineteen_fields", "line_group_not_numeric",
		"line_start_not_numeric", "line_group_non_ascii_digits",
		"line_group_non_ascii_space", "line_start_non_ascii_digit", "line_empty",
		"pid_zero", "pid_negative",
		"open_enoent", "open_esrch", "open_eacces", "open_eperm", "open_emfile",
		"open_enfile", "open_enomem", "open_eio", "open_eloop", "open_enotdir",
		"open_eintr",
		"read_esrch", "read_enoent", "read_eacces", "read_eperm", "read_enomem",
		"read_eio", "read_eintr", "read_esrch_close_failure_stays_unproved",
		"scan_passes_foreign_names_and_ended_processes",
		"scan_unreadable_process_stays_unproved")
}

// The same rules against the real kernel: live processes of this test carry
// names with non-ASCII bytes, a forged tail, parentheses, and a newline while
// the unchanged reader, member scan, and capability probe run. A process that
// is killed and reaped between the reader's open and read produces the
// kernel's own ESRCH, and a zombie stays present until it is reaped.
func TestRemoteAlphaESServiceTLSStatusProcessIdentityLiveProcesses(t *testing.T) {
	const probe = remoteAlphaESProcessIdentityLivePrelude + `
NAMES={
    "utf8":b"sl\xc3\xa9\xc3\xa9p",
    "invalid_utf8":b"\xff\xfe\xfd",
    "high_bytes":bytes(range(0xf1,0x100)),
    "forged_tail":b"a) S 1 99 99 0",
    "newline":b"new\nline",
    "parens":b"((a)(",
    "whitespace":b" \t ",
    "ascii":b"plain",
}
pids={}
try:
    for label,name in NAMES.items():pids[label]=start(name)
    for label,name in NAMES.items():
        pid=pids[label]
        try:
            want=(pid,start_time_of(pid))
            seen=(name_of(pid)==name+b"\n",os.getpgid(pid)==pid,
                  module.read_proc_identity(pid),module.scan_group_members(pid))
            record("live_"+label,seen==(True,True,want,[want]),(seen,want))
        except BaseException as exc:
            record("live_"+label,False,type(exc).__name__+":"+str(exc))
    try:
        module.validate_process_capability()
        record("live_capability_probe_beside_named_processes",
               module.WITNESS_DISPOSITION_UNPROVED is False,"closeout unproved")
    except BaseException as exc:
        record("live_capability_probe_beside_named_processes",False,
               type(exc).__name__+":"+str(exc))
finally:
    for pid in pids.values():stop(pid)

class ReapAfterOpen:
    """Real os, except that the victim is killed and reaped right after its
    stat file was opened, so the kernel itself answers the read."""
    def __init__(self,victim):
        self.path="/proc/%d/stat"%victim;self.victim=victim;self.fd=None;self.read_errno=None
    def __getattr__(self,name):return getattr(os,name)
    def open(self,path,flags,*args,**kwargs):
        fd=os.open(path,flags,*args,**kwargs)
        if path==self.path and self.fd is None:
            self.fd=fd
            os.kill(self.victim,signal.SIGKILL);os.waitpid(self.victim,0)
        return fd
    def read(self,fd,n):
        mine=fd==self.fd and self.read_errno is None
        try:raw=os.read(fd,n)
        except OSError as exc:
            if mine:self.read_errno=exc.errno
            raise
        if mine:self.read_errno=0
        return raw
def ended_before_read(label,call,want):
    victim=start(b"victim")
    proxy=ReapAfterOpen(victim);module.os=proxy
    try:got=("value",call(victim))
    except BaseException as exc:got=("raised",type(exc).__name__+":"+str(exc))
    finally:
        module.os=os
        if proxy.fd is None:stop(victim)
    record(label,got==("value",want) and proxy.read_errno==errno.ESRCH,(got,proxy.read_errno))
ended_before_read("live_ended_before_read_is_absent",module.read_proc_identity,None)
ended_before_read("live_scan_passes_process_ended_before_read",module.scan_group_members,[])

zombie=start(b"zombie",stay=False)
try:
    try:
        os.waitid(os.P_PID,zombie,os.WEXITED|os.WNOWAIT)
        want=(zombie,start_time_of(zombie))
        seen=(module.read_proc_identity(zombie),module.scan_group_members(zombie))
    finally:
        os.waitpid(zombie,0)
    after=module.read_proc_identity(zombie)
    record("live_zombie_present_until_reaped",seen==(want,[want]) and after is None,(seen,want,after))
except BaseException as exc:
    record("live_zombie_present_until_reaped",False,type(exc).__name__+":"+str(exc))
print(json.dumps({"capability":True,"cases":cases,"detail":detail},sort_keys=True))
`
	result := runRemoteAlphaESProcessIdentityProbe(t, probe)
	requireRemoteAlphaESLiveProcStat(t, result)
	assertRemoteAlphaESProcessIdentityCases(t, result,
		"live_utf8", "live_invalid_utf8", "live_high_bytes", "live_forged_tail",
		"live_newline", "live_parens", "live_whitespace", "live_ascii",
		"live_capability_probe_beside_named_processes",
		"live_ended_before_read_is_absent",
		"live_scan_passes_process_ended_before_read",
		"live_zombie_present_until_reaped")
}

// An unrelated process with a non-ASCII name starts after the capability
// probe and stays alive. The real cleanup owner, member scan, and reader must
// finish one fixed command while that process lives and report no
// uncertainty. The unrelated process is ended only after the bound, so a
// collector that holds its cleanup on it fails here without hanging the test.
func TestRemoteAlphaESServiceTLSStatusUnrelatedProcessNameDoesNotHoldCleanup(t *testing.T) {
	const probe = remoteAlphaESProcessIdentityLivePrelude + `
BOUND=20.0
child=pathlib.Path(sys.argv[2])/"fixed_child"
child.write_text("#!/usr/bin/python3\nimport sys\nsys.stdout.write('fixed')\n")
child.chmod(0o700)
module.OPENSSL=str(child)
module.validate_process_capability()
module.PROCESS_CAPABILITY_READY=True
unrelated=start(b"sl\xc3\xa9\xc3\xa9p")
state={}
def run():
    try:state["result"]=module.run_fixed((str(child),"version"))
    except BaseException as exc:state["error"]=type(exc).__name__+":"+str(exc)
thread=threading.Thread(target=run,daemon=True);reaped=False
try:
    began=time.monotonic();thread.start();thread.join(BOUND)
    returned=not thread.is_alive();elapsed=round(time.monotonic()-began,3)
    reaped=os.waitpid(unrelated,os.WNOHANG)!=(0,0)
    alive=not reaped and name_of(unrelated)==b"sl\xc3\xa9\xc3\xa9p\n"
finally:
    if not reaped:stop(unrelated)
thread.join(60)
seen={"returned":returned,"unrelated_alive":alive,"elapsed":elapsed,
      "result":repr(state.get("result")),"error":state.get("error"),
      "finished":not thread.is_alive(),"closeout_unproved":module.WITNESS_DISPOSITION_UNPROVED}
record("returned_while_unrelated_process_lived",returned and alive,seen)
record("fixed_command_completed",state.get("result")==(0,b"fixed",b""),seen)
record("cleanup_reported_no_uncertainty",
       "error" not in state and module.WITNESS_DISPOSITION_UNPROVED is False,seen)
print(json.dumps({"capability":True,"cases":cases,"detail":detail},sort_keys=True))
`
	result := runRemoteAlphaESProcessIdentityProbe(t, probe, t.TempDir())
	requireRemoteAlphaESLiveProcStat(t, result)
	assertRemoteAlphaESProcessIdentityCases(t, result,
		"returned_while_unrelated_process_lived", "fixed_command_completed",
		"cleanup_reported_no_uncertainty")
}

func TestRemoteAlphaESServiceTLSStatusProcessIdentityDocumentsContract(t *testing.T) {
	plans := compactDocSection(t, mustRead(t, "PLANS.md"),
		"`Reopened redesign seam`: the P0s/P0t shared status-and-renewal helper",
		"The P0u implementation/self-audit/merge-readiness slice")
	remote := compactDocSection(t, mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"),
		"### P0s/P0t Dedicated ES TLS Status-Only Collector",
		"### P0u Mac-Side Operator Healthcheck TLS Status/Renew Recovery Session")
	access := compactDocSection(t, mustRead(t, ".docs/system_overview/remote_alpha_access_contract.md"),
		"## 1. Authority, scope, and status", "## 2. Versioned profile and ownership")
	for label, section := range map[string]string{"PLANS": plans, "Remote Alpha": remote, "access contract": access} {
		assertContainsAll(t, label+" process identity read", section,
			"as bytes", "kernel-written fields after the last `)`",
			"`ENOENT` or `ESRCH`", "absent, not unproved",
			"The name or the exit of an unrelated process therefore neither fails the capability probe nor prolongs the unresolved-cleanup hold",
			"time limit")
	}
	for label, section := range map[string]string{"PLANS": plans, "Remote Alpha": remote} {
		assertContainsAll(t, label+" process identity bounds", section,
			"may hold any byte", "it is never decoded, compared, or otherwise interpreted",
			"Every other open or read error is unproved, never absent",
			"`process_identity_unproved`", "never counts a visible zombie as absent")
	}
	assertContainsAll(t, "access contract process identity bounds", access,
		"never decodes the process name", "the hold gains no time limit")

	source := mustRead(t, remoteAlphaESServiceTLSStatusCollectorPath())
	reader := docSection(t, source, "\ndef read_proc_identity(", "\ndef scan_group_members(")
	assertContainsNone(t, "collector process identity reader", reader, ".decode(", "str(pid)")
	assertContainsAll(t, "collector process identity reader", reader, `raw.rfind(b")")`)
}
