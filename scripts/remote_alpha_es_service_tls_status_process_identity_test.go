package scripts_test

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
	cmd.Dir = executionSubstrateRepoRoot
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
# The PID namespace of a fixed command needs root and has its own tests.
` + remoteAlphaESStatusLocalChildNamespace + `held=[]
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
// forged tail inside a name must not be parsed, and every fault stays
// unproved. The stat file never proves absence: after ENOENT or ESRCH at
// open, ESRCH at read, or a negative group ID, the process is absent only
// when the injected pidfd_open answers that no process has the ID. While a
// process has it, the reader reads again and ends unproved, never absent.
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
    # process: what pidfd_open answers. None means it must not be asked at
    # all, "exists" opens descriptor 901, an errno fails with that error.
    # clears: after that many reads of the stat file it shows a plain line.
    def __init__(self,raw=b"",open_error=None,read_error=None,close_error=None,
                 process=None,clears=None,pidfd_close_error=None):
        self.raw=raw;self.open_error=open_error;self.read_error=read_error
        self.close_error=close_error;self.opened=0;self.closed=0
        self.process=process;self.clears=clears;self.pidfd_close_error=pidfd_close_error
        self.asked=0;self.pidfd_closed=0
    def __getattr__(self,name):return getattr(os,name)
    def cleared(self):return self.clears is not None and self.opened>self.clears
    def open(self,path,flags,*args,**kwargs):
        if path!="/proc/4242/stat" or args or kwargs:raise AssertionError("unexpected fake open")
        self.opened+=1
        if self.opened>40:raise AssertionError("the reader does not stop reading")
        if self.open_error is not None and not self.cleared():raise self.open_error
        return 900
    def read(self,fd,n):
        if fd!=900:raise AssertionError("unexpected fake read")
        if self.cleared():return line(b"sleep")[:n]
        if self.read_error is not None:raise self.read_error
        return self.raw[:n]
    def pidfd_open(self,pid,flags):
        if pid!=4242 or flags!=0:raise AssertionError("unexpected fake pidfd_open")
        self.asked+=1
        if self.process is None:raise AssertionError("pidfd_open asked without an unclear answer")
        if self.process=="exists":return 901
        raise fault(self.process)
    def close(self,fd):
        if fd==901:
            self.pidfd_closed+=1
            if self.pidfd_close_error is not None:raise self.pidfd_close_error
            return
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

# The kernel gives each of these four answers for a live process while a
# thread other than its first calls exec, so none of them proves absence.
READS=getattr(module,"PROC_IDENTITY_READS",4)
record("reads_bounded",getattr(module,"PROC_IDENTITY_READS",None)==4,READS)
UNCLEAR={
    "open_enoent":(dict(open_error=fault(errno.ENOENT)),0),
    "open_esrch":(dict(open_error=fault(errno.ESRCH)),0),
    "read_esrch":(dict(read_error=fault(errno.ESRCH)),1),
    "group_negative":(dict(raw=line(b"sleep",swap(2,b"-1"))),1),
}
def confirmed(label,fake,want,asked,pidfd_closed):
    got=outcome(fake)+(fake.asked,fake.pidfd_closed)
    record(label,got==want+(asked,pidfd_closed),got)
for label,(answer,closes) in UNCLEAR.items():
    # Absent only on the kernel's word that no process has the ID.
    confirmed(label,FakeOS(process=errno.ESRCH,**answer),(ABSENT,1,closes),1,0)
    confirmed(label+"_no_leader_einval",FakeOS(process=errno.EINVAL,**answer),(ABSENT,1,closes),1,0)
    # A process still has the ID: read again, and never call it absent.
    confirmed(label+"_while_process_exists",FakeOS(process="exists",**answer),
              (UNPROVED,READS,closes*READS),READS,READS)
    confirmed(label+"_then_clear",FakeOS(process="exists",clears=1,**answer),
              (PRESENT,2,closes+1),1,1)
    confirmed(label+"_clear_on_last_read",FakeOS(process="exists",clears=READS-1,**answer),
              (PRESENT,READS,closes*(READS-1)+1),READS-1,READS-1)
    refused=[errno.errorcode[code] for code in
             (errno.ENOENT,errno.EPERM,errno.EACCES,errno.EMFILE,errno.ENFILE,
              errno.ENOMEM,errno.ENOSYS,errno.ENODEV,errno.EIO)
             if outcome(FakeOS(process=code,**answer))!=(UNPROVED,1,closes)]
    record(label+"_other_pidfd_error_unproved",not refused,refused)
confirmed("group_other_negative",FakeOS(raw=line(b"sleep",swap(2,b"-777")),process="exists"),
          (UNPROVED,READS,READS),READS,READS)
expect("group_zero_is_a_value",FakeOS(line(b"sleep",swap(2,b"0"))),(("value",(0,START)),1,1))
module.WITNESS_DISPOSITION_UNPROVED=False
fake=FakeOS(open_error=fault(errno.ENOENT),process="exists",pidfd_close_error=fault(errno.EIO))
got=outcome(fake)+(fake.asked,fake.pidfd_closed)
record("pidfd_close_failure_stays_unproved",
       got==(("raised","OSError"),1,0,1,1) and module.WITNESS_DISPOSITION_UNPROVED is True,
       (got,module.WITNESS_DISPOSITION_UNPROVED))
module.WITNESS_DISPOSITION_UNPROVED=False
class NoPidfdOS(FakeOS):
    def __getattribute__(self,name):
        if name=="pidfd_open":raise AttributeError(name)
        return object.__getattribute__(self,name)
    def __getattr__(self,name):
        if name=="pidfd_open":raise AttributeError(name)
        return getattr(os,name)
expect("no_pidfd_open_is_capability_unavailable",NoPidfdOS(open_error=fault(errno.ENOENT)),
       (("incomplete","process_capability_unavailable"),1,0))
for code in (errno.EACCES,errno.EPERM,errno.EMFILE,errno.ENFILE,errno.ENOMEM,
             errno.EIO,errno.ELOOP,errno.ENOTDIR,errno.EINTR):
    expect("open_"+errno.errorcode[code].lower(),FakeOS(open_error=fault(code)),(UNPROVED,1,0))
for code in (errno.ENOENT,errno.EACCES,errno.EPERM,errno.ENOMEM,errno.EIO,errno.EINTR):
    # Only ESRCH at read is an unclear answer. Every other read error stays a
    # failure of this read and never reaches the confirmation.
    fake=FakeOS(read_error=fault(code));got=outcome(fake)+(fake.asked,)
    record("read_"+errno.errorcode[code].lower(),
           got[0] in (UNPROVED,("raised",type(fault(code)).__name__)) and got[1:]==(1,1,0),got)
module.WITNESS_DISPOSITION_UNPROVED=False
got=outcome(FakeOS(read_error=fault(errno.ESRCH),close_error=fault(errno.EIO)))
record("read_esrch_close_failure_stays_unproved",
       got==(("raised","OSError"),1,1) and module.WITNESS_DISPOSITION_UNPROVED is True,
       (got,module.WITNESS_DISPOSITION_UNPROVED))
module.WITNESS_DISPOSITION_UNPROVED=False

class FakeProc:
    # table: per stat path a list of answers, served in order, the last one
    # for good. existing: the IDs that pidfd_open finds a process for.
    def __init__(self,table,existing=()):
        self.table={path:list(answers) for path,answers in table.items()}
        self.existing=set(existing);self.fds={};self.last=900;self.closed=0;self.asked=[]
    def __getattr__(self,name):return getattr(os,name)
    def listdir(self,path):
        if path!="/proc":raise AssertionError("unexpected fake listdir")
        return ["self","1","4242","thread-self","4300","4400","4500","uptime"]
    def open(self,path,flags,*args,**kwargs):
        answers=self.table[path]
        kind,value=answers.pop(0) if len(answers)>1 else answers[0]
        if kind=="open_error":raise value
        self.last+=1;self.fds[self.last]=(kind,value);return self.last
    def read(self,fd,n):
        kind,value=self.fds[fd]
        if kind=="read_error":raise value
        return value[:n]
    def pidfd_open(self,pid,flags):
        if flags!=0:raise AssertionError("unexpected fake pidfd_open")
        self.asked.append(pid)
        if pid not in self.existing:raise fault(errno.ESRCH)
        self.last+=1;self.fds[self.last]=("pidfd",pid);return self.last
    def close(self,fd):
        del self.fds[fd];self.closed+=1
def scan(table,existing=()):
    fake=FakeProc(table,existing);module.os=fake
    try:kind=("value",module.scan_group_members(PGID))
    except module.Incomplete as exc:kind=("incomplete",str(exc))
    except BaseException as exc:kind=("raised",type(exc).__name__)
    finally:module.os=os
    return kind,fake.closed,len(fake.fds),fake.asked
member=("raw",line(b"sl\xc3\xa9\xc3\xa9p"))
table={
    "/proc/1/stat":[("open_error",fault(errno.ENOENT))],
    "/proc/4242/stat":[member],
    "/proc/4300/stat":[("raw",line(b"\xff\xfe",swap(2,b"555"),head=b"4300 ("))],
    "/proc/4400/stat":[("read_error",fault(errno.ESRCH))],
    "/proc/4500/stat":[("open_error",fault(errno.ESRCH))],
}
got=scan(table)
record("scan_passes_foreign_names_and_ended_processes",
       got==(("value",[(PID,START)]),3,0,[1,4400,4500]),got)
hidden=dict(table);hidden["/proc/4300/stat"]=[("open_error",fault(errno.EACCES))]
got=scan(hidden)
record("scan_unreadable_process_stays_unproved",got==(UNPROVED,1,0,[1]),got)
# A live member of the group must stay in the scan whatever the stat file
# answers first, and a member that never becomes readable leaves the scan
# unproved. Neither may make the group look empty.
for label,first,closes in (("open_enoent",("open_error",fault(errno.ENOENT)),0),
                           ("open_esrch",("open_error",fault(errno.ESRCH)),0),
                           ("read_esrch",("read_error",fault(errno.ESRCH)),1),
                           ("group_negative",("raw",line(b"sleep",swap(2,b"-1"))),1)):
    racing=dict(table);racing["/proc/4242/stat"]=[first,member]
    got=scan(racing,existing=[PID])
    record("scan_keeps_live_member_after_"+label,
           got==(("value",[(PID,START)]),closes+4,0,[1,PID,4400,4500]),got)
    stuck=dict(table);stuck["/proc/4242/stat"]=[first]
    got=scan(stuck,existing=[PID])
    record("scan_live_member_unclear_after_"+label+"_stays_unproved",
           got==(UNPROVED,(closes+1)*READS,0,[1]+[PID]*READS),got)
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
		"pid_zero", "pid_negative", "reads_bounded",
		"open_enoent", "open_enoent_no_leader_einval", "open_enoent_while_process_exists",
		"open_enoent_then_clear", "open_enoent_clear_on_last_read",
		"open_enoent_other_pidfd_error_unproved",
		"open_esrch", "open_esrch_no_leader_einval", "open_esrch_while_process_exists",
		"open_esrch_then_clear", "open_esrch_clear_on_last_read",
		"open_esrch_other_pidfd_error_unproved",
		"read_esrch", "read_esrch_no_leader_einval", "read_esrch_while_process_exists",
		"read_esrch_then_clear", "read_esrch_clear_on_last_read",
		"read_esrch_other_pidfd_error_unproved",
		"group_negative", "group_negative_no_leader_einval",
		"group_negative_while_process_exists", "group_negative_then_clear",
		"group_negative_clear_on_last_read", "group_negative_other_pidfd_error_unproved",
		"group_other_negative", "group_zero_is_a_value",
		"pidfd_close_failure_stays_unproved", "no_pidfd_open_is_capability_unavailable",
		"open_eacces", "open_eperm", "open_emfile",
		"open_enfile", "open_enomem", "open_eio", "open_eloop", "open_enotdir",
		"open_eintr",
		"read_enoent", "read_eacces", "read_eperm", "read_enomem",
		"read_eio", "read_eintr", "read_esrch_close_failure_stays_unproved",
		"scan_passes_foreign_names_and_ended_processes",
		"scan_unreadable_process_stays_unproved",
		"scan_keeps_live_member_after_open_enoent",
		"scan_live_member_unclear_after_open_enoent_stays_unproved",
		"scan_keeps_live_member_after_open_esrch",
		"scan_live_member_unclear_after_open_esrch_stays_unproved",
		"scan_keeps_live_member_after_read_esrch",
		"scan_live_member_unclear_after_read_esrch_stays_unproved",
		"scan_keeps_live_member_after_group_negative",
		"scan_live_member_unclear_after_group_negative_stays_unproved")
}

// The same rules against the real kernel: live processes of this test carry
// names with non-ASCII bytes, a forged tail, parentheses, and a newline while
// the unchanged reader, member scan, and capability probe run. A process that
// is killed and reaped between the reader's open and read produces the
// kernel's own ESRCH, and a zombie stays present until it is reaped.
//
// Absence is decided by the kernel's own pidfd_open here. The stat answers
// that the kernel gives for a live process during an exec from a thread
// other than the first are injected for one stat file only: for a live child
// they must never read as absent, for a reaped child they must. A reaped
// group leader whose group still has a member is absent itself, while the
// scan of its group still finds the member.
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

class UnclearStat:
    """Real os, pidfd_open included, except for the stat file of one process:
    its first reads get an answer that the kernel gives for a live process
    during an exec from a thread other than the first."""
    def __init__(self,pid,kind,count):
        self.pid=pid;self.path="/proc/%d/stat"%pid;self.kind=kind;self.left=count
        self.fds=set();self.injected=0
    def __getattr__(self,name):return getattr(os,name)
    def open(self,path,flags,*args,**kwargs):
        if path!=self.path or self.left<=0:return os.open(path,flags,*args,**kwargs)
        self.left-=1;self.injected+=1
        if self.kind=="open_enoent":raise FileNotFoundError(errno.ENOENT,"injected")
        if self.kind=="open_esrch":raise ProcessLookupError(errno.ESRCH,"injected")
        fd=os.open("/proc/self/stat",flags,*args,**kwargs);self.fds.add(fd);return fd
    def read(self,fd,n):
        if fd not in self.fds:return os.read(fd,n)
        self.fds.discard(fd)
        if self.kind=="read_esrch":raise ProcessLookupError(errno.ESRCH,"injected")
        raw=os.read(fd,n);close=raw.rindex(b")");fields=raw[close+2:].split();fields[2]=b"-1"
        return b"%d (injected) "%self.pid+b" ".join(fields)+b"\n"
def through(proxy,call,*args):
    module.os=proxy
    try:return ("value",call(*args))
    except module.Incomplete as exc:return ("incomplete",str(exc))
    except BaseException as exc:return ("raised",type(exc).__name__+":"+str(exc))
    finally:module.os=os
KINDS=("open_enoent","open_esrch","read_esrch","group_negative")
READS=getattr(module,"PROC_IDENTITY_READS",4)
for kind in KINDS:
    label="live_"+kind
    child=start(b"alive")
    try:
        want=(child,start_time_of(child))
        once=UnclearStat(child,kind,1);read_once=through(once,module.read_proc_identity,child)
        scanning=UnclearStat(child,kind,1);scanned=through(scanning,module.scan_group_members,child)
        last=UnclearStat(child,kind,READS-1);read_last=through(last,module.read_proc_identity,child)
        always=UnclearStat(child,kind,10**6);stuck=through(always,module.read_proc_identity,child)
        hidden=UnclearStat(child,kind,10**6);hidden_scan=through(hidden,module.scan_group_members,child)
        seen=(read_once,once.injected,scanned,scanning.injected,read_last,last.injected,
              stuck,always.injected,hidden_scan,hidden.injected)
        record(label+"_for_live_process_is_not_absent",
               seen==(("value",want),1,("value",[want]),1,("value",want),READS-1,
                      ("incomplete","process_identity_unproved"),READS,
                      ("incomplete","process_identity_unproved"),READS),(seen,want))
    except BaseException as exc:
        record(label+"_for_live_process_is_not_absent",False,type(exc).__name__+":"+str(exc))
    finally:
        stop(child)
    try:
        always=UnclearStat(child,kind,10**6)
        seen=(through(always,module.read_proc_identity,child),always.injected,
              through(UnclearStat(child,kind,10**6),module.scan_group_members,child))
        record(label+"_for_reaped_process_is_absent",seen==(("value",None),1,("value",[])),seen)
    except BaseException as exc:
        record(label+"_for_reaped_process_is_absent",False,type(exc).__name__+":"+str(exc))

# A group leader that was reaped while its group still has a member: the
# number stays in use as a group ID, and no process has it as its own ID.
try:
    pid_r,pid_w=os.pipe();hold_r,hold_w=os.pipe()
    leader=os.fork()
    if leader==0:
        code=1
        try:
            for fd in [pid_r,hold_w]+held:os.close(fd)
            os.setsid()
            member=os.fork()
            if member==0:
                os.close(pid_w);os.read(hold_r,1);os._exit(0)
            os.write(pid_w,b"%d\n"%member);code=0
        except BaseException:pass
        os._exit(code)
    os.close(pid_w);os.close(hold_r)
    try:
        with os.fdopen(pid_r,"rb") as handle:member=int(handle.read())
        os.waitpid(leader,0)
        want=(member,start_time_of(member))
        try:os.killpg(leader,0);group_lives=True
        except ProcessLookupError:group_lives=False
        seen=(group_lives,os.getpgid(member)==leader,module.read_proc_identity(leader),
              module.scan_group_members(leader))
        record("live_reaped_leader_of_live_group_is_absent",seen==(True,True,None,[want]),(seen,want))
    finally:
        os.close(hold_w)
except BaseException as exc:
    record("live_reaped_leader_of_live_group_is_absent",False,type(exc).__name__+":"+str(exc))
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
		"live_zombie_present_until_reaped",
		"live_open_enoent_for_live_process_is_not_absent",
		"live_open_enoent_for_reaped_process_is_absent",
		"live_open_esrch_for_live_process_is_not_absent",
		"live_open_esrch_for_reaped_process_is_absent",
		"live_read_esrch_for_live_process_is_not_absent",
		"live_read_esrch_for_reaped_process_is_absent",
		"live_group_negative_for_live_process_is_not_absent",
		"live_group_negative_for_reaped_process_is_absent",
		"live_reaped_leader_of_live_group_is_absent")
}

// A live process whose threads other than the first keep calling exec is the
// case in which the kernel can show a wrong stat answer. The reader and the
// member scan must never report that process as absent or under another
// identity, and the proof of group absence must not return while it lives.
// The exec loop is real; whether the kernel shows a wrong answer in a given
// run is up to the kernel, and the injected cases above cover each answer.
func TestRemoteAlphaESServiceTLSStatusProcessIdentityThreadExecStaysPresent(t *testing.T) {
	const probe = remoteAlphaESProcessIdentityLivePrelude + `
BOUND=60.0;GENERATIONS=30;READS_WANTED=2000
script=pathlib.Path(sys.argv[2])/"thread_exec.py"
script.write_text(
    "import os,sys,threading\n"
    "try:os.write(int(sys.argv[1]),b'x')\n"
    "except OSError:os._exit(0)\n"
    "def again():\n"
    "    if threading.get_native_id()==os.getpid():os._exit(3)\n"
    "    os.execv(sys.executable,[sys.executable,'-I','-S',sys.argv[0],sys.argv[1]])\n"
    "thread=threading.Thread(target=again);thread.start();thread.join();os._exit(4)\n")
count_r,count_w=os.pipe();go_r,go_w=os.pipe();os.set_inheritable(count_w,True)
storm=os.fork()
if storm==0:
    try:
        os.close(count_r);os.close(go_w);os.setsid()
        if os.read(go_r,1)==b"g":
            os.close(go_r)
            os.execv(sys.executable,[sys.executable,"-I","-S",str(script),str(count_w)])
    finally:os._exit(1)
os.close(count_w);os.close(go_r);os.set_blocking(count_r,False)
execs=0
def drain():
    global execs
    try:execs+=len(os.read(count_r,65536))
    except BlockingIOError:pass
state={}
reaped=False
try:
    deadline=time.monotonic()+BOUND
    while os.getpgid(storm)!=storm and time.monotonic()<deadline:time.sleep(.005)
    want=(storm,start_time_of(storm))
    before=module.read_proc_identity(storm)
    os.write(go_w,b"g");os.close(go_w)
    counts={"reads":0,"same":0,"absent":0,"other":0,"unproved":0,
            "scans":0,"scan_same":0,"scan_missing":0,"scan_unproved":0}
    while (execs<GENERATIONS or counts["reads"]<READS_WANTED) and time.monotonic()<deadline:
        drain()
        try:got=module.read_proc_identity(storm)
        except module.Incomplete:counts["unproved"]+=1
        else:counts["same" if got==want else "absent" if got is None else "other"]+=1
        counts["reads"]+=1
        if counts["reads"]%20==0:
            try:members=module.scan_group_members(storm)
            except module.Incomplete:counts["scan_unproved"]+=1
            else:counts["scan_same" if members==[want] else "scan_missing"]+=1
            counts["scans"]+=1
    def prove():
        try:state["result"]=module.prove_group_absent(storm)
        except BaseException as exc:state["error"]=type(exc).__name__+":"+str(exc)
    thread=threading.Thread(target=prove,daemon=True)
    mark=execs;thread.start()
    while execs<mark+10 and time.monotonic()<deadline:
        drain();time.sleep(.01)
    held=thread.is_alive() and not state
    alive=os.waitpid(storm,os.WNOHANG)==(0,0)
    if alive:stop(storm)
    reaped=True
    thread.join(30)
    seen={"before":before,"want":want,"execs":execs,"counts":counts,"held":held,
          "alive":alive,"finished":not thread.is_alive(),"state":state}
    record("thread_exec_loop_ran",before==want and alive and execs>=GENERATIONS+10
           and counts["reads"]>=READS_WANTED,seen)
    record("thread_exec_process_never_absent",counts["absent"]==0 and counts["scan_missing"]==0,seen)
    record("thread_exec_process_keeps_identity",counts["other"]==0
           and counts["unproved"]*100<=counts["reads"] and counts["scan_unproved"]*100<=counts["scans"]
           and counts["same"]>0 and counts["scan_same"]>0,seen)
    record("group_absence_proof_held_while_process_lived",held and alive,seen)
    record("group_absence_proof_returned_after_reap",
           not thread.is_alive() and "error" not in state and "result" in state,seen)
finally:
    if not reaped:
        try:stop(storm)
        except OSError:pass
    os.close(count_r)
print(json.dumps({"capability":True,"cases":cases,"detail":detail},sort_keys=True))
`
	result := runRemoteAlphaESProcessIdentityProbe(t, probe, t.TempDir())
	requireRemoteAlphaESLiveProcStat(t, result)
	assertRemoteAlphaESProcessIdentityCases(t, result,
		"thread_exec_loop_ran", "thread_exec_process_never_absent",
		"thread_exec_process_keeps_identity",
		"group_absence_proof_held_while_process_lived",
		"group_absence_proof_returned_after_reap")
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
			"The stat file never proves that a process is absent",
			"listed process is absent only when `pidfd_open` confirms that no process has its ID",
			"an answer that stays unclear is unproved, never absent",
			"The name or the exit of an unrelated process therefore neither fails the capability probe nor prolongs the unresolved-cleanup hold",
			"time limit")
		// The rule that the audit of 64a0e0c refuted must not come back.
		assertContainsNone(t, label+" process identity read", section,
			"absent, not unproved", "no longer exists")
	}
	for label, section := range map[string]string{"PLANS": plans, "Remote Alpha": remote} {
		assertContainsAll(t, label+" process identity bounds", section,
			"may hold any byte", "it is never decoded, compared, or otherwise interpreted",
			"a thread other than the first thread of a live process calls exec, the kernel can answer `ENOENT` or `ESRCH` at open, `ESRCH` at read, or a line with a negative group ID",
			"`EINVAL` from a kernel that answers so for a number that no process leads",
			"four times at most",
			"Every other open or read error is unproved, never absent",
			"`process_identity_unproved`", "never counts a visible zombie as absent")
	}
	assertContainsAll(t, "access contract process identity bounds", access,
		"never decodes the process name", "the hold gains no time limit",
		"the kernel can answer `ENOENT`, `ESRCH`, or a negative group ID for a live process")

	source := mustRead(t, remoteAlphaESServiceTLSStatusCollectorPath())
	reader := docSection(t, source, "\ndef read_proc_identity(", "\ndef scan_group_members(")
	assertContainsNone(t, "collector process identity reader", reader, ".decode(", "str(pid)")
	assertContainsAll(t, "collector process identity reader", reader, `raw.rfind(b")")`,
		"if process_absent(pid):", "os.pidfd_open(pid, 0)", "range(PROC_IDENTITY_READS)")
	assertContainsAll(t, "collector process identity read bound", source, "\nPROC_IDENTITY_READS = 4\n")
}
