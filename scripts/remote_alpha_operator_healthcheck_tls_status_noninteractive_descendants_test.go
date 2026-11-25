package scripts_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// The noninteractive remote TLS status collector makes itself a child
// subreaper and, after every fixed command, kills and reaps its children
// until the kernel reports that none is left. These tests cover that
// descendant containment in two ways, as
// .docs/system_overview/capability_probing.md states.
//
// The first group gives the drain and the descendant capability probe a
// deterministic backend in place of the kernel operations. It runs on every
// host and proves the order of the steps, every refusal, and what is reported
// as unproved. It proves nothing about a kernel.
//
// The second group, whose names hold "Real", uses real processes as the user
// that runs the tests. It first asks, by an attempt in a child of its own,
// whether this host lets a process become a child subreaper and list its
// children, and skips itself only on the explicit answer that it does not.
//
// The Python children import only the source-controlled collector. They never
// run its entry point, an operator route, or a real OpenSSL child, and they
// write nothing outside t.TempDir().

// remoteCollectorDescendantStandIn replaces the collector's capability flag
// and its descendant drain together. The tests of this package that call the
// collector's command runner directly use it, because the real drain needs a
// process that is a child subreaper. The stand-in proves only that the test
// process has no child left after a command: the fixed child must have been
// reaped by the command runner itself. It proves nothing about descendants.
// It also gives the runner a descendant backend whose parent-death request
// does nothing, because the real request needs Linux's prctl, which macOS
// does not have; the real-kernel tests prove the real request. The guard
// below refuses every other script that replaces the flag, the drain, or the
// probe.
const remoteCollectorDescendantStandIn = `
def _remote_collector_drain_stand_in(direct=None, backend=None):
    import os as _os
    try:
        _os.waitpid(-1, _os.WNOHANG)
    except ChildProcessError:
        return True
    return False
class _RemoteCollectorBackendStandIn(m.DescendantBackend):
    def __init__(self):
        super().__init__()
        self.parent_death_request = lambda: (lambda: 0)
m.drain_descendants = _remote_collector_drain_stand_in
m.DescendantBackend = _RemoteCollectorBackendStandIn
m.DESCENDANT_CAPABILITY_READY = True
`

func runRemoteCollectorDescendantProbe(t *testing.T, probe string, args ...string) map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	argv := append([]string{"-I", "-B", "-c", probe, p0vRemoteCollectorPath()}, args...)
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", argv...)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	cmd.WaitDelay = 10 * time.Second
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("descendant probe timed out: %v\n%s", ctx.Err(), output)
	}
	if err != nil {
		t.Fatalf("descendant probe: %v\n%s", err, output)
	}
	var result map[string]any
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("descendant probe JSON: %v\n%s", err, output)
	}
	return result
}

func assertRemoteCollectorDescendantCases(t *testing.T, result map[string]any, want ...string) {
	t.Helper()
	cases, ok := result["cases"].(map[string]any)
	if !ok {
		t.Fatalf("descendant probe returned no cases: %v", result)
	}
	detail, _ := result["detail"].(map[string]any)
	for _, label := range want {
		if cases[label] != true {
			t.Errorf("%s failed: %v", label, detail[label])
		}
	}
	if len(cases) != len(want) {
		t.Errorf("descendant probe returned %d cases, want %d: %v", len(cases), len(want), cases)
	}
}

const remoteCollectorDescendantLoader = `
import errno,importlib.util,json,os,signal,sys,time,types
spec=importlib.util.spec_from_file_location("remote_descendants",sys.argv[1])
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
cases={};detail={}
def record(label,passed,seen):
    cases[label]=bool(passed)
    if not passed:detail[label]=repr(seen)
`

// The deterministic backend holds a small model of this process's children.
// A child is alive or ended; an ended child stays listed until it is reaped.
// A kill ends an alive child, unless the child refuses it as a root process
// does; a relay leaves one new child each time it is killed, until its
// generations are used up. The probe's fork makes the probe child, which
// starts the grandchild and ends at once; the grandchild comes to this
// process only after this process has become a child subreaper, and it ends
// by itself when this process closes the hold pipe's write end, as the real
// grandchild does at the end of its input. The clock moves only by sleep.
// The backend records every call but one: the fixed child's parent-death
// request, which it resolves to a request that does nothing. It records as a
// violation a signal to anything but an unreaped child, a signal other than SIGKILL, a reap of a
// child that has not ended, a blocking wait on a child that has not ended, a
// wait with other options than the drain's, and a close of a descriptor that
// is not open.
const remoteCollectorDescendantModel = `
class Exited(BaseException):
    pass
class Direct:
    # The fixed child's process handle: it reaps only its own process.
    def __init__(self,kernel,pid,returncode=None):
        self.kernel=kernel;self.pid=pid;self.returncode=returncode;self.polls=0
    def poll(self):
        self.polls+=1
        if self.returncode is None and self.kernel.children.get(self.pid)=="ended":
            del self.kernel.children[self.pid];self.kernel.reaped.append(self.pid)
            self.returncode=-signal.SIGKILL
        return self.returncode
class Kernel:
    drain_options=os.WEXITED|os.WNOHANG|os.WNOWAIT
    def __init__(self,children=(),ended=(),refusing=(),relay=0,probe_status=0,adopt=True,report=None,child_side=False,**faults):
        self.children={pid:"alive" for pid in children}
        for pid in ended:self.children[pid]="ended"
        self.refusing=set(refusing);self.relay=relay;self.faults=faults
        self.probe_status=probe_status;self.adopt=adopt;self.report=report;self.child_side=child_side
        self.now=0.0;self.events=[];self.violations=[];self.reaped=[];self.kills=[]
        self.descriptors=set();self.last_fd=800;self.pipes=[];self.forks=0
        self.subreaper=False;self.next_pid=6000;self.direct=None
    def _raise(self,name):
        fault=self.faults.get(name)
        if isinstance(fault,list):fault=fault.pop(0) if fault else None
        if fault is not None:raise fault
    def _new_fd(self):
        self.last_fd+=1;self.descriptors.add(self.last_fd);return self.last_fd
    def role(self,fd):
        for name,(read_end,write_end) in zip(("report","hold"),self.pipes):
            if fd==read_end:return name+"_read"
            if fd==write_end:return name+"_write"
        return "unknown"
    def monotonic(self):
        return self.now
    def sleep(self,seconds):
        self.events.append(("sleep",seconds));self.now+=seconds
    def set_child_subreaper(self):
        self.events.append(("set_child_subreaper",));self._raise("set_child_subreaper")
        self.subreaper=True
    def waitid(self,idtype,ident,options):
        self.events.append(("waitid",));self._raise("waitid")
        if idtype!=os.P_ALL or options!=self.drain_options:
            self.violations.append(("waitid options",idtype,ident,options))
        if not self.children:raise ChildProcessError(errno.ECHILD,"no child")
        ended=sorted(pid for pid,state in self.children.items() if state=="ended")
        return types.SimpleNamespace(si_pid=ended[0]) if ended else None
    def waitpid(self,pid,options):
        self.events.append(("waitpid",pid,options));self._raise("waitpid")
        if self.direct is not None and pid==self.direct.pid and self.direct.returncode is None:
            self.violations.append(("raw reap of the fixed child",pid))
        if pid not in self.children:
            self.violations.append(("wait for a process that is no child",pid))
            raise ChildProcessError(errno.ECHILD,"no child")
        if self.children[pid]!="ended":
            if options&os.WNOHANG:return (0,0)
            self.violations.append(("blocking wait on a child that has not ended",pid))
            return (0,0)
        del self.children[pid];self.reaped.append(pid)
        return (pid,(self.probe_status<<8) if pid==self.middle_pid() else 0)
    def middle_pid(self):
        return 4100
    def listdir(self,path):
        self.events.append(("listdir",path));self._raise("listdir")
        if path!="/proc/self/task":self.violations.append(("listdir",path))
        return ["100"]
    def read_children(self,path):
        self.events.append(("read_children",path));self._raise("read_children")
        if path!="/proc/self/task/100/children":self.violations.append(("read_children",path))
        return "".join("%d "%pid for pid in sorted(self.children))
    def kill(self,pid,sig):
        self.events.append(("kill",pid,sig));self.kills.append(pid)
        if sig!=signal.SIGKILL:self.violations.append(("signal",pid,sig))
        if pid not in self.children:
            self.violations.append(("signal to a process that is no child",pid))
            raise ProcessLookupError(errno.ESRCH,"no process")
        if pid in self.refusing:raise PermissionError(errno.EPERM,"not permitted")
        if self.children[pid]=="alive":
            self.children[pid]="ended"
            if self.relay>0:
                self.relay-=1;self.next_pid+=1;self.children[self.next_pid]="alive"
    def fork(self):
        self.forks+=1;self.events.append(("fork",));self._raise("fork")
        if self.child_side:return 0 if self.forks==1 else 4101
        if self.forks==1:
            # The probe child starts the grandchild, reports it, and ends.
            self.children[4100]="ended"
            if self.adopt and self.subreaper:self.children[4101]="alive"
            if self.report is None:self.report=b"4101"
            return 4100
        self.violations.append(("fork",self.forks))
        return 4199
    def pipe(self):
        self.events.append(("pipe",));self._raise("pipe")
        ends=(self._new_fd(),self._new_fd());self.pipes.append(ends);return ends
    def read(self,fd,size):
        self.events.append(("read",self.role(fd),size));self._raise("read")
        if self.role(fd)=="report_read":return self.report
        return b""
    def write(self,fd,data):
        self.events.append(("write",self.role(fd),data));self._raise("write")
        return len(data)
    def close(self,fd):
        role=self.role(fd);self.events.append(("close",role))
        if fd not in self.descriptors:self.violations.append(("close of a descriptor that is not open",fd))
        self.descriptors.discard(fd);self._raise("close")
        if role=="hold_write" and not self.child_side and self.children.get(4101)=="alive":
            self.children[4101]="ended"
    def exit(self,code):
        self.events.append(("exit",code));raise Exited(code)
    def parent_death_request(self):
        # Resolved by the command runner before each spawn; the model's
        # request does nothing and records no event.
        self._raise("parent_death_request")
        return lambda:0
def names(kernel):
    return [event[0] for event in kernel.events]
def probe(kernel):
    try:m.validate_descendant_capability(kernel)
    except m.DescendantCapabilityUnavailable as exc:return str(exc)
    return None
`

func TestRemoteAlphaOperatorHealthcheckTLSStatusNoninteractiveDescendantDrain(t *testing.T) {
	probe := remoteCollectorDescendantLoader + remoteCollectorDescendantModel + `
k=Kernel()
record("a drain with no child is proved by the first wait",
       m.drain_descendants(None,k) is True and names(k)==["waitid"] and k.violations==[],k.events)

k=Kernel(children=[10,11])
proved=m.drain_descendants(None,k)
record("a drain kills every listed child and proves that none is left",
       proved and sorted(k.kills)==[10,11] and sorted(k.reaped)==[10,11] and k.violations==[],(proved,k.events,k.violations))

k=Kernel(children=[20,21]);direct=Direct(k,20);k.direct=direct
proved=m.drain_descendants(direct,k)
record("a drain reaps the fixed child only through its own handle",
       proved and direct.returncode==-signal.SIGKILL and direct.polls>=1
       and not any(event[0]=="waitpid" and event[1]==20 for event in k.events) and k.violations==[],
       (proved,direct.returncode,k.events,k.violations))

k=Kernel(children=[30]);direct=Direct(k,30,returncode=0)
proved=m.drain_descendants(direct,k)
record("a reused process ID of a reaped fixed child is reaped as any other child",
       proved and direct.polls==0 and ("waitpid",30,os.WNOHANG) in k.events and k.violations==[],
       (proved,direct.polls,k.events))

k=Kernel(children=[40],refusing=[40])
proved=m.drain_descendants(None,k)
sleeps=[event[1] for event in k.events if event[0]=="sleep"]
record("a child that refuses the kill is reported unproved at the bound",
       proved is False and m.DESCENDANT_DRAIN_SECONDS<=k.now<m.DESCENDANT_DRAIN_SECONDS+0.05+1e-9
       and k.children=={40:"alive"} and k.kills.count(40)>1 and max(sleeps)<=0.05 and k.violations==[],
       (proved,k.now,k.children,len(k.kills),k.violations))

k=Kernel(children=[50],relay=5)
proved=m.drain_descendants(None,k)
record("a relay that leaves a new child at each kill is drained over several rounds",
       proved and len(k.reaped)==6 and len(k.kills)>=6 and k.violations==[],(proved,k.reaped,k.kills))

k=Kernel(waitid=OSError(errno.EINVAL,"invalid"))
proved=m.drain_descendants(None,k)
record("a failing wait is never taken as proof",
       proved is False and k.now>=m.DESCENDANT_DRAIN_SECONDS and k.violations==[],(proved,k.now))

k=Kernel(ended=[60],read_children=OSError(errno.ENOENT,"no list"))
proved=m.drain_descendants(None,k)
record("an ended child is reaped and proved gone without the children list",
       proved and k.reaped==[60] and k.violations==[],(proved,k.events))

k=Kernel(children=[61],read_children=OSError(errno.ENOENT,"no list"))
proved=m.drain_descendants(None,k)
record("a live child that cannot be listed is reported unproved",
       proved is False and k.kills==[] and k.children=={61:"alive"},(proved,k.events))

k=Kernel(children=[70],ended=range(1000,1100))
proved=m.drain_descendants(None,k)
first_kill=names(k).index("kill")
record("a kill round comes after at most the bounded number of reaps",
       proved and names(k)[:first_kill].count("waitpid")==m.DESCENDANT_REAPS_PER_ROUND==64
       and len(k.reaped)==101 and k.violations==[],(proved,names(k)[:first_kill].count("waitpid")))

listed=[]
for listing in ("0 ","-3 ","x ","7 7 8 "):
    k=Kernel();k.read_children=lambda path,listing=listing:listing
    try:listed.append(sorted(m.own_children(k)))
    except ValueError:listed.append("refused")
record("the children list refuses a non-positive or malformed process ID",
       listed==["refused","refused","refused",[7,8]],listed)

big=os.path.join(sys.argv[2],"children")
with open(big,"wb") as handle:handle.write(b"1 "*(m.MAX_CHILDREN_LIST_BYTES//2))
exact=len(m._read_children_file(big))
with open(big,"ab") as handle:handle.write(b"1")
try:m._read_children_file(big);over="read"
except OSError as exc:over=exc.errno
record("the children list read is bounded",
       exact==m.MAX_CHILDREN_LIST_BYTES==65536 and over==errno.EOVERFLOW,(exact,over))
print(json.dumps({"cases":cases,"detail":detail}))
`
	result := runRemoteCollectorDescendantProbe(t, probe, t.TempDir())
	assertRemoteCollectorDescendantCases(t, result,
		"a drain with no child is proved by the first wait",
		"a drain kills every listed child and proves that none is left",
		"a drain reaps the fixed child only through its own handle",
		"a reused process ID of a reaped fixed child is reaped as any other child",
		"a child that refuses the kill is reported unproved at the bound",
		"a relay that leaves a new child at each kill is drained over several rounds",
		"a failing wait is never taken as proof",
		"an ended child is reaped and proved gone without the children list",
		"a live child that cannot be listed is reported unproved",
		"a kill round comes after at most the bounded number of reaps",
		"the children list refuses a non-positive or malformed process ID",
		"the children list read is bounded")
}

func TestRemoteAlphaOperatorHealthcheckTLSStatusNoninteractiveDescendantProbe(t *testing.T) {
	probe := remoteCollectorDescendantLoader + remoteCollectorDescendantModel + `
k=Kernel()
failure=probe(k)
order=names(k)
record("a probe adopts, kills, and reaps the grandchild and sets the flag",
       failure is None and m.DESCENDANT_CAPABILITY_READY is True and k.subreaper
       and order.index("waitid")<order.index("set_child_subreaper")<order.index("fork")
       and k.kills==[4101] and sorted(k.reaped)==[4100,4101] and k.children=={}
       and ("waitpid",4100,0) in k.events and k.descriptors==set() and k.violations==[],
       (failure,k.events,k.violations,k.descriptors))
# The probe proves that the collector can kill an adopted descendant, so the
# grandchild must still be held when the drain kills it.
record("the probe kills the grandchild while the hold pipe is still open",
       k.events.index(("kill",4101,signal.SIGKILL))<k.events.index(("close","hold_write")),k.events)

k=Kernel(children=[70])
failure=probe(k)
record("a probe refuses a child that it did not start and leaves it alone",
       failure=="child_present" and m.DESCENDANT_CAPABILITY_READY is False and names(k)==["waitid"]
       and k.children=={70:"alive"},(failure,k.events))

k=Kernel(set_child_subreaper=OSError(errno.EINVAL,"invalid"))
failure=probe(k)
record("a refused child subreaper is unproved before any fork",
       failure=="probe_failed" and m.DESCENDANT_CAPABILITY_READY is False and "fork" not in names(k)
       and k.descriptors==set(),(failure,k.events))

k=Kernel(probe_status=1)
failure=probe(k)
record("a probe child that fails is unproved and everything is closed and reaped",
       failure=="probe_child" and m.DESCENDANT_CAPABILITY_READY is False and k.descriptors==set()
       and k.children=={} and k.violations==[],(failure,k.events,k.children))

k=Kernel(adopt=False)
failure=probe(k)
record("a grandchild that does not come to the probe is unproved",
       failure=="not_adopted" and m.DESCENDANT_CAPABILITY_READY is False and k.kills==[]
       and k.descriptors==set() and k.violations==[],(failure,k.events))

k=Kernel(report=b"x")
failure=probe(k)
record("a malformed report of the grandchild is unproved",
       failure=="not_adopted" and m.DESCENDANT_CAPABILITY_READY is False and k.descriptors==set(),(failure,k.events))
record("after a failed probe the hold pipe closes first, and the grandchild is reaped without a signal",
       k.kills==[] and k.children=={} and 4101 in k.reaped and k.violations==[],(k.kills,k.children,k.events))

assert probe(Kernel()) is None and m.DESCENDANT_CAPABILITY_READY is True
k=Kernel(refusing=[4101])
failure=probe(k)
record("a grandchild that cannot be killed is unproved and clears an earlier flag",
       failure=="not_drained" and m.DESCENDANT_CAPABILITY_READY is False and k.descriptors==set(),
       (failure,k.events,m.DESCENDANT_CAPABILITY_READY))

k=Kernel(close=[None,None,None,OSError(errno.EIO,"close")])
failure=probe(k)
record("a failed close of a probe descriptor is unproved",
       failure=="probe_close" and m.DESCENDANT_CAPABILITY_READY is False,(failure,k.events))

class NoWait:
    def __init__(self):raise AttributeError("waitid")
original=m.DescendantBackend
m.DescendantBackend=NoWait
try:failure=probe(None)
finally:m.DescendantBackend=original
record("a Python without the kernel operations is unproved",
       failure=="probe_failed" and m.DESCENDANT_CAPABILITY_READY is False,failure)

k=Kernel(child_side=True)
try:m.validate_descendant_capability(k);ended="returned"
except Exited as exc:ended=exc.args[0]
first_exit=names(k).index("exit")
record("the probe child closes the ends it does not use, starts the grandchild, reports it, and ends",
       k.events[:first_exit+1]==[("waitid",),("set_child_subreaper",),("pipe",),("pipe",),("fork",),
           ("close","report_read"),("close","hold_write"),("fork",),("write","report_write",b"4101"),("exit",0)],
       k.events)

k=Kernel(child_side=True)
try:m._descendant_probe_member(902,903,k)
except Exited:pass
record("the grandchild closes the report end and waits on the hold end until it ends",
       k.events[:4]==[("fork",),("close","unknown"),("read","unknown",1),("exit",0)],k.events)

k=Kernel(fork=OSError(errno.EAGAIN,"no process"))
try:m._descendant_probe_member(902,903,k)
except Exited:pass
record("a probe child that cannot start the grandchild ends with a failure",
       k.events==[("fork",),("exit",1)],k.events)
print(json.dumps({"cases":cases,"detail":detail}))
`
	result := runRemoteCollectorDescendantProbe(t, probe)
	assertRemoteCollectorDescendantCases(t, result,
		"a probe adopts, kills, and reaps the grandchild and sets the flag",
		"the probe kills the grandchild while the hold pipe is still open",
		"a probe refuses a child that it did not start and leaves it alone",
		"a refused child subreaper is unproved before any fork",
		"a probe child that fails is unproved and everything is closed and reaped",
		"a grandchild that does not come to the probe is unproved",
		"a malformed report of the grandchild is unproved",
		"after a failed probe the hold pipe closes first, and the grandchild is reaped without a signal",
		"a grandchild that cannot be killed is unproved and clears an earlier flag",
		"a failed close of a probe descriptor is unproved",
		"a Python without the kernel operations is unproved",
		"the probe child closes the ends it does not use, starts the grandchild, reports it, and ends",
		"the grandchild closes the report end and waits on the hold end until it ends",
		"a probe child that cannot start the grandchild ends with a failure")
}

// The command runner with real fixed children and the deterministic backend
// in place of the drain's kernel operations: the flag gates every spawn, the
// drain runs on every path, and an unproved drain fails the command and every
// later one.
func TestRemoteAlphaOperatorHealthcheckTLSStatusNoninteractiveDescendantRunCommand(t *testing.T) {
	probe := remoteCollectorDescendantLoader + remoteCollectorDescendantModel + `
spawns=[]
RealPopen=m.subprocess.Popen
def counting_popen(*args,**kwargs):
    spawns.append(args[0]);return RealPopen(*args,**kwargs)
m.subprocess.Popen=counting_popen
current={"kernel":Kernel()}
m.DescendantBackend=lambda:current["kernel"]
ok=(sys.executable,"-c","print('ok')")

result=m.run_command(ok)
record("no fixed command starts before the probe",
       result.runtime_failed and result.returncode==125 and spawns==[] and current["kernel"].events==[],(result,spawns))

assert probe(Kernel()) is None and m.DESCENDANT_CAPABILITY_READY is True
current["kernel"]=Kernel()
result=m.run_command(ok)
record("a proved drain keeps the command's result",
       result.returncode==0 and result.stdout==b"ok\n" and not result.runtime_failed and len(spawns)==1
       and names(current["kernel"])==["waitid"],(result,current["kernel"].events))

current["kernel"]=Kernel()
m.subprocess.Popen=lambda *args,**kwargs:(_ for _ in ()).throw(FileNotFoundError(errno.ENOENT,"missing"))
result=m.run_command(ok)
record("a spawn that fails is drained and keeps its result",
       result.returncode==127 and not result.runtime_failed and names(current["kernel"])==["waitid"],(result,current["kernel"].events))

current["kernel"]=Kernel(children=[90],refusing=[90])
result=m.run_command(ok)
record("a spawn that fails with an unproved drain is a runtime failure",
       result.returncode==125 and result.runtime_failed and m.DESCENDANT_CAPABILITY_READY is False,result)

assert probe(Kernel()) is None and m.DESCENDANT_CAPABILITY_READY is True
current["kernel"]=Kernel()
m.subprocess.Popen=lambda *args,**kwargs:(_ for _ in ()).throw(ValueError("unexpected"))
try:m.run_command(ok);raised=None
except ValueError as exc:raised=str(exc)
record("an unexpected error of the spawn is drained before it goes on",
       raised=="unexpected" and names(current["kernel"])==["waitid"],(raised,current["kernel"].events))

m.subprocess.Popen=counting_popen
spawns.clear()
current["kernel"]=Kernel(children=[91],refusing=[91])
result=m.run_command(ok)
refused=m.run_command(ok)
record("an unproved drain fails a successful command, clears the flag, and refuses every later command before its spawn",
       result.runtime_failed and result.returncode==125 and result.stdout==b"" and m.DESCENDANT_CAPABILITY_READY is False
       and refused.runtime_failed and len(spawns)==1,(result,refused,spawns))

current["kernel"]=Kernel()
result=m.run_command(ok,b"x"*(m.MAX_COMMAND_STDIN_BYTES+1))
record("an input over the bound is refused before the flag and the spawn",
       result.overflow and len(spawns)==1 and current["kernel"].events==[],(result,spawns))
m.subprocess.Popen=RealPopen

assert probe(Kernel()) is None and m.DESCENDANT_CAPABILITY_READY is True
current["kernel"]=Kernel();limit=m.FIXED_CHILD_PROCESS_LIMIT;m.FIXED_CHILD_PROCESS_LIMIT="no limit"
try:result=m.run_command(ok)
finally:m.FIXED_CHILD_PROCESS_LIMIT=limit
record("a fixed child whose setup before its exec fails does not run, and the command is a drained runtime failure",
       result.returncode==125 and result.runtime_failed and result.stdout==b"" and names(current["kernel"])==["waitid"]
       and m.DESCENDANT_CAPABILITY_READY is True,(result,current["kernel"].events))

# The parent-death request comes from the backend, and the runner resolves it
# before the spawn. A C library without prctl, as on macOS, then matters only
# to the real backend, where it is a runtime failure without a spawn.
m.subprocess.Popen=counting_popen
spawns.clear();unresolved=[]
for fault in (AttributeError("dlsym(RTLD_DEFAULT, prctl): symbol not found"),OSError(errno.ENOSYS,"no prctl")):
    current["kernel"]=Kernel(parent_death_request=fault)
    result=m.run_command(ok)
    unresolved.append((result,names(current["kernel"]),m.DESCENDANT_CAPABILITY_READY))
record("a parent-death request that cannot be resolved starts no fixed child, and the command is a drained runtime failure",
       spawns==[] and all(result.returncode==125 and result.runtime_failed and seen==["waitid"] and ready is True
                          for result,seen,ready in unresolved),(unresolved,spawns))
class LibcWithoutPrctl:
    def __getattr__(self,name):
        raise AttributeError("dlsym(RTLD_DEFAULT, %s): symbol not found"%name)
RealCDLL=m.ctypes.CDLL;m.ctypes.CDLL=lambda *args,**kwargs:LibcWithoutPrctl()
try:
    current["kernel"]=Kernel();result=m.run_command(ok)
finally:
    m.ctypes.CDLL=RealCDLL
record("the runner takes the parent-death request only from the backend, so a C library without prctl does not stop it",
       result.returncode==0 and result.stdout==b"ok\n" and not result.runtime_failed and len(spawns)==1
       and names(current["kernel"])==["waitid"],(result,spawns,current["kernel"].events))
m.subprocess.Popen=RealPopen

import contextlib,io
collected=[]
def collect_status():
    collected.append(m.DESCENDANT_CAPABILITY_READY);return m.safe_failure_payload("","collected")
m.collect_status=collect_status
args=["--protocol",m.PROTOCOL_VERSION,"--collector-sha256","a"*64]
def run_main(kernel):
    current["kernel"]=kernel;collected.clear();out=io.StringIO()
    with contextlib.redirect_stdout(out):code=m.main(args)
    return code,json.loads(out.getvalue())
code,document=run_main(Kernel())
record("the entry point runs the probe before it reads any status",
       collected==[True] and document["result"]["failure_class"]=="collected",(collected,document["result"]))
code,document=run_main(Kernel(children=[95]))
record("a failed probe emits the unavailable document and reads no status",
       collected==[] and code==1 and document["result"]["failure_class"]=="remote_status_unavailable"
       and document["collector_sha256"]=="a"*64,(collected,document["result"]))
print(json.dumps({"cases":cases,"detail":detail}))
`
	result := runRemoteCollectorDescendantProbe(t, probe)
	assertRemoteCollectorDescendantCases(t, result,
		"no fixed command starts before the probe",
		"a proved drain keeps the command's result",
		"a spawn that fails is drained and keeps its result",
		"a spawn that fails with an unproved drain is a runtime failure",
		"an unexpected error of the spawn is drained before it goes on",
		"an unproved drain fails a successful command, clears the flag, and refuses every later command before its spawn",
		"an input over the bound is refused before the flag and the spawn",
		"a fixed child whose setup before its exec fails does not run, and the command is a drained runtime failure",
		"a parent-death request that cannot be resolved starts no fixed child, and the command is a drained runtime failure",
		"the runner takes the parent-death request only from the backend, so a C library without prctl does not stop it",
		"the entry point runs the probe before it reads any status",
		"a failed probe emits the unavailable document and reads no status")
}

// The real tests need a host that lets a process become a child subreaper and
// list its children. The prelude decides that by an attempt in a child of its
// own, never by an OS label or a user ID. Only the explicit answer that this
// host cannot do it skips; any other shape of answer is a failure.
func requireRemoteCollectorDescendantKernel(t *testing.T, result map[string]any) {
	t.Helper()
	switch result["capability"] {
	case true:
	case false:
		reason, ok := result["reason"].(string)
		if !ok || reason == "" {
			t.Fatalf("child subreaper probe refused without a reason: %v", result)
		}
		t.Skipf("skipping real descendant containment test: %s", reason)
	default:
		t.Fatalf("child subreaper probe did not state its capability: %v", result)
	}
}

const remoteCollectorDescendantRealPrelude = remoteCollectorDescendantLoader + `
import ctypes
def unavailable():
    if getattr(os,"waitid",None) is None or getattr(os,"P_ALL",None) is None or getattr(os,"WNOWAIT",None) is None:
        return "this Python has no os.waitid"
    try:prctl=ctypes.CDLL(None,use_errno=True).prctl
    except AttributeError:return "this C library has no prctl"
    report_r,report_w=os.pipe()
    pid=os.fork()
    if pid==0:
        answer=b"ok"
        try:
            if prctl(ctypes.c_int(36),ctypes.c_ulong(1),ctypes.c_ulong(0),ctypes.c_ulong(0),ctypes.c_ulong(0))!=0:
                answer=b"prctl(PR_SET_CHILD_SUBREAPER) refused: "+errno.errorcode.get(ctypes.get_errno(),"?").encode()
            else:
                try:
                    with open("/proc/self/task/%d/children"%os.getpid(),"rb") as handle:handle.read()
                except OSError as exc:
                    answer=b"cannot read /proc/self/task/<tid>/children: "+errno.errorcode.get(exc.errno,"?").encode()
            os.write(report_w,answer)
        finally:
            os._exit(0)
    os.close(report_w)
    answer=os.read(report_r,4096).decode();os.close(report_r)
    os.waitpid(pid,0)
    return None if answer=="ok" else answer
reason=unavailable()
if reason is not None:
    print(json.dumps({"capability":False,"reason":reason}));sys.exit(0)
fifo=os.path.join(sys.argv[2],"alive")
os.mkfifo(fifo)
def watch():
    # Every process of a stand-in holds this FIFO open for writing. A read
    # gives end of input only when no such process is left.
    return os.open(fifo,os.O_RDONLY|os.O_NONBLOCK)
def gone(fd,seconds=1.0):
    # End of input counts only after the stand-in's byte, so that a stand-in
    # that never opened the FIFO cannot pass.
    deadline=time.monotonic()+seconds;seen=0
    while True:
        try:
            chunk=os.read(fd,64)
            if chunk==b"":return seen>0
            seen+=len(chunk);continue
        except BlockingIOError:
            pass
        if time.monotonic()>deadline:return False
        time.sleep(0.01)
def no_child():
    try:os.waitid(os.P_ALL,0,os.WEXITED|os.WNOHANG|os.WNOWAIT)
    except ChildProcessError:return True
    return False
def standin(body):
    return (sys.executable,"-c","import os,signal,sys,time\nw=os.open(%r,os.O_WRONLY);os.write(w,b'x')\n"%fifo+body)
`

// Each stand-in for a fixed command starts descendants that ignore TERM and
// hold the FIFO. The collector's real drain must leave none of them, whatever
// their process group or session, and the collector must have no child left.
// The process limit of the fixed child would refuse these descendants to an
// unprivileged fixed child, so the cases switch it off, as it is for a
// collector that runs as root and for the root command of the fixed sudo
// path: there the drain is the only containment.
func TestRemoteAlphaOperatorHealthcheckTLSStatusNoninteractiveDescendantRealKernel(t *testing.T) {
	probe := remoteCollectorDescendantRealPrelude + `
m.FIXED_CHILD_PROCESS_LIMIT=None
m.validate_descendant_capability()
record("the probe makes the collector a child subreaper and proves the drain",
       m.DESCENDANT_CAPABILITY_READY is True and no_child(),m.DESCENDANT_CAPABILITY_READY)
# The same probe once more, through the real kernel operations with a record
# of the collector's own calls: the drain must kill the grandchild while the
# hold pipe still holds it, so the grandchild ends by that KILL and not by
# itself.
backend=m.DescendantBackend();seen=[];ends=[];reported=[]
real={name:getattr(backend,name) for name in ("pipe","close","kill","read","waitpid")}
def role(fd):
    for name,(read_end,write_end) in zip(("report","hold"),ends):
        if fd==read_end:return name+"_read"
        if fd==write_end:return name+"_write"
    return "other"
def recording_pipe():
    pair=real["pipe"]();ends.append(pair);return pair
def recording_close(fd):
    seen.append(("close",role(fd)));real["close"](fd)
def recording_kill(pid,signum):
    seen.append(("kill",pid,signum));real["kill"](pid,signum)
def recording_read(fd,size):
    data=real["read"](fd,size)
    if role(fd)=="report_read" and data.isdigit():reported.append(int(data))
    return data
def recording_waitpid(pid,options):
    waited,status=real["waitpid"](pid,options)
    if waited==pid:seen.append(("reaped",pid,status))
    return waited,status
backend.pipe,backend.close,backend.kill=recording_pipe,recording_close,recording_kill
backend.read,backend.waitpid=recording_read,recording_waitpid
m.validate_descendant_capability(backend)
grandchild=reported[0] if len(reported)==1 else -1
statuses=[event[2] for event in seen if event[0]=="reaped" and event[1]==grandchild]
killed=("kill",grandchild,signal.SIGKILL) in seen and ("close","hold_write") in seen
record("the real probe kills the grandchild while the hold pipe is still open, and the grandchild ends by that KILL",
       m.DESCENDANT_CAPABILITY_READY is True and no_child() and grandchild>0 and killed
       and seen.index(("kill",grandchild,signal.SIGKILL))<seen.index(("close","hold_write"))
       and len(statuses)==1 and os.WIFSIGNALED(statuses[0]) and os.WTERMSIG(statuses[0])==signal.SIGKILL,
       (grandchild,seen))
stay="""
signal.signal(signal.SIGTERM,signal.SIG_IGN)
if os.fork()==0:
    %s
    os.close(1);os.close(2);time.sleep(60);os._exit(0)
print('ok')
"""
for label,leave in (("in the group","pass"),("leaving the group","os.setsid()")):
    fd=watch()
    result=m.run_command(standin(stay%leave))
    record("a descendant %s that outlives a normal completion is ended"%label,
           result.returncode==0 and result.stdout==b"ok\n" and not result.runtime_failed and gone(fd) and no_child(),
           result)
    os.close(fd)
relay="""
signal.signal(signal.SIGTERM,signal.SIG_IGN)
for generation in range(40):
    if os.fork()!=0:os._exit(0)
    %s
    time.sleep(0.005)
time.sleep(60)
"""
for label,leave in (("in the group","pass"),("leaving the group","os.setsid()")):
    fd=watch()
    result=m.run_command(standin("os.close(1);os.close(2)\n"+relay%leave))
    record("a fork relay %s is ended"%label,
           result.returncode==0 and not result.runtime_failed and gone(fd) and no_child(),result)
    os.close(fd)
old_timeout,old_grace=m.COMMAND_TIMEOUT_SECONDS,m.COMMAND_TERMINATION_GRACE_SECONDS
m.COMMAND_TIMEOUT_SECONDS,m.COMMAND_TERMINATION_GRACE_SECONDS=0.5,0.2
try:
    fd=watch()
    result=m.run_command(standin("""
signal.signal(signal.SIGTERM,signal.SIG_IGN)
if os.fork()==0:
    os.setsid();time.sleep(60);os._exit(0)
os._exit(0)
"""))
    record("a descendant that holds the output after the fixed child ended is ended at the timeout",
           result.timed_out and gone(fd) and no_child(),result)
    os.close(fd)
    fd=watch()
    result=m.run_command(standin("""
signal.signal(signal.SIGTERM,signal.SIG_IGN)
if os.fork()==0:
    os.setsid();os.close(1);os.close(2);time.sleep(60);os._exit(0)
time.sleep(60)
"""))
    record("a descendant that leaves the group of a fixed child that ignores TERM is ended at the timeout",
           result.timed_out and gone(fd) and no_child(),result)
    os.close(fd)
    handles=[]
    RealPopen=m.subprocess.Popen
    def keeping_popen(*args,**kwargs):
        handles.append(RealPopen(*args,**kwargs));return handles[-1]
    RealReap,RealWait=m.reap_child,m.wait_for_child_exit
    m.subprocess.Popen=keeping_popen
    # The fixed child gets the group KILL, but the lifecycle neither sees it
    # end nor reaps it, as when it is still not terminal after the grace
    # period.
    m.wait_for_child_exit=lambda proc,grace:False
    m.reap_child=lambda proc:m.ChildLifecycleResult(resolved=False,returncode=None)
    fd=watch()
    try:result=m.run_command(standin("signal.signal(signal.SIGTERM,signal.SIG_IGN)\ntime.sleep(60)\n"))
    finally:m.subprocess.Popen,m.reap_child,m.wait_for_child_exit=RealPopen,RealReap,RealWait
    record("a fixed child that the lifecycle leaves unreaped is reaped through its own handle by the drain",
           result.runtime_failed and len(handles)==1 and handles[0].returncode==-signal.SIGKILL
           and gone(fd) and no_child() and m.DESCENDANT_CAPABILITY_READY is True,
           (result,[handle.returncode for handle in handles]))
    os.close(fd)
finally:
    m.COMMAND_TIMEOUT_SECONDS,m.COMMAND_TERMINATION_GRACE_SECONDS=old_timeout,old_grace
record("every command leaves the flag set and no child",
       m.DESCENDANT_CAPABILITY_READY is True and no_child(),m.DESCENDANT_CAPABILITY_READY)
print(json.dumps({"capability":True,"cases":cases,"detail":detail}))
`
	result := runRemoteCollectorDescendantProbe(t, probe, t.TempDir())
	requireRemoteCollectorDescendantKernel(t, result)
	assertRemoteCollectorDescendantCases(t, result,
		"the probe makes the collector a child subreaper and proves the drain",
		"the real probe kills the grandchild while the hold pipe is still open, and the grandchild ends by that KILL",
		"a descendant in the group that outlives a normal completion is ended",
		"a descendant leaving the group that outlives a normal completion is ended",
		"a fork relay in the group is ended",
		"a fork relay leaving the group is ended",
		"a descendant that holds the output after the fixed child ended is ended at the timeout",
		"a descendant that leaves the group of a fixed child that ignores TERM is ended at the timeout",
		"a fixed child that the lifecycle leaves unreaped is reaped through its own handle by the drain",
		"every command leaves the flag set and no child")
}

// The probe refuses to start while the collector has a child that it did not
// start, and it never signals that child.
func TestRemoteAlphaOperatorHealthcheckTLSStatusNoninteractiveDescendantRealProbeRefusesAChild(t *testing.T) {
	probe := remoteCollectorDescendantRealPrelude + `
fd=watch()
hold_r,hold_w=os.pipe();ready_r,ready_w=os.pipe()
pid=os.fork()
if pid==0:
    os.close(hold_w);os.close(ready_r)
    os.write(os.open(fifo,os.O_WRONLY),b"x");os.write(ready_w,b"r");os.read(hold_r,1);os._exit(0)
os.close(hold_r);os.close(ready_w)
assert os.read(ready_r,1)==b"r";os.close(ready_r)
try:m.validate_descendant_capability();failure=None
except m.DescendantCapabilityUnavailable as exc:failure=str(exc)
alive=os.waitid(os.P_PID,pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) is None
record("a probe with a child present refuses and leaves the child alone",
       failure=="child_present" and m.DESCENDANT_CAPABILITY_READY is False and alive and not gone(fd,0.2),(failure,alive))
result=m.run_command((sys.executable,"-c","print('ok')"))
record("no fixed command starts after a refused probe",result.runtime_failed and result.returncode==125,result)
os.close(hold_w);os.waitpid(pid,0);os.close(fd)
print(json.dumps({"capability":True,"cases":cases,"detail":detail}))
`
	result := runRemoteCollectorDescendantProbe(t, probe, t.TempDir())
	requireRemoteCollectorDescendantKernel(t, result)
	assertRemoteCollectorDescendantCases(t, result,
		"a probe with a child present refuses and leaves the child alone",
		"no fixed command starts after a refused probe")
}

// The stand-in replaces the flag and the drain together, and no other string
// expression of this package replaces either of them or the probe. The guard
// reads the text of the scripts with the same reader as the guard of the
// root collector's fixtures, and it knows the same ways of replacing.
func TestRemoteAlphaOperatorHealthcheckTLSStatusNoninteractiveDescendantStandInIsWhole(t *testing.T) {
	names := []string{"DESCENDANT_CAPABILITY_READY", "drain_descendants", "validate_descendant_capability"}
	for _, name := range names {
		for _, spelling := range []string{"m.%s = x", "setattr(m, \"%s\", x)", "mock.patch.object(m, '%s', x)", "ns[\"%s\"] = x"} {
			text := strings.ReplaceAll(spelling, "%s", name)
			if !remoteAlphaESStatusReplaces(text, "", name) {
				t.Fatalf("the guard does not see %q replace %s", text, name)
			}
		}
		for _, spelling := range []string{"m.%s == x", "m.%s(None)", "if not m.%s:"} {
			text := strings.ReplaceAll(spelling, "%s", name)
			if remoteAlphaESStatusReplaces(text, "", name) {
				t.Fatalf("the guard takes %q for a replacement of %s", text, name)
			}
		}
	}
	if !remoteAlphaESStatusReplaces(remoteCollectorDescendantStandIn, "", "DESCENDANT_CAPABILITY_READY") ||
		!remoteAlphaESStatusReplaces(remoteCollectorDescendantStandIn, "", "drain_descendants") ||
		remoteAlphaESStatusReplaces(remoteCollectorDescendantStandIn, "", "validate_descendant_capability") {
		t.Fatalf("the stand-in must replace the flag and the drain together and leave the probe")
	}
	// The command runner resolves the fixed child's parent-death request from
	// a new descendant backend before each spawn. The stand-in's backend keeps
	// every real operation but that request, which needs Linux's prctl.
	if !remoteAlphaESStatusReplaces(remoteCollectorDescendantStandIn, "", "DescendantBackend") ||
		!strings.Contains(remoteCollectorDescendantStandIn, "(m.DescendantBackend):\n    def __init__(self):\n        super().__init__()\n        self.parent_death_request = lambda: (lambda: 0)\n") ||
		strings.Count(remoteCollectorDescendantStandIn, "self.") != 1 {
		t.Fatalf("the stand-in must give the runner a real descendant backend whose only change is a parent-death request that does nothing")
	}
	scripts, unresolved := remoteAlphaESStatusFixtureScripts(t)
	standIns := 0
	for _, script := range append(scripts, unresolved...) {
		if script.text == remoteCollectorDescendantStandIn {
			standIns++
			continue
		}
		for _, name := range names {
			if remoteAlphaESStatusReplaces(script.text, "", name) {
				t.Errorf("%s replaces %s outside the shared stand-in", script, name)
			}
		}
	}
	if standIns != 1 {
		t.Fatalf("found the shared stand-in %d times, want once", standIns)
	}
}

// The design document, the plan, and the capability probing overview state
// the same rule, and the collector's source holds the steps that it names.
func TestRemoteAlphaOperatorHealthcheckTLSStatusNoninteractiveDescendantDocumentsContract(t *testing.T) {
	design := mustRead(t, ".docs/remote_alpha_operator_healthcheck_noninteractive_status.md")
	bounds := compactDocSection(t, design, "The remote collector enforces these hard local bounds", "## 9. Remote Privilege Posture")
	assertContainsAll(t, "P0v descendant containment", bounds,
		"- descendant drain bound: `2` seconds",
		"- ended descendants reaped between two kill rounds of the drain: at most `64`",
		"- children list read per collector thread: at most `65536` bytes",
		"`Bounded slice rule` descendant containment",
		"leaves the group with `setsid` or `setpgid`",
		"`prctl(PR_SET_CHILD_SUBREAPER)`",
		"it must have no child of its own when it starts",
		"`/proc/self/task/<tid>/children`",
		"emit the existing `remote_status_unavailable` document before any status input is read and before any fixed command",
		"never by an OS label, a kernel version, or the caller's user ID",
		"No fixed command runs without a successful probe.",
		"the fixed child only through its own process handle",
		"repeats until `waitid` reports that the collector has no child left",
		"The list only selects the processes to kill and never proves an absence.",
		"so its process ID cannot be reused under the signal",
		"the command is a runtime failure, whatever it returned",
		"A drain never turns a failure into a success",
		"no command falls back to the process-group signals alone",
		"An unproved drain also clears the capability flag, so every later fixed command of the invocation is refused before its spawn",
		"an unprivileged collector cannot end a root descendant of the fixed `sudo -n` path",
		"The bound turns each of them into a reported failure",
		"no command returns success while a descendant still lives",
		"A process that a host service starts on a descendant's behalf is no descendant.",
		"- process limit of the fixed child: `RLIMIT_NPROC` set to `(0, 0)`",
		"`prctl(PR_SET_PDEATHSIG)`", "proves that the collector is still its parent after that request",
		"refuses an unprivileged fixed child every new process and every new thread",
		"and a collector that is killed takes it along unless the program itself undoes that request",
		"The fixed child's program can undo its own parent-death request; a changed binary that does so outlives a killed collector, as one process that the process limit still keeps from starting any other.",
		"root is not bound by the process limit", "clears the parent-death request",
		"every fixed command when the SSH target is root")
	assertContainsNone(t, "P0v descendant containment", bounds, "best effort", "waitpid` reports",
		"each round only shrinks what is left", "a relay that stays ahead", "takes it along.")
	privilege := compactDocSection(t, design, "## 9. Remote Privilege Posture", "## 10. Final Route Schema")
	assertContainsAll(t, "P0v privilege posture", privilege,
		"detects a root descendant that outlives the command and reports the check unavailable, but cannot end it",
		"neither the process limit nor the parent-death request binds it",
		"No root-side runner, such as `unshare` started through `sudo`, is used")
	validation := compactDocSection(t, design, "## 14. Validation And Later Gates", "")
	assertContainsAll(t, "P0v validation", validation,
		"descendant containment tests: a deterministic backend in place of the kernel operations on every host",
		"skip with an explicit reason only when the attempt is refused")

	routeRules := compactDocSection(t, mustRead(t, standingRouteRulesPath),
		"`Bounded slice rule` P0v descendant containment refinement:", "P0v's implemented status schema is")
	assertContainsAll(t, "route rules P0v descendant containment", routeRules,
		"makes itself a child subreaper before any status input is read",
		"`waitid` reports no child", "two-second descendant drain bound",
		"refuses every later fixed command of the invocation before its spawn",
		"detects but cannot end a root descendant of the fixed `sudo -n` path",
		"sets its own `RLIMIT_NPROC` to `(0, 0)`", "root is not bound by that limit",
		"dies with a killed collector unless its program undoes that request itself",
		"a changed binary can undo its own parent-death request and then outlives a killed collector, as one process that the process limit still keeps from starting any other",
		"no root-side runner is added",
		"The route schema, failure vocabulary, internal protocol, sudo allowlist, and privilege posture do not change.")
	assertContainsNone(t, "route rules P0v descendant containment", routeRules, "dies with a killed collector.")

	probing := compactDocSection(t, mustRead(t, ".docs/system_overview/capability_probing.md"),
		"The noninteractive remote TLS status collector proves its descendant", "")
	assertContainsAll(t, "capability probing descendant containment", probing,
		"replace the flag and the descendant drain together, by one shared stand-in that proves only that the test process has no child left",
		"a guard test refuses a script that replaces one of the two without the other",
		"The command runner takes the fixed child's parent-death request from the descendant backend and resolves it before each spawn",
		"gives the runner a backend whose only change is a parent-death request that does nothing, and these tests run on every host, macOS included",
		"A request that cannot be resolved makes the command a runtime failure without a spawn.",
		"skips itself, with an explicit reason, only when the attempt to make the test process a child subreaper and to list its children is refused",
		"also skips itself when an attempt shows that the limit does not bind the user that runs the tests")

	source := mustRead(t, p0vRemoteCollectorPath())
	for _, line := range []string{
		"DESCENDANT_DRAIN_SECONDS = 2.0",
		"DESCENDANT_REAPS_PER_ROUND = 64",
		"MAX_CHILDREN_LIST_BYTES = 65536",
		"PR_SET_CHILD_SUBREAPER = 36",
		"PR_SET_PDEATHSIG = 1",
		"FIXED_CHILD_PROCESS_LIMIT: int | None = 0",
		"DESCENDANT_CAPABILITY_READY = False",
	} {
		if strings.Count(source, "\n"+line+"\n") != 1 {
			t.Fatalf("collector source must declare %q exactly once", line)
		}
	}
	run := docSection(t, source, "\ndef run_command(", "\ndef supervise_fixed_child(")
	assertContainsAll(t, "collector command runner", run,
		"    if not DESCENDANT_CAPABILITY_READY:\n        return CommandResult(returncode=125, stdout=b\"\", stderr=b\"\", runtime_failed=True)\n",
		"    try:\n        result = supervise_fixed_child(args, input_bytes, spawned)\n    finally:\n",
		"            proved = drain_descendants(spawned[0] if spawned else None)\n",
		"        if not proved:\n            DESCENDANT_CAPABILITY_READY = False\n")
	request := docSection(t, source, "\ndef _parent_death_request(", "\ndef _read_children_file(")
	assertContainsAll(t, "collector parent-death request", request,
		"    prctl = ctypes.CDLL(None, use_errno=True).prctl\n",
		"        return prctl(ctypes.c_int(PR_SET_PDEATHSIG), ctypes.c_ulong(signal.SIGKILL), ctypes.c_ulong(0),\n")
	backend := docSection(t, source, "\nclass DescendantBackend:", "\nDESCENDANT_CAPABILITY_READY = False\n")
	assertContainsAll(t, "collector descendant backend", backend,
		"        self.parent_death_request = _parent_death_request\n")
	if got := strings.Count(source, "_parent_death_request"); got != 2 {
		t.Fatalf("collector names _parent_death_request %d times, want its definition and the backend", got)
	}
	setup := docSection(t, source, "\ndef fixed_child_setup(", "\ndef supervise_fixed_child(")
	assertContainsAll(t, "collector fixed child setup", setup,
		"    request_parent_death = DescendantBackend().parent_death_request()\n    limit = FIXED_CHILD_PROCESS_LIMIT\n",
		"        if request_parent_death() != 0:\n            raise OSError(ctypes.get_errno(), \"prctl\")\n",
		"        if os.getppid() != parent:\n            raise OSError(errno.ESRCH, \"collector ended\")\n",
		"        if limit is not None:\n            resource.setrlimit(resource.RLIMIT_NPROC, (limit, limit))\n")
	assertContainsNone(t, "collector fixed child setup", setup, "CDLL", "prctl(")
	// The parent-death request comes first, then the proof that the collector
	// is still the parent, and the limit last.
	if strings.Index(setup, "request_parent_death()") > strings.Index(setup, "os.getppid()") ||
		strings.Index(setup, "os.getppid()") > strings.Index(setup, "RLIMIT_NPROC") {
		t.Fatalf("the fixed child setup is not in the order: parent-death request, parent proof, process limit")
	}
	supervise := docSection(t, source, "\ndef supervise_fixed_child(", "\ndef direct_file_sha256(")
	assertContainsAll(t, "collector fixed child spawn", supervise,
		"    try:\n        setup = fixed_child_setup(os.getpid())\n    except Exception:\n",
		"        return CommandResult(returncode=125, stdout=b\"\", stderr=b\"\", runtime_failed=True)\n    try:\n        proc = subprocess.Popen(\n",
		"            start_new_session=True,\n            preexec_fn=setup,\n",
		"    except subprocess.SubprocessError:\n")
	if strings.Index(supervise, "setup = fixed_child_setup(") > strings.Index(supervise, "subprocess.Popen(") {
		t.Fatalf("the fixed child setup must be prepared before the spawn")
	}
	if got := strings.Count(source, "preexec_fn="); got != 1 {
		t.Fatalf("collector passes preexec_fn %d times, want once", got)
	}
	main := docSection(t, source, "\ndef main(", "\nif __name__ == \"__main__\":")
	assertContainsAll(t, "collector entry point", main,
		"    try:\n        validate_descendant_capability()\n        payload = collect_status()\n")
	drain := docSection(t, source, "\ndef drain_descendants(", "\ndef _descendant_probe_member(")
	assertContainsAll(t, "collector drain", drain,
		"backend.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG | os.WNOWAIT)",
		"            except ChildProcessError:\n                return True\n")
	if strings.Count(drain, "return True") != 1 {
		t.Fatalf("the drain must prove only through the wait that reports no child")
	}
	assertContainsNone(t, "collector drain", drain, "killpg", "waitpid(-1")
	if got := strings.Count(source, "spawned.append(proc)"); got != 1 {
		t.Fatalf("collector records the fixed child for the drain %d times, want once", got)
	}
}

// Red-team finding RT12-3 (report 12-redteam.md of the workstream). The drain
// kills the collector's own children once per round, reaps at most 64 ended
// children per round, pauses for up to 50 milliseconds between two rounds,
// and reads at most 65536 bytes of a children list. Descendants that only
// wait can use each of these numbers, without a relay and without a race. A
// chain in which every process is the parent of the next gives the collector
// one child per round: the kill of one link hands it the next one, and the
// pauses alone let the drain's two seconds hold no more than about 46
// rounds, however fast the host, so of a chain of 80 the far end is still
// alive when the drain gives up. A herd whose list is longer than one read is
// not killed at all, because the round that cannot read the list kills
// nothing; the case sets the read bound to 256 bytes so that 120 processes
// are enough.
//
// An unprivileged fixed child cannot start either, because its process limit
// refuses it every new process (RealProcessLimit). These cases switch the
// limit off, as it is for a collector that runs as root and for the root
// command of the fixed sudo path. There the drain is the only containment,
// and what it cannot end within its bound must be a reported failure: the
// command is a runtime failure without output, the capability flag is
// cleared, and the next command is refused before its spawn. The processes of
// each stand-in end by themselves when the release file appears; the probe
// then drains what is left and proves the capability again.
func TestRemoteAlphaOperatorHealthcheckTLSStatusNoninteractiveDescendantRealCrowd(t *testing.T) {
	probe := remoteCollectorDescendantRealPrelude + `
m.FIXED_CHILD_PROCESS_LIMIT=None
m.validate_descendant_capability()
release=os.path.join(sys.argv[2],"release")
def clean():
    # Let what a case left end by itself, end the rest, and prove the capability again.
    open(release,"wb").close()
    deadline=time.monotonic()+60
    while not m.drain_descendants() and time.monotonic()<deadline:pass
    os.unlink(release)
    m.validate_descendant_capability()
wait="""
def wait():
    end=time.monotonic()+60
    while time.monotonic()<end and not os.path.exists(%r):time.sleep(0.02)
    os._exit(0)
signal.signal(signal.SIGTERM,signal.SIG_IGN)
ready_r,ready_w=os.pipe()
"""%release
chain=wait+"""
if os.fork()==0:
    os.close(0);os.close(1);os.close(2);os.close(ready_r);os.setsid()
    level=1
    while level<80:
        if os.fork()!=0:break
        level+=1
    if level==80:os.write(ready_w,b"r")
    os.close(ready_w);wait()
os.close(ready_w);os.read(ready_r,1);print('ok')
"""
herd=wait+"""
if os.fork()==0:
    os.close(0);os.close(1);os.close(2);os.close(ready_r);os.setsid()
    for index in range(120):
        if os.fork()==0:os.close(ready_w);wait()
    os.write(ready_w,b"r");os._exit(0)
os.close(ready_w);os.read(ready_r,1);print('ok')
"""
ok=(sys.executable,"-c","print('ok')")
def closed(fd,seconds):
    # The stand-in's byte was read before; end of input means that no process of it is left.
    deadline=time.monotonic()+seconds
    while True:
        try:
            if os.read(fd,64)==b"":return True
        except BlockingIOError:pass
        if time.monotonic()>deadline:return False
        time.sleep(0.01)
def crowd(body,label):
    fd=watch()
    result=m.run_command(standin(body))
    flag=m.DESCENDANT_CAPABILITY_READY
    left=not gone(fd,0.2)
    refused=m.run_command(ok)
    record(label+" is a runtime failure without output that clears the flag and refuses the next command",
           result.runtime_failed and result.returncode==125 and result.stdout==b"" and not result.timed_out
           and flag is False and left and refused.runtime_failed and refused.returncode==125,(result,flag,left,refused))
    clean()
    record(label+" ends when released, and the capability is proved again",
           closed(fd,5.0) and no_child() and m.DESCENDANT_CAPABILITY_READY is True,m.DESCENDANT_CAPABILITY_READY)
    os.close(fd)
crowd(chain,"a chain of eighty waiting processes, each the parent of the next, that outlasts the drain")
old_bound=m.MAX_CHILDREN_LIST_BYTES
m.MAX_CHILDREN_LIST_BYTES=256
try:crowd(herd,"a herd of waiting processes whose list is longer than one read")
finally:m.MAX_CHILDREN_LIST_BYTES=old_bound
print(json.dumps({"capability":True,"cases":cases,"detail":detail}))
`
	result := runRemoteCollectorDescendantProbe(t, probe, t.TempDir())
	requireRemoteCollectorDescendantKernel(t, result)
	assertRemoteCollectorDescendantCases(t, result,
		"a chain of eighty waiting processes, each the parent of the next, that outlasts the drain is a runtime failure without output that clears the flag and refuses the next command",
		"a chain of eighty waiting processes, each the parent of the next, that outlasts the drain ends when released, and the capability is proved again",
		"a herd of waiting processes whose list is longer than one read is a runtime failure without output that clears the flag and refuses the next command",
		"a herd of waiting processes whose list is longer than one read ends when released, and the capability is proved again")
}

// The process limit of an unprivileged fixed child (red-team finding RT12-3).
// Between its fork and its exec the fixed child sets RLIMIT_NPROC to (0, 0),
// and the kernel then refuses it every new process and every new thread, so
// that a chain, a herd or a relay cannot start and the drain finds nothing
// but the fixed child. The limit is the fixed child's own. Root is not bound
// by it, so the probe asks the kernel, by an attempt in a child of its own,
// whether the limit binds this user, and skips itself only on the explicit
// answer that a fork still worked under it.
func TestRemoteAlphaOperatorHealthcheckTLSStatusNoninteractiveDescendantRealProcessLimit(t *testing.T) {
	probe := remoteCollectorDescendantRealPrelude + `
import resource
def unbound():
    report_r,report_w=os.pipe();pid=os.fork()
    if pid==0:
        answer=b"bound"
        try:
            os.close(report_r);resource.setrlimit(resource.RLIMIT_NPROC,(0,0))
            try:
                child=os.fork()
                if child==0:os._exit(0)
                os.waitpid(child,0);answer=b"a fork still worked under RLIMIT_NPROC (0, 0)"
            except BlockingIOError:pass
        except BaseException as exc:answer=("unexpected answer: %r"%exc).encode()
        os.write(report_w,answer);os._exit(0)
    os.close(report_w);answer=os.read(report_r,4096).decode();os.close(report_r);os.waitpid(pid,0)
    if answer=="bound":return None
    if answer.startswith("a fork still worked"):return "the kernel does not bind this user by the process limit: "+answer
    raise RuntimeError(answer)
reason=unbound()
if reason is not None:
    print(json.dumps({"capability":False,"reason":reason}));sys.exit(0)
m.validate_descendant_capability()
own=resource.getrlimit(resource.RLIMIT_NPROC)
# Should the limit fail, the chain stays bounded and ends at the release.
release=os.path.join(sys.argv[2],"release")
chain="""
signal.signal(signal.SIGTERM,signal.SIG_IGN)
try:pid=os.fork()
except OSError as exc:print(errno.errorcode[exc.errno]);sys.exit(0)
if pid==0:
    os.close(1);os.close(2)
    for level in range(80):
        if os.fork()!=0:break
    end=time.monotonic()+60
    while time.monotonic()<end and not os.path.exists(%r):time.sleep(0.02)
    os._exit(0)
print('started')
"""%release
fd=watch()
result=m.run_command(standin("import errno\n"+chain))
record("an unprivileged fixed child cannot start a process, so a chain never starts and nothing is left",
       result.returncode==0 and result.stdout==b"EAGAIN\n" and not result.runtime_failed and gone(fd) and no_child()
       and m.DESCENDANT_CAPABILITY_READY is True,result)
os.close(fd)
thread="""
import threading
try:threading.Thread(target=time.sleep,args=(60,),daemon=True).start()
except RuntimeError:print('refused');sys.exit(0)
print('started')
"""
fd=watch()
result=m.run_command(standin(thread))
record("an unprivileged fixed child cannot start a thread",
       result.returncode==0 and result.stdout==b"refused\n" and not result.runtime_failed and gone(fd) and no_child(),result)
os.close(fd)
record("the process limit is the fixed child's own, and the collector's own limit is unchanged",
       resource.getrlimit(resource.RLIMIT_NPROC)==own,(own,resource.getrlimit(resource.RLIMIT_NPROC)))
# Nothing is left after a pass; after a failure this ends what is.
open(release,"wb").close();deadline=time.monotonic()+60
while not m.drain_descendants() and time.monotonic()<deadline:pass
print(json.dumps({"capability":True,"cases":cases,"detail":detail}))
`
	result := runRemoteCollectorDescendantProbe(t, probe, t.TempDir())
	requireRemoteCollectorDescendantKernel(t, result)
	assertRemoteCollectorDescendantCases(t, result,
		"an unprivileged fixed child cannot start a process, so a chain never starts and nothing is left",
		"an unprivileged fixed child cannot start a thread",
		"the process limit is the fixed child's own, and the collector's own limit is unchanged")
}

// A collector that is killed during a fixed command takes the fixed child
// with it (observation O12-1 of the red-team): between its fork and its exec
// the fixed child asks the kernel to kill it when the collector's thread
// ends, and proves that the collector was still its parent after that
// request. The collector here is a child of the probe, with the real probe
// and a stand-in that never ends by itself and starts nothing. The stand-in
// ignores TERM before it reports, so only a KILL ends it, and the case holds
// the request to SIGKILL by behaviour. The control runs the same collector
// with a setup that does nothing, and there the fixed child outlives it. An
// exec of a set-user-ID program such as sudo clears the request, so the fixed
// sudo path stays a stated limit, and so does a changed binary that undoes
// the request itself.
func TestRemoteAlphaOperatorHealthcheckTLSStatusNoninteractiveDescendantRealCollectorDeath(t *testing.T) {
	probe := remoteCollectorDescendantRealPrelude + `
import subprocess
release=os.path.join(sys.argv[2],"release")
# Not standin(): this one ignores TERM before it writes its byte.
stay=(sys.executable,"-c",("import os,signal,sys,time\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
      "w=os.open(%r,os.O_WRONLY);os.write(w,b'x')\nend=time.monotonic()+60\n"
      "while time.monotonic()<end and not os.path.exists(%r):time.sleep(0.02)\n")%(fifo,release))
head="""import importlib.util,json,sys
spec=importlib.util.spec_from_file_location("remote_collector_death",sys.argv[1])
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
"""
tail="""m.validate_descendant_capability()
m.run_command(tuple(json.loads(sys.argv[2])))
"""
def collector_death(source,wait):
    fd=watch()
    collector=subprocess.Popen([sys.executable,"-I","-B","-c",source,sys.argv[1],json.dumps(stay)],
                               stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    deadline=time.monotonic()+30;seen=b""
    while not seen and time.monotonic()<deadline and collector.poll() is None:
        try:seen=os.read(fd,64)
        except BlockingIOError:time.sleep(0.01)
    started=seen==b"x" and collector.poll() is None
    collector.kill();_out,errors=collector.communicate()  # this probe's own unreaped child
    ended=gone_after(fd,wait)
    released=None
    if not ended:
        open(release,"wb").close();released=gone_after(fd,10.0);os.unlink(release)
    os.close(fd)
    return started,ended,released,errors[-2000:]
def gone_after(fd,seconds):
    # The stand-in has written its byte already; end of input means it is gone.
    deadline=time.monotonic()+seconds
    while True:
        try:
            if os.read(fd,64)==b"":return True
        except BlockingIOError:pass
        if time.monotonic()>deadline:return False
        time.sleep(0.01)
started,ended,released,errors=collector_death(head+tail,10.0)
record("a killed collector takes its fixed child with it",started and ended is True,(started,ended,errors))
started,ended,released,errors=collector_death(head+"m.fixed_child_setup=lambda parent:(lambda:None)\n"+tail,1.0)
record("without the setup the same fixed child outlives a killed collector",
       started and ended is False and released is True,(started,ended,released,errors))
print(json.dumps({"capability":True,"cases":cases,"detail":detail}))
`
	result := runRemoteCollectorDescendantProbe(t, probe, t.TempDir())
	requireRemoteCollectorDescendantKernel(t, result)
	assertRemoteCollectorDescendantCases(t, result,
		"a killed collector takes its fixed child with it",
		"without the setup the same fixed child outlives a killed collector")
}
