package executionsubstrate_test

import (
	"strings"
	"testing"
)

// Each fixed command of the TLS status collector runs in a PID namespace of
// its own. These tests cover that containment in two ways.
//
// The first group gives the collector a deterministic backend in place of the
// kernel operations. It runs on every host and proves the order of the steps,
// every refusal, and what is reported as unproved. It proves nothing about a
// kernel.
//
// The second group, whose names hold "Real", uses the real kernel. Creating a
// PID namespace needs root on Linux, so each of those tests first asks the
// kernel by an attempt in a child of its own, and skips itself only on the
// explicit answer that no namespace can be created here. The CI job runs them
// once more as root and requires a pass from each.
//
// The Python children import only the source-controlled collector. They never
// run its entry point, an operator route, or a real OpenSSL child, and they
// write nothing outside t.TempDir().

// The deterministic backend holds a small model of what the kernel does for
// one namespace. The anchor ends when its control pipe is closed or when it is
// killed. When the anchor ends, the member is killed. The anchor becomes
// terminal only when it has ended and the member is reaped. Options change
// one of these answers at a time. The backend records every call, and it
// records as a violation a close of a descriptor that is not open, a blocking
// wait, and a signal to anything but an unreaped child.
const remoteAlphaESChildNamespaceModel = `
import types
class Backend:
    clone_newpid=0x20000000
    anchor=4001;member=4002
    def __init__(self,probe=False,missing=(),away=False,**faults):
        self.probe=probe;self.faults=faults;self.events=[];self.violations=[]
        self.descriptors=set();self.last_fd=700;self.pipes=[];self.own=None
        self.home=not away;self.forked=[];self.reaped=[];self.kills=[];self.polls=0
        self.released=False
        for name in missing:setattr(self,name,None)
    def _new_fd(self):
        self.last_fd+=1;self.descriptors.add(self.last_fd);return self.last_fd
    def _raise(self,name):
        fault=self.faults.get(name)
        if isinstance(fault,list):fault=fault.pop(0) if fault else None
        if fault is not None:raise fault
    def role(self,fd):
        if fd==self.own:return "own"
        names=(["hold"] if self.probe else [])+["control"]
        for name,(read_end,write_end) in zip(names,self.pipes):
            if fd==read_end:return name+"_read"
            if fd==write_end:return name+"_write"
        return "unknown"
    def name(self,pid):
        return "anchor" if pid==self.anchor else "member" if pid==self.member else "unknown"
    def open(self,path,flags):
        self.events.append(("open",path,flags));self._raise("open")
        self.own=self._new_fd();return self.own
    def fstat(self,fd):
        self.events.append(("fstat",self.role(fd)));self._raise("fstat")
        return types.SimpleNamespace(st_dev=5,st_ino=100)
    def stat(self,path):
        self.events.append(("stat",path));self._raise("stat")
        return types.SimpleNamespace(st_dev=5,st_ino=100 if self.home else 101)
    def pipe(self):
        self.events.append(("pipe",));self._raise("pipe")
        ends=(self._new_fd(),self._new_fd());self.pipes.append(ends);return ends
    def unshare(self,flags):
        self.events.append(("unshare",flags));self._raise("unshare");self.home=False
    def setns(self,fd,flags):
        self.events.append(("setns",self.role(fd),flags));self._raise("setns")
        if not self.faults.get("reset_stays_away"):self.home=True
    def fork(self):
        which="member" if self.forked else "anchor"
        self.events.append(("fork",which,"home" if self.home else "away"));self._raise("fork_"+which)
        pid=self.anchor if which=="anchor" else self.member
        self.forked.append(pid);return pid
    def close(self,fd):
        role=self.role(fd);self.events.append(("close",role))
        if fd not in self.descriptors:self.violations.append(("close of a descriptor that is not open",role))
        self.descriptors.discard(fd)
        fault=self.faults.get("close_"+role)
        if fault is not None:raise fault
        if role=="control_write":self.released=True
    def _unreaped(self,pid):
        return pid in self.forked and pid not in self.reaped
    def _anchor_saw_end(self):
        return self.released and not self.faults.get("anchor_ignores_release")
    def _anchor_ended(self):
        return self._anchor_saw_end() or self.anchor in self.kills
    def _anchor_terminal(self):
        if not self._unreaped(self.anchor) or not self._anchor_ended():return False
        if self.polls<self.faults.get("anchor_after_polls",0):return False
        if self.faults.get("anchor_terminal_with_member"):return True
        return not self._unreaped(self.member)
    def _member_terminal(self):
        if not self._unreaped(self.member):return False
        if self.member in self.kills or self.faults.get("member_early"):return True
        return self._anchor_ended() and not self.faults.get("member_never")
    def terminal(self,pid):
        self.events.append(("terminal",self.name(pid)));self._raise("terminal")
        if not self._unreaped(pid):
            self.violations.append(("observed what is not an unreaped child",self.name(pid)))
            raise ChildProcessError()
        return self._anchor_terminal() if pid==self.anchor else self._member_terminal()
    def waitpid(self,pid,flags):
        which=self.name(pid);self.events.append(("waitpid",which))
        if flags!=os.WNOHANG:self.violations.append(("blocking wait",which))
        if which=="anchor":self.polls+=1
        if which=="member" and self.faults.get("member_lost_at_reap"):
            self.reaped.append(pid);raise ChildProcessError()
        self._raise("waitpid_"+which)
        if not self._unreaped(pid):raise ChildProcessError()
        if pid==self.anchor:
            if not self._anchor_terminal():return (0,0)
            status=self.faults.get("anchor_status",0 if self._anchor_saw_end() else signal.SIGKILL)
        else:
            if not self._member_terminal():return (0,0)
            status=self.faults.get("member_status",signal.SIGKILL)
        self.reaped.append(pid);return (pid,status)
    def kill(self,pid,signum):
        which=self.name(pid);self.events.append(("kill",which,signum))
        if not self._unreaped(pid) or signum!=signal.SIGKILL:
            self.violations.append(("signal to what is not an unreaped child",which,signum))
        self._raise("kill");self.kills.append(pid)
RDONLY=os.O_RDONLY|os.O_CLOEXEC;NEWPID=Backend.clone_newpid
OPEN=[("open","/proc/self/ns/pid",RDONLY),("fstat","own"),("stat","/proc/self/ns/pid_for_children"),("pipe",),
      ("unshare",NEWPID),("fork","anchor","away"),("close","control_read")]
RESET=[("setns","own",NEWPID),("fstat","own"),("stat","/proc/self/ns/pid_for_children")]
END=[("close","control_write"),("waitpid","anchor"),("close","own")]
def literal(exc):
    return exc.args[0] if isinstance(exc,module.Incomplete) and exc.args else type(exc).__name__
def opened(backend):
    namespace=module.ChildNamespace(backend);raised=None
    try:namespace.open()
    except BaseException as exc:raised=exc
    return namespace,raised
def kinds(backend,*wanted):
    return [event for event in backend.events if event[0] in wanted]
`

// The fixed order of one command: prove that children are created at home,
// make the pipe, open the namespace, fork the anchor, and close the anchor's
// pipe end; then the reset with its proof; then the end, which closes the
// control pipe, reaps the anchor, and closes the collector's own namespace
// descriptor last. Every refusal happens before the step it protects.
func TestRemoteAlphaESServiceTLSStatusChildNamespaceSequence(t *testing.T) {
	const probe = remoteAlphaESProcessIdentityLoader + remoteAlphaESChildNamespaceModel + `
backend=Backend();namespace,raised=opened(backend);at_open=list(backend.events)
namespace.restore();at_reset=list(backend.events);unproved=namespace.close()
record("one command opens, resets and ends its namespace in the fixed order",
       raised is None and at_open==OPEN and at_reset==OPEN+RESET and backend.events==OPEN+RESET+END,backend.events)
record("a proved namespace reports nothing unproved and leaves nothing behind",
       unproved is False and namespace.reaped and not namespace.killed and not backend.kills
       and not backend.descriptors and backend.home and not backend.violations,
       (unproved,backend.kills,backend.descriptors,backend.violations))
count=len(backend.events);again=namespace.close()
record("a second close does nothing",again is False and len(backend.events)==count,backend.events[count:])
try:namespace.open();second=None
except BaseException as exc:second=exc
record("one object opens one namespace only",
       literal(second)=="child_namespace_unproved" and len(backend.events)==count,(second,backend.events[count:]))

backend=Backend();namespace,raised=opened(backend);unproved=namespace.close()
record("close resets the namespace itself before it ends the anchor",
       backend.events==OPEN+RESET+END and unproved is False and backend.home,backend.events)
backend=Backend();module.ChildNamespace(backend).restore()
record("a reset without an opened namespace does nothing",backend.events==[],backend.events)

for name in ("unshare","setns","clone_newpid","fork"):
    backend=Backend(missing=(name,));namespace,raised=opened(backend)
    record("a missing "+name+" refuses before anything is touched",
           literal(raised)=="process_capability_unavailable" and backend.events==[]
           and namespace.close() is False and backend.events==[],(raised,backend.events))

backend=Backend(away=True);namespace,raised=opened(backend);unproved=namespace.close()
record("children that are not created at home refuse before the pipe, the namespace and the anchor",
       literal(raised)=="child_namespace_unproved" and backend.events==OPEN[:3]+[("close","own")]
       and not backend.forked and not backend.descriptors and unproved is False,(raised,backend.events))

CLOSED=[("close","control_read"),("close","control_write"),("close","own")]
for label,fault,expected in (
    ("an unreadable own namespace",{"open":OSError(errno.EACCES,"denied")},OPEN[:1]),
    ("an unreadable child namespace link",{"stat":OSError(errno.ENOENT,"absent")},OPEN[:3]+CLOSED[2:]),
    ("a failed control pipe",{"pipe":OSError(errno.EMFILE,"no descriptor")},OPEN[:4]+CLOSED[2:]),
    ("a refused namespace",{"unshare":PermissionError(errno.EPERM,"refused")},OPEN[:5]+CLOSED),
    ("a failed anchor fork",{"fork_anchor":OSError(errno.ENOMEM,"no process")},OPEN[:6]+RESET+CLOSED)):
    backend=Backend(**fault);namespace,raised=opened(backend);namespace.restore();unproved=namespace.close()
    record(label+" means no anchor, and everything opened is closed",
           isinstance(raised,OSError) and backend.events==expected and not backend.forked
           and not backend.descriptors and backend.home and unproved is False and not backend.violations,
           (raised,backend.events,backend.violations))

backend=Backend(close_control_read=OSError(errno.EIO,"close failed"));namespace,raised=opened(backend)
flag=namespace.unproved;namespace.restore();unproved=namespace.close()
record("a failed close of the anchor's pipe end is unproved, and the anchor is still ended and reaped",
       isinstance(raised,OSError) and flag and unproved is True and namespace.reaped and not namespace.killed
       and backend.events==OPEN+RESET+END and not backend.violations,(raised,backend.events))

backend=Backend(reset_stays_away=True);namespace,raised=opened(backend);namespace.restore()
flag=namespace.unproved;unproved=namespace.close()
record("a reset that is not proved is unproved at close, after the anchor is reaped",
       raised is None and flag and unproved is True and namespace.reaped
       and backend.events==OPEN+RESET+RESET+END,backend.events)
count=len(backend.events);later,refused=opened(backend)
record("while the reset stays unproved the next command refuses before any namespace or anchor",
       literal(refused)=="child_namespace_unproved" and backend.events[count:]==OPEN[:3]
       and backend.forked==[Backend.anchor],(refused,backend.events[count:]))

backend=Backend(setns=OSError(errno.EPERM,"refused"));namespace,raised=opened(backend);namespace.restore()
unproved=namespace.close()
record("a failed reset is unproved at close, after the anchor is reaped",
       raised is None and unproved is True and namespace.reaped and not backend.home,backend.events)
print(json.dumps({"cases":cases,"detail":detail}))
`
	result := runRemoteAlphaESProcessIdentityProbe(t, probe)
	assertRemoteAlphaESProcessIdentityCases(t, result,
		"one command opens, resets and ends its namespace in the fixed order",
		"a proved namespace reports nothing unproved and leaves nothing behind",
		"a second close does nothing",
		"one object opens one namespace only",
		"close resets the namespace itself before it ends the anchor",
		"a reset without an opened namespace does nothing",
		"a missing unshare refuses before anything is touched",
		"a missing setns refuses before anything is touched",
		"a missing clone_newpid refuses before anything is touched",
		"a missing fork refuses before anything is touched",
		"children that are not created at home refuse before the pipe, the namespace and the anchor",
		"an unreadable own namespace means no anchor, and everything opened is closed",
		"an unreadable child namespace link means no anchor, and everything opened is closed",
		"a failed control pipe means no anchor, and everything opened is closed",
		"a refused namespace means no anchor, and everything opened is closed",
		"a failed anchor fork means no anchor, and everything opened is closed",
		"a failed close of the anchor's pipe end is unproved, and the anchor is still ended and reaped",
		"a reset that is not proved is unproved at close, after the anchor is reaped",
		"while the reset stays unproved the next command refuses before any namespace or anchor",
		"a failed reset is unproved at close, after the anchor is reaped")
}

// The end of a namespace is its anchor's reap. The collector waits for the
// anchor alone without blocking, accepts status zero, and accepts a KILL only
// when it sent that KILL itself. It sends one KILL, after the grace period or
// at once when the control pipe could not be closed, and only while the
// anchor is its unreaped child. An anchor that is not terminal holds the
// caller without a time limit. A lost reap is unproved and nothing is
// signaled after it, because the process ID is no longer reserved.
func TestRemoteAlphaESServiceTLSStatusChildNamespaceAnchorWait(t *testing.T) {
	const probe = remoteAlphaESProcessIdentityLoader + remoteAlphaESChildNamespaceModel + `
def ended(grace=1000.0,**faults):
    module.CHILD_GRACE=grace
    backend=Backend(**faults);namespace,raised=opened(backend);namespace.restore()
    started=time.monotonic();unproved=namespace.close()
    return backend,namespace,unproved,time.monotonic()-started
WAIT=("waitpid","anchor");KILL=("kill","anchor",signal.SIGKILL)

backend,namespace,unproved,_=ended(anchor_status=1<<8)
record("an anchor that ends with a nonzero status is unproved",
       unproved is True and namespace.reaped and not namespace.killed and not backend.kills,backend.events)
backend,namespace,unproved,_=ended(anchor_status=signal.SIGKILL)
record("an anchor that something else killed is unproved",
       unproved is True and namespace.reaped and not namespace.killed and not backend.kills,backend.events)

backend,namespace,unproved,elapsed=ended(grace=0.2,anchor_ignores_release=True)
seen=kinds(backend,"waitpid","kill")
record("an anchor that does not end is sent one KILL, after the grace period, and is then reaped",
       unproved is False and namespace.reaped and namespace.killed and backend.kills==[Backend.anchor]
       and elapsed>=0.2 and seen[:2]==[WAIT,WAIT] and seen[-2:]==[KILL,WAIT] and not backend.violations,(elapsed,seen))
backend,namespace,unproved,_=ended(grace=0.05,anchor_ignores_release=True,anchor_status=signal.SIGTERM)
record("after the collector's KILL any other end of the anchor is unproved",
       unproved is True and namespace.reaped and namespace.killed and backend.kills==[Backend.anchor],backend.events)

backend,namespace,unproved,elapsed=ended(close_control_write=OSError(errno.EIO,"close failed"))
record("a failed close of the control pipe sends the KILL at once and is unproved",
       unproved is True and namespace.reaped and namespace.killed
       and kinds(backend,"waitpid","kill")==[WAIT,KILL,WAIT] and elapsed<30 and not backend.violations,
       (elapsed,backend.events))

backend,namespace,unproved,elapsed=ended(grace=0.05,anchor_after_polls=25)
seen=kinds(backend,"waitpid","kill")
record("an anchor that is not terminal holds the caller past the grace period, with one KILL",
       namespace.reaped and backend.polls==25 and seen.count(KILL)==1 and seen.count(WAIT)==25
       and elapsed>0.05 and unproved is False and not backend.violations,(elapsed,backend.polls,seen.count(KILL)))

backend,namespace,unproved,_=ended(waitpid_anchor=ChildProcessError())
record("a lost anchor reap is unproved and ends the wait",
       unproved is True and not namespace.reaped and kinds(backend,"waitpid","kill")==[WAIT]
       and not backend.descriptors,backend.events)
backend,namespace,unproved,_=ended(waitpid_anchor=ChildProcessError(),close_control_write=OSError(errno.EIO,"close failed"))
record("nothing is signaled after a lost anchor reap",
       unproved is True and not namespace.reaped and not namespace.killed
       and kinds(backend,"waitpid","kill")==[WAIT],backend.events)

backend,namespace,unproved,_=ended(waitpid_anchor=[OSError(errno.EIO,"wait failed")])
record("a wait that failed once is unproved, and the anchor is still reaped",
       unproved is True and namespace.reaped and not backend.kills
       and kinds(backend,"waitpid","kill")==[WAIT,WAIT],backend.events)
backend,namespace,unproved,_=ended(close_control_write=OSError(errno.EIO,"close failed"),
                                   kill=[PermissionError(errno.EPERM,"refused")])
record("a KILL that failed is sent again until it is delivered",
       unproved is True and namespace.reaped and namespace.killed and backend.kills==[Backend.anchor]
       and kinds(backend,"waitpid","kill")==[WAIT,KILL,WAIT,KILL,WAIT] and not backend.violations,backend.events)

backend,namespace,unproved,_=ended(close_own=OSError(errno.EIO,"close failed"))
record("a failed close of the collector's own namespace descriptor is unproved",
       unproved is True and namespace.reaped and backend.events[-1]==("close","own"),backend.events)
print(json.dumps({"cases":cases,"detail":detail}))
`
	result := runRemoteAlphaESProcessIdentityProbe(t, probe)
	assertRemoteAlphaESProcessIdentityCases(t, result,
		"an anchor that ends with a nonzero status is unproved",
		"an anchor that something else killed is unproved",
		"an anchor that does not end is sent one KILL, after the grace period, and is then reaped",
		"after the collector's KILL any other end of the anchor is unproved",
		"a failed close of the control pipe sends the KILL at once and is unproved",
		"an anchor that is not terminal holds the caller past the grace period, with one KILL",
		"a lost anchor reap is unproved and ends the wait",
		"nothing is signaled after a lost anchor reap",
		"a wait that failed once is unproved, and the anchor is still reaped",
		"a KILL that failed is sent again until it is delivered",
		"a failed close of the collector's own namespace descriptor is unproved")
}

// The second part of the capability probe accepts exactly one behavior: after
// the control pipe closes, the member is terminal by a KILL that the collector
// did not send, the anchor is not terminal while the member is unreaped, and
// the anchor then ends with status zero by itself. Every other answer refuses
// with the capability literal, and on every path both children are reaped and
// every probe descriptor is closed.
func TestRemoteAlphaESServiceTLSStatusChildNamespaceProbe(t *testing.T) {
	const probe = remoteAlphaESProcessIdentityLoader + remoteAlphaESChildNamespaceModel + `
def probed(grace=1000.0,**faults):
    module.CHILD_GRACE=grace;module.WITNESS_DISPOSITION_UNPROVED=False
    backend=Backend(probe=True,**faults);raised=None
    try:module.validate_child_namespace(backend)
    except BaseException as exc:raised=exc
    return backend,raised,module.WITNESS_DISPOSITION_UNPROVED
def refused(raised):return literal(raised)=="process_capability_unavailable"
def settled(backend):
    return (sorted(backend.reaped)==sorted(backend.forked) and not backend.descriptors
            and backend.home and not backend.violations)
MEMBER_KILL=("kill","member",signal.SIGKILL);ANCHOR_KILL=("kill","anchor",signal.SIGKILL)
PROBE=([("pipe",)]+OPEN+[("fork","member","away")]+RESET+
       [("close","hold_read"),("terminal","member"),("close","control_write"),("terminal","member"),
        ("terminal","anchor"),("waitpid","member"),("close","hold_write"),("waitpid","anchor"),("close","own")])

backend,raised,witness=probed()
record("the probe accepts the one proving behavior, in the fixed order",
       raised is None and backend.events==PROBE,(raised,backend.events))
record("an accepted probe signals nothing and leaves no child, descriptor or namespace setting",
       not backend.kills and settled(backend) and backend.forked==[Backend.anchor,Backend.member]
       and not witness,(backend.kills,backend.reaped,backend.descriptors,backend.violations))

for name in ("unshare","setns","clone_newpid","fork"):
    backend,raised,witness=probed(missing=(name,))
    record("a missing "+name+" refuses the capability without a child",
           refused(raised) and not backend.forked and settled(backend) and not witness
           and backend.events==[("pipe",),("close","hold_read"),("close","hold_write")],(raised,backend.events))

for label,fault,forked in (
    ("a refused namespace",{"unshare":PermissionError(errno.EPERM,"refused")},[]),
    ("a failed anchor fork",{"fork_anchor":OSError(errno.ENOMEM,"no process")},[]),
    ("a failed member fork",{"fork_member":OSError(errno.ENOMEM,"no process")},[Backend.anchor])):
    backend,raised,witness=probed(**fault)
    record(label+" refuses the capability",
           refused(raised) and backend.forked==forked and settled(backend) and not backend.kills and not witness,
           (raised,backend.events))

backend,raised,witness=probed(reset_stays_away=True)
record("a reset that is not proved refuses the capability and is reported as unproved",
       refused(raised) and witness and sorted(backend.reaped)==sorted(backend.forked)
       and not backend.descriptors and kinds(backend,"kill")==[MEMBER_KILL] and not backend.violations,
       (raised,witness,backend.events))

backend,raised,witness=probed(member_early=True)
record("a member that is terminal before the pipe closes refuses the capability",
       refused(raised) and settled(backend) and kinds(backend,"kill")==[MEMBER_KILL]
       and ("close","control_write") in backend.events,(raised,backend.events))
backend,raised,witness=probed(grace=0.05,member_never=True)
record("a member that outlives the anchor's end refuses the capability",
       refused(raised) and settled(backend) and kinds(backend,"kill")==[MEMBER_KILL],(raised,backend.events))
backend,raised,witness=probed(member_status=0)
record("a member that ended by itself refuses the capability",
       refused(raised) and settled(backend) and not backend.kills,(raised,backend.events))
backend,raised,witness=probed(anchor_terminal_with_member=True)
record("an anchor that is terminal while the member is unreaped refuses the capability",
       refused(raised) and settled(backend) and kinds(backend,"kill")==[MEMBER_KILL],(raised,backend.events))

backend,raised,witness=probed(anchor_status=1<<8)
record("an anchor that ends with a nonzero status refuses the capability and is reported as unproved",
       refused(raised) and witness and settled(backend) and not backend.kills,(raised,witness,backend.events))
backend,raised,witness=probed(grace=0.05,anchor_after_polls=12)
record("an anchor that needed the collector's KILL refuses the capability",
       refused(raised) and settled(backend) and kinds(backend,"kill")==[ANCHOR_KILL],(raised,backend.events))
backend,raised,witness=probed(grace=0.05,anchor_ignores_release=True)
record("an anchor that ignores the end of its input refuses the capability",
       refused(raised) and settled(backend) and kinds(backend,"kill")==[MEMBER_KILL,ANCHOR_KILL],(raised,backend.events))

backend,raised,witness=probed(close_hold_read=OSError(errno.EIO,"close failed"))
record("a failed close of a probe descriptor refuses the capability and is reported as unproved",
       refused(raised) and witness and sorted(backend.reaped)==sorted(backend.forked)
       and kinds(backend,"kill")==[MEMBER_KILL] and not backend.violations,(raised,witness,backend.events))
backend,raised,witness=probed(close_control_write=OSError(errno.EIO,"close failed"))
record("a failed close of the control pipe refuses the capability, and the anchor is killed at once",
       refused(raised) and witness and sorted(backend.reaped)==sorted(backend.forked)
       and kinds(backend,"kill")==[MEMBER_KILL,ANCHOR_KILL] and not backend.violations,(raised,witness,backend.events))

backend,raised,witness=probed(member_lost_at_reap=True)
record("a lost member reap refuses the capability, and the member is not signaled afterwards",
       refused(raised) and witness and not backend.kills and Backend.anchor in backend.reaped
       and not backend.descriptors and not backend.violations,(raised,witness,backend.events))
backend,raised,witness=probed(member_early=True,kill=[PermissionError(errno.EPERM,"refused")])
record("a failed KILL of the member is reported as unproved, and the member is still reaped",
       refused(raised) and witness and sorted(backend.reaped)==sorted(backend.forked)
       and not backend.descriptors,(raised,witness,backend.events))
print(json.dumps({"cases":cases,"detail":detail}))
`
	result := runRemoteAlphaESProcessIdentityProbe(t, probe)
	assertRemoteAlphaESProcessIdentityCases(t, result,
		"the probe accepts the one proving behavior, in the fixed order",
		"an accepted probe signals nothing and leaves no child, descriptor or namespace setting",
		"a missing unshare refuses the capability without a child",
		"a missing setns refuses the capability without a child",
		"a missing clone_newpid refuses the capability without a child",
		"a missing fork refuses the capability without a child",
		"a refused namespace refuses the capability",
		"a failed anchor fork refuses the capability",
		"a failed member fork refuses the capability",
		"a reset that is not proved refuses the capability and is reported as unproved",
		"a member that is terminal before the pipe closes refuses the capability",
		"a member that outlives the anchor's end refuses the capability",
		"a member that ended by itself refuses the capability",
		"an anchor that is terminal while the member is unreaped refuses the capability",
		"an anchor that ends with a nonzero status refuses the capability and is reported as unproved",
		"an anchor that needed the collector's KILL refuses the capability",
		"an anchor that ignores the end of its input refuses the capability",
		"a failed close of a probe descriptor refuses the capability and is reported as unproved",
		"a failed close of the control pipe refuses the capability, and the anchor is killed at once",
		"a lost member reap refuses the capability, and the member is not signaled afterwards",
		"a failed KILL of the member is reported as unproved, and the member is still reaped")
}

// One fixed command composes the namespace with the unchanged cleanup: open,
// spawn, reset directly after the spawn attempt, the cleanup owner, and the
// end of the namespace last. A refusal before the spawn opens nothing. What
// the end of the namespace leaves unproved makes an otherwise good command
// incomplete. The namespace here is a recorder, so this runs on every host;
// the process boundary is the shared local stand-in.
func TestRemoteAlphaESServiceTLSStatusChildNamespaceFixedCommand(t *testing.T) {
	const probe = remoteAlphaESProcessIdentityLoader + remoteAlphaESStatusLocalProcessBoundary + `
root=pathlib.Path(sys.argv[2]);child=root/"fixed-openssl"
child.write_text("#!/bin/sh\nprintf fixed\n");child.chmod(0o700);module.OPENSSL=str(child)
order=[];made=[];plan={}
class Recorder:
    def __init__(self):made.append(self)
    def open(self):
        order.append("open")
        if "open" in plan:raise plan["open"]
    def restore(self):order.append("restore")
    def close(self):order.append("close");return bool(plan.get("close_unproved"))
module.ChildNamespace=Recorder
real_popen=module.subprocess.Popen
def popen(*args,**kwargs):
    order.append("spawn")
    if "spawn" in plan:raise plan["spawn"]
    return real_popen(*args,**kwargs)
module.subprocess.Popen=popen
real_owner=module.own_child_until_proved
def owner(proc):
    order.append("cleanup");return real_owner(proc)
module.own_child_until_proved=owner
def literal(exc):
    return exc.args[0] if isinstance(exc,module.Incomplete) and exc.args else type(exc).__name__
def command(argv=None,**changes):
    del order[:];plan.clear();plan.update(changes);module.WITNESS_DISPOSITION_UNPROVED=False
    try:return module.run_fixed(argv or (module.OPENSSL,"version")),None,list(order)
    except BaseException as exc:return None,exc,list(order)
WHOLE=["open","spawn","restore","cleanup","close"]

before=len(made);result,raised,seen=command()
record("a good command opens, spawns, resets, cleans up and ends its namespace in this order",
       result==(0,b"fixed",b"") and raised is None and seen==WHOLE
       and not module.WITNESS_DISPOSITION_UNPROVED,(result,raised,seen))
command()
record("each command has a namespace of its own",len(made)==before+2 and made[-1] is not made[-2],len(made)-before)

result,raised,seen=command(close_unproved=True)
record("a good command whose namespace end is unproved is incomplete",
       result is None and literal(raised)=="child_namespace_unproved" and seen==WHOLE
       and module.WITNESS_DISPOSITION_UNPROVED,(result,raised,seen))
reason=module._failure_reason("collection",raised)
record("an unproved namespace end is reported as an unproved OpenSSL child",
       reason=="openssl_child_unproved",reason)

for label,fault in (("a refused namespace",OSError(errno.EPERM,"refused")),
                    ("a missing namespace operation",module.Incomplete("process_capability_unavailable")),
                    ("children that are not created at home",module.Incomplete("child_namespace_unproved"))):
    result,raised,seen=command(open=fault)
    record(label+" means no spawn",
           result is None and literal(raised)=="child_spawn_unproved" and seen==["open","close"]
           and not module.WITNESS_DISPOSITION_UNPROVED,(result,raised,seen))

result,raised,seen=command(spawn=OSError(errno.ENOMEM,"no process"))
record("a failed spawn is followed by the reset and the end of the namespace",
       result is None and literal(raised)=="child_spawn_unproved" and seen==["open","spawn","restore","close"]
       and not module.WITNESS_DISPOSITION_UNPROVED,(result,raised,seen))
result,raised,seen=command(spawn=OSError(errno.ENOMEM,"no process"),close_unproved=True)
record("a failed command keeps its own reason when the namespace end is unproved too",
       result is None and literal(raised)=="child_spawn_unproved" and seen==["open","spawn","restore","close"]
       and module.WITNESS_DISPOSITION_UNPROVED,(result,raised,seen))

limit=module.MAX_OUTPUT;module.MAX_OUTPUT=2
result,raised,seen=command()
module.MAX_OUTPUT=limit
record("a command that fails after the spawn still ends its namespace after the cleanup",
       result is None and literal(raised)=="child_output_overflow" and seen==WHOLE,(result,raised,seen))

module.PROCESS_CAPABILITY_READY=False
result,raised,seen=command()
module.PROCESS_CAPABILITY_READY=True
record("a command without a proved capability opens no namespace",
       result is None and literal(raised)=="process_capability_unavailable" and seen==["close"],(result,raised,seen))
result,raised,seen=command(argv=("/bin/true",))
record("a command that is not the fixed command opens no namespace",
       result is None and literal(raised)=="invalid_fixed_command" and seen==["close"],(result,raised,seen))
print(json.dumps({"cases":cases,"detail":detail}))
`
	result := runRemoteAlphaESProcessIdentityProbe(t, probe, t.TempDir())
	assertRemoteAlphaESProcessIdentityCases(t, result,
		"a good command opens, spawns, resets, cleans up and ends its namespace in this order",
		"each command has a namespace of its own",
		"a good command whose namespace end is unproved is incomplete",
		"an unproved namespace end is reported as an unproved OpenSSL child",
		"a refused namespace means no spawn",
		"a missing namespace operation means no spawn",
		"children that are not created at home means no spawn",
		"a failed spawn is followed by the reset and the end of the namespace",
		"a failed command keeps its own reason when the namespace end is unproved too",
		"a command that fails after the spawn still ends its namespace after the cleanup",
		"a command without a proved capability opens no namespace",
		"a command that is not the fixed command opens no namespace")
}

// The anchor's own code, run for real in a forked child of the probe and
// without a namespace, so that it runs as any user. The probe is the anchor's
// parent and a child subreaper: a process that the anchor leaves unreaped
// stays with the probe as a zombie and shows. The anchor closes every
// inherited descriptor but its standard streams and the control pipe, reaps
// each process that ends while it waits, goes on doing so until the control
// pipe closes, and then ends with status zero. Inside a namespace the
// processes it reaps are the orphans of the namespace; here they are two
// children that end when the probe says so.
//
// The probe decides by attempts whether this host has what the anchor and
// the probe use: a list of its own descriptors in /proc/self/fd, pidfd_open
// with pidfd_send_signal, and prctl. Only the explicit answer that one of them
// is missing skips.
func TestRemoteAlphaESServiceTLSStatusChildNamespaceAnchorProcess(t *testing.T) {
	const probe = remoteAlphaESProcessIdentityLoader + `
import ctypes,select
def unavailable():
    try:os.listdir("/proc/self/fd")
    except OSError as exc:return "cannot list /proc/self/fd: "+errno.errorcode.get(exc.errno,str(exc.errno))
    if getattr(os,"pidfd_open",None) is None or getattr(signal,"pidfd_send_signal",None) is None:
        return "this Python has no os.pidfd_open or signal.pidfd_send_signal"
    try:fd=os.pidfd_open(os.getpid())
    except OSError as exc:return "pidfd_open refused: "+errno.errorcode.get(exc.errno,str(exc.errno))
    os.close(fd)
    try:prctl=ctypes.CDLL(None,use_errno=True).prctl
    except AttributeError:return "this C library has no prctl"
    if prctl(36,1,0,0,0)!=0:  # PR_SET_CHILD_SUBREAPER
        raise RuntimeError("prctl(PR_SET_CHILD_SUBREAPER) failed: %d"%ctypes.get_errno())
    return None
reason=unavailable()
if reason is not None:
    print(json.dumps({"capability":False,"reason":reason}));sys.exit(0)
def terminal(pid):
    # Whether the child has ended, without reaping it.
    return os.waitid(os.P_PID,pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) is not None
def reaped(pidfd):
    # A zombie still takes a signal through its pidfd. ESRCH comes only after
    # its parent has reaped it.
    try:signal.pidfd_send_signal(pidfd,0)
    except ProcessLookupError:return True
    return False
def until(condition):
    # The bound only ends a failing case; a passing one returns at once.
    deadline=time.monotonic()+20.0
    while not condition():
        if time.monotonic()>deadline:return False
        time.sleep(0.005)
    return True
control_r,control_w=os.pipe();kept_r,kept_w=os.pipe();report_r,report_w=os.pipe()
first_go_r,first_go_w=os.pipe();second_go_r,second_go_w=os.pipe()
anchor=os.fork()
if anchor==0:
    try:
        for fd in (control_w,kept_r,report_r,first_go_w,second_go_w):os.close(fd)
        members=[]
        for go in (first_go_r,second_go_r):
            pid=os.fork()
            if pid==0:
                for fd in (control_r,kept_w,report_w,first_go_r,second_go_r):
                    if fd!=go:os.close(fd)
                os.read(go,1);os._exit(0)
            members.append(pid)
        os.write(report_w,("%d %d"%tuple(members)).encode())
        for fd in (report_w,first_go_r,second_go_r):os.close(fd)
    except BaseException:
        os._exit(3)
    module._child_namespace_anchor(control_r)
    os._exit(4)
for fd in (control_r,kept_w,report_w,first_go_r,second_go_r):os.close(fd)
first,second=(int(word) for word in os.read(report_r,64).split());os.close(report_r)
# Both wait for the probe, so both are alive here and each pidfd names it.
pidfds={first:os.pidfd_open(first),second:os.pidfd_open(second)}
ready,_write,_error=select.select([kept_r],[],[],20.0)
closed=bool(ready) and os.read(kept_r,1)==b""
record("the anchor closes every inherited descriptor but its standard streams and the control pipe",
       closed and not terminal(anchor),(ready,closed))
os.close(first_go_w)
record("the anchor reaps a process that ends while it waits",
       until(lambda:reaped(pidfds[first])) and not terminal(anchor),terminal(anchor))
os.close(second_go_w)
record("the anchor goes on reaping until its control pipe closes",
       until(lambda:reaped(pidfds[second])) and not terminal(anchor),terminal(anchor))
os.close(control_w)
waited,status=os.waitpid(anchor,0)
record("the anchor ends with status zero when its control pipe closes",
       waited==anchor and os.WIFEXITED(status) and os.WEXITSTATUS(status)==0,status)
# The anchor was the probe's only child. A process that the anchor left
# behind came to the probe, which adopts orphans.
left=[];remaining=True;deadline=time.monotonic()+20.0
while time.monotonic()<deadline:
    try:pid,_status=os.waitpid(-1,os.WNOHANG)
    except ChildProcessError:remaining=False;break
    if pid==0:time.sleep(0.01)
    else:left.append(pid)
record("no process is left to the probe",left==[] and not remaining,(left,remaining))
for pidfd in pidfds.values():os.close(pidfd)
os.close(kept_r)
print(json.dumps({"capability":True,"cases":cases,"detail":detail}))
`
	result := runRemoteAlphaESProcessIdentityProbe(t, probe)
	switch result["capability"] {
	case true:
	case false:
		reason, ok := result["reason"].(string)
		if !ok || reason == "" {
			t.Fatalf("anchor probe refused without a reason: %v", result)
		}
		t.Skipf("skipping the anchor process test: %s", reason)
	default:
		t.Fatalf("anchor probe did not state its capability: %v", result)
	}
	assertRemoteAlphaESProcessIdentityCases(t, result,
		"the anchor closes every inherited descriptor but its standard streams and the control pipe",
		"the anchor reaps a process that ends while it waits",
		"the anchor goes on reaping until its control pipe closes",
		"the anchor ends with status zero when its control pipe closes",
		"no process is left to the probe")
}

// The three documents state the same rule, and the collector's source holds
// the steps that the rule names.
func TestRemoteAlphaESServiceTLSStatusChildNamespaceDocumentsContract(t *testing.T) {
	plans := compactDocSection(t, mustRead(t, "PLANS.md"),
		"`Bounded slice rule` fixed-child containment refinement:",
		"The facade uses one fixed remote Python stage-creation helper.")
	remote := compactDocSection(t, mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"),
		"`Bounded slice rule` for fixed-child containment:",
		"The exact client verification argv is")
	access := compactDocSection(t, mustRead(t, ".docs/system_overview/remote_alpha_access_contract.md"),
		"Process-group disposition reaches only a process that stays in the fixed",
		"After bootstrap stage removal and status-lock acquisition")
	for label, section := range map[string]string{"PLANS": plans, "Remote Alpha": remote, "access contract": access} {
		assertContainsAll(t, label+" fixed-child containment", section,
			"`/proc/self/ns/pid_for_children`", "`unshare(CLONE_NEWPID)`", "`setns`",
			"one fixed internal anchor", "status zero",
			"second process of the namespace and a direct child of the collector",
			"admits no new", "`openssl_child_unproved`",
			"ommand falls back to process-group disposition alone",
			"time limit", "still runs as root")
		assertContainsNone(t, label+" fixed-child containment", section,
			"best effort", "falls back to the process group when")
	}
	for label, section := range map[string]string{"PLANS": plans, "Remote Alpha": remote} {
		assertContainsAll(t, label+" fixed-child containment steps", section,
			"leaves the group with `setsid` or `setpgid`",
			"the kernel, not a scan, accounts for its processes",
			"Directly after the spawn attempt, successful or not",
			"nonblocking `waitpid`", "one KILL", "reaps it exactly once",
			"lifecycle ownership and the status lock retained", "that hold has no time limit",
			"`child_namespace_unproved`", "`process_capability_unproved`",
			"an orphan that ends as a zombie in the fixed child's process group",
			"the anchor must not be terminal while the member is unreaped",
			"never by an OS label, a kernel version, or the caller's user ID",
			"process ID 2 and parent ID 0", "keeps exactly one thread",
			"prove nothing about the kernel path; only a run as root on Linux does",
			"changes no process-group signal, hold, direct-child reap, lock, publication, public code, schema, reader, or retry authority")
	}

	fixtures := compactDocSection(t, mustRead(t, ".docs/system_overview/capability_probing.md"),
		"Root-package tests of the Remote Alpha TLS status collector", "")
	assertContainsAll(t, "capability probing fixture rule for the namespace", fixtures,
		"which only root can create on Linux",
		"replace the namespace by one shared stand-in that does nothing, together with the namespace part of the capability probe",
		"A fixture replaces both or neither",
		"A fixture that uses the stand-in proves nothing about the containment.",
		"a deterministic backend in the place of the kernel operations",
		"skips itself, with an explicit reason, only when the kernel refuses",
		"The CI job runs that group once more as root and fails unless each of its tests passes",
		"only the test binary runs as root")

	source := mustRead(t, remoteAlphaESServiceTLSStatusCollectorPath())
	if got := strings.Count(source, `"child_namespace_unproved": "openssl_child_unproved",`); got != 1 {
		t.Fatalf("collector maps child_namespace_unproved to openssl_child_unproved %d times, want once", got)
	}
	capability := docSection(t, source, "\ndef validate_process_capability(", "\ndef read_proc_identity(")
	if !strings.HasSuffix(strings.TrimRight(capability, "\n"), "\n    validate_child_namespace()") {
		t.Fatalf("the capability probe does not end with its namespace part")
	}
	anchor := docSection(t, source, "\ndef _child_namespace_anchor(", "\ndef _child_namespace_probe_member(")
	assertContainsAll(t, "collector namespace anchor", anchor,
		"_close_inherited_descriptors(control_read)", "os.waitpid(-1, os.WNOHANG)",
		`if os.read(control_read, 1) == b"":`, "os._exit(code)")
	namespace := docSection(t, source, "\nclass ChildNamespace:", "\ndef validate_child_namespace(")
	assertContainsAll(t, "collector child namespace", namespace,
		`backend.open("/proc/self/ns/pid", os.O_RDONLY | os.O_CLOEXEC)`,
		`self.backend.stat("/proc/self/ns/pid_for_children")`,
		"backend.unshare(backend.clone_newpid)",
		"self.backend.setns(self.own_fd, self.backend.clone_newpid)",
		"backend.waitpid(self.anchor, os.WNOHANG)", "backend.kill(self.anchor, signal.SIGKILL)")
	assertContainsNone(t, "collector child namespace", namespace, "killpg", "scan_group_members", "listdir")
	fixed := docSection(t, source, "\ndef run_fixed(", "\ndef _run_fixed_in_namespace(")
	if got := strings.Count(fixed, "if namespace.close():"); got != 2 {
		t.Fatalf("run_fixed ends its namespace on %d paths, want on both", got)
	}
	assertContainsAll(t, "collector fixed command", fixed,
		"namespace = ChildNamespace()", `raise Incomplete("child_namespace_unproved")`)
	body := docSection(t, source, "\ndef _run_fixed_in_namespace(", "\ndef nested(")
	assertContainsAll(t, "collector fixed command body", body,
		"        namespace.open()\n        try:\n            proc = subprocess.Popen(",
		"        finally:\n            namespace.restore()\n")
}

// The real tests need a kernel that lets this process create a PID namespace.
// The prelude decides that by an attempt in a child of its own, never by an
// OS label or a user ID. Only the explicit answer that no namespace can be
// created here skips; any other shape of answer is a failure.
func requireRemoteAlphaESChildNamespaceKernel(t *testing.T, result map[string]any) {
	t.Helper()
	switch result["capability"] {
	case true:
	case false:
		reason, ok := result["reason"].(string)
		if !ok || reason == "" {
			t.Fatalf("PID namespace probe refused without a reason: %v", result)
		}
		t.Skipf("skipping real PID namespace test: %s", reason)
	default:
		t.Fatalf("PID namespace probe did not state its capability: %v", result)
	}
}

const remoteAlphaESChildNamespaceRealPrelude = remoteAlphaESProcessIdentityLoader + `
import ctypes,subprocess
def unavailable():
    if any(getattr(os,name,None) is None for name in ("unshare","setns","CLONE_NEWPID")):
        return "this Python has no os.unshare, os.setns or os.CLONE_NEWPID"
    answer_r,answer_w=os.pipe();pid=os.fork()
    if pid==0:
        try:
            os.close(answer_r)
            try:os.unshare(os.CLONE_NEWPID);answer=b"created"
            except OSError as exc:answer=errno.errorcode.get(exc.errno,str(exc.errno)).encode()
            os.write(answer_w,answer)
        except BaseException:pass
        os._exit(0)
    os.close(answer_w);answer=os.read(answer_r,64);os.close(answer_r);os.waitpid(pid,0)
    if answer==b"created":return None
    if answer in (b"EPERM",b"EINVAL",b"ENOSYS"):
        return "the kernel refuses a new PID namespace to this process: "+answer.decode()
    raise RuntimeError("unexpected answer to the namespace attempt: %r"%answer)
reason=unavailable()
if reason is not None:
    print(json.dumps({"capability":False,"reason":reason}));sys.exit(0)
# The grace bound is not under test here: a loaded test host must not turn one
# late scheduling into a failure.
module.CHILD_GRACE=30.0
def at_home():
    own=os.stat("/proc/self/ns/pid");children=os.stat("/proc/self/ns/pid_for_children")
    return (own.st_dev,own.st_ino)==(children.st_dev,children.st_ino)
def descriptors(pid="self"):
    found=[]
    for name in os.listdir("/proc/%s/fd"%pid):
        try:os.stat("/proc/%s/fd/%s"%(pid,name));found.append(int(name))
        except OSError:pass
    return sorted(found)
def no_child():
    try:os.waitpid(-1,os.WNOHANG);return False
    except ChildProcessError:return True
# A control case leaves processes behind on purpose, and a killed collector
# leaves its children to whoever adopts them. This probe adopts them itself
# and reaps them, so that nothing depends on the host's first process. That
# does not reach into a child PID namespace: an orphan there goes to the first
# process of its namespace.
if ctypes.CDLL(None,use_errno=True).prctl(36,1,0,0,0)!=0:  # PR_SET_CHILD_SUBREAPER
    raise RuntimeError("this probe cannot adopt orphans")
def reap_all(seconds):
    # The wait statuses of every child, or None when one is left after the bound.
    statuses=[];deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        try:pid,status=os.waitpid(-1,os.WNOHANG)
        except ChildProcessError:return sorted(statuses)
        if pid==0:time.sleep(0.01)
        else:statuses.append(status)
    return None
`

// The stand-in for the fixed OpenSSL command of the real tests. It reports
// itself and one descendant on a FIFO that every process of the command keeps
// open for writing, so the reader sees the end of input exactly when no
// process of the command is left. The identities it reports are the ones the
// process sees itself: inside a PID namespace those are the namespace's.
//
// The descendant leaves the fixed child's process group with setsid or
// setpgid, daemonizes, or is a relay in which every process forks a successor
// and ends. In those modes it ignores TERM and HUP. In the mode "group" it
// stays in the group and keeps the default signals. In the mode "linger" the
// fixed child itself stays as well. Every process ends by itself when the
// release file appears, or after 60 seconds.
const remoteAlphaESChildNamespaceFixedChild = `
child=root/"fixed-openssl"
child.write_text('''#!/usr/bin/python3 -I
import os,signal,sys,time
mode,fifo,release=sys.argv[1:4]
out=os.open(fifo,os.O_WRONLY)
ready_r,ready_w=os.pipe()
def say(label):
    os.write(out,("%s %d %d %d %d\\n"%(label,os.getpid(),os.getppid(),os.getpgid(0),os.getsid(0))).encode())
def detach(label,ignore=True):
    for fd in (0,1,2,ready_r):
        try:os.close(fd)
        except OSError:pass
    if ignore:
        signal.signal(signal.SIGTERM,signal.SIG_IGN);signal.signal(signal.SIGHUP,signal.SIG_IGN)
    say(label);os.write(ready_w,b"r");os.close(ready_w)
def stay():
    end=time.monotonic()+60
    while time.monotonic()<end and not os.path.exists(release):time.sleep(0.02)
    os._exit(0)
say("fixed")
if os.fork()==0:
    try:
        if mode in ("setsid","linger"):os.setsid();detach("escaped");stay()
        if mode=="setpgid":os.setpgid(0,0);detach("escaped");stay()
        if mode=="daemon":
            os.setsid()
            if os.fork()==0:detach("escaped");stay()
            os._exit(0)
        if mode=="relay":
            os.setsid();detach("escaped");end=time.monotonic()+60
            while time.monotonic()<end and not os.path.exists(release):
                if os.fork()>0:os._exit(0)
                time.sleep(0.005)
            os._exit(0)
        if mode=="group":detach("stayed",ignore=False);stay()
    except BaseException:pass
    os._exit(1)
os.close(ready_w);os.read(ready_r,1)
if mode=="linger":
    for fd in (0,1,2):os.close(fd)
    stay()
sys.stdout.write("fixed");sys.stdout.flush()
''')
child.chmod(0o700);module.OPENSSL=str(child)
def drain(reader):
    # Everything written so far, and whether a writer is still there.
    data=b""
    while True:
        try:chunk=os.read(reader,65536)
        except BlockingIOError:return data,True
        if chunk==b"":return data,False
        data+=chunk
def let_go(reader,release):
    release.write_bytes(b"");deadline=time.monotonic()+30
    while time.monotonic()<deadline:
        if not drain(reader)[1]:return True
        time.sleep(0.02)
    return False
def reports(data):
    seen={}
    for line in data.decode().splitlines():
        label,pid,ppid,pgid,sid=line.split();seen[label]=[int(pid),int(ppid),int(pgid),int(sid)]
    return seen
`

// The kernel does what the rule relies on. The whole capability probe accepts
// this kernel and leaves nothing behind. The fork after open is the second
// process of a new namespace and its parent is outside it. The anchor keeps
// no descriptor of the collector but its standard streams and the control
// pipe. A fork after the reset is an ordinary child. A namespace whose anchor
// is gone admits no new process.
func TestRemoteAlphaESServiceTLSStatusChildNamespaceRealKernel(t *testing.T) {
	const probe = remoteAlphaESChildNamespaceRealPrelude + `
before=descriptors()
try:module.validate_process_capability();raised=None
except BaseException as exc:raised=exc
record("the whole capability probe accepts this kernel",
       raised is None and not module.WITNESS_DISPOSITION_UNPROVED,raised)
record("the probe leaves no child, descriptor or namespace setting",
       no_child() and descriptors()==before and at_home(),(descriptors(),before))

# Descriptors that the anchor inherits and must close.
extra_r,extra_w=os.pipe();os.set_inheritable(extra_w,True);spare=os.open("/dev/null",os.O_RDONLY)
namespace=module.ChildNamespace();namespace.open()
report_r,report_w=os.pipe()
try:
    member=os.fork()
    if member==0:
        try:os.write(report_w,json.dumps([os.getpid(),os.getppid()]).encode())
        except BaseException:pass
        os._exit(0)
finally:namespace.restore()
os.close(report_w);inside=json.loads(os.read(report_r,64));os.close(report_r)
record("the fork after open is the second process of a new namespace, with its parent outside",
       inside==[2,0],inside)
record("the reset is proved",at_home() and not namespace.unproved,namespace.unproved)
report_r,report_w=os.pipe();ordinary=os.fork()
if ordinary==0:
    try:os.write(report_w,json.dumps(os.getpid()).encode())
    except BaseException:pass
    os._exit(0)
os.close(report_w);outside=json.loads(os.read(report_r,64));os.close(report_r);os.waitpid(ordinary,0)
record("a fork after the reset is an ordinary child",outside==ordinary,(outside,ordinary))

control=os.readlink("/proc/self/fd/%d"%namespace.control_write)
deadline=time.monotonic()+10;held=[]
while time.monotonic()<deadline:
    held=descriptors(namespace.anchor)
    if len(held)==4:break
    time.sleep(0.01)
record("the anchor keeps only its standard streams and the control pipe",
       len(held)==4 and held[:3]==[0,1,2]
       and os.readlink("/proc/%d/fd/%d"%(namespace.anchor,held[3]))==control,held)
os.waitpid(member,0)
unproved=namespace.close()
record("close returns after the anchor is reaped with status zero and without a KILL",
       unproved is False and namespace.reaped and not namespace.killed and no_child(),(unproved,namespace.killed))
os.close(extra_r);os.close(extra_w);os.close(spare)
record("the namespace leaves no descriptor in the collector",descriptors()==before,(descriptors(),before))

namespace=module.ChildNamespace();namespace.open()
os.kill(namespace.anchor,signal.SIGKILL)  # this probe's own unreaped child
deadline=time.monotonic()+10
while not module.waitid_terminal(namespace.anchor) and time.monotonic()<deadline:time.sleep(0.01)
refusal=None;stray=-1
try:
    stray=os.fork()
    if stray==0:os._exit(0)
except OSError as exc:refusal=exc
finally:namespace.restore()
if stray>0:os.waitpid(stray,0)
record("a namespace whose anchor is gone admits no new process",
       isinstance(refusal,OSError) and refusal.errno==errno.ENOMEM and stray==-1,(refusal,stray))
unproved=namespace.close()
record("an anchor that something else killed is unproved, and the collector is at home again",
       unproved is True and namespace.reaped and not namespace.killed and at_home() and no_child()
       and descriptors()==before,(unproved,namespace.killed))
print(json.dumps({"capability":True,"cases":cases,"detail":detail}))
`
	result := runRemoteAlphaESProcessIdentityProbe(t, probe)
	requireRemoteAlphaESChildNamespaceKernel(t, result)
	assertRemoteAlphaESProcessIdentityCases(t, result,
		"the whole capability probe accepts this kernel",
		"the probe leaves no child, descriptor or namespace setting",
		"the fork after open is the second process of a new namespace, with its parent outside",
		"the reset is proved",
		"a fork after the reset is an ordinary child",
		"the anchor keeps only its standard streams and the control pipe",
		"close returns after the anchor is reaped with status zero and without a KILL",
		"the namespace leaves no descriptor in the collector",
		"a namespace whose anchor is gone admits no new process",
		"an anchor that something else killed is unproved, and the collector is at home again")
}

// The real fixed command, with the real probe, the real process boundary and
// the real namespace. A descendant that the process-group cleanup cannot
// reach is gone when the command returns: the FIFO that every process of the
// command holds reports the end of input at once. An orphan that stays in the
// group ends as a zombie whose parent is the anchor; the anchor reaps it, or
// the absence scan of the unchanged cleanup would see it forever.
//
// The last case is the control. The same fixture without the namespace leaves
// the same descendant alive after the command returned, so the cases above
// can fail.
func TestRemoteAlphaESServiceTLSStatusChildNamespaceRealDescendants(t *testing.T) {
	const probe = remoteAlphaESChildNamespaceRealPrelude + `
root=pathlib.Path(sys.argv[2])
` + remoteAlphaESChildNamespaceFixedChild + `
before=descriptors()
module.validate_process_capability();module.PROCESS_CAPABILITY_READY=True
def command(mode,tag):
    fifo=root/("events-"+tag);release=root/("release-"+tag)
    os.mkfifo(fifo);reader=os.open(fifo,os.O_RDONLY|os.O_NONBLOCK)
    try:result=module.run_fixed((module.OPENSSL,mode,str(fifo),str(release)));raised=None
    except BaseException as exc:result=None;raised=exc
    data,alive=drain(reader)
    released=let_go(reader,release) if alive else None
    os.close(reader)
    return result,raised,alive,released,reports(data),reap_all(30)
first=None
for mode,label in (("setsid","a descendant that left the group with setsid"),
                   ("setpgid","a descendant that left the group with setpgid"),
                   ("daemon","a daemonized descendant"),
                   ("relay","a fork relay")):
    result,raised,alive,released,seen,orphans=command(mode,mode)
    first=first or seen.get("fixed")
    record(label+" is gone when the command returns",
           result==(0,b"fixed",b"") and raised is None and alive is False and orphans==[]
           and "escaped" in seen and seen["escaped"][0]>2 and seen["escaped"][2]!=2,
           (result,raised,alive,orphans,seen))
record("the fixed child is the second process of its namespace and leads its own group and session",
       first==[2,0,2,2],first)
result,raised,alive,released,seen,orphans=command("group","group")
record("an orphan that stays in the group is reaped by the anchor and does not hold the cleanup",
       result==(0,b"fixed",b"") and raised is None and alive is False and orphans==[]
       and "stayed" in seen and seen["stayed"][2]==2,(result,raised,alive,orphans,seen))
record("the commands leave no child, descriptor or namespace setting, and nothing unproved",
       no_child() and descriptors()==before and at_home()
       and not module.WITNESS_DISPOSITION_UNPROVED,(descriptors(),before))
# The control: the same fixture, and no namespace.
` + remoteAlphaESStatusLocalChildNamespace + `result,raised,alive,released,seen,orphans=command("setsid","control")
record("without the namespace the same descendant outlives the command",
       result==(0,b"fixed",b"") and raised is None and alive is True and released is True
       and orphans==[0] and "escaped" in seen,(result,raised,alive,released,orphans,seen))
print(json.dumps({"capability":True,"cases":cases,"detail":detail}))
`
	result := runRemoteAlphaESProcessIdentityProbe(t, probe, t.TempDir())
	requireRemoteAlphaESChildNamespaceKernel(t, result)
	assertRemoteAlphaESProcessIdentityCases(t, result,
		"a descendant that left the group with setsid is gone when the command returns",
		"a descendant that left the group with setpgid is gone when the command returns",
		"a daemonized descendant is gone when the command returns",
		"a fork relay is gone when the command returns",
		"the fixed child is the second process of its namespace and leads its own group and session",
		"an orphan that stays in the group is reaped by the anchor and does not hold the cleanup",
		"the commands leave no child, descriptor or namespace setting, and nothing unproved",
		"without the namespace the same descendant outlives the command")
}

// A collector that is killed in the middle of a fixed command takes the fixed
// child and its escaped descendant with it: its end closes the control pipe,
// the anchor ends, and the kernel kills what is left in the namespace. The
// collector here is a child of the probe that runs the real fixed command
// with a fixed child that never ends by itself. The control runs the same
// collector without the namespace, and there both processes outlive it.
func TestRemoteAlphaESServiceTLSStatusChildNamespaceRealCollectorDeath(t *testing.T) {
	const probe = remoteAlphaESChildNamespaceRealPrelude + `
root=pathlib.Path(sys.argv[2])
` + remoteAlphaESChildNamespaceFixedChild + `
head='''import importlib.util,os,sys
spec=importlib.util.spec_from_file_location("status_collector_death",sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
module.OPENSSL=sys.argv[2];module.CHILD_TIMEOUT=60.0
'''
standin='''` + remoteAlphaESStatusLocalChildNamespace + `'''
tail='''module.validate_process_capability();module.PROCESS_CAPABILITY_READY=True
module.run_fixed((module.OPENSSL,"linger",sys.argv[3],sys.argv[4]))
'''
def collector_death(tag,source,wait):
    fifo=root/("events-"+tag);release=root/("release-"+tag);log=root/("collector-"+tag+".log")
    os.mkfifo(fifo);reader=os.open(fifo,os.O_RDONLY|os.O_NONBLOCK)
    with open(log,"wb") as errors:
        collector=subprocess.Popen(["/usr/bin/python3","-I","-B","-c",source,sys.argv[1],str(child),str(fifo),str(release)],
                                   stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=errors)
    data=b"";deadline=time.monotonic()+60
    while data.count(b"\n")<2 and time.monotonic()<deadline and collector.poll() is None:
        data+=drain(reader)[0];time.sleep(0.01)
    started=data.count(b"\n")>=2 and collector.poll() is None
    collector.kill();collector.wait()  # this probe's own unreaped child
    gone=False;deadline=time.monotonic()+wait
    while time.monotonic()<deadline and not gone:
        more,alive=drain(reader);data+=more;gone=not alive
        if not gone:time.sleep(0.01)
    released=let_go(reader,release) if not gone else None
    os.close(reader)
    return started,gone,released,reports(data),reap_all(30),log.read_bytes()[-2000:]
started,gone,released,seen,orphans,log=collector_death("contained",head+tail,30)
record("the collector was killed while its fixed child and an escaped descendant were alive in the namespace",
       started and seen.get("fixed")==[2,0,2,2] and "escaped" in seen and seen["escaped"][2]!=2,(started,seen,log))
record("a killed collector takes its fixed child and every descendant with it",
       started and gone is True,(started,gone,seen,log))
# The probe adopted the killed collector's two children: the fixed child, which
# the kernel killed, and the anchor, which ended by itself.
record("after a killed collector the kernel killed the fixed child, and the anchor ended with status zero",
       started and orphans==[0,signal.SIGKILL],(started,orphans,log))
started,gone,released,seen,orphans,log=collector_death("control",head+standin+tail,1)
record("without the namespace the same processes outlive a killed collector",
       started and gone is False and released is True and orphans==[0,0]
       and "escaped" in seen,(started,gone,released,orphans,seen,log))
print(json.dumps({"capability":True,"cases":cases,"detail":detail}))
`
	result := runRemoteAlphaESProcessIdentityProbe(t, probe, t.TempDir())
	requireRemoteAlphaESChildNamespaceKernel(t, result)
	assertRemoteAlphaESProcessIdentityCases(t, result,
		"the collector was killed while its fixed child and an escaped descendant were alive in the namespace",
		"a killed collector takes its fixed child and every descendant with it",
		"after a killed collector the kernel killed the fixed child, and the anchor ended with status zero",
		"without the namespace the same processes outlive a killed collector")
}
