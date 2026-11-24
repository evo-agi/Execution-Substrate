package scripts_test

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
// one namespace. The anchor reports ready at once. It ends when its control
// pipe is closed or when it is killed. When the anchor ends, the member, the
// fixed child and every stray are killed. A stray is a child of the
// collector inside the namespace that the fixed child made; strays come in
// waves, and a wave appears after the collector has listed its children as
// often as the wave's number, as when a living stray makes the next one. The
// anchor becomes terminal only when it has ended and the member, the fixed
// child and every stray are reaped. A child at home is listed and never
// ends. Options change one of these answers at a time. The backend records
// every call, and it records as a violation a close of a descriptor that is
// not open, a blocking wait, a wait for a child at home, and a signal to
// anything but an unreaped child.
const remoteAlphaESChildNamespaceModel = `
import types
class Backend:
    clone_newpid=0x20000000
    anchor=4001;member=4002;fixed=4003
    def __init__(self,probe=False,missing=(),away=False,strays=(),home_children=(),**faults):
        self.probe=probe;self.faults=faults;self.events=[];self.violations=[]
        self.descriptors=set();self.last_fd=700;self.pipes=[];self.own=None
        self.home=not away;self.forked=[];self.reaped=[];self.kills=[];self.polls=0
        self.released=False;self.waves=[list(wave) for wave in strays];self.lists=0
        self.home_children=list(home_children);self.fixed_polls=0
        for name in missing:setattr(self,name,None)
    def _new_fd(self):
        self.last_fd+=1;self.descriptors.add(self.last_fd);return self.last_fd
    def _raise(self,name):
        fault=self.faults.get(name)
        if isinstance(fault,list):fault=fault.pop(0) if fault else None
        if fault is not None:raise fault
    def role(self,fd):
        if fd==self.own:return "own"
        names=(["hold"] if self.probe else [])+["control","ready"]
        for name,(read_end,write_end) in zip(names,self.pipes):
            if fd==read_end:return name+"_read"
            if fd==write_end:return name+"_write"
        return "unknown"
    def name(self,pid):
        if pid in self.home_children:return "home"
        if any(pid in wave for wave in self.waves):return "stray"
        return {self.anchor:"anchor",self.member:"member",self.fixed:"fixed"}.get(pid,"unknown")
    def spawn_fixed(self):
        # The fixed child and the first wave of strays, as Popen and the fixed
        # child make them.
        self.forked.append(self.fixed)
        if self.waves:self.forked.extend(self.waves[0])
    def reap_fixed(self):
        # The cleanup owner's reap of the fixed child.
        if self._fixed_terminal():self.reaped.append(self.fixed)
        else:self.violations.append(("the fixed child was not terminal at its reap",))
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
    def read(self,fd,size):
        self.events.append(("read",self.role(fd),size));self._raise("read")
        return self.faults.get("ready_word",b"r")
    def close(self,fd):
        role=self.role(fd);self.events.append(("close",role))
        if fd not in self.descriptors:self.violations.append(("close of a descriptor that is not open",role))
        self.descriptors.discard(fd)
        fault=self.faults.get("close_"+role)
        if fault is not None:raise fault
        if role=="control_write":self.released=True
    def children(self):
        self.events.append(("children",));self._raise("children")
        listed=[pid for pid in self.home_children+self.forked if pid in self.home_children or self._unreaped(pid)]
        if self.faults.get("member_unlisted"):listed=[pid for pid in listed if pid!=self.member]
        # The next wave is made while this list is read, so it is not in it.
        self.lists+=1
        if self.lists<len(self.waves) and self.fixed in self.forked:self.forked.extend(self.waves[self.lists])
        return listed
    def pid_namespace(self,pid):
        self.events.append(("pid_namespace",self.name(pid)));self._raise("pid_namespace")
        at_home=pid in self.home_children or (pid==self.member and self.faults.get("member_at_home"))
        return (5,100) if at_home else (5,101)
    def _unreaped(self,pid):
        return pid in self.forked and pid not in self.reaped
    def _strays_unreaped(self):
        return any(self._unreaped(pid) for wave in self.waves for pid in wave)
    def _anchor_saw_end(self):
        return self.released and not self.faults.get("anchor_ignores_release")
    def _anchor_ended(self):
        return self._anchor_saw_end() or self.anchor in self.kills
    def _anchor_terminal(self):
        if not self._unreaped(self.anchor) or not self._anchor_ended():return False
        if self.polls<self.faults.get("anchor_after_polls",0):return False
        if self.faults.get("anchor_terminal_with_member"):return True
        return not self._unreaped(self.member) and not self._unreaped(self.fixed) and not self._strays_unreaped()
    def _member_terminal(self):
        if not self._unreaped(self.member):return False
        if self.member in self.kills or self.faults.get("member_early"):return True
        return self._anchor_ended() and not self.faults.get("member_never")
    def _fixed_terminal(self):
        if not self._unreaped(self.fixed):return False
        return self._anchor_ended() and self.fixed_polls>=self.faults.get("fixed_after_polls",0)
    def _stray_terminal(self):
        return self._anchor_ended() and self.lists>=self.faults.get("stray_after_lists",0)
    def terminal(self,pid):
        self.events.append(("terminal",self.name(pid)));self._raise("terminal")
        if not self._unreaped(pid):
            self.violations.append(("observed what is not an unreaped child",self.name(pid)))
            raise ChildProcessError()
        if pid==self.fixed:
            self.fixed_polls+=1;return self._fixed_terminal()
        return self._anchor_terminal() if pid==self.anchor else self._member_terminal()
    def waitpid(self,pid,flags):
        which=self.name(pid);self.events.append(("waitpid",which))
        if flags!=os.WNOHANG:self.violations.append(("blocking wait",which))
        if which=="home":self.violations.append(("wait for a child at home",pid));return (0,0)
        if which=="anchor":self.polls+=1
        if which=="member" and self.faults.get("member_lost_at_reap"):
            self.reaped.append(pid);raise ChildProcessError()
        self._raise("waitpid_"+which)
        if not self._unreaped(pid):raise ChildProcessError()
        if pid==self.anchor:
            if not self._anchor_terminal():return (0,0)
            status=self.faults.get("anchor_status",0 if self._anchor_saw_end() else signal.SIGKILL)
        elif which=="stray":
            if not self._stray_terminal():return (0,0)
            status=signal.SIGKILL
        elif pid==self.fixed:
            if not self._fixed_terminal():return (0,0)
            status=signal.SIGKILL
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
OPEN=[("open","/proc/self/ns/pid",RDONLY),("fstat","own"),("stat","/proc/self/ns/pid_for_children"),("pipe",),("pipe",),
      ("unshare",NEWPID),("fork","anchor","away"),("close","control_read"),("close","ready_write"),
      ("read","ready_read",1),("close","ready_read")]
RESET=[("setns","own",NEWPID),("fstat","own"),("stat","/proc/self/ns/pid_for_children")]
END=[("close","control_write"),("children",),("waitpid","anchor"),("close","own")]
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
// make the control and ready pipes, open the namespace, fork the anchor,
// close the anchor's pipe ends, and read the anchor's ready byte; then the
// reset with its proof; then the end, which closes the control pipe, lists
// the collector's children for strays, reaps the anchor, and closes the
// collector's own namespace descriptor last. When an earlier release closed
// the control pipe, the end only waits for the anchor. Every refusal happens
// before the step it protects.
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

# The capability probe releases its namespace before close, and end() begins
# with the same release.
backend=Backend();namespace,raised=opened(backend);namespace.restore()
released=namespace.release();at_release=list(backend.events);unproved=namespace.close()
record("a release before close closes the control pipe once, and close then only waits for the anchor",
       raised is None and released is True and at_release==OPEN+RESET+END[:1]
       and backend.events==OPEN+RESET+END and unproved is False and namespace.reaped
       and not namespace.killed and not backend.violations,(at_release,backend.events,backend.violations))
backend=Backend(close_control_write=OSError(errno.EIO,"close failed"));namespace,raised=opened(backend)
namespace.restore();released=namespace.release();flag=namespace.unproved;unproved=namespace.close()
record("a failed release before close is unproved, and close kills the anchor at once",
       raised is None and released is False and flag and unproved is True and namespace.reaped
       and namespace.killed and backend.events==OPEN+RESET+END[:1]+[("children",),("waitpid","anchor"),
       ("kill","anchor",signal.SIGKILL),("children",),("waitpid","anchor"),("close","own")] and not backend.violations,
       (backend.events,backend.violations))

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

CLOSED=[("close","control_read"),("close","control_write"),("close","ready_read"),("close","ready_write"),("close","own")]
for label,fault,expected in (
    ("an unreadable own namespace",{"open":OSError(errno.EACCES,"denied")},OPEN[:1]),
    ("an unreadable child namespace link",{"stat":OSError(errno.ENOENT,"absent")},OPEN[:3]+CLOSED[4:]),
    ("a failed control pipe",{"pipe":OSError(errno.EMFILE,"no descriptor")},OPEN[:4]+CLOSED[4:]),
    ("a failed ready pipe",{"pipe":[None,OSError(errno.EMFILE,"no descriptor")]},OPEN[:5]+CLOSED[:2]+CLOSED[4:]),
    ("a refused namespace",{"unshare":PermissionError(errno.EPERM,"refused")},OPEN[:6]+CLOSED),
    ("a failed anchor fork",{"fork_anchor":OSError(errno.ENOMEM,"no process")},OPEN[:7]+RESET+CLOSED)):
    backend=Backend(**fault);namespace,raised=opened(backend);namespace.restore();unproved=namespace.close()
    record(label+" means no anchor, and everything opened is closed",
           isinstance(raised,OSError) and backend.events==expected and not backend.forked
           and not backend.descriptors and backend.home and unproved is False and not backend.violations,
           (raised,backend.events,backend.violations))

backend=Backend(close_control_read=OSError(errno.EIO,"close failed"));namespace,raised=opened(backend)
flag=namespace.unproved;namespace.restore();unproved=namespace.close()
record("a failed close of the anchor's pipe end is unproved, and the anchor is still ended and reaped",
       isinstance(raised,OSError) and flag and unproved is True and namespace.reaped and not namespace.killed
       and backend.events==OPEN[:8]+RESET+END[:1]+[("close","ready_read"),("close","ready_write")]+END[1:]
       and not backend.descriptors and not backend.violations,(raised,backend.events))

# The anchor reports ready only after the kernel accepted its parent-death
# signal; no fixed child is spawned before that byte.
backend=Backend(ready_word=b"",anchor_status=1<<8);namespace,raised=opened(backend)
namespace.restore();unproved=namespace.close()
record("an anchor that does not report ready refuses the command, and its end is unproved",
       literal(raised)=="child_namespace_unproved" and backend.events==OPEN+RESET+END and unproved is True
       and namespace.reaped and not backend.descriptors and not backend.violations,(raised,backend.events))
backend=Backend(read=OSError(errno.EIO,"read failed"));namespace,raised=opened(backend)
namespace.restore();unproved=namespace.close()
record("a failed read of the ready pipe refuses the command, and close closes the pipe and reaps the anchor",
       isinstance(raised,OSError) and backend.events==OPEN[:10]+RESET+END[:1]+[("close","ready_read")]+END[1:]
       and namespace.reaped and not backend.descriptors and not backend.violations,(raised,backend.events))

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
		"a release before close closes the control pipe once, and close then only waits for the anchor",
		"a failed release before close is unproved, and close kills the anchor at once",
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
		"a failed ready pipe means no anchor, and everything opened is closed",
		"a refused namespace means no anchor, and everything opened is closed",
		"a failed anchor fork means no anchor, and everything opened is closed",
		"a failed close of the anchor's pipe end is unproved, and the anchor is still ended and reaped",
		"an anchor that does not report ready refuses the command, and its end is unproved",
		"a failed read of the ready pipe refuses the command, and close closes the pipe and reaps the anchor",
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

// The end of a namespace before the cleanup of its fixed child. It closes the
// control pipe and sends the anchor, the collector's unreaped child, one
// KILL, so that nothing a process of the namespace does to the pipe or to the
// anchor keeps the namespace alive. It then waits without a time limit until
// the fixed child is terminal, and only after that lists the collector's
// children: each child outside the collector's own PID namespace but the
// anchor and the fixed child is a stray that the fixed command made, and is
// reaped once it has ended and never signaled. It returns only when one list
// holds no stray, so a stray that a stray made while a list was read is
// reaped too. The fixed child stays unreaped for the cleanup owner. A child
// at home is never waited for or signaled.
func TestRemoteAlphaESServiceTLSStatusChildNamespaceEnd(t *testing.T) {
	const probe = remoteAlphaESProcessIdentityLoader + remoteAlphaESChildNamespaceModel + `
module.CHILD_GRACE=1000.0
def spawned(**options):
    backend=Backend(**options);namespace,raised=opened(backend);namespace.restore();backend.spawn_fixed()
    return backend,namespace,raised,len(backend.events)
KILL=("kill","anchor",signal.SIGKILL)
def strays_reaped(backend):
    return all(pid in backend.reaped for wave in backend.waves for pid in wave)

backend,namespace,raised,count=spawned()
released=namespace.end(Backend.fixed);at_end=backend.events[count:];kept=backend._unreaped(Backend.fixed)
backend.reap_fixed();count=len(backend.events);unproved=namespace.close()
record("end closes the control pipe, kills the anchor once, and returns when the fixed child is terminal and no stray is listed",
       raised is None and released is True and at_end==[("close","control_write"),KILL,("terminal","fixed"),("children",)]
       and namespace.killed and backend.kills==[Backend.anchor] and not backend.violations,(raised,at_end))
record("end leaves the fixed child unreaped for the cleanup owner",kept,backend.reaped)
record("close after end only waits for the anchor, and a KILL that it did not need is no failure",
       backend.events[count:]==END[1:] and unproved is False and namespace.reaped and backend.kills==[Backend.anchor]
       and not backend.descriptors and not backend.violations,(unproved,backend.events[count:]))
backend,namespace,raised,count=spawned(anchor_status=signal.SIGKILL)
namespace.end(Backend.fixed);backend.reap_fixed();unproved=namespace.close()
record("an anchor that the end's KILL ended is accepted at close",
       unproved is False and namespace.reaped and namespace.killed,(unproved,backend.events))

backend,namespace,raised,count=spawned(strays=[[4101],[4102],[4103]])
namespace.end(Backend.fixed);lists=kinds(backend,"children");waited=kinds(backend,"waitpid")
backend.reap_fixed();unproved=namespace.close()
record("end reaps every stray, also one made while a list was read, and returns only after a list holds none",
       strays_reaped(backend) and len(lists)>=4 and waited.count(("waitpid","stray"))==3
       and unproved is False and namespace.reaped and backend.kills==[Backend.anchor] and not backend.violations,
       (backend.reaped,lists,waited,backend.events))
backend,namespace,raised,count=spawned(strays=[[4101]],stray_after_lists=4)
namespace.end(Backend.fixed);lists=len(kinds(backend,"children"))
record("a stray that ends late holds end until it is reaped",
       strays_reaped(backend) and lists>=5 and backend._unreaped(Backend.fixed) and not backend.violations,
       (lists,backend.reaped))
backend,namespace,raised,count=spawned(home_children=[3001],strays=[[4101]])
namespace.end(Backend.fixed);backend.reap_fixed();unproved=namespace.close()
record("a child at home is listed but never waited for or signaled",
       ("pid_namespace","home") in backend.events and ("waitpid","home") not in backend.events
       and backend.kills==[Backend.anchor] and strays_reaped(backend) and unproved is False and not backend.violations,
       backend.events)
backend,namespace,raised,count=spawned(fixed_after_polls=3)
namespace.end(Backend.fixed);seen=backend.events[count:]
record("end lists the children only after the fixed child is terminal",
       seen.count(("terminal","fixed"))==3 and seen.index(("children",))>len(seen)-2
       and seen.count(("children",))==1,seen)

backend,namespace,raised,count=spawned(strays=[[4101]],children=[OSError(errno.EIO,"read failed")])
released=namespace.end(Backend.fixed)
record("a failed list is unproved, and end lists again until a list holds no stray",
       released is True and namespace.unproved and strays_reaped(backend)
       and len(kinds(backend,"children"))>=3,backend.events[count:])
backend,namespace,raised,count=spawned(strays=[[4101]],waitpid_stray=[OSError(errno.EIO,"wait failed")])
namespace.end(Backend.fixed)
record("a failed wait for a stray is unproved, and the stray is still reaped",
       namespace.unproved and strays_reaped(backend) and not backend.violations,backend.events[count:])
backend,namespace,raised,count=spawned(kill=PermissionError(errno.EPERM,"refused"))
released=namespace.end(Backend.fixed)
record("a failed KILL of the anchor is unproved, and end returns without waiting",
       released is True and namespace.unproved and not namespace.killed
       and backend.events[count:]==[("close","control_write"),KILL],backend.events[count:])
backend,namespace,raised,count=spawned(close_control_write=OSError(errno.EIO,"close failed"))
released=namespace.end(Backend.fixed);backend.reap_fixed();unproved=namespace.close()
record("a failed release is returned, and the anchor is still killed",
       released is False and namespace.killed and unproved is True and namespace.reaped
       and backend.kills==[Backend.anchor] and not backend.violations,backend.events[count:])

# Without end, as when the spawn failed after Popen's fork, close reaps the
# child that Popen left in the namespace, or the anchor could never become
# terminal.
backend=Backend(strays=[[4101]]);namespace,raised=opened(backend);namespace.restore()
backend.forked.append(4101);count=len(backend.events);unproved=namespace.close()
record("close reaps a child that a failed spawn left in the namespace, and then the anchor",
       backend.events[count:]==END[:2]+[("pid_namespace","stray"),("waitpid","stray")]+END[2:]
       and unproved is False and namespace.reaped and not namespace.killed and strays_reaped(backend)
       and not backend.violations,backend.events[count:])
print(json.dumps({"cases":cases,"detail":detail}))
`
	result := runRemoteAlphaESProcessIdentityProbe(t, probe)
	assertRemoteAlphaESProcessIdentityCases(t, result,
		"end closes the control pipe, kills the anchor once, and returns when the fixed child is terminal and no stray is listed",
		"end leaves the fixed child unreaped for the cleanup owner",
		"close after end only waits for the anchor, and a KILL that it did not need is no failure",
		"an anchor that the end's KILL ended is accepted at close",
		"end reaps every stray, also one made while a list was read, and returns only after a list holds none",
		"a stray that ends late holds end until it is reaped",
		"a child at home is listed but never waited for or signaled",
		"end lists the children only after the fixed child is terminal",
		"a failed list is unproved, and end lists again until a list holds no stray",
		"a failed wait for a stray is unproved, and the stray is still reaped",
		"a failed KILL of the anchor is unproved, and end returns without waiting",
		"a failed release is returned, and the anchor is still killed",
		"close reaps a child that a failed spawn left in the namespace, and then the anchor")
}

// The second part of the capability probe accepts exactly one behavior: after
// the control pipe closes, the member is terminal by a KILL that the collector
// did not send, the anchor is not terminal while the member is unreaped, the
// ended member is listed among the collector's children outside its own PID
// namespace, as end() and close() find a stray, and the anchor then ends with
// status zero by itself. Every other answer refuses
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
        ("terminal","anchor"),("children",),("pid_namespace","member"),("waitpid","member"),("close","hold_write"),
        ("children",),("waitpid","anchor"),("close","own")])

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
backend,raised,witness=probed(member_unlisted=True)
record("a member that is not listed among the collector's children refuses the capability",
       refused(raised) and settled(backend) and not witness and kinds(backend,"kill")==[MEMBER_KILL],(raised,backend.events))
backend,raised,witness=probed(member_at_home=True)
record("a member that is listed in the collector's own PID namespace refuses the capability",
       refused(raised) and settled(backend) and not witness and kinds(backend,"kill")==[MEMBER_KILL],(raised,backend.events))
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
		"a member that is not listed among the collector's children refuses the capability",
		"a member that is listed in the collector's own PID namespace refuses the capability",
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
// spawn, and reset directly after the spawn attempt. On every path after the
// spawn the namespace is ended before the cleanup owner runs, so that a
// zombie which a descendant outside the group left unreaped in it, or a
// stray child of the collector, cannot hold the cleanup; a fixed child that
// still runs at a failure is then killed by the kernel. The close of the
// namespace comes last on every path. A refusal before the spawn opens
// nothing. What the close of the namespace leaves unproved makes an
// otherwise good command incomplete. The namespace here is
// a recorder, so this runs on every host; the process boundary is the shared
// local stand-in.
func TestRemoteAlphaESServiceTLSStatusChildNamespaceFixedCommand(t *testing.T) {
	const probe = remoteAlphaESProcessIdentityLoader + remoteAlphaESStatusLocalProcessBoundary + `
root=pathlib.Path(sys.argv[2]);child=root/"fixed-openssl"
child.write_text("#!/bin/sh\nprintf fixed\n");child.chmod(0o700);module.OPENSSL=str(child)
slow=root/"slow-openssl"
slow.write_text("#!/bin/sh\nexec sleep 30\n");slow.chmod(0o700)
order=[];made=[];plan={};spawned=[];at_release=[];ended=[]
class Recorder:
    def __init__(self):made.append(self)
    def open(self):
        order.append("open")
        if "open" in plan:raise plan["open"]
    def restore(self):
        order.append("restore")
        if "restore" in plan:raise plan["restore"]
    def end(self,fixed_child):
        # Whether the fixed child had ended when its namespace was ended.
        order.append("end");ended.append(fixed_child==spawned[-1].pid)
        at_release.append(module.waitid_terminal(spawned[-1].pid))
        return not plan.get("release_failed")
    def close(self):order.append("close");return bool(plan.get("close_unproved"))
module.ChildNamespace=Recorder
real_popen=module.subprocess.Popen
def popen(*args,**kwargs):
    order.append("spawn")
    if "spawn" in plan:raise plan["spawn"]
    proc=real_popen(*args,**kwargs);spawned.append(proc);return proc
module.subprocess.Popen=popen
real_owner=module.own_child_until_proved
def owner(proc):
    order.append("cleanup");return real_owner(proc)
module.own_child_until_proved=owner
def literal(exc):
    return exc.args[0] if isinstance(exc,module.Incomplete) and exc.args else type(exc).__name__
def command(argv=None,**changes):
    del order[:];del at_release[:];del ended[:];plan.clear();plan.update(changes);module.WITNESS_DISPOSITION_UNPROVED=False
    try:return module.run_fixed(argv or (module.OPENSSL,"version")),None,list(order)
    except BaseException as exc:return None,exc,list(order)
WHOLE=["open","spawn","restore","end","cleanup","close"]

before=len(made);result,raised,seen=command()
record("a good command opens, spawns, resets, ends its namespace, cleans up and closes the namespace in this order",
       result==(0,b"fixed",b"") and raised is None and seen==WHOLE
       and not module.WITNESS_DISPOSITION_UNPROVED,(result,raised,seen))
record("a good command ends its namespace only after the fixed child has ended, and names that child",
       at_release==[True] and ended==[True],(at_release,ended))
command()
record("each command has a namespace of its own",len(made)==before+2 and made[-1] is not made[-2],len(made)-before)
result,raised,seen=command(release_failed=True)
record("a failed release in the end leaves the result to the close of the namespace",
       result==(0,b"fixed",b"") and raised is None and seen==WHOLE,(result,raised,seen))

result,raised,seen=command(close_unproved=True)
record("a good command whose namespace close is unproved is incomplete",
       result is None and literal(raised)=="child_namespace_unproved" and seen==WHOLE
       and module.WITNESS_DISPOSITION_UNPROVED,(result,raised,seen))
reason=module._failure_reason("collection",raised)
record("an unproved namespace close is reported as an unproved OpenSSL child",
       reason=="openssl_child_unproved",reason)

for label,fault in (("a refused namespace",OSError(errno.EPERM,"refused")),
                    ("a missing namespace operation",module.Incomplete("process_capability_unavailable")),
                    ("children that are not created at home",module.Incomplete("child_namespace_unproved"))):
    result,raised,seen=command(open=fault)
    record(label+" means no spawn",
           result is None and literal(raised)=="child_spawn_unproved" and seen==["open","close"]
           and not module.WITNESS_DISPOSITION_UNPROVED,(result,raised,seen))

result,raised,seen=command(spawn=OSError(errno.ENOMEM,"no process"))
record("a failed spawn is followed by the reset and the close of the namespace",
       result is None and literal(raised)=="child_spawn_unproved" and seen==["open","spawn","restore","close"]
       and not module.WITNESS_DISPOSITION_UNPROVED,(result,raised,seen))
result,raised,seen=command(spawn=OSError(errno.ENOMEM,"no process"),close_unproved=True)
record("a failed command keeps its own reason when the namespace close is unproved too",
       result is None and literal(raised)=="child_spawn_unproved" and seen==["open","spawn","restore","close"]
       and module.WITNESS_DISPOSITION_UNPROVED,(result,raised,seen))

limit=module.MAX_OUTPUT;module.MAX_OUTPUT=2
result,raised,seen=command()
module.MAX_OUTPUT=limit
record("a command that fails after the spawn ends its namespace before the cleanup, as a good command does",
       result is None and literal(raised)=="child_output_overflow" and seen==WHOLE,(result,raised,seen))
fixed,limit=module.OPENSSL,module.CHILD_TIMEOUT;module.OPENSSL,module.CHILD_TIMEOUT=str(slow),0.2
result,raised,seen=command()
module.OPENSSL,module.CHILD_TIMEOUT=fixed,limit
record("a fixed child that is still running at its timeout has its namespace ended before the cleanup",
       result is None and literal(raised)=="child_timeout" and seen==WHOLE and at_release==[False],
       (result,raised,seen,at_release))
fixed=module.OPENSSL;module.OPENSSL=str(slow)
result,raised,seen=command(restore=OSError(errno.EPERM,"refused"))
module.OPENSSL=fixed
record("a failed reset after the spawn ends the namespace of a running fixed child before the cleanup",
       result is None and literal(raised)=="child_run_unproved" and seen==WHOLE and at_release==[False],
       (result,raised,seen,at_release))
result,raised,seen=command(spawn=OSError(errno.ENOMEM,"no process"),restore=OSError(errno.EPERM,"refused"))
record("a failed reset after a failed spawn ends nothing before the close of the namespace",
       result is None and literal(raised)=="child_spawn_unproved" and seen==["open","spawn","restore","close"],
       (result,raised,seen))

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
		"a good command opens, spawns, resets, ends its namespace, cleans up and closes the namespace in this order",
		"a good command ends its namespace only after the fixed child has ended, and names that child",
		"each command has a namespace of its own",
		"a failed release in the end leaves the result to the close of the namespace",
		"a good command whose namespace close is unproved is incomplete",
		"an unproved namespace close is reported as an unproved OpenSSL child",
		"a refused namespace means no spawn",
		"a missing namespace operation means no spawn",
		"children that are not created at home means no spawn",
		"a failed spawn is followed by the reset and the close of the namespace",
		"a failed command keeps its own reason when the namespace close is unproved too",
		"a command that fails after the spawn ends its namespace before the cleanup, as a good command does",
		"a fixed child that is still running at its timeout has its namespace ended before the cleanup",
		"a failed reset after the spawn ends the namespace of a running fixed child before the cleanup",
		"a failed reset after a failed spawn ends nothing before the close of the namespace",
		"a command without a proved capability opens no namespace",
		"a command that is not the fixed command opens no namespace")
}

// The anchor's own code, run for real in a forked child of the probe and
// without a namespace, so that it runs as any user. The probe is the anchor's
// parent and a child subreaper: a process that the anchor leaves unreaped
// stays with the probe as a zombie and shows. The anchor closes every
// inherited descriptor but its standard streams, the control pipe and the
// ready pipe, then reports ready with one byte and closes the ready pipe,
// reaps each process that ends while it waits, goes on doing so until the
// control pipe closes, however many poll periods that takes, and then ends
// with status zero. Inside a namespace the processes it reaps are the
// orphans of the namespace; here they are two children that end when the
// probe says so. An anchor whose parent ends is killed by the kernel, even
// while another process still holds its control pipe open. The order of the
// closing and the ready byte is decided without a race: the ready pipe is
// full when the anchor starts, so its byte waits until the probe reads.
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
first_go_r,first_go_w=os.pipe();second_go_r,second_go_w=os.pipe();ready_r,ready_w=os.pipe()
# The ready pipe is full before the anchor starts, so its one byte waits in
# the write until the probe reads. An anchor that closes what it inherited
# before it reports ready has closed it while it waits there; one that
# reports first still holds it, however fast it would close it afterwards.
os.set_blocking(ready_w,False);filled=0
for size in (65536,1):
    while True:
        try:filled+=os.write(ready_w,b"f"*size)
        except BlockingIOError:break
os.set_blocking(ready_w,True)
anchor=os.fork()
if anchor==0:
    try:
        for fd in (control_w,kept_r,report_r,first_go_w,second_go_w,ready_r):os.close(fd)
        members=[]
        for go in (first_go_r,second_go_r):
            pid=os.fork()
            if pid==0:
                for fd in (control_r,kept_w,report_w,first_go_r,second_go_r,ready_w):
                    if fd!=go:os.close(fd)
                os.read(go,1);os._exit(0)
            members.append(pid)
        os.write(report_w,("%d %d"%tuple(members)).encode())
        for fd in (report_w,first_go_r,second_go_r):os.close(fd)
    except BaseException:
        os._exit(3)
    module._child_namespace_anchor(control_r,ready_w)
    os._exit(4)
for fd in (control_r,kept_w,report_w,first_go_r,second_go_r,ready_w):os.close(fd)
first,second=(int(word) for word in os.read(report_r,64).split());os.close(report_r)
# Both wait for the probe, so both are alive here and each pidfd names it.
pidfds={first:os.pidfd_open(first),second:os.pidfd_open(second)}
# While the anchor's byte waits, the inherited write end of kept must already
# be closed: the probe reads the ready pipe only after that end of input.
ready,_write,_error=select.select([kept_r],[],[],20.0)
closed=bool(ready) and os.read(kept_r,1)==b""
data=b""
while len(data)<=filled:
    ready,_write,_error=select.select([ready_r],[],[],20.0)
    chunk=os.read(ready_r,65536) if ready else b""
    if not chunk:break
    data+=chunk
word=data[filled:]
# Once the byte is here, the anchor has closed what it inherited. A fork keeps
# the numbers of the descriptors, so the anchor's own list shows what is left.
held=sorted(int(name) for name in os.listdir("/proc/%d/fd"%anchor))
record("the anchor closes every inherited descriptor but its standard streams, the control pipe and the ready pipe before it reports ready",
       closed and data[:filled]==b"f"*filled and word==b"r" and set(held)<={0,1,2,control_r,ready_w}
       and not terminal(anchor),(closed,filled,len(data),word,held))
ready,_write,_error=select.select([ready_r],[],[],20.0)
record("the anchor reports ready with one byte and then closes the ready pipe",
       bool(ready) and os.read(ready_r,1)==b"" and not terminal(anchor),ready)
os.close(ready_r)
os.close(first_go_w)
record("the anchor reaps a process that ends while it waits",
       until(lambda:reaped(pidfds[first])) and not terminal(anchor),terminal(anchor))
os.close(second_go_w)
record("the anchor goes on reaping until its control pipe closes",
       until(lambda:reaped(pidfds[second])) and not terminal(anchor),terminal(anchor))
# A fixed command can run for many poll periods; the anchor ends only on the
# end of its input, never by a time of its own.
pause=50*module.CHILD_NAMESPACE_POLL;time.sleep(pause)
record("the anchor is still waiting after fifty poll periods without the end of its input",
       not terminal(anchor),pause)
os.close(control_w)
waited,status=os.waitpid(anchor,0)
record("the anchor ends with status zero when its control pipe closes",
       waited==anchor and os.WIFEXITED(status) and os.WEXITSTATUS(status)==0,status)
# A parent that ends. The probe keeps a write end of the control pipe, so the
# anchor never sees the end of its input; only the kernel can end it. The
# anchor comes to the probe, which adopts orphans, and the probe reaps it.
control_r,control_w=os.pipe();report_r,report_w=os.pipe()
parent=os.fork()
if parent==0:
    try:
        os.close(report_r);ready_r,ready_w=os.pipe()
        pid=os.fork()
        if pid==0:
            os.close(ready_r);os.close(report_w)
            module._child_namespace_anchor(control_r,ready_w)
            os._exit(4)
        os.close(ready_w);word=os.read(ready_r,1)
        os.write(report_w,("%d %s"%(pid,word.decode() or "-")).encode())
    except BaseException:pass
    os._exit(0)
os.close(control_r);os.close(report_w)
answer=os.read(report_r,64).decode().split();os.close(report_r);os.waitpid(parent,0)
orphan=int(answer[0]) if len(answer)==2 else -1
status=None;deadline=time.monotonic()+20.0
while orphan>0 and status is None and time.monotonic()<deadline:
    waited,code=os.waitpid(orphan,os.WNOHANG)
    if waited==orphan:status=code
    else:time.sleep(0.005)
os.close(control_w)
if orphan>0 and status is None:
    # The case failed; the end of its input ends the anchor.
    _waited,status=os.waitpid(orphan,0);status=("not killed",status)
record("an anchor whose parent ends is killed by the kernel while its control pipe is still open",
       len(answer)==2 and answer[1]=="r" and isinstance(status,int) and os.WIFSIGNALED(status)
       and os.WTERMSIG(status)==signal.SIGKILL,(answer,status))
# The two anchors were the probe's only children. A process that an anchor
# left behind came to the probe, which adopts orphans.
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
		"the anchor closes every inherited descriptor but its standard streams, the control pipe and the ready pipe before it reports ready",
		"the anchor reports ready with one byte and then closes the ready pipe",
		"the anchor reaps a process that ends while it waits",
		"the anchor goes on reaping until its control pipe closes",
		"the anchor is still waiting after fifty poll periods without the end of its input",
		"the anchor ends with status zero when its control pipe closes",
		"an anchor whose parent ends is killed by the kernel while its control pipe is still open",
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
			"time limit", "still runs as root",
			"on every path after the spawn the collector closes the control pipe before the cleanup owner runs",
			"no group signal can end", "without the grace period of TERM before KILL",
			"`prctl(PR_SET_PDEATHSIG)`", "ready byte", "`clone` and `CLONE_PARENT`", "stray",
			"waits without a time limit until the fixed child is terminal")
		assertContainsNone(t, label+" fixed-child containment", section,
			"best effort", "falls back to the process group when", "the fixed child may still run",
			"holds the invocation until the descendant ends by itself")
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
			"changes no process-group signal, hold, direct-child reap, lock, publication, public code, schema, reader, or retry authority",
			"before the cleanup owner runs", "a zombie that is not an orphan, so the anchor cannot reap it",
			"the zombie goes to the anchor, which reaps it",
			"fixed child that still runs at a timeout, an interruption, an output overflow, or a failed step after the spawn",
			"`/proc/self/task/<tid>/children`", "never signals it", "until one list of its children holds no stray",
			"read after the fixed child was seen terminal, is final",
			"the ended member must be listed among the collector's children outside its own PID namespace",
			"undo the anchor's parent-death signal", "keeps the anchor or a stray from becoming terminal")
	}

	fixtures := compactDocSection(t, mustRead(t, ".docs/system_overview/capability_probing.md"),
		"Tests of the Remote Alpha TLS status collector in `scripts/`", "")
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
		"_close_inherited_descriptors(control_read, ready_write)", "os.waitpid(-1, os.WNOHANG)",
		`if os.read(control_read, 1) == b"":`, "os._exit(code)", "PR_SET_PDEATHSIG", `os.write(ready_write, b"r")`)
	if got := strings.Count(source, "\nPR_SET_PDEATHSIG = 1\n"); got != 1 {
		t.Fatalf("collector declares PR_SET_PDEATHSIG = 1 %d times, want once", got)
	}
	// The anchor's code below its docstring is pinned whole. It asks for its
	// parent-death signal before it closes what it inherited, and reports
	// ready only after both. It ends only at the end of its input, on an
	// error, or by a KILL, so that no timer and no other exit can end a
	// namespace while its fixed command still runs; a test that waits can
	// bound such an exit only up to the length of its own command.
	const anchorCode = `    code = 1
    try:
        prctl = ctypes.CDLL(None, use_errno=True).prctl
        if prctl(ctypes.c_int(PR_SET_PDEATHSIG), ctypes.c_ulong(signal.SIGKILL), ctypes.c_ulong(0),
                 ctypes.c_ulong(0), ctypes.c_ulong(0)) != 0:
            raise OSError(ctypes.get_errno(), "prctl")
        _close_inherited_descriptors(control_read, ready_write)
        if os.write(ready_write, b"r") != 1:
            raise OSError(errno.EIO, "ready")
        os.close(ready_write)
        while True:
            ready, _write, _error = select.select([control_read], [], [], CHILD_NAMESPACE_POLL)
            try:
                while os.waitpid(-1, os.WNOHANG)[0] > 0:
                    pass
            except ChildProcessError:
                pass
            if ready:
                if os.read(control_read, 1) == b"":
                    code = 0
                break
    except BaseException:
        pass
    os._exit(code)
`
	docstringEnd := "\n    \"\"\"\n"
	if index := strings.Index(anchor, docstringEnd); index < 0 ||
		strings.TrimRight(anchor[index+len(docstringEnd):], "\n") != strings.TrimRight(anchorCode, "\n") {
		t.Fatalf("the namespace anchor's code is not the pinned code:\n%s", anchor)
	}
	namespace := docSection(t, source, "\nclass ChildNamespace:", "\ndef validate_child_namespace(")
	assertContainsAll(t, "collector child namespace", namespace,
		`backend.open("/proc/self/ns/pid", os.O_RDONLY | os.O_CLOEXEC)`,
		`self.backend.stat("/proc/self/ns/pid_for_children")`,
		"backend.unshare(backend.clone_newpid)",
		"self.backend.setns(self.own_fd, self.backend.clone_newpid)",
		"backend.waitpid(self.anchor, os.WNOHANG)", "backend.kill(self.anchor, signal.SIGKILL)",
		"word = backend.read(self.ready_read, 1)", "if word != b\"r\":",
		"if backend.terminal(fixed_child) and self._reap_strays(self.anchor, fixed_child) == 0:",
		"self._reap_strays(self.anchor)\n", "if backend.pid_namespace(pid) == self.home_ns:",
		"backend.waitpid(pid, os.WNOHANG)")
	assertContainsNone(t, "collector child namespace", namespace, "killpg", "scan_group_members", "listdir")
	// The namespace signals only its anchor, and only with KILL: a stray is
	// reaped and never signaled.
	if kills, anchorKills := strings.Count(namespace, "kill("), strings.Count(namespace, "backend.kill(self.anchor, signal.SIGKILL)"); kills != 2 || anchorKills != 2 {
		t.Fatalf("the namespace sends %d signals, %d of them a KILL to the anchor; want 2 and 2", kills, anchorKills)
	}
	// The ready byte is read before open() returns, and so before any spawn.
	open := docSection(t, namespace, "\n    def open(self)", "\n    def restore(self)")
	assertContainsAll(t, "collector namespace open", open, "word = backend.read(self.ready_read, 1)")
	fixed := docSection(t, source, "\ndef run_fixed(", "\ndef _run_fixed_in_namespace(")
	if got := strings.Count(fixed, "if namespace.close():"); got != 2 {
		t.Fatalf("run_fixed ends its namespace on %d paths, want on both", got)
	}
	assertContainsAll(t, "collector fixed command", fixed,
		"namespace = ChildNamespace()", `raise Incomplete("child_namespace_unproved")`)
	body := docSection(t, source, "\ndef _run_fixed_in_namespace(", "\ndef nested(")
	assertContainsAll(t, "collector fixed command body", body,
		"        namespace.open()\n        try:\n            proc = subprocess.Popen(",
		"        finally:\n            namespace.restore()\n",
		"            namespace.end(proc.pid)\n            cleanup_uncertain = own_child_until_proved(proc)\n            code = proc.returncode\n")
	// On every path after the spawn the namespace ends before the cleanup:
	// each call of the cleanup owner directly follows an end for the spawned
	// child, and a new call must be placed the same way. A bare release, which
	// leaves the end to the anchor, is not used here.
	owners, ends := 0, 0
	lines := strings.Split(body, "\n")
	for index, line := range lines {
		if strings.TrimSpace(line) == "namespace.end(proc.pid)" {
			ends++
		}
		if strings.Contains(line, "own_child_until_proved(") {
			owners++
			if index == 0 || strings.TrimSpace(lines[index-1]) != "namespace.end(proc.pid)" {
				t.Fatalf("a cleanup owner call does not directly follow an end: %q", line)
			}
		}
	}
	if owners != 3 || ends != 3 {
		t.Fatalf("the fixed command body has %d cleanup owner calls and %d ends, want 3 and 3", owners, ends)
	}
	assertContainsNone(t, "collector fixed command body", body, "namespace.release()")
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
//
// In the modes "zombie" and "qalive" the descendant first starts a child of
// its own, which stays in the fixed child's group and reports "held", and then
// leaves the group with setsid and ignores TERM and HUP. It does not reap that
// child: in "zombie" the child has ended before the fixed child does, in
// "qalive" it lives until a signal or the release ends it. The descendant
// itself ends after the number of seconds in the optional fourth argument
// (60 by default) or when the release file appears; only when the time ran
// out does it report "lapsed". Before it ends it closes the FIFO and then
// reaps its child.
//
// The modes "zombie-run" and "zombie-out" start the same descendant as
// "zombie", and the command then fails after the spawn. In "zombie-run" the
// fixed child itself stays, without its standard streams, until the release,
// so the command reaches its time limit while the fixed child still runs. In
// "zombie-out" the descendant keeps the fixed child's standard output open, so
// the fixed child ends but its output never does, and the command reaches its
// time limit after the fixed child has ended.
//
// In the mode "slow" the fixed child starts nothing and writes its output
// after one second, which is fifty poll periods of the anchor.
const remoteAlphaESChildNamespaceFixedChild = `
child=root/"fixed-openssl"
child.write_text('''#!/usr/bin/python3 -I
import os,signal,sys,time
mode,fifo,release=sys.argv[1:4]
lapse=float(sys.argv[4]) if len(sys.argv)>4 else 60.0
out=os.open(fifo,os.O_WRONLY)
ready_r,ready_w=os.pipe()
def say(label):
    os.write(out,("%s %d %d %d %d\\n"%(label,os.getpid(),os.getppid(),os.getpgid(0),os.getsid(0))).encode())
def detach(label,ignore=True,keep=()):
    for fd in (0,1,2,ready_r):
        if fd in keep:continue
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
if mode=="slow":
    time.sleep(1.0);sys.stdout.write("fixed");sys.stdout.flush();sys.exit(0)
if os.fork()==0:
    try:
        if mode in ("zombie","qalive","zombie-run","zombie-out"):
            held_r,held_w=os.pipe();held=os.fork()
            if held==0:
                for fd in (0,1,2,ready_r,ready_w,held_r):os.close(fd)
                say("held");os.write(held_w,b"h");os.close(held_w)
                if mode=="qalive":stay()
                os._exit(0)
            os.close(held_w);os.read(held_r,1);os.close(held_r)
            # A zombie of this process, which it does not reap.
            if mode!="qalive":os.waitid(os.P_PID,held,os.WEXITED|os.WNOWAIT)
            os.setsid();detach("escaped",keep=(1,) if mode=="zombie-out" else ());end=time.monotonic()+lapse
            while time.monotonic()<end and not os.path.exists(release):time.sleep(0.02)
            if not os.path.exists(release):say("lapsed")
            os.close(out);os.waitpid(held,0);os._exit(0)
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
if mode in ("linger","zombie-run"):
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
// A descendant that left the group can keep a child of its own in the group
// and leave it unreaped. That child is no orphan, and once it has ended no
// group signal can end its zombie. The namespace therefore ends before the
// cleanup when the fixed child has ended: the descendant is killed long
// before it would end by itself, and the cleanup does not wait for it. A
// fixed command that runs for many poll periods of the anchor returns its own
// output, so the anchor holds the namespace for as long as the command runs.
//
// The last cases are the controls. The same fixture without the namespace
// leaves the same descendant alive after the command returned, and a
// descendant that keeps an ended child in the group holds the cleanup until it
// ends by itself, so the cases above can fail.
func TestRemoteAlphaESServiceTLSStatusChildNamespaceRealDescendants(t *testing.T) {
	const probe = remoteAlphaESChildNamespaceRealPrelude + `
root=pathlib.Path(sys.argv[2])
` + remoteAlphaESChildNamespaceFixedChild + `
before=descriptors()
module.validate_process_capability();module.PROCESS_CAPABILITY_READY=True
took={}
def command(mode,tag,*extra):
    fifo=root/("events-"+tag);release=root/("release-"+tag)
    os.mkfifo(fifo);reader=os.open(fifo,os.O_RDONLY|os.O_NONBLOCK)
    started=time.monotonic()
    try:result=module.run_fixed((module.OPENSSL,mode,str(fifo),str(release))+extra);raised=None
    except BaseException as exc:result=None;raised=exc
    took[tag]=time.monotonic()-started
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
# The descendant would end by itself only after LAPSE seconds.
LAPSE=15.0
for mode,label in (("zombie","a descendant outside the group that keeps an ended child unreaped in it"),
                   ("qalive","a descendant outside the group that keeps a living child in it, unreaped once killed")):
    result,raised,alive,released,seen,orphans=command(mode,mode,str(LAPSE))
    record(label+" does not hold the cleanup and is gone when the command returns",
           result==(0,b"fixed",b"") and raised is None and alive is False and orphans==[]
           and "lapsed" not in seen and took[mode]<LAPSE
           and "held" in seen and seen["held"][2]==2 and "escaped" in seen and seen["escaped"][2]!=2,
           (result,raised,alive,orphans,took[mode],seen))
# The same descendant, and a command that fails after the spawn.
limit=module.CHILD_TIMEOUT;module.CHILD_TIMEOUT=1.0
for mode,label in (("zombie-run","a fixed child that still runs at its time limit"),
                   ("zombie-out","a fixed child that ended while a descendant keeps its output open")):
    result,raised,alive,released,seen,orphans=command(mode,mode,str(LAPSE))
    record(label+", with a descendant outside the group that keeps an ended child unreaped in it, does not hold the cleanup",
           result is None and isinstance(raised,module.Incomplete) and raised.args==("child_timeout",)
           and alive is False and orphans==[] and "lapsed" not in seen and took[mode]<LAPSE
           and "held" in seen and seen["held"][2]==2 and "escaped" in seen and seen["escaped"][2]!=2,
           (result,raised,alive,orphans,took[mode],seen))
module.CHILD_TIMEOUT=limit
result,raised,alive,released,seen,orphans=command("slow","slow")
record("a fixed command that runs for fifty poll periods of the anchor returns its own output",
       result==(0,b"fixed",b"") and raised is None and alive is False and orphans==[]
       and took["slow"]>=1.0,(result,raised,alive,orphans,took["slow"]))
record("the commands leave no child, descriptor or namespace setting, and nothing unproved",
       no_child() and descriptors()==before and at_home()
       and not module.WITNESS_DISPOSITION_UNPROVED,(descriptors(),before))
# The controls: the same fixture, and no namespace.
` + remoteAlphaESStatusLocalChildNamespace + `result,raised,alive,released,seen,orphans=command("setsid","control")
record("without the namespace the same descendant outlives the command",
       result==(0,b"fixed",b"") and raised is None and alive is True and released is True
       and orphans==[0] and "escaped" in seen,(result,raised,alive,released,orphans,seen))
result,raised,alive,released,seen,orphans=command("zombie","control-zombie","2")
record("without the namespace a descendant that keeps an ended child in the group holds the cleanup until it ends by itself",
       result==(0,b"fixed",b"") and raised is None and alive is False and orphans==[0]
       and "lapsed" in seen and took["control-zombie"]>=2.0,(result,raised,alive,orphans,took["control-zombie"],seen))
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
		"a descendant outside the group that keeps an ended child unreaped in it does not hold the cleanup and is gone when the command returns",
		"a descendant outside the group that keeps a living child in it, unreaped once killed does not hold the cleanup and is gone when the command returns",
		"a fixed child that still runs at its time limit, with a descendant outside the group that keeps an ended child unreaped in it, does not hold the cleanup",
		"a fixed child that ended while a descendant keeps its output open, with a descendant outside the group that keeps an ended child unreaped in it, does not hold the cleanup",
		"a fixed command that runs for fifty poll periods of the anchor returns its own output",
		"the commands leave no child, descriptor or namespace setting, and nothing unproved",
		"without the namespace the same descendant outlives the command",
		"without the namespace a descendant that keeps an ended child in the group holds the cleanup until it ends by itself")
}

// A collector that is killed in the middle of a fixed command takes the fixed
// child and its escaped descendant with it: its death ends the anchor, by the
// end of the control pipe or by the parent-death signal, whichever comes
// first, and the kernel kills what is left in the namespace. The collector
// here is a child of the probe that runs the real fixed command with a fixed
// child that never ends by itself. The control runs the same collector
// without the namespace, and there both processes outlive it.
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
# the kernel killed, and the anchor, which ended at the end of its input or by
# its parent-death signal.
record("after a killed collector the kernel killed the fixed child, and the anchor ended by the end of its input or its parent-death signal",
       started and orphans in ([0,signal.SIGKILL],[signal.SIGKILL,signal.SIGKILL]),(started,orphans,log))
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
		"after a killed collector the kernel killed the fixed child, and the anchor ended by the end of its input or its parent-death signal",
		"without the namespace the same processes outlive a killed collector")
}

// The stand-in for the fixed OpenSSL command of the red-team's cases (report
// 12-redteam.md of the workstream). It reports on the same FIFO as the
// stand-in above and in the same five fields, and the helpers above read it.
// Every process ends by itself when the release file appears, or after the
// number of seconds in the optional fourth argument (60 by default); only
// when the time ran out does it report "lapsed".
//
// In the modes "sibling" and "sibling-setsid" the fixed child makes one more
// process with clone and CLONE_PARENT. That process is in the namespace, and
// its parent is the fixed child's parent: the collector. It ignores TERM and
// HUP. In "sibling" it stays in the fixed child's group, in "sibling-setsid"
// it leaves it with setsid. The fixed child then writes its output and ends.
//
// The other modes start the descendant of the mode "zombie" above: it keeps
// an ended child of its own unreaped in the fixed child's group, leaves the
// group with setsid, and ignores TERM and HUP. Before that it makes the
// anchor deaf to the release. In the modes that start with "pipe" it opens
// the collector's end of the control pipe once more, through
// /proc/<collector>/fd, and reports "kept" with the number of descriptors it
// holds in the second field. In the modes that start with "stop" it stops
// the anchor, the first process of its namespace, with PTRACE_SEIZE and
// PTRACE_INTERRUPT, and reports "seized" with the error number of the seize
// in the second field, zero when the anchor is stopped. In the modes that
// end with "-run" the fixed child itself stays, without its standard
// streams, and no child is left unreaped in its group.
const remoteAlphaESChildNamespaceHostileChild = remoteAlphaESChildNamespaceFixedChild + `
hostile=root/"hostile-openssl"
hostile.write_text('''#!/usr/bin/python3 -I
import ctypes,os,signal,sys,time
mode,fifo,release=sys.argv[1:4]
lapse=float(sys.argv[4]) if len(sys.argv)>4 else 60.0
out=os.open(fifo,os.O_WRONLY)
ready_r,ready_w=os.pipe()
libc=ctypes.CDLL(None,use_errno=True)
def say(label,first=None):
    os.write(out,("%s %d %d %d %d\\n"%(label,os.getpid() if first is None else first,os.getppid(),os.getpgid(0),os.getsid(0))).encode())
def stay():
    end=time.monotonic()+lapse
    while time.monotonic()<end and not os.path.exists(release):time.sleep(0.02)
    if not os.path.exists(release):say("lapsed")
def deaf():
    for fd in (0,1,2,ready_r):os.close(fd)
    signal.signal(signal.SIGTERM,signal.SIG_IGN);signal.signal(signal.SIGHUP,signal.SIG_IGN)
def collector_pid():
    # /proc is the host's: the fourth field of this process's stat line is its
    # parent as the host numbers it.
    raw=open("/proc/self/stat","rb").read()
    return int(raw[raw.rfind(b")")+2:].split()[1])
say("fixed")
if mode.startswith("sibling"):
    # clone3 has the number 435 on every architecture. With CLONE_PARENT it
    # wants the exit signal zero: the kernel takes the caller's own.
    args=(ctypes.c_uint64*11)();args[0]=0x00008000
    pid=libc.syscall(435,ctypes.byref(args),ctypes.c_size_t(ctypes.sizeof(args)))
    if pid<0:say("refused",ctypes.get_errno());os._exit(1)
    if pid==0:
        try:
            deaf()
            if mode=="sibling-setsid":os.setsid()
            say("sibling");os.write(ready_w,b"r");os.close(ready_w);stay()
        except BaseException:pass
        os._exit(0)
else:
    collector=collector_pid()  # read in the fixed child, whose parent is the collector
    if os.fork()==0:
        try:
            deaf()
            if mode.startswith("pipe"):
                kept=[];base="/proc/%d/fd"%collector
                for name in os.listdir(base):
                    path=base+"/"+name
                    try:
                        # The control pipe is the one pipe that the collector holds for writing only.
                        if os.readlink(path).startswith("pipe:") and os.stat(path,follow_symlinks=False).st_mode&0o600==0o200:
                            kept.append(os.open(path,os.O_WRONLY|os.O_NONBLOCK))
                    except OSError:pass
                say("kept",len(kept))
            else:
                libc.ptrace.argtypes=(ctypes.c_long,ctypes.c_long,ctypes.c_void_p,ctypes.c_void_p)
                libc.ptrace.restype=ctypes.c_long
                refused=ctypes.get_errno() if libc.ptrace(0x4206,1,None,None)!=0 else 0  # PTRACE_SEIZE
                if refused==0:libc.ptrace(0x4207,1,None,None)  # PTRACE_INTERRUPT
                say("seized",refused)
            if not mode.endswith("-run"):
                held=os.fork()
                if held==0:say("held");os._exit(0)
                os.waitid(os.P_PID,held,os.WEXITED|os.WNOWAIT)
            os.setsid();say("escaped");os.write(ready_w,b"r");os.close(ready_w);stay()
        except BaseException:pass
        os._exit(0)
os.close(ready_w);os.read(ready_r,1)
if mode.endswith("-run"):
    for fd in (0,1,2):os.close(fd)
    stay();os._exit(0)
sys.stdout.write("fixed");sys.stdout.flush()
''')
hostile.chmod(0o700);module.OPENSSL=str(hostile)
`

// Red-team finding RT12-1. A process that the fixed child makes with clone
// and CLONE_PARENT is a child of the collector inside the namespace. The
// anchor reaps only the orphans of the namespace, and the kernel lets the
// anchor become terminal only when no process of the namespace is unreaped.
// Unreaped, the stray's zombie would hold the unchanged group cleanup when it
// stays in the fixed child's group, and the wait for the anchor otherwise;
// neither wait has a bound. The end of the namespace before the cleanup
// therefore reaps every such stray.
//
// Each case runs its own collector as a child of the probe, with the real
// probe and the real fixed command, and the probe gives it twenty seconds. A
// collector that has not returned by then is killed, and the case fails. A
// collector that returned must have returned the fixed child's output and
// left no process of the command and no child of its own.
func TestRemoteAlphaESServiceTLSStatusChildNamespaceRealSiblings(t *testing.T) {
	const probe = remoteAlphaESChildNamespaceRealPrelude + `
root=pathlib.Path(sys.argv[2])
` + remoteAlphaESChildNamespaceHostileChild + `
source='''import importlib.util,json,os,sys
spec=importlib.util.spec_from_file_location("status_collector_sibling",sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
module.OPENSSL=sys.argv[2]
module.validate_process_capability();module.PROCESS_CAPABILITY_READY=True
try:result=module.run_fixed((module.OPENSSL,sys.argv[5],sys.argv[3],sys.argv[4]));answer=["returned",result[0],result[1].decode()]
except module.Incomplete as exc:answer=["incomplete",exc.args[0]]
try:os.waitpid(-1,os.WNOHANG);child=True
except ChildProcessError:child=False
print(json.dumps({"answer":answer,"child":child}))
'''
BOUND=20.0
def bounded(mode):
    fifo=root/("events-"+mode);release=root/("release-"+mode);log=root/("collector-"+mode+".log")
    os.mkfifo(fifo);reader=os.open(fifo,os.O_RDONLY|os.O_NONBLOCK)
    with open(log,"wb") as errors:
        collector=subprocess.Popen(["/usr/bin/python3","-I","-B","-c",source,sys.argv[1],str(hostile),str(fifo),str(release),mode],
                                   stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=errors)
    started=time.monotonic()
    try:output,_=collector.communicate(timeout=BOUND);held=False
    except subprocess.TimeoutExpired:
        held=True;collector.kill();output,_=collector.communicate()  # this probe's own unreaped child
    took=time.monotonic()-started
    data,alive=drain(reader)
    released=let_go(reader,release) if alive else None
    os.close(reader)
    try:answer=json.loads(output)
    except ValueError:answer=None
    return held,took,answer,alive,released,reports(data),reap_all(30),log.read_bytes()[-2000:]
children=[]
for mode,label,inside in (("sibling","that stays in its group",True),
                          ("sibling-setsid","that left the group with setsid",False)):
    held,took,answer,alive,released,seen,orphans,log=bounded(mode)
    sibling=seen.get("sibling")
    record("the fixed child made a sibling "+label+": a child of the collector inside the namespace",
           seen.get("fixed")==[2,0,2,2] and sibling is not None and sibling[0]>2 and sibling[1]==0
           and (sibling[2]==2)==inside,(seen,log))
    record("a sibling of the fixed child "+label+" does not hold the command",
           held is False and answer is not None and answer["answer"]==["returned",0,"fixed"]
           and alive is False and "lapsed" not in seen and orphans==[],
           (held,took,answer,alive,released,orphans,seen,log))
    children.append(None if answer is None else answer["child"])
record("a collector that met a sibling of its fixed child has no child left when the command returned",
       children==[False,False],children)
print(json.dumps({"capability":True,"cases":cases,"detail":detail}))
`
	result := runRemoteAlphaESProcessIdentityProbe(t, probe, t.TempDir())
	requireRemoteAlphaESChildNamespaceKernel(t, result)
	assertRemoteAlphaESProcessIdentityCases(t, result,
		"the fixed child made a sibling that stays in its group: a child of the collector inside the namespace",
		"a sibling of the fixed child that stays in its group does not hold the command",
		"the fixed child made a sibling that left the group with setsid: a child of the collector inside the namespace",
		"a sibling of the fixed child that left the group with setsid does not hold the command",
		"a collector that met a sibling of its fixed child has no child left when the command returned")
}

// Red-team finding RT12-2. A process of the namespace can keep the anchor
// from acting on the end of its input: it holds the control pipe open, or it
// stops the anchor. Had the namespace ended only by that end of input, a
// descendant that keeps an ended child unreaped in the fixed child's group
// would hold the cleanup again until it ends by itself, and a killed
// collector would leave its fixed child and every descendant alive. The
// collector therefore sends the anchor one KILL before the cleanup, and the
// anchor asked the kernel to kill it when the collector dies.
//
// The first two cases run the real fixed command in this process, with a
// descendant that would end by itself only after LAPSE seconds. The last two
// kill a collector in the middle of a fixed command whose child never ends
// by itself, and give the kernel ten seconds. A kernel that refuses the
// ptrace request leaves the descendant of the "stop" modes no way to stop
// the anchor; the case then holds as it does for any other descendant.
func TestRemoteAlphaESServiceTLSStatusChildNamespaceRealDeafAnchor(t *testing.T) {
	const probe = remoteAlphaESChildNamespaceRealPrelude + `
root=pathlib.Path(sys.argv[2])
` + remoteAlphaESChildNamespaceHostileChild + `
before=descriptors()
module.validate_process_capability();module.PROCESS_CAPABILITY_READY=True
def attacked(mode,seen):
    # The descendant did to the anchor what its mode says, or the kernel refused it.
    if mode.startswith("pipe"):return "kept" in seen and seen["kept"][0]>=1
    return "seized" in seen
LAPSE=8.0
for mode,label in (("pipe-zombie","a descendant that keeps the control pipe open"),
                   ("stop-zombie","a descendant that stopped the anchor")):
    fifo=root/("events-"+mode);release=root/("release-"+mode)
    os.mkfifo(fifo);reader=os.open(fifo,os.O_RDONLY|os.O_NONBLOCK)
    started=time.monotonic()
    try:result=module.run_fixed((module.OPENSSL,mode,str(fifo),str(release),str(LAPSE)));raised=None
    except BaseException as exc:result=None;raised=exc
    took=time.monotonic()-started
    data,alive=drain(reader)
    released=let_go(reader,release) if alive else None
    os.close(reader);seen=reports(data);orphans=reap_all(30)
    record(label+" and an ended child unreaped in the group does not hold the cleanup and is gone when the command returns",
           result==(0,b"fixed",b"") and raised is None and alive is False and orphans==[]
           and "lapsed" not in seen and took<LAPSE and attacked(mode,seen)
           and "held" in seen and seen["held"][2]==2 and "escaped" in seen and seen["escaped"][2]!=2,
           (result,raised,alive,orphans,took,seen))
record("the commands leave no child, descriptor or namespace setting, and nothing unproved",
       no_child() and descriptors()==before and at_home()
       and not module.WITNESS_DISPOSITION_UNPROVED,(descriptors(),before))
source='''import importlib.util,os,sys
spec=importlib.util.spec_from_file_location("status_collector_deaf_anchor",sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
module.OPENSSL=sys.argv[2];module.CHILD_TIMEOUT=60.0
module.validate_process_capability();module.PROCESS_CAPABILITY_READY=True
module.run_fixed((module.OPENSSL,sys.argv[5],sys.argv[3],sys.argv[4]))
'''
for mode,label in (("pipe-run","a descendant keeps the control pipe open"),
                   ("stop-run","a descendant stopped the anchor")):
    fifo=root/("events-"+mode);release=root/("release-"+mode);log=root/("collector-"+mode+".log")
    os.mkfifo(fifo);reader=os.open(fifo,os.O_RDONLY|os.O_NONBLOCK)
    with open(log,"wb") as errors:
        collector=subprocess.Popen(["/usr/bin/python3","-I","-B","-c",source,sys.argv[1],str(hostile),str(fifo),str(release),mode],
                                   stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=errors)
    data=b"";deadline=time.monotonic()+60
    while b"escaped" not in data and time.monotonic()<deadline and collector.poll() is None:
        data+=drain(reader)[0];time.sleep(0.01)
    started=b"escaped" in data and collector.poll() is None
    collector.kill();collector.wait()  # this probe's own unreaped child
    gone=False;deadline=time.monotonic()+10
    while time.monotonic()<deadline and not gone:
        more,alive=drain(reader);data+=more;gone=not alive
        if not gone:time.sleep(0.01)
    released=let_go(reader,release) if not gone else None
    os.close(reader);seen=reports(data);orphans=reap_all(30)
    record("a killed collector takes its fixed child and every descendant with it although "+label,
           started and attacked(mode,seen) and gone is True and "lapsed" not in seen and orphans is not None,
           (started,gone,released,orphans,seen,log.read_bytes()[-2000:]))
print(json.dumps({"capability":True,"cases":cases,"detail":detail}))
`
	result := runRemoteAlphaESProcessIdentityProbe(t, probe, t.TempDir())
	requireRemoteAlphaESChildNamespaceKernel(t, result)
	assertRemoteAlphaESProcessIdentityCases(t, result,
		"a descendant that keeps the control pipe open and an ended child unreaped in the group does not hold the cleanup and is gone when the command returns",
		"a descendant that stopped the anchor and an ended child unreaped in the group does not hold the cleanup and is gone when the command returns",
		"the commands leave no child, descriptor or namespace setting, and nothing unproved",
		"a killed collector takes its fixed child and every descendant with it although a descendant keeps the control pipe open",
		"a killed collector takes its fixed child and every descendant with it although a descendant stopped the anchor")
}
