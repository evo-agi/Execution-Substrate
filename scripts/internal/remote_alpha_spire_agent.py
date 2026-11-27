"""SPIRE agent bootstrap trust and recovery on the Remote Alpha box.

Run through scripts/remote_alpha_spire_agent.sh as root on the box. Modes:

  status            read-only report: units, agent SVID expiry, bootstrap
                    mode, bootstrap bundle file and its freshness, the bundle
                    refresh timer, boot-time runtime directories
  pin [--apply]     export the server bundle over the admin socket, write it
                    to the bootstrap bundle file, replace insecure_bootstrap
                    with trust_bundle_path, add a tmpfiles.d rule for the
                    SPIRE runtime directories if none exists, restart the
                    agent, install the bundle refresh timer
  refresh [--apply] rewrite the bootstrap bundle file from the server bundle
                    when they differ, on a host already pinned; nothing else.
                    The refresh timer runs it every 6 hours
  recover [--apply] [--evict-old-agent]
                    re-attest an agent whose SVID expired (or that never
                    attested) with a fresh single-use join token, after the
                    same pinning steps

pin, recover and refresh only check and print their plan unless --apply is
given.
The contract is in .docs/system_overview/remote_supported_host_alpha.md,
section "Remote SPIRE Agent Bootstrap Trust And Recovery Helper".

Every path, account, unit and command is fixed in Layout. The entry point at
the bottom of this file uses Layout() unchanged and reads no environment
variable; tests import this file and pass their own Layout.

Root parses nothing that SPIRE produces. The server bundle, the bundle file
and the agent's own SVID are read and parsed (PEM, base64, openssl x509) only
in the SPIRE data check: this file's own code, run by root as the SPIRE
account through setpriv (spire_view_main). Root hands it the bytes it reads,
takes back a small JSON reply that it checks field by field, and writes the
bundle file from the reply after a size check, without parsing it.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import dataclasses
import datetime
import fcntl
import grp
import hashlib
import json
import math
import os
import pwd
import re
import selectors
import shutil
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import time

SCHEMA_VERSION = "execution-substrate.remote-alpha.spire-agent.v1"

PUBLIC_SCRIPT = "scripts/remote_alpha_spire_agent.sh"


@dataclasses.dataclass(frozen=True)
class Layout:
    """Everything the helper touches on the box. Defaults are the box values."""

    trust_domain: str = "execution.internal"
    # SPIFFE ID path that `token generate -spiffeID` gives a new agent. The
    # box's workload entries name it as their parent.
    agent_alias_path: str = "/spire-agent"
    # Workload SPIFFE ID that a process running as this helper's user (root
    # on the box) receives; used as the end-to-end Workload API check.
    workload_spiffe_id: str = "spiffe://execution.internal/workload"

    server_unit: str = "spire-server.service"
    agent_unit: str = "spire-agent.service"
    # Units that Require= the agent unit. A restart of the agent restarts
    # them; recover starts them again at its end.
    dependent_units: tuple = ("es.service",)

    spire_user: str = "spire"
    spire_group: str = "spire"
    # Owner of the files this helper writes outside SPIRE's own directories.
    file_owner: str = "root"
    file_group: str = "root"
    # The effective UID this helper must run with.
    required_euid: int = 0

    server_socket: str = "/run/spire/server/private/api.sock"
    agent_socket: str = "/run/spire/sockets/agent.sock"
    agent_config: str = "/etc/spire/agent/agent.conf"
    bundle_path: str = "/etc/spire/agent/bootstrap-bundle.pem"
    agent_data_dir: str = "/var/lib/spire/agent"
    # Mode for a new agent data directory when none exists to copy from.
    agent_data_dir_mode: int = 0o750
    runtime_dirs: tuple = (
        "/run/spire",
        "/run/spire/server",
        "/run/spire/server/private",
        "/run/spire/sockets",
    )
    runtime_dir_root: str = "/run"
    tmpfiles_root: str = "/"
    tmpfiles_path: str = "/etc/tmpfiles.d/spire.conf"
    # Directory holding the passwd and group files that a sandbox check of a
    # new tmpfiles.d rule resolves owners against.
    account_db_dir: str = "/etc"
    # tmpfs parent for the private directory that holds the join token.
    scratch_parent: str = "/run"
    # The lock file sits in a directory of its own directly in /run, so the
    # refresh unit can get write access to that directory alone (as its
    # RuntimeDirectory=) and not to the rest of /run.
    lock_path: str = "/run/execution-substrate-remote-alpha-spire-agent/lock"

    spire_server_bin: str = "/usr/local/bin/spire-server"
    spire_agent_bin: str = "/usr/local/bin/spire-agent"
    systemctl_bin: str = "/usr/bin/systemctl"
    setpriv_bin: str = "/usr/bin/setpriv"
    openssl_bin: str = "/usr/bin/openssl"
    tmpfiles_bin: str = "/usr/bin/systemd-tmpfiles"
    command_path_env: str = "/usr/sbin:/usr/bin:/sbin:/bin"

    # The bundle refresh timer that pin installs. The SPIRE server prepares
    # its next CA at half of the current CA's life and makes it active at
    # about five sixths, so a copy of the bundle goes stale within a third of
    # the CA lifetime (56 h for the host's ca_ttl of 168h). The timer runs
    # refresh every 6 hours from a root-owned copy of this file.
    systemd_unit_dir: str = "/etc/systemd/system"
    refresh_unit_name: str = "execution-substrate-spire-bundle-refresh"
    refresh_on_calendar: str = "*-*-* 00/6:00:00"
    installed_helper_path: str = "/usr/local/libexec/execution-substrate/remote_alpha_spire_agent.py"
    # Directories pin may create for the copy, outermost first; each must be
    # owned by file_owner and writable by no one else.
    installed_helper_dirs: tuple = ("/usr/local/libexec", "/usr/local/libexec/execution-substrate")
    # The interpreter and its options for the timer's runs: isolated mode
    # and no bytecode files as the wrapper script uses them, and -S, so that
    # no .pth file in a site directory runs code in the unattended root run.
    python_argv: tuple = ("/usr/bin/python3", "-I", "-B", "-S")
    # status: a server CA missing from the bundle file that was issued longer
    # ago than this is attention, since the timer should have added it.
    bundle_refresh_grace_seconds: int = 12 * 3600
    # Bounds on the server bundle, checked before any certificate is parsed
    # or written: its PEM text (and so the bundle file) at most this many
    # bytes, and at most this many certificates (the server publishes two or
    # three: the active CA, a prepared one, perhaps an old one).
    bundle_max_bytes: int = 1 << 20
    server_bundle_max_certificates: int = 16
    # Most bytes of stdout, and of stderr, kept from any command; a command
    # that prints more is stopped and the run fails.
    command_output_max_bytes: int = 4 << 20
    # Time limit for one run of the SPIRE data check (spire_view_main), which
    # runs spire-server bundle show and openssl for each certificate as the
    # SPIRE account; each of those commands has command_timeout_seconds.
    spire_view_timeout_seconds: int = 120

    join_token_ttl_seconds: int = 120
    # status reports "attention" below this many seconds of agent SVID life.
    svid_attention_seconds: int = 12 * 3600
    command_timeout_seconds: int = 30
    agent_health_timeout_seconds: int = 60
    attestation_timeout_seconds: int = 60
    workload_svid_timeout_seconds: int = 45
    dependent_unit_timeout_seconds: int = 60
    poll_interval_seconds: float = 0.5


# --------------------------------------------------------------------------
# Errors and reporting


class Refusal(Exception):
    """A precondition does not hold. Nothing was changed by this run."""


class Failure(Exception):
    """A step failed after this run started to change the box."""


class Interrupted(Failure):
    """SIGHUP, SIGINT or SIGTERM asked this run to stop."""


_STOP_SIGNALS = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)


def _stop_on_signal(signum, frame):
    # Ignore further stop signals so cleanup and rollback can finish.
    for sig in _STOP_SIGNALS:
        signal.signal(sig, signal.SIG_IGN)
    raise Interrupted(f"stopped by {signal.Signals(signum).name}")


@contextlib.contextmanager
def signals_deferred():
    """Hold stop signals while a cleanup or rollback step runs, so a first
    signal cannot cut it short; a held signal is delivered (and raises
    Interrupted) when the step ends. Yields the mask from before, which a
    process started inside must get back (children inherit the blocked mask)."""
    old = signal.pthread_sigmask(signal.SIG_BLOCK, _STOP_SIGNALS)
    try:
        yield old
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, old)


class CommandError(Exception):
    def __init__(self, message: str, returncode: int | None = None, output: str = ""):
        super().__init__(message)
        self.returncode = returncode
        self.output = output


_JOIN_TOKEN_ID_RE = re.compile(r"(spire/agent/join_token/)[^\s\"'/,;)\]}]+")


class Report:
    """Collects checks and actions. Everything it prints is redacted."""

    def __init__(self, mode: str, apply: bool):
        self.mode = mode
        self.apply = apply
        self.checks: list[dict] = []
        self.actions: list[str] = []
        self.plan: list[str] = []
        self.secrets: list[str] = []
        self.result = ""
        self.message = ""

    def redact(self, text: str) -> str:
        for secret in self.secrets:
            if secret:
                text = text.replace(secret, "<redacted>")
        return _JOIN_TOKEN_ID_RE.sub(r"\1<redacted>", text)

    def check(self, name: str, state: str, detail: str, **fields) -> None:
        entry = {"name": name, "state": state, "detail": detail}
        entry.update(fields)
        self.checks.append(entry)

    def action(self, text: str) -> None:
        self.actions.append(text)

    def planned(self, text: str) -> None:
        self.plan.append(text)

    def attention_count(self) -> int:
        return sum(1 for c in self.checks if c["state"] in ("attention", "fail"))

    def document(self) -> dict:
        doc = {
            "schema_version": SCHEMA_VERSION,
            "mode": self.mode,
            "apply": self.apply,
            "result": self.result,
            "message": self.message,
            "checks": self.checks,
            "plan": self.plan,
            "actions": self.actions,
        }
        return self._redact_tree(doc)

    def _redact_tree(self, value):
        # Redact each string where it stands. A regex over serialized JSON
        # can swallow the backslash of an escaped quote that follows an agent
        # ID (SPIRE logs spiffe_id="..."), which breaks the JSON.
        if isinstance(value, str):
            return self.redact(value)
        if isinstance(value, list):
            return [self._redact_tree(v) for v in value]
        if isinstance(value, dict):
            return {k: self._redact_tree(v) for k, v in value.items()}
        return value

    def render_text(self) -> str:
        doc = self.document()
        lines = [f"SPIRE agent {doc['mode']} ({SCHEMA_VERSION})"]
        for check in doc["checks"]:
            lines.append(f"  [{check['state']}] {check['name']}: {check['detail']}")
        if doc["plan"]:
            lines.append("Plan:" if not doc["apply"] else "Planned steps:")
            lines.extend(f"  - {step}" for step in doc["plan"])
        if doc["actions"]:
            lines.append("Changes made:")
            lines.extend(f"  - {step}" for step in doc["actions"])
        lines.append(f"Result: {doc['result']}" + (f" - {doc['message']}" if doc["message"] else ""))
        # Details can quote what SPIRE, systemd or openssl printed; control
        # characters in them must not reach the terminal as escapes.
        return _TERMINAL_UNSAFE_RE.sub("?", "\n".join(lines)) + "\n"


_TERMINAL_UNSAFE_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


# --------------------------------------------------------------------------
# Small helpers


def utc_now() -> float:
    return time.time()


def iso_utc(epoch: float) -> str:
    return datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def stamp_utc() -> str:
    return datetime.datetime.now(tz=datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def fingerprint(agent_id: str) -> str:
    return "sha256:" + hashlib.sha256(agent_id.encode("utf-8")).hexdigest()[:16]


def owner_names(st: os.stat_result) -> tuple[str, str]:
    try:
        user = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        user = str(st.st_uid)
    try:
        group = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        group = str(st.st_gid)
    return user, group


def describe(st: os.stat_result) -> str:
    user, group = owner_names(st)
    return f"{user}:{group} {stat.S_IMODE(st.st_mode):04o}"


def lstat_or_none(path: str) -> os.stat_result | None:
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None


def resolve_ids(user: str, group: str) -> tuple[int, int]:
    return pwd.getpwnam(user).pw_uid, grp.getgrnam(group).gr_gid


def read_regular_file(path: str, limit: int = 1 << 20) -> tuple[bytes, os.stat_result] | None:
    """Read a regular file without following a final symlink and without
    blocking on a FIFO. Returns None when the path does not exist."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise Refusal(f"cannot open {path}: {exc.strerror}") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise Refusal(f"{path} is not a regular file")
        if st.st_size > limit:
            raise Refusal(f"{path} is larger than {limit} bytes")
        chunks = []
        remaining = limit + 1
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > limit:
            raise Refusal(f"{path} is larger than {limit} bytes")
        return data, st
    finally:
        os.close(fd)


def fsync_dir(path: str) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(path: str, data: bytes, mode: int, uid: int, gid: int) -> None:
    """Replace path with data through a same-directory temporary file and a
    rename. The temporary file has its final owner and mode before the rename."""
    directory = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix="." + os.path.basename(path) + ".", suffix=".tmp", dir=directory)
    try:
        try:
            os.fchown(fd, uid, gid)
            os.fchmod(fd, mode)
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
    fsync_dir(directory)


def create_exclusive(path: str, data: bytes, mode: int, uid: int, gid: int) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    fsync_dir(os.path.dirname(path))


def take_new_dir(path: str, uid: int, gid: int, mode: int) -> None:
    """Give a directory this run has just created its final owner and mode.
    It acts through a descriptor opened without following symlinks, and only
    on an empty directory that this process still owns with no group or
    other access, so a symlink or another directory put in its place under
    the same name is refused, never handed over."""
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o077 or os.listdir(fd):
            raise Failure(f"{path} is no longer the empty directory this run created; it was left as it is")
        os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


# --------------------------------------------------------------------------
# Commands


class OutputTooLarge(CommandError):
    pass


def collect_output(proc: subprocess.Popen, stdin: bytes | None, limit: int, timeout: float) -> tuple[bytes, bytes]:
    """Feed stdin to a started process and read its stdout and stderr until
    it exits. A process that prints more than limit bytes on either, or runs
    past the timeout, is killed, and so is one this run stops waiting for
    (a stop signal)."""
    deadline = time.monotonic() + timeout
    pending = memoryview(stdin or b"")
    bufs = {proc.stdout: bytearray(), proc.stderr: bytearray()}
    sel = selectors.DefaultSelector()
    try:
        for f in bufs:
            sel.register(f, selectors.EVENT_READ)
        if proc.stdin is not None:
            os.set_blocking(proc.stdin.fileno(), False)
            if pending:
                sel.register(proc.stdin, selectors.EVENT_WRITE)
            else:
                proc.stdin.close()
        while sel.get_map():
            left = deadline - time.monotonic()
            if left <= 0:
                raise subprocess.TimeoutExpired(proc.args, timeout)
            for key, _ in sel.select(left):
                f = key.fileobj
                if f is proc.stdin:
                    try:
                        written = os.write(f.fileno(), pending[:65536])
                    except BlockingIOError:
                        continue
                    except BrokenPipeError:
                        written = len(pending)
                    pending = pending[written:]
                    if not pending:
                        sel.unregister(f)
                        f.close()
                    continue
                chunk = os.read(f.fileno(), 65536)
                if not chunk:
                    sel.unregister(f)
                    continue
                bufs[f] += chunk
                if len(bufs[f]) > limit:
                    raise OutputTooLarge("output limit")
        proc.wait(timeout=max(deadline - time.monotonic(), 0.001))
        return bytes(bufs[proc.stdout]), bytes(bufs[proc.stderr])
    except BaseException:
        proc.kill()
        proc.wait()
        raise
    finally:
        sel.close()
        for f in (proc.stdin, proc.stdout, proc.stderr):
            if f is not None:
                with contextlib.suppress(OSError):
                    f.close()


# True only in the SPIRE data check (spire_view_main), which root starts as
# the SPIRE account. The functions that parse what SPIRE produces call
# require_spire_view first, so a root process that reached one would stop
# with an error instead of parsing.
_IN_SPIRE_VIEW = False


def require_spire_view(what: str) -> None:
    if not _IN_SPIRE_VIEW:
        raise AssertionError(f"{what} parses data from SPIRE and runs only in the SPIRE data check, as the SPIRE account, never as root")


class Runner:
    def __init__(self, layout: Layout, report: Report):
        self.L = layout
        self.report = report

    def env(self) -> dict:
        return {"PATH": self.L.command_path_env, "LC_ALL": "C"}

    def as_spire(self, argv: list[str]) -> list[str]:
        if _IN_SPIRE_VIEW:
            # The SPIRE data check already runs as the SPIRE account.
            return list(argv)
        return [
            self.L.setpriv_bin,
            f"--reuid={self.L.spire_user}",
            f"--regid={self.L.spire_group}",
            "--init-groups",
            "--reset-env",
            "--",
        ] + argv

    def run(self, argv: list[str], *, spire: bool = False, stdin: bytes | None = None,
            timeout: float | None = None, check: bool = True, max_output: int | None = None) -> subprocess.CompletedProcess:
        full = self.as_spire(argv) if spire else list(argv)
        name = f"{os.path.basename(argv[0])} {' '.join(argv[1:3])}"
        limit = max_output if max_output is not None else self.L.command_output_max_bytes
        try:
            child = subprocess.Popen(
                full,
                stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self.env(),
                cwd="/",
            )
        except OSError as exc:
            raise CommandError(f"cannot run {argv[0]}: {exc.strerror}") from None
        try:
            out, err = collect_output(child, stdin, limit, timeout if timeout is not None else self.L.command_timeout_seconds)
        except subprocess.TimeoutExpired:
            raise CommandError(f"{name} timed out") from None
        except OutputTooLarge:
            raise OutputTooLarge(f"{name} printed more than {limit} bytes; it was stopped") from None
        proc = subprocess.CompletedProcess(full, child.returncode, out, err)
        if check and proc.returncode != 0:
            output = (proc.stderr or b"").decode("utf-8", "replace").strip() or (proc.stdout or b"").decode("utf-8", "replace").strip()
            raise CommandError(
                f"{os.path.basename(argv[0])} {' '.join(argv[1:3])} exited {proc.returncode}: {output[-600:]}",
                proc.returncode,
                output,
            )
        return proc

    def text(self, argv: list[str], **kwargs) -> str:
        return self.run(argv, **kwargs).stdout.decode("utf-8", "replace")

    # systemd

    def unit(self, unit: str) -> dict:
        out = self.text([
            self.L.systemctl_bin, "show", unit,
            "--property=ActiveState,SubState,MainPID,NRestarts,RuntimeDirectory,LoadState",
        ])
        props = {}
        for line in out.splitlines():
            key, sep, value = line.partition("=")
            if sep:
                props[key] = value
        return props

    def unit_props(self, unit: str, props: list[str]) -> dict:
        out = self.text([self.L.systemctl_bin, "show", unit, "--property=" + ",".join(props)])
        values = {}
        for line in out.splitlines():
            key, sep, value = line.partition("=")
            if sep:
                values[key] = value
        return values

    def unit_action(self, action: str, unit: str, timeout: float | None = None) -> None:
        self.run([self.L.systemctl_bin, action, unit], timeout=timeout or 120)

    # SPIRE server, always as the spire account over the admin socket

    def server_json(self, args: list[str]) -> dict:
        out = self.text([self.L.spire_server_bin] + args + ["-socketPath", self.L.server_socket, "-output", "json"], spire=True)
        try:
            doc = json.loads(out)
        except (ValueError, RecursionError):
            # RecursionError: JSON nested deeper than Python's decoder goes.
            raise CommandError(f"spire-server {' '.join(args[:2])} printed no JSON") from None
        if not isinstance(doc, dict):
            raise CommandError(f"spire-server {' '.join(args[:2])} printed unexpected JSON")
        return doc


# --------------------------------------------------------------------------
# The SPIRE data check
#
# Everything SPIRE produces that the helper parses as certificates (the
# server bundle, the bundle file it was copied into, the agent's own SVID)
# is parsed in a separate process that root starts as the SPIRE account:
# setpriv, then python_argv with SPIRE_VIEW_BOOT, which reads this file's
# own code from stdin, runs it as a module and calls spire_view_main with
# the request that follows. That process runs spire-server and openssl
# itself, so a flaw in openssl or in the PEM parsing gives no more than the
# SPIRE account already has. Root reads its reply as JSON, checks every
# field (check_bundle_reply, check_agent_reply), and takes the bundle's PEM
# text as opaque bytes: it checks their size and characters and writes them,
# and parses nothing in them.

SPIRE_VIEW_BOOT = (
    "import sys, types\n"
    "data = sys.stdin.buffer\n"
    "source = data.read(int(data.readline()))\n"
    "mod = types.ModuleType('remote_alpha_spire_agent_view')\n"
    "mod.__file__ = 'remote_alpha_spire_agent.py'\n"
    "sys.modules[mod.__name__] = mod\n"
    "exec(compile(source, mod.__file__, 'exec'), mod.__dict__)\n"
    "sys.exit(mod.spire_view_main(data.read()))\n"
)

# This file's bytes, read once per run, for the SPIRE data check.
_OWN_SOURCE: bytes | None = None


def own_source(L: Layout) -> bytes:
    global _OWN_SOURCE
    if _OWN_SOURCE is None:
        _OWN_SOURCE = read_own_helper(L, for_install=False)
    return _OWN_SOURCE


def printable(text: str, limit: int) -> str:
    """text with every character outside printable ASCII replaced, cut to
    limit characters, for a reply that root shows in its report."""
    return re.sub(r"[^\x20-\x7e]", "?", text)[:limit]


def spire_view(r: Runner, request: dict, max_output: int) -> dict:
    """Root side: run the SPIRE data check as the SPIRE account and return
    its reply, a JSON object that the caller checks field by field."""
    L = r.L
    source = own_source(L)
    body = json.dumps(dict(request, layout=dataclasses.asdict(L)), sort_keys=True).encode("ascii")
    stdin = str(len(source)).encode("ascii") + b"\n" + source + body
    what = f"the SPIRE data check ({request['op']}) as {L.spire_user}"
    try:
        proc = r.run(list(L.python_argv) + ["-c", SPIRE_VIEW_BOOT], spire=True, stdin=stdin,
                     timeout=L.spire_view_timeout_seconds, max_output=max_output, check=False)
    except OutputTooLarge:
        raise CommandError(f"{what} printed more than {max_output} bytes; it was stopped") from None
    except CommandError as exc:
        raise CommandError(f"{what}: {exc}") from None
    if proc.returncode != 0:
        tail = printable((proc.stderr or b"").decode("utf-8", "replace").strip()[-600:], 600)
        raise CommandError(f"{what} exited {proc.returncode}: {tail}")
    try:
        reply = json.loads(proc.stdout)
    except (ValueError, RecursionError):
        raise CommandError(f"{what} printed no JSON") from None
    if not isinstance(reply, dict):
        raise CommandError(f"{what} printed JSON that is not an object")
    return reply


_REPLY_TEXT_RE = re.compile(r"[\x20-\x7e]*")
_REPLY_PEM_RE = re.compile(r"[A-Za-z0-9+/= \n-]+")


def _bad_reply(why: str):
    raise CommandError(f"the SPIRE data check's reply is not one root accepts: {why}")


def _reply_keys(value, keys: tuple, what: str) -> dict:
    if not isinstance(value, dict) or set(value) != set(keys):
        _bad_reply(f"{what} must be an object with exactly the keys {', '.join(keys)}")
    return value


def _reply_text(value, limit: int, what: str) -> str:
    if not isinstance(value, str) or len(value) > limit or not _REPLY_TEXT_RE.fullmatch(value):
        _bad_reply(f"{what} must be printable ASCII text of at most {limit} characters")
    return value


def check_bundle_reply(L: Layout, reply: dict, fetch_server: bool, sent_file: bool) -> tuple[dict, dict]:
    """Root side: the server and file parts of a bundle reply, each checked
    against the only shapes view_bundle produces."""
    _reply_keys(reply, ("server", "file"), "the reply")
    srv = reply["server"]
    if not fetch_server:
        if srv is not None:
            _bad_reply("it holds a server bundle that was not asked for")
        server = {"state": "skipped"}
    elif isinstance(srv, dict) and srv.get("ok") is True:
        _reply_keys(srv, ("ok", "pem", "count"), "the server part")
        pem, count = srv["pem"], srv["count"]
        if not isinstance(pem, str) or not 0 < len(pem) <= L.bundle_max_bytes or not _REPLY_PEM_RE.fullmatch(pem):
            _bad_reply(f"the server bundle must be PEM characters only, 1 to {L.bundle_max_bytes} of them")
        if type(count) is not int or not 1 <= count <= L.server_bundle_max_certificates:
            _bad_reply(f"the certificate count must be a whole number from 1 to {L.server_bundle_max_certificates}")
        server = {"state": "ok", "bundle": ServerBundle(pem.encode("ascii"), count)}
    elif isinstance(srv, dict) and srv.get("ok") is False:
        _reply_keys(srv, ("ok", "kind", "error"), "the server part")
        if srv["kind"] not in ("refusal", "command"):
            _bad_reply("the server error kind must be refusal or command")
        server = {"state": "refused" if srv["kind"] == "refusal" else "failed",
                  "reason": _reply_text(srv["error"], 2000, "the server error")}
    else:
        _bad_reply("the server part must say ok true or false")
    f = reply["file"]
    if not sent_file:
        if f is not None:
            _bad_reply("it holds a file state for a file that was not sent")
        return server, {}
    state = f.get("state") if isinstance(f, dict) else None
    ok = server["state"] == "ok"
    if state == "unparseable" or (state == "unknown" and not ok) or (state == "matches" and ok):
        _reply_keys(f, ("state",), "the file part")
        return server, {"state": state}
    if state == "differs" and ok and isinstance(f, dict) and "coverage" in f:
        _reply_keys(f, ("state", "coverage"), "the file part")
        cov = _reply_keys(f["coverage"], ("state", "detail"), "the coverage verdict")
        if cov["state"] not in ("ok", "info", "attention"):
            _bad_reply("the coverage state must be ok, info or attention")
        return server, {"state": "differs", "coverage": {"state": cov["state"], "detail": _reply_text(cov["detail"], 8000, "the coverage detail")}}
    if state == "differs" and ok:
        _reply_keys(f, ("state", "error"), "the file part")
        return server, {"state": "differs", "error": _reply_text(f["error"], 2000, "the file error")}
    _bad_reply(f"the file state {state!r} does not fit the server part ({server['state']})")


def agent_view(r: Runner, data: bytes) -> dict:
    """Root side: the SPIRE data check's reading of agent-data.json."""
    reply = spire_view(r, {"op": "agent", "data": base64.b64encode(data).decode("ascii")}, max_output=64 << 10)
    return check_agent_reply(r.L, reply)


def check_agent_reply(L: Layout, reply: dict) -> dict:
    state = reply.get("state")
    if state == "not_json":
        _reply_keys(reply, ("state",), "the reply")
        return {"state": state}
    if state in ("unattested", "unreadable"):
        _reply_keys(reply, ("state", "reason"), "the reply")
        return {"state": state, "reason": _reply_text(reply["reason"], 500, "the reason")}
    if state != "attested":
        _bad_reply(f"the agent state {state!r} is not one view_agent gives")
    _reply_keys(reply, ("state", "agent_id", "not_after", "reattestable"), "the reply")
    agent_id, not_after, reattestable = reply["agent_id"], reply["not_after"], reply["reattestable"]
    prefix = f"spiffe://{L.trust_domain}/spire/agent/"
    if not isinstance(agent_id, str) or len(agent_id) > 2048 or not re.fullmatch(re.escape(prefix) + r"[\x21-\x7e]+", agent_id):
        _bad_reply(f"the agent ID must be printable ASCII without spaces under {prefix}")
    if type(not_after) not in (int, float) or not math.isfinite(not_after):
        _bad_reply("the SVID expiry must be a finite number")
    if type(reattestable) is not bool:
        _bad_reply("reattestable must be true or false")
    return {"state": state, "agent_id": agent_id, "not_after": float(not_after), "reattestable": reattestable}


def spire_view_main(raw: bytes) -> int:
    """The SPIRE data check's entry point. Root starts it as the SPIRE
    account (spire_view); it never runs in root's process. raw is the JSON
    request: the op, root's Layout, and the bytes root read."""
    global _IN_SPIRE_VIEW
    request = json.loads(raw)
    L = Layout(**{k: tuple(v) if isinstance(v, list) else v for k, v in request["layout"].items()})
    if os.geteuid() != pwd.getpwnam(L.spire_user).pw_uid:
        sys.stderr.write(f"the SPIRE data check runs only as {L.spire_user}, not as uid {os.geteuid()}\n")
        return 3
    _IN_SPIRE_VIEW = True
    r = Runner(L, Report("spire-view", False))
    if request["op"] == "bundle":
        reply = view_bundle(r, request)
    elif request["op"] == "agent":
        reply = view_agent(r, base64.b64decode(request["data"], validate=True))
    else:
        sys.stderr.write(f"unknown SPIRE data check {request['op']!r}\n")
        return 2
    sys.stdout.write(json.dumps(reply, sort_keys=True))
    sys.stdout.flush()
    return 0


# --------------------------------------------------------------------------
# Reading state


def spiffe_id(td_path: dict) -> str:
    if not isinstance(td_path, dict):
        return ""
    td, path = td_path.get("trust_domain", ""), td_path.get("path", "")
    if not isinstance(td, str) or not isinstance(path, str):
        return ""
    return f"spiffe://{td}{path}"


def server_items(doc: dict, key: str, what: str) -> list[dict]:
    """doc[key] from spire-server's JSON: a list of objects, or none."""
    items = doc.get(key)
    if items is None:
        return []
    if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
        raise CommandError(f"spire-server {what} printed {key} that is not a list of objects")
    return items


def list_agents(r: Runner) -> list[dict]:
    doc = r.server_json(["agent", "list"])
    if doc.get("next_page_token"):
        raise CommandError("spire-server agent list returned more than one page")
    agents = []
    for item in server_items(doc, "agents", "agent list"):
        try:
            expires = int(item.get("x509svid_expires_at", "0"))
        except (TypeError, ValueError, OverflowError):
            expires = 0
        agents.append({
            "id": spiffe_id(item.get("id")),
            "expires_at": expires,
            "banned": bool(item.get("banned")),
            "can_reattest": bool(item.get("can_reattest")),
            "attestation_type": str(item.get("attestation_type", "")),
        })
    return agents


def list_entries(r: Runner) -> list[dict]:
    doc = r.server_json(["entry", "show"])
    if doc.get("next_page_token"):
        raise CommandError("spire-server entry show returned more than one page")
    entries = []
    for item in server_items(doc, "entries", "entry show"):
        entries.append({
            "id": str(item.get("id", "")),
            "spiffe_id": spiffe_id(item.get("spiffe_id")),
            "parent_id": spiffe_id(item.get("parent_id")),
        })
    return entries


def openssl_cert_fields(r: Runner, data: bytes, der: bool) -> dict:
    require_spire_view("openssl x509")
    argv = [r.L.openssl_bin, "x509", "-noout", "-startdate", "-enddate", "-ext", "subjectAltName,basicConstraints"]
    if der:
        argv[2:2] = ["-inform", "DER"]
    out = r.text(argv, stdin=data)
    fields = {"uris": re.findall(r"URI:([^,\s]+)", out), "ca": bool(re.search(r"\bCA:TRUE\b", out))}
    for key, label in (("not_before", "notBefore"), ("not_after", "notAfter")):
        match = re.search(rf"^{label}=(.+)$", out, re.MULTILINE)
        if not match:
            raise CommandError(f"openssl printed no {label}")
        try:
            fields[key] = float(ssl.cert_time_to_seconds(match.group(1).strip()))
        except ValueError:
            raise CommandError(f"openssl printed an unreadable {label}") from None
    return fields


_PEM_CERT_RE = re.compile(r"-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=\n]+?)-----END CERTIFICATE-----\n?")


def parse_pem_certificates(text: str) -> list[bytes]:
    """Strict: the text must hold only CERTIFICATE blocks and whitespace."""
    require_spire_view("PEM parsing")
    if "\r" in text:
        raise ValueError("carriage return in PEM text")
    ders = []
    rest = _PEM_CERT_RE.sub(lambda m: (ders.append(m.group(1)), "")[1], text)
    if rest.strip():
        raise ValueError("text other than CERTIFICATE blocks")
    out = []
    for body in ders:
        try:
            out.append(base64.b64decode(body.replace("\n", ""), validate=True))
        except binascii.Error:
            raise ValueError("invalid base64 in a CERTIFICATE block") from None
    if not out:
        raise ValueError("no CERTIFICATE block")
    return out


def pem_encode(ders: list[bytes]) -> bytes:
    parts = []
    for der in ders:
        b64 = base64.b64encode(der).decode("ascii")
        parts.append("-----BEGIN CERTIFICATE-----\n")
        parts.extend(b64[i:i + 64] + "\n" for i in range(0, len(b64), 64))
        parts.append("-----END CERTIFICATE-----\n")
    return "".join(parts).encode("ascii")


def read_local_agent(r: Runner) -> dict:
    """The agent's own identity from its data directory: state is one of
    valid, expired, unattested, unreadable. Root reads agent-data.json and
    the SPIRE data check parses it (view_agent)."""
    L = r.L
    data_dir_st = lstat_or_none(L.agent_data_dir)
    if data_dir_st is None:
        return {"state": "unattested", "reason": "agent data directory is missing"}
    if not stat.S_ISDIR(data_dir_st.st_mode):
        return {"state": "unreadable", "reason": "agent data path is not a directory"}
    path = os.path.join(L.agent_data_dir, "agent-data.json")
    for attempt in range(3):
        try:
            got = read_regular_file(path)
        except Refusal as exc:
            return {"state": "unreadable", "reason": str(exc)}
        if got is None:
            return {"state": "unattested", "reason": "agent-data.json is missing"}
        try:
            view = agent_view(r, got[0])
        except CommandError as exc:
            return {"state": "unreadable", "reason": str(exc)}
        if view["state"] != "not_json":
            break
        if attempt == 2:
            return {"state": "unreadable", "reason": "agent-data.json is not JSON"}
        # The agent may be rewriting the file.
        time.sleep(L.poll_interval_seconds)
    if view["state"] != "attested":
        return view
    state = "valid" if view["not_after"] > utc_now() else "expired"
    return {"state": state, "agent_id": view["agent_id"], "not_after": view["not_after"],
            "reattestable": view["reattestable"]}


def view_agent(r: Runner, data: bytes) -> dict:
    """In the SPIRE data check: the agent ID and SVID expiry in the bytes of
    agent-data.json (state attested), or why there is none."""
    L = r.L
    try:
        doc = json.loads(data)
    except (ValueError, RecursionError):
        return {"state": "not_json"}
    svid = doc.get("svid") if isinstance(doc, dict) else None
    if not isinstance(svid, list) or not svid:
        return {"state": "unattested", "reason": "agent-data.json holds no SVID"}
    try:
        pem = base64.b64decode(svid[0], validate=True).decode("ascii")
        leaf = parse_pem_certificates(_PEM_CERT_RE.search(pem).group(0))[0]
        fields = openssl_cert_fields(r, leaf, der=True)
    except (binascii.Error, UnicodeDecodeError, AttributeError, ValueError, TypeError, CommandError):
        return {"state": "unreadable", "reason": "the agent SVID in agent-data.json cannot be parsed"}
    prefix = f"spiffe://{L.trust_domain}/spire/agent/"
    if len(fields["uris"]) != 1 or not fields["uris"][0].startswith(prefix):
        return {"state": "unreadable", "reason": "the agent SVID does not name one agent ID in the trust domain"}
    return {"state": "attested", "agent_id": fields["uris"][0], "not_after": fields["not_after"],
            "reattestable": bool(doc.get("reattestable"))}


def check_server_socket(r: Runner) -> None:
    L = r.L
    st = lstat_or_none(L.server_socket)
    if st is None:
        raise Refusal(f"server admin socket {L.server_socket} is missing")
    if not stat.S_ISSOCK(st.st_mode):
        raise Refusal(f"server admin socket {L.server_socket} is not a socket")
    user, group = owner_names(st)
    if (user, group) != (L.spire_user, L.spire_group) or stat.S_IMODE(st.st_mode) != 0o600:
        raise Refusal(f"server admin socket is {describe(st)}, expected {L.spire_user}:{L.spire_group} 0600")
    # Only root and the SPIRE account may be able to replace the socket or
    # any directory above it up to the runtime root: each directory is owned
    # by one of them, is not world writable, and is group writable only for
    # a SPIRE group with no other member (listed or by primary group).
    parent = os.path.dirname(L.server_socket)
    root = os.path.normpath(L.runtime_dir_root)
    if os.path.commonpath([root, parent]) != root or parent == root:
        raise Refusal(f"server admin socket {L.server_socket} is not below {root}")
    while parent != root:
        pst = os.lstat(parent)
        puser, pgroup = owner_names(pst)
        pmode = stat.S_IMODE(pst.st_mode)
        group_ok = not pmode & 0o020 or (pgroup == L.spire_group and group_members(pgroup) <= {L.spire_user})
        if not stat.S_ISDIR(pst.st_mode) or puser not in (L.file_owner, L.spire_user) or pmode & 0o002 or not group_ok:
            raise Refusal(f"server admin socket directory {parent} is {describe(pst)}; only {L.file_owner} and {L.spire_user} may be able to write it")
        parent = os.path.dirname(parent)


def group_members(group: str) -> set[str]:
    """Listed members plus accounts whose primary group it is."""
    g = grp.getgrnam(group)
    return set(g.gr_mem) | {pw.pw_name for pw in pwd.getpwall() if pw.pw_gid == g.gr_gid}


def export_server_bundle(r: Runner) -> list[bytes]:
    """In the SPIRE data check: the trust domain's X.509 authorities, read as
    spire over the admin socket. A process that only holds the server's TCP
    port cannot answer there. Each authority must be a CA certificate for the
    trust domain, and at least one must not have expired."""
    L = r.L
    try:
        out = r.text([L.spire_server_bin, "bundle", "show", "-socketPath", L.server_socket, "-format", "pem"], spire=True, max_output=L.bundle_max_bytes)
    except OutputTooLarge:
        raise Refusal(f"spire-server bundle show printed more than {L.bundle_max_bytes} bytes") from None
    try:
        ders = parse_pem_certificates(out)
    except ValueError as exc:
        raise Refusal(f"spire-server bundle show output is not a PEM bundle: {exc}") from None
    if len(ders) > L.server_bundle_max_certificates:
        raise Refusal(f"the server bundle holds {len(ders)} certificates, more than the {L.server_bundle_max_certificates} this helper accepts")
    if len(pem_encode(ders)) > L.bundle_max_bytes:
        raise Refusal(f"the server bundle is larger than {L.bundle_max_bytes} bytes as a PEM file")
    now = utc_now()
    current = 0
    for der in ders:
        fields = openssl_cert_fields(r, der, der=True)
        if not fields["ca"] or fields["uris"] != [f"spiffe://{r.L.trust_domain}"]:
            raise Refusal("the server bundle holds a certificate that is not a CA certificate for the trust domain")
        if fields["not_after"] > now:
            current += 1
    if not current:
        raise Refusal("the server bundle holds no unexpired CA certificate")
    if len(set(ders)) != len(ders):
        raise Refusal("the server bundle repeats a certificate")
    return ders


@dataclasses.dataclass(frozen=True)
class ServerBundle:
    """The server bundle as the SPIRE data check checked it: its canonical
    PEM text, which root writes to the bundle file without parsing, and the
    number of CA certificates in it."""

    pem: bytes
    count: int


def bundle_file_bytes(r: Runner) -> tuple[dict, bytes | None]:
    """Root side: what lstat says about the bundle file, and its bytes when
    it is a regular file within the size bound."""
    L = r.L
    st = lstat_or_none(L.bundle_path)
    if st is None:
        return {"state": "absent"}, None
    if not stat.S_ISREG(st.st_mode):
        return {"state": "not_regular", "meta": describe(st)}, None
    if st.st_size > L.bundle_max_bytes:
        return {"state": "oversized", "meta": describe(st)}, None
    got = read_regular_file(L.bundle_path, limit=L.bundle_max_bytes)
    if got is None:
        return {"state": "absent"}, None
    return {"state": "read", "meta": describe(got[1])}, got[0]


def bundle_view(r: Runner, *, fetch_server: bool) -> tuple[dict, dict]:
    """Root side: the server bundle, fetched and checked by the SPIRE data
    check when fetch_server, and the bundle file's state against it. The
    server part is skipped, ok (with a ServerBundle), refused or failed (with
    a reason). The file part's state is absent, not_regular or oversized
    (from lstat, never parsed) or unparseable, unknown, matches or differs
    (from the SPIRE data check, with its coverage verdict or an error)."""
    file_state, data = bundle_file_bytes(r)
    if not fetch_server and data is None:
        return {"state": "skipped"}, file_state
    request = {"op": "bundle", "fetch_server": fetch_server,
               "file": None if data is None else base64.b64encode(data).decode("ascii")}
    reply = spire_view(r, request, max_output=2 * r.L.bundle_max_bytes + (64 << 10))
    server, file_reply = check_bundle_reply(r.L, reply, fetch_server, data is not None)
    if data is not None:
        file_state = dict(file_reply, meta=file_state["meta"])
    return server, file_state


def require_server_bundle(server: dict) -> ServerBundle:
    if server["state"] == "refused":
        raise Refusal(server["reason"])
    if server["state"] != "ok":
        raise CommandError(server.get("reason") or "the server bundle was not read")
    return server["bundle"]


def view_bundle(r: Runner, request: dict) -> dict:
    """In the SPIRE data check: the server bundle (when asked), checked by
    export_server_bundle, and the bundle file's bytes against it."""
    server, server_ders = None, None
    if request["fetch_server"]:
        try:
            server_ders = export_server_bundle(r)
            server = {"ok": True, "pem": pem_encode(server_ders).decode("ascii"), "count": len(server_ders)}
        except Refusal as exc:
            server = {"ok": False, "kind": "refusal", "error": printable(str(exc), 2000)}
        except CommandError as exc:
            server = {"ok": False, "kind": "command", "error": printable(str(exc), 2000)}
    file = None
    if request["file"] is not None:
        file = view_bundle_file(r, base64.b64decode(request["file"], validate=True), server_ders)
    return {"server": server, "file": file}


def view_bundle_file(r: Runner, data: bytes, server_ders: list[bytes] | None) -> dict:
    try:
        file_ders = parse_pem_certificates(data.decode("ascii"))
    except (ValueError, UnicodeDecodeError):
        return {"state": "unparseable"}
    if server_ders is None:
        return {"state": "unknown"}
    if set(file_ders) == set(server_ders) and len(file_ders) == len(server_ders):
        return {"state": "matches"}
    try:
        return {"state": "differs", "coverage": bundle_coverage(r, file_ders, server_ders)}
    except CommandError as exc:
        return {"state": "differs", "error": printable(str(exc), 2000)}


def bundle_coverage(r: Runner, file_ders: list[bytes], server_ders: list[bytes]) -> dict:
    """How a bundle file that differs from the server bundle serves a fresh
    bootstrap. The server's own certificate chains to its active CA, which is
    always an unexpired CA of the server bundle, and a CA the server has
    prepared becomes active at about five sixths of its predecessor's life.
    So the file needs every unexpired server CA, and should trust no
    unexpired CA the server no longer publishes. A missing CA issued within
    the grace period is the timer's next run to add (info); one issued
    earlier, or an extra CA, needs attention. A difference in expired CAs
    alone is harmless (ok)."""
    L = r.L
    fix = f"run sudo {PUBLIC_SCRIPT} refresh --apply"
    if len(file_ders) > L.server_bundle_max_certificates:
        return {"state": "attention", "detail": f"holds {len(file_ders)} certificates, more than the {L.server_bundle_max_certificates} this helper accepts in a bundle; {fix}"}
    now = utc_now()
    fresh, stale, extra = [], [], []
    for der in server_ders:
        if der in file_ders:
            continue
        fields = openssl_cert_fields(r, der, der=True)
        if fields["not_after"] <= now:
            continue
        (fresh if fields["not_before"] > now - L.bundle_refresh_grace_seconds else stale).append(fields)
    for der in file_ders:
        if der in server_ders:
            continue
        fields = openssl_cert_fields(r, der, der=True)
        if fields["not_after"] > now:
            extra.append(fields)
    hours = L.bundle_refresh_grace_seconds / 3600
    problems = []
    if stale:
        issued = ", ".join(iso_utc(f["not_before"]) for f in stale)
        problems.append(f"lacks {len(stale)} unexpired server CA certificate(s) issued more than {hours:g} h ago ({issued}); a fresh bootstrap fails once the server signs with it")
    if extra:
        until = ", ".join(iso_utc(f["not_after"]) for f in extra)
        problems.append(f"trusts {len(extra)} unexpired CA certificate(s) the server no longer publishes (valid until {until})")
    if problems:
        return {"state": "attention", "detail": "; ".join(problems) + f"; {fix}"}
    if fresh:
        issued = ", ".join(iso_utc(f["not_before"]) for f in fresh)
        return {"state": "info", "detail": f"lacks {len(fresh)} server CA certificate(s) issued in the last {hours:g} h ({issued}); the refresh timer adds it, or {fix}"}
    return {"state": "ok", "detail": "differs from the server bundle only in expired CA certificates"}


_BOOTSTRAP_KEYS = ("insecure_bootstrap", "trust_bundle_path", "trust_bundle_url",
                   "trust_bundle_format", "trust_bundle_unix_socket")


def analyze_agent_config(text: str, bundle_path: str) -> dict:
    """Classify the bootstrap lines of a hand-written agent.conf.

    insecure: exactly one `insecure_bootstrap = true` line inside the single
              `agent {` block, and no trust bundle key anywhere.
    pinned:   exactly one `trust_bundle_path = "<bundle_path>"` line inside
              the block, no insecure_bootstrap, trust_bundle_url or
              trust_bundle_unix_socket, and trust_bundle_format absent or
              "pem".
    Anything else is unrecognized. A key named anywhere outside such a line
    (a comment, a one-line block), a quoted key anywhere, a heredoc or a
    non-ASCII character makes the file unrecognized.
    """
    def unrecognized(reason: str) -> dict:
        return {"state": "unrecognized", "reason": reason}

    if "\r" in text:
        return unrecognized("carriage returns")
    if "/*" in text:
        return unrecognized("a block comment")
    if "<<" in text:
        return unrecognized("a heredoc")
    # HCL matches keys with Go's Unicode case folding (U+017F folds to "s")
    # and decodes escapes in quoted keys, wherever they stand on a line.
    if not text.isascii():
        return unrecognized("a non-ASCII character")
    if re.search(r'"\s*=', text):
        return unrecognized("a quoted key")
    lines = text.split("\n")
    opens = [i for i, line in enumerate(lines) if re.fullmatch(r"agent\s*\{\s*", line)]
    if len(opens) != 1:
        return unrecognized("not exactly one line `agent {`")
    start = opens[0]
    end = next((i for i in range(start + 1, len(lines)) if re.fullmatch(r"\}\s*", lines[i])), None)
    if end is None:
        return unrecognized("no closing `}` line for the agent block")
    found: dict[str, list[tuple[int, str]]] = {key: [] for key in _BOOTSTRAP_KEYS}
    for key in _BOOTSTRAP_KEYS:
        pattern = re.compile(r"\s*" + key + r"\s*=\s*(.*?)\s*")
        for i in range(start + 1, end):
            m = pattern.fullmatch(lines[i])
            if m:
                found[key].append((i, m.group(1)))
        # HCL matches keys without regard to case.
        if text.lower().count(key) != len(found[key]):
            return unrecognized(f"{key} appears outside a plain line of the agent block")
    insecure = found["insecure_bootstrap"]
    paths = found["trust_bundle_path"]
    if found["trust_bundle_url"] or found["trust_bundle_unix_socket"]:
        return unrecognized("trust_bundle_url or trust_bundle_unix_socket is set")
    if insecure and not paths and not found["trust_bundle_format"]:
        if len(insecure) == 1 and insecure[0][1] == "true":
            return {"state": "insecure", "line": insecure[0][0]}
        return unrecognized("insecure_bootstrap is not exactly one `= true` line")
    if paths and not insecure:
        formats = found["trust_bundle_format"]
        if len(formats) > 1 or (formats and formats[0][1] != '"pem"'):
            return unrecognized('trust_bundle_format is not absent or "pem"')
        if len(paths) == 1 and paths[0][1] == '"' + bundle_path + '"':
            return {"state": "pinned", "line": paths[0][0]}
        return unrecognized(f"trust_bundle_path is not exactly {bundle_path}")
    return unrecognized("neither one insecure_bootstrap line nor one trust_bundle_path line")


def pinned_config_text(text: str, bundle_path: str) -> str:
    analysis = analyze_agent_config(text, bundle_path)
    if analysis["state"] != "insecure":
        raise ValueError("config is not in the insecure state")
    lines = text.split("\n")
    line = lines[analysis["line"]]
    indent = line[: len(line) - len(line.lstrip())]
    lines[analysis["line"]] = f'{indent}trust_bundle_path = "{bundle_path}"'
    new_text = "\n".join(lines)
    if analyze_agent_config(new_text, bundle_path)["state"] != "pinned":
        raise ValueError("edited config does not classify as pinned")
    return new_text


def read_agent_config(r: Runner) -> tuple[bytes, os.stat_result, dict]:
    got = read_regular_file(r.L.agent_config)
    if got is None:
        raise Refusal(f"{r.L.agent_config} is missing")
    data, st = got
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Refusal(f"{r.L.agent_config} is not UTF-8") from None
    return data, st, analyze_agent_config(text, r.L.bundle_path)


def spire_confirms_pinned(r: Runner) -> tuple[bool, str]:
    """Ask SPIRE's own config parser whether agent.conf is pinned, since the
    line scan above can miss spellings HCL accepts. Plain validate refuses a
    config in which SPIRE sees no trust bundle and no insecure_bootstrap
    (say, a trust_bundle_path line swallowed by a heredoc). With -trustBundle
    on the command line, validate refuses a config that SPIRE reads as
    insecure ("only one of insecure_bootstrap or trust_bundle_path ...").
    The scan allows no other bundle source and no second spelling of the key
    (no quoted key, heredoc or non-ASCII character, and key names counted
    without regard to case), so a config that passes both is read by SPIRE
    with the one trust_bundle_path line the scan saw."""
    L = r.L
    for label, extra in (("plain", []),
                         ("with -trustBundle", ["-trustBundle", L.bundle_path, "-trustBundleFormat", "pem"])):
        proc = r.run([L.spire_agent_bin, "validate", "-config", L.agent_config] + extra, spire=True, check=False)
        if proc.returncode != 0:
            detail = (proc.stdout + proc.stderr).decode("utf-8", "replace").strip()[-400:]
            return False, f"spire-agent validate {label}: {detail}"
    return True, ""


def tmpfiles_coverage(r: Runner) -> dict:
    """Which runtime directories are recreated at boot, by a tmpfiles.d rule
    (as systemd-tmpfiles merges the configuration) or by a RuntimeDirectory=
    of the SPIRE units."""
    L = r.L
    out = r.text([L.tmpfiles_bin, f"--root={L.tmpfiles_root}", "--cat-config"])
    rule_paths = set()
    for raw in out.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) < 2 or fields[0][0] not in "dDvqQ":
            continue
        path = fields[1].replace("%t", L.runtime_dir_root)
        if "%" in path.replace("%%", ""):
            continue
        rule_paths.add(os.path.normpath(path.replace("%%", "%")))
    runtime_paths = set()
    for unit in (L.server_unit, L.agent_unit):
        for entry in r.unit(unit).get("RuntimeDirectory", "").split():
            path = os.path.normpath(os.path.join(L.runtime_dir_root, entry))
            while path.startswith(L.runtime_dir_root + "/"):
                runtime_paths.add(path)
                path = os.path.dirname(path)
    covered = {d: ("tmpfiles" if d in rule_paths else "RuntimeDirectory" if d in runtime_paths else "") for d in L.runtime_dirs}
    return {"covered": covered, "missing": [d for d in L.runtime_dirs if not covered[d]]}


_NAME_RE = re.compile(r"[a-z_][a-z0-9_-]*\$?")


def tmpfiles_lines(r: Runner, missing: list[str]) -> list[tuple[str, str, int, int, int]]:
    """One `d` line per missing runtime directory, copying its current owner
    and mode. Returns (line, path, mode, uid, gid) tuples."""
    lines = []
    for path in missing:
        st = lstat_or_none(path)
        if st is None or not stat.S_ISDIR(st.st_mode):
            raise Refusal(f"runtime directory {path} does not exist as a directory, so its owner and mode cannot be copied into a boot rule")
        user, group = owner_names(st)
        if not _NAME_RE.fullmatch(user) or not _NAME_RE.fullmatch(group) or re.search(r"\s", path):
            raise Refusal(f"runtime directory {path} has an owner, group or path that a tmpfiles.d line cannot hold")
        mode = stat.S_IMODE(st.st_mode)
        lines.append((f"d {path} {mode:04o} {user} {group} -", path, mode, st.st_uid, st.st_gid))
    return lines


def sandbox_check_tmpfiles(r: Runner, body: str, expected: list[tuple[str, str, int, int, int]]) -> None:
    """Apply the candidate rule with the box's own systemd-tmpfiles under an
    empty alternate root, and check it creates exactly the expected
    directories with the expected owner and mode. Nothing outside the
    sandbox is touched."""
    L = r.L
    sandbox = tempfile.mkdtemp(prefix="es-spire-tmpfiles-check.", dir=L.scratch_parent)
    try:
        os.mkdir(os.path.join(sandbox, "etc"), 0o755)
        for name in ("passwd", "group"):
            shutil.copyfile(os.path.join(L.account_db_dir, name), os.path.join(sandbox, "etc", name))
        candidate = os.path.join(sandbox, "candidate.conf")
        create_exclusive(candidate, body.encode("utf-8"), 0o644, os.geteuid(), os.getegid())
        proc = r.run([L.tmpfiles_bin, f"--root={sandbox}", "--create", candidate], check=False)
        if proc.returncode != 0:
            detail = (proc.stdout + proc.stderr).decode("utf-8", "replace").replace(sandbox, "<sandbox>").strip()[-400:]
            raise Failure(f"systemd-tmpfiles refused the new rule in a sandbox ({detail}); nothing was written")
        for _, path, mode, uid, gid in expected:
            st = lstat_or_none(sandbox + path)
            if st is None or not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode) != mode or (st.st_uid, st.st_gid) != (uid, gid):
                raise Failure(f"systemd-tmpfiles did not create {path} as the rule says in a sandbox; nothing was written")
    finally:
        with signals_deferred():
            shutil.rmtree(sandbox, ignore_errors=True)


# --------------------------------------------------------------------------
# Waiting


def wait_for(predicate, timeout: float, interval: float):
    deadline = time.monotonic() + timeout
    while True:
        value = predicate()
        if value:
            return value
        if time.monotonic() >= deadline:
            return value
        time.sleep(interval)


def agent_healthy(r: Runner) -> bool:
    try:
        return r.run([r.L.spire_agent_bin, "healthcheck", "-socketPath", r.L.agent_socket], spire=True, check=False, timeout=10).returncode == 0
    except CommandError:
        return False


def workload_svid_ok(r: Runner) -> bool:
    try:
        proc = r.run([r.L.spire_agent_bin, "api", "fetch", "x509", "-socketPath", r.L.agent_socket, "-timeout", "5s"], check=False, timeout=15)
    except CommandError:
        return False
    if proc.returncode != 0:
        return False
    ids = re.findall(r"^SPIFFE ID:\s*(\S+)\s*$", proc.stdout.decode("utf-8", "replace"), re.MULTILINE)
    return r.L.workload_spiffe_id in ids


def unit_active(r: Runner, unit: str) -> bool:
    return r.unit(unit).get("ActiveState") == "active"


# --------------------------------------------------------------------------
# Shared preflight and pinning steps


def require_root(L: Layout) -> None:
    if os.geteuid() != L.required_euid:
        raise UsageError(f"this helper must run as root; use: sudo {PUBLIC_SCRIPT} <mode>")


class UsageError(Exception):
    pass


def require_commands(L: Layout) -> None:
    paths = [getattr(L, name) for name in ("spire_server_bin", "spire_agent_bin", "systemctl_bin", "setpriv_bin", "openssl_bin", "tmpfiles_bin")]
    # python_argv[0] runs the SPIRE data check.
    for path in paths + [L.python_argv[0]]:
        if not os.path.isabs(path) or not os.access(path, os.X_OK):
            raise Refusal(f"required command {path} is missing or not executable")


def take_lock(L: Layout):
    """The lock file lives in a directory of its own, which the refresh unit
    names as its RuntimeDirectory=; a missing one is created here."""
    lock_dir = os.path.dirname(L.lock_path)
    with contextlib.suppress(FileExistsError):
        os.mkdir(lock_dir, 0o700)
    dst = os.lstat(lock_dir)
    if not stat.S_ISDIR(dst.st_mode) or dst.st_uid != os.geteuid() or stat.S_IMODE(dst.st_mode) & 0o022:
        raise Refusal(f"lock directory {lock_dir} is {describe(dst)}; it must be a directory owned by this user that no one else can write")
    fd = os.open(L.lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    st = os.fstat(fd)
    if st.st_uid != os.geteuid() or not stat.S_ISREG(st.st_mode):
        os.close(fd)
        raise Refusal(f"lock file {L.lock_path} is not a regular file owned by this user")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise Refusal("another run of this helper holds the lock") from None
    return fd


def require_server(r: Runner, rep: Report) -> None:
    unit = r.unit(r.L.server_unit)
    if unit.get("ActiveState") != "active":
        raise Refusal(f"{r.L.server_unit} is {unit.get('ActiveState', 'unknown')}; start it first")
    check_server_socket(r)
    rep.check("server", "ok", f"{r.L.server_unit} active; admin socket {r.L.spire_user}:{r.L.spire_group} 0600")


class Pinning:
    """The pinning steps shared by pin and recover."""

    def __init__(self, r: Runner, rep: Report):
        self.r = r
        self.rep = rep
        self.L = r.L
        self.server_bundle: ServerBundle | None = None
        self.bundle_state: dict = {}
        self.config_bytes = b""
        self.config_stat: os.stat_result | None = None
        self.config_state: dict = {}
        self.tmpfiles: dict = {}
        self.tmpfiles_new: list[tuple[str, str, int, int, int]] = []
        self.backup_path = ""
        self.config_changed = False

    def inspect(self) -> None:
        L = self.L
        self.config_bytes, self.config_stat, self.config_state = read_agent_config(self.r)
        if self.config_state["state"] == "unrecognized":
            raise Refusal(f"{L.agent_config} has a bootstrap setting this helper does not edit ({self.config_state['reason']}); edit it by hand")
        bundle_dir = os.path.dirname(L.bundle_path)
        dst = lstat_or_none(bundle_dir)
        if dst is None or not stat.S_ISDIR(dst.st_mode):
            raise Refusal(f"{bundle_dir} is not a directory")
        if self.config_state["state"] == "insecure":
            self.rep.check("bootstrap", "attention", "insecure_bootstrap = true")
        else:
            confirmed, detail = spire_confirms_pinned(self.r)
            if not confirmed:
                raise Refusal(f"{L.agent_config} reads as pinned to this helper, but SPIRE's own parser does not confirm it ({detail}); inspect it by hand")
            self.rep.check("bootstrap", "ok", f"trust_bundle_path = \"{L.bundle_path}\" (confirmed by spire-agent validate, plain and with -trustBundle)")
        server, self.bundle_state = bundle_view(self.r, fetch_server=True)
        self.server_bundle = require_server_bundle(server)
        if self.bundle_state["state"] == "not_regular":
            raise Refusal(f"{L.bundle_path} exists and is not a regular file")
        if self.bundle_state["state"] != "matches":
            self.rep.planned(f"write the server bundle ({self.server_bundle.count} CA certificate(s), read over the admin socket and checked as {L.spire_user}) to {L.bundle_path} as {L.file_owner}:{L.file_group} 0644 (file is {self.bundle_state['state']})")
        self.rep.check("bundle file", "ok" if self.bundle_state["state"] == "matches" else "info", f"{self.bundle_state['state']}")
        self.tmpfiles = tmpfiles_coverage(self.r)
        if self.tmpfiles["missing"]:
            self.tmpfiles_new = tmpfiles_lines(self.r, self.tmpfiles["missing"])
            if lstat_or_none(L.tmpfiles_path) is not None:
                raise Refusal(f"{L.tmpfiles_path} exists but does not recreate {', '.join(self.tmpfiles['missing'])}; edit it by hand")
            if not os.path.isdir(os.path.dirname(L.tmpfiles_path)):
                raise Refusal(f"{os.path.dirname(L.tmpfiles_path)} is not a directory")
            self.rep.planned(f"write {L.tmpfiles_path} so that boot recreates {', '.join(self.tmpfiles['missing'])} with their current owner and mode, after systemd-tmpfiles applies it as expected in a sandbox root")
            self.rep.check("reboot readiness", "attention", "no boot-time rule recreates " + ", ".join(self.tmpfiles["missing"]))
        else:
            self.rep.check("reboot readiness", "ok", "every SPIRE runtime directory is recreated at boot")
        if self.config_state["state"] == "insecure":
            self.rep.planned(f"replace insecure_bootstrap = true with trust_bundle_path = \"{L.bundle_path}\" in {L.agent_config}, keeping a timestamped backup, then run spire-agent validate as {L.spire_user}, plain and with -trustBundle {L.bundle_path}, and restore the backup if either refuses")

    def apply_bundle(self) -> None:
        if self.bundle_state["state"] == "matches":
            return
        write_bundle(self.r, self.rep, self.server_bundle)

    def apply_config(self) -> None:
        L = self.L
        if self.config_state["state"] != "insecure":
            return
        current = read_regular_file(L.agent_config)
        if current is None or current[0] != self.config_bytes:
            raise Failure(f"{L.agent_config} changed during this run; nothing was edited")
        st = self.config_stat
        new_text = pinned_config_text(self.config_bytes.decode("utf-8"), L.bundle_path)
        self.backup_path = f"{L.agent_config}.bak-{stamp_utc()}"
        create_exclusive(self.backup_path, self.config_bytes, stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid)
        self.rep.action(f"backed up {L.agent_config} to {self.backup_path}")
        self.config_changed = True
        try:
            atomic_write(L.agent_config, new_text.encode("utf-8"), stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid)
            self.rep.action(f"replaced insecure_bootstrap = true with trust_bundle_path = \"{L.bundle_path}\" in {L.agent_config}")
            confirmed, detail = spire_confirms_pinned(self.r)
            if not confirmed:
                raise Failure(f"spire-agent validate refused the edited config ({detail})")
        except BaseException as exc:
            self.restore_config()
            if isinstance(exc, Failure) and not isinstance(exc, Interrupted):
                raise Failure(f"{exc}; the original config was restored") from None
            raise
        self.rep.action("spire-agent validate accepted the edited config, plain and with -trustBundle")

    def restore_config(self) -> None:
        L = self.L
        st = self.config_stat
        with signals_deferred():
            atomic_write(L.agent_config, self.config_bytes, stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid)
            back = read_regular_file(L.agent_config)
            if back is None or back[0] != self.config_bytes:
                raise Failure(f"restoring {L.agent_config} from {self.backup_path} did not reproduce the original bytes")
            self.config_changed = False
            self.rep.action(f"restored the original {L.agent_config} (backup kept at {self.backup_path})")

    def apply_tmpfiles(self) -> None:
        L = self.L
        if not self.tmpfiles_new:
            return
        uid, gid = resolve_ids(L.file_owner, L.file_group)
        body = (
            f"# Written by {PUBLIC_SCRIPT} on {stamp_utc()}.\n"
            "# Recreates the SPIRE runtime directories at boot with the owner and\n"
            "# mode they had when this file was written.\n"
            + "".join(entry[0] + "\n" for entry in self.tmpfiles_new)
        )
        sandbox_check_tmpfiles(self.r, body, self.tmpfiles_new)
        create_exclusive(L.tmpfiles_path, body.encode("utf-8"), 0o644, uid, gid)
        after = tmpfiles_coverage(self.r)
        if after["missing"]:
            os.unlink(L.tmpfiles_path)
            raise Failure(f"systemd-tmpfiles does not read the new {L.tmpfiles_path}; it was removed")
        self.rep.action(f"wrote {L.tmpfiles_path}: " + "; ".join(entry[0] for entry in self.tmpfiles_new))



def write_bundle(r: Runner, rep: Report, bundle: ServerBundle) -> None:
    """Root's one use of the server bundle: write the PEM text the SPIRE data
    check produced, after a size check, and read the bytes back. Nothing in
    them is parsed here."""
    L = r.L
    if not 0 < len(bundle.pem) <= L.bundle_max_bytes:
        raise Failure(f"the server bundle is {len(bundle.pem)} bytes, outside 1 to {L.bundle_max_bytes}; {L.bundle_path} was not written")
    uid, gid = resolve_ids(L.file_owner, L.file_group)
    atomic_write(L.bundle_path, bundle.pem, 0o644, uid, gid)
    try:
        got = read_regular_file(L.bundle_path, limit=L.bundle_max_bytes)
        state = "absent" if got is None else "matches" if got[0] == bundle.pem else "different bytes"
    except Refusal as exc:
        state = str(exc)
    if state != "matches":
        raise Failure(f"{L.bundle_path} was written but does not read back as the server bundle ({state})")
    rep.action(f"wrote {L.bundle_path} ({bundle.count} CA certificate(s))")


# --------------------------------------------------------------------------
# Bundle refresh timer


# This file, as loaded. pin installs a copy of exactly these bytes for the
# timer, and status compares the installed copy with them.
HELPER_SOURCE = os.path.abspath(__file__)
UNIT_MARKER = f"# Written by {PUBLIC_SCRIPT} pin, which rewrites it; do not edit."


def refresh_unit_paths(L: Layout) -> tuple[str, str]:
    base = os.path.join(L.systemd_unit_dir, L.refresh_unit_name)
    return base + ".service", base + ".timer"


def refresh_unit_texts(L: Layout) -> dict:
    """The two unit files pin writes. The service runs refresh as root in a
    sandbox. refresh writes only the bundle file (through a temporary file in
    its directory) and the lock file, so the file system is read-only except
    the bundle file's directory and the lock directory (the unit's
    RuntimeDirectory=, which systemd creates and keeps). ReadOnlyPaths=/run
    keeps the rest of /run read-only: on systemd 255, ProtectSystem=strict
    leaves /run writable once ProtectKernelTunables= or ProtectControlGroups=
    is set. The capability bounding set keeps only what setpriv needs to run
    commands as spire and what root needs to reach the admin socket inside
    spire's 0700 directory; the system call filter, the address families and
    the other restrictions narrow what the run can do directly.

    The sandbox is not what keeps a flaw in parsing SPIRE's data from root:
    root in the unit can still ask systemd over D-Bus (/run/systemd/private,
    the system bus), which the helper's own systemctl calls need, to start a
    command outside the sandbox, connect to any UNIX socket root owns, and
    read any file (CAP_DAC_READ_SEARCH). What keeps such a flaw from root is
    that root parses none of SPIRE's data: the SPIRE data check does, as the
    SPIRE account."""
    service, timer = refresh_unit_paths(L)
    service_text = (
        f"{UNIT_MARKER}\n"
        "[Unit]\n"
        "Description=Refresh the SPIRE agent bootstrap bundle from the SPIRE server (Execution Substrate)\n"
        f"After={L.server_unit}\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"ExecStart={' '.join(L.python_argv)} {L.installed_helper_path} refresh --apply\n"
        "TimeoutStartSec=5min\n"
        f"RuntimeDirectory={os.path.basename(os.path.dirname(L.lock_path))}\n"
        "RuntimeDirectoryMode=0700\n"
        "RuntimeDirectoryPreserve=yes\n"
        "ProtectSystem=strict\n"
        f"ReadWritePaths={os.path.dirname(L.bundle_path)}\n"
        "ReadOnlyPaths=/run\n"
        "ProtectHome=yes\n"
        "PrivateTmp=yes\n"
        "PrivateDevices=yes\n"
        "NoNewPrivileges=yes\n"
        "CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_DAC_READ_SEARCH\n"
        "RestrictAddressFamilies=AF_UNIX\n"
        "RestrictNamespaces=yes\n"
        "RestrictSUIDSGID=yes\n"
        "RestrictRealtime=yes\n"
        "LockPersonality=yes\n"
        "MemoryDenyWriteExecute=yes\n"
        "ProtectKernelTunables=yes\n"
        "ProtectKernelModules=yes\n"
        "ProtectControlGroups=yes\n"
        "SystemCallFilter=@system-service\n"
        "SystemCallErrorNumber=EPERM\n"
    )
    timer_text = (
        f"{UNIT_MARKER}\n"
        "[Unit]\n"
        "Description=Refresh the SPIRE agent bootstrap bundle every 6 hours (Execution Substrate)\n"
        "\n"
        "[Timer]\n"
        f"OnCalendar={L.refresh_on_calendar}\n"
        "RandomizedDelaySec=15min\n"
        "Persistent=true\n"
        "\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )
    return {service: service_text.encode("ascii"), timer: timer_text.encode("ascii")}


def read_own_helper(L: Layout, *, for_install: bool) -> bytes:
    got = read_regular_file(HELPER_SOURCE, limit=4 << 20)
    if got is None:
        raise Refusal(f"cannot read this helper's own file {HELPER_SOURCE}")
    data, st = got
    if for_install:
        uid, _ = resolve_ids(L.file_owner, L.file_group)
        if st.st_uid != uid or stat.S_IMODE(st.st_mode) & 0o022:
            raise Refusal(f"{HELPER_SOURCE} is {describe(st)}; pin installs a copy of it for the refresh timer only when it is owned by {L.file_owner} and writable by no one else")
    return data


def helper_copy_dirs(L: Layout) -> tuple[list[str], list[str]]:
    """The directories that hold the helper copy, and the one above them:
    the ones missing that pin may create, and a problem for each that exists
    but is not a directory owned by root or file_owner that no one else can
    write. Whoever can write one of them can replace the file root runs."""
    uid, _ = resolve_ids(L.file_owner, L.file_group)
    missing, problems = [], []
    for d in (os.path.dirname(L.installed_helper_dirs[0]),) + tuple(L.installed_helper_dirs):
        st = lstat_or_none(d)
        if st is None and d in L.installed_helper_dirs:
            missing.append(d)
            continue
        if st is None or not stat.S_ISDIR(st.st_mode) or st.st_uid not in (0, uid) or stat.S_IMODE(st.st_mode) & 0o022:
            what = describe(st) if st is not None else "missing"
            problems.append(f"{d} is {what}; the refresh timer's helper copy needs directories owned by {L.file_owner} that no one else can write")
    return missing, problems


# What systemd reports about the definition it runs for each refresh unit.
UNIT_DEFINITION_PROPS = ["FragmentPath", "DropInPaths", "NeedDaemonReload"]


def unit_definition_problems(state: dict) -> list[str]:
    """systemd must run the unit files pin wrote and nothing else: each unit
    loaded (not masked, not failed to load) from its file in
    systemd_unit_dir, with no drop-in, and no change on disk that systemd has
    not loaded."""
    problems = []
    for key in ("service", "timer"):
        props, path = state[key], state["unit_paths"][key]
        unit = os.path.basename(path)
        if props.get("LoadState") != "loaded":
            problems.append(f"systemd reports {unit} as {props.get('LoadState') or 'unknown'}, not loaded")
            if props.get("LoadState") in ("not-found", "", None):
                continue
        if props.get("FragmentPath") != path:
            problems.append(f"systemd loads {unit} from {props.get('FragmentPath') or 'nowhere'}, not {path}")
        if props.get("DropInPaths"):
            problems.append(f"{unit} has drop-ins that change it: {props['DropInPaths']}")
        if props.get("NeedDaemonReload") == "yes":
            problems.append(f"{unit} changed on disk since systemd last loaded it")
    return problems


def refresh_timer_state(r: Runner, own: bytes) -> dict:
    """The helper copy and the two unit files (each absent, matches,
    differs, foreign or unreadable; matches includes owner file_owner and
    mode 0644), and systemd's view of the two units."""
    L = r.L
    uid, _ = resolve_ids(L.file_owner, L.file_group)
    wanted = [(L.installed_helper_path, own)] + list(refresh_unit_texts(L).items())
    files = {}
    for path, want in wanted:
        try:
            got = read_regular_file(path, limit=4 << 20)
        except Refusal:
            files[path] = "unreadable"
            continue
        if got is None:
            files[path] = "absent"
        elif got[0] == want and got[1].st_uid == uid and stat.S_IMODE(got[1].st_mode) == 0o644:
            files[path] = "matches"
        elif path != L.installed_helper_path and not got[0].startswith(UNIT_MARKER.encode("ascii") + b"\n"):
            files[path] = "foreign"
        else:
            files[path] = "not as pin writes it"
    timer = r.unit_props(L.refresh_unit_name + ".timer", ["LoadState", "ActiveState", "UnitFileState"] + UNIT_DEFINITION_PROPS)
    service = r.unit_props(L.refresh_unit_name + ".service", ["LoadState", "Result", "ExecMainStartTimestamp", "ExecMainStatus"] + UNIT_DEFINITION_PROPS)
    service_path, timer_path = refresh_unit_paths(L)
    return {"files": files, "wanted": dict(wanted), "timer": timer, "service": service,
            "unit_paths": {"service": service_path, "timer": timer_path}}


def timer_enabled(state: dict) -> bool:
    return state["timer"].get("UnitFileState") == "enabled" and state["timer"].get("ActiveState") == "active"


def check_refresh_timer(r: Runner, rep: Report) -> None:
    L = r.L
    service_unit = L.refresh_unit_name + ".service"
    timer_unit = L.refresh_unit_name + ".timer"
    try:
        state = refresh_timer_state(r, read_own_helper(L, for_install=False))
    except (Refusal, CommandError) as exc:
        rep.check("refresh timer", "fail", str(exc))
        return
    _, problems = helper_copy_dirs(L)
    problems += [f"{path} is {s}" for path, s in state["files"].items() if s != "matches"]
    problems += unit_definition_problems(state)
    if not timer_enabled(state):
        problems.append(f"{timer_unit} is {state['timer'].get('UnitFileState') or 'unknown'} and {state['timer'].get('ActiveState') or 'unknown'}")
    hints = [f"run sudo {PUBLIC_SCRIPT} pin --apply"] if problems else []
    result = state["service"].get("Result", "")
    if result != "success":
        problems.append(f"its last run failed (Result={result or 'unknown'}, exit status {state['service'].get('ExecMainStatus') or 'unknown'})")
        hints.append(f"see journalctl -u {service_unit}")
    if problems:
        rep.check("refresh timer", "attention", "; ".join(problems) + "; " + " and ".join(hints))
        return
    last = state["service"].get("ExecMainStartTimestamp") or "none since boot or since pin installed it"
    rep.check("refresh timer", "ok", f"{timer_unit} enabled and active ({L.refresh_on_calendar}), runs refresh --apply from {L.installed_helper_path}; last run: {last}")


class TimerInstall:
    """pin's last step: a root-owned copy of this helper and the two units
    that run refresh --apply from it every 6 hours."""

    def __init__(self, r: Runner, rep: Report):
        self.r = r
        self.rep = rep
        self.L = r.L
        self.own = b""
        self.state: dict = {}
        self.new_dirs: list[str] = []
        self.writes: list[str] = []
        self.enable = False

    def needed(self) -> bool:
        return bool(self.new_dirs or self.writes or self.enable)

    def inspect(self) -> None:
        L = self.L
        timer_unit = L.refresh_unit_name + ".timer"
        if os.path.dirname(L.installed_helper_path) != L.installed_helper_dirs[-1]:
            raise Refusal(f"{L.installed_helper_path} is not directly in {L.installed_helper_dirs[-1]}")
        self.own = read_own_helper(L, for_install=True)
        self.new_dirs, problems = helper_copy_dirs(L)
        if problems:
            raise Refusal(problems[0])
        ust = lstat_or_none(L.systemd_unit_dir)
        if ust is None or not stat.S_ISDIR(ust.st_mode):
            raise Refusal(f"{L.systemd_unit_dir} is not a directory")
        self.state = refresh_timer_state(self.r, self.own)
        for path, s in self.state["files"].items():
            if s == "foreign":
                raise Refusal(f"{path} exists and was not written by {PUBLIC_SCRIPT}; move it away by hand")
            if s == "unreadable":
                raise Refusal(f"{path} exists and is not a regular file")
            if s != "matches":
                self.writes.append(path)
        # A drop-in or a unit file elsewhere would change what systemd runs;
        # pin does not install around one.
        for key in ("service", "timer"):
            props, path = self.state[key], self.state["unit_paths"][key]
            if props.get("DropInPaths"):
                raise Refusal(f"{os.path.basename(path)} has drop-ins ({props['DropInPaths']}) that would change what the refresh timer runs; remove them by hand")
            if props.get("FragmentPath") not in ("", path):
                raise Refusal(f"systemd loads {os.path.basename(path)} from {props['FragmentPath']}, which pin does not manage; remove it by hand")
        reload_needed = any(self.state[k].get("NeedDaemonReload") == "yes" for k in ("service", "timer"))
        self.enable = bool(self.writes) or reload_needed or not timer_enabled(self.state)
        if not self.needed():
            self.rep.check("refresh timer", "ok", f"{timer_unit} installed, enabled and active")
            return
        self.rep.check("refresh timer", "info", "; ".join(f"{p} is {s}" for p, s in self.state["files"].items() if s != "matches") or f"{timer_unit} is not enabled and active")
        dirs = f"create {', '.join(self.new_dirs)} as {L.file_owner}:{L.file_group} 0755, " if self.new_dirs else ""
        files = f"write {', '.join(self.writes)} as {L.file_owner}:{L.file_group} 0644 (the helper copy is this helper's own bytes), " if self.writes else ""
        self.rep.planned(f"install the bundle refresh timer: {dirs}{files}run systemctl daemon-reload and enable --now {timer_unit}, so that systemd runs refresh --apply from {L.installed_helper_path} at {L.refresh_on_calendar}; on a failure put these files back as they were")

    def apply(self) -> bool:
        if not self.needed():
            return False
        L = self.L
        timer_unit = L.refresh_unit_name + ".timer"
        uid, gid = resolve_ids(L.file_owner, L.file_group)
        before = {}
        for path in self.writes:
            got = read_regular_file(path, limit=4 << 20)
            before[path] = got
        was_enabled = self.state["timer"].get("UnitFileState") == "enabled"
        made: list[str] = []
        try:
            for d in self.new_dirs:
                os.mkdir(d, 0o700)
                made.append(d)
                take_new_dir(d, uid, gid, 0o755)
                self.rep.action(f"created {d}")
            # The copy first, so the units never name a missing file.
            for path in sorted(self.writes, key=lambda p: p != L.installed_helper_path):
                atomic_write(path, self.state["wanted"][path], 0o644, uid, gid)
                self.rep.action(f"wrote {path}")
            self.r.run([L.systemctl_bin, "daemon-reload"], timeout=120)
            self.r.run([L.systemctl_bin, "enable", "--now", timer_unit], timeout=120)
            after = refresh_timer_state(self.r, self.own)
            off = [f"{p} is {s}" for p, s in after["files"].items() if s != "matches"]
            if not timer_enabled(after):
                off.append(f"{timer_unit} is {after['timer'].get('UnitFileState') or 'unknown'} and {after['timer'].get('ActiveState') or 'unknown'}")
            # Includes each unit's LoadState.
            off += unit_definition_problems(after)
            if off:
                raise Failure("; ".join(off))
            self.rep.action(f"enabled and started {timer_unit}: systemd runs refresh --apply at {L.refresh_on_calendar}")
            return True
        except BaseException as exc:
            self.rollback(before, was_enabled, made)
            if isinstance(exc, Interrupted):
                raise
            if isinstance(exc, (Failure, CommandError, OSError)):
                detail = str(exc) if not isinstance(exc, OSError) else f"{exc.strerror}: {exc.filename}"
                raise Failure(f"the bundle refresh timer was not installed ({detail}); its files were put back as they were") from None
            raise

    def rollback(self, before: dict, was_enabled: bool, made: list[str]) -> None:
        L = self.L
        timer_unit = L.refresh_unit_name + ".timer"
        with signals_deferred():
            try:
                if not was_enabled:
                    self.r.run([L.systemctl_bin, "disable", "--now", timer_unit], timeout=120, check=False)
                for path, got in before.items():
                    if got is None:
                        with contextlib.suppress(FileNotFoundError):
                            os.unlink(path)
                    else:
                        atomic_write(path, got[0], stat.S_IMODE(got[1].st_mode), got[1].st_uid, got[1].st_gid)
                for d in reversed(made):
                    os.rmdir(d)
                self.r.run([L.systemctl_bin, "daemon-reload"], timeout=120, check=False)
            except (OSError, CommandError) as exc:
                detail = str(exc) if not isinstance(exc, OSError) else f"{exc.strerror}: {exc.filename}"
                raise Failure(f"installing the bundle refresh timer failed and putting its files back failed too ({detail}); the box needs a hand check") from None
            self.rep.action("put the refresh timer's files back as they were")


# --------------------------------------------------------------------------
# Modes


def mode_status(r: Runner, rep: Report) -> None:
    L = r.L
    now = utc_now()
    for unit in (L.server_unit, L.agent_unit) + tuple(L.dependent_units):
        props = r.unit(unit)
        active = props.get("ActiveState", "unknown")
        rep.check(unit, "ok" if active == "active" else "attention",
                  f"{active} ({props.get('SubState', 'unknown')}), restarts {props.get('NRestarts', '?')}")
    server_ok = True
    try:
        check_server_socket(r)
        rep.check("server admin socket", "ok", f"{L.spire_user}:{L.spire_group} 0600")
    except Refusal as exc:
        server_ok = False
        rep.check("server admin socket", "fail", str(exc))

    local = read_local_agent(r)
    if local["state"] in ("valid", "expired"):
        left = local["not_after"] - now
        detail = (f"{local['agent_id']} ({fingerprint(local['agent_id'])}), SVID "
                  f"{'valid' if left > 0 else 'EXPIRED'} until {iso_utc(local['not_after'])} ({left / 3600:.1f} h left)")
        if local["state"] == "expired":
            rep.check("agent identity", "fail", detail + f"; run sudo {PUBLIC_SCRIPT} recover", seconds_left=int(left), fingerprint=fingerprint(local["agent_id"]))
        elif left < L.svid_attention_seconds:
            rep.check("agent identity", "attention", detail + "; the agent is not renewing its SVID", seconds_left=int(left), fingerprint=fingerprint(local["agent_id"]))
        else:
            rep.check("agent identity", "ok", detail, seconds_left=int(left), fingerprint=fingerprint(local["agent_id"]))
    else:
        rep.check("agent identity", "fail", f"{local['state']}: {local['reason']}")

    fetch_server = False
    if server_ok:
        try:
            agents = list_agents(r)
            record = next((a for a in agents if local.get("agent_id") and a["id"] == local["agent_id"]), None)
            if record is None:
                rep.check("server agent record", "fail" if local["state"] == "valid" else "info", "the server has no record for the local agent ID")
            elif record["banned"]:
                rep.check("server agent record", "fail", "the server has banned the local agent")
            else:
                detail = f"expires {iso_utc(record['expires_at'])}, attestation {record['attestation_type']}, can re-attest {str(record['can_reattest']).lower()}"
                if record["expires_at"] > now:
                    rep.check("server agent record", "ok", detail)
                elif local["state"] == "valid":
                    # The record trails a renewed SVID until the agent presents it.
                    rep.check("server agent record", "attention", detail + "; behind the agent's own SVID, which the agent presents on its next sync")
                else:
                    rep.check("server agent record", "fail", detail)
            stale = [a for a in agents if a["id"] != local.get("agent_id")]
            rep.check("other agent records", "info", f"{len(stale)} ({sum(1 for a in stale if a['expires_at'] <= now)} expired)", count=len(stale))
            fetch_server = True
        except (CommandError, Refusal) as exc:
            rep.check("server queries", "fail", str(exc))
    try:
        server, bstate = bundle_view(r, fetch_server=fetch_server)
    except Refusal as exc:
        server, bstate = {"state": "skipped"}, {"state": "unreadable", "reason": str(exc)}
    except CommandError as exc:
        server, bstate = {"state": "failed", "reason": str(exc)}, {"state": "unreadable", "reason": str(exc)}
    if fetch_server and server["state"] in ("refused", "failed"):
        rep.check("server queries", "fail", server["reason"])

    try:
        _, cst, analysis = read_agent_config(r)
        meta = describe(cst)
        if analysis["state"] == "insecure":
            rep.check("bootstrap", "attention", f"insecure_bootstrap = true in {L.agent_config} ({meta}): a fresh bootstrap trusts any server on the agent's server address; run sudo {PUBLIC_SCRIPT} pin")
        elif analysis["state"] == "pinned":
            confirmed, detail = spire_confirms_pinned(r)
            if confirmed:
                rep.check("bootstrap", "ok", f"trust_bundle_path = \"{L.bundle_path}\" in {L.agent_config} ({meta}), confirmed by spire-agent validate, plain and with -trustBundle")
            else:
                rep.check("bootstrap", "attention", f"{L.agent_config} ({meta}) reads as pinned to this helper, but SPIRE's own parser does not confirm it ({detail}); inspect it by hand")
        else:
            rep.check("bootstrap", "attention", f"unrecognized bootstrap setting in {L.agent_config}: {analysis['reason']}")
    except (Refusal, CommandError) as exc:
        analysis = {"state": "unreadable"}
        rep.check("bootstrap", "fail", str(exc))

    if bstate["state"] == "matches":
        rep.check("bundle file", "ok", f"{L.bundle_path} matches the server bundle ({bstate['meta']})")
    elif bstate["state"] == "absent" and analysis.get("state") == "pinned":
        rep.check("bundle file", "attention", f"{L.bundle_path} is absent although agent.conf names it; a fresh bootstrap would fail; recover writes it")
    elif bstate["state"] == "differs":
        if "coverage" in bstate:
            coverage = bstate["coverage"]
            rep.check("bundle file", coverage["state"], f"{L.bundle_path} ({bstate['meta']}) {coverage['detail']}")
        else:
            rep.check("bundle file", "fail", f"{L.bundle_path} differs from the server bundle, and its certificates cannot be read: {bstate['error']}")
    elif bstate["state"] in ("oversized", "unparseable") and analysis.get("state") == "pinned":
        rep.check("bundle file", "attention", f"{L.bundle_path} ({bstate['meta']}): {bstate['state']}; run sudo {PUBLIC_SCRIPT} refresh --apply")
    else:
        reason = f" ({bstate['reason']})" if bstate.get("reason") else ""
        rep.check("bundle file", "info" if bstate["state"] in ("absent", "unknown") else "attention", f"{L.bundle_path}: {bstate['state']}{reason}")

    if analysis.get("state") == "pinned":
        check_refresh_timer(r, rep)

    try:
        coverage = tmpfiles_coverage(r)
        if coverage["missing"]:
            rep.check("reboot readiness", "attention", "no boot-time rule recreates " + ", ".join(coverage["missing"]) + f"; run sudo {PUBLIC_SCRIPT} pin")
        else:
            rep.check("reboot readiness", "ok", "; ".join(f"{d} by {how}" for d, how in coverage["covered"].items()))
    except CommandError as exc:
        rep.check("reboot readiness", "fail", str(exc))

    rep.check("agent health", "ok" if agent_healthy(r) else "fail", "spire-agent healthcheck as " + L.spire_user)
    rep.result = "ok" if rep.attention_count() == 0 else "attention"


def mode_pin(r: Runner, rep: Report, apply: bool) -> None:
    L = r.L
    require_server(r, rep)
    if not unit_active(r, L.agent_unit):
        raise Refusal(f"{L.agent_unit} is not active; pin restarts a running agent. If its SVID expired, use recover")
    local = read_local_agent(r)
    if local["state"] != "valid":
        raise Refusal(f"the agent's local state is {local['state']} ({local.get('reason', 'SVID expired')}); use recover")
    record = next((a for a in list_agents(r) if a["id"] == local["agent_id"]), None)
    if record is None or record["banned"]:
        raise Refusal("the server has no unbanned record for the local agent ID")
    if not agent_healthy(r):
        raise Refusal(f"spire-agent healthcheck fails before any change; inspect {L.agent_unit} first")
    rep.check("agent identity", "ok", f"{local['agent_id']} ({fingerprint(local['agent_id'])}) valid until {iso_utc(local['not_after'])}")
    pinning = Pinning(r, rep)
    pinning.inspect()
    if pinning.config_state["state"] == "insecure":
        rep.planned(f"restart {L.agent_unit} (systemd restarts {', '.join(L.dependent_units)} with it), then check that the agent ID is unchanged, the agent is healthy and serves a workload SVID, and these units are active again: {', '.join(L.dependent_units)}; on a failure restore the original config and restart again")
    timer = TimerInstall(r, rep)
    timer.inspect()
    if not apply:
        rep.result = "planned" if rep.plan else "ok"
        rep.message = "no changes made; rerun with --apply" if rep.plan else "nothing to change"
        return
    if not rep.plan:
        rep.result = "ok"
        rep.message = "nothing to change"
        return
    pinning.apply_bundle()
    pinning.apply_tmpfiles()
    pinning.apply_config()
    message = "pinned; no restart needed"
    if pinning.config_changed:
        before = {u: unit_active(r, u) for u in L.dependent_units}
        try:
            r.unit_action("restart", L.agent_unit)
            verify_after_start(r, rep, expect_agent_id=local["agent_id"], dependents_before=before)
        except (CommandError, Failure) as exc:
            rep.action(f"verification after restart failed: {exc}")
            try:
                pinning.restore_config()
                r.unit_action("restart", L.agent_unit)
                verify_after_start(r, rep, expect_agent_id=local["agent_id"], dependents_before=before)
                rep.action("rolled back to the original config; the agent runs again with its original identity")
            except (CommandError, Failure) as exc2:
                raise Failure(f"pin failed ({exc}) and the rollback failed too ({exc2}); the box needs a hand check") from None
            raise Failure(f"pin failed and was rolled back: {exc}") from None
        message = "pinned; the agent restarted with its original identity"
    # The timer comes last: its refresh refuses an agent.conf that is not
    # pinned. A failure here leaves the pin in place and is reported.
    try:
        if timer.apply():
            message += "; the bundle refresh timer is installed"
    except Failure as exc:
        raise Failure(f"{message}, but {exc}") from None
    rep.result = "ok"
    rep.message = message


def mode_refresh(r: Runner, rep: Report, apply: bool) -> None:
    """Rewrite the bootstrap bundle file from the server bundle when they
    differ, on a host whose agent.conf is already pinned to it. The agent
    reads the file only at a fresh bootstrap, so nothing restarts; refresh
    needs a running server but not a healthy agent. It edits no config, unit
    or boot rule: that is pin's job."""
    L = r.L
    require_server(r, rep)
    _, cst, analysis = read_agent_config(r)
    if analysis["state"] != "pinned":
        reason = analysis.get("reason") or "it uses insecure_bootstrap"
        raise Refusal(f"{L.agent_config} is not pinned to {L.bundle_path} ({reason}); run sudo {PUBLIC_SCRIPT} pin")
    confirmed, detail = spire_confirms_pinned(r)
    if not confirmed:
        raise Refusal(f"{L.agent_config} reads as pinned to this helper, but SPIRE's own parser does not confirm it ({detail}); inspect it by hand")
    rep.check("bootstrap", "ok", f"trust_bundle_path = \"{L.bundle_path}\" in {L.agent_config} ({describe(cst)}), confirmed by spire-agent validate, plain and with -trustBundle")
    bundle_dir = os.path.dirname(L.bundle_path)
    dst = lstat_or_none(bundle_dir)
    if dst is None or not stat.S_ISDIR(dst.st_mode):
        raise Refusal(f"{bundle_dir} is not a directory")
    server, state = bundle_view(r, fetch_server=True)
    bundle = require_server_bundle(server)
    if state["state"] == "not_regular":
        raise Refusal(f"{L.bundle_path} exists and is not a regular file")
    if state["state"] == "matches":
        rep.check("bundle file", "ok", f"{L.bundle_path} matches the server bundle ({bundle.count} CA certificate(s))")
        rep.result = "ok"
        rep.message = "nothing to change"
        return
    rep.check("bundle file", "info", f"{L.bundle_path}: {state['state']}")
    rep.planned(f"write the server bundle ({bundle.count} CA certificate(s), read over the admin socket and checked as {L.spire_user}) to {L.bundle_path} as {L.file_owner}:{L.file_group} 0644 (file is {state['state']})")
    if not apply:
        rep.result = "planned"
        rep.message = "no changes made; rerun with --apply"
        return
    write_bundle(r, rep, bundle)
    rep.result = "ok"
    rep.message = "refreshed; SPIRE reads the file only at a fresh bootstrap, so nothing restarted"


def verify_after_start(r: Runner, rep: Report, *, expect_agent_id: str, dependents_before: dict, start_dependents: bool = False) -> None:
    L = r.L
    if not wait_for(lambda: agent_healthy(r), L.agent_health_timeout_seconds, L.poll_interval_seconds):
        raise Failure(f"{L.agent_unit} did not become healthy within {L.agent_health_timeout_seconds} s")
    local = read_local_agent(r)
    if local.get("agent_id") != expect_agent_id or local["state"] != "valid":
        raise Failure("the agent's identity after the start is not the expected one")

    # SPIRE moves a renewed SVID into the agent's record when the agent
    # first presents it, so a record can trail the agent's own SVID for a
    # few seconds after a start.
    def live_record():
        return any(a["id"] == expect_agent_id and not a["banned"] and a["expires_at"] > utc_now() for a in list_agents(r))

    if not wait_for(live_record, L.agent_health_timeout_seconds, L.poll_interval_seconds):
        raise Failure("the server has no live record for the agent after the start")
    rep.action(f"agent healthy with identity {fingerprint(expect_agent_id)}, SVID valid until {iso_utc(local['not_after'])}")
    if not wait_for(lambda: workload_svid_ok(r), L.workload_svid_timeout_seconds, L.poll_interval_seconds):
        raise Failure(f"no workload SVID for {L.workload_spiffe_id} within {L.workload_svid_timeout_seconds} s")
    rep.action(f"Workload API served {L.workload_spiffe_id}")
    # A restart of the agent restarts its active dependents through
    # Requires=; a failed start leaves them stopped, and a start of the agent
    # does not start them. So start each one that should run and is not.
    for unit in L.dependent_units:
        if not (start_dependents or dependents_before.get(unit)):
            continue
        if not unit_active(r, unit):
            r.unit_action("start", unit)
            rep.action(f"started {unit}")
        if not wait_for(lambda: unit_active(r, unit), L.dependent_unit_timeout_seconds, L.poll_interval_seconds):
            raise Failure(f"{unit} is not active within {L.dependent_unit_timeout_seconds} s")
        rep.action(f"{unit} active")


def mode_recover(r: Runner, rep: Report, apply: bool, evict_old: bool) -> None:
    L = r.L
    require_server(r, rep)
    local = read_local_agent(r)
    old_id = local.get("agent_id", "")
    if local["state"] == "valid":
        raise Refusal(f"the agent's SVID is valid until {iso_utc(local['not_after'])}; recover only runs after it expired or when the agent never attested")
    if local["state"] == "unreadable":
        raise Refusal(f"the agent's local state cannot be read ({local['reason']}); inspect {L.agent_data_dir} by hand")
    agents = list_agents(r)
    if old_id:
        record = next((a for a in agents if a["id"] == old_id), None)
        if record is not None and record["expires_at"] > utc_now() and not record["banned"]:
            raise Refusal("the local SVID has expired but the server still records a live SVID for it; inspect by hand")
        rep.check("agent identity", "fail", f"{old_id} ({fingerprint(old_id)}) expired at {iso_utc(local['not_after'])}")
    else:
        rep.check("agent identity", "fail", f"unattested: {local['reason']}")
    alias = f"spiffe://{L.trust_domain}{L.agent_alias_path}"
    entries = list_entries(r)
    children = [e for e in entries if e["parent_id"] == alias]
    if not children:
        raise Refusal(f"no registration entry names {alias} as its parent, so a new agent would serve no workload; inspect the entries by hand")
    rep.check("registration entries", "ok", f"{len(children)} entr{'y' if len(children) == 1 else 'ies'} under {alias}")
    old_aliases = [e for e in entries if old_id and e["parent_id"] == old_id]
    data_st = lstat_or_none(L.agent_data_dir)
    if data_st is not None and not stat.S_ISDIR(data_st.st_mode):
        raise Refusal(f"{L.agent_data_dir} is not a directory")
    pinning = Pinning(r, rep)
    pinning.inspect()
    stamp = stamp_utc()
    backup_dir = f"{L.agent_data_dir}.recover-{stamp}"
    if lstat_or_none(backup_dir) is not None:
        raise Refusal(f"{backup_dir} already exists")
    rep.planned(f"stop {L.agent_unit} (systemd stops {', '.join(L.dependent_units)} with it)")
    if data_st is not None:
        rep.planned(f"move {L.agent_data_dir} aside to {backup_dir} (kept, not deleted) and create an empty one with the same owner and mode")
    else:
        rep.planned(f"create {L.agent_data_dir} as {L.spire_user}:{L.spire_group} {L.agent_data_dir_mode:04o}")
    rep.planned(f"generate a join token for {alias} with a {L.join_token_ttl_seconds} s lifetime, kept in memory and in a 0600 file of {L.spire_user} inside a directory under {L.scratch_parent} that only this helper can change, never printed or passed as an argument")
    rep.planned(f"attest once as {L.spire_user} with the pinned agent.conf, -trustBundle {L.bundle_path} (so SPIRE itself refuses to start if it still reads insecure_bootstrap) and that token file, delete the token file as soon as the new agent appears, then stop that process")
    rep.planned(f"start {L.agent_unit} and {', '.join(L.dependent_units)}, and check health, the new identity and a workload SVID")
    if evict_old and old_id:
        rep.planned(f"evict the old agent record and delete its {len(old_aliases)} alias entr{'y' if len(old_aliases) == 1 else 'ies'}")
    if not apply:
        rep.result = "planned"
        rep.message = "no changes made; rerun with --apply"
        return

    pinning.apply_bundle()
    pinning.apply_tmpfiles()
    pinning.apply_config()

    r.unit_action("stop", L.agent_unit)
    if not wait_for(lambda: not unit_active(r, L.agent_unit), 30, L.poll_interval_seconds):
        raise Failure(f"{L.agent_unit} did not stop")
    rep.action(f"stopped {L.agent_unit}")
    spire_uid, spire_gid = resolve_ids(L.spire_user, L.spire_group)
    if data_st is not None:
        new_uid, new_gid, new_mode = data_st.st_uid, data_st.st_gid, stat.S_IMODE(data_st.st_mode)
    else:
        new_uid, new_gid, new_mode = spire_uid, spire_gid, L.agent_data_dir_mode
    # From the rename on, any failure or stop signal puts the old data
    # directory back. The rollback reads what is on disk, so it is right
    # wherever in these steps the failure happened.
    try:
        if data_st is not None:
            os.rename(L.agent_data_dir, backup_dir)
            rep.action(f"moved {L.agent_data_dir} to {backup_dir}")
        # The SPIRE account may be able to write the parent directory, so the
        # new directory gets its owner and mode through a descriptor, never
        # by a path that could by then name a symlink.
        os.mkdir(L.agent_data_dir, 0o700)
        take_new_dir(L.agent_data_dir, new_uid, new_gid, new_mode)
        rep.action(f"created an empty {L.agent_data_dir}")
        new_id = attest_once(r, rep, old_id, alias, spire_uid, spire_gid)
    except (CommandError, Failure, OSError) as exc:
        rollback_data_dir(r, rep, backup_dir, stamp, had_data_dir=data_st is not None)
        reason = f"{exc.strerror}: {exc.filename}" if isinstance(exc, OSError) else str(exc)
        raise Failure(f"attestation failed: {reason}") from None

    r.unit_action("start", L.agent_unit)
    rep.action(f"started {L.agent_unit}")
    verify_after_start(r, rep, expect_agent_id=new_id, dependents_before={}, start_dependents=True)

    if evict_old and old_id:
        if any(a["id"] == old_id for a in list_agents(r)):
            r.run([L.spire_server_bin, "agent", "evict", "-socketPath", L.server_socket, "-spiffeID", old_id], spire=True)
            rep.action(f"evicted the old agent record {fingerprint(old_id)}")
        for entry in old_aliases:
            r.run([L.spire_server_bin, "entry", "delete", "-socketPath", L.server_socket, "-entryID", entry["id"]], spire=True)
            rep.action(f"deleted the old alias entry {entry['id']}")
    elif old_id:
        rep.action(f"left the expired agent record {fingerprint(old_id)} and its alias entry in place (use --evict-old-agent to remove them)")
    rep.result = "ok"
    rep.message = f"recovered; new agent identity {fingerprint(new_id)}"


def attest_once(r: Runner, rep: Report, old_id: str, alias: str, spire_uid: int, spire_gid: int) -> str:
    """Attest a fresh agent once with a single-use join token. The token
    lives only in this process's memory and in a 0600 file inside a private
    directory on tmpfs, and is never printed or put on a command line."""
    L = r.L
    scratch = tempfile.mkdtemp(prefix="es-spire-agent-recover.", dir=L.scratch_parent)
    proc = None
    log_fd = -1
    try:
        # The directory stays this process's own. The SPIRE account may only
        # pass through it (group search) to read its token file; it cannot
        # create, rename or replace anything in it, so every path below names
        # what this process created.
        take_new_dir(scratch, os.geteuid(), spire_gid, 0o710)
        doc = r.server_json(["token", "generate", "-spiffeID", alias, "-ttl", str(L.join_token_ttl_seconds)])
        token = doc.get("value")
        if not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", token):
            raise Failure("spire-server token generate returned no token")
        rep.secrets.append(token)
        token_path = os.path.join(scratch, "join-token")
        fd = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            os.fchown(fd, spire_uid, spire_gid)
            os.fchmod(fd, 0o600)
            os.write(fd, token.encode("ascii"))
        finally:
            os.close(fd)
        rep.action(f"generated a join token ({L.join_token_ttl_seconds} s lifetime) into a 0600 file in a private directory")
        # The log is created here and read back through the same descriptor,
        # never reopened by name.
        log_fd = os.open(os.path.join(scratch, "attest.log"),
                         os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        # A stop signal while Popen waits for the exec would leave the agent
        # running with no handle to stop it, so signals are held until proc
        # is set; the agent itself starts with the normal mask.
        with signals_deferred() as mask:
            proc = subprocess.Popen(
                # -trustBundle makes SPIRE refuse to start if its own reading
                # of agent.conf still has insecure_bootstrap ("only one of ...").
                r.as_spire([L.spire_agent_bin, "run", "-config", L.agent_config,
                            "-trustBundle", L.bundle_path, "-trustBundleFormat", "pem",
                            "-joinTokenFile", token_path]),
                stdin=subprocess.DEVNULL, stdout=log_fd, stderr=subprocess.STDOUT,
                env=r.env(), cwd="/", start_new_session=True,
                preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, mask),
            )

        def attested():
            if proc.poll() is not None:
                return "exited"
            local = read_local_agent(r)
            if local["state"] == "valid" and local.get("agent_id") != old_id:
                return local["agent_id"]
            return ""

        outcome = wait_for(attested, L.attestation_timeout_seconds, L.poll_interval_seconds)
        try:
            os.unlink(token_path)
        except FileNotFoundError:
            pass
        if not outcome or outcome == "exited":
            # Redact before cutting, so a cut cannot split a token.
            tail = rep.redact(os.pread(log_fd, 1 << 20, 0).decode("utf-8", "replace"))[-1500:]
            why = "the attesting agent exited" if outcome == "exited" else f"no new agent identity within {L.attestation_timeout_seconds} s"
            raise Failure(f"{why}; agent log tail: {tail}")
        new_id = outcome
        if not any(a["id"] == new_id and a["expires_at"] > utc_now() for a in list_agents(r)):
            raise Failure("the server does not list the newly attested agent")
        rep.action(f"attested a new agent {fingerprint(new_id)}; the token file was deleted")
        return new_id
    finally:
        with signals_deferred():
            if proc is not None and proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=15)
            if log_fd >= 0:
                os.close(log_fd)
            shutil.rmtree(scratch, ignore_errors=True)
            if os.path.lexists(scratch):
                rep.action(f"WARNING: could not remove {scratch}; delete it by hand")


def rollback_data_dir(r: Runner, rep: Report, backup_dir: str, stamp: str, had_data_dir: bool) -> None:
    """Put the data directory back as it was before recover's swap. It acts
    on what is on disk: the backup exists only if the rename happened (its
    name was checked to be free before), and without an old directory any
    directory now there is the one this run created."""
    L = r.L
    with signals_deferred():
        try:
            swapped = os.path.lexists(backup_dir)
            if (swapped or not had_data_dir) and os.path.lexists(L.agent_data_dir):
                failed_dir = f"{L.agent_data_dir}.failed-{stamp}"
                os.rename(L.agent_data_dir, failed_dir)
                rep.action(f"moved the new data directory aside to {failed_dir}")
            if swapped:
                os.rename(backup_dir, L.agent_data_dir)
                rep.action(f"moved {backup_dir} back to {L.agent_data_dir}")
        except OSError as exc:
            rep.action(f"WARNING: could not put the old data directory back: {exc.strerror}")
        rep.action(f"{L.agent_unit} and {', '.join(L.dependent_units)} are left stopped; a join token generated by this run expires {L.join_token_ttl_seconds} s after it was generated")


# --------------------------------------------------------------------------
# Entry point


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PUBLIC_SCRIPT,
        description="SPIRE agent bootstrap trust and recovery on the Remote Alpha box. Run with sudo.",
    )
    parser.add_argument("mode", choices=("status", "pin", "recover", "refresh"))
    parser.add_argument("--apply", action="store_true", help="pin/recover/refresh: make the changes (default: check and print the plan)")
    parser.add_argument("--evict-old-agent", action="store_true", help="recover: also evict the expired agent record and delete its alias entry")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    return parser


def main(argv: list[str], layout: Layout) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code not in (0, None) else 0
    if args.apply and args.mode == "status":
        parser.print_usage(sys.stderr)
        print(f"{PUBLIC_SCRIPT}: --apply is only for pin, recover and refresh", file=sys.stderr)
        return 2
    if args.evict_old_agent and args.mode != "recover":
        parser.print_usage(sys.stderr)
        print(f"{PUBLIC_SCRIPT}: --evict-old-agent is only for recover", file=sys.stderr)
        return 2
    rep = Report(args.mode, args.apply)
    try:
        require_root(layout)
    except UsageError as exc:
        print(f"{PUBLIC_SCRIPT}: {exc}", file=sys.stderr)
        return 2
    os.umask(0o077)
    runner = Runner(layout, rep)
    code = 0
    lock_fd = None
    try:
        try:
            # A stop signal (Ctrl-C, an SSH hangup, systemd or kill) raises
            # Interrupted, so the steps below clean up, roll back and report.
            for sig in _STOP_SIGNALS:
                signal.signal(sig, _stop_on_signal)
            require_commands(layout)
            if args.mode != "status":
                lock_fd = take_lock(layout)
            if args.mode == "status":
                mode_status(runner, rep)
                code = 0 if rep.result == "ok" else 1
            elif args.mode == "pin":
                mode_pin(runner, rep, args.apply)
            elif args.mode == "refresh":
                mode_refresh(runner, rep, args.apply)
            else:
                mode_recover(runner, rep, args.apply, args.evict_old_agent)
        except Refusal as exc:
            rep.result = "refused"
            rep.message = f"{exc}; nothing was changed"
            code = 1
        except (Failure, CommandError, OSError) as exc:
            rep.result = "failed"
            rep.message = str(exc) if not isinstance(exc, OSError) else f"{exc.strerror}: {exc.filename}"
            code = 1
    except Interrupted as exc:
        # The first stop signal landed inside one of the handlers above;
        # later ones are ignored, so this handler cannot be cut short.
        rep.result = "failed"
        rep.message = str(exc)
        code = 1
    finally:
        for sig in _STOP_SIGNALS:
            signal.signal(sig, signal.SIG_IGN)
        if lock_fd is not None:
            os.close(lock_fd)
    out = json.dumps(rep.document(), indent=2, sort_keys=True) + "\n" if args.json else rep.render_text()
    sys.stdout.write(out)
    sys.stdout.flush()
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:], Layout()))
