"""Named user caller identities for AGS and ES on the Remote Alpha box.

A user identity is the SPIFFE ID spiffe://execution.internal/user/<name> in a
client certificate signed by a separate user CA. Run through
scripts/remote_alpha_user_identity.sh.

Box modes (root on the box; nothing changes without --apply):

  status                       read-only report
  init-ca [--apply] [--replace]
                               create the user CA (key stays root-only here);
                               --replace makes a new one when the old one is
                               installed nowhere and no name is active
  issue --name N --csr F --out F [--apply]
                               sign a 90-day leaf for user/N from a CSR
  allow --name N [--apply]     install the user CA as a client trust anchor
                               bound to the user/ namespace if needed, add
                               user/N to the AGS and ES allowlists, restart
                               AGS then ES
  revoke --name N [--apply] [--remove-ca]
                               mark the name revoked for good, remove user/N
                               and its workload grant rules, restart; with
                               --remove-ca also retire the user CA and remove
                               it and its binding (every later revoke finishes
                               that removal)

Caller modes (the caller, never root, on the machine that calls AGS and ES):

  request --name N [--renew]   make the private key and a CSR
  install --name N --cert F [--server-ca F]
                               install the issued certificate
  check --name N [--url https://HOST:PORT [--service es|ags]]
                               check local files, then call the service

The contract is in .docs/system_overview/remote_supported_host_alpha.md,
section "Remote Alpha User Caller Identities". The caller modes must also run
with the Mac's own Python 3.9 in /usr/bin and its LibreSSL openssl.

Every path, account, unit and command is fixed in Layout. The entry point at
the bottom of this file uses Layout() unchanged and reads no environment
variable; tests import this file and pass their own Layout.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import copy
import dataclasses
import datetime
import errno
import fcntl
import functools
import hashlib
import http.client
import json
import os
import pwd
import re
import secrets
import shutil
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse

SCHEMA_VERSION = "execution-substrate.remote-alpha.user-identity.v1"
REGISTRY_SCHEMA_VERSION = "execution-substrate.remote-alpha.user-identity.registry.v1"
BACKUP_SCHEMA_VERSION = "execution-substrate.remote-alpha.user-identity.backup.v1"

PUBLIC_SCRIPT = "scripts/remote_alpha_user_identity.sh"

# init-ca --replace builds the new CA in a directory with this prefix inside
# the user CA directory, then renames it to next/.
NEXT_STAGING_PREFIX = "next.staging-"

BOX_MODES = ("status", "init-ca", "issue", "allow", "revoke")
CALLER_MODES = ("request", "install", "check")

# 1 to 32 characters of a-z, 0-9 and "-", starting with a letter and not
# ending with "-".
NAME_RE = re.compile(r"\A[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?\Z")


@dataclasses.dataclass(frozen=True)
class Layout:
    """Everything the helper touches. Defaults are the box and Mac values."""

    trust_domain: str = "execution.internal"
    # SPIFFE ID path namespace of user identities: <namespace>/<name>.
    path_namespace: str = "user"

    # Box modes must run with this effective UID.
    required_euid: int = 0
    # Owner of every box file and directory this helper reads or writes.
    box_owner_uid: int = 0

    ags_config: str = "/etc/execution-substrate/ags.json"
    es_config: str = "/etc/execution-substrate/es.json"
    # The client CA files AGS and ES must name in tls.client_ca_file. The
    # recovery runbook keeps them byte-identical.
    ags_client_ca: str = "/etc/execution-substrate/tls/external-client-auth-ca.pem"
    es_client_ca: str = "/etc/execution-substrate/es-tls/server-client-ca.pem"
    user_ca_dir: str = "/etc/execution-substrate/user-ca"

    # The configs of the box's other services that read client or root CA
    # files (CGS does not run on the box). allow refuses while any of these,
    # or any other field of the AGS and ES configs, names either client CA
    # file, so the user CA is trusted by AGS and ES clients and nowhere else.
    other_service_configs: tuple = ("/etc/execution-substrate/ars.json", "/etc/execution-substrate/egs.json")

    ags_unit: str = "ags.service"
    es_unit: str = "es.service"
    lock_path: str = "/run/execution-substrate-remote-alpha-user-identity.lock"

    openssl_bin: str = "/usr/bin/openssl"
    systemctl_bin: str = "/usr/bin/systemctl"
    command_path_env: str = "/usr/sbin:/usr/bin:/sbin:/bin"

    ca_organization: str = "Execution Substrate"
    ca_common_name: str = "Execution Substrate Remote Alpha User CA"
    ca_days: int = 400
    ca_key_bits: int = 3072
    leaf_days: int = 90

    # Caller key directory root; "" means ~/.config/execution-substrate/callers
    # of the effective user (from the password database, not $HOME).
    caller_root: str = ""
    caller_key_bits: int = 3072
    # Caller modes refuse to run with this effective UID (root); tests that
    # run as root set -1.
    refused_caller_euid: int = 0

    command_timeout_seconds: int = 120
    unit_timeout_seconds: int = 120
    # After a restart, wait this long, read the unit, wait again and require
    # the same main process.
    settle_seconds: float = 3.0
    request_timeout_seconds: float = 15.0
    cert_attention_days: int = 14
    ca_attention_days: int = 30


# --------------------------------------------------------------------------
# Errors and reporting


class Refusal(Exception):
    """A precondition does not hold. Nothing was changed by this run."""


class Failure(Exception):
    """A step failed after this run started to change something."""


class Interrupted(Failure):
    """SIGHUP, SIGINT or SIGTERM asked this run to stop."""


class UsageError(Exception):
    pass


class CommandError(Exception):
    pass


_STOP_SIGNALS = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)


def _stop_on_signal(signum, frame):
    # Ignore further stop signals so cleanup and rollback can finish.
    for sig in _STOP_SIGNALS:
        signal.signal(sig, signal.SIG_IGN)
    raise Interrupted(f"stopped by {signal.Signals(signum).name}")


_held_stops = []


@contextlib.contextmanager
def signals_deferred():
    """Hold stop signals while a step that must not be cut short runs (a
    rollback, the commit of a CA replacement). A signal that arrives meanwhile
    does not interrupt the step and does not replace its outcome: when the
    step ends, the signal is dropped, further stop signals are ignored, and
    held_stops_note() names it for the report."""
    old = signal.pthread_sigmask(signal.SIG_BLOCK, _STOP_SIGNALS)
    try:
        yield
    finally:
        pending = signal.sigpending() & set(_STOP_SIGNALS)
        if pending:
            # Setting SIG_IGN discards a pending signal.
            for sig in _STOP_SIGNALS:
                signal.signal(sig, signal.SIG_IGN)
            _held_stops.extend(sorted(signal.Signals(sig).name for sig in pending))
        signal.pthread_sigmask(signal.SIG_SETMASK, old)


def held_stops_note() -> str:
    if not _held_stops:
        return ""
    return f"; {' and '.join(_held_stops)} arrived meanwhile and was held until that step finished"


def printable(value) -> str:
    """value as text with every character that is not printable (a newline,
    an escape sequence, a direction override) written as a Python escape, so
    that text from a CSR, a certificate or a file can neither add a line to a
    report nor rewrite one on the terminal."""
    text = str(value)
    if text.isprintable():
        return text
    out = []
    for ch in text:
        if ch.isprintable():
            out.append(ch)
        elif ord(ch) < 0x100:
            out.append(f"\\x{ord(ch):02x}")
        elif ord(ch) < 0x10000:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(f"\\U{ord(ch):08x}")
    return "".join(out)


class Report:
    """Collects checks, the plan and the actions taken. It never holds a
    private key; render() refuses to print anything that looks like one."""

    def __init__(self, mode: str, apply: bool):
        self.mode = mode
        self.apply = apply
        self.checks: list = []
        self.plan: list = []
        self.actions: list = []
        self.facts: dict = {}
        self.result = ""
        self.message = ""

    def check(self, name: str, state: str, detail: str) -> None:
        self.checks.append({"name": name, "state": state, "detail": detail})

    def planned(self, text: str) -> None:
        self.plan.append(text)

    def action(self, text: str) -> None:
        self.actions.append(text)

    def attention_count(self) -> int:
        return sum(1 for c in self.checks if c["state"] in ("attention", "fail"))

    def document(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "mode": self.mode,
            "apply": self.apply,
            "result": self.result,
            "message": self.message,
            "checks": self.checks,
            "facts": self.facts,
            "plan": self.plan,
            "actions": self.actions,
        }

    def render(self, as_json: bool) -> str:
        doc = self.document()
        if as_json:
            out = json.dumps(doc, indent=2, sort_keys=True) + "\n"
        else:
            p = printable
            lines = [f"User identity {doc['mode']} ({SCHEMA_VERSION})"]
            for c in doc["checks"]:
                lines.append(f"  [{p(c['state'])}] {p(c['name'])}: {p(c['detail'])}")
            for key in sorted(doc["facts"]):
                lines.append(f"  {p(key)}: {p(doc['facts'][key])}")
            if doc["plan"]:
                lines.append("Plan:" if not doc["apply"] else "Planned steps:")
                lines.extend(f"  - {p(step)}" for step in doc["plan"])
            if doc["actions"]:
                lines.append("Changes made:")
                lines.extend(f"  - {p(step)}" for step in doc["actions"])
            lines.append(f"Result: {p(doc['result'])}" + (f" - {p(doc['message'])}" if doc["message"] else ""))
            out = "\n".join(lines) + "\n"
        if "PRIVATE KEY" in out:
            # Defence in depth: nothing this helper reports may carry a key.
            return json.dumps({"schema_version": SCHEMA_VERSION, "mode": self.mode, "result": "failed",
                               "message": "report suppressed: it contained private key text"}) + "\n"
        return out


# --------------------------------------------------------------------------
# Small helpers


def utc_now() -> float:
    return time.time()


def iso_utc(epoch: float) -> str:
    return datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def stamp_utc() -> str:
    return datetime.datetime.now(tz=datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def days_left(not_after: float) -> int:
    return int((not_after - utc_now()) // 86400)


def spiffe_id(L: Layout, name: str) -> str:
    return f"spiffe://{L.trust_domain}/{L.path_namespace}/{name}"


def prefix_for(L: Layout, name: str) -> str:
    return f"{L.path_namespace}/{name}"


def require_name(name) -> str:
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise UsageError("--name must be 1 to 32 characters of a-z, 0-9 and '-', start with a letter and not end with '-'")
    return name


def matches_prefix(path: str, prefix: str) -> bool:
    """Whether prefix could authorize path under any AGS or ES build.

    This is the broader rule of the builds before ES PR #38 (their
    matchesAuthorizedPathPrefix, which ignores leading and trailing slashes),
    and the box may still run such an AGS. The shared rule since then,
    internal/callerallowlist.Matches, matches a subset of these pairs, since it
    first refuses any prefix that is not canonical or has one segment. The
    helper refuses an entry that covers user/<name> by this rule, so it
    refuses at least every entry that covers it on either build.
    """
    p = path.strip("/")
    q = prefix.strip("/")
    if not p or not q:
        return False
    return p == q or p.startswith(q + "/")


def lstat_or_none(path: str):
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None


def read_regular_file(path: str, limit: int):
    """Read a regular file without following a final symlink and without
    blocking on a FIFO. Returns (bytes, stat) or None when it does not exist."""
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


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def atomic_write(path: str, data: bytes, mode: int, uid: int = -1, gid: int = -1) -> None:
    """Replace path through a same-directory temporary file and a rename. The
    temporary file has its final owner and mode before the rename."""
    directory = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix="." + os.path.basename(path) + ".", suffix=".tmp", dir=directory)
    try:
        try:
            if uid != -1 or gid != -1:
                os.fchown(fd, uid, gid)
            os.fchmod(fd, mode)
            _write_all(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
    fsync_dir(directory)


def create_exclusive(path: str, data: bytes, mode: int) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.fchmod(fd, mode)
        _write_all(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    fsync_dir(os.path.dirname(os.path.abspath(path)))


# --------------------------------------------------------------------------
# DER and PEM: just enough X.509 to check every field this helper relies on,
# without parsing openssl text output (which differs between OpenSSL and
# LibreSSL).


class DERError(ValueError):
    pass


def _der_guarded(fn):
    """Turn any other error that a malformed encoding raises inside fn (an
    index past the end, a month 13, a non-ASCII time) into a DERError, so
    every bad input ends as a refusal and never as a traceback."""
    @functools.wraps(fn)
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except DERError:
            raise
        except (IndexError, ValueError, OverflowError) as exc:
            raise DERError(f"malformed encoding ({type(exc).__name__}: {exc})") from None
    return wrapped


OID_CN = "2.5.4.3"
OID_O = "2.5.4.10"
OID_RSA = "1.2.840.113549.1.1.1"
OID_EC = "1.2.840.10045.2.1"
OID_P256 = "1.2.840.10045.3.1.7"
OID_P384 = "1.3.132.0.34"
OID_SHA256_RSA = "1.2.840.113549.1.1.11"
OID_BASIC_CONSTRAINTS = "2.5.29.19"
OID_KEY_USAGE = "2.5.29.15"
OID_EXT_KEY_USAGE = "2.5.29.37"
OID_SAN = "2.5.29.17"
OID_SKI = "2.5.29.14"
OID_AKI = "2.5.29.35"
OID_NAME_CONSTRAINTS = "2.5.29.30"
OID_EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"

KU_DIGITAL_SIGNATURE = 0
KU_KEY_CERT_SIGN = 5
KU_CRL_SIGN = 6

TAG_BOOLEAN = 0x01
TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_UTF8 = 0x0C
TAG_PRINTABLE = 0x13
TAG_IA5 = 0x16
TAG_UTCTIME = 0x17
TAG_GENTIME = 0x18
TAG_SEQUENCE = 0x30
TAG_SET = 0x31


class TLV:
    __slots__ = ("tag", "start", "body_start", "end", "data")

    def __init__(self, data: bytes, tag: int, start: int, body_start: int, end: int):
        self.data = data
        self.tag = tag
        self.start = start
        self.body_start = body_start
        self.end = end

    @property
    def body(self) -> bytes:
        return self.data[self.body_start:self.end]

    @property
    def raw(self) -> bytes:
        return self.data[self.start:self.end]

    def children(self) -> list:
        return der_sequence(self.data, self.body_start, self.end)

    def expect(self, tag: int, what: str) -> "TLV":
        if self.tag != tag:
            raise DERError(f"{what}: expected tag 0x{tag:02x}, found 0x{self.tag:02x}")
        return self


@_der_guarded
def der_read(data: bytes, pos: int, limit: int) -> TLV:
    if pos + 2 > limit:
        raise DERError("truncated element")
    tag = data[pos]
    if tag & 0x1F == 0x1F:
        raise DERError("multi-byte tags are not supported")
    first = data[pos + 1]
    pos2 = pos + 2
    if first < 0x80:
        length = first
    elif first == 0x80:
        raise DERError("indefinite length is not DER")
    else:
        count = first & 0x7F
        if count > 4 or pos2 + count > limit:
            raise DERError("bad length")
        length = int.from_bytes(data[pos2:pos2 + count], "big")
        if data[pos2] == 0 or length < 0x80:
            raise DERError("length is not minimally encoded")
        pos2 += count
    end = pos2 + length
    if end > limit:
        raise DERError("element runs past its container")
    return TLV(data, tag, pos, pos2, end)


@_der_guarded
def der_sequence(data: bytes, start: int, end: int) -> list:
    items = []
    pos = start
    while pos < end:
        item = der_read(data, pos, end)
        items.append(item)
        pos = item.end
    return items


@_der_guarded
def der_top(data: bytes) -> TLV:
    top = der_read(data, 0, len(data))
    if top.end != len(data):
        raise DERError("trailing data after the outer element")
    return top


@_der_guarded
def decode_oid(body: bytes) -> str:
    if not body:
        raise DERError("empty OID")
    parts = []
    value = 0
    for i, byte in enumerate(body):
        if value == 0 and byte == 0x80:
            raise DERError("OID arc is not minimally encoded")
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
        elif i == len(body) - 1:
            raise DERError("truncated OID")
    first = parts[0]
    if first < 40:
        head = [0, first]
    elif first < 80:
        head = [1, first - 40]
    else:
        head = [2, first - 80]
    return ".".join(str(p) for p in head + parts[1:])


@_der_guarded
def decode_integer(body: bytes) -> int:
    if not body:
        raise DERError("empty INTEGER")
    return int.from_bytes(body, "big", signed=True)


@_der_guarded
def decode_time(item: TLV) -> float:
    text = item.body.decode("ascii")
    if item.tag == TAG_UTCTIME:
        if not re.fullmatch(r"\d{12}Z", text):
            raise DERError("bad UTCTime")
        year = int(text[0:2])
        year += 2000 if year < 50 else 1900
        rest = text[2:]
    elif item.tag == TAG_GENTIME:
        if not re.fullmatch(r"\d{14}Z", text):
            raise DERError("bad GeneralizedTime")
        year = int(text[0:4])
        rest = text[4:]
    else:
        raise DERError("bad time tag")
    moment = datetime.datetime(year, int(rest[0:2]), int(rest[2:4]), int(rest[4:6]), int(rest[6:8]),
                               int(rest[8:10]), tzinfo=datetime.timezone.utc)
    return moment.timestamp()


@_der_guarded
def decode_name(item: TLV) -> list:
    """A Name as a list of RDNs, each a list of (oid, tag, text)."""
    item.expect(TAG_SEQUENCE, "Name")
    rdns = []
    for rdn in item.children():
        rdn.expect(TAG_SET, "RDN")
        avas = []
        for ava in rdn.children():
            ava.expect(TAG_SEQUENCE, "AttributeTypeAndValue")
            parts = ava.children()
            if len(parts) != 2:
                raise DERError("bad AttributeTypeAndValue")
            oid = decode_oid(parts[0].expect(TAG_OID, "attribute type").body)
            value = parts[1]
            try:
                text = value.body.decode("utf-8")
            except UnicodeDecodeError:
                text = None
            avas.append((oid, value.tag, text))
        rdns.append(avas)
    return rdns


def name_is_single_cn(rdns: list, cn: str) -> bool:
    return (len(rdns) == 1 and len(rdns[0]) == 1 and rdns[0][0][0] == OID_CN
            and rdns[0][0][1] in (TAG_UTF8, TAG_PRINTABLE) and rdns[0][0][2] == cn)


def name_text(rdns: list) -> str:
    labels = {OID_CN: "CN", OID_O: "O"}
    out = []
    for rdn in rdns:
        out.append("+".join(f"{labels.get(oid, oid)}={printable(text) if text is not None else '?'}" for oid, _, text in rdn))
    return ", ".join(out)


@_der_guarded
def decode_spki(item: TLV) -> dict:
    item.expect(TAG_SEQUENCE, "SubjectPublicKeyInfo")
    parts = item.children()
    if len(parts) != 2:
        raise DERError("bad SubjectPublicKeyInfo")
    alg = parts[0].expect(TAG_SEQUENCE, "key algorithm").children()
    oid = decode_oid(alg[0].expect(TAG_OID, "key algorithm OID").body)
    bits = parts[1].expect(TAG_BIT_STRING, "public key")
    if not bits.body or bits.body[0] != 0:
        raise DERError("public key BIT STRING has unused bits")
    key = {"der": item.raw, "sha256": sha256_hex(item.raw)}
    if oid == OID_RSA:
        if len(alg) != 2 or alg[1].tag != TAG_NULL or alg[1].body:
            raise DERError("RSA key parameters must be NULL")
        rsa = der_top(bits.body[1:]).expect(TAG_SEQUENCE, "RSAPublicKey").children()
        if len(rsa) != 2:
            raise DERError("bad RSAPublicKey")
        modulus_body = rsa[0].expect(TAG_INTEGER, "modulus").body
        exponent_body = rsa[1].expect(TAG_INTEGER, "exponent").body
        modulus = decode_integer(modulus_body)
        exponent = decode_integer(exponent_body)
        if modulus <= 0 or exponent <= 1:
            raise DERError("bad RSA public key")
        key.update(kind="rsa", size=modulus.bit_length(), exponent=exponent,
                   canonical=integer_is_minimal(modulus_body) and integer_is_minimal(exponent_body))
    elif oid == OID_EC:
        if len(alg) != 2:
            raise DERError("EC key without a named curve")
        curve = decode_oid(alg[1].expect(TAG_OID, "EC curve").body)
        size = {OID_P256: 256, OID_P384: 384}.get(curve, 0)
        point = bits.body[1:]
        # The uncompressed form, 0x04 then both coordinates at full length,
        # is the one encoding Go's crypto/x509 reads, and the only one the
        # key-reuse check can compare byte for byte.
        key.update(kind="ec", curve=curve, size=size,
                   canonical=bool(size) and len(point) == 1 + 2 * (size // 8) and point[0] == 0x04)
    else:
        key.update(kind=oid, size=0, canonical=False)
    return key


def integer_is_minimal(body: bytes) -> bool:
    """Whether a DER INTEGER body has no redundant leading byte."""
    return not (len(body) > 1 and ((body[0] == 0x00 and body[1] < 0x80) or (body[0] == 0xFF and body[1] >= 0x80)))


def key_text(key: dict) -> str:
    if key["kind"] == "rsa":
        return f"RSA-{key['size']}"
    if key["kind"] == "ec":
        return {OID_P256: "EC P-256", OID_P384: "EC P-384"}.get(key["curve"], f"EC {key['curve']}")
    return f"key algorithm {key['kind']}"


@_der_guarded
def decode_general_names(body: bytes) -> list:
    """GeneralNames as a list of (kind, value)."""
    seq = der_top(body).expect(TAG_SEQUENCE, "GeneralNames")
    names = []
    for gn in seq.children():
        kind = {0x86: "URI", 0x82: "DNS", 0x81: "email", 0x87: "IP"}.get(gn.tag, f"tag-0x{gn.tag:02x}")
        if kind in ("URI", "DNS", "email"):
            try:
                value = gn.body.decode("ascii")
            except UnicodeDecodeError:
                raise DERError(f"{kind} name is not ASCII") from None
        else:
            value = gn.body.hex()
        names.append((kind, value))
    return names


@_der_guarded
def decode_extensions(item: TLV) -> dict:
    """[3] Extensions as {oid: (critical, value bytes)}; duplicates refused."""
    seq = der_top(item.body).expect(TAG_SEQUENCE, "Extensions")
    out = {}
    for ext in seq.children():
        parts = ext.expect(TAG_SEQUENCE, "Extension").children()
        if len(parts) not in (2, 3):
            raise DERError("bad Extension")
        oid = decode_oid(parts[0].expect(TAG_OID, "extension OID").body)
        critical = False
        if len(parts) == 3:
            flag = parts[1].expect(TAG_BOOLEAN, "critical flag").body
            if flag != b"\xff":
                # DER forbids an explicit FALSE (it is the DEFAULT).
                raise DERError("critical flag is not DER TRUE")
            critical = True
        value = parts[-1].expect(TAG_OCTET_STRING, "extension value").body
        if oid in out:
            raise DERError(f"duplicate extension {oid}")
        out[oid] = (critical, value)
    return out


@_der_guarded
def ext_basic_constraints(value: bytes) -> tuple:
    seq = der_top(value).expect(TAG_SEQUENCE, "BasicConstraints").children()
    ca = False
    pathlen = None
    rest = list(seq)
    if rest and rest[0].tag == TAG_BOOLEAN:
        if rest[0].body != b"\xff":
            raise DERError("cA is not DER TRUE")
        ca = True
        rest = rest[1:]
    if rest:
        pathlen = decode_integer(rest[0].expect(TAG_INTEGER, "pathLenConstraint").body)
        rest = rest[1:]
    if rest:
        raise DERError("bad BasicConstraints")
    return ca, pathlen


@_der_guarded
def ext_key_usage(value: bytes) -> set:
    bits = der_top(value).expect(TAG_BIT_STRING, "KeyUsage").body
    if not bits:
        raise DERError("empty KeyUsage")
    unused = bits[0]
    out = set()
    payload = bits[1:]
    for i, byte in enumerate(payload):
        for j in range(8):
            if byte & (0x80 >> j):
                out.add(i * 8 + j)
    if payload and unused and payload[-1] & ((1 << unused) - 1):
        raise DERError("KeyUsage sets unused bits")
    return out


@_der_guarded
def ext_eku(value: bytes) -> list:
    seq = der_top(value).expect(TAG_SEQUENCE, "ExtKeyUsage").children()
    return [decode_oid(item.expect(TAG_OID, "key purpose").body) for item in seq]


@_der_guarded
def ext_name_constraints(value: bytes) -> dict:
    seq = der_top(value).expect(TAG_SEQUENCE, "NameConstraints").children()
    out = {"permitted": [], "excluded": []}
    for part in seq:
        if part.tag == 0xA0:
            key = "permitted"
        elif part.tag == 0xA1:
            key = "excluded"
        else:
            raise DERError("bad NameConstraints")
        for subtree in part.children():
            fields = subtree.expect(TAG_SEQUENCE, "GeneralSubtree").children()
            if len(fields) != 1:
                raise DERError("GeneralSubtree with minimum or maximum")
            gn = fields[0]
            kind = {0x86: "URI", 0x82: "DNS", 0x81: "email"}.get(gn.tag, f"tag-0x{gn.tag:02x}")
            out[key].append((kind, gn.body.decode("ascii", "replace")))
    return out


@_der_guarded
def parse_certificate(der: bytes) -> dict:
    cert = der_top(der).expect(TAG_SEQUENCE, "Certificate").children()
    if len(cert) != 3:
        raise DERError("bad Certificate")
    tbs_item = cert[0].expect(TAG_SEQUENCE, "TBSCertificate")
    tbs = tbs_item.children()
    index = 0
    version = 1
    if tbs and tbs[0].tag == 0xA0:
        version = decode_integer(der_top(tbs[0].body).expect(TAG_INTEGER, "version").body) + 1
        index = 1
    fields = tbs[index:]
    if len(fields) < 6:
        raise DERError("bad TBSCertificate")
    serial = decode_integer(fields[0].expect(TAG_INTEGER, "serial").body)
    sig_alg = decode_oid(fields[1].expect(TAG_SEQUENCE, "signature algorithm").children()[0].body)
    issuer = fields[2]
    validity = fields[3].expect(TAG_SEQUENCE, "Validity").children()
    if len(validity) != 2:
        raise DERError("bad Validity")
    subject = fields[4]
    spki = decode_spki(fields[5])
    extensions = {}
    for extra in fields[6:]:
        if extra.tag == 0xA3:
            extensions = decode_extensions(extra)
        elif extra.tag in (0x81, 0x82):
            raise DERError("issuer or subject unique IDs are not accepted")
        else:
            raise DERError("bad TBSCertificate field")
    outer_alg = decode_oid(cert[1].expect(TAG_SEQUENCE, "signatureAlgorithm").children()[0].body)
    if outer_alg != sig_alg:
        raise DERError("signature algorithm mismatch")
    return {
        "der": der,
        "sha256": sha256_hex(der),
        "version": version,
        "serial": serial,
        "signature_algorithm": sig_alg,
        "issuer_der": issuer.raw,
        "issuer": decode_name(issuer),
        "subject_der": subject.raw,
        "subject": decode_name(subject),
        "not_before": decode_time(validity[0]),
        "not_after": decode_time(validity[1]),
        "key": spki,
        "extensions": extensions,
    }


@_der_guarded
def parse_csr(der: bytes) -> dict:
    csr = der_top(der).expect(TAG_SEQUENCE, "CertificationRequest").children()
    if len(csr) != 3:
        raise DERError("bad CertificationRequest")
    info = csr[0].expect(TAG_SEQUENCE, "CertificationRequestInfo").children()
    if len(info) != 4:
        raise DERError("bad CertificationRequestInfo")
    version = decode_integer(info[0].expect(TAG_INTEGER, "version").body)
    attributes = info[3].expect(0xA0, "attributes").children()
    return {
        "version": version,
        "subject": decode_name(info[1]),
        "key": decode_spki(info[2]),
        "attribute_count": len(attributes),
        "signature_algorithm": decode_oid(csr[1].expect(TAG_SEQUENCE, "signatureAlgorithm").children()[0].body),
    }


_PEM_RE = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----\n((?:[A-Za-z0-9+/=]{1,76}\n)+)-----END \1-----\n?")


def pem_blocks(data: bytes, what: str) -> list:
    """Every PEM block of data as (label, der, block bytes). Only white space
    may stand between blocks; carriage returns are refused."""
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise Refusal(f"{what} is not ASCII PEM") from None
    if "\r" in text:
        raise Refusal(f"{what} has carriage returns")
    blocks = []
    pos = 0
    while True:
        while pos < len(text) and text[pos] in " \t\n":
            pos += 1
        if pos >= len(text):
            break
        match = _PEM_RE.match(text, pos)
        if not match:
            raise Refusal(f"{what} has text outside PEM blocks or a malformed block at byte {pos}")
        try:
            der = base64.b64decode("".join(match.group(2).split()), validate=True)
        except (binascii.Error, ValueError):
            raise Refusal(f"{what} has a PEM block that is not base64") from None
        blocks.append((match.group(1), der, match.group(0).encode("ascii")))
        pos = match.end()
    return blocks


def pem_encode(label: str, der: bytes) -> bytes:
    body = base64.b64encode(der).decode("ascii")
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return ("-----BEGIN " + label + "-----\n" + "\n".join(lines) + "\n-----END " + label + "-----\n").encode("ascii")


def single_pem(data: bytes, label: str, what: str) -> bytes:
    blocks = pem_blocks(data, what)
    if len(blocks) != 1 or blocks[0][0] != label:
        raise Refusal(f"{what} must hold exactly one {label} block")
    return blocks[0][1]


def load_certificate_file(path: str, what: str) -> dict:
    found = read_regular_file(path, 64 * 1024)
    if found is None:
        raise Refusal(f"{what} {path} does not exist")
    der = single_pem(found[0], "CERTIFICATE", f"{what} {path}")
    try:
        return parse_certificate(der)
    except DERError as exc:
        raise Refusal(f"{what} {path} is not a certificate this helper can read: {exc}") from None


# --------------------------------------------------------------------------
# Certificate profiles


def leaf_profile_problems(L: Layout, cert: dict, name: str) -> list:
    """Problems with a user leaf, judged without its issuer."""
    problems = []
    ext = cert["extensions"]
    if cert["version"] != 3:
        problems.append("not an X.509 v3 certificate")
    if not name_is_single_cn(cert["subject"], name):
        problems.append(f"subject is {name_text(cert['subject'])}, want CN={name}")
    try:
        if OID_BASIC_CONSTRAINTS not in ext or not ext[OID_BASIC_CONSTRAINTS][0]:
            problems.append("basic constraints missing or not critical")
        elif ext_basic_constraints(ext[OID_BASIC_CONSTRAINTS][1]) != (False, None):
            problems.append("basic constraints are not CA:FALSE")
        if OID_KEY_USAGE not in ext or not ext[OID_KEY_USAGE][0]:
            problems.append("key usage missing or not critical")
        elif ext_key_usage(ext[OID_KEY_USAGE][1]) != {KU_DIGITAL_SIGNATURE}:
            problems.append("key usage is not exactly digitalSignature")
        if OID_EXT_KEY_USAGE not in ext:
            problems.append("extended key usage missing")
        elif ext_eku(ext[OID_EXT_KEY_USAGE][1]) != [OID_EKU_CLIENT_AUTH]:
            problems.append("extended key usage is not exactly clientAuth")
        if OID_SAN not in ext:
            problems.append("subject alternative name missing")
        elif decode_general_names(ext[OID_SAN][1]) != [("URI", spiffe_id(L, name))]:
            problems.append(f"subject alternative names are not exactly URI:{spiffe_id(L, name)}")
    except DERError as exc:
        problems.append(f"unreadable extension: {exc}")
    allowed = {OID_BASIC_CONSTRAINTS, OID_KEY_USAGE, OID_EXT_KEY_USAGE, OID_SAN, OID_SKI, OID_AKI}
    extra = sorted(set(ext) - allowed)
    if extra:
        problems.append("unexpected extensions " + ", ".join(extra))
    return problems


def ca_profile_problems(L: Layout, cert: dict) -> list:
    problems = []
    ext = cert["extensions"]
    want_subject = [[(OID_O, TAG_UTF8, L.ca_organization)], [(OID_CN, TAG_UTF8, L.ca_common_name)]]
    subject = [[(oid, TAG_UTF8 if tag in (TAG_UTF8, TAG_PRINTABLE) else tag, text) for oid, tag, text in rdn]
               for rdn in cert["subject"]]
    if subject != want_subject:
        problems.append(f"subject is {name_text(cert['subject'])}")
    if cert["issuer_der"] != cert["subject_der"]:
        problems.append("not self-issued")
    if cert["key"]["kind"] != "rsa" or cert["key"]["size"] != L.ca_key_bits:
        problems.append(f"key is {key_text(cert['key'])}, want RSA-{L.ca_key_bits}")
    if cert["signature_algorithm"] != OID_SHA256_RSA:
        problems.append("not signed with sha256WithRSAEncryption")
    try:
        if OID_BASIC_CONSTRAINTS not in ext or not ext[OID_BASIC_CONSTRAINTS][0]:
            problems.append("basic constraints missing or not critical")
        elif ext_basic_constraints(ext[OID_BASIC_CONSTRAINTS][1]) != (True, 0):
            problems.append("basic constraints are not CA:TRUE, pathlen:0")
        if OID_KEY_USAGE not in ext or not ext[OID_KEY_USAGE][0]:
            problems.append("key usage missing or not critical")
        elif ext_key_usage(ext[OID_KEY_USAGE][1]) != {KU_KEY_CERT_SIGN, KU_CRL_SIGN}:
            problems.append("key usage is not exactly keyCertSign, cRLSign")
        if OID_NAME_CONSTRAINTS not in ext or not ext[OID_NAME_CONSTRAINTS][0]:
            problems.append("name constraints missing or not critical")
        elif ext_name_constraints(ext[OID_NAME_CONSTRAINTS][1]) != {"permitted": [("URI", L.trust_domain)], "excluded": []}:
            problems.append(f"name constraints do not permit exactly URI:{L.trust_domain}")
        if OID_EXT_KEY_USAGE not in ext:
            problems.append("extended key usage missing")
        elif ext_eku(ext[OID_EXT_KEY_USAGE][1]) != [OID_EKU_CLIENT_AUTH]:
            problems.append("extended key usage is not exactly clientAuth")
        if OID_SKI not in ext:
            problems.append("subject key identifier missing")
    except DERError as exc:
        problems.append(f"unreadable extension: {exc}")
    extra = sorted(set(ext) - {OID_BASIC_CONSTRAINTS, OID_KEY_USAGE, OID_EXT_KEY_USAGE, OID_NAME_CONSTRAINTS, OID_SKI, OID_AKI})
    if extra:
        problems.append("unexpected extensions " + ", ".join(extra))
    return problems


def csr_problems(csr: dict, name: str) -> list:
    problems = []
    if csr["version"] != 0:
        problems.append("CSR version is not 1")
    if not name_is_single_cn(csr["subject"], name):
        problems.append(f"CSR subject is {name_text(csr['subject'])}, want exactly CN={name}")
    if csr["attribute_count"]:
        problems.append("CSR carries attributes or requested extensions; make it with the request mode")
    key = csr["key"]
    if key["kind"] == "rsa":
        if not 3072 <= key["size"] <= 8192:
            problems.append(f"CSR key is {key_text(key)}; RSA keys must have 3072 to 8192 bits")
        elif not key["canonical"]:
            problems.append("CSR key is RSA with an integer that is not minimally encoded; make the CSR with the request mode")
    elif key["kind"] == "ec":
        if key["curve"] not in (OID_P256, OID_P384):
            problems.append(f"CSR key is {key_text(key)}; EC keys must be P-256 or P-384")
        elif not key["canonical"]:
            problems.append(f"CSR key is {key_text(key)} but not an uncompressed point; AGS and ES read only that form, "
                            "and the key-reuse check compares keys in it")
    else:
        problems.append(f"CSR key is {key_text(key)}; use RSA or EC")
    return problems


# --------------------------------------------------------------------------
# Commands


class Runner:
    def __init__(self, layout: Layout):
        self.L = layout

    def run(self, argv: list, *, timeout=None, check: bool = True, cwd: str = "/", stdin=None) -> subprocess.CompletedProcess:
        try:
            proc = subprocess.run(
                list(argv),
                input=stdin,
                stdin=None if stdin is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={"PATH": self.L.command_path_env, "LC_ALL": "C"},
                cwd=cwd,
                timeout=timeout if timeout is not None else self.L.command_timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise CommandError(f"{os.path.basename(argv[0])} {' '.join(argv[1:3])} timed out") from None
        except OSError as exc:
            raise CommandError(f"cannot run {argv[0]}: {exc.strerror}") from None
        if check and proc.returncode != 0:
            output = (proc.stderr or b"").decode("utf-8", "replace").strip() or (proc.stdout or b"").decode("utf-8", "replace").strip()
            raise CommandError(f"{os.path.basename(argv[0])} {' '.join(argv[1:3])} exited {proc.returncode}: {output[-600:]}")
        return proc

    # openssl

    def openssl(self, args: list, **kwargs) -> subprocess.CompletedProcess:
        return self.run([self.L.openssl_bin] + list(args), **kwargs)

    def public_key_der(self, key_path: str) -> bytes:
        out = self.openssl(["pkey", "-in", key_path, "-pubout", "-outform", "DER"]).stdout
        try:
            return decode_spki(der_top(out))["der"]
        except DERError as exc:
            raise CommandError(f"openssl pkey printed no public key: {exc}") from None

    def csr_signature_ok(self, csr_pem: bytes) -> bool:
        proc = self.openssl(["req", "-noout", "-verify"], check=False, stdin=csr_pem)
        text = (proc.stdout + proc.stderr).decode("utf-8", "replace").lower()
        return proc.returncode == 0 and "verify ok" in text and "fail" not in text

    def chain_ok(self, ca_path: str, cert_path: str, purpose: str) -> bool:
        proc = self.openssl(["verify", "-CAfile", ca_path, "-no-CApath", "-no-CAstore", "-purpose", purpose, cert_path], check=False)
        return proc.returncode == 0 and proc.stdout.decode("utf-8", "replace").rstrip().endswith(": OK")

    # systemd

    def unit(self, unit: str) -> dict:
        out = self.run([self.L.systemctl_bin, "show", unit, "--property=ActiveState,SubState,MainPID,LoadState"]).stdout
        props = {}
        for line in out.decode("utf-8", "replace").splitlines():
            key, sep, value = line.partition("=")
            if sep:
                props[key] = value
        return props

    def restart(self, unit: str) -> None:
        self.run([self.L.systemctl_bin, "restart", unit], timeout=self.L.unit_timeout_seconds)


def unit_running(props: dict) -> bool:
    return props.get("ActiveState") == "active" and props.get("SubState") == "running" and props.get("MainPID", "0") not in ("", "0")


def restart_and_confirm(r: Runner, unit: str) -> str:
    """Restart unit and require it to stay running with one main process
    across two settle periods. Returns its main PID."""
    r.restart(unit)
    time.sleep(r.L.settle_seconds)
    first = r.unit(unit)
    if not unit_running(first):
        raise Failure(f"{unit} is {first.get('ActiveState', '?')}/{first.get('SubState', '?')} after restart")
    time.sleep(r.L.settle_seconds)
    second = r.unit(unit)
    if not unit_running(second) or second.get("MainPID") != first.get("MainPID"):
        raise Failure(f"{unit} did not stay running after restart (main PID {first.get('MainPID')} -> {second.get('MainPID')}, {second.get('ActiveState')}/{second.get('SubState')})")
    return second["MainPID"]


# --------------------------------------------------------------------------
# Box files


def require_box_dir(L: Layout, path: str) -> None:
    st = lstat_or_none(path)
    if st is None:
        raise Refusal(f"{path} does not exist")
    if not stat.S_ISDIR(st.st_mode):
        raise Refusal(f"{path} is not a directory")
    if st.st_uid != L.box_owner_uid or st.st_mode & 0o022:
        raise Refusal(f"{path} must be owned by UID {L.box_owner_uid} and not writable by group or others")


def read_box_file(L: Layout, path: str, limit: int, *, missing_ok: bool = False):
    require_box_dir(L, os.path.dirname(path))
    found = read_regular_file(path, limit)
    if found is None:
        if missing_ok:
            return None
        raise Refusal(f"{path} does not exist")
    data, st = found
    if st.st_uid != L.box_owner_uid or st.st_mode & 0o022:
        raise Refusal(f"{path} must be owned by UID {L.box_owner_uid} and not writable by group or others")
    refuse_extended_attributes(path)
    return data, st


def refuse_extended_attributes(path: str) -> None:
    """Refuse a file that carries an extended attribute this helper would
    drop when it replaces the file (a POSIX ACL, a user. or trusted.
    attribute). security. attributes belong to the kernel's security modules,
    which label a new file themselves."""
    if not hasattr(os, "listxattr"):
        return
    try:
        names = os.listxattr(path, follow_symlinks=False)
    except OSError as exc:
        if exc.errno in (errno.ENOTSUP, errno.EOPNOTSUPP):
            return
        raise Refusal(f"cannot list the extended attributes of {path}: {exc.strerror}") from None
    kept = sorted(n for n in names if not n.startswith("security."))
    if kept:
        raise Refusal(f"{path} carries the extended attribute {kept[0]}; replacing the file would drop it, so this helper refuses such files")


class FileState:
    """One box file this run may replace: its path, its bytes and metadata
    when read, and the bytes this run wants it to have."""

    def __init__(self, path: str, data: bytes, st: os.stat_result):
        self.path = path
        self.old = data
        self.st = st
        self.new = data
        # revoke --remove-ca: this config's bytes with every edit but the
        # removal of the user binding, written instead of new when the
        # service's client CA file could not be written without the user CA.
        self.keep_binding = None

    @property
    def changed(self) -> bool:
        return self.new != self.old

    def write(self, data: bytes) -> None:
        atomic_write(self.path, data, stat.S_IMODE(self.st.st_mode), self.st.st_uid, self.st.st_gid)

    def write_new(self) -> None:
        self.write(self.new)

    def restore(self) -> None:
        self.write(self.old)

    def current_is(self, data: bytes) -> bool:
        found = read_regular_file(self.path, max(len(self.old), len(self.new)) + 1)
        return found is not None and found[0] == data


# --------------------------------------------------------------------------
# Service JSON configs: the allowlist array is edited in place and every
# other byte is kept.


def _no_duplicate_keys(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r}")
        out[key] = value
    return out


def _refuse_constant(name):
    raise ValueError(f"{name} is not JSON")


def parse_json_strict(text: str):
    return json.loads(text, object_pairs_hook=_no_duplicate_keys, parse_constant=_refuse_constant)


_WS = re.compile(r"[ \t\n\r]*")


def find_member_span(text: str, keys: tuple) -> tuple:
    """Source span (start, end) of the value at keys in the JSON object text,
    walking members in order. Duplicate keys on the path are refused."""
    decoder = json.JSONDecoder()

    def skip(i: int) -> int:
        return _WS.match(text, i).end()

    def walk(i: int, path: tuple):
        i = skip(i)
        if i >= len(text) or text[i] != "{":
            raise ValueError("expected an object")
        i = skip(i + 1)
        found = None
        if text[i] == "}":
            return None
        while True:
            key, i = decoder.raw_decode(text, i)
            if not isinstance(key, str):
                raise ValueError("object key is not a string")
            i = skip(i)
            if text[i] != ":":
                raise ValueError("expected ':'")
            start = skip(i + 1)
            _, end = decoder.raw_decode(text, start)
            if key == path[0]:
                if found is not None:
                    raise ValueError(f"duplicate key {key!r}")
                found = (start, end) if len(path) == 1 else walk(start, path[1:])
            i = skip(end)
            if text[i] == ",":
                i = skip(i + 1)
                continue
            if text[i] == "}":
                return found
            raise ValueError("expected ',' or '}'")

    span = walk(0, keys)
    if span is None:
        raise ValueError("missing " + ".".join(keys))
    return span


def array_element_spans(text: str, start: int, end: int) -> list:
    decoder = json.JSONDecoder()
    if text[start] != "[" or text[end - 1] != "]":
        raise ValueError("not an array")
    spans = []
    i = _WS.match(text, start + 1).end()
    if text[i] == "]":
        return spans
    while True:
        _, element_end = decoder.raw_decode(text, i)
        spans.append((i, element_end))
        i = _WS.match(text, element_end).end()
        if text[i] == ",":
            i = _WS.match(text, i + 1).end()
            continue
        if text[i] == "]" and i == end - 1:
            return spans
        raise ValueError("malformed array")


def array_with_added(text: str, start: int, end: int, value: str) -> str:
    spans = array_element_spans(text, start, end)
    encoded = json.dumps(value)
    if not spans:
        return text[:start] + "[" + encoded + "]" + text[end:]
    if len(spans) >= 2:
        separator = text[spans[-2][1]:spans[-1][0]]
    elif "\n" in text[start:spans[0][0]]:
        separator = "," + text[start + 1:spans[0][0]]
    else:
        separator = ", "
    last_end = spans[-1][1]
    return text[:last_end] + separator + encoded + text[last_end:]


def array_with_removed(text: str, start: int, end: int, index: int, allow_empty: bool = False) -> str:
    spans = array_element_spans(text, start, end)
    if len(spans) < 2:
        if allow_empty and len(spans) == 1 and index == 0:
            return text[:start] + "[]" + text[end:]
        raise Refusal("the allowlist would become empty, which AGS and ES refuse")
    if index > 0:
        cut = (spans[index - 1][1], spans[index][1])
    else:
        cut = (spans[0][0], spans[1][0])
    return text[:cut[0]] + text[cut[1]:]


def object_member_spans(text: str, start: int, end: int) -> list:
    """(key start, key end, value start, value end, key) of each member of
    the JSON object at text[start:end]."""
    decoder = json.JSONDecoder()
    if text[start] != "{" or text[end - 1] != "}":
        raise ValueError("not an object")
    spans = []
    i = _WS.match(text, start + 1).end()
    if text[i] == "}":
        if i != end - 1:
            raise ValueError("malformed object")
        return spans
    while True:
        key, key_end = decoder.raw_decode(text, i)
        if not isinstance(key, str):
            raise ValueError("object key is not a string")
        colon = _WS.match(text, key_end).end()
        if text[colon] != ":":
            raise ValueError("expected ':'")
        value_start = _WS.match(text, colon + 1).end()
        _, value_end = decoder.raw_decode(text, value_start)
        spans.append((i, key_end, value_start, value_end, key))
        i = _WS.match(text, value_end).end()
        if text[i] == ",":
            i = _WS.match(text, i + 1).end()
            continue
        if text[i] == "}" and i == end - 1:
            return spans
        raise ValueError("malformed object")


def object_with_member_added(text: str, start: int, end: int, key: str, value) -> str:
    """The object at text[start:end] with the member key: value added last,
    laid out like the members already there."""
    spans = object_member_spans(text, start, end)
    if not spans:
        return text[:start] + "{" + json.dumps(key) + ": " + json.dumps(value) + "}" + text[end:]
    if len(spans) >= 2:
        separator = text[spans[-2][3]:spans[-1][0]]
    elif "\n" in text[start:spans[0][0]]:
        separator = "," + text[start + 1:spans[0][0]]
    else:
        separator = ", "
    colon = text[spans[-1][1]:spans[-1][2]]
    last_end = spans[-1][3]
    return text[:last_end] + separator + json.dumps(key) + colon + json.dumps(value) + text[last_end:]


def object_with_member_removed(text: str, start: int, end: int, key: str) -> str:
    spans = object_member_spans(text, start, end)
    found = [i for i, span in enumerate(spans) if span[4] == key]
    if len(found) != 1:
        raise ValueError(f"the object has {len(found)} members {key!r}")
    index = found[0]
    if len(spans) == 1:
        return text[:start] + "{}" + text[end:]
    if index > 0:
        cut = (spans[index - 1][3], spans[index][3])
    else:
        cut = (spans[0][0], spans[1][0])
    return text[:cut[0]] + text[cut[1]:]


_GO_FIELD_KEY = re.compile(r"\A[a-z0-9_]+\Z")

ISSUER_KEYS = ("path_prefix", "issuer_certificate_sha256")
_SHA256_HEX = re.compile(r"\A[0-9a-f]{64}\Z")


class ServiceConfig:
    """One service's JSON config. Edits are byte-preserving: each changes one
    value in place, keeps every byte outside it, and the edited document must
    parse to the expected one."""

    PATH = ("authorization", "allowed_spiffe_path_prefixes")
    ISSUERS = ("security", "namespace_issuers")
    RULES = ("admission_policy", "workload_grants", "rules")

    def __init__(self, label: str, file: FileState):
        self.label = label
        self.file = file
        try:
            self.text = file.old.decode("utf-8")
            self.doc = parse_json_strict(self.text)
        except (UnicodeDecodeError, ValueError) as exc:
            raise Refusal(f"{file.path} is not strict JSON: {exc}") from None
        if not isinstance(self.doc, dict):
            raise Refusal(f"{file.path} is not a JSON object")
        # Go's encoding/json matches object keys to struct fields without
        # regard to case, so "Authorization" would also feed a field this
        # helper reads or edits. Every real field name is lower-case ASCII;
        # refuse any other key on the objects read here, so no case variant
        # can hide.
        security = self.doc.get("security")
        policy = self.doc.get("admission_policy")
        grants = policy.get("workload_grants") if isinstance(policy, dict) else None
        objects = [("the top level", self.doc), ("authorization", self.doc.get("authorization")),
                   ("tls", self.doc.get("tls")), ("security", security), ("admission_policy", policy),
                   ("admission_policy.workload_grants", grants)]
        issuers = security.get("namespace_issuers") if isinstance(security, dict) else None
        rules = grants.get("rules") if isinstance(grants, dict) else None
        for listed, where in ((issuers, "security.namespace_issuers"), (rules, "admission_policy.workload_grants.rules")):
            if isinstance(listed, list):
                objects.extend((f"{where}[{i}]", item) for i, item in enumerate(listed))
        for where, obj in objects:
            if isinstance(obj, dict):
                odd = sorted(k for k in obj if not _GO_FIELD_KEY.match(k))
                if odd:
                    raise Refusal(f"{file.path} has key {odd[0]!r} in {where}; only lower-case ASCII keys are accepted")
        authorization = self.doc.get("authorization")
        prefixes = authorization.get("allowed_spiffe_path_prefixes") if isinstance(authorization, dict) else None
        if not isinstance(prefixes, list) or not prefixes or not all(isinstance(p, str) for p in prefixes):
            raise Refusal(f"{file.path} authorization.allowed_spiffe_path_prefixes is not a non-empty list of strings")
        self.prefixes = list(prefixes)
        tls = self.doc.get("tls")
        self.client_ca_file = tls.get("client_ca_file") if isinstance(tls, dict) else None
        self.bootstrap_cn = security.get("bootstrap_issuer_common_name") if isinstance(security, dict) else None
        self.namespace_issuers = self._read_issuers(security)
        self.issuers_as_read = self.namespace_issuers
        self.grant_rules = self._read_rules(policy, grants)
        try:
            self.span = find_member_span(self.text, self.PATH)
        except ValueError as exc:
            raise Refusal(f"{file.path}: cannot locate the allowlist: {exc}") from None
        self.text_now = self.text
        self.expected = copy.deepcopy(self.doc)

    def _read_issuers(self, security):
        """security.namespace_issuers as (path_prefix, sha256) pairs, or None
        when the member is absent."""
        if not isinstance(security, dict) or "namespace_issuers" not in security:
            return None
        items = security["namespace_issuers"]
        if not isinstance(items, list):
            raise Refusal(f"{self.file.path} security.namespace_issuers is not a list")
        out = []
        for i, item in enumerate(items):
            if not isinstance(item, dict) or sorted(item) != sorted(ISSUER_KEYS) or not all(isinstance(v, str) for v in item.values()):
                raise Refusal(f"{self.file.path} security.namespace_issuers[{i}] is not an object of exactly the strings "
                              "path_prefix and issuer_certificate_sha256")
            out.append((item["path_prefix"], item["issuer_certificate_sha256"]))
        return out

    def _read_rules(self, policy, grants):
        """admission_policy.workload_grants.rules, or [] when absent."""
        if policy is None or grants is None:
            if policy is not None and not isinstance(policy, dict):
                raise Refusal(f"{self.file.path} admission_policy is not an object")
            return []
        if not isinstance(grants, dict):
            raise Refusal(f"{self.file.path} admission_policy.workload_grants is not an object")
        rules = grants.get("rules", [])
        if not isinstance(rules, list):
            raise Refusal(f"{self.file.path} admission_policy.workload_grants.rules is not a list")
        for i, rule in enumerate(rules):
            if not isinstance(rule, dict) or any(not isinstance(rule.get(k, ""), str) for k in ("publisher_principal", "caller_principal")):
                raise Refusal(f"{self.file.path} admission_policy.workload_grants.rules[{i}] is not an object with string principals")
        return list(rules)

    def covering(self, prefix: str) -> list:
        """Entries other than prefix itself that authorize the path prefix."""
        return [p for p in self.prefixes if p != prefix and matches_prefix(prefix, p)]

    def _apply(self, start: int, end: int, new_text: str, change, what: str) -> None:
        """Take new_text, which must keep every byte of the current text
        before start and from end on, and must parse to the document expected
        so far with change applied."""
        old = self.text_now
        expected = copy.deepcopy(self.expected)
        change(expected)
        try:
            if parse_json_strict(new_text) != expected:
                raise ValueError(f"the edited document differs beyond {what}")
        except ValueError as exc:
            raise Failure(f"{self.file.path}: {what} check failed: {exc}") from None
        tail = old[end:]
        if new_text[:start] != old[:start]:
            raise Failure(f"{self.file.path}: {what} changed bytes before the edited value")
        if not new_text.endswith(tail) or len(new_text) - len(tail) < start:
            raise Failure(f"{self.file.path}: {what} changed bytes after the edited value")
        self.text_now = new_text
        self.expected = expected
        self.file.new = new_text.encode("utf-8")

    def set_prefixes(self, new_prefixes: list) -> None:
        """Append one entry, or remove entries, keeping the order of the rest."""
        start, end = find_member_span(self.text_now, self.PATH)
        old = self.prefixes
        if len(new_prefixes) == len(old) + 1 and new_prefixes[:-1] == old:
            text = array_with_added(self.text_now, start, end, new_prefixes[-1])
        elif len(new_prefixes) < len(old):
            removed = []
            j = 0
            for i, p in enumerate(old):
                if j < len(new_prefixes) and new_prefixes[j] == p:
                    j += 1
                else:
                    removed.append(i)
            if j != len(new_prefixes) or not removed:
                raise Failure("internal error: not a removal")
            text = self.text_now
            for i in reversed(removed):
                s, e = find_member_span(text, self.PATH)
                text = array_with_removed(text, s, e, i)
        else:
            raise Failure("internal error: unsupported allowlist change")

        def change(doc):
            doc["authorization"]["allowed_spiffe_path_prefixes"] = list(new_prefixes)
        self._apply(start, end, text, change, "the allowlist edit")
        self.prefixes = list(new_prefixes)

    def binding_problem(self, namespace: str, sha: str):
        """Why security.namespace_issuers cannot also bind namespace to the CA
        with SHA-256 sha (AGS and ES refuse one CA bound twice and equal or
        nested namespaces), or None."""
        for p, s in self.namespace_issuers or []:
            if p == namespace and s == sha:
                continue
            if s == sha:
                return f"binds the user CA to {p!r}"
            if matches_prefix(p, namespace) or matches_prefix(namespace, p):
                return f"binds {p!r} to another CA ({s[:16]}...)"
        return None

    def binds(self, namespace: str, sha: str) -> bool:
        return (namespace, sha) in (self.namespace_issuers or [])

    def user_bindings(self, namespace: str, sha, as_read: bool = False) -> list:
        """The bindings of namespace, of a namespace inside it, or of the CA
        with SHA-256 sha (as read, or with this run's edits)."""
        issuers = self.issuers_as_read if as_read else self.namespace_issuers
        return [(p, s) for p, s in issuers or [] if matches_prefix(p, namespace) or s == sha]

    def binds_alone(self, namespace: str, sha: str, as_read: bool = False) -> bool:
        """Whether namespace is bound to the CA with SHA-256 sha and to
        nothing else, and that CA to nothing else: the state in which that CA
        vouches only for namespace/ paths."""
        return self.user_bindings(namespace, sha, as_read) == [(namespace, sha)]

    def add_namespace_issuer(self, namespace: str, sha: str) -> None:
        if not isinstance(self.doc.get("security"), dict):
            raise Refusal(f"{self.file.path} has no security object to hold the namespace issuer binding")
        entry = {"path_prefix": namespace, "issuer_certificate_sha256": sha}
        if self.namespace_issuers is None:
            start, end = find_member_span(self.text_now, ("security",))
            text = object_with_member_added(self.text_now, start, end, "namespace_issuers", [entry])

            def change(doc):
                doc["security"]["namespace_issuers"] = [entry]
        else:
            start, end = find_member_span(self.text_now, self.ISSUERS)
            text = array_with_added(self.text_now, start, end, entry)

            def change(doc):
                doc["security"]["namespace_issuers"].append(entry)
        self._apply(start, end, text, change, "the namespace issuer edit")
        self.namespace_issuers = (self.namespace_issuers or []) + [(namespace, sha)]

    def remove_namespace_issuer(self, namespace: str, sha: str) -> bool:
        current = self.namespace_issuers or []
        found = [i for i, pair in enumerate(current) if pair == (namespace, sha)]
        if not found:
            return False
        if len(found) == len(current):
            start, end = find_member_span(self.text_now, ("security",))
            text = object_with_member_removed(self.text_now, start, end, "namespace_issuers")

            def change(doc):
                del doc["security"]["namespace_issuers"]
            remaining = None
        else:
            start, end = find_member_span(self.text_now, self.ISSUERS)
            text = self.text_now
            for i in reversed(found):
                s, e = find_member_span(text, self.ISSUERS)
                text = array_with_removed(text, s, e, i)
            remaining = [pair for pair in current if pair != (namespace, sha)]

            def change(doc):
                doc["security"]["namespace_issuers"] = [dict(zip(ISSUER_KEYS, pair)) for pair in remaining]
        self._apply(start, end, text, change, "the namespace issuer edit")
        self.namespace_issuers = remaining
        return True

    def rules_naming(self, principal: str) -> list:
        """The workload grant rules whose publisher or caller is principal or
        a path below it. ES admits a caller below an allowlist entry, so a
        rule for user/<name>/x is legal beside the entry user/<name>, and once
        that entry goes, ES refuses to start with the rule still there."""
        def names(value) -> bool:
            return isinstance(value, str) and (value == principal or value.startswith(principal + "/"))
        return [i for i, rule in enumerate(self.grant_rules)
                if names(rule.get("publisher_principal")) or names(rule.get("caller_principal"))]

    def remove_grant_rules(self, principal: str) -> int:
        """Remove every workload grant rule whose publisher or caller is
        principal or below it. Returns how many were removed."""
        found = self.rules_naming(principal)
        if not found:
            return 0
        start, end = find_member_span(self.text_now, self.RULES)
        text = self.text_now
        for i in reversed(found):
            s, e = find_member_span(text, self.RULES)
            text = array_with_removed(text, s, e, i, True)
        remaining = [rule for i, rule in enumerate(self.grant_rules) if i not in found]

        def change(doc):
            doc["admission_policy"]["workload_grants"]["rules"] = copy.deepcopy(remaining)
        self._apply(start, end, text, change, "the workload grant edit")
        self.grant_rules = remaining
        return len(found)


# --------------------------------------------------------------------------
# Client CA files


def names_user_ca(L: Layout, cert: dict) -> bool:
    """Whether a certificate's subject carries the user CA's Common Name."""
    return any(oid == OID_CN and text == L.ca_common_name for rdn in cert["subject"] for oid, _, text in rdn)


def analyze_client_ca(path: str, data: bytes, user_ca_pem, L: Layout = None, retired: tuple = ()) -> dict:
    """Read a client CA file. Every block must be a certificate. The user CA,
    when given, is absent or present exactly once as the byte-exact final
    block, and is never the only or first certificate. With L, also list as
    strays the other blocks that name the user CA or are a retired user CA
    (by SHA-256 in retired): an older user CA left in the file stays trusted."""
    blocks = pem_blocks(data, path)
    if not blocks:
        raise Refusal(f"{path} holds no certificate")
    user_der = single_pem(user_ca_pem, "CERTIFICATE", "user CA certificate") if user_ca_pem is not None else None
    strays = []
    for label, der, _ in blocks:
        if label != "CERTIFICATE":
            raise Refusal(f"{path} holds a {label} block")
        try:
            cert = parse_certificate(der)
        except DERError as exc:
            raise Refusal(f"{path} holds an unreadable certificate: {exc}") from None
        if L is not None and der != user_der and (names_user_ca(L, cert) or cert["sha256"] in retired):
            strays.append(cert["sha256"])
    info = {"certificates": len(blocks), "user_ca_present": False, "first_sha256": sha256_hex(blocks[0][1]), "strays": strays}
    if user_ca_pem is None:
        return info
    positions = [i for i, block in enumerate(blocks) if block[1] == user_der]
    if not positions:
        return info
    if len(positions) > 1:
        raise Refusal(f"{path} holds the user CA more than once")
    if positions[0] == 0:
        raise Refusal(f"{path} holds the user CA as its first certificate; the external client CA must stay first")
    if positions[0] != len(blocks) - 1 or not data.endswith(user_ca_pem):
        raise Refusal(f"{path} holds the user CA, but not as its byte-exact final block")
    info["user_ca_present"] = True
    return info


def with_user_ca(path: str, data: bytes, user_ca_pem: bytes) -> bytes:
    if not data.endswith(b"\n"):
        raise Refusal(f"{path} does not end with a newline")
    return data + user_ca_pem


def without_user_ca(path: str, data: bytes, user_ca_pem: bytes) -> bytes:
    if not data.endswith(user_ca_pem):
        raise Refusal(f"{path} does not end with the user CA")
    rest = data[:-len(user_ca_pem)]
    analyze_client_ca(path, rest, None)
    return rest


# --------------------------------------------------------------------------
# User CA directory and registry


class UserCA:
    def __init__(self, L: Layout):
        self.L = L
        self.dir = L.user_ca_dir
        self.key_path = os.path.join(self.dir, "ca-key.pem")
        self.cert_path = os.path.join(self.dir, "ca-cert.pem")
        self.registry_path = os.path.join(self.dir, "registry.json")
        self.issued_dir = os.path.join(self.dir, "issued")
        self.backups_dir = os.path.join(self.dir, "backups")
        self.retired_dir = os.path.join(self.dir, "retired")
        # init-ca --replace builds the new CA here; the registry naming it is
        # the moment of the change.
        self.next_dir = os.path.join(self.dir, "next")

    def exists(self) -> bool:
        return lstat_or_none(self.dir) is not None

    def require_private_dir(self, path: str) -> None:
        st = lstat_or_none(path)
        if st is None or not stat.S_ISDIR(st.st_mode):
            raise Refusal(f"{path} is missing or not a directory")
        if st.st_uid != self.L.box_owner_uid or stat.S_IMODE(st.st_mode) != 0o700:
            raise Refusal(f"{path} must be a directory owned by UID {self.L.box_owner_uid} with mode 0700")

    def _read_cert(self, path: str) -> tuple:
        raw = read_box_file(self.L, path, 64 * 1024)[0]
        try:
            cert = parse_certificate(single_pem(raw, "CERTIFICATE", path))
        except DERError as exc:
            raise Refusal(f"{path} is unreadable: {exc}") from None
        if pem_encode("CERTIFICATE", cert["der"]) != raw:
            raise Refusal(f"{path} is not in canonical PEM form")
        problems = ca_profile_problems(self.L, cert)
        if problems:
            raise Refusal(f"{path}: " + "; ".join(problems))
        return raw, cert

    def _check_key(self, path: str) -> None:
        key = read_regular_file(path, 64 * 1024)
        if key is None:
            raise Refusal(f"{path} does not exist")
        if key[1].st_uid != self.L.box_owner_uid or stat.S_IMODE(key[1].st_mode) != 0o600:
            raise Refusal(f"{path} must be owned by UID {self.L.box_owner_uid} with mode 0600")

    def key_problem(self) -> str:
        """What is wrong with the CA key file, or "" (for revoke, which needs
        no key and must not stop on one)."""
        try:
            self._check_key(self.key_path)
        except Refusal as exc:
            return str(exc)
        return ""

    def load(self, allow_pending: bool = False, need_key: bool = True):
        """Check the CA directory and read the CA certificate and registry.

        A next/ directory means an init-ca --replace did not finish. Only
        init-ca --replace (allow_pending) goes on: it gets "committed" when
        the registry already names the CA in next/ (the CA was replaced, the
        files still have to move into place) or next/ is empty (both files
        moved; init-ca --replace only ever puts next/ in place whole), and
        "staged" when neither (the replacement never took effect). Otherwise
        it returns None. need_key False skips the CA key check (revoke)."""
        require_box_dir(self.L, os.path.dirname(self.dir))
        for path in (self.dir, self.issued_dir, self.backups_dir, self.retired_dir):
            self.require_private_dir(path)
        reg = read_box_file(self.L, self.registry_path, 4 * 1024 * 1024)
        if stat.S_IMODE(reg[1].st_mode) != 0o600:
            raise Refusal(f"{self.registry_path} must have mode 0600")
        try:
            self.registry = parse_json_strict(reg[0].decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise Refusal(f"{self.registry_path} is not strict JSON: {exc}") from None
        pending = None
        if lstat_or_none(self.next_dir) is not None:
            if not allow_pending:
                raise Refusal(f"an init-ca --replace did not finish ({self.next_dir} exists); run init-ca --replace --apply to finish it")
            self.require_private_dir(self.next_dir)
            found = read_regular_file(os.path.join(self.next_dir, "ca-cert.pem"), 64 * 1024)
            named = not os.listdir(self.next_dir)
            if found is not None and isinstance(self.registry, dict) and isinstance(self.registry.get("ca"), dict):
                try:
                    der = single_pem(found[0], "CERTIFICATE", "the new CA certificate")
                except Refusal:
                    der = b""
                named = self.registry["ca"].get("sha256") == sha256_hex(der)
            pending = "committed" if named else "staged"
        if pending == "committed":
            # finish_replacement moves the key first, then the certificate, so
            # either may already be in place.
            next_key = os.path.join(self.next_dir, "ca-key.pem")
            next_cert = os.path.join(self.next_dir, "ca-cert.pem")
            self._check_key(next_key if lstat_or_none(next_key) is not None else self.key_path)
            self.cert_pem, self.cert = self._read_cert(next_cert if lstat_or_none(next_cert) is not None else self.cert_path)
        else:
            if need_key:
                self._check_key(self.key_path)
            self.cert_pem, self.cert = self._read_cert(self.cert_path)
        self.check_registry()
        return pending

    def check_registry(self) -> None:
        reg = self.registry
        ok = (isinstance(reg, dict) and reg.get("schema_version") == REGISTRY_SCHEMA_VERSION
              and reg.get("trust_domain") == self.L.trust_domain and reg.get("path_namespace") == self.L.path_namespace
              and isinstance(reg.get("ca"), dict) and reg["ca"].get("sha256") == self.cert["sha256"]
              and reg["ca"].get("public_key_sha256") == self.cert["key"]["sha256"]
              and isinstance(reg.get("retired_cas"), list)
              and all(isinstance(c, dict) and isinstance(c.get("sha256"), str) and isinstance(c.get("public_key_sha256"), str)
                      for c in reg["retired_cas"])
              and isinstance(reg.get("names"), dict) and isinstance(reg.get("events"), list))
        if not ok:
            raise Refusal(f"{self.registry_path} does not match this helper's schema or the CA certificate")
        units = (self.L.ags_unit, self.L.es_unit)
        for name, entry in reg["names"].items():
            if not NAME_RE.match(name) or not isinstance(entry, dict) or entry.get("state") not in ("active", "revoked") \
                    or not isinstance(entry.get("certificates"), list) \
                    or not all(u in units for u in entry.get("pending_restarts", [])):
                raise Refusal(f"{self.registry_path} has a malformed entry for {name!r}")

    @property
    def retired(self) -> bool:
        return "retired_at" in self.registry["ca"]

    def retired_by(self) -> str:
        """The name whose revoke --remove-ca retired the current CA, or ""."""
        for event in reversed(self.registry["events"]):
            if isinstance(event, dict) and event.get("detail") == "retired the user CA":
                name = event.get("name")
                return name if isinstance(name, str) and NAME_RE.match(name) else ""
        return ""

    def retired_shas(self) -> tuple:
        return tuple(c["sha256"] for c in self.registry["retired_cas"])

    def save_registry(self) -> None:
        data = (json.dumps(self.registry, indent=2, sort_keys=True) + "\n").encode("utf-8")
        atomic_write(self.registry_path, data, 0o600)

    def save_registry_or_fail(self) -> None:
        try:
            self.save_registry()
        except OSError as exc:
            raise Failure(f"could not save {self.registry_path}: {exc.strerror}") from None

    def event(self, mode: str, name: str, detail: str, backup: str = "") -> None:
        entry = {"at": iso_utc(utc_now()), "mode": mode, "name": name, "detail": detail}
        if backup:
            entry["backup"] = backup
        self.registry["events"].append(entry)

    def entry(self, name: str):
        return self.registry["names"].get(name)

    def unexpired(self, name: str) -> list:
        entry = self.entry(name) or {}
        now = utc_now()
        return [c for c in entry.get("certificates", []) if c.get("not_after_epoch", 0) > now]

    def pending_revocations(self) -> list:
        return sorted(n for n, e in self.registry["names"].items() if e.get("pending_restarts"))

    def known_key_digests(self) -> set:
        out = {self.cert["key"]["sha256"]}
        out.update(c["public_key_sha256"] for c in self.registry["retired_cas"])
        for entry in self.registry["names"].values():
            for cert in entry["certificates"]:
                out.add(cert.get("public_key_sha256"))
        return out

    def finish_replacement(self) -> None:
        """Move the new CA from next/ into place; the registry already names it."""
        for name in ("ca-key.pem", "ca-cert.pem"):
            source = os.path.join(self.next_dir, name)
            if lstat_or_none(source) is not None:
                os.rename(source, os.path.join(self.dir, name))
        fsync_dir(self.dir)
        os.rmdir(self.next_dir)
        fsync_dir(self.dir)


# --------------------------------------------------------------------------
# Box preflight


def require_root(L: Layout) -> None:
    if os.geteuid() != L.required_euid:
        raise UsageError(f"box modes must run as root; use: sudo {PUBLIC_SCRIPT} <mode>")


def require_commands(L: Layout, names: tuple) -> None:
    for name in names:
        path = getattr(L, name)
        if not os.path.isabs(path) or not os.access(path, os.X_OK):
            raise Refusal(f"required command {path} is missing or not executable")


def take_lock(L: Layout):
    try:
        fd = os.open(L.lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, 0o600)
    except OSError as exc:
        # A symbolic link (O_NOFOLLOW) or a directory in its place.
        raise Refusal(f"cannot open the lock file {L.lock_path}: {exc.strerror}") from None
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


def json_strings(value, where: str = ""):
    """Every string value in a JSON document, with its key path."""
    if isinstance(value, dict):
        for key, item in value.items():
            yield from json_strings(item, f"{where}.{key}" if where else key)
    elif isinstance(value, list):
        for i, item in enumerate(value):
            yield from json_strings(item, f"{where}[{i}]")
    elif isinstance(value, str):
        yield where, value


def client_ca_references(L: Layout, configs: list, ca_stats: list) -> list:
    """Each place, other than AGS's and ES's own tls.client_ca_file, where one
    of configs ((label, path, document) triples) names a client CA file, by
    path or as the same file through another name."""
    ca_paths = {os.path.normpath(L.ags_client_ca), os.path.normpath(L.es_client_ca)}
    ca_ids = {(st.st_dev, st.st_ino) for st in ca_stats}
    allowed = {("AGS", "tls.client_ca_file"), ("ES", "tls.client_ca_file")}
    found = []
    for label, path, doc in configs:
        for where, value in json_strings(doc):
            if not value.startswith("/") or (label, where) in allowed:
                continue
            same = os.path.normpath(value) in ca_paths
            if not same:
                try:
                    st = os.stat(value)
                    same = (st.st_dev, st.st_ino) in ca_ids
                except (OSError, ValueError):
                    same = False
            if same:
                found.append(f"{path} {where} names {value}")
    return found


class Box:
    """The four service files allow and revoke may change, and the other
    service configs they check.

    On disk, a client CA file that holds the user CA always has its
    service's user binding beside it: allow writes the configs (the binding)
    before the client CA files, and revoke --remove-ca removes the user CA
    from the client CA files before the binding, and keeps a service's
    binding when its client CA file could not be written. A stop at any point
    of either, even one no signal handler sees, leaves no service that would
    start trusting the user CA without its binding."""

    # Each service's label, config key and client CA file key, in restart order.
    SERVICES = (("AGS", "ags_config", "ags_ca"), ("ES", "es_config", "es_ca"))
    # allow: the binding before the trust. revoke: the trust out before the binding.
    ADD_ORDER = ("ags_config", "es_config", "ags_ca", "es_ca")
    REMOVE_ORDER = ("ags_ca", "es_ca", "ags_config", "es_config")

    def __init__(self, L: Layout, ca: UserCA):
        self.L = L
        self.ca = ca
        self.files = {}
        for key, path, limit in (("ags_config", L.ags_config, 1 << 20), ("es_config", L.es_config, 1 << 20),
                                 ("ags_ca", L.ags_client_ca, 1 << 20), ("es_ca", L.es_client_ca, 1 << 20)):
            data, st = read_box_file(L, path, limit)
            self.files[key] = FileState(path, data, st)
        self.ags = ServiceConfig("AGS", self.files["ags_config"])
        self.es = ServiceConfig("ES", self.files["es_config"])

    def config(self, label: str) -> ServiceConfig:
        return self.ags if label == "AGS" else self.es

    def service_of(self, key: str) -> tuple:
        return next(service for service in self.SERVICES if key in service)

    def key_of(self, f: FileState) -> str:
        return next(key for key, other in self.files.items() if other is f)

    def unbound_trust(self, as_read: bool = False) -> list:
        """The services whose client CA file holds the user CA while their
        config does not bind the user namespace to it alone, as read or with
        this run's edits."""
        found = []
        for label, _, ca_key in self.SERVICES:
            f = self.files[ca_key]
            data = f.old if as_read else f.new
            holds = analyze_client_ca(f.path, data, self.ca.cert_pem)["user_ca_present"]
            if holds and not self.config(label).binds_alone(self.L.path_namespace, self.ca.cert["sha256"], as_read):
                found.append(label)
        return found

    def ca_file_references(self) -> list:
        configs = [("AGS", self.L.ags_config, self.ags.doc), ("ES", self.L.es_config, self.es.doc)]
        for path in self.L.other_service_configs:
            data, _ = read_box_file(self.L, path, 1 << 20)
            try:
                doc = parse_json_strict(data.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise Refusal(f"{path} is not strict JSON: {exc}") from None
            configs.append((os.path.basename(path), path, doc))
        return client_ca_references(self.L, configs, [self.files["ags_ca"].st, self.files["es_ca"].st])

    def require_topology(self, revoke: bool = False) -> None:
        """The box layout this helper was written for. revoke checks only the
        client CA paths, so none of allow's other checks can block a
        revocation; what can still block one, and how to revoke by hand then,
        is in the runbook."""
        for config, expected in ((self.ags, self.L.ags_client_ca), (self.es, self.L.es_client_ca)):
            if config.client_ca_file != expected:
                raise Refusal(f"{config.label} tls.client_ca_file is {config.client_ca_file!r}, want {expected!r}")
            if revoke:
                continue
            if not isinstance(config.bootstrap_cn, str) or not config.bootstrap_cn.strip():
                raise Refusal(f"{config.label} security.bootstrap_issuer_common_name is empty")
            if config.bootstrap_cn.strip() == self.L.ca_common_name:
                raise Refusal(f"{config.label} bootstrap issuer Common Name equals the user CA's")
        if revoke:
            return
        ags, es, pem = self.files["ags_ca"].old, self.files["es_ca"].old, self.ca.cert_pem
        # allow also finishes its own change cut short between the two client
        # CA file writes: one file then ends with the user CA, the other not.
        if ags != es and not (ags.endswith(pem) and ags[:-len(pem)] == es) and not (es.endswith(pem) and es[:-len(pem)] == ags):
            raise Refusal(f"{self.L.ags_client_ca} and {self.L.es_client_ca} differ; they must be identical, or differ only by "
                          "the user CA at the end of one (see the recovery runbook)")
        references = self.ca_file_references()
        if references:
            raise Refusal("a client CA file of AGS and ES is also read elsewhere, so the user CA would be trusted there too: "
                          + "; ".join(references))

    def client_ca_info(self, key: str) -> dict:
        f = self.files[key]
        return analyze_client_ca(f.path, f.old, self.ca.cert_pem, self.L, self.ca.retired_shas())

    def ca_state(self) -> bool:
        states = [self.client_ca_info(k)["user_ca_present"] for k in ("ags_ca", "es_ca")]
        return states[0] and states[1]

    def strays(self) -> list:
        return sorted({sha for k in ("ags_ca", "es_ca") for sha in self.client_ca_info(k)["strays"]})

    def units_for_changes(self) -> list:
        units = []
        if self.files["ags_config"].changed or self.files["ags_ca"].changed:
            units.append(self.L.ags_unit)
        if self.files["es_config"].changed or self.files["es_ca"].changed:
            units.append(self.L.es_unit)
        return units

    def backup(self, mode: str, name: str) -> str:
        # A unique name even for two runs in the same second.
        directory = tempfile.mkdtemp(prefix=f"{stamp_utc()}-{mode}-{name}-", dir=self.ca.backups_dir)
        manifest = {"schema_version": BACKUP_SCHEMA_VERSION, "mode": mode, "name": name, "files": []}
        for key in ("ags_config", "es_config", "ags_ca", "es_ca"):
            f = self.files[key]
            copy_path = os.path.join(directory, key)
            create_exclusive(copy_path, f.old, 0o600)
            manifest["files"].append({"key": key, "path": f.path, "sha256": sha256_hex(f.old), "uid": f.st.st_uid,
                                      "gid": f.st.st_gid, "mode": f"{stat.S_IMODE(f.st.st_mode):04o}"})
        create_exclusive(os.path.join(directory, "manifest.json"), (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(), 0o600)
        fsync_dir(self.ca.backups_dir)
        return directory

    def apply(self, r: Runner, rep: Report, mode: str, name: str, commit=None) -> str:
        """Back up, write the changed files, restart the affected units in
        order, run commit(backup) if given, and roll back exactly on any
        failure, including a failure of commit."""
        backup = self.backup(mode, name)
        rep.action(f"backed up the four service files to {backup}")
        written = []
        attempted = []
        units = self.units_for_changes()
        try:
            for key in self.ADD_ORDER:
                f = self.files[key]
                if f.changed:
                    written.append(f)
                    f.write_new()
                    # No digest of the configs: ags.json holds the AGS signer key.
                    detail = f"sha256 {sha256_hex(f.new)[:16]}..., " if key.endswith("_ca") else "edited, "
                    rep.action(f"wrote {f.path} ({detail}owner and mode kept)")
            for unit in units:
                attempted.append(unit)
                pid = restart_and_confirm(r, unit)
                rep.action(f"restarted {unit}; running as PID {pid}")
            if commit is not None:
                commit(backup)
        except (Failure, CommandError, OSError) as exc:
            cause = str(exc) if not isinstance(exc, OSError) else f"{exc.strerror}: {exc.filename}"
            incomplete = None
            with signals_deferred():
                try:
                    self.rollback(r, rep, written, attempted)
                except Failure as rollback_exc:
                    incomplete = rollback_exc
            if incomplete is not None:
                raise Failure(f"{cause}; {incomplete}; the backed-up bytes are in {backup}{held_stops_note()}") from None
            raise Failure(f"{cause}; rolled back to the backed-up bytes in {backup}{held_stops_note()}") from None
        return backup

    def rollback(self, r: Runner, rep: Report, written: list, attempted: list) -> None:
        """Restore every file this run wrote (or may have written) and restart
        the units this run restarted, so they run on the old files again.

        Client CA files go back first. A service whose client CA file may
        still hold the user CA keeps its config as written, binding included:
        a binding never goes before the trust it holds."""
        problems = []
        untrusted_unknown = set()
        kept = set()
        for f in reversed(written):
            key = self.key_of(f)
            label, config_key, ca_key = self.service_of(key)
            if key == config_key and ca_key in untrusted_unknown:
                kept.add(key)
                problems.append(f"kept {f.path} as written, with the {self.L.path_namespace} binding, because "
                                f"{self.files[ca_key].path} may still hold the user CA")
                continue
            try:
                f.restore()
                rep.action(f"rollback: restored {f.path}")
            except OSError as exc:
                if self._holds(f, f.old):
                    rep.action(f"rollback: {f.path} still holds its backed-up bytes")
                    continue
                problems.append(f"restore {f.path}: {exc.strerror}")
                if key == ca_key:
                    untrusted_unknown.add(ca_key)
        for unit in attempted:
            try:
                pid = restart_and_confirm(r, unit)
                rep.action(f"rollback: restarted {unit}; running as PID {pid}")
            except (Failure, CommandError) as exc:
                problems.append(str(exc))
        for f in written:
            if self.key_of(f) in kept:
                continue
            try:
                same = f.current_is(f.old)
            except (Refusal, OSError) as exc:
                problems.append(f"cannot read back {f.path}: {exc}")
                continue
            if not same:
                problems.append(f"{f.path} does not hold its backed-up bytes")
        if problems:
            raise Failure("rollback incomplete: " + "; ".join(problems))

    @staticmethod
    def _holds(f: FileState, data: bytes) -> bool:
        try:
            return f.current_is(data)
        except (Refusal, OSError):
            return False

    def apply_forward(self, r: Runner, rep: Report, units: list) -> tuple:
        """Write every changed file and restart units in order, going on past
        a failure and never rolling back: used by revoke, whose removal must
        stay on disk even when a service cannot restart, so that the service
        starts without the name whenever it starts. A config whose client CA
        file could not be written without the user CA keeps its binding. Stop
        signals are held while the files are written and stop the run before
        the restarts. Returns the problems and the units that did not come
        back."""
        problems = []
        failed = []
        still_trusted = set()
        held = len(_held_stops)
        with signals_deferred():
            for key in self.REMOVE_ORDER:
                f = self.files[key]
                label, config_key, ca_key = self.service_of(key)
                data = f.new
                if key == config_key and ca_key in still_trusted and f.keep_binding is not None:
                    data = f.keep_binding
                    rep.action(f"kept the {self.L.path_namespace} binding in {f.path}, because {self.files[ca_key].path} "
                               "still holds the user CA")
                if data == f.old:
                    continue
                try:
                    f.write(data)
                except OSError as exc:
                    problems.append(f"could not write {f.path}: {exc.strerror}")
                    if key == ca_key:
                        still_trusted.add(ca_key)
                    continue
                detail = f"sha256 {sha256_hex(data)[:16]}..., " if key.endswith("_ca") else "edited, "
                rep.action(f"wrote {f.path} ({detail}owner and mode kept)")
        if len(_held_stops) > held:
            raise Interrupted(f"stopped by {' and '.join(_held_stops[held:])}, held until the service files were written")
        for unit in units:
            try:
                pid = restart_and_confirm(r, unit)
                rep.action(f"restarted {unit}; running as PID {pid}")
            except Interrupted:
                raise
            except (Failure, CommandError) as exc:
                problems.append(str(exc))
                failed.append(unit)
        return problems, failed


# --------------------------------------------------------------------------
# Box modes


def ca_config_text(L: Layout) -> str:
    return (
        "[ req ]\n"
        "distinguished_name = dn\n"
        "prompt = no\n"
        "utf8 = yes\n"
        "string_mask = utf8only\n"
        "[ dn ]\n"
        f"O = {L.ca_organization}\n"
        f"CN = {L.ca_common_name}\n"
        "[ v3_user_ca ]\n"
        "basicConstraints = critical, CA:TRUE, pathlen:0\n"
        "keyUsage = critical, keyCertSign, cRLSign\n"
        "extendedKeyUsage = clientAuth\n"
        "subjectKeyIdentifier = hash\n"
        f"nameConstraints = critical, permitted;URI:{L.trust_domain}\n"
    )


def leaf_extension_text(L: Layout, name: str) -> str:
    return (
        "[ v3_user ]\n"
        "basicConstraints = critical, CA:FALSE\n"
        "keyUsage = critical, digitalSignature\n"
        "extendedKeyUsage = clientAuth\n"
        "subjectKeyIdentifier = hash\n"
        "authorityKeyIdentifier = keyid\n"
        f"subjectAltName = URI:{spiffe_id(L, name)}\n"
    )


def new_serial() -> int:
    # A positive 127-bit number: the top bit is set and the 126 bits below it
    # are random, so the DER INTEGER always takes 16 bytes.
    return (1 << 126) | secrets.randbits(126)


def make_ca_material(r: Runner, L: Layout, directory: str) -> dict:
    """Generate the CA key and self-signed certificate in directory (0700,
    this run's own) and check them. Returns the parsed certificate."""
    key_path = os.path.join(directory, "ca-key.pem")
    cert_path = os.path.join(directory, "ca-cert.pem")
    cnf_path = os.path.join(directory, "ca.cnf")
    create_exclusive(cnf_path, ca_config_text(L).encode("utf-8"), 0o600)
    r.openssl(["genrsa", "-out", key_path, str(L.ca_key_bits)], cwd=directory)
    os.chmod(key_path, 0o600)
    r.openssl(["req", "-new", "-x509", "-key", key_path, "-sha256", "-days", str(L.ca_days),
               "-set_serial", hex(new_serial()), "-config", cnf_path, "-extensions", "v3_user_ca",
               "-out", cert_path], cwd=directory)
    os.unlink(cnf_path)
    raw = read_regular_file(cert_path, 64 * 1024)[0]
    cert = parse_certificate(single_pem(raw, "CERTIFICATE", "new CA certificate"))
    problems = ca_profile_problems(L, cert)
    if r.public_key_der(key_path) != cert["key"]["der"]:
        problems.append("key does not match certificate")
    if not r.chain_ok(cert_path, cert_path, "any"):
        problems.append("openssl does not verify the self-signed certificate")
    if problems:
        raise Failure("new CA certificate check failed: " + "; ".join(problems))
    canonical = pem_encode("CERTIFICATE", cert["der"])
    if canonical != raw:
        atomic_write(cert_path, canonical, 0o644)
    os.chmod(cert_path, 0o644)
    return cert


def ca_record(cert: dict) -> dict:
    return {"sha256": cert["sha256"], "public_key_sha256": cert["key"]["sha256"], "subject": name_text(cert["subject"]),
            "serial": format(cert["serial"], "x"), "not_before": iso_utc(cert["not_before"]),
            "not_after": iso_utc(cert["not_after"]), "created_at": iso_utc(utc_now())}


def refuse_bootstrap_clash(L: Layout) -> None:
    for path in (L.ags_config, L.es_config):
        data, st = read_box_file(L, path, 1 << 20)
        config = ServiceConfig("AGS" if path == L.ags_config else "ES", FileState(path, data, st))
        if isinstance(config.bootstrap_cn, str) and config.bootstrap_cn.strip() == L.ca_common_name:
            raise Refusal(f"{path} bootstrap issuer Common Name equals the user CA's")


def ca_plan(rep: Report, L: Layout, where: str) -> None:
    rep.planned(f"create an RSA-{L.ca_key_bits} CA key in {where} (0600, no passphrase, never leaves the box)")
    rep.planned(f"self-sign the user CA: O={L.ca_organization}, CN={L.ca_common_name}, CA:TRUE pathlen:0, "
                f"keyCertSign+cRLSign, extended key usage clientAuth, name constraint URI:{L.trust_domain}, {L.ca_days} days")


def mode_init_ca(r: Runner, rep: Report, apply: bool, replace: bool = False) -> None:
    if replace:
        mode_init_ca_replace(r, rep, apply)
        return
    L = r.L
    ca = UserCA(L)
    parent = os.path.dirname(ca.dir)
    require_box_dir(L, parent)
    if ca.exists():
        raise Refusal(f"{ca.dir} already exists; the user CA is created once (init-ca --replace replaces it)")
    refuse_bootstrap_clash(L)
    rep.check("parent", "ok", f"{parent} owned by UID {L.box_owner_uid}, not group/other writable")
    ca_plan(rep, L, f"a new {ca.dir} (0700)")
    rep.planned("write an empty registry; no service file is touched")
    if not apply:
        rep.result = "planned"
        rep.message = "nothing changed; rerun with --apply"
        return
    staging = tempfile.mkdtemp(prefix=os.path.basename(ca.dir) + ".new-", dir=parent)
    try:
        os.chmod(staging, 0o700)
        cert = make_ca_material(r, L, staging)
        for sub in ("issued", "backups", "retired"):
            os.mkdir(os.path.join(staging, sub), 0o700)
        registry = {
            "schema_version": REGISTRY_SCHEMA_VERSION,
            "trust_domain": L.trust_domain,
            "path_namespace": L.path_namespace,
            "ca": ca_record(cert),
            "retired_cas": [],
            "names": {},
            "events": [{"at": iso_utc(utc_now()), "mode": "init-ca", "name": "", "detail": "created the user CA"}],
        }
        create_exclusive(os.path.join(staging, "registry.json"), (json.dumps(registry, indent=2, sort_keys=True) + "\n").encode(), 0o600)
        fsync_dir(staging)
        os.rename(staging, ca.dir)
        fsync_dir(parent)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    rep.action(f"created {ca.dir} with the CA key (0600) and certificate")
    rep.facts.update(ca_sha256=cert["sha256"], ca_not_after=iso_utc(cert["not_after"]))
    rep.result = "ok"
    rep.message = "user CA created; no service file was touched"


def mode_init_ca_replace(r: Runner, rep: Report, apply: bool) -> None:
    """Replace the user CA, for example after its key may have leaked. The
    old CA must be in neither client CA file, bound by neither service, and no
    name may be active; every revoked name stays revoked."""
    L = r.L
    ca = UserCA(L)
    if not ca.exists():
        raise Refusal("the user CA does not exist; run init-ca without --replace")
    pending = ca.load(allow_pending=True)
    if pending == "committed":
        rep.check("replacement", "attention", f"the registry already names the new CA {ca.cert['sha256'][:16]}..., "
                  f"and its move out of {ca.next_dir} did not finish")
        rep.planned(f"move the new CA key and certificate from {ca.next_dir} into {ca.dir}")
        if not apply:
            rep.result = "planned"
            rep.message = "nothing changed; rerun with --apply to finish the replacement"
            return
        with signals_deferred():
            try:
                ca.finish_replacement()
            except OSError as exc:
                raise Failure(f"moving the new CA into place failed again ({exc.strerror}: {exc.filename}); "
                              "run init-ca --replace --apply again to finish") from None
        rep.action("moved the new CA into place")
        rep.facts.update(ca_sha256=ca.cert["sha256"], ca_not_after=iso_utc(ca.cert["not_after"]))
        rep.result = "ok"
        rep.message = "the user CA replacement is finished; no service file was touched" + held_stops_note()
        return
    refuse_bootstrap_clash(L)
    active = sorted(n for n, e in ca.registry["names"].items() if e["state"] == "active")
    if active:
        raise Refusal("--replace is refused while names are active (revoke them first): " + ", ".join(active))
    unfinished = ca.pending_revocations()
    if unfinished:
        raise Refusal(f"the revocation of {', '.join(unfinished)} is not finished; run revoke --name {unfinished[0]} --apply first")
    box = Box(L, ca)
    for key in ("ags_ca", "es_ca"):
        info = box.client_ca_info(key)
        if info["user_ca_present"]:
            raise Refusal(f"{box.files[key].path} still holds the user CA; run revoke --remove-ca first")
        if info["strays"]:
            raise Refusal(f"{box.files[key].path} holds an older user CA ({info['strays'][0][:16]}...); remove it by hand first")
    for config in (box.ags, box.es):
        bound = [p for p, s in config.namespace_issuers or [] if s == ca.cert["sha256"] or matches_prefix(p, L.path_namespace)]
        if bound:
            raise Refusal(f"{config.label} security.namespace_issuers still binds {bound[0]!r}; run revoke --remove-ca first")
        listed = [p for p in config.prefixes if matches_prefix(p, L.path_namespace)]
        if listed:
            raise Refusal(f"{config.label} allowlist still holds {listed[0]!r}")
    old = ca.registry["ca"]
    rep.check("user CA", "ok", f"{old['sha256'][:16]}... is installed nowhere and no name is active")
    if pending == "staged":
        rep.planned(f"discard the unfinished replacement in {ca.next_dir}, which the registry never named")
    ca_plan(rep, L, ca.next_dir)
    rep.planned(f"keep the old CA certificate as {ca.retired_dir}/{old['sha256']}.pem and delete the old CA key")
    rep.planned("name the new CA in the registry, keeping every name (all revoked) and every record; no service file is touched")
    if not apply:
        rep.result = "planned"
        rep.message = "nothing changed; rerun with --apply"
        return
    if pending == "staged":
        shutil.rmtree(ca.next_dir)
        fsync_dir(ca.dir)
    # Build the new CA beside next/ and put it in place whole, so next/ is
    # never there empty or half-made: an empty next/ always means that both
    # files of a named CA have moved into place. A build cut short leaves a
    # staging directory, removed here by the next replacement.
    for entry in os.listdir(ca.dir):
        if entry.startswith(NEXT_STAGING_PREFIX):
            shutil.rmtree(os.path.join(ca.dir, entry))
    staging = tempfile.mkdtemp(prefix=NEXT_STAGING_PREFIX, dir=ca.dir)
    try:
        os.chmod(staging, 0o700)
        cert = make_ca_material(r, L, staging)
        fsync_dir(staging)
        os.rename(staging, ca.next_dir)
        fsync_dir(ca.dir)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    kept = os.path.join(ca.retired_dir, f"{old['sha256']}.pem")
    found = read_regular_file(kept, 64 * 1024)
    if found is None:
        create_exclusive(kept, ca.cert_pem, 0o644)
    elif found[0] != ca.cert_pem:
        raise Failure(f"{kept} exists and differs from the old CA certificate")
    now = iso_utc(utc_now())
    retired = dict(old)
    retired.setdefault("retired_at", now)
    retired["replaced_at"] = now
    ca.registry["retired_cas"].append(retired)
    ca.registry["ca"] = ca_record(cert)
    ca.event("init-ca", "", f"replaced the user CA {old['sha256'][:16]}... with {cert['sha256'][:16]}...")
    with signals_deferred():
        try:
            ca.save_registry_or_fail()
        except Failure as exc:
            raise Failure(f"{exc}; the user CA was not replaced, and the next init-ca --replace discards {ca.next_dir}") from None
        rep.action(f"named the new CA {cert['sha256'][:16]}... in the registry; the old one is retired")
        try:
            ca.finish_replacement()
        except OSError as exc:
            raise Failure(f"the registry names the new CA, but moving it into place failed ({exc.strerror}); "
                          "run init-ca --replace --apply again to finish") from None
    rep.action(f"moved the new CA key and certificate into {ca.dir}; the old key is gone")
    rep.facts.update(ca_sha256=cert["sha256"], ca_not_after=iso_utc(cert["not_after"]), retired_ca_sha256=old["sha256"])
    rep.result = "ok"
    rep.message = "user CA replaced; issue and allow use the new one, and every revoked name stays revoked" + held_stops_note()


def mode_issue(r: Runner, rep: Report, apply: bool, name: str, csr_path: str, out_path: str) -> None:
    L = r.L
    ca = UserCA(L)
    if not ca.exists():
        raise Refusal("the user CA does not exist; run init-ca first")
    ca.load()
    refuse_retired(ca)
    entry = ca.entry(name)
    if entry and entry["state"] == "revoked":
        raise Refusal(f"{prefix_for(L, name)} was revoked; names are never reused, choose another name")
    now = utc_now()
    if ca.cert["not_after"] < now + L.leaf_days * 86400 + 86400:
        raise Refusal(f"the user CA expires on {iso_utc(ca.cert['not_after'])}, before a {L.leaf_days}-day certificate would")
    if not os.path.isabs(csr_path) or not os.path.isabs(out_path):
        raise UsageError("--csr and --out must be absolute paths")
    found = read_regular_file(csr_path, 16 * 1024)
    if found is None:
        raise Refusal(f"{csr_path} does not exist")
    csr_der = single_pem(found[0], "CERTIFICATE REQUEST", csr_path)
    try:
        csr = parse_csr(csr_der)
    except DERError as exc:
        raise Refusal(f"{csr_path} is not a CSR this helper can read: {exc}") from None
    problems = csr_problems(csr, name)
    if problems:
        raise Refusal("; ".join(problems))
    if csr["key"]["sha256"] in ca.known_key_digests():
        raise Refusal("the CSR's key is already used by the CA or an earlier certificate; make a new key with request --renew")
    if not r.csr_signature_ok(pem_encode("CERTIFICATE REQUEST", csr_der)):
        raise Refusal("the CSR self-signature does not verify")
    out_dir = os.path.dirname(out_path)
    if lstat_or_none(out_path) is not None:
        raise Refusal(f"{out_path} already exists")
    st = lstat_or_none(out_dir)
    if st is None or not stat.S_ISDIR(st.st_mode):
        raise Refusal(f"{out_dir} is not a directory")
    rep.check("ca", "ok", f"user CA {ca.cert['sha256'][:16]}... valid until {iso_utc(ca.cert['not_after'])}")
    rep.check("csr", "ok", f"subject CN={name}, {key_text(csr['key'])}, public key sha256 {csr['key']['sha256']}")
    rep.facts.update(csr_public_key_sha256=csr["key"]["sha256"], spiffe_id=spiffe_id(L, name))
    rep.check("csr signature", "ok", "self-signature verifies")
    rep.planned(f"sign a {L.leaf_days}-day client certificate for {spiffe_id(L, name)}")
    rep.planned(f"record it in {ca.registry_path} and {ca.issued_dir}/, and write it to {out_path} (0644)")
    if not apply:
        rep.result = "planned"
        rep.message = "nothing changed; compare the CSR public key sha256 with the request output, then rerun with --apply"
        return
    work = tempfile.mkdtemp(prefix=".issue-", dir=ca.dir)
    try:
        csr_copy = os.path.join(work, "request.csr")
        create_exclusive(csr_copy, pem_encode("CERTIFICATE REQUEST", csr_der), 0o600)
        ext_path = os.path.join(work, "leaf.cnf")
        create_exclusive(ext_path, leaf_extension_text(L, name).encode("utf-8"), 0o600)
        serial = new_serial()
        leaf_path = os.path.join(work, "leaf.pem")
        r.openssl(["x509", "-req", "-in", csr_copy, "-CA", ca.cert_path, "-CAkey", ca.key_path,
                   "-set_serial", hex(serial), "-days", str(L.leaf_days), "-sha256",
                   "-extfile", ext_path, "-extensions", "v3_user", "-out", leaf_path], cwd=work)
        raw = read_regular_file(leaf_path, 64 * 1024)[0]
        leaf = parse_certificate(single_pem(raw, "CERTIFICATE", "new certificate"))
        problems = leaf_profile_problems(L, leaf, name)
        if leaf["serial"] != serial:
            problems.append("serial differs from the one requested")
        if leaf["issuer_der"] != ca.cert["subject_der"]:
            problems.append("issuer is not the user CA")
        if leaf["key"]["der"] != csr["key"]["der"]:
            problems.append("public key differs from the CSR's")
        if leaf["not_after"] > ca.cert["not_after"]:
            problems.append("outlasts the CA")
        lifetime = leaf["not_after"] - leaf["not_before"]
        if abs(lifetime - L.leaf_days * 86400) > 120 or leaf["not_before"] > utc_now() + 120:
            problems.append("validity is not the expected window")
        if leaf["signature_algorithm"] != OID_SHA256_RSA:
            problems.append("not signed with sha256WithRSAEncryption")
        if not r.chain_ok(ca.cert_path, leaf_path, "sslclient"):
            problems.append("openssl does not verify it against the user CA for client use")
        if problems:
            raise Failure("signed certificate check failed, nothing recorded: " + "; ".join(problems))
        pem = pem_encode("CERTIFICATE", leaf["der"])
        serial_hex = format(serial, "032x")
        create_exclusive(os.path.join(ca.issued_dir, f"{serial_hex}.pem"), pem, 0o644)
        record = {"serial": serial_hex, "sha256": leaf["sha256"], "public_key_sha256": leaf["key"]["sha256"],
                  "not_before": iso_utc(leaf["not_before"]), "not_after": iso_utc(leaf["not_after"]),
                  "not_after_epoch": int(leaf["not_after"]), "issued_at": iso_utc(utc_now())}
        if entry is None:
            entry = {"spiffe_id": spiffe_id(L, name), "state": "active", "created_at": iso_utc(utc_now()), "certificates": []}
            ca.registry["names"][name] = entry
        entry["certificates"].append(record)
        ca.event("issue", name, f"serial {serial_hex}")
        kept = os.path.join(ca.issued_dir, f"{serial_hex}.pem")
        try:
            ca.save_registry_or_fail()
        except Failure as exc:
            raise Failure(f"{exc}; serial {serial_hex} was signed and kept in {kept} but is not recorded, so issue again "
                          "with the same CSR once the registry can be saved") from None
        rep.action(f"signed serial {serial_hex} for {spiffe_id(L, name)}, valid until {record['not_after']}")
        try:
            create_exclusive(out_path, pem, 0o644)
        except OSError as exc:
            raise Failure(f"serial {serial_hex} for {spiffe_id(L, name)} was signed and recorded, but {out_path} could not "
                          f"be written ({exc.strerror}); copy {kept} to the caller instead (its key is now recorded, so "
                          "issuing again needs a new key)") from None
        rep.action(f"wrote {out_path}")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    rep.facts.update(certificate_sha256=leaf["sha256"], serial=serial_hex, not_after=record["not_after"])
    rep.result = "ok"
    rep.message = f"copy {out_path} to the caller and run install there"


def refuse_retired(ca: UserCA) -> None:
    if ca.retired:
        raise Refusal(f"the user CA was retired by revoke --remove-ca at {ca.registry['ca']['retired_at']}; "
                      "make a new one with init-ca --replace")


def mode_allow(r: Runner, rep: Report, apply: bool, name: str) -> None:
    L = r.L
    ca = UserCA(L)
    if not ca.exists():
        raise Refusal("the user CA does not exist; run init-ca first")
    ca.load()
    refuse_retired(ca)
    entry = ca.entry(name)
    if entry is None:
        raise Refusal(f"{prefix_for(L, name)} has no certificate; run issue first")
    if entry["state"] == "revoked":
        raise Refusal(f"{prefix_for(L, name)} was revoked; names are never reused")
    if not ca.unexpired(name):
        raise Refusal(f"{prefix_for(L, name)} has no unexpired certificate; issue one first")
    if ca.cert["not_after"] <= utc_now():
        raise Refusal("the user CA has expired")
    pending = ca.pending_revocations()
    if pending:
        raise Refusal(f"the revocation of {', '.join(pending)} is not finished; run revoke --name {pending[0]} --apply first")
    box = Box(L, ca)
    box.require_topology()
    strays = box.strays()
    if strays:
        raise Refusal(f"the client CA files hold another user CA ({strays[0][:16]}...), which would stay trusted; remove it first")
    present = box.ca_state()
    prefix = prefix_for(L, name)
    sha = ca.cert["sha256"]
    for config in (box.ags, box.es):
        covering = config.covering(prefix)
        if covering:
            raise Refusal(f"{config.label} allowlist entry {covering[0]!r} already authorizes {prefix}; revoking the name could not take effect")
        problem = config.binding_problem(L.path_namespace, sha)
        if problem:
            raise Refusal(f"{config.label} security.namespace_issuers {problem}, which AGS and ES refuse beside the user CA's binding")
    added_binding = False
    for config in (box.ags, box.es):
        if config.binds(L.path_namespace, sha):
            rep.check(f"{config.label} namespace issuer", "ok", f"binds {L.path_namespace} to the user CA")
        else:
            config.add_namespace_issuer(L.path_namespace, sha)
            added_binding = True
            rep.planned(f"bind {L.path_namespace} to the user CA in {config.label} security.namespace_issuers ({config.file.path}), "
                        f"so the user CA vouches only for {L.path_namespace}/ identities and no other CA for them")
    for key in ("ags_ca", "es_ca"):
        f = box.files[key]
        # One file may already end with the user CA: an earlier allow was
        # stopped between the two client CA file writes.
        if not box.client_ca_info(key)["user_ca_present"]:
            f.new = with_user_ca(f.path, f.old, ca.cert_pem)
            rep.planned(f"append the user CA to the end of {f.path}, after its binding is written")
    for config in (box.ags, box.es):
        if prefix in config.prefixes:
            rep.check(f"{config.label} allowlist", "ok", f"already holds {prefix}")
        else:
            config.set_prefixes(config.prefixes + [prefix])
            rep.planned(f"add {prefix} to the {config.label} allowlist in {config.file.path}")
    units = box.units_for_changes()
    if not units:
        rep.result = "ok"
        rep.message = f"{prefix} is already allowed, the user CA is installed and bound; nothing to do"
        return
    rep.planned("restart " + " then ".join(units) + "; any failure restores the exact previous bytes and restarts again")
    rep.planned("add no network grant: a run this caller publishes or submits gets network access only through a rule the box owner writes")
    if not apply:
        rep.result = "planned"
        rep.message = "nothing changed; rerun with --apply"
        return

    def commit(backup: str) -> None:
        # Inside the transaction: if the registry cannot record the change,
        # the service files go back too.
        ca.event("allow", name, "user CA installed" if not present else "allowlists updated", backup)
        ca.save_registry_or_fail()

    try:
        box.apply(r, rep, "allow", name, commit)
    except Failure as exc:
        if not added_binding:
            raise
        raise Failure(f"{exc}. If the unit's log says unknown field \"namespace_issuers\", that AGS or ES build is older "
                      "than the namespace issuer binding: redeploy AGS and ES from trunk_dev before allow") from None
    rep.result = "ok"
    rep.message = f"{prefix} is allowed by AGS and ES; check from the caller with: {PUBLIC_SCRIPT} check --name {name} --url https://<box>:<port>"


def ordered_units(L: Layout, units) -> list:
    return [u for u in (L.ags_unit, L.es_unit) if u in set(units)]


def mode_revoke(r: Runner, rep: Report, apply: bool, name: str, remove_ca: bool) -> None:
    L = r.L
    ca = UserCA(L)
    if not ca.exists():
        raise Refusal("the user CA does not exist")
    # A revocation needs the CA certificate and the registry, never the CA
    # key: a key file whose owner or mode has drifted, perhaps a sign of the
    # very leak this revocation answers, is reported but does not stop it.
    ca.load(need_key=False)
    key_problem = ca.key_problem()
    if key_problem:
        rep.check("user CA key", "attention", f"{key_problem}; revoke goes on, since it needs no CA key")
    entry = ca.entry(name)
    if entry is None:
        raise Refusal(f"{prefix_for(L, name)} is not in the registry")
    box = Box(L, ca)
    box.require_topology(revoke=True)
    prefix = prefix_for(L, name)
    principal = spiffe_id(L, name)
    ns = L.path_namespace
    for config in (box.ags, box.es):
        # Every exact copy and every slash variant of the entry: an older
        # AGS trims slashes, so "/user/<name>/" authorizes the name there.
        mine = [i for i, p in enumerate(config.prefixes) if p.strip("/") == prefix]
        if mine:
            config.set_prefixes([p for i, p in enumerate(config.prefixes) if i not in mine])
            rep.planned(f"remove {len(mine)} entr{'y' if len(mine) == 1 else 'ies'} for {prefix} from the {config.label} allowlist in {config.file.path}")
        covering = config.covering(prefix)
        if covering:
            raise Refusal(f"{config.label} allowlist entry {covering[0]!r} would still authorize {prefix}")
        removed = config.remove_grant_rules(principal)
        if removed:
            rep.planned(f"remove {removed} workload grant rule(s) naming {principal} or a path below it as publisher or caller "
                        f"from {config.file.path}")
    # --remove-ca retires the user CA. Once it is retired, every revoke also
    # finishes taking it out of the service files, from wherever an earlier
    # run stopped or failed: from each client CA file that still ends with
    # it, then each binding whose service no longer trusts it.
    remove = remove_ca or ca.retired
    retire = False
    if remove:
        if not ca.retired:
            others = sorted(n for n, e in ca.registry["names"].items() if n != name and e["state"] == "active")
            if others:
                raise Refusal("--remove-ca is refused while other names are active: " + ", ".join(others))
            lingering = sorted({p for config in (box.ags, box.es) for p in config.prefixes if matches_prefix(p, ns)})
            if lingering:
                raise Refusal("--remove-ca is refused while user entries remain in the allowlists: " + ", ".join(lingering))
        sha = ca.cert["sha256"]
        for label, _, ca_key in Box.SERVICES:
            f = box.files[ca_key]
            config = box.config(label)
            if box.client_ca_info(ca_key)["user_ca_present"]:
                f.new = without_user_ca(f.path, f.old, ca.cert_pem)
                rep.planned(f"remove the user CA from the end of {f.path}")
            if config.binds(ns, sha):
                config.file.keep_binding = config.file.new
                config.remove_namespace_issuer(ns, sha)
                rep.planned(f"remove the binding of {ns} to the user CA from {label} security.namespace_issuers"
                            + (f", only once {f.path} is written without the user CA" if f.changed else ""))
        retire = not ca.retired
        if retire:
            rep.planned("retire the user CA in the registry: issue and allow refuse it from now on, and init-ca --replace makes a new one")
    pending = entry.get("pending_restarts", [])
    units = ordered_units(L, box.units_for_changes() + pending)
    if units:
        rep.planned("restart " + " then ".join(units) + "; a failure keeps the removal on disk and is reported, nothing is put back")
    if entry["state"] != "revoked":
        rep.planned(f"mark {name} revoked in the registry for good")
    strays = box.strays()

    def finish(text: str, unbound: list) -> None:
        # revoke ends "ok" only when no service is left trusting a user CA
        # without its binding and nothing else needs the owner.
        notes = []
        if unbound:
            notes.append(f"{' and '.join(unbound)} trusts the user CA without its {ns} binding, so a copy of the user CA "
                         f"key could pass there as the operator: run allow again for an active name to write the binding, "
                         f"or revoke --remove-ca once no name is active.")
        if strays:
            notes.append(f"The client CA files still hold another user CA ({strays[0][:16]}...); remove it by hand.")
        if key_problem:
            notes.append(f"The user CA key file needs attention ({key_problem}); if the key may have leaked, revoke every "
                         "name, run revoke --remove-ca and then init-ca --replace.")
        rep.result = "attention" if notes else "ok"
        rep.message = " ".join([text] + notes)

    if not units and entry["state"] == "revoked" and not retire:
        finish(f"{prefix} is already revoked and in no allowlist; nothing to do", box.unbound_trust())
        return
    if not apply:
        rep.result = "planned"
        rep.message = "nothing changed; rerun with --apply"
        return
    done = (f"{prefix} can no longer call the AGS or ES API; its certificates stay cryptographically valid until they expire. "
            "Remove any Unix login of the same person separately.")
    # The registry records the revocation, the retirement and the services
    # still to restart before anything else changes, so a failure later never
    # leaves a name or CA that allow or issue would accept again, and running
    # revoke again knows what is left to do.
    if entry["state"] != "revoked":
        entry["state"] = "revoked"
        entry["revoked_at"] = iso_utc(utc_now())
        ca.event("revoke", name, "marked revoked")
    if retire:
        ca.registry["ca"]["retired_at"] = iso_utc(utc_now())
        ca.event("revoke", name, "retired the user CA")
    if units:
        entry["pending_restarts"] = units
    try:
        ca.save_registry_or_fail()
    except Failure as exc:
        raise Failure(f"{exc}; nothing changed") from None
    rep.action(f"recorded in the registry: {name} revoked" + (", user CA retired" if retire else "")
               + (f", {' and '.join(units)} to restart" if units else ""))
    if not units:
        finish(done, box.unbound_trust())
        return
    unfinished = (f"the registry marks {name} revoked and lists the services still to restart, so run revoke again "
                  "to finish")
    backup = ""
    try:
        if any(f.changed for f in box.files.values()):
            try:
                backup = box.backup("revoke", name)
            except OSError as exc:
                raise Failure(f"AGS and ES were not changed and may still allow {prefix}: could not back up the service "
                              f"files ({exc.strerror}: {exc.filename}); {unfinished} once that is fixed") from None
            rep.action(f"backed up the four service files to {backup}")
        problems, failed = box.apply_forward(r, rep, units)
    except Interrupted as exc:
        raise Interrupted(f"{exc}; {unfinished}") from None
    # What the services will load, read back from disk.
    try:
        unbound = Box(L, ca).unbound_trust(as_read=True)
    except Refusal as exc:
        problems.append(f"cannot read the service files back: {exc}")
        unbound = []
    if problems:
        entry["pending_restarts"] = ordered_units(L, failed) or units
        with contextlib.suppress(Failure):
            ca.save_registry_or_fail()
        trust = (f" {' and '.join(unbound)} still trusts the user CA without its {ns} binding." if unbound else "")
        raise Failure(f"the revocation is not complete: {'; '.join(problems)}. Every file that was written keeps the "
                      f"removal, so a service that starts later starts without {prefix}, and a service whose client CA "
                      f"file could not be written keeps its {ns} binding; nothing was put back.{trust} Repair the "
                      f"service or file (journalctl -u <unit>), then {unfinished}")
    entry.pop("pending_restarts", None)
    detail = "user CA removed" if remove and (box.files["ags_ca"].changed or box.files["es_ca"].changed) else "service files updated"
    ca.event("revoke", name, detail, backup)
    try:
        ca.save_registry_or_fail()
    except Failure as exc:
        rep.result = "attention"
        rep.message = (f"{prefix} is revoked in the registry and at AGS and ES, but this run's last registry update was "
                       f"not saved ({exc}); status shows the restarts as unfinished until revoke runs again")
        return
    finish(done, unbound)


def mode_status(r: Runner, rep: Report) -> None:
    L = r.L
    ca = UserCA(L)
    rep.result = "ok"
    if not ca.exists():
        rep.check("user CA", "ok", f"not created ({ca.dir} absent)")
        ca_pem = None
    else:
        try:
            ca.load()
        except Refusal as exc:
            rep.check("user CA", "fail", str(exc))
            rep.result = "attention"
            return
        left = days_left(ca.cert["not_after"])
        if ca.retired:
            rep.check("user CA", "ok", f"sha256 {ca.cert['sha256'][:16]}..., retired at {ca.registry['ca']['retired_at']}; "
                      "issue and allow refuse it, init-ca --replace makes a new one")
        else:
            rep.check("user CA", "attention" if left < L.ca_attention_days else "ok",
                      f"sha256 {ca.cert['sha256'][:16]}..., valid until {iso_utc(ca.cert['not_after'])} ({left} days)")
        ca_pem = ca.cert_pem
    try:
        files = {}
        for key, path in (("ags_config", L.ags_config), ("es_config", L.es_config), ("ags_ca", L.ags_client_ca), ("es_ca", L.es_client_ca)):
            data, st = read_box_file(L, path, 1 << 20)
            files[key] = FileState(path, data, st)
        ags = ServiceConfig("AGS", files["ags_config"])
        es = ServiceConfig("ES", files["es_config"])
    except Refusal as exc:
        rep.check("service files", "fail", str(exc))
        rep.result = "attention"
        return
    for config, expected in ((ags, L.ags_client_ca), (es, L.es_client_ca)):
        state = "ok" if config.client_ca_file == expected else "attention"
        rep.check(f"{config.label} client CA path", state, str(config.client_ca_file))
    same = files["ags_ca"].old == files["es_ca"].old
    rep.check("client CA files identical", "ok" if same else "attention", "yes" if same else "no")
    retired = ca.retired_shas() if ca_pem is not None else ()
    present = {}
    for key in ("ags_ca", "es_ca"):
        try:
            info = analyze_client_ca(files[key].path, files[key].old, ca_pem, L, retired)
            present[key] = info["user_ca_present"]
            rep.check(f"{files[key].path}", "ok", f"{info['certificates']} certificate(s); user CA {'present' if info['user_ca_present'] else 'absent'}")
            for sha in info["strays"]:
                rep.check(f"{files[key].path} older user CA", "attention",
                          f"{sha[:16]}... names the user CA or is a retired one, and stays trusted while it is here; remove it")
        except Refusal as exc:
            rep.check(f"{files[key].path}", "fail", str(exc))
            present[key] = None
    installed = all(present.get(k) for k in ("ags_ca", "es_ca"))
    try:
        references = client_ca_references(L, [("AGS", L.ags_config, ags.doc), ("ES", L.es_config, es.doc)]
                                          + [(os.path.basename(p), p, parse_json_strict(read_box_file(L, p, 1 << 20)[0].decode("utf-8")))
                                             for p in L.other_service_configs],
                                          [files["ags_ca"].st, files["es_ca"].st])
        rep.check("client CA files read elsewhere", "attention" if references else "ok",
                  "; ".join(references) if references else "only by AGS and ES tls.client_ca_file")
    except (Refusal, UnicodeDecodeError, ValueError) as exc:
        rep.check("client CA files read elsewhere", "attention", f"cannot tell: {exc}")
    sha = ca.cert["sha256"] if ca_pem is not None else None
    ns = L.path_namespace
    retired_ca = ca_pem is not None and ca.retired
    finish_hint = f"run revoke --name {ca.retired_by() or '<the revoked name>'} --remove-ca --apply to finish removing it" if retired_ca else ""
    # Each service on its own: what it loads at its next start is its own
    # client CA file and its own config, whatever the other service has.
    for config, key in ((ags, "ags_ca"), (es, "es_ca")):
        check = f"{config.label} namespace issuer"
        bindings = config.user_bindings(ns, sha)
        if present.get(key):
            if not config.binds_alone(ns, sha):
                rep.check(check, "attention",
                          f"the user CA is trusted but {ns} is not bound to it alone in {config.file.path}, so it could sign other "
                          "identities, the operator's included; "
                          + (finish_hint if retired_ca else "run allow again for an active name to write the binding, "
                             "or revoke --remove-ca once no name is active"))
            elif retired_ca:
                rep.check(check, "attention", f"the retired user CA is still in {files[key].path}, bound to {ns} so it vouches "
                          f"only for {ns}/ paths; {finish_hint}")
            else:
                rep.check(check, "ok", f"binds {ns} to the user CA")
        elif bindings == [(ns, sha)]:
            rep.check(check, "attention",
                      f"binds {ns} to the retired user CA, which {files[key].path} no longer holds; {finish_hint}" if retired_ca
                      else f"binds {ns} to the user CA, which {files[key].path} does not hold; run allow again to finish installing it")
        elif bindings:
            rep.check(check, "attention", f"binds {bindings[0][0]!r} to {bindings[0][1][:16]}..., which is not the user CA bound alone")
    names = ca.registry["names"] if ca_pem is not None else {}
    listed = {}
    for config in (ags, es):
        for p in config.prefixes:
            if matches_prefix(p, L.path_namespace):
                listed.setdefault(p, []).append(config.label)
    for p in sorted(listed):
        stripped = p.strip("/")
        name = stripped.split("/", 1)[1] if "/" in stripped else ""
        entry = names.get(name)
        where = listed[p]
        if p != prefix_for(L, name) or not NAME_RE.match(name):
            rep.check(f"allowlist {p}", "attention", f"in {'+'.join(where)}; not the exact form {L.path_namespace}/<name>, and it may "
                      f"authorize more than one name at an older AGS")
        elif entry is None or entry["state"] != "active":
            rep.check(f"allowlist {p}", "attention", f"in {'+'.join(where)} but not an active registry name")
        elif len(where) != len(set(where)):
            rep.check(f"allowlist {p}", "attention", f"listed more than once ({'+'.join(where)})")
        elif sorted(where) != ["AGS", "ES"]:
            rep.check(f"allowlist {p}", "attention", f"only in {'+'.join(where)}")
        elif not installed:
            rep.check(f"allowlist {p}", "attention", "allowed, but the user CA is not installed in both client CA files")
        else:
            rep.check(f"allowlist {p}", "ok", "allowed by AGS and ES")
    namespace_id = f"spiffe://{L.trust_domain}/{L.path_namespace}/"
    for config in (ags, es):
        for i, rule in enumerate(config.grant_rules):
            for field in ("publisher_principal", "caller_principal"):
                value = rule.get(field, "")
                if value.startswith(namespace_id):
                    entry = names.get(value[len(namespace_id):])
                    if entry is None or entry["state"] != "active":
                        rep.check(f"{config.label} workload grant rule {i}", "attention",
                                  f"{field} {value} is not an active user; revoke removes such rules")
    for name in sorted(names):
        entry = names[name]
        unexpired = ca.unexpired(name)
        latest = max((c.get("not_after_epoch", 0) for c in unexpired), default=0)
        if entry.get("pending_restarts"):
            rep.check(f"name {name}", "attention", f"revoked, but {' and '.join(entry['pending_restarts'])} did not confirm a restart "
                      "without it; run revoke again to finish")
        elif entry["state"] == "revoked":
            rep.check(f"name {name}", "ok", f"revoked at {entry.get('revoked_at', '?')}; {len(unexpired)} certificate(s) not yet expired")
        elif not unexpired:
            rep.check(f"name {name}", "attention", "active, but every certificate has expired; issue a new one")
        else:
            left = days_left(latest)
            rep.check(f"name {name}", "attention" if left < L.cert_attention_days else "ok",
                      f"active; {len(unexpired)} unexpired certificate(s), latest valid {left} more days; "
                      f"{'allowed' if prefix_for(L, name) in listed else 'not allowed'}")
    for unit in (L.ags_unit, L.es_unit):
        try:
            props = r.unit(unit)
            rep.check(unit, "ok" if unit_running(props) else "attention", f"{props.get('ActiveState', '?')}/{props.get('SubState', '?')}")
        except CommandError as exc:
            rep.check(unit, "attention", str(exc))
    if rep.attention_count():
        rep.result = "attention"


# --------------------------------------------------------------------------
# Caller modes


def caller_root(L: Layout) -> str:
    if L.caller_root:
        return L.caller_root
    home = pwd.getpwuid(os.geteuid()).pw_dir
    return os.path.join(home, ".config", "execution-substrate", "callers")


def require_not_root(L: Layout) -> None:
    if os.geteuid() == L.refused_caller_euid:
        raise UsageError("caller modes run as the caller, not as root")


def require_private_caller_dir(path: str) -> None:
    st = lstat_or_none(path)
    if st is None or not stat.S_ISDIR(st.st_mode):
        raise Refusal(f"{path} is missing or not a directory")
    if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o077:
        raise Refusal(f"{path} must be owned by you and closed to group and others (chmod 700)")


def caller_dir(L: Layout, name: str, create: bool) -> str:
    root = caller_root(L)
    directory = os.path.join(root, name)
    if create:
        os.makedirs(directory, mode=0o700, exist_ok=True)
    require_private_caller_dir(root)
    require_private_caller_dir(directory)
    return directory


def read_private_key_path(path: str) -> None:
    st = lstat_or_none(path)
    if st is None:
        raise Refusal(f"{path} does not exist")
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o600:
        raise Refusal(f"{path} must be a regular file owned by you with mode 0600")


def csr_config_text(name: str) -> str:
    return (
        "[ req ]\n"
        "distinguished_name = dn\n"
        "prompt = no\n"
        "[ dn ]\n"
        f"CN = {name}\n"
    )


def mode_request(r: Runner, rep: Report, name: str, renew: bool) -> None:
    L = r.L
    directory = caller_dir(L, name, create=True)
    key_path = os.path.join(directory, "key.pem")
    if renew:
        if lstat_or_none(key_path) is None or lstat_or_none(os.path.join(directory, "cert.pem")) is None:
            raise Refusal("--renew needs an installed key and certificate; run request without --renew first")
        target = os.path.join(directory, "pending")
        if lstat_or_none(target) is not None:
            raise Refusal(f"{target} exists: a renewal is pending; install its certificate or remove {target}")
        os.mkdir(target, 0o700)
    else:
        if lstat_or_none(key_path) is not None:
            raise Refusal(f"{key_path} exists; use --renew to rotate the key")
        for leftover in ("request.csr", "cert.pem"):
            if lstat_or_none(os.path.join(directory, leftover)) is not None:
                raise Refusal(f"{os.path.join(directory, leftover)} exists without a key; remove it first")
        target = directory
    new_key = os.path.join(target, "key.pem")
    csr_path = os.path.join(target, "request.csr")
    cnf_path = os.path.join(target, ".request.cnf")
    try:
        r.openssl(["genrsa", "-out", new_key, str(L.caller_key_bits)], cwd=target)
        os.chmod(new_key, 0o600)
        read_private_key_path(new_key)
        create_exclusive(cnf_path, csr_config_text(name).encode("utf-8"), 0o600)
        r.openssl(["req", "-new", "-key", new_key, "-sha256", "-config", cnf_path, "-out", csr_path], cwd=target)
        os.unlink(cnf_path)
        os.chmod(csr_path, 0o644)
        raw = read_regular_file(csr_path, 16 * 1024)[0]
        csr = parse_csr(single_pem(raw, "CERTIFICATE REQUEST", csr_path))
        problems = csr_problems(csr, name)
        if csr["key"]["der"] != r.public_key_der(new_key):
            problems.append("CSR key differs from the new private key")
        if not r.csr_signature_ok(raw):
            problems.append("CSR self-signature does not verify")
        if problems:
            raise Failure("new CSR check failed: " + "; ".join(problems))
    except BaseException:
        for path in (cnf_path, csr_path, new_key):
            with contextlib.suppress(FileNotFoundError):
                os.unlink(path)
        if renew:
            with contextlib.suppress(OSError):
                os.rmdir(target)
        raise
    rep.action(f"generated an RSA-{L.caller_key_bits} key in {new_key} (0600; it never leaves this machine)")
    rep.action(f"wrote the CSR {csr_path}")
    rep.facts.update(csr=csr_path, csr_sha256=sha256_hex(raw), public_key_sha256=csr["key"]["sha256"],
                     spiffe_id=spiffe_id(L, name))
    rep.result = "ok"
    rep.message = (f"copy only {csr_path} to the box and run there: sudo {PUBLIC_SCRIPT} issue --name {name} "
                   f"--csr <copied csr> --out <cert file>; check that it reports public key sha256 {csr['key']['sha256']}")


def mode_install(r: Runner, rep: Report, name: str, cert_path: str, server_ca_path: str) -> None:
    L = r.L
    directory = caller_dir(L, name, create=False)
    cert = load_certificate_file(cert_path, "certificate")
    problems = leaf_profile_problems(L, cert, name)
    now = utc_now()
    if not cert["not_before"] - 300 <= now < cert["not_after"]:
        problems.append(f"not valid now (valid {iso_utc(cert['not_before'])} to {iso_utc(cert['not_after'])})")
    if problems:
        raise Refusal("; ".join(problems))
    key_path = os.path.join(directory, "key.pem")
    pending = os.path.join(directory, "pending")
    pending_key = os.path.join(pending, "key.pem")
    promote = False
    if lstat_or_none(pending_key) is not None:
        read_private_key_path(pending_key)
        promote = r.public_key_der(pending_key) == cert["key"]["der"]
    if not promote:
        read_private_key_path(key_path)
        if r.public_key_der(key_path) != cert["key"]["der"]:
            raise Refusal("the certificate does not match the local key or a pending renewal key")
    server_ca = None
    if server_ca_path:
        found = read_regular_file(server_ca_path, 256 * 1024)
        if found is None:
            raise Refusal(f"{server_ca_path} does not exist")
        blocks = pem_blocks(found[0], server_ca_path)
        if not blocks or any(label != "CERTIFICATE" for label, _, _ in blocks):
            raise Refusal(f"{server_ca_path} must hold only certificates")
        for _, der, _ in blocks:
            try:
                parsed = parse_certificate(der)
                ok = OID_BASIC_CONSTRAINTS in parsed["extensions"] and ext_basic_constraints(parsed["extensions"][OID_BASIC_CONSTRAINTS][1])[0]
            except DERError:
                ok = False
            if not ok:
                raise Refusal(f"{server_ca_path} holds a certificate that is not a CA")
        server_ca = b"".join(pem_encode("CERTIFICATE", der) for _, der, _ in blocks)
    pem = pem_encode("CERTIFICATE", cert["der"])
    if promote:
        previous = os.path.join(directory, "previous")
        if lstat_or_none(previous) is not None:
            shutil.rmtree(previous)
        os.mkdir(previous, 0o700)
        for item in ("key.pem", "cert.pem", "request.csr"):
            if lstat_or_none(os.path.join(directory, item)) is not None:
                os.rename(os.path.join(directory, item), os.path.join(previous, item))
        os.rename(pending_key, key_path)
        if lstat_or_none(os.path.join(pending, "request.csr")) is not None:
            os.rename(os.path.join(pending, "request.csr"), os.path.join(directory, "request.csr"))
        os.rmdir(pending)
        rep.action(f"promoted the renewal key; the old key and certificate are in {previous}")
    atomic_write(os.path.join(directory, "cert.pem"), pem, 0o644)
    rep.action(f"installed {os.path.join(directory, 'cert.pem')}")
    if server_ca is not None:
        atomic_write(os.path.join(directory, "server-ca.pem"), server_ca, 0o644)
        rep.action(f"installed {os.path.join(directory, 'server-ca.pem')}")
    rep.facts.update(certificate_sha256=cert["sha256"], not_after=iso_utc(cert["not_after"]), spiffe_id=spiffe_id(L, name))
    rep.result = "ok"
    rep.message = f"installed; next: {PUBLIC_SCRIPT} check --name {name} --url https://<box>:<port>"


def parse_service_url(url: str) -> tuple:
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        raise UsageError("--url is not a valid URL") from None
    if parts.scheme != "https" or not parts.hostname or port is None or parts.username or parts.password \
            or parts.path not in ("", "/") or parts.query or parts.fragment:
        raise UsageError("--url must be https://<host>:<port> with nothing after the port")
    return parts.hostname, port


ES_CHECK = ("GET", "/v1/executions:contract")
AGS_CHECK = ("POST", "/v1/artifacts:publish")


def call_service(L: Layout, host: str, port: int, service: str, cert_path: str, key_path: str, server_ca: str) -> dict:
    """One mTLS request. Returns {"outcome", "detail", "status"}."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=server_ca)
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    method, path = ES_CHECK if service == "es" else AGS_CHECK
    conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=L.request_timeout_seconds)
    try:
        try:
            conn.connect()
        except ssl.SSLCertVerificationError as exc:
            return {"outcome": "server_not_trusted", "status": 0,
                    "detail": f"the server certificate is not trusted for {host}: {exc.verify_message}"}
        except ssl.SSLError as exc:
            return {"outcome": "client_certificate_refused", "status": 0,
                    "detail": f"TLS handshake refused ({exc.reason or exc}); the server does not trust this certificate's CA, or the certificate is invalid"}
        except OSError as exc:
            return {"outcome": "unreachable", "status": 0, "detail": f"cannot connect to {host}:{port}: {exc.strerror or exc}"}
        try:
            headers = {"Accept": "application/json"}
            if method == "POST":
                # An empty body: AGS authorizes the caller, then refuses the
                # body before its publish service runs.
                headers.update({"Content-Type": "application/json", "Content-Length": "0"})
            conn.request(method, path, body=b"" if method == "POST" else None, headers=headers)
            response = conn.getresponse()
            body = response.read(64 * 1024)
        except (ssl.SSLError, ConnectionError, http.client.HTTPException) as exc:
            return {"outcome": "client_certificate_refused", "status": 0,
                    "detail": f"the server closed the connection after the handshake ({exc.__class__.__name__}); with TLS 1.3 this is how a refused client certificate shows"}
    finally:
        conn.close()
    status = response.status
    text = body.decode("utf-8", "replace").strip()
    code = ""
    if response.getheader("Content-Type", "").startswith("application/json"):
        with contextlib.suppress(ValueError, AttributeError):
            code = json.loads(text).get("code", "")
    if service == "es" and status == 200:
        return {"outcome": "authorized", "status": status, "detail": "ES accepted the caller and returned its contract"}
    if service == "ags" and status == 400 and code == "invalid_request":
        return {"outcome": "authorized", "status": status,
                "detail": "AGS accepted the caller, then refused the empty publish body as intended (nothing was published)"}
    if status == 401:
        return {"outcome": "not_authenticated", "status": status,
                "detail": "the server did not accept the certificate as a caller identity (expired, wrong SAN, or a CA certificate)"}
    if status == 403 and text == "Caller not authorized for this operation":
        return {"outcome": "not_allowed", "status": status,
                "detail": "authenticated, but the identity is not on the allowlist; run allow on the box"}
    if status == 403:
        return {"outcome": "refused", "status": status, "detail": f"refused: {text[:200]}"}
    return {"outcome": "unexpected", "status": status, "detail": f"unexpected HTTP {status}{(' ' + code) if code else ''}"}


def mode_check(r: Runner, rep: Report, name: str, url: str, service: str, server_ca_path: str) -> None:
    L = r.L
    directory = caller_dir(L, name, create=False)
    key_path = os.path.join(directory, "key.pem")
    cert_path = os.path.join(directory, "cert.pem")
    read_private_key_path(key_path)
    cert = load_certificate_file(cert_path, "installed certificate")
    problems = leaf_profile_problems(L, cert, name)
    if r.public_key_der(key_path) != cert["key"]["der"]:
        problems.append("does not match key.pem")
    if problems:
        rep.check("certificate", "fail", "; ".join(problems))
    else:
        left = days_left(cert["not_after"])
        state = "fail" if cert["not_after"] <= utc_now() else ("attention" if left < L.cert_attention_days else "ok")
        rep.check("certificate", state, f"{spiffe_id(L, name)}, valid until {iso_utc(cert['not_after'])} ({left} days); matches key.pem")
    if lstat_or_none(os.path.join(directory, "pending")) is not None:
        rep.check("renewal", "attention", "a renewal key is pending; install its certificate")
    rep.facts.update(certificate_sha256=cert["sha256"])
    if url:
        host, port = parse_service_url(url)
        server_ca = server_ca_path or os.path.join(directory, "server-ca.pem")
        if lstat_or_none(server_ca) is None:
            raise Refusal(f"no server CA: pass --server-ca or install one with install --server-ca ({server_ca} is absent)")
        result = call_service(L, host, port, service, cert_path, key_path, server_ca)
        rep.check(f"{service.upper()} call", "ok" if result["outcome"] == "authorized" else "attention", result["detail"])
        rep.facts.update(outcome=result["outcome"], http_status=result["status"])
    rep.result = "attention" if rep.attention_count() else "ok"


# --------------------------------------------------------------------------
# Entry point


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PUBLIC_SCRIPT,
        description="Named user caller identities for AGS and ES on the Remote Alpha box.",
        # No abbreviated options: --apply is the safety switch.
        allow_abbrev=False,
    )
    parser.add_argument("mode", choices=BOX_MODES + CALLER_MODES)
    parser.add_argument("--name", help="user name: the identity is spiffe://execution.internal/user/<name>")
    parser.add_argument("--apply", action="store_true", help="box modes: make the changes (default: check and print the plan)")
    parser.add_argument("--csr", help="issue: absolute path of the CSR")
    parser.add_argument("--out", help="issue: absolute path for the new certificate (must not exist)")
    parser.add_argument("--remove-ca", action="store_true", help="revoke: also remove the user CA from both client CA files and retire it")
    parser.add_argument("--replace", action="store_true", help="init-ca: replace a user CA that is installed nowhere and has no active name")
    parser.add_argument("--renew", action="store_true", help="request: make a new key and CSR for renewal")
    parser.add_argument("--cert", help="install: the issued certificate")
    parser.add_argument("--server-ca", help="install, check: the AGS/ES server CA bundle")
    parser.add_argument("--url", help="check: https://<host>:<port> of ES or AGS")
    parser.add_argument("--service", choices=("es", "ags"), default="es", help="check: which service --url names (default es)")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    return parser


_MODE_OPTIONS = {
    "status": set(),
    "init-ca": {"apply", "replace"},
    "issue": {"name", "apply", "csr", "out"},
    "allow": {"name", "apply"},
    "revoke": {"name", "apply", "remove_ca"},
    "request": {"name", "renew"},
    "install": {"name", "cert", "server_ca"},
    "check": {"name", "url", "service", "server_ca"},
}
_REQUIRED = {"issue": ("name", "csr", "out"), "allow": ("name",), "revoke": ("name",), "request": ("name",),
             "install": ("name", "cert"), "check": ("name",)}


def check_usage(args) -> None:
    allowed = _MODE_OPTIONS[args.mode]
    defaults = {"apply": False, "remove_ca": False, "replace": False, "renew": False, "service": "es"}
    for option in ("name", "apply", "csr", "out", "remove_ca", "replace", "renew", "cert", "server_ca", "url", "service"):
        value = getattr(args, option)
        if option not in allowed and value not in (None, defaults.get(option)):
            raise UsageError(f"--{option.replace('_', '-')} is not an option of {args.mode}")
    for option in _REQUIRED.get(args.mode, ()):
        if not getattr(args, option):
            raise UsageError(f"{args.mode} needs --{option}")
    if args.mode == "check" and args.service != "es" and not args.url:
        raise UsageError("--service needs --url")
    if args.name is not None:
        require_name(args.name)


def main(argv: list, layout: Layout) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code not in (0, None) else 0
    rep = Report(args.mode, bool(args.apply))
    try:
        check_usage(args)
        if args.mode in BOX_MODES:
            require_root(layout)
        else:
            require_not_root(layout)
    except UsageError as exc:
        parser.print_usage(sys.stderr)
        print(f"{PUBLIC_SCRIPT}: {exc}", file=sys.stderr)
        return 2
    os.umask(0o077)
    runner = Runner(layout)
    code = 0
    lock_fd = None
    try:
        try:
            for sig in _STOP_SIGNALS:
                signal.signal(sig, _stop_on_signal)
            if args.mode in BOX_MODES:
                require_commands(layout, ("openssl_bin", "systemctl_bin"))
                if args.mode != "status":
                    lock_fd = take_lock(layout)
            else:
                require_commands(layout, ("openssl_bin",))
            if args.mode == "status":
                mode_status(runner, rep)
            elif args.mode == "init-ca":
                mode_init_ca(runner, rep, args.apply, args.replace)
            elif args.mode == "issue":
                mode_issue(runner, rep, args.apply, args.name, args.csr, args.out)
            elif args.mode == "allow":
                mode_allow(runner, rep, args.apply, args.name)
            elif args.mode == "revoke":
                mode_revoke(runner, rep, args.apply, args.name, args.remove_ca)
            elif args.mode == "request":
                mode_request(runner, rep, args.name, args.renew)
            elif args.mode == "install":
                mode_install(runner, rep, args.name, args.cert, args.server_ca or "")
            else:
                mode_check(runner, rep, args.name, args.url or "", args.service, args.server_ca or "")
            code = 0 if rep.result in ("ok", "planned") else 1
        except UsageError as exc:
            rep.result = "refused"
            rep.message = str(exc)
            code = 2
        except Refusal as exc:
            rep.result = "refused"
            rep.message = f"{exc}; nothing was changed"
            code = 1
        except (Failure, CommandError, OSError, DERError) as exc:
            rep.result = "failed"
            rep.message = str(exc) if not isinstance(exc, OSError) else f"{exc.strerror}: {exc.filename}"
            code = 1
    except Interrupted as exc:
        rep.result = "failed"
        rep.message = str(exc)
        code = 1
    finally:
        for sig in _STOP_SIGNALS:
            signal.signal(sig, signal.SIG_IGN)
        if lock_fd is not None:
            os.close(lock_fd)
    sys.stdout.write(rep.render(args.json))
    sys.stdout.flush()
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:], Layout()))
