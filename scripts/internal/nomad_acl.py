#!/usr/bin/env -S python3 -I
"""Nomad access control (ACL) setup and check for Execution Substrate.

ES submits Nomad jobs with one least-privilege ACL client token. This tool is
the one place that sets that up and checks it. It talks to a loopback Nomad
HTTP address only, never prints or passes a token on a command line, and
reads and writes token files with fixed custody rules. Before it sends
anything on a connection, it asks the kernel which user owns the socket that
accepted it, and refuses unless that is Nomad's user (--nomad-uid, default
root): while Nomad is down any local account can hold its port, and must not
receive a token or a bootstrap secret.

  provision  Bootstrap Nomad's ACL system when needed (the operator keeps the
             management token in a root-only file), create the ES namespace
             and policies, and write the ES token file (and optionally a
             read-only observer token file for operator readiness checks).
             Re-running keeps working tokens; --rotate replaces them.
  check      Verify that Nomad enforces ACLs, that the ES and observer
             tokens are client tokens with only their policy and no roles,
             that the ES token can plan in the ES namespace, that the ES and
             observer policies have exactly this tool's rules and no job
             ACL, that no anonymous policy exists, and that requests without
             a token cannot plan jobs there. With --management-token-file, also
             verify that the ES and observer tokens are the only live tokens
             with their policies, and ask Nomad that no other policy, role,
             auth method or management token holds any job capability there.
             That part writes to Nomad: it creates and deletes short-lived
             probe tokens.

Exit status: 0 on success, 1 on a refusal (one line on stderr), 2 on usage.
"""
from __future__ import annotations

import argparse
import datetime
import functools
import http.client
import ipaddress
import json
import os
import re
import socket
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

NAMESPACE = "es-submit-v1"
ES_POLICY = "es-submit-v1"
ES_TOKEN_NAME = "es-submit-v1"
OBSERVER_POLICY = "es-observer-v1"
OBSERVER_TOKEN_NAME = "es-observer-v1"
ANONYMOUS_POLICY = "anonymous"

ES_POLICY_RULES = (
    'namespace "' + NAMESPACE + '" {\n'
    '  capabilities = ["submit-job", "read-job", "read-logs"]\n'
    "}\n"
)
OBSERVER_POLICY_RULES = (
    'agent {\n  policy = "read"\n}\n'
    'node {\n  policy = "read"\n}\n'
    'namespace "' + NAMESPACE + '" {\n'
    '  capabilities = ["read-job", "read-logs"]\n'
    "}\n"
)

TOKEN_PATTERN = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z", re.ASCII)
MAX_RESPONSE_BYTES = 1 << 20
HTTP_TIMEOUT_SECONDS = 10
DEFAULT_LEADER_WAIT_SECONDS = 30
PROC_NET_TCP = (("/proc/net/tcp", True), ("/proc/net/tcp6", False))
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC

# A job used only for plan requests in `check`. Plan registers nothing, but
# Nomad checks submit-job before planning, so a refused plan proves that the
# caller cannot submit in the namespace.
PROBE_JOB_ID = "es-acl-probe"
# Short-lived tokens that ask Nomad whether a policy or role holds any
# capability in the ES namespace. Each is deleted after its probe; the TTL
# bounds a token whose deletion failed. Nomad's default minimum token TTL is
# one minute.
PROBE_TOKEN_NAME = "es-acl-probe"
PROBE_TOKEN_TTL = "5m"


class Refusal(Exception):
    """A safe, token-free failure message for the operator."""


# --- HTTP -------------------------------------------------------------------


def _proc_net_endpoint(text: str):
    """Decode a /proc/net/tcp{,6} address: hex words in host byte order, then
    a hex port. An IPv4-mapped IPv6 address is returned as IPv4."""
    address_hex, port_hex = text.split(":")
    raw = bytes.fromhex(address_hex)
    packed = b"".join(
        int.from_bytes(raw[i : i + 4], "big").to_bytes(4, sys.byteorder) for i in range(0, len(raw), 4)
    )
    address = ipaddress.ip_address(packed)
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address, int(port_hex, 16)


def _endpoint(sockaddr):
    address = ipaddress.ip_address(sockaddr[0])
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address, sockaddr[1]


def _accepting_socket_owners(sock: socket.socket) -> set[int]:
    """The owners of the socket(s) on the other end of this loopback
    connection, from the kernel's TCP tables. The server side of a connection
    is owned by the user that owns the listening socket, whether it is still
    a pending request or already accepted."""
    ours = _endpoint(sock.getsockname())
    theirs = _endpoint(sock.getpeername())
    owners: set[int] = set()
    for path, required in PROC_NET_TCP:
        try:
            with open(path, encoding="ascii") as handle:
                lines = handle.read().splitlines()[1:]
        except OSError:
            if required:
                raise Refusal(f"cannot read {path} to see who holds Nomad's port; no request was sent") from None
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 8:
                continue
            if _proc_net_endpoint(fields[1]) == theirs and _proc_net_endpoint(fields[2]) == ours:
                owners.add(int(fields[7]))
    return owners


def require_nomads_socket(sock: socket.socket, nomad_uid: int, base: str) -> None:
    owners: set[int] = set()
    for _ in range(20):
        owners = _accepting_socket_owners(sock)
        if owners:
            break
        time.sleep(0.01)
    if owners != {nomad_uid}:
        found = ", ".join(str(owner) for owner in sorted(owners)) or "nobody the kernel lists"
        raise Refusal(
            f"the process listening on {base} runs as uid {found}, not Nomad's uid {nomad_uid}: "
            "another local account may hold Nomad's port while Nomad is down; nothing was sent"
        )


class _NomadsConnection(http.client.HTTPConnection):
    """An HTTP connection that sends nothing until the kernel shows that
    Nomad's user owns the accepting socket."""

    def __init__(self, *args, nomad_uid: int, base: str, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._nomad_uid = nomad_uid
        self._base = base

    def connect(self) -> None:
        super().connect()
        try:
            require_nomads_socket(self.sock, self._nomad_uid, self._base)
        except BaseException:
            self.close()
            raise


class _NomadsHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, nomad_uid: int, base: str) -> None:
        super().__init__()
        self._connection = functools.partial(_NomadsConnection, nomad_uid=nomad_uid, base=base)

    def http_open(self, req):
        return self.do_open(self._connection, req)


class Nomad:
    def __init__(self, address: str, nomad_uid: int = 0) -> None:
        parsed = urllib.parse.urlsplit(address)
        host = parsed.hostname or ""
        if (
            parsed.scheme != "http"
            or host not in ("127.0.0.1", "::1")
            or parsed.port is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise Refusal("nomad address must be http://127.0.0.1:<port> or http://[::1]:<port>")
        self.base = address.rstrip("/")
        # Never follow redirects and never use a proxy: a token must reach
        # only the loopback Nomad named here, and only once the kernel shows
        # that Nomad's user owns the socket that accepted the connection.
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirect(),
            _NomadsHTTPHandler(nomad_uid, self.base),
        )

    def request(self, method: str, path: str, token: str | None = None, body=None):
        headers = {"Accept": "application/json"}
        data = None
        if token is not None:
            headers["X-Nomad-Token"] = token
        if body is not None:
            data = json.dumps(body, sort_keys=True).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
                status = response.status
                payload = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as error:
            status = error.code
            payload = error.read(MAX_RESPONSE_BYTES + 1)
            error.close()
        except (urllib.error.URLError, OSError) as error:
            raise Refusal(f"nomad is unreachable at {self.base}: {_reason(error)}") from None
        if len(payload) > MAX_RESPONSE_BYTES:
            raise Refusal(f"nomad response to {method} {path} is too large")
        return status, payload

    def json(self, method: str, path: str, token: str | None = None, body=None, expect=(200,)):
        status, payload = self.request(method, path, token, body)
        if status not in expect:
            raise Refusal(f"nomad {method} {path} returned HTTP {status}: {_text(payload)}")
        if not payload:
            return None
        try:
            return json.loads(payload)
        except ValueError:
            raise Refusal(f"nomad {method} {path} returned a body that is not JSON") from None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def _reason(error: BaseException) -> str:
    reason = getattr(error, "reason", error)
    return str(reason)[:200]


def _text(payload: bytes) -> str:
    text = payload.decode("utf-8", "replace").strip().replace("\n", " ")
    return text[:200] if text else "(empty body)"


# --- token files ------------------------------------------------------------


def _clean_absolute(path: str, label: str) -> None:
    if (
        not path
        or not path.startswith("/")
        or path.startswith("//")
        or os.path.normpath(path) != path
        or os.path.dirname(path) == "/"
        or "\x00" in path
        or "\n" in path
    ):
        raise Refusal(f"{label} must be a clean absolute path with a non-root parent directory")


def _open_safe_parent(path: str, label: str) -> int:
    parent = os.path.dirname(path)
    try:
        fd = os.open(parent, DIR_FLAGS)
    except OSError:
        raise Refusal(f"{label} parent directory {parent} is unavailable") from None
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
        os.close(fd)
        raise Refusal(
            f"{label} parent directory {parent} must belong to root or the current user "
            "and must not be writable by group or others"
        )
    return fd


def parse_owner(value: str) -> tuple[int, int]:
    match = re.fullmatch(r"([0-9]{1,10}):([0-9]{1,10})", value or "", re.ASCII)
    if not match:
        raise Refusal("token owner must be <uid>:<gid> in numbers")
    return int(match.group(1)), int(match.group(2))


def read_token_file(path: str, label: str, owner_uid: int | None = None) -> str:
    """Read a token file: regular, one link, mode 0400 or 0600, owned by
    owner_uid (default: the current user), safe parent, canonical UUID."""
    _clean_absolute(path, label)
    want_uid = os.geteuid() if owner_uid is None else owner_uid
    parent_fd = _open_safe_parent(path, label)
    try:
        name = os.path.basename(path)
        try:
            fd = os.open(name, FILE_FLAGS, dir_fd=parent_fd)
        except FileNotFoundError:
            raise Refusal(f"{label} {path} does not exist") from None
        except OSError:
            raise Refusal(f"{label} {path} is unavailable or is a symbolic link") from None
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != want_uid
                or stat.S_IMODE(info.st_mode) not in (0o400, 0o600)
            ):
                raise Refusal(
                    f"{label} {path} must be a regular file with one link, owned by uid {want_uid}, mode 0400 or 0600"
                )
            data = os.read(fd, 64)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
    text = data.decode("ascii", "replace")
    if text.endswith("\n"):
        text = text[:-1]
    if not TOKEN_PATTERN.fullmatch(text):
        raise Refusal(f"{label} {path} must hold exactly one Nomad token secret ID")
    return text


def file_exists_no_follow(path: str) -> bool:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    return True


def write_token_file(path: str, label: str, secret: str, uid: int, gid: int, mode: int, replace: bool) -> None:
    """Write secret atomically: a new file in the same directory, owned and
    moded before it holds the secret's final name. Without replace, an
    existing file is never overwritten."""
    _clean_absolute(path, label)
    if not TOKEN_PATTERN.fullmatch(secret):
        raise Refusal(f"refusing to write a malformed token to {label}")
    parent_fd = _open_safe_parent(path, label)
    name = os.path.basename(path)
    temp = f".{name}.tmp-{uuid.uuid4().hex}"
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent_fd)
        try:
            os.fchmod(fd, 0o600)
            if os.geteuid() == 0:
                os.fchown(fd, uid, gid)
            elif (uid, gid) != (os.geteuid(), os.getegid()):
                raise Refusal(f"only root can write {label} for uid {uid} gid {gid}")
            payload = (secret + "\n").encode("ascii")
            if os.write(fd, payload) != len(payload):
                raise Refusal(f"short write to {label}")
            os.fchmod(fd, mode)
            os.fsync(fd)
        finally:
            os.close(fd)
        if replace:
            os.rename(temp, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        else:
            try:
                os.link(temp, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd, follow_symlinks=False)
            except FileExistsError:
                raise Refusal(f"{label} {path} appeared while it was being written") from None
            os.unlink(temp, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except Refusal:
        _unlink_quietly(temp, parent_fd)
        raise
    except OSError as error:
        _unlink_quietly(temp, parent_fd)
        raise Refusal(f"could not write {label} {path}: {error.strerror}") from None
    finally:
        os.close(parent_fd)


def _unlink_quietly(name: str, dir_fd: int) -> None:
    try:
        os.unlink(name, dir_fd=dir_fd)
    except OSError:
        pass


def remove_token_file(path: str) -> None:
    parent_fd = _open_safe_parent(path, "token file")
    try:
        os.unlink(os.path.basename(path), dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


# --- Nomad state ------------------------------------------------------------


def token_self(nomad: Nomad, token: str | None):
    status, payload = nomad.request("GET", "/v1/acl/token/self", token)
    if status != 200:
        return status, None
    try:
        return status, json.loads(payload)
    except ValueError:
        raise Refusal("nomad GET /v1/acl/token/self returned a body that is not JSON") from None


def require_acl_enabled(nomad: Nomad) -> None:
    status, payload = nomad.request("GET", "/v1/acl/token/self", None)
    document = None
    if status == 200:
        try:
            document = json.loads(payload)
        except ValueError:
            raise Refusal("nomad GET /v1/acl/token/self returned a body that is not JSON") from None
    if status == 200 and isinstance(document, dict) and document.get("AccessorID") == "acls-disabled":
        raise Refusal(
            "nomad ACLs are disabled: add `acl { enabled = true }` to the Nomad agent configuration and restart Nomad"
        )
    if status != 200 or not isinstance(document, dict) or document.get("AccessorID") != "anonymous":
        raise Refusal(
            "nomad did not answer as an ACL-enabled agent "
            f"(GET /v1/acl/token/self returned HTTP {status}: {_text(payload)})"
        )


def wait_for_leader(nomad: Nomad, seconds: int) -> None:
    """Nomad bootstraps ACLs only with a leader. It answers "" while it elects
    one and an error while it has none; only a named leader counts."""
    deadline = time.monotonic() + seconds
    while True:
        status, payload = nomad.request("GET", "/v1/status/leader", None)
        leader = None
        if status == 200:
            try:
                leader = json.loads(payload)
            except ValueError:
                leader = None
        if isinstance(leader, str) and leader.strip():
            return
        if time.monotonic() >= deadline:
            raise Refusal(
                f"nomad has no leader after {seconds}s (GET /v1/status/leader returned HTTP {status}: "
                f"{_text(payload)}); rerun once Nomad has elected one"
            )
        time.sleep(1)


def require_management(nomad: Nomad, token: str) -> None:
    status, document = token_self(nomad, token)
    if status != 200 or not isinstance(document, dict) or document.get("Type") != "management":
        raise Refusal("the management token file does not hold a working Nomad management token")


def bootstrap_or_load_management(nomad: Nomad, path: str) -> str:
    if file_exists_no_follow(path):
        token = read_token_file(path, "management token file")
        status, document = token_self(nomad, token)
        if status == 200 and isinstance(document, dict) and document.get("Type") == "management":
            return token
        # Nomad does not know the saved secret. An earlier bootstrap may have
        # failed before Nomad installed it (no leader yet, a lost response), so
        # offer it again: Nomad accepts it only while ACLs are not bootstrapped.
        return _bootstrap(nomad, path, token, created=False)
    secret = str(uuid.uuid4())
    # The secret is on disk before Nomad sees it, so a lost response never
    # loses the management token.
    write_token_file(path, "management token file", secret, os.geteuid(), os.getegid(), 0o600, replace=False)
    return _bootstrap(nomad, path, secret, created=True)


def _bootstrap(nomad: Nomad, path: str, secret: str, created: bool) -> str:
    status, payload = nomad.request("POST", "/v1/acl/bootstrap", None, {"BootstrapSecret": secret})
    if status == 200:
        require_management(nomad, secret)
        print("nomad acl: bootstrapped; management token kept in the management token file")
        return secret
    if status == 400 and b"bootstrap already done" in payload.lower():
        if created:
            remove_token_file(path)
            raise Refusal(
                "nomad ACLs were already bootstrapped by someone else and the management token file is absent: "
                "put that management token into the file (mode 0600, owned by this user) or follow Nomad's "
                "ACL bootstrap reset procedure, then rerun"
            )
        raise Refusal(
            "the management token file does not hold a working Nomad management token and nomad ACLs were "
            "already bootstrapped: put the management token into the file (mode 0600, owned by this user) or "
            "follow Nomad's ACL bootstrap reset procedure, then rerun"
        )
    raise Refusal(
        f"nomad ACL bootstrap returned HTTP {status}: {_text(payload)}; the management token was kept "
        "in the management token file, so a rerun can finish or reuse it"
    )


def upsert_namespace(nomad: Nomad, management: str) -> None:
    nomad.json(
        "POST",
        "/v1/namespace/" + NAMESPACE,
        management,
        {"Name": NAMESPACE, "Description": "Execution Substrate submit path; ES is the only client writer"},
    )


def upsert_policy(nomad: Nomad, management: str, name: str, rules: str, description: str) -> None:
    """Write the whole policy. JobACL is written as null, which clears a job
    ACL someone attached: Nomad would give the policy's capabilities to the
    workloads of the job it names."""
    nomad.json(
        "POST",
        "/v1/acl/policy/" + name,
        management,
        {"Name": name, "Description": description, "Rules": rules, "JobACL": None},
    )


def require_no_anonymous_policy(nomad: Nomad) -> None:
    status, payload = nomad.request("GET", "/v1/acl/policy/" + ANONYMOUS_POLICY, None)
    if status == 200:
        raise Refusal(
            "nomad has an `anonymous` ACL policy, so requests without a token hold capabilities and ES refuses "
            "to submit: review what depends on it, delete it with `nomad acl policy delete anonymous`, and rerun"
        )
    if status != 404:
        raise Refusal(f"nomad GET /v1/acl/policy/anonymous returned HTTP {status}: {_text(payload)}")


def list_tokens(nomad: Nomad, management: str):
    tokens = nomad.json("GET", "/v1/acl/tokens", management)
    if not isinstance(tokens, list):
        raise Refusal("nomad GET /v1/acl/tokens did not return a list")
    return [token for token in tokens if isinstance(token, dict)]


def ensure_client_token(
    nomad: Nomad,
    management: str,
    name: str,
    policy: str,
    path: str,
    label: str,
    uid: int,
    gid: int,
    rotate: bool,
) -> str:
    keep_accessor = ""
    if not rotate and file_exists_no_follow(path):
        try:
            secret = read_token_file(path, label, owner_uid=uid)
            status, document = token_self(nomad, secret)
        except Refusal:
            status, document = 0, None
        if (
            status == 200
            and isinstance(document, dict)
            and document.get("Type") == "client"
            and document.get("Name") == name
            and document.get("Policies") == [policy]
            and not document.get("Roles")
            and not document.get("ExpirationTime")
        ):
            keep_accessor = str(document.get("AccessorID") or "")
    if not keep_accessor:
        created = nomad.json(
            "POST",
            "/v1/acl/token",
            management,
            {"Name": name, "Type": "client", "Policies": [policy]},
        )
        secret = created.get("SecretID") if isinstance(created, dict) else None
        keep_accessor = created.get("AccessorID") if isinstance(created, dict) else None
        if not isinstance(secret, str) or not TOKEN_PATTERN.fullmatch(secret) or not keep_accessor:
            raise Refusal("nomad did not return a usable token")
        write_token_file(path, label, secret, uid, gid, 0o400, replace=True)
        print(f"nomad acl: wrote a new {name} token (accessor {keep_accessor}) to the {label}")
    else:
        print(f"nomad acl: kept the working {name} token (accessor {keep_accessor})")
    # Exactly one live token carries this name and policy.
    for token in list_tokens(nomad, management):
        accessor = str(token.get("AccessorID") or "")
        if accessor == keep_accessor:
            continue
        if token.get("Name") == name or policy in (token.get("Policies") or []):
            nomad.json("DELETE", "/v1/acl/token/" + urllib.parse.quote(accessor, safe=""), management)
            print(f"nomad acl: deleted the stale {name} token (accessor {accessor})")
    return keep_accessor


def _plan_probe_status(nomad: Nomad, token: str | None) -> int:
    status, _ = nomad.request("POST", "/v1/job/" + PROBE_JOB_ID + "/plan?namespace=" + NAMESPACE, token, _probe_plan_body())
    return status


def _namespace_probe_status(nomad: Nomad, token: str | None) -> int:
    """Nomad answers a namespace read with 200 when the token holds any job
    capability in that namespace (submit, scale, dispatch, alloc-lifecycle,
    alloc-exec, read and the rest), and with 403 when it holds none, including
    when a deny shadows a glob grant. Variables capabilities are not job
    capabilities and do not count; ES's jobs read no Nomad variables."""
    status, _ = nomad.request("GET", "/v1/namespace/" + NAMESPACE, token)
    return status


def policy_document(nomad: Nomad, token: str, name: str) -> dict | None:
    """ACL policy name as Nomad stores it, read with token (the management
    token, or a client token that holds the policy). None when Nomad has no
    such policy."""
    status, payload = nomad.request("GET", "/v1/acl/policy/" + urllib.parse.quote(name, safe=""), token)
    if status == 404:
        return None
    if status != 200:
        raise Refusal(f"nomad GET /v1/acl/policy/{name} returned HTTP {status}: {_text(payload)}")
    try:
        document = json.loads(payload)
    except ValueError:
        raise Refusal(f"nomad GET /v1/acl/policy/{name} returned a body that is not JSON") from None
    if not isinstance(document, dict) or not isinstance(document.get("Rules"), str):
        raise Refusal(f"nomad GET /v1/acl/policy/{name} returned no rules")
    return document


def is_designed_policy(document: dict, rules: str) -> bool:
    """True when the policy has exactly the tool's rules and no job ACL
    (Nomad returns JobACL null when none is set)."""
    return document.get("Rules") == rules and document.get("JobACL") is None


def grants_in_namespace(nomad: Nomad, management: str) -> list[str]:
    """Every ACL policy other than ES's and the observer's, and every ACL
    role, that Nomad lets hold any job capability in the ES namespace. The
    observer policy is left out only while its rules are exactly the tool's
    read-only ones and it has no job ACL. Nomad itself decides, so a grant
    counts however its rules are written (HCL, JSON, escapes, globs) and
    whatever job capability it gives (submit, scale, dispatch,
    alloc-lifecycle, alloc-exec, read and the rest): for each policy or
    role, a short-lived client token holding only it reads the ES namespace
    and plans the probe job there, and any answer but 403 to either counts
    as a grant. Each probe token is deleted after its probe."""
    subjects = []
    for stub in nomad.json("GET", "/v1/acl/policies", management) or []:
        name = stub.get("Name") if isinstance(stub, dict) else None
        if not isinstance(name, str) or not name:
            raise Refusal("nomad GET /v1/acl/policies returned an entry without a name")
        if name == ES_POLICY:
            continue
        if name == OBSERVER_POLICY:
            document = policy_document(nomad, management, name)
            if document is not None and is_designed_policy(document, OBSERVER_POLICY_RULES):
                continue
        subjects.append(("policy " + name, {"Policies": [name]}))
    for stub in nomad.json("GET", "/v1/acl/roles", management) or []:
        role_id = stub.get("ID") if isinstance(stub, dict) else None
        name = stub.get("Name") if isinstance(stub, dict) else None
        if not isinstance(role_id, str) or not role_id or not isinstance(name, str):
            raise Refusal("nomad GET /v1/acl/roles returned an entry without an ID and a name")
        subjects.append(("role " + name, {"Roles": [{"ID": role_id}]}))
    granted = []
    for label, grant in subjects:
        body = {"Name": PROBE_TOKEN_NAME, "Type": "client", "ExpirationTTL": PROBE_TOKEN_TTL}
        body.update(grant)
        created = nomad.json("POST", "/v1/acl/token", management, body)
        secret = created.get("SecretID") if isinstance(created, dict) else None
        accessor = created.get("AccessorID") if isinstance(created, dict) else None
        if not isinstance(accessor, str) or not accessor:
            raise Refusal("nomad did not return a usable probe token")
        try:
            if not isinstance(secret, str) or not TOKEN_PATTERN.fullmatch(secret):
                raise Refusal("nomad did not return a usable probe token")
            statuses = (_namespace_probe_status(nomad, secret), _plan_probe_status(nomad, secret))
        finally:
            nomad.json("DELETE", "/v1/acl/token/" + urllib.parse.quote(accessor, safe=""), management)
        if statuses != (403, 403):
            granted.append(label)
    return sorted(granted)


def require_no_auth_methods(nomad: Nomad, management: str) -> None:
    """An auth method's binding rules can issue tokens with any policy or
    role, including ES's, so this lock does not hold while one exists."""
    methods = nomad.json("GET", "/v1/acl/auth-methods", management)
    if not isinstance(methods, list):
        raise Refusal("nomad GET /v1/acl/auth-methods did not return a list")
    if methods:
        names = sorted(str(method.get("Name")) for method in methods if isinstance(method, dict))
        raise Refusal(
            "nomad has ACL auth methods (" + ", ".join(names) + "), whose binding rules can issue tokens that "
            "submit in " + NAMESPACE + ": ES must be the only client writer there; delete them and rerun"
        )


_EXPIRATION_PATTERN = re.compile(
    r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})\Z", re.ASCII
)


def _token_has_expired(expiration) -> bool:
    """True only for an RFC 3339 expiration time that has passed. A token
    without one, with Go's zero time (year 1), or with one this tool cannot
    read, counts as live."""
    if not isinstance(expiration, str) or expiration.startswith("0001-"):
        return False
    match = _EXPIRATION_PATTERN.fullmatch(expiration)
    if match is None:
        return False
    fraction = (match.group(2) or "")[:6].ljust(6, "0")
    zone = "+00:00" if match.group(3) == "Z" else match.group(3)
    try:
        moment = datetime.datetime.fromisoformat(match.group(1) + "." + fraction + zone)
    except ValueError:
        return False
    return moment <= datetime.datetime.now(datetime.timezone.utc)


def other_management_tokens(nomad: Nomad, management: str) -> list[str]:
    """Accessor IDs of live management tokens other than the one in the
    management token file. Each of them can submit in any namespace."""
    status, own = token_self(nomad, management)
    own_accessor = own.get("AccessorID") if status == 200 and isinstance(own, dict) else None
    if not own_accessor:
        raise Refusal("the management token file does not hold a working Nomad management token")
    return sorted(
        str(token.get("AccessorID"))
        for token in list_tokens(nomad, management)
        if token.get("Type") == "management"
        and token.get("AccessorID") != own_accessor
        and not _token_has_expired(token.get("ExpirationTime"))
    )


def require_exclusive_writer(nomad: Nomad, management: str) -> None:
    require_no_auth_methods(nomad, management)
    extra_management = other_management_tokens(nomad, management)
    if extra_management:
        raise Refusal(
            "nomad has other management tokens (accessors " + ", ".join(extra_management) + "), each of which "
            "can submit in " + NAMESPACE + ": ES must be the only client writer there and the management token "
            "file must hold the only management token; delete the others and rerun"
        )
    others = grants_in_namespace(nomad, management)
    if others:
        raise Refusal(
            "other ACL grants hold capabilities in " + NAMESPACE + " (" + ", ".join(others) + "): "
            "only ES may submit or change jobs there and only the read-only observer may read them; "
            "narrow or delete them and rerun"
        )


def live_token_accessors_with_policy(nomad: Nomad, management: str, policy: str) -> list[str]:
    """Accessor IDs of live tokens that list policy directly."""
    return sorted(
        str(token.get("AccessorID"))
        for token in list_tokens(nomad, management)
        if policy in (token.get("Policies") or []) and not _token_has_expired(token.get("ExpirationTime"))
    )


def require_designed_policy(nomad: Nomad, token: str, name: str, rules: str, required: bool) -> None:
    """Refuse unless ACL policy name has exactly the tool's rules and no job
    ACL (or, when not required, does not exist)."""
    document = policy_document(nomad, token, name)
    if document is None and not required:
        return
    if document is None or document.get("Rules") != rules:
        raise Refusal(
            "the " + name + " policy's rules differ from the ones this tool writes; "
            "rerun provision (scripts/nomad_acl_setup.sh) to restore them"
        )
    if document.get("JobACL") is not None:
        raise Refusal(
            "the " + name + " policy has a job ACL, which gives its capabilities to the workloads of the job it "
            "names; rerun provision (scripts/nomad_acl_setup.sh) to clear it"
        )


# --- commands ---------------------------------------------------------------


def command_provision(args) -> None:
    nomad = Nomad(args.addr, args.nomad_uid)
    es_uid, es_gid = parse_owner(args.es_token_owner)
    observer_owner = None
    if args.observer_token_file:
        observer_owner = parse_owner(args.observer_token_owner or "")
    elif args.observer_token_owner:
        raise Refusal("--observer-token-owner needs --observer-token-file")
    paths = [args.management_token_file, args.es_token_file] + ([args.observer_token_file] if args.observer_token_file else [])
    if len(set(paths)) != len(paths):
        raise Refusal("the management, ES and observer token files must be different files")

    wait_for_leader(nomad, args.leader_wait_seconds)
    require_acl_enabled(nomad)
    management = bootstrap_or_load_management(nomad, args.management_token_file)
    require_no_anonymous_policy(nomad)
    # The namespace must exist for Nomad to answer the probes in it. The
    # tool's own policies are written first, so a widened copy of either is
    # restored before the probes judge every other grant.
    upsert_namespace(nomad, management)
    upsert_policy(nomad, management, ES_POLICY, ES_POLICY_RULES, "Execution Substrate: submit, read and log jobs in " + NAMESPACE)
    if observer_owner is not None:
        upsert_policy(
            nomad,
            management,
            OBSERVER_POLICY,
            OBSERVER_POLICY_RULES,
            "Execution Substrate operator checks: read agent, nodes, and jobs in " + NAMESPACE,
        )
    require_exclusive_writer(nomad, management)
    ensure_client_token(
        nomad, management, ES_TOKEN_NAME, ES_POLICY, args.es_token_file, "ES token file", es_uid, es_gid, args.rotate
    )
    if observer_owner is not None:
        ensure_client_token(
            nomad,
            management,
            OBSERVER_TOKEN_NAME,
            OBSERVER_POLICY,
            args.observer_token_file,
            "observer token file",
            observer_owner[0],
            observer_owner[1],
            args.rotate,
        )
    print("nomad acl: provisioned namespace " + NAMESPACE + ", policies and tokens")


def _probe_plan_body() -> dict:
    return {
        "Job": {
            "ID": PROBE_JOB_ID,
            "Name": PROBE_JOB_ID,
            "Type": "batch",
            "Namespace": NAMESPACE,
            "Datacenters": ["dc1"],
            "TaskGroups": [
                {
                    "Name": "probe",
                    "Count": 1,
                    "Tasks": [{"Name": "probe", "Driver": "docker", "Config": {"image": "alpine:3.20", "command": "/bin/true"}}],
                }
            ],
        }
    }


def command_check(args) -> None:
    nomad = Nomad(args.addr, args.nomad_uid)
    require_acl_enabled(nomad)
    require_no_anonymous_policy(nomad)

    es_uid = None
    if args.es_token_owner:
        es_uid = parse_owner(args.es_token_owner)[0]
    es_token = read_token_file(args.es_token_file, "ES token file", owner_uid=es_uid)
    status, document = token_self(nomad, es_token)
    if (
        status != 200
        or not isinstance(document, dict)
        or document.get("Type") != "client"
        or document.get("Policies") != [ES_POLICY]
        or document.get("Roles")
        or document.get("SecretID") != es_token
    ):
        raise Refusal(
            "the ES token file does not hold the ES client token with only the " + ES_POLICY + " policy and no roles"
        )
    es_accessor = str(document.get("AccessorID") or "")
    # A token may read the policies it holds, so this needs no management token.
    require_designed_policy(nomad, es_token, ES_POLICY, ES_POLICY_RULES, required=True)

    plan_path = "/v1/job/" + PROBE_JOB_ID + "/plan?namespace=" + NAMESPACE
    status, payload = nomad.request("POST", plan_path, None, _probe_plan_body())
    if status != 403:
        raise Refusal(f"a plan without a token in {NAMESPACE} returned HTTP {status}, want 403: {_text(payload)}")
    status, payload = nomad.request("POST", plan_path, es_token, _probe_plan_body())
    if status != 200:
        raise Refusal(f"a plan with the ES token in {NAMESPACE} returned HTTP {status}, want 200: {_text(payload)}")
    default_body = _probe_plan_body()
    default_body["Job"]["Namespace"] = "default"
    status, payload = nomad.request("POST", "/v1/job/" + PROBE_JOB_ID + "/plan?namespace=default", es_token, default_body)
    if status != 403:
        raise Refusal(f"a plan with the ES token in namespace default returned HTTP {status}, want 403")
    status, payload = nomad.request("GET", "/v1/nodes", es_token)
    if status != 403:
        raise Refusal(f"the ES token could read nodes (HTTP {status}); its policy is wider than {ES_POLICY}")

    observer_accessor = None
    if args.observer_token_file:
        observer = read_token_file(args.observer_token_file, "observer token file", owner_uid=None if not args.observer_token_owner else parse_owner(args.observer_token_owner)[0])
        status, document = token_self(nomad, observer)
        if (
            status != 200
            or not isinstance(document, dict)
            or document.get("Type") != "client"
            or document.get("Policies") != [OBSERVER_POLICY]
            or document.get("Roles")
            or document.get("SecretID") != observer
        ):
            raise Refusal(
                "the observer token file does not hold the observer client token with only the "
                + OBSERVER_POLICY + " policy and no roles"
            )
        observer_accessor = str(document.get("AccessorID") or "")
        require_designed_policy(nomad, observer, OBSERVER_POLICY, OBSERVER_POLICY_RULES, required=True)
        status, _ = nomad.request("POST", plan_path, observer, _probe_plan_body())
        if status != 403:
            raise Refusal(f"the observer token could plan jobs in {NAMESPACE} (HTTP {status})")
    exclusive = ""
    if args.management_token_file:
        management = read_token_file(args.management_token_file, "management token file", owner_uid=os.geteuid())
        require_management(nomad, management)
        require_designed_policy(nomad, management, OBSERVER_POLICY, OBSERVER_POLICY_RULES, required=observer_accessor is not None)
        holders = live_token_accessors_with_policy(nomad, management, ES_POLICY)
        if holders != [es_accessor]:
            raise Refusal(
                "live tokens holding the " + ES_POLICY + " policy are (accessors " + ", ".join(holders) + "), want only "
                "the ES token's (" + es_accessor + "); rerun provision to delete the others"
            )
        if observer_accessor is not None:
            holders = live_token_accessors_with_policy(nomad, management, OBSERVER_POLICY)
            if holders != [observer_accessor]:
                raise Refusal(
                    "live tokens holding the " + OBSERVER_POLICY + " policy are (accessors " + ", ".join(holders) + "), "
                    "want only the observer token's (" + observer_accessor + "); rerun provision to delete the others"
                )
        require_exclusive_writer(nomad, management)
        exclusive = ", it is the only token with that policy, and no other grant holds capabilities there"
    print(
        "nomad acl: ok (ACLs enforced, no anonymous policy, ES token is the " + ES_POLICY + " client token, "
        "policies as designed" + exclusive + ")"
    )


NOMAD_UID_HELP = "uid that Nomad's HTTP listener runs as; nothing is sent to a listener owned by any other user (default 0)"


def _non_negative_int(text: str) -> int:
    if not re.fullmatch(r"[0-9]{1,10}", text, re.ASCII):
        raise argparse.ArgumentTypeError("must be a non-negative integer")
    return int(text)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="nomad_acl.py", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    provision = sub.add_parser("provision")
    provision.add_argument("--addr", required=True)
    provision.add_argument("--nomad-uid", type=_non_negative_int, default=0, help=NOMAD_UID_HELP)
    provision.add_argument("--management-token-file", required=True)
    provision.add_argument("--es-token-file", required=True)
    provision.add_argument("--es-token-owner", required=True, help="<uid>:<gid> of the user ES runs as")
    provision.add_argument("--observer-token-file")
    provision.add_argument("--observer-token-owner", help="<uid>:<gid> of the operator who runs readiness checks")
    provision.add_argument("--rotate", action="store_true", help="replace the ES and observer tokens")
    provision.add_argument(
        "--leader-wait-seconds",
        type=_non_negative_int,
        default=DEFAULT_LEADER_WAIT_SECONDS,
        help="how long to wait for Nomad to name a leader before bootstrapping (default 30)",
    )

    check = sub.add_parser("check")
    check.add_argument("--addr", required=True)
    check.add_argument("--nomad-uid", type=_non_negative_int, default=0, help=NOMAD_UID_HELP)
    check.add_argument("--es-token-file", required=True)
    check.add_argument("--es-token-owner", help="<uid>:<gid> expected to own the ES token file (default: current user)")
    check.add_argument("--observer-token-file")
    check.add_argument("--observer-token-owner")
    check.add_argument(
        "--management-token-file",
        help="also prove, with the management token, that the ES and observer tokens are the only ones with their policies and that no other policy, role, auth method or management token holds any job capability in the ES namespace (creates and deletes short-lived probe tokens)",
    )

    args = parser.parse_args(argv)
    try:
        if args.command == "provision":
            for path, label in (
                (args.management_token_file, "--management-token-file"),
                (args.es_token_file, "--es-token-file"),
                (args.observer_token_file, "--observer-token-file"),
            ):
                if path is not None:
                    _clean_absolute(path, label)
            command_provision(args)
        else:
            if args.management_token_file is not None:
                _clean_absolute(args.management_token_file, "--management-token-file")
            command_check(args)
    except Refusal as refusal:
        print(f"nomad acl: refused: {refusal}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
