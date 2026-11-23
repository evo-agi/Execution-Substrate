from __future__ import annotations

import datetime as dt
import errno
import hashlib
import json
import os
import re
import selectors
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Callable

PROTOCOL_VERSION = "execution-substrate.remote-alpha.operator-healthcheck-tls-status-noninteractive.remote.v1"

OPERATOR_CERT_PATH = "/etc/execution-substrate/tls/operator-client-cert.pem"
OPERATOR_KEY_PATH = "/etc/execution-substrate/tls/operator-client-key.pem"
SERVER_CLIENT_CA_PATH = "/etc/execution-substrate/es-tls/server-client-ca.pem"

OPENSSL = "/usr/bin/openssl"
SHA256SUM = "/usr/bin/sha256sum"
STAT = "/usr/bin/stat"
SUDO = "/usr/bin/sudo"

EXPECTED_OPERATOR_URI = "spiffe://execution.internal/operator/local"
LEGACY_OPERATOR_URI = "spiffe://execution.internal/operator"
EXPECTED_URI_LABEL = "operator/local"

MAX_FIXED_TLS_FILE_BYTES = 1048576
MAX_COMMAND_STDOUT_BYTES = 65536
MAX_COMMAND_STDERR_BYTES = 8192
MAX_COMMAND_STDIN_BYTES = 65536
COMMAND_TIMEOUT_SECONDS = 10.0
COMMAND_TERMINATION_GRACE_SECONDS = 1.0
READ_CHUNK_SIZE = 16384

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
FORBIDDEN_PATTERNS = [
    re.compile(r"-----BEGIN"),
    re.compile(r"PRIVATE KEY"),
    re.compile(r"BEGIN CERTIFICATE"),
    re.compile(r"/etc/execution-substrate"),
    re.compile(r"\b(?:hvs|hvb|s)\.[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
]
CHILD_ENV = {
    "LC_ALL": "C",
    "LANG": "C",
    "TZ": "UTC",
    "PATH": "/usr/bin:/bin",
    "HOME": "/",
    "OPENSSL_CONF": "/dev/null",
}


@dataclass(frozen=True)
class Paths:
    cert: str = OPERATOR_CERT_PATH
    key: str = OPERATOR_KEY_PATH
    ca: str = SERVER_CLIENT_CA_PATH


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes = b""
    timed_out: bool = False
    overflow: bool = False
    runtime_failed: bool = False


@dataclass(frozen=True)
class OperationResult:
    ok: bool
    stdout: bytes
    fixed_sudo_used: bool = False
    noninteractive_auth_required: bool = False
    unavailable: bool = False


@dataclass(frozen=True)
class ChildLifecycleResult:
    resolved: bool
    returncode: int | None


@dataclass(frozen=True)
class PipeReadResult:
    status: str
    data: bytes = b""


def parse_args(argv: list[str]) -> tuple[str, str]:
    if len(argv) != 4:
        raise ValueError("usage")
    if argv[0] != "--protocol" or argv[2] != "--collector-sha256":
        raise ValueError("usage")
    protocol = argv[1]
    collector_sha256 = argv[3]
    if protocol != PROTOCOL_VERSION:
        raise ValueError("usage")
    if not SHA256_RE.fullmatch(collector_sha256):
        raise ValueError("usage")
    return protocol, collector_sha256


def child_returncode(proc: subprocess.Popen[bytes]) -> int | None:
    return getattr(proc, "returncode", None)


def child_has_exited(proc: subprocess.Popen[bytes]) -> bool:
    try:
        return proc.poll() is not None
    except Exception:
        return child_returncode(proc) is not None


def request_process_group_termination(proc: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass


def request_process_group_kill(proc: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def wait_for_child_exit(proc: subprocess.Popen[bytes], grace_seconds: float) -> bool:
    deadline = time.monotonic() + max(0.0, grace_seconds)
    while True:
        if child_has_exited(proc):
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.05, remaining))


def reap_child(proc: subprocess.Popen[bytes]) -> ChildLifecycleResult:
    try:
        return ChildLifecycleResult(resolved=True, returncode=proc.wait(timeout=0))
    except subprocess.TimeoutExpired:
        return ChildLifecycleResult(resolved=False, returncode=child_returncode(proc))
    except Exception:
        return ChildLifecycleResult(resolved=False, returncode=child_returncode(proc))


def resolve_child_lifecycle(
    proc: subprocess.Popen[bytes],
    *,
    terminate_required: bool,
    grace_seconds: float | None = None,
) -> ChildLifecycleResult:
    if grace_seconds is None:
        grace_seconds = COMMAND_TERMINATION_GRACE_SECONDS
    if terminate_required and not child_has_exited(proc):
        request_process_group_termination(proc)
        if not wait_for_child_exit(proc, grace_seconds):
            request_process_group_kill(proc)
            wait_for_child_exit(proc, grace_seconds)
    return reap_child(proc)


def close_registered(selector: selectors.BaseSelector, registered_fileobjs: list[object]) -> None:
    for fileobj in registered_fileobjs:
        try:
            selector.unregister(fileobj)
        except Exception:
            pass
    try:
        selector.close()
    except Exception:
        pass
    for fileobj in registered_fileobjs:
        try:
            fileobj.close()
        except Exception:
            pass


def remove_registered_fileobj(registered_fileobjs: list[object], fileobj: object) -> None:
    try:
        registered_fileobjs.remove(fileobj)
    except ValueError:
        pass


def read_pipe_chunk(fileobj: object, chunk_size: int) -> PipeReadResult:
    try:
        chunk = os.read(fileobj.fileno(), chunk_size)
    except BlockingIOError as exc:
        if exc.errno in {errno.EAGAIN, errno.EWOULDBLOCK}:
            return PipeReadResult(status="transient")
        return PipeReadResult(status="failed")
    except InterruptedError:
        return PipeReadResult(status="transient")
    except OSError:
        return PipeReadResult(status="failed")
    if not chunk:
        return PipeReadResult(status="eof")
    return PipeReadResult(status="data", data=chunk)


def run_command(args: tuple[str, ...], input_bytes: bytes | None = None) -> CommandResult:
    if input_bytes is not None and len(input_bytes) > MAX_COMMAND_STDIN_BYTES:
        return CommandResult(returncode=125, stdout=b"", stderr=b"", overflow=True)
    try:
        proc = subprocess.Popen(
            list(args),
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            env=CHILD_ENV,
            start_new_session=True,
        )
    except OSError:
        return CommandResult(returncode=127, stdout=b"", stderr=b"")

    try:
        selector = selectors.DefaultSelector()
    except Exception:
        resolve_child_lifecycle(proc, terminate_required=True)
        return CommandResult(returncode=125, stdout=b"", stderr=b"", runtime_failed=True)

    registered_fileobjs: list[object] = []
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    stdout_size = 0
    stderr_size = 0
    stdin_offset = 0
    stdin_open = proc.stdin is not None
    stdout_open = proc.stdout is not None
    stderr_open = proc.stderr is not None
    payload = input_bytes or b""

    try:
        if proc.stdin is not None:
            os.set_blocking(proc.stdin.fileno(), False)
            selector.register(proc.stdin, selectors.EVENT_WRITE, "stdin")
            registered_fileobjs.append(proc.stdin)
        if proc.stdout is not None:
            os.set_blocking(proc.stdout.fileno(), False)
            selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
            registered_fileobjs.append(proc.stdout)
        if proc.stderr is not None:
            os.set_blocking(proc.stderr.fileno(), False)
            selector.register(proc.stderr, selectors.EVENT_READ, "stderr")
            registered_fileobjs.append(proc.stderr)
    except Exception:
        resolve_child_lifecycle(proc, terminate_required=True)
        close_registered(selector, registered_fileobjs)
        return CommandResult(returncode=125, stdout=b"", stderr=b"", runtime_failed=True)

    deadline = time.monotonic() + COMMAND_TIMEOUT_SECONDS
    terminal_status: str | None = None
    normal_completion = False

    try:
        while True:
            if time.monotonic() >= deadline:
                terminal_status = "timeout"
                break

            if proc.poll() is not None and not stdout_open and not stderr_open:
                if stdin_open and proc.stdin is not None:
                    try:
                        selector.unregister(proc.stdin)
                    except Exception:
                        pass
                    try:
                        proc.stdin.close()
                    except Exception:
                        pass
                    remove_registered_fileobj(registered_fileobjs, proc.stdin)
                    stdin_open = False
                normal_completion = True
                break

            timeout = max(0.0, min(0.1, deadline - time.monotonic()))
            events = selector.select(timeout)
            if not events and proc.poll() is not None:
                for fileobj, stream_name in ((proc.stdout, "stdout"), (proc.stderr, "stderr")):
                    if fileobj is None:
                        continue
                    if stream_name == "stdout" and not stdout_open:
                        continue
                    if stream_name == "stderr" and not stderr_open:
                        continue
                    read_result = read_pipe_chunk(fileobj, READ_CHUNK_SIZE)
                    if read_result.status == "transient":
                        continue
                    if read_result.status == "failed":
                        stdout_chunks.clear()
                        stderr_chunks.clear()
                        terminal_status = "runtime_failed"
                        break
                    chunk = read_result.data
                    if stream_name == "stdout":
                        if read_result.status == "eof":
                            try:
                                selector.unregister(fileobj)
                            except Exception:
                                pass
                            stdout_open = False
                        else:
                            stdout_size += len(chunk)
                            if stdout_size > MAX_COMMAND_STDOUT_BYTES:
                                terminal_status = "stdout_overflow"
                                break
                            stdout_chunks.append(chunk)
                    else:
                        if read_result.status == "eof":
                            try:
                                selector.unregister(fileobj)
                            except Exception:
                                pass
                            stderr_open = False
                        else:
                            stderr_size += len(chunk)
                            if stderr_size > MAX_COMMAND_STDERR_BYTES:
                                terminal_status = "stderr_overflow"
                                break
                            stderr_chunks.append(chunk)
                if terminal_status:
                    break
                continue

            for key, _mask in events:
                stream_name = key.data
                fileobj = key.fileobj
                if stream_name == "stdin":
                    if stdin_offset >= len(payload):
                        try:
                            selector.unregister(fileobj)
                        except Exception:
                            pass
                        try:
                            fileobj.close()
                        except Exception:
                            pass
                        remove_registered_fileobj(registered_fileobjs, fileobj)
                        stdin_open = False
                        continue
                    try:
                        written = os.write(fileobj.fileno(), payload[stdin_offset : stdin_offset + READ_CHUNK_SIZE])
                        stdin_offset += written
                    except BlockingIOError:
                        continue
                    except OSError:
                        try:
                            selector.unregister(fileobj)
                        except Exception:
                            pass
                        try:
                            fileobj.close()
                        except Exception:
                            pass
                        remove_registered_fileobj(registered_fileobjs, fileobj)
                        stdin_open = False
                elif stream_name == "stdout":
                    if not stdout_open:
                        continue
                    read_result = read_pipe_chunk(fileobj, READ_CHUNK_SIZE)
                    if read_result.status == "transient":
                        continue
                    if read_result.status == "failed":
                        stdout_chunks.clear()
                        stderr_chunks.clear()
                        terminal_status = "runtime_failed"
                        break
                    if read_result.status == "eof":
                        try:
                            selector.unregister(fileobj)
                        except Exception:
                            pass
                        stdout_open = False
                        continue
                    chunk = read_result.data
                    stdout_size += len(chunk)
                    if stdout_size > MAX_COMMAND_STDOUT_BYTES:
                        terminal_status = "stdout_overflow"
                        break
                    stdout_chunks.append(chunk)
                elif stream_name == "stderr":
                    if not stderr_open:
                        continue
                    read_result = read_pipe_chunk(fileobj, READ_CHUNK_SIZE)
                    if read_result.status == "transient":
                        continue
                    if read_result.status == "failed":
                        stdout_chunks.clear()
                        stderr_chunks.clear()
                        terminal_status = "runtime_failed"
                        break
                    if read_result.status == "eof":
                        try:
                            selector.unregister(fileobj)
                        except Exception:
                            pass
                        stderr_open = False
                        continue
                    chunk = read_result.data
                    stderr_size += len(chunk)
                    if stderr_size > MAX_COMMAND_STDERR_BYTES:
                        terminal_status = "stderr_overflow"
                        break
                    stderr_chunks.append(chunk)
            if terminal_status:
                break
    except Exception:
        terminal_status = "runtime_failed"
    finally:
        lifecycle = resolve_child_lifecycle(
            proc,
            terminate_required=terminal_status is not None or not normal_completion,
        )
        close_registered(selector, registered_fileobjs)

    if not lifecycle.resolved:
        return CommandResult(returncode=125, stdout=b"", stderr=b"", runtime_failed=True)
    if terminal_status:
        if terminal_status == "timeout":
            return CommandResult(returncode=124, stdout=b"", stderr=b"", timed_out=True)
        if terminal_status in {"stdout_overflow", "stderr_overflow"}:
            return CommandResult(returncode=125, stdout=b"", stderr=b"", overflow=True)
        return CommandResult(returncode=125, stdout=b"", stderr=b"", runtime_failed=True)

    return CommandResult(returncode=lifecycle.returncode or 0, stdout=b"".join(stdout_chunks), stderr=b"".join(stderr_chunks))


def direct_file_sha256(path: str, *, paths: Paths) -> str | None:
    if path not in {paths.cert, paths.key, paths.ca}:
        return None
    try:
        source = Path(path)
        try:
            if source.stat().st_size > MAX_FIXED_TLS_FILE_BYTES:
                return None
        except OSError:
            return None
        digest = hashlib.sha256()
        total = 0
        with source.open("rb") as handle:
            while True:
                chunk = handle.read(READ_CHUNK_SIZE)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_FIXED_TLS_FILE_BYTES:
                    return None
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def direct_stat_label(path: str) -> str:
    try:
        metadata = Path(path).stat()
    except OSError:
        return "unavailable"
    mode = metadata.st_mode & 0o777
    if mode & 0o077:
        return "readable_by_group_or_other"
    return "owner_only_or_root_controlled"


def sudo_allowlist(paths: Paths) -> set[tuple[str, ...]]:
    return {
        (OPENSSL, "x509", "-in", paths.cert, "-noout", "-dates"),
        (OPENSSL, "x509", "-in", paths.cert, "-noout", "-fingerprint", "-sha256"),
        (OPENSSL, "x509", "-in", paths.cert, "-pubkey", "-noout"),
        (OPENSSL, "x509", "-in", paths.cert, "-noout", "-subject", "-issuer", "-nameopt", "RFC2253"),
        (OPENSSL, "x509", "-in", paths.cert, "-outform", "DER"),
        (OPENSSL, "verify", "-CAfile", paths.ca, paths.cert),
        (OPENSSL, "pkey", "-in", paths.key, "-pubout", "-outform", "DER"),
        (SHA256SUM, paths.cert),
        (STAT, "-c", "%a:%u:%g:%F", paths.cert),
        (STAT, "-c", "%a:%u:%g:%F", paths.key),
        (STAT, "-c", "%a:%u:%g:%F", paths.ca),
    }


def run_fixed(
    args: tuple[str, ...],
    *,
    paths: Paths,
    runner: Callable[[tuple[str, ...], bytes | None], CommandResult] = run_command,
    input_bytes: bytes | None = None,
) -> OperationResult:
    if input_bytes is not None and len(input_bytes) > MAX_COMMAND_STDIN_BYTES:
        return OperationResult(ok=False, stdout=b"", unavailable=True)
    result = runner(args, input_bytes)
    if result.returncode == 0 and not result.timed_out and not result.overflow:
        return OperationResult(ok=True, stdout=result.stdout)
    if command_unavailable(result):
        return OperationResult(ok=False, stdout=b"", unavailable=True)
    if input_bytes is not None:
        return OperationResult(ok=False, stdout=b"", unavailable=True)
    if args not in sudo_allowlist(paths):
        return OperationResult(ok=False, stdout=b"", unavailable=True)
    sudo_args = (SUDO, "-n", *args)
    sudo_result = runner(sudo_args, None)
    if sudo_result.returncode == 0 and not sudo_result.timed_out and not sudo_result.overflow:
        return OperationResult(ok=True, stdout=sudo_result.stdout, fixed_sudo_used=True)
    if command_unavailable(sudo_result):
        return OperationResult(ok=False, stdout=b"", unavailable=True)
    return OperationResult(ok=False, stdout=b"", noninteractive_auth_required=True)


def sha256sum_operation(
    path: str,
    *,
    paths: Paths,
    runner: Callable[[tuple[str, ...], bytes | None], CommandResult],
) -> OperationResult:
    direct = direct_file_sha256(path, paths=paths)
    if direct is not None:
        return OperationResult(ok=True, stdout=(direct + "\n").encode("ascii"))
    return run_fixed((SHA256SUM, path), paths=paths, runner=runner)


def parse_sha256sum(stdout: bytes) -> str | None:
    text = stdout.decode("utf-8", "replace").strip()
    token = text.split()[0] if text.split() else ""
    if SHA256_RE.fullmatch(token):
        return token
    return None


def parse_openssl_date(value: str) -> str | None:
    if "=" in value:
        value = value.split("=", 1)[1].strip()
    try:
        parsed = parsedate_to_datetime(value.strip())
    except Exception:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_dates(stdout: bytes) -> tuple[str | None, str | None]:
    not_before = None
    not_after = None
    text = stdout.decode("utf-8", "replace")
    for line in text.splitlines():
        if line.startswith("notBefore="):
            not_before = parse_openssl_date(line)
        elif line.startswith("notAfter="):
            not_after = parse_openssl_date(line)
    return not_before, not_after


def parse_fingerprint(stdout: bytes) -> str | None:
    text = stdout.decode("utf-8", "replace").strip()
    if "=" not in text:
        return None
    value = text.split("=", 1)[1].replace(":", "").lower()
    if SHA256_RE.fullmatch(value):
        return value
    return None


def contains_control(text: str) -> bool:
    return any((ord(ch) < 32 and ch not in "\n\t") or ord(ch) == 127 for ch in text)


def split_rfc2253_components(value: str) -> list[str] | None:
    if contains_control(value):
        return None
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for char in value:
        if escaped:
            current.append("\\" + char)
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == ",":
            parts.append("".join(current))
            current = []
            continue
        current.append(char)
    if escaped:
        return None
    parts.append("".join(current))
    if any("=" not in part for part in parts):
        return None
    return [part.strip() for part in parts]


def rfc2253_component_values(name: str, key: str) -> list[str] | None:
    components = split_rfc2253_components(name)
    if components is None:
        return None
    values: list[str] = []
    for component in components:
        comp_key, comp_value = component.split("=", 1)
        if comp_key.strip() == key:
            values.append(comp_value.strip())
    return values


# The same client certificate decoder is in
# scripts/internal/remote_alpha_operator_healthcheck_tls_renew.sh. Both tools
# must stay self-contained (this collector is streamed over SSH and its hash is
# pinned; the staged renew route copies only its two shell scripts), so each
# carries the decoder, and
# TestRemoteAlphaOperatorHealthcheckTLSCertificateDecoderCopiesMatch fails
# unless the lines between the BEGIN and END markers are identical in both files.
# BEGIN client-certificate-der-decoder
SUBJECT_ALT_NAME_OID = bytes((0x55, 0x1D, 0x11))
BASIC_CONSTRAINTS_OID = bytes((0x55, 0x1D, 0x13))
KEY_USAGE_OID = bytes((0x55, 0x1D, 0x0F))
EXTENDED_KEY_USAGE_OID = bytes((0x55, 0x1D, 0x25))
CLIENT_AUTH_USAGE_OID = bytes((0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02))
ANY_EXTENDED_KEY_USAGE_OID = bytes((0x55, 0x1D, 0x25, 0x00))
MAX_URI_SAN_LENGTH = 256


def der_element(data: bytes, offset: int, end: int) -> tuple[int, int, int] | None:
    """Return (tag, content start, content end) of the DER element at offset.

    Only what certificates use is accepted: one-byte tags and definite,
    minimally encoded lengths that stay inside data[:end].
    """
    if offset + 2 > end:
        return None
    tag = data[offset]
    if tag & 0x1F == 0x1F:
        return None
    first = data[offset + 1]
    position = offset + 2
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0 or count > 4 or position + count > end or data[position] == 0:
            return None
        length = int.from_bytes(data[position : position + count], "big")
        if length < 0x80:
            return None
        position += count
    if length > end - position:
        return None
    return tag, position, position + length


def der_children(data: bytes, start: int, end: int) -> list[tuple[int, int, int]] | None:
    """Return the DER elements that exactly fill data[start:end]."""
    children: list[tuple[int, int, int]] = []
    offset = start
    while offset < end:
        element = der_element(data, offset, end)
        if element is None:
            return None
        children.append(element)
        offset = element[2]
    return children


def der_value(data: bytes, value: tuple[int, int, int]) -> tuple[int, int, int] | None:
    """Return the one element that exactly fills an extension's octet string."""
    element = der_element(data, value[1], value[2])
    if element is None or element[2] != value[2]:
        return None
    return element


def der_object_identifier_valid(content: bytes) -> bool:
    """Report whether content is an object identifier that Go's parser reads.

    That is at least one subidentifier, each in minimal base 128, at most five
    bytes long and below 2**31.
    """
    if not content:
        return False
    position = 0
    while position < len(content):
        if content[position] == 0x80:
            return False
        value = 0
        count = 0
        while True:
            if position >= len(content) or count == 5 or value >= 1 << 24:
                return False
            byte = content[position]
            position += 1
            count += 1
            value = (value << 7) | (byte & 0x7F)
            if byte < 0x80:
                break
    return True


def der_unsigned_integer_valid(content: bytes) -> bool:
    """Report whether content is a minimal, non-negative INTEGER below 2**63."""
    if not content or content[0] >= 0x80:
        return False
    if len(content) > 1 and content[0] == 0 and content[1] < 0x80:
        return False
    return int.from_bytes(content, "big") < 1 << 63


def san_uris(der: bytes, value: tuple[int, int, int]) -> list[str] | None:
    """Return the URI entries of a subjectAltName value, or None if malformed."""
    names = der_value(der, value)
    if names is None or names[0] != 0x30:
        return None
    general_names = der_children(der, names[1], names[2])
    if general_names is None:
        return None
    uris: list[str] = []
    for tag, start, end in general_names:
        raw = der[start:end]
        # Go's certificate parser refuses an rfc822Name, dNSName or URI that is
        # not IA5 text, and an iPAddress that is not 4 or 16 bytes long. It
        # ignores every other entry, a constructed [6] among them.
        if tag in (0x81, 0x82, 0x86) and any(byte >= 0x80 for byte in raw):
            return None
        if tag == 0x87 and len(raw) not in (4, 16):
            return None
        if tag != 0x86:
            continue
        if not raw or len(raw) > MAX_URI_SAN_LENGTH or any(byte < 33 or byte > 126 for byte in raw):
            return None
        uris.append(raw.decode("ascii"))
    return uris


def basic_constraints_ca(der: bytes, value: tuple[int, int, int]) -> bool | None:
    """Return the cA flag of a basicConstraints value, or None if malformed."""
    sequence = der_value(der, value)
    if sequence is None or sequence[0] != 0x30:
        return None
    fields = der_children(der, sequence[1], sequence[2])
    if fields is None:
        return None
    is_ca = False
    if fields and fields[0][0] == 0x01:
        tag, start, end = fields.pop(0)
        if end - start != 1 or der[start] not in (0x00, 0xFF):
            return None
        is_ca = der[start] == 0xFF
    if fields and fields[0][0] == 0x02:
        tag, start, end = fields.pop(0)
        if not der_unsigned_integer_valid(der[start:end]):
            return None
    if fields:
        return None
    return is_ca


def key_usage_signs_certificates(der: bytes, value: tuple[int, int, int]) -> bool | None:
    """Report whether a keyUsage value has keyCertSign or cRLSign, or None if malformed."""
    bits = der_value(der, value)
    if bits is None or bits[0] != 0x03:
        return None
    content = der[bits[1] : bits[2]]
    if not content or content[0] > 7 or (len(content) == 1 and content[0] != 0):
        return None
    if len(content) > 1 and content[-1] & ((1 << content[0]) - 1):
        return None
    # Bit 5 is keyCertSign and bit 6 is cRLSign, both in the first byte.
    return len(content) > 1 and content[1] & 0x06 != 0


def extended_key_usages(der: bytes, value: tuple[int, int, int]) -> list[bytes] | None:
    """Return the object identifiers of an extKeyUsage value, or None if malformed."""
    sequence = der_value(der, value)
    if sequence is None or sequence[0] != 0x30:
        return None
    usages = der_children(der, sequence[1], sequence[2])
    if usages is None:
        return None
    oids: list[bytes] = []
    for tag, start, end in usages:
        if tag != 0x06 or not der_object_identifier_valid(der[start:end]):
            return None
        oids.append(der[start:end])
    return oids


def decode_client_certificate(der: bytes) -> dict[str, object] | None:
    """Return what ES's caller rule reads from a DER client certificate.

    The certificate is decoded structurally. OpenSSL's printed SAN text cannot
    tell a URI that contains ", DNS:" apart from two SAN entries, or a DNS name
    that contains ", URI:" apart from a URI SAN. The result has:

    - "uri_sans": every URI SAN in certificate order, duplicates included;
    - "end_entity": False when basicConstraints marks a CA or keyUsage has
      keyCertSign or cRLSign, which ES refuses (contracts.md section 3A);
    - "client_auth": False when an extKeyUsage is present and allows neither
      clientAuth nor anyExtendedKeyUsage, which Go's TLS server refuses.

    None means the certificate, its extensions or a name is malformed, or the
    certificate is not version 3 although it has extensions, which Go would
    then ignore.
    """
    certificate = der_element(der, 0, len(der))
    if certificate is None or certificate[0] != 0x30 or certificate[2] != len(der):
        return None
    parts = der_children(der, certificate[1], certificate[2])
    if parts is None or [part[0] for part in parts] != [0x30, 0x30, 0x03]:
        return None
    tbs = der_children(der, parts[0][1], parts[0][2])
    if tbs is None:
        return None
    facts: dict[str, object] = {"uri_sans": [], "end_entity": True, "client_auth": True}
    if not any(item[0] == 0xA3 for item in tbs):
        return facts
    # Go reads extensions only from a version 3 TBSCertificate, as its last
    # field after the optional issuer and subject unique identifiers.
    layout = [item[0] for item in tbs]
    if layout[:7] != [0xA0, 0x02, 0x30, 0x30, 0x30, 0x30, 0x30] or layout[-1] != 0xA3:
        return None
    if layout[7:-1] not in ([], [0x81], [0x82], [0x81, 0x82]):
        return None
    version = der_children(der, tbs[0][1], tbs[0][2])
    if version is None or len(version) != 1 or version[0][0] != 0x02 or der[version[0][1] : version[0][2]] != b"\x02":
        return None
    wrapper = der_children(der, tbs[-1][1], tbs[-1][2])
    if wrapper is None or len(wrapper) != 1 or wrapper[0][0] != 0x30:
        return None
    extensions = der_children(der, wrapper[0][1], wrapper[0][2])
    if extensions is None:
        return None
    values: dict[bytes, tuple[int, int, int]] = {}
    for tag, start, end in extensions:
        if tag != 0x30:
            return None
        fields = der_children(der, start, end)
        if fields is None or len(fields) not in {2, 3} or fields[0][0] != 0x06 or fields[-1][0] != 0x04:
            return None
        if len(fields) == 3 and (fields[1][0] != 0x01 or fields[1][2] - fields[1][1] != 1 or der[fields[1][1]] not in (0x00, 0xFF)):
            return None
        oid = der[fields[0][1] : fields[0][2]]
        if not der_object_identifier_valid(oid) or oid in values:
            return None
        values[oid] = fields[-1]
    if SUBJECT_ALT_NAME_OID in values:
        uris = san_uris(der, values[SUBJECT_ALT_NAME_OID])
        if uris is None:
            return None
        facts["uri_sans"] = uris
    if BASIC_CONSTRAINTS_OID in values:
        is_ca = basic_constraints_ca(der, values[BASIC_CONSTRAINTS_OID])
        if is_ca is None:
            return None
        if is_ca:
            facts["end_entity"] = False
    if KEY_USAGE_OID in values:
        signs = key_usage_signs_certificates(der, values[KEY_USAGE_OID])
        if signs is None:
            return None
        if signs:
            facts["end_entity"] = False
    if EXTENDED_KEY_USAGE_OID in values:
        usages = extended_key_usages(der, values[EXTENDED_KEY_USAGE_OID])
        if usages is None:
            return None
        if usages and CLIENT_AUTH_USAGE_OID not in usages and ANY_EXTENDED_KEY_USAGE_OID not in usages:
            facts["client_auth"] = False
    return facts
# END client-certificate-der-decoder


def command_unavailable(result: CommandResult) -> bool:
    return result.timed_out or result.overflow or result.runtime_failed or result.returncode in {124, 125, 126, 127}


def public_key_digest_from_cert(
    *,
    paths: Paths,
    runner: Callable[[tuple[str, ...], bytes | None], CommandResult],
) -> tuple[str | None, bool, bool]:
    pub = run_fixed((OPENSSL, "x509", "-in", paths.cert, "-pubkey", "-noout"), paths=paths, runner=runner)
    if not pub.ok:
        return None, pub.fixed_sudo_used, pub.noninteractive_auth_required
    der = run_fixed((OPENSSL, "pkey", "-pubin", "-outform", "DER"), paths=paths, runner=runner, input_bytes=pub.stdout)
    if not der.ok:
        return None, pub.fixed_sudo_used or der.fixed_sudo_used, pub.noninteractive_auth_required or der.noninteractive_auth_required
    return hashlib.sha256(der.stdout).hexdigest(), pub.fixed_sudo_used or der.fixed_sudo_used, False


def public_key_digest_from_key(
    *,
    paths: Paths,
    runner: Callable[[tuple[str, ...], bytes | None], CommandResult],
) -> tuple[str | None, bool, bool]:
    der = run_fixed((OPENSSL, "pkey", "-in", paths.key, "-pubout", "-outform", "DER"), paths=paths, runner=runner)
    if not der.ok:
        return None, der.fixed_sudo_used, der.noninteractive_auth_required
    return hashlib.sha256(der.stdout).hexdigest(), der.fixed_sudo_used, False


def classify_subject_and_issuer(
    *,
    paths: Paths,
    runner: Callable[[tuple[str, ...], bytes | None], CommandResult],
) -> tuple[str | None, str | None, str | None, bool, bool]:
    result = run_fixed(
        (OPENSSL, "x509", "-in", paths.cert, "-noout", "-subject", "-issuer", "-nameopt", "RFC2253"),
        paths=paths,
        runner=runner,
    )
    if not result.ok:
        return None, None, None, result.fixed_sudo_used, result.noninteractive_auth_required
    try:
        text = result.stdout.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return "subject_malformed", "issuer_malformed", None, result.fixed_sudo_used, False
    subject_line = ""
    issuer_line = ""
    for line in text.splitlines():
        if line.startswith("subject="):
            subject_line = line[len("subject=") :]
        if line.startswith("issuer="):
            issuer_line = line[len("issuer=") :]
    subject_values = rfc2253_component_values(subject_line, "CN") if subject_line else None
    if subject_line and subject_values is None:
        subject_label = "subject_malformed"
    elif subject_values and "client.operator" in subject_values:
        subject_label = "client_operator"
    elif subject_line:
        subject_label = "other_subject"
    else:
        subject_label = "subject_unavailable"

    issuer_values = split_rfc2253_components(issuer_line) if issuer_line else None
    if issuer_line and issuer_values is None:
        issuer_label = "issuer_malformed"
    elif issuer_line:
        issuer_label = "issuer_present"
    else:
        issuer_label = "issuer_unavailable"
    issuer_digest = hashlib.sha256(issuer_line.encode("utf-8")).hexdigest() if issuer_line else None
    return subject_label, issuer_label, issuer_digest, result.fixed_sudo_used, False


def classify_identity(
    *,
    paths: Paths,
    runner: Callable[[tuple[str, ...], bytes | None], CommandResult],
) -> tuple[dict[str, object], bool, bool]:
    result = run_fixed((OPENSSL, "x509", "-in", paths.cert, "-outform", "DER"), paths=paths, runner=runner)
    if not result.ok:
        return (
            {
                "status": "not_available",
                "expected_uri_label": EXPECTED_URI_LABEL,
                "matches_expected": None,
                "legacy_operator_uri_present": None,
                "classification": "identity_unavailable",
                "failure_class": "remote_status_unavailable",
            },
            result.fixed_sudo_used,
            result.noninteractive_auth_required,
        )
    facts = decode_client_certificate(result.stdout)
    if facts is None:
        return (
            {
                "status": "fail",
                "expected_uri_label": EXPECTED_URI_LABEL,
                "matches_expected": False,
                "legacy_operator_uri_present": False,
                "classification": "identity_malformed",
                "failure_class": "identity_mismatch",
            },
            result.fixed_sudo_used,
            False,
        )
    # ES refuses a certificate with more than one URI SAN (caller
    # authentication contract, contracts.md section 3A), so the expected
    # identity must be the certificate's only URI SAN. ES also refuses a leaf
    # that is not an end-entity certificate, and Go's TLS server refuses one
    # whose extended key usage does not allow client authentication.
    uris = facts["uri_sans"]
    expected = uris == [EXPECTED_OPERATOR_URI]
    legacy = isinstance(uris, list) and LEGACY_OPERATOR_URI in uris
    status = "fail"
    failure: str | None = "identity_mismatch"
    if not expected:
        classification = "legacy_operator_identity" if legacy else "identity_mismatch"
    elif facts["end_entity"] is not True:
        classification = "identity_not_end_entity"
    elif facts["client_auth"] is not True:
        classification = "identity_not_for_client_auth"
    else:
        status = "pass"
        classification = "expected_operator_local_identity"
        failure = None
    return (
        {
            "status": status,
            "expected_uri_label": EXPECTED_URI_LABEL,
            "matches_expected": expected,
            "legacy_operator_uri_present": legacy,
            "classification": classification,
            "failure_class": failure,
        },
        result.fixed_sudo_used,
        False,
    )


def classify_trust(
    *,
    issuer_digest: str | None,
    paths: Paths,
    runner: Callable[[tuple[str, ...], bytes | None], CommandResult],
) -> tuple[dict[str, object], bool, bool]:
    args = (OPENSSL, "verify", "-CAfile", paths.ca, paths.cert)
    direct = runner(args, None)
    if direct.returncode == 0 and not direct.timed_out and not direct.overflow:
        return (
            {
                "status": "pass",
                "classification": "trusted_by_fixed_ca",
                "issuer_digest_sha256": issuer_digest,
                "failure_class": None,
            },
            False,
            False,
        )
    if direct.returncode == 2 and not direct.timed_out and not direct.overflow:
        return (
            {
                "status": "fail",
                "classification": "trust_verification_failed",
                "issuer_digest_sha256": issuer_digest,
                "failure_class": "trust_chain_failed",
            },
            False,
            False,
        )
    if command_unavailable(direct):
        return (
            {
                "status": "not_available",
                "classification": "trust_verification_unavailable",
                "issuer_digest_sha256": issuer_digest,
                "failure_class": "trust_chain_unavailable",
            },
            False,
            False,
        )

    sudo_result = runner((SUDO, "-n", *args), None)
    if sudo_result.returncode == 0 and not sudo_result.timed_out and not sudo_result.overflow:
        return (
            {
                "status": "pass",
                "classification": "trusted_by_fixed_ca",
                "issuer_digest_sha256": issuer_digest,
                "failure_class": None,
            },
            True,
            False,
        )
    if sudo_result.returncode == 2 and not sudo_result.timed_out and not sudo_result.overflow:
        return (
            {
                "status": "fail",
                "classification": "trust_verification_failed",
                "issuer_digest_sha256": issuer_digest,
                "failure_class": "trust_chain_failed",
            },
            True,
            False,
        )
    if command_unavailable(sudo_result):
        return (
            {
                "status": "not_available",
                "classification": "trust_verification_unavailable",
                "issuer_digest_sha256": issuer_digest,
                "failure_class": "trust_chain_unavailable",
            },
            False,
            False,
        )
    if args in sudo_allowlist(paths):
        failure = "noninteractive_auth_required"
        status = "not_available"
        classification = "trust_noninteractive_auth_required"
    else:
        failure = "trust_chain_failed"
        status = "fail"
        classification = "trust_verification_failed"
    return (
        {
            "status": status,
            "classification": classification,
            "issuer_digest_sha256": issuer_digest,
            "failure_class": failure,
        },
        False,
        failure == "noninteractive_auth_required",
    )


def collect_status(
    *,
    paths: Paths = Paths(),
    runner: Callable[[tuple[str, ...], bytes | None], CommandResult] = run_command,
    now: Callable[[], dt.datetime] | None = None,
) -> dict[str, object]:
    current_time = (now() if now is not None else dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    fixed_sudo_used = False
    noninteractive_auth_required = False

    cert_file = sha256sum_operation(paths.cert, paths=paths, runner=runner)
    fixed_sudo_used = fixed_sudo_used or cert_file.fixed_sudo_used
    noninteractive_auth_required = noninteractive_auth_required or cert_file.noninteractive_auth_required
    cert_file_sha = parse_sha256sum(cert_file.stdout) if cert_file.ok else None

    dates = run_fixed((OPENSSL, "x509", "-in", paths.cert, "-noout", "-dates"), paths=paths, runner=runner)
    fixed_sudo_used = fixed_sudo_used or dates.fixed_sudo_used
    noninteractive_auth_required = noninteractive_auth_required or dates.noninteractive_auth_required
    not_before, not_after = parse_dates(dates.stdout) if dates.ok else (None, None)

    public_fp = run_fixed((OPENSSL, "x509", "-in", paths.cert, "-noout", "-fingerprint", "-sha256"), paths=paths, runner=runner)
    fixed_sudo_used = fixed_sudo_used or public_fp.fixed_sudo_used
    noninteractive_auth_required = noninteractive_auth_required or public_fp.noninteractive_auth_required
    public_fingerprint = parse_fingerprint(public_fp.stdout) if public_fp.ok else None

    cert_pubkey, cert_pubkey_sudo, cert_pubkey_auth = public_key_digest_from_cert(paths=paths, runner=runner)
    key_pubkey, key_pubkey_sudo, key_pubkey_auth = public_key_digest_from_key(paths=paths, runner=runner)
    fixed_sudo_used = fixed_sudo_used or cert_pubkey_sudo or key_pubkey_sudo
    noninteractive_auth_required = noninteractive_auth_required or cert_pubkey_auth or key_pubkey_auth

    subject_label, issuer_label, issuer_digest, subject_sudo, subject_auth = classify_subject_and_issuer(paths=paths, runner=runner)
    fixed_sudo_used = fixed_sudo_used or subject_sudo
    noninteractive_auth_required = noninteractive_auth_required or subject_auth

    identity, identity_sudo, identity_auth = classify_identity(paths=paths, runner=runner)
    fixed_sudo_used = fixed_sudo_used or identity_sudo
    noninteractive_auth_required = noninteractive_auth_required or identity_auth

    trust_chain, trust_sudo, trust_auth = classify_trust(issuer_digest=issuer_digest, paths=paths, runner=runner)
    fixed_sudo_used = fixed_sudo_used or trust_sudo
    noninteractive_auth_required = noninteractive_auth_required or trust_auth

    expired = None
    not_yet_valid = None
    if not_before:
        parsed_before = dt.datetime.fromisoformat(not_before.replace("Z", "+00:00"))
        not_yet_valid = current_time < parsed_before
    if not_after:
        parsed_after = dt.datetime.fromisoformat(not_after.replace("Z", "+00:00"))
        expired = current_time > parsed_after

    certificate_failure = None
    certificate_status = "pass"
    if noninteractive_auth_required:
        certificate_status = "not_available"
        certificate_failure = "noninteractive_auth_required"
    elif not_before is None or not_after is None or public_fingerprint is None or cert_file_sha is None or cert_pubkey is None:
        certificate_status = "not_available"
        certificate_failure = "remote_status_unavailable"
    elif expired:
        certificate_status = "fail"
        certificate_failure = "cert_metadata_expired"
    elif not_yet_valid:
        certificate_status = "fail"
        certificate_failure = "cert_metadata_not_yet_valid"

    key_pair_failure = None
    public_key_match = None
    key_pair_status = "not_available"
    if cert_pubkey is not None and key_pubkey is not None:
        public_key_match = cert_pubkey == key_pubkey
        key_pair_status = "pass" if public_key_match else "fail"
        key_pair_failure = None if public_key_match else "key_pair_mismatch"
    elif noninteractive_auth_required:
        key_pair_failure = "noninteractive_auth_required"
    else:
        key_pair_failure = "remote_status_unavailable"

    failure_class = first_failure(
        certificate_failure,
        key_pair_failure,
        identity.get("failure_class"),
        trust_chain.get("failure_class"),
    )
    if noninteractive_auth_required:
        failure_class = "noninteractive_auth_required"

    status_available = failure_class not in {"noninteractive_auth_required", "remote_status_unavailable"} and certificate_status != "not_available"
    ok = failure_class is None
    result_status = "pass" if ok else ("not_available" if not status_available else "fail")
    helper_exit_code = 0 if ok else 1

    return {
        "protocol_version": PROTOCOL_VERSION,
        "collector_sha256": "",
        "helper_exit_code": helper_exit_code,
        "status_available": status_available,
        "result": {
            "status": result_status,
            "ok": ok,
            "summary_label": "remote_status_passed" if ok else "remote_status_blocked",
            "failure_class": failure_class,
        },
        "auth_posture": {
            "runs_as_root": os.geteuid() == 0 if hasattr(os, "geteuid") else False,
            "fixed_sudo_used": fixed_sudo_used,
            "noninteractive_auth_required": noninteractive_auth_required,
            "direct_read_succeeded": not fixed_sudo_used and cert_file_sha is not None,
            "sudo_prompt_allowed": False,
        },
        "certificate": {
            "status": certificate_status,
            "not_before": not_before,
            "not_after": not_after,
            "expired": expired,
            "not_yet_valid": not_yet_valid,
            "public_fingerprint_sha256": public_fingerprint,
            "file_sha256": cert_file_sha,
            "public_key_sha256": cert_pubkey,
            "subject_label": subject_label,
            "issuer_label": issuer_label,
            "issuer_digest_sha256": issuer_digest,
            "failure_class": certificate_failure,
        },
        "key_pair": {
            "status": key_pair_status,
            "public_key_match": public_key_match,
            "cert_public_key_sha256": cert_pubkey,
            "key_public_key_sha256": key_pubkey,
            "failure_class": key_pair_failure,
        },
        "identity": identity,
        "trust_chain": trust_chain,
        "file_posture": {
            "certificate": direct_stat_label(paths.cert),
            "key": direct_stat_label(paths.key),
            "trust_bundle": direct_stat_label(paths.ca),
            "safe_mode_labels": [
                "fixed_operator_cert_path",
                "fixed_operator_key_path",
                "fixed_server_client_ca_path",
            ],
        },
        "redaction": {
            "private_key_pem_bodies_included": False,
            "certificate_pem_bodies_included": False,
            "raw_stdout_retained": False,
            "raw_stderr_retained": False,
            "raw_logs_retained": False,
            "env_values_included": False,
            "remote_paths_included": False,
            "endpoint_secrets_included": False,
            "raw_openssl_output_included": False,
            "raw_exceptions_included": False,
            "command_strings_included": False,
        },
    }


def first_failure(*values: object) -> str | None:
    for value in values:
        if isinstance(value, str):
            return value
    return None


def scan_payload(payload: dict[str, object]) -> None:
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    for pattern in FORBIDDEN_PATTERNS:
        if pattern.search(text):
            raise ValueError("forbidden")


def safe_failure_payload(collector_sha256: str, failure_class: str) -> dict[str, object]:
    payload = {
        "protocol_version": PROTOCOL_VERSION,
        "collector_sha256": collector_sha256,
        "helper_exit_code": 1,
        "status_available": False,
        "result": {
            "status": "not_available",
            "ok": False,
            "summary_label": "remote_status_blocked",
            "failure_class": failure_class,
        },
        "auth_posture": {
            "runs_as_root": os.geteuid() == 0 if hasattr(os, "geteuid") else False,
            "fixed_sudo_used": False,
            "noninteractive_auth_required": failure_class == "noninteractive_auth_required",
            "direct_read_succeeded": False,
            "sudo_prompt_allowed": False,
        },
        "certificate": {
            "status": "not_available",
            "not_before": None,
            "not_after": None,
            "expired": None,
            "not_yet_valid": None,
            "public_fingerprint_sha256": None,
            "file_sha256": None,
            "public_key_sha256": None,
            "subject_label": None,
            "issuer_label": None,
            "issuer_digest_sha256": None,
            "failure_class": failure_class,
        },
        "key_pair": {
            "status": "not_available",
            "public_key_match": None,
            "cert_public_key_sha256": None,
            "key_public_key_sha256": None,
            "failure_class": failure_class,
        },
        "identity": {
            "status": "not_available",
            "expected_uri_label": EXPECTED_URI_LABEL,
            "matches_expected": None,
            "legacy_operator_uri_present": None,
            "classification": "identity_unavailable",
            "failure_class": failure_class,
        },
        "trust_chain": {
            "status": "not_available",
            "classification": "trust_unavailable",
            "issuer_digest_sha256": None,
            "failure_class": failure_class,
        },
        "file_posture": {
            "certificate": "unavailable",
            "key": "unavailable",
            "trust_bundle": "unavailable",
            "safe_mode_labels": [],
        },
        "redaction": {
            "private_key_pem_bodies_included": False,
            "certificate_pem_bodies_included": False,
            "raw_stdout_retained": False,
            "raw_stderr_retained": False,
            "raw_logs_retained": False,
            "env_values_included": False,
            "remote_paths_included": False,
            "endpoint_secrets_included": False,
            "raw_openssl_output_included": False,
            "raw_exceptions_included": False,
            "command_strings_included": False,
        },
    }
    return payload


def emit(payload: dict[str, object]) -> int:
    scan_payload(payload)
    sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
    return int(payload["helper_exit_code"])


def main(argv: list[str]) -> int:
    try:
        _protocol, collector_sha256 = parse_args(argv)
    except Exception:
        return emit(safe_failure_payload("", "remote_status_unavailable"))

    try:
        payload = collect_status()
        payload["collector_sha256"] = collector_sha256
        return emit(payload)
    except Exception:
        return emit(safe_failure_payload(collector_sha256, "remote_status_unavailable"))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
