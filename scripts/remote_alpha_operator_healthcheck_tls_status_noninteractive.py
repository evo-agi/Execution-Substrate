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
from pathlib import Path
from typing import Any, Callable

FINAL_SCHEMA_VERSION = "execution-substrate.remote-alpha.operator-healthcheck-tls-status-noninteractive.v1"
REMOTE_PROTOCOL_VERSION = "execution-substrate.remote-alpha.operator-healthcheck-tls-status-noninteractive.remote.v1"

ROUTE_ID = "operator-healthcheck-tls-status-noninteractive"
ROUTE_VERSION = "v1"
OWNER_REPO = "execution-substrate"

MAX_COLLECTOR_SOURCE_BYTES = 131072
MAX_STDOUT_BYTES = 65536
MAX_STDERR_BYTES = 8192
MAX_FINAL_JSON_BYTES = 65536
SSH_TIMEOUT_SECONDS = 20.0
TERMINATION_GRACE_SECONDS = 2.0

SAFE_USAGE_ERROR = "invalid operator-healthcheck TLS noninteractive status invocation"
SAFE_PREFLIGHT_ERROR = "operator-healthcheck TLS noninteractive status local prerequisite failed"
SAFE_STARTUP_ERROR = "p0v_isolated_runtime_required"
SAFE_FINAL_EMISSION_ERROR = "p0v_final_emission_failed"
SAFE_RUNTIME_ERROR = "p0v_runtime_failed"

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SECRET_LIKE_RE = re.compile(
    r"root-token|unseal-key|client-token|vault-token|api-key|jwt-svid|"
    r"private-key|password|secret|BEGIN[ -](?:RSA[ -])?PRIVATE[ -]KEY|BEGIN[ -]CERTIFICATE|"
    r"(?:^|[^A-Za-z0-9_-])(?:hvs|hvb|s)\.[A-Za-z0-9_-]{20,}(?:$|[^A-Za-z0-9_-])|"
    r"(?:^|[^A-Za-z0-9_-])sk-[A-Za-z0-9_-]{20,}(?:$|[^A-Za-z0-9_-])|"
    r"(?:^|[^A-Za-z0-9_-])(?:token|password|secret)\s*=",
    re.IGNORECASE,
)
TARGET_FORBIDDEN_RE = re.compile(r"^-|[\s;`|&<>]|\$\(")
SUPPORTED_SSH = "/usr/bin/ssh"
NULL_SSH_CONFIG = "/dev/null"
REMOTE_PYTHON = "/usr/bin/python3"

RESULT_SUMMARY_LABELS = {"remote_status_passed", "remote_status_blocked"}
STATUS_VALUES = {"pass", "fail", "not_available"}
SUBJECT_LABELS = {"client_operator", "other_subject", "subject_malformed", "subject_unavailable"}
ISSUER_LABELS = {"issuer_present", "issuer_unavailable", "issuer_malformed"}
EXPECTED_URI_LABELS = {"operator/local"}
IDENTITY_CLASSIFICATIONS = {
    "expected_operator_local_identity",
    "legacy_operator_identity",
    "identity_mismatch",
    "identity_malformed",
    "identity_unavailable",
}
TRUST_CLASSIFICATIONS = {
    "trusted_by_fixed_ca",
    "trust_verification_failed",
    "trust_verification_unavailable",
    "trust_noninteractive_auth_required",
    "trust_unavailable",
}
FILE_POSTURE_LABELS = {"owner_only_or_root_controlled", "readable_by_group_or_other", "unavailable"}
SAFE_MODE_LABELS = {
    "fixed_operator_cert_path",
    "fixed_operator_key_path",
    "fixed_server_client_ca_path",
}
SSH_BATCH_LABELS = {"used", "not_attempted"}
LINEAGE_AUTHORITY_LABELS = {"none"}
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

FAILURE_CLASSES = {
    "ssh_batch_mode_failed",
    "remote_status_unavailable",
    "unexpected_output_shape",
    "forbidden_output_material",
    "noninteractive_auth_required",
    "cert_metadata_expired",
    "cert_metadata_not_yet_valid",
    "trust_chain_unavailable",
    "trust_chain_failed",
    "identity_mismatch",
    "key_pair_mismatch",
    "remote_status_failed",
    "local_runtime_failed",
}

SUMMARY_BY_FAILURE = {
    None: "operator_healthcheck_tls_status_passed",
    "ssh_batch_mode_failed": "no_prompt_ssh_transport_failed",
    "remote_status_unavailable": "remote_status_unavailable",
    "unexpected_output_shape": "remote_protocol_shape_invalid",
    "forbidden_output_material": "forbidden_output_material_detected",
    "noninteractive_auth_required": "noninteractive_auth_required",
    "cert_metadata_expired": "certificate_expired",
    "cert_metadata_not_yet_valid": "certificate_not_yet_valid",
    "trust_chain_unavailable": "trust_chain_unavailable",
    "trust_chain_failed": "trust_chain_failed",
    "identity_mismatch": "identity_mismatch",
    "key_pair_mismatch": "key_pair_mismatch",
    "remote_status_failed": "remote_status_failed",
    "local_runtime_failed": "local_runtime_failed",
}

REMOTE_TOP_LEVEL_KEYS = {
    "protocol_version",
    "collector_sha256",
    "helper_exit_code",
    "status_available",
    "result",
    "auth_posture",
    "certificate",
    "key_pair",
    "identity",
    "trust_chain",
    "file_posture",
    "redaction",
}

REMOTE_NESTED_KEYS = {
    "result": {"status", "ok", "summary_label", "failure_class"},
    "auth_posture": {
        "runs_as_root",
        "fixed_sudo_used",
        "noninteractive_auth_required",
        "direct_read_succeeded",
        "sudo_prompt_allowed",
    },
    "certificate": {
        "status",
        "not_before",
        "not_after",
        "expired",
        "not_yet_valid",
        "public_fingerprint_sha256",
        "file_sha256",
        "public_key_sha256",
        "subject_label",
        "issuer_label",
        "issuer_digest_sha256",
        "failure_class",
    },
    "key_pair": {
        "status",
        "public_key_match",
        "cert_public_key_sha256",
        "key_public_key_sha256",
        "failure_class",
    },
    "identity": {
        "status",
        "expected_uri_label",
        "matches_expected",
        "legacy_operator_uri_present",
        "classification",
        "failure_class",
    },
    "trust_chain": {"status", "classification", "issuer_digest_sha256", "failure_class"},
    "file_posture": {"certificate", "key", "trust_bundle", "safe_mode_labels"},
    "redaction": {
        "private_key_pem_bodies_included",
        "certificate_pem_bodies_included",
        "raw_stdout_retained",
        "raw_stderr_retained",
        "raw_logs_retained",
        "env_values_included",
        "remote_paths_included",
        "endpoint_secrets_included",
        "raw_openssl_output_included",
        "raw_exceptions_included",
        "command_strings_included",
    },
}

FORBIDDEN_FINAL_PATTERNS = [
    re.compile(r"-----BEGIN"),
    re.compile(r"PRIVATE KEY"),
    re.compile(r"BEGIN CERTIFICATE"),
    re.compile(r"/etc/execution-substrate"),
    re.compile(r"/Users/"),
    re.compile(r"/home/[^/\s]+/"),
    re.compile(r"/var/folders/"),
    re.compile(r"/private/"),
    re.compile(r"\b(?:hvs|hvb|s)\.[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
]


class UsageError(Exception):
    pass


class LocalPreflightError(Exception):
    pass


class StartupIsolationError(Exception):
    pass


class ProtocolError(Exception):
    pass


class ForbiddenMaterialError(Exception):
    pass


class FinalSchemaError(Exception):
    pass


@dataclass(frozen=True)
class ParsedArgs:
    ssh_target: str
    output_format: str


@dataclass(frozen=True)
class ProcessResult:
    status: str
    returncode: int | None
    stdout: bytes
    stderr: bytes
    child_started: bool = True
    cleanup_failed: bool = False


@dataclass(frozen=True)
class PipeReadResult:
    status: str
    data: bytes = b""


@dataclass(frozen=True)
class RouteOutcome:
    generated_at: str
    target_hash: str
    route_runtime_sha256: str
    collector_sha256: str
    source_rev: None
    live_contact_attempted: bool
    failure_class: str | None
    transport_exit_code: int | None
    helper_exit_code: int | None
    remote: dict[str, Any] | None = None


def require_isolated_startup() -> None:
    if getattr(sys.flags, "isolated", 0) != 1:
        raise StartupIsolationError()
    if getattr(sys.flags, "no_site", 0) != 1:
        raise StartupIsolationError()
    if not sys.dont_write_bytecode:
        raise StartupIsolationError()


def parse_args(argv: list[str]) -> ParsedArgs:
    ssh_target: str | None = None
    output_format: str | None = None
    seen: set[str] = set()
    i = 0
    while i < len(argv):
        arg = argv[i]
        if SECRET_LIKE_RE.search(arg):
            raise UsageError()
        if "=" in arg and arg.startswith("--"):
            raise UsageError()
        if arg == "--ssh-target":
            if arg in seen or i + 1 >= len(argv):
                raise UsageError()
            value = argv[i + 1]
            if not value or value.startswith("--") or "\n" in value or "\r" in value:
                raise UsageError()
            if SECRET_LIKE_RE.search(value):
                raise UsageError()
            ssh_target = value
            seen.add(arg)
            i += 2
            continue
        if arg == "--format":
            if arg in seen or i + 1 >= len(argv):
                raise UsageError()
            value = argv[i + 1]
            if value != "json":
                raise UsageError()
            output_format = value
            seen.add(arg)
            i += 2
            continue
        raise UsageError()

    if ssh_target is None or output_format != "json":
        raise UsageError()
    validate_ssh_target(ssh_target)
    return ParsedArgs(ssh_target=ssh_target, output_format=output_format)


def validate_ssh_target(value: str) -> None:
    if TARGET_FORBIDDEN_RE.search(value):
        raise UsageError()


def script_paths() -> tuple[Path, Path, Path]:
    runtime_path = Path(__file__).resolve()
    scripts_dir = runtime_path.parent
    repo_root = scripts_dir.parent
    collector_path = scripts_dir / "internal" / "remote_alpha_operator_healthcheck_tls_status_noninteractive_remote.py"
    return repo_root, runtime_path, collector_path


def read_source(path: Path, limit: int | None = None) -> bytes:
    try:
        stat = path.stat()
        if not path.is_file() or (limit is not None and stat.st_size > limit):
            raise LocalPreflightError()
        return path.read_bytes()
    except OSError as exc:
        raise LocalPreflightError() from exc


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def target_sha256_label(target: str) -> str:
    return sha256_hex(target.encode("utf-8"))


def remote_command(collector_sha256: str) -> str:
    if not SHA256_RE.fullmatch(collector_sha256):
        raise LocalPreflightError()
    return (
        "exec "
        + REMOTE_PYTHON
        + " -I -S -B - --protocol "
        + REMOTE_PROTOCOL_VERSION
        + " --collector-sha256 "
        + collector_sha256
    )


def require_supported_ssh() -> None:
    if not os.path.isfile(SUPPORTED_SSH) or not os.access(SUPPORTED_SSH, os.X_OK):
        raise LocalPreflightError()
    if not os.path.exists(NULL_SSH_CONFIG):
        raise LocalPreflightError()


def build_ssh_argv(ssh_target: str, collector_sha256: str) -> list[str]:
    validate_ssh_target(ssh_target)
    return [
        SUPPORTED_SSH,
        "-F",
        NULL_SSH_CONFIG,
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "NumberOfPasswordPrompts=0",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "ConnectionAttempts=1",
        "-o",
        "ProxyCommand=none",
        "-o",
        "ProxyJump=none",
        "-o",
        "PermitLocalCommand=no",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "ForwardAgent=no",
        "-o",
        "RequestTTY=no",
        "-o",
        "ControlMaster=no",
        "-o",
        "ControlPath=none",
        "-o",
        "ControlPersist=no",
        "-o",
        "CanonicalizeHostname=no",
        ssh_target,
        remote_command(collector_sha256),
    ]


def process_is_running(proc: subprocess.Popen[bytes]) -> bool:
    try:
        return proc.poll() is None
    except Exception:
        return True


def reap_started_process(proc: subprocess.Popen[bytes], grace_seconds: float = TERMINATION_GRACE_SECONDS) -> tuple[bool, int | None]:
    try:
        return True, proc.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        return False, getattr(proc, "returncode", None)
    except Exception:
        return False, getattr(proc, "returncode", None)


def terminate_process_group(proc: subprocess.Popen[bytes], grace_seconds: float = TERMINATION_GRACE_SECONDS) -> bool:
    resolved, _ = reap_started_process(proc, 0)
    if resolved:
        return True
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass
    resolved, _ = reap_started_process(proc, grace_seconds)
    if resolved:
        return True
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    resolved, _ = reap_started_process(proc, grace_seconds)
    return resolved


def cleanup_registered_fileobjs(selector: Any, registered_fileobjs: list[Any]) -> bool:
    cleanup_failed = False
    for fileobj in registered_fileobjs:
        try:
            selector.unregister(fileobj)
        except Exception:
            pass
        try:
            fileobj.close()
        except Exception:
            cleanup_failed = True
    try:
        selector.close()
    except Exception:
        cleanup_failed = True
    return cleanup_failed


def read_pipe_chunk(fileobj: Any, chunk_size: int) -> PipeReadResult:
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


def bounded_subprocess_run(
    argv: list[str],
    stdin_bytes: bytes,
    timeout_seconds: float = SSH_TIMEOUT_SECONDS,
    stdout_limit: int = MAX_STDOUT_BYTES,
    stderr_limit: int = MAX_STDERR_BYTES,
) -> ProcessResult:
    child_started = False
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=True,
        )
        child_started = True
    except Exception:
        return ProcessResult(status="spawn_failed", returncode=None, stdout=b"", stderr=b"", child_started=False)

    registered_fileobjs: list[Any] = []
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    stdout_size = 0
    stderr_size = 0
    stdin_offset = 0
    stdin_open = proc.stdin is not None
    stdout_open = proc.stdout is not None
    stderr_open = proc.stderr is not None

    try:
        selector = selectors.DefaultSelector()
    except Exception:
        terminate_process_group(proc)
        return ProcessResult(status="local_runtime_failed", returncode=proc.returncode, stdout=b"", stderr=b"", child_started=child_started)

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
        terminate_process_group(proc)
        cleanup_registered_fileobjs(selector, registered_fileobjs)
        return ProcessResult(status="local_runtime_failed", returncode=proc.returncode, stdout=b"", stderr=b"", child_started=child_started)

    deadline = time.monotonic() + timeout_seconds
    terminal_status: str | None = None
    normal_completion = False
    cleanup_failed = False
    lifecycle_unresolved = False
    final_returncode: int | None = None

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
                    read_result = read_pipe_chunk(fileobj, 4096)
                    if read_result.status == "transient":
                        continue
                    if read_result.status == "failed":
                        stdout_chunks.clear()
                        stderr_chunks.clear()
                        terminal_status = "local_runtime_failed"
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
                            if stdout_size > stdout_limit:
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
                            if stderr_size > stderr_limit:
                                terminal_status = "stderr_overflow"
                                break
                            stderr_chunks.append(chunk)
                if terminal_status:
                    break
                continue

            for key, mask in events:
                stream_name = key.data
                fileobj = key.fileobj
                if stream_name == "stdin":
                    if stdin_offset >= len(stdin_bytes):
                        try:
                            selector.unregister(fileobj)
                        except Exception:
                            pass
                        try:
                            fileobj.close()
                        except Exception:
                            pass
                        stdin_open = False
                        continue
                    try:
                        written = os.write(fileobj.fileno(), stdin_bytes[stdin_offset : stdin_offset + 8192])
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
                        stdin_open = False
                elif stream_name == "stdout":
                    if not stdout_open:
                        continue
                    read_result = read_pipe_chunk(fileobj, 4096)
                    if read_result.status == "transient":
                        continue
                    if read_result.status == "failed":
                        stdout_chunks.clear()
                        stderr_chunks.clear()
                        terminal_status = "local_runtime_failed"
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
                    if stdout_size > stdout_limit:
                        terminal_status = "stdout_overflow"
                        break
                    stdout_chunks.append(chunk)
                elif stream_name == "stderr":
                    if not stderr_open:
                        continue
                    read_result = read_pipe_chunk(fileobj, 4096)
                    if read_result.status == "transient":
                        continue
                    if read_result.status == "failed":
                        stdout_chunks.clear()
                        stderr_chunks.clear()
                        terminal_status = "local_runtime_failed"
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
                    if stderr_size > stderr_limit:
                        terminal_status = "stderr_overflow"
                        break
                    stderr_chunks.append(chunk)
            if terminal_status:
                break
    except Exception:
        terminal_status = "local_runtime_failed"
    finally:
        if normal_completion:
            resolved, final_returncode = reap_started_process(proc)
            if not resolved:
                lifecycle_unresolved = not terminate_process_group(proc)
                final_returncode = proc.returncode
        elif process_is_running(proc):
            lifecycle_unresolved = not terminate_process_group(proc)
            final_returncode = proc.returncode
        else:
            resolved, final_returncode = reap_started_process(proc)
            if not resolved:
                lifecycle_unresolved = True
        cleanup_failed = cleanup_registered_fileobjs(selector, registered_fileobjs)

    if lifecycle_unresolved:
        return ProcessResult(status="local_runtime_failed", returncode=final_returncode, stdout=b"", stderr=b"", child_started=child_started)

    if terminal_status:
        return ProcessResult(
            status=terminal_status,
            returncode=final_returncode,
            stdout=b"",
            stderr=b"",
            child_started=child_started,
            cleanup_failed=cleanup_failed,
        )
    return ProcessResult(
        status="ok",
        returncode=final_returncode,
        stdout=b"".join(stdout_chunks),
        stderr=b"".join(stderr_chunks),
        child_started=child_started,
        cleanup_failed=cleanup_failed,
    )


def duplicate_rejecting_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError()
        result[key] = value
    return result


def reject_json_constant(value: str) -> None:
    raise ProtocolError()


def strict_json_loads(text: str) -> Any:
    try:
        return json.loads(
            text,
            object_pairs_hook=duplicate_rejecting_pairs,
            parse_constant=reject_json_constant,
        )
    except ProtocolError:
        raise
    except Exception as exc:
        raise ProtocolError() from exc


def require_object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProtocolError()
    return value


def require_keys(label: str, value: dict[str, Any], allowed: set[str]) -> None:
    if set(value.keys()) != allowed:
        raise ProtocolError()


def require_status(value: Any) -> str:
    if value not in STATUS_VALUES:
        raise ProtocolError()
    return str(value)


def require_enum(value: Any, allowed: set[str]) -> str:
    if isinstance(value, str) and value in allowed:
        return value
    raise ProtocolError()


def require_optional_enum(value: Any, allowed: set[str]) -> str | None:
    if value is None:
        return None
    return require_enum(value, allowed)


def require_optional_failure(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or value not in FAILURE_CLASSES:
        raise ProtocolError()
    return value


def require_optional_bool(value: Any) -> bool | None:
    if value is None or isinstance(value, bool):
        return value
    raise ProtocolError()


def require_optional_sha256(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str) and SHA256_RE.fullmatch(value):
        return value
    raise ProtocolError()


def require_sha256(value: Any) -> str:
    if isinstance(value, str) and SHA256_RE.fullmatch(value):
        return value
    raise ProtocolError()


def require_optional_timestamp(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not TIMESTAMP_RE.fullmatch(value):
        raise ProtocolError()
    try:
        dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProtocolError() from exc
    return value


def require_timestamp(value: Any) -> str:
    if not isinstance(value, str) or not TIMESTAMP_RE.fullmatch(value):
        raise ProtocolError()
    try:
        dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProtocolError() from exc
    return value


def require_bool(value: Any) -> bool:
    if type(value) is bool:
        return value
    raise ProtocolError()


def require_int(value: Any, allowed: set[int] | None = None) -> int:
    if type(value) is not int:
        raise ProtocolError()
    if allowed is not None and value not in allowed:
        raise ProtocolError()
    return value


def require_optional_int(value: Any) -> int | None:
    if value is None:
        return None
    return require_int(value)


def require_exact_list(value: Any, expected: list[str]) -> list[str]:
    if not isinstance(value, list) or value != expected:
        raise ProtocolError()
    return value


def validate_remote_protocol_bytes(stdout: bytes, stderr: bytes, collector_sha256: str) -> dict[str, Any]:
    if stderr:
        raise ProtocolError()
    if not stdout.endswith(b"\n") or stdout.count(b"\n") != 1:
        raise ProtocolError()
    try:
        text = stdout.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise ProtocolError() from exc
    payload = require_object(strict_json_loads(text[:-1]))
    validate_remote_protocol(payload, collector_sha256)
    return payload


def validate_remote_protocol(payload: dict[str, Any], collector_sha256: str) -> None:
    require_keys("remote", payload, REMOTE_TOP_LEVEL_KEYS)
    if payload["protocol_version"] != REMOTE_PROTOCOL_VERSION:
        raise ProtocolError()
    if payload["collector_sha256"] != collector_sha256:
        raise ProtocolError()
    require_int(payload["helper_exit_code"], {0, 1, 2})
    require_bool(payload["status_available"])

    for key, allowed in REMOTE_NESTED_KEYS.items():
        nested = require_object(payload[key])
        require_keys(key, nested, allowed)

    result = payload["result"]
    require_status(result["status"])
    require_bool(result["ok"])
    require_enum(result["summary_label"], RESULT_SUMMARY_LABELS)
    require_optional_failure(result["failure_class"])

    auth = payload["auth_posture"]
    for key in auth:
        require_bool(auth[key])
    if auth["sudo_prompt_allowed"]:
        raise ProtocolError()

    cert = payload["certificate"]
    require_status(cert["status"])
    for key in ("not_before", "not_after"):
        require_optional_timestamp(cert[key])
    require_optional_enum(cert["subject_label"], SUBJECT_LABELS)
    require_optional_enum(cert["issuer_label"], ISSUER_LABELS)
    for key in ("expired", "not_yet_valid"):
        require_optional_bool(cert[key])
    for key in ("public_fingerprint_sha256", "file_sha256", "public_key_sha256", "issuer_digest_sha256"):
        require_optional_sha256(cert[key])
    require_optional_failure(cert["failure_class"])

    key_pair = payload["key_pair"]
    require_status(key_pair["status"])
    require_optional_bool(key_pair["public_key_match"])
    require_optional_sha256(key_pair["cert_public_key_sha256"])
    require_optional_sha256(key_pair["key_public_key_sha256"])
    require_optional_failure(key_pair["failure_class"])

    identity = payload["identity"]
    require_status(identity["status"])
    require_enum(identity["expected_uri_label"], EXPECTED_URI_LABELS)
    require_optional_enum(identity["classification"], IDENTITY_CLASSIFICATIONS)
    require_optional_bool(identity["matches_expected"])
    require_optional_bool(identity["legacy_operator_uri_present"])
    require_optional_failure(identity["failure_class"])

    trust = payload["trust_chain"]
    require_status(trust["status"])
    require_optional_enum(trust["classification"], TRUST_CLASSIFICATIONS)
    require_optional_sha256(trust["issuer_digest_sha256"])
    require_optional_failure(trust["failure_class"])

    file_posture = payload["file_posture"]
    for key in ("certificate", "key", "trust_bundle"):
        require_optional_enum(file_posture[key], FILE_POSTURE_LABELS)
    labels = file_posture["safe_mode_labels"]
    if not isinstance(labels, list) or len(labels) > 12:
        raise ProtocolError()
    for label in labels:
        require_enum(label, SAFE_MODE_LABELS)

    redaction = payload["redaction"]
    for value in redaction.values():
        if require_bool(value) is not False:
            raise ProtocolError()

    if result["ok"]:
        if result["status"] != "pass" or result["failure_class"] is not None or payload["helper_exit_code"] != 0:
            raise ProtocolError()
        if payload["status_available"] is not True:
            raise ProtocolError()
    else:
        if result["failure_class"] is None or payload["helper_exit_code"] != 1:
            raise ProtocolError()
        if result["status"] not in {"fail", "not_available"}:
            raise ProtocolError()
        if payload["status_available"] and result["status"] == "not_available":
            raise ProtocolError()


def default_status_objects() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    certificate = {
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
        "failure_class": None,
    }
    key_pair = {
        "status": "not_available",
        "public_key_match": None,
        "cert_public_key_sha256": None,
        "key_public_key_sha256": None,
        "failure_class": None,
    }
    identity = {
        "status": "not_available",
        "expected_uri_label": "operator/local",
        "matches_expected": None,
        "legacy_operator_uri_present": None,
        "classification": None,
        "failure_class": None,
    }
    trust_chain = {
        "status": "not_available",
        "classification": None,
        "issuer_digest_sha256": None,
        "failure_class": None,
    }
    return certificate, key_pair, identity, trust_chain


def default_redaction() -> dict[str, Any]:
    return {
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
        "final_schema_validated": True,
        "forbidden_material_scan": "pass",
    }


def classify_remote_failure(remote: dict[str, Any]) -> str | None:
    for path in (
        ("result", "failure_class"),
        ("certificate", "failure_class"),
        ("key_pair", "failure_class"),
        ("identity", "failure_class"),
        ("trust_chain", "failure_class"),
    ):
        current: Any = remote
        for part in path:
            current = current.get(part) if isinstance(current, dict) else None
        if current is not None:
            return require_optional_failure(current)
    if remote["result"]["ok"] is True:
        return None
    return "remote_status_failed"


def build_document(outcome: RouteOutcome) -> dict[str, Any]:
    generated_at = outcome.generated_at
    target_hash = outcome.target_hash
    route_runtime_sha256 = outcome.route_runtime_sha256
    collector_sha256 = outcome.collector_sha256
    source_rev = outcome.source_rev
    live_contact_attempted = outcome.live_contact_attempted
    failure_class = outcome.failure_class
    transport_exit_code = outcome.transport_exit_code
    helper_exit_code = outcome.helper_exit_code
    remote = outcome.remote

    if failure_class is not None and failure_class not in FAILURE_CLASSES:
        failure_class = "remote_status_failed"

    if remote is None:
        certificate, key_pair, identity, trust_chain = default_status_objects()
        status_available = False
        result_ok = False
        result_status = "not_available"
        auth_posture = {
            "ssh_batch_mode": "used" if live_contact_attempted else "not_attempted",
            "tty_required": False,
            "pseudo_tty_created": False,
            "sudo_prompt_allowed": False,
            "password_prompt_observed": False,
            "noninteractive_ready": False,
            "fixed_sudo_used": False,
        }
    else:
        remote_failure = classify_remote_failure(remote)
        if failure_class is None:
            failure_class = remote_failure
        certificate = remote["certificate"]
        key_pair = remote["key_pair"]
        identity = remote["identity"]
        trust_chain = remote["trust_chain"]
        status_available = remote["status_available"]
        result_ok = bool(remote["result"]["ok"] and failure_class is None)
        result_status = "pass" if result_ok else ("fail" if status_available else "not_available")
        auth_posture = {
            "ssh_batch_mode": "used",
            "tty_required": False,
            "pseudo_tty_created": False,
            "sudo_prompt_allowed": False,
            "password_prompt_observed": False,
            "noninteractive_ready": not remote["auth_posture"]["noninteractive_auth_required"],
            "fixed_sudo_used": remote["auth_posture"]["fixed_sudo_used"],
        }

    summary_label = SUMMARY_BY_FAILURE.get(failure_class, "remote_status_failed")
    if failure_class is None:
        summary_label = SUMMARY_BY_FAILURE[None]

    return {
        "schema_version": FINAL_SCHEMA_VERSION,
        "route": {
            "id": ROUTE_ID,
            "version": ROUTE_VERSION,
            "owner_repo": OWNER_REPO,
            "requires_interactive_tty": False,
            "supports_noninteractive": True,
            "scheduled_execution_allowed": False,
            "current_status": "implemented",
        },
        "generated_at": generated_at,
        "target": {
            "kind": "ssh_target_sha256",
            "sha256": target_hash,
        },
        "provenance": {
            "route_runtime_sha256": route_runtime_sha256,
            "remote_collector_sha256": collector_sha256,
            "internal_protocol_version": REMOTE_PROTOCOL_VERSION,
            "source_revision": source_rev,
        },
        "live_contact_attempted": live_contact_attempted,
        "status_available": status_available,
        "result": {
            "status": result_status,
            "ok": result_ok,
            "summary": summary_label,
        },
        "failure_class": failure_class,
        "exit_codes": {
            "facade_exit_code": None,
            "transport_exit_code": transport_exit_code,
            "helper_exit_code": helper_exit_code,
        },
        "auth_posture": auth_posture,
        "certificate": certificate,
        "key_pair": key_pair,
        "identity": identity,
        "trust_chain": trust_chain,
        "redaction": default_redaction(),
        "non_authority_labels": [
            "evidence_projection_only",
            "not_cp_run_control",
            "not_im_readiness_authority",
            "not_es_runtime_truth",
            "not_maintenance_agent_authority",
            "not_bridge_authority",
            "not_coordinator_authority",
            "not_production_readiness",
            "not_operational_acceptance",
            "not_live_proof",
            "not_renewal_authority",
        ],
        "owning_repo_contract_labels": {
            "route_contract_owner": "execution-substrate",
            "profile_diagnostic_owner": "control-plane",
            "profile_provenance_owner": "infrastructure-manager",
            "scheduler_summary_owner": "maintenance-agent",
            "bridge_projection_owner": "bridge",
        },
        "profile_lineage_hints": {
            "profile_refresh_may_be_needed": bool(failure_class in {"cert_metadata_expired", "identity_mismatch", "trust_chain_failed"}),
            "cp_diagnose_remote_profile_rerun_may_be_needed": bool(failure_class in {"cert_metadata_expired", "identity_mismatch", "trust_chain_failed"}),
            "mutates_profile": False,
            "lineage_authority": "none",
        },
    }


def canonical_json_bytes(document: dict[str, Any]) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"


FINAL_TOP_LEVEL_KEYS = {
    "schema_version",
    "route",
    "generated_at",
    "target",
    "provenance",
    "live_contact_attempted",
    "status_available",
    "result",
    "failure_class",
    "exit_codes",
    "auth_posture",
    "certificate",
    "key_pair",
    "identity",
    "trust_chain",
    "redaction",
    "non_authority_labels",
    "owning_repo_contract_labels",
    "profile_lineage_hints",
}

FINAL_NESTED_KEYS = {
    "route": {
        "id",
        "version",
        "owner_repo",
        "requires_interactive_tty",
        "supports_noninteractive",
        "scheduled_execution_allowed",
        "current_status",
    },
    "target": {"kind", "sha256"},
    "provenance": {
        "route_runtime_sha256",
        "remote_collector_sha256",
        "internal_protocol_version",
        "source_revision",
    },
    "result": {"status", "ok", "summary"},
    "exit_codes": {"facade_exit_code", "transport_exit_code", "helper_exit_code"},
    "auth_posture": {
        "ssh_batch_mode",
        "tty_required",
        "pseudo_tty_created",
        "sudo_prompt_allowed",
        "password_prompt_observed",
        "noninteractive_ready",
        "fixed_sudo_used",
    },
    "owning_repo_contract_labels": {
        "route_contract_owner",
        "profile_diagnostic_owner",
        "profile_provenance_owner",
        "scheduler_summary_owner",
        "bridge_projection_owner",
    },
    "profile_lineage_hints": {
        "profile_refresh_may_be_needed",
        "cp_diagnose_remote_profile_rerun_may_be_needed",
        "mutates_profile",
        "lineage_authority",
    },
}

EXPECTED_NON_AUTHORITY_LABELS = [
    "evidence_projection_only",
    "not_cp_run_control",
    "not_im_readiness_authority",
    "not_es_runtime_truth",
    "not_maintenance_agent_authority",
    "not_bridge_authority",
    "not_coordinator_authority",
    "not_production_readiness",
    "not_operational_acceptance",
    "not_live_proof",
    "not_renewal_authority",
]


def validate_source_revision(value: Any) -> None:
    if value is None:
        return None
    raise FinalSchemaError()


def final_protocol_error_to_schema_error(func: Callable[[], Any]) -> Any:
    try:
        return func()
    except ProtocolError as exc:
        raise FinalSchemaError() from exc


def validate_final_document(document: dict[str, Any]) -> bytes:
    try:
        require_keys("final", document, FINAL_TOP_LEVEL_KEYS)
        for key, allowed in FINAL_NESTED_KEYS.items():
            nested = require_object(document[key])
            require_keys(key, nested, allowed)

        if document["schema_version"] != FINAL_SCHEMA_VERSION:
            raise FinalSchemaError()
        route = document["route"]
        if route != {
            "id": ROUTE_ID,
            "version": ROUTE_VERSION,
            "owner_repo": OWNER_REPO,
            "requires_interactive_tty": False,
            "supports_noninteractive": True,
            "scheduled_execution_allowed": False,
            "current_status": "implemented",
        }:
            raise FinalSchemaError()
        final_protocol_error_to_schema_error(lambda: require_timestamp(document["generated_at"]))

        target = document["target"]
        if target["kind"] != "ssh_target_sha256":
            raise FinalSchemaError()
        final_protocol_error_to_schema_error(lambda: require_sha256(target["sha256"]))

        provenance = document["provenance"]
        final_protocol_error_to_schema_error(lambda: require_sha256(provenance["route_runtime_sha256"]))
        final_protocol_error_to_schema_error(lambda: require_sha256(provenance["remote_collector_sha256"]))
        if provenance["internal_protocol_version"] != REMOTE_PROTOCOL_VERSION:
            raise FinalSchemaError()
        validate_source_revision(provenance["source_revision"])

        live_contact_attempted = final_protocol_error_to_schema_error(lambda: require_bool(document["live_contact_attempted"]))
        status_available = final_protocol_error_to_schema_error(lambda: require_bool(document["status_available"]))
        failure_class = final_protocol_error_to_schema_error(lambda: require_optional_failure(document["failure_class"]))

        result = document["result"]
        result_status = final_protocol_error_to_schema_error(lambda: require_status(result["status"]))
        result_ok = final_protocol_error_to_schema_error(lambda: require_bool(result["ok"]))
        expected_summary = SUMMARY_BY_FAILURE[None] if failure_class is None else SUMMARY_BY_FAILURE.get(failure_class)
        if expected_summary is None or result["summary"] != expected_summary:
            raise FinalSchemaError()

        exit_codes = document["exit_codes"]
        if exit_codes["facade_exit_code"] is not None:
            raise FinalSchemaError()
        final_protocol_error_to_schema_error(lambda: require_optional_int(exit_codes["transport_exit_code"]))
        final_protocol_error_to_schema_error(lambda: require_optional_int(exit_codes["helper_exit_code"]))

        auth = document["auth_posture"]
        final_protocol_error_to_schema_error(lambda: require_enum(auth["ssh_batch_mode"], SSH_BATCH_LABELS))
        for key in (
            "tty_required",
            "pseudo_tty_created",
            "sudo_prompt_allowed",
            "password_prompt_observed",
            "noninteractive_ready",
            "fixed_sudo_used",
        ):
            final_protocol_error_to_schema_error(lambda key=key: require_bool(auth[key]))
        if auth["tty_required"] or auth["pseudo_tty_created"] or auth["sudo_prompt_allowed"] or auth["password_prompt_observed"]:
            raise FinalSchemaError()

        final_protocol_error_to_schema_error(lambda: validate_remote_leaf_objects(document))

        redaction = document["redaction"]
        require_keys("redaction", redaction, set(default_redaction().keys()))
        for key, value in redaction.items():
            if key == "forbidden_material_scan":
                if value != "pass":
                    raise FinalSchemaError()
            elif final_protocol_error_to_schema_error(lambda value=value: require_bool(value)) is not (key in {"final_schema_validated"}):
                raise FinalSchemaError()

        final_protocol_error_to_schema_error(lambda: require_exact_list(document["non_authority_labels"], EXPECTED_NON_AUTHORITY_LABELS))
        owners = document["owning_repo_contract_labels"]
        if owners != {
            "route_contract_owner": "execution-substrate",
            "profile_diagnostic_owner": "control-plane",
            "profile_provenance_owner": "infrastructure-manager",
            "scheduler_summary_owner": "maintenance-agent",
            "bridge_projection_owner": "bridge",
        }:
            raise FinalSchemaError()

        lineage = document["profile_lineage_hints"]
        for key in (
            "profile_refresh_may_be_needed",
            "cp_diagnose_remote_profile_rerun_may_be_needed",
            "mutates_profile",
        ):
            final_protocol_error_to_schema_error(lambda key=key: require_bool(lineage[key]))
        final_protocol_error_to_schema_error(lambda: require_enum(lineage["lineage_authority"], LINEAGE_AUTHORITY_LABELS))
        if lineage["mutates_profile"]:
            raise FinalSchemaError()

        if result_ok:
            if failure_class is not None or result_status != "pass" or not status_available:
                raise FinalSchemaError()
            if exit_codes["helper_exit_code"] not in (0, None):
                raise FinalSchemaError()
        else:
            if failure_class is None or result_status not in {"fail", "not_available"}:
                raise FinalSchemaError()
            if status_available and result_status == "not_available":
                raise FinalSchemaError()
        if failure_class == "local_runtime_failed":
            if status_available or result_ok or result_status != "not_available":
                raise FinalSchemaError()
            if exit_codes["helper_exit_code"] is not None:
                raise FinalSchemaError()
        elif not live_contact_attempted:
            raise FinalSchemaError()
        if document["route"]["scheduled_execution_allowed"]:
            raise FinalSchemaError()

        payload = canonical_json_bytes(document)
        scan_forbidden_material(payload)
        return payload
    except FinalSchemaError:
        raise
    except Exception as exc:
        raise FinalSchemaError() from exc


def validate_remote_leaf_objects(document: dict[str, Any]) -> None:
    cert = require_object(document["certificate"])
    require_keys("certificate", cert, REMOTE_NESTED_KEYS["certificate"])
    require_status(cert["status"])
    require_optional_timestamp(cert["not_before"])
    require_optional_timestamp(cert["not_after"])
    require_optional_bool(cert["expired"])
    require_optional_bool(cert["not_yet_valid"])
    for key in ("public_fingerprint_sha256", "file_sha256", "public_key_sha256", "issuer_digest_sha256"):
        require_optional_sha256(cert[key])
    require_optional_enum(cert["subject_label"], SUBJECT_LABELS)
    require_optional_enum(cert["issuer_label"], ISSUER_LABELS)
    require_optional_failure(cert["failure_class"])

    key_pair = require_object(document["key_pair"])
    require_keys("key_pair", key_pair, REMOTE_NESTED_KEYS["key_pair"])
    require_status(key_pair["status"])
    require_optional_bool(key_pair["public_key_match"])
    require_optional_sha256(key_pair["cert_public_key_sha256"])
    require_optional_sha256(key_pair["key_public_key_sha256"])
    require_optional_failure(key_pair["failure_class"])

    identity = require_object(document["identity"])
    require_keys("identity", identity, REMOTE_NESTED_KEYS["identity"])
    require_status(identity["status"])
    require_enum(identity["expected_uri_label"], EXPECTED_URI_LABELS)
    require_optional_bool(identity["matches_expected"])
    require_optional_bool(identity["legacy_operator_uri_present"])
    require_optional_enum(identity["classification"], IDENTITY_CLASSIFICATIONS)
    require_optional_failure(identity["failure_class"])

    trust = require_object(document["trust_chain"])
    require_keys("trust_chain", trust, REMOTE_NESTED_KEYS["trust_chain"])
    require_status(trust["status"])
    require_optional_enum(trust["classification"], TRUST_CLASSIFICATIONS)
    require_optional_sha256(trust["issuer_digest_sha256"])
    require_optional_failure(trust["failure_class"])


def scan_forbidden_material(json_bytes: bytes) -> None:
    if len(json_bytes) > MAX_FINAL_JSON_BYTES:
        raise ForbiddenMaterialError()
    text = json_bytes.decode("utf-8", "strict")
    for pattern in FORBIDDEN_FINAL_PATTERNS:
        if pattern.search(text):
            raise ForbiddenMaterialError()


def emit_document(document: dict[str, Any]) -> int:
    payload = validate_final_document(document)
    sys.stdout.buffer.write(payload)
    return 0 if document["result"]["ok"] is True else 1


def failure_from_process_result(result: ProcessResult) -> str:
    if result.status in {"spawn_failed", "local_runtime_failed"}:
        return "local_runtime_failed"
    if result.status == "timeout":
        return "ssh_batch_mode_failed"
    if result.status in {"stdout_overflow", "stderr_overflow"}:
        return "unexpected_output_shape"
    if result.returncode in (126, 127):
        return "remote_status_unavailable"
    return "ssh_batch_mode_failed"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def run_route(
    argv: list[str],
    *,
    runner: Callable[[list[str], bytes], ProcessResult] = bounded_subprocess_run,
    now_func: Callable[[], str] = utc_now,
) -> int:
    try:
        require_isolated_startup()
        parsed = parse_args(argv)
        _, runtime_path, collector_path = script_paths()
        runtime_source = read_source(runtime_path)
        collector_source = read_source(collector_path, MAX_COLLECTOR_SOURCE_BYTES)
        require_supported_ssh()
    except StartupIsolationError:
        print(f"error: {SAFE_STARTUP_ERROR}", file=sys.stderr)
        return 2
    except UsageError:
        print(f"error: {SAFE_USAGE_ERROR}", file=sys.stderr)
        return 2
    except LocalPreflightError:
        print(f"error: {SAFE_PREFLIGHT_ERROR}", file=sys.stderr)
        return 2

    runtime_hash = sha256_hex(runtime_source)
    collector_hash = sha256_hex(collector_source)
    target_hash = target_sha256_label(parsed.ssh_target)
    source_rev = None
    generated_at = now_func()
    ssh_argv = build_ssh_argv(parsed.ssh_target, collector_hash)

    try:
        process_result = runner(ssh_argv, collector_source)
    except Exception:
        process_result = ProcessResult(status="local_runtime_failed", returncode=None, stdout=b"", stderr=b"", child_started=False)
    remote_payload: dict[str, Any] | None = None
    failure_class: str | None = None
    helper_exit_code: int | None = None

    if process_result.status == "ok":
        try:
            remote_payload = validate_remote_protocol_bytes(process_result.stdout, process_result.stderr, collector_hash)
            helper_exit_code = int(remote_payload["helper_exit_code"])
            if process_result.returncode != helper_exit_code:
                remote_payload = None
                helper_exit_code = None
                failure_class = "unexpected_output_shape"
        except ProtocolError:
            if process_result.returncode not in (0, None) and not process_result.stdout:
                failure_class = failure_from_process_result(process_result)
            else:
                failure_class = "unexpected_output_shape"
        except Exception:
            failure_class = "unexpected_output_shape"
    else:
        failure_class = failure_from_process_result(process_result)

    if remote_payload is None and failure_class is None:
        failure_class = failure_from_process_result(process_result)
    # Classify cleanup-only failures after primary process/protocol outcomes.
    if process_result.cleanup_failed and failure_class is None:
        if remote_payload is not None:
            failure_class = classify_remote_failure(remote_payload)
        if failure_class is None:
            remote_payload = None
            helper_exit_code = None
            failure_class = "local_runtime_failed"

    outcome = RouteOutcome(
        generated_at=generated_at,
        target_hash=target_hash,
        route_runtime_sha256=runtime_hash,
        collector_sha256=collector_hash,
        source_rev=source_rev,
        live_contact_attempted=process_result.child_started,
        failure_class=failure_class,
        transport_exit_code=process_result.returncode,
        helper_exit_code=helper_exit_code,
        remote=remote_payload,
    )
    document = build_document(outcome)

    try:
        return emit_document(document)
    except (ForbiddenMaterialError, FinalSchemaError):
        print(f"error: {SAFE_FINAL_EMISSION_ERROR}", file=sys.stderr)
        return 1


def main() -> int:
    try:
        return run_route(sys.argv[1:])
    except Exception:
        print(f"error: {SAFE_RUNTIME_ERROR}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
