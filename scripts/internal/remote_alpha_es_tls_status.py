#!/usr/bin/env python3
"""Fixed Remote Alpha P0s/P0t status evidence. No renewal entry point."""
from __future__ import annotations

import datetime as dt
import ctypes
import fcntl
import hashlib
import json
import math
import os
import posixpath
import re
import secrets
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time
from email.utils import parsedate_to_datetime
from enum import Enum
from typing import NamedTuple
from urllib.parse import urlparse

CONTRACT = "execution-substrate.remote-alpha.es-tls-status-collector/v1"
STATUS_ROOT = "/var/lib/execution-substrate-remote-alpha/v1/status"
OPENSSL = "/usr/bin/openssl"
MAX_INPUT = 1048576
MAX_OUTPUT = 65536
MAX_ERROR = 8192
MAX_SUMMARY = 1048576
MAX_JSON_CONTAINER_DEPTH = 64
CHILD_TIMEOUT = 10.0
CHILD_GRACE = 1.0
CHUNK = 16384
SIGNALS = (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM)
CHILD_ENV = {"LC_ALL": "C", "LANG": "C", "TZ": "UTC", "PATH": "/usr/bin:/bin", "HOME": "/", "OPENSSL_CONF": "/dev/null"}
TRUST_FD_OPERAND = "@selected-ca-fd@"
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_NOFOLLOW | os.O_CLOEXEC
HEX32 = re.compile(r"^[0-9a-f]{32}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
LATCHED_SIGNAL: int | None = None

ARS = "/etc/execution-substrate/ars-tls"
AGS = "/etc/execution-substrate/tls"
ES = "/etc/execution-substrate/es-tls"
EGS = "/etc/execution-substrate/egs-tls"
CONFIG = {name: f"/etc/execution-substrate/{name}.json" for name in ("ars", "ags", "es", "egs")}

SCOPES = {
    "artifact-registry": {
        "route": "es-service-tls-status",
        "schema": "execution-substrate.remote-alpha.es-service-tls-status-summary.v1",
        "canonical": "es-service-tls-status-summary.json",
        "lock": ".es-service-tls-status.lock",
        "required_config": ("ars", "ags", "es"),
        "certs": (
            ("ars_trusted_runtime_client_ca", f"{ARS}/runtime-ca.pem", "ca", None, None),
            ("ars_server", f"{ARS}/ars-server-cert.pem", "server", "server.artifact-registry.internal", "server"),
            ("ags_artifact_registry_client", f"{AGS}/ags-client-cert.pem", "client", None, "client"),
            ("ags_artifact_registry_root_ca", f"{AGS}/runtime-ca.pem", "ca", None, None),
            ("es_artifact_registry_client", f"{ES}/artifact-registry-client-cert.pem", "client", None, "client"),
            ("es_artifact_registry_root_ca", f"{ES}/artifact-registry-root-ca.pem", "ca", None, None),
        ),
        "pairs": (
            ("ars_server", "ars_server", f"{ARS}/ars-server-key.pem"),
            ("ags_artifact_registry_client", "ags_artifact_registry_client", f"{AGS}/ags-client-key.pem"),
            ("es_artifact_registry_client", "es_artifact_registry_client", f"{ES}/artifact-registry-client-key.pem"),
        ),
        "verify": (
            ("ags_client_cert_against_ars_client_ca", "ars_trusted_runtime_client_ca", "ags_artifact_registry_client", "sslclient", ""),
            ("es_client_cert_against_ars_client_ca", "ars_trusted_runtime_client_ca", "es_artifact_registry_client", "sslclient", ""),
            ("ars_server_cert_against_ags_root_ca", "ags_artifact_registry_root_ca", "ars_server", "sslserver", "server.artifact-registry.internal"),
            ("ars_server_cert_against_es_root_ca", "es_artifact_registry_root_ca", "ars_server", "sslserver", "server.artifact-registry.internal"),
        ),
        "bindings": (
            ("ars_client_ca", "ars", ("tls", "client_ca_file"), f"{ARS}/runtime-ca.pem"),
            ("ars_cert", "ars", ("tls", "cert_file"), f"{ARS}/ars-server-cert.pem"),
            ("ars_key", "ars", ("tls", "key_file"), f"{ARS}/ars-server-key.pem"),
            ("ags_client_cert", "ags", ("dependencies", "artifact_registry", "client_cert_file"), f"{AGS}/ags-client-cert.pem"),
            ("ags_client_key", "ags", ("dependencies", "artifact_registry", "client_key_file"), f"{AGS}/ags-client-key.pem"),
            ("ags_root_ca", "ags", ("dependencies", "artifact_registry", "root_ca_file"), f"{AGS}/runtime-ca.pem"),
            ("es_client_cert", "es", ("dependencies", "artifact_registry", "client_cert_file"), f"{ES}/artifact-registry-client-cert.pem"),
            ("es_client_key", "es", ("dependencies", "artifact_registry", "client_key_file"), f"{ES}/artifact-registry-client-key.pem"),
            ("es_root_ca", "es", ("dependencies", "artifact_registry", "root_ca_file"), f"{ES}/artifact-registry-root-ca.pem"),
        ),
        "urls": (("ags_ars_url", "ags", ("dependencies", "artifact_registry", "base_url"), 8442),
                 ("es_ars_url", "es", ("dependencies", "artifact_registry", "base_url"), 8442)),
    },
    "execution-governance": {
        "route": "es-governance-tls-status",
        "schema": "execution-substrate.remote-alpha.es-governance-tls-status-summary.v1",
        "canonical": "es-governance-tls-status-summary.json",
        "lock": ".es-governance-tls-status.lock",
        "required_config": ("ags", "es", "egs"),
        "certs": (
            ("egs_trusted_runtime_client_ca", f"{EGS}/runtime-ca.pem", "ca", None, None),
            ("egs_server", f"{EGS}/egs-server-cert.pem", "server", "server.execution-governance.internal", "server"),
            ("es_execution_governance_client", f"{ES}/execution-governance-client-cert.pem", "client", None, "client"),
            ("es_execution_governance_root_ca", f"{ES}/execution-governance-root-ca.pem", "ca", None, None),
        ),
        "pairs": (("egs_server", "egs_server", f"{EGS}/egs-server-key.pem"),
                  ("es_execution_governance_client", "es_execution_governance_client", f"{ES}/execution-governance-client-key.pem")),
        "verify": (("es_execution_governance_client_cert_against_egs_client_ca", "egs_trusted_runtime_client_ca", "es_execution_governance_client", "sslclient", ""),
                   ("egs_server_cert_against_es_execution_governance_root_ca", "es_execution_governance_root_ca", "egs_server", "sslserver", "server.execution-governance.internal")),
        "bindings": (
            ("egs_client_ca", "egs", ("tls", "client_ca_file"), f"{EGS}/runtime-ca.pem"),
            ("egs_cert", "egs", ("tls", "cert_file"), f"{EGS}/egs-server-cert.pem"),
            ("egs_key", "egs", ("tls", "key_file"), f"{EGS}/egs-server-key.pem"),
            ("es_client_cert", "es", ("dependencies", "execution_governance", "client_cert_file"), f"{ES}/execution-governance-client-cert.pem"),
            ("es_client_key", "es", ("dependencies", "execution_governance", "client_key_file"), f"{ES}/execution-governance-client-key.pem"),
            ("es_root_ca", "es", ("dependencies", "execution_governance", "root_ca_file"), f"{ES}/execution-governance-root-ca.pem"),
            ("es_server_name", "es", ("dependencies", "execution_governance", "server_name"), "server.execution-governance.internal"),
        ),
        "urls": (("es_egs_url", "es", ("dependencies", "execution_governance", "base_url"), 8443),),
    },
}

class Incomplete(Exception):
    pass


class _VerifiedFinalLeafAbsent(Exception):
    """Private evidence of the original final-leaf stat and settled closeout."""


class StrictJSONRejected(Incomplete):
    pass


class StrictJSONDepthRejected(StrictJSONRejected):
    pass


# This is private invocation state for the already verified root bootstrap.
# It is not a status record, terminal writer, or alternate collector contract.
WITNESS_SELECTION: tuple[str, str] | None = None
WITNESS_CLOSEOUT_PROVED = False
WITNESS_DISPOSITION_UNPROVED = False

_FAILURE_REASON_LITERALS = {
    "protected_ancestry": {
        "unsafe_protected_ancestor": "protected_state_unproved",
        "extended_access_unproved": "protected_state_unproved",
        "entry_identity_changed": "protected_state_unproved",
    },
    "scope_lock": {
        "unsafe_lock": "lock_state_unproved",
        "unsafe_protected_file": "lock_state_unproved",
        "lock_identity_changed": "lock_state_unproved",
        "entry_identity_changed": "lock_state_unproved",
        "extended_access_unproved": "lock_state_unproved",
        # flock may raise for reasons other than contention.
        "same_scope_lock_contended": "lock_acquisition_unproved",
    },
    "process_capability": {
        "process_capability_unavailable": "process_capability_unproved",
        "child_waitid_unavailable": "process_capability_unproved",
        "child_waitid_indeterminate": "process_capability_unproved",
    },
    "prior_snapshot": {
        "prior_summary_unaccepted": "prior_summary_unaccepted",
        "unsafe_existing_summary": "prior_read_unproved",
        "unsafe_protected_file": "prior_read_unproved",
        "extended_access_unproved": "prior_read_unproved",
        "summary_leaf_changed": "prior_read_unproved",
        "leaf_identity_changed": "prior_read_unproved",
        "record_size": "prior_read_unproved",
        "record_changed": "prior_read_unproved",
    },
    "collection": {
        "invalid_fixed_path": "fixed_input_unproved",
        "unsafe_input_ancestor": "fixed_input_unproved",
        "input_ancestor_changed": "fixed_input_unproved",
        "unsafe_fixed_input": "fixed_input_unproved",
        "fixed_input_changed": "fixed_input_unproved",
        "fixed_input_overflow": "fixed_input_unproved",
        "config_read_unproved": "fixed_input_unproved",
        "certificate_read_unproved": "fixed_input_unproved",
        "key_read_unproved": "fixed_input_unproved",
        "fixed_input_close_unproved": "fixed_input_unproved",
        "fixed_input_read_unproved": "fixed_input_unproved",
        "invalid_fixed_command": "fixed_command_unproved",
        "invalid_verification_inputs": "fixed_command_unproved",
        "child_pipe_unproved": "openssl_child_unproved",
        "child_spawn_unproved": "openssl_child_unproved",
        "child_run_unproved": "openssl_child_unproved",
        "child_resource_unproved": "openssl_child_unproved",
        "child_waitid_indeterminate": "openssl_child_unproved",
        "child_waitid_unavailable": "openssl_child_unproved",
        "process_identity_unproved": "openssl_child_unproved",
        "process_members_unproved": "openssl_child_unproved",
        "process_member_signal_unproved": "openssl_child_unproved",
        "child_reap_unproved": "openssl_child_unproved",
        "child_unreaped": "openssl_child_unproved",
        "child_interrupted": "openssl_child_unproved",
        "child_timeout": "openssl_child_unproved",
        "child_output_overflow": "openssl_child_unproved",
        "process_capability_unavailable": "openssl_child_unproved",
        "unexpected_openssl_grammar": "openssl_grammar_unaccepted",
    },
    "record_encoding": {
        **{name: "record_unaccepted" for name in (
            "record_code", "record_scope", "record_shape", "record_identity",
            "record_generation", "record_timestamp", "record_freshness",
            "record_roles", "record_status", "record_topology_shape",
            "record_topology_code", "record_topology_relationship",
            "record_certificate_shape", "record_certificate_hash",
            "record_certificate_flag", "record_certificate_role_flag",
            "record_trust_anchor_role", "record_certificate_absence",
            "record_certificate_time", "record_certificate_metadata",
            "record_certificate_validity", "record_certificate_semantics",
            "record_verification_shape", "record_verification_relationship",
            "record_pair_shape", "record_pair_consistency",
            "record_pair_relationship", "record_blockers", "record_result",
            "record_effects", "record_security", "record_encoding",
        )},
    },
    "publication_precommit": {
        **{name: "publication_unproved" for name in (
            "summary_write", "temporary_identity", "precommit_signal",
            "signal_boundary_unproved", "publication_returned",
            "unsafe_existing_summary", "unsafe_protected_file",
            "extended_access_unproved", "summary_leaf_changed",
            "leaf_identity_changed", "record_size", "record_changed",
        )},
    },
}


def _failure_reason(phase: str, failure: BaseException) -> str:
    # Never convert an exception or an argument to text, even for comparison.
    if type(phase) is not str or type(failure) is not Incomplete or len(failure.args) != 1:
        return "unknown"
    literal = failure.args[0]
    if type(literal) is not str:
        return "unknown"
    if literal in ("interrupted", "child_interrupted"):
        return "interrupted"
    return _FAILURE_REASON_LITERALS.get(phase, {}).get(literal, "unknown")


class _PriorSummaryState(Enum):
    ABSENT = "absent"
    VALID = "valid"
    INVALID_OR_UNACCEPTED = "invalid_or_unaccepted"


class _PriorSummarySnapshot(NamedTuple):
    state: _PriorSummaryState
    generation: str | None = None
    reason_class: str | None = None


def _latch(signum: int, _frame: object) -> None:
    global LATCHED_SIGNAL
    if LATCHED_SIGNAL is None:
        LATCHED_SIGNAL = signum


def check_signal() -> None:
    if LATCHED_SIGNAL is not None:
        raise Incomplete("interrupted")


def file_identity(info: os.stat_result) -> tuple[int, int]:
    return (info.st_dev, info.st_ino)


def leaf_identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode), info.st_uid, info.st_gid,
            stat.S_IMODE(info.st_mode), info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def same_leaf(parent_fd: int, name: str, info: os.stat_result) -> None:
    entry = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if leaf_identity(entry) != leaf_identity(info):
        raise Incomplete("leaf_identity_changed")


def same_entry(parent_fd: int, name: str, info: os.stat_result) -> None:
    entry = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if file_identity(entry) != file_identity(info):
        raise Incomplete("entry_identity_changed")


def check_extended(fd: int) -> None:
    try:
        attrs = os.listxattr(fd)
    except (AttributeError, OSError) as exc:
        raise Incomplete("extended_access_unproved") from exc
    if any(attr not in ("security.selinux", "com.apple.provenance") for attr in attrs):
        raise Incomplete("extended_access_unproved")


def check_protected_dir(fd: int, exact_mode: int | None = None) -> os.stat_result:
    info = os.fstat(fd)
    mode = stat.S_IMODE(info.st_mode)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or mode & 0o022:
        raise Incomplete("unsafe_protected_ancestor")
    if exact_mode is not None and mode != exact_mode:
        raise Incomplete("unsafe_protected_ancestor")
    check_extended(fd)
    return info


def open_status_dir() -> int:
    global WITNESS_DISPOSITION_UNPROVED
    fd = os.open("/", DIR_FLAGS)
    try:
        check_protected_dir(fd)
        for name, mode in (("var", None), ("lib", None), ("execution-substrate-remote-alpha", 0o755), ("v1", 0o755), ("status", 0o755)):
            child = os.open(name, DIR_FLAGS, dir_fd=fd)
            try:
                info = check_protected_dir(child, mode)
                same_entry(fd, name, info)
            except BaseException:
                try:
                    os.close(child)
                except BaseException:
                    WITNESS_DISPOSITION_UNPROVED = True
                    raise
                raise
            previous_fd = fd
            fd = child
            try:
                os.close(previous_fd)
            except BaseException:
                WITNESS_DISPOSITION_UNPROVED = True
                raise
        return fd
    except BaseException:
        try:
            os.close(fd)
        except BaseException:
            WITNESS_DISPOSITION_UNPROVED = True
            raise
        raise


def check_protected_file(fd: int, mode: int) -> os.stat_result:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != mode or info.st_nlink != 1:
        raise Incomplete("unsafe_protected_file")
    check_extended(fd)
    return info


def read_protected_summary_leaf(status_fd: int, name: str) -> bytes | None:
    """Read a canonical regular leaf without any blocking final-entry open."""
    try:
        entry = os.stat(name, dir_fd=status_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if (not stat.S_ISREG(entry.st_mode) or entry.st_uid != 0 or entry.st_gid != 0 or
            stat.S_IMODE(entry.st_mode) != 0o644 or entry.st_nlink != 1 or
            entry.st_size > MAX_SUMMARY):
        raise Incomplete("unsafe_existing_summary")
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | FILE_FLAGS, dir_fd=status_fd)
    except OSError as exc:
        raise Incomplete("summary_leaf_changed") from exc
    try:
        info = check_protected_file(fd, 0o644)
        if leaf_identity(info) != leaf_identity(entry):
            raise Incomplete("summary_leaf_changed")
        same_leaf(status_fd, name, info)
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(fd, min(CHUNK, MAX_SUMMARY + 1 - total))
            if not block:
                break
            total += len(block)
            if total > MAX_SUMMARY:
                raise Incomplete("record_size")
            chunks.append(block)
        after = check_protected_file(fd, 0o644)
        if total != info.st_size or leaf_identity(after) != leaf_identity(info):
            raise Incomplete("record_changed")
        same_leaf(status_fd, name, after)
        return b"".join(chunks)
    finally:
        os.close(fd)


def check_existing(status_fd: int, name: str) -> None:
    read_protected_summary_leaf(status_fd, name)


def open_scope_lock(status_fd: int, name: str) -> int:
    try:
        entry = os.stat(name, dir_fd=status_fd, follow_symlinks=False)
    except FileNotFoundError:
        entry = None
    if entry is not None and (not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1):
        raise Incomplete("unsafe_lock")
    flags = os.O_RDWR | os.O_CREAT | FILE_FLAGS
    try:
        fd = os.open(name, flags | os.O_EXCL, 0o600, dir_fd=status_fd)
    except FileExistsError:
        fd = os.open(name, flags, 0o600, dir_fd=status_fd)
    else:
        try:
            os.fchmod(fd, 0o600)
            os.fsync(status_fd)
        except BaseException:
            os.close(fd)
            raise
    try:
        info = check_protected_file(fd, 0o600)
        if entry is not None and file_identity(info) != file_identity(entry):
            raise Incomplete("lock_identity_changed")
        same_entry(status_fd, name, info)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise Incomplete("same_scope_lock_contended") from exc
        return fd
    except BaseException:
        os.close(fd)
        raise




def canonical_material_path(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("/") or value == "/" or "\x00" in value:
        return False
    if "//" in value or value.endswith("/") or any(part in ("", ".", "..") for part in value.split("/")[1:]):
        return False
    return posixpath.normpath(value) == value


def check_input_ancestor(info: os.stat_result) -> None:
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
        raise Incomplete("unsafe_input_ancestor")


def _close_fixed_input(fd: int) -> None:
    # Close errors are never evidence that the final input leaf is absent.
    global WITNESS_DISPOSITION_UNPROVED
    try:
        os.close(fd)
    except BaseException as exc:
        WITNESS_DISPOSITION_UNPROVED = True
        if isinstance(exc, Exception) and not isinstance(exc, Incomplete):
            raise Incomplete("fixed_input_close_unproved") from exc
        raise


def open_fixed_regular(path: str, limit: int, read_content: bool = True) -> bytes | None:
    if not canonical_material_path(path):
        raise Incomplete("invalid_fixed_path")
    parts = path.split("/")[1:]
    chain: list[tuple[int | None, str | None, int, os.stat_result]] = []
    failure: BaseException | None = None
    verified_final_leaf_absent = False
    non_final_not_found = False
    try:
        root_fd = os.open("/", DIR_FLAGS)
        try:
            root_info = os.fstat(root_fd)
            check_input_ancestor(root_info)
            check_extended(root_fd)
        except BaseException:
            _close_fixed_input(root_fd)
            raise
        chain.append((None, None, root_fd, root_info))
        for part in parts[:-1]:
            parent_fd = chain[-1][2]
            child: int | None = None
            try:
                child = os.open(part, DIR_FLAGS, dir_fd=parent_fd)
                info = os.fstat(child)
                check_input_ancestor(info)
                check_extended(child)
                same_entry(parent_fd, part, info)
            except OSError as exc:
                if child is not None:
                    closing_child, child = child, None
                    _close_fixed_input(closing_child)
                raise Incomplete("unsafe_input_ancestor") from exc
            except BaseException:
                if child is not None:
                    closing_child, child = child, None
                    _close_fixed_input(closing_child)
                raise
            chain.append((parent_fd, part, child, info))
            child = None

        def revalidate_ancestry() -> None:
            try:
                for parent_fd, name, directory_fd, original in chain:
                    current = os.fstat(directory_fd)
                    check_input_ancestor(current)
                    check_extended(directory_fd)
                    if file_identity(current) != file_identity(original):
                        raise Incomplete("input_ancestor_changed")
                    if parent_fd is not None and name is not None:
                        same_entry(parent_fd, name, current)
            except OSError as exc:
                raise Incomplete("input_ancestor_changed") from exc

        parent_fd = chain[-1][2]
        name = parts[-1]
        try:
            entry = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            revalidate_ancestry()
            verified_final_leaf_absent = True
        except OSError as exc:
            raise Incomplete("unsafe_fixed_input") from exc
        if not verified_final_leaf_absent:
            if not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1 or not 0 <= entry.st_size <= limit:
                raise Incomplete("unsafe_fixed_input")
            try:
                file_fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | FILE_FLAGS, dir_fd=parent_fd)
            except OSError as exc:
                raise Incomplete("fixed_input_changed") from exc
            try:
                info = os.fstat(file_fd)
                if leaf_identity(info) != leaf_identity(entry):
                    raise Incomplete("fixed_input_changed")
                check_extended(file_fd)
                try:
                    same_leaf(parent_fd, name, info)
                except OSError as exc:
                    raise Incomplete("fixed_input_changed") from exc
                if not read_content:
                    revalidate_ancestry()
                    return None
                chunks: list[bytes] = []
                total = 0
                while True:
                    block = os.read(file_fd, CHUNK)
                    if not block:
                        break
                    total += len(block)
                    if total > limit:
                        raise Incomplete("fixed_input_overflow")
                    chunks.append(block)
                after = os.fstat(file_fd)
                if total != info.st_size or leaf_identity(after) != leaf_identity(info):
                    raise Incomplete("fixed_input_changed")
                check_extended(file_fd)
                try:
                    same_leaf(parent_fd, name, after)
                except OSError as exc:
                    raise Incomplete("fixed_input_changed") from exc
                revalidate_ancestry()
                return b"".join(chunks)
            finally:
                _close_fixed_input(file_fd)
    except FileNotFoundError as exc:
        failure = exc
        non_final_not_found = True
    except BaseException as exc:
        failure = exc
        raise
    finally:
        close_failure: Exception | None = None
        close_interrupt: BaseException | None = None
        while chain:
            _parent, _name, directory_fd, _info = chain.pop()
            try:
                _close_fixed_input(directory_fd)
            except BaseException as exc:
                if isinstance(exc, Exception):
                    if close_failure is None:
                        close_failure = exc
                elif close_interrupt is None:
                    close_interrupt = exc
        if failure is None or isinstance(failure, Exception):
            if close_interrupt is not None:
                raise close_interrupt
            if close_failure is not None and (failure is None or not isinstance(failure, Incomplete)):
                raise close_failure
    if non_final_not_found:
        raise Incomplete("fixed_input_read_unproved") from None
    if verified_final_leaf_absent:
        raise _VerifiedFinalLeafAbsent()


def waitid_terminal(pid: int) -> bool:
    """Observe one child with WNOWAIT without releasing its PID."""
    try:
        waitid = ctypes.CDLL(None, use_errno=True).waitid
        waitid.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_int)
        waitid.restype = ctypes.c_int
        options = os.WEXITED | os.WNOHANG | os.WNOWAIT
        info = ctypes.create_string_buffer(256)
        if waitid(os.P_PID, pid, info, options) != 0:
            raise OSError(ctypes.get_errno(), "nonreaping waitid failed")
        signo = ctypes.c_int.from_buffer_copy(info).value
        if signo not in (0, signal.SIGCHLD):
            raise Incomplete("child_waitid_indeterminate")
        return signo == signal.SIGCHLD
    except (AttributeError, OSError, ValueError) as exc:
        raise Incomplete("child_waitid_unavailable") from exc


def leader_terminal(proc: subprocess.Popen[bytes]) -> bool:
    """Observe only this child with WNOWAIT; never release its group ID."""
    terminal = waitid_terminal(proc.pid)
    if terminal:
        proc._status_terminal = True
    return terminal


class ProcessCapabilityBackend:
    """Fixed local operations; tests inject a deterministic behavior backend."""

    def __init__(self) -> None:
        self.wnowait = getattr(os, "WNOWAIT", None)
        self.p_pid = getattr(os, "P_PID", None)
        self.wexited = getattr(os, "WEXITED", None)
        self.wnohang = getattr(os, "WNOHANG", None)
        self.pidfd_open = getattr(os, "pidfd_open", None)
        self.pidfd_send_signal = getattr(signal, "pidfd_send_signal", None)
        self.terminal = waitid_terminal
        self.pipe = os.pipe
        self.close = os.close
        self.read = os.read
        self.write = os.write
        self.fork = getattr(os, "fork", None)
        self.waitpid = os.waitpid
        self.kill = os.kill
        self.read_identity = read_proc_identity
        self.scan_members = scan_group_members


def validate_process_capability(backend: ProcessCapabilityBackend | None = None) -> None:
    """Prove cleanup behavior with one fixed child before the first OpenSSL spawn."""
    global WITNESS_DISPOSITION_UNPROVED
    if backend is None:
        backend = ProcessCapabilityBackend()
    if any(getattr(backend, name, None) is None for name in
           ("wnowait", "p_pid", "wexited", "wnohang", "pidfd_open",
            "pidfd_send_signal", "terminal", "fork")):
        raise Incomplete("process_capability_unavailable")
    read_fd = -1
    write_fd = -1
    probe_fd = -1
    pid = -1
    reaped = False
    waitable = True
    closeout_uncertain = False
    failure: Exception | None = None
    try:
        read_fd, write_fd = backend.pipe()
        pid = backend.fork()
        if pid == 0:
            # The child executes only this fixed internal release-and-exit path.
            child_code = 1
            try:
                for name in os.listdir("/proc/self/fd"):
                    fd = int(name)
                    if fd > 2 and fd != read_fd:
                        try:
                            os.close(fd)
                        except OSError:
                            pass
                if backend.read(read_fd, 1) == b"x":
                    child_code = 0
            except BaseException:
                pass
            os._exit(child_code)
        if pid < 0:
            raise Incomplete("process_capability_unavailable")
        closing_fd, read_fd = read_fd, -1
        try:
            backend.close(closing_fd)
        except BaseException:
            WITNESS_DISPOSITION_UNPROVED = True
            raise
        identity = backend.read_identity(pid)
        if identity is None or identity[1] <= 0:
            raise Incomplete("process_capability_unavailable")
        probe_fd = backend.pidfd_open(pid, 0)
        if backend.read_identity(pid) != identity:
            raise Incomplete("process_capability_unavailable")
        if (pid, identity[1]) not in backend.scan_members(identity[0]):
            raise Incomplete("process_capability_unavailable")
        backend.pidfd_send_signal(probe_fd, 0, None, 0)
        backend.write(write_fd, b"x")
        closing_fd, write_fd = write_fd, -1
        try:
            backend.close(closing_fd)
        except BaseException:
            WITNESS_DISPOSITION_UNPROVED = True
            raise
        deadline = time.monotonic() + CHILD_GRACE
        while time.monotonic() < deadline:
            if backend.terminal(pid):
                break
            time.sleep(0.01)
        else:
            raise Incomplete("process_capability_unavailable")
        waited, status = backend.waitpid(pid, backend.wnohang)
        if waited != pid:
            raise Incomplete("process_capability_unavailable")
        reaped = True
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            raise Incomplete("process_capability_unavailable")
    except ChildProcessError as exc:
        # A broken WNOWAIT may already have released the PID.
        waitable = False
        failure = exc
    except Exception as exc:
        failure = exc
    finally:
        pending_read, pending_write = read_fd, write_fd
        read_fd = write_fd = -1
        for fd in (pending_read, pending_write):
            if fd >= 0:
                try:
                    backend.close(fd)
                except Exception as exc:
                    closeout_uncertain = True
                    WITNESS_DISPOSITION_UNPROVED = True
                    failure = exc
        if pid > 0 and not reaped and waitable:
            try:
                if probe_fd >= 0:
                    backend.pidfd_send_signal(probe_fd, signal.SIGKILL, None, 0)
                else:
                    # Before pidfd acquisition this child is still waitable,
                    # so its numeric PID remains reserved by this parent.
                    backend.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except Exception as exc:
                closeout_uncertain = True
                failure = exc
            while True:
                try:
                    waited, _status = backend.waitpid(pid, backend.wnohang)
                    if waited == pid:
                        reaped = True
                        break
                except ChildProcessError:
                    # A broken nonreaping waitid may already have reaped it.
                    failure = Incomplete("process_capability_unavailable")
                    waitable = False
                    closeout_uncertain = True
                    break
                except Exception as exc:
                    closeout_uncertain = True
                    failure = exc
                time.sleep(0.01)
        if probe_fd >= 0:
            closing_fd, probe_fd = probe_fd, -1
            try:
                backend.close(closing_fd)
            except Exception as exc:
                closeout_uncertain = True
                WITNESS_DISPOSITION_UNPROVED = True
                failure = exc
    if closeout_uncertain or not reaped:
        WITNESS_DISPOSITION_UNPROVED = True
    if failure is not None or not reaped:
        raise Incomplete("process_capability_unavailable") from failure


def read_proc_identity(pid: int) -> tuple[int, int] | None:
    """Return (PGID, starttime) from one bounded, no-follow proc stat read."""
    global WITNESS_DISPOSITION_UNPROVED
    if pid <= 0:
        raise Incomplete("process_identity_unproved")
    try:
        fd = os.open(f"/proc/{pid}/stat",
                     os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise Incomplete("process_identity_unproved") from exc
    try:
        raw = os.read(fd, 4097)
    finally:
        try:
            os.close(fd)
        except BaseException:
            WITNESS_DISPOSITION_UNPROVED = True
            raise
    if len(raw) > 4096:
        raise Incomplete("process_identity_unproved")
    try:
        text = raw.decode("ascii", "strict")
        close = text.rfind(")")
        if close < 0 or not text.startswith(str(pid) + " ("):
            raise ValueError()
        fields = text[close + 2:].split()
        if len(fields) < 20:
            raise ValueError()
        return int(fields[2]), int(fields[19])
    except (UnicodeError, ValueError, IndexError) as exc:
        raise Incomplete("process_identity_unproved") from exc


def scan_group_members(pgid: int) -> list[tuple[int, int]]:
    """Enumerate only process identities currently observed in this group."""
    try:
        names = os.listdir("/proc")
    except OSError as exc:
        raise Incomplete("process_members_unproved") from exc
    members = []
    for name in names:
        if not name.isdecimal():
            continue
        pid = int(name)
        identity = read_proc_identity(pid)
        if identity is not None and identity[0] == pgid:
            members.append((pid, identity[1]))
    return members


def signal_same_group_members(pgid: int, signum: int) -> None:
    """Pin each observed identity before signaling; never signal a bare PID."""
    global WITNESS_DISPOSITION_UNPROVED
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise Incomplete("process_capability_unavailable")
    unproved = False
    for pid, starttime in scan_group_members(pgid):
        try:
            fd = os.pidfd_open(pid, 0)
        except ProcessLookupError:
            continue
        except Exception:
            unproved = True
            continue
        try:
            try:
                identity = read_proc_identity(pid)
            except Exception:
                unproved = True
                continue
            if identity != (pgid, starttime):
                continue
            try:
                signal.pidfd_send_signal(fd, signum, None, 0)
            except ProcessLookupError:
                continue
            except Exception:
                unproved = True
        finally:
            closing_fd, fd = fd, -1
            try:
                os.close(closing_fd)
            except BaseException as exc:
                WITNESS_DISPOSITION_UNPROVED = True
                if not isinstance(exc, Exception):
                    raise
                unproved = True
    if unproved:
        raise Incomplete("process_member_signal_unproved")
def reap_child(proc: subprocess.Popen[bytes]) -> int:
    deadline = time.monotonic() + CHILD_GRACE
    proc._status_reap_started = True
    while time.monotonic() < deadline:
        try:
            pid, status = os.waitpid(proc.pid, os.WNOHANG)
        except (ChildProcessError, OSError) as exc:
            raise Incomplete("child_reap_unproved") from exc
        if pid == proc.pid:
            proc._status_reaped = True
            proc.returncode = os.waitstatus_to_exitcode(status)
            return proc.returncode
        time.sleep(0.01)
    raise Incomplete("child_unreaped")


def prove_group_absent(pgid: int) -> bool:
    """After reap, prove absence by identity scans without numeric signals."""
    uncertain = False
    while True:
        try:
            members = scan_group_members(pgid)
            if not any(read_proc_identity(pid) == (pgid, starttime)
                       for pid, starttime in members):
                return uncertain
        except Exception:
            # An unproved scan remains under the caller's lifecycle lock.
            uncertain = True
        time.sleep(0.05)


def terminate_child(proc: subprocess.Popen[bytes]) -> bool:
    """Own the whole group until every member is gone and leader is reaped."""
    uncertain = False

    def signal_group_or_members(signum: int) -> None:
        nonlocal uncertain
        try:
            os.killpg(proc.pid, signum)
            return
        except ProcessLookupError:
            return
        except PermissionError:
            # A terminal leader alone needs no destructive signal. This is
            # proved by the same identity scan, never by an OS label.
            try:
                if leader_terminal(proc):
                    members = scan_group_members(proc.pid)
                    if members and all(pid == proc.pid for pid, _start in members):
                        return
            except (Incomplete, OSError):
                pass
            uncertain = True
        except BaseException:
            uncertain = True
        try:
            signal_same_group_members(proc.pid, signum)
        except BaseException:
            # The unresolved-cleanup hold retries; it may never return.
            uncertain = True

    def resolved_with_leader_reserved() -> bool:
        nonlocal uncertain
        try:
            if not leader_terminal(proc):
                return False
            members = scan_group_members(proc.pid)
        except Exception:
            uncertain = True
            return False
        return bool(members) and all(pid == proc.pid for pid, _start in members)

    def wait_bounded(seconds: float) -> bool:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if resolved_with_leader_reserved():
                return True
            time.sleep(0.01)
        return resolved_with_leader_reserved()

    # A known proc.returncode does not release the WNOWAIT reservation.
    grace = min(CHILD_GRACE, 0.05) if getattr(proc, "_status_terminal", False) else CHILD_GRACE
    signal_group_or_members(signal.SIGTERM)
    if not wait_bounded(grace):
        signal_group_or_members(signal.SIGKILL)
        wait_bounded(grace)
    # Persistent group and member signaling failure is an exceptional
    # unresolved-cleanup hold. It retains the caller's lock and never returns
    # while a same-group descendant can remain live.
    while not resolved_with_leader_reserved():
        signal_group_or_members(signal.SIGKILL)
        time.sleep(0.05)
    while not getattr(proc, "_status_reaped", False):
        try:
            reap_child(proc)
        except Incomplete:
            uncertain = True
            time.sleep(0.01)
    uncertain = prove_group_absent(proc.pid) or uncertain
    return uncertain


def own_child_until_proved(proc: subprocess.Popen[bytes]) -> bool:
    """Never release a spawned child or its lock on an ordinary cleanup fault."""
    uncertain = False
    backoff = threading.Event()
    while True:
        try:
            if getattr(proc, "_status_reaped", False):
                # The numeric PGID may have been reused; never signal it now.
                uncertain = prove_group_absent(proc.pid) or uncertain
            else:
                uncertain = terminate_child(proc) or uncertain
            return uncertain
        except Exception:
            uncertain = True
            backoff.wait(0.05)


PROCESS_CAPABILITY_READY = False


def run_fixed(argv: tuple[str, ...], input_bytes: bytes | None = None,
              anchor_bytes: bytes | None = None) -> tuple[int, bytes, bytes]:
    global WITNESS_DISPOSITION_UNPROVED
    check_signal()
    if not argv or argv[0] != OPENSSL or (input_bytes is not None and len(input_bytes) > MAX_INPUT):
        raise Incomplete("invalid_fixed_command")
    if anchor_bytes is not None:
        if input_bytes is None or len(anchor_bytes) > MAX_INPUT or argv.count(TRUST_FD_OPERAND) != 1:
            raise Incomplete("invalid_fixed_command")
    elif TRUST_FD_OPERAND in argv:
        raise Incomplete("invalid_fixed_command")
    if not PROCESS_CAPABILITY_READY:
        raise Incomplete("process_capability_unavailable")

    anchor_read = -1
    anchor_write = -1
    if anchor_bytes is not None:
        try:
            anchor_read, anchor_write = os.pipe()
        except OSError as exc:
            raise Incomplete("child_pipe_unproved") from exc
        argv = tuple(f"/dev/fd/{anchor_read}" if arg == TRUST_FD_OPERAND else arg for arg in argv)
    proc: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    result: tuple[int, bytes, bytes] | None = None
    failure: BaseException | None = None
    resource_error = False
    cleanup_uncertain = False
    pending_streams = []

    def close_stream_once(stream: object) -> None:
        nonlocal resource_error
        global WITNESS_DISPOSITION_UNPROVED
        for index, owned in enumerate(pending_streams):
            if owned is stream:
                del pending_streams[index]
                try:
                    stream.close()
                except BaseException:
                    resource_error = True
                    WITNESS_DISPOSITION_UNPROVED = True
                    raise
                return
        resource_error = True
        WITNESS_DISPOSITION_UNPROVED = True
        raise Incomplete("child_resource_unproved")

    try:
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False,
                                close_fds=True, pass_fds=(anchor_read,) if anchor_read >= 0 else (),
                                start_new_session=True, env=CHILD_ENV)
        pending_streams = [stream for stream in (proc.stdin, proc.stdout, proc.stderr) if stream is not None]
        # From here through reap, this function is the sole cleanup owner.
        try:
            if anchor_read >= 0:
                closing_fd, anchor_read = anchor_read, -1
                try:
                    os.close(closing_fd)
                except BaseException:
                    WITNESS_DISPOSITION_UNPROVED = True
                    raise
            selector = selectors.DefaultSelector()
            out = bytearray()
            err = bytearray()
            assert proc.stdout is not None and proc.stderr is not None
            for stream, label in ((proc.stdout, "out"), (proc.stderr, "err")):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, ("read", label))
            if proc.stdin is not None:
                os.set_blocking(proc.stdin.fileno(), False)
                selector.register(proc.stdin, selectors.EVENT_WRITE, ("write", "stdin"))
            if anchor_write >= 0:
                os.set_blocking(anchor_write, False)
                selector.register(anchor_write, selectors.EVENT_WRITE, ("write", "anchor"))
            payloads = {"stdin": input_bytes or b"", "anchor": anchor_bytes or b""}
            offsets = {"stdin": 0, "anchor": 0}
            deadline = time.monotonic() + CHILD_TIMEOUT
            while selector.get_map() or not leader_terminal(proc):
                if LATCHED_SIGNAL is not None:
                    raise Incomplete("child_interrupted")
                if time.monotonic() > deadline:
                    raise Incomplete("child_timeout")
                for key, _mask in selector.select(0.05):
                    stream = key.fileobj
                    operation, label = key.data
                    if operation == "write":
                        fd = proc.stdin.fileno() if label == "stdin" and proc.stdin is not None else int(stream)
                        payload = payloads[label]
                        try:
                            sent = os.write(fd, payload[offsets[label]:offsets[label] + CHUNK]) if offsets[label] < len(payload) else 0
                        except BrokenPipeError:
                            sent = 0
                        offsets[label] += sent
                        if sent == 0 or offsets[label] >= len(payload):
                            selector.unregister(stream)
                            if label == "stdin" and proc.stdin is not None:
                                close_stream_once(proc.stdin)
                            elif label == "anchor" and anchor_write >= 0:
                                closing_fd, anchor_write = anchor_write, -1
                                try:
                                    os.close(closing_fd)
                                except BaseException:
                                    WITNESS_DISPOSITION_UNPROVED = True
                                    raise
                    else:
                        try:
                            chunk = os.read(stream.fileno(), CHUNK)
                        except BlockingIOError:
                            continue
                        if not chunk:
                            selector.unregister(stream)
                            close_stream_once(stream)
                            continue
                        target = out if label == "out" else err
                        target.extend(chunk)
                        if len(target) > (MAX_OUTPUT if label == "out" else MAX_ERROR):
                            raise Incomplete("child_output_overflow")
            cleanup_uncertain = own_child_until_proved(proc)
            code = proc.returncode
            check_signal()
            result = code, bytes(out), bytes(err)
        except BaseException as exc:
            failure = exc
            cleanup_uncertain = own_child_until_proved(proc) or cleanup_uncertain
        finally:
            if selector is not None:
                try:
                    selector.close()
                except BaseException:
                    resource_error = True
                    WITNESS_DISPOSITION_UNPROVED = True
            for stream in tuple(pending_streams):
                try:
                    close_stream_once(stream)
                except BaseException:
                    pass
    except BaseException as exc:
        if proc is None:
            failure = Incomplete("child_spawn_unproved")
            failure.__cause__ = exc
        else:
            failure = Incomplete("child_run_unproved")
            failure.__cause__ = exc
            cleanup_uncertain = own_child_until_proved(proc) or cleanup_uncertain
    finally:
        pending_read, pending_write = anchor_read, anchor_write
        anchor_read = anchor_write = -1
        for fd in (pending_read, pending_write):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    resource_error = True
                    WITNESS_DISPOSITION_UNPROVED = True
    if resource_error or cleanup_uncertain:
        WITNESS_DISPOSITION_UNPROVED = True
    if failure is not None:
        if isinstance(failure, Incomplete):
            raise failure
        raise Incomplete("child_run_unproved") from failure
    if resource_error or cleanup_uncertain or result is None:
        raise Incomplete("child_resource_unproved")
    return result

def nested(payload: object, keys: tuple[str, ...]) -> object:
    value = payload
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def fixed_url(value: object, port: int) -> bool:
    if not isinstance(value, str):
        return False
    try:
        url = urlparse(value)
        return (url.scheme == "https" and url.hostname in ("127.0.0.1", "localhost") and
                url.port == port and url.username is None and url.password is None and
                url.path in ("", "/") and not url.query and not url.fragment)
    except ValueError:
        return False


def _config_structure_valid(payload: dict[str, object]) -> bool:
    if "tls" in payload:
        tls = payload["tls"]
        if not isinstance(tls, dict) or any(key in tls and not isinstance(tls[key], str)
                                                 for key in ("cert_file", "key_file", "client_ca_file")):
            return False
        if any(key in tls and not canonical_material_path(tls[key])
               for key in ("cert_file", "key_file", "client_ca_file")):
            return False
    if "dependencies" in payload:
        dependencies = payload["dependencies"]
        if not isinstance(dependencies, dict):
            return False
        for dependency in dependencies.values():
            if not isinstance(dependency, dict) or any(key in dependency and not isinstance(dependency[key], str)
                                                      for key in ("client_cert_file", "client_key_file", "root_ca_file")):
                return False
            if any(key in dependency and not canonical_material_path(dependency[key])
                   for key in ("client_cert_file", "client_key_file", "root_ca_file")):
                return False
    return True


def read_config(name: str, required: bool) -> tuple[dict[str, object], str]:
    try:
        raw = open_fixed_regular(CONFIG[name], MAX_INPUT)
    except _VerifiedFinalLeafAbsent:
        return {}, "config_missing" if required else "absent"
    except OSError as exc:
        raise Incomplete("config_read_unproved") from exc
    assert raw is not None
    try:
        decoded = strict_json(raw)
        if not isinstance(decoded, dict) or not _config_structure_valid(decoded):
            raise ValueError()
        return decoded, "pass"
    except (UnicodeError, ValueError, Incomplete):
        return {}, "config_malformed" if required else "related_config_malformed"


def collect_topology(scope: dict[str, object]) -> list[dict[str, str]]:
    required = scope["required_config"]
    payloads = {name: read_config(name, name in required) for name in CONFIG}
    checks: list[dict[str, str]] = []
    for name in required:
        checks.append({"id": name + "_config", "status": "pass" if payloads[name][1] == "pass" else "fail", "code": payloads[name][1]})
    related = next(name for name in CONFIG if name not in required)
    related_state = payloads[related][1]
    checks.append({"id": related + "_related_config", "status": "fail" if related_state == "related_config_malformed" else "pass",
                   "code": related_state})
    for label, config_name, keys, expected in scope["bindings"]:
        actual = nested(payloads[config_name][0], keys)
        ok = actual == expected
        checks.append({"id": label, "status": "pass" if ok else "fail", "code": "pass" if ok else "topology_mismatch"})
    for label, config_name, keys, port in scope["urls"]:
        ok = fixed_url(nested(payloads[config_name][0], keys), port)
        checks.append({"id": label, "status": "pass" if ok else "fail", "code": "pass" if ok else "topology_mismatch"})
    covered = {item[1] for item in scope["certs"]} | {item[2] for item in scope["pairs"]}
    unrelated = ("ags", "es", "egs") if scope["route"] == "es-service-tls-status" else ("ars", "ags", "es")
    service_disjoint = all(
        not isinstance(value := nested(payloads[name][0], ("tls", field)), str) or value not in covered
        for name in unrelated for field in ("cert_file", "key_file", "client_ca_file")
    )
    malformed = next(("related_config_malformed" if payloads[name][1] == "config_malformed" else payloads[name][1]
                      for name in unrelated if payloads[name][1] in ("config_missing", "config_malformed", "related_config_malformed")), None)
    service_code = malformed or ("pass" if service_disjoint else "topology_overlap")
    checks.append({"id": "related_service_tls_disjoint", "status": "pass" if service_code == "pass" else "fail", "code": service_code})
    if scope["route"] == "es-governance-tls-status":
        ags = payloads["ags"][0]
        deps = ags.get("dependencies") if isinstance(ags, dict) else None
        ok = not isinstance(deps, dict) or "execution_governance" not in deps
        ags_state = payloads["ags"][1]
        ags_code = ("related_config_malformed" if ags_state == "config_malformed" else ags_state
                    if ags_state != "pass" else "pass" if ok else "ags_scope_present")
        checks.append({"id": "ags_governance_exclusion", "status": "pass" if ags_code == "pass" else "fail", "code": ags_code})
        dependency_disjoint = True
        for name, (payload, _) in payloads.items():
            dependencies = payload.get("dependencies") if isinstance(payload, dict) else None
            if not isinstance(dependencies, dict):
                continue
            for dependency_name, dependency in dependencies.items():
                if name == "es" and dependency_name == "execution_governance":
                    continue
                if not isinstance(dependency, dict):
                    continue
                for field in ("client_cert_file", "client_key_file", "root_ca_file"):
                    value = dependency.get(field)
                    if isinstance(value, str) and value in covered:
                        dependency_disjoint = False
        malformed_dependency = next(("related_config_malformed" if state == "config_malformed" else state
                                     for _name, (_payload, state) in payloads.items()
                                     if state in ("config_missing", "config_malformed", "related_config_malformed")), None)
        dependency_code = malformed_dependency or ("pass" if dependency_disjoint else "topology_overlap")
        checks.append({"id": "related_dependency_tls_disjoint", "status": "pass" if dependency_code == "pass" else "fail",
                       "code": dependency_code})
    return checks


def parse_openssl_time(value: str) -> str | None:
    if re.fullmatch(r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2} [0-9]{4} GMT", value) is None:
        return None
    try:
        parsed = parsedate_to_datetime(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError):
        return None


LIBRESSL_PEM_ERROR_PATH = b"/AppleInternal/Library/BuildRoots/4~CVR0ugD7d_x9KkNiDhb6ZUdowAfhsgliSKtR7QU/Library/Caches/com.apple.xbs/TemporaryDirectory.kapob0/Sources/libressl/libressl-3.3/crypto/pem/pem_lib.c:694"


def _known_malformed_pem(code: int, output: bytes, error: bytes, kind: str) -> bool:
    if code != 1 or output != b"" or kind not in ("certificate", "key"):
        return False
    target3013 = (b"Could not read certificate from /dev/stdin\nUnable to load certificate\n"
                  if kind == "certificate" else b"Could not read key from /dev/stdin\n")
    if error == target3013:
        return True
    expected = b"TRUSTED CERTIFICATE" if kind == "certificate" else b"ANY PRIVATE KEY"
    first = b"unable to load certificate\n" if kind == "certificate" else b"unable to load key\n"
    pattern = (re.escape(first) + rb"[0-9]+:error:09FFF06C:PEM routines:CRYPTO_internal:no start line:" +
               re.escape(LIBRESSL_PEM_ERROR_PATH) + rb":Expecting: " + re.escape(expected) + rb"\n")
    return re.fullmatch(pattern, error) is not None


def _valid_der_sequence(data: bytes) -> bool:
    if len(data) < 64 or data[0] != 0x30:
        return False
    first = data[1]
    if first < 0x80:
        return len(data) == 2 + first
    length_octets = first & 0x7f
    if not 1 <= length_octets <= 4 or len(data) < 2 + length_octets or data[2] == 0:
        return False
    payload_length = int.from_bytes(data[2:2 + length_octets], "big")
    return payload_length >= 128 and len(data) == 2 + length_octets + payload_length


def _valid_x509_text(output: bytes) -> bool:
    if not output.startswith(b"Certificate:\n    Data:\n") or b"\r" in output or b"\x00" in output:
        return False
    row = rb"[0-9a-f]{2}(?::[0-9a-f]{2})*:?(?:\n|\Z)"
    legacy_tail = rb"(?: {9}" + row + rb")+"
    openssl3_tail = rb"    Signature Value:\n(?: {8}" + row + rb")+"
    pattern = rb"\n    Signature Algorithm: [A-Za-z0-9-]+\n(?:" + legacy_tail + rb"|" + openssl3_tail + rb")\Z"
    return re.search(pattern, output) is not None


SINGLE_TRUST_ANCHOR = re.compile(
    rb"[ \t\r\n\v\f]*-----BEGIN CERTIFICATE-----\r?\n(?:[A-Za-z0-9+/=]+\r?\n)+"
    rb"-----END CERTIFICATE-----[ \t\r\n\v\f]*"
)


def cert_metadata(path: str, observed_at: dt.datetime | None = None,
                  single_trust_anchor: bool = False) -> tuple[dict[str, object], bytes | None]:
    empty: dict[str, object] = {"not_before": None, "not_after": None, "expired": None, "not_yet_valid": None,
                                 "sha256": None, "fingerprint_sha256": None, "public_key_sha256": None,
                                 "subject_sha256": None, "issuer_sha256": None}
    try:
        raw = open_fixed_regular(path, MAX_INPUT)
    except _VerifiedFinalLeafAbsent:
        return empty | {"status": "fail", "code": "certificate_missing"}, None
    except OSError as exc:
        raise Incomplete("certificate_read_unproved") from exc
    assert raw is not None
    if single_trust_anchor and SINGLE_TRUST_ANCHOR.fullmatch(raw) is None:
        return empty | {"status": "fail", "code": "trust_anchor_count_mismatch"}, None
    code, output, error = run_fixed((OPENSSL, "x509", "-in", "/dev/stdin", "-noout", "-subject", "-issuer", "-dates", "-fingerprint", "-sha256", "-nameopt", "RFC2253"), raw)
    if code != 0:
        if _known_malformed_pem(code, output, error, "certificate"):
            return empty | {"status": "fail", "code": "certificate_malformed"}, None
        raise Incomplete("unexpected_openssl_grammar")
    try:
        if error or not output.endswith(b"\n"):
            raise ValueError()
        lines = output.decode("utf-8", "strict").split("\n")[:-1]
        if len(lines) != 5:
            raise ValueError()
        keys = ("subject", "issuer", "notBefore", "notAfter")
        fields = {}
        for line, key in zip(lines[:4], keys):
            if not line.startswith(key + "=") or not line[len(key) + 1:]:
                raise ValueError()
            fields[key] = line[len(key) + 1:]
        if not re.fullmatch(r"(?:sha256 Fingerprint|SHA256 Fingerprint)=(?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}", lines[4]):
            raise ValueError()
        fingerprint = lines[4].split("=", 1)[1].replace(":", "").lower()
        before = parse_openssl_time(fields["notBefore"])
        after = parse_openssl_time(fields["notAfter"])
        if not before or not after or not HEX64.fullmatch(fingerprint):
            raise ValueError()
        before_dt = dt.datetime.strptime(before, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
        after_dt = dt.datetime.strptime(after, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    except (UnicodeError, ValueError, KeyError) as exc:
        raise Incomplete("unexpected_openssl_grammar") from exc
    pub_code, public, pub_error = run_fixed((OPENSSL, "x509", "-in", "/dev/stdin", "-pubkey", "-noout"), raw)
    if pub_code != 0 or pub_error or re.fullmatch(rb"-----BEGIN PUBLIC KEY-----\n(?:[A-Za-z0-9+/=]{1,64}\n)+-----END PUBLIC KEY-----\n", public) is None:
        raise Incomplete("unexpected_openssl_grammar")
    der_code, der, der_error = run_fixed((OPENSSL, "pkey", "-pubin", "-outform", "DER"), public)
    if der_code != 0 or der_error or not _valid_der_sequence(der):
        raise Incomplete("unexpected_openssl_grammar")
    checked = observed_at or dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    expired = checked > after_dt
    not_yet = checked < before_dt
    return {
        "not_before": before, "not_after": after, "expired": expired, "not_yet_valid": not_yet,
        "sha256": hashlib.sha256(raw).hexdigest(), "fingerprint_sha256": fingerprint,
        "public_key_sha256": hashlib.sha256(der).hexdigest(),
        "subject_sha256": hashlib.sha256(fields["subject"].encode()).hexdigest(),
        "issuer_sha256": hashlib.sha256(fields["issuer"].encode()).hexdigest(),
        "status": "fail" if expired or not_yet else "pass",
        "code": "certificate_expired" if expired else "certificate_not_yet_valid" if not_yet else "pass",
    }, raw


def cert_role(item: tuple[str, str, str, str | None, str | None], observed_at: dt.datetime | None = None) -> tuple[dict[str, object], bytes | None]:
    label, path, role, hostname, eku = item
    meta, raw = cert_metadata(path, observed_at, role == "ca")
    record = {"label": label, "path": path, "role": role, **meta, "san_match": None, "eku_match": None}
    if raw is not None and role != "ca":
        code, output, error = run_fixed((OPENSSL, "x509", "-in", "/dev/stdin", "-noout", "-text"), raw)
        if code != 0:
            raise Incomplete("unexpected_openssl_grammar")
        if error or not _valid_x509_text(output):
            raise Incomplete("unexpected_openssl_grammar")
        text = output.decode("utf-8", "strict")
        if hostname is not None:
            san = re.search(r"X509v3 Subject Alternative Name:\s*\n\s*([^\n]+)", text)
            if san is None:
                if record["status"] == "pass":
                    record["status"], record["code"] = "fail", "san_missing"
            else:
                names = re.findall(r"(?:^|[,\s])DNS:([A-Za-z0-9.-]+)(?=$|[,\s])", san.group(1))
                record["san_match"] = hostname in names
                if not record["san_match"] and record["status"] == "pass":
                    record["status"], record["code"] = "fail", "san_mismatch"
        extension = re.search(r"X509v3 Extended Key Usage:\s*\n\s*([^\n]+)", text)
        if extension is None:
            if record["status"] == "pass":
                record["status"], record["code"] = "fail", "eku_missing"
        else:
            expected = "TLS Web Server Authentication" if eku == "server" else "TLS Web Client Authentication"
            record["eku_match"] = expected in [part.strip() for part in extension.group(1).split(",")]
            if not record["eku_match"] and record["status"] == "pass":
                record["status"], record["code"] = "fail", "eku_mismatch"
    return record, raw


def key_pair(label: str, cert: dict[str, object], key_path: str) -> dict[str, object]:
    if cert["public_key_sha256"] is None:
        return {"label": label, "status": "fail", "code": "certificate_unavailable", "matches": False}
    try:
        raw = open_fixed_regular(key_path, MAX_INPUT)
    except _VerifiedFinalLeafAbsent:
        return {"label": label, "status": "fail", "code": "key_missing", "matches": False}
    except OSError as exc:
        raise Incomplete("key_read_unproved") from exc
    assert raw is not None
    code, der, error = run_fixed((OPENSSL, "pkey", "-in", "/dev/stdin", "-pubout", "-outform", "DER"), raw)
    if code != 0:
        if _known_malformed_pem(code, der, error, "key"):
            return {"label": label, "status": "fail", "code": "key_malformed", "matches": False}
        raise Incomplete("unexpected_openssl_grammar")
    if error or not _valid_der_sequence(der):
        raise Incomplete("unexpected_openssl_grammar")
    matches = hashlib.sha256(der).hexdigest() == cert["public_key_sha256"]
    return {"label": label, "status": "pass" if matches else "fail", "code": "pass" if matches else "key_mismatch", "matches": matches}


def verify_chain(label: str, ca: dict[str, object], cert: dict[str, object], ca_bytes: bytes | None, cert_bytes: bytes | None, purpose: str, hostname: str) -> dict[str, object]:
    if ca["sha256"] is None or cert["sha256"] is None:
        return {"label": label, "status": "fail", "code": "certificate_unavailable", "purpose": purpose, "hostname": hostname}
    if ca_bytes is None or cert_bytes is None or purpose not in ("sslclient", "sslserver") or bool(hostname) != (purpose == "sslserver"):
        raise Incomplete("invalid_verification_inputs")
    argv = [OPENSSL, "verify", "-trusted", TRUST_FD_OPERAND, "-purpose", purpose]
    if hostname:
        argv += ["-verify_hostname", hostname]
    argv += ["/dev/stdin"]
    code, output, error = run_fixed(tuple(argv), cert_bytes, ca_bytes)
    if code == 0:
        if output != b"/dev/stdin: OK\n" or error:
            raise Incomplete("unexpected_openssl_grammar")
    else:
        operand = rb"/dev/stdin"
        wrong_ca = (rb"CN = [A-Za-z0-9.-]+\nerror 20 at 0 depth lookup:unable to get local issuer certificate\n" +
                    operand + rb": verification failed: 20 \(unable to get local issuer certificate\)\n")
        expired = ((rb"CN = Remote Alpha Internal Runtime Root CA\nerror 10 at 1 depth lookup:certificate has expired\n" * 3) +
                   rb"CN = [A-Za-z0-9.-]+\nerror 10 at 0 depth lookup:certificate has expired\n" +
                   operand + rb": verification failed: 10 \(certificate has expired\)\n")
        not_yet = (rb"CN = [A-Za-z0-9.-]+\nerror 9 at 0 depth lookup:certificate is not yet valid\n" +
                   operand + rb": verification failed: 9 \(certificate is not yet valid\)\n")
        openssl3 = rb"CN=[A-Za-z0-9.-]+\nerror (?:20 at 0 depth lookup: unable to get local issuer certificate|62 at 0 depth lookup: hostname mismatch)\nerror /dev/stdin: verification failed\n"
        admitted_libressl = not error and any(re.fullmatch(pattern, output) is not None for pattern in (wrong_ca, expired, not_yet))
        admitted_openssl3 = not output and re.fullmatch(openssl3, error) is not None
        if admitted_openssl3 and not hostname and b"error 62 " in error:
            admitted_openssl3 = False
        target3013_end = rb"error /dev/stdin: verification failed\n"
        target3013_leaf = rb"CN = [A-Za-z0-9.-]+\nerror "
        target3013_patterns = (
            target3013_leaf + rb"20 at 0 depth lookup: unable to get local issuer certificate\n" + target3013_end,
            target3013_leaf + rb"10 at 0 depth lookup: certificate has expired\n" + target3013_end,
            target3013_leaf + rb"9 at 0 depth lookup: certificate is not yet valid\n" + target3013_end,
            rb"CN = Remote Alpha Internal Runtime Root CA\nerror 10 at 1 depth lookup: certificate has expired\n" + target3013_end,
        )
        if purpose == "sslclient":
            target3013_patterns += (target3013_leaf + rb"26 at 0 depth lookup: unsuitable certificate purpose\n" + target3013_end,)
        if purpose == "sslserver" and hostname:
            target3013_patterns += (target3013_leaf + rb"62 at 0 depth lookup: hostname mismatch\n" + target3013_end,)
        admitted_target3013 = not output and any(re.fullmatch(pattern, error) is not None for pattern in target3013_patterns)
        if code != 2 or not (admitted_libressl or admitted_openssl3 or admitted_target3013):
            raise Incomplete("unexpected_openssl_grammar")
    return {"label": label, "status": "pass" if code == 0 else "fail", "code": "pass" if code == 0 else "chain_failed", "purpose": purpose, "hostname": hostname}


def collect(scope_name: str, previous_generation: str | None = None) -> dict[str, object]:
    scope = SCOPES[scope_name]
    observed_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    topology = collect_topology(scope)
    observations = [cert_role(item, observed_at) for item in scope["certs"]]
    certs = [record for record, _raw in observations]
    by_label = {record["label"]: record for record in certs}
    cert_bytes = {item[0]: raw for item, (_record, raw) in zip(scope["certs"], observations)}
    pairs = [key_pair(label, by_label[cert_label], key_path) for label, cert_label, key_path in scope["pairs"]]
    verification = [verify_chain(label, by_label[ca], by_label[cert], cert_bytes[ca], cert_bytes[cert], purpose, hostname)
                    for label, ca, cert, purpose, hostname in scope["verify"]]
    blockers = sorted({str(item["code"]) for item in topology + certs + pairs + verification if item["status"] != "pass"})
    ok = not blockers
    generation = secrets.token_hex(16)
    while generation == previous_generation:
        generation = secrets.token_hex(16)
    return {
        "schema_version": scope["schema"], "collector_contract": CONTRACT, "finalized": True,
        "generation": generation, "scope": scope_name, "route": scope["route"],
        "checked_at": observed_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "topology": topology, "certificates": certs, "key_pairs": pairs,
        "verification": verification, "blockers": blockers,
        "result": {"status": "pass" if ok else "fail", "ok": ok},
        "non_effects": {name: False for name in ("renewal_attempted", "backup_created", "material_generated", "material_installed", "service_restart_attempted", "post_renewal_probe_attempted")},
        "security": {name: False for name in ("private_key_bytes_included", "private_key_digest_included", "raw_openssl_output_included", "raw_config_included")},
    }


def expected_topology_ids(scope: dict[str, object]) -> list[str]:
    ids = [name + "_config" for name in scope["required_config"]]
    ids += [next(name for name in CONFIG if name not in scope["required_config"]) + "_related_config"]
    ids += [item[0] for item in scope["bindings"]]
    ids += [item[0] for item in scope["urls"]]
    ids += ["related_service_tls_disjoint"]
    if scope["route"] == "es-governance-tls-status":
        ids += ["ags_governance_exclusion", "related_dependency_tls_disjoint"]
    return ids


TOPOLOGY_FAILURES = {"config_missing", "config_malformed", "related_config_malformed", "topology_mismatch", "topology_overlap", "ags_scope_present"}
CERTIFICATE_FAILURES = {"certificate_missing", "certificate_malformed", "trust_anchor_count_mismatch", "certificate_expired", "certificate_not_yet_valid", "san_missing", "san_mismatch", "eku_missing", "eku_mismatch"}
PAIR_FAILURES = {"certificate_unavailable", "key_missing", "key_malformed", "key_mismatch"}
VERIFICATION_FAILURES = {"certificate_unavailable", "chain_failed"}


def _check_status_code(record: dict[str, object], failures: set[str]) -> None:
    status, code = record["status"], record["code"]
    if not isinstance(status, str) or not isinstance(code, str) or not (
        (status == "pass" and code == "pass") or (status == "fail" and code in failures)
    ):
        raise Incomplete("record_code")


def _valid_optional_hash(value: object) -> bool:
    return value is None or isinstance(value, str) and HEX64.fullmatch(value) is not None


def _record_timestamp(value: object) -> dt.datetime | None:
    if not isinstance(value, str) or TIMESTAMP.fullmatch(value) is None:
        return None
    try:
        return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None


def validate_document(document: object, scope_name: str, previous_generation: str | None = None, now: dt.datetime | None = None) -> None:
    if scope_name not in SCOPES:
        raise Incomplete("record_scope")
    if not isinstance(document, dict) or set(document) != {"schema_version", "collector_contract", "finalized", "generation", "scope", "route", "checked_at", "topology", "certificates", "key_pairs", "verification", "blockers", "result", "non_effects", "security"}:
        raise Incomplete("record_shape")
    scope = SCOPES[scope_name]
    if (document["schema_version"] != scope["schema"] or document["collector_contract"] != CONTRACT or
            document["finalized"] is not True or document["scope"] != scope_name or document["route"] != scope["route"]):
        raise Incomplete("record_identity")
    generation = document["generation"]
    if not isinstance(generation, str) or not HEX32.fullmatch(generation) or generation == previous_generation:
        raise Incomplete("record_generation")
    checked = _record_timestamp(document["checked_at"])
    if checked is None:
        raise Incomplete("record_timestamp")
    current = now or dt.datetime.now(dt.timezone.utc)
    if current - checked > dt.timedelta(minutes=5) or checked - current > dt.timedelta(seconds=30):
        raise Incomplete("record_freshness")
    for key, expected in (("topology", expected_topology_ids(scope)), ("certificates", [x[0] for x in scope["certs"]]),
                          ("key_pairs", [x[0] for x in scope["pairs"]]), ("verification", [x[0] for x in scope["verify"]])):
        value = document[key]
        if not isinstance(value, list) or [x.get("id" if key == "topology" else "label") for x in value if isinstance(x, dict)] != expected or len(value) != len(expected):
            raise Incomplete("record_roles")
    all_records = document["topology"] + document["certificates"] + document["key_pairs"] + document["verification"]
    if any(not isinstance(x, dict) or x.get("status") not in ("pass", "fail") for x in all_records):
        raise Incomplete("record_status")
    topology_by_id = {record["id"]: record for record in document["topology"]}
    required = scope["required_config"]
    related = next(name for name in CONFIG if name not in required)
    related_id = related + "_related_config"
    for record in document["topology"]:
        if set(record) != {"id", "status", "code"}:
            raise Incomplete("record_topology_shape")
        identifier, status, code = record["id"], record["status"], record["code"]
        if not isinstance(code, str):
            raise Incomplete("record_topology_code")
        if identifier == related_id:
            allowed = {("pass", "pass"), ("pass", "absent"), ("fail", "related_config_malformed")}
        elif identifier in {name + "_config" for name in required}:
            allowed = {("pass", "pass"), ("fail", "config_missing"), ("fail", "config_malformed")}
        elif identifier.endswith("_disjoint"):
            allowed = {("pass", "pass"), ("fail", "topology_overlap"), ("fail", "config_missing"),
                       ("fail", "related_config_malformed")}
        elif identifier == "ags_governance_exclusion":
            allowed = {("pass", "pass"), ("fail", "ags_scope_present"), ("fail", "config_missing"),
                       ("fail", "related_config_malformed")}
        else:
            allowed = {("pass", "pass"), ("fail", "topology_mismatch")}
        if (status, code) not in allowed:
            raise Incomplete("record_topology_code")
    for name in required:
        if topology_by_id[name + "_config"]["status"] != "pass":
            for label, config_name, _keys, _expected in scope["bindings"]:
                if config_name == name and topology_by_id[label]["code"] != "topology_mismatch":
                    raise Incomplete("record_topology_relationship")
            for label, config_name, _keys, _port in scope["urls"]:
                if config_name == name and topology_by_id[label]["code"] != "topology_mismatch":
                    raise Incomplete("record_topology_relationship")
    unrelated = ("ags", "es", "egs") if scope["route"] == "es-service-tls-status" else ("ars", "ags", "es")
    def unavailable(names: tuple[str, ...]) -> str | None:
        for name in names:
            code = topology_by_id[related_id]["code"] if name == related else topology_by_id[name + "_config"]["code"]
            if code == "config_missing":
                return "config_missing"
            if code in ("config_malformed", "related_config_malformed"):
                return "related_config_malformed"
        return None
    service_unavailable = unavailable(unrelated)
    service_code = topology_by_id["related_service_tls_disjoint"]["code"]
    if (service_unavailable is not None and service_code != service_unavailable or
            service_unavailable is None and service_code in ("config_missing", "related_config_malformed")):
        raise Incomplete("record_topology_relationship")
    if scope["route"] == "es-governance-tls-status":
        ags_unavailable = unavailable(("ags",))
        ags_code = topology_by_id["ags_governance_exclusion"]["code"]
        if (ags_unavailable is not None and ags_code != ags_unavailable or
                ags_unavailable is None and ags_code in ("config_missing", "related_config_malformed")):
            raise Incomplete("record_topology_relationship")
        dependency_unavailable = unavailable(tuple(CONFIG))
        dependency_code = topology_by_id["related_dependency_tls_disjoint"]["code"]
        if (dependency_unavailable is not None and dependency_code != dependency_unavailable or
                dependency_unavailable is None and dependency_code in ("config_missing", "related_config_malformed")):
            raise Incomplete("record_topology_relationship")
    for record, spec in zip(document["certificates"], scope["certs"]):
        if set(record) != {"label", "path", "role", "status", "code", "not_before", "not_after", "expired", "not_yet_valid", "sha256", "fingerprint_sha256", "public_key_sha256", "subject_sha256", "issuer_sha256", "san_match", "eku_match"} or (record["label"], record["path"], record["role"]) != spec[:3]:
            raise Incomplete("record_certificate_shape")
        _check_status_code(record, CERTIFICATE_FAILURES)
        if any(not _valid_optional_hash(record[key]) for key in ("sha256", "fingerprint_sha256", "public_key_sha256", "subject_sha256", "issuer_sha256")):
            raise Incomplete("record_certificate_hash")
        if any(record[key] is not None and type(record[key]) is not bool for key in ("expired", "not_yet_valid", "san_match", "eku_match")):
            raise Incomplete("record_certificate_flag")
        if (spec[2] == "ca" and (record["san_match"] is not None or record["eku_match"] is not None)) or (spec[2] == "client" and record["san_match"] is not None):
            raise Incomplete("record_certificate_role_flag")
        if record["code"] == "trust_anchor_count_mismatch" and spec[2] != "ca":
            raise Incomplete("record_trust_anchor_role")
        if record["code"] in ("certificate_missing", "certificate_malformed", "trust_anchor_count_mismatch"):
            if any(record[key] is not None for key in ("not_before", "not_after", "expired", "not_yet_valid", "sha256", "fingerprint_sha256", "public_key_sha256", "subject_sha256", "issuer_sha256", "san_match", "eku_match")):
                raise Incomplete("record_certificate_absence")
            continue
        before = _record_timestamp(record["not_before"])
        after = _record_timestamp(record["not_after"])
        if before is None or after is None or before > after:
            raise Incomplete("record_certificate_time")
        if any(record[key] is None for key in ("sha256", "fingerprint_sha256", "public_key_sha256", "subject_sha256", "issuer_sha256")):
            raise Incomplete("record_certificate_metadata")
        expired = checked > after
        not_yet = checked < before
        if record["expired"] is not expired or record["not_yet_valid"] is not not_yet:
            raise Incomplete("record_certificate_validity")
        role = spec[2]
        expected_code = ("certificate_expired" if expired else "certificate_not_yet_valid" if not_yet
                         else "san_missing" if role == "server" and record["san_match"] is None
                         else "san_mismatch" if role == "server" and record["san_match"] is False
                         else "eku_missing" if role != "ca" and record["eku_match"] is None
                         else "eku_mismatch" if role != "ca" and record["eku_match"] is False else "pass")
        if record["code"] != expected_code or record["status"] != ("pass" if expected_code == "pass" else "fail"):
            raise Incomplete("record_certificate_semantics")
    certificate_by_label = {record["label"]: record for record in document["certificates"]}
    for record, spec in zip(document["verification"], scope["verify"]):
        if set(record) != {"label", "status", "code", "purpose", "hostname"} or (record["label"], record["purpose"], record["hostname"]) != (spec[0], spec[3], spec[4]):
            raise Incomplete("record_verification_shape")
        _check_status_code(record, VERIFICATION_FAILURES)
        unavailable_cert = (certificate_by_label[spec[1]]["sha256"] is None or
                            certificate_by_label[spec[2]]["sha256"] is None)
        if unavailable_cert != (record["code"] == "certificate_unavailable"):
            raise Incomplete("record_verification_relationship")
    for record, spec in zip(document["key_pairs"], scope["pairs"]):
        if set(record) != {"label", "status", "code", "matches"} or type(record["matches"]) is not bool:
            raise Incomplete("record_pair_shape")
        _check_status_code(record, PAIR_FAILURES)
        if record["matches"] is not (record["status"] == "pass"):
            raise Incomplete("record_pair_consistency")
        unavailable_cert = certificate_by_label[spec[1]]["public_key_sha256"] is None
        if unavailable_cert != (record["code"] == "certificate_unavailable"):
            raise Incomplete("record_pair_relationship")
    blockers = sorted({x["code"] for x in all_records if x["status"] != "pass"})
    if document["blockers"] != blockers:
        raise Incomplete("record_blockers")
    ok = not blockers
    if not isinstance(document["result"], dict) or set(document["result"]) != {"status", "ok"} or document["result"]["status"] != ("pass" if ok else "fail") or document["result"]["ok"] is not ok:
        raise Incomplete("record_result")
    if not isinstance(document["non_effects"], dict) or set(document["non_effects"]) != {"renewal_attempted", "backup_created", "material_generated", "material_installed", "service_restart_attempted", "post_renewal_probe_attempted"} or any(value is not False for value in document["non_effects"].values()):
        raise Incomplete("record_effects")
    if not isinstance(document["security"], dict) or set(document["security"]) != {"private_key_bytes_included", "private_key_digest_included", "raw_openssl_output_included", "raw_config_included"} or any(value is not False for value in document["security"].values()):
        raise Incomplete("record_security")


def encode_document(document: dict[str, object], scope_name: str) -> bytes:
    validate_document(document, scope_name)
    encoded = (json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
    if len(encoded) > MAX_SUMMARY or any(token in encoded for token in (b"-----BEGIN", b"PRIVATE KEY", b"BEGIN CERTIFICATE")):
        raise Incomplete("record_encoding")
    return encoded


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise StrictJSONRejected("duplicate_record_field")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise StrictJSONRejected("non_json_constant")


def strict_json(raw: bytes) -> object:
    try:
        document = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_unique_pairs,
                              parse_constant=_reject_json_constant)
    except RecursionError:
        raise StrictJSONDepthRejected("json_container_depth") from None
    except (UnicodeError, ValueError):
        raise StrictJSONRejected("strict_json_rejected") from None
    pending: list[tuple[object, int]] = [(document, 1)]
    while pending:
        value, depth = pending.pop()
        if isinstance(value, (dict, list)):
            if depth > MAX_JSON_CONTAINER_DEPTH:
                raise StrictJSONDepthRejected("json_container_depth")
            children = value.values() if isinstance(value, dict) else value
            pending.extend((child, depth + 1 if isinstance(child, (dict, list)) else depth)
                           for child in children)
        elif isinstance(value, float) and not math.isfinite(value):
            raise StrictJSONRejected("non_finite_json_number")
    return document


def preexisting_generation(status_fd: int, scope_name: str) -> _PriorSummarySnapshot:
    scope = SCOPES[scope_name]
    raw = read_protected_summary_leaf(status_fd, scope["canonical"])
    if raw is None:
        return _PriorSummarySnapshot(_PriorSummaryState.ABSENT)
    try:
        document = strict_json(raw)
    except StrictJSONRejected:
        return _PriorSummarySnapshot(_PriorSummaryState.INVALID_OR_UNACCEPTED, reason_class="strict_json")
    if not isinstance(document, dict):
        return _PriorSummarySnapshot(_PriorSummaryState.INVALID_OR_UNACCEPTED, reason_class="snapshot_shape")
    if (document.get("schema_version") != scope["schema"] or
            document.get("collector_contract") != CONTRACT or document.get("finalized") is not True or
            document.get("scope") != scope_name or document.get("route") != scope["route"]):
        return _PriorSummarySnapshot(_PriorSummaryState.INVALID_OR_UNACCEPTED, reason_class="snapshot_identity")
    generation = document.get("generation")
    if type(generation) is not str or not HEX32.fullmatch(generation):
        return _PriorSummarySnapshot(_PriorSummaryState.INVALID_OR_UNACCEPTED, reason_class="snapshot_generation")
    return _PriorSummarySnapshot(_PriorSummaryState.VALID, generation)


def read_accepted_status(scope_name: str, previous_generation: str | None, now: dt.datetime | None = None) -> dict[str, object]:
    scope = SCOPES[scope_name]
    status_fd = open_status_dir()
    try:
        name = scope["canonical"]
        raw = read_protected_summary_leaf(status_fd, name)
        if raw is None:
            raise Incomplete("record_missing")
        document = strict_json(raw)
        validate_document(document, scope_name, previous_generation, now)
        return document
    finally:
        os.close(status_fd)


def publish(status_fd: int, scope_name: str, payload: bytes) -> None:
    global WITNESS_DISPOSITION_UNPROVED
    scope = SCOPES[scope_name]
    name = scope["canonical"]
    temporary = "." + name + "." + secrets.token_hex(16) + ".tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | FILE_FLAGS, 0o600, dir_fd=status_fd)
    identity: tuple[int, int] | None = None
    try:
        identity = file_identity(os.fstat(fd))
        check_protected_file(fd, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise Incomplete("summary_write")
            view = view[written:]
        os.fsync(fd)
        os.fchmod(fd, 0o644)
        os.fsync(fd)
        info = check_protected_file(fd, 0o644)
        if file_identity(info) != identity or info.st_size != len(payload):
            raise Incomplete("temporary_identity")
        same_entry(status_fd, temporary, info)
        check_existing(status_fd, name)
        try:
            signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
            if LATCHED_SIGNAL is not None or set(signal.sigpending()) & set(SIGNALS):
                raise Incomplete("precommit_signal")
        except (AttributeError, OSError) as exc:
            raise Incomplete("signal_boundary_unproved") from exc
        os.replace(temporary, name, src_dir_fd=status_fd, dst_dir_fd=status_fd)
        os._exit(0)
    finally:
        try:
            if identity is None:
                try:
                    identity = file_identity(os.fstat(fd))
                except OSError:
                    WITNESS_DISPOSITION_UNPROVED = True
            if identity is not None:
                try:
                    entry = os.stat(temporary, dir_fd=status_fd, follow_symlinks=False)
                    if file_identity(entry) == identity and stat.S_ISREG(entry.st_mode) and entry.st_nlink == 1:
                        os.unlink(temporary, dir_fd=status_fd)
                    else:
                        WITNESS_DISPOSITION_UNPROVED = True
                except OSError:
                    WITNESS_DISPOSITION_UNPROVED = True
        finally:
            os.close(fd)


def parse_cli(argv: list[str]) -> str:
    if len(argv) != 2 or argv[0] != "--scope" or argv[1] not in SCOPES:
        raise Incomplete("unsupported_status_invocation")
    return argv[1]


def main(argv: list[str]) -> int:
    global PROCESS_CAPABILITY_READY, WITNESS_SELECTION, WITNESS_CLOSEOUT_PROVED, WITNESS_DISPOSITION_UNPROVED
    WITNESS_SELECTION = None
    WITNESS_CLOSEOUT_PROVED = False
    WITNESS_DISPOSITION_UNPROVED = False
    if globals().get("ES_TLS_STATUS_BOOTSTRAP_VERIFIED") is not True:
        return 2
    bootstrap_interrupted = globals().get("ES_TLS_STATUS_BOOTSTRAP_INTERRUPTED")
    if not isinstance(bootstrap_interrupted, list) or len(bootstrap_interrupted) != 1:
        return 1
    if bootstrap_interrupted[0] is True:
        WITNESS_SELECTION = ("collector_entry", "interrupted")
        WITNESS_CLOSEOUT_PROVED = True
        return 1
    if bootstrap_interrupted[0] is not False:
        return 1
    try:
        scope_name = parse_cli(argv)
    except Incomplete:
        return 2
    for signum in SIGNALS:
        signal.signal(signum, _latch)
    if bootstrap_interrupted[0] or LATCHED_SIGNAL is not None:
        WITNESS_SELECTION = ("collector_entry", "interrupted")
        WITNESS_CLOSEOUT_PROVED = True
        return 1
    status_fd = None
    lock_fd = None
    phase = "protected_ancestry"
    try:
        status_fd = open_status_dir()
        phase = "scope_lock"
        lock_fd = open_scope_lock(status_fd, SCOPES[scope_name]["lock"])
        phase = "process_capability"
        PROCESS_CAPABILITY_READY = False
        validate_process_capability()
        PROCESS_CAPABILITY_READY = True
        phase = "prior_snapshot"
        prior = preexisting_generation(status_fd, scope_name)
        if prior.state is _PriorSummaryState.INVALID_OR_UNACCEPTED:
            raise Incomplete("prior_summary_unaccepted")
        if prior.state is _PriorSummaryState.VALID:
            previous = prior.generation
            if previous is None:
                raise Incomplete("prior_summary_unaccepted")
        elif prior.state is _PriorSummaryState.ABSENT:
            previous = None
        else:
            raise Incomplete("prior_summary_unaccepted")
        phase = "collection"
        record = collect(scope_name, previous)
        check_signal()
        phase = "record_encoding"
        encoded = encode_document(record, scope_name)
        phase = "publication_precommit"
        publish(status_fd, scope_name, encoded)
        raise Incomplete("publication_returned")
    except (Incomplete, OSError, ValueError, UnicodeError, json.JSONDecodeError) as failure:
        WITNESS_SELECTION = (phase, _failure_reason(phase, failure))
        if type(failure) is not Incomplete:
            WITNESS_DISPOSITION_UNPROVED = True
        return 1
    finally:
        PROCESS_CAPABILITY_READY = False
        close_interrupt: BaseException | None = None
        if lock_fd is not None:
            closing_fd, lock_fd = lock_fd, None
            try:
                os.close(closing_fd)
            except BaseException as exc:
                WITNESS_DISPOSITION_UNPROVED = True
                if not isinstance(exc, Exception):
                    close_interrupt = exc
        if status_fd is not None:
            closing_fd, status_fd = status_fd, None
            try:
                os.close(closing_fd)
            except BaseException as exc:
                WITNESS_DISPOSITION_UNPROVED = True
                if not isinstance(exc, Exception) and close_interrupt is None:
                    close_interrupt = exc
        if close_interrupt is not None:
            raise close_interrupt
        if WITNESS_SELECTION is not None and not WITNESS_DISPOSITION_UNPROVED:
            WITNESS_CLOSEOUT_PROVED = True


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
