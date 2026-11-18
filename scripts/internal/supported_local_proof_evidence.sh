#!/usr/bin/env bash
set -euo pipefail

# This helper is transported to the guest on stdin, so failure finalization
# does not depend on the guest repository bootstrap having completed.
if [[ "$#" -lt 2 || "$#" -gt 3 ]]; then
  echo "usage: supported_local_proof_evidence.sh collect-safe ROOT | receive-safe HOST_ROOT LABEL" >&2
  exit 2
fi
case "$1" in
  collect-safe|receive-safe) ;;
  *)
    echo "unsupported safe evidence action" >&2
    exit 2
    ;;
esac

# FD 3 preserves the archive stream for receive-safe while stdin carries this
# fixed Python program. collect-safe never reads FD 3.
python3 - "$@" 3<&0 <<'PY'
from __future__ import annotations

import hashlib
import io
import json
import os
import pathlib
import re
import stat
import sys
import tarfile


SCHEMA = "supported-local-proof-safe-evidence-v1"
MANIFEST_NAME = "safe-evidence-manifest.json"
MAX_FILE_BYTES = 32 << 20
MAX_TOTAL_BYTES = 64 << 20
MAX_ARCHIVE_BYTES = MAX_TOTAL_BYTES + (1 << 20)
SAFE_MODE = 0o600

# Every name is a literal top-level proof output. No directory traversal or
# guest-tree scan can promote an unclassified file into this set.
CLASSIFIED = {
    "guest-repo-snapshot.sha256": "repository_lineage",
    "repo-snapshot-match.txt": "repository_lineage",
    "execution-roots-setup-safe.json": "proof_assertions",
    "nomad-agent-safe.json": "supported_host",
    "nomad-leader-safe.json": "supported_host",
    "nomad-nodes-safe.json": "supported_host",
    "node-details-safe.json": "supported_host",
    "nomad-service-safe.json": "supported_host",
    "docker-info-safe.json": "supported_host",
    "nomad-compute-override-safe.json": "supported_host",
    "runtime-identity-vault-log-assertions.json": "proof_assertions",
    "control-plane-normal-shell-log-assertions.json": "proof_assertions",
    "control-plane-normal-shell-result-evidence.json": "proof_assertions",
}
EXECUTION_NAMES = (
    "summary.json",
    "status-safe.json",
    "staging-check.txt",
    "nomad-execution-safe.json",
)
for name in EXECUTION_NAMES:
    CLASSIFIED[name] = "execution_evidence"
    CLASSIFIED["runtime-identity-vault-" + name] = "runtime_identity_execution"
    CLASSIFIED["control-plane-normal-shell-" + name] = "normal_shell_execution"


class EvidenceError(Exception):
    pass


def require(condition: bool) -> None:
    if not condition:
        raise EvidenceError


def clean_root(value: str) -> pathlib.Path:
    require(os.path.isabs(value))
    require(os.path.normpath(value) == value)
    require(".." not in pathlib.PurePath(value).parts)
    return pathlib.Path(value)


def clean_member(name: str) -> None:
    require(name != "" and name not in (".", ".."))
    require(not os.path.isabs(name) and "/" not in name and "\\" not in name)
    require(".." not in name)
    require(name == MANIFEST_NAME or name in CLASSIFIED)


for candidate in CLASSIFIED:
    clean_member(candidate)


def encoded_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def projected_json(name: str, payload: bytes) -> bytes:
    source = json.loads(payload)
    require(isinstance(source, dict))
    if name == "execution-roots-setup-safe.json":
        fixed = {
            "schema": "supported-local-execution-roots-setup-safe-v1",
            "profile": "service-root-v1",
            "configured_root_uid": 0,
            "configured_root_gid": 0,
            "configured_root_mode": "0755",
            "static_root_owner_mode_checked": True,
            "operator_write_access_required": False,
            "container_identity_or_behavioral_capability_proved": False,
        }
        require(set(source) == set(fixed) and
                all(type(source[key]) is type(value) and source[key] == value
                    for key, value in fixed.items()))
        return encoded_json(fixed)
    shapes = {
        "nomad-agent-safe.json": ("supported-local-nomad-agent-safe-v1", {
            "version": "version", "region_present": "bool", "datacenter_present": "bool", "node_name_present": "bool",
            "dev_mode": "bool", "client_enabled": "bool", "server_enabled": "bool"}),
        "nomad-nodes-safe.json": ("supported-local-nomad-nodes-safe-v1", {
            "node_count": "count", "ready_count": "count", "eligible_count": "count"}),
        "node-details-safe.json": ("supported-local-node-details-safe-v1", {
            "detail_count": "count", "positive_compute_count": "count", "docker_healthy_count": "count"}),
        "nomad-service-safe.json": ("supported-local-nomad-service-safe-v1", {
            "loaded": "bool", "active": "bool", "running": "bool", "enabled": "bool",
            "main_pid_positive": "bool", "exec_main_status_zero": "bool"}),
        "docker-info-safe.json": ("supported-local-docker-info-safe-v1", {
            "server_version": "version", "architecture": "architecture", "storage_driver": "driver",
            "cgroup_version": "cgroup", "cpu_count": "count", "memory_bytes": "bytes",
            "local_volume_capable": "bool"}),
        "nomad-leader-safe.json": ("supported-local-nomad-leader-safe-v1", {"leader_present": "bool"}),
        "nomad-compute-override-safe.json": ("supported-local-compute-override-safe-v1", {"override_present": "bool"}),
    }
    if name in shapes:
        schema, fields = shapes[name]
        require(set(source) == {"schema", *fields} and source["schema"] == schema)
        for key, kind in fields.items():
            value = source[key]
            if kind == "bool":
                require(value is None or isinstance(value, bool))
            elif kind == "text":
                require(value is None or isinstance(value, str) and
                        re.fullmatch(r"[A-Za-z0-9._/-]{1,128}", value, re.ASCII) is not None)
            elif kind == "version":
                require(value is None or isinstance(value, str) and
                        re.fullmatch(r"v?[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}", value, re.ASCII) is not None)
            elif kind == "architecture":
                require(value is None or value in ("amd64", "arm64", "x86_64", "aarch64"))
            elif kind == "driver":
                require(value is None or value in ("overlay2", "overlay", "btrfs", "zfs", "vfs", "devicemapper"))
            elif kind == "cgroup":
                require(value is None or value in ("1", "2"))
            else:
                maximum = (1 << 60) if kind == "bytes" else 1_000_000
                require(value is None or isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= maximum)
        return encoded_json(source)
    if name.endswith("status-safe.json"):
        require(set(source) == {"schema", "state", "terminal", "exit_code"} and
                source["schema"] == "supported-local-execution-status-safe-v1")
        require(source["state"] is None or isinstance(source["state"], str) and
                source["state"] in ("pending", "running", "terminal", "complete", "failed", "lost"))
        require(source["terminal"] is None or isinstance(source["terminal"], bool))
        code = source["exit_code"]
        require(code is None or isinstance(code, int) and not isinstance(code, bool) and 0 <= code <= 255)
        return encoded_json(source)
    if name.endswith("nomad-execution-safe.json"):
        require(set(source) == {"schema", "run_id", "job_id", "allocation_id",
                                "job_observed", "allocation_observed"} and
                source["schema"] == "supported-local-nomad-execution-safe-v1" and
                isinstance(source["job_observed"], bool) and isinstance(source["allocation_observed"], bool))
        require(isinstance(source["run_id"], str) and
                re.fullmatch(r"run-[0-9a-f]{16}", source["run_id"], re.ASCII) is not None)
        require(source["job_id"] == "exec-" + source["run_id"])
        require(isinstance(source["allocation_id"], str) and
                re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",
                             source["allocation_id"], re.ASCII) is not None)
        return encoded_json(source)
    if name == "control-plane-normal-shell-result-evidence.json":
        require(set(source) == {"schema", "bundle_sha256", "bundle_size", "members", "proof_status",
                                 "realization", "workspace_mutation_marker_present", "final_message_marker_present",
                                 "credential_material_present", "credential_material_bytes"})
        require(source["schema"] == "supported-local-normal-shell-result-evidence-v1" and
                source["proof_status"] == "ok" and source["realization"] == "supported-local-proof-codex-shim/v1")
        require(all(source[key] is True for key in ("workspace_mutation_marker_present",
                                                "final_message_marker_present", "credential_material_present")))
        require(isinstance(source["bundle_sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", source["bundle_sha256"]) is not None)
        require(isinstance(source["bundle_size"], int) and not isinstance(source["bundle_size"], bool) and
                0 < source["bundle_size"] <= 16 << 20)
        require(isinstance(source["credential_material_bytes"], int) and not isinstance(source["credential_material_bytes"], bool) and
                1 <= source["credential_material_bytes"] <= 4096)
        expected = {"runtime-contract-proof.json", "codex-stdout.txt", "codex-stderr.txt",
                    "codex-final-message.txt", "workspace.diff", "workspace.tar.gz"}
        rows = source["members"]
        require(isinstance(rows, list) and [row.get("path") for row in rows if isinstance(row, dict)] == sorted(expected))
        for row in rows:
            require(isinstance(row, dict) and set(row) == {"path", "size", "sha256"} and row["path"] in expected)
            require(isinstance(row["size"], int) and not isinstance(row["size"], bool) and 0 <= row["size"] <= 8 << 20)
            require(isinstance(row["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is not None)
        return encoded_json(source)
    raise EvidenceError


def safe_projection(name: str, payload: bytes) -> bytes | None:
    # A failed execution-loop summary can contain an untrusted HTTP error
    # message. Successful summaries are projected to fixed non-secret fields.
    if name == "summary.json" or name.endswith("-summary.json"):
        try:
            source = json.loads(payload)
        except (ValueError, UnicodeDecodeError):
            raise EvidenceError from None
        require(isinstance(source, dict))
        if source.get("ok") is not True or source.get("message") != "execution completed successfully":
            return None
        run_id = source.get("run_id")
        require(isinstance(run_id, str) and re.fullmatch(r"run-[0-9a-f]{16}", run_id, re.ASCII) is not None)
        result: dict[str, object] = {"schema": "supported-local-proof-summary-v1", "ok": True,
                                     "run_id": run_id}
        for key in ("terminal", "logs_available", "result_available"):
            if isinstance(source.get(key), bool):
                result[key] = source[key]
        for key in ("exit_code", "result_bytes"):
            value = source.get(key)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                result[key] = value
        if source.get("state") in ("pending", "running", "terminal", "complete", "failed", "lost"):
            result["state"] = source["state"]
        return encoded_json(result)
    if name.endswith("-log-assertions.json"):
        try:
            source = json.loads(payload)
        except (ValueError, UnicodeDecodeError):
            raise EvidenceError from None
        require(isinstance(source, dict) and source.get("schema") == "supported-local-proof-log-assertions-v1")
        result = {"schema": "supported-local-proof-log-assertions-v1"}
        for key in ("identity_endpoint_used", "identity_jwt_received", "vault_login_success",
                    "secret_read_success", "runtime_contract_proved"):
            if isinstance(source.get(key), bool):
                result[key] = source[key]
        return encoded_json(result)
    if name in ("guest-repo-snapshot.sha256", "repo-snapshot-match.txt"):
        require(re.fullmatch(rb"[0-9a-f]{64}\n", payload) is not None)
        return payload
    if name.endswith("staging-check.txt"):
        require(payload in (b"present\n", b"absent\n"))
        return payload
    return projected_json(name, payload)


def source_files(root: pathlib.Path) -> list[tuple[str, str, bytes]]:
    if not os.path.lexists(root):
        return []
    metadata = os.lstat(root)
    require(stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode))
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    collected: list[tuple[str, str, bytes]] = []
    total_bytes = 0
    try:
        opened_root = os.fstat(root_fd)
        require((opened_root.st_dev, opened_root.st_ino) == (metadata.st_dev, metadata.st_ino))
        for name in sorted(CLASSIFIED):
            try:
                before = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1)
            require(0 <= before.st_size <= MAX_FILE_BYTES)
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=root_fd)
            try:
                opened = os.fstat(fd)
                identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_size,
                                         item.st_nlink, item.st_mtime_ns, item.st_ctime_ns)
                require(stat.S_ISREG(opened.st_mode) and identity(opened) == identity(before))
                with os.fdopen(fd, "rb", closefd=False) as stream:
                    data = stream.read(MAX_FILE_BYTES + 1)
                after = os.fstat(fd)
                require(len(data) == before.st_size and identity(after) == identity(before))
            finally:
                os.close(fd)
            projected = safe_projection(name, data)
            if projected is None:
                continue
            require(len(projected) <= MAX_FILE_BYTES)
            total_bytes += len(projected)
            require(total_bytes <= MAX_TOTAL_BYTES)
            collected.append((name, CLASSIFIED[name], projected))
    finally:
        os.close(root_fd)
    retained = {name: json.loads(data) for name, _, data in collected
                if name.endswith("summary.json") or name.endswith("nomad-execution-safe.json")}
    for prefix in ("", "runtime-identity-vault-", "control-plane-normal-shell-"):
        summary = retained.get(prefix + "summary.json")
        execution = retained.get(prefix + "nomad-execution-safe.json")
        if execution is not None:
            require(summary is not None and summary["run_id"] == execution["run_id"])
    return collected


def collect(root: pathlib.Path) -> None:
    files = source_files(root)
    manifest = {
        "schema": SCHEMA,
        "files": [
            {
                "path": name,
                "classification": classification,
                "file_type": "regular",
                "mode": "0600",
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
            for name, classification, data in files
        ],
    }
    payloads = [(name, data) for name, _, data in files]
    payloads.append((MANIFEST_NAME, encoded_json(manifest)))
    archive_bytes = io.BytesIO()
    with tarfile.open(fileobj=archive_bytes, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in sorted(payloads):
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            entry.mode = SAFE_MODE
            entry.uid = 0
            entry.gid = 0
            entry.mtime = 0
            entry.type = tarfile.REGTYPE
            archive.addfile(entry, io.BytesIO(data))
    output = archive_bytes.getvalue()
    require(len(output) <= MAX_ARCHIVE_BYTES)
    sys.stdout.buffer.write(output)


def receive(host_root: pathlib.Path, label: str) -> None:
    require(label in ("setup", "final", "failure"))
    with os.fdopen(3, "rb", closefd=False) as stream:
        archive_bytes = stream.read(MAX_ARCHIVE_BYTES + 1)
    require(0 < len(archive_bytes) <= MAX_ARCHIVE_BYTES)
    payloads: dict[str, bytes] = {}
    names: list[str] = []
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
        for member in archive:
            name = member.name
            clean_member(name)
            require(name not in payloads and member.isfile() and member.type == tarfile.REGTYPE)
            require(member.mode == SAFE_MODE and member.uid == 0 and member.gid == 0 and member.mtime == 0)
            require(0 <= member.size <= MAX_FILE_BYTES or (name == MANIFEST_NAME and member.size <= (1 << 20)))
            source = archive.extractfile(member)
            require(source is not None)
            data = source.read(MAX_FILE_BYTES + 1)
            require(len(data) == member.size)
            payloads[name] = data
            names.append(name)
    require(names == sorted(names) and MANIFEST_NAME in payloads)
    manifest = json.loads(payloads[MANIFEST_NAME])
    require(isinstance(manifest, dict) and set(manifest) == {"schema", "files"} and manifest["schema"] == SCHEMA)
    rows = manifest["files"]
    require(isinstance(rows, list) and len(rows) == len(payloads) - 1)
    require([row.get("path") for row in rows] == sorted(name for name in payloads if name != MANIFEST_NAME))
    total_bytes = 0
    for row in rows:
        require(isinstance(row, dict) and set(row) ==
                {"path", "classification", "file_type", "mode", "size", "sha256"})
        name = row["path"]
        clean_member(name)
        data = payloads[name]
        total_bytes += len(data)
        require(total_bytes <= MAX_TOTAL_BYTES)
        require(row["classification"] == CLASSIFIED[name] and row["file_type"] == "regular")
        require(row["mode"] == "0600" and row["size"] == len(data))
        require(row["sha256"] == hashlib.sha256(data).hexdigest())

    host_meta = os.lstat(host_root)
    require(stat.S_ISDIR(host_meta.st_mode) and not stat.S_ISLNK(host_meta.st_mode))
    require(stat.S_IMODE(host_meta.st_mode) == 0o700 and host_meta.st_uid == os.geteuid())
    host_fd = os.open(host_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened_host = os.fstat(host_fd)
        require((opened_host.st_dev, opened_host.st_ino) == (host_meta.st_dev, host_meta.st_ino))
        try:
            os.mkdir("guest-evidence", 0o700, dir_fd=host_fd)
        except FileExistsError:
            pass
        parent_meta = os.stat("guest-evidence", dir_fd=host_fd, follow_symlinks=False)
        require(stat.S_ISDIR(parent_meta.st_mode) and stat.S_IMODE(parent_meta.st_mode) == 0o700 and
                parent_meta.st_uid == os.geteuid())
        parent_fd = os.open("guest-evidence", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                            os.O_CLOEXEC, dir_fd=host_fd)
        claim_fd = None
        claim = ".claim-" + label
        try:
            parent_opened = os.fstat(parent_fd)
            require((parent_opened.st_dev, parent_opened.st_ino) == (parent_meta.st_dev, parent_meta.st_ino))
            claim_fd = os.open(claim, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                               os.O_CLOEXEC, SAFE_MODE, dir_fd=parent_fd)
            try:
                os.stat(label, dir_fd=parent_fd, follow_symlinks=False)
                raise EvidenceError
            except FileNotFoundError:
                pass
            temporary = ".pending-%s-%d-%s" % (label, os.getpid(), os.urandom(8).hex())
            os.mkdir(temporary, 0o700, dir_fd=parent_fd)
            stage_fd = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                               os.O_CLOEXEC, dir_fd=parent_fd)
            published = False
            try:
                for name in sorted(payloads):
                    file_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                                      os.O_CLOEXEC, SAFE_MODE, dir_fd=stage_fd)
                    try:
                        with os.fdopen(file_fd, "wb", closefd=False) as stream:
                            stream.write(payloads[name])
                            stream.flush()
                        os.fchmod(file_fd, SAFE_MODE)
                        os.fsync(file_fd)
                    finally:
                        os.close(file_fd)
                os.fsync(stage_fd)
                try:
                    os.stat(label, dir_fd=parent_fd, follow_symlinks=False)
                    raise EvidenceError
                except FileNotFoundError:
                    pass
                os.rename(temporary, label, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                published = True
            finally:
                if not published:
                    names_in_stage = set(os.listdir(stage_fd))
                    if names_in_stage <= set(payloads):
                        for name in names_in_stage:
                            os.unlink(name, dir_fd=stage_fd)
                        os.rmdir(temporary, dir_fd=parent_fd)
                os.close(stage_fd)
        finally:
            if claim_fd is not None:
                os.close(claim_fd)
                os.unlink(claim, dir_fd=parent_fd)
            os.close(parent_fd)
        final_host = os.fstat(host_fd)
        require((final_host.st_dev, final_host.st_ino) == (host_meta.st_dev, host_meta.st_ino))
        require(stat.S_IMODE(final_host.st_mode) == 0o700)
    finally:
        os.close(host_fd)


try:
    action = sys.argv[1]
    target = clean_root(sys.argv[2])
    if action == "collect-safe" and len(sys.argv) == 3:
        collect(target)
    elif action == "receive-safe" and len(sys.argv) == 4:
        receive(target, sys.argv[3])
    else:
        raise EvidenceError
except (EvidenceError, OSError, ValueError, KeyError, TypeError, tarfile.TarError):
    print("supported-local safe evidence collection failed", file=sys.stderr)
    raise SystemExit(1)
PY
