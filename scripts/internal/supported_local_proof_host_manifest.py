#!/usr/bin/env -S python3 -I
"""Complete, fail-closed manifest for retained host proof evidence."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys

MANIFEST = "host-evidence-manifest.json"
MAX_FILE_BYTES = 32 << 20
MAX_TOTAL_BYTES = 64 << 20
PHASES = {"source-snapshot", "input-preparation", "package-identity", "package-normal-shell",
          "runtime-support-build", "spire-stage", "guest-bootstrap", "snapshot-transfer",
          "snapshot-extract", "snapshot-drop", "tooling-transfer", "input-transfer",
          "guest-setup", "cleanup-guest-scratch", "prepare-only-up", "full-check",
          "supported-host-capture", "runtime-identity-execute", "normal-shell-execute",
          "runtime-identity-capture", "normal-shell-capture", "result-validation", "guest-cleanup"}
TOP_LEVEL = {"proof-metadata.json": "host_metadata", "source-manifest.json": "source_lineage",
             "source-snapshot.json": "source_lineage", "proof-closeout.json": "proof_closeout"}
TOP_LEVEL.update({f"phase-{phase}.json": "host_phase" for phase in PHASES})
GUEST = {
    "guest-repo-snapshot.sha256": "repository_lineage",
    "repo-snapshot-match.txt": "repository_lineage",
    "execution-roots-setup-safe.json": "proof_assertions",
    "nomad-agent-safe.json": "supported_host",
    "nomad-nodes-safe.json": "supported_host",
    "node-details-safe.json": "supported_host",
    "nomad-service-safe.json": "supported_host",
    "docker-info-safe.json": "supported_host",
    "nomad-leader-safe.json": "supported_host",
    "nomad-compute-override-safe.json": "supported_host",
    "runtime-identity-vault-log-assertions.json": "proof_assertions",
    "control-plane-normal-shell-log-assertions.json": "proof_assertions",
    "control-plane-normal-shell-result-evidence.json": "proof_assertions",
    "safe-evidence-manifest.json": "generation_manifest",
}
for name in ("summary.json", "status-safe.json", "staging-check.txt", "nomad-execution-safe.json"):
    GUEST[name] = "execution_evidence"
    GUEST["runtime-identity-vault-" + name] = "runtime_identity_execution"
    GUEST["control-plane-normal-shell-" + name] = "normal_shell_execution"


class HostEvidenceError(Exception):
    pass


def require(value: bool) -> None:
    if not value:
        raise HostEvidenceError


def canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def private_directory(path: Path) -> tuple[int, os.stat_result]:
    metadata = os.lstat(path)
    require(stat.S_ISDIR(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o700 and
            metadata.st_uid == os.geteuid())
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    observed = os.fstat(fd)
    if (observed.st_dev, observed.st_ino) != (metadata.st_dev, metadata.st_ino):
        os.close(fd)
        raise HostEvidenceError
    return fd, observed


def child_directory(parent_fd: int, name: str) -> int:
    metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    require(stat.S_ISDIR(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o700 and
            metadata.st_uid == os.geteuid())
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
    observed = os.fstat(fd)
    if (observed.st_dev, observed.st_ino) != (metadata.st_dev, metadata.st_ino):
        os.close(fd)
        raise HostEvidenceError
    return fd


def read_file(parent_fd: int, name: str) -> tuple[bytes, os.stat_result]:
    before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.geteuid() and
            stat.S_IMODE(before.st_mode) == 0o600 and 0 <= before.st_size <= MAX_FILE_BYTES)
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent_fd)
    try:
        opened = os.fstat(fd)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_size,
                                  value.st_nlink, value.st_mtime_ns, value.st_ctime_ns)
        require(identity(opened) == identity(before))
        with os.fdopen(fd, "rb", closefd=False) as source:
            data = source.read(MAX_FILE_BYTES + 1)
        require(len(data) == before.st_size and identity(os.fstat(fd)) == identity(before))
        return data, before
    finally:
        os.close(fd)


def row(path: str, classification: str, data: bytes, metadata: os.stat_result) -> dict:
    return {"path": path, "classification": classification, "file_type": "regular",
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}", "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


def finalize(path: Path) -> None:
    require(path.is_absolute() and os.path.normpath(str(path)) == str(path))
    root_fd, root_meta = private_directory(path)
    rows = []
    total = 0
    try:
        names = set(os.listdir(root_fd))
        require(MANIFEST not in names and names <= set(TOP_LEVEL) | {"guest-evidence"})
        for name in sorted(names & set(TOP_LEVEL)):
            data, metadata = read_file(root_fd, name)
            total += len(data)
            require(total <= MAX_TOTAL_BYTES)
            rows.append(row(name, TOP_LEVEL[name], data, metadata))
        if "guest-evidence" in names:
            generations_fd = child_directory(root_fd, "guest-evidence")
            try:
                labels = set(os.listdir(generations_fd))
                require(labels <= {"setup", "final", "failure"})
                for label in sorted(labels):
                    generation_fd = child_directory(generations_fd, label)
                    try:
                        files = set(os.listdir(generation_fd))
                        require("safe-evidence-manifest.json" in files and files <= set(GUEST))
                        for name in sorted(files):
                            data, metadata = read_file(generation_fd, name)
                            total += len(data)
                            require(total <= MAX_TOTAL_BYTES)
                            rows.append(row(f"guest-evidence/{label}/{name}", GUEST[name], data, metadata))
                    finally:
                        os.close(generation_fd)
            finally:
                os.close(generations_fd)
        rows.sort(key=lambda item: item["path"])
        current = os.fstat(root_fd)
        require((current.st_dev, current.st_ino) == (root_meta.st_dev, root_meta.st_ino))
        payload = canonical({"schema": "supported-local-host-evidence-manifest-v2",
                             "root_record": True, "self_excluded": True, "files": rows})
        fd = os.open(MANIFEST, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=root_fd)
        try:
            with os.fdopen(fd, "wb", closefd=False) as output:
                output.write(payload)
                output.flush()
            os.fchmod(fd, 0o600)
            os.fsync(fd)
            created = os.fstat(fd)
        finally:
            os.close(fd)
        reopened, observed = read_file(root_fd, MANIFEST)
        require(reopened == payload and (observed.st_dev, observed.st_ino) ==
                (created.st_dev, created.st_ino))
        require(set(os.listdir(root_fd)) == names | {MANIFEST})
        print(hashlib.sha256(reopened).hexdigest())
    finally:
        os.close(root_fd)


if __name__ == "__main__":
    try:
        if len(sys.argv) != 3 or sys.argv[1] != "finalize":
            raise HostEvidenceError
        finalize(Path(sys.argv[2]))
    except (HostEvidenceError, OSError, ValueError, TypeError):
        print("supported-local host evidence manifest failed", file=sys.stderr)
        raise SystemExit(1)
