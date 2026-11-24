#!/usr/bin/env -S python3 -I
"""Private proof bootstrap scratch and deterministic Git-bound source snapshot."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile

MAX_FILE_BYTES = 16 << 20
MAX_SOURCE_BYTES = 64 << 20
MAX_SNAPSHOT_BYTES = 64 << 20
OWNER_NAME = ".proof-bootstrap-owner.json"
SCRATCH_FILES = {
    OWNER_NAME,
    "host-repo-snapshot.tar.gz",
    "runtime_identity_vault_success.input.json",
    "control_plane_normal_shell_runtime.input.json",
}
SCRATCH_SUBDIRS = {
    "payload": {"runtime_identity_vault_login.tar.gz", "control_plane_normal_shell_runtime.tar.gz"},
    "bin": {"es-runtime-support", "spire.tar.gz"},
}
SENSITIVE_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".db", ".sqlite", ".sqlite3",
                      ".wal", ".shm", ".zip", ".tar", ".tar.gz", ".tgz", ".gz")
SENSITIVE_PARTS = {".git", ".tmp", "__pycache__", "node_modules", "vendor", "cache", "caches",
                   "dist", "payload", "workdirs", "es-staging", "es-results", "spire-data",
                   "ars-storage", "bringup-state", "tls"}
UNTRACKED_EXTENSIONS = {".go", ".py", ".sh", ".md"}
PROOF_ID = re.compile(r"[A-Za-z0-9_-]{1,80}\Z", re.ASCII)


class ProofBoundaryError(Exception):
    pass


def require(value: bool) -> None:
    if not value:
        raise ProofBoundaryError


def canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def clean_absolute(value: str) -> Path:
    require(value.startswith("/") and not value.startswith("//") and os.path.normpath(value) == value)
    require(value != "/" and "\x00" not in value)
    return Path(value)


def clean_relative(value: str) -> tuple[str, ...]:
    require(value and not value.startswith("/") and "\\" not in value and "\x00" not in value)
    parts = value.split("/")
    require(all(part not in ("", ".", "..") for part in parts))
    require(PurePosixPath(value).as_posix() == value)
    return tuple(parts)


def private_dir(path: Path) -> tuple[int, os.stat_result]:
    metadata = os.lstat(path)
    require(stat.S_ISDIR(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o700)
    require(metadata.st_uid == os.geteuid())
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    observed = os.fstat(fd)
    if (observed.st_dev, observed.st_ino) != (metadata.st_dev, metadata.st_ino):
        os.close(fd)
        raise ProofBoundaryError
    return fd, observed


def write_exclusive(dir_fd: int, name: str, data: bytes) -> None:
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=dir_fd)
    try:
        with os.fdopen(fd, "wb", closefd=False) as target:
            target.write(data)
            target.flush()
        os.fchmod(fd, 0o600)
        os.fsync(fd)
    finally:
        os.close(fd)


def create_scratch(path: Path, proof_id: str) -> None:
    require(PROOF_ID.fullmatch(proof_id) is not None)
    old = os.umask(0o077)
    try:
        os.mkdir(path, 0o700)
    finally:
        os.umask(old)
    fd, metadata = private_dir(path)
    try:
        nonce = os.urandom(16).hex()
        write_exclusive(fd, OWNER_NAME, canonical({"schema": "supported-local-bootstrap-owner-v1",
                                                    "proof_id": proof_id, "nonce": nonce}))
        print(f"{metadata.st_dev}:{metadata.st_ino}:{nonce}")
    finally:
        os.close(fd)


def checked_regular(dir_fd: int, name: str) -> None:
    metadata = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1 and metadata.st_uid == os.geteuid())


def cleanup_scratch(path: Path, identity: str) -> None:
    values = identity.split(":")
    require(len(values) == 3 and values[0].isdigit() and values[1].isdigit() and re.fullmatch(r"[0-9a-f]{32}", values[2]) is not None)
    fd, metadata = private_dir(path)
    try:
        require((metadata.st_dev, metadata.st_ino) == (int(values[0]), int(values[1])))
        checked_regular(fd, OWNER_NAME)
        marker_fd = os.open(OWNER_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        try:
            marker = json.loads(os.read(marker_fd, 512))
        finally:
            os.close(marker_fd)
        require(marker.get("schema") == "supported-local-bootstrap-owner-v1" and marker.get("nonce") == values[2])
        root_names = set(os.listdir(fd))
        require(root_names <= SCRATCH_FILES | set(SCRATCH_SUBDIRS) and OWNER_NAME in root_names)
        sub_fds: dict[str, int] = {}
        try:
            for name in root_names - set(SCRATCH_SUBDIRS):
                checked_regular(fd, name)
            for name in root_names & set(SCRATCH_SUBDIRS):
                sub_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                sub_fds[name] = sub_fd
                sub_meta = os.fstat(sub_fd)
                require(stat.S_ISDIR(sub_meta.st_mode) and stat.S_IMODE(sub_meta.st_mode) == 0o700 and sub_meta.st_uid == os.geteuid())
                names = set(os.listdir(sub_fd))
                require(names <= SCRATCH_SUBDIRS[name])
                for child in names:
                    checked_regular(sub_fd, child)
            for name, sub_fd in sub_fds.items():
                for child in sorted(os.listdir(sub_fd)):
                    checked_regular(sub_fd, child)
                    os.unlink(child, dir_fd=sub_fd)
                os.rmdir(name, dir_fd=fd)
            for name in sorted(root_names - set(SCRATCH_SUBDIRS) - {OWNER_NAME}):
                checked_regular(fd, name)
                os.unlink(name, dir_fd=fd)
            current = os.fstat(fd)
            require((current.st_dev, current.st_ino) == (metadata.st_dev, metadata.st_ino))
            observed = os.lstat(path)
            require((observed.st_dev, observed.st_ino) == (metadata.st_dev, metadata.st_ino))
            checked_regular(fd, OWNER_NAME)
            os.unlink(OWNER_NAME, dir_fd=fd)
        finally:
            for sub_fd in sub_fds.values():
                os.close(sub_fd)
    finally:
        os.close(fd)
    os.rmdir(path)


def guarded_git(repo: Path, *args: str) -> bytes:
    env = os.environ.copy()
    env.update({"GIT_OPTIONAL_LOCKS": "0", "GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0",
                "GIT_PAGER": "cat", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                "LC_ALL": "C", "LANG": "C"})
    command = ["git", "--no-pager", "-C", str(repo), "-c", "core.fsmonitor=false",
               "-c", "core.untrackedCache=false", "-c", "diff.external=", "-c", "diff.textconv=false", *args]
    return subprocess.run(command, cwd=repo, env=env, capture_output=True, check=True).stdout


def git_paths(repo: Path, *args: str) -> set[str]:
    return {entry.decode("utf-8", "strict") for entry in guarded_git(repo, *args).split(b"\0") if entry}


def include_source(path: str, kind: str) -> bool:
    parts = clean_relative(path)
    lower = [part.lower() for part in parts]
    base = lower[-1]
    if path == ".out/Dockerfile" and kind == "tracked":
        return True
    if ".out" in lower or any(part in SENSITIVE_PARTS for part in lower):
        return False
    if base == ".env" or base.startswith(".env.") or base.endswith(SENSITIVE_SUFFIXES):
        return False
    if any(token in base for token in ("secret", "token", "password", "private", "credential")):
        return False
    if kind == "tracked":
        return True
    suffix = Path(base).suffix
    if suffix not in UNTRACKED_EXTENSIONS:
        return False
    return parts[0] in {"es", "ags", "ars", "cmd", "scripts", ".docs", ".examples"} or len(parts) == 1


def read_beneath(root_fd: int, relative: str) -> tuple[bytes, int]:
    parts = clean_relative(relative)
    parent_fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = next_fd
        before = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= MAX_FILE_BYTES)
        require(stat.S_IMODE(before.st_mode) & 0o7000 == 0)
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent_fd)
        try:
            opened = os.fstat(fd)
            identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_size,
                                      value.st_nlink, value.st_mtime_ns, value.st_ctime_ns)
            require(identity(opened) == identity(before))
            with os.fdopen(fd, "rb", closefd=False) as source:
                data = source.read(MAX_FILE_BYTES + 1)
            require(len(data) == before.st_size and identity(os.fstat(fd)) == identity(before))
            return data, stat.S_IMODE(before.st_mode)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def snapshot(repo: Path, scratch: Path, evidence: Path) -> None:
    root_meta = os.lstat(repo)
    require(stat.S_ISDIR(root_meta.st_mode))
    scratch_fd, _ = private_dir(scratch)
    evidence_fd, _ = private_dir(evidence)
    repo_fd = os.open(repo, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened_repo = os.fstat(repo_fd)
        require((opened_repo.st_dev, opened_repo.st_ino) == (root_meta.st_dev, root_meta.st_ino))
        tracked = git_paths(repo, "ls-files", "--cached", "-z")
        untracked = git_paths(repo, "ls-files", "--others", "--exclude-standard", "-z")
        require(not tracked & untracked)
        files = []
        total = 0
        for path in sorted(tracked | untracked):
            kind = "tracked" if path in tracked else "untracked"
            if not include_source(path, kind):
                continue
            data, mode = read_beneath(repo_fd, path)
            total += len(data)
            require(total <= MAX_SOURCE_BYTES)
            files.append((path, kind, mode, data))
        require(any(path == ".out/Dockerfile" and kind == "tracked" for path, kind, _, _ in files) or ".out/Dockerfile" not in tracked)
        manifest = {"schema": "supported-local-source-manifest-v1", "files": [
            {"path": path, "classification": kind, "file_type": "regular", "mode": f"{mode:04o}",
             "size": len(data), "sha256": sha(data)} for path, kind, mode, data in files]}
        body = io.BytesIO()
        with gzip.GzipFile(filename="", mode="wb", fileobj=body, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for path, _, mode, data in files:
                    member = tarfile.TarInfo(path)
                    member.size = len(data)
                    member.mode = mode
                    member.uid = member.gid = member.mtime = 0
                    member.uname = member.gname = ""
                    archive.addfile(member, io.BytesIO(data))
        archive_bytes = body.getvalue()
        require(len(archive_bytes) <= MAX_SNAPSHOT_BYTES)
        write_exclusive(scratch_fd, "host-repo-snapshot.tar.gz", archive_bytes)
        write_exclusive(evidence_fd, "source-manifest.json", canonical(manifest))
        write_exclusive(evidence_fd, "source-snapshot.json", canonical({
            "schema": "supported-local-source-snapshot-v1", "sha256": sha(archive_bytes),
            "size": len(archive_bytes), "file_count": len(files),
            "tracked_count": sum(kind == "tracked" for _, kind, _, _ in files),
            "untracked_count": sum(kind == "untracked" for _, kind, _, _ in files)}))
    finally:
        os.close(repo_fd)
        os.close(evidence_fd)
        os.close(scratch_fd)


def main(args: list[str]) -> None:
    if len(args) == 4 and args[1] == "create-scratch":
        create_scratch(clean_absolute(args[2]), args[3])
    elif len(args) == 4 and args[1] == "cleanup-scratch":
        cleanup_scratch(clean_absolute(args[2]), args[3])
    elif len(args) == 5 and args[1] == "snapshot":
        snapshot(clean_absolute(args[2]), clean_absolute(args[3]), clean_absolute(args[4]))
    else:
        raise ProofBoundaryError


if __name__ == "__main__":
    try:
        main(sys.argv)
    except (ProofBoundaryError, OSError, ValueError, TypeError, json.JSONDecodeError, subprocess.CalledProcessError, tarfile.TarError):
        print("supported-local private bootstrap boundary failed", file=sys.stderr)
        raise SystemExit(1)
