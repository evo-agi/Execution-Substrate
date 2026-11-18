#!/usr/bin/env python3
"""Fixed service-root-v1 provisioning for two fresh supported-local ES roots."""
from __future__ import annotations

import contextlib
import functools
import json
import os
import re
import stat
import sys

PROFILE = "service-root-v1"
ROOT_NAMES = ("es-staging", "es-results")
MARKER = ".supported-local-es-root-binding-v1"
ROOT_UID = 0
ROOT_GID = 0
ROOT_MODE = 0o755
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
PROOF_ID = re.compile(r"[A-Za-z0-9_-]{1,80}\Z", re.ASCII)


class Refusal(Exception):
    """A fixed safe failure at this narrow setup or static-check boundary."""


def guarded(function):
    @functools.wraps(function)
    def call(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except Refusal:
            raise
        except (OSError, ValueError, TypeError, UnicodeError, KeyError, IndexError):
            raise Refusal() from None
    return call


def clean_proof_path(path: str, proof_id: str) -> None:
    if not isinstance(path, str) or not isinstance(proof_id, str):
        raise Refusal()
    if not PROOF_ID.fullmatch(proof_id):
        raise Refusal()
    if (not path.startswith("/") or path.startswith("//") or path == "/"
            or "\x00" in path or os.path.normpath(path) != path
            or os.path.dirname(path) == "/"):
        raise Refusal()
    source_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
    if (path == source_root or path.startswith(source_root + "/")
            or source_root.startswith(path + "/")):
        raise Refusal()


def identity(s):
    return (s.st_dev, s.st_ino, stat.S_IFMT(s.st_mode), s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode))


def object_identity(s):
    return (s.st_dev, s.st_ino, stat.S_IFMT(s.st_mode))


def file_signature(s):
    return identity(s) + (s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


@guarded
def open_chain(path: str):
    if not path.startswith("/") or os.path.normpath(path) != path or path.startswith("//"):
        raise Refusal()
    root_fd = os.open("/", DIR_FLAGS)
    chain = [(root_fd, None, None, identity(os.fstat(root_fd)))]
    try:
        for component in path.split("/")[1:]:
            if component in ("", ".", ".."):
                raise Refusal()
            parent_fd = chain[-1][0]
            named = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
            if not stat.S_ISDIR(named.st_mode):
                raise Refusal()
            fd = os.open(component, DIR_FLAGS, dir_fd=parent_fd)
            if identity(os.fstat(fd)) != identity(named):
                os.close(fd)
                raise Refusal()
            chain.append((fd, parent_fd, component, identity(named)))
        return chain
    except Exception:
        close_chain(chain)
        raise


def close_chain(chain) -> None:
    for fd, _, _, _ in reversed(chain):
        os.close(fd)


@guarded
def assert_chain_stable(chain) -> None:
    for fd, parent_fd, name, expected in chain:
        if identity(os.fstat(fd)) != expected:
            raise Refusal()
        if parent_fd is not None:
            named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if identity(named) != expected:
                raise Refusal()


def absent(root_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=root_fd, follow_symlinks=False)
    except FileNotFoundError:
        return True
    return False


@guarded
def preflight_path(path: str, proof_id: str) -> None:
    clean_proof_path(path, proof_id)
    parent, name = os.path.split(path)
    chain = open_chain(parent)
    try:
        if not absent(chain[-1][0], name):
            raise Refusal()
        assert_chain_stable(chain)
    finally:
        close_chain(chain)


def marker_bytes(proof_id: str, root_stat) -> bytes:
    return (json.dumps({"schema": "supported-local-es-root-binding-v1",
                        "proof_id": proof_id, "device": root_stat.st_dev,
                        "inode": root_stat.st_ino}, sort_keys=True,
                       separators=(",", ":")) + "\n").encode("ascii")


@guarded
def bind_fresh_proof(path: str, proof_id: str) -> str:
    clean_proof_path(path, proof_id)
    chain = open_chain(path)
    try:
        root_fd = chain[-1][0]
        root_stat = os.fstat(root_fd)
        if root_stat.st_uid != os.geteuid() or not all(absent(root_fd, n) for n in (*ROOT_NAMES, MARKER)):
            raise Refusal()
        payload = marker_bytes(proof_id, root_stat)
        marker_fd = os.open(MARKER, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                            0o600, dir_fd=root_fd)
        try:
            os.fchmod(marker_fd, 0o600)
            if os.write(marker_fd, payload) != len(payload):
                raise Refusal()
            os.fsync(marker_fd)
            marker_stat = os.fstat(marker_fd)
            if (not stat.S_ISREG(marker_stat.st_mode) or marker_stat.st_nlink != 1
                    or marker_stat.st_uid != root_stat.st_uid
                    or marker_stat.st_gid != root_stat.st_gid
                    or stat.S_IMODE(marker_stat.st_mode) != 0o600
                    or marker_stat.st_dev != root_stat.st_dev):
                raise Refusal()
            visible = os.stat(MARKER, dir_fd=root_fd, follow_symlinks=False)
            if identity(visible) != identity(marker_stat):
                raise Refusal()
            binding = f"{root_stat.st_dev}:{root_stat.st_ino}:{marker_stat.st_ino}"
        finally:
            os.close(marker_fd)
        assert_chain_stable(chain)
        return binding
    finally:
        close_chain(chain)


def read_marker(root_fd: int, proof_id: str, root_stat, binding: str | None = None) -> None:
    marker_fd = os.open(MARKER, FILE_FLAGS, dir_fd=root_fd)
    try:
        before = os.fstat(marker_fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != root_stat.st_uid or before.st_gid != root_stat.st_gid
                or before.st_dev != root_stat.st_dev or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_size > 256 or before.st_size <= 0):
            raise Refusal()
        data = os.read(marker_fd, before.st_size + 1)
        after = os.fstat(marker_fd)
        visible = os.stat(MARKER, dir_fd=root_fd, follow_symlinks=False)
        if (len(data) != before.st_size or file_signature(before) != file_signature(after)
                or file_signature(before) != file_signature(visible)
                or data != marker_bytes(proof_id, root_stat)):
            raise Refusal()
        if binding is not None and binding != f"{root_stat.st_dev}:{root_stat.st_ino}:{before.st_ino}":
            raise Refusal()
    finally:
        os.close(marker_fd)


class SystemOps:
    mkdir = staticmethod(os.mkdir)
    open = staticmethod(os.open)
    fchown = staticmethod(os.fchown)
    fchmod = staticmethod(os.fchmod)
    fstat = staticmethod(os.fstat)
    stat = staticmethod(os.stat)


def check_child(root_fd: int, root_stat, name: str, ops) -> None:
    named = ops.stat(name, dir_fd=root_fd, follow_symlinks=False)
    if not stat.S_ISDIR(named.st_mode):
        raise Refusal()
    fd = ops.open(name, DIR_FLAGS, dir_fd=root_fd)
    try:
        held = ops.fstat(fd)
        visible = ops.stat(name, dir_fd=root_fd, follow_symlinks=False)
        for child in (named, held, visible):
            if (not stat.S_ISDIR(child.st_mode) or child.st_dev != root_stat.st_dev
                    or child.st_uid != ROOT_UID or child.st_gid != ROOT_GID
                    or stat.S_IMODE(child.st_mode) != ROOT_MODE or child.st_nlink < 1):
                raise Refusal()
        if identity(named) != identity(held) or identity(held) != identity(visible):
            raise Refusal()
    finally:
        os.close(fd)


def check_held_child(root_fd: int, root_stat, name: str, fd: int, acquired_identity, ops) -> None:
    held = ops.fstat(fd)
    visible = ops.stat(name, dir_fd=root_fd, follow_symlinks=False)
    for child in (held, visible):
        if (not stat.S_ISDIR(child.st_mode) or child.st_dev != root_stat.st_dev
                or child.st_uid != ROOT_UID or child.st_gid != ROOT_GID
                or stat.S_IMODE(child.st_mode) != ROOT_MODE or child.st_nlink < 1
                or object_identity(child) != acquired_identity):
            raise Refusal()
    if identity(held) != identity(visible):
        raise Refusal()


@guarded
def provision_pair(path: str, proof_id: str, binding: str, ops=None) -> None:
    clean_proof_path(path, proof_id)
    ops = ops or SystemOps()
    with contextlib.ExitStack() as held_descriptors:
        chain = open_chain(path)
        held_descriptors.callback(close_chain, chain)
        root_fd = chain[-1][0]
        root_stat = os.fstat(root_fd)
        read_marker(root_fd, proof_id, root_stat, binding)
        if not all(absent(root_fd, name) for name in ROOT_NAMES):
            raise Refusal()
        assert_chain_stable(chain)
        held_children = []
        for name in ROOT_NAMES:
            ops.mkdir(name, ROOT_MODE, dir_fd=root_fd)
            # The proof parent is operator-owned. mkdir/open is not an atomic
            # creation handle; check the acquired object before mutating it.
            fd = ops.open(name, DIR_FLAGS, dir_fd=root_fd)
            held_descriptors.callback(os.close, fd)
            assert_chain_stable(chain)
            read_marker(root_fd, proof_id, root_stat, binding)
            acquired = ops.fstat(fd)
            visible = ops.stat(name, dir_fd=root_fd, follow_symlinks=False)
            if (not stat.S_ISDIR(acquired.st_mode) or acquired.st_dev != root_stat.st_dev
                    or acquired.st_uid != os.geteuid() or acquired.st_nlink < 1
                    or identity(acquired) != identity(visible)):
                raise Refusal()
            acquired_identity = object_identity(acquired)
            held_children.append((name, fd, acquired_identity))
            ops.fchown(fd, ROOT_UID, ROOT_GID)
            ops.fchmod(fd, ROOT_MODE)
            check_held_child(root_fd, root_stat, name, fd, acquired_identity, ops)
            assert_chain_stable(chain)
        for name, fd, acquired_identity in held_children:
            check_held_child(root_fd, root_stat, name, fd, acquired_identity, ops)
        assert_chain_stable(chain)
        read_marker(root_fd, proof_id, root_stat, binding)


def read_config(root_fd: int):
    fd = os.open("es.json", FILE_FLAGS, dir_fd=root_fd)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > (1 << 20):
            raise Refusal()
        data = os.read(fd, before.st_size + 1)
        after = os.fstat(fd)
        named = os.stat("es.json", dir_fd=root_fd, follow_symlinks=False)
        if (len(data) != before.st_size or file_signature(before) != file_signature(after)
                or file_signature(before) != file_signature(named)):
            raise Refusal()
        return json.loads(data)
    finally:
        os.close(fd)


@guarded
def check_profile(path: str, proof_id: str, config_path: str, ops=None) -> None:
    clean_proof_path(path, proof_id)
    if config_path != path + "/es.json":
        raise Refusal()
    ops = ops or SystemOps()
    chain = open_chain(path)
    try:
        root_fd = chain[-1][0]
        root_stat = os.fstat(root_fd)
        read_marker(root_fd, proof_id, root_stat)
        config = read_config(root_fd)
        execution = config.get("execution") if isinstance(config, dict) else None
        if not isinstance(execution, dict):
            raise Refusal()
        if (execution.get("staging_root_dir") != path + "/es-staging"
                or execution.get("results_root_dir") != path + "/es-results"):
            raise Refusal()
        for name in ROOT_NAMES:
            check_child(root_fd, root_stat, name, ops)
        assert_chain_stable(chain)
    finally:
        close_chain(chain)


def main(argv: list[str]) -> int:
    try:
        if len(argv) == 4 and argv[1] == "preflight":
            preflight_path(argv[2], argv[3])
        elif len(argv) == 4 and argv[1] == "bind":
            print(bind_fresh_proof(argv[2], argv[3]))
        elif len(argv) == 5 and argv[1] == "provision":
            if os.geteuid() != 0:
                raise Refusal()
            provision_pair(argv[2], argv[3], argv[4])
        elif len(argv) == 5 and argv[1] == "check":
            check_profile(argv[2], argv[3], argv[4])
        else:
            raise Refusal()
        return 0
    except Exception:
        print("supported-local execution roots invalid", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
