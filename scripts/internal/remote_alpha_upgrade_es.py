#!/usr/bin/env python3
"""Remote Alpha ES upgrade: the pieces that do not depend on the host.

This file is the implementation behind scripts/remote_alpha_upgrade_es.sh.
This first part holds the two pure steps the upgrade is built on:

  migrate-config  add the keys current ES requires to an older es.json
  provision-key   create the retained-result key file, or accept an
                  existing one that already meets ES's rules

Both refuse anything they do not recognise rather than guess. Neither
prints key material.
"""

import argparse
import errno
import json
import os
import stat
import sys

# The retained-result key: exactly 32 raw bytes (an HMAC-SHA-256 key), a
# regular file with one link, owned by the user ES runs as, mode 0400 or
# 0600, in a directory owned by that user or root that is not group- or
# world-writable. ES checks this when it starts
# (es/admission/result_auth.go); provision-key checks it first so that a
# bad key is refused before ES is stopped.
RETAINED_RESULT_KEY_BYTES = 32
RETAINED_RESULT_KEY_MODES = (0o400, 0o600)

IDENTIFIER_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789_-")


class Refusal(Exception):
    """A condition the upgrade will not proceed past."""


def valid_identifier(value):
    # Mirrors validRetainedResultAuthIdentifier in es/config/config.go; the
    # migrated config is then checked by config.Load itself (esconfigcheck).
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 32
        and "a" <= value[0] <= "z"
        and set(value) <= IDENTIFIER_CHARS
    )


def clean_absolute(path):
    return (
        isinstance(path, str)
        and path.startswith("/")
        and not path.startswith("//")
        and os.path.normpath(path) == path
        and path.strip() == path
        and "\x00" not in path
        and os.path.dirname(path) != "/"
    )


def leaf_paths(value, prefix=""):
    """Every key path of a JSON document, with list positions as [].

    Values are not returned, so the result is safe to print."""
    paths = set()
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else key
            child_paths = leaf_paths(child, path)
            paths |= child_paths or {path}
    elif isinstance(value, list):
        for child in value:
            paths |= leaf_paths(child, prefix + "[]") or {prefix + "[]"}
    return paths


def insert_after(mapping, after_key, key, value):
    """A copy of mapping with key inserted just after after_key."""
    if after_key not in mapping:
        raise Refusal(f"expected key {after_key!r} is missing")
    out = {}
    for existing, existing_value in mapping.items():
        out[existing] = existing_value
        if existing == after_key:
            out[key] = value
    return out


def migrate_config(doc, token_file, auth, expected_source_paths=None):
    """Return (new_doc, changes) for an es.json document.

    token_file is the path for nomad.token_file; auth is the
    execution.retained_result_auth object. When expected_source_paths is
    given, the input's key paths must equal it exactly, so an es.json with
    any key this upgrade was not written for is refused. A document that
    already carries exactly these values is returned unchanged with no
    changes; one that carries other values is refused."""
    if not isinstance(doc, dict):
        raise Refusal("es.json is not a JSON object")
    if not clean_absolute(token_file):
        raise Refusal("the token file must be a clean absolute path with a non-root parent")
    if set(auth) != {"store_id", "key_id", "key_file"}:
        raise Refusal("retained_result_auth needs exactly store_id, key_id and key_file")
    if not valid_identifier(auth["store_id"]) or not valid_identifier(auth["key_id"]):
        raise Refusal("store_id and key_id must be canonical 1-32 byte identifiers")
    if not clean_absolute(auth["key_file"]) or auth["key_file"] == token_file:
        raise Refusal("the key file must be a clean absolute path, different from the token file")

    nomad = doc.get("nomad")
    execution = doc.get("execution")
    if not isinstance(nomad, dict) or not nomad.get("base_url"):
        raise Refusal("es.json has no nomad.base_url: this upgrade is for a submit-enabled ES")
    if not isinstance(execution, dict):
        raise Refusal("es.json has no execution section")

    has_token = "token_file" in nomad
    has_auth = "retained_result_auth" in execution
    if has_token or has_auth:
        if nomad.get("token_file") == token_file and execution.get("retained_result_auth") == auth:
            return doc, []
        raise Refusal(
            "es.json already has nomad.token_file or execution.retained_result_auth with other values; "
            "it was changed by something other than this upgrade"
        )

    if expected_source_paths is not None:
        found = leaf_paths(doc)
        expected = set(expected_source_paths)
        if found != expected:
            raise Refusal(
                "es.json's keys differ from the build this upgrade was written for: "
                f"unexpected {sorted(found - expected)}, missing {sorted(expected - found)}"
            )

    new_doc = dict(doc)
    new_nomad = dict(nomad)
    new_nomad["token_file"] = token_file
    new_doc["nomad"] = new_nomad
    new_doc["execution"] = insert_after(execution, "results_root_dir", "retained_result_auth", dict(auth))
    return new_doc, ["nomad.token_file", "execution.retained_result_auth"]


def render_json(doc):
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def check_key_parent(parent_fd, owner_uid):
    st = os.fstat(parent_fd)
    if not stat.S_ISDIR(st.st_mode):
        raise Refusal("the key's parent is not a directory")
    if st.st_uid not in (owner_uid, 0):
        raise Refusal("the key's parent directory must be owned by ES's user or root")
    if st.st_mode & 0o022:
        raise Refusal("the key's parent directory must not be group- or world-writable")


def check_key_stat(st, owner_uid):
    if not stat.S_ISREG(st.st_mode):
        raise Refusal("the key path is not a regular file")
    if st.st_nlink != 1:
        raise Refusal("the key file must have exactly one link")
    if st.st_uid != owner_uid:
        raise Refusal("the key file must be owned by ES's user")
    if stat.S_IMODE(st.st_mode) not in RETAINED_RESULT_KEY_MODES:
        raise Refusal("the key file's mode must be 0400 or 0600")
    if st.st_size != RETAINED_RESULT_KEY_BYTES:
        raise Refusal("the key file must hold exactly 32 bytes")


def provision_key(key_file, owner_uid, owner_gid, create_parent=True, dry_run=False):
    """Create the retained-result key, or accept an existing valid one.

    Returns "created", "exists" or (dry_run) "would create". The parent
    directory is created root:root 0755 when missing and create_parent is
    true. The key is written with O_EXCL and O_NOFOLLOW from os.urandom and
    then given to owner_uid with mode 0400. The key is never printed."""
    if not clean_absolute(key_file):
        raise Refusal("the key file must be a clean absolute path with a non-root parent")
    parent, name = os.path.split(key_file)
    try:
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError:
        if not create_parent:
            raise Refusal("the key's parent directory does not exist")
        if dry_run:
            return "would create"
        grand = os.path.dirname(parent)
        if not os.path.isdir(grand) or os.path.islink(grand):
            raise Refusal("the key directory's parent does not exist")
        os.mkdir(parent, 0o755)
        os.chown(parent, 0, 0) if os.geteuid() == 0 else None
        os.chmod(parent, 0o755)
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise Refusal("the key's parent is a symbolic link or not a directory")
        raise
    try:
        check_key_parent(parent_fd, owner_uid)
        try:
            st = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            st = None
        if st is not None:
            check_key_stat(st, owner_uid)
            return "exists"
        if dry_run:
            return "would create"
        fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o400,
            dir_fd=parent_fd,
        )
        try:
            data = os.urandom(RETAINED_RESULT_KEY_BYTES)
            written = os.write(fd, data)
            if written != RETAINED_RESULT_KEY_BYTES:
                raise Refusal("short write of the key file")
            os.fchown(fd, owner_uid, owner_gid)
            os.fchmod(fd, 0o400)
            os.fsync(fd)
            check_key_stat(os.fstat(fd), owner_uid)
        finally:
            os.close(fd)
        os.fsync(parent_fd)
        return "created"
    finally:
        os.close(parent_fd)


def cmd_migrate_config(args):
    with open(args.input, encoding="utf-8") as handle:
        doc = json.load(handle)
    expected = None
    if args.expected_paths:
        with open(args.expected_paths, encoding="utf-8") as handle:
            expected = [line.strip() for line in handle if line.strip()]
    auth = {"store_id": args.store_id, "key_id": args.key_id, "key_file": args.key_file}
    new_doc, changes = migrate_config(doc, args.token_file, auth, expected)
    if args.output:
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(render_json(new_doc))
    print(json.dumps({"changes": changes}))


def cmd_provision_key(args):
    result = provision_key(args.key_file, args.owner_uid, args.owner_gid, dry_run=args.dry_run)
    print(json.dumps({"key_file": args.key_file, "result": result}))


def main(argv):
    parser = argparse.ArgumentParser(prog="remote_alpha_upgrade_es.py")
    sub = parser.add_subparsers(dest="command", required=True)

    mc = sub.add_parser("migrate-config")
    mc.add_argument("--input", required=True)
    mc.add_argument("--output")
    mc.add_argument("--expected-paths")
    mc.add_argument("--token-file", required=True)
    mc.add_argument("--store-id", required=True)
    mc.add_argument("--key-id", required=True)
    mc.add_argument("--key-file", required=True)
    mc.set_defaults(func=cmd_migrate_config)

    pk = sub.add_parser("provision-key")
    pk.add_argument("--key-file", required=True)
    pk.add_argument("--owner-uid", type=int, required=True)
    pk.add_argument("--owner-gid", type=int, required=True)
    pk.add_argument("--dry-run", action="store_true")
    pk.set_defaults(func=cmd_provision_key)

    args = parser.parse_args(argv)
    try:
        args.func(args)
    except Refusal as exc:
        print(f"remote alpha ES upgrade refused: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
