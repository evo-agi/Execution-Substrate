#!/usr/bin/env -S python3 -I
"""Remote Alpha ES upgrade: move the box's ES to a named commit, with Nomad's
API behind HTTPS and its gossip encrypted.

This file is the implementation behind scripts/remote_alpha_upgrade_es.sh.
It leaves the box at the named commit with Nomad serving its API and RPC only
over TLS 1.3 (part 2b of the Nomad lock) and encrypting its gossip with a
keyring the setup's nomad_gossip_issue wrote (red-team RT60-1): the shape
"https-gossip". check and apply first read the host's shape from nomad.hcl,
Nomad's TLS directory, es.json, the installed ES binaries and Nomad's gossip
keyring. They start from either of two shapes:

  locked-http     where the upgrade of ES PR #54 left the box: ES built from
                  16cbf739, Nomad enforcing ACLs on plain HTTP, no keyring
  https           where the upgrade of ES PR #60 left it, or a later run of
                  this one: Nomad on HTTPS with ES's pin, ES a clean build of
                  any commit but 16cbf739, and either no keyring or a sound
                  one, but not both the payload's build and a keyring

On either, check reports every change apply would make. On "https-gossip"
for the named commit there is nothing to do: both exit 0 and change nothing.
Any other shape is refused, naming what each part looks like. Both also
read the move, from the commit the installed ES binaries were built from to
the named one, in the clone's history: one that is not forward (to an older
commit, to one on another line, or to one whose order the clone cannot
show) runs only when root names it on the command line as
--allow-downgrade <installed commit>..<named commit>, and apply records it
in its backup. rollback puts back a backup only when no backup made after
it is still in effect (each was put back since) and the installed ES
binaries are what its apply left (the byte rule), and records each rollback
in that backup. The host steps:

  build           (unprivileged) build es, es-runtime-support and the
                  config check helper from this clean checkout, with
                  provenance
  check           (root, read-only) verify the payload and the host and
                  print every change apply would make; refuse anything
                  this upgrade was not written for
  apply           (root) check, back up, stop ES; on locked-http issue
                  Nomad's TLS material; write the gossip keyring if there
                  is none; restart Nomad when either changed (on HTTPS,
                  with its ACLs provisioned again or checked); migrate
                  es.json, install the binaries, start ES and verify; on
                  any failure, put the backup back
  rollback        (root) put back the backup of the apply that left the
                  host as it is, remove what apply created (the TLS
                  directory, the keyring) and start Nomad and ES

and the host-independent pieces they are built on:

  migrate-config  add the Nomad TLS keys current ES requires to the box's
                  es.json
  provision-key   create the retained-result key file, or accept an
                  existing one that already meets ES's rules (check and
                  apply use it to verify the key the first upgrade made)
  backup          copy named files, with owner, mode and SHA-256, into a
                  new root-only backup directory
  restore         put every file of such a backup back exactly

Everything refuses what it does not recognise rather than guess. Nothing
prints key or token material.
"""

import argparse
import errno
import grp
import hashlib
import json
import os
import pwd
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time

# The retained-result key: exactly 32 raw bytes (an HMAC-SHA-256 key), a
# regular file with one link, owned by the user ES runs as, mode 0400 or
# 0600, in a directory owned by that user or root that is not group- or
# world-writable. ES checks this when it starts
# (es/admission/result_auth.go); provision-key checks it first so that a
# bad key is refused before ES is stopped.
RETAINED_RESULT_KEY_BYTES = 32
RETAINED_RESULT_KEY_MODES = (0o400, 0o600)


class Refusal(Exception):
    """A condition the upgrade will not proceed past."""


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


# Nomad's HTTPS identity on the box: what scripts/70_linux_setup.sh issues
# and what ES then trusts. A test keeps the TLS paths and the server name
# equal to the setup's.
NOMAD_PORT = 4646
NOMAD_TLS_DIR = "/etc/nomad.d/tls"
NOMAD_CA_FILE = NOMAD_TLS_DIR + "/ca.pem"
NOMAD_CERT_FILE = NOMAD_TLS_DIR + "/server.pem"
NOMAD_KEY_FILE = NOMAD_TLS_DIR + "/server-key.pem"
NOMAD_SERVER_NAME = "server.global.nomad"
NOMAD_TLS_KEYS = ("server_name", "root_ca_file", "server_spki_sha256")
SPKI_CHARS = set("0123456789abcdef")


def nomad_port():
    """Nomad's HTTP(S) port: 4646, or a free one the real-Nomad test sets
    under a test host root."""
    if HOST_ROOT != "/" and os.environ.get("ES_UPGRADE_TEST_NOMAD_PORT"):
        return int(os.environ["ES_UPGRADE_TEST_NOMAD_PORT"])
    return NOMAD_PORT


def nomad_http_addr():
    return f"http://127.0.0.1:{nomad_port()}"


def nomad_https_addr():
    return f"https://127.0.0.1:{nomad_port()}"


def valid_spki(value):
    return isinstance(value, str) and len(value) == 64 and set(value) <= SPKI_CHARS


def migrate_config(doc, spki_sha256, expected_source_paths=None):
    """Return (new_doc, changes) for an es.json document.

    The box's es.json reaches Nomad at its plain-HTTP address. The migrated
    one reaches it at the HTTPS address, trusting only Nomad's CA for
    Nomad's server name, and pins spki_sha256, the SHA-256 of the server
    certificate's public key. When expected_source_paths is given, the
    input's key paths must equal it exactly, so an es.json with any key this
    upgrade was not written for is refused. A document that already carries
    exactly these values is returned unchanged with no changes; one that
    carries other values is refused."""
    if not isinstance(doc, dict):
        raise Refusal("es.json is not a JSON object")
    if not valid_spki(spki_sha256):
        raise Refusal("the pin must be the lowercase hex SHA-256 of Nomad's server public key (64 characters)")
    nomad = doc.get("nomad")
    if not isinstance(nomad, dict) or not nomad.get("base_url"):
        raise Refusal("es.json has no nomad.base_url: this upgrade is for a submit-enabled ES")

    target = {"base_url": nomad_https_addr(), "server_name": NOMAD_SERVER_NAME,
              "root_ca_file": NOMAD_CA_FILE, "server_spki_sha256": spki_sha256}
    if any(key in nomad for key in NOMAD_TLS_KEYS):
        if all(nomad.get(key) == value for key, value in target.items()):
            return doc, []
        raise Refusal(
            "es.json already has Nomad TLS settings with other values; "
            "it was changed by something other than this upgrade"
        )
    if nomad["base_url"] != nomad_http_addr():
        raise Refusal(f"es.json's nomad.base_url is {nomad['base_url']!r}, not {nomad_http_addr()!r}")

    if expected_source_paths is not None:
        found = leaf_paths(doc)
        expected = set(expected_source_paths)
        if found != expected:
            raise Refusal(
                "es.json's keys differ from the build this upgrade was written for: "
                f"unexpected {sorted(found - expected)}, missing {sorted(expected - found)}"
            )

    new_nomad = dict(nomad, base_url=target["base_url"])
    after = "base_url"
    for key in NOMAD_TLS_KEYS:
        new_nomad = insert_after(new_nomad, after, key, target[key])
        after = key
    new_doc = dict(doc)
    new_doc["nomad"] = new_nomad
    return new_doc, ["nomad.base_url", *[f"nomad.{key}" for key in NOMAD_TLS_KEYS]]


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


BACKUP_MANIFEST = "manifest.json"
# v2: the backups of this upgrade. A v1 backup, of ES PR #54's upgrade,
# also holds directory owners and modes that this restore does not put
# back, so it is refused here; the script at 16cbf739 restores it.
BACKUP_SCHEMA = "execution-substrate.remote-alpha.es-upgrade-backup.v2"


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def read_regular_file(path):
    """(data, stat) of a regular file, opened without following a link."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise Refusal(f"{path} is a symbolic link")
        raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise Refusal(f"{path} is not a regular file")
        chunks = []
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks), st
    finally:
        os.close(fd)


def atomic_replace(path, data, uid, gid, mode):
    """Replace path with data, owner and mode in one rename.

    The new file is written next to the old one, synced, and renamed over
    it; the directory is synced after. A symbolic link at path is
    replaced, never followed."""
    parent, name = os.path.split(path)
    tmp = os.path.join(parent, f".{name}.es-upgrade.{os.getpid()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        if os.geteuid() == 0:
            os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        os.unlink(tmp)
        raise
    os.close(fd)
    os.rename(tmp, path)
    dir_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def file_record(path):
    try:
        data, st = read_regular_file(path)
    except FileNotFoundError:
        return {"path": path, "exists": False}, None
    return {
        "path": path,
        "exists": True,
        "sha256": sha256_bytes(data),
        "size": len(data),
        "mode": format(stat.S_IMODE(st.st_mode), "04o"),
        "uid": st.st_uid,
        "gid": st.st_gid,
    }, data


def backup_files(backup_dir, paths):
    """Copy each path into a new backup directory and write its manifest.

    The directory must not exist yet; it is created 0700. A path that does
    not exist is recorded as absent. Returns the manifest."""
    if len(set(paths)) != len(paths) or not all(clean_absolute(p) for p in paths):
        raise Refusal("backup paths must be distinct clean absolute paths")
    os.mkdir(backup_dir, 0o700)
    os.chmod(backup_dir, 0o700)
    files_dir = os.path.join(backup_dir, "files")
    os.mkdir(files_dir, 0o700)
    entries = []
    for index, path in enumerate(paths):
        record, data = file_record(path)
        if data is not None:
            copy = f"{index:02d}-{os.path.basename(path)}"
            fd = os.open(os.path.join(files_dir, copy), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            record["copy"] = copy
        entries.append(record)
    manifest = {"schema": BACKUP_SCHEMA, "files": entries}
    fd = os.open(os.path.join(backup_dir, BACKUP_MANIFEST), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(manifest, indent=2) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    return manifest


def read_backup_document(backup_dir, name, cut_off):
    """The JSON document name in backup_dir. apply writes it before it
    changes the host, so a missing or cut-short one is refused, saying so
    (cut_off), not a traceback (re-check 49 of ES PR #67, O67-3)."""
    path = os.path.join(backup_dir, name)
    try:
        data, _ = read_regular_file(path)
        return json.loads(data)
    except FileNotFoundError:
        raise Refusal(f"{path} is missing: {cut_off}; nothing was changed") from None
    except ValueError as exc:
        raise Refusal(f"{path} cannot be read ({exc}): {cut_off}; nothing was changed") from None


BACKUP_COPY_NAME = re.compile(r"[0-9]{2,}-[^/\x00]+")
BACKUP_FILE_MODE = re.compile(r"[0-7]{4}")
BACKUP_SHA256 = re.compile(r"[0-9a-f]{64}")
# An owner or group that chown takes: Linux's uid_t and gid_t are 32 bits,
# and the largest value, (uid_t)-1, means "leave it as it is".
BACKUP_ID_LIMIT = 2**32 - 1


def check_backup_manifest(manifest, path):
    """Refuse a manifest, read from path, that is valid JSON but not the
    document backup_files writes, naming what is wrong, rather than fail
    with a traceback on a value of another type (re-check 50 of ES PR #67,
    O50-1): an object with the schema and a list of files, each an object
    with its path (clean and absolute, with no NUL) and whether it existed
    and, if it did, its copy's name in files/ (with no NUL), its digest,
    size, mode, and an owner and group that chown takes. Each value it
    admits is one restore_files can use, so it is refused here, before
    anything stops, rather than by open() or chown later, after the first
    file was put back (re-check 51, N67-9 and S51-3)."""
    def refuse(what):
        raise Refusal(f"{path} is not the manifest apply writes ({what}); nothing was changed")

    if not isinstance(manifest, dict):
        kind = {list: "list", str: "string", int: "number", float: "number", bool: "boolean"}.get(type(manifest), "null")
        refuse(f"it is a JSON {kind}, not an object")
    if manifest.get("schema") != BACKUP_SCHEMA:
        raise Refusal("the backup manifest has an unknown schema")
    files = manifest.get("files")
    if not isinstance(files, list):
        refuse("its files are not a list")
    for index, entry in enumerate(files):
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str) or type(entry.get("exists")) is not bool:
            refuse(f"file {index} is not an object with a path and whether it existed")
        if "\x00" in entry["path"]:
            refuse(f"file {index}'s path holds a NUL")
        if not clean_absolute(entry["path"]):
            refuse(f"file {index}'s path, {entry['path']!r}, is not a clean absolute path")
        if not entry["exists"]:
            continue
        copy, digest, mode = entry.get("copy"), entry.get("sha256"), entry.get("mode")
        if not (isinstance(copy, str) and BACKUP_COPY_NAME.fullmatch(copy)
                and isinstance(digest, str) and BACKUP_SHA256.fullmatch(digest)
                and isinstance(mode, str) and BACKUP_FILE_MODE.fullmatch(mode)
                and all(type(entry.get(key)) is int and entry[key] >= 0 for key in ("size", "uid", "gid"))
                and entry["uid"] < BACKUP_ID_LIMIT and entry["gid"] < BACKUP_ID_LIMIT):
            refuse(f"file {index}, {entry['path']!r}, lacks its copy's name, digest, size, mode, owner or group")


def load_backup(backup_dir):
    st = os.lstat(backup_dir)
    if not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o700 or st.st_uid != os.geteuid():
        raise Refusal("the backup directory must be a 0700 directory owned by the user running the restore")
    manifest = read_backup_document(backup_dir, BACKUP_MANIFEST,
                                    "the backup's apply stopped before it changed the host, so there is nothing to put back")
    check_backup_manifest(manifest, os.path.join(backup_dir, BACKUP_MANIFEST))
    for entry in manifest["files"]:
        if not entry["exists"]:
            continue
        copy_path = os.path.join(backup_dir, "files", entry["copy"])
        try:
            copy, _ = read_regular_file(copy_path)
        except FileNotFoundError:
            raise Refusal(f"the backup copy of {entry['path']}, {copy_path}, is missing; nothing was changed") from None
        except OSError as exc:
            raise Refusal(f"the backup copy of {entry['path']}, {copy_path}, cannot be read ({exc}); nothing was changed") from None
        if sha256_bytes(copy) != entry["sha256"] or len(copy) != entry["size"]:
            raise Refusal(f"the backup copy of {entry['path']} does not match its manifest")
    return manifest


def restore_files(backup_dir):
    """Put every backed-up file back with its bytes, owner and mode.

    The whole backup is verified before anything is written. Files that
    were absent at backup time are left as they are and reported."""
    manifest = load_backup(backup_dir)
    # Each file goes back into the folder it was taken from: one that is
    # gone is refused before the first file is put back.
    for entry in manifest["files"]:
        parent = os.path.dirname(entry["path"])
        if entry["exists"] and not os.path.isdir(parent):
            raise Refusal(f"{parent}, where the backup puts {entry['path']} back, is not a folder; nothing was changed")
    restored, left = [], []
    for entry in manifest["files"]:
        if not entry["exists"]:
            left.append(entry["path"])
            continue
        try:
            current, _ = file_record(entry["path"])
        except Refusal:
            current = {}  # a link or a non-file now stands there: replace it
        same = all(current.get(k) == entry[k] for k in ("exists", "sha256", "mode", "uid", "gid"))
        if not same:
            copy, _ = read_regular_file(os.path.join(backup_dir, "files", entry["copy"]))
            atomic_replace(entry["path"], copy, entry["uid"], entry["gid"], int(entry["mode"], 8))
        after, _ = file_record(entry["path"])
        if after.get("sha256") != entry["sha256"] or after.get("mode") != entry["mode"]:
            raise Refusal(f"{entry['path']} does not match its backup after the restore")
        restored.append({"path": entry["path"], "changed": not same})
    return {"restored": restored, "absent_at_backup": left}


def cmd_backup(args):
    manifest = backup_files(args.backup_dir, args.path)
    print(json.dumps({"backup_dir": args.backup_dir, "files": len(manifest["files"])}))


def cmd_restore(args):
    print(json.dumps(restore_files(args.backup_dir)))


def cmd_migrate_config(args):
    with open(args.input, encoding="utf-8") as handle:
        doc = json.load(handle)
    expected = None
    if args.expected_paths:
        with open(args.expected_paths, encoding="utf-8") as handle:
            expected = [line.strip() for line in handle if line.strip()]
    new_doc, changes = migrate_config(doc, args.spki_sha256, expected)
    if args.output:
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(render_json(new_doc))
    print(json.dumps({"changes": changes}))


def cmd_provision_key(args):
    result = provision_key(args.key_file, args.owner_uid, args.owner_gid, dry_run=args.dry_run)
    print(json.dumps({"key_file": args.key_file, "result": result}))




# ---------------------------------------------------------------------------
# The Remote Alpha host. The paths and values below are the box's as the
# read-only preflight of 2026-11-24 read them (project files
# es-box-upgrade/01-preflight/) and as the upgrade of ES PR #54 and the
# host-network repair of that day left them (es-box-upgrade/08-box-run-report.md,
# 09-nomad-network/). check refuses a host that differs from them.
# ---------------------------------------------------------------------------

ES_CONFIG = "/etc/execution-substrate/es.json"
ES_CONFIG_MODE = 0o640  # root:es
AGS_CONFIG = "/etc/execution-substrate/ags.json"
ES_BINARY = "/usr/local/lib/execution-substrate/bin/es"
RUNTIME_SUPPORT = "/usr/local/bin/es-runtime-support"
BINARY_MODE = 0o755  # root:root
ES_EXEC_START = f"argv[]={ES_BINARY} -config {ES_CONFIG} ;"
HEALTHCHECK_ENV = "/etc/execution-substrate/healthcheck.env"
NOMAD_DIR = "/etc/nomad.d"
NOMAD_HCL = "/etc/nomad.d/nomad.hcl"
# The EnvironmentFile of the package's nomad.service, which Nomad reads as
# root; optional ("-" in the unit).
NOMAD_ENV = "/etc/nomad.d/nomad.env"
# How root puts nomad.env back as a new file of its own, with its contents:
# the only way that an old write handle no longer reaches it.


def replace_remedy(path, mode):
    """How the operator puts back a file of Nomad's that another account
    could write: as a new file of root's, since a chown, a chmod or setfacl
    in place leaves a handle that the account opened earlier able to write
    it. install opens its source, so this is for a regular file only."""
    return (f"put it back as a new file of root's, then check what it sets: rm -f {path}.new && "
            f"install -o root -g root -m {mode:04o} {path} {path}.new && mv -T {path}.new {path} "
            f"(a chown, a chmod or setfacl leaves a handle that another account opened earlier able to write it)")


NOMAD_ENV_REMEDY = replace_remedy(NOMAD_ENV, 0o600)
NOMAD_CONFIG_MODE = 0o640  # root:root, as scripts/70_linux_setup.sh writes nomad.hcl
# apply replaces nomad.hcl only on a host it moves to HTTPS; on one already
# on HTTPS, nomad.hcl stays the same file (re-check 51 of ES PR #67, S51-1).
NOMAD_HCL_REMEDY = replace_remedy(NOMAD_HCL, NOMAD_CONFIG_MODE)
# Nomad runs as root, so only root may change what it reads or keeps (audit
# INF-16). ES PR #54's upgrade made these directories root:root with these
# modes. Nomad's TLS directory goes in the first, root:root 0755 as the
# setup makes it, and holds exactly the setup's three files.
NOMAD_DIRS = ((NOMAD_DIR, 0o755), ("/opt/nomad", 0o755), ("/opt/nomad/data", 0o700))
# Nor may another account keep an ACL on them. HashiCorp's package gives
# /etc/nomad.d and the data directory to the nomad account, which may set an
# ACL on a folder while it owns it, and the owner and mode do not show one.
# A default ACL decides the mode of each file root then creates in the
# folder, whatever the umask, and an access ACL keeps entries on the folder.
# scripts/70_linux_setup.sh removes both when it takes the folders back
# (re-check 48 of ES PR #66); this upgrade refuses a folder that has one,
# and nomad.hcl, Nomad's TLS directory and its server folder with one.
POSIX_ACLS = ("system.posix_acl_access", "system.posix_acl_default")
NOMAD_TLS_DIR_MODE = 0o755
NOMAD_TLS_FILES = ("ca.pem", "server-key.pem", "server.pem")
NOMAD_ACL_DIR = "/etc/execution-substrate/nomad-acl"
ES_TOKEN_FILE = NOMAD_ACL_DIR + "/es-token"
# The healthcheck runbook runs its checks with sudo, so the read-only
# observer token is root's. Pass the same OBSERVER_USER to any later
# `nomad_acl_setup.sh check` or `rotate` on this host.
OBSERVER_USER = "root"
KEY_FILE = "/etc/execution-substrate/retained-result-auth/es.key"
STORE_ID = "remote-alpha"
KEY_ID = "k1"
BACKUP_ROOT = "/var/backups/execution-substrate-es-upgrade"
ES_USER = "es"
SERVICES = ("ars", "ags", "egs", "es", "vault", "spire-server", "spire-agent", "nomad", "docker")
PAYLOAD_FILES = ("es", "es-runtime-support", "esconfigcheck")
# The binaries apply installs. Each must name the commit in its own Go build
# info, not only in provenance.json. esconfigcheck is a checker the upgrade
# runs, not something it installs.
STAMPED_PAYLOAD_FILES = ("es", "es-runtime-support")
# The package each payload file is built from, below the module's path.
PAYLOAD_PACKAGES = {"es": "cmd/es", "es-runtime-support": "cmd/es-runtime-support",
                    "esconfigcheck": "scripts/internal/esconfigcheck"}
# The commands build runs, and the git that reads a commit's go.mod and
# go.sum, take nothing from the environment but what is set here
# (audit 33, A33-1). PATH holds only root's folders, where git is. git reads
# only the repository's own config: neither the system's nor the user's
# (XDG_CONFIG_HOME, ~/.gitconfig), where another account's hook could wait.
# It reads the objects a commit names, not what refs/replace puts in their
# place.
BUILD_PATH = "/usr/bin:/bin"
GIT_ENV = {"PATH": BUILD_PATH, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_NO_REPLACE_OBJECTS": "1"}
# The only variables build passes on from its own environment: what Go's
# module download needs to reach the module proxy from behind a proxy.
# None of them can change what is compiled, since Go checks every module
# against the commit's go.sum.
BUILD_PASSED_VARIABLES = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy",
                          "SSL_CERT_FILE", "SSL_CERT_DIR")
# The one module proxy build's Go is told to fetch modules through, and
# nothing else. With "direct" after it, as the toolchain's go.env has it, a
# module the proxy does not have would make Go look the module's path up on
# the server the path names, whose go-import tag can send Go to any server
# to download it over the module proxy protocol, which GOVCS cannot forbid
# (audit 35, A35-1). Without it, such a module fails the build. The
# proxy itself may answer a download with a redirect to its own storage
# (storage.googleapis.com), which Go follows (audit 36, A36-1);
# go.sum checks every byte, wherever they come from.
BUILD_GOPROXY = "https://proxy.golang.org"
# What build asks go env for, as JSON.
BUILD_GO_ENV_KEYS = ("GOVERSION", "GOROOT", "GONOPROXY")
SUPPORTED_GO_VERSION = "go1.26.5"
SUMMARY_SCHEMA = "execution-substrate.remote-alpha.es-upgrade-summary.v2"
LEADER_WAIT_SECONDS = 90
PLACEMENT_WAIT_SECONDS = 120
ES_WAIT_SECONDS = 60
# Docker labels every container of a Nomad allocation with the allocation's
# ID, so running allocations show without a Nomad token.
NOMAD_ALLOC_LABEL = "com.hashicorp.nomad.alloc_id"
# check runs the new ES's config loader on the migrated es.json before the
# server key exists; any well-formed pin stands in for it there.
PLACEHOLDER_PIN = "0" * 64

# The ES build that ES PR #54's upgrade installed: the box's es and
# es-runtime-support name it in their Go build info.
BOX_ES_COMMIT = "16cbf739eea8c6a673aef8048aefb69cebd5121b"

# The key paths of the box's es.json: those the preflight read (ES build
# 74748063) and the four that ES PR #54's upgrade added. Any other set is
# refused.
START_ES_PATHS = (
    "authorization.allowed_spiffe_path_prefixes[]",
    *[f"dependencies.{dep}.{field}" for dep in ("artifact_registry", "execution_governance")
      for field in ("base_url", "client_cert_file", "client_key_file", "root_ca_file", "server_name", "timeout_seconds")],
    "execution.base_image",
    "execution.results_root_dir",
    *[f"execution.retained_result_auth.{field}" for field in ("key_file", "key_id", "store_id")],
    *[f"execution.runtime_profiles.control_plane_normal_shell.{field}"
      for field in ("codex_cli_path", "credential_vault_secret_field", "credential_vault_secret_path", "enabled", "image")],
    "execution.runtime_support_binary",
    "execution.spire_workload_api_socket_path",
    "execution.staging_root_dir",
    *[f"http.{field}" for field in ("bind_address", "port", "read_timeout_seconds", "shutdown_timeout_seconds", "write_timeout_seconds")],
    "nomad.base_url",
    "nomad.datacenter",
    "nomad.timeout_seconds",
    "nomad.token_file",
    "runtime_config.workload_zone_vault_config_ref.digest",
    "security.bootstrap_issuer_common_name",
    "tls.cert_file",
    "tls.client_ca_file",
    "tls.key_file",
    *[f"verification.{part}.{field}" for part in ("derivation_attestation", "provenance", "trust_model", "workload_identity_binding")
      for field in ("algorithm", "key_id", "public_key_hex")],
    "workload_vault_auth.default_mode",
)

# SHA-256 of the box's nomad.hcl before ES PR #54's lock (529 bytes, Remote
# Alpha 0.7's one-host config, as the preflight read it) and after the lock
# and the host-network repair (1126 bytes): the file this upgrade starts from.
NOMAD_HCL_PRELOCK_SHA256 = "5d5e106c1eb0ec8ba74efed66272051bba0a61adac4fead2e6021b6f9b7d96b8"
NOMAD_HCL_LOCKED_SHA256 = "ea33305501c6f9cfc24fb00c678042580ed7d84ab6867f49c27a335d131d5163"

# What this upgrade appends to that nomad.hcl: the tls block of the supported
# config, scripts/70_linux_setup.sh, at its NOMAD_TLS_DIR. A test keeps the
# two equal.
NOMAD_TLS_BLOCK = f"""
# HTTPS and RPC over TLS 1.3 only, with the certificate this script issues.
# Clients authenticate with ACL tokens, not certificates.
tls {{
  http = true
  rpc  = true

  ca_file   = "{NOMAD_CA_FILE}"
  cert_file = "{NOMAD_CERT_FILE}"
  key_file  = "{NOMAD_KEY_FILE}"

  verify_server_hostname = true
  verify_https_client    = false
  tls_min_version        = "tls13"
}}
"""
# Nomad's gossip keyring, which Nomad reads from its data directory when it
# starts (scripts/70_linux_setup.sh's NOMAD_GOSSIP_KEYRING on a supported
# host), and the server folder Nomad keeps it in. Nomad makes that folder
# 0755 inside its 0700 data directory.
NOMAD_SERVER_DIR = "/opt/nomad/data/server"
NOMAD_GOSSIP_KEYRING = NOMAD_SERVER_DIR + "/serf.keyring"
# The paths apply may create. Its backup names those this run creates, and a
# restore removes them; it removes nothing else.
CREATED_BY_APPLY = (NOMAD_TLS_DIR, NOMAD_GOSSIP_KEYRING)
# What apply backs up (backup_host), in that order; restore_host puts back
# a backup only when its manifest names exactly these (re-check 51, N67-9).
BACKED_UP_BY_APPLY = (ES_CONFIG, ES_BINARY, RUNTIME_SUPPORT, NOMAD_HCL)
# `nomad config validate` warns, and still exits 0, when it cannot read the
# TLS files a config names, and when a config has no TLS at all.
NOMAD_VALIDATE_REFUSED = ("Error when parsing TLS configuration", "mTLS is not configured")

SCRIPTS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SETUP_SCRIPT = os.path.join(SCRIPTS_DIR, "70_linux_setup.sh")
ACL_SETUP_SCRIPT = os.path.join(SCRIPTS_DIR, "nomad_acl_setup.sh")
TLS_IDENTITY_TOOL = os.path.join(SCRIPTS_DIR, "internal", "nomad_tls_identity.py")

HOST_ROOT = "/"


def host(path):
    """A host path, under --host-root when the tests set one."""
    if HOST_ROOT == "/":
        return path
    return os.path.join(HOST_ROOT, path.lstrip("/"))


def as_root():
    return os.geteuid() == 0


def test_mode():
    """Under a test --host-root, the user running the tests stands in for
    root and for every account the host has."""
    return HOST_ROOT != "/"


def box_es_commit():
    """BOX_ES_COMMIT. Under a test --host-root, ES_UPGRADE_TEST_BOX_ES_COMMIT
    may name another: the git history a test builds, which the order of a
    move is read from, cannot hold BOX_ES_COMMIT itself."""
    if test_mode() and os.environ.get("ES_UPGRADE_TEST_BOX_ES_COMMIT"):
        return os.environ["ES_UPGRADE_TEST_BOX_ES_COMMIT"]
    return BOX_ES_COMMIT


# The kernel's audit login uid of this process: the user who logged in to
# the session it runs in, kept across sudo, and unset (4294967295) in a
# process that no login started, such as a systemd-run unit.
LOGINUID_FILE = "/proc/self/loginuid"
LOGINUID_UNSET = 4294967295


def loginuid_file():
    """LOGINUID_FILE. Under a test --host-root, ES_UPGRADE_TEST_LOGINUID_FILE
    may name another file, so that a test decides what it holds."""
    if test_mode() and os.environ.get("ES_UPGRADE_TEST_LOGINUID_FILE"):
        return os.environ["ES_UPGRADE_TEST_LOGINUID_FILE"]
    return LOGINUID_FILE


def who_ran():
    """Who ran this, as far as the process can tell, for a record:
    sudo_user, the user SUDO_USER names (None when it is unset or empty, as
    when sudo did not start this process itself, under systemd-run for
    one); uid, the real uid; and login_user, the user the audit login uid
    names (None when it is unset, as under systemd-run, or cannot be read;
    the uid itself when no user has it). Root can set either; this is a
    record, not a check."""
    login_user = None
    try:
        with open(loginuid_file(), encoding="ascii") as handle:
            login_uid = int(handle.read().strip())
    except (OSError, ValueError, UnicodeDecodeError):
        login_uid = None
    if login_uid is not None and 0 <= login_uid < LOGINUID_UNSET:
        try:
            login_user = pwd.getpwuid(login_uid).pw_name
        except KeyError:
            login_user = str(login_uid)
    return {"sudo_user": os.environ.get("SUDO_USER") or None, "uid": os.getuid(), "login_user": login_user}


def describe_who(record):
    return (f"sudo user {record['sudo_user'] or 'not named'}, uid {record['uid']}, "
            f"login user {record['login_user'] or 'not set'}")


def root_ids():
    return (os.getuid(), os.getgid()) if test_mode() else (0, 0)


# The commands that run as root on the host. Each runs code from this
# checkout as root: this file, and the setup's nomad_tls functions,
# nomad_acl_setup.sh with nomad_acl.py, and nomad_tls_identity.py next to it.
CHECKOUT_GUARDED = ("check", "apply", "rollback")


def checkout_owner():
    """The uid that alone may be able to change the checkout: root on a host.
    Under a test --host-root the guard runs only when a test names the uid in
    ES_UPGRADE_TEST_CHECKOUT_OWNER, and None means it does not run."""
    if not test_mode():
        return 0
    value = os.environ.get("ES_UPGRADE_TEST_CHECKOUT_OWNER")
    return int(value) if value else None


def folders_above_problems(path, owners):
    """Why someone other than owners could move or replace what path names,
    or [] when nobody else can: every folder from / down to path's parent
    must belong to one of owners and be writable by neither its group nor
    others, unless it has the sticky bit (as /tmp has), which lets no one
    move or replace another's entry."""
    problems = []
    while True:
        parent = os.path.dirname(path)
        if parent == path:
            break
        path = parent
        try:
            st = os.lstat(path)
        except OSError as exc:
            problems.append(f"{path}: {exc.strerror}")
            continue
        mode = stat.S_IMODE(st.st_mode)
        if not stat.S_ISDIR(st.st_mode):
            problems.append(f"{path} is not a folder")
            continue
        if st.st_uid not in owners:
            problems.append(f"{path} belongs to uid {st.st_uid}")
        if mode & 0o022 and not mode & stat.S_ISVTX:
            problems.append(f"{path} is writable by its group or others ({mode:04o}) without the sticky bit")
    return problems


def tree_problems(top, owners):
    """Why someone other than owners could change top or anything under it,
    or [] when nobody else can: top and everything under it must belong to
    one of owners, be a folder or a regular file, and be writable by neither
    its group nor others. No symbolic link counts: one could point
    anywhere."""
    problems = []

    def entry(path):
        try:
            st = os.lstat(path)
        except OSError as exc:
            problems.append(f"{path}: {exc.strerror}")
            return False
        mode = stat.S_IMODE(st.st_mode)
        if stat.S_ISLNK(st.st_mode):
            problems.append(f"{path} is a symbolic link")
            return False
        if not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):
            problems.append(f"{path} is neither a folder nor a regular file")
            return False
        if st.st_uid not in owners:
            problems.append(f"{path} belongs to uid {st.st_uid}")
        if mode & 0o022:
            problems.append(f"{path} is writable by its group or others ({mode:04o})")
        return stat.S_ISDIR(st.st_mode)

    if not entry(top):
        return problems

    def walk_error(exc):
        problems.append(f"{exc.filename}: {exc.strerror}")

    for path, dirs, files in os.walk(top, onerror=walk_error):
        dirs.sort()
        for name in sorted(dirs) + sorted(files):
            entry(os.path.join(path, name))
    return problems


def checkout_problems(scripts_dir, owner):
    """Why someone other than owner could change the code this upgrade runs
    as root, or [] when nobody else can. Every folder from / down to
    scripts_dir must belong to root or owner and be writable by neither its
    group nor others, unless it has the sticky bit (as /tmp has), which lets
    no one move or replace another's entry. Everything under scripts_dir
    must belong to owner, be a folder or a regular file, and be writable by
    neither its group nor others. No symbolic link counts: one could point
    anywhere."""
    real = os.path.realpath(scripts_dir)
    if real != scripts_dir:
        return [f"{scripts_dir} is reached through a symbolic link ({real})"]
    return folders_above_problems(real, (0, owner)) + tree_problems(real, (owner,))


def require_root_only_checkout():
    """Refuse unless nobody but root (under a test --host-root, the uid the
    test names) can change this checkout: red-team RT60-2. The operator hands
    the clone to root before check (the contract's chown and chmod); this
    makes that step a precondition the script checks every time."""
    owner = checkout_owner()
    if owner is None:
        return
    problems = checkout_problems(SCRIPTS_DIR, owner)
    if problems:
        who = "root" if owner == 0 else f"uid {owner}"
        shown = "; ".join(problems[:20])
        more = f" (and {len(problems) - 20} more)" if len(problems) > 20 else ""
        raise Refusal(
            f"someone other than {who} can change the code this upgrade runs as root: {shown}{more}; "
            f"hand the clone to root first (chown -R root:root and chmod -R go-w); nothing was changed"
        )


def user_ids(name):
    if test_mode():
        return os.getuid(), os.getgid()
    try:
        entry = pwd.getpwnam(name)
    except KeyError:
        raise Refusal(f"user {name} does not exist")
    return entry.pw_uid, entry.pw_gid


def group_id(name):
    if test_mode():
        return os.getgid()
    try:
        return grp.getgrnam(name).gr_gid
    except KeyError:
        raise Refusal(f"group {name} does not exist")


def group_alive(pgid):
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def stop_process_group(proc):
    """End every process of a command's own process group and wait until
    none is left: SIGTERM, then SIGKILL after five seconds."""
    for signum in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(proc.pid, signum)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            proc.poll()
            if proc.returncode is not None and not group_alive(proc.pid):
                return
            time.sleep(0.05)
    proc.poll()
    if proc.returncode is None or group_alive(proc.pid):
        raise Refusal(f"{proc.args[0]} and its children did not stop")


class Completed:
    def __init__(self, args, returncode, stdout, stderr):
        self.args, self.returncode, self.stdout, self.stderr = args, returncode, stdout, stderr


def run(args, env=None, timeout=120, check=False, cwd=None, input=None):
    """Run a command in a process group of its own. When it times out, or a
    signal interrupts the wait, the whole group is ended and drained before
    the exception goes on, so no descendant keeps changing the host during
    a rollback. Descendants left after a normal exit are ended too. input,
    when given, is the command's standard input."""
    proc = subprocess.Popen(args, stdin=subprocess.DEVNULL if input is None else subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, env=env, cwd=cwd, start_new_session=True)
    try:
        stdout, stderr = proc.communicate(input=input, timeout=timeout)
    except BaseException as exc:
        stop_process_group(proc)
        if isinstance(exc, subprocess.TimeoutExpired):
            raise Refusal(f"{' '.join(args[:3])} did not finish within {timeout} s") from None
        raise
    if group_alive(proc.pid):
        stop_process_group(proc)
    if check and proc.returncode != 0:
        raise Refusal(f"{' '.join(args[:3])} failed: {(stderr or stdout).strip()[:400]}")
    return Completed(args, proc.returncode, stdout, stderr)


def stop_service(name):
    """systemctl stop, then proof that the unit is no longer running."""
    run(["systemctl", "stop", name], timeout=120, check=True)
    state = run(["systemctl", "is-active", name]).stdout.strip()
    if state not in ("inactive", "failed"):
        raise Refusal(f"{name} is {state!r} after systemctl stop")


def write_new_file(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())


def write_new_file_renamed(path, text):
    """write_new_file to a temporary name beside path, then rename it to
    path and sync the folder: path is either absent or whole."""
    tmp = path + ".new"
    write_new_file(tmp, text)
    os.rename(tmp, path)
    dir_fd = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def curl_status(url, extra=(), timeout=10):
    proc = run(["curl", "--noproxy", "*", "-sS", "-m", str(timeout), "-o", "/dev/null", "-w", "%{http_code}", *extra, url],
               timeout=timeout + 5)
    return proc.stdout.strip() if proc.returncode == 0 else f"error: {(proc.stderr or '').strip()[:200]}"


def curl_json(url, extra=(), timeout=10):
    proc = run(["curl", "--noproxy", "*", "-sS", "-m", str(timeout), "-w", "\n%{http_code}", *extra, url], timeout=timeout + 5)
    if proc.returncode != 0:
        return None, f"error: {(proc.stderr or '').strip()[:200]}"
    body, _, code = proc.stdout.rpartition("\n")
    try:
        return json.loads(body), code
    except ValueError:
        return None, code


def healthcheck_env():
    data, _ = read_regular_file(host(HEALTHCHECK_ENV))
    env = {}
    for line in data.decode().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, _, value = line.partition("=")
            env[key.strip()] = value.strip().strip("\"'")
    for key in ("CA_CERT", "OPERATOR_CERT", "OPERATOR_KEY"):
        if not env.get(key):
            raise Refusal(f"healthcheck.env has no {key}")
    return env


def health_urls():
    """The healthcheck runbook's step 4: ES's health and contract endpoints
    and AGS's health endpoint, at the addresses their configs name."""
    urls = []
    for path, suffixes in ((ES_CONFIG, ("/health", "/v1/executions:contract")), (AGS_CONFIG, ("/health",))):
        data, _ = read_regular_file(host(path))
        http = json.loads(data).get("http") or {}
        address, port = http.get("bind_address"), http.get("port")
        if not isinstance(address, str) or not address or ":" in address or not isinstance(port, int):
            raise Refusal(f"{path} has no IPv4 http.bind_address and http.port")
        urls += [f"https://{address}:{port}{suffix}" for suffix in suffixes]
    return urls


def service_health():
    env = healthcheck_env()
    tls = ["--cacert", env["CA_CERT"], "--cert", env["OPERATOR_CERT"], "--key", env["OPERATOR_KEY"]]
    return {url: curl_status(url, tls) for url in health_urls()}


def healthy(result):
    return bool(result) and all(code == "200" for code in result.values())


def services_active():
    proc = run(["systemctl", "is-active", *SERVICES])
    return dict(zip(SERVICES, proc.stdout.split()))


def es_unit_problems():
    proc = run(["systemctl", "show", "es.service", "-p", "User", "-p", "ExecStart"])
    props = dict(line.split("=", 1) for line in proc.stdout.splitlines() if "=" in line)
    problems = []
    if props.get("User") != ES_USER:
        problems.append(f"es.service runs as {props.get('User')!r}, not {ES_USER}")
    if ES_EXEC_START not in props.get("ExecStart", ""):
        problems.append(f"es.service does not start {ES_BINARY} with {ES_CONFIG}")
    return problems


def wait_seconds(seconds):
    """The host's wait, or a short one the tests set under a test host root."""
    if test_mode() and os.environ.get("ES_UPGRADE_TEST_WAIT_SECONDS"):
        return int(os.environ["ES_UPGRADE_TEST_WAIT_SECONDS"])
    return seconds


def wait_for(predicate, seconds, step=2):
    seconds = wait_seconds(seconds)
    step = min(step, max(seconds, 0.1))
    deadline = time.monotonic() + seconds
    while True:
        result = predicate()
        if result or time.monotonic() >= deadline:
            return result
        time.sleep(step)


def nomad_curl_args(addr):
    """curl's options for Nomad at addr: over HTTPS, TLS 1.3 only, trusting
    only Nomad's CA."""
    if addr.startswith("https://"):
        return ["--proto", "=https", "--tlsv1.3", "--cacert", host(NOMAD_CA_FILE), "--capath", "/dev/null"]
    return ["--proto", "=http"]


def anonymous_nomad_problems():
    """What two requests without a token over HTTPS show against the lock.
    Nomad must refuse an anonymous job list, so it enforces its ACLs. That
    list asks only about the namespace default, so Nomad must also answer 404
    for its anonymous ACL policy: such a policy would give requests without a
    token capabilities in whatever namespace it names, ES's among them. ES
    makes the same policy request before each submit, and so does
    nomad_acl_state_check in scripts/internal/nomad_acl.sh. Both requests
    only read."""
    addr = nomad_https_addr()
    problems = []
    code = curl_status(addr + "/v1/jobs", nomad_curl_args(addr), timeout=5)
    if code != "403":
        problems.append(f"Nomad answers an anonymous job list over HTTPS with {code}, not 403")
    code = curl_status(addr + "/v1/acl/policy/anonymous", nomad_curl_args(addr), timeout=5)
    if code != "404":
        problems.append(f"Nomad answers a request without a token for its anonymous ACL policy over HTTPS with {code}, not 404")
    return problems


def nomad_secret_id(text):
    """Whether text has the form of a Nomad secret ID (a lowercase UUID)."""
    return (len(text) == 36 and all(text[i] == "-" for i in (8, 13, 18, 23))
            and set(text.replace("-", "")) <= set("0123456789abcdef"))


def nomad_gossip_state():
    """(encrypted, what Nomad reports) from /v1/agent/self over HTTPS, read
    with the observer token, which may read the agent. Nomad reports
    stats.serf.encrypted as the string "true" when it encrypts its gossip.
    The token goes to curl in its config on standard input, never on a
    command line."""
    addr = nomad_https_addr()
    try:
        data, _ = read_regular_file(host(f"{NOMAD_ACL_DIR}/observer-token"))
        token = data.decode("ascii").strip()
    except (Refusal, OSError, UnicodeDecodeError) as exc:
        return False, f"cannot read the observer token: {exc}"
    if not nomad_secret_id(token):
        return False, "the observer token file does not hold a Nomad secret ID"
    proc = run(["curl", "--noproxy", "*", "-sS", "-m", "10", "--config", "-", "-w", "\n%{http_code}",
                *nomad_curl_args(addr), addr + "/v1/agent/self"],
               timeout=15, input=f'header = "X-Nomad-Token: {token}"\n')
    if proc.returncode != 0:
        return False, f"error: {(proc.stderr or '').strip()[:200]}"
    body, _, code = proc.stdout.rpartition("\n")
    if code != "200":
        return False, f"/v1/agent/self answered {code}"
    try:
        doc = json.loads(body)
    except ValueError:
        return False, "/v1/agent/self did not answer JSON"
    stats = doc.get("stats") if isinstance(doc, dict) and isinstance(doc.get("stats"), dict) else {}
    serf = stats.get("serf") if isinstance(stats.get("serf"), dict) else {}
    value = serf.get("encrypted")
    return value == "true", f"stats.serf.encrypted {value!r}"


def nomad_leader_named(addr):
    doc, code = curl_json(addr + "/v1/status/leader", nomad_curl_args(addr), timeout=5)
    return code == "200" and isinstance(doc, str) and doc != ""


def valid_commit(commit):
    return isinstance(commit, str) and len(commit) == 40 and set(commit) <= set("0123456789abcdef")


GO_BUILDINFO_MAGIC = b"\xff Go buildinf:"


def go_uvarint_string(data):
    """(string, rest) of a Go uvarint-length-prefixed string."""
    length = shift = i = 0
    while True:
        if i >= len(data) or shift > 63:
            raise Refusal("the Go build info is truncated")
        byte = data[i]
        i += 1
        length |= (byte & 0x7F) << shift
        if byte < 0x80:
            break
        shift += 7
    if i + length > len(data):
        raise Refusal("the Go build info is truncated")
    return data[i:i + length], data[i + length:]


def go_modinfo(blob):
    """(Go version, [module info lines]) from a 64-bit little-endian ELF Go
    binary's .go.buildinfo section: what `go version -m` reads, read here
    without running anything. A test keeps the two in agreement."""
    if blob[:6] != b"\x7fELF\x02\x01" or len(blob) < 64:
        raise Refusal("not a 64-bit little-endian ELF file")
    (shoff,) = struct.unpack_from("<Q", blob, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", blob, 0x3A)
    if shentsize != 64 or shstrndx >= shnum or shoff + shnum * 64 > len(blob):
        raise Refusal("the ELF section headers are malformed")

    def section(index):
        # (name, file offset, size). Only the sections read here must lie in
        # the file; .bss and the like occupy none of it.
        name, _, _, _, offset, size = struct.unpack_from("<IIQQQQ", blob, shoff + index * 64)
        return name, offset, size

    def contents(offset, size):
        if offset + size > len(blob):
            raise Refusal("an ELF section lies outside the file")
        return blob[offset:offset + size]

    _, names_at, names_size = section(shstrndx)
    names = contents(names_at, names_size)
    data = None
    for index in range(shnum):
        name, offset, size = section(index)
        if name >= len(names):
            raise Refusal("an ELF section name lies outside its table")
        end = names.find(b"\0", name)
        if end >= 0 and names[name:end] == b".go.buildinfo":
            if data is not None:
                raise Refusal("the binary has two .go.buildinfo sections")
            data = contents(offset, size)
    if data is None or len(data) < 32 or data[:14] != GO_BUILDINFO_MAGIC or not data[15] & 2:
        raise Refusal("the binary carries no Go build info in the inline format of Go 1.18 and later")
    version, rest = go_uvarint_string(data[32:])
    modinfo, _ = go_uvarint_string(rest)
    if len(modinfo) >= 33 and modinfo[-17] == ord("\n"):
        modinfo = modinfo[16:-16]
    try:
        return version.decode("utf-8"), modinfo.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        raise Refusal("the Go build info is not UTF-8") from None


def go_build_info(blob):
    """(Go version, [build setting lines]) from a Go binary's build info."""
    version, lines = go_modinfo(blob)
    return version, [line[len("build\t"):] for line in lines if line.startswith("build\t")]


def go_mod_requires(text):
    """(module path, {path: version}) of a go.mod: its module line and every
    require. A go.mod that replaces a module, whose code go.sum then does
    not pin, is refused, as is any line this does not read."""
    module, requires, block = None, {}, None
    for number, raw in enumerate(text.splitlines(), 1):
        fields = raw.split("//", 1)[0].split()
        if not fields:
            continue
        if block is not None:
            if fields == [")"]:
                block = None
                continue
            verb, args = block, fields
        elif fields[1:] == ["("]:
            block = fields[0]
            continue
        else:
            verb, args = fields[0], fields[1:]
        if verb == "replace":
            raise Refusal("the commit's go.mod replaces a module, and build and check take only modules that go.sum pins")
        if verb == "module" and len(args) == 1 and module is None:
            module = args[0]
        elif verb == "require" and len(args) == 2 and args[0] not in requires:
            requires[args[0]] = args[1]
        elif verb not in ("go", "toolchain", "godebug", "exclude", "retract", "tool", "ignore"):
            raise Refusal(f"line {number} of the commit's go.mod is not read here: {raw.strip()!r}")
    if module is None:
        raise Refusal("the commit's go.mod names no module")
    return module, requires


def go_sum_hashes(text):
    """{(path, version): {hash}} of a go.sum's h1 hashes of module code (not
    the /go.mod lines). h1 is the only kind Go writes; a hash of any other
    kind pins nothing here until someone has looked at what it means."""
    hashes = {}
    for number, raw in enumerate(text.splitlines(), 1):
        fields = raw.split()
        if not fields:
            continue
        if len(fields) != 3:
            raise Refusal(f"line {number} of the commit's go.sum is not read here: {raw.strip()!r}")
        path, version, hash_ = fields
        if not version.endswith("/go.mod") and hash_.startswith("h1:"):
            hashes.setdefault((path, version), set()).add(hash_)
    return hashes


def module_git(repo, owners, what):
    """The git command that reads the objects of the clone repo, once only
    owners can change those objects: the clone's .git must be a folder that
    belongs to them, with nothing that makes git read objects from
    elsewhere. Run it with GIT_ENV, so that git reads only that
    repository's config. git does not check an object's bytes against its
    name when it reads it, so the folder git reads objects from decides
    what a commit holds and what its parents are. A .git file ("gitdir:
    <path>", as git worktree add and git clone --separate-git-dir leave) or
    link sends git to another folder, so .git must be a folder itself, as
    build requires (audit 34, A34-2). A grafts file (info/grafts) gives
    commits other parents than their own objects name, which neither
    "git rev-parse --is-shallow-repository" nor GIT_NO_REPLACE_OBJECTS
    turns off, and git hints at it on standard error only while
    advice.graftFileDeprecated is on, so it is refused here (audit 44,
    O44-2). Otherwise refuses, saying that what (what the caller reads
    there, with its verb) is not in such objects."""
    git_dir = os.path.join(repo, ".git")
    problems = folders_above_problems(git_dir, (0,) + tuple(owners))
    if not os.path.lexists(git_dir):
        problems.append(f"{git_dir} does not exist")
    elif not stat.S_ISDIR(os.lstat(git_dir).st_mode):
        problems.append(f"{git_dir} is not a folder, so git would read the objects of a folder it names")
    else:
        problems += tree_problems(git_dir, owners)
        for rel in ("commondir", "objects/info/alternates", "objects/info/http-alternates"):
            if os.path.lexists(os.path.join(git_dir, rel)):
                problems.append(f"{git_dir}/{rel} exists, which makes git read objects from elsewhere")
        if os.path.lexists(os.path.join(git_dir, "info", "grafts")):
            problems.append(f"{git_dir}/info/grafts exists, which gives commits other parents than their own")
    if problems:
        shown = "; ".join(problems[:20])
        more = f" (and {len(problems) - 20} more)" if len(problems) > 20 else ""
        raise Refusal(f"{what} not in git objects that only "
                      f"{' and '.join(f'uid {uid}' for uid in owners)} can change: {shown}{more}")
    return ["git", "--git-dir=" + git_dir]


def commit_module_pins(repo, commit, owners, env):
    """What a build of commit may hold, read from the commit's own go.mod
    and go.sum in the git objects of the clone repo (audit 33,
    A33-2): the module's path, the version go.mod requires of each
    dependency, and the hashes go.sum holds. Only owners may be able to
    change those objects (module_git), and git runs with env (GIT_ENV), so
    it reads only that repository's config."""
    git = module_git(repo, owners, "the commit's go.mod and go.sum are")
    found = run(git + ["rev-parse", "--verify", "--quiet", commit + "^{commit}"], env=env)
    if found.returncode != 0 or found.stdout.strip() != commit:
        raise Refusal(f"the clone {repo} does not hold the commit {commit}")
    files = {name: run(git + ["cat-file", "blob", f"{commit}:{name}"], env=env, check=True).stdout
             for name in ("go.mod", "go.sum")}
    module, requires = go_mod_requires(files["go.mod"])
    return {"module": module, "requires": requires, "sums": go_sum_hashes(files["go.sum"])}


def go_module_problems(lines, pins, package):
    """Why the module lines of a binary's build info (path, mod, dep and =>
    lines, as `go version -m` shows them without its leading tab) show a
    program other than package, or code other than what the commit's go.mod
    and go.sum pin (pins, from commit_module_pins), or [] when they do not.
    Each dependency must have the version go.mod requires and a hash go.sum
    holds for that version: a module a go.work raised to another version, a
    module a go.work put in place of a dependency (the version "(devel)"),
    vendored code (an empty hash) and any hash of another kind are refused.
    A replaced module leaves a "=>" line, and the commit's go.mod replaces
    nothing (commit_module_pins refuses one that does), so any is refused.
    Red-team audits 32 (A32-1) and 33 (A33-2)."""
    problems = []
    seen = set()
    for line in lines:
        fields = line.split("\t")
        kind, shown = fields[0], " ".join(f for f in fields[1:] if f)
        seen.add(kind)
        if kind in ("go", "build"):
            continue
        if kind == "path":
            if fields[1:] != [package]:
                problems.append(f"the program {shown}, not {package}")
        elif kind == "mod":
            if len(fields) < 2 or fields[1] != pins["module"]:
                problems.append(f"the main module {shown}, not {pins['module']}")
        elif kind == "dep":
            path, version, hash_ = (fields[1:] + ["", "", ""])[:3]
            wanted = pins["requires"].get(path)
            if wanted is None:
                problems.append(f"the dependency {shown}, which the commit's go.mod does not require")
            elif version != wanted:
                problems.append(f"the dependency {shown}, where the commit's go.mod requires {wanted}")
            elif len(fields) != 4 or hash_ not in pins["sums"].get((path, version), ()):
                problems.append(f"the dependency {shown} without a hash the commit's go.sum holds for it")
        elif kind == "=>":
            problems.append(f"a replaced module ({shown})")
        else:
            problems.append(f"a module line Go does not write ({line})")
    for kind, what in (("path", "no program path"), ("mod", "no main module")):
        if kind not in seen:
            problems.append(what)
    return problems


def check_build_stamp(name, blob, commit, pins):
    """Refuse a binary whose own build info does not name a clean build of
    commit with the supported Go, from the modules the commit pins."""
    version, lines = go_modinfo(blob)
    settings = dict(line[len("build\t"):].partition("=")[::2] for line in lines if line.startswith("build\t"))
    if version != SUPPORTED_GO_VERSION or settings.get("vcs.revision") != commit or settings.get("vcs.modified") != "false":
        raise Refusal(f"the payload file {name} is not, by its own Go build info, a clean {SUPPORTED_GO_VERSION} build of "
                      f"{commit}: Go {version!r}, vcs.revision {settings.get('vcs.revision')!r}, "
                      f"vcs.modified {settings.get('vcs.modified')!r}")
    check_build_modules(name, lines, commit, pins)


def check_build_modules(name, lines, commit, pins):
    """Refuse a binary whose build info shows a program other than its
    payload file's, or a module other than what the commit's go.mod and
    go.sum pin."""
    problems = go_module_problems(lines, pins, pins["module"] + "/" + PAYLOAD_PACKAGES[name])
    if problems:
        raise Refusal(f"the payload file {name} was not built from the modules {commit} pins, by its own Go build info: "
                      + "; ".join(problems))


def module_repo():
    """The clone that holds the commit's go.mod and go.sum: this checkout.
    Under a test --host-root, ES_UPGRADE_TEST_MODULE_REPO may name another."""
    if test_mode() and os.environ.get("ES_UPGRADE_TEST_MODULE_REPO"):
        return os.environ["ES_UPGRADE_TEST_MODULE_REPO"]
    return os.path.dirname(SCRIPTS_DIR)


def owned_by_root(st):
    uid, gid = root_ids()
    return st.st_uid == uid and st.st_gid == gid


def load_payload(payload_dir, commit):
    """Verify a build's payload and copy nothing. Returns the provenance.

    The directory and its files must be root:root and not writable by group
    or others, so no other account can change them after the check. Every
    file's SHA-256 must match provenance.json, which must name the commit,
    and each installed binary must name it in its own Go build info and
    show there its own program and no module other than what the commit's
    go.mod and go.sum pin, as this checkout's git objects hold them, which
    only root can change."""
    if not valid_commit(commit):
        raise Refusal("the commit must be a full lower-case 40-character SHA-1")
    st = os.lstat(payload_dir)
    if not stat.S_ISDIR(st.st_mode) or st.st_mode & 0o022 or not owned_by_root(st):
        raise Refusal("the payload directory must be a directory that root owns (root:root) and group and others cannot write")
    data, pst = read_regular_file(os.path.join(payload_dir, "provenance.json"))
    if pst.st_mode & 0o022 or not owned_by_root(pst):
        raise Refusal("provenance.json must be root:root and not writable by group or others")
    prov = json.loads(data)
    if prov.get("commit") != commit:
        raise Refusal(f"the payload was built from {prov.get('commit')!r}, not the named commit {commit!r}")
    if prov.get("go_version") != SUPPORTED_GO_VERSION or prov.get("vcs_modified") is not False:
        raise Refusal("the payload was not built with the supported Go toolchain from a clean checkout")
    pins = commit_module_pins(module_repo(), commit, (root_ids()[0],), GIT_ENV)
    for name in PAYLOAD_FILES:
        blob, fst = read_regular_file(os.path.join(payload_dir, name))
        if fst.st_mode & 0o022 or not owned_by_root(fst):
            raise Refusal(f"the payload file {name} must be root:root and not writable by group or others")
        if sha256_bytes(blob) != prov.get("sha256", {}).get(name):
            raise Refusal(f"the payload file {name} does not match its provenance")
        if name in STAMPED_PAYLOAD_FILES:
            check_build_stamp(name, blob, commit, pins)
    return prov


def stage_payload(payload_dir, prov, stage_dir):
    """Copy the verified payload into a root-only directory, and require each
    copy to have the SHA-256 that load_payload verified, build info included."""
    os.mkdir(stage_dir, 0o700)
    for name in PAYLOAD_FILES:
        blob, _ = read_regular_file(os.path.join(payload_dir, name))
        if sha256_bytes(blob) != prov["sha256"][name]:
            raise Refusal(f"the payload file {name} changed while it was copied")
        fd = os.open(os.path.join(stage_dir, name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
        with os.fdopen(fd, "wb") as handle:
            handle.write(blob)
    return stage_dir


def esconfigcheck(helper, doc):
    tmpdir = tempfile.mkdtemp(prefix="es-upgrade-config-")
    try:
        path = os.path.join(tmpdir, "es.json")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(render_json(doc))
        proc = run([helper, path], timeout=30)
        return proc.returncode == 0, (proc.stdout + proc.stderr).strip()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def retained_result_auth():
    return {"store_id": STORE_ID, "key_id": KEY_ID, "key_file": KEY_FILE}


def other_nomad_configs():
    """Files besides nomad.hcl that `nomad agent -config /etc/nomad.d` loads."""
    return sorted(name for name in os.listdir(host(NOMAD_DIR))
                  if name != "nomad.hcl" and name.endswith((".hcl", ".json")))


def posix_acls(path):
    """The POSIX ACLs that path has. os has listxattr only on Linux, where
    the box runs; on macOS, where the tests also run, nothing has a POSIX
    ACL."""
    listxattr = getattr(os, "listxattr", None)
    if listxattr is None:
        return []
    present = listxattr(path)
    return [name for name in POSIX_ACLS if name in present]


def owner_mode(st):
    return {"uid": st.st_uid, "gid": st.st_gid, "mode": format(stat.S_IMODE(st.st_mode), "04o")}


def setup_functions(region):
    """The functions of one region of scripts/70_linux_setup.sh, between its
    "# BEGIN <region>" and "# END <region>" lines."""
    data, _ = read_regular_file(SETUP_SCRIPT)
    text = data.decode("utf-8")
    begin = text.find(f"\n# BEGIN {region}")
    end = text.find(f"\n# END {region}\n", begin + 1)
    if begin < 0 or end < 0:
        raise Refusal(f"scripts/70_linux_setup.sh has no {region} functions")
    return text[begin + 1:end + 1]


def setup_tls_functions():
    """The nomad_tls functions of scripts/70_linux_setup.sh, which issue and
    check Nomad's TLS material on every supported host."""
    return setup_functions("nomad_tls")


def nomad_tls(function, *args):
    """Run one of the setup's nomad_tls functions as the user running this
    script: root on the host, so the material is root's."""
    script = "set -euo pipefail\n" + setup_tls_functions() + '"$@"\n'
    return run(["bash", "-c", script, "nomad-tls", function, *args], timeout=120)


def nomad_gossip(function, *args):
    """Run one of the setup's nomad_gossip functions, which write and check
    Nomad's gossip keyring on every supported host, as the user running this
    script: root on the host, so the keyring is root's."""
    script = "set -euo pipefail\n" + setup_functions("nomad_gossip") + '"$@"\n'
    return run(["bash", "-c", script, "nomad-gossip", function, *args], timeout=60)


def server_spki_sha256():
    """The pin: the SHA-256 of the public key in Nomad's server certificate."""
    proc = nomad_tls("nomad_tls_spki_sha256", host(NOMAD_CERT_FILE))
    pin = proc.stdout.strip()
    if proc.returncode != 0 or not valid_spki(pin):
        raise Refusal(f"cannot read the public key of {NOMAD_CERT_FILE}: {proc.stderr.strip()[:200]}")
    return pin


# The host's shape. Each part of the host this upgrade changes is read on its
# own and reports (shape, state): shape is the part's form ("locked-http"
# where ES PR #54's upgrade left it, "https" once Nomad is on HTTPS, and for
# the binaries and the keyring the forms below) or None, and state says what
# was found. host_shape puts the parts together.

def nomad_hcl_shape(text):
    digest = sha256_bytes(text)
    if digest == NOMAD_HCL_LOCKED_SHA256:
        return "locked-http", "locked-http (ES PR #54's lock, plain HTTP)"
    if digest == NOMAD_HCL_PRELOCK_SHA256:
        return None, "pre-lock (Remote Alpha 0.7's config: ES PR #54's upgrade has not run)"
    block = NOMAD_TLS_BLOCK.encode()
    if text.endswith(block) and sha256_bytes(text[:-len(block)]) == NOMAD_HCL_LOCKED_SHA256:
        return "https", "https (the lock and the supported config's tls block)"
    return None, f"unknown (SHA-256 {digest})"


def tls_dir_shape():
    path = host(NOMAD_TLS_DIR)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return "locked-http", "absent"
    if not stat.S_ISDIR(st.st_mode):
        return None, "present, but not a directory"
    if not owned_by_root(st) or stat.S_IMODE(st.st_mode) != NOMAD_TLS_DIR_MODE:
        return None, f"present, but not root:root {NOMAD_TLS_DIR_MODE:04o} ({owner_mode(st)})"
    acls = posix_acls(path)
    if acls:
        return None, f"present, but has an ACL ({', '.join(acls)}; setfacl -b -k {NOMAD_TLS_DIR} removes it)"
    names = tuple(sorted(os.listdir(path)))
    if names != NOMAD_TLS_FILES:
        return None, f"present, but holds {list(names)}, not exactly {list(NOMAD_TLS_FILES)}"
    if nomad_tls("nomad_tls_material_ok", path).returncode != 0:
        return None, "present, but its material fails the setup's nomad_tls_material_ok"
    return "https", "https (root's material that passes the setup's nomad_tls_material_ok)"


def es_config_shape(doc, pin):
    """pin is the live server certificate's key SHA-256, or None if there is
    no valid certificate."""
    if not isinstance(doc, dict) or not isinstance(doc.get("nomad"), dict):
        return None, "unknown (no nomad block)"
    nomad = doc["nomad"]
    execution = doc.get("execution") if isinstance(doc.get("execution"), dict) else {}
    if nomad.get("token_file") != ES_TOKEN_FILE or execution.get("retained_result_auth") != retained_result_auth():
        return None, "unknown (nomad.token_file or execution.retained_result_auth is not what ES PR #54's upgrade set)"
    found, start = leaf_paths(doc), set(START_ES_PATHS)
    if found == start:
        if nomad.get("base_url") == nomad_http_addr():
            return "locked-http", f"locked-http (Nomad at {nomad_http_addr()})"
        return None, f"unknown (nomad.base_url {nomad.get('base_url')!r})"
    if found == start | {f"nomad.{key}" for key in NOMAD_TLS_KEYS}:
        try:
            _, changes = migrate_config(doc, nomad.get("server_spki_sha256"))
        except Refusal as exc:
            return None, f"unknown ({exc})"
        if changes:
            return None, "unknown (Nomad TLS keys this upgrade did not write)"
        if pin != nomad["server_spki_sha256"]:
            return None, "https keys, but nomad.server_spki_sha256 is not the key of the server certificate on disk"
        return "https", f"https (Nomad at {nomad_https_addr()}, its server key pinned)"
    return None, f"unknown (keys: unexpected {sorted(found - start)}, missing {sorted(start - found)})"


def binaries_shape(commit, prov):
    """(form, state, installed): the form of the installed es and
    es-runtime-support, and the one commit both are clean builds of, or
    None when they are not."""
    revisions = {}
    for name, path in (("es", ES_BINARY), ("es-runtime-support", RUNTIME_SUPPORT)):
        try:
            blob, _ = read_regular_file(host(path))
            _, lines = go_build_info(blob)
        except (Refusal, OSError) as exc:
            return None, f"unknown ({name}: {exc})", None
        settings = dict(line.partition("=")[::2] for line in lines)
        revision = settings.get("vcs.revision")
        if settings.get("vcs.modified") != "false":
            return None, f"unknown ({name} is a build of a modified checkout of {revision})", None
        if revision == commit and (prov is None or sha256_bytes(blob) != prov["sha256"].get(name)):
            return None, f"unknown ({name} names {commit} but is not the verified payload's build)", None
        revisions[name] = revision
    found = set(revisions.values())
    box = box_es_commit()
    if found == {box}:
        return "locked-http", f"locked-http (builds of {box})", box
    if found == {commit}:
        return "https", f"https (the payload's builds of {commit})", commit
    if len(found) == 1 and valid_commit(revisions["es"]):
        return "other", f"other (clean builds of {revisions['es']}, which apply replaces)", revisions["es"]
    return None, "unknown (" + ", ".join(f"{name} built from {rev}" for name, rev in revisions.items()) + ")", None


def keyring_shape():
    """Nomad's gossip keyring: "absent", or "sound" when it is root's and the
    setup's nomad_gossip_keyring_ok accepts it. Nomad's server folder must
    be root's and writable by no one else either way."""
    folder = host(NOMAD_SERVER_DIR)
    try:
        st = os.lstat(folder)
    except FileNotFoundError:
        return None, f"{NOMAD_SERVER_DIR} is missing (Nomad makes it when it first starts)"
    if not stat.S_ISDIR(st.st_mode) or not owned_by_root(st) or stat.S_IMODE(st.st_mode) & 0o022:
        return None, f"{NOMAD_SERVER_DIR} is not a root:root directory only root can write ({owner_mode(st)})"
    acls = posix_acls(folder)
    if acls:
        # A default ACL there would make the setup's issuer refuse the
        # keyring it writes, after ES has stopped.
        return None, f"{NOMAD_SERVER_DIR} has an ACL ({', '.join(acls)}; setfacl -b -k {NOMAD_SERVER_DIR} removes it)"
    if not os.path.lexists(host(NOMAD_GOSSIP_KEYRING)):
        return "absent", "absent"
    if nomad_gossip("nomad_gossip_keyring_ok", host(NOMAD_GOSSIP_KEYRING)).returncode != 0:
        return None, "present, but it fails the setup's nomad_gossip_keyring_ok"
    return "sound", "sound (root's keyring that passes the setup's nomad_gossip_keyring_ok)"


SHAPE_PARTS = ("nomad.hcl", "Nomad's TLS directory", "es.json", "the ES binaries", "Nomad's gossip keyring")
TLS_PARTS = SHAPE_PARTS[:3]


def host_shape(commit, prov):
    """(shape or None, {part: state}, pin or None, {part: form}, installed):
    installed is the one commit the installed ES binaries are clean builds
    of, or None. Reads only. The shapes:

      locked-http     every TLS part and the binaries locked-http, no keyring
      https           every TLS part https, the binaries the payload's
                      builds or other clean builds, the keyring absent or
                      sound, but not the payload's builds with a keyring
      https-gossip    every TLS part https, the payload's builds, a sound
                      keyring: where apply leaves the host
    """
    def guarded(read, *fallback):
        try:
            return read()
        except (Refusal, OSError, ValueError, UnicodeDecodeError) as exc:
            return (None, f"unreadable ({exc})", *fallback)

    found = {}
    found["nomad.hcl"] = guarded(lambda: nomad_hcl_shape(read_regular_file(host(NOMAD_HCL))[0]))
    found["Nomad's TLS directory"] = guarded(tls_dir_shape)
    pin = None
    if found["Nomad's TLS directory"][0] == "https":
        try:
            pin = server_spki_sha256()
        except Refusal as exc:
            found["Nomad's TLS directory"] = (None, f"present, but {exc}")
    found["es.json"] = guarded(lambda: es_config_shape(json.loads(read_regular_file(host(ES_CONFIG))[0]), pin))
    binaries_form, binaries_state, installed = guarded(lambda: binaries_shape(commit, prov), None)
    found["the ES binaries"] = (binaries_form, binaries_state)
    found["Nomad's gossip keyring"] = guarded(keyring_shape)
    tls = {found[part][0] for part in TLS_PARTS}
    binaries, keyring = found["the ES binaries"][0], found["Nomad's gossip keyring"][0]
    shape = None
    if tls == {"locked-http"} and binaries == "locked-http" and keyring == "absent":
        shape = "locked-http"
    elif tls == {"https"} and binaries in ("https", "other") and keyring in ("absent", "sound"):
        shape = "https-gossip" if (binaries, keyring) == ("https", "sound") else "https"
    forms = {part: found[part][0] for part in SHAPE_PARTS}
    return shape, {part: found[part][1] for part in SHAPE_PARTS}, pin, forms, installed


def describe_parts(parts):
    return "; ".join(f"{part}: {state}" for part, state in parts.items())


def commit_order(installed, commit):
    """(order, why): how the named commit stands to the installed build in
    the history of the clone (module_repo), read with GIT_ENV from git
    objects only root can change (module_git): "forward" when installed is
    an ancestor of commit, "backward" when commit is an ancestor of
    installed, "sideways" when neither is, and "unknown" when the clone
    does not hold both or is shallow, so that its history may stop short of
    either."""
    repo = module_repo()
    git = module_git(repo, (root_ids()[0],), "the history of the installed and named commits is")
    shallow = run(git + ["rev-parse", "--is-shallow-repository"], env=GIT_ENV)
    if shallow.returncode != 0 or shallow.stdout.strip() not in ("true", "false"):
        raise Refusal(f"git cannot tell whether the clone {repo} is shallow: {(shallow.stderr or shallow.stdout).strip()[:300]}")
    if shallow.stdout.strip() == "true":
        return "unknown", f"the clone {repo} is shallow, so its history may stop short of {installed}"
    for name in (installed, commit):
        found = run(git + ["rev-parse", "--verify", "--quiet", name + "^{commit}"], env=GIT_ENV)
        if found.returncode != 0 or found.stdout.strip() != name:
            return "unknown", f"the clone {repo} does not hold the commit {name}"

    def is_ancestor(older, newer):
        # A commit whose parent the clone lacks makes git complain on
        # standard error, and git 2.43 still answers "not an ancestor"
        # (exit 1) where git 2.56 exits 128: either way a damaged history is
        # refused here, not read as a move that is not forward.
        proc = run(git + ["merge-base", "--is-ancestor", older, newer], env=GIT_ENV)
        if proc.returncode not in (0, 1) or proc.stderr.strip():
            raise Refusal(f"git cannot read the history of {older} and {newer} in the clone {repo}: "
                          f"exit {proc.returncode}, {proc.stderr.strip()[:300]!r}")
        return proc.returncode == 0

    if is_ancestor(installed, commit):
        return "forward", f"{installed} is an ancestor of {commit}"
    if is_ancestor(commit, installed):
        return "backward", f"{commit} is an ancestor of {installed}, so older"
    return "sideways", f"neither of {installed} and {commit} is an ancestor of the other"


def inspect_move(report, block, installed, commit, allow_downgrade):
    """Refuse a move of ES that is not forward along the clone's history:
    to a commit older than the installed build, on another line of history,
    or whose order the clone cannot show. Root lets one such move through
    only by naming it on the command line, as --allow-downgrade
    <installed commit>..<named commit> (allow_downgrade: every value given),
    and nowhere else: no file or variable stands in for it. That stops
    mistakes (a stale clone or payload, a wrong or reused commit) and
    leaves a record; it cannot stop root, who can install binaries without
    this script. Reports the move, and for one root named, who ran it
    (who_ran)."""
    named = None
    if allow_downgrade:
        if len(allow_downgrade) > 1:
            block("move", "--allow-downgrade is given more than once; name the one move once")
            return
        parts = allow_downgrade[0].split("..")
        if len(parts) != 2 or not all(valid_commit(part) for part in parts):
            block("move", f"--allow-downgrade {allow_downgrade[0]!r} does not name a move as <installed commit>..<named commit>, "
                  "each a full lower-case 40-character SHA-1")
            return
        named = (parts[0], parts[1])
    if installed is None:
        if named is not None:
            block("move", "--allow-downgrade names a move, but the installed ES binaries are not clean builds of one commit")
        return
    if not valid_commit(commit):
        # The payload check refuses it; git is never handed a name that is
        # not a full commit.
        return
    if installed == commit:
        order, why = "same", f"the installed ES binaries are builds of {commit} already"
    else:
        try:
            order, why = commit_order(installed, commit)
        except (Refusal, OSError) as exc:
            block("move", str(exc))
            return
    move = {"from": installed, "to": commit, "order": order, "why": why}
    report["move"] = move
    if order in ("forward", "same"):
        if named is not None:
            block("move", f"--allow-downgrade is only for a move that is not forward, and this one is {order} ({why}); leave it out")
        return
    if named is None:
        block("move", f"moving ES from {installed} to {commit} is not forward ({order}: {why}); it runs only when root "
              "names this move on the command line as --allow-downgrade <installed commit>..<named commit>")
        return
    if named != (installed, commit):
        block("move", f"--allow-downgrade names the move {named[0]}..{named[1]}, but this one is {installed}..{commit}")
        return
    move["authorized"] = f"--allow-downgrade {installed}..{commit}"
    move.update(who_ran())


def inspect_host(payload_dir, commit, allow_downgrade=None):
    """Everything check reports. Reads only; returns (report, blockers, the
    form of each part of the host's shape)."""
    blockers = []
    report = {"schema": SUMMARY_SCHEMA, "commit": commit, "host_root": HOST_ROOT}

    def block(scope, message):
        blockers.append({"scope": scope, "summary": message})

    if HOST_ROOT == "/" and not as_root():
        block("privilege", "run as root (sudo -n)")
    if commit == box_es_commit():
        block("commit", f"{box_es_commit()} is the build ES PR #54's upgrade installed; name the commit to move to")

    try:
        prov = load_payload(payload_dir, commit)
        report["payload"] = {"commit": prov["commit"], "go_version": prov["go_version"], "sha256": prov["sha256"]}
    except (Refusal, OSError, ValueError) as exc:
        prov = None
        block("payload", str(exc))

    shape, parts, pin, forms, installed = host_shape(commit, prov)
    report["shape"] = shape or "unknown"
    report["parts"] = parts
    if shape is None:
        block("shape", "the host is in no shape this upgrade knows; it takes locked-http or https to https-gossip: "
              + describe_parts(parts))
    inspect_move(report, block, installed, commit, allow_downgrade)

    active = services_active()
    report["services"] = active
    if len(active) != len(SERVICES) or any(state != "active" for state in active.values()):
        block("services", "not every service is active")
    for problem in es_unit_problems():
        block("es_unit", problem)
    try:
        report["health"] = service_health()
        if not healthy(report["health"]):
            block("health", "ES and AGS do not all answer 200 (healthcheck runbook step 4)")
    except (Refusal, OSError, ValueError) as exc:
        block("health", str(exc))

    try:
        _, st = read_regular_file(host(ES_CONFIG))
        report["es_config"] = owner_mode(st)
        if (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) != (root_ids()[0], group_id(ES_USER), ES_CONFIG_MODE):
            block("es_config", "es.json is not root:es 0640")
    except (Refusal, OSError) as exc:
        block("es_config", str(exc))
    try:
        _, st = read_regular_file(host(NOMAD_HCL))
        report["nomad_hcl"] = owner_mode(st)
        if not owned_by_root(st) or stat.S_IMODE(st.st_mode) != NOMAD_CONFIG_MODE:
            block("nomad_hcl", f"nomad.hcl is not root:root 0640 ({owner_mode(st)}); {NOMAD_HCL_REMEDY}")
        acls = posix_acls(host(NOMAD_HCL))
        if acls:
            block("nomad_hcl", f"nomad.hcl has an ACL ({', '.join(acls)}); {NOMAD_HCL_REMEDY}")
        others = other_nomad_configs()
        if others:
            block("nomad_hcl", f"Nomad would also load {others} from {NOMAD_DIR}")
    except (Refusal, OSError) as exc:
        block("nomad_hcl", str(exc))
    # HashiCorp's package gives nomad.env to the nomad account, as it does
    # everything in /etc/nomad.d; the setup takes it back (re-check 49 of ES
    # PR #66, O49-2). This upgrade does not, so it refuses one that another
    # account could change, as it refuses such a nomad.hcl. Its remedy puts
    # the file back as a new one, as the setup does: a chown, a chmod or
    # setfacl in place leaves a handle that account opened earlier able to
    # write it (re-check 50 of #67, S67-3).
    try:
        st = os.lstat(host(NOMAD_ENV))
        if not stat.S_ISREG(st.st_mode):
            # The remedy for the other refusals copies the file (install
            # opens its source): on a FIFO it would wait, and on a link it
            # would copy the link's target (re-check 51 of #67, N67-8).
            kind = ("a link" if stat.S_ISLNK(st.st_mode) else "a folder" if stat.S_ISDIR(st.st_mode)
                    else "a FIFO" if stat.S_ISFIFO(st.st_mode) else "not a file")
            block("nomad_env", f"{NOMAD_ENV}, which Nomad's unit reads as root, is {kind}, not a regular file; "
                  "remove it")
        elif not owned_by_root(st) or stat.S_IMODE(st.st_mode) & ~0o755:
            block("nomad_env", f"{NOMAD_ENV}, which Nomad's unit reads as root, is not root:root without write for "
                  f"group or others ({owner_mode(st)}); {NOMAD_ENV_REMEDY}")
        else:
            acls = posix_acls(host(NOMAD_ENV))
            if acls:
                block("nomad_env", f"{NOMAD_ENV} has an ACL ({', '.join(acls)}); {NOMAD_ENV_REMEDY}")
    except FileNotFoundError:
        pass
    except OSError as exc:
        block("nomad_env", str(exc))
    for path, mode in NOMAD_DIRS:
        try:
            st = os.lstat(host(path))
            if not stat.S_ISDIR(st.st_mode) or not owned_by_root(st) or stat.S_IMODE(st.st_mode) != mode:
                block("nomad_dirs", f"{path} is not a root:root {mode:04o} directory")
                continue
            acls = posix_acls(host(path))
            if acls:
                block("nomad_dirs", f"{path} has an ACL ({', '.join(acls)}; setfacl -b -k {path} removes it)")
        except OSError as exc:
            block("nomad_dirs", str(exc))

    if shape == "locked-http":
        inspect_start(report, block, payload_dir, prov)
    elif shape == "https":
        inspect_https(report, block, payload_dir, prov, pin, forms)
    elif shape == "https-gossip":
        inspect_migrated(report, block, gossip=True)
    report["blockers"] = blockers
    return report, blockers, forms


def acl_files():
    """(file, owner uid, mode) of each token file nomad_acl_setup.sh made.
    The management token is root's; under a test host root it is the test
    user's, or root's when the real script runs through sudo."""
    management_uid = 0 if not test_mode() or acl_setup_sudo() else os.getuid()
    return (("management-token", management_uid, 0o600), ("es-token", user_ids(ES_USER)[0], 0o400),
            ("observer-token", user_ids(OBSERVER_USER)[0], 0o400))


def es_config_target(doc, shape, pin):
    """(es.json, changes): the es.json apply installs on a host whose es.json
    doc is in shape "locked-http" or "https", with pin the server key's
    SHA-256. check and apply both take it from here, so a step that adds
    keys to es.json is written once. doc must have Nomad's TLS keys exactly
    when shape is "https", so such a step may rely on the shape it is given
    (re-check 48 of ES PR #67: nothing else made a wrong shape fail)."""
    nomad = doc.get("nomad") if isinstance(doc, dict) else None
    has_tls = isinstance(nomad, dict) and any(key in nomad for key in NOMAD_TLS_KEYS)
    if has_tls != (shape == "https"):
        raise Refusal(f"es.json {'has' if has_tls else 'has no'} Nomad TLS keys, but the host's shape is {shape}")
    if shape == "locked-http":
        return migrate_config(doc, pin, START_ES_PATHS)
    return migrate_config(doc, pin)


def inspect_start(report, block, payload_dir, prov):
    """The checks of a locked-http host, which apply will change."""
    def migrate():
        data, _ = read_regular_file(host(ES_CONFIG))
        return es_config_target(json.loads(data), "locked-http", PLACEHOLDER_PIN)

    inspect_ahead(report, block, payload_dir, prov, migrate, nomad_http_addr())
    report["changes"] = [
        f"issue Nomad's TLS material into {NOMAD_TLS_DIR} with the setup's nomad_tls_issue",
        f"write Nomad's gossip keyring to {NOMAD_GOSSIP_KEYRING} with the setup's nomad_gossip_issue",
        "append the supported config's tls block to nomad.hcl and restart Nomad on HTTPS, with its gossip encrypted",
        "provision Nomad's ACLs again (the observer policy gains list-jobs) and check placement",
        "es.json: " + ", ".join(report.get("es_config", {}).get("changes", [])),
        f"install es and es-runtime-support built from {report['commit']}",
    ]


def inspect_https(report, block, payload_dir, prov, pin, forms):
    """The checks of an https host, which apply will change: Nomad must run
    as an https host does (and encrypt its gossip if it has a keyring), and
    the host must be ready for the change."""
    keyring_absent = forms["Nomad's gossip keyring"] == "absent"
    inspect_migrated(report, block, gossip=not keyring_absent)

    def migrate():
        data, _ = read_regular_file(host(ES_CONFIG))
        return es_config_target(json.loads(data), "https", pin)

    inspect_ahead(report, block, payload_dir, prov, migrate, None)
    changes = []
    if keyring_absent:
        changes += [f"write Nomad's gossip keyring to {NOMAD_GOSSIP_KEYRING} with the setup's nomad_gossip_issue",
                    "restart Nomad on HTTPS, which then encrypts its gossip, and check its ACLs and placement"]
    if forms["the ES binaries"] != "https":
        changes.append(f"install es and es-runtime-support built from {report['commit']}")
    report["changes"] = changes


def inspect_ahead(report, block, payload_dir, prov, migrate, leader_addr):
    """The checks of a host that apply will change: the new ES must accept
    the es.json it will run with (migrate returns it and its changes), the
    token files and the retained-result key must be as provision and ES PR
    #54's upgrade left them, the setup's functions must be at hand, Nomad
    must have a named leader at leader_addr (unless None, when the caller
    checked it) and no allocation may be running."""
    try:
        migrated, changes = migrate()
        report.setdefault("es_config", {})["changes"] = changes
        if prov is not None:
            ok, out = esconfigcheck(os.path.join(payload_dir, "esconfigcheck"), migrated)
            report["es_config"]["new_es_accepts_migrated_config"] = ok
            if not ok:
                block("es_config", f"the new ES refuses the migrated config: {out[:300]}")
    except (Refusal, OSError, ValueError) as exc:
        block("es_config", str(exc))

    for name, uid, mode in acl_files():
        path = f"{NOMAD_ACL_DIR}/{name}"
        try:
            st = os.lstat(host(path))
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != uid or stat.S_IMODE(st.st_mode) != mode:
                block("nomad_acl", f"{path} is not a {mode:04o} file of uid {uid} with one link, as provision left it")
        except OSError as exc:
            block("nomad_acl", f"{path}: {exc.strerror}")
    try:
        uid, gid = user_ids(ES_USER)
        report["retained_result_key"] = provision_key(host(KEY_FILE), uid, gid, create_parent=False, dry_run=True)
        if report["retained_result_key"] != "exists":
            block("retained_result_key", "the retained-result key ES PR #54's upgrade made is missing")
    except (Refusal, OSError) as exc:
        block("retained_result_key", str(exc))

    if shutil.which("openssl") is None:
        block("tools", "openssl is not installed; the setup's nomad_tls and nomad_gossip functions need it")
    for region in ("nomad_tls", "nomad_gossip"):
        try:
            setup_functions(region)
        except (Refusal, OSError, UnicodeDecodeError) as exc:
            block("tools", str(exc))

    if leader_addr is not None and not nomad_leader_named(leader_addr):
        block("nomad", f"Nomad has no named leader at {leader_addr}")
    proc = run(["docker", "ps", "--quiet", "--no-trunc", "--filter", f"label={NOMAD_ALLOC_LABEL}"], timeout=30)
    if proc.returncode != 0:
        block("nomad", f"cannot list the containers of Nomad's allocations: {proc.stderr.strip()[:200]}")
    else:
        running = proc.stdout.split()
        report["nomad_allocation_containers"] = len(running)
        if running:
            block("nomad", f"{len(running)} container(s) of Nomad allocations are running; wait until they finish")


def inspect_migrated(report, block, gossip):
    """The read-only proof that Nomad runs on HTTPS as ES's settings expect,
    and, when gossip is true (a keyring is in place), that it encrypts its
    gossip."""
    report["changes"] = []
    if not nomad_leader_named(nomad_https_addr()):
        block("nomad", f"Nomad has no named leader at {nomad_https_addr()}")
    ok, out = tls_identity_check()
    report["nomad_tls_identity"] = out
    if not ok:
        block("nomad", f"ES's Nomad TLS settings do not hold against the running Nomad: {out}")
    for problem in anonymous_nomad_problems():
        block("nomad", problem)
    if gossip:
        encrypted, state = nomad_gossip_state()
        report["nomad_gossip"] = state
        if not encrypted:
            block("nomad", f"Nomad has a gossip keyring but does not report its gossip encrypted: {state}")


def write_summary(path, report):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(report, indent=2, sort_keys=True) + "\n")


def backup_root_ready():
    root = host(BACKUP_ROOT)
    try:
        os.mkdir(root, 0o700)
    except FileExistsError:
        pass
    st = os.lstat(root)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != root_ids()[0]:
        raise Refusal(f"{BACKUP_ROOT} must be a directory root owns")
    os.chmod(root, 0o700)
    return root


CREATED_MANIFEST = "created.json"
# What apply writes into its backup before it changes anything: the move it
# makes (inspect_move's report).
MOVE_RECORD = "move.json"
# The names of the folders in BACKUP_ROOT when apply made the backup, so a
# rollback can tell which backups were made after the one it puts back,
# whatever the clock said (audit 47, A47-1).
EARLIER_BACKUPS = "earlier.json"
# Written into a backup once a rollback (rollback's or apply's own) has put
# its files back and removed what its apply created.
RESTORED_RECORD = "restored-{at}-{pid}.json"
RESTORED_RECORD_NAME = re.compile(r"restored-\d{8}T\d{6}Z-\d+\.json")


def backup_host(commit, created):
    """Back up every file apply changes into a new backup directory, and name
    every path it creates: created, a subset of CREATED_BY_APPLY, none of
    which may exist yet. A path that exists already is refused before
    anything is written. Returns the backup directory."""
    if not set(created) <= set(CREATED_BY_APPLY):
        raise Refusal(f"apply does not create {sorted(set(created) - set(CREATED_BY_APPLY))}")
    for path in created:
        if os.path.lexists(host(path)):
            raise Refusal(f"{path} exists already; nothing was changed")
    root = backup_root_ready()
    earlier = sorted(name for name in os.listdir(root) if stat.S_ISDIR(os.lstat(os.path.join(root, name)).st_mode))
    backup_dir = os.path.join(root, time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + commit[:12])
    backup_files(backup_dir, [host(p) for p in BACKED_UP_BY_APPLY])
    write_new_file(os.path.join(backup_dir, CREATED_MANIFEST), json.dumps(list(created), indent=2) + "\n")
    # EARLIER_BACKUPS comes after CREATED_MANIFEST, whole or not at all, and
    # before cmd_apply writes MOVE_RECORD, stages the payload and changes the
    # host (re-check 48 of ES PR #67, S1): a folder that has it has
    # CREATED_MANIFEST too, and a partial EARLIER_BACKUPS would block the
    # rollback of every other backup. An apply cut off before it leaves a
    # folder the order rule skips: rollback refuses it when its
    # BACKUP_MANIFEST or CREATED_MANIFEST is not whole, and otherwise puts
    # back the files it found, while the host is as that apply left it.
    write_new_file_renamed(os.path.join(backup_dir, EARLIER_BACKUPS), json.dumps(earlier, indent=2) + "\n")
    return backup_dir


def load_created(backup_dir):
    created = read_backup_document(backup_dir, CREATED_MANIFEST,
                                   "the backup's apply stopped before it changed the host, so there is nothing to put back")
    if (not isinstance(created, list) or not all(isinstance(path, str) for path in created)
            or not set(created) <= set(CREATED_BY_APPLY)):
        raise Refusal(f"the backup's {CREATED_MANIFEST} names paths that apply does not create")
    return created


def remove_created(created):
    removed = []
    for path in created:
        try:
            st = os.lstat(host(path))
        except FileNotFoundError:
            continue
        if stat.S_ISDIR(st.st_mode):
            shutil.rmtree(host(path))
        else:
            os.unlink(host(path))
        removed.append(path)
    return removed


def acl_setup_sudo():
    return test_mode() and os.environ.get("ES_UPGRADE_TEST_ACL_SUDO") == "1"


def acl_setup(action, **extra_env):
    """Run scripts/nomad_acl_setup.sh from this checkout against Nomad's
    HTTPS address, trusting only Nomad's CA."""
    settings = dict(NOMAD_ADDR=nomad_https_addr(), NOMAD_CACERT=host(NOMAD_CA_FILE), NOMAD_ACL_DIR=host(NOMAD_ACL_DIR),
                    ES_USER=ES_USER, OBSERVER_USER=OBSERVER_USER, NOMAD_USER="root", **extra_env)
    if acl_setup_sudo():
        # The real script, as root, against a real Nomad that the test runs
        # as its own user, who also stands in for ES and the observer.
        name = pwd.getpwuid(os.getuid()).pw_name
        settings.update(ES_USER=name, OBSERVER_USER=name, NOMAD_USER=name)
        argv = ["sudo", "-n", "env", *[f"{key}={value}" for key, value in settings.items()], "bash", ACL_SETUP_SCRIPT, action]
        proc = run(argv, timeout=300)
    else:
        override = os.environ.get("ES_UPGRADE_TEST_ACL_SETUP") if test_mode() else None
        argv = [override, action] if override else ["bash", ACL_SETUP_SCRIPT, action]
        proc = run(argv, env=dict(os.environ, **settings), timeout=300)
    if proc.returncode != 0:
        raise Refusal(f"nomad_acl_setup.sh {action} failed: {(proc.stderr or proc.stdout).strip()[:400]}")
    return proc


def validate_nomad_hcl(text):
    """nomad config validate on text, its TLS paths read through a test host
    root (on the host they are the same). validate only warns, and exits 0,
    about TLS files it cannot read, so that warning is refused here."""
    view = text.replace(f'"{NOMAD_TLS_DIR}/', f'"{host(NOMAD_TLS_DIR)}/') if test_mode() else text
    tmpdir = tempfile.mkdtemp(prefix="es-upgrade-nomad-")
    try:
        with open(os.path.join(tmpdir, "nomad.hcl"), "w", encoding="utf-8") as handle:
            handle.write(view)
        proc = run(["nomad", "config", "validate", tmpdir], timeout=60, check=True)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    for line in (proc.stdout + proc.stderr).splitlines():
        if any(refused in line for refused in NOMAD_VALIDATE_REFUSED):
            raise Refusal(f"nomad config validate: {line.strip()[:300]}")


def issue_gossip_keyring(log):
    """Write Nomad's gossip keyring with the setup's nomad_gossip_issue. Nomad
    reads it when it next starts."""
    proc = nomad_gossip("nomad_gossip_issue", host(NOMAD_GOSSIP_KEYRING))
    if proc.returncode != 0:
        raise Refusal(f"nomad_gossip_issue failed: {proc.stderr.strip()[:300]}")
    shape, state = keyring_shape()
    if shape != "sound":
        raise Refusal(f"Nomad's new gossip keyring is {state}")
    log(f"Nomad's gossip keyring written to {NOMAD_GOSSIP_KEYRING}")


def require_gossip_encrypted(log):
    encrypted, state = nomad_gossip_state()
    if not encrypted:
        raise Refusal(f"Nomad does not report its gossip encrypted: {state}")
    log('Nomad reports its gossip encrypted (stats.serf.encrypted "true")')


def apply_nomad_tls(log):
    """Issue Nomad's TLS material and write its gossip keyring, restart Nomad
    on HTTPS, check that it encrypts its gossip, provision its ACLs again
    and prove that it places ES's jobs. Returns the server key's pin."""
    text, _ = read_regular_file(host(NOMAD_HCL))
    if sha256_bytes(text) != NOMAD_HCL_LOCKED_SHA256:
        raise Refusal("nomad.hcl changed after check")
    proc = nomad_tls("nomad_tls_issue", host(NOMAD_TLS_DIR))
    if proc.returncode != 0:
        raise Refusal(f"nomad_tls_issue failed: {proc.stderr.strip()[:300]}")
    shape, state = tls_dir_shape()
    if shape != "https":
        raise Refusal(f"Nomad's new TLS directory is {state}")
    pin = server_spki_sha256()
    log(f"Nomad's TLS material issued in {NOMAD_TLS_DIR}; server key SHA-256 {pin}")
    new_text = text + NOMAD_TLS_BLOCK.encode()
    validate_nomad_hcl(new_text.decode("utf-8"))
    log("nomad.hcl with the tls block validated")
    issue_gossip_keyring(log)
    stop_service("nomad")
    log("nomad stopped")
    ruid, rgid = root_ids()
    atomic_replace(host(NOMAD_HCL), new_text, ruid, rgid, NOMAD_CONFIG_MODE)
    log("tls block added to nomad.hcl")
    started_at = int(time.time())
    run(["systemctl", "start", "nomad"], timeout=120, check=True)
    if not wait_for(lambda: nomad_leader_named(nomad_https_addr()), LEADER_WAIT_SECONDS):
        raise Refusal(f"Nomad named no leader at {nomad_https_addr()} within {LEADER_WAIT_SECONDS} s of its start")
    log("nomad started on HTTPS with a named leader")
    acl_setup("provision")
    log("nomad ACLs provisioned again (nomad_acl_setup.sh provision, which ends with its check)")
    require_gossip_encrypted(log)
    check_placement(started_at, log)
    return pin


def apply_nomad_gossip(log):
    """Write Nomad's gossip keyring and restart Nomad on HTTPS, which then
    encrypts its gossip; check its ACLs and prove that it places ES's jobs."""
    issue_gossip_keyring(log)
    stop_service("nomad")
    log("nomad stopped")
    started_at = int(time.time())
    run(["systemctl", "start", "nomad"], timeout=120, check=True)
    if not wait_for(lambda: nomad_leader_named(nomad_https_addr()), LEADER_WAIT_SECONDS):
        raise Refusal(f"Nomad named no leader at {nomad_https_addr()} within {LEADER_WAIT_SECONDS} s of its start")
    log("nomad started on HTTPS with a named leader")
    acl_setup("check")
    log("nomad ACLs checked (nomad_acl_setup.sh check)")
    require_gossip_encrypted(log)
    check_placement(started_at, log)


def check_placement(started_at, log):
    # Every check before this passes on a Nomad that can place nothing: prove
    # that the restarted node has a host-mode network and that ES's job
    # shapes plan.
    acl_setup("placement", ES_CONFIG=host(ES_CONFIG), NOMAD_STARTED_AT=str(started_at),
              NOMAD_PLACEMENT_WAIT_SECONDS=str(PLACEMENT_WAIT_SECONDS))
    log("nomad can place ES's jobs (nomad_acl_setup.sh placement)")


def install_es(stage_dir, migrated, log):
    uid, gid = user_ids(ES_USER)
    if provision_key(host(KEY_FILE), uid, gid, create_parent=False, dry_run=True) != "exists":
        raise Refusal("the retained-result key ES PR #54's upgrade made is missing")
    _, tst = read_regular_file(host(ES_TOKEN_FILE))
    if tst.st_uid != uid or stat.S_IMODE(tst.st_mode) not in (0o400, 0o600):
        raise Refusal("the ES Nomad token file is not ES's own 0400/0600 file")
    ok, out = esconfigcheck(os.path.join(stage_dir, "esconfigcheck"), migrated)
    if not ok:
        raise Refusal(f"the new ES refuses the migrated config: {out[:300]}")
    ruid, rgid = root_ids()
    new_config = render_json(migrated).encode()
    if new_config != read_regular_file(host(ES_CONFIG))[0]:
        atomic_replace(host(ES_CONFIG), new_config, ruid, group_id(ES_USER), ES_CONFIG_MODE)
        log("es.json migrated")
    else:
        log("es.json unchanged")
    for name, dest in (("es", ES_BINARY), ("es-runtime-support", RUNTIME_SUPPORT)):
        blob, _ = read_regular_file(os.path.join(stage_dir, name))
        atomic_replace(host(dest), blob, ruid, rgid, BINARY_MODE)
    log("es and es-runtime-support installed")


def tls_identity_check():
    """(ok, line) of nomad_tls_identity.py check, which makes ES's own TLS
    checks against the running Nomad with the installed es.json. Its CA path
    is read through a test host root (on the host it is the same)."""
    try:
        data, _ = read_regular_file(host(ES_CONFIG))
        doc = json.loads(data)
        nomad = doc.get("nomad") if isinstance(doc, dict) else None
        if not isinstance(nomad, dict):
            return False, "es.json has no nomad block"
    except (Refusal, OSError, ValueError) as exc:
        return False, str(exc)
    if test_mode() and isinstance(nomad.get("root_ca_file"), str):
        nomad["root_ca_file"] = host(nomad["root_ca_file"])
    override = os.environ.get("ES_UPGRADE_TEST_TLS_IDENTITY") if test_mode() else None
    tmpdir = tempfile.mkdtemp(prefix="es-upgrade-identity-")
    try:
        path = os.path.join(tmpdir, "es.json")
        write_new_file(path, render_json(doc))
        argv = [override] if override else [sys.executable, "-I", TLS_IDENTITY_TOOL]
        proc = run([*argv, "check", path, nomad_https_addr()], timeout=30)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    return proc.returncode == 0, ((proc.stdout if proc.returncode == 0 else proc.stderr) or "").strip()[:300]


def verify_after(log):
    if not wait_for(lambda: services_active().get("es") == "active" and healthy(service_health()), ES_WAIT_SECONDS):
        raise Refusal(f"ES did not come back healthy: {services_active().get('es')}, {service_health()}")
    log("ES and AGS answer 200")
    ok, out = tls_identity_check()
    if not ok:
        raise Refusal(f"ES's Nomad TLS settings do not hold against the running Nomad: {out}")
    log(out)
    problems = anonymous_nomad_problems()
    if problems:
        raise Refusal("; ".join(problems))
    acl_setup("check")
    log("Nomad refuses an anonymous job list and holds no anonymous policy over HTTPS; nomad_acl_setup.sh check passed")
    require_gossip_encrypted(log)


def live_nomad_addr():
    """Nomad's address under the nomad.hcl on disk."""
    try:
        text, _ = read_regular_file(host(NOMAD_HCL))
    except (Refusal, OSError):
        return nomad_http_addr()
    return nomad_https_addr() if text.endswith(NOMAD_TLS_BLOCK.encode()) else nomad_http_addr()


def build_commit(blob):
    """The commit a clean Go build names in its own build info, or None."""
    try:
        _, lines = go_build_info(blob)
    except (Refusal, struct.error, ValueError, IndexError):
        return None
    settings = dict(line.partition("=")[::2] for line in lines)
    revision = settings.get("vcs.revision")
    return revision if settings.get("vcs.modified") == "false" and valid_commit(revision) else None


# The ES binaries a rollback puts back, and what each installed one may be
# for a rollback of a backup to run.
ROLLBACK_BINARIES = (("es", ES_BINARY), ("es-runtime-support", RUNTIME_SUPPORT))
BACKUP_COPY = "the backup's copy"
STAGED_COPY = "the payload its apply installed"
# The record of each rollback, written into the backup it puts back.
ROLLBACK_RECORD = "rollback-{at}-{pid}.json"


def rollback_move(backup_dir, manifest):
    """(move, problems): what a rollback of the backup in backup_dir, whose
    manifest load_backup verified, puts in place of the installed es and
    es-runtime-support. For each, move names what the installed file is,
    byte for byte: BACKUP_COPY (the backup's apply stopped before it
    replaced that file, or this backup was put back already), STAGED_COPY
    (the copy of the payload that the backup's apply staged in the backup,
    so that apply installed it), or None; and the commit the installed file
    and the backup's copy are clean builds of (build_commit). problems names
    each file that is neither copy: then the backup is not of the apply
    that left the host as it is (an older backup after a later apply, or
    builds put in place without this script), and putting it back would
    move ES to another build without the move check or its record (audit
    44, A44-1)."""
    copies = {entry["path"]: entry for entry in manifest["files"]}
    staged_dir = os.path.join(backup_dir, "payload")
    try:
        staged = stat.S_ISDIR(os.lstat(staged_dir).st_mode)
    except FileNotFoundError:
        staged = False
    move = {"installed": {}, "from": {}, "to": {}}
    problems = []
    for name, path in ROLLBACK_BINARIES:
        entry = copies.get(host(path), {"exists": False})
        backup_copy = None
        if entry["exists"]:
            backup_copy, _ = read_regular_file(os.path.join(backup_dir, "files", entry["copy"]))
        move["to"][name] = build_commit(backup_copy) if backup_copy is not None else None
        move["installed"][name] = move["from"][name] = None
        try:
            blob, _ = read_regular_file(host(path))
        except (Refusal, OSError) as exc:
            problems.append(f"{path} cannot be read ({exc})")
            continue
        move["from"][name] = build_commit(blob)
        if backup_copy is not None and blob == backup_copy:
            move["installed"][name] = BACKUP_COPY
            continue
        try:
            staged_copy = read_regular_file(os.path.join(staged_dir, name))[0] if staged else None
        except (Refusal, OSError):
            staged_copy = None
        if staged_copy is not None and blob == staged_copy:
            move["installed"][name] = STAGED_COPY
            continue
        problems.append(f"{path} (a build of {move['from'][name] or 'no one clean commit'}) is neither "
                        f"{BACKUP_COPY} nor {STAGED_COPY}")
    return move, problems


def later_backups_not_put_back(backup_dir):
    """The problems that stop a rollback of backup_dir under the order rule
    (audit 47, A47-1): it must be a folder of BACKUP_ROOT, and each
    backup apply made while it was there (whose EARLIER_BACKUPS names it)
    must have been put back since (it holds a RESTORED_RECORD). Builds are
    reproducible, so a later apply of the same commit installs bytes equal
    to an older backup's staged payload, and rollback_move alone would take
    that older backup. A folder without EARLIER_BACKUPS was made by an
    earlier version of this script (ES PR #60's or #54's), before any backup
    this one makes, or by an apply cut off before it changed anything."""
    root = host(BACKUP_ROOT)
    name = os.path.basename(os.path.realpath(backup_dir))
    if os.path.dirname(os.path.realpath(backup_dir)) != os.path.realpath(root):
        return [f"it is not a folder of {BACKUP_ROOT}, so the backups made after it cannot be told"]
    problems = []
    for other in sorted(os.listdir(root)):
        path = os.path.join(root, other)
        if other == name or not stat.S_ISDIR(os.lstat(path).st_mode):
            continue
        try:
            data, _ = read_regular_file(os.path.join(path, EARLIER_BACKUPS))
            earlier = json.loads(data)
            if not isinstance(earlier, list) or not all(isinstance(entry, str) for entry in earlier):
                raise ValueError("not a list of names")
        except FileNotFoundError:
            continue
        except (Refusal, OSError, ValueError) as exc:
            problems.append(f"{os.path.join(path, EARLIER_BACKUPS)} cannot be read ({exc})")
            continue
        if name in earlier and not any(RESTORED_RECORD_NAME.fullmatch(entry) and
                                       stat.S_ISREG(os.lstat(os.path.join(path, entry)).st_mode)
                                       for entry in os.listdir(path)):
            problems.append(f"{path} was made after it, and that apply has not been put back "
                            f"(no {RESTORED_RECORD.format(at='<UTC>', pid='<pid>')} in it)")
    return problems


def record_restored(backup_dir, by):
    """Write, into a new file in backup_dir, that its files are back and
    what its apply created is removed. Returns a line for the log."""
    at = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    path = os.path.join(backup_dir, RESTORED_RECORD.format(at=at, pid=os.getpid()))
    write_new_file(path, json.dumps({"at": at, "by": by}, indent=2, sort_keys=True) + "\n")
    return f"put back, recorded in {path}"


def record_rollback(backup_dir, move, by):
    """Write the record of a rollback of backup_dir (rollback_move's move),
    with what started it (by: "rollback", or "apply" rolling itself back),
    the time and who ran it, into a new file in the backup. Returns a line
    that says so, for the log."""
    at = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    record = dict(move, by=by, at=at, **who_ran())
    path = os.path.join(backup_dir, ROLLBACK_RECORD.format(at=at, pid=os.getpid()))
    write_new_file(path, json.dumps(record, indent=2, sort_keys=True) + "\n")
    return f"rollback recorded in {path}: ES from {move['from']} to {move['to']} ({describe_who(record)})"


def restore_host(backup_dir, log, by):
    """Put back every file the backup holds and remove every path apply
    created, then start Nomad and ES. Nomad's ACL policies stay as provision
    last wrote them: the observer policy keeps list-jobs, a read. by is
    "rollback" for the rollback command, which refuses a backup whose apply
    did not leave the host as it is (rollback_move), or "apply" for apply
    putting back its own backup, which goes on whatever it finds. Either way
    the rollback is recorded in the backup before a service is touched;
    apply goes on, logging why, if that record cannot be written."""
    # The whole backup is verified before a service is touched, and holds
    # what apply backs up: restore_files writes each path its manifest names.
    manifest = load_backup(backup_dir)
    backed_up = [host(path) for path in BACKED_UP_BY_APPLY]
    if [entry["path"] for entry in manifest["files"]] != backed_up:
        raise Refusal(f"{backup_dir}'s manifest does not name the files apply backs up ({', '.join(backed_up)}), "
                      "in that order; nothing was changed")
    created = load_created(backup_dir)
    if by == "rollback":
        move, problems = rollback_move(backup_dir, manifest)
        problems = later_backups_not_put_back(backup_dir) + problems
        if problems:
            raise Refusal(f"{backup_dir} is not the backup of the apply that left the host as it is: "
                          + "; ".join(problems) + "; put back the newest backup first; nothing was changed")
        try:
            log(record_rollback(backup_dir, move, by))
        except OSError as exc:
            raise Refusal(f"the rollback cannot be recorded in {backup_dir} ({exc}); nothing was changed") from None
    else:
        try:
            move, _ = rollback_move(backup_dir, manifest)
            log(record_rollback(backup_dir, move, by))
        except Exception as exc:  # noqa: BLE001 - apply's own rollback goes on
            log(f"the rollback could not be recorded ({exc!r}); putting the backup back all the same")
    # Nothing is put back under a running service: if either will not stop,
    # the restore stops here and reports it.
    stop_service("es")
    stop_service("nomad")
    log("es and nomad stopped for the restore")
    result = restore_files(backup_dir)
    result["removed"] = remove_created(created)
    log(f"files restored from {backup_dir}; removed {result['removed']}")
    try:
        log(record_restored(backup_dir, by))
    except OSError as exc:
        log(f"that the backup is put back could not be recorded ({exc}); a rollback of an earlier backup "
            "is refused until this one is put back again")
    run(["systemctl", "start", "nomad"], timeout=120, check=True)
    addr = live_nomad_addr()
    leader = bool(wait_for(lambda: nomad_leader_named(addr), LEADER_WAIT_SECONDS))
    run(["systemctl", "start", "es"], timeout=120, check=True)
    log("nomad and es started")
    # ES's /health does not ask Nomad, so a Nomad without a leader fails
    # the restore here rather than passing unseen.
    if not leader:
        raise Refusal(f"Nomad named no leader at {addr} within {LEADER_WAIT_SECONDS} s of the restore")
    log(f"nomad has a named leader at {addr}")
    return result


def health_after_restore():
    """(problems, details) after a restore: ES's and AGS's endpoints must
    answer 200 and, when the restored nomad.hcl serves HTTPS, ES's es.json
    must hold against the running Nomad (tls_identity_check), since ES's
    /health does not ask Nomad (audit 47, O47-2)."""
    try:
        problems = []
        if not wait_for(lambda: healthy(service_health()), ES_WAIT_SECONDS):
            problems.append("ES and AGS do not all answer 200")
        details = {"services": services_active(), "health": service_health()}
        if live_nomad_addr() == nomad_https_addr():
            ok, details["nomad_tls_identity"] = tls_identity_check()
            if not ok:
                problems.append("ES's Nomad TLS settings do not hold against the running Nomad: "
                                + details["nomad_tls_identity"])
        return problems, details
    except Exception as exc:  # noqa: BLE001 - reported, never raised
        return [str(exc)], {"error": str(exc)}


class Interrupted(Exception):
    """SIGTERM, SIGHUP or SIGINT arrived during apply."""


INTERRUPT_SIGNALS = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)


def ignore_interrupts():
    for signum in INTERRUPT_SIGNALS:
        signal.signal(signum, signal.SIG_IGN)


def raise_interrupted(signum, _frame):
    # The first signal ends the forward path. Any later one is ignored from
    # this point, so it cannot break off the drain of a command or the
    # rollback.
    ignore_interrupts()
    raise Interrupted(f"signal {signum}")


OUTPUT = {"lost": False}


def say(text, stream=None):
    """Print, and never raise. A terminal that hung up (EIO) or a pipe whose
    reader went away (EPIPE) must not stop apply or its rollback: the first
    failed write sends the standard output and error to /dev/null, and the
    events stay in the summary."""
    try:
        print(text, file=stream or sys.stdout, flush=True)
    except (OSError, ValueError):
        OUTPUT["lost"] = True
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, 1)
            os.dup2(devnull, 2)
            os.close(devnull)
        except OSError:
            pass


def cmd_check(args):
    report, blockers, _ = inspect_host(args.payload, args.commit, args.allow_downgrade)
    report["mode"] = "check"
    if not blockers:
        report["result"] = "nothing to do" if report["shape"] == "https-gossip" else "ready"
    say(json.dumps(report, indent=2, sort_keys=True))
    if blockers:
        raise Refusal(f"{len(blockers)} blocker(s); nothing was changed")


def cmd_apply(args):
    events = []

    def log(message):
        events.append({"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": message})
        say(message)

    report, blockers, forms = inspect_host(args.payload, args.commit, args.allow_downgrade)
    report["mode"] = "apply"
    report["events"] = events
    if blockers:
        say(json.dumps(report, indent=2, sort_keys=True))
        raise Refusal(f"{len(blockers)} blocker(s); nothing was changed")
    shape = report["shape"]
    if shape == "https-gossip":
        # Already applied for this commit, and verified in place: no backup,
        # and no service is touched.
        report["result"] = "nothing to do"
        say(json.dumps(report, indent=2, sort_keys=True))
        return
    # What apply does to the keyring follows from the form check found
    # (absent: write one; sound: keep it), so the keyring must still have
    # that form now, on either start. Any change since the check, a keyring
    # that appeared, went away or turned unsound, is refused before the
    # backup, with nothing changed.
    form, state = keyring_shape()
    if form != forms["Nomad's gossip keyring"]:
        raise Refusal(f"Nomad's gossip keyring changed after check: {state}; nothing was changed")
    keyring_absent = form == "absent"
    created = ([NOMAD_TLS_DIR] if shape == "locked-http" else []) + ([NOMAD_GOSSIP_KEYRING] if keyring_absent else [])
    prov = load_payload(args.payload, args.commit)
    backup_dir = backup_host(args.commit, created)
    report["backup_dir"] = backup_dir
    summary_path = os.path.join(backup_dir, "summary.json")
    log("backup written to " + backup_dir)
    # The record of the move, in the backup before anything changes: a
    # move that is not forward shows there with the --allow-downgrade that
    # let it through, even if this run is killed before its summary.
    move = report["move"]
    write_new_file(os.path.join(backup_dir, MOVE_RECORD), json.dumps(move, indent=2, sort_keys=True) + "\n")
    if "authorized" in move:
        log(f"moving ES from {move['from']} to {move['to']}, which is not forward ({move['order']}), "
            f"as root named it: {move['authorized']} ({describe_who(move)})")
    stage_dir = stage_payload(args.payload, prov, os.path.join(backup_dir, "payload"))
    data, _ = read_regular_file(host(ES_CONFIG))
    config = json.loads(data)

    # From here on, any failure or interruption puts the backup back. The
    # handler raises once at most (it sets every signal aside first), and the
    # outer try catches the one case the inner except cannot: that first
    # signal landing while another failure is being caught.
    failure = None
    for signum in INTERRUPT_SIGNALS:
        signal.signal(signum, raise_interrupted)
    try:
        try:
            stop_service("es")
            log("es stopped")
            if shape == "locked-http":
                pin = apply_nomad_tls(log)
            else:
                pin = server_spki_sha256()
                if keyring_absent:
                    apply_nomad_gossip(log)
            migrated, _ = es_config_target(config, shape, pin)
            install_es(stage_dir, migrated, log)
            run(["systemctl", "start", "es"], timeout=120, check=True)
            log("es started")
            verify_after(log)
            report["result"] = "applied"
            ignore_interrupts()
        except BaseException as exc:  # noqa: BLE001 - every failure after the backup rolls back
            failure = exc
            ignore_interrupts()
    except Interrupted as exc:
        failure = failure if failure is not None else exc
    if failure is not None:
        log(f"apply failed: {failure!r}; rolling back")
        report["failure"] = repr(failure)
        try:
            report["rollback"] = restore_host(backup_dir, log, "apply")
        except Exception as rexc:  # noqa: BLE001
            report["result"] = "rollback_failed"
            report["rollback_failure"] = repr(rexc)
        else:
            problems, report["after_rollback"] = health_after_restore()
            if problems:
                report["after_rollback"]["problems"] = problems
            report["result"] = "rolled_back_unhealthy" if problems else "rolled_back"
        report["output_lost"] = OUTPUT["lost"]
        write_summary(summary_path, report)
        say(json.dumps(report, indent=2, sort_keys=True))
        raise Refusal(f"apply failed; result {report['result']}; summary {summary_path}")
    report["after"] = {"services": services_active(), "health": service_health()}
    report["output_lost"] = OUTPUT["lost"]
    write_summary(summary_path, report)
    say(json.dumps(report, indent=2, sort_keys=True))
    log("summary written to " + summary_path)


def cmd_rollback(args):
    # A terminal that hangs up must not break off a restore halfway.
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    result = restore_host(args.backup_dir, say, "rollback")
    problems, after = health_after_restore()
    say(json.dumps({"restored": result, "after": after}, indent=2, sort_keys=True))
    if problems:
        raise Refusal("after the rollback: " + "; ".join(problems))


def changeable_refusal(owners, what, problems):
    shown = "; ".join(problems[:20])
    more = f" (and {len(problems) - 20} more)" if len(problems) > 20 else ""
    return Refusal(f"someone other than root and uid {owners[1]} can change {what}: {shown}{more}; build takes only "
                   f"what root and uid {owners[1]} alone can change (chmod -R go-w, in folders that only they can change)")


def remove_build_folder(top):
    """Remove a private folder build made, with everything in it. Go makes
    the folders of a module cache read-only."""
    for path, dirs, _ in os.walk(top):
        for name in dirs:
            sub = os.path.join(path, name)
            if stat.S_ISDIR(os.lstat(sub).st_mode):
                os.chmod(sub, 0o700)
    shutil.rmtree(top)


def cmd_build(args):
    """Build the payload from this checkout (unprivileged).

    The build takes nothing that an account other than root and the user
    running it can change (audits 32 and 33, A32-1 and A33-1):
    the clone, .git included; the Go toolchain; the folders the payload
    goes in; and the module cache, when --module-cache names one. Go and
    git get no setting from the environment but proxy and CA variables,
    which cannot change what is compiled: a fixed PATH; GOWORK=off, since
    Go reads a go.work from any folder above the module; no go env file;
    a private HOME, so git reads no user config and Go's caches are not
    under the user's home or an inherited XDG_CACHE_HOME; Go's telemetry
    off, so Go starts no child that outlives its command; modules fetched
    only through the module proxy at proxy.golang.org, which may redirect a
    download to its own storage (GOPROXY with no "direct", and a refusal
    when the toolchain's go.env names modules to fetch from their own
    servers), and no git or other VCS tool to fetch one (GOVCS); a fresh
    build cache and temporary folder, removed afterwards, whether the build
    succeeds or not (a refusal says when the removal failed); and a fresh
    module cache unless --module-cache names a checked one, which `go mod
    verify` checks first. Go checks every module against the commit's
    go.sum, and each binary's build info is compared with the commit's
    go.mod and go.sum."""
    os.umask(0o022)
    owners = (0, os.geteuid())
    repo = os.path.realpath(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    out_dir = os.path.realpath(args.out)
    if out_dir == repo or out_dir.startswith(repo + os.sep):
        raise Refusal("the payload directory must be outside the checkout, which must stay clean")
    if not valid_commit(args.commit):
        raise Refusal("the commit must be a full lower-case 40-character SHA-1")
    if os.sep not in args.go:
        raise Refusal(f"--go names the go command by its path (such as /usr/local/go/bin/go): {args.go!r} would be "
                      f"a file in the current folder, not a command looked up on PATH")
    go = os.path.realpath(args.go)
    module_cache = os.path.realpath(args.module_cache) if args.module_cache else None
    clone_problems = folders_above_problems(repo, owners) + tree_problems(repo, owners)
    git_dir = os.path.join(repo, ".git")
    if not os.path.lexists(git_dir) or not stat.S_ISDIR(os.lstat(git_dir).st_mode):
        # Without its own .git, git and Go would take the repository of a
        # folder above the clone, with config nothing here checked.
        clone_problems.append(f"{git_dir} is not a folder")
    for what, problems in (
            ("the clone build compiles", clone_problems),
            ("the go command build runs", folders_above_problems(go, owners) + tree_problems(go, owners)),
            ("the folder the payload goes in", folders_above_problems(out_dir, owners))):
        if problems:
            raise changeable_refusal(owners, what, problems)
    if module_cache is not None:
        if module_cache == repo or module_cache.startswith(repo + os.sep):
            raise Refusal("the module cache must be outside the checkout, which must stay clean")
        problems = folders_above_problems(module_cache, owners)
        if not problems and not os.path.lexists(module_cache):
            os.mkdir(module_cache, 0o700)
        problems = problems or tree_problems(module_cache, owners)
        if problems:
            raise changeable_refusal(owners, "the module cache", problems)

    work = tempfile.mkdtemp(prefix="es-upgrade-build-", dir=os.path.dirname(out_dir))
    try:
        sums, version = build_payload(args, repo, out_dir, go, module_cache, owners, work)
    except BaseException as exc:
        try:
            remove_build_folder(work)
        except OSError as removal:
            if isinstance(exc, Refusal):
                raise Refusal(f"{exc}; and the build's private folder {work} could not be removed ({removal})") from None
        raise
    try:
        remove_build_folder(work)
    except OSError as exc:
        raise Refusal(f"the build's private folder {work} could not be removed ({exc}); no provenance was written")
    prov = {"commit": args.commit, "go_version": version, "vcs_modified": False, "sha256": sums,
            "built_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    with open(os.path.join(out_dir, "provenance.json"), "x", encoding="utf-8") as handle:
        handle.write(json.dumps(prov, indent=2, sort_keys=True) + "\n")
    say(json.dumps(prov, indent=2, sort_keys=True))


def go_config_dir(home):
    """The folder Go keeps its own settings in (os.UserConfigDir) when HOME
    is home and XDG_CONFIG_HOME is not set, as in build's environment."""
    if sys.platform == "darwin":
        return os.path.join(home, "Library", "Application Support")
    return os.path.join(home, ".config")


def build_payload(args, repo, out_dir, go, module_cache, owners, work):
    folders = {name: os.path.join(work, name) for name in ("home", "tmp", "go-build", "gopath", "go-mod")}
    for path in folders.values():
        os.mkdir(path, 0o700)
    # Go's telemetry is on (mode "local") unless the mode file in Go's
    # settings folder says "off". With it on, a go command run under a home
    # that has no upload token, as each fresh HOME here, starts a child in a
    # session of its own, which run() cannot end, and that child writes in
    # HOME after the command has exited, after build may have removed the
    # folder (audit 34, A34-1). With "off", Go writes nothing there
    # and starts no child. This file is what `go telemetry off` writes;
    # GOTELEMETRY is a value go env reports, not a setting it reads.
    telemetry = os.path.join(go_config_dir(folders["home"]), "go", "telemetry")
    os.makedirs(telemetry, 0o700)
    with open(os.path.join(telemetry, "mode"), "x", encoding="utf-8") as handle:
        handle.write("off\n")
    env = {key: os.environ[key] for key in BUILD_PASSED_VARIABLES if key in os.environ}
    env.update(GIT_ENV)
    env.update(HOME=folders["home"], TMPDIR=folders["tmp"], GOTMPDIR=folders["tmp"], GOCACHE=folders["go-build"],
               GOPATH=folders["gopath"], GOMODCACHE=module_cache or folders["go-mod"],
               GOWORK="off", GOENV="off", GOFLAGS="-mod=readonly", GOTOOLCHAIN="local",
               CGO_ENABLED="0", GOOS="linux", GOARCH="amd64",
               # Modules come only through BUILD_GOPROXY, in place of the
               # toolchain's "https://proxy.golang.org,direct"
               # (audits 35 and 36, A35-1 and A36-1).
               GOPROXY=BUILD_GOPROXY,
               # And should Go ever fetch a module directly, it runs no git
               # or other VCS tool to do it, as the operator
               # (audit 34, O34-1).
               GOVCS="*:off")
    # GONOPROXY is the one setting left that makes Go fetch a module from
    # its own server rather than through GOPROXY, "direct" or not. Go takes
    # it, or GOPRIVATE in its place, from the toolchain's go.env when the
    # environment does not set it, and an empty value in the environment
    # does not override go.env, so build asks Go what it will use. It asks
    # for JSON: plain go env prints each value as it is, and a value can
    # hold a carriage return, a vertical tab or U+2028, which a reader of
    # lines takes for a line end while Go keeps them in its pattern list
    # (audit 36, A36-2).
    answer = run([go, "env", "-json", *BUILD_GO_ENV_KEYS], env=env, check=True).stdout
    try:
        reported = json.loads(answer)
    except ValueError:
        reported = None
    if not isinstance(reported, dict) or not all(isinstance(reported.get(key), str) for key in BUILD_GO_ENV_KEYS):
        raise Refusal(f"go env -json did not report {', '.join(BUILD_GO_ENV_KEYS)}: {answer.strip()[:300]!r}")
    version, goroot, noproxy = (reported[key] for key in BUILD_GO_ENV_KEYS)
    if version != SUPPORTED_GO_VERSION:
        raise Refusal(f"the build needs {SUPPORTED_GO_VERSION}, found {version}")
    goroot = os.path.realpath(goroot)
    problems = folders_above_problems(goroot, owners) + tree_problems(goroot, owners)
    if problems:
        raise changeable_refusal(owners, f"the Go toolchain {goroot}", problems)
    # Any value is refused, even one Go would read as no pattern at all, so
    # no reading of Go's pattern list can differ from Go's.
    if noproxy:
        raise Refusal(f"the Go toolchain {goroot} sets GONOPROXY or GOPRIVATE to {noproxy!r} in its go.env, which makes "
                      f"Go fetch the modules it names from their own servers, not through {BUILD_GOPROXY}; build "
                      f"refuses any value there")
    head = run(["git", "-C", repo, "rev-parse", "HEAD"], env=env, check=True).stdout.strip()
    if head != args.commit:
        raise Refusal(f"the checkout is at {head}, not {args.commit}")
    status = run(["git", "-C", repo, "status", "--porcelain", "--ignored", "--untracked-files=all"], env=env, check=True)
    if status.stdout.strip():
        raise Refusal("the checkout has uncommitted, untracked or ignored files")
    pins = commit_module_pins(repo, args.commit, owners, env)
    if module_cache is not None:
        verified = run([go, "mod", "verify"], cwd=repo, env=env, timeout=900)
        if verified.returncode != 0:
            raise Refusal(f"go mod verify refused the module cache {module_cache}: "
                          f"{(verified.stderr or verified.stdout).strip()[:400]}")
    os.mkdir(out_dir, 0o755)
    sums = {}
    for name in PAYLOAD_FILES:
        out = os.path.join(out_dir, name)
        package = PAYLOAD_PACKAGES[name]
        # -trimpath keeps the clone's, the toolchain's and the module cache's
        # folders out of the binary, so two builds of one commit give the
        # same bytes wherever they run, and anyone can check a payload by
        # building it again.
        proc = run([go, "build", "-trimpath", "-buildvcs=true", "-o", out, "./" + package],
                   cwd=repo, env=env, timeout=900)
        if proc.returncode != 0:
            raise Refusal(f"go build ./{package} failed: {proc.stderr.strip()[:400]}")
        info = run([go, "version", "-m", out], env=env, check=True).stdout
        if f"vcs.revision={args.commit}" not in info or "vcs.modified=false" not in info:
            raise Refusal(f"{name} does not carry the commit as a clean build")
        problems = go_module_problems([line[1:] for line in info.splitlines() if line.startswith("\t")],
                                      pins, pins["module"] + "/" + package)
        if problems:
            raise Refusal(f"{name} was not built from the modules the commit pins: " + "; ".join(problems))
        blob, _ = read_regular_file(out)
        sums[name] = sha256_bytes(blob)
    return sums, version


def main(argv):
    parser = argparse.ArgumentParser(prog="remote_alpha_upgrade_es.py")
    parser.add_argument("--host-root", default="/", help=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest="command", required=True)

    mc = sub.add_parser("migrate-config")
    mc.add_argument("--input", required=True)
    mc.add_argument("--output")
    mc.add_argument("--expected-paths")
    mc.add_argument("--spki-sha256", required=True)
    mc.set_defaults(func=cmd_migrate_config)

    pk = sub.add_parser("provision-key")
    pk.add_argument("--key-file", required=True)
    pk.add_argument("--owner-uid", type=int, required=True)
    pk.add_argument("--owner-gid", type=int, required=True)
    pk.add_argument("--dry-run", action="store_true")
    pk.set_defaults(func=cmd_provision_key)

    bk = sub.add_parser("backup")
    bk.add_argument("--backup-dir", required=True)
    bk.add_argument("--path", action="append", required=True)
    bk.set_defaults(func=cmd_backup)

    rs = sub.add_parser("restore")
    rs.add_argument("--backup-dir", required=True)
    rs.set_defaults(func=cmd_restore)

    for name, func in (("check", cmd_check), ("apply", cmd_apply)):
        # Only the full names: --allow-downgrade is recorded as root typed
        # it, not as a prefix argparse would take for it (audit 44, O44-1).
        sp = sub.add_parser(name, allow_abbrev=False)
        sp.add_argument("--payload", required=True)
        sp.add_argument("--commit", required=True)
        # Every value is kept, so that one given twice is refused rather
        # than the last taken (inspect_move).
        sp.add_argument("--allow-downgrade", action="append", metavar="INSTALLED..COMMIT")
        sp.set_defaults(func=func)

    rb = sub.add_parser("rollback")
    rb.add_argument("--backup-dir", required=True)
    rb.set_defaults(func=cmd_rollback)

    bd = sub.add_parser("build")
    bd.add_argument("--out", required=True)
    bd.add_argument("--commit", required=True)
    bd.add_argument("--go", default="/usr/local/go/bin/go")
    bd.add_argument("--module-cache")
    bd.set_defaults(func=cmd_build)

    args = parser.parse_args(argv)
    global HOST_ROOT
    if args.host_root != "/" and not os.path.isabs(args.host_root):
        print("remote alpha ES upgrade refused: --host-root must be absolute", file=sys.stderr)
        return 2
    # Another spelling of "/" ("//", "/.", "/tmp/..") is the host, not a test
    # root: test mode would otherwise turn off the checkout guard and allow
    # the test overrides while every path is the host's.
    HOST_ROOT = os.path.realpath(args.host_root)
    try:
        if args.command in CHECKOUT_GUARDED:
            require_root_only_checkout()
        args.func(args)
    except Refusal as exc:
        say(f"remote alpha ES upgrade refused: {exc}", sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
