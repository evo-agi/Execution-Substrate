#!/usr/bin/env -S python3 -I
"""Remote Alpha ES upgrade: move the box's ES to a named commit and put
Nomad's API behind HTTPS.

This file is the implementation behind scripts/remote_alpha_upgrade_es.sh.
It takes the box from where the upgrade of ES PR #54 left it, ES built from
16cbf739 and Nomad enforcing ACLs on plain HTTP (the shape "locked-http"), to
the named commit with Nomad serving its API and RPC only over TLS 1.3 (the
shape "https"), part 2b of the Nomad lock. check and apply first read the
host's shape from nomad.hcl, Nomad's TLS directory, es.json and the installed
ES binaries. On "locked-http" check reports every change apply would make. On
"https" for the named commit there is nothing to do: both exit 0 and change
nothing. Any other shape is refused, naming what each part looks like. The
host steps:

  build           (unprivileged) build es, es-runtime-support and the
                  config check helper from this clean checkout, with
                  provenance
  check           (root, read-only) verify the payload and the host and
                  print every change apply would make; refuse anything
                  this upgrade was not written for
  apply           (root) check, back up, stop ES, issue Nomad's TLS
                  material, restart Nomad on HTTPS, provision its ACLs
                  again, migrate es.json, install the binaries, start ES
                  and verify; on any failure, put the backup back
  rollback        (root) put a backup back and start Nomad and ES

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


def load_backup(backup_dir):
    st = os.lstat(backup_dir)
    if not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o700 or st.st_uid != os.geteuid():
        raise Refusal("the backup directory must be a 0700 directory owned by the user running the restore")
    data, _ = read_regular_file(os.path.join(backup_dir, BACKUP_MANIFEST))
    manifest = json.loads(data)
    if manifest.get("schema") != BACKUP_SCHEMA:
        raise Refusal("the backup manifest has an unknown schema")
    for entry in manifest["files"]:
        if not entry["exists"]:
            continue
        copy, _ = read_regular_file(os.path.join(backup_dir, "files", entry["copy"]))
        if sha256_bytes(copy) != entry["sha256"] or len(copy) != entry["size"]:
            raise Refusal(f"the backup copy of {entry['path']} does not match its manifest")
    return manifest


def restore_files(backup_dir):
    """Put every backed-up file back with its bytes, owner and mode.

    The whole backup is verified before anything is written. Files that
    were absent at backup time are left as they are and reported."""
    manifest = load_backup(backup_dir)
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
NOMAD_CONFIG_MODE = 0o640  # root:root, as scripts/70_linux_setup.sh writes nomad.hcl
# Nomad runs as root, so only root may change what it reads or keeps (audit
# INF-16). ES PR #54's upgrade made these directories root:root with these
# modes. Nomad's TLS directory goes in the first, root:root 0755 as the
# setup makes it, and holds exactly the setup's three files.
NOMAD_DIRS = ((NOMAD_DIR, 0o755), ("/opt/nomad", 0o755), ("/opt/nomad/data", 0o700))
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
# The paths apply creates. Its backup names those it created, and a restore
# removes them; it removes nothing else.
CREATED_BY_APPLY = (NOMAD_TLS_DIR,)
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


def checkout_problems(scripts_dir, owner):
    """Why someone other than owner could change the code this upgrade runs
    as root, or [] when nobody else can. Every folder from / down to
    scripts_dir must belong to root or owner and be writable by neither its
    group nor others, unless it has the sticky bit (as /tmp has), which lets
    no one move or replace another's entry. Everything under scripts_dir
    must belong to owner, be a folder or a regular file, and be writable by
    neither its group nor others. No symbolic link counts: one could point
    anywhere."""
    problems = []
    real = os.path.realpath(scripts_dir)
    if real != scripts_dir:
        problems.append(f"{scripts_dir} is reached through a symbolic link ({real})")
        return problems
    path = real
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
        if st.st_uid not in (0, owner):
            problems.append(f"{path} belongs to uid {st.st_uid}")
        if mode & 0o022 and not mode & stat.S_ISVTX:
            problems.append(f"{path} is writable by its group or others ({mode:04o}) without the sticky bit")

    def entry(path):
        try:
            st = os.lstat(path)
        except OSError as exc:
            problems.append(f"{path}: {exc.strerror}")
            return
        mode = stat.S_IMODE(st.st_mode)
        if stat.S_ISLNK(st.st_mode):
            problems.append(f"{path} is a symbolic link")
            return
        if not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):
            problems.append(f"{path} is neither a folder nor a regular file")
            return
        if st.st_uid != owner:
            problems.append(f"{path} belongs to uid {st.st_uid}")
        if mode & 0o022:
            problems.append(f"{path} is writable by its group or others ({mode:04o})")

    entry(real)

    def walk_error(exc):
        problems.append(f"{exc.filename}: {exc.strerror}")

    for top, dirs, files in os.walk(real, onerror=walk_error):
        dirs.sort()
        for name in sorted(dirs) + sorted(files):
            entry(os.path.join(top, name))
    return problems


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


def run(args, env=None, timeout=120, check=False, cwd=None):
    """Run a command in a process group of its own. When it times out, or a
    signal interrupts the wait, the whole group is ended and drained before
    the exception goes on, so no descendant keeps changing the host during
    a rollback. Descendants left after a normal exit are ended too."""
    proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, env=env, cwd=cwd, start_new_session=True)
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
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


def go_build_info(blob):
    """(Go version, [build setting lines]) from a 64-bit little-endian ELF
    Go binary's .go.buildinfo section: what `go version -m` reads, read here
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
        lines = modinfo.decode("utf-8").splitlines()
        return version.decode("utf-8"), [line[len("build\t"):] for line in lines if line.startswith("build\t")]
    except UnicodeDecodeError:
        raise Refusal("the Go build info is not UTF-8") from None


def check_build_stamp(name, blob, commit):
    """Refuse a binary whose own build info does not name a clean build of
    commit with the supported Go."""
    version, lines = go_build_info(blob)
    settings = dict(line.partition("=")[::2] for line in lines)
    if version != SUPPORTED_GO_VERSION or settings.get("vcs.revision") != commit or settings.get("vcs.modified") != "false":
        raise Refusal(f"the payload file {name} is not, by its own Go build info, a clean {SUPPORTED_GO_VERSION} build of "
                      f"{commit}: Go {version!r}, vcs.revision {settings.get('vcs.revision')!r}, "
                      f"vcs.modified {settings.get('vcs.modified')!r}")


def owned_by_root(st):
    uid, gid = root_ids()
    return st.st_uid == uid and st.st_gid == gid


def load_payload(payload_dir, commit):
    """Verify a build's payload and copy nothing. Returns the provenance.

    The directory and its files must be root:root and not writable by group
    or others, so no other account can change them after the check. Every
    file's SHA-256 must match provenance.json, which must name the commit,
    and each installed binary must name it in its own Go build info."""
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
    for name in PAYLOAD_FILES:
        blob, fst = read_regular_file(os.path.join(payload_dir, name))
        if fst.st_mode & 0o022 or not owned_by_root(fst):
            raise Refusal(f"the payload file {name} must be root:root and not writable by group or others")
        if sha256_bytes(blob) != prov.get("sha256", {}).get(name):
            raise Refusal(f"the payload file {name} does not match its provenance")
        if name in STAMPED_PAYLOAD_FILES:
            check_build_stamp(name, blob, commit)
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


def owner_mode(st):
    return {"uid": st.st_uid, "gid": st.st_gid, "mode": format(stat.S_IMODE(st.st_mode), "04o")}


def setup_tls_functions():
    """The nomad_tls functions of scripts/70_linux_setup.sh, which issue and
    check Nomad's TLS material on every supported host."""
    data, _ = read_regular_file(SETUP_SCRIPT)
    text = data.decode("utf-8")
    begin = text.find("\n# BEGIN nomad_tls")
    end = text.find("\n# END nomad_tls\n", begin + 1)
    if begin < 0 or end < 0:
        raise Refusal("scripts/70_linux_setup.sh has no nomad_tls functions")
    return text[begin + 1:end + 1]


def nomad_tls(function, *args):
    """Run one of the setup's nomad_tls functions as the user running this
    script: root on the host, so the material is root's."""
    script = "set -euo pipefail\n" + setup_tls_functions() + '"$@"\n'
    return run(["bash", "-c", script, "nomad-tls", function, *args], timeout=120)


def server_spki_sha256():
    """The pin: the SHA-256 of the public key in Nomad's server certificate."""
    proc = nomad_tls("nomad_tls_spki_sha256", host(NOMAD_CERT_FILE))
    pin = proc.stdout.strip()
    if proc.returncode != 0 or not valid_spki(pin):
        raise Refusal(f"cannot read the public key of {NOMAD_CERT_FILE}: {proc.stderr.strip()[:200]}")
    return pin


# The host's shape. Each part of the host this upgrade changes is read on its
# own and reports (shape, state): shape is "locked-http" (where ES PR #54's
# upgrade left it), "https" (where this upgrade leaves it) or None, and state
# says what was found. The host has a shape only when every part agrees.

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
    revisions = {}
    for name, path in (("es", ES_BINARY), ("es-runtime-support", RUNTIME_SUPPORT)):
        try:
            blob, _ = read_regular_file(host(path))
            _, lines = go_build_info(blob)
        except (Refusal, OSError) as exc:
            return None, f"unknown ({name}: {exc})"
        settings = dict(line.partition("=")[::2] for line in lines)
        revision = settings.get("vcs.revision")
        if settings.get("vcs.modified") != "false":
            return None, f"unknown ({name} is a build of a modified checkout of {revision})"
        if revision == commit and (prov is None or sha256_bytes(blob) != prov["sha256"].get(name)):
            return None, f"unknown ({name} names {commit} but is not the verified payload's build)"
        revisions[name] = revision
    found = set(revisions.values())
    if found == {BOX_ES_COMMIT}:
        return "locked-http", f"locked-http (builds of {BOX_ES_COMMIT})"
    if found == {commit}:
        return "https", f"https (the payload's builds of {commit})"
    return None, "unknown (" + ", ".join(f"{name} built from {rev}" for name, rev in revisions.items()) + ")"


SHAPE_PARTS = ("nomad.hcl", "Nomad's TLS directory", "es.json", "the ES binaries")


def host_shape(commit, prov):
    """(shape or None, {part: state}, pin or None). Reads only."""
    def guarded(read):
        try:
            return read()
        except (Refusal, OSError, ValueError, UnicodeDecodeError) as exc:
            return None, f"unreadable ({exc})"

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
    found["the ES binaries"] = guarded(lambda: binaries_shape(commit, prov))
    shapes = {shape for shape, _ in found.values()}
    shape = shapes.pop() if len(shapes) == 1 else None
    return shape, {part: found[part][1] for part in SHAPE_PARTS}, pin


def describe_parts(parts):
    return "; ".join(f"{part}: {state}" for part, state in parts.items())


def inspect_host(payload_dir, commit):
    """Everything check reports. Reads only; returns (report, blockers)."""
    blockers = []
    report = {"schema": SUMMARY_SCHEMA, "commit": commit, "host_root": HOST_ROOT}

    def block(scope, message):
        blockers.append({"scope": scope, "summary": message})

    if HOST_ROOT == "/" and not as_root():
        block("privilege", "run as root (sudo -n)")
    if commit == BOX_ES_COMMIT:
        block("commit", f"{BOX_ES_COMMIT} is the build ES PR #54's upgrade installed; name the commit to move to")

    try:
        prov = load_payload(payload_dir, commit)
        report["payload"] = {"commit": prov["commit"], "go_version": prov["go_version"], "sha256": prov["sha256"]}
    except (Refusal, OSError, ValueError) as exc:
        prov = None
        block("payload", str(exc))

    shape, parts, pin = host_shape(commit, prov)
    report["shape"] = shape or "unknown"
    report["parts"] = parts
    if shape is None:
        block("shape", "the host is in no shape this upgrade knows; it takes locked-http to https: " + describe_parts(parts))

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
            block("nomad_hcl", "nomad.hcl is not root:root 0640")
        others = other_nomad_configs()
        if others:
            block("nomad_hcl", f"Nomad would also load {others} from {NOMAD_DIR}")
    except (Refusal, OSError) as exc:
        block("nomad_hcl", str(exc))
    for path, mode in NOMAD_DIRS:
        try:
            st = os.lstat(host(path))
            if not stat.S_ISDIR(st.st_mode) or not owned_by_root(st) or stat.S_IMODE(st.st_mode) != mode:
                block("nomad_dirs", f"{path} is not a root:root {mode:04o} directory")
        except OSError as exc:
            block("nomad_dirs", str(exc))

    if shape == "locked-http":
        inspect_start(report, block, payload_dir, prov)
    elif shape == "https":
        inspect_migrated(report, block)
    report["blockers"] = blockers
    return report, blockers


def acl_files():
    """(file, owner uid, mode) of each token file nomad_acl_setup.sh made.
    The management token is root's; under a test host root it is the test
    user's, or root's when the real script runs through sudo."""
    management_uid = 0 if not test_mode() or acl_setup_sudo() else os.getuid()
    return (("management-token", management_uid, 0o600), ("es-token", user_ids(ES_USER)[0], 0o400),
            ("observer-token", user_ids(OBSERVER_USER)[0], 0o400))


def inspect_start(report, block, payload_dir, prov):
    """The checks of a locked-http host, which apply will change."""
    try:
        data, _ = read_regular_file(host(ES_CONFIG))
        migrated, changes = migrate_config(json.loads(data), PLACEHOLDER_PIN, START_ES_PATHS)
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
        block("tools", "openssl is not installed; the setup's nomad_tls functions need it")
    try:
        setup_tls_functions()
    except (Refusal, OSError, UnicodeDecodeError) as exc:
        block("tools", str(exc))

    if not nomad_leader_named(nomad_http_addr()):
        block("nomad", f"Nomad has no named leader at {nomad_http_addr()}")
    proc = run(["docker", "ps", "--quiet", "--no-trunc", "--filter", f"label={NOMAD_ALLOC_LABEL}"], timeout=30)
    if proc.returncode != 0:
        block("nomad", f"cannot list the containers of Nomad's allocations: {proc.stderr.strip()[:200]}")
    else:
        running = proc.stdout.split()
        report["nomad_allocation_containers"] = len(running)
        if running:
            block("nomad", f"{len(running)} container(s) of Nomad allocations are running; wait until they finish")

    report["changes"] = [
        f"issue Nomad's TLS material into {NOMAD_TLS_DIR} with the setup's nomad_tls_issue",
        "append the supported config's tls block to nomad.hcl and restart Nomad on HTTPS",
        "provision Nomad's ACLs again (the observer policy gains list-jobs) and check placement",
        "es.json: " + ", ".join(report.get("es_config", {}).get("changes", [])),
        f"install es and es-runtime-support built from {report['commit']}",
    ]


def inspect_migrated(report, block):
    """The read-only proof that an https host runs as this upgrade leaves it."""
    report["changes"] = []
    if not nomad_leader_named(nomad_https_addr()):
        block("nomad", f"Nomad has no named leader at {nomad_https_addr()}")
    ok, out = tls_identity_check()
    report["nomad_tls_identity"] = out
    if not ok:
        block("nomad", f"ES's Nomad TLS settings do not hold against the running Nomad: {out}")
    for problem in anonymous_nomad_problems():
        block("nomad", problem)


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


def backup_host(backup_dir):
    """Back up every file apply changes, and name every path it creates."""
    manifest = backup_files(backup_dir, [host(p) for p in (ES_CONFIG, ES_BINARY, RUNTIME_SUPPORT, NOMAD_HCL)])
    for path in CREATED_BY_APPLY:
        if os.path.lexists(host(path)):
            raise Refusal(f"{path} exists already")
    write_new_file(os.path.join(backup_dir, CREATED_MANIFEST), json.dumps(list(CREATED_BY_APPLY), indent=2) + "\n")
    return manifest


def load_created(backup_dir):
    data, _ = read_regular_file(os.path.join(backup_dir, CREATED_MANIFEST))
    created = json.loads(data)
    if not isinstance(created, list) or not set(created) <= set(CREATED_BY_APPLY):
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


def apply_nomad_tls(log):
    """Issue Nomad's TLS material, restart Nomad on HTTPS, provision its ACLs
    again and prove that it places ES's jobs. Returns the server key's pin."""
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
    # Every check above passes on a Nomad that can place nothing: prove that
    # the restarted node has a host-mode network and that ES's job shapes plan.
    acl_setup("placement", ES_CONFIG=host(ES_CONFIG), NOMAD_STARTED_AT=str(started_at),
              NOMAD_PLACEMENT_WAIT_SECONDS=str(PLACEMENT_WAIT_SECONDS))
    log("nomad can place ES's jobs (nomad_acl_setup.sh placement)")
    return pin


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
    atomic_replace(host(ES_CONFIG), render_json(migrated).encode(), ruid, group_id(ES_USER), ES_CONFIG_MODE)
    log("es.json migrated")
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


def live_nomad_addr():
    """Nomad's address under the nomad.hcl on disk."""
    try:
        text, _ = read_regular_file(host(NOMAD_HCL))
    except (Refusal, OSError):
        return nomad_http_addr()
    return nomad_https_addr() if text.endswith(NOMAD_TLS_BLOCK.encode()) else nomad_http_addr()


def restore_host(backup_dir, log):
    """Put back every file the backup holds and remove every path apply
    created, then start Nomad and ES. Nomad's ACL policies stay as provision
    last wrote them: the observer policy keeps list-jobs, a read."""
    # The whole backup is verified before a service is touched.
    load_backup(backup_dir)
    created = load_created(backup_dir)
    # Nothing is put back under a running service: if either will not stop,
    # the restore stops here and reports it.
    stop_service("es")
    stop_service("nomad")
    log("es and nomad stopped for the restore")
    result = restore_files(backup_dir)
    result["removed"] = remove_created(created)
    log(f"files restored from {backup_dir}; removed {result['removed']}")
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
    try:
        ok = wait_for(lambda: healthy(service_health()), ES_WAIT_SECONDS)
        return bool(ok), {"services": services_active(), "health": service_health()}
    except Exception as exc:  # noqa: BLE001 - reported, never raised
        return False, {"error": str(exc)}


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
    report, blockers = inspect_host(args.payload, args.commit)
    report["mode"] = "check"
    if not blockers:
        report["result"] = "nothing to do" if report["shape"] == "https" else "ready"
    say(json.dumps(report, indent=2, sort_keys=True))
    if blockers:
        raise Refusal(f"{len(blockers)} blocker(s); nothing was changed")


def cmd_apply(args):
    events = []

    def log(message):
        events.append({"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": message})
        say(message)

    report, blockers = inspect_host(args.payload, args.commit)
    report["mode"] = "apply"
    report["events"] = events
    if blockers:
        say(json.dumps(report, indent=2, sort_keys=True))
        raise Refusal(f"{len(blockers)} blocker(s); nothing was changed")
    if report["shape"] == "https":
        # Already applied for this commit, and verified in place: no backup,
        # and no service is touched.
        report["result"] = "nothing to do"
        say(json.dumps(report, indent=2, sort_keys=True))
        return
    prov = load_payload(args.payload, args.commit)
    backup_dir = os.path.join(backup_root_ready(),
                              time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + args.commit[:12])
    backup_host(backup_dir)
    report["backup_dir"] = backup_dir
    summary_path = os.path.join(backup_dir, "summary.json")
    log("backup written to " + backup_dir)
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
            pin = apply_nomad_tls(log)
            migrated, _ = migrate_config(config, pin, START_ES_PATHS)
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
            report["rollback"] = restore_host(backup_dir, log)
        except Exception as rexc:  # noqa: BLE001
            report["result"] = "rollback_failed"
            report["rollback_failure"] = repr(rexc)
        else:
            ok, report["after_rollback"] = health_after_restore()
            report["result"] = "rolled_back" if ok else "rolled_back_unhealthy"
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
    result = restore_host(args.backup_dir, say)
    ok, after = health_after_restore()
    say(json.dumps({"restored": result, "after": after}, indent=2, sort_keys=True))
    if not ok:
        raise Refusal("ES and AGS do not all answer 200 after the rollback")


def cmd_build(args):
    """Build the payload from this checkout (unprivileged)."""
    repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    out_dir = os.path.abspath(args.out)
    if out_dir == repo or out_dir.startswith(repo + os.sep):
        raise Refusal("the payload directory must be outside the checkout, which must stay clean")
    if not valid_commit(args.commit):
        raise Refusal("the commit must be a full lower-case 40-character SHA-1")
    go = args.go
    env = dict(os.environ, GOTOOLCHAIN="local", CGO_ENABLED="0", GOOS="linux", GOARCH="amd64", GOFLAGS="-mod=readonly")
    version = run([go, "env", "GOVERSION"], env=env, check=True).stdout.strip()
    if version != SUPPORTED_GO_VERSION:
        raise Refusal(f"the build needs {SUPPORTED_GO_VERSION}, found {version}")
    head = run(["git", "-C", repo, "rev-parse", "HEAD"], check=True).stdout.strip()
    if head != args.commit:
        raise Refusal(f"the checkout is at {head}, not {args.commit}")
    if run(["git", "-C", repo, "status", "--porcelain"], check=True).stdout.strip():
        raise Refusal("the checkout has uncommitted or untracked files")
    os.mkdir(out_dir, 0o755)
    sums = {}
    for name, pkg in (("es", "./cmd/es"), ("es-runtime-support", "./cmd/es-runtime-support"),
                      ("esconfigcheck", "./scripts/internal/esconfigcheck")):
        out = os.path.join(out_dir, name)
        proc = run([go, "build", "-buildvcs=true", "-o", out, pkg], cwd=repo, env=env, timeout=900)
        if proc.returncode != 0:
            raise Refusal(f"go build {pkg} failed: {proc.stderr.strip()[:400]}")
        info = run([go, "version", "-m", out], env=env, check=True).stdout
        if f"vcs.revision={args.commit}" not in info or "vcs.modified=false" not in info:
            raise Refusal(f"{name} does not carry the commit as a clean build")
        blob, _ = read_regular_file(out)
        sums[name] = sha256_bytes(blob)
    prov = {"commit": args.commit, "go_version": version, "vcs_modified": False, "sha256": sums,
            "built_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    with open(os.path.join(out_dir, "provenance.json"), "x", encoding="utf-8") as handle:
        handle.write(json.dumps(prov, indent=2, sort_keys=True) + "\n")
    say(json.dumps(prov, indent=2, sort_keys=True))


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
        sp = sub.add_parser(name)
        sp.add_argument("--payload", required=True)
        sp.add_argument("--commit", required=True)
        sp.set_defaults(func=func)

    rb = sub.add_parser("rollback")
    rb.add_argument("--backup-dir", required=True)
    rb.set_defaults(func=cmd_rollback)

    bd = sub.add_parser("build")
    bd.add_argument("--out", required=True)
    bd.add_argument("--commit", required=True)
    bd.add_argument("--go", default="/usr/local/go/bin/go")
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
