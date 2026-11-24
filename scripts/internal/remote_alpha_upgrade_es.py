#!/usr/bin/env -S python3 -I
"""Remote Alpha ES upgrade: move the box's ES to a named commit and lock Nomad.

This file is the implementation behind scripts/remote_alpha_upgrade_es.sh.
The host steps, for the one host shape the preflight read:

  build           (unprivileged) build es, es-runtime-support and the
                  config check helper from this clean checkout, with
                  provenance
  check           (root, read-only) verify the payload and the host and
                  print every change apply would make; refuse anything
                  this upgrade was not written for
  apply           (root) check, back up, stop ES, lock Nomad, provision
                  the retained-result key, migrate es.json, install the
                  binaries, start ES and verify; on any failure, put the
                  backup back
  rollback        (root) put a backup back and start Nomad and ES

and the host-independent pieces they are built on:

  migrate-config  add the keys current ES requires to an older es.json
  provision-key   create the retained-result key file, or accept an
                  existing one that already meets ES's rules
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


BACKUP_MANIFEST = "manifest.json"
BACKUP_SCHEMA = "execution-substrate.remote-alpha.es-upgrade-backup.v1"


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




# ---------------------------------------------------------------------------
# The Remote Alpha host. Every path and value below comes from the read-only
# preflight of 2026-11-24 (project files es-box-upgrade/01-preflight/), and
# check refuses a host that differs from them.
# ---------------------------------------------------------------------------

ES_CONFIG = "/etc/execution-substrate/es.json"
ES_CONFIG_MODE = 0o640  # root:es
AGS_CONFIG = "/etc/execution-substrate/ags.json"
ES_BINARY = "/usr/local/lib/execution-substrate/bin/es"
RUNTIME_SUPPORT = "/usr/local/bin/es-runtime-support"
BINARY_MODE = 0o755  # root:root
ES_UNIT = "/etc/systemd/system/es.service"
ES_UNIT_DROPIN = "/etc/systemd/system/es.service.d/10-account.conf"
ES_EXEC_START = f"argv[]={ES_BINARY} -config {ES_CONFIG} ;"
HEALTHCHECK_ENV = "/etc/execution-substrate/healthcheck.env"
NOMAD_DIR = "/etc/nomad.d"
NOMAD_HCL = "/etc/nomad.d/nomad.hcl"
NOMAD_ENV = "/etc/nomad.d/nomad.env"
NOMAD_CONFIG_MODE = 0o640  # root:root, as scripts/70_linux_setup.sh writes nomad.hcl
NOMAD_DATA_PARENT = "/opt/nomad"
NOMAD_DATA_DIR = "/opt/nomad/data"
# Nomad runs as root, so only root may change what it reads or keeps (audit
# INF-16): its config directory, its data directory and that directory's
# parent become root:root with these modes, and every entry in the data
# directory becomes root:root.
LOCKED_DIRS = ((NOMAD_DIR, 0o755), (NOMAD_DATA_PARENT, 0o755), (NOMAD_DATA_DIR, 0o700))
NOMAD_ACL_DIR = "/etc/execution-substrate/nomad-acl"
ES_TOKEN_FILE = NOMAD_ACL_DIR + "/es-token"
NOMAD_ADDR = "http://127.0.0.1:4646"
# The healthcheck runbook runs its checks with sudo, so the read-only
# observer token goes to root. Pass the same OBSERVER_USER to any later
# `nomad_acl_setup.sh check` or `rotate` on this host.
OBSERVER_USER = "root"
KEY_FILE = "/etc/execution-substrate/retained-result-auth/es.key"
STORE_ID = "remote-alpha"
KEY_ID = "k1"
BACKUP_ROOT = "/var/backups/execution-substrate-es-upgrade"
ES_USER = "es"
SERVICES = ("ars", "ags", "egs", "es", "vault", "spire-server", "spire-agent", "nomad", "docker")
PAYLOAD_FILES = ("es", "es-runtime-support", "esconfigcheck")
SUPPORTED_GO_VERSION = "go1.26.5"
SUMMARY_SCHEMA = "execution-substrate.remote-alpha.es-upgrade-summary.v1"
LEADER_WAIT_SECONDS = 90
ES_WAIT_SECONDS = 60

# The key paths of the box's es.json (preflight, ES build 74748063). The
# config migration refuses any other set.
EXPECTED_ES_PATHS = (
    "authorization.allowed_spiffe_path_prefixes[]",
    *[f"dependencies.{dep}.{field}" for dep in ("artifact_registry", "execution_governance")
      for field in ("base_url", "client_cert_file", "client_key_file", "root_ca_file", "server_name", "timeout_seconds")],
    "execution.base_image",
    "execution.results_root_dir",
    *[f"execution.runtime_profiles.control_plane_normal_shell.{field}"
      for field in ("codex_cli_path", "credential_vault_secret_field", "credential_vault_secret_path", "enabled", "image")],
    "execution.runtime_support_binary",
    "execution.spire_workload_api_socket_path",
    "execution.staging_root_dir",
    *[f"http.{field}" for field in ("bind_address", "port", "read_timeout_seconds", "shutdown_timeout_seconds", "write_timeout_seconds")],
    "nomad.base_url",
    "nomad.datacenter",
    "nomad.timeout_seconds",
    "runtime_config.workload_zone_vault_config_ref.digest",
    "security.bootstrap_issuer_common_name",
    "tls.cert_file",
    "tls.client_ca_file",
    "tls.key_file",
    *[f"verification.{part}.{field}" for part in ("derivation_attestation", "provenance", "trust_model", "workload_identity_binding")
      for field in ("algorithm", "key_id", "public_key_hex")],
    "workload_vault_auth.default_mode",
)

# SHA-256 of the box's nomad.hcl as the preflight read it (529 bytes, Remote
# Alpha 0.7's one-host config). The lock edits only this exact file.
NOMAD_HCL_BOX_SHA256 = "5d5e106c1eb0ec8ba74efed66272051bba0a61adac4fead2e6021b6f9b7d96b8"

# The box's nomad.hcl carries the Docker driver's legacy client options.
# The lock replaces them with the driver allowlist and adds the acl block
# and the Docker plugin block of the supported config
# (scripts/70_linux_setup.sh; a test keeps these pieces equal to it).
NOMAD_LEGACY_OPTIONS = """  options = {
    "docker.cleanup.image" = "false"
    "docker.volumes.enabled" = "true"
  }
"""
NOMAD_LOCKED_OPTIONS = """  options = {
    "driver.allowlist" = "docker"
  }
"""
NOMAD_ACL_BLOCK = """acl {
  enabled = true
}
"""
NOMAD_PLUGIN_BLOCK = """# ES runs every task through its runtime helper on the Docker driver, so only
# that driver is enabled and the Docker plugin is limited (audit INF-02): no
# privileged containers, and only the capabilities the helper uses to prepare
# a run and drop to the workload user. ES's bind mounts need volumes enabled.
# Runtime profile images must survive image garbage collection.
plugin "docker" {
  config {
    allow_privileged = false
    allow_caps       = ["chown", "dac_override", "fowner", "kill", "setgid", "setuid", "setpcap"]

    volumes {
      enabled = true
    }

    gc {
      image = false
    }
  }
}
"""
NOMAD_LOCK_BLOCKS = "\n" + NOMAD_ACL_BLOCK + "\n" + NOMAD_PLUGIN_BLOCK

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


def run(args, env=None, timeout=120, check=False):
    proc = subprocess.run(args, capture_output=True, text=True, env=env, timeout=timeout)
    if check and proc.returncode != 0:
        raise Refusal(f"{' '.join(args[:3])} failed: {(proc.stderr or proc.stdout).strip()[:400]}")
    return proc


def write_new_file(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())


def lock_nomad_hcl(text):
    """(new_text, state) for nomad.hcl: state is "apply" or "applied"."""
    if text.count(NOMAD_LOCKED_OPTIONS) == 1 and text.endswith(NOMAD_LOCK_BLOCKS) and NOMAD_LEGACY_OPTIONS not in text:
        return text, "applied"
    if text.count(NOMAD_LEGACY_OPTIONS) != 1:
        raise Refusal("nomad.hcl does not hold the Docker client options this upgrade was written for")
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(("acl", "plugin", "tls", "vault", "consul")) and not stripped.startswith("#"):
            raise Refusal(f"nomad.hcl already has a block this upgrade would add or does not know: {stripped[:40]!r}")
    if not text.endswith("\n"):
        raise Refusal("nomad.hcl does not end with a newline")
    return text.replace(NOMAD_LEGACY_OPTIONS, NOMAD_LOCKED_OPTIONS) + NOMAD_LOCK_BLOCKS, "apply"


def plan_nomad_hcl(text):
    """lock_nomad_hcl for the box's own nomad.hcl, or its locked form, only."""
    new_text, state = lock_nomad_hcl(text)
    original = text
    if state == "applied":
        original = text[: -len(NOMAD_LOCK_BLOCKS)].replace(NOMAD_LOCKED_OPTIONS, NOMAD_LEGACY_OPTIONS)
    if sha256_bytes(original.encode()) != NOMAD_HCL_BOX_SHA256:
        raise Refusal("nomad.hcl is not the file the preflight read")
    return new_text, state


def other_nomad_configs():
    """Files besides nomad.hcl that `nomad agent -config /etc/nomad.d` loads."""
    return sorted(name for name in os.listdir(host(NOMAD_DIR))
                  if name != "nomad.hcl" and name.endswith((".hcl", ".json")))


def dir_record(path):
    st = os.lstat(host(path))
    if not stat.S_ISDIR(st.st_mode):
        raise Refusal(f"{path} is not a directory")
    return {"path": path, "uid": st.st_uid, "gid": st.st_gid, "mode": format(stat.S_IMODE(st.st_mode), "04o")}


def raise_error(exc):
    raise exc


def foreign_owned_entries(top):
    """[relative path, uid, gid] of every entry below top that is not
    root:root. Symbolic links are listed, never followed."""
    ruid, rgid = root_ids()
    found = []
    for dirpath, dirnames, filenames in os.walk(top, followlinks=False, onerror=raise_error):
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            st = os.lstat(path)
            if (st.st_uid, st.st_gid) != (ruid, rgid):
                found.append([os.path.relpath(path, top), st.st_uid, st.st_gid])
    return sorted(found)


def curl_status(url, extra=(), timeout=10):
    proc = run(["curl", "--noproxy", "*", "-sS", "-m", str(timeout), "-o", "/dev/null", "-w", "%{http_code}", *extra, url],
               timeout=timeout + 5)
    return proc.stdout.strip() if proc.returncode == 0 else f"error: {(proc.stderr or '').strip()[:200]}"


def curl_json(url, timeout=10):
    proc = run(["curl", "--noproxy", "*", "-sS", "-m", str(timeout), "-w", "\n%{http_code}", url], timeout=timeout + 5)
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


def wait_for(predicate, seconds, step=2):
    deadline = time.monotonic() + seconds
    while True:
        result = predicate()
        if result or time.monotonic() >= deadline:
            return result
        time.sleep(step)


def nomad_leader_named():
    doc, code = curl_json(NOMAD_ADDR + "/v1/status/leader", timeout=5)
    return code == "200" and isinstance(doc, str) and doc != ""


def valid_commit(commit):
    return isinstance(commit, str) and len(commit) == 40 and set(commit) <= set("0123456789abcdef")


def load_payload(payload_dir, commit):
    """Verify a build's payload against its provenance and copy nothing.

    Returns the provenance. The directory must not be writable by others;
    every file's SHA-256 must match, and the commit must be the one named."""
    if not valid_commit(commit):
        raise Refusal("the commit must be a full lower-case 40-character SHA-1")
    st = os.lstat(payload_dir)
    if not stat.S_ISDIR(st.st_mode) or st.st_mode & 0o022:
        raise Refusal("the payload directory must be a directory that group and others cannot write")
    data, _ = read_regular_file(os.path.join(payload_dir, "provenance.json"))
    prov = json.loads(data)
    if prov.get("commit") != commit:
        raise Refusal(f"the payload was built from {prov.get('commit')!r}, not the named commit {commit!r}")
    if prov.get("go_version") != SUPPORTED_GO_VERSION or prov.get("vcs_modified") is not False:
        raise Refusal("the payload was not built with the supported Go toolchain from a clean checkout")
    for name in PAYLOAD_FILES:
        blob, fst = read_regular_file(os.path.join(payload_dir, name))
        if fst.st_mode & 0o022 or sha256_bytes(blob) != prov.get("sha256", {}).get(name):
            raise Refusal(f"the payload file {name} does not match its provenance")
    return prov


def stage_payload(payload_dir, prov, stage_dir):
    """Copy the verified payload into a root-only directory and re-verify."""
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


def inspect_host(payload_dir, commit):
    """Everything check reports. Reads only; returns (report, blockers)."""
    blockers = []
    report = {"schema": SUMMARY_SCHEMA, "commit": commit, "host_root": HOST_ROOT}

    def block(scope, message):
        blockers.append({"scope": scope, "summary": message})

    if HOST_ROOT == "/" and not as_root():
        block("privilege", "run as root (sudo -n)")

    try:
        prov = load_payload(payload_dir, commit)
        report["payload"] = {"commit": prov["commit"], "go_version": prov["go_version"], "sha256": prov["sha256"]}
    except (Refusal, OSError, ValueError) as exc:
        prov = None
        block("payload", str(exc))

    active = services_active()
    report["services"] = active
    if len(active) != len(SERVICES) or any(state != "active" for state in active.values()):
        block("services", "not every service is active")
    for problem in es_unit_problems():
        block("es_unit", problem)

    try:
        data, st = read_regular_file(host(ES_CONFIG))
        config = json.loads(data)
        report["es_config"] = {"sha256": sha256_bytes(data), "uid": st.st_uid, "gid": st.st_gid,
                               "mode": format(stat.S_IMODE(st.st_mode), "04o")}
        if (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) != (root_ids()[0], group_id(ES_USER), ES_CONFIG_MODE):
            block("es_config", "es.json is not root:es 0640")
        migrated, changes = migrate_config(config, ES_TOKEN_FILE, retained_result_auth(), EXPECTED_ES_PATHS)
        report["es_config"]["changes"] = changes
        if not changes:
            block("es_config", "es.json is already migrated: this upgrade has already been applied")
        if prov is not None:
            ok, out = esconfigcheck(os.path.join(payload_dir, "esconfigcheck"), migrated)
            report["es_config"]["new_es_accepts_migrated_config"] = ok
            if not ok:
                block("es_config", f"the new ES refuses the migrated config: {out[:300]}")
    except (Refusal, OSError, ValueError) as exc:
        block("es_config", str(exc))

    try:
        report["health"] = service_health()
        if not healthy(report["health"]):
            block("health", "ES and AGS do not all answer 200 (healthcheck runbook step 4)")
    except (Refusal, OSError, ValueError) as exc:
        block("health", str(exc))

    state = None
    try:
        text, st = read_regular_file(host(NOMAD_HCL))
        _, state = plan_nomad_hcl(text.decode())
        report["nomad_hcl"] = {"sha256": sha256_bytes(text), "lock": state, "uid": st.st_uid, "gid": st.st_gid,
                               "mode": format(stat.S_IMODE(st.st_mode), "04o")}
        if state == "applied":
            block("nomad_hcl", "Nomad is already locked: this upgrade has already been applied")
        others = other_nomad_configs()
        if others:
            block("nomad_hcl", f"Nomad would also load {others} from {NOMAD_DIR}")
        read_regular_file(host(NOMAD_ENV))
    except (Refusal, OSError, UnicodeDecodeError) as exc:
        block("nomad_hcl", str(exc))

    try:
        report["nomad_dirs"] = [dir_record(path) for path, _ in LOCKED_DIRS]
        foreign = foreign_owned_entries(host(NOMAD_DATA_DIR))
        report["nomad_data_foreign_owned"] = {"count": len(foreign), "first": foreign[:10]}
    except (Refusal, OSError) as exc:
        block("nomad_dirs", str(exc))

    if not nomad_leader_named():
        block("nomad", "Nomad has no named leader")
    jobs, code = curl_json(NOMAD_ADDR + "/v1/jobs?namespace=*", timeout=10)
    if code != "200" or not isinstance(jobs, list):
        block("nomad", f"cannot list Nomad's jobs anonymously (HTTP {code})")
    else:
        busy = [job.get("ID") for job in jobs if job.get("Status") in ("pending", "running")]
        report["nomad_jobs"] = {"total": len(jobs), "pending_or_running": busy}
        if busy:
            block("nomad", f"Nomad jobs are pending or running: {busy[:10]}")

    try:
        uid, gid = user_ids(ES_USER)
        report["retained_result_key"] = provision_key(host(KEY_FILE), uid, gid, dry_run=True)
    except (Refusal, OSError) as exc:
        block("retained_result_key", str(exc))
    report["nomad_acl_dir_exists"] = os.path.lexists(host(NOMAD_ACL_DIR))

    report["blockers"] = blockers
    return report, blockers


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


def backup_host(backup_dir):
    """Back up every file the upgrade changes, and the owner and mode of
    every directory it changes."""
    paths = [host(p) for p in (ES_CONFIG, ES_UNIT, ES_UNIT_DROPIN, ES_BINARY, RUNTIME_SUPPORT, NOMAD_HCL, NOMAD_ENV)]
    manifest = backup_files(backup_dir, paths)
    write_new_file(os.path.join(backup_dir, "directories.json"),
                   json.dumps([dir_record(path) for path, _ in LOCKED_DIRS], indent=2) + "\n")
    return manifest


def acl_setup(action):
    """Run scripts/nomad_acl_setup.sh from this checkout."""
    script = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "nomad_acl_setup.sh")
    override = os.environ.get("ES_UPGRADE_TEST_ACL_SETUP") if HOST_ROOT != "/" else None
    env = dict(os.environ, NOMAD_ACL_DIR=host(NOMAD_ACL_DIR), ES_USER=ES_USER, OBSERVER_USER=OBSERVER_USER,
               NOMAD_USER="root", NOMAD_ADDR=NOMAD_ADDR)
    return run([override or "bash", *([] if override else [script]), action], env=env, timeout=300, check=True)


def apply_nomad_lock(backup_dir, log):
    text, _ = read_regular_file(host(NOMAD_HCL))
    new_text, state = plan_nomad_hcl(text.decode())
    if state != "apply":
        raise Refusal("Nomad is already locked")
    tmpdir = tempfile.mkdtemp(prefix="es-upgrade-nomad-")
    try:
        with open(os.path.join(tmpdir, "nomad.hcl"), "w", encoding="utf-8") as handle:
            handle.write(new_text)
        run(["nomad", "config", "validate", tmpdir], timeout=60, check=True)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    log("locked nomad.hcl validated")
    run(["systemctl", "stop", "nomad"], timeout=120, check=True)
    log("nomad stopped")
    ruid, rgid = root_ids()
    data_dir = host(NOMAD_DATA_DIR)
    ledger = foreign_owned_entries(data_dir)
    write_new_file(os.path.join(backup_dir, "ownership.json"),
                   json.dumps({"root": NOMAD_DATA_DIR, "entries": ledger}, indent=2) + "\n")
    for rel, _, _ in ledger:
        os.lchown(os.path.join(data_dir, rel), ruid, rgid)
    atomic_replace(host(NOMAD_HCL), new_text.encode(), ruid, rgid, NOMAD_CONFIG_MODE)
    env_data, _ = read_regular_file(host(NOMAD_ENV))
    atomic_replace(host(NOMAD_ENV), env_data, ruid, rgid, NOMAD_CONFIG_MODE)
    for path, mode in LOCKED_DIRS:
        os.chown(host(path), ruid, rgid, follow_symlinks=False)
        os.chmod(host(path), mode)
    log(f"nomad config and data root-owned ({len(ledger)} data entries changed owner); nomad.hcl locked")
    run(["systemctl", "start", "nomad"], timeout=120, check=True)
    if not wait_for(nomad_leader_named, LEADER_WAIT_SECONDS):
        raise Refusal(f"Nomad named no leader within {LEADER_WAIT_SECONDS} s of its start")
    log("nomad started with a named leader")
    acl_setup("provision")
    log("nomad ACLs provisioned (nomad_acl_setup.sh provision, which ends with its check)")


def install_es(stage_dir, migrated, log):
    uid, gid = user_ids(ES_USER)
    log(f"retained-result key: {provision_key(host(KEY_FILE), uid, gid)}")
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


def verify_after(log):
    if not wait_for(lambda: services_active().get("es") == "active" and healthy(service_health()), ES_WAIT_SECONDS):
        raise Refusal(f"ES did not come back healthy: {services_active().get('es')}, {service_health()}")
    log("ES and AGS answer 200")
    code = curl_status(NOMAD_ADDR + "/v1/jobs", timeout=5)
    if code != "403":
        raise Refusal(f"Nomad answers an anonymous job list with HTTP {code}, not 403")
    acl_setup("check")
    log("Nomad refuses anonymous requests; nomad_acl_setup.sh check passed")


def restore_host(backup_dir, log):
    """Put back every file and owner the backup holds, then start Nomad and ES."""
    run(["systemctl", "stop", "es"], timeout=120)
    run(["systemctl", "stop", "nomad"], timeout=120)
    log("es and nomad stopped for the restore")
    result = restore_files(backup_dir)
    ownership = os.path.join(backup_dir, "ownership.json")
    if os.path.lexists(ownership):
        data, _ = read_regular_file(ownership)
        doc = json.loads(data)
        data_dir = host(doc["root"])
        for rel, uid, gid in doc["entries"]:
            try:
                os.lchown(os.path.join(data_dir, rel), uid, gid)
            except FileNotFoundError:
                pass
        result["nomad_data_owners_restored"] = len(doc["entries"])
    data, _ = read_regular_file(os.path.join(backup_dir, "directories.json"))
    for record in json.loads(data):
        os.chown(host(record["path"]), record["uid"], record["gid"], follow_symlinks=False)
        os.chmod(host(record["path"]), int(record["mode"], 8))
    log("files, owners and modes restored from " + backup_dir)
    run(["systemctl", "start", "nomad"], timeout=120, check=True)
    result["nomad_leader"] = bool(wait_for(nomad_leader_named, LEADER_WAIT_SECONDS))
    run(["systemctl", "start", "es"], timeout=120, check=True)
    log("nomad and es started")
    return result


def health_after_restore():
    try:
        ok = wait_for(lambda: healthy(service_health()), ES_WAIT_SECONDS)
        return bool(ok), {"services": services_active(), "health": service_health()}
    except Exception as exc:  # noqa: BLE001 - reported, never raised
        return False, {"error": str(exc)}


class Interrupted(Exception):
    """SIGTERM or SIGHUP arrived during apply."""


def raise_interrupted(signum, _frame):
    raise Interrupted(f"signal {signum}")


def cmd_check(args):
    report, blockers = inspect_host(args.payload, args.commit)
    report["mode"] = "check"
    print(json.dumps(report, indent=2, sort_keys=True))
    if blockers:
        raise Refusal(f"{len(blockers)} blocker(s); nothing was changed")


def cmd_apply(args):
    events = []

    def log(message):
        events.append({"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": message})
        print(message, flush=True)

    report, blockers = inspect_host(args.payload, args.commit)
    report["mode"] = "apply"
    report["events"] = events
    if blockers:
        print(json.dumps(report, indent=2, sort_keys=True))
        raise Refusal(f"{len(blockers)} blocker(s); nothing was changed")
    prov = load_payload(args.payload, args.commit)
    backup_dir = os.path.join(backup_root_ready(),
                              time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + args.commit[:12])
    backup_host(backup_dir)
    report["backup_dir"] = backup_dir
    summary_path = os.path.join(backup_dir, "summary.json")
    log("backup written to " + backup_dir)
    stage_dir = stage_payload(args.payload, prov, os.path.join(backup_dir, "payload"))
    data, _ = read_regular_file(host(ES_CONFIG))
    migrated, _ = migrate_config(json.loads(data), ES_TOKEN_FILE, retained_result_auth(), EXPECTED_ES_PATHS)

    # From here on, any failure or interruption puts the backup back.
    for signum in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, raise_interrupted)
    try:
        run(["systemctl", "stop", "es"], timeout=120, check=True)
        log("es stopped")
        apply_nomad_lock(backup_dir, log)
        install_es(stage_dir, migrated, log)
        run(["systemctl", "start", "es"], timeout=120, check=True)
        log("es started")
        verify_after(log)
        report["result"] = "applied"
    except BaseException as exc:  # noqa: BLE001 - every failure after the backup rolls back
        for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            signal.signal(signum, signal.SIG_IGN)
        log(f"apply failed: {exc!r}; rolling back")
        report["failure"] = repr(exc)
        try:
            report["rollback"] = restore_host(backup_dir, log)
        except Exception as rexc:  # noqa: BLE001
            report["result"] = "rollback_failed"
            report["rollback_failure"] = repr(rexc)
        else:
            ok, report["after_rollback"] = health_after_restore()
            report["result"] = "rolled_back" if ok else "rolled_back_unhealthy"
        write_summary(summary_path, report)
        print(json.dumps(report, indent=2, sort_keys=True))
        raise Refusal(f"apply failed; result {report['result']}; summary {summary_path}")
    report["after"] = {"services": services_active(), "health": service_health()}
    write_summary(summary_path, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    log("summary written to " + summary_path)


def cmd_rollback(args):
    result = restore_host(args.backup_dir, lambda message: print(message, flush=True))
    ok, after = health_after_restore()
    print(json.dumps({"restored": result, "after": after}, indent=2, sort_keys=True))
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
        proc = subprocess.run([go, "build", "-buildvcs=true", "-o", out, pkg], cwd=repo, env=env,
                              capture_output=True, text=True, timeout=900)
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
    print(json.dumps(prov, indent=2, sort_keys=True))


def main(argv):
    parser = argparse.ArgumentParser(prog="remote_alpha_upgrade_es.py")
    parser.add_argument("--host-root", default="/", help=argparse.SUPPRESS)
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
    HOST_ROOT = args.host_root
    try:
        args.func(args)
    except Refusal as exc:
        print(f"remote alpha ES upgrade refused: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
