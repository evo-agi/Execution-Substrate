#!/usr/bin/env -S python3 -I
"""Remote Alpha signing key rotation: give the box's AGS and EGS new keys.

This file is the implementation behind scripts/remote_alpha_rotate_signing_keys.sh.
AGS seals artifact evidence with its signer key and EGS signs the runtime
trust policy with its own; ES verifies both with the public keys in its
verification group (.docs/system_overview/configuration.md, "Signing keys").
This rotation replaces both keys on one host, in ags.json, egs.json and
es.json together, and retires ARS's index, whose every record is sealed with
a key the rotation retires:

  check     (root, read-only) read the configs, ARS's index, the units and
            the backups; check that the configs agree with each other, that
            each unit starts with its config, that ARS, EGS, AGS and ES run
            and answer, and that no earlier rotation was left half done; and
            print every change apply would make
  apply     (root) check; make a new AGS key and a new EGS key on this host;
            back the three configs up; write AGS's and EGS's new signers,
            EGS's allow list (the new AGS key ID instead of the old one, the
            old one revoked, the publication revision one higher), ES's four
            verification keys and every workload grant's signer key ID; stop
            ES, AGS and ARS; move ARS's index into the backup and give ARS an
            empty one; start ARS, restart EGS, start AGS and ES, and check
            that all four run and answer; on any failure or interrupting
            signal, put the backup back and start them again
  rollback  (root) put a backup back and start the services again, or
            remove the folder an apply stopped before it changed anything;
            it records its start (rollback-started.json) before it changes
            anything and its end, with the same ID, in rollback.json, and it
            refuses a backup whose files a rollback already put back

The keys come from the host's own /usr/bin/openssl, so nothing built from a
checkout runs as root to make them. Each is written as the signer object
scripts/internal/signingkeygen writes, with the same key ID: the role, a
hyphen, and the first 16 hex digits of the SHA-256 of the public key. A
private key reaches openssl and this process only through pipes, and only
the new configs and the root-only backup ever hold one; no output names one.

ES starts listening only after it has fetched EGS's trust policy and
verified it with verification.trust_model (es/app/app.go, Start), so ES
answering after the restart shows that the new EGS key and ES agree. ES
refuses evidence sealed with the old AGS key from then on. Those artifacts
are published again from their sources through AGS when they are still
needed, never re-signed: ARS keeps one record per artifact digest
(.docs/system_overview/contracts.md, section 6), and the index this rotation
moves into the backup is what lets ARS take the new record.

Everything refuses what it does not recognise rather than guess.
"""

import argparse
import errno
import grp
import hashlib
import json
import os
import pwd
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time

SCHEMA = "execution-substrate.remote-alpha.signing-key-rotation.v1"
BACKUP_SCHEMA = "execution-substrate.remote-alpha.signing-key-rotation-backup.v1"
BACKUP_ROOT = "/var/backups/execution-substrate-signing-keys"
BACKUP_MANIFEST = "manifest.json"
INDEX_MANIFEST = "ars-index.manifest.json"
INDEX_COPY = "ars-index.json"
SUMMARY = "summary.json"
ROLLBACK_RECORD = "rollback.json"
ROLLBACK_STARTED = "rollback-started.json"
# An apply builds its backup under this prefix and renames it to its final
# name once every copy and the manifest are on disk. No config is written
# before that rename, so a folder still named this way holds nothing that
# was applied.
INCOMPLETE_PREFIX = ".incomplete-"
# Every temporary file this rotation writes next to a file it replaces is
# named ".<name><TEMP_MARK><random>".
TEMP_MARK = ".signing-key-rotation."

CONFIG_DIR = "/etc/execution-substrate"
# Each config the rotation writes, with the group its service reads it as.
# The Remote Alpha services keep them root:<service> 0640.
CONFIGS = (
    ("egs", CONFIG_DIR + "/egs.json", "egs"),
    ("ags", CONFIG_DIR + "/ags.json", "ags"),
    ("es", CONFIG_DIR + "/es.json", "es"),
)
# ARS's config, read for its index and its address, never written.
ARS_CONFIG = CONFIG_DIR + "/ars.json"
CONFIG_MODE = 0o640
CONFIG_MAX_BYTES = 1 << 20
INDEX_MAX_BYTES = 64 << 20
EMPTY_INDEX = b"{}\n"
HEALTHCHECK_ENV = CONFIG_DIR + "/healthcheck.env"
UNITS = ("ars", "egs", "ags", "es")
BINARY_DIR = "/usr/local/lib/execution-substrate/bin"
HEALTH_WAIT_SECONDS = 60
LISTEN_WAIT_SECONDS = 60
OPENSSL = "/usr/bin/openssl"
SYSTEMCTL = "/usr/bin/systemctl"
CURL = "/usr/bin/curl"
CHILD_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}

# The DER encodings openssl gives an Ed25519 key (RFC 8410): a PKCS #8
# private key whose last 32 bytes are the seed, and a SubjectPublicKeyInfo
# whose last 32 bytes are the public key.
ED25519_PRIVATE_DER_PREFIX = bytes.fromhex("302e020100300506032b657004220420")
ED25519_PUBLIC_DER_PREFIX = bytes.fromhex("302a300506032b6570032100")
HEX = set("0123456789abcdef")

# The JSON field names of the objects the rotation reads and writes. A test
# compares each list with the Go type the services decode into
# (agsconfig.SignerConfig, egsconfig.SignerConfig, esconfig.VerificationConfig,
# esconfig.SignerVerifierConfig, egscontract.SignerPolicy), so a field added
# there fails the test until the rotation knows it.
SIGNER_FIELDS = ("algorithm", "key_id", "private_key_hex", "public_key_hex")
VERIFIER_FIELDS = ("algorithm", "key_id", "public_key_hex")
SIGNER_POLICY_FIELDS = ("allowed_signers", "revoked_signers")
VERIFICATION_FROM = (
    ("trust_model", "egs"),
    ("provenance", "ags"),
    ("derivation_attestation", "ags"),
    ("workload_identity_binding", "ags"),
)


class Refusal(Exception):
    """Nothing was changed."""


class Failed(Exception):
    """Something was changed; the message says what state it left."""


class Interrupted(Exception):
    pass


# The host root and test hooks.

HOST_ROOT = "/"


def set_host_root(value):
    """A --host-root whose real path is / is the host itself, whatever its
    spelling (//, /., /etc/..), so it never turns the test hooks on."""
    global HOST_ROOT
    HOST_ROOT = "/" if os.path.realpath(value) == "/" else value


def host(path):
    """A host path, under --host-root when the tests set one."""
    if HOST_ROOT == "/":
        return path
    return os.path.join(HOST_ROOT, path.lstrip("/"))


def test_mode():
    """Under a test --host-root, the user running the tests stands in for
    root and for every service account unless a test names other IDs."""
    return HOST_ROOT != "/"


def test_env(name):
    if not test_mode():
        return None
    return os.environ.get("SIGNING_KEY_ROTATION_TEST_" + name) or None


def root_uid():
    if test_mode():
        value = test_env("ROOT_UID")
        return int(value) if value else os.getuid()
    return 0


def root_gid():
    if test_mode():
        value = test_env("ROOT_GID")
        return int(value) if value else os.getgid()
    return 0


def group_id(name):
    if test_mode():
        value = test_env("GID_" + name.upper())
        return int(value) if value else os.getgid()
    try:
        return grp.getgrnam(name).gr_gid
    except KeyError:
        raise Refusal(f"group {name} does not exist")


def user_id(name):
    if test_mode():
        value = test_env("UID_" + name.upper())
        return int(value) if value else os.getuid()
    try:
        return pwd.getpwnam(name).pw_uid
    except KeyError:
        raise Refusal(f"user {name} does not exist")


def program(name, default):
    return test_env(name) or default


def wait_seconds(seconds):
    value = test_env("WAIT_SECONDS")
    return int(value) if value else seconds


def test_point(name):
    """Under a test host root, end the process at a named point
    (SIGNING_KEY_ROTATION_TEST_KILL_AT), fail there as a full disk would
    (SIGNING_KEY_ROTATION_TEST_FAIL_AT), or wait there while the file
    SIGNING_KEY_ROTATION_TEST_PAUSE_MARKER, which it makes, exists
    (SIGNING_KEY_ROTATION_TEST_PAUSE_AT), so a test can change the host as
    someone else would while the rotation runs. Outside the tests it does
    nothing."""
    if test_env("KILL_AT") == name:
        os.kill(os.getpid(), signal.SIGKILL)
    if test_env("FAIL_AT") == name:
        raise OSError(errno.ENOSPC, "No space left on device")
    if test_env("PAUSE_AT") == name:
        marker = test_env("PAUSE_MARKER")
        os.close(os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600))
        deadline = time.monotonic() + 120
        while os.path.lexists(marker):
            if time.monotonic() > deadline:
                raise OSError(errno.ETIMEDOUT, f"the test did not remove {marker}")
            time.sleep(0.02)


def temp_suffix():
    return test_env("TEMP_SUFFIX") or secrets.token_hex(8)


# Signals. While apply or rollback runs, SIGTERM, SIGHUP, SIGINT and SIGQUIT
# are only recorded. apply turns the first one into a rollback at the next
# step; a rollback never stops for one.

INTERRUPT_SIGNALS = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT, signal.SIGQUIT)
SIGNALS = {"received": [], "armed": False}


def record_signal(signum, _frame):
    SIGNALS["received"].append(signal.Signals(signum).name)


def catch_signals():
    for signum in INTERRUPT_SIGNALS:
        signal.signal(signum, record_signal)


def check_stop():
    if SIGNALS["armed"] and SIGNALS["received"]:
        raise Interrupted(f"{SIGNALS['received'][0]} received")


# Strict JSON. The services read their configs with Go's encoding/json, which
# matches a field name in any letter case and lets a later key win; Python's
# json matches names exactly. A config that both read differently is refused.

def strict_object(pairs):
    seen = {}
    out = {}
    for key, value in pairs:
        if not key.isascii():
            raise ValueError(f"the key {key!r} is not ASCII")
        folded = key.lower()
        if folded in seen:
            if seen[folded] == key:
                raise ValueError(f"the key {key!r} appears twice")
            raise ValueError(f"the keys {seen[folded]!r} and {key!r} differ only in letter case, which the services read as one")
        seen[folded] = key
        out[key] = value
    return out


def refuse_constant(name):
    raise ValueError(f"{name} is not JSON")


def finite_number(text):
    value = float(text)
    if value in (float("inf"), float("-inf")):
        raise ValueError(f"the number {text[:40]} is too large for the services to read")
    return value


def has_lone_surrogate(doc):
    """Whether a string in doc holds a UTF-16 surrogate that pairs with
    nothing, from an escape such as \\ud800. Go's encoding/json reads one as
    U+FFFD, Python keeps it and cannot write it back as UTF-8. Keys are
    ASCII already (strict_object)."""
    stack = [doc]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, str):
            try:
                item.encode("utf-8")
            except UnicodeEncodeError:
                return True
    return False


def parse_strict(data, what):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Refusal(f"{what} is not UTF-8") from None
    try:
        doc = json.loads(text, object_pairs_hook=strict_object, parse_constant=refuse_constant,
                         parse_float=finite_number)
    except RecursionError:
        raise Refusal(f"{what} is nested too deeply") from None
    except ValueError as exc:
        raise Refusal(f"{what} is not JSON that every service reads the same way: {exc}") from None
    if not isinstance(doc, dict):
        raise Refusal(f"{what} is not a JSON object")
    if has_lone_surrogate(doc):
        raise Refusal(f"{what} is not JSON that every service reads the same way: a string holds a \\u escape "
                      "of half a UTF-16 surrogate pair, which the services read as U+FFFD")
    return doc


# Files.

def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def mode_text(st):
    return format(stat.S_IMODE(st.st_mode), "04o")


def read_open_file(fd, path, limit):
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        raise Refusal(f"{path} is not a regular file")
    if st.st_size > limit:
        raise Refusal(f"{path} is larger than {limit} bytes")
    chunks, total = [], 0
    while True:
        chunk = os.read(fd, 1 << 20)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise Refusal(f"{path} is larger than {limit} bytes")
        chunks.append(chunk)
    return b"".join(chunks), st


def read_regular_file(path, limit=CONFIG_MAX_BYTES, dir_fd=None, shown=None):
    """(data, stat) of a regular file, opened without following a link."""
    shown = shown or path
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise Refusal(f"{shown} is a symbolic link") from None
        raise Refusal(f"cannot open {shown}: {exc.strerror}") from None
    try:
        return read_open_file(fd, shown, limit)
    finally:
        os.close(fd)


def write_all(fd, data):
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


def sync_dir(path=None, dir_fd=None):
    fd = dir_fd if dir_fd is not None else os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        if dir_fd is None:
            os.close(fd)


def write_new_file(path, data):
    """A new 0600 file, refusing anything already at path."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        write_all(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def replace_file(dir_fd, name, data, uid, gid, mode, point=None):
    """Replace name in the folder dir_fd with data, owner and mode in one
    rename. The new file is created next to the old one under a name of its
    own, synced, and renamed over it; nothing at either name is followed,
    and the new file is removed on any failure before the rename."""
    tmp = f".{name}{TEMP_MARK}{temp_suffix()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dir_fd)
    renamed = False
    try:
        try:
            write_all(fd, data)
            if os.geteuid() == 0:
                os.fchown(fd, uid, gid)
            os.fchmod(fd, mode)
            os.fsync(fd)
        finally:
            os.close(fd)
        if point:
            test_point(point)
        os.rename(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        renamed = True
        os.fsync(dir_fd)
    finally:
        if not renamed:
            try:
                os.unlink(tmp, dir_fd=dir_fd)
            except OSError:
                pass


def open_dir(path):
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)


def replace_config(path, data, uid, gid, mode, point=None):
    parent, name = os.path.split(host(path))
    dir_fd = open_dir(parent)
    try:
        replace_file(dir_fd, name, data, uid, gid, mode, point)
    finally:
        os.close(dir_fd)


def write_record(folder, name, doc):
    """A 0600 JSON record in a backup folder, written in one rename."""
    test_point("write-" + name)
    data = (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode()
    dir_fd = open_dir(folder)
    try:
        replace_file(dir_fd, name, data, os.geteuid(), os.getegid(), 0o600)
    finally:
        os.close(dir_fd)


def render_json(doc):
    return (json.dumps(doc, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def folder_chain_problems(path):
    """Why someone other than root could replace a folder from the host
    root down to path, or anything in it: each must be a folder, not a
    link, that root owns and that neither its group nor others can write."""
    problems = []
    parts = [p for p in path.strip("/").split("/") if p]
    for i in range(len(parts) + 1):
        shown = "/" + "/".join(parts[:i])
        try:
            st = os.lstat(host(shown))
        except OSError as exc:
            problems.append(f"{shown}: {exc.strerror}")
            break
        if not stat.S_ISDIR(st.st_mode):
            problems.append(f"{shown} is not a folder")
            break
        if st.st_uid != root_uid():
            problems.append(f"the folder {shown} does not belong to root")
        if stat.S_IMODE(st.st_mode) & 0o022:
            problems.append(f"the folder {shown} is writable by its group or others ({mode_text(st)})")
    return problems


def leftover_temp_files(dir_fd, folder):
    """The temporary files a stopped rotation left in a folder."""
    try:
        names = os.listdir(dir_fd)
    except OSError:
        return []
    return [os.path.join(folder, name) for name in sorted(names) if name.startswith(".") and TEMP_MARK in name]


def remove_temp_files(dir_fd, names):
    removed = []
    for path in names:
        name = os.path.basename(path)
        if not (name.startswith(".") and TEMP_MARK in name):
            continue
        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        if stat.S_ISDIR(st.st_mode):
            raise Failed(f"{path} is a folder, not a file a rotation left")
        os.unlink(name, dir_fd=dir_fd)
        removed.append(path)
    if removed:
        os.fsync(dir_fd)
    return removed


# Commands.

def kill_group(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        pass
    try:
        proc.communicate(timeout=5)
    except Exception:  # noqa: BLE001 - reaping only
        pass


def run(args, data=None, timeout=60):
    """Run a command with bytes in and out and a fixed environment, in a
    process group of its own, and kill the whole group if it outlives the
    timeout."""
    try:
        proc = subprocess.Popen(args, stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=dict(CHILD_ENV),
                                start_new_session=True, close_fds=True)
    except OSError as exc:
        raise Refusal(f"cannot run {args[0]}: {exc.strerror}") from None
    try:
        out, err = proc.communicate(data, timeout=timeout)
    except subprocess.TimeoutExpired:
        kill_group(proc)
        raise Refusal(f"{' '.join(os.path.basename(a) if i == 0 else a for i, a in enumerate(args[:3]))} "
                      f"did not finish within {timeout} s") from None
    except BaseException:
        kill_group(proc)
        raise
    return subprocess.CompletedProcess(args, proc.returncode, out, err)


def systemctl(*args, check=True):
    proc = run([program("SYSTEMCTL", SYSTEMCTL), *args], timeout=120)
    if check and proc.returncode != 0:
        raise Refusal(f"systemctl {' '.join(args)} failed: {proc.stderr.decode(errors='replace').strip()[:300]}")
    return proc.stdout.decode(errors="replace")


def units_active():
    out = systemctl("is-active", *UNITS, check=False).split()
    return dict(zip(UNITS, out + ["unknown"] * (len(UNITS) - len(out))))


def exec_start_problems(unit):
    """Why unit does not start its binary with the config this rotation
    writes or reads: exactly one ExecStart, whose program (systemd's path=,
    what it runs) is the binary and whose argv is the binary and -config
    <path> (or --config, or either with =). systemctl show prints each
    command as { path=<program> ; argv[]=<words> ; ... }; with systemd's @
    prefix argv[0] is only the name the program is given, so argv alone does
    not say what runs."""
    binary = f"{BINARY_DIR}/{unit}"
    config = f"{CONFIG_DIR}/{unit}.json"
    out = systemctl("show", f"{unit}.service", "-p", "ExecStart")
    lines = [line[len("ExecStart="):] for line in out.splitlines() if line.startswith("ExecStart=")]
    commands = [line for line in lines if line.strip()]
    if len(commands) != 1:
        return [f"{unit}.service has {len(commands)} ExecStart commands, not one"]
    text = commands[0]
    path, argv = "?", []
    if text.startswith("{ path="):
        path_end = text.find(" ; ")
        if path_end > 0:
            path = text[len("{ path="):path_end]
            rest = text[path_end + len(" ; "):]
            if rest.startswith("argv[]="):
                argv_end = rest.find(" ;")
                if argv_end > 0:
                    argv = rest[len("argv[]="):argv_end].split()
    allowed = [[binary, flag, config] for flag in ("-config", "--config")] + \
        [[binary, f"{flag}={config}"] for flag in ("-config", "--config")]
    if path != binary or argv not in allowed:
        return [f"{unit}.service does not start {binary} with -config {config} (its ExecStart runs {path} "
                f"as {' '.join(argv) or '?'})"]
    return []


def healthcheck_env():
    data, _ = read_regular_file(host(HEALTHCHECK_ENV), shown=HEALTHCHECK_ENV)
    env = {}
    for line in data.decode(errors="replace").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, _, value = line.partition("=")
            env[key.strip()] = value.strip().strip("\"'")
    for key in ("CA_CERT", "OPERATOR_CERT", "OPERATOR_KEY"):
        if not env.get(key):
            raise Refusal(f"healthcheck.env has no {key}")
    return env


def http_address(name, doc):
    http = doc.get("http") if isinstance(doc.get("http"), dict) else {}
    address, port = http.get("bind_address"), http.get("port")
    if not isinstance(address, str) or not address or ":" in address or not isinstance(port, int) \
            or isinstance(port, bool) or not 0 < port < 65536:
        raise Refusal(f"{name}.json has no IPv4 http.bind_address and http.port")
    return address, port


def health_urls(docs):
    """ES's health and contract endpoints and AGS's health endpoint, at the
    addresses their configs name (the healthcheck runbook's step 4)."""
    urls = []
    for name, suffixes in (("es", ("/health", "/v1/executions:contract")), ("ags", ("/health",))):
        address, port = http_address(name, docs[name])
        urls += [f"https://{address}:{port}{suffix}" for suffix in suffixes]
    return urls


def health(docs):
    env = healthcheck_env()
    result = {}
    for url in health_urls(docs):
        # -q first: root's ~/.curlrc is not read.
        proc = run([program("CURL", CURL), "-q", "--noproxy", "*", "--proto", "=https", "-sS", "-m", "10",
                    "-o", "/dev/null", "-w", "%{http_code}", "--cacert", env["CA_CERT"], "--cert", env["OPERATOR_CERT"],
                    "--key", env["OPERATOR_KEY"], url], timeout=15)
        out = proc.stdout.decode(errors="replace").strip()
        result[url] = out if proc.returncode == 0 else "error: " + proc.stderr.decode(errors="replace").strip()[:200]
    return result


def listening(address, port):
    try:
        with socket.create_connection((address, port), timeout=2):
            return True
    except OSError:
        return False


def all_up(docs):
    """Whether ARS, EGS, AGS and ES are active, ARS and EGS accept
    connections, and ES and AGS answer 200."""
    active = units_active()
    accepting = {name: listening(*http_address(name, docs[name])) for name in ("ars", "egs")}
    answers = health(docs)
    ok = all(state == "active" for state in active.values()) and all(accepting.values()) \
        and all(code == "200" for code in answers.values())
    return ok, {"units": active, "accepting_connections": accepting, "health": answers}


def wait_until_up(docs):
    deadline = time.monotonic() + wait_seconds(HEALTH_WAIT_SECONDS)
    while True:
        check_stop()
        ok, seen = all_up(docs)
        if ok or time.monotonic() >= deadline:
            return ok, seen
        time.sleep(1)


def wait_listening(name, docs):
    address, port = http_address(name, docs[name])
    seconds = wait_seconds(LISTEN_WAIT_SECONDS)
    deadline = time.monotonic() + seconds
    while not listening(address, port):
        check_stop()
        if time.monotonic() >= deadline:
            raise Refusal(f"{name.upper()} does not accept connections on {address}:{port} within {seconds} s")
        time.sleep(0.2)


# Keys.

def openssl_der(args, data=None):
    proc = run([program("OPENSSL", OPENSSL), *args], data=data, timeout=30)
    if proc.returncode != 0:
        raise Refusal(f"openssl {args[0]} failed: {proc.stderr.decode(errors='replace').strip()[:200]}")
    return proc.stdout


def key_id(role, public):
    return f"{role}-{sha256_hex(public)[:16]}"


def new_signer(role):
    """A new Ed25519 key for role from the host's openssl, as the signer
    object AGS and EGS take."""
    private_der = openssl_der(["genpkey", "-algorithm", "ED25519", "-outform", "DER"])
    if len(private_der) != 48 or not private_der.startswith(ED25519_PRIVATE_DER_PREFIX):
        raise Refusal("openssl genpkey did not give an Ed25519 PKCS #8 private key")
    public_der = openssl_der(["pkey", "-inform", "DER", "-pubout", "-outform", "DER"], private_der)
    if len(public_der) != 44 or not public_der.startswith(ED25519_PUBLIC_DER_PREFIX):
        raise Refusal("openssl pkey did not give an Ed25519 public key")
    seed, public = private_der[16:], public_der[12:]
    # A known key's seed is one byte repeated; AGS, EGS and ES refuse one
    # (.docs/system_overview/contracts.md, section 3B).
    if len(set(seed)) == 1:
        raise Refusal("openssl gave a known key: its seed is one byte repeated")
    return {"algorithm": "ed25519", "key_id": key_id(role, public), "private_key_hex": seed.hex(),
            "public_key_hex": public.hex()}


def public_part(signer):
    return {"algorithm": signer["algorithm"], "key_id": signer["key_id"], "public_key_hex": signer["public_key_hex"]}


# The configs.

def is_hex(value, length):
    return isinstance(value, str) and len(value) == length and set(value) <= HEX


def signer_problems(name, signer):
    if not isinstance(signer, dict):
        return [f"{name}.json has no signer object"]
    if sorted(signer) != sorted(SIGNER_FIELDS):
        return [f"{name}.json signer has the fields {sorted(signer)}, not exactly {list(SIGNER_FIELDS)}"]
    problems = []
    if signer["algorithm"] != "ed25519":
        problems.append(f"{name}.json signer.algorithm is not ed25519")
    if not isinstance(signer["key_id"], str) or not signer["key_id"]:
        problems.append(f"{name}.json has no signer.key_id")
    if not (is_hex(signer["private_key_hex"], 64) or is_hex(signer["private_key_hex"], 128)):
        problems.append(f"{name}.json signer.private_key_hex is not a 32- or 64-byte key in lower-case hex")
    if not is_hex(signer["public_key_hex"], 64):
        problems.append(f"{name}.json signer.public_key_hex is not a 32-byte key in lower-case hex")
    return problems


def seed_is_one_byte(signer):
    seed = bytes.fromhex(signer["private_key_hex"][:64])
    return len(set(seed)) == 1


def grant_rules(es_doc):
    """The workload grant rules of es.json, or [] when it has none."""
    policy = es_doc.get("admission_policy")
    if policy is None:
        return []
    if not isinstance(policy, dict):
        raise Refusal("es.json admission_policy is not an object")
    grants = policy.get("workload_grants")
    if grants is None:
        return []
    rules = grants.get("rules") if isinstance(grants, dict) else None
    if not isinstance(rules, list) or not all(isinstance(rule, dict) for rule in rules):
        raise Refusal("es.json admission_policy.workload_grants.rules is not a list of rules")
    return rules


def consistency_problems(docs):
    """Whether the three configs agree: ES trusts exactly the EGS key and
    the AGS key in exactly its four verification entries, EGS allows the AGS
    key, and every grant names it."""
    problems = signer_problems("ags", docs["ags"].get("signer")) + signer_problems("egs", docs["egs"].get("signer"))
    if problems:
        return problems
    signers = {"ags": docs["ags"]["signer"], "egs": docs["egs"]["signer"]}
    if signers["ags"]["public_key_hex"] == signers["egs"]["public_key_hex"]:
        problems.append("AGS and EGS sign with the same key")
    verification = docs["es"].get("verification")
    if not isinstance(verification, dict):
        return problems + ["es.json has no verification object"]
    entries = [entry for entry, _ in VERIFICATION_FROM]
    if sorted(verification) != sorted(entries):
        problems.append(f"es.json verification has the entries {sorted(verification)}, not exactly {entries}")
    for entry, role in VERIFICATION_FROM:
        if verification.get(entry) != public_part(signers[role]):
            problems.append(f"es.json verification.{entry} is not {role.upper()}'s signer key")
    runtime_trust = docs["egs"].get("runtime_trust")
    policy = runtime_trust.get("signer_policy") if isinstance(runtime_trust, dict) else None
    if not isinstance(policy, dict):
        problems.append("egs.json has no runtime_trust.signer_policy")
    else:
        if not set(policy) <= set(SIGNER_POLICY_FIELDS):
            problems.append(f"egs.json runtime_trust.signer_policy has fields other than {list(SIGNER_POLICY_FIELDS)}")
        allowed, revoked = policy.get("allowed_signers"), policy.get("revoked_signers", [])
        if not isinstance(allowed, list) or not all(isinstance(s, str) for s in allowed):
            problems.append("egs.json runtime_trust.signer_policy.allowed_signers is not a list of key IDs")
        elif signers["ags"]["key_id"] not in allowed:
            problems.append("egs.json does not allow AGS's signer key ID")
        if not isinstance(revoked, list) or not all(isinstance(s, str) for s in revoked):
            problems.append("egs.json runtime_trust.signer_policy.revoked_signers is not a list of key IDs")
    publication = docs["egs"].get("publication")
    if not isinstance(publication, dict) or not isinstance(publication.get("update_revision"), int) \
            or isinstance(publication.get("update_revision"), bool) or publication["update_revision"] < 1:
        problems.append("egs.json has no positive publication.update_revision")
    try:
        rules = grant_rules(docs["es"])
    except Refusal as exc:
        return problems + [str(exc)]
    for rule in rules:
        if rule.get("signer_key_id") != signers["ags"]["key_id"]:
            problems.append(f"es.json workload grant {rule.get('id')!r} names a signer other than AGS's key")
    return problems


def planned_changes(docs, index):
    """What apply changes on a host that inspect accepts."""
    old_ags_id = docs["ags"]["signer"]["key_id"]
    revision = docs["egs"]["publication"]["update_revision"]
    changes = [
        "ags.json signer: a new AGS key",
        "egs.json signer: a new EGS key",
        f"egs.json runtime_trust.signer_policy.allowed_signers: the new AGS key ID instead of {old_ags_id}",
        f"egs.json runtime_trust.signer_policy.revoked_signers: add {old_ags_id}",
        f"egs.json publication.update_revision: {revision} to {revision + 1}",
        *[f"es.json verification.{entry}: the new {role.upper()} public key" for entry, role in VERIFICATION_FROM],
    ]
    rules = grant_rules(docs["es"])
    if rules:
        changes.append(f"es.json admission_policy.workload_grants: the new AGS key ID in {len(rules)} rule(s)")
    count = "its records" if index.get("entries") is None else f"its {index['entries']} record(s)"
    changes.append(f"ARS index {index['path']}: {count}, each sealed with a key this rotation retires, move into the "
                   "backup, and ARS starts again on an empty index")
    return changes


def rotate(docs, ags_new, egs_new):
    """The three configs with the new keys, from configs that
    consistency_problems accepts."""
    old_ags_id = docs["ags"]["signer"]["key_id"]
    ags = json.loads(json.dumps(docs["ags"]))
    egs = json.loads(json.dumps(docs["egs"]))
    es = json.loads(json.dumps(docs["es"]))
    ags["signer"] = dict(ags_new)
    egs["signer"] = dict(egs_new)
    policy = egs["runtime_trust"]["signer_policy"]
    policy["allowed_signers"] = [ags_new["key_id"] if s == old_ags_id else s for s in policy["allowed_signers"]]
    revoked = list(policy.get("revoked_signers", []))
    if old_ags_id not in revoked:
        revoked.append(old_ags_id)
    policy["revoked_signers"] = revoked
    egs["publication"]["update_revision"] += 1
    news = {"ags": ags_new, "egs": egs_new}
    for entry, role in VERIFICATION_FROM:
        es["verification"][entry] = public_part(news[role])
    for rule in grant_rules(es):
        rule["signer_key_id"] = ags_new["key_id"]
    return {"ags": ags, "egs": egs, "es": es}


# ARS's index. ARS's account owns the folder that holds it, so every step
# opens one folder at a time from the host root without following a link and
# works inside that folder.

def index_path(ars_doc):
    storage = ars_doc.get("storage")
    path = storage.get("index_file") if isinstance(storage, dict) else None
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//") \
            or os.path.normpath(path) != path or path == "/":
        raise Refusal("ars.json storage.index_file is not an absolute path in normal form")
    return path


def open_index_folder(path):
    """(fd of the folder that holds the index, problems): every folder above
    it belongs to root and is writable by neither its group nor others, and
    the folder itself belongs to root or ARS's account, with the same rule."""
    parts = path.strip("/").split("/")[:-1]
    problems = []
    fd = os.open(HOST_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    shown = ""
    try:
        for i, part in enumerate(parts):
            shown += "/" + part
            try:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            except OSError as exc:
                reason = "is a symbolic link or not a folder" if exc.errno in (errno.ELOOP, errno.ENOTDIR) else exc.strerror
                raise Refusal(f"the folder {shown} {reason}") from None
            os.close(fd)
            fd = next_fd
            st = os.fstat(fd)
            owners = (root_uid(), user_id("ars")) if i == len(parts) - 1 else (root_uid(),)
            if st.st_uid not in owners:
                problems.append(f"the folder {shown} belongs to uid {st.st_uid}")
            if stat.S_IMODE(st.st_mode) & 0o022:
                problems.append(f"the folder {shown} is writable by its group or others ({mode_text(st)})")
    except BaseException:
        os.close(fd)
        raise
    return fd, problems


def read_index(dir_fd, path):
    data, st = read_regular_file(os.path.basename(path), INDEX_MAX_BYTES, dir_fd=dir_fd, shown=path)
    problems = []
    if st.st_nlink != 1:
        problems.append(f"{path} has {st.st_nlink} links")
    if st.st_uid not in (root_uid(), user_id("ars")) or st.st_gid not in (root_gid(), group_id("ars")):
        problems.append(f"{path} belongs to {st.st_uid}:{st.st_gid}, not ARS's account or root")
    if stat.S_IMODE(st.st_mode) & 0o022:
        problems.append(f"{path} is writable by its group or others ({mode_text(st)})")
    return data, st, problems


def count_records(data):
    """How many records the index holds, or None. The count only informs:
    the index is not parsed for anything else."""
    try:
        doc = json.loads(data)
    except (ValueError, RecursionError, MemoryError):
        return None
    return len(doc) if isinstance(doc, dict) else None


def index_state(ars_doc):
    """ARS's index as inspect sees it: (record, problems, leftovers)."""
    record = {"path": None, "entries": None}
    try:
        path = index_path(ars_doc)
        record["path"] = path
        dir_fd, problems = open_index_folder(path)
    except Refusal as exc:
        return record, [str(exc)], []
    try:
        try:
            data, st, more = read_index(dir_fd, path)
        except Refusal as exc:
            return record, problems + [str(exc)], []
        record.update(entries=count_records(data), sha256=sha256_hex(data), size=len(data), uid=st.st_uid,
                      gid=st.st_gid, mode=mode_text(st))
        leftovers = [p for p in leftover_temp_files(dir_fd, os.path.dirname(path))
                     if os.path.basename(p).startswith("." + os.path.basename(path) + TEMP_MARK)]
        return record, problems + more, leftovers
    finally:
        os.close(dir_fd)


# Inspection.

def read_config(name, path, group):
    """(doc, data, record, problems) of a config that must be root:<group>
    0640 with one link, read strictly."""
    data, st = read_regular_file(host(path), shown=path)
    record = {"path": path, "sha256": sha256_hex(data), "size": len(data), "uid": st.st_uid, "gid": st.st_gid,
              "mode": mode_text(st)}
    problems = []
    if st.st_uid != root_uid() or st.st_gid != group_id(group) or stat.S_IMODE(st.st_mode) != CONFIG_MODE \
            or st.st_nlink != 1:
        problems.append(f"{path} is not root:{group} {CONFIG_MODE:04o} with one link")
    return parse_strict(data, path), data, record, problems


def healthcheck_env_problems():
    try:
        _, st = read_regular_file(host(HEALTHCHECK_ENV), shown=HEALTHCHECK_ENV)
    except Refusal as exc:
        return [str(exc)]
    if st.st_uid != root_uid() or stat.S_IMODE(st.st_mode) & 0o022 or st.st_nlink != 1:
        return [f"{HEALTHCHECK_ENV} is not a file root owns with one link that neither its group nor others can write"]
    return []


def backup_entries():
    """The folders under the backup root, or [] when there is none."""
    root = host(BACKUP_ROOT)
    try:
        names = sorted(os.listdir(root))
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise Refusal(f"cannot list {BACKUP_ROOT}: {exc.strerror}") from None
    return [(name, os.path.join(root, name)) for name in names]


def recorded(path, name, shown):
    """The record name in the backup folder path, or None."""
    if not os.path.lexists(os.path.join(path, name)):
        return None
    data, _ = read_regular_file(os.path.join(path, name), shown=os.path.join(shown, name))
    return parse_strict(data, os.path.join(shown, name))


def last_outcome(path, shown):
    """(the result the last apply or rollback recorded in the backup folder
    path, whether a rollback started there and recorded no end). A rollback
    writes rollback-started.json before it changes anything and
    rollback.json, with the same rollback_id, when it ends; rollback.json is
    later than summary.json."""
    started = recorded(path, ROLLBACK_STARTED, shown)
    rollback = recorded(path, ROLLBACK_RECORD, shown)
    summary = recorded(path, SUMMARY, shown)
    unfinished = started is not None and (rollback is None or rollback.get("rollback_id") != started.get("rollback_id"))
    latest = rollback if rollback is not None else summary
    return (latest or {}).get("result"), unfinished


def unfinished_problems():
    """A rotation or rollback that a SIGKILL, a crash or a lost record left
    without an end, or a rollback that could not put everything back: a
    backup that is still being built, that has no summary.json and no
    rollback.json, whose rollback started and recorded no end, or whose
    last result is rollback_failed."""
    problems = []
    for name, path in backup_entries():
        shown = os.path.join(BACKUP_ROOT, name)
        if name.startswith(INCOMPLETE_PREFIX):
            problems.append(f"{shown} is the backup of an apply that stopped before it changed anything; "
                            f"`rollback --backup-dir {shown}` removes it")
            continue
        if not os.path.lexists(os.path.join(path, SUMMARY)) and not os.path.lexists(os.path.join(path, ROLLBACK_RECORD)):
            problems.append(f"a rotation did not finish (it was stopped, or its summary could not be written): its "
                            f"backup is {shown}; `rollback --backup-dir {shown}` puts that backup back")
            continue
        try:
            result, unfinished = last_outcome(path, shown)
        except Refusal as exc:
            problems.append(f"cannot read the records of {shown}: {exc}")
            continue
        if unfinished:
            problems.append(f"a rollback of {shown} did not finish (it was stopped, or its record could not be "
                            f"written); `rollback --backup-dir {shown}` finishes it")
        elif result == "rollback_failed":
            problems.append(f"the last rollback of {shown} could not put everything back (rollback_failed); "
                            f"`rollback --backup-dir {shown}` tries again, or, once the host is settled by hand, "
                            f"move {shown} out of {BACKUP_ROOT}")
    return problems


def inspect(mode):
    """Read everything check and apply look at. Returns (report, state):
    the report holds no private key; state holds the documents and bytes
    apply works from."""
    report = {"schema": SCHEMA, "host_root": HOST_ROOT, "mode": mode}
    problems = folder_chain_problems(CONFIG_DIR)
    docs, data, files = {}, {}, {}
    for name, path, group in CONFIGS + (("ars", ARS_CONFIG, "ars"),):
        try:
            docs[name], data[name], files[name], more = read_config(name, path, group)
            problems += more
        except Refusal as exc:
            problems.append(str(exc))
    report["files"] = files
    problems += healthcheck_env_problems()
    for unit in UNITS:
        try:
            problems += exec_start_problems(unit)
        except Refusal as exc:
            problems.append(str(exc))
    try:
        problems += unfinished_problems()
    except Refusal as exc:
        problems.append(str(exc))
    index = {"path": None, "entries": None}
    try:
        leftovers = find_leftovers(docs.get("ars"))
    except (Refusal, OSError) as exc:
        problems.append(f"cannot look for files a stopped rotation left: {exc}")
        leftovers = []
    for _, _, paths in leftovers:
        for path in paths:
            problems.append(f"{path} was left by a rotation that was stopped while it wrote files; "
                            "`rollback` of that rotation's backup removes it")
    if "ars" in docs:
        index, more, _ = index_state(docs["ars"])
        problems += more
    report["ars_index"] = index
    report["ars_index_entries"] = index.get("entries")
    if len(docs) == 4:
        consistency = consistency_problems(docs)
        problems += consistency
        if not consistency:
            report["current"] = {
                role: dict(public_part(docs[role]["signer"]),
                           private_seed_is_one_byte_repeated=seed_is_one_byte(docs[role]["signer"]))
                for role in ("ags", "egs")
            }
            report["workload_grant_rules"] = len(grant_rules(docs["es"]))
        try:
            ok, report["before"] = all_up(docs)
        except Refusal as exc:
            ok = False
            problems.append(str(exc))
        if not ok:
            problems.append("ARS, EGS, AGS and ES must all run, ARS and EGS accept connections, and ES and AGS "
                            "answer 200, before the rotation")
    report["problems"] = problems
    if not problems:
        report["changes"] = planned_changes(docs, index)
    return report, {"docs": docs, "data": data, "files": files, "index": index}


# Backups.

def backup_root_ready():
    root = host(BACKUP_ROOT)
    parent_problems = folder_chain_problems(os.path.dirname(BACKUP_ROOT))
    if parent_problems:
        raise Refusal("; ".join(parent_problems))
    try:
        os.mkdir(root, 0o700)
    except FileExistsError:
        pass
    st = os.lstat(root)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != root_uid():
        raise Refusal(f"{BACKUP_ROOT} must be a folder root owns")
    os.chmod(root, 0o700)
    return root


def make_backup(state, rotated_data, ags_new):
    """Copy the three configs, as inspect read them, into a new 0700 folder
    with a manifest of their bytes, owners and modes and of the bytes apply
    will write. The folder gets its final name only once all of it is on
    disk and every config still holds what inspect read. The copies hold
    the old private keys, so they are 0600 and the folder is root's alone."""
    root = backup_root_ready()
    name = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + ags_new["key_id"]
    incomplete = os.path.join(root, INCOMPLETE_PREFIX + name)
    final = os.path.join(root, name)
    os.mkdir(incomplete, 0o700)
    try:
        os.chmod(incomplete, 0o700)
        entries = []
        for config, path, _ in CONFIGS:
            data = state["data"][config]
            write_new_file(os.path.join(incomplete, f"{config}.json"), data)
            entries.append(dict(state["files"][config], copy=f"{config}.json",
                                rotated_sha256=sha256_hex(rotated_data[config])))
        manifest = {"schema": BACKUP_SCHEMA, "files": entries}
        write_new_file(os.path.join(incomplete, BACKUP_MANIFEST),
                       (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode())
        sync_dir(incomplete)
        test_point("backup-copied")
        for config, path, _ in CONFIGS:
            now, _ = read_regular_file(host(path), shown=path)
            if sha256_hex(now) != state["files"][config]["sha256"]:
                raise Refusal(f"{path} changed while apply ran")
        check_stop()
        test_point("backup-written")
        os.rename(incomplete, final)
        sync_dir(root)
    except BaseException:
        shutil.rmtree(incomplete, ignore_errors=True)
        raise
    return final


def backup_index(backup_dir, dir_fd, path):
    """Copy ARS's index into the backup with a manifest of its own, written
    last: an index manifest on disk means the copy is complete."""
    data, st, problems = read_index(dir_fd, path)
    if problems:
        raise Refusal("; ".join(problems))
    write_new_file(os.path.join(backup_dir, INDEX_COPY), data)
    record = {"schema": BACKUP_SCHEMA, "path": path, "copy": INDEX_COPY, "sha256": sha256_hex(data),
              "size": len(data), "uid": st.st_uid, "gid": st.st_gid, "mode": mode_text(st)}
    write_record(backup_dir, INDEX_MANIFEST, record)
    return record


def exact_keys(doc, keys, what):
    if not isinstance(doc, dict) or sorted(doc) != sorted(keys):
        raise Refusal(f"{what} does not have exactly the fields {sorted(keys)}")


def is_count(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def read_backup(backup_dir):
    """A backup of this rotation, with every field and copy checked before
    anything is restored: (entries with their copies, index record and copy
    or None)."""
    try:
        st = os.lstat(backup_dir)
    except OSError as exc:
        raise Refusal(f"cannot read {backup_dir}: {exc.strerror}") from None
    if not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o700 or st.st_uid != root_uid():
        raise Refusal("the backup folder must be a 0700 folder root owns")
    data, _ = read_regular_file(os.path.join(backup_dir, BACKUP_MANIFEST))
    manifest = parse_strict(data, "the backup manifest")
    exact_keys(manifest, ("schema", "files"), "the backup manifest")
    if manifest["schema"] != BACKUP_SCHEMA:
        raise Refusal("the backup manifest is not one of this rotation")
    files = manifest["files"]
    if not isinstance(files, list) or len(files) != len(CONFIGS):
        raise Refusal("the backup manifest does not list the three configs")
    entries = []
    for entry, (config, path, group) in zip(files, CONFIGS):
        exact_keys(entry, ("path", "copy", "sha256", "rotated_sha256", "size", "uid", "gid", "mode"),
                   f"the backup manifest's entry for {path}")
        if entry["path"] != path or entry["copy"] != f"{config}.json":
            raise Refusal("the backup manifest does not list the three configs in order")
        if not is_hex(entry["sha256"], 64) or not is_hex(entry["rotated_sha256"], 64) or not is_count(entry["size"]):
            raise Refusal(f"the backup manifest's entry for {path} has no SHA-256 or size")
        if entry["uid"] != root_uid() or entry["gid"] != group_id(group) or entry["mode"] != f"{CONFIG_MODE:04o}":
            raise Refusal(f"the backup manifest gives {path} an owner or mode other than root:{group} {CONFIG_MODE:04o}")
        copy, _ = read_regular_file(os.path.join(backup_dir, entry["copy"]))
        if sha256_hex(copy) != entry["sha256"] or len(copy) != entry["size"]:
            raise Refusal(f"the backup copy of {path} does not match its manifest")
        entries.append((entry, copy, parse_strict(copy, f"the backup copy of {path}")))
    index = None
    if os.path.lexists(os.path.join(backup_dir, INDEX_MANIFEST)):
        data, _ = read_regular_file(os.path.join(backup_dir, INDEX_MANIFEST))
        record = parse_strict(data, "the index manifest")
        exact_keys(record, ("schema", "path", "copy", "sha256", "size", "uid", "gid", "mode"), "the index manifest")
        if record["schema"] != BACKUP_SCHEMA or record["copy"] != INDEX_COPY or not isinstance(record["path"], str):
            raise Refusal("the index manifest is not one of this rotation")
        if not is_hex(record["sha256"], 64) or not is_count(record["size"]):
            raise Refusal("the index manifest has no SHA-256 or size")
        mode = record["mode"]
        if record["uid"] not in (root_uid(), user_id("ars")) or record["gid"] not in (root_gid(), group_id("ars")) \
                or not (isinstance(mode, str) and len(mode) == 4 and set(mode) <= set("01234567")) \
                or int(mode, 8) & 0o7022:
            raise Refusal("the index manifest gives the index an owner or mode this rotation does not restore")
        copy, _ = read_regular_file(os.path.join(backup_dir, INDEX_COPY), INDEX_MAX_BYTES)
        if sha256_hex(copy) != record["sha256"] or len(copy) != record["size"]:
            raise Refusal("the backup copy of ARS's index does not match its manifest")
        index = (record, copy)
    return entries, index


def stale_problems(entries):
    """Configs that changed since the rotation that made the backup: a
    rollback restores a backup only over the configs it replaced, or over
    its own copies."""
    problems = []
    for entry, _, _ in entries:
        try:
            now, _ = read_regular_file(host(entry["path"]), shown=entry["path"])
        except Refusal as exc:
            problems.append(str(exc))
            continue
        if sha256_hex(now) not in (entry["sha256"], entry["rotated_sha256"]):
            problems.append(f"{entry['path']} is neither the config this backup's rotation wrote nor the one it replaced")
    return problems


# Output.

OUTPUT = {"lost": False}


def say(text, stream=None):
    """Print, and never raise: a terminal that hung up must not stop apply or
    its rollback."""
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


def require_root():
    if not test_mode() and os.geteuid() != 0:
        raise Refusal("run it as root")


# The checkout. check, apply and rollback run this file as root, so nobody
# but root may be able to change it (red-team RT60-2). The wrapper,
# scripts/remote_alpha_rotate_signing_keys.sh, checks that before any of
# this file runs, which is the check that counts: a check in this file is
# gone once someone replaces the file. This one is the second line, for this
# file started on its own, and it covers the whole scripts folder.

SCRIPTS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def checkout_owner():
    """The uid that alone may be able to change the checkout: root on a host.
    Under a test --host-root the guard runs only when a test names the uid in
    SIGNING_KEY_ROTATION_TEST_CHECKOUT_OWNER, and None means it does not run."""
    if not test_mode():
        return 0
    value = test_env("CHECKOUT_OWNER")
    return int(value) if value else None


def checkout_problems(scripts_dir, owner):
    """Why someone other than owner could change the code this rotation runs
    as root, or [] when nobody else can. Every folder from / down to
    scripts_dir must belong to root or owner and be writable by neither its
    group nor others, unless it has the sticky bit (as /tmp has). Everything
    under scripts_dir must belong to owner, be a folder or a regular file,
    and be writable by neither its group nor others. No symbolic link
    counts: one could point anywhere."""
    problems = []
    real = os.path.realpath(scripts_dir)
    if real != scripts_dir:
        return [f"{scripts_dir} is reached through a symbolic link ({real})"]
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
    owner = checkout_owner()
    if owner is None:
        return
    problems = checkout_problems(SCRIPTS_DIR, owner)
    if problems:
        who = "root" if owner == 0 else f"uid {owner}"
        shown = "; ".join(problems[:20])
        more = f" (and {len(problems) - 20} more)" if len(problems) > 20 else ""
        raise Refusal(f"someone other than {who} can change the code this rotation runs as root: {shown}{more}; "
                      "hand the clone to root first (chown -R root:root and chmod -R go-w); nothing was changed")


# The service steps. apply stops at the first failed step and rolls back; a
# rollback tries every step and records how each one went.

def take_step(steps, name, action, best_effort):
    try:
        action()
    except Exception as exc:  # noqa: BLE001 - recorded; apply re-raises
        steps.append({"step": name, "result": "failed", "error": str(exc)})
        if best_effort:
            return False
        raise
    steps.append({"step": name, "result": "done"})
    if not best_effort:
        check_stop()
    return True


def stop_services(steps, best_effort):
    """Stop ES, then AGS, then ARS. Returns whether every stop worked."""
    ok = True
    for unit in ("es", "ags", "ars"):
        ok &= take_step(steps, f"stop {unit}", lambda unit=unit: systemctl("stop", unit), best_effort)
    return ok


def start_services(steps, docs, best_effort):
    """Start ARS on its index, restart EGS on its key, then AGS, then ES,
    which fetches EGS's trust policy when it starts, so EGS must already
    accept connections. Returns whether every step worked."""
    ok = True
    ok &= take_step(steps, "start ars", lambda: systemctl("start", "ars"), best_effort)
    ok &= take_step(steps, "wait for ars", lambda: wait_listening("ars", docs), best_effort)
    ok &= take_step(steps, "restart egs", lambda: systemctl("restart", "egs"), best_effort)
    ok &= take_step(steps, "wait for egs", lambda: wait_listening("egs", docs), best_effort)
    ok &= take_step(steps, "start ags", lambda: systemctl("start", "ags"), best_effort)
    ok &= take_step(steps, "start es", lambda: systemctl("start", "es"), best_effort)
    return ok


def require_ars_stopped():
    state = units_active()["ars"]
    if state not in ("inactive", "failed"):
        raise Refusal(f"ars is {state} after systemctl stop ars")


def restore(report, docs, configs, index, leftovers):
    """Put configs (entries with their copies) and the index (record and
    copy, or None) back, start the services again, and wait for them. Every
    step is tried; the result says what state the host is in, and is
    rolled_back only when every step worked and the services answer."""
    steps = report.setdefault("rollback_steps", [])
    services_ok = stop_services(steps, True)
    restored_ok = True
    if leftovers:
        restored_ok &= take_step(steps, "remove the temporary files a stopped rotation left",
                                 lambda: remove_leftovers(report, leftovers), True)
    for entry, copy, _ in configs:
        restored_ok &= take_step(steps, f"restore {entry['path']}", lambda e=entry, c=copy: restore_config(e, c), True)
    if index is not None:
        restored_ok &= take_step(steps, f"restore {index[0]['path']}", lambda: restore_index(*index), True)
    services_ok &= start_services(steps, docs, True)
    if not restored_ok:
        report["result"] = "rollback_failed"
        return
    try:
        ok, report["after_rollback"] = wait_until_up(docs)
    except Exception as exc:  # noqa: BLE001 - recorded in the result
        ok = False
        report["after_rollback_error"] = str(exc)
    report["result"] = "rolled_back" if ok and services_ok else "rolled_back_unhealthy"


def restore_config(entry, copy):
    replace_config(entry["path"], copy, entry["uid"], entry["gid"], int(entry["mode"], 8))
    test_point("restored-" + os.path.basename(entry["path"]))
    after, _ = read_regular_file(host(entry["path"]), shown=entry["path"])
    if sha256_hex(after) != entry["sha256"]:
        raise Failed(f"{entry['path']} does not match its backup after the restore")


def restore_index(record, copy):
    require_ars_stopped()
    dir_fd, problems = open_index_folder(record["path"])
    try:
        if problems:
            raise Failed("; ".join(problems))
        name = os.path.basename(record["path"])
        replace_file(dir_fd, name, copy, record["uid"], record["gid"], int(record["mode"], 8))
        test_point("restored-index")
        after, _ = read_regular_file(name, INDEX_MAX_BYTES, dir_fd=dir_fd, shown=record["path"])
        if after != copy:
            raise Failed(f"{record['path']} does not match its backup after the restore")
    finally:
        os.close(dir_fd)


def remove_leftovers(report, leftovers):
    removed = []
    for folder, index_file, paths in leftovers:
        if index_file is None:
            dir_fd = open_dir(host(folder))
        else:
            dir_fd, _ = open_index_folder(index_file)
        try:
            removed += remove_temp_files(dir_fd, paths)
        finally:
            os.close(dir_fd)
    report["removed"] = removed


def find_leftovers(ars_doc):
    """[(folder, the index it holds or None, [temporary files a stopped
    rotation left there])] for the config folder and the index folder."""
    found = []
    dir_fd = open_dir(host(CONFIG_DIR))
    try:
        paths = leftover_temp_files(dir_fd, CONFIG_DIR)
    finally:
        os.close(dir_fd)
    if paths:
        found.append((CONFIG_DIR, None, paths))
    if ars_doc is not None:
        record, _, paths = index_state(ars_doc)
        if paths:
            found.append((os.path.dirname(record["path"]), record["path"], paths))
    return found


# The commands.

def finish(report, backup_dir, record_name):
    """Print the report, then write it into the backup folder. A record that
    cannot be written is said on its own line and fails the run, but it
    never hides the report or calls a changed host unchanged."""
    report["output_lost"] = OUTPUT["lost"]
    report["signals_received"] = list(SIGNALS["received"])
    say(json.dumps(report, indent=2, sort_keys=True))
    path = os.path.join(backup_dir, record_name)
    try:
        write_record(backup_dir, record_name, report)
    except OSError as exc:
        return (f"the result is {report['result']}, but {path} could not be written: {exc.strerror or exc}; "
                f"until the report above is saved there (root's, mode 0600), check names this backup as unfinished")
    return None


def cmd_check(_args):
    report, _ = inspect("check")
    if not report["problems"]:
        report["result"] = "ready"
    say(json.dumps(report, indent=2, sort_keys=True))
    if report["problems"]:
        raise Refusal(f"{len(report['problems'])} problem(s); nothing was changed")


def cmd_apply(_args):
    catch_signals()
    SIGNALS["armed"] = True
    events = []

    def log(message):
        events.append({"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": message})
        say(message, sys.stderr)

    report, state = inspect("apply")
    report["events"] = events
    if report["problems"]:
        say(json.dumps(report, indent=2, sort_keys=True))
        raise Refusal(f"{len(report['problems'])} problem(s); nothing was changed")
    docs = state["docs"]
    try:
        check_stop()
        ags_new, egs_new = new_signer("ags"), new_signer("egs")
        if ags_new["public_key_hex"] == egs_new["public_key_hex"]:
            raise Refusal("openssl gave AGS and EGS the same key")
        rotated = rotate(docs, ags_new, egs_new)
        rotated["ars"] = docs["ars"]
        data = {name: render_json(rotated[name]) for name, _, _ in CONFIGS}
        report["new"] = {"ags": public_part(ags_new), "egs": public_part(egs_new)}
        check_stop()
        backup_dir = make_backup(state, data, ags_new)
    except Interrupted as exc:
        raise Refusal(f"{exc} before any change; nothing was changed") from None
    except (Refusal, OSError, ValueError) as exc:
        # ValueError: a config that cannot be written back as it was read,
        # which the strict reader should already have refused in check.
        raise Refusal(f"{exc}; nothing was changed") from None
    report["backup_dir"] = backup_dir
    log("backup written to " + backup_dir)

    # From here on, any failure or interrupting signal puts the backup back.
    steps = report["steps"] = []
    written, index_backup = [], {}
    failure = None
    try:
        for name, path, group in CONFIGS:
            now, _ = read_regular_file(host(path), shown=path)
            if sha256_hex(now) != state["files"][name]["sha256"]:
                raise Refusal(f"{path} changed while apply ran")
            written.append(name)
            replace_config(path, data[name], root_uid(), group_id(group), CONFIG_MODE, point="config-temp-written:" + name)
            after, _ = read_regular_file(host(path), shown=path)
            if after != data[name]:
                raise Refusal(f"{path} does not hold the rotated config after the write")
            log(f"{path} written")
            check_stop()
        stop_services(steps, False)
        require_ars_stopped()
        index_file = state["index"]["path"]
        dir_fd, problems = open_index_folder(index_file)
        try:
            if problems:
                raise Refusal("; ".join(problems))
            index_backup["record"] = backup_index(backup_dir, dir_fd, index_file)
            replace_file(dir_fd, os.path.basename(index_file), EMPTY_INDEX, index_backup["record"]["uid"],
                         index_backup["record"]["gid"], int(index_backup["record"]["mode"], 8), point="index-temp-written")
        finally:
            os.close(dir_fd)
        log(f"ARS index moved into the backup; {index_file} is empty")
        check_stop()
        start_services(steps, rotated, False)
        log("es, ags and ars stopped; ars started, egs restarted, ags and es started")
        ok, report["after"] = wait_until_up(rotated)
        if not ok:
            raise Refusal("ARS, EGS, AGS and ES do not all run and answer after the restart")
        report["result"] = "rotated"
    except (Exception, Interrupted) as exc:  # noqa: BLE001 - every failure after the backup rolls back
        failure = exc
    SIGNALS["armed"] = False

    if failure is not None:
        log(f"apply failed: {failure}; rolling back")
        report["failure"] = str(failure)
        try:
            configs = []
            for name, path, group in CONFIGS:
                if name in written:
                    copy = state["data"][name]
                    configs.append((dict(state["files"][name], rotated_sha256=sha256_hex(data[name])), copy, docs[name]))
            index = None
            if "record" in index_backup:
                record = index_backup["record"]
                copy, _ = read_regular_file(os.path.join(backup_dir, INDEX_COPY), INDEX_MAX_BYTES)
                index = ({k: record[k] for k in ("path", "uid", "gid", "mode")}, copy)
            restore(report, docs, configs, index, find_leftovers(docs["ars"]))
        except Exception as exc:  # noqa: BLE001 - recorded in the result
            report["result"] = "rollback_failed"
            report["rollback_failure"] = str(exc)
        problem = finish(report, backup_dir, SUMMARY)
        tail = f"; {problem}" if problem else f"; summary {os.path.join(backup_dir, SUMMARY)}"
        raise Failed(f"apply failed: {failure}; result {report['result']}{tail}")
    problem = finish(report, backup_dir, SUMMARY)
    if problem:
        raise Failed(problem)
    log("summary written to " + os.path.join(backup_dir, SUMMARY))


def cmd_rollback(args):
    catch_signals()
    backup_dir = args.backup_dir
    root = host(BACKUP_ROOT)
    parent, name = os.path.split(os.path.normpath(backup_dir))
    if os.path.realpath(parent) != os.path.realpath(root) or not name or name.startswith(".") and not name.startswith(INCOMPLETE_PREFIX):
        raise Refusal(f"{backup_dir} is not a folder directly under {BACKUP_ROOT}")
    if name.startswith(INCOMPLETE_PREFIX):
        st = os.lstat(backup_dir)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != root_uid():
            raise Refusal(f"{backup_dir} is not a folder root owns")
        shutil.rmtree(backup_dir)
        sync_dir(root)
        say(json.dumps({"schema": SCHEMA, "mode": "rollback", "backup_dir": backup_dir,
                        "result": "removed_incomplete_backup"}, indent=2, sort_keys=True))
        return
    entries, index = read_backup(backup_dir)
    problems = stale_problems(entries)
    if problems:
        raise Refusal("; ".join(problems) + "; this backup is not the latest rotation's, so it is not put back")
    result, unfinished = last_outcome(backup_dir, backup_dir)
    # Both results mean every file is back; only a rollback_failed one, or
    # one that did not finish, has something left to put back.
    if result in ("rolled_back", "rolled_back_unhealthy") and not unfinished:
        hint = "" if result == "rolled_back" else (
            "; the services did not all start or answer then: start the ones that do not run"
            " (systemctl start ars, then egs, ags and es) and run check")
        raise Refusal(f"{backup_dir} was rolled back already (result {result}): its files are back, and putting its "
                      f"index back again would drop the records ARS took since, so nothing was changed{hint}")
    current_docs = {}
    for config, path, group in CONFIGS + (("ars", ARS_CONFIG, "ars"),):
        data, _ = read_regular_file(host(path), shown=path)
        current_docs[config] = parse_strict(data, path)
    if index is not None and index[0]["path"] != index_path(current_docs["ars"]):
        raise Refusal("the index manifest names another index than ars.json does")
    backup_docs = {entry["path"]: doc for entry, _, doc in entries}
    restoring = {role: (backup_docs[f"{CONFIG_DIR}/{role}.json"].get("signer") or {}).get("key_id") for role in ("ags", "egs")}
    current = {role: (current_docs[role].get("signer") or {}).get("key_id") for role in ("ags", "egs")}
    say(f"rollback: putting back AGS key {restoring['ags']} and EGS key {restoring['egs']} from {backup_dir} "
        f"(now {current['ags']} and {current['egs']})", sys.stderr)
    rollback_id = secrets.token_hex(8)
    report = {"schema": SCHEMA, "mode": "rollback", "backup_dir": backup_dir, "restoring": restoring, "replacing": current,
              "rollback_id": rollback_id}
    docs = {name: backup_docs[path] for name, path, _ in CONFIGS}
    docs["ars"] = current_docs["ars"]
    # Written before anything changes, so that check names a rollback that a
    # SIGKILL or a crash stops, and ended by rollback.json with the same ID.
    write_record(backup_dir, ROLLBACK_STARTED, {"schema": SCHEMA, "rollback_id": rollback_id,
                                                "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
    try:
        restore(report, docs, entries, index, find_leftovers(current_docs["ars"]))
    except Exception as exc:  # noqa: BLE001 - recorded in the result
        report["result"] = "rollback_failed"
        report["rollback_failure"] = str(exc)
    problem = finish(report, backup_dir, ROLLBACK_RECORD)
    if report["result"] != "rolled_back":
        raise Failed(f"rollback result {report['result']}" + (f"; {problem}" if problem else ""))
    if problem:
        raise Failed(problem)


def main(argv):
    parser = argparse.ArgumentParser(prog="remote_alpha_rotate_signing_keys.py")
    parser.add_argument("--host-root", default="/", help=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check").set_defaults(func=cmd_check)
    sub.add_parser("apply").set_defaults(func=cmd_apply)
    rb = sub.add_parser("rollback")
    rb.add_argument("--backup-dir", required=True)
    rb.set_defaults(func=cmd_rollback)
    args = parser.parse_args(argv)
    if not os.path.isabs(args.host_root):
        print("remote alpha signing key rotation refused: --host-root must be absolute", file=sys.stderr)
        return 2
    set_host_root(args.host_root)
    try:
        require_root()
        require_root_only_checkout()
        args.func(args)
    except Refusal as exc:
        say(f"remote alpha signing key rotation refused: {exc}", sys.stderr)
        return 1
    except Failed as exc:
        say(f"remote alpha signing key rotation: {exc}", sys.stderr)
        return 1
    except OSError as exc:
        say(f"remote alpha signing key rotation stopped: {exc}", sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
