#!/usr/bin/env -S python3 -I
"""Remote Alpha signing key rotation: give the box's AGS and EGS new keys.

This file is the implementation behind scripts/remote_alpha_rotate_signing_keys.sh.
AGS seals artifact evidence with its signer key and EGS signs the runtime
trust policy with its own; ES verifies both with the public keys in its
verification group (.docs/system_overview/configuration.md, "Signing keys").
This rotation replaces both keys on one host, in ags.json, egs.json and
es.json together:

  check     (root, read-only) read the three configs, check that they agree
            with each other, check that AGS, EGS and ES run and answer, and
            print every change apply would make
  apply     (root) check; make a new AGS key and a new EGS key on this host;
            back the three configs up; write AGS's and EGS's new signers,
            EGS's allow list (the new AGS key ID instead of the old one, the
            old one revoked, the publication revision one higher), ES's four
            verification keys and every workload grant's signer key ID; stop
            ES, restart EGS and AGS, start ES, and check that all three run
            and answer; on any failure, put the backup back and restart them
  rollback  (root) put a backup back and restart EGS, AGS and ES

The keys come from the host's own /usr/bin/openssl, so nothing built from a
checkout runs as root to make them. Each is written as the signer object
scripts/internal/signingkeygen writes, with the same key ID: the role, a
hyphen, and the first 16 hex digits of the SHA-256 of the public key. A
private key reaches openssl and this process only through pipes, and only
the new configs and the root-only backup ever hold one; no output names one.

ES starts listening only after it has fetched EGS's trust policy and
verified it with verification.trust_model (es/app/app.go, Start), so ES
answering after the restart shows that the new EGS key and ES agree. ES
refuses evidence sealed with the old AGS key from then on: artifacts
published before the rotation are published again from their sources
through AGS when they are still needed, never re-signed.

Everything refuses what it does not recognise rather than guess.
"""

import argparse
import errno
import grp
import hashlib
import json
import os
import signal
import stat
import subprocess
import sys
import time

SCHEMA = "execution-substrate.remote-alpha.signing-key-rotation.v1"
BACKUP_SCHEMA = "execution-substrate.remote-alpha.signing-key-rotation-backup.v1"
BACKUP_MANIFEST = "manifest.json"
BACKUP_ROOT = "/var/backups/execution-substrate-signing-keys"

CONFIG_DIR = "/etc/execution-substrate"
# Each config the rotation writes, with the group its service reads it as.
# The Remote Alpha services keep them root:<service> 0640.
CONFIGS = (
    ("egs", CONFIG_DIR + "/egs.json", "egs"),
    ("ags", CONFIG_DIR + "/ags.json", "ags"),
    ("es", CONFIG_DIR + "/es.json", "es"),
)
CONFIG_MODE = 0o640
ARS_CONFIG = CONFIG_DIR + "/ars.json"
HEALTHCHECK_ENV = CONFIG_DIR + "/healthcheck.env"
UNITS = ("egs", "ags", "es")
HEALTH_WAIT_SECONDS = 60
OPENSSL = "/usr/bin/openssl"

# The DER encodings openssl gives an Ed25519 key (RFC 8410): a PKCS #8
# private key whose last 32 bytes are the seed, and a SubjectPublicKeyInfo
# whose last 32 bytes are the public key.
ED25519_PRIVATE_DER_PREFIX = bytes.fromhex("302e020100300506032b657004220420")
ED25519_PUBLIC_DER_PREFIX = bytes.fromhex("302a300506032b6570032100")
HEX = set("0123456789abcdef")

VERIFICATION_FROM = (
    ("trust_model", "egs"),
    ("provenance", "ags"),
    ("derivation_attestation", "ags"),
    ("workload_identity_binding", "ags"),
)


class Refusal(Exception):
    pass


class Interrupted(Exception):
    pass


HOST_ROOT = "/"


def host(path):
    """A host path, under --host-root when the tests set one."""
    if HOST_ROOT == "/":
        return path
    return os.path.join(HOST_ROOT, path.lstrip("/"))


def test_mode():
    """Under a test --host-root, the user running the tests stands in for
    root and for every service account."""
    return HOST_ROOT != "/"


def root_uid():
    return os.getuid() if test_mode() else 0


def group_id(name):
    if test_mode():
        return os.getgid()
    try:
        return grp.getgrnam(name).gr_gid
    except KeyError:
        raise Refusal(f"group {name} does not exist")


def openssl():
    if test_mode() and os.environ.get("SIGNING_KEY_ROTATION_TEST_OPENSSL"):
        return os.environ["SIGNING_KEY_ROTATION_TEST_OPENSSL"]
    return OPENSSL


def wait_seconds(seconds):
    if test_mode() and os.environ.get("SIGNING_KEY_ROTATION_TEST_WAIT_SECONDS"):
        return int(os.environ["SIGNING_KEY_ROTATION_TEST_WAIT_SECONDS"])
    return seconds


# Files.

def sha256_hex(data):
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


def write_new_file(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_replace(path, data, uid, gid, mode):
    """Replace path with data, owner and mode in one rename. The new file is
    written next to the old one, synced, and renamed over it; a symbolic
    link at path is replaced, never followed."""
    parent, name = os.path.split(path)
    tmp = os.path.join(parent, f".{name}.signing-key-rotation.{os.getpid()}")
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
    sync_dir(parent)


def render_json(doc):
    return (json.dumps(doc, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


# Commands.

def run(args, data=None, timeout=60):
    """Run a command with bytes in and out, in a process group of its own,
    and end the group if it outlives the timeout."""
    try:
        return subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
                              start_new_session=True, check=False)
    except subprocess.TimeoutExpired:
        raise Refusal(f"{' '.join(args[:3])} did not finish within {timeout} s") from None
    except OSError as exc:
        raise Refusal(f"cannot run {args[0]}: {exc.strerror}") from None


def systemctl(*args, check=True):
    proc = run(["systemctl", *args], timeout=120)
    if check and proc.returncode != 0:
        raise Refusal(f"systemctl {' '.join(args)} failed: {proc.stderr.decode(errors='replace').strip()[:300]}")
    return proc.stdout.decode(errors="replace")


def units_active():
    out = systemctl("is-active", *UNITS, check=False).split()
    return dict(zip(UNITS, out + ["unknown"] * (len(UNITS) - len(out))))


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


def health_urls(docs):
    """ES's health and contract endpoints and AGS's health endpoint, at the
    addresses their configs name (the healthcheck runbook's step 4)."""
    urls = []
    for name, suffixes in (("es", ("/health", "/v1/executions:contract")), ("ags", ("/health",))):
        http = docs[name].get("http") if isinstance(docs[name].get("http"), dict) else {}
        address, port = http.get("bind_address"), http.get("port")
        if not isinstance(address, str) or not address or ":" in address or not isinstance(port, int):
            raise Refusal(f"{name}.json has no IPv4 http.bind_address and http.port")
        urls += [f"https://{address}:{port}{suffix}" for suffix in suffixes]
    return urls


def health(docs):
    env = healthcheck_env()
    result = {}
    for url in health_urls(docs):
        proc = run(["curl", "--noproxy", "*", "-sS", "-m", "10", "-o", "/dev/null", "-w", "%{http_code}",
                    "--cacert", env["CA_CERT"], "--cert", env["OPERATOR_CERT"], "--key", env["OPERATOR_KEY"], url],
                   timeout=15)
        out = proc.stdout.decode(errors="replace").strip()
        result[url] = out if proc.returncode == 0 else "error: " + proc.stderr.decode(errors="replace").strip()[:200]
    return result


def all_up(docs):
    active = units_active()
    answers = health(docs)
    ok = all(state == "active" for state in active.values()) and all(code == "200" for code in answers.values())
    return ok, {"units": active, "health": answers}


def wait_until_up(docs):
    deadline = time.monotonic() + wait_seconds(HEALTH_WAIT_SECONDS)
    while True:
        ok, seen = all_up(docs)
        if ok or time.monotonic() >= deadline:
            return ok, seen
        time.sleep(1)


def restart_services():
    """Stop ES, restart EGS and AGS, start ES: ES loads EGS's trust policy
    when it starts, so it starts last, after EGS signs with the key ES now
    trusts."""
    systemctl("stop", "es")
    systemctl("restart", "egs")
    systemctl("restart", "ags")
    systemctl("start", "es")


# Keys.

def openssl_der(args, data=None):
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    try:
        proc = subprocess.run([openssl(), *args], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=30, env=env, start_new_session=True, check=False)
    except subprocess.TimeoutExpired:
        raise Refusal(f"openssl {args[0]} did not finish within 30 s") from None
    except OSError as exc:
        raise Refusal(f"cannot run {openssl()}: {exc.strerror}") from None
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
    problems = []
    if signer.get("algorithm") != "ed25519":
        problems.append(f"{name}.json signer.algorithm is not ed25519")
    if not isinstance(signer.get("key_id"), str) or not signer["key_id"]:
        problems.append(f"{name}.json has no signer.key_id")
    if not (is_hex(signer.get("private_key_hex"), 64) or is_hex(signer.get("private_key_hex"), 128)):
        problems.append(f"{name}.json signer.private_key_hex is not a 32- or 64-byte key in lower-case hex")
    if not is_hex(signer.get("public_key_hex"), 64):
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
    the AGS key, EGS allows the AGS key, and every grant names it."""
    problems = signer_problems("ags", docs["ags"].get("signer")) + signer_problems("egs", docs["egs"].get("signer"))
    if problems:
        return problems
    signers = {"ags": docs["ags"]["signer"], "egs": docs["egs"]["signer"]}
    if signers["ags"]["public_key_hex"] == signers["egs"]["public_key_hex"]:
        problems.append("AGS and EGS sign with the same key")
    verification = docs["es"].get("verification")
    if not isinstance(verification, dict):
        return problems + ["es.json has no verification object"]
    for entry, role in VERIFICATION_FROM:
        want = public_part(signers[role])
        if verification.get(entry) != want:
            problems.append(f"es.json verification.{entry} is not {role.upper()}'s signer key")
    runtime_trust = docs["egs"].get("runtime_trust")
    policy = runtime_trust.get("signer_policy") if isinstance(runtime_trust, dict) else None
    if not isinstance(policy, dict):
        problems.append("egs.json has no runtime_trust.signer_policy")
    else:
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


def planned_changes(docs):
    """What rotate changes in configs that consistency_problems accepts."""
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


def ars_index_entries():
    """How many records ARS's index holds (a count only), or None."""
    try:
        data, _ = read_regular_file(host(ARS_CONFIG))
        index_file = (json.loads(data).get("storage") or {}).get("index_file")
        if not isinstance(index_file, str) or not os.path.isabs(index_file):
            return None
        index, _ = read_regular_file(host(index_file))
        doc = json.loads(index)
    except (OSError, ValueError, Refusal, AttributeError):
        return None
    return len(doc) if isinstance(doc, (dict, list)) else None


# Inspection.

def read_configs():
    """Each config's document, bytes and file record; refuses a file that is
    not root:<service> 0640 or not a JSON object."""
    docs, files, problems = {}, {}, []
    for name, path, group in CONFIGS:
        data, st = read_regular_file(host(path))
        files[name] = {"path": path, "sha256": sha256_hex(data), "size": len(data), "uid": st.st_uid,
                       "gid": st.st_gid, "mode": format(stat.S_IMODE(st.st_mode), "04o")}
        if st.st_uid != root_uid() or st.st_gid != group_id(group) or stat.S_IMODE(st.st_mode) != CONFIG_MODE \
                or st.st_nlink != 1:
            problems.append(f"{path} is not root:{group} {CONFIG_MODE:04o} with one link")
        try:
            doc = json.loads(data)
        except ValueError:
            raise Refusal(f"{path} is not JSON")
        if not isinstance(doc, dict):
            raise Refusal(f"{path} is not a JSON object")
        docs[name] = doc
    return docs, files, problems


def inspect():
    report = {"schema": SCHEMA, "host_root": HOST_ROOT}
    docs, files, problems = read_configs()
    report["files"] = files
    problems += consistency_problems(docs)
    if not problems:
        report["current"] = {
            role: dict(public_part(docs[role]["signer"]),
                       private_seed_is_one_byte_repeated=seed_is_one_byte(docs[role]["signer"]))
            for role in ("ags", "egs")
        }
        report["workload_grant_rules"] = len(grant_rules(docs["es"]))
    ok, seen = all_up(docs)
    report["before"] = seen
    if not ok:
        problems.append("AGS, EGS and ES must all run, and ES and AGS answer 200, before the rotation")
    report["ars_index_entries"] = ars_index_entries()
    report["problems"] = problems
    return report, docs


# Backups.

def backup_root_ready():
    root = host(BACKUP_ROOT)
    try:
        os.mkdir(root, 0o700)
    except FileExistsError:
        pass
    st = os.lstat(root)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != root_uid():
        raise Refusal(f"{BACKUP_ROOT} must be a directory root owns")
    os.chmod(root, 0o700)
    return root


def backup_configs(backup_dir):
    """Copy the three configs into a new 0700 directory with a manifest of
    their bytes, owners and modes. The copies hold the old private keys, so
    they are 0600 and the directory is root's alone."""
    os.mkdir(backup_dir, 0o700)
    os.chmod(backup_dir, 0o700)
    entries = []
    for name, path, _ in CONFIGS:
        data, st = read_regular_file(host(path))
        copy = f"{name}.json"
        write_new_file(os.path.join(backup_dir, copy), data)
        entries.append({"path": path, "copy": copy, "sha256": sha256_hex(data), "size": len(data),
                        "uid": st.st_uid, "gid": st.st_gid, "mode": format(stat.S_IMODE(st.st_mode), "04o")})
    write_new_file(os.path.join(backup_dir, BACKUP_MANIFEST),
                   (json.dumps({"schema": BACKUP_SCHEMA, "files": entries}, indent=2) + "\n").encode())
    sync_dir(backup_dir)


def restore_configs(backup_dir):
    """Put every config of a backup back with its bytes, owner and mode,
    after checking the whole backup."""
    st = os.lstat(backup_dir)
    if not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o700 or st.st_uid != os.geteuid():
        raise Refusal("the backup directory must be a 0700 directory owned by the user running the restore")
    data, _ = read_regular_file(os.path.join(backup_dir, BACKUP_MANIFEST))
    manifest = json.loads(data)
    expected = [path for _, path, _ in CONFIGS]
    if manifest.get("schema") != BACKUP_SCHEMA or [e.get("path") for e in manifest.get("files", [])] != expected:
        raise Refusal("the backup manifest is not one of this rotation")
    copies = []
    for entry in manifest["files"]:
        if entry.get("copy") not in ("egs.json", "ags.json", "es.json"):
            raise Refusal("the backup manifest names an unexpected copy")
        copy, _ = read_regular_file(os.path.join(backup_dir, entry["copy"]))
        if sha256_hex(copy) != entry["sha256"] or len(copy) != entry["size"]:
            raise Refusal(f"the backup copy of {entry['path']} does not match its manifest")
        copies.append((entry, copy))
    restored = []
    for entry, copy in copies:
        atomic_replace(host(entry["path"]), copy, entry["uid"], entry["gid"], int(entry["mode"], 8))
        after, _ = read_regular_file(host(entry["path"]))
        if sha256_hex(after) != entry["sha256"]:
            raise Refusal(f"{entry['path']} does not match its backup after the restore")
        restored.append(entry["path"])
    return restored


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


def write_summary(path, report):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(report, indent=2, sort_keys=True) + "\n")


INTERRUPT_SIGNALS = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)


def ignore_interrupts():
    for signum in INTERRUPT_SIGNALS:
        signal.signal(signum, signal.SIG_IGN)


def raise_interrupted(signum, _frame):
    ignore_interrupts()
    raise Interrupted(f"signal {signum}")


def require_root():
    if not test_mode() and os.geteuid() != 0:
        raise Refusal("run it as root")


def cmd_check(_args):
    require_root()
    report, docs = inspect()
    report["mode"] = "check"
    if not report["problems"]:
        report["changes"] = planned_changes(docs)
        report["result"] = "ready"
    say(json.dumps(report, indent=2, sort_keys=True))
    if report["problems"]:
        raise Refusal(f"{len(report['problems'])} problem(s); nothing was changed")


def cmd_apply(_args):
    require_root()
    events = []

    def log(message):
        events.append({"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": message})
        say(message, sys.stderr)

    report, docs = inspect()
    report["mode"] = "apply"
    report["events"] = events
    if report["problems"]:
        say(json.dumps(report, indent=2, sort_keys=True))
        raise Refusal(f"{len(report['problems'])} problem(s); nothing was changed")

    ags_new, egs_new = new_signer("ags"), new_signer("egs")
    if ags_new["public_key_hex"] == egs_new["public_key_hex"]:
        raise Refusal("openssl gave AGS and EGS the same key; nothing was changed")
    report["changes"] = planned_changes(docs)
    rotated = rotate(docs, ags_new, egs_new)
    report["new"] = {"ags": public_part(ags_new), "egs": public_part(egs_new)}
    data = {name: render_json(rotated[name]) for name, _, _ in CONFIGS}

    backup_dir = os.path.join(backup_root_ready(),
                              time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + ags_new["key_id"])
    backup_configs(backup_dir)
    report["backup_dir"] = backup_dir
    summary_path = os.path.join(backup_dir, "summary.json")
    log("backup written to " + backup_dir)

    # From here on, any failure or interruption puts the backup back.
    failure = None
    for signum in INTERRUPT_SIGNALS:
        signal.signal(signum, raise_interrupted)
    try:
        try:
            for name, path, group in CONFIGS:
                atomic_replace(host(path), data[name], root_uid(), group_id(group), CONFIG_MODE)
                written, _ = read_regular_file(host(path))
                if written != data[name]:
                    raise Refusal(f"{path} does not hold the rotated config after the write")
                log(f"{path} written")
            restart_services()
            log("es stopped, egs and ags restarted, es started")
            ok, report["after"] = wait_until_up(rotated)
            if not ok:
                raise Refusal("AGS, EGS and ES do not all run and answer after the restart")
            report["result"] = "rotated"
            ignore_interrupts()
        except BaseException as exc:  # noqa: BLE001 - every failure after the backup rolls back
            failure = exc
            ignore_interrupts()
    except Interrupted as exc:
        failure = failure if failure is not None else exc
    if failure is not None:
        log(f"apply failed: {failure}; rolling back")
        report["failure"] = str(failure)
        try:
            report["rollback"] = restore_configs(backup_dir)
            restart_services()
        except Exception as rexc:  # noqa: BLE001
            report["result"] = "rollback_failed"
            report["rollback_failure"] = str(rexc)
        else:
            ok, report["after_rollback"] = wait_until_up(docs)
            report["result"] = "rolled_back" if ok else "rolled_back_unhealthy"
        report["output_lost"] = OUTPUT["lost"]
        write_summary(summary_path, report)
        say(json.dumps(report, indent=2, sort_keys=True))
        raise Refusal(f"apply failed; result {report['result']}; summary {summary_path}")
    report["output_lost"] = OUTPUT["lost"]
    write_summary(summary_path, report)
    say(json.dumps(report, indent=2, sort_keys=True))
    log("summary written to " + summary_path)


def cmd_rollback(args):
    require_root()
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    restored = restore_configs(args.backup_dir)
    restart_services()
    docs, _, _ = read_configs()
    ok, after = wait_until_up(docs)
    say(json.dumps({"schema": SCHEMA, "mode": "rollback", "restored": restored, "after": after,
                    "result": "rolled_back" if ok else "rolled_back_unhealthy"}, indent=2, sort_keys=True))
    if not ok:
        raise Refusal("AGS, EGS and ES do not all run and answer after the rollback")


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
    global HOST_ROOT
    if args.host_root != "/" and not os.path.isabs(args.host_root):
        print("remote alpha signing key rotation refused: --host-root must be absolute", file=sys.stderr)
        return 2
    HOST_ROOT = args.host_root
    try:
        args.func(args)
    except (Refusal, OSError) as exc:
        say(f"remote alpha signing key rotation refused: {exc}", sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
