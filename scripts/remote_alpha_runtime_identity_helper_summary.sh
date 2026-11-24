#!/usr/bin/env bash
set -euo pipefail
set +x
umask 077

remote_alpha_runtime_identity_helper_schema="execution-substrate.remote-runtime-identity-helper-summary.v1alpha1"
remote_alpha_runtime_identity_helper_default_output="/var/tmp/execution-substrate-remote-alpha/runtime-identity-helper-summary.json"

# Copy of remote_alpha_prepare_output_dir from scripts/internal/remote_alpha_output_dir.sh,
# which explains it; TestRemoteAlphaOutputDirCopiesMatch keeps the two identical.
remote_alpha_prepare_output_dir() {
  python3 -I - "$1" <<'REMOTE_ALPHA_OUTPUT_DIR_PY'
import os
import stat
import sys

if not sys.argv[1]:
    sys.exit("remote alpha output folder: no folder given")
parts = [part for part in os.path.abspath(sys.argv[1]).split("/") if part]
trusted = {0, os.geteuid()}
if os.environ.get("SUDO_UID", "").isdigit():
    trusted.add(int(os.environ["SUDO_UID"]))
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
shown = "/"
fd = os.open("/", flags)
try:
    for index in range(len(parts) + 1):
        info = os.fstat(fd)
        last = index == len(parts)
        if info.st_uid not in trusted:
            sys.exit(
                f"remote alpha output folder: {shown} belongs to uid {info.st_uid}, not to root, "
                "the user running this step or the user who ran sudo; refusing to write under it"
            )
        if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH) and (
            last or info.st_uid != 0 or not info.st_mode & stat.S_ISVTX
        ):
            sys.exit(f"remote alpha output folder: {shown} can be written by its group or others; refusing to write under it")
        if last:
            break
        shown = "/" + "/".join(parts[: index + 1])
        try:
            next_fd = os.open(parts[index], flags, dir_fd=fd)
        except FileNotFoundError:
            try:
                os.mkdir(parts[index], 0o755, dir_fd=fd)
            except FileExistsError:
                pass
            next_fd = os.open(parts[index], flags, dir_fd=fd)
        os.close(fd)
        fd = next_fd
except OSError as exc:
    sys.exit(f"remote alpha output folder: {shown} is not a directory or is a symbolic link ({exc.strerror})")
finally:
    os.close(fd)
REMOTE_ALPHA_OUTPUT_DIR_PY
}

remote_alpha_runtime_identity_helper_usage() {
  cat <<'EOF'
Usage:
  sudo scripts/remote_alpha_runtime_identity_helper_summary.sh

Optional flags:
  --output <runtime-identity-helper-summary.json>
  --dry-run
  --check-only
  --pretty
  --runtime-support-path </usr/local/bin/es-runtime-support>
  --spire-agent-socket-path </run/spire/sockets/agent.sock>
  --spire-server-socket-path </run/spire/server/private/api.sock>
  --workload-spiffe-id <spiffe://execution.internal/workload>
  --audience <vault>
  --help

Default behavior writes the non-secret Remote Alpha runtime identity helper
summary expected by Infrastructure Manager. The summary is evidence only: it
does not run the CP/ES proof, does not claim submit readiness, and does not
persist JWT-SVID bodies, private keys, Vault tokens, API keys, or secret
payloads.

--dry-run/--check-only prints a non-secret diagnostic summary to stdout, skips
the SPIRE JWT fetch smoke, and does not write the output file.
EOF
}

remote_alpha_runtime_identity_helper_main() {
  local output_path="${REMOTE_ALPHA_RUNTIME_IDENTITY_HELPER_SUMMARY_PATH:-${remote_alpha_runtime_identity_helper_default_output}}"
  local dry_run=0
  local pretty=0
  local runtime_support_path="${REMOTE_ALPHA_RUNTIME_SUPPORT_PATH:-/usr/local/bin/es-runtime-support}"
  local spire_agent_socket_path="${REMOTE_ALPHA_SPIRE_AGENT_SOCKET_PATH:-/run/spire/sockets/agent.sock}"
  local spire_server_socket_path="${REMOTE_ALPHA_SPIRE_SERVER_SOCKET_PATH:-/run/spire/server/private/api.sock}"
  local workload_spiffe_id="${REMOTE_ALPHA_WORKLOAD_SPIFFE_ID:-spiffe://execution.internal/workload}"
  local audience="${REMOTE_ALPHA_SPIRE_JWT_AUDIENCE:-vault}"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --output)
        output_path="$2"
        shift 2
        ;;
      --dry-run|--check-only)
        dry_run=1
        shift
        ;;
      --pretty)
        pretty=1
        shift
        ;;
      --runtime-support-path)
        runtime_support_path="$2"
        shift 2
        ;;
      --spire-agent-socket-path)
        spire_agent_socket_path="$2"
        shift 2
        ;;
      --spire-server-socket-path)
        spire_server_socket_path="$2"
        shift 2
        ;;
      --workload-spiffe-id)
        workload_spiffe_id="$2"
        shift 2
        ;;
      --audience)
        audience="$2"
        shift 2
        ;;
      --help|-h)
        remote_alpha_runtime_identity_helper_usage
        return 0
        ;;
      *)
        echo "unknown argument: $1" >&2
        remote_alpha_runtime_identity_helper_usage >&2
        return 2
        ;;
    esac
  done

  if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required" >&2
    return 1
  fi
  if [[ "${dry_run}" != "1" ]]; then
    remote_alpha_prepare_output_dir "$(dirname "${output_path}")" || return 1
  fi

  REMOTE_ALPHA_RUNTIME_IDENTITY_HELPER_SCHEMA="${remote_alpha_runtime_identity_helper_schema}" \
  REMOTE_ALPHA_RUNTIME_IDENTITY_HELPER_OUTPUT="${output_path}" \
  REMOTE_ALPHA_RUNTIME_IDENTITY_HELPER_DRY_RUN="${dry_run}" \
  REMOTE_ALPHA_RUNTIME_IDENTITY_HELPER_PRETTY="${pretty}" \
  REMOTE_ALPHA_RUNTIME_SUPPORT_PATH="${runtime_support_path}" \
  REMOTE_ALPHA_SPIRE_AGENT_SOCKET_PATH="${spire_agent_socket_path}" \
  REMOTE_ALPHA_SPIRE_SERVER_SOCKET_PATH="${spire_server_socket_path}" \
  REMOTE_ALPHA_WORKLOAD_SPIFFE_ID="${workload_spiffe_id}" \
  REMOTE_ALPHA_SPIRE_JWT_AUDIENCE="${audience}" \
  python3 <<'PY'
import datetime
import getpass
import grp
import hashlib
import json
import os
import pathlib
import pwd
import re
import socket
import stat
import subprocess
import sys

SCHEMA = os.environ["REMOTE_ALPHA_RUNTIME_IDENTITY_HELPER_SCHEMA"]
OUTPUT = pathlib.Path(os.environ["REMOTE_ALPHA_RUNTIME_IDENTITY_HELPER_OUTPUT"])
DRY_RUN = os.environ["REMOTE_ALPHA_RUNTIME_IDENTITY_HELPER_DRY_RUN"] == "1"
PRETTY = os.environ["REMOTE_ALPHA_RUNTIME_IDENTITY_HELPER_PRETTY"] == "1"
RUNTIME_SUPPORT_PATH = pathlib.Path(os.environ["REMOTE_ALPHA_RUNTIME_SUPPORT_PATH"])
SPIRE_AGENT_SOCKET_PATH = os.environ["REMOTE_ALPHA_SPIRE_AGENT_SOCKET_PATH"]
SPIRE_SERVER_SOCKET_PATH = os.environ["REMOTE_ALPHA_SPIRE_SERVER_SOCKET_PATH"]
WORKLOAD_SPIFFE_ID = os.environ["REMOTE_ALPHA_WORKLOAD_SPIFFE_ID"]
AUDIENCE = os.environ["REMOTE_ALPHA_SPIRE_JWT_AUDIENCE"]

SECRET_PATTERNS = [
    re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    re.compile(r"(?:^|[^A-Za-z0-9])(?:hvs|s|b)\.[A-Za-z0-9._-]{12,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----"),
    re.compile(r"(?i)(unseal[_ -]?key|root[_ -]?token|client[_ -]?token)\s*[:=]\s*[A-Za-z0-9+/=._-]{8,}"),
    re.compile(r"(?i)(api[_ -]?key|credential|raw[_ -]?secret[_ -]?payload)\s*[:=]\s*[A-Za-z0-9+/=._-]{8,}"),
]


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sanitize(value, *, max_len=240):
    text = str(value or "")
    for pattern in SECRET_PATTERNS:
        text = pattern.sub("<redacted>", text)
    text = text.replace("\x00", "")
    if len(text) > max_len:
        text = text[: max_len - 3] + "..."
    return text


def run_command(args, *, timeout=10, discard_stdout=False, sanitize_stdout=True):
    try:
        proc = subprocess.run(
            args,
            check=False,
            text=True,
            stdout=subprocess.DEVNULL if discard_stdout else subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except FileNotFoundError:
        return {
            "ok": False,
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "error": f"command not found: {args[0]}",
        }
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "error": f"command timed out: {args[0]}",
        }
    return {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "stdout": "" if discard_stdout else (sanitize(proc.stdout) if sanitize_stdout else (proc.stdout or "")),
        "stderr": sanitize(proc.stderr),
        "error": "",
    }


def command_status(args, *, timeout=10):
    proc = run_command(args, timeout=timeout)
    output = (proc.get("stdout") or proc.get("stderr") or proc.get("error") or "").strip()
    return {
        "status": "pass" if proc["ok"] else "fail",
        "returncode": proc["returncode"],
        "detail": output.splitlines()[0] if output else "",
    }


def systemctl_is_active(service_name):
    proc = run_command(["systemctl", "is-active", service_name], timeout=5)
    if proc["returncode"] is None:
        return "unknown"
    value = (proc["stdout"] or proc["stderr"]).strip().splitlines()
    return value[0] if value else ("active" if proc["ok"] else "unknown")


def stat_payload(path):
    payload = {
        "path": os.fspath(path),
        "exists": False,
        "executable": False,
        "is_socket": False,
        "mode": "",
        "owner": "",
        "group": "",
        "size_bytes": None,
        "sha256": "",
    }
    try:
        info = os.lstat(path)
    except OSError as exc:
        payload["error"] = sanitize(exc)
        return payload
    payload.update(
        {
            "exists": True,
            "executable": bool(info.st_mode & stat.S_IXUSR),
            "is_socket": stat.S_ISSOCK(info.st_mode),
            "mode": stat.filemode(info.st_mode),
            "size_bytes": info.st_size,
        }
    )
    try:
        payload["owner"] = pwd.getpwuid(info.st_uid).pw_name
    except KeyError:
        payload["owner"] = str(info.st_uid)
    try:
        payload["group"] = grp.getgrgid(info.st_gid).gr_name
    except KeyError:
        payload["group"] = str(info.st_gid)
    if stat.S_ISREG(info.st_mode):
        try:
            digest = hashlib.sha256()
            with open(path, "rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            payload["sha256"] = digest.hexdigest()
        except OSError as exc:
            payload["sha256_error"] = sanitize(exc)
    return payload


def helper_binary_payload():
    payload = stat_payload(RUNTIME_SUPPORT_PATH)
    if payload["exists"] and payload["executable"]:
        proc = run_command([os.fspath(RUNTIME_SUPPORT_PATH)], timeout=5)
        text = (proc.get("stdout") or proc.get("stderr") or proc.get("error") or "").strip()
        payload["help_excerpt"] = [text.splitlines()[0]] if text else []
    else:
        payload["help_excerpt"] = []
    payload["status"] = "pass" if payload["exists"] and payload["executable"] else "fail"
    return payload


def spire_server_command(*args):
    base = ["spire-server", *args]
    if SPIRE_SERVER_SOCKET_PATH:
        with_socket = [*base, "-socketPath", SPIRE_SERVER_SOCKET_PATH]
        proc = run_command(with_socket, timeout=10, sanitize_stdout=False)
        if proc["ok"]:
            return proc
    return run_command(base, timeout=10, sanitize_stdout=False)


def spire_health():
    agent = command_status(["spire-agent", "healthcheck", "-socketPath", SPIRE_AGENT_SOCKET_PATH], timeout=10)
    server_proc = spire_server_command("healthcheck")
    server_output = (server_proc.get("stdout") or server_proc.get("stderr") or server_proc.get("error") or "").strip()
    server = {
        "status": "pass" if server_proc["ok"] else "fail",
        "returncode": server_proc["returncode"],
        "detail": server_output.splitlines()[0] if server_output else "",
    }
    return {
        "spire_server_health": server["status"] == "pass",
        "spire_agent_health": agent["status"] == "pass",
        "spire_server_active": systemctl_is_active("spire-server"),
        "spire_agent_active": systemctl_is_active("spire-agent"),
        "server_healthcheck": server,
        "agent_healthcheck": agent,
    }


def parse_spire_entry(text):
    result = {
        "status": "not_found",
        "spiffe_id": "",
        "parent_id": "",
        "entry_id": "",
        "selectors": [],
        "entry_expires_at": None,
        "x509_svid_ttl": "",
        "jwt_svid_ttl": "",
        "alpha_root_selectors_present": False,
    }
    selectors = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower().replace(" ", "_").replace("-", "_")
        value = value.strip()
        if key == "spiffe_id":
            result["spiffe_id"] = value
        elif key == "parent_id":
            result["parent_id"] = value
        elif key == "entry_id":
            result["entry_id"] = value
        elif key == "selector":
            selectors.append(value)
        elif key in {"entry_expires_at", "entry_expiry"}:
            result["entry_expires_at"] = value or None
        elif key in {"x509_svid_ttl", "x509_svid_ttl_seconds"}:
            result["x509_svid_ttl"] = value
        elif key in {"jwt_svid_ttl", "jwt_svid_ttl_seconds"}:
            result["jwt_svid_ttl"] = value
    result["selectors"] = sorted(set(selectors))
    result["alpha_root_selectors_present"] = "unix:uid:0" in result["selectors"] and "unix:gid:0" in result["selectors"]
    if result["spiffe_id"] == WORKLOAD_SPIFFE_ID:
        result["status"] = "pass"
    return result


def spire_registration():
    proc = spire_server_command("entry", "show", "-spiffeID", WORKLOAD_SPIFFE_ID)
    payload = parse_spire_entry(proc.get("stdout") or "")
    payload["command_status"] = "pass" if proc["ok"] else "fail"
    if not proc["ok"]:
        payload["error"] = (proc.get("stderr") or proc.get("error") or "").splitlines()[0] if (proc.get("stderr") or proc.get("error")) else ""
    return payload


def trust_domain_from_spiffe_id():
    prefix = "spiffe://"
    if not WORKLOAD_SPIFFE_ID.startswith(prefix):
        return ""
    return WORKLOAD_SPIFFE_ID[len(prefix) :].split("/", 1)[0]


def spire_fetch_smoke():
    if DRY_RUN:
        return {
            "jwt": {
                "status": "not_proven",
                "reason": "dry_run_skips_jwt_svid_fetch",
                "output_discarded": True,
            }
        }
    attempts = [
        ["spire-agent", "api", "fetch", "jwt", "-socketPath", SPIRE_AGENT_SOCKET_PATH, "-audience", AUDIENCE],
        ["spire-agent", "api", "fetch", "jwt", "-socketPath", SPIRE_AGENT_SOCKET_PATH, "-audience", AUDIENCE, "-output", "json"],
        ["spire-agent", "api", "fetch", "jwt", "-socketPath", SPIRE_AGENT_SOCKET_PATH, "-audience", AUDIENCE, "-write", "/dev/stdout"],
    ]
    if os.geteuid() != 0:
        return {
            "jwt": {
                "status": "not_proven",
                "reason": "root_required_for_helper_local_spire_fetch_smoke",
                "output_discarded": True,
            }
        }
    for args in attempts:
        proc = run_command(args, timeout=10, discard_stdout=True)
        if proc["ok"]:
            return {
                "jwt": {
                    "status": "pass",
                    "audience": AUDIENCE,
                    "output_discarded": True,
                }
            }
    return {
        "jwt": {
            "status": "fail",
            "audience": AUDIENCE,
            "output_discarded": True,
            "error": "SPIRE JWT fetch smoke failed without recording JWT-SVID output",
        }
    }


def can_connect_socket_as(uid, gid):
    if os.geteuid() != 0:
        return "unknown"
    pid = os.fork()
    if pid == 0:
        try:
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.settimeout(1)
            try:
                client.connect(SPIRE_AGENT_SOCKET_PATH)
            finally:
                client.close()
            os._exit(10)
        except Exception:
            os._exit(11)
    _, status_code = os.waitpid(pid, 0)
    if os.WIFEXITED(status_code) and os.WEXITSTATUS(status_code) == 10:
        return "true"
    if os.WIFEXITED(status_code) and os.WEXITSTATUS(status_code) == 11:
        return "false"
    return "unknown"


def direct_socket_access_for_user(name):
    try:
        record = pwd.getpwnam(name)
    except KeyError:
        return "unknown"
    return can_connect_socket_as(record.pw_uid, record.pw_gid)


def docker_group_members():
    try:
        record = grp.getgrnam("docker")
    except KeyError:
        return []
    return sorted(record.gr_mem)


def ds_in_docker_group():
    try:
        groups = [g.gr_name for g in grp.getgrall() if "ds" in g.gr_mem]
        primary = grp.getgrgid(pwd.getpwnam("ds").pw_gid).gr_name
        groups.append(primary)
    except KeyError:
        return "unknown"
    return "docker" in set(groups)


def passwordless_sudo_for_ds():
    if os.geteuid() != 0:
        return "unknown"
    if not pathlib.Path("/usr/bin/sudo").exists() and not pathlib.Path("/bin/sudo").exists():
        return "unknown"
    proc = run_command(["sudo", "-u", "ds", "-H", "sh", "-lc", "sudo -n true >/dev/null 2>&1"], timeout=5)
    return "true" if proc["ok"] else "false"


def exposure_checks():
    uid_10000_access = "unknown"
    if os.geteuid() == 0:
        uid_10000_access = can_connect_socket_as(10000, 10000)
    return {
        "ds_in_docker_group": ds_in_docker_group(),
        "docker_group_members": docker_group_members(),
        "passwordless_sudo_for_ds": passwordless_sudo_for_ds(),
        "ds_direct_socket_access": direct_socket_access_for_user("ds"),
        "uid_10000_direct_socket_access": uid_10000_access,
    }


def docker_readiness():
    active = systemctl_is_active("docker")
    info = command_status(["docker", "info"], timeout=10)
    return {
        "service_active": active,
        "docker_info": info["status"],
        "ready": active == "active" and info["status"] == "pass",
    }


def nomad_readiness():
    active = systemctl_is_active("nomad")
    proc = run_command(["nomad", "node", "status", "-json"], timeout=10, sanitize_stdout=False)
    node_ready = False
    node_count = 0
    if proc["ok"] and proc["stdout"]:
        try:
            nodes = json.loads(proc["stdout"])
            if isinstance(nodes, list):
                node_count = len(nodes)
                node_ready = any(isinstance(item, dict) and str(item.get("Status", "")).lower() == "ready" for item in nodes)
        except Exception:
            node_ready = False
    return {
        "service_active": active,
        "node_status": "pass" if proc["ok"] else "fail",
        "node_count": node_count,
        "node_ready": node_ready,
        "ready": active == "active" and node_ready,
    }


def validate_summary_text(text):
    for pattern in SECRET_PATTERNS:
        if pattern.search(text):
            raise SystemExit(f"refusing to write summary with secret-like material matching {pattern.pattern}")


def write_json(payload):
    text = json.dumps(payload, sort_keys=True, indent=2 if PRETTY else None)
    text += "\n"
    validate_summary_text(text)
    if DRY_RUN:
        sys.stdout.write(text)
        return
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    tmp = OUTPUT.with_name(f".{OUTPUT.name}.tmp.{os.getpid()}")
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chmod(tmp, 0o644)
    os.replace(tmp, OUTPUT)
    os.chmod(OUTPUT, 0o644)
    print(f"wrote {OUTPUT}")


generated_at = utc_now()
helper = helper_binary_payload()
health = spire_health()
registration = spire_registration()
socket_info = stat_payload(pathlib.Path(SPIRE_AGENT_SOCKET_PATH))
fetch_smoke = spire_fetch_smoke()
exposure = exposure_checks()
docker = docker_readiness()
nomad = nomad_readiness()

reasons = []
if helper.get("status") != "pass":
    reasons.append("runtime_support_binary_missing_or_not_executable")
if health.get("spire_server_health") is not True:
    reasons.append("spire_server_health_failed")
if health.get("spire_agent_health") is not True:
    reasons.append("spire_agent_health_failed")
if registration.get("status") != "pass":
    reasons.append("workload_registration_missing")
if registration.get("alpha_root_selectors_present") is not True:
    reasons.append("alpha_root_selectors_not_observed")
if fetch_smoke.get("jwt", {}).get("status") != "pass":
    reasons.append("helper_local_jwt_fetch_not_proven")
if exposure.get("ds_direct_socket_access") != "false":
    reasons.append("ds_raw_spire_socket_access_not_proven_absent")
if exposure.get("uid_10000_direct_socket_access") != "false":
    reasons.append("uid_10000_raw_spire_socket_access_not_proven_absent")
if docker.get("ready") is not True:
    reasons.append("docker_readiness_not_proven")
if nomad.get("ready") is not True:
    reasons.append("nomad_readiness_not_proven")

if DRY_RUN:
    overall_status = "dry_run"
elif reasons:
    overall_status = "fail"
else:
    overall_status = "pass"

payload = {
    "schema": SCHEMA,
    "generated_at": generated_at,
    "checked_at": generated_at,
    "mode": "dry_run" if DRY_RUN else "generate",
    "host": {
        "hostname": socket.gethostname(),
        "effective_user": getpass.getuser(),
        "effective_uid": os.geteuid(),
    },
    "helper_binary": helper,
    "health": {
        "spire_server_health": health["spire_server_health"],
        "spire_agent_health": health["spire_agent_health"],
        "spire_server_active": health["spire_server_active"],
        "spire_agent_active": health["spire_agent_active"],
        "docker_active": docker["service_active"],
        "nomad_active": nomad["service_active"],
        "nomad_node_ready": nomad["node_ready"],
    },
    "spire": {
        "trust_domain": trust_domain_from_spiffe_id(),
        "workload_spiffe_id": WORKLOAD_SPIFFE_ID,
        "workload_api_socket": socket_info,
        "server_healthcheck": health["server_healthcheck"],
        "agent_healthcheck": health["agent_healthcheck"],
        "registration": registration,
        "fetch_smoke": fetch_smoke,
    },
    "exposure_checks": exposure,
    "docker_readiness": docker,
    "nomad_readiness": nomad,
    "runtime_identity_helper_local_fetch": "pass" if fetch_smoke.get("jwt", {}).get("status") == "pass" else "not_proven",
    "overall_status": overall_status,
    "reasons": reasons,
    "readiness_not_claimed": [
        "submit_ready",
        "runtime_profile_ready",
        "control_plane_proof",
        "vault_readiness",
    ],
    "non_authority_labels": [
        "evidence_only",
        "not_cp_run_control",
        "not_es_submit_authority",
        "not_runtime_profile_readiness",
        "not_milestone_3_proof",
        "not_production_readiness",
    ],
    "redaction": {
        "jwt_svid_bodies": "not_recorded",
        "x509_svid_bodies": "not_recorded",
        "private_keys": "not_recorded",
        "vault_tokens": "not_recorded",
        "api_keys": "not_recorded",
        "raw_prompts": "not_recorded",
    },
}

write_json(payload)
if not DRY_RUN and overall_status != "pass":
    print("runtime identity helper summary did not pass all checks", file=sys.stderr)
    raise SystemExit(1)
PY
}

remote_alpha_runtime_identity_helper_main "$@"
