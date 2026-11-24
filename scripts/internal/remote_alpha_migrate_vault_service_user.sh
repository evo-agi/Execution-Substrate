#!/usr/bin/env bash
set -euo pipefail

remote_alpha_migrate_vault_service_user_summary_schema_version="execution-substrate.remote-alpha.vault-service-user-migration-summary.v1"
remote_alpha_migrate_vault_service_user_default_artifact_root="/var/tmp/execution-substrate-remote-alpha"
remote_alpha_migrate_vault_service_user_non_authority_labels=(
  "not_service_health"
  "not_submit_readiness"
  "not_runtime_profile_readiness"
  "not_producer_contract_compatibility"
  "not_retained_result_readiness"
  "not_governed_proof"
  "not_workload_credential_success_proof"
  "not_vault_production_ready"
  "not_support_bundle_authority"
)

remote_alpha_migrate_vault_service_user_defaults() {
  REMOTE_ALPHA_OPERATION_MODE="check_only"
  REMOTE_ALPHA_SERVICE_NAME="${REMOTE_ALPHA_SERVICE_NAME:-vault}"
  REMOTE_ALPHA_SERVICE_USER="${REMOTE_ALPHA_SERVICE_USER:-vault}"
  REMOTE_ALPHA_SERVICE_GROUP="${REMOTE_ALPHA_SERVICE_GROUP:-vault}"
  REMOTE_ALPHA_SERVICE_UNIT_PATH="${REMOTE_ALPHA_SERVICE_UNIT_PATH:-}"
  REMOTE_ALPHA_SERVICE_DROPIN_DIR="${REMOTE_ALPHA_SERVICE_DROPIN_DIR:-}"
  REMOTE_ALPHA_SERVICE_DROPIN_PATH="${REMOTE_ALPHA_SERVICE_DROPIN_PATH:-}"
  REMOTE_ALPHA_VAULT_CONFIG_PATH="${REMOTE_ALPHA_VAULT_CONFIG_PATH:-}"
  REMOTE_ALPHA_VAULT_HEALTH_URL="${REMOTE_ALPHA_VAULT_HEALTH_URL:-}"
  REMOTE_ALPHA_VAULT_HEALTH_CACERT_PATH="${REMOTE_ALPHA_VAULT_HEALTH_CACERT_PATH:-}"
  REMOTE_ALPHA_VAULT_AUDIT_PATH="${REMOTE_ALPHA_VAULT_AUDIT_PATH:-}"
  REMOTE_ALPHA_ES_CONFIG_PATH="${REMOTE_ALPHA_ES_CONFIG_PATH:-/etc/execution-substrate/es.json}"
  REMOTE_ALPHA_HEALTHCHECK_ENV_PATH="${REMOTE_ALPHA_HEALTHCHECK_ENV_PATH:-/etc/execution-substrate/healthcheck.env}"
  REMOTE_ALPHA_BACKUP_ROOT_DIR="${REMOTE_ALPHA_BACKUP_ROOT_DIR:-${remote_alpha_migrate_vault_service_user_default_artifact_root}}"
  REMOTE_ALPHA_PRECHECK_PATH="${REMOTE_ALPHA_PRECHECK_PATH:-${remote_alpha_migrate_vault_service_user_default_artifact_root}/vault-service-user-migration-check-only.json}"
  REMOTE_ALPHA_SUMMARY_PATH="${REMOTE_ALPHA_SUMMARY_PATH:-}"
  REMOTE_ALPHA_GOVERNED_SMOKE_PROFILE="${REMOTE_ALPHA_GOVERNED_SMOKE_PROFILE:-}"
  REMOTE_ALPHA_GOVERNED_SMOKE_COMMAND="${REMOTE_ALPHA_GOVERNED_SMOKE_COMMAND:-}"
}

remote_alpha_migrate_vault_service_user_finalize_paths() {
  if [[ -z "${REMOTE_ALPHA_SUMMARY_PATH}" ]]; then
    if [[ "${REMOTE_ALPHA_OPERATION_MODE}" == "apply" ]]; then
      REMOTE_ALPHA_SUMMARY_PATH="${remote_alpha_migrate_vault_service_user_default_artifact_root}/vault-service-user-migration-apply-summary.json"
    else
      REMOTE_ALPHA_SUMMARY_PATH="${remote_alpha_migrate_vault_service_user_default_artifact_root}/vault-service-user-migration-check-only.json"
    fi
  fi
}

remote_alpha_migrate_vault_service_user_usage() {
  cat <<'EOF'
Usage:
  sudo scripts/remote_alpha_migrate_vault_service_user.sh
  sudo scripts/remote_alpha_migrate_vault_service_user.sh --apply

Optional flags:
  --check-only
  --dry-run
  --apply
  --summary-path </path/to/vault-service-user-migration-check-only.json>
  --preflight-path </path/to/vault-service-user-migration-check-only.json>
  --service-name <vault>
  --service-user <vault>
  --service-group <vault>
  --service-unit-path </path/to/vault.service>
  --service-dropin-dir </path/to/vault.service.d>
  --service-dropin-path </path/to/vault.service.d/10-account.conf>
  --config-path </path/to/vault.hcl-or-json>
  --vault-health-url <https://host:8200/v1/sys/health>
  --vault-health-cacert-path </path/to/ca.pem>
  --audit-path </path/to/audit.log>
  --es-config-path </path/to/es.json>
  --healthcheck-env-path </path/to/healthcheck.env>
  --backup-root-dir </path/to/backup-root>
  --governed-smoke-profile <documented-profile-name>
  --governed-smoke-command <shell command>
  --help

Default behavior is non-mutating check-only. Apply requires --apply. This
helper is bounded Vault host/service hardening only; it does not claim Vault
production readiness, governed execution proof, full ES/runtime de-root, full
Nomad client de-root, or SPIRE redesign.
EOF
}

remote_alpha_migrate_vault_service_user_parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --check-only|--dry-run)
        REMOTE_ALPHA_OPERATION_MODE="check_only"
        shift
        ;;
      --apply)
        REMOTE_ALPHA_OPERATION_MODE="apply"
        shift
        ;;
      --summary-path)
        REMOTE_ALPHA_SUMMARY_PATH="$2"
        shift 2
        ;;
      --preflight-path)
        REMOTE_ALPHA_PRECHECK_PATH="$2"
        shift 2
        ;;
      --service-name)
        REMOTE_ALPHA_SERVICE_NAME="$2"
        shift 2
        ;;
      --service-user)
        REMOTE_ALPHA_SERVICE_USER="$2"
        shift 2
        ;;
      --service-group)
        REMOTE_ALPHA_SERVICE_GROUP="$2"
        shift 2
        ;;
      --service-unit-path)
        REMOTE_ALPHA_SERVICE_UNIT_PATH="$2"
        shift 2
        ;;
      --service-dropin-dir)
        REMOTE_ALPHA_SERVICE_DROPIN_DIR="$2"
        shift 2
        ;;
      --service-dropin-path)
        REMOTE_ALPHA_SERVICE_DROPIN_PATH="$2"
        shift 2
        ;;
      --config-path)
        REMOTE_ALPHA_VAULT_CONFIG_PATH="$2"
        shift 2
        ;;
      --vault-health-url)
        REMOTE_ALPHA_VAULT_HEALTH_URL="$2"
        shift 2
        ;;
      --vault-health-cacert-path)
        REMOTE_ALPHA_VAULT_HEALTH_CACERT_PATH="$2"
        shift 2
        ;;
      --audit-path)
        REMOTE_ALPHA_VAULT_AUDIT_PATH="$2"
        shift 2
        ;;
      --es-config-path)
        REMOTE_ALPHA_ES_CONFIG_PATH="$2"
        shift 2
        ;;
      --healthcheck-env-path)
        REMOTE_ALPHA_HEALTHCHECK_ENV_PATH="$2"
        shift 2
        ;;
      --backup-root-dir)
        REMOTE_ALPHA_BACKUP_ROOT_DIR="$2"
        shift 2
        ;;
      --governed-smoke-profile)
        REMOTE_ALPHA_GOVERNED_SMOKE_PROFILE="$2"
        shift 2
        ;;
      --governed-smoke-command)
        REMOTE_ALPHA_GOVERNED_SMOKE_COMMAND="$2"
        shift 2
        ;;
      --help|-h)
        remote_alpha_migrate_vault_service_user_usage
        return 1
        ;;
      *)
        echo "unknown argument: $1" >&2
        remote_alpha_migrate_vault_service_user_usage >&2
        return 2
        ;;
    esac
  done
}

remote_alpha_migrate_vault_service_user_require_root() {
  if [[ "$(id -u)" != "0" ]]; then
    echo "remote alpha Vault service-user migration helper must run as root; use sudo scripts/remote_alpha_migrate_vault_service_user.sh" >&2
    return 1
  fi
}

remote_alpha_migrate_vault_service_user_public_wrapper_path() {
  local internal_dir
  internal_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  printf '%s\n' "$(cd "${internal_dir}/.." && pwd)/remote_alpha_migrate_vault_service_user.sh"
}

remote_alpha_migrate_vault_service_user_prepare_check_only_root_context() {
  local wrapper_path sudo_output rc

  if [[ "${REMOTE_ALPHA_OPERATION_MODE}" != "check_only" ]]; then
    return 0
  fi
  if [[ "$(id -u)" == "0" ]]; then
    return 0
  fi

  export REMOTE_ALPHA_VAULT_SERVICE_USER_PREREQUISITE_COMMAND="sudo -n true"
  export REMOTE_ALPHA_VAULT_SERVICE_USER_PREREQUISITE_ATTEMPTED="true"

  if command -v sudo >/dev/null 2>&1; then
    set +e
    sudo_output="$(sudo -n true 2>&1)"
    rc=$?
    set -e
    if [[ ${rc} -eq 0 ]]; then
      wrapper_path="$(remote_alpha_migrate_vault_service_user_public_wrapper_path)"
      exec sudo -n "${wrapper_path}" "$@"
    fi
    export REMOTE_ALPHA_VAULT_SERVICE_USER_PREREQUISITE_BLOCKED="true"
    export REMOTE_ALPHA_VAULT_SERVICE_USER_PREREQUISITE_REASON="noninteractive_root_unavailable"
    export REMOTE_ALPHA_VAULT_SERVICE_USER_PREREQUISITE_SUMMARY="noninteractive root/sudo unavailable"
    export REMOTE_ALPHA_VAULT_SERVICE_USER_PREREQUISITE_DETAIL="${sudo_output:-sudo -n true failed}"
    export REMOTE_ALPHA_VAULT_SERVICE_USER_PREREQUISITE_RETURN_CODE="${rc}"
    return 0
  fi

  export REMOTE_ALPHA_VAULT_SERVICE_USER_PREREQUISITE_BLOCKED="true"
  export REMOTE_ALPHA_VAULT_SERVICE_USER_PREREQUISITE_REASON="noninteractive_root_unavailable"
  export REMOTE_ALPHA_VAULT_SERVICE_USER_PREREQUISITE_SUMMARY="noninteractive root/sudo unavailable"
  export REMOTE_ALPHA_VAULT_SERVICE_USER_PREREQUISITE_DETAIL="sudo is not installed"
  export REMOTE_ALPHA_VAULT_SERVICE_USER_PREREQUISITE_RETURN_CODE="127"
  return 0
}

remote_alpha_migrate_vault_service_user_require_command() {
  local name=$1
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "${name} is required" >&2
    return 1
  fi
}

remote_alpha_migrate_vault_service_user_validate_summary_file() {
  local summary_path=$1

  python3 - "${summary_path}" <<'PY'
import pathlib
import re
import sys

summary_path = pathlib.Path(sys.argv[1])
text = summary_path.read_text(encoding="utf-8")

secret_patterns = [
    re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    re.compile(r"(?:^|[^A-Za-z0-9])(?:hvs|s|b)\.[A-Za-z0-9._-]{12,}"),
    re.compile(r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r'(?i)(?:unseal[_ -]?key|root[_ -]?token|client[_ -]?token)\s*[:=]\s*["' + "'" + r']?[A-Za-z0-9+/=._-]{8,}'),
    re.compile(r'(?i)raw[_ -]?secret[_ -]?payload\s*[:=]\s*["' + "'" + r']?[A-Za-z0-9+/=._-]{8,}'),
    re.compile(r'(?i)codex.{0,16}(?:credential|token|api[_ -]?key)\s*[:=]\s*["' + "'" + r']?[A-Za-z0-9+/=._-]{8,}'),
]
overclaim_patterns = [
    re.compile(r"full ES/runtime de-root", re.IGNORECASE),
    re.compile(r"full Nomad client de-root", re.IGNORECASE),
    re.compile(r"governed execution proof", re.IGNORECASE),
    re.compile(r"Vault production readiness", re.IGNORECASE),
]

for pattern in secret_patterns:
    if pattern.search(text):
        raise SystemExit(f"summary contains secret-like material matching {pattern.pattern}: {summary_path}")
for pattern in overclaim_patterns:
    if pattern.search(text):
        raise SystemExit(f"summary contains overclaim text matching {pattern.pattern}: {summary_path}")
PY
}

remote_alpha_migrate_vault_service_user_main() {
  local tmp_dir=""
  local summary_tmp_path=""
  local python_status=0
  local original_args=("$@")

  remote_alpha_migrate_vault_service_user_defaults
  remote_alpha_migrate_vault_service_user_parse_args "$@" || return $?
  remote_alpha_migrate_vault_service_user_finalize_paths
  remote_alpha_migrate_vault_service_user_prepare_check_only_root_context "${original_args[@]}"
  if [[ "${REMOTE_ALPHA_OPERATION_MODE}" == "apply" ]]; then
    remote_alpha_migrate_vault_service_user_require_root || return 1
  fi
  remote_alpha_migrate_vault_service_user_require_command python3 || return 1
  if [[ "$(id -u)" == "0" ]]; then
    remote_alpha_migrate_vault_service_user_require_command systemctl || return 1
  fi
  if [[ "${REMOTE_ALPHA_OPERATION_MODE}" == "apply" ]]; then
    remote_alpha_migrate_vault_service_user_require_command curl || return 1
    remote_alpha_migrate_vault_service_user_require_command install || return 1
  fi

  tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/remote-alpha-vault-service-user.XXXXXX")"
  summary_tmp_path="${tmp_dir}/summary.json"
  trap 'rm -rf "'"${tmp_dir}"'"' EXIT

  if python3 - \
    "${remote_alpha_migrate_vault_service_user_summary_schema_version}" \
    "${REMOTE_ALPHA_OPERATION_MODE}" \
    "${summary_tmp_path}" \
    "${REMOTE_ALPHA_PRECHECK_PATH}" \
    "${REMOTE_ALPHA_SERVICE_NAME}" \
    "${REMOTE_ALPHA_SERVICE_USER}" \
    "${REMOTE_ALPHA_SERVICE_GROUP}" \
    "${REMOTE_ALPHA_SERVICE_UNIT_PATH}" \
    "${REMOTE_ALPHA_SERVICE_DROPIN_DIR}" \
    "${REMOTE_ALPHA_SERVICE_DROPIN_PATH}" \
    "${REMOTE_ALPHA_VAULT_CONFIG_PATH}" \
    "${REMOTE_ALPHA_VAULT_HEALTH_URL}" \
    "${REMOTE_ALPHA_VAULT_HEALTH_CACERT_PATH}" \
    "${REMOTE_ALPHA_VAULT_AUDIT_PATH}" \
    "${REMOTE_ALPHA_ES_CONFIG_PATH}" \
    "${REMOTE_ALPHA_HEALTHCHECK_ENV_PATH}" \
    "${REMOTE_ALPHA_BACKUP_ROOT_DIR}" \
    "${REMOTE_ALPHA_GOVERNED_SMOKE_PROFILE}" \
    "${REMOTE_ALPHA_GOVERNED_SMOKE_COMMAND}" <<'PY'
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat as statmod
import subprocess
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

SCHEMA_VERSION = sys.argv[1]
MODE = sys.argv[2]
SUMMARY_PATH = pathlib.Path(sys.argv[3])
PRECHECK_PATH = pathlib.Path(sys.argv[4])
SERVICE_NAME = sys.argv[5].strip()
SERVICE_USER = sys.argv[6].strip()
SERVICE_GROUP = sys.argv[7].strip()
EXPLICIT_SERVICE_UNIT_PATH = sys.argv[8].strip()
EXPLICIT_DROPIN_DIR = sys.argv[9].strip()
EXPLICIT_DROPIN_PATH = sys.argv[10].strip()
EXPLICIT_CONFIG_PATH = sys.argv[11].strip()
EXPLICIT_VAULT_HEALTH_URL = sys.argv[12].strip()
EXPLICIT_VAULT_HEALTH_CACERT = sys.argv[13].strip()
EXPLICIT_AUDIT_PATH = sys.argv[14].strip()
ES_CONFIG_PATH = pathlib.Path(sys.argv[15])
HEALTHCHECK_ENV_PATH = pathlib.Path(sys.argv[16])
BACKUP_ROOT_DIR = pathlib.Path(sys.argv[17])
GOVERNED_SMOKE_PROFILE = sys.argv[18].strip()
GOVERNED_SMOKE_COMMAND = sys.argv[19]

SERVICE_DROPIN_TEXT = f"[Service]\nUser={SERVICE_USER}\nGroup={SERVICE_GROUP}\nUMask=0027\n"
EXPLICIT_NON_CLAIMS = [
    "not_vault_production_ready",
    "not_governed_execution_proof",
    "not_full_es_runtime_deroot",
    "not_full_nomad_client_deroot",
    "not_spire_redesign",
]
NON_AUTHORITY_LABELS = [
    "not_service_health",
    "not_submit_readiness",
    "not_runtime_profile_readiness",
    "not_producer_contract_compatibility",
    "not_retained_result_readiness",
    "not_governed_proof",
    "not_workload_credential_success_proof",
    "not_vault_production_ready",
    "not_support_bundle_authority",
]
CHECK_ONLY_PREREQUISITE_BLOCKED = os.environ.get("REMOTE_ALPHA_VAULT_SERVICE_USER_PREREQUISITE_BLOCKED", "").strip() == "true"
CHECK_ONLY_PREREQUISITE_REASON = os.environ.get("REMOTE_ALPHA_VAULT_SERVICE_USER_PREREQUISITE_REASON", "").strip()
CHECK_ONLY_PREREQUISITE_SUMMARY = os.environ.get("REMOTE_ALPHA_VAULT_SERVICE_USER_PREREQUISITE_SUMMARY", "").strip()
CHECK_ONLY_PREREQUISITE_DETAIL = os.environ.get("REMOTE_ALPHA_VAULT_SERVICE_USER_PREREQUISITE_DETAIL", "").strip()
CHECK_ONLY_PREREQUISITE_COMMAND = os.environ.get("REMOTE_ALPHA_VAULT_SERVICE_USER_PREREQUISITE_COMMAND", "").strip()
CHECK_ONLY_PREREQUISITE_ATTEMPTED = os.environ.get("REMOTE_ALPHA_VAULT_SERVICE_USER_PREREQUISITE_ATTEMPTED", "").strip() == "true"
CHECK_ONLY_PREREQUISITE_RETURN_CODE = os.environ.get("REMOTE_ALPHA_VAULT_SERVICE_USER_PREREQUISITE_RETURN_CODE", "").strip()


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_text(value):
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def run_command(args):
    return subprocess.run(args, check=False, capture_output=True, text=True)


def mode_string(mode_bits):
    return format(mode_bits & 0o7777, "04o")


def stat_path(path_value):
    path = pathlib.Path(path_value)
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return {
            "path": str(path),
            "exists": False,
            "uid": None,
            "gid": None,
            "mode": "",
            "file_type": "",
        }
    if statmod.S_ISDIR(info.st_mode):
        file_type = "directory"
    elif statmod.S_ISREG(info.st_mode):
        file_type = "regular file"
    elif statmod.S_ISLNK(info.st_mode):
        file_type = "symbolic link"
    elif statmod.S_ISSOCK(info.st_mode):
        file_type = "socket"
    else:
        file_type = "other"
    return {
        "path": str(path),
        "exists": True,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": mode_string(statmod.S_IMODE(info.st_mode)),
        "file_type": file_type,
    }


# Root changes owners and modes in directories the vault account may own
# (red-team RT-3). So the plan treats a path as usable only when no part of it
# is a symbolic link, and only directories dedicated to Vault may change: owned
# by the Vault account or group, and never a shared system directory. The apply
# step acts through descriptors opened without following links, so a name
# swapped after the plan cannot point it anywhere else.
DIR_OPEN_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_OPEN_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
STORAGE_MAX_DEPTH = 64
SHARED_SYSTEM_DIRECTORIES = frozenset(
    {
        "/", "/bin", "/boot", "/dev", "/etc", "/etc/ssl", "/etc/ssl/certs", "/etc/ssl/private",
        "/etc/systemd", "/etc/systemd/system", "/home", "/lib", "/lib64", "/opt", "/proc",
        "/root", "/run", "/sbin", "/srv", "/sys", "/tmp", "/usr", "/usr/bin", "/usr/lib",
        "/usr/local", "/usr/local/bin", "/usr/sbin", "/var", "/var/lib", "/var/log", "/var/tmp",
    }
)


class PathRefusal(RuntimeError):
    pass


def path_parts(path_value):
    if not isinstance(path_value, str) or not path_value.startswith("/"):
        return None
    parts = [part for part in path_value.split("/") if part not in ("", ".")]
    if ".." in parts:
        return None
    return parts


def clean_path(path_value):
    parts = path_parts(path_value)
    return None if parts is None else "/" + "/".join(parts)


def path_shape_problem(path_value):
    parts = path_parts(path_value)
    if parts is None:
        return f"{path_value} must be an absolute path without '..'"
    current = ""
    for part in parts:
        current = f"{current}/{part}"
        try:
            info = os.lstat(current)
        except OSError:
            # Missing or not a directory: the checks that follow report it.
            return ""
        if statmod.S_ISLNK(info.st_mode):
            return f"{path_value} goes through the symbolic link {current}; give Vault the real path"
    return ""


def dedicated_directory_problem(path_value, uid, gid, account, writable_mode=None):
    # writable_mode is the directory's mode when this step gives vault write
    # access to the directory or to what it holds (log and audit parents, the
    # storage directory, and a storage parent that must stand in for it). Such
    # a directory must be one vault can write already, so that a directory
    # vault can only read never becomes writable by it (audit 03 of PR #49,
    # A03-2).
    shown = clean_path(path_value)
    if shown is None:
        return f"{path_value} must be an absolute path without '..'"
    if shown in SHARED_SYSTEM_DIRECTORIES:
        return f"{shown} is a shared system directory, not one dedicated to Vault"
    if uid != account["uid"] and gid != account["gid"]:
        return (
            f"{shown} is not dedicated to Vault: it belongs to {uid}:{gid}, "
            f"not to the {SERVICE_USER} account or the {SERVICE_GROUP} group; "
            f"if it holds only Vault files, give it to the {SERVICE_GROUP} group first"
        )
    if writable_mode is not None and uid != account["uid"] and not writable_mode & 0o020:
        return (
            f"{shown} is not writable by {SERVICE_USER} now (it belongs to {uid}:{gid} with mode {writable_mode:04o}), "
            f"and this step would give {SERVICE_USER} write access to it or to what it holds; "
            f"if it holds only Vault files, give it to {SERVICE_USER} first"
        )
    return ""


def planned_directory_conflicts(config_access, tls_items, storage_access, log_access, audit_access):
    def usable_path(item):
        if not item or item.get("classification") == "blocker":
            return ""
        return clean_path(item.get("path") or "") or ""

    read_paths = [path for path in [usable_path(config_access)] + [usable_path(item) for item in tls_items] if path]
    write_paths = [path for path in (usable_path(log_access), usable_path(audit_access)) if path]
    storage_path = usable_path(storage_access)
    planned = {}
    for path in read_paths:
        planned.setdefault(os.path.dirname(path), set()).add(f"root:{SERVICE_GROUP}")
    for path in write_paths:
        planned.setdefault(os.path.dirname(path), set()).add(f"{SERVICE_USER}:{SERVICE_GROUP}")
    if storage_path:
        planned.setdefault(storage_path, set()).add(f"{SERVICE_USER}:{SERVICE_GROUP}")
    problems = [
        f"{directory} would have to belong to both {' and '.join(sorted(owners))}"
        for directory, owners in sorted(planned.items())
        if len(owners) > 1
    ]
    if storage_path:
        for path in read_paths:
            if os.path.commonpath([path, storage_path]) == storage_path:
                problems.append(
                    f"{path} is inside the storage directory {storage_path}, "
                    f"which becomes {SERVICE_USER}:{SERVICE_GROUP} throughout"
                )
    return problems


def read_json_file(path):
    try:
        return json.loads(path.read_text(encoding="utf-8")), ""
    except FileNotFoundError:
        return None, f"{path} does not exist"
    except Exception as exc:  # noqa: BLE001
        return None, str(exc)


def write_json(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def base_workload_zone_semantics():
    return {
        "classification": "pass",
        "summary": "workload-side Vault credential acquisition remains preserved",
        "exec_workload_identity_endpoint_owned_by_es": True,
        "workload_performs_vault_jwt_login": True,
        "es_vault_token_brokerage": False,
    }


def base_redaction_flags():
    return {
        "vault_tokens_persisted": False,
        "root_tokens_persisted": False,
        "unseal_keys_persisted": False,
        "jwt_svids_persisted": False,
        "pem_private_keys_persisted": False,
        "api_keys_persisted": False,
        "codex_credentials_persisted": False,
        "raw_secret_payloads_persisted": False,
    }


def blocked_check_only_summary():
    prerequisite_summary = CHECK_ONLY_PREREQUISITE_SUMMARY or "noninteractive root/sudo unavailable"
    prerequisite_detail = CHECK_ONLY_PREREQUISITE_DETAIL or "the check-only helper could not acquire root without an interactive password handoff"
    blocker_summary = prerequisite_summary
    if prerequisite_detail and prerequisite_detail not in blocker_summary:
        blocker_summary = f"{blocker_summary}: {prerequisite_detail}"
    return {
        "schema_version": SCHEMA_VERSION,
        "collection_status": "preflight_blocked",
        "mode": {
            "name": "check_only",
            "non_mutating": True,
            "explicit_apply_required": True,
        },
        "generated_at": utc_now(),
        "host": {
            "hostname": os.uname().nodename,
            "euid": os.geteuid(),
        },
        "service": {
            "name": SERVICE_NAME,
        },
        "prerequisite_probe": {
            "classification": "blocker",
            "name": CHECK_ONLY_PREREQUISITE_REASON or "noninteractive_root_unavailable",
            "summary": blocker_summary,
            "attempted": CHECK_ONLY_PREREQUISITE_ATTEMPTED,
            "command": CHECK_ONLY_PREREQUISITE_COMMAND,
            "return_code": int(CHECK_ONLY_PREREQUISITE_RETURN_CODE) if CHECK_ONLY_PREREQUISITE_RETURN_CODE else None,
            "detail": prerequisite_detail,
        },
        "workload_zone_semantics": base_workload_zone_semantics(),
        "plan": {
            "apply_ready": False,
            "mutation_scope": [],
            "planned_changed_paths": [],
            "planned_service_dropin_path": None,
            "preflight_artifact_path": str(PRECHECK_PATH),
        },
        "proof": {
            "check_only_is_not_proof": True,
            "host_mutation_performed": False,
            "governed_execution_smoke_run": False,
        },
        "apply_performed": False,
        "governed_smoke_performed": False,
        "blockers": [
            {
                "name": CHECK_ONLY_PREREQUISITE_REASON or "noninteractive_root_unavailable",
                "summary": blocker_summary,
            }
        ],
        "warnings": [],
        "skipped_checks": [
            {
                "name": "vault_service_user_migration_discovery",
                "reason": blocker_summary,
            },
            {
                "name": "governed_execution_smoke",
                "reason": "governed execution smoke is not part of blocked check-only collection",
            },
        ],
        "redaction": base_redaction_flags(),
        "non_authority_labels": NON_AUTHORITY_LABELS,
        "explicit_non_claims": EXPLICIT_NON_CLAIMS,
        "overall_classification": "blocker",
    }


def service_show(service_name):
    proc = run_command(
        [
            "systemctl",
            "show",
            service_name,
            "--property=User,Group,UMask,ExecStart,FragmentPath,ActiveState,SubState",
            "--no-pager",
        ]
    )
    values = {
        "service_name": service_name,
        "user": "",
        "group": "",
        "umask": "",
        "exec_start": "",
        "fragment_path": "",
        "active_state": "",
        "sub_state": "",
        "effective_user": "root(default)",
        "effective_group": "root(default)",
    }
    if proc.returncode != 0:
        return None, f"systemctl show {service_name} failed"
    for raw in proc.stdout.splitlines():
        if "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key == "User":
            values["user"] = value
        elif key == "Group":
            values["group"] = value
        elif key == "UMask":
            values["umask"] = value
        elif key == "ExecStart":
            values["exec_start"] = value
        elif key == "FragmentPath":
            values["fragment_path"] = value
        elif key == "ActiveState":
            values["active_state"] = value
        elif key == "SubState":
            values["sub_state"] = value
    if values["user"]:
        values["effective_user"] = values["user"]
    if values["group"]:
        values["effective_group"] = values["group"]
    return values, ""


def systemctl_state(mode, service_name):
    proc = run_command(["systemctl", mode, service_name])
    return proc.returncode == 0


def load_service_account():
    result = {
        "classification": "blocker",
        "summary": "",
        "service_user": SERVICE_USER,
        "service_group": SERVICE_GROUP,
        "uid": None,
        "gid": None,
        "primary_group": "",
        "supplementary_groups": [],
        "group_members": [],
    }

    group_proc = run_command(["getent", "group", SERVICE_GROUP])
    if group_proc.returncode != 0:
        result["summary"] = f"required Vault service group {SERVICE_GROUP} does not exist"
        return result
    group_fields = group_proc.stdout.strip().split(":")
    if len(group_fields) < 4:
        result["summary"] = f"failed to parse group entry for {SERVICE_GROUP}"
        return result
    result["gid"] = int(group_fields[2])
    group_entry_members = [item.strip() for item in group_fields[3].split(",") if item.strip()]

    passwd_proc = run_command(["getent", "passwd"])
    if passwd_proc.returncode != 0:
        result["summary"] = f"failed to enumerate passwd entries while validating {SERVICE_GROUP}"
        return result
    primary_group_users = []
    for raw in passwd_proc.stdout.splitlines():
        fields = raw.strip().split(":")
        if len(fields) < 4:
            continue
        if fields[3].strip() == str(result["gid"]):
            primary_group_users.append(fields[0].strip())

    uid_proc = run_command(["id", "-u", SERVICE_USER])
    gid_proc = run_command(["id", "-g", SERVICE_USER])
    primary_group_proc = run_command(["id", "-gn", SERVICE_USER])
    groups_proc = run_command(["id", "-nG", SERVICE_USER])
    if min(uid_proc.returncode, gid_proc.returncode, primary_group_proc.returncode, groups_proc.returncode) != 0:
        result["summary"] = f"required Vault service user {SERVICE_USER} does not exist"
        return result

    result["uid"] = int(uid_proc.stdout.strip())
    result["gid"] = int(gid_proc.stdout.strip())
    result["primary_group"] = primary_group_proc.stdout.strip()
    group_names = [item.strip() for item in groups_proc.stdout.split() if item.strip()]
    result["supplementary_groups"] = [item for item in group_names if item != result["primary_group"]]

    group_members = []
    for item in primary_group_users + group_entry_members:
        if item and item not in group_members:
            group_members.append(item)
    result["group_members"] = group_members

    if result["primary_group"] != SERVICE_GROUP:
        result["summary"] = f"{SERVICE_USER} does not use primary group {SERVICE_GROUP}"
        return result
    if result["supplementary_groups"]:
        result["summary"] = f"{SERVICE_USER} has supplementary groups: {', '.join(result['supplementary_groups'])}"
        return result
    unexpected = [item for item in group_members if item != SERVICE_USER]
    if unexpected:
        result["summary"] = f"{SERVICE_GROUP} contains unexpected members: {', '.join(unexpected)}"
        return result

    result["classification"] = "pass"
    result["summary"] = f"dedicated {SERVICE_USER}:{SERVICE_GROUP} account exists and is narrow"
    return result


def parse_execstart_config_path(exec_start):
    if not exec_start:
        return ""
    match = re.search(r"-config(?:=|\s+)([^\s;]+)", exec_start)
    if match:
        return match.group(1).strip()
    return ""


def normalize_listener_url(address, tls_disable):
    value = (address or "").strip()
    if not value:
        return ""
    if "://" in value:
        return value
    scheme = "http" if str(tls_disable).lower() in {"1", "true", "yes"} else "https"
    return f"{scheme}://{value}"


def parse_value(raw):
    value = raw.strip().rstrip(",")
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    if value.lower() in {"true", "false"}:
        return value.lower()
    return value


def parse_vault_hcl(raw_text):
    payload = {
        "api_addr": "",
        "log_file": "",
        "storage": [],
        "listeners": [],
        "audit_paths": [],
    }
    current = None
    for raw in raw_text.splitlines():
        line = raw.split("#", 1)[0].split("//", 1)[0].strip()
        if not line:
            continue
        block = re.match(r'([A-Za-z_][A-Za-z0-9_]*)\s+"([^"]+)"\s*\{', line)
        if block:
            current = {"kind": block.group(1), "label": block.group(2), "values": {}}
            continue
        if line == "}":
            if current:
                kind = current["kind"]
                label = current["label"]
                values = current["values"]
                if kind in {"storage", "ha_storage"}:
                    payload["storage"].append({"type": label, **values})
                elif kind == "listener":
                    payload["listeners"].append({"type": label, **values})
                elif kind == "audit":
                    path_value = values.get("path") or values.get("file_path") or ""
                    if path_value:
                        payload["audit_paths"].append(path_value)
            current = None
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        parsed = parse_value(value)
        if current:
            current["values"][key] = parsed
        elif key == "api_addr":
            payload["api_addr"] = parsed
        elif key == "log_file":
            payload["log_file"] = parsed
    return payload


def parse_vault_config(config_path):
    path = pathlib.Path(config_path)
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, f"Vault config {path} does not exist"
    except Exception as exc:  # noqa: BLE001
        return None, f"failed to read Vault config {path}: {exc}"

    payload = None
    if raw.lstrip().startswith("{"):
        try:
            node = json.loads(raw)
        except Exception as exc:  # noqa: BLE001
            return None, f"failed to decode Vault config json: {exc}"
        storage_items = []
        storage = node.get("storage")
        if isinstance(storage, list):
            for item in storage:
                if isinstance(item, dict):
                    storage_items.append(item)
        elif isinstance(storage, dict):
            if "type" in storage:
                storage_items.append(storage)
            else:
                for kind, value in storage.items():
                    if isinstance(value, dict):
                        storage_items.append({"type": kind, **value})
        listeners = []
        listener = node.get("listener")
        if isinstance(listener, list):
            for item in listener:
                if isinstance(item, dict):
                    listeners.append(item)
        elif isinstance(listener, dict):
            if "type" in listener:
                listeners.append(listener)
            else:
                for kind, value in listener.items():
                    if isinstance(value, dict):
                        listeners.append({"type": kind, **value})
        audit_paths = []
        audit = node.get("audit")
        if isinstance(audit, list):
            for item in audit:
                if isinstance(item, dict):
                    path_value = str(item.get("path") or item.get("file_path") or "").strip()
                    if path_value:
                        audit_paths.append(path_value)
        elif isinstance(audit, dict):
            path_value = str(audit.get("path") or audit.get("file_path") or "").strip()
            if path_value:
                audit_paths.append(path_value)
        payload = {
            "api_addr": str(node.get("api_addr") or "").strip(),
            "log_file": str(node.get("log_file") or "").strip(),
            "storage": storage_items,
            "listeners": listeners,
            "audit_paths": audit_paths,
        }
    else:
        payload = parse_vault_hcl(raw)

    listeners = payload.get("listeners") or []
    listener_tls_paths = []
    listener_urls = []
    for listener in listeners:
        tls_cert_file = str(listener.get("tls_cert_file") or "").strip()
        tls_key_file = str(listener.get("tls_key_file") or "").strip()
        tls_client_ca_file = str(listener.get("tls_client_ca_file") or listener.get("tls_ca_cert_file") or "").strip()
        for item in (tls_cert_file, tls_key_file, tls_client_ca_file):
            if item and item not in listener_tls_paths:
                listener_tls_paths.append(item)
        listener_url = normalize_listener_url(str(listener.get("address") or ""), listener.get("tls_disable"))
        if listener_url and listener_url not in listener_urls:
            listener_urls.append(listener_url)

    local_storage_path = ""
    local_storage_type = ""
    for storage in payload.get("storage") or []:
        storage_type = str(storage.get("type") or "").strip()
        path_value = str(storage.get("path") or "").strip()
        if storage_type in {"file", "raft"} and path_value:
            local_storage_type = storage_type
            local_storage_path = path_value
            break

    return {
        "config_path": str(path),
        "api_addr": payload.get("api_addr") or "",
        "listener_urls": listener_urls,
        "tls_read_paths": listener_tls_paths,
        "log_file": payload.get("log_file") or "",
        "audit_paths": payload.get("audit_paths") or [],
        "local_storage_type": local_storage_type,
        "local_storage_path": local_storage_path,
    }, ""


def ensure_parent_exists(path_value):
    parent = pathlib.Path(path_value).parent
    parent_stat = stat_path(parent)
    if not parent_stat["exists"]:
        return False, f"parent directory does not exist: {parent}"
    if parent_stat["file_type"] != "directory":
        return False, f"parent path is not a directory: {parent}"
    return True, ""


def plan_file_access(path_value, label, target_gid):
    info = stat_path(path_value)
    parent_info = stat_path(pathlib.Path(path_value).parent)
    desired = {
        "classification": "pass",
        "summary": f"{label} path is present and can be prepared for {SERVICE_USER}:{SERVICE_GROUP} read access",
        "path": path_value,
        "path_exists": info["exists"],
        "current": info,
        "parent": parent_info,
        "required_access": "read",
        "planned_owner": f"root:{SERVICE_GROUP}",
        "planned_mode": "0640",
        "planned_parent_owner": f"root:{SERVICE_GROUP}",
        "planned_parent_mode": "0750",
        "apply_adjustment_required": False,
    }
    shape_problem = path_shape_problem(path_value)
    if shape_problem:
        desired["classification"] = "blocker"
        desired["summary"] = f"{label} path {shape_problem}"
        return desired
    if not info["exists"] or info["file_type"] != "regular file":
        desired["classification"] = "blocker"
        desired["summary"] = f"{label} path is missing or not a regular file"
        return desired
    if not parent_info["exists"] or parent_info["file_type"] != "directory":
        desired["classification"] = "blocker"
        desired["summary"] = f"{label} parent directory is missing"
        return desired
    parent_problem = dedicated_directory_problem(
        str(pathlib.Path(path_value).parent), parent_info["uid"], parent_info["gid"], account_status
    )
    if parent_problem:
        desired["classification"] = "blocker"
        desired["summary"] = f"{label} parent directory {parent_problem}"
        return desired
    if info["uid"] != 0 or info["gid"] != target_gid or info["mode"] != "0640":
        desired["apply_adjustment_required"] = True
    if parent_info["uid"] != 0 or parent_info["gid"] != target_gid or parent_info["mode"] != "0750":
        desired["apply_adjustment_required"] = True
    return desired


def plan_directory_access(path_value, label):
    info = stat_path(path_value)
    desired = {
        "classification": "pass",
        "summary": f"{label} path can be prepared for dedicated Vault ownership",
        "path": path_value,
        "path_exists": info["exists"],
        "current": info,
        "required_access": "write",
        "planned_owner": f"{SERVICE_USER}:{SERVICE_GROUP}",
        "planned_mode": "0750",
        "apply_adjustment_required": False,
    }
    shape_problem = path_shape_problem(path_value)
    if shape_problem:
        desired["classification"] = "blocker"
        desired["summary"] = f"{label} path {shape_problem}"
        return desired
    if clean_path(path_value) in SHARED_SYSTEM_DIRECTORIES:
        desired["classification"] = "blocker"
        desired["summary"] = f"{label} path {clean_path(path_value)} is a shared system directory, not one dedicated to Vault"
        return desired
    parent_value = str(pathlib.Path(path_value).parent)
    parent_info = stat_path(parent_value)
    # The parent only receives a new storage directory, so it must be
    # dedicated to Vault; to stand in for a storage directory that is not,
    # vault must be able to write it already.
    parent_problem = "is missing"
    parent_stand_in_problem = "is missing"
    if parent_info["exists"]:
        parent_problem = dedicated_directory_problem(parent_value, parent_info["uid"], parent_info["gid"], account_status)
        parent_stand_in_problem = dedicated_directory_problem(
            parent_value, parent_info["uid"], parent_info["gid"], account_status, int(parent_info["mode"], 8)
        )
    if info["exists"]:
        if info["file_type"] != "directory":
            desired["classification"] = "blocker"
            desired["summary"] = f"{label} path exists but is not a directory"
            return desired
        if info["uid"] != account_status["uid"] or info["gid"] != account_status["gid"] or info["mode"] != "0750":
            desired["apply_adjustment_required"] = True
            own_problem = dedicated_directory_problem(
                path_value, info["uid"], info["gid"], account_status, int(info["mode"], 8)
            )
            if own_problem and parent_stand_in_problem:
                desired["classification"] = "blocker"
                desired["summary"] = f"{label} directory {own_problem}, and its parent {parent_stand_in_problem}"
        return desired
    ok, error = ensure_parent_exists(path_value)
    if not ok:
        desired["classification"] = "blocker"
        desired["summary"] = error
        return desired
    if parent_problem:
        desired["classification"] = "blocker"
        desired["summary"] = f"{label} directory cannot be created because its parent {parent_problem}"
        return desired
    desired["apply_adjustment_required"] = True
    desired["summary"] = f"{label} path does not exist yet but can be created during apply"
    return desired


def plan_file_or_parent_write_access(path_value, label):
    info = stat_path(path_value)
    desired = {
        "classification": "pass",
        "summary": f"{label} path can be prepared for Vault write access",
        "path": path_value,
        "path_exists": info["exists"],
        "current": info,
        "required_access": "write",
        "planned_owner": f"{SERVICE_USER}:{SERVICE_GROUP}",
        "planned_mode": "0640",
        "planned_parent_owner": f"{SERVICE_USER}:{SERVICE_GROUP}",
        "planned_parent_mode": "0750",
        "apply_adjustment_required": False,
    }
    shape_problem = path_shape_problem(path_value)
    if shape_problem:
        desired["classification"] = "blocker"
        desired["summary"] = f"{label} path {shape_problem}"
        return desired
    if info["exists"] and info["file_type"] != "regular file":
        desired["classification"] = "blocker"
        desired["summary"] = f"{label} path exists but is not a regular file"
        return desired
    ok, error = ensure_parent_exists(path_value)
    if not ok:
        desired["classification"] = "blocker"
        desired["summary"] = error
        return desired
    parent_info = stat_path(pathlib.Path(path_value).parent)
    desired["parent"] = parent_info
    parent_problem = dedicated_directory_problem(
        str(pathlib.Path(path_value).parent), parent_info["uid"], parent_info["gid"], account_status,
        int(parent_info["mode"], 8),
    )
    if parent_problem:
        desired["classification"] = "blocker"
        desired["summary"] = f"{label} parent directory {parent_problem}; the apply step would make it writable by {SERVICE_USER}"
        return desired
    if not info["exists"]:
        desired["apply_adjustment_required"] = True
        desired["summary"] = f"{label} file is absent but its parent can be prepared for Vault-managed creation"
        return desired
    if info["uid"] != account_status["uid"] or info["gid"] != account_status["gid"] or info["mode"] != "0640":
        desired["apply_adjustment_required"] = True
    if parent_info["uid"] != account_status["uid"] or parent_info["gid"] != account_status["gid"] or parent_info["mode"] != "0750":
        desired["apply_adjustment_required"] = True
    return desired


def load_health_env():
    values = {}
    try:
        lines = HEALTHCHECK_ENV_PATH.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return None, f"{HEALTHCHECK_ENV_PATH} does not exist"
    except Exception as exc:  # noqa: BLE001
        return None, f"failed to read {HEALTHCHECK_ENV_PATH}: {exc}"
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    for key in ("CA_CERT", "OPERATOR_CERT", "OPERATOR_KEY"):
        if not values.get(key):
            return None, f"{HEALTHCHECK_ENV_PATH} is missing {key}"
    return values, ""


def load_es_runtime():
    payload, error = read_json_file(ES_CONFIG_PATH)
    if payload is None:
        return None, error
    http = payload.get("http") or {}
    bind_address = str(http.get("bind_address") or "").strip()
    port = int(http.get("port") or 0)
    if not bind_address or port <= 0:
        return None, "ES config is missing http.bind_address or http.port"
    return {
        "health_url": f"https://{bind_address}:{port}/health",
        "contract_url": f"https://{bind_address}:{port}/v1/executions:contract",
    }, ""


def curl_json(url, health_env, cacert_override=""):
    args = ["curl", "--fail-with-body", "--silent", "--show-error"]
    cacert = cacert_override or health_env.get("CA_CERT", "")
    if cacert:
        args.extend(["--cacert", cacert])
    if health_env.get("OPERATOR_CERT"):
        args.extend(["--cert", health_env["OPERATOR_CERT"]])
    if health_env.get("OPERATOR_KEY"):
        args.extend(["--key", health_env["OPERATOR_KEY"]])
    args.append(url)
    proc = run_command(args)
    if proc.returncode != 0:
        return None, proc.stderr.strip() or proc.stdout.strip() or f"curl failed for {url}"
    try:
        return json.loads(proc.stdout), ""
    except Exception as exc:  # noqa: BLE001
        return None, f"failed to decode json from {url}: {exc}"


def probe_vault_health(vault_url, vault_cacert, health_env):
    if vault_url:
        payload, error = curl_json(vault_url, health_env, vault_cacert)
        if payload is None:
            return {
                "status": "fail",
                "method": "https_sys_health",
                "url": vault_url,
                "summary": error,
            }
        return {
            "status": "pass" if payload.get("initialized") is True and payload.get("sealed") is False else "fail",
            "method": "https_sys_health",
            "url": vault_url,
            "initialized": payload.get("initialized"),
            "sealed": payload.get("sealed"),
            "summary": "Vault sys/health responded",
        }
    if systemctl_state("is-active", SERVICE_NAME):
        return {
            "status": "pass",
            "method": "systemctl_is_active",
            "url": "",
            "summary": f"{SERVICE_NAME} is active",
        }
    return {
        "status": "fail",
        "method": "systemctl_is_active",
        "url": "",
        "summary": f"{SERVICE_NAME} is not active",
    }


def probe_es_health(es_runtime, health_env):
    payload, error = curl_json(es_runtime["health_url"], health_env)
    if payload is None:
        return {"status": "fail", "url": es_runtime["health_url"], "summary": error}
    ok = payload.get("ready") is True and payload.get("status") == "healthy"
    return {"status": "pass" if ok else "fail", "url": es_runtime["health_url"], "summary": "ES /health responded"}


def probe_es_contract(es_runtime, health_env):
    payload, error = curl_json(es_runtime["contract_url"], health_env)
    if payload is None:
        return {"status": "fail", "url": es_runtime["contract_url"], "summary": error}
    governed = payload.get("governed_execution") or {}
    ok = (
        payload.get("schema_version") == "execution-substrate.producer-contract/v1"
        and payload.get("service") == "execution"
        and governed.get("contract") == "governed-execution-producer/v1"
        and governed.get("enabled") is True
    )
    return {
        "status": "pass" if ok else "fail",
        "url": es_runtime["contract_url"],
        "summary": "ES contract probe matched the current producer contract" if ok else "ES contract probe did not match the current producer contract",
    }


def secret_like_hits(text):
    patterns = [
        re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
        re.compile(r"(?:^|[^A-Za-z0-9])(?:hvs|s|b)\.[A-Za-z0-9._-]{12,}"),
        re.compile(r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----"),
        re.compile(r"sk-[A-Za-z0-9]{20,}"),
    ]
    return [pattern.pattern for pattern in patterns if pattern.search(text)]


def run_governed_smoke():
    if not GOVERNED_SMOKE_PROFILE or not GOVERNED_SMOKE_COMMAND.strip():
        return {
            "status": "skipped",
            "profile": GOVERNED_SMOKE_PROFILE,
            "passed": False,
            "command_digest": sha256_text(GOVERNED_SMOKE_COMMAND or ""),
            "summary": "governed execution smoke was skipped because the operator did not supply both a documented profile and command",
        }
    proc = subprocess.run(
        ["/bin/sh", "-lc", GOVERNED_SMOKE_COMMAND],
        check=False,
        capture_output=True,
        text=True,
    )
    combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
    denied = secret_like_hits(combined)
    if denied:
        return {
            "status": "fail",
            "profile": GOVERNED_SMOKE_PROFILE,
            "passed": False,
            "command_digest": sha256_text(GOVERNED_SMOKE_COMMAND),
            "exit_code": proc.returncode,
            "summary": "governed execution smoke emitted secret-like material and was failed closed",
        }
    return {
        "status": "pass" if proc.returncode == 0 else "fail",
        "profile": GOVERNED_SMOKE_PROFILE,
        "passed": proc.returncode == 0,
        "command_digest": sha256_text(GOVERNED_SMOKE_COMMAND),
        "exit_code": proc.returncode,
        "summary": "governed execution smoke completed" if proc.returncode == 0 else "governed execution smoke failed",
    }


def plan_summary():
    if CHECK_ONLY_PREREQUISITE_BLOCKED:
        return blocked_check_only_summary()

    service_meta, service_error = service_show(SERVICE_NAME)
    if service_meta is None:
        return {
            "schema_version": SCHEMA_VERSION,
            "collection_status": "collected",
            "mode": {
                "name": "check_only",
                "non_mutating": True,
                "explicit_apply_required": True,
            },
            "generated_at": utc_now(),
            "host": {"hostname": os.uname().nodename, "euid": os.geteuid()},
            "service": {"name": SERVICE_NAME},
            "prerequisite_probe": {},
            "blockers": [{"name": "service_identity", "summary": service_error}],
            "warnings": [],
            "skipped_checks": [],
            "proof": {"check_only_is_not_proof": True, "host_mutation_performed": False, "governed_execution_smoke_run": False},
            "workload_zone_semantics": base_workload_zone_semantics(),
            "plan": {
                "apply_ready": False,
                "mutation_scope": [],
                "planned_changed_paths": [],
                "preflight_artifact_path": str(PRECHECK_PATH),
            },
            "apply_performed": False,
            "governed_smoke_performed": False,
            "redaction": base_redaction_flags(),
            "non_authority_labels": NON_AUTHORITY_LABELS,
            "explicit_non_claims": EXPLICIT_NON_CLAIMS,
            "overall_classification": "blocker",
        }

    service_unit_path = EXPLICIT_SERVICE_UNIT_PATH or service_meta.get("fragment_path") or f"/etc/systemd/system/{SERVICE_NAME}.service"
    service_dropin_dir = EXPLICIT_DROPIN_DIR or f"{service_unit_path}.d"
    service_dropin_path = EXPLICIT_DROPIN_PATH or str(pathlib.Path(service_dropin_dir) / "10-account.conf")
    config_path = EXPLICIT_CONFIG_PATH or parse_execstart_config_path(service_meta.get("exec_start", ""))
    vault_config, vault_config_error = (parse_vault_config(config_path) if config_path else (None, "could not resolve Vault config path from flags or ExecStart"))
    health_env, health_env_error = load_health_env()
    es_runtime, es_runtime_error = load_es_runtime()

    blockers = []
    warnings = []

    global account_status
    account_status = load_service_account()
    if account_status["classification"] == "blocker":
        blockers.append({"name": "service_account", "summary": account_status["summary"]})

    config_access = {
        "classification": "blocker",
        "summary": vault_config_error,
    }
    storage_access = {"classification": "pass", "summary": "local storage is not configured"}
    log_access = {"classification": "pass", "summary": "Vault log file is not configured"}
    audit_access = {"classification": "pass", "summary": "Vault audit file is not configured"}
    tls_access = {"classification": "pass", "summary": "listener TLS paths are not configured", "items": []}

    planned_changed_paths = []
    mutation_scope = []

    if vault_config is None:
        blockers.append({"name": "vault_config", "summary": vault_config_error})
    elif account_status["classification"] != "blocker":
        config_access = plan_file_access(vault_config["config_path"], "Vault config", account_status["gid"])
        if config_access["classification"] == "blocker":
            blockers.append({"name": "config_access", "summary": config_access["summary"]})
        elif config_access.get("apply_adjustment_required"):
            planned_changed_paths.extend([str(pathlib.Path(vault_config["config_path"]).parent), vault_config["config_path"]])
            mutation_scope.append("config_tls_permissions")

        if vault_config["local_storage_path"]:
            storage_access = plan_directory_access(vault_config["local_storage_path"], f"local {vault_config['local_storage_type']} storage")
            if storage_access["classification"] == "blocker":
                blockers.append({"name": "storage_access", "summary": storage_access["summary"]})
            elif storage_access.get("apply_adjustment_required"):
                planned_changed_paths.append(vault_config["local_storage_path"])
                mutation_scope.append("vault_writable_paths")

        if vault_config["log_file"]:
            log_access = plan_file_or_parent_write_access(vault_config["log_file"], "Vault log file")
            if log_access["classification"] == "blocker":
                blockers.append({"name": "log_access", "summary": log_access["summary"]})
            elif log_access.get("apply_adjustment_required"):
                planned_changed_paths.extend([str(pathlib.Path(vault_config["log_file"]).parent), vault_config["log_file"]])
                mutation_scope.append("vault_writable_paths")

        audit_path = EXPLICIT_AUDIT_PATH or (vault_config["audit_paths"][0] if vault_config["audit_paths"] else "")
        if audit_path:
            audit_access = plan_file_or_parent_write_access(audit_path, "Vault audit file")
            if audit_access["classification"] == "blocker":
                blockers.append({"name": "audit_access", "summary": audit_access["summary"]})
            elif audit_access.get("apply_adjustment_required"):
                planned_changed_paths.extend([str(pathlib.Path(audit_path).parent), audit_path])
                mutation_scope.append("vault_writable_paths")

        tls_items = []
        for tls_path in vault_config["tls_read_paths"]:
            item = plan_file_access(tls_path, "Vault listener TLS path", account_status["gid"])
            tls_items.append(item)
            if item["classification"] == "blocker":
                blockers.append({"name": "tls_read_paths", "summary": item["summary"]})
            elif item.get("apply_adjustment_required"):
                planned_changed_paths.extend([str(pathlib.Path(tls_path).parent), tls_path])
                mutation_scope.append("config_tls_permissions")
        if tls_items:
            tls_access = {
                "classification": "pass" if all(item["classification"] == "pass" for item in tls_items) else "blocker",
                "summary": "Vault listener TLS paths were inspected",
                "items": tls_items,
            }
        for conflict in planned_directory_conflicts(config_access, tls_items, storage_access, log_access, audit_access):
            blockers.append({"name": "path_ownership_conflict", "summary": conflict})

    if health_env is None:
        blockers.append({"name": "healthcheck_env", "summary": health_env_error})
    if es_runtime is None:
        blockers.append({"name": "es_runtime", "summary": es_runtime_error})

    change_required = service_meta["effective_user"] != SERVICE_USER or service_meta["effective_group"] != SERVICE_GROUP or service_meta.get("umask") != "0027"
    if change_required:
        planned_changed_paths.append(service_dropin_path)
        mutation_scope.append("systemd_dropin")

    planned_changed_paths = sorted(dict.fromkeys(item for item in planned_changed_paths if item))
    mutation_scope = sorted(dict.fromkeys(item for item in mutation_scope if item))

    overall_classification = "blocker" if blockers else "pass"
    return {
        "schema_version": SCHEMA_VERSION,
        "collection_status": "collected",
        "mode": {
            "name": "check_only",
            "non_mutating": True,
            "explicit_apply_required": True,
        },
        "generated_at": utc_now(),
        "host": {
            "hostname": os.uname().nodename,
            "euid": os.geteuid(),
        },
        "service": {
            "name": SERVICE_NAME,
            "service_unit_path": service_unit_path,
            "service_dropin_dir": service_dropin_dir,
            "service_dropin_path": service_dropin_path,
            "current_identity": service_meta,
            "planned_identity": {
                "user": SERVICE_USER,
                "group": SERVICE_GROUP,
                "umask": "0027",
                "change_required": change_required,
                "dropin_text_digest": sha256_text(SERVICE_DROPIN_TEXT),
            },
        },
        "validation": {
            "service_account": account_status,
            "current_service_identity": {
                "classification": "pass",
                "summary": "current Vault service identity was inspected without mutation",
                **service_meta,
            },
            "planned_systemd_change": {
                "classification": "pass",
                "summary": "planned systemd drop-in is limited to dedicated Vault service-user settings",
                "dropin_path": service_dropin_path,
                "change_required": change_required,
                "dropin_text_digest": sha256_text(SERVICE_DROPIN_TEXT),
            },
            "config_access": config_access,
            "storage_access": storage_access,
            "log_access": log_access,
            "audit_access": audit_access,
            "tls_read_paths": tls_access,
        },
        "prerequisite_probe": {},
        "workload_zone_semantics": base_workload_zone_semantics(),
        "plan": {
            "apply_ready": not blockers,
            "mutation_scope": mutation_scope,
            "planned_changed_paths": planned_changed_paths,
            "planned_service_dropin_path": service_dropin_path,
            "preflight_artifact_path": str(PRECHECK_PATH),
        },
        "proof": {
            "check_only_is_not_proof": True,
            "host_mutation_performed": False,
            "governed_execution_smoke_run": False,
        },
        "apply_performed": False,
        "governed_smoke_performed": False,
        "blockers": blockers,
        "warnings": warnings,
        "skipped_checks": [],
        "redaction": base_redaction_flags(),
        "non_authority_labels": NON_AUTHORITY_LABELS,
        "explicit_non_claims": EXPLICIT_NON_CLAIMS,
        "overall_classification": overall_classification,
    }


def write_temp_summary(payload):
    write_json(SUMMARY_PATH, payload)


def create_backup(preflight_summary, service_meta, changed_paths):
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_dir = BACKUP_ROOT_DIR / f"vault-service-user-migration-{timestamp}"
    backup_dir.mkdir(parents=True, exist_ok=True)
    preflight_copy_path = backup_dir / PRECHECK_PATH.name
    write_json(preflight_copy_path, preflight_summary)
    service_snapshot_path = backup_dir / "pre-apply-service.json"
    write_json(service_snapshot_path, service_meta)
    snapshot_manifest_path = backup_dir / "snapshot-manifest.json"
    write_json(
        snapshot_manifest_path,
        {
            "generated_at": utc_now(),
            "paths": [stat_path(item) for item in changed_paths],
        },
    )
    rollback_notes = [
        f"Restore the previous drop-in from {backup_dir / 'dropin.before.conf'} if one was captured, otherwise remove the dedicated Vault drop-in.",
        "Restore the path owner and mode observations recorded in snapshot-manifest.json before restarting Vault.",
        f"Restart {SERVICE_NAME}.service and rerun the Vault /sys/health, ES /health, and ES GET /v1/executions:contract checks.",
    ]
    rollback_notes_path = backup_dir / "rollback-notes.txt"
    rollback_notes_path.write_text("\n".join(rollback_notes) + "\n", encoding="utf-8")
    return {
        "path": str(backup_dir),
        "preflight_copy_path": str(preflight_copy_path),
        "service_snapshot_path": str(service_snapshot_path),
        "snapshot_path": str(snapshot_manifest_path),
        "rollback_notes_path": str(rollback_notes_path),
        "rollback_notes": rollback_notes,
    }


def touch_backup_sentinel():
    sentinel = os.environ.get("REMOTE_ALPHA_TEST_BACKUP_SENTINEL_PATH", "").strip()
    if sentinel:
        pathlib.Path(sentinel).write_text("backup-created\n", encoding="utf-8")


def run_install_dropin(dropin_path):
    temp_path = SUMMARY_PATH.parent / ".vault-service-user-dropin.tmp"
    temp_path.write_text(SERVICE_DROPIN_TEXT, encoding="utf-8")
    run_command(["install", "-d", "-m", "0755", str(pathlib.Path(dropin_path).parent)])
    proc = run_command(["install", "-m", "0644", str(temp_path), dropin_path])
    temp_path.unlink(missing_ok=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "failed to install Vault service drop-in")


def run_simple_command(args, error_summary):
    proc = run_command(args)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or error_summary)


def split_parent(path_value, label):
    parts = path_parts(path_value)
    if not parts:
        raise PathRefusal(f"{label} {path_value} must be an absolute path without '..' below /")
    return "/" + "/".join(parts[:-1]), parts[-1]


def open_directory_path(path_value, label):
    parts = path_parts(path_value)
    if parts is None:
        raise PathRefusal(f"{label} {path_value} must be an absolute path without '..'")
    fd = os.open("/", DIR_OPEN_FLAGS)
    for index, part in enumerate(parts):
        try:
            next_fd = os.open(part, DIR_OPEN_FLAGS, dir_fd=fd)
        except OSError as exc:
            os.close(fd)
            shown = "/" + "/".join(parts[: index + 1])
            raise PathRefusal(f"{label}: {shown} is missing, is not a directory or is a symbolic link ({exc.strerror})") from None
        os.close(fd)
        fd = next_fd
    return fd


def open_regular_file(dir_fd, name, label, shown, missing_ok=False):
    try:
        fd = os.open(name, FILE_OPEN_FLAGS, dir_fd=dir_fd)
    except FileNotFoundError:
        if missing_ok:
            return None
        raise PathRefusal(f"{label}: {shown} is missing") from None
    except OSError as exc:
        raise PathRefusal(f"{label}: {shown} is not a regular file or is a symbolic link ({exc.strerror})") from None
    info = os.fstat(fd)
    if not statmod.S_ISREG(info.st_mode) or info.st_nlink != 1:
        os.close(fd)
        raise PathRefusal(f"{label}: {shown} must be a regular file with one link")
    return fd


def require_dedicated_directory(dir_fd, path_value, label, account, becomes_vault_writable=False):
    info = os.fstat(dir_fd)
    writable_mode = statmod.S_IMODE(info.st_mode) if becomes_vault_writable else None
    problem = dedicated_directory_problem(path_value, info.st_uid, info.st_gid, account, writable_mode)
    if problem:
        raise PathRefusal(f"{label}: {problem}")


def change_read_file(path_value, label, account, root_uid, apply):
    # Config and TLS files: the parent goes to root first, so the vault account
    # can no longer swap names in it, then the file itself.
    parent_value, name = split_parent(path_value, label)
    parent_fd = open_directory_path(parent_value, f"{label} parent directory")
    try:
        require_dedicated_directory(parent_fd, parent_value, f"{label} parent directory", account)
        if apply:
            os.fchown(parent_fd, root_uid, account["gid"])
            os.fchmod(parent_fd, 0o750)
        file_fd = open_regular_file(parent_fd, name, label, path_value)
        try:
            if apply:
                os.fchown(file_fd, root_uid, account["gid"])
                os.fchmod(file_fd, 0o640)
        finally:
            os.close(file_fd)
    finally:
        os.close(parent_fd)


def change_write_file(path_value, label, account, apply):
    # Log and audit files: the parent goes to vault, so it must be a directory
    # dedicated to Vault that vault can write already; the file, when present,
    # goes to vault.
    parent_value, name = split_parent(path_value, label)
    parent_fd = open_directory_path(parent_value, f"{label} parent directory")
    try:
        require_dedicated_directory(parent_fd, parent_value, f"{label} parent directory", account, True)
        if apply:
            os.fchown(parent_fd, account["uid"], account["gid"])
            os.fchmod(parent_fd, 0o750)
        file_fd = open_regular_file(parent_fd, name, label, path_value, missing_ok=True)
        if file_fd is not None:
            try:
                if apply:
                    os.fchown(file_fd, account["uid"], account["gid"])
                    os.fchmod(file_fd, 0o640)
            finally:
                os.close(file_fd)
    finally:
        os.close(parent_fd)


def own_storage_tree(dir_fd, shown, label, account, depth, apply):
    if depth > STORAGE_MAX_DEPTH:
        raise PathRefusal(f"{label}: {shown} is more than {STORAGE_MAX_DEPTH} directories below the storage directory")
    if apply:
        os.fchown(dir_fd, account["uid"], account["gid"])
    for entry in sorted(os.listdir(dir_fd)):
        where = f"{shown}/{entry}"
        try:
            info = os.stat(entry, dir_fd=dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            # Vault keeps running during this step and may remove its own
            # temporary files; a vanished entry needs no change.
            continue
        if statmod.S_ISDIR(info.st_mode):
            try:
                child_fd = os.open(entry, DIR_OPEN_FLAGS, dir_fd=dir_fd)
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise PathRefusal(f"{label}: {where} is not a directory or is a symbolic link ({exc.strerror})") from None
            try:
                own_storage_tree(child_fd, where, label, account, depth + 1, apply)
            finally:
                os.close(child_fd)
        elif statmod.S_ISREG(info.st_mode):
            file_fd = open_regular_file(dir_fd, entry, label, where, missing_ok=True)
            if file_fd is None:
                continue
            try:
                if apply:
                    os.fchown(file_fd, account["uid"], account["gid"])
            finally:
                os.close(file_fd)
        else:
            raise PathRefusal(f"{label}: {where} is not a directory or a regular file")


def change_storage(path_value, label, account, apply):
    # The storage directory and everything in it go to vault. It must be a
    # directory dedicated to Vault that vault can write already, or sit
    # directly in one; a missing one is created only in a directory dedicated
    # to Vault.
    shown = clean_path(path_value)
    if shown in SHARED_SYSTEM_DIRECTORIES:
        raise PathRefusal(f"{label}: {shown} is a shared system directory, not one dedicated to Vault")
    parent_value, name = split_parent(path_value, label)
    parent_fd = open_directory_path(parent_value, f"{label} parent directory")
    try:
        parent_info = os.fstat(parent_fd)
        parent_problem = dedicated_directory_problem(parent_value, parent_info.st_uid, parent_info.st_gid, account)
        parent_stand_in_problem = dedicated_directory_problem(
            parent_value, parent_info.st_uid, parent_info.st_gid, account, statmod.S_IMODE(parent_info.st_mode)
        )
        created = False
        try:
            storage_fd = os.open(name, DIR_OPEN_FLAGS, dir_fd=parent_fd)
        except FileNotFoundError:
            if parent_problem:
                raise PathRefusal(f"{label}: will not create {shown} because its parent {parent_problem}") from None
            if not apply:
                return
            try:
                os.mkdir(name, 0o750, dir_fd=parent_fd)
            except FileExistsError:
                raise PathRefusal(f"{label}: {shown} appeared while this step ran") from None
            storage_fd = os.open(name, DIR_OPEN_FLAGS, dir_fd=parent_fd)
            created = True
        except OSError as exc:
            raise PathRefusal(f"{label}: {shown} is not a directory or is a symbolic link ({exc.strerror})") from None
        try:
            info = os.fstat(storage_fd)
            # A directory this step just created is root's and empty, and its
            # parent passed the rule for creating one.
            if not created:
                own_problem = dedicated_directory_problem(
                    path_value, info.st_uid, info.st_gid, account, statmod.S_IMODE(info.st_mode)
                )
                if own_problem and parent_stand_in_problem:
                    raise PathRefusal(f"{label}: {own_problem}, and its parent {parent_stand_in_problem}")
            own_storage_tree(storage_fd, shown, label, account, 0, apply)
            if apply:
                os.fchmod(storage_fd, 0o750)
        finally:
            os.close(storage_fd)
    finally:
        os.close(parent_fd)


def apply_path_changes(preflight_summary):
    validation = preflight_summary.get("validation") or {}
    config_access = validation.get("config_access") or {}
    tls_items = (validation.get("tls_read_paths") or {}).get("items") or []
    storage_access = validation.get("storage_access") or {}
    log_access = validation.get("log_access") or {}
    audit_access = validation.get("audit_access") or {}

    targets = []
    if config_access.get("apply_adjustment_required"):
        targets.append(("read", config_access["path"], "Vault config"))
    for item in tls_items:
        if item.get("apply_adjustment_required"):
            targets.append(("read", item["path"], "Vault listener TLS path"))
    for kind, item, label in (
        ("storage", storage_access, "Vault storage"),
        ("write", log_access, "Vault log file"),
        ("write", audit_access, "Vault audit file"),
    ):
        if item.get("classification") == "blocker" or not item.get("apply_adjustment_required") or not item.get("path"):
            continue
        targets.append((kind, item["path"], label))
    if not targets:
        return

    account = load_service_account()
    if account["classification"] != "pass":
        raise PathRefusal(f"the Vault service account is not ready: {account['summary']}; no path was changed")
    conflicts = planned_directory_conflicts(config_access, tls_items, storage_access, log_access, audit_access)
    if conflicts:
        raise PathRefusal("; ".join(conflicts) + "; no path was changed")
    # Root in production (the apply step requires it); the test user in tests.
    root_uid = os.geteuid()

    # The first pass opens and checks every path and changes nothing, so a
    # refusal there leaves the host as it was. The second pass checks each
    # path again as it changes it.
    for apply in (False, True):
        try:
            for kind, path_value, label in targets:
                if kind == "read":
                    change_read_file(path_value, label, account, root_uid, apply)
                elif kind == "write":
                    change_write_file(path_value, label, account, apply)
                else:
                    change_storage(path_value, label, account, apply)
        except (PathRefusal, OSError) as exc:
            if apply:
                raise PathRefusal(
                    f"{exc}; some Vault paths may already have changed, compare them with snapshot-manifest.json in the backup"
                ) from None
            raise PathRefusal(f"{exc}; no path was changed") from None


def build_apply_summary(result_status, ok, preflight_summary, backup, changes, post_apply_checks, skipped_checks, summary_text):
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": {
            "name": "apply",
            "non_mutating": False,
            "explicit_apply_required": True,
        },
        "generated_at": utc_now(),
        "host": {
            "hostname": os.uname().nodename,
            "euid": os.geteuid(),
        },
        "service": preflight_summary.get("service", {}),
        "preflight": {
            "path": str(PRECHECK_PATH),
            "apply_ready": (preflight_summary.get("plan") or {}).get("apply_ready") is True,
            "overall_classification": preflight_summary.get("overall_classification"),
        },
        "changes": changes,
        "backup": backup,
        "post_apply_checks": post_apply_checks,
        "skipped_checks": skipped_checks,
        "proof": {
            "host_mutation_performed": True,
            "governed_execution_smoke_run": (post_apply_checks.get("governed_execution_smoke") or {}).get("status") != "skipped",
        },
        "workload_zone_semantics": preflight_summary.get("workload_zone_semantics", {}),
        "apply_performed": True,
        "governed_smoke_performed": (post_apply_checks.get("governed_execution_smoke") or {}).get("status") != "skipped",
        "redaction": base_redaction_flags(),
        "explicit_non_claims": EXPLICIT_NON_CLAIMS,
        "result": {
            "status": result_status,
            "ok": ok,
            "summary": summary_text,
        },
        "overall_classification": "pass" if ok else "blocker",
    }


summary = {}
exit_code = 0

try:
    if MODE == "check_only":
        summary = plan_summary()
        exit_code = 0 if summary.get("overall_classification") == "pass" else 1
    else:
        if PRECHECK_PATH.exists():
            preflight_summary, preflight_error = read_json_file(PRECHECK_PATH)
            if preflight_summary is None:
                preflight_summary = plan_summary()
                summary = build_apply_summary(
                    "preflight_blocked",
                    False,
                    preflight_summary,
                    {"path": "", "snapshot_path": "", "rollback_notes_path": "", "rollback_notes": []},
                    {"changed_paths": []},
                    {},
                    [],
                    f"existing preflight artifact could not be read: {preflight_error}",
                )
                exit_code = 1
            else:
                if (preflight_summary.get("schema_version") != SCHEMA_VERSION or (preflight_summary.get("mode") or {}).get("name") != "check_only" or (preflight_summary.get("mode") or {}).get("non_mutating") is not True or (preflight_summary.get("plan") or {}).get("apply_ready") is not True):
                    summary = build_apply_summary(
                        "preflight_blocked",
                        False,
                        preflight_summary,
                        {"path": "", "snapshot_path": "", "rollback_notes_path": "", "rollback_notes": []},
                        {"changed_paths": []},
                        {},
                        [],
                        "existing preflight artifact did not prove apply readiness",
                    )
                    exit_code = 1
                else:
                    pass
        else:
            preflight_summary = plan_summary()
            write_json(PRECHECK_PATH, preflight_summary)
            if (preflight_summary.get("plan") or {}).get("apply_ready") is not True:
                summary = build_apply_summary(
                    "preflight_blocked",
                    False,
                    preflight_summary,
                    {"path": "", "snapshot_path": "", "rollback_notes_path": "", "rollback_notes": []},
                    {"changed_paths": []},
                    {},
                    [],
                    "preflight checks were rerun and are not ready for apply",
                )
                exit_code = 1

        if not summary:
            service_meta = (preflight_summary.get("validation") or {}).get("current_service_identity") or {}
            changed_paths = list((preflight_summary.get("plan") or {}).get("planned_changed_paths") or [])
            backup = create_backup(preflight_summary, service_meta, changed_paths)
            existing_dropin_path = pathlib.Path((preflight_summary.get("service") or {}).get("service_dropin_path") or "")
            if existing_dropin_path and existing_dropin_path.exists():
                shutil.copyfile(existing_dropin_path, pathlib.Path(backup["path"]) / "dropin.before.conf")
            touch_backup_sentinel()

            apply_error = ""
            try:
                # Paths first: a refusal there leaves the unit as it was, and
                # the new user takes effect only at the restart below.
                apply_path_changes(preflight_summary)
                run_install_dropin((preflight_summary.get("service") or {}).get("service_dropin_path"))
                run_simple_command(["systemctl", "daemon-reload"], "failed to reload systemd")
                run_simple_command(["systemctl", "restart", f"{SERVICE_NAME}.service"], "failed to restart Vault service")
            except Exception as exc:  # noqa: BLE001
                apply_error = str(exc)

            health_env, health_env_error = load_health_env()
            es_runtime, es_runtime_error = load_es_runtime()
            vault_health_url = EXPLICIT_VAULT_HEALTH_URL
            vault_cacert = EXPLICIT_VAULT_HEALTH_CACERT
            if not vault_health_url:
                config_node = preflight_summary.get("validation", {}).get("config_access", {})
                config_path = config_node.get("path", "")
                if config_path:
                    config_meta, config_meta_error = parse_vault_config(config_path)
                    if config_meta_error == "":
                        base_url = config_meta.get("api_addr") or (config_meta.get("listener_urls") or [""])[0]
                        if base_url:
                            vault_health_url = base_url.rstrip("/") + "/v1/sys/health"
                        if not vault_cacert and config_meta.get("tls_read_paths"):
                            vault_cacert = config_meta["tls_read_paths"][-1]

            vault_health = (
                probe_vault_health(vault_health_url, vault_cacert, health_env or {})
                if health_env is not None
                else {"status": "fail", "summary": health_env_error, "method": "unavailable", "url": vault_health_url}
            )
            es_health = (
                probe_es_health(es_runtime, health_env)
                if health_env is not None and es_runtime is not None
                else {"status": "fail", "summary": health_env_error or es_runtime_error, "url": ""}
            )
            es_contract = (
                probe_es_contract(es_runtime, health_env)
                if health_env is not None and es_runtime is not None
                else {"status": "fail", "summary": health_env_error or es_runtime_error, "url": ""}
            )
            governed_smoke = run_governed_smoke()

            post_apply_checks = {
                "vault_health": vault_health,
                "es_health": es_health,
                "es_contract": es_contract,
                "governed_execution_smoke": governed_smoke,
            }
            skipped_checks = []
            if governed_smoke["status"] == "skipped":
                skipped_checks.append(
                    {
                        "name": "governed_execution_smoke",
                        "reason": governed_smoke["summary"],
                    }
                )

            ok = (
                not apply_error
                and vault_health["status"] == "pass"
                and es_health["status"] == "pass"
                and es_contract["status"] == "pass"
                and governed_smoke["status"] in {"pass", "skipped"}
            )
            result_status = "applied" if ok else "post_apply_validation_failed"
            result_summary = "Vault service-user apply completed with honest bounded post-apply checks"
            if apply_error:
                result_summary = apply_error
            summary = build_apply_summary(
                result_status,
                ok,
                preflight_summary,
                backup,
                {"changed_paths": changed_paths},
                post_apply_checks,
                skipped_checks,
                result_summary,
            )
            exit_code = 0 if ok else 1

    write_json(SUMMARY_PATH, summary)
except Exception as exc:  # noqa: BLE001
    summary = {
        "schema_version": SCHEMA_VERSION,
        "mode": {
            "name": "apply" if MODE == "apply" else "check_only",
            "non_mutating": MODE != "apply",
            "explicit_apply_required": True,
        },
        "generated_at": utc_now(),
        "host": {"hostname": os.uname().nodename, "euid": os.geteuid()},
        "apply_performed": MODE == "apply",
        "governed_smoke_performed": False,
        "redaction": base_redaction_flags(),
        "non_authority_labels": NON_AUTHORITY_LABELS if MODE != "apply" else [],
        "explicit_non_claims": EXPLICIT_NON_CLAIMS,
        "result": {
            "status": "helper_error",
            "ok": False,
            "summary": str(exc),
        },
        "overall_classification": "blocker",
    }
    write_json(SUMMARY_PATH, summary)
    exit_code = 1

sys.exit(exit_code)
PY
  then
    python_status=0
  else
    python_status=$?
  fi

  if [[ ! -f "${summary_tmp_path}" ]]; then
    echo "vault service-user migration helper did not produce a summary artifact" >&2
    return 1
  fi

  remote_alpha_migrate_vault_service_user_validate_summary_file "${summary_tmp_path}" || {
    rm -f -- "${summary_tmp_path}"
    return 1
  }

  mkdir -p "$(dirname "${REMOTE_ALPHA_SUMMARY_PATH}")"
  mv "${summary_tmp_path}" "${REMOTE_ALPHA_SUMMARY_PATH}"
  /bin/chmod 0644 "${REMOTE_ALPHA_SUMMARY_PATH}" 2>/dev/null || true
  printf '%s\n' "${REMOTE_ALPHA_SUMMARY_PATH}"
  return "${python_status}"
}
