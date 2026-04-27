#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${REPO_ROOT:-}" ]]; then
  REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_HELPER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  REPO_ROOT="$(cd "${REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_HELPER_DIR}/../.." && pwd)"
fi

remote_alpha_prepare_es_writable_state_ownership_summary_schema_version="execution-substrate.remote-alpha.es-writable-state-ownership-summary.v1"
remote_alpha_prepare_es_writable_state_ownership_stage_schema_version="execution-substrate.remote-alpha.es-writable-state-ownership-stage-provenance.v1"
remote_alpha_prepare_es_writable_state_ownership_remote_stage_root_default="/var/tmp/execution-substrate-remote-alpha/helper-staging"
remote_alpha_prepare_es_writable_state_ownership_remote_summary_path_default="/var/tmp/execution-substrate-remote-alpha/es-writable-state-ownership-summary.json"
remote_alpha_prepare_es_writable_state_ownership_backup_root_dir_default="/var/tmp/execution-substrate-remote-alpha"
remote_alpha_prepare_es_writable_state_ownership_default_output_dir="${REPO_ROOT}/.out/remote-alpha-m75q"

REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_KEEP_STAGING_ON_FAILURE="false"
REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_SHOW_HELP="false"
REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_STAGING_OCCURRED="false"
REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_CHECKER_RAN="false"
REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_APPLY_RAN="false"
REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_TRANSIENT_STAGING_REMOVED="false"
REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_STAGING_RETAINED_FOR_DIAGNOSTICS="false"
REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_UPLOAD_PREPARED="false"
REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_CLEANUP_COMPLETED="false"
REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_CHECKER_EXIT_CODE=""
REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_APPLY_EXIT_CODE=""
REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_SUDO_UNAVAILABLE="false"
REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_WRAPPER_TOOLING_ERROR="false"
REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_FAILURE_CLASSIFICATION=""
REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_BLOCKER_DETAIL=""

REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_LOCAL_FILE_META_PATH=""
REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_STAGE_STAT_META_PATH=""
REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_CHECK_VALIDATION_META_PATH=""
REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_GIT_COMMIT=""
REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_UPLOAD_ROOT=""
REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_ARTIFACT_ROOT=""
REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_STAGE_REMOTE_STAGING_ROOT=""
REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_STAGED_WRAPPER_PATH=""
REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_STAGED_INTERNAL_PATH=""
REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_STAGE_STAT_ARTIFACT_PATH=""
REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_CHECK_OUTPUT_ARTIFACT_PATH=""

remote_alpha_prepare_es_writable_state_ownership_init_expected_slice_inputs() {
  remote_alpha_prepare_es_writable_state_ownership_expected_service_name="${remote_alpha_prepare_es_writable_state_ownership_expected_service_name:-es}"
  remote_alpha_prepare_es_writable_state_ownership_expected_service_user="${remote_alpha_prepare_es_writable_state_ownership_expected_service_user:-es}"
  remote_alpha_prepare_es_writable_state_ownership_expected_service_group="${remote_alpha_prepare_es_writable_state_ownership_expected_service_group:-es}"
  remote_alpha_prepare_es_writable_state_ownership_expected_config_path="${remote_alpha_prepare_es_writable_state_ownership_expected_config_path:-/etc/execution-substrate/es.json}"
  remote_alpha_prepare_es_writable_state_ownership_expected_healthcheck_env_path="${remote_alpha_prepare_es_writable_state_ownership_expected_healthcheck_env_path:-/etc/execution-substrate/healthcheck.env}"
  remote_alpha_prepare_es_writable_state_ownership_expected_service_unit_path="${remote_alpha_prepare_es_writable_state_ownership_expected_service_unit_path:-/etc/systemd/system/es.service}"
}

remote_alpha_prepare_es_writable_state_ownership_defaults() {
  remote_alpha_prepare_es_writable_state_ownership_init_expected_slice_inputs
  REMOTE_ALPHA_OPERATION_MODE="check_only"
  REMOTE_ALPHA_SERVICE_NAME="${remote_alpha_prepare_es_writable_state_ownership_expected_service_name}"
  REMOTE_ALPHA_SERVICE_USER="${remote_alpha_prepare_es_writable_state_ownership_expected_service_user}"
  REMOTE_ALPHA_SERVICE_GROUP="${remote_alpha_prepare_es_writable_state_ownership_expected_service_group}"
  REMOTE_ALPHA_CONFIG_PATH="${remote_alpha_prepare_es_writable_state_ownership_expected_config_path}"
  REMOTE_ALPHA_HEALTHCHECK_ENV_PATH="${remote_alpha_prepare_es_writable_state_ownership_expected_healthcheck_env_path}"
  REMOTE_ALPHA_SERVICE_UNIT_PATH="${remote_alpha_prepare_es_writable_state_ownership_expected_service_unit_path}"
  REMOTE_ALPHA_SUMMARY_PATH="${REMOTE_ALPHA_SUMMARY_PATH:-${remote_alpha_prepare_es_writable_state_ownership_remote_summary_path_default}}"
  REMOTE_ALPHA_SUMMARY_DIR="$(dirname "${REMOTE_ALPHA_SUMMARY_PATH}")"
  remote_alpha_prepare_es_writable_state_ownership_backup_root_dir="${REMOTE_ALPHA_TEST_BACKUP_ROOT:-${remote_alpha_prepare_es_writable_state_ownership_backup_root_dir_default}}"
  REMOTE_ALPHA_ROTATE_NONEMPTY_ROOTS="false"
  REMOTE_ALPHA_ACCEPT_STALE_ORPHANED_RUNS="false"
  REMOTE_ALPHA_FIX_PARENT_CHAIN="false"
  REMOTE_ALPHA_RECONCILE_ARTIFACTS="false"
}

remote_alpha_prepare_es_writable_state_ownership_usage() {
  cat <<'EOF'
Usage:
  scripts/remote_alpha_prepare_es_writable_state_ownership.sh --ssh-target <user@host>
  scripts/remote_alpha_prepare_es_writable_state_ownership.sh --ssh-target <user@host> --apply
  scripts/remote_alpha_prepare_es_writable_state_ownership.sh --ssh-target <user@host> --apply --rotate-nonempty-roots
  scripts/remote_alpha_prepare_es_writable_state_ownership.sh --ssh-target <user@host> --apply --rotate-nonempty-roots --accept-stale-orphaned-runs
  scripts/remote_alpha_prepare_es_writable_state_ownership.sh --ssh-target <user@host> --apply --fix-parent-chain
  scripts/remote_alpha_prepare_es_writable_state_ownership.sh --ssh-target <user@host> --apply --reconcile-artifacts
  sudo scripts/remote_alpha_prepare_es_writable_state_ownership.sh
  sudo scripts/remote_alpha_prepare_es_writable_state_ownership.sh --apply
  sudo scripts/remote_alpha_prepare_es_writable_state_ownership.sh --apply --rotate-nonempty-roots
  sudo scripts/remote_alpha_prepare_es_writable_state_ownership.sh --apply --rotate-nonempty-roots --accept-stale-orphaned-runs
  sudo scripts/remote_alpha_prepare_es_writable_state_ownership.sh --apply --fix-parent-chain
  sudo scripts/remote_alpha_prepare_es_writable_state_ownership.sh --apply --reconcile-artifacts

Repo-side staged wrapper flags:
  --ssh-target <user@host>
  --check-only
  --dry-run
  --apply
  --rotate-nonempty-roots
  --accept-stale-orphaned-runs
  --fix-parent-chain
  --reconcile-artifacts
  --run-id <timestamp-or-id>
  --output-dir </path/to/output-dir>
  --check-output </path/to/es-writable-state-ownership-check-only.json>
  --apply-summary-output </path/to/es-writable-state-ownership-apply-summary.json>
  --helper-staging-record-output </path/to/es-writable-state-ownership-helper-staging-record.json>
  --provenance-output </path/to/es-writable-state-ownership-helper-staging-record.json>
  --remote-summary-path </remote/path/to/es-writable-state-ownership-summary.json>
  --interactive-sudo
  --keep-staging-on-failure

Host-local helper flags:
  --check-only
  --dry-run
  --apply
  --rotate-nonempty-roots
  --accept-stale-orphaned-runs
  --fix-parent-chain
  --reconcile-artifacts
  --summary-path </path/to/es-writable-state-ownership-summary.json>
  --help

Default behavior is non-mutating check-only for the sealed stable writable-state
ownership slice only.
EOF
}

remote_alpha_prepare_es_writable_state_ownership_reject_slice_override_env() {
  local name=$1
  local expected=$2
  local actual=""

  actual="$(printenv "${name}" 2>/dev/null || true)"
  if [[ -z "${actual}" ]]; then
    return 0
  fi
  if [[ "${actual}" != "${expected}" ]]; then
    printf 'remote alpha ES writable-state ownership does not accept %s override for this sealed stable-root slice; expected repo-owned value %q (got %q)\n' "${name}" "${expected}" "${actual}" >&2
    return 1
  fi
  return 0
}

remote_alpha_prepare_es_writable_state_ownership_require_pinned_slice_inputs() {
  remote_alpha_prepare_es_writable_state_ownership_init_expected_slice_inputs
  remote_alpha_prepare_es_writable_state_ownership_reject_slice_override_env "REMOTE_ALPHA_SERVICE_NAME" "${remote_alpha_prepare_es_writable_state_ownership_expected_service_name}" || return 1
  remote_alpha_prepare_es_writable_state_ownership_reject_slice_override_env "REMOTE_ALPHA_SERVICE_USER" "${remote_alpha_prepare_es_writable_state_ownership_expected_service_user}" || return 1
  remote_alpha_prepare_es_writable_state_ownership_reject_slice_override_env "REMOTE_ALPHA_SERVICE_GROUP" "${remote_alpha_prepare_es_writable_state_ownership_expected_service_group}" || return 1
  remote_alpha_prepare_es_writable_state_ownership_reject_slice_override_env "REMOTE_ALPHA_CONFIG_PATH" "${remote_alpha_prepare_es_writable_state_ownership_expected_config_path}" || return 1
  remote_alpha_prepare_es_writable_state_ownership_reject_slice_override_env "REMOTE_ALPHA_HEALTHCHECK_ENV_PATH" "${remote_alpha_prepare_es_writable_state_ownership_expected_healthcheck_env_path}" || return 1
  remote_alpha_prepare_es_writable_state_ownership_reject_slice_override_env "REMOTE_ALPHA_SERVICE_UNIT_PATH" "${remote_alpha_prepare_es_writable_state_ownership_expected_service_unit_path}" || return 1
}

remote_alpha_prepare_es_writable_state_ownership_has_ssh_target() {
  local arg
  for arg in "$@"; do
    if [[ "${arg}" == "--ssh-target" ]]; then
      return 0
    fi
  done
  return 1
}

remote_alpha_prepare_es_writable_state_ownership_require_root() {
  if [[ "$(id -u)" != "0" ]]; then
    echo "remote alpha ES writable-state ownership helper must run as root; use sudo scripts/remote_alpha_prepare_es_writable_state_ownership.sh" >&2
    return 1
  fi
}

remote_alpha_prepare_es_writable_state_ownership_require_command() {
  local name=$1
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "${name} is required" >&2
    return 1
  fi
}

remote_alpha_prepare_es_writable_state_ownership_json_field() {
  local json_path=$1
  local dotted_path=$2

  python3 - "${json_path}" "${dotted_path}" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
value = payload
for part in sys.argv[2].split("."):
    if isinstance(value, dict):
        value = value.get(part)
    else:
        value = None
        break
if value is None:
    sys.exit(1)
if isinstance(value, bool):
    print("true" if value else "false")
elif isinstance(value, (dict, list)):
    print(json.dumps(value, sort_keys=True))
else:
    print(value)
PY
}

remote_alpha_prepare_es_writable_state_ownership_parse_host_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --service-name)
        echo "remote alpha ES writable-state ownership does not accept --service-name for this sealed stable-root slice" >&2
        return 2
        ;;
      --service-user)
        echo "remote alpha ES writable-state ownership does not accept --service-user for this sealed stable-root slice" >&2
        return 2
        ;;
      --service-group)
        echo "remote alpha ES writable-state ownership does not accept --service-group for this sealed stable-root slice" >&2
        return 2
        ;;
      --config-path)
        echo "remote alpha ES writable-state ownership does not accept --config-path for this sealed stable-root slice" >&2
        return 2
        ;;
      --healthcheck-env-path)
        echo "remote alpha ES writable-state ownership does not accept --healthcheck-env-path for this sealed stable-root slice" >&2
        return 2
        ;;
      --service-unit-path)
        echo "remote alpha ES writable-state ownership does not accept --service-unit-path for this sealed stable-root slice" >&2
        return 2
        ;;
      --check-only|--dry-run)
        REMOTE_ALPHA_OPERATION_MODE="check_only"
        shift
        ;;
      --apply)
        REMOTE_ALPHA_OPERATION_MODE="apply"
        shift
        ;;
      --rotate-nonempty-roots)
        REMOTE_ALPHA_ROTATE_NONEMPTY_ROOTS="true"
        shift
        ;;
      --accept-stale-orphaned-runs)
        REMOTE_ALPHA_ACCEPT_STALE_ORPHANED_RUNS="true"
        shift
        ;;
      --fix-parent-chain)
        REMOTE_ALPHA_FIX_PARENT_CHAIN="true"
        shift
        ;;
      --reconcile-artifacts)
        REMOTE_ALPHA_RECONCILE_ARTIFACTS="true"
        shift
        ;;
      --summary-path)
        REMOTE_ALPHA_SUMMARY_PATH="$2"
        REMOTE_ALPHA_SUMMARY_DIR="$(dirname "${REMOTE_ALPHA_SUMMARY_PATH}")"
        shift 2
        ;;
      --help|-h)
        REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_SHOW_HELP="true"
        remote_alpha_prepare_es_writable_state_ownership_usage
        return 1
        ;;
      *)
        echo "unknown argument: $1" >&2
        remote_alpha_prepare_es_writable_state_ownership_usage >&2
        return 2
        ;;
    esac
  done

  if [[ "${REMOTE_ALPHA_ROTATE_NONEMPTY_ROOTS}" == "true" && "${REMOTE_ALPHA_OPERATION_MODE}" != "apply" ]]; then
    echo "remote alpha ES writable-state ownership requires --apply with --rotate-nonempty-roots" >&2
    return 2
  fi
  if [[ "${REMOTE_ALPHA_ACCEPT_STALE_ORPHANED_RUNS}" == "true" && "${REMOTE_ALPHA_OPERATION_MODE}" != "apply" ]]; then
    echo "remote alpha ES writable-state ownership requires --apply with --accept-stale-orphaned-runs" >&2
    return 2
  fi
  if [[ "${REMOTE_ALPHA_ACCEPT_STALE_ORPHANED_RUNS}" == "true" && "${REMOTE_ALPHA_ROTATE_NONEMPTY_ROOTS}" != "true" ]]; then
    echo "remote alpha ES writable-state ownership requires --rotate-nonempty-roots with --accept-stale-orphaned-runs" >&2
    return 2
  fi
  if [[ "${REMOTE_ALPHA_FIX_PARENT_CHAIN}" == "true" && "${REMOTE_ALPHA_OPERATION_MODE}" != "apply" ]]; then
    echo "remote alpha ES writable-state ownership requires --apply with --fix-parent-chain" >&2
    return 2
  fi
  if [[ "${REMOTE_ALPHA_RECONCILE_ARTIFACTS}" == "true" && "${REMOTE_ALPHA_OPERATION_MODE}" != "apply" ]]; then
    echo "remote alpha ES writable-state ownership requires --apply with --reconcile-artifacts" >&2
    return 2
  fi
  if [[ "${REMOTE_ALPHA_FIX_PARENT_CHAIN}" == "true" && "${REMOTE_ALPHA_ROTATE_NONEMPTY_ROOTS}" == "true" ]]; then
    echo "remote alpha ES writable-state ownership does not accept --fix-parent-chain together with --rotate-nonempty-roots" >&2
    return 2
  fi
  if [[ "${REMOTE_ALPHA_FIX_PARENT_CHAIN}" == "true" && "${REMOTE_ALPHA_ACCEPT_STALE_ORPHANED_RUNS}" == "true" ]]; then
    echo "remote alpha ES writable-state ownership does not accept --fix-parent-chain together with --accept-stale-orphaned-runs" >&2
    return 2
  fi
  if [[ "${REMOTE_ALPHA_RECONCILE_ARTIFACTS}" == "true" && "${REMOTE_ALPHA_ROTATE_NONEMPTY_ROOTS}" == "true" ]]; then
    echo "remote alpha ES writable-state ownership does not accept --reconcile-artifacts together with --rotate-nonempty-roots" >&2
    return 2
  fi
  if [[ "${REMOTE_ALPHA_RECONCILE_ARTIFACTS}" == "true" && "${REMOTE_ALPHA_ACCEPT_STALE_ORPHANED_RUNS}" == "true" ]]; then
    echo "remote alpha ES writable-state ownership does not accept --reconcile-artifacts together with --accept-stale-orphaned-runs" >&2
    return 2
  fi
  if [[ "${REMOTE_ALPHA_RECONCILE_ARTIFACTS}" == "true" && "${REMOTE_ALPHA_FIX_PARENT_CHAIN}" == "true" ]]; then
    echo "remote alpha ES writable-state ownership does not accept --reconcile-artifacts together with --fix-parent-chain" >&2
    return 2
  fi
}

remote_alpha_prepare_es_writable_state_ownership_python() {
  python3 - \
    "${remote_alpha_prepare_es_writable_state_ownership_summary_schema_version}" \
    "${REMOTE_ALPHA_OPERATION_MODE}" \
    "${REMOTE_ALPHA_SUMMARY_PATH}" \
    "${REMOTE_ALPHA_SERVICE_NAME}" \
    "${REMOTE_ALPHA_SERVICE_USER}" \
    "${REMOTE_ALPHA_SERVICE_GROUP}" \
    "${REMOTE_ALPHA_CONFIG_PATH}" \
    "${REMOTE_ALPHA_HEALTHCHECK_ENV_PATH}" \
    "${REMOTE_ALPHA_SERVICE_UNIT_PATH}" \
    "${remote_alpha_prepare_es_writable_state_ownership_backup_root_dir}" \
    "${REMOTE_ALPHA_ROTATE_NONEMPTY_ROOTS}" \
    "${REMOTE_ALPHA_ACCEPT_STALE_ORPHANED_RUNS}" \
    "${REMOTE_ALPHA_FIX_PARENT_CHAIN}" \
    "${REMOTE_ALPHA_RECONCILE_ARTIFACTS}" <<'PY'
import json
import os
import pathlib
import stat as statmod
import subprocess
import sys
from datetime import datetime, timezone
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest

SCHEMA_VERSION = sys.argv[1]
MODE = sys.argv[2]
SUMMARY_PATH = sys.argv[3]
SERVICE_NAME = sys.argv[4]
SERVICE_USER = sys.argv[5]
SERVICE_GROUP = sys.argv[6]
CONFIG_PATH = sys.argv[7]
HEALTHCHECK_ENV_PATH = sys.argv[8]
SERVICE_UNIT_PATH = sys.argv[9]
BACKUP_ROOT_DIR = sys.argv[10]
ROTATE_NONEMPTY_ROOTS = sys.argv[11] == "true"
ACCEPT_STALE_ORPHANED_RUNS = sys.argv[12] == "true"
FIX_PARENT_CHAIN = sys.argv[13] == "true"
RECONCILE_ARTIFACTS = sys.argv[14] == "true"
TARGET_MODE = 0o750
MARKER_NAME = "ownership-normalization.json"
MARKER_SCHEMA_VERSION = "execution-substrate.es.runtime-ownership-normalization.v1"
RESULT_BUNDLE_NAME = "result.tar.gz"
ROTATION_FLAG = "--rotate-nonempty-roots"
STALE_ORPHAN_ACCEPTANCE_FLAG = "--accept-stale-orphaned-runs"
PARENT_CHAIN_FLAG = "--fix-parent-chain"
RECONCILE_FLAG = "--reconcile-artifacts"
TERMINAL_ALLOCATION_STATUSES = {"complete", "failed", "lost"}


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def utc_stamp():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def make_status(classification, summary, **kwargs):
    payload = {"classification": classification, "summary": summary}
    payload.update(kwargs)
    return payload


def clone_json(value):
    return json.loads(json.dumps(value))


def run_command(args, check=False):
    return subprocess.run(args, capture_output=True, text=True, check=check)


def mode_string(mode_bits):
    return format(mode_bits & 0o7777, "04o")


def sha256_file(path):
    import hashlib
    data = pathlib.Path(path).read_bytes()
    return hashlib.sha256(data).hexdigest()


def safe_sha256(path):
    try:
        return sha256_file(path)
    except Exception:  # noqa: BLE001
        return ""


def stat_path(path):
    rendered = os.fspath(path)
    try:
        link_info = os.lstat(rendered)
    except FileNotFoundError:
        return {
            "path": rendered,
            "exists": False,
            "uid": None,
            "gid": None,
            "owner": "",
            "group": "",
            "mode": "",
            "mode_bits": 0,
            "file_type": "",
            "size": 0,
            "error": "not found",
        }
    info = link_info
    file_type = "other"
    if statmod.S_ISLNK(link_info.st_mode):
        try:
            info = os.stat(rendered)
        except FileNotFoundError:
            info = link_info
        file_type = "symbolic link"
    elif statmod.S_ISDIR(info.st_mode):
        file_type = "directory"
    elif statmod.S_ISREG(info.st_mode):
        file_type = "regular file"
    owner = ""
    group = ""
    try:
        import pwd
        owner = pwd.getpwuid(info.st_uid).pw_name
    except Exception:  # noqa: BLE001
        owner = str(info.st_uid)
    try:
        import grp
        group = grp.getgrgid(info.st_gid).gr_name
    except Exception:  # noqa: BLE001
        group = str(info.st_gid)
    return {
        "path": rendered,
        "exists": True,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "owner": owner,
        "group": group,
        "mode": mode_string(statmod.S_IMODE(info.st_mode)),
        "mode_bits": statmod.S_IMODE(info.st_mode),
        "file_type": file_type,
        "size": info.st_size,
    }


def selected_permission_bits(stat_info, uid, gid):
    mode_bits = stat_info["mode_bits"]
    if uid == stat_info["uid"]:
        return (mode_bits >> 6) & 0o7
    if gid == stat_info["gid"]:
        return (mode_bits >> 3) & 0o7
    return mode_bits & 0o7


def preserved_owner_permission_bits(stat_info, gid):
    mode_bits = stat_info["mode_bits"]
    if gid == stat_info["gid"]:
        return (mode_bits >> 3) & 0o7
    return mode_bits & 0o7


def ensure_traversable(path, uid, gid, include_self):
    checked = []
    for directory in directory_chain(path, include_self=include_self):
        directory_stat = stat_path(directory)
        checked.append(
            {
                "path": directory,
                "exists": directory_stat["exists"],
                "file_type": directory_stat["file_type"],
                "mode": directory_stat["mode"],
            }
        )
        if not directory_stat["exists"]:
            return False, checked, f"directory does not exist: {directory}"
        if directory_stat["file_type"] == "symbolic link":
            continue
        if directory_stat["file_type"] != "directory":
            return False, checked, f"path is not a directory: {directory}"
        if selected_permission_bits(directory_stat, uid, gid) & 0o1 == 0:
            return False, checked, f"directory is not traversable by target UID:GID: {directory}"
    return True, checked, ""


def inspect_directory_access(path, uid, gid):
    directory_stat = stat_path(path)
    result = {
        "path": os.fspath(path),
        "path_exists": directory_stat["exists"],
        "file_type": directory_stat["file_type"],
        "owner_uid": directory_stat["uid"],
        "owner_gid": directory_stat["gid"],
        "mode": directory_stat["mode"],
        "mode_bits": directory_stat["mode_bits"],
        "es_can_traverse": False,
        "es_can_read": False,
        "es_can_write": False,
        "es_can_manage_entries": False,
        "access_error": "",
    }
    if not directory_stat["exists"]:
        result["access_error"] = directory_stat.get("error", "path does not exist")
        return result
    if directory_stat["file_type"] != "directory":
        result["access_error"] = "path is not a directory"
        return result

    traversable, checked, error = ensure_traversable(path, uid, gid, include_self=True)
    result["traversal_chain"] = checked
    result["es_can_traverse"] = traversable
    if not traversable:
        result["access_error"] = error
        return result

    bits = selected_permission_bits(directory_stat, uid, gid)
    result["es_can_read"] = bool(bits & 0o4)
    result["es_can_write"] = bool(bits & 0o2)
    result["es_can_manage_entries"] = result["es_can_write"] and result["es_can_traverse"]
    return result


def inspect_file_access(path, uid, gid):
    file_stat = stat_path(path)
    result = {
        "path": os.fspath(path),
        "path_exists": file_stat["exists"],
        "file_type": file_stat["file_type"],
        "owner_uid": file_stat["uid"],
        "owner_gid": file_stat["gid"],
        "mode": file_stat["mode"],
        "mode_bits": file_stat["mode_bits"],
        "es_can_read": False,
        "es_can_write": False,
        "access_error": "",
    }
    if not file_stat["exists"]:
        result["access_error"] = file_stat.get("error", "path does not exist")
        return result

    traversable, checked, error = ensure_traversable(path, uid, gid, include_self=False)
    result["traversal_chain"] = checked
    if not traversable:
        result["access_error"] = error
        return result

    bits = selected_permission_bits(file_stat, uid, gid)
    result["es_can_read"] = bool(bits & 0o4)
    result["es_can_write"] = bool(bits & 0o2)
    return result


def ancestor_chain(path):
    target = pathlib.Path(path).absolute()
    ordered = list(reversed(target.parents))
    deduped = []
    for item in ordered:
        rendered = os.fspath(item)
        if not deduped or deduped[-1] != rendered:
            deduped.append(rendered)
    return deduped


def directory_chain(path, include_self):
    target = pathlib.Path(path).absolute()
    if not include_self:
        target = target.parent
    ordered = list(reversed([target, *target.parents]))
    deduped = []
    for item in ordered:
        rendered = os.fspath(item)
        if not deduped or deduped[-1] != rendered:
            deduped.append(rendered)
    return deduped


def inspect_service_meta():
    unit_name = SERVICE_NAME if SERVICE_NAME.endswith(".service") else SERVICE_NAME + ".service"
    proc = run_command(
        [
            "systemctl",
            "show",
            unit_name,
            "--property=ExecStart,User,Group,ActiveState,SubState,FragmentPath",
            "--no-pager",
        ]
    )
    fields = {
        "exec_start": "",
        "user": "",
        "group": "",
        "effective_user": "root(default)",
        "effective_group": "root(default)",
        "active_state": "",
        "sub_state": "",
        "fragment_path": "",
    }
    if proc.returncode != 0:
        return make_status("blocker", f"failed to inspect {unit_name}: {proc.stderr.strip() or proc.stdout.strip()}", **fields)
    for raw in proc.stdout.splitlines():
        key, _, value = raw.partition("=")
        value = value.strip()
        if key == "ExecStart":
            fields["exec_start"] = value
        elif key == "User":
            fields["user"] = value
            fields["effective_user"] = value or "root(default)"
        elif key == "Group":
            fields["group"] = value
            fields["effective_group"] = value or "root(default)"
        elif key == "ActiveState":
            fields["active_state"] = value
        elif key == "SubState":
            fields["sub_state"] = value
        elif key == "FragmentPath":
            fields["fragment_path"] = value
    blockers = []
    if fields["fragment_path"] and fields["fragment_path"] != SERVICE_UNIT_PATH:
        blockers.append(f"service fragment path mismatch: {fields['fragment_path']}")
    if fields["effective_user"] not in {"root(default)", "root"}:
        blockers.append(f"service user is not root(default): {fields['effective_user']}")
    if fields["effective_group"] not in {"root(default)", "root"}:
        blockers.append(f"service group is not root(default): {fields['effective_group']}")
    if fields["active_state"] != "active" or fields["sub_state"] != "running":
        blockers.append(f"service is not active/running: {fields['active_state'] or 'unknown'}/{fields['sub_state'] or 'unknown'}")
    if blockers:
        return make_status("blocker", blockers[0], blockers=blockers, **fields)
    return make_status("pass", "es.service matches the pinned root(default) writable-state prep posture", blockers=[], **fields)


def inspect_service_account():
    result = {
        "service_user": SERVICE_USER,
        "service_group": SERVICE_GROUP,
        "user_exists": False,
        "group_exists": False,
        "uid": None,
        "gid": None,
        "primary_group": "",
        "group_entry_members": [],
        "primary_group_users": [],
        "group_members": [],
        "supplementary_groups": [],
        "group_names": [],
        "narrow_dedicated_account": False,
    }
    group_proc = run_command(["getent", "group", SERVICE_GROUP])
    group_line = ""
    if group_proc.returncode == 0:
        result["group_exists"] = True
        for raw in group_proc.stdout.splitlines():
            if raw.strip():
                group_line = raw.strip()
                break
    if result["group_exists"]:
        fields = group_line.split(":")
        if len(fields) >= 4:
            result["gid"] = int(fields[2])
            group_members = []
            for member in fields[3].split(","):
                member = member.strip()
                if member and member not in group_members:
                    group_members.append(member)
            result["group_entry_members"] = group_members
        passwd_proc = run_command(["getent", "passwd"])
        if passwd_proc.returncode == 0:
            primary_group_users = []
            for raw in passwd_proc.stdout.splitlines():
                if not raw.strip():
                    continue
                fields = raw.split(":")
                if len(fields) < 4:
                    continue
                username = fields[0].strip()
                gid = fields[3].strip()
                if username and gid == str(result["gid"]) and username not in primary_group_users:
                    primary_group_users.append(username)
            result["primary_group_users"] = primary_group_users
            combined = []
            for member in primary_group_users + result["group_entry_members"]:
                if member and member not in combined:
                    combined.append(member)
            result["group_members"] = combined

    uid_proc = run_command(["id", "-u", SERVICE_USER])
    gid_proc = run_command(["id", "-g", SERVICE_USER])
    primary_group_proc = run_command(["id", "-gn", SERVICE_USER])
    groups_proc = run_command(["id", "-nG", SERVICE_USER])
    if uid_proc.returncode == 0 and gid_proc.returncode == 0 and primary_group_proc.returncode == 0 and groups_proc.returncode == 0:
        result["user_exists"] = True
        result["uid"] = int(uid_proc.stdout.strip())
        if result["gid"] is None:
            result["gid"] = int(gid_proc.stdout.strip())
        result["primary_group"] = primary_group_proc.stdout.strip()
        group_names = []
        for item in groups_proc.stdout.split():
            item = item.strip()
            if item and item not in group_names:
                group_names.append(item)
        result["group_names"] = group_names
        result["supplementary_groups"] = [item for item in group_names if item != result["primary_group"]]

    if not result["group_exists"] or not result["user_exists"]:
        missing = []
        if not result["group_exists"]:
            missing.append(f"group {SERVICE_GROUP}")
        if not result["user_exists"]:
            missing.append(f"user {SERVICE_USER}")
        return make_status("blocker", "the dedicated es:es account is missing or incomplete: " + ", ".join(missing), **result)

    unexpected_group_members = [member for member in result["group_members"] if member != SERVICE_USER]
    if unexpected_group_members:
        return make_status("blocker", "the es group is broader than allowed for this slice: " + ", ".join(unexpected_group_members), unexpected_group_members=unexpected_group_members, **result)
    if result["primary_group"] != SERVICE_GROUP:
        return make_status("blocker", f"{SERVICE_USER} does not use primary group {SERVICE_GROUP}", **result)
    if result["supplementary_groups"]:
        return make_status("blocker", "the es account has supplementary groups: " + ", ".join(result["supplementary_groups"]), **result)

    result["narrow_dedicated_account"] = True
    return make_status("pass", "dedicated es:es account exists and is narrow", **result)


def load_healthcheck_env(path):
    env_path = pathlib.Path(path)
    values = {}
    try:
        lines = env_path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return make_status("blocker", "healthcheck env file does not exist", path=str(env_path), present=False)
    except Exception as exc:  # noqa: BLE001
        return make_status("blocker", f"failed to read healthcheck env file: {exc}", path=str(env_path), present=False)

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()

    required = {
        "CA_CERT": values.get("CA_CERT", ""),
        "OPERATOR_CERT": values.get("OPERATOR_CERT", ""),
        "OPERATOR_KEY": values.get("OPERATOR_KEY", ""),
    }
    missing = sorted(key for key, value in required.items() if not value)
    if missing:
        return make_status(
            "blocker",
            "healthcheck env is missing required validation inputs: " + ", ".join(missing),
            path=str(env_path),
            present=True,
            values=required,
        )

    return make_status("pass", "healthcheck env contains the required validation inputs", path=str(env_path), present=True, values=required)


def load_runtime_config():
    try:
        payload = json.loads(pathlib.Path(CONFIG_PATH).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return make_status("blocker", "ES config file does not exist", path=CONFIG_PATH, execution={}, runtime={})
    except Exception as exc:  # noqa: BLE001
        return make_status("blocker", f"failed to read ES config: {exc}", path=CONFIG_PATH, execution={}, runtime={})
    http = payload.get("http") or {}
    bind_address = str(http.get("bind_address") or "").strip()
    try:
        port = int(http.get("port") or 0)
    except Exception:  # noqa: BLE001
        port = 0
    execution = payload.get("execution") or {}
    staging_root = str(execution.get("staging_root_dir") or "").strip()
    results_root = str(execution.get("results_root_dir") or "").strip()
    nomad = payload.get("nomad") or {}
    nomad_base_url = str(nomad.get("base_url") or "").strip()
    nomad_datacenter = str(nomad.get("datacenter") or "").strip()
    try:
        nomad_timeout_seconds = int(nomad.get("timeout_seconds") or 0)
    except Exception:  # noqa: BLE001
        nomad_timeout_seconds = 0
    runtime = {
        "bind_address": bind_address,
        "port": port,
        "health_url": f"https://{bind_address}:{port}/health" if bind_address and port > 0 else "",
        "contract_url": f"https://{bind_address}:{port}/v1/executions:contract" if bind_address and port > 0 else "",
        "staging_root_dir": staging_root,
        "results_root_dir": results_root,
        "nomad": {
            "base_url": nomad_base_url,
            "datacenter": nomad_datacenter,
            "timeout_seconds": nomad_timeout_seconds,
        },
    }
    missing = [
        field
        for field, value in [
            ("http.bind_address", bind_address),
            ("http.port", str(port) if port > 0 else ""),
            ("execution.staging_root_dir", staging_root),
            ("execution.results_root_dir", results_root),
        ]
        if not value
    ]
    if missing:
        return make_status("blocker", "ES config is missing required fields for this slice: " + ", ".join(missing), path=CONFIG_PATH, execution=runtime, runtime=runtime)
    return make_status("pass", "ES config contains the runtime paths required for this slice", path=CONFIG_PATH, execution=runtime, runtime=runtime)


def build_nomad_url(base_url, request_path, datacenter):
    parsed = urlparse.urlparse(base_url)
    clean_path = request_path if request_path.startswith("/") else "/" + request_path
    query = urlparse.urlencode({"dc": datacenter}) if datacenter else ""
    return urlparse.urlunparse((parsed.scheme, parsed.netloc, clean_path, "", query, ""))


def nomad_get_json(runtime_status, request_path):
    runtime = runtime_status.get("runtime") or runtime_status.get("execution") or {}
    nomad = runtime.get("nomad") or {}
    base_url = str(nomad.get("base_url") or "").strip()
    datacenter = str(nomad.get("datacenter") or "").strip()
    try:
        timeout_seconds = int(nomad.get("timeout_seconds") or 0)
    except Exception:  # noqa: BLE001
        timeout_seconds = 0
    if not base_url or not datacenter or timeout_seconds <= 0:
        return None, None, "nomad runtime config is missing base_url, datacenter, or timeout_seconds", ""

    request_url = build_nomad_url(base_url, request_path, datacenter)
    request = urlrequest.Request(request_url, headers={"Accept": "application/json"})
    try:
        with urlrequest.urlopen(request, timeout=timeout_seconds) as response:
            body = response.read().decode("utf-8")
            try:
                payload = json.loads(body)
            except Exception as exc:  # noqa: BLE001
                return None, response.getcode(), f"nomad response was not valid JSON: {exc}", request_url
            return payload, response.getcode(), "", request_url
    except urlerror.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        if exc.code == 404:
            return None, exc.code, "", request_url
        detail = body.strip() or str(exc)
        return None, exc.code, f"nomad returned HTTP {exc.code}: {detail}", request_url
    except Exception as exc:  # noqa: BLE001
        return None, None, str(exc), request_url


def task_state_is_terminal(task_state):
    state = str((task_state or {}).get("State") or "").strip()
    return state == "dead"


def allocation_is_active(allocation):
    client_status = str((allocation or {}).get("ClientStatus") or "").strip()
    if client_status not in TERMINAL_ALLOCATION_STATUSES:
        return True
    task_state = ((allocation or {}).get("TaskStates") or {}).get("task") or {}
    return not task_state_is_terminal(task_state)


def classify_legacy_run_with_nomad(runtime_status, run_id):
    job_id = f"exec-{run_id}"
    job_payload, job_status, job_error, job_url = nomad_get_json(runtime_status, f"/v1/job/{job_id}")
    if job_error:
        return {
            "run_id": run_id,
            "classification": "unknown",
            "scheduler_state": "scheduler_unavailable" if job_status is None else "unknown",
            "summary": "active runs cannot be safely ruled out because Nomad job state could not be read",
            "job_id": job_id,
            "job_url": job_url,
            "job_status_code": job_status,
            "evidence_sources": ["not observed"],
            "scheduler_error": job_error,
            "explicit_stale_orphan_acceptance_required": False,
        }
    if job_status == 404:
        return {
            "run_id": run_id,
            "classification": "stale_orphan_candidate",
            "scheduler_state": "absent_in_scheduler",
            "summary": "Nomad no longer reports the run and the directory remains only as filesystem-backed legacy state",
            "job_id": job_id,
            "job_url": job_url,
            "job_status_code": job_status,
            "evidence_sources": ["Nomad job absent/404", "filesystem-only legacy state"],
            "explicit_stale_orphan_acceptance_required": True,
        }

    job_state = str((job_payload or {}).get("Status") or "").strip()
    allocations_payload, allocations_status, allocations_error, allocations_url = nomad_get_json(runtime_status, f"/v1/job/{job_id}/allocations")
    if allocations_error:
        return {
            "run_id": run_id,
            "classification": "unknown",
            "scheduler_state": "scheduler_unavailable" if allocations_status is None else "unknown",
            "summary": "active runs cannot be safely ruled out because Nomad allocation state could not be read",
            "job_id": job_id,
            "job_url": job_url,
            "job_status": job_state,
            "allocations_url": allocations_url,
            "allocations_status_code": allocations_status,
            "evidence_sources": ["Nomad job status", "not observed"],
            "scheduler_error": allocations_error,
            "explicit_stale_orphan_acceptance_required": False,
        }

    allocations = allocations_payload if isinstance(allocations_payload, list) else []
    if not allocations:
        if job_state == "dead":
            return {
                "run_id": run_id,
                "classification": "terminal",
                "scheduler_state": "terminal",
                "summary": "Nomad still reports the job, but it is terminal and no active allocation remains",
                "job_id": job_id,
                "job_url": job_url,
                "job_status": job_state,
                "allocations_url": allocations_url,
                "allocations_status_code": allocations_status,
                "evidence_sources": ["Nomad job status", "filesystem-only legacy state"],
                "explicit_stale_orphan_acceptance_required": True,
            }
        return {
            "run_id": run_id,
            "classification": "active",
            "scheduler_state": "active",
            "summary": "Nomad still reports a non-terminal job for the run directory",
            "job_id": job_id,
            "job_url": job_url,
            "job_status": job_state,
            "allocations_url": allocations_url,
            "allocations_status_code": allocations_status,
            "evidence_sources": ["Nomad job status"],
            "explicit_stale_orphan_acceptance_required": False,
        }

    allocation_summaries = []
    active_allocation_ids = []
    for entry in sorted(allocations, key=lambda item: item.get("ModifyIndex", 0), reverse=True):
        allocation_id = str(entry.get("ID") or "").strip()
        detail_payload, detail_status, detail_error, detail_url = nomad_get_json(runtime_status, f"/v1/allocation/{allocation_id}")
        if detail_error or detail_status == 404 or not isinstance(detail_payload, dict):
            return {
                "run_id": run_id,
                "classification": "unknown",
                "scheduler_state": "scheduler_unavailable" if detail_status is None else "unknown",
                "summary": "active runs cannot be safely ruled out because Nomad allocation detail could not be read",
                "job_id": job_id,
                "job_url": job_url,
                "job_status": job_state,
                "allocation_id": allocation_id,
                "allocation_url": detail_url,
                "allocation_status_code": detail_status,
                "evidence_sources": ["Nomad job status", "not observed"],
                "scheduler_error": detail_error or "allocation detail was not available",
                "explicit_stale_orphan_acceptance_required": False,
            }
        task_state = ((detail_payload.get("TaskStates") or {}).get("task") or {})
        client_status = str(detail_payload.get("ClientStatus") or "").strip()
        allocation_active = allocation_is_active(detail_payload)
        allocation_summaries.append(
            {
                "allocation_id": allocation_id,
                "client_status": client_status,
                "task_state": str(task_state.get("State") or "").strip(),
                "modify_index": detail_payload.get("ModifyIndex"),
                "active": allocation_active,
            }
        )
        if allocation_active:
            active_allocation_ids.append(allocation_id)

    if active_allocation_ids:
        return {
            "run_id": run_id,
            "classification": "active",
            "scheduler_state": "active",
            "summary": "Nomad still reports at least one non-terminal allocation for the run directory",
            "job_id": job_id,
            "job_url": job_url,
            "job_status": job_state,
            "allocations_url": allocations_url,
            "allocations_status_code": allocations_status,
            "allocations": allocation_summaries,
            "active_allocation_ids": active_allocation_ids,
            "evidence_sources": ["Nomad job status"],
            "explicit_stale_orphan_acceptance_required": False,
        }

    return {
        "run_id": run_id,
        "classification": "terminal",
        "scheduler_state": "terminal",
        "summary": "Nomad reports only terminal allocations for the run directory",
        "job_id": job_id,
        "job_url": job_url,
        "job_status": job_state,
        "allocations_url": allocations_url,
        "allocations_status_code": allocations_status,
        "allocations": allocation_summaries,
        "evidence_sources": ["Nomad job status", "filesystem-only legacy state"],
        "explicit_stale_orphan_acceptance_required": True,
    }


def preserve_existing_owner_label(meta):
    owner = str(meta.get("owner") or "").strip()
    return owner or str(meta.get("uid"))


def common_live_parent_path(runtime_status):
    runtime = runtime_status.get("runtime") or runtime_status.get("execution") or {}
    staging_root = str(runtime.get("staging_root_dir") or "").strip()
    results_root = str(runtime.get("results_root_dir") or "").strip()
    if not staging_root or not results_root:
        return "", "runtime config did not provide both staging/results roots"
    staging_parent = os.fspath(pathlib.Path(staging_root).parent)
    results_parent = os.fspath(pathlib.Path(results_root).parent)
    common_parent = os.path.commonpath([staging_root, results_root])
    if common_parent in {staging_root, results_root, "", "/"}:
        return "", "the live staging/results roots do not share a bounded common parent traversal directory"
    if staging_parent != common_parent or results_parent != common_parent:
        return "", "the live staging/results roots do not share the same direct parent; helper will not widen parent traversal scope"
    return common_parent, ""


def list_quarantined_root_paths(common_parent, runtime_status):
    runtime = runtime_status.get("runtime") or runtime_status.get("execution") or {}
    parent_path = pathlib.Path(common_parent)
    quarantined = []
    for root_name in (
        pathlib.Path(str(runtime.get("staging_root_dir") or "")).name,
        pathlib.Path(str(runtime.get("results_root_dir") or "")).name,
    ):
        if not root_name:
            continue
        prefix = root_name + ".pre-es-writable-state-ownership-"
        try:
            for child in sorted(parent_path.iterdir(), key=lambda item: item.name):
                if child.name.startswith(prefix):
                    quarantined.append(os.fspath(child))
        except Exception:  # noqa: BLE001
            break
    deduped = []
    for item in quarantined:
        if item not in deduped:
            deduped.append(item)
    return deduped


def inspect_parent_traversal(runtime_status, expected_uid, expected_gid):
    common_parent, error = common_live_parent_path(runtime_status)
    result = {
        "supported_fix": False,
        "path": common_parent,
        "changed_paths": [common_parent] if common_parent else [],
        "owner_strategy": "preserve_existing_owner",
        "target_group": SERVICE_GROUP,
        "target_gid": expected_gid,
        "target_mode": "0750",
        "target_owner": "",
        "target_owner_uid": None,
        "quarantined_paths_observed": [],
        "quarantined_paths_touched_in_apply": False,
        "ancestor_chain": [],
        "ancestor_chain_traversable_for_es": False,
        "needs_owner_or_mode_change": False,
    }
    if error:
        return make_status("blocker", error, **result)

    meta = stat_path(common_parent)
    result.update(
        {
            "exists": meta["exists"],
            "owner": meta["owner"],
            "group": meta["group"],
            "owner_uid": meta["uid"],
            "owner_gid": meta["gid"],
            "mode": meta["mode"],
            "mode_bits": meta["mode_bits"],
            "file_type": meta["file_type"],
            "size": meta["size"],
            "target_owner": preserve_existing_owner_label(meta),
            "target_owner_uid": meta["uid"],
            "quarantined_paths_observed": list_quarantined_root_paths(common_parent, runtime_status),
        }
    )
    if not meta["exists"]:
        return make_status("blocker", f"parent traversal path does not exist: {common_parent}", **result)
    if meta["file_type"] != "directory":
        return make_status("blocker", f"parent traversal path is not a directory: {common_parent}", **result)

    ancestors_ok = True
    blocked_ancestor = ""
    for ancestor in ancestor_chain(pathlib.Path(common_parent).parent):
        ancestor_meta = stat_path(ancestor)
        result["ancestor_chain"].append(
            {
                "path": ancestor,
                "exists": ancestor_meta["exists"],
                "owner": ancestor_meta["owner"],
                "group": ancestor_meta["group"],
                "mode": ancestor_meta["mode"],
            }
        )
        if not ancestor_meta["exists"]:
            ancestors_ok = False
            blocked_ancestor = ancestor
            break
        if preserved_owner_permission_bits(ancestor_meta, expected_gid) & 0o1 == 0:
            ancestors_ok = False
            blocked_ancestor = ancestor
            break
    result["ancestor_chain_traversable_for_es"] = ancestors_ok
    target_uid = meta["uid"]
    target_gid = expected_gid
    needs_change = preserved_owner_permission_bits(meta, expected_gid) & 0o1 == 0
    result["needs_owner_or_mode_change"] = needs_change
    result["supported_fix"] = True
    result["target_owner_uid"] = target_uid
    if not ancestors_ok:
        result["ancestor_chain_warning"] = (
            "ancestor traversal above the bounded common parent path was not modeled as future-es-compatible; this helper will not widen scope beyond "
            + common_parent
        )
        result["blocked_ancestor_path"] = blocked_ancestor

    if not needs_change:
        return make_status(
            "pass",
            "common parent traversal directory already grants bounded ES traversal without changing ownership",
            **result,
        )
    return make_status(
        "warning",
        "common parent traversal directory can be prepared for bounded ES traversal by preserving the existing owner and setting group "
        + SERVICE_GROUP
        + " mode 0750",
        **result,
    )


def inspect_root(path, expected_uid, expected_gid):
    meta = stat_path(path)
    result = {
        "path": path,
        "target_owner": SERVICE_USER,
        "target_group": SERVICE_GROUP,
        "target_uid": expected_uid,
        "target_gid": expected_gid,
        "target_mode": "0750",
        "exists": meta["exists"],
        "owner": meta["owner"],
        "group": meta["group"],
        "owner_uid": meta["uid"],
        "owner_gid": meta["gid"],
        "mode": meta["mode"],
        "mode_bits": meta["mode_bits"],
        "file_type": meta["file_type"],
        "size": meta["size"],
        "entries": [],
        "entry_count": 0,
        "empty": False,
        "parent_chain": [],
        "parent_chain_traversable_for_es": False,
        "apply_can_fix_with_root_only_reowner": False,
        "blocked_parent_path": "",
    }
    if not meta["exists"]:
        return make_status("blocker", f"path does not exist: {path}", **result)
    if meta["file_type"] != "directory":
        return make_status("blocker", f"path is not a directory: {path}", **result)

    parent_ok = True
    direct_parent = pathlib.Path(path).parent
    parent_chain_paths = ancestor_chain(direct_parent)
    direct_parent_rendered = os.fspath(direct_parent)
    if not parent_chain_paths or parent_chain_paths[-1] != direct_parent_rendered:
        parent_chain_paths.append(direct_parent_rendered)
    for ancestor in parent_chain_paths:
        ancestor_meta = stat_path(ancestor)
        result["parent_chain"].append(
            {
                "path": ancestor,
                "exists": ancestor_meta["exists"],
                "owner": ancestor_meta["owner"],
                "group": ancestor_meta["group"],
                "mode": ancestor_meta["mode"],
            }
        )
        if not ancestor_meta["exists"]:
            parent_ok = False
            result["blocked_parent_path"] = ancestor
            break
        if selected_permission_bits(ancestor_meta, expected_uid, expected_gid) & 0o1 == 0:
            parent_ok = False
            result["blocked_parent_path"] = ancestor
    result["parent_chain_traversable_for_es"] = parent_ok
    result["apply_can_fix_with_root_only_reowner"] = parent_ok

    entries = []
    try:
        for child in sorted(pathlib.Path(path).iterdir()):
            entries.append(child.name)
    except Exception as exc:  # noqa: BLE001
        return make_status("blocker", f"failed to list directory {path}: {exc}", **result)
    result["entries"] = entries[:20]
    result["entry_count"] = len(entries)
    result["empty"] = len(entries) == 0

    needs_reowner = meta["uid"] != expected_uid or meta["gid"] != expected_gid or meta["mode_bits"] != TARGET_MODE
    result["needs_reowner"] = needs_reowner
    result["nonempty_requires_rotation"] = bool(result["entry_count"] and needs_reowner)
    if not parent_ok:
        return make_status(
            "blocker",
            "changing only this stable root would not make it traversable/manageable for es because the parent chain remains blocked",
            **result,
        )
    if not result["empty"] and needs_reowner:
        return make_status(
            "blocker",
            "stable root contains existing entries and blocks default apply; explicit maintenance-window rotation is required instead of recursive ownership change",
            **result,
        )
    if not result["empty"]:
        result["needs_reowner"] = False
        result["nonempty_requires_rotation"] = False
        result["live_entries_require_artifact_reconciliation"] = True
        return make_status(
            "pass",
            "stable root already matches the documented es:es 0750 model; existing live entries require separate bounded artifact reconciliation rather than another root rotation",
            **result,
        )
    if needs_reowner:
        return make_status(
            "warning",
            "stable root is empty and can be re-owned to the documented es:es 0750 model",
            **result,
        )
    return make_status("pass", "stable root already matches the documented es:es 0750 model", **result)


def inspect_active_runs(runtime_status):
    runtime = runtime_status.get("runtime") or runtime_status.get("execution") or {}
    staging_root = runtime.get("staging_root_dir", "")
    results_root = runtime.get("results_root_dir", "")
    if runtime_status["classification"] == "blocker":
        return make_status("blocker", "active-run status cannot be evaluated because the ES config is invalid", observed_runs=[])

    staging_path = pathlib.Path(staging_root)
    results_path = pathlib.Path(results_root)
    try:
        children = sorted(staging_path.iterdir(), key=lambda item: item.name)
    except Exception as exc:  # noqa: BLE001
        return make_status("blocker", f"active-run inspection failed under execution.staging_root_dir: {exc}", observed_runs=[])

    if not children:
        return make_status("pass", "no staging-root run directories were observed", observed_runs=[])

    observed = []
    blockers = []
    legacy_acceptance_runs = []
    for child in children:
        if not child.is_dir():
            observed.append(
                {
                    "run_id": child.name,
                    "classification": "unknown",
                    "scheduler_state": "not_observed",
                    "summary": "unexpected non-directory entry under execution.staging_root_dir prevents safely ruling out live work",
                    "marker_path": str(child / "run" / "platform" / MARKER_NAME),
                    "retained_result_path": str(results_path / child.name / RESULT_BUNDLE_NAME),
                    "evidence_sources": ["not observed"],
                    "explicit_stale_orphan_acceptance_required": False,
                }
            )
            blockers.append(child.name)
            continue

        marker_path = child / "run" / "platform" / MARKER_NAME
        retained_bundle = results_path / child.name / RESULT_BUNDLE_NAME
        marker_exists = marker_path.exists()
        retained_exists = retained_bundle.exists()
        classification = "terminal"
        scheduler_state = "not_observed"
        summary = "completed-run evidence observed"
        evidence_sources = []
        explicit_stale_orphan_acceptance_required = False
        if marker_exists:
            try:
                payload = json.loads(marker_path.read_text(encoding="utf-8"))
            except Exception as exc:  # noqa: BLE001
                classification = "unknown"
                summary = f"normalization marker could not be read: {exc}"
                evidence_sources = ["normalization marker"]
            else:
                if payload.get("schema_version") != MARKER_SCHEMA_VERSION:
                    classification = "unknown"
                    summary = "normalization marker schema_version is invalid"
                elif str(payload.get("run_id") or "").strip() != child.name:
                    classification = "unknown"
                    summary = "normalization marker run_id does not match the staging-root run directory"
                evidence_sources = ["normalization marker"]
        elif retained_exists:
            classification = "terminal"
            summary = "retained result bundle observed for the run directory"
            evidence_sources = ["ES retained-result evidence"]
        else:
            scheduler_backed = classify_legacy_run_with_nomad(runtime_status, child.name)
            classification = scheduler_backed["classification"]
            scheduler_state = scheduler_backed.get("scheduler_state", "not_observed")
            summary = scheduler_backed["summary"]
            evidence_sources = scheduler_backed.get("evidence_sources", ["not observed"])
            explicit_stale_orphan_acceptance_required = scheduler_backed.get("explicit_stale_orphan_acceptance_required", False)

        observed_run = {
            "run_id": child.name,
            "classification": classification,
            "scheduler_state": scheduler_state,
            "summary": summary,
            "marker_path": str(marker_path),
            "marker_exists": marker_exists,
            "retained_result_path": str(retained_bundle),
            "retained_result_exists": retained_exists,
            "evidence_sources": evidence_sources,
            "explicit_stale_orphan_acceptance_required": explicit_stale_orphan_acceptance_required,
        }
        if not marker_exists and not retained_exists:
            observed_run.update(
                {
                    key: value
                    for key, value in scheduler_backed.items()
                    if key not in {"run_id", "classification", "scheduler_state", "summary", "evidence_sources", "explicit_stale_orphan_acceptance_required"}
                }
            )
        observed.append(observed_run)
        if classification in {"active", "unknown"}:
            blockers.append(child.name)
        elif explicit_stale_orphan_acceptance_required:
            legacy_acceptance_runs.append(child.name)

    if blockers:
        return make_status(
            "blocker",
            "active runs are present or cannot be safely ruled out: " + ", ".join(blockers),
            observed_runs=observed,
            legacy_orphan_acceptance_required=bool(legacy_acceptance_runs),
            legacy_orphan_acceptance_flag=STALE_ORPHAN_ACCEPTANCE_FLAG if legacy_acceptance_runs else "",
            legacy_orphan_acceptance_run_ids=legacy_acceptance_runs,
        )
    return make_status(
        "pass",
        (
            "all observed staging-root run directories are terminal, retained, or explicitly classifiable for bounded rotation"
            if not legacy_acceptance_runs
            else "all observed staging-root run directories are drain-safe, but legacy stale/orphan acceptance is still required for marker-free and retained-result-free runs"
        ),
        observed_runs=observed,
        legacy_orphan_acceptance_required=bool(legacy_acceptance_runs),
        legacy_orphan_acceptance_flag=STALE_ORPHAN_ACCEPTANCE_FLAG if legacy_acceptance_runs else "",
        legacy_orphan_acceptance_run_ids=legacy_acceptance_runs,
    )


def artifact_quarantine_root_hint(live_root):
    root = pathlib.Path(live_root)
    return os.fspath(root.with_name(root.name + ".reconcile-es-writable-state-ownership-" + utc_stamp()))


def direct_child_names(path):
    try:
        return sorted(child.name for child in pathlib.Path(path).iterdir())
    except Exception:
        return []


def stat_matches_expected(meta, expected_uid, expected_gid, expected_mode):
    return (
        meta.get("exists") is True
        and meta.get("uid") == expected_uid
        and meta.get("gid") == expected_gid
        and meta.get("mode_bits") == expected_mode
    )


def inspect_retained_artifact_reconciliation(runtime_status, expected_uid, expected_gid):
    runtime = runtime_status.get("runtime") or runtime_status.get("execution") or {}
    results_root = str(runtime.get("results_root_dir") or "").strip()
    quarantine_root_hint = artifact_quarantine_root_hint(results_root) if results_root else ""
    result = {
        "supported": True,
        "apply_ready": False,
        "explicit_flag": RECONCILE_FLAG,
        "results_quarantine_root_hint": quarantine_root_hint,
        "retained_run_candidates": [],
        "changed_paths": [],
    }
    if runtime_status["classification"] == "blocker" or not results_root:
        return make_status(
            "not_observed",
            "retained-result artifact reconciliation could not be evaluated because execution.results_root_dir is unavailable",
            **result,
        )

    results_root_path = pathlib.Path(results_root)
    if not results_root_path.is_dir():
        return make_status(
            "not_observed",
            "no live retained-result run directories were observed under execution.results_root_dir",
            **result,
        )

    blocking = False
    warning = False
    allowed_names = {RESULT_BUNDLE_NAME, MARKER_NAME}
    for run_dir in sorted(child for child in results_root_path.iterdir() if child.is_dir()):
        run_dir_meta = stat_path(run_dir)
        direct_entries = direct_child_names(run_dir)
        bundle_path = run_dir / RESULT_BUNDLE_NAME
        sidecar_path = run_dir / MARKER_NAME
        bundle_exists = bundle_path.exists()
        sidecar_exists = sidecar_path.exists()
        if not bundle_exists and not sidecar_exists:
            continue

        unexpected_entries = [name for name in direct_entries if name not in allowed_names]
        bundle_meta = stat_path(bundle_path)
        sidecar_meta = stat_path(sidecar_path)
        bundle_access = inspect_file_access(bundle_path, expected_uid, expected_gid) if bundle_exists else None
        sidecar_access = inspect_file_access(sidecar_path, expected_uid, expected_gid) if sidecar_exists else None

        dir_needs_change = not stat_matches_expected(run_dir_meta, expected_uid, expected_gid, TARGET_MODE)
        bundle_needs_change = bundle_exists and (
            not stat_matches_expected(bundle_meta, expected_uid, expected_gid, 0o600)
            or not bundle_access["es_can_read"]
            or bundle_access["file_type"] != "regular file"
        )
        sidecar_needs_change = sidecar_exists and (
            not stat_matches_expected(sidecar_meta, expected_uid, expected_gid, 0o640)
            or not sidecar_access["es_can_read"]
            or sidecar_access["file_type"] != "regular file"
        )
        compatible = bundle_exists and sidecar_exists and not unexpected_entries and not dir_needs_change and not bundle_needs_change and not sidecar_needs_change

        planned_action = "none"
        summary = "retained run directory already matches the future-es-readable model"
        target_path = ""
        direct_repair_scope = [os.fspath(run_dir), os.fspath(bundle_path)]
        if sidecar_exists:
            direct_repair_scope.append(os.fspath(sidecar_path))

        if unexpected_entries or not bundle_exists or not sidecar_exists:
            planned_action = "quarantine_retained_run_dir"
            target_path = os.fspath(pathlib.Path(quarantine_root_hint) / run_dir.name) if quarantine_root_hint else ""
            warning = True
            summary = (
                "retained run directory lacks the preserved normalization evidence required for future non-root proof and must be quarantined outside the live results root"
                if not unexpected_entries and bundle_exists and not sidecar_exists
                else "retained run directory falls outside the bounded in-place repair scope and must be quarantined outside the live results root"
            )
            result["changed_paths"].append(os.fspath(run_dir))
        elif compatible:
            planned_action = "none"
        else:
            planned_action = "repair_retained_artifacts_in_place"
            warning = True
            summary = "retained run directory can be repaired in place by reconciling only the run dir, bundle, and preserved normalization sidecar"
            result["changed_paths"].extend(direct_repair_scope)

        observed = {
            "run_id": run_dir.name,
            "classification": "warning" if planned_action != "none" else "pass",
            "summary": summary,
            "planned_action": planned_action,
            "current_path": os.fspath(run_dir),
            "quarantine_target": target_path,
            "unexpected_direct_entries": unexpected_entries,
            "direct_entries": direct_entries,
            "run_dir": {
                "path": os.fspath(run_dir),
                "owner": run_dir_meta["owner"],
                "group": run_dir_meta["group"],
                "mode": run_dir_meta["mode"],
                "target_owner": SERVICE_USER,
                "target_group": SERVICE_GROUP,
                "target_mode": "0750",
            },
            "bundle": {
                "path": os.fspath(bundle_path),
                "exists": bundle_exists,
                "owner": bundle_meta["owner"],
                "group": bundle_meta["group"],
                "mode": bundle_meta["mode"],
                "target_owner": SERVICE_USER,
                "target_group": SERVICE_GROUP,
                "target_mode": "0600",
                "es_can_read": None if bundle_access is None else bundle_access["es_can_read"],
            },
            "preserved_normalization_evidence": {
                "path": os.fspath(sidecar_path),
                "exists": sidecar_exists,
                "owner": sidecar_meta["owner"],
                "group": sidecar_meta["group"],
                "mode": sidecar_meta["mode"],
                "target_owner": SERVICE_USER,
                "target_group": SERVICE_GROUP,
                "target_mode": "0640",
                "es_can_read": None if sidecar_access is None else sidecar_access["es_can_read"],
            },
        }
        result["retained_run_candidates"].append(observed)

    result["apply_ready"] = warning and not blocking
    if blocking:
        return make_status(
            "blocker",
            "one or more retained-result artifacts fall outside the bounded reconciliation scope",
            **result,
        )
    if warning:
        return make_status(
            "warning",
            "bounded retained-result artifact reconciliation is available if the operator passes --apply --reconcile-artifacts",
            **result,
        )
    return make_status("pass", "no retained-result artifacts require bounded reconciliation", **result)


def inspect_stage_root_reconciliation(runtime_status, expected_uid, expected_gid, active_run_status):
    runtime = runtime_status.get("runtime") or runtime_status.get("execution") or {}
    staging_root = str(runtime.get("staging_root_dir") or "").strip()
    quarantine_root_hint = artifact_quarantine_root_hint(staging_root) if staging_root else ""
    result = {
        "supported": True,
        "apply_ready": False,
        "explicit_flag": RECONCILE_FLAG,
        "staging_quarantine_root_hint": quarantine_root_hint,
        "stage_root_candidates": [],
        "changed_paths": [],
    }
    if runtime_status["classification"] == "blocker" or not staging_root:
        return make_status(
            "not_observed",
            "staging-root artifact reconciliation could not be evaluated because execution.staging_root_dir is unavailable",
            **result,
        )

    staging_root_path = pathlib.Path(staging_root)
    if not staging_root_path.is_dir():
        return make_status(
            "not_observed",
            "no live run-scoped staging roots were observed under execution.staging_root_dir",
            **result,
        )

    observed_runs = {
        str(item.get("run_id") or ""): item
        for item in active_run_status.get("observed_runs", [])
        if isinstance(item, dict) and str(item.get("run_id") or "").strip()
    }
    blocking = False
    warning = False
    for run_dir in sorted(child for child in staging_root_path.iterdir() if child.is_dir()):
        access = inspect_directory_access(run_dir, expected_uid, expected_gid)
        meta = stat_path(run_dir)
        compatible = (
            access["path_exists"]
            and meta["uid"] == expected_uid
            and meta["gid"] == expected_gid
            and meta["mode_bits"] == TARGET_MODE
            and access["es_can_manage_entries"]
            and access["es_can_read"]
        )
        if compatible:
            continue

        run_id = run_dir.name
        evidence = observed_runs.get(run_id, {})
        classification = str(evidence.get("classification") or "unknown")
        scheduler_state = str(evidence.get("scheduler_state") or "not_observed")
        planned_action = "quarantine_stage_root"
        candidate_classification = "warning"
        summary = "inactive incompatible run-scoped stage root can be quarantined outside the live staging root"
        if classification in {"active", "unknown"}:
            blocking = True
            planned_action = "block"
            candidate_classification = "blocker"
            summary = "run-scoped stage root cannot be moved because active or unknown scheduler state still blocks mutation"
        else:
            warning = True
            result["changed_paths"].append(os.fspath(run_dir))

        result["stage_root_candidates"].append(
            {
                "run_id": run_id,
                "classification": candidate_classification,
                "summary": summary,
                "planned_action": planned_action,
                "current_path": os.fspath(run_dir),
                "quarantine_target": "" if planned_action == "block" else os.fspath(pathlib.Path(quarantine_root_hint) / run_id),
                "current_owner": meta["owner"],
                "current_group": meta["group"],
                "current_mode": meta["mode"],
                "target_owner": SERVICE_USER,
                "target_group": SERVICE_GROUP,
                "target_mode": "0750",
                "es_can_traverse": access["es_can_traverse"],
                "es_can_read": access["es_can_read"],
                "es_can_manage_entries": access["es_can_manage_entries"],
                "run_state_classification": classification,
                "scheduler_state": scheduler_state,
                "evidence_sources": evidence.get("evidence_sources", ["not observed"]),
            }
        )

    result["apply_ready"] = warning and not blocking
    if blocking:
        return make_status(
            "blocker",
            "one or more incompatible run-scoped stage roots cannot be reconciled because active or unknown run state remains",
            **result,
        )
    if warning:
        return make_status(
            "warning",
            "bounded incompatible stage-root reconciliation is available if the operator passes --apply --reconcile-artifacts",
            **result,
        )
    return make_status("pass", "no run-scoped staging roots require bounded reconciliation", **result)


def inspect_artifact_reconciliation(runtime_status, expected_uid, expected_gid, active_run_status):
    retained_status = inspect_retained_artifact_reconciliation(runtime_status, expected_uid, expected_gid)
    stage_status = inspect_stage_root_reconciliation(runtime_status, expected_uid, expected_gid, active_run_status)
    blocking = retained_status["classification"] == "blocker" or stage_status["classification"] == "blocker"
    warning = retained_status["classification"] == "warning" or stage_status["classification"] == "warning"
    changed_paths = []
    for status in (retained_status, stage_status):
        for path in status.get("changed_paths", []):
            if path not in changed_paths:
                changed_paths.append(path)
    return make_status(
        "blocker" if blocking else "warning" if warning else "pass",
        (
            "bounded incompatible live artifacts cannot be reconciled safely under the current gates"
            if blocking
            else (
                "bounded incompatible live artifact reconciliation is available if the operator passes --apply --reconcile-artifacts"
                if warning
                else "no incompatible live artifacts require bounded reconciliation"
            )
        ),
        supported=True,
        apply_ready=(retained_status.get("apply_ready") or stage_status.get("apply_ready")) and not blocking,
        explicit_flag=RECONCILE_FLAG,
        changed_paths=changed_paths,
        retained_results=retained_status,
        stage_roots=stage_status,
    )


def compute_check_summary():
    service_status = inspect_service_meta()
    account_status = inspect_service_account()
    healthcheck_env_status = load_healthcheck_env(HEALTHCHECK_ENV_PATH)
    runtime_status = load_runtime_config()
    blockers = []
    warnings = []

    if service_status["classification"] == "blocker":
        blockers.append({"scope": "service_posture", "summary": service_status["summary"]})
    if account_status["classification"] == "blocker":
        blockers.append({"scope": "service_account", "summary": account_status["summary"]})
    if healthcheck_env_status["classification"] == "blocker":
        blockers.append({"scope": "healthcheck_env", "summary": healthcheck_env_status["summary"]})
    if runtime_status["classification"] == "blocker":
        blockers.append({"scope": "runtime_config", "summary": runtime_status["summary"]})

    staging_status = make_status("blocker", "staging root was not inspected")
    results_status = make_status("blocker", "results root was not inspected")
    parent_traversal_status = make_status("blocker", "parent traversal path was not inspected")
    active_run_status = make_status("not_observed", "active-run/drain state was not observed")
    artifact_reconciliation_status = make_status("not_observed", "artifact reconciliation was not inspected")
    changing_only_roots_would_help = False
    roots_nonempty_requires_rotation = False

    if account_status["classification"] == "pass" and runtime_status["classification"] == "pass":
        uid = account_status["uid"]
        gid = account_status["gid"]
        staging_status = inspect_root(runtime_status["execution"]["staging_root_dir"], uid, gid)
        results_status = inspect_root(runtime_status["execution"]["results_root_dir"], uid, gid)
        parent_traversal_status = inspect_parent_traversal(runtime_status, uid, gid)
        if staging_status["classification"] == "blocker":
            blockers.append({"scope": "staging_root", "summary": staging_status["summary"]})
        elif staging_status["classification"] == "warning":
            warnings.append({"scope": "staging_root", "summary": staging_status["summary"]})
        if results_status["classification"] == "blocker":
            blockers.append({"scope": "results_root", "summary": results_status["summary"]})
        elif results_status["classification"] == "warning":
            warnings.append({"scope": "results_root", "summary": results_status["summary"]})
        if parent_traversal_status["classification"] == "blocker":
            blockers.append({"scope": "parent_traversal", "summary": parent_traversal_status["summary"]})
        elif parent_traversal_status["classification"] == "warning":
            warnings.append({"scope": "parent_traversal", "summary": parent_traversal_status["summary"]})

        changing_only_roots_would_help = (
            staging_status.get("apply_can_fix_with_root_only_reowner") is True
            and results_status.get("apply_can_fix_with_root_only_reowner") is True
        )
        roots_nonempty_requires_rotation = bool(
            staging_status.get("nonempty_requires_rotation") or results_status.get("nonempty_requires_rotation")
        )

        active_run_status = inspect_active_runs(runtime_status)
        if active_run_status["classification"] == "blocker":
            blockers.append({"scope": "active_run_or_retained_content", "summary": active_run_status["summary"]})

        artifact_reconciliation_status = inspect_artifact_reconciliation(runtime_status, uid, gid, active_run_status)
        if artifact_reconciliation_status["classification"] == "blocker":
            blockers.append({"scope": "artifact_reconciliation", "summary": artifact_reconciliation_status["summary"]})
        elif artifact_reconciliation_status["classification"] == "warning":
            warnings.append({"scope": "artifact_reconciliation", "summary": artifact_reconciliation_status["summary"]})

    roots_need_change = bool(staging_status.get("needs_reowner")) or bool(results_status.get("needs_reowner"))
    rotation_supported = roots_nonempty_requires_rotation and changing_only_roots_would_help
    parent_traversal_fix_supported = parent_traversal_status.get("supported_fix") is True
    parent_traversal_needs_change = bool(parent_traversal_status.get("needs_owner_or_mode_change"))
    legacy_orphan_acceptance_required = bool(active_run_status.get("legacy_orphan_acceptance_required"))
    rotation_explicit_flags_required = []
    if rotation_supported:
        rotation_explicit_flags_required.append(ROTATION_FLAG)
    if legacy_orphan_acceptance_required:
        rotation_explicit_flags_required.append(STALE_ORPHAN_ACCEPTANCE_FLAG)
    parent_traversal_apply_ready = (
        parent_traversal_fix_supported
        and parent_traversal_needs_change
        and service_status["classification"] == "pass"
        and account_status["classification"] == "pass"
        and healthcheck_env_status["classification"] == "pass"
        and runtime_status["classification"] == "pass"
        and active_run_status["classification"] == "pass"
        and not roots_need_change
        and not rotation_supported
    )
    rotation_apply_ready = (
        rotation_supported
        and service_status["classification"] == "pass"
        and account_status["classification"] == "pass"
        and healthcheck_env_status["classification"] == "pass"
        and runtime_status["classification"] == "pass"
        and active_run_status["classification"] == "pass"
    )
    artifact_reconciliation_apply_ready = (
        artifact_reconciliation_status.get("apply_ready") is True
        and service_status["classification"] == "pass"
        and account_status["classification"] == "pass"
        and healthcheck_env_status["classification"] == "pass"
        and runtime_status["classification"] == "pass"
        and active_run_status["classification"] == "pass"
        and not roots_need_change
        and not rotation_supported
        and not parent_traversal_needs_change
    )
    blocker_scopes = {item["scope"] for item in blockers}
    only_nonempty_root_blockers = blocker_scopes.issubset({"staging_root", "results_root"}) and roots_nonempty_requires_rotation and rotation_apply_ready
    only_parent_traversal_blockers = blocker_scopes.issubset({"staging_root", "results_root"}) and parent_traversal_apply_ready
    only_artifact_reconciliation_warnings = (
        not blockers
        and artifact_reconciliation_status["classification"] == "warning"
        and not rotation_supported
        and not parent_traversal_needs_change
        and not roots_need_change
    )
    rollback_notes = [
        "Restore the pre-apply owner/group/mode snapshot for the two stable roots only.",
        "Do not recursively re-owner retained run/debug trees as part of rollback for this bounded slice.",
    ]
    if rotation_supported:
        rollback_notes = [
            "Stop es.service before rollback.",
            "Remove the fresh live staging/results roots only if they are empty or capture them separately before rollback.",
            "Move the preserved old roots back to the configured execution.staging_root_dir and execution.results_root_dir paths.",
            "Start es.service and revalidate /health and /v1/executions:contract after rollback.",
            "Confirm es.service remains root(default) after rollback.",
        ]
    elif parent_traversal_needs_change:
        rollback_notes = [
            "Restore the pre-apply owner/group/mode snapshot for the bounded parent traversal path only.",
            "Preserve the existing parent owner strategy on rollback; do not make ES the owner of unrelated host state.",
            "Do not recursively re-owner retained run/debug trees or quarantined old roots as part of rollback.",
            "Confirm es.service remains root(default); the parent-only traversal fix should not require a restart.",
        ]
    elif artifact_reconciliation_apply_ready:
        rollback_notes = [
            "Restore the pre-apply owner/group/mode snapshot for any retained run directory, retained bundle, or preserved normalization sidecar that was repaired in place.",
            "Move each quarantined retained-result or stage-root directory back only if the original live path is absent and the operator has confirmed the restored path is still safe to expose.",
            "Do not recursively re-owner arbitrary retained/debug trees as part of rollback for this bounded artifact-reconciliation slice.",
            "Confirm es.service remains root(default); bounded artifact reconciliation should not require a restart.",
        ]
    overall = "blocker" if blockers else ("warning" if warnings else "pass")
    summary = {
        "schema_version": SCHEMA_VERSION,
        "mode": {
            "name": "check_only",
            "non_mutating": True,
            "explicit_apply_required": True,
        },
        "proof": {
            "check_only_is_not_proof": True,
            "host_mutation_performed": False,
        },
        "service": {
            "name": SERVICE_NAME,
            "service_user": SERVICE_USER,
            "service_group": SERVICE_GROUP,
            "config_path": CONFIG_PATH,
            "healthcheck_env_path": HEALTHCHECK_ENV_PATH,
            "service_unit_path": SERVICE_UNIT_PATH,
        },
        "validation": {
            "es_service_posture": service_status,
            "service_account_narrowness": account_status,
            "healthcheck_env": healthcheck_env_status,
            "runtime_config": runtime_status,
            "parent_traversal": parent_traversal_status,
            "active_run_or_drain": active_run_status,
            "artifact_reconciliation": artifact_reconciliation_status,
        },
        "roots": {
            "staging": staging_status,
            "results": results_status,
        },
        "plan": {
            "apply_ready": (
                not blockers
                and artifact_reconciliation_status["classification"] == "pass"
                and not parent_traversal_needs_change
                and not rotation_supported
            ),
            "roots_need_change": roots_need_change,
            "roots_nonempty_block_apply": roots_nonempty_requires_rotation,
            "changing_only_root_directories_would_make_es_manageable": changing_only_roots_would_help,
            "target_owner": f"{SERVICE_USER}:{SERVICE_GROUP}",
            "target_mode": "0750",
            "changed_paths": [
                runtime_status["execution"]["staging_root_dir"] if runtime_status["classification"] == "pass" else "",
                runtime_status["execution"]["results_root_dir"] if runtime_status["classification"] == "pass" else "",
            ],
            "backup_parent_dir": BACKUP_ROOT_DIR,
            "restart_required_in_apply_mode": rotation_supported,
            "rotation_apply_ready": rotation_apply_ready,
            "rotation_requires_explicit_flag": rotation_supported,
            "rotation_flag": ROTATION_FLAG,
            "rotation_explicit_flags_required": rotation_explicit_flags_required,
            "legacy_orphan_acceptance_required": legacy_orphan_acceptance_required,
            "legacy_orphan_acceptance_flag": STALE_ORPHAN_ACCEPTANCE_FLAG if legacy_orphan_acceptance_required else "",
            "rotation_maintenance_window_required": rotation_supported,
            "rotation_preserves_old_roots": rotation_supported,
            "rotation_preserves_old_root_contents_without_recursive_chown": rotation_supported,
            "only_nonempty_root_blockers": only_nonempty_root_blockers,
            "parent_traversal_fix_supported": parent_traversal_fix_supported,
            "parent_traversal_apply_ready": parent_traversal_apply_ready,
            "parent_traversal_requires_explicit_flag": parent_traversal_needs_change,
            "parent_traversal_flag": PARENT_CHAIN_FLAG if parent_traversal_fix_supported else "",
            "parent_traversal_changed_paths": parent_traversal_status.get("changed_paths", []),
            "parent_traversal_target_owner_strategy": parent_traversal_status.get("owner_strategy", ""),
            "parent_traversal_target_owner": parent_traversal_status.get("target_owner", ""),
            "parent_traversal_target_group": parent_traversal_status.get("target_group", ""),
            "parent_traversal_target_mode": parent_traversal_status.get("target_mode", ""),
            "only_parent_traversal_blockers": only_parent_traversal_blockers,
            "artifact_reconciliation_apply_ready": artifact_reconciliation_apply_ready,
            "artifact_reconciliation_requires_explicit_flag": artifact_reconciliation_status["classification"] == "warning",
            "artifact_reconciliation_flag": RECONCILE_FLAG,
            "artifact_reconciliation_changed_paths": artifact_reconciliation_status.get("changed_paths", []),
            "only_artifact_reconciliation_warnings": only_artifact_reconciliation_warnings,
            "blockers": blockers,
            "warnings": warnings,
            "rollback_notes": rollback_notes,
        },
        "parent_traversal": {
            "supported": parent_traversal_fix_supported,
            "apply_ready": parent_traversal_apply_ready,
            "explicit_flag": PARENT_CHAIN_FLAG if parent_traversal_fix_supported else "",
            "changed_paths": parent_traversal_status.get("changed_paths", []),
            "target_owner_strategy": parent_traversal_status.get("owner_strategy", ""),
            "target_owner": parent_traversal_status.get("target_owner", ""),
            "target_group": parent_traversal_status.get("target_group", ""),
            "target_mode": parent_traversal_status.get("target_mode", ""),
            "quarantined_paths_observed": parent_traversal_status.get("quarantined_paths_observed", []),
            "summary": (
                "explicit parent-chain traversal preparation is available if the operator passes --apply --fix-parent-chain"
                if parent_traversal_apply_ready
                else (
                    "common parent traversal is already compatible with future non-root ES"
                    if parent_traversal_fix_supported and not parent_traversal_needs_change
                    else (
                        "parent-chain traversal can be prepared with an explicit bounded parent-only fix"
                        if parent_traversal_fix_supported
                        else "bounded parent-chain traversal preparation is not available under the current gates"
                    )
                )
            ),
        },
        "rotation": {
            "supported": rotation_supported,
            "apply_ready": rotation_apply_ready,
            "explicit_flag": ROTATION_FLAG,
            "explicit_flags_required": rotation_explicit_flags_required,
            "legacy_orphan_acceptance_required": legacy_orphan_acceptance_required,
            "legacy_orphan_acceptance_flag": STALE_ORPHAN_ACCEPTANCE_FLAG if legacy_orphan_acceptance_required else "",
            "maintenance_window_required": rotation_supported,
            "service_stop_required": rotation_supported,
            "service_start_required": rotation_supported,
            "old_roots_preserved": rotation_supported,
            "old_root_recursive_chown_forbidden": True,
            "old_root_delete_forbidden": True,
            "summary": (
                (
                    "explicit maintenance-window root rotation is available if the operator passes --apply --rotate-nonempty-roots"
                    if not legacy_orphan_acceptance_required
                    else "explicit maintenance-window root rotation is available if the operator passes --apply --rotate-nonempty-roots --accept-stale-orphaned-runs"
                )
                if rotation_apply_ready
                else (
                    "non-empty roots require an explicit maintenance-window root rotation path"
                    if rotation_supported
                    else "non-empty root rotation is not available under the current gates"
                )
            ),
        },
        "artifact_reconciliation": {
            "supported": True,
            "apply_ready": artifact_reconciliation_apply_ready,
            "explicit_flag": RECONCILE_FLAG,
            "changed_paths": artifact_reconciliation_status.get("changed_paths", []),
            "retained_results": artifact_reconciliation_status.get("retained_results", {}),
            "stage_roots": artifact_reconciliation_status.get("stage_roots", {}),
            "summary": (
                "explicit bounded live-artifact reconciliation is available if the operator passes --apply --reconcile-artifacts"
                if artifact_reconciliation_apply_ready
                else (
                    "bounded live-artifact reconciliation is not required"
                    if artifact_reconciliation_status["classification"] == "pass"
                    else artifact_reconciliation_status["summary"]
                )
            ),
        },
        "blockers": blockers,
        "warnings": warnings,
        "not_claimed": {
            "service_user_change": True,
            "recursive_retained_tree_reownership": True,
            "config_or_tls_rewrite": True,
            "governed_proof": True,
            "nomad_task_user_model_change": True,
            "runtime_helper_design_change": True,
            "vault_runtime_handoff_change": True,
        },
        "result": {
            "status": overall,
            "ok": not blockers,
            "non_mutating": True,
        },
        "overall_classification": overall,
    }
    return summary


def write_json(path, payload):
    pathlib.Path(path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def choose_backup_dir(prefix):
    root = pathlib.Path(BACKUP_ROOT_DIR)
    base_name = prefix + "-" + utc_stamp()
    candidate = root / base_name
    suffix = 0
    while candidate.exists():
        suffix += 1
        candidate = root / f"{base_name}-{suffix}"
    return candidate


def create_backup(summary, rotation_mode):
    backup_dir = choose_backup_dir("es-writable-state-ownership")
    backup_dir.mkdir(parents=True, exist_ok=False)
    observed_quarantined_roots = []
    for path in summary["validation"].get("parent_traversal", {}).get("quarantined_paths_observed", []):
        observed_quarantined_roots.append(inspect_preserved_root(path))
    snapshot = {
        "created_at": utc_now(),
        "rotation_mode": rotation_mode,
        "service": summary["validation"]["es_service_posture"],
        "service_account": summary["validation"]["service_account_narrowness"],
        "healthcheck_env": summary["validation"]["healthcheck_env"],
        "runtime_config": summary["validation"]["runtime_config"],
        "parent_traversal": summary["validation"]["parent_traversal"],
        "artifact_reconciliation": summary["validation"].get("artifact_reconciliation", {}),
        "roots": summary["roots"],
        "quarantined_roots_observed": observed_quarantined_roots,
        "config_sha256": sha256_file(CONFIG_PATH),
        "service_unit_sha256": safe_sha256(SERVICE_UNIT_PATH),
        "active_run_or_drain": summary["validation"]["active_run_or_drain"],
        "rollback_notes": summary["plan"]["rollback_notes"],
    }
    snapshot_path = backup_dir / "pre-apply-snapshot.json"
    write_json(snapshot_path, snapshot)

    backup_path_file = os.environ.get("REMOTE_ALPHA_TEST_BACKUP_PATH_FILE", "").strip()
    if backup_path_file:
        pathlib.Path(backup_path_file).write_text(str(backup_dir), encoding="utf-8")
    backup_sentinel = os.environ.get("REMOTE_ALPHA_TEST_BACKUP_SENTINEL_PATH", "").strip()
    if backup_sentinel:
        pathlib.Path(backup_sentinel).write_text(str(snapshot_path), encoding="utf-8")

    return {
        "status": "created",
        "path": os.fspath(backup_dir),
        "snapshot_manifest_path": os.fspath(snapshot_path),
        "rollback_notes": summary["plan"]["rollback_notes"],
        "snapshot": snapshot,
    }


def apply_root_change(path, target_uid, target_gid):
    os.chown(path, target_uid, target_gid)
    os.chmod(path, TARGET_MODE)


def service_unit_name():
    return SERVICE_NAME if SERVICE_NAME.endswith(".service") else SERVICE_NAME + ".service"


def stop_service():
    run_command(["systemctl", "stop", service_unit_name()], check=True)


def start_service():
    run_command(["systemctl", "start", service_unit_name()], check=True)


def choose_quarantine_path(live_path):
    source = pathlib.Path(live_path)
    base_name = source.name + ".pre-es-writable-state-ownership-" + utc_stamp()
    candidate = source.with_name(base_name)
    suffix = 0
    while candidate.exists():
        suffix += 1
        candidate = source.with_name(base_name + f"-{suffix}")
    return candidate


def choose_artifact_quarantine_root(live_root):
    root = pathlib.Path(live_root)
    base_name = root.name + ".reconcile-es-writable-state-ownership-" + utc_stamp()
    candidate = root.with_name(base_name)
    suffix = 0
    while candidate.exists():
        suffix += 1
        candidate = root.with_name(base_name + f"-{suffix}")
    return candidate


def create_root_owned_quarantine_root(path):
    root_path = pathlib.Path(path)
    root_path.mkdir(parents=False, exist_ok=False)
    if os.geteuid() == 0:
        os.chown(root_path, 0, 0)
    os.chmod(root_path, 0o700)


def repair_retained_result_artifact_paths(candidate, target_uid, target_gid):
    run_dir_path = candidate["run_dir"]["path"]
    apply_root_change(run_dir_path, target_uid, target_gid)
    bundle_path = candidate["bundle"]["path"]
    if candidate["bundle"]["exists"]:
        os.chown(bundle_path, target_uid, target_gid)
        os.chmod(bundle_path, 0o600)
    evidence_path = candidate["preserved_normalization_evidence"]["path"]
    if candidate["preserved_normalization_evidence"]["exists"]:
        os.chown(evidence_path, target_uid, target_gid)
        os.chmod(evidence_path, 0o640)


def inspect_preserved_root(path):
    meta = stat_path(path)
    result = {
        "path": os.fspath(path),
        "exists": meta["exists"],
        "owner": meta["owner"],
        "group": meta["group"],
        "owner_uid": meta["uid"],
        "owner_gid": meta["gid"],
        "mode": meta["mode"],
        "mode_bits": meta["mode_bits"],
        "file_type": meta["file_type"],
        "size": meta["size"],
        "entries": [],
        "entry_count": 0,
        "empty": False,
    }
    if not meta["exists"]:
        return make_status("blocker", f"preserved root is missing: {path}", **result)
    if meta["file_type"] != "directory":
        return make_status("blocker", f"preserved root is not a directory: {path}", **result)
    try:
        entries = sorted(child.name for child in pathlib.Path(path).iterdir())
    except Exception as exc:  # noqa: BLE001
        return make_status("blocker", f"failed to list preserved root {path}: {exc}", **result)
    result["entries"] = entries[:20]
    result["entry_count"] = len(entries)
    result["empty"] = len(entries) == 0
    return make_status("pass", "old root was preserved for rollback/debug evidence", **result)


def create_fresh_root(path, target_uid, target_gid):
    root_path = pathlib.Path(path)
    root_path.mkdir(parents=False, exist_ok=False)
    os.chown(root_path, target_uid, target_gid)
    os.chmod(root_path, TARGET_MODE)


def curl_json(url, env_values):
    proc = run_command(
        [
            "curl",
            "--fail-with-body",
            "--silent",
            "--show-error",
            "--cacert",
            env_values["CA_CERT"],
            "--cert",
            env_values["OPERATOR_CERT"],
            "--key",
            env_values["OPERATOR_KEY"],
            url,
        ]
    )
    if proc.returncode != 0:
        return None, proc.stderr.strip() or proc.stdout.strip()
    try:
        return json.loads(proc.stdout), ""
    except Exception as exc:  # noqa: BLE001
        return None, str(exc)


def validate_health_and_contract(runtime_status, healthcheck_env_status):
    if runtime_status["classification"] != "pass" or healthcheck_env_status["classification"] != "pass":
        return (
            make_status("not_observed", "health validation prerequisites were unavailable"),
            make_status("not_observed", "contract validation prerequisites were unavailable"),
        )

    runtime = runtime_status["runtime"]
    env_values = healthcheck_env_status["values"]

    health_payload, health_error = curl_json(runtime["health_url"], env_values)
    if health_payload is None:
        health_result = make_status("blocker", "/health request failed after maintenance window", url=runtime["health_url"], stderr=health_error)
    elif health_payload.get("ready") is True and health_payload.get("status") == "healthy":
        health_result = make_status("pass", "/health passed after maintenance window", url=runtime["health_url"])
    else:
        health_result = make_status("blocker", "/health did not report healthy/ready after maintenance window", url=runtime["health_url"], payload=health_payload)

    contract_payload, contract_error = curl_json(runtime["contract_url"], env_values)
    if contract_payload is None:
        contract_result = make_status("blocker", "/v1/executions:contract request failed after maintenance window", url=runtime["contract_url"], stderr=contract_error)
    else:
        governed = contract_payload.get("governed_execution") or {}
        if (
            contract_payload.get("schema_version") == "execution-substrate.producer-contract/v1"
            and contract_payload.get("service") == "execution"
            and governed.get("contract") == "governed-execution-producer/v1"
            and governed.get("enabled") is True
        ):
            contract_result = make_status("pass", "/v1/executions:contract passed after maintenance window", url=runtime["contract_url"])
        else:
            contract_result = make_status("blocker", "/v1/executions:contract did not match the expected ES producer contract", url=runtime["contract_url"], payload=contract_payload)

    return health_result, contract_result


def compare_observed_quarantined_root(pre_apply_status, post_apply_status):
    path = pre_apply_status.get("path") or post_apply_status.get("path")
    summary = "quarantined root remained outside the bounded parent-traversal mutation plan"
    blockers = []
    if pre_apply_status.get("classification") == "blocker":
        blockers.append(f"pre-apply quarantine evidence was already invalid for {path}")
    if post_apply_status.get("classification") == "blocker":
        blockers.append(post_apply_status.get("summary") or f"post-apply quarantine evidence is invalid for {path}")
    for field in ("owner", "group", "mode", "entry_count"):
        if pre_apply_status.get(field) != post_apply_status.get(field):
            blockers.append(
                f"quarantined root field changed for {path}: {field} {pre_apply_status.get(field)!r} -> {post_apply_status.get(field)!r}"
            )
    if blockers:
        summary = blockers[0]
    return make_status(
        "blocker" if blockers else "pass",
        summary,
        path=path,
        unchanged=not blockers,
        pre_apply=pre_apply_status,
        post_apply=post_apply_status,
        blockers=blockers,
    )


def finalize_apply_summary(apply_summary, blockers, non_mutating):
    classification = "blocker" if blockers else "pass"
    apply_summary["blockers"] = blockers
    apply_summary["result"] = {
        "status": classification,
        "ok": not blockers,
        "non_mutating": non_mutating,
    }
    apply_summary["overall_classification"] = classification
    return apply_summary


def run_in_place_apply(summary, apply_summary):
    runtime = summary["validation"]["runtime_config"]["execution"]
    healthcheck_env_status = summary["validation"]["healthcheck_env"]
    target_uid = summary["validation"]["service_account_narrowness"]["uid"]
    target_gid = summary["validation"]["service_account_narrowness"]["gid"]
    backup = create_backup(summary, "empty_root_reowner")
    changed_paths = []
    for path in (runtime["staging_root_dir"], runtime["results_root_dir"]):
        apply_root_change(path, target_uid, target_gid)
        changed_paths.append(path)

    apply_summary["proof"]["host_mutation_performed"] = True
    apply_summary["backup"] = backup
    apply_summary["changed_paths"] = changed_paths
    apply_summary["changes"] = {
        "mode": "empty_root_reowner",
        "changed_paths": changed_paths,
        "preserved_paths": [],
        "service_stop_performed": False,
        "service_start_performed": False,
        "service_restart_performed": False,
    }

    post_service = inspect_service_meta()
    post_staging = inspect_root(runtime["staging_root_dir"], target_uid, target_gid)
    post_results = inspect_root(runtime["results_root_dir"], target_uid, target_gid)
    health_result = make_status("not_observed", "maintenance-window health validation was not required for empty-root in-place re-owner")
    contract_result = make_status("not_observed", "maintenance-window contract validation was not required for empty-root in-place re-owner")
    blockers = []
    if post_service["classification"] == "blocker":
        blockers.append({"scope": "service_posture", "summary": post_service["summary"]})
    for scope, status in (("staging_root", post_staging), ("results_root", post_results)):
        if status["classification"] == "blocker":
            blockers.append({"scope": scope, "summary": status["summary"]})

    apply_summary["roots"] = {"staging": post_staging, "results": post_results}
    apply_summary["post_apply_validation"] = {
        "classification": "blocker" if blockers else "pass",
        "summary": (
            "stable roots were re-owned in place without restarting es.service"
            if not blockers
            else "stable-root in-place re-owner left one or more post-apply validations blocked"
        ),
        "es_service_posture": post_service,
        "service_stop_performed": False,
        "service_start_performed": False,
        "service_restart_performed": False,
        "health": health_result,
        "contract": contract_result,
        "healthcheck_env": healthcheck_env_status,
    }
    return finalize_apply_summary(apply_summary, blockers, non_mutating=False)


def run_rotation_apply(summary, apply_summary):
    runtime = summary["validation"]["runtime_config"]["execution"]
    healthcheck_env_status = summary["validation"]["healthcheck_env"]
    target_uid = summary["validation"]["service_account_narrowness"]["uid"]
    target_gid = summary["validation"]["service_account_narrowness"]["gid"]
    staging_live = runtime["staging_root_dir"]
    results_live = runtime["results_root_dir"]
    staging_quarantine = choose_quarantine_path(staging_live)
    results_quarantine = choose_quarantine_path(results_live)
    backup = create_backup(summary, "nonempty_root_rotation")
    changed_paths = [staging_live, results_live]
    preserved_paths = [str(staging_quarantine), str(results_quarantine)]
    service_stop_performed = False
    service_start_performed = False
    failure_blocker = None
    recovery_status = make_status("not_observed", "no failure recovery path was needed")

    apply_summary["proof"]["host_mutation_performed"] = True
    apply_summary["backup"] = backup
    apply_summary["changed_paths"] = changed_paths
    apply_summary["quarantine_paths"] = {
        "staging": str(staging_quarantine),
        "results": str(results_quarantine),
    }
    apply_summary["backup"]["quarantine_paths"] = apply_summary["quarantine_paths"]

    try:
        stop_service()
        service_stop_performed = True
        os.rename(staging_live, staging_quarantine)
        os.rename(results_live, results_quarantine)
        create_fresh_root(staging_live, target_uid, target_gid)
        create_fresh_root(results_live, target_uid, target_gid)
        start_service()
        service_start_performed = True
    except Exception as exc:  # noqa: BLE001
        failure_blocker = f"bounded maintenance-window root rotation failed: {exc}"
        if service_stop_performed and not service_start_performed:
            try:
                start_service()
                service_start_performed = True
                recovery_status = make_status("warning", "best-effort es.service start was attempted after the rotation failure")
            except Exception as recovery_exc:  # noqa: BLE001
                recovery_status = make_status("blocker", f"best-effort es.service start failed after the rotation error: {recovery_exc}")

    post_service = inspect_service_meta()
    post_staging = inspect_root(staging_live, target_uid, target_gid)
    post_results = inspect_root(results_live, target_uid, target_gid)
    preserved_staging = inspect_preserved_root(staging_quarantine)
    preserved_results = inspect_preserved_root(results_quarantine)
    health_result, contract_result = validate_health_and_contract(summary["validation"]["runtime_config"], healthcheck_env_status)

    blockers = []
    if failure_blocker:
        blockers.append({"scope": "rotation_apply", "summary": failure_blocker})
    if recovery_status["classification"] == "blocker":
        blockers.append({"scope": "service_recovery", "summary": recovery_status["summary"]})
    if post_service["classification"] == "blocker":
        blockers.append({"scope": "service_posture", "summary": post_service["summary"]})
    for scope, status in (
        ("staging_root", post_staging),
        ("results_root", post_results),
        ("preserved_staging_root", preserved_staging),
        ("preserved_results_root", preserved_results),
    ):
        if status["classification"] == "blocker":
            blockers.append({"scope": scope, "summary": status["summary"]})
    if health_result["classification"] == "blocker":
        blockers.append({"scope": "health", "summary": health_result["summary"]})
    if contract_result["classification"] == "blocker":
        blockers.append({"scope": "contract", "summary": contract_result["summary"]})

    apply_summary["roots"] = {"staging": post_staging, "results": post_results}
    apply_summary["preserved_roots"] = {"staging": preserved_staging, "results": preserved_results}
    apply_summary["changes"] = {
        "mode": "nonempty_root_rotation",
        "changed_paths": changed_paths,
        "preserved_paths": preserved_paths,
        "service_stop_performed": service_stop_performed,
        "service_start_performed": service_start_performed,
        "service_restart_performed": False,
    }
    apply_summary["rotation"] = clone_json(summary["rotation"])
    apply_summary["rotation"]["applied"] = True
    apply_summary["rotation"]["quarantine_paths"] = apply_summary["quarantine_paths"]
    apply_summary["rotation"]["old_retained_content_deleted"] = False
    apply_summary["rotation"]["old_root_recursive_chown_performed"] = False
    apply_summary["post_apply_validation"] = {
        "classification": "blocker" if blockers else "pass",
        "summary": (
            "bounded maintenance-window root rotation completed and es.service returned to active/running root(default)"
            if not blockers
            else "bounded maintenance-window root rotation left one or more post-apply validations blocked"
        ),
        "es_service_posture": post_service,
        "service_stop_performed": service_stop_performed,
        "service_start_performed": service_start_performed,
        "service_restart_performed": False,
        "health": health_result,
        "contract": contract_result,
        "failure_recovery": recovery_status,
    }
    return finalize_apply_summary(apply_summary, blockers, non_mutating=False)


def run_parent_traversal_apply(summary, apply_summary):
    runtime_status = summary["validation"]["runtime_config"]
    runtime = runtime_status["execution"]
    account_status = summary["validation"]["service_account_narrowness"]
    parent_traversal_status = summary["validation"]["parent_traversal"]
    backup = create_backup(summary, "parent_traversal_prepare")
    changed_paths = list(parent_traversal_status.get("changed_paths", []))
    target_owner_uid = parent_traversal_status.get("target_owner_uid")
    target_gid = parent_traversal_status.get("target_gid")
    service_uid = account_status["uid"]
    service_gid = account_status["gid"]

    apply_summary["proof"]["host_mutation_performed"] = True
    apply_summary["backup"] = backup
    apply_summary["changed_paths"] = changed_paths
    apply_summary["changes"] = {
        "mode": "parent_traversal_prepare",
        "changed_paths": changed_paths,
        "preserved_paths": parent_traversal_status.get("quarantined_paths_observed", []),
        "service_stop_performed": False,
        "service_start_performed": False,
        "service_restart_performed": False,
    }

    for path in changed_paths:
        apply_root_change(path, target_owner_uid, target_gid)

    post_service = inspect_service_meta()
    post_parent_traversal = inspect_parent_traversal(runtime_status, service_uid, service_gid)
    post_staging = inspect_root(runtime["staging_root_dir"], service_uid, service_gid)
    post_results = inspect_root(runtime["results_root_dir"], service_uid, service_gid)
    health_result = make_status("not_observed", "parent-only traversal preparation did not restart es.service; /health was not revalidated at this slice")
    contract_result = make_status("not_observed", "parent-only traversal preparation did not restart es.service; /v1/executions:contract was not revalidated at this slice")

    quarantined_roots = []
    for pre_apply_status in backup["snapshot"].get("quarantined_roots_observed", []):
        post_apply_status = inspect_preserved_root(pre_apply_status["path"])
        quarantined_roots.append(compare_observed_quarantined_root(pre_apply_status, post_apply_status))

    blockers = []
    if post_service["classification"] == "blocker":
        blockers.append({"scope": "service_posture", "summary": post_service["summary"]})
    if post_parent_traversal["classification"] != "pass":
        blockers.append({"scope": "parent_traversal", "summary": post_parent_traversal["summary"]})
    for scope, status in (("staging_root", post_staging), ("results_root", post_results)):
        if status["classification"] == "blocker":
            blockers.append({"scope": scope, "summary": status["summary"]})
    for status in quarantined_roots:
        if status["classification"] == "blocker":
            blockers.append({"scope": "quarantined_root", "summary": status["summary"]})

    apply_summary["roots"] = {"staging": post_staging, "results": post_results}
    apply_summary["parent_traversal"] = clone_json(summary["parent_traversal"])
    apply_summary["parent_traversal"]["applied"] = True
    apply_summary["parent_traversal"]["post_apply"] = post_parent_traversal
    apply_summary["quarantined_roots"] = quarantined_roots
    apply_summary["post_apply_validation"] = {
        "classification": "blocker" if blockers else "pass",
        "summary": (
            "bounded parent-chain traversal preparation completed without restarting es.service"
            if not blockers
            else "bounded parent-chain traversal preparation left one or more post-apply validations blocked"
        ),
        "es_service_posture": post_service,
        "parent_traversal": post_parent_traversal,
        "quarantined_roots": quarantined_roots,
        "service_stop_performed": False,
        "service_start_performed": False,
        "service_restart_performed": False,
        "health": health_result,
        "contract": contract_result,
    }
    return finalize_apply_summary(apply_summary, blockers, non_mutating=False)


def run_artifact_reconciliation_apply(summary, apply_summary):
    runtime_status = summary["validation"]["runtime_config"]
    runtime = runtime_status["execution"]
    account_status = summary["validation"]["service_account_narrowness"]
    artifact_status = summary["validation"]["artifact_reconciliation"]
    retained_status = artifact_status.get("retained_results", {})
    stage_status = artifact_status.get("stage_roots", {})
    target_uid = account_status["uid"]
    target_gid = account_status["gid"]
    backup = create_backup(summary, "artifact_reconciliation")
    changed_paths = list(artifact_status.get("changed_paths", []))
    preserved_paths = []
    health_result = make_status("not_observed", "bounded artifact reconciliation did not restart es.service; /health was not revalidated at this slice")
    contract_result = make_status("not_observed", "bounded artifact reconciliation did not restart es.service; /v1/executions:contract was not revalidated at this slice")
    results_quarantine_root = None
    staging_quarantine_root = None

    apply_summary["proof"]["host_mutation_performed"] = True
    apply_summary["backup"] = backup
    apply_summary["changed_paths"] = changed_paths
    apply_summary["changes"] = {
        "mode": "artifact_reconciliation",
        "changed_paths": changed_paths,
        "preserved_paths": preserved_paths,
        "service_stop_performed": False,
        "service_start_performed": False,
        "service_restart_performed": False,
    }

    try:
        for candidate in retained_status.get("retained_run_candidates", []):
            planned_action = candidate.get("planned_action")
            if planned_action == "repair_retained_artifacts_in_place":
                repair_retained_result_artifact_paths(candidate, target_uid, target_gid)
            elif planned_action == "quarantine_retained_run_dir":
                if results_quarantine_root is None:
                    results_quarantine_root = choose_artifact_quarantine_root(runtime["results_root_dir"])
                    create_root_owned_quarantine_root(results_quarantine_root)
                    preserved_paths.append(os.fspath(results_quarantine_root))
                os.rename(candidate["current_path"], os.fspath(pathlib.Path(results_quarantine_root) / candidate["run_id"]))

        for candidate in stage_status.get("stage_root_candidates", []):
            if candidate.get("planned_action") != "quarantine_stage_root":
                continue
            if staging_quarantine_root is None:
                staging_quarantine_root = choose_artifact_quarantine_root(runtime["staging_root_dir"])
                create_root_owned_quarantine_root(staging_quarantine_root)
                preserved_paths.append(os.fspath(staging_quarantine_root))
            os.rename(candidate["current_path"], os.fspath(pathlib.Path(staging_quarantine_root) / candidate["run_id"]))
    except Exception as exc:  # noqa: BLE001
        apply_summary["changes"]["preserved_paths"] = preserved_paths
        apply_summary["quarantine_paths"] = {
            "results": "" if results_quarantine_root is None else os.fspath(results_quarantine_root),
            "staging": "" if staging_quarantine_root is None else os.fspath(staging_quarantine_root),
        }
        apply_summary["post_apply_validation"] = {
            "classification": "blocker",
            "summary": f"bounded artifact reconciliation failed: {exc}",
            "service_stop_performed": False,
            "service_start_performed": False,
            "service_restart_performed": False,
            "health": health_result,
            "contract": contract_result,
        }
        return finalize_apply_summary(apply_summary, [{"scope": "artifact_reconciliation", "summary": f"bounded artifact reconciliation failed: {exc}"}], non_mutating=False)

    post_service = inspect_service_meta()
    post_staging = inspect_root(runtime["staging_root_dir"], target_uid, target_gid)
    post_results = inspect_root(runtime["results_root_dir"], target_uid, target_gid)
    post_active_runs = inspect_active_runs(runtime_status)
    post_artifact_status = inspect_artifact_reconciliation(runtime_status, target_uid, target_gid, post_active_runs)
    quarantined_roots = []
    for pre_apply_status in backup["snapshot"].get("quarantined_roots_observed", []):
        post_apply_status = inspect_preserved_root(pre_apply_status["path"])
        quarantined_roots.append(compare_observed_quarantined_root(pre_apply_status, post_apply_status))

    results_quarantine_status = (
        make_status("not_observed", "no retained-result run directories were quarantined")
        if results_quarantine_root is None
        else inspect_preserved_root(results_quarantine_root)
    )
    staging_quarantine_status = (
        make_status("not_observed", "no run-scoped staging roots were quarantined")
        if staging_quarantine_root is None
        else inspect_preserved_root(staging_quarantine_root)
    )

    blockers = []
    if post_service["classification"] == "blocker":
        blockers.append({"scope": "service_posture", "summary": post_service["summary"]})
    for scope, status in (
        ("staging_root", post_staging),
        ("results_root", post_results),
        ("active_run_or_retained_content", post_active_runs),
        ("artifact_reconciliation", post_artifact_status),
        ("results_quarantine", results_quarantine_status),
        ("staging_quarantine", staging_quarantine_status),
    ):
        if status["classification"] == "blocker":
            blockers.append({"scope": scope, "summary": status["summary"]})
    for status in quarantined_roots:
        if status["classification"] == "blocker":
            blockers.append({"scope": "quarantined_root", "summary": status["summary"]})

    apply_summary["roots"] = {"staging": post_staging, "results": post_results}
    apply_summary["quarantine_paths"] = {
        "results": "" if results_quarantine_root is None else os.fspath(results_quarantine_root),
        "staging": "" if staging_quarantine_root is None else os.fspath(staging_quarantine_root),
    }
    apply_summary["changes"]["preserved_paths"] = preserved_paths
    apply_summary["artifact_reconciliation"] = clone_json(summary["artifact_reconciliation"])
    apply_summary["artifact_reconciliation"]["applied"] = True
    apply_summary["artifact_reconciliation"]["post_apply"] = post_artifact_status
    apply_summary["quarantined_roots"] = quarantined_roots
    apply_summary["post_apply_validation"] = {
        "classification": "blocker" if blockers else "pass",
        "summary": (
            "bounded incompatible live-artifact reconciliation completed without restarting es.service"
            if not blockers
            else "bounded incompatible live-artifact reconciliation left one or more post-apply validations blocked"
        ),
        "es_service_posture": post_service,
        "artifact_reconciliation": post_artifact_status,
        "active_run_or_drain": post_active_runs,
        "quarantined_roots": quarantined_roots,
        "results_quarantine": results_quarantine_status,
        "staging_quarantine": staging_quarantine_status,
        "service_stop_performed": False,
        "service_start_performed": False,
        "service_restart_performed": False,
        "health": health_result,
        "contract": contract_result,
    }
    return finalize_apply_summary(apply_summary, blockers, non_mutating=False)


def run_apply():
    summary = compute_check_summary()
    apply_summary = clone_json(summary)
    apply_summary["mode"] = {
        "name": "apply",
        "non_mutating": False,
        "explicit_apply_required": True,
    }
    apply_summary["proof"] = {
        "check_only_is_not_proof": False,
        "host_mutation_performed": False,
        "governed_proof_run": False,
        "recursive_old_root_reownership_performed": False,
        "old_root_content_deleted": False,
    }
    apply_summary["backup"] = {"status": "not_created", "path": "", "snapshot_manifest_path": "", "rollback_notes": []}
    apply_summary["changed_paths"] = []
    apply_summary["quarantine_paths"] = {}
    apply_summary["changes"] = {
        "mode": "none",
        "changed_paths": [],
        "preserved_paths": [],
        "service_stop_performed": False,
        "service_start_performed": False,
        "service_restart_performed": False,
    }

    if ROTATE_NONEMPTY_ROOTS:
        if not summary["plan"]["rotation_apply_ready"]:
            apply_summary["post_apply_validation"] = {
                "classification": "blocker",
                "summary": "explicit non-empty-root rotation was requested but the maintenance-window gates are not clean",
                "service_stop_performed": False,
                "service_start_performed": False,
                "service_restart_performed": False,
            }
            return finalize_apply_summary(apply_summary, summary["blockers"], non_mutating=True)
        if summary["plan"].get("legacy_orphan_acceptance_required") and not ACCEPT_STALE_ORPHANED_RUNS:
            blockers = list(summary["blockers"])
            blockers.append(
                {
                    "scope": "legacy_orphan_acceptance",
                    "summary": "explicit legacy stale/orphan acceptance is required before bounded non-empty-root rotation may proceed",
                }
            )
            apply_summary["post_apply_validation"] = {
                "classification": "blocker",
                "summary": "explicit non-empty-root rotation was requested without the required legacy stale/orphan acceptance flag",
                "service_stop_performed": False,
                "service_start_performed": False,
                "service_restart_performed": False,
            }
            return finalize_apply_summary(apply_summary, blockers, non_mutating=True)
        return run_rotation_apply(summary, apply_summary)

    if FIX_PARENT_CHAIN:
        if not summary["plan"]["parent_traversal_apply_ready"]:
            apply_summary["post_apply_validation"] = {
                "classification": "blocker",
                "summary": "explicit parent-chain traversal preparation was requested but the bounded parent-only gates are not clean",
                "service_stop_performed": False,
                "service_start_performed": False,
                "service_restart_performed": False,
            }
            return finalize_apply_summary(apply_summary, summary["blockers"], non_mutating=True)
        return run_parent_traversal_apply(summary, apply_summary)

    if RECONCILE_ARTIFACTS:
        if not summary["plan"]["artifact_reconciliation_apply_ready"]:
            apply_summary["post_apply_validation"] = {
                "classification": "blocker",
                "summary": "explicit bounded artifact reconciliation was requested but the reconciliation gates are not clean",
                "service_stop_performed": False,
                "service_start_performed": False,
                "service_restart_performed": False,
            }
            return finalize_apply_summary(apply_summary, summary["blockers"], non_mutating=True)
        return run_artifact_reconciliation_apply(summary, apply_summary)

    if summary["blockers"]:
        apply_summary["post_apply_validation"] = {
            "classification": "blocker",
            "summary": "default apply is blocked by the check-only gates for this bounded slice",
            "service_stop_performed": False,
            "service_start_performed": False,
            "service_restart_performed": False,
        }
        return finalize_apply_summary(apply_summary, summary["blockers"], non_mutating=True)

    if not summary["plan"]["roots_need_change"]:
        apply_summary["post_apply_validation"] = {
            "classification": "pass",
            "summary": "stable roots already matched the documented es:es 0750 model; no mutation was required",
            "es_service_posture": summary["validation"]["es_service_posture"],
            "service_stop_performed": False,
            "service_start_performed": False,
            "service_restart_performed": False,
            "health": make_status("not_observed", "apply was a no-op"),
            "contract": make_status("not_observed", "apply was a no-op"),
        }
        blockers = []
        if summary["validation"].get("artifact_reconciliation", {}).get("classification") == "warning":
            blockers.append(
                {
                    "scope": "artifact_reconciliation",
                    "summary": "default apply is not permitted while explicit bounded artifact reconciliation is still required",
                }
            )
            apply_summary["post_apply_validation"]["classification"] = "blocker"
            apply_summary["post_apply_validation"]["summary"] = "default apply is not permitted while explicit bounded artifact reconciliation is still required"
        return finalize_apply_summary(apply_summary, blockers, non_mutating=True)

    return run_in_place_apply(summary, apply_summary)


def main():
    if MODE == "check_only":
        summary = compute_check_summary()
        print(json.dumps(summary, indent=2, sort_keys=True))
        raise SystemExit(1 if summary["overall_classification"] == "blocker" else 0)
    summary = run_apply()
    pathlib.Path(SUMMARY_PATH).parent.mkdir(parents=True, exist_ok=True)
    write_json(SUMMARY_PATH, summary)
    raise SystemExit(1 if summary["overall_classification"] == "blocker" else 0)


main()
PY
}

remote_alpha_prepare_es_writable_state_ownership_host_main() {
  remote_alpha_prepare_es_writable_state_ownership_defaults
  remote_alpha_prepare_es_writable_state_ownership_require_pinned_slice_inputs || return 1
  remote_alpha_prepare_es_writable_state_ownership_parse_host_args "$@" || return $?
  if [[ "${REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_SHOW_HELP}" == "true" ]]; then
    return 0
  fi

  remote_alpha_prepare_es_writable_state_ownership_require_root || return 1
  remote_alpha_prepare_es_writable_state_ownership_require_command python3 || return 1
  remote_alpha_prepare_es_writable_state_ownership_python
}

remote_alpha_prepare_es_writable_state_ownership_stage_defaults() {
  remote_alpha_prepare_es_writable_state_ownership_init_expected_slice_inputs
  REMOTE_ALPHA_OPERATION_MODE="check_only"
  REMOTE_ALPHA_ROTATE_NONEMPTY_ROOTS="false"
  REMOTE_ALPHA_ACCEPT_STALE_ORPHANED_RUNS="false"
  REMOTE_ALPHA_FIX_PARENT_CHAIN="false"
  REMOTE_ALPHA_RECONCILE_ARTIFACTS="false"
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_OUTPUT_DIR=""
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_CHECK_OUTPUT_PATH=""
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_APPLY_SUMMARY_OUTPUT_PATH=""
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_PROVENANCE_OUTPUT_PATH=""
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_STAGE_ROOT="${remote_alpha_prepare_es_writable_state_ownership_remote_stage_root_default}"
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_SUMMARY_PATH="${remote_alpha_prepare_es_writable_state_ownership_remote_summary_path_default}"
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_SSH_BIN="${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_SSH_BIN:-ssh}"
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_SCP_BIN="${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_SCP_BIN:-scp}"
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_SUDO_MODE="${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_SUDO_MODE:-noninteractive}"
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_SSH_TARGET=""
}

remote_alpha_prepare_es_writable_state_ownership_stage_validate_sudo_mode() {
  case "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_SUDO_MODE}" in
    noninteractive|interactive)
      ;;
    *)
      echo "unsupported sudo mode: ${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_SUDO_MODE}" >&2
      return 1
      ;;
  esac
}

remote_alpha_prepare_es_writable_state_ownership_stage_parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --ssh-target)
        REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_SSH_TARGET="$2"
        shift 2
        ;;
      --check-only|--dry-run)
        REMOTE_ALPHA_OPERATION_MODE="check_only"
        shift
        ;;
      --apply)
        REMOTE_ALPHA_OPERATION_MODE="apply"
        shift
        ;;
      --rotate-nonempty-roots)
        REMOTE_ALPHA_ROTATE_NONEMPTY_ROOTS="true"
        shift
        ;;
      --accept-stale-orphaned-runs)
        REMOTE_ALPHA_ACCEPT_STALE_ORPHANED_RUNS="true"
        shift
        ;;
      --fix-parent-chain)
        REMOTE_ALPHA_FIX_PARENT_CHAIN="true"
        shift
        ;;
      --reconcile-artifacts)
        REMOTE_ALPHA_RECONCILE_ARTIFACTS="true"
        shift
        ;;
      --run-id)
        REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_RUN_ID="$2"
        shift 2
        ;;
      --output-dir)
        REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_OUTPUT_DIR="$2"
        shift 2
        ;;
      --check-output)
        REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_CHECK_OUTPUT_PATH="$2"
        shift 2
        ;;
      --apply-summary-output)
        REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_APPLY_SUMMARY_OUTPUT_PATH="$2"
        shift 2
        ;;
      --helper-staging-record-output|--provenance-output)
        REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_PROVENANCE_OUTPUT_PATH="$2"
        shift 2
        ;;
      --remote-summary-path)
        REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_SUMMARY_PATH="$2"
        shift 2
        ;;
      --interactive-sudo)
        REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_SUDO_MODE="interactive"
        shift
        ;;
      --keep-staging-on-failure)
        REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_KEEP_STAGING_ON_FAILURE="true"
        shift
        ;;
      --help|-h)
        REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_SHOW_HELP="true"
        remote_alpha_prepare_es_writable_state_ownership_usage
        return 0
        ;;
      *)
        echo "unknown argument: $1" >&2
        remote_alpha_prepare_es_writable_state_ownership_usage >&2
        return 2
        ;;
    esac
  done

  remote_alpha_prepare_es_writable_state_ownership_stage_validate_sudo_mode || return 1
  if [[ -z "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_SSH_TARGET:-}" ]]; then
    echo "--ssh-target is required" >&2
    return 2
  fi
  if [[ "${REMOTE_ALPHA_ROTATE_NONEMPTY_ROOTS}" == "true" && "${REMOTE_ALPHA_OPERATION_MODE}" != "apply" ]]; then
    echo "remote alpha ES writable-state ownership requires --apply with --rotate-nonempty-roots" >&2
    return 2
  fi
  if [[ "${REMOTE_ALPHA_ACCEPT_STALE_ORPHANED_RUNS}" == "true" && "${REMOTE_ALPHA_OPERATION_MODE}" != "apply" ]]; then
    echo "remote alpha ES writable-state ownership requires --apply with --accept-stale-orphaned-runs" >&2
    return 2
  fi
  if [[ "${REMOTE_ALPHA_ACCEPT_STALE_ORPHANED_RUNS}" == "true" && "${REMOTE_ALPHA_ROTATE_NONEMPTY_ROOTS}" != "true" ]]; then
    echo "remote alpha ES writable-state ownership requires --rotate-nonempty-roots with --accept-stale-orphaned-runs" >&2
    return 2
  fi
  if [[ "${REMOTE_ALPHA_FIX_PARENT_CHAIN}" == "true" && "${REMOTE_ALPHA_OPERATION_MODE}" != "apply" ]]; then
    echo "remote alpha ES writable-state ownership requires --apply with --fix-parent-chain" >&2
    return 2
  fi
  if [[ "${REMOTE_ALPHA_RECONCILE_ARTIFACTS}" == "true" && "${REMOTE_ALPHA_OPERATION_MODE}" != "apply" ]]; then
    echo "remote alpha ES writable-state ownership requires --apply with --reconcile-artifacts" >&2
    return 2
  fi
  if [[ "${REMOTE_ALPHA_FIX_PARENT_CHAIN}" == "true" && "${REMOTE_ALPHA_ROTATE_NONEMPTY_ROOTS}" == "true" ]]; then
    echo "remote alpha ES writable-state ownership does not accept --fix-parent-chain together with --rotate-nonempty-roots" >&2
    return 2
  fi
  if [[ "${REMOTE_ALPHA_FIX_PARENT_CHAIN}" == "true" && "${REMOTE_ALPHA_ACCEPT_STALE_ORPHANED_RUNS}" == "true" ]]; then
    echo "remote alpha ES writable-state ownership does not accept --fix-parent-chain together with --accept-stale-orphaned-runs" >&2
    return 2
  fi
  if [[ "${REMOTE_ALPHA_RECONCILE_ARTIFACTS}" == "true" && "${REMOTE_ALPHA_ROTATE_NONEMPTY_ROOTS}" == "true" ]]; then
    echo "remote alpha ES writable-state ownership does not accept --reconcile-artifacts together with --rotate-nonempty-roots" >&2
    return 2
  fi
  if [[ "${REMOTE_ALPHA_RECONCILE_ARTIFACTS}" == "true" && "${REMOTE_ALPHA_ACCEPT_STALE_ORPHANED_RUNS}" == "true" ]]; then
    echo "remote alpha ES writable-state ownership does not accept --reconcile-artifacts together with --accept-stale-orphaned-runs" >&2
    return 2
  fi
  if [[ "${REMOTE_ALPHA_RECONCILE_ARTIFACTS}" == "true" && "${REMOTE_ALPHA_FIX_PARENT_CHAIN}" == "true" ]]; then
    echo "remote alpha ES writable-state ownership does not accept --reconcile-artifacts together with --fix-parent-chain" >&2
    return 2
  fi
}

remote_alpha_prepare_es_writable_state_ownership_stage_finalize_paths() {
  if [[ -z "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_OUTPUT_DIR}" ]]; then
    REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_OUTPUT_DIR="${remote_alpha_prepare_es_writable_state_ownership_default_output_dir}"
  fi
  if [[ -z "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_CHECK_OUTPUT_PATH}" ]]; then
    REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_CHECK_OUTPUT_PATH="${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_OUTPUT_DIR}/es-writable-state-ownership-check-only.json"
  fi
  if [[ -z "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_APPLY_SUMMARY_OUTPUT_PATH}" ]]; then
    REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_APPLY_SUMMARY_OUTPUT_PATH="${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_OUTPUT_DIR}/es-writable-state-ownership-apply-summary.json"
  fi
  if [[ -z "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_PROVENANCE_OUTPUT_PATH}" ]]; then
    REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_PROVENANCE_OUTPUT_PATH="${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_OUTPUT_DIR}/es-writable-state-ownership-helper-staging-record.json"
  fi
}

remote_alpha_prepare_es_writable_state_ownership_stage_ensure_parent_dir() {
  local path=$1
  mkdir -p "$(dirname "${path}")"
}

remote_alpha_prepare_es_writable_state_ownership_stage_helper_paths() {
  printf '%s\n' \
    "${REPO_ROOT}/scripts/remote_alpha_prepare_es_writable_state_ownership.sh" \
    "${REPO_ROOT}/scripts/internal/remote_alpha_prepare_es_writable_state_ownership.sh"
}

remote_alpha_prepare_es_writable_state_ownership_stage_git_commit() {
  if command -v git >/dev/null 2>&1; then
    git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || true
    return 0
  fi
  printf '\n'
}

remote_alpha_prepare_es_writable_state_ownership_stage_make_local_upload_tree() {
  local upload_dir=$1
  mkdir -p "${upload_dir}/scripts/internal"
  cp "${REPO_ROOT}/scripts/remote_alpha_prepare_es_writable_state_ownership.sh" "${upload_dir}/scripts/remote_alpha_prepare_es_writable_state_ownership.sh"
  cp "${REPO_ROOT}/scripts/internal/remote_alpha_prepare_es_writable_state_ownership.sh" "${upload_dir}/scripts/internal/remote_alpha_prepare_es_writable_state_ownership.sh"
}

remote_alpha_prepare_es_writable_state_ownership_stage_required_upload_paths() {
  printf '%s\n' \
    "scripts/remote_alpha_prepare_es_writable_state_ownership.sh" \
    "scripts/internal/remote_alpha_prepare_es_writable_state_ownership.sh"
}

remote_alpha_prepare_es_writable_state_ownership_stage_validate_local_upload_tree() {
  local upload_dir=$1
  local -a missing=()
  local relative_path

  while IFS= read -r relative_path; do
    if [[ -z "${relative_path}" ]]; then
      continue
    fi
    if [[ ! -f "${upload_dir}/${relative_path}" ]]; then
      missing+=("${relative_path}")
    fi
  done < <(remote_alpha_prepare_es_writable_state_ownership_stage_required_upload_paths)

  if (( ${#missing[@]} == 0 )); then
    return 0
  fi

  local joined_missing
  joined_missing="$(IFS=', '; printf '%s' "${missing[*]}")"
  printf 'local staged ES writable-state ownership upload tree is missing required files: %s\n' "${joined_missing}" >&2
  return 1
}

remote_alpha_prepare_es_writable_state_ownership_stage_local_file_meta() {
  local output_path=$1
  shift
  python3 - "$output_path" "$@" <<'PY'
import hashlib
import json
import pathlib
import sys

output_path = pathlib.Path(sys.argv[1])
files = []
for raw_path in sys.argv[2:]:
    path = pathlib.Path(raw_path)
    files.append({"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
output_path.write_text(json.dumps(files, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

remote_alpha_prepare_es_writable_state_ownership_stage_ssh() {
  "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_SSH_BIN}" "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_SSH_TARGET}" "$@"
}

remote_alpha_prepare_es_writable_state_ownership_stage_ssh_with_tty() {
  "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_SSH_BIN}" -tt "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_SSH_TARGET}" "$@"
}

remote_alpha_prepare_es_writable_state_ownership_stage_build_remote_bash_command() {
  local script=$1
  shift
  python3 - "${script}" "$@" <<'PY'
import shlex
import sys
parts = ["/bin/bash", "-c", sys.argv[1], "remote-alpha-stage", *sys.argv[2:]]
print(" ".join(shlex.quote(part) for part in parts))
PY
}

remote_alpha_prepare_es_writable_state_ownership_stage_run_remote_batch() {
  local script=$1
  shift
  remote_alpha_prepare_es_writable_state_ownership_stage_ssh /bin/bash -s -- "$@" <<<"${script}"
}

remote_alpha_prepare_es_writable_state_ownership_stage_run_remote_batch_with_tty() {
  local script=$1
  shift
  local remote_command
  remote_command="$(remote_alpha_prepare_es_writable_state_ownership_stage_build_remote_bash_command "${script}" "$@")"
  remote_alpha_prepare_es_writable_state_ownership_stage_ssh_with_tty "${remote_command}"
}

remote_alpha_prepare_es_writable_state_ownership_stage_scp() {
  "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_SCP_BIN}" "$@"
}

remote_alpha_prepare_es_writable_state_ownership_stage_note_blocker() {
  local message=$1
  if [[ -z "${REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_BLOCKER_DETAIL}" ]]; then
    REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_BLOCKER_DETAIL="${message}"
  fi
}

remote_alpha_prepare_es_writable_state_ownership_stage_note_sudo_unavailable() {
  local message=$1
  REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_SUDO_UNAVAILABLE="true"
  REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_FAILURE_CLASSIFICATION="sudo_unavailable"
  remote_alpha_prepare_es_writable_state_ownership_stage_note_blocker "${message}"
}

remote_alpha_prepare_es_writable_state_ownership_stage_note_wrapper_tooling_error() {
  local message=$1
  REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_WRAPPER_TOOLING_ERROR="true"
  if [[ "${REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_FAILURE_CLASSIFICATION}" != "sudo_unavailable" ]]; then
    REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_FAILURE_CLASSIFICATION="wrapper_tooling_error"
  fi
  remote_alpha_prepare_es_writable_state_ownership_stage_note_blocker "${message}"
}

remote_alpha_prepare_es_writable_state_ownership_stage_noninteractive_sudo_preflight() {
  remote_alpha_prepare_es_writable_state_ownership_stage_run_remote_batch \
    'set -euo pipefail
sudo -n true >/dev/null 2>&1'
}

remote_alpha_prepare_es_writable_state_ownership_stage_remote_prepare_upload_root() {
  remote_alpha_prepare_es_writable_state_ownership_stage_run_remote_batch \
    'set -euo pipefail
upload_root=$1
rm -rf -- "${upload_root}"
mkdir -p -- "${upload_root}/scripts/internal"' \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_UPLOAD_ROOT}"
}

remote_alpha_prepare_es_writable_state_ownership_stage_remote_prepare_artifact_root() {
  remote_alpha_prepare_es_writable_state_ownership_stage_run_remote_batch \
    'set -euo pipefail
artifact_root=$1
rm -rf -- "${artifact_root}"
mkdir -p -- "${artifact_root}"' \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_ARTIFACT_ROOT}"
}

remote_alpha_prepare_es_writable_state_ownership_stage_fetch_remote_file() {
  local remote_path=$1
  local local_path=$2
  remote_alpha_prepare_es_writable_state_ownership_stage_scp "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_SSH_TARGET}:${remote_path}" "${local_path}"
}

remote_alpha_prepare_es_writable_state_ownership_stage_upload_remote_tree() {
  local upload_dir=$1
  local relative_path

  while IFS= read -r relative_path; do
    if [[ -z "${relative_path}" ]]; then
      continue
    fi
    remote_alpha_prepare_es_writable_state_ownership_stage_scp \
      "${upload_dir}/${relative_path}" \
      "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_SSH_TARGET}:${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_UPLOAD_ROOT}/${relative_path}" || return 1
  done < <(remote_alpha_prepare_es_writable_state_ownership_stage_required_upload_paths)
}

remote_alpha_prepare_es_writable_state_ownership_stage_remove_remote_user_owned_roots() {
  if [[ -z "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_UPLOAD_ROOT}" && -z "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_ARTIFACT_ROOT}" ]]; then
    return 0
  fi
  remote_alpha_prepare_es_writable_state_ownership_stage_run_remote_batch \
    'set -euo pipefail
upload_root=$1
artifact_root=$2
if [[ -n "${upload_root}" ]]; then
  rm -rf -- "${upload_root}" || true
fi
if [[ -n "${artifact_root}" ]]; then
  rm -rf -- "${artifact_root}" || true
fi' \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_UPLOAD_ROOT}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_ARTIFACT_ROOT}"
}

remote_alpha_prepare_es_writable_state_ownership_stage_remove_remote_artifact_root() {
  if [[ -z "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_ARTIFACT_ROOT}" ]]; then
    return 0
  fi
  remote_alpha_prepare_es_writable_state_ownership_stage_run_remote_batch \
    'set -euo pipefail
artifact_root=$1
if [[ -n "${artifact_root}" ]]; then
  rm -rf -- "${artifact_root}" || true
fi' \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_ARTIFACT_ROOT}"
}

remote_alpha_prepare_es_writable_state_ownership_stage_remote_install_staged_tree() {
  local sudo_cmd script
  if [[ "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_SUDO_MODE}" == "interactive" ]]; then
    sudo_cmd="sudo"
  else
    sudo_cmd="sudo -n"
  fi
  script="$(cat <<EOF
set -euo pipefail
upload_root=\$1
staging_root=\$2

${sudo_cmd} rm -rf -- "\${staging_root}"
${sudo_cmd} install -d -m 0755 -o root -g root "\${staging_root}"
${sudo_cmd} install -d -m 0755 -o root -g root "\${staging_root}/scripts"
${sudo_cmd} install -d -m 0755 -o root -g root "\${staging_root}/scripts/internal"
${sudo_cmd} install -m 0755 -o root -g root "\${upload_root}/scripts/remote_alpha_prepare_es_writable_state_ownership.sh" "\${staging_root}/scripts/remote_alpha_prepare_es_writable_state_ownership.sh"
${sudo_cmd} install -m 0644 -o root -g root "\${upload_root}/scripts/internal/remote_alpha_prepare_es_writable_state_ownership.sh" "\${staging_root}/scripts/internal/remote_alpha_prepare_es_writable_state_ownership.sh"
rm -rf -- "\${upload_root}"
EOF
)"
  if [[ "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_SUDO_MODE}" == "interactive" ]]; then
    remote_alpha_prepare_es_writable_state_ownership_stage_run_remote_batch_with_tty "${script}" \
      "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_UPLOAD_ROOT}" \
      "${REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_STAGE_REMOTE_STAGING_ROOT}"
    return 0
  fi
  remote_alpha_prepare_es_writable_state_ownership_stage_run_remote_batch "${script}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_UPLOAD_ROOT}" \
    "${REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_STAGE_REMOTE_STAGING_ROOT}"
}

remote_alpha_prepare_es_writable_state_ownership_stage_run_interactive_check_sequence() {
  local script status=0
  script="$(cat <<EOF
set -euo pipefail
upload_root=\$1
staging_root=\$2
staged_wrapper=\$3
stage_stat_path=\$4
check_output=\$5

mkdir -p -- "\$(dirname "\${stage_stat_path}")"
mkdir -p -- "\$(dirname "\${check_output}")"
sudo -v
cleanup() {
  sudo rm -rf -- "\${staging_root}" || true
}
trap cleanup EXIT
sudo rm -rf -- "\${staging_root}"
sudo install -d -m 0755 -o root -g root "\${staging_root}"
sudo install -d -m 0755 -o root -g root "\${staging_root}/scripts"
sudo install -d -m 0755 -o root -g root "\${staging_root}/scripts/internal"
sudo install -m 0755 -o root -g root "\${upload_root}/scripts/remote_alpha_prepare_es_writable_state_ownership.sh" "\${staging_root}/scripts/remote_alpha_prepare_es_writable_state_ownership.sh"
sudo install -m 0644 -o root -g root "\${upload_root}/scripts/internal/remote_alpha_prepare_es_writable_state_ownership.sh" "\${staging_root}/scripts/internal/remote_alpha_prepare_es_writable_state_ownership.sh"
rm -rf -- "\${upload_root}"
for path in \
  "\${staging_root}" \
  "\${staging_root}/scripts" \
  "\${staging_root}/scripts/internal" \
  "\${staging_root}/scripts/remote_alpha_prepare_es_writable_state_ownership.sh" \
  "\${staging_root}/scripts/internal/remote_alpha_prepare_es_writable_state_ownership.sh"
do
  owner=\$(sudo stat -c '%U' "\${path}")
  group=\$(sudo stat -c '%G' "\${path}")
  mode=\$(sudo stat -c '%a' "\${path}")
  display_path="\${path}"
  if [[ -n "\${FAKE_REMOTE_ROOT:-}" && "\${display_path}" == "\${FAKE_REMOTE_ROOT}"* ]]; then
    display_path="\${display_path#\${FAKE_REMOTE_ROOT}}"
  fi
  printf '%s\t%s\t%s\t%s\n' "\${owner}" "\${group}" "\${mode}" "\${display_path}"
done >"\${stage_stat_path}"
set +e
sudo "\${staged_wrapper}" --check-only >"\${check_output}"
status=\$?
set -e
exit "\${status}"
EOF
)"
  set +e
  remote_alpha_prepare_es_writable_state_ownership_stage_run_remote_batch_with_tty "${script}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_UPLOAD_ROOT}" \
    "${REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_STAGE_REMOTE_STAGING_ROOT}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_STAGED_WRAPPER_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_STAGE_STAT_ARTIFACT_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_CHECK_OUTPUT_ARTIFACT_PATH}"
  status=$?
  return "${status}"
}

remote_alpha_prepare_es_writable_state_ownership_stage_validate_stage_stat() {
  local stat_path=$1
  local output_path=$2
  python3 - "$stat_path" "$output_path" "${REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_STAGE_REMOTE_STAGING_ROOT}" <<'PY'
import json
import pathlib
import sys

stat_path = pathlib.Path(sys.argv[1])
output_path = pathlib.Path(sys.argv[2])
staging_root = sys.argv[3]
items = []
errors = []
for raw_line in stat_path.read_text(encoding="utf-8").splitlines():
    if not raw_line.strip():
        continue
    parts = raw_line.split("\t", 3)
    if len(parts) != 4:
        parts = raw_line.split("\\t", 3)
    if len(parts) != 4:
        errors.append(f"unexpected staged helper stat line: {raw_line}")
        continue
    owner, group, mode, path = parts
    mode_text = mode.zfill(4)
    mode_value = int(mode_text, 8)
    root_owned = owner == "root"
    not_group_or_other_writable = (mode_value & 0o022) == 0
    inside_staging_root = path == staging_root or path.startswith(staging_root + "/")
    items.append({
        "path": path,
        "owner": owner,
        "group": group,
        "mode": mode_text,
        "root_owned": root_owned,
        "not_group_or_other_writable": not_group_or_other_writable,
        "inside_staging_root": inside_staging_root,
    })
    if not root_owned:
        errors.append(f"path is not root-owned: {path}")
    if not not_group_or_other_writable:
        errors.append(f"path is group-writable or world-writable: {path}")
    if not inside_staging_root:
        errors.append(f"path is outside the staged helper root: {path}")
if len(items) != 5:
    errors.append(f"expected 5 staged helper paths, found {len(items)}")
payload = {
    "staged_root": staging_root,
    "items": items,
    "validation_errors": errors,
    "root_owned_before_execution": not errors and len(items) == 5,
}
output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
if errors:
    raise SystemExit(1)
PY
}

remote_alpha_prepare_es_writable_state_ownership_stage_run_remote_check_only() {
  local output_path=$1
  local script
  script="$(cat <<EOF
set -euo pipefail
staged_wrapper=\$1
sudo -n "\${staged_wrapper}" --check-only
EOF
)"
  remote_alpha_prepare_es_writable_state_ownership_stage_run_remote_batch "${script}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_STAGED_WRAPPER_PATH}" >"${output_path}"
}

remote_alpha_prepare_es_writable_state_ownership_stage_validate_check_report() {
  local report_path=$1
  local meta_path=$2
  python3 - "$report_path" "$meta_path" "${remote_alpha_prepare_es_writable_state_ownership_summary_schema_version}" <<'PY'
import json
import pathlib
import sys

report_path = pathlib.Path(sys.argv[1])
meta_path = pathlib.Path(sys.argv[2])
expected_schema = sys.argv[3]
payload = {"valid_json": False, "accepted_evidence": False}

def write_meta(value):
    meta_path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")

try:
    report = json.loads(report_path.read_text(encoding="utf-8"))
except Exception as exc:  # noqa: BLE001
    payload["error"] = f"malformed check-only JSON: {exc}"
    write_meta(payload)
    raise SystemExit(1)

errors = []
if report.get("schema_version") != expected_schema:
    errors.append(f"unexpected schema_version: {report.get('schema_version')!r}")
mode = report.get("mode") or {}
proof = report.get("proof") or {}
if mode.get("name") != "check_only":
    errors.append("mode.name must be check_only")
if mode.get("non_mutating") is not True:
    errors.append("mode.non_mutating must be true")
if proof.get("host_mutation_performed") is not False:
    errors.append("proof.host_mutation_performed must be false")

payload.update({
    "valid_json": True,
    "schema_version": report.get("schema_version"),
    "overall_classification": report.get("overall_classification"),
    "apply_ready": (report.get("plan") or {}).get("apply_ready"),
    "roots_nonempty_block_apply": (report.get("plan") or {}).get("roots_nonempty_block_apply"),
    "rotation_apply_ready": (report.get("plan") or {}).get("rotation_apply_ready"),
    "parent_traversal_apply_ready": (report.get("plan") or {}).get("parent_traversal_apply_ready"),
    "artifact_reconciliation_apply_ready": (report.get("plan") or {}).get("artifact_reconciliation_apply_ready"),
    "legacy_orphan_acceptance_required": (report.get("plan") or {}).get("legacy_orphan_acceptance_required"),
    "warning_count": len(report.get("warnings") or []),
    "blocker_count": len(report.get("blockers") or []),
    "expected_exit_code": 1 if report.get("overall_classification") == "blocker" else 0,
})
if errors:
    payload["errors"] = errors
    write_meta(payload)
    raise SystemExit(1)
payload["accepted_evidence"] = True
payload["errors"] = []
write_meta(payload)
PY
}

remote_alpha_prepare_es_writable_state_ownership_stage_run_remote_apply() {
  local script
  script="$(cat <<EOF
set -euo pipefail
staged_wrapper=\$1
summary_path=\$2
shift 2
apply_flags=("\$@")
sudo -n "\${staged_wrapper}" --apply "\${apply_flags[@]}" --summary-path "\${summary_path}" >/dev/null
EOF
)"
  local apply_flags=()
  if [[ "${REMOTE_ALPHA_ROTATE_NONEMPTY_ROOTS}" == "true" ]]; then
    apply_flags+=("--rotate-nonempty-roots")
  fi
  if [[ "${REMOTE_ALPHA_ACCEPT_STALE_ORPHANED_RUNS}" == "true" ]]; then
    apply_flags+=("--accept-stale-orphaned-runs")
  fi
  if [[ "${REMOTE_ALPHA_FIX_PARENT_CHAIN}" == "true" ]]; then
    apply_flags+=("--fix-parent-chain")
  fi
  if [[ "${REMOTE_ALPHA_RECONCILE_ARTIFACTS}" == "true" ]]; then
    apply_flags+=("--reconcile-artifacts")
  fi
  remote_alpha_prepare_es_writable_state_ownership_stage_run_remote_batch "${script}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_STAGED_WRAPPER_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_SUMMARY_PATH}" \
    "${apply_flags[@]}"
}

remote_alpha_prepare_es_writable_state_ownership_stage_run_interactive_apply_sequence() {
  local script status=0
  script="$(cat <<EOF
set -euo pipefail
upload_root=\$1
staging_root=\$2
staged_wrapper=\$3
summary_path=\$4
shift 4
apply_flags=("\$@")
sudo -v
cleanup() {
  sudo rm -rf -- "\${staging_root}" || true
}
trap cleanup EXIT
sudo rm -rf -- "\${staging_root}"
sudo install -d -m 0755 -o root -g root "\${staging_root}"
sudo install -d -m 0755 -o root -g root "\${staging_root}/scripts"
sudo install -d -m 0755 -o root -g root "\${staging_root}/scripts/internal"
sudo install -m 0755 -o root -g root "\${upload_root}/scripts/remote_alpha_prepare_es_writable_state_ownership.sh" "\${staging_root}/scripts/remote_alpha_prepare_es_writable_state_ownership.sh"
sudo install -m 0644 -o root -g root "\${upload_root}/scripts/internal/remote_alpha_prepare_es_writable_state_ownership.sh" "\${staging_root}/scripts/internal/remote_alpha_prepare_es_writable_state_ownership.sh"
rm -rf -- "\${upload_root}"
sudo "\${staged_wrapper}" --apply "\${apply_flags[@]}" --summary-path "\${summary_path}" >/dev/null
EOF
)"
  local apply_flags=()
  if [[ "${REMOTE_ALPHA_ROTATE_NONEMPTY_ROOTS}" == "true" ]]; then
    apply_flags+=("--rotate-nonempty-roots")
  fi
  if [[ "${REMOTE_ALPHA_ACCEPT_STALE_ORPHANED_RUNS}" == "true" ]]; then
    apply_flags+=("--accept-stale-orphaned-runs")
  fi
  if [[ "${REMOTE_ALPHA_FIX_PARENT_CHAIN}" == "true" ]]; then
    apply_flags+=("--fix-parent-chain")
  fi
  if [[ "${REMOTE_ALPHA_RECONCILE_ARTIFACTS}" == "true" ]]; then
    apply_flags+=("--reconcile-artifacts")
  fi
  set +e
  remote_alpha_prepare_es_writable_state_ownership_stage_run_remote_batch_with_tty "${script}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_UPLOAD_ROOT}" \
    "${REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_STAGE_REMOTE_STAGING_ROOT}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_STAGED_WRAPPER_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_SUMMARY_PATH}" \
    "${apply_flags[@]}"
  status=$?
  return "${status}"
}

remote_alpha_prepare_es_writable_state_ownership_stage_remote_cleanup() {
  if [[ "${REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_CLEANUP_COMPLETED}" == "true" ]]; then
    return 0
  fi
  if [[ "${REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_UPLOAD_PREPARED}" != "true" && "${REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_STAGING_OCCURRED}" != "true" && -z "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_ARTIFACT_ROOT}" ]]; then
    return 0
  fi

  local script
  script="$(cat <<EOF
set -euo pipefail
staging_root=\$1
upload_root=\$2
artifact_root=\$3
sudo -n rm -rf -- "\${staging_root}" || true
rm -rf -- "\${upload_root}" || true
rm -rf -- "\${artifact_root}" || true
EOF
)"
  remote_alpha_prepare_es_writable_state_ownership_stage_run_remote_batch "${script}" \
    "${REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_STAGE_REMOTE_STAGING_ROOT}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_UPLOAD_ROOT}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_ARTIFACT_ROOT}"
}

remote_alpha_prepare_es_writable_state_ownership_stage_visible_cleanup_if_needed() {
  if [[ "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_SUDO_MODE}" != "interactive" ]]; then
    return 0
  fi
  if ! remote_alpha_prepare_es_writable_state_ownership_stage_remove_remote_user_owned_roots; then
    remote_alpha_prepare_es_writable_state_ownership_stage_note_wrapper_tooling_error "could not remove remote transient upload or artifact roots after interactive staged ES writable-state ownership execution"
    return 1
  fi
  REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_CLEANUP_COMPLETED="true"
  REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_TRANSIENT_STAGING_REMOVED="true"
  return 0
}

remote_alpha_prepare_es_writable_state_ownership_stage_write_provenance() {
  python3 - \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_PROVENANCE_OUTPUT_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_LOCAL_FILE_META_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_STAGE_STAT_META_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_CHECK_VALIDATION_META_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_CHECK_OUTPUT_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_APPLY_SUMMARY_OUTPUT_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_RUN_ID}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_SSH_TARGET}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_GIT_COMMIT}" \
    "${REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_CHECKER_EXIT_CODE}" \
    "${REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_APPLY_EXIT_CODE}" \
    "${REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_STAGE_REMOTE_STAGING_ROOT}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_STAGED_WRAPPER_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_STAGED_INTERNAL_PATH}" \
    "${REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_STAGING_OCCURRED}" \
    "${REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_STAGING_RETAINED_FOR_DIAGNOSTICS}" \
    "${REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_TRANSIENT_STAGING_REMOVED}" \
    "${REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_CHECKER_RAN}" \
    "${REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_APPLY_RAN}" \
    "${REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_SUDO_UNAVAILABLE}" \
    "${REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_WRAPPER_TOOLING_ERROR}" \
    "${REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_FAILURE_CLASSIFICATION}" \
    "${REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_BLOCKER_DETAIL}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_SUDO_MODE}" \
    "${REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_CLEANUP_COMPLETED}" \
    "${remote_alpha_prepare_es_writable_state_ownership_stage_schema_version}" <<'PY'
import json
import pathlib
import sys

(
    output_path,
    local_file_meta_path,
    stage_stat_meta_path,
    check_validation_meta_path,
    check_output_path,
    apply_summary_output_path,
    run_id,
    ssh_target,
    git_commit,
    checker_exit_code,
    apply_exit_code,
    remote_staged_path,
    staged_wrapper_path,
    staged_internal_path,
    staging_occurred,
    staging_retained_for_diagnostics,
    transient_staging_removed,
    checker_ran,
    apply_ran,
    sudo_unavailable,
    wrapper_tooling_error,
    failure_classification,
    blocker_detail,
    sudo_mode,
    remote_cleanup_completed,
    schema_version,
) = sys.argv[1:]

def load_json(path: str):
    p = pathlib.Path(path)
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))

payload = {
    "schema_version": schema_version,
    "run_id": run_id,
    "ssh_target": ssh_target,
    "git_commit": git_commit,
    "local_git_commit": git_commit,
    "local_files": load_json(local_file_meta_path) or [],
    "remote_staged_path": remote_staged_path,
    "remote_staging": load_json(stage_stat_meta_path) or {},
    "checker": load_json(check_validation_meta_path) or {},
    "checker_exit_code": int(checker_exit_code) if checker_exit_code else None,
    "apply_exit_code": int(apply_exit_code) if apply_exit_code else None,
    "checker_ran": checker_ran == "true",
    "apply_ran": apply_ran == "true",
    "staging_occurred": staging_occurred == "true",
    "staging_retained_for_diagnostics": staging_retained_for_diagnostics == "true",
    "transient_staging_removed": transient_staging_removed == "true",
    "sudo_unavailable": sudo_unavailable == "true",
    "wrapper_tooling_error": wrapper_tooling_error == "true",
    "failure_classification": failure_classification or None,
    "sudo_or_preflight_blocker": blocker_detail or None,
    "sudo_mode": sudo_mode,
    "remote_cleanup_completed": remote_cleanup_completed == "true",
    "local_outputs": {
        "check_output_path": pathlib.Path(check_output_path).name,
        "apply_summary_output_path": pathlib.Path(apply_summary_output_path).name,
        "helper_staging_record_output_path": pathlib.Path(output_path).name,
    },
    "staged_files": [
        {"local_path": "scripts/remote_alpha_prepare_es_writable_state_ownership.sh", "remote_path": staged_wrapper_path},
        {"local_path": "scripts/internal/remote_alpha_prepare_es_writable_state_ownership.sh", "remote_path": staged_internal_path},
    ],
}
pathlib.Path(output_path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

remote_alpha_prepare_es_writable_state_ownership_stage_finalize_on_exit() {
  if [[ "${REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_KEEP_STAGING_ON_FAILURE}" == "true" && "${REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_WRAPPER_TOOLING_ERROR}" == "true" ]]; then
    REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_STAGING_RETAINED_FOR_DIAGNOSTICS="true"
  else
    if [[ "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_SUDO_MODE}" == "interactive" ]]; then
      if remote_alpha_prepare_es_writable_state_ownership_stage_remove_remote_user_owned_roots >/dev/null 2>&1; then
        if [[ "${REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_UPLOAD_PREPARED}" == "true" || "${REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_STAGING_OCCURRED}" == "true" ]]; then
          REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_CLEANUP_COMPLETED="true"
          REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_TRANSIENT_STAGING_REMOVED="true"
        fi
      fi
    elif remote_alpha_prepare_es_writable_state_ownership_stage_remote_cleanup >/dev/null 2>&1; then
      REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_CLEANUP_COMPLETED="true"
      REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_TRANSIENT_STAGING_REMOVED="true"
    fi
  fi
  if [[ -n "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_PROVENANCE_OUTPUT_PATH:-}" ]]; then
    remote_alpha_prepare_es_writable_state_ownership_stage_write_provenance >/dev/null 2>&1 || true
  fi
}

remote_alpha_prepare_es_writable_state_ownership_stage_main() {
  remote_alpha_prepare_es_writable_state_ownership_stage_defaults
  remote_alpha_prepare_es_writable_state_ownership_stage_parse_args "$@" || return $?
  remote_alpha_prepare_es_writable_state_ownership_stage_finalize_paths

  remote_alpha_prepare_es_writable_state_ownership_require_command python3 || return 1
  remote_alpha_prepare_es_writable_state_ownership_require_command ssh || return 1
  remote_alpha_prepare_es_writable_state_ownership_require_command scp || return 1

  remote_alpha_prepare_es_writable_state_ownership_stage_ensure_parent_dir "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_CHECK_OUTPUT_PATH}"
  remote_alpha_prepare_es_writable_state_ownership_stage_ensure_parent_dir "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_APPLY_SUMMARY_OUTPUT_PATH}"
  remote_alpha_prepare_es_writable_state_ownership_stage_ensure_parent_dir "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_PROVENANCE_OUTPUT_PATH}"

  local tmpdir local_upload_dir stage_stat_path
  tmpdir="$(mktemp -d)"
  local_upload_dir="${tmpdir}/upload"
  stage_stat_path="${tmpdir}/stage-stat.txt"
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_LOCAL_FILE_META_PATH="${tmpdir}/local-files.json"
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_STAGE_STAT_META_PATH="${tmpdir}/stage-stat.json"
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_CHECK_VALIDATION_META_PATH="${tmpdir}/check-validation.json"
  trap "remote_alpha_prepare_es_writable_state_ownership_stage_finalize_on_exit; rm -rf -- '${tmpdir}'" EXIT

  remote_alpha_prepare_es_writable_state_ownership_stage_make_local_upload_tree "${local_upload_dir}" || {
    remote_alpha_prepare_es_writable_state_ownership_stage_note_wrapper_tooling_error "could not assemble the local ES writable-state ownership upload tree"
    return 1
  }
  remote_alpha_prepare_es_writable_state_ownership_stage_validate_local_upload_tree "${local_upload_dir}" || {
    remote_alpha_prepare_es_writable_state_ownership_stage_note_wrapper_tooling_error "local ES writable-state ownership upload tree was missing required staged files"
    return 1
  }
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_GIT_COMMIT="$(remote_alpha_prepare_es_writable_state_ownership_stage_git_commit)"
  local helper_paths=(
    "${REPO_ROOT}/scripts/remote_alpha_prepare_es_writable_state_ownership.sh"
    "${REPO_ROOT}/scripts/internal/remote_alpha_prepare_es_writable_state_ownership.sh"
  )
  remote_alpha_prepare_es_writable_state_ownership_stage_local_file_meta "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_LOCAL_FILE_META_PATH}" "${helper_paths[@]}"

  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_UPLOAD_ROOT="/tmp/execution-substrate-es-writable-state-ownership-upload-${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_RUN_ID}"
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_ARTIFACT_ROOT="/tmp/execution-substrate-es-writable-state-ownership-artifacts-${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_RUN_ID}"
  REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_STAGE_REMOTE_STAGING_ROOT="${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_STAGE_ROOT}/${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_RUN_ID}"
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_STAGED_WRAPPER_PATH="${REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_STAGE_REMOTE_STAGING_ROOT}/scripts/remote_alpha_prepare_es_writable_state_ownership.sh"
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_STAGED_INTERNAL_PATH="${REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_STAGE_REMOTE_STAGING_ROOT}/scripts/internal/remote_alpha_prepare_es_writable_state_ownership.sh"
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_STAGE_STAT_ARTIFACT_PATH="${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_ARTIFACT_ROOT}/stage-stat.txt"
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_CHECK_OUTPUT_ARTIFACT_PATH="${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_ARTIFACT_ROOT}/es-writable-state-ownership-check-only.json"

  if [[ "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_SUDO_MODE}" != "interactive" ]]; then
    remote_alpha_prepare_es_writable_state_ownership_stage_noninteractive_sudo_preflight || {
      remote_alpha_prepare_es_writable_state_ownership_stage_note_sudo_unavailable "noninteractive sudo preflight failed for root-owned staged ES writable-state ownership execution"
      return 1
    }
  fi

  remote_alpha_prepare_es_writable_state_ownership_stage_remote_prepare_upload_root || {
    remote_alpha_prepare_es_writable_state_ownership_stage_note_wrapper_tooling_error "could not prepare remote upload root for staged ES writable-state ownership helper tree"
    return 1
  }
  REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_UPLOAD_PREPARED="true"
  remote_alpha_prepare_es_writable_state_ownership_stage_remote_prepare_artifact_root || {
    remote_alpha_prepare_es_writable_state_ownership_stage_note_wrapper_tooling_error "could not prepare remote artifact root for staged ES writable-state ownership helper tree"
    return 1
  }
  remote_alpha_prepare_es_writable_state_ownership_stage_upload_remote_tree "${local_upload_dir}" || {
    remote_alpha_prepare_es_writable_state_ownership_stage_note_wrapper_tooling_error "could not copy staged ES writable-state ownership helper tree to remote upload root"
    return 1
  }

  if [[ "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_SUDO_MODE}" == "interactive" ]]; then
    set +e
    remote_alpha_prepare_es_writable_state_ownership_stage_run_interactive_check_sequence
    REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_CHECKER_EXIT_CODE=$?
    set -e
    REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_STAGING_OCCURRED="true"
    REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_CHECKER_RAN="true"
    remote_alpha_prepare_es_writable_state_ownership_stage_fetch_remote_file \
      "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_STAGE_STAT_ARTIFACT_PATH}" \
      "${stage_stat_path}" || {
      remote_alpha_prepare_es_writable_state_ownership_stage_note_wrapper_tooling_error "could not fetch remote staged ES writable-state ownership helper ownership evidence"
      return 1
    }
    remote_alpha_prepare_es_writable_state_ownership_stage_validate_stage_stat "${stage_stat_path}" "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_STAGE_STAT_META_PATH}" || {
      remote_alpha_prepare_es_writable_state_ownership_stage_note_wrapper_tooling_error "staged ES writable-state ownership helper tree failed root-owned or non-writable validation"
      return 1
    }
    remote_alpha_prepare_es_writable_state_ownership_stage_fetch_remote_file \
      "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_CHECK_OUTPUT_ARTIFACT_PATH}" \
      "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_CHECK_OUTPUT_PATH}" || {
      remote_alpha_prepare_es_writable_state_ownership_stage_note_wrapper_tooling_error "staged ES writable-state ownership helper did not produce fetchable check-only JSON output"
      return 1
    }
  else
    remote_alpha_prepare_es_writable_state_ownership_stage_remote_install_staged_tree || {
      remote_alpha_prepare_es_writable_state_ownership_stage_note_wrapper_tooling_error "could not install staged ES writable-state ownership helper tree as root-owned remote staging"
      return 1
    }
    REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_STAGING_OCCURRED="true"
    remote_alpha_prepare_es_writable_state_ownership_stage_run_remote_batch \
      'set -euo pipefail
staging_root=$1
for path in \
  "${staging_root}" \
  "${staging_root}/scripts" \
  "${staging_root}/scripts/internal" \
  "${staging_root}/scripts/remote_alpha_prepare_es_writable_state_ownership.sh" \
  "${staging_root}/scripts/internal/remote_alpha_prepare_es_writable_state_ownership.sh"
do
  owner=$(sudo -n stat -c "%U" "${path}")
  group=$(sudo -n stat -c "%G" "${path}")
  mode=$(sudo -n stat -c "%a" "${path}")
  printf "%s\t%s\t%s\t%s\n" "${owner}" "${group}" "${mode}" "${path}"
done' \
      "${REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_STAGE_REMOTE_STAGING_ROOT}" >"${stage_stat_path}" || {
      remote_alpha_prepare_es_writable_state_ownership_stage_note_wrapper_tooling_error "could not verify remote staged ES writable-state ownership helper ownership and mode"
      return 1
    }
    remote_alpha_prepare_es_writable_state_ownership_stage_validate_stage_stat "${stage_stat_path}" "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_STAGE_STAT_META_PATH}" || {
      remote_alpha_prepare_es_writable_state_ownership_stage_note_wrapper_tooling_error "staged ES writable-state ownership helper tree failed root-owned or non-writable validation"
      return 1
    }
    set +e
    remote_alpha_prepare_es_writable_state_ownership_stage_run_remote_check_only "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_CHECK_OUTPUT_PATH}"
    REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_CHECKER_EXIT_CODE=$?
    set -e
    REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_CHECKER_RAN="true"
  fi

  [[ -s "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_CHECK_OUTPUT_PATH}" ]] || {
    remote_alpha_prepare_es_writable_state_ownership_stage_note_wrapper_tooling_error "staged ES writable-state ownership helper did not produce local check-only JSON output"
    return 1
  }
  remote_alpha_prepare_es_writable_state_ownership_stage_validate_check_report "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_CHECK_OUTPUT_PATH}" "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_CHECK_VALIDATION_META_PATH}" || {
    remote_alpha_prepare_es_writable_state_ownership_stage_note_wrapper_tooling_error "staged ES writable-state ownership check-only output was malformed or violated the non-mutating helper contract"
    return 1
  }

  local overall
  overall="$(remote_alpha_prepare_es_writable_state_ownership_json_field "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_CHECK_OUTPUT_PATH}" "overall_classification" 2>/dev/null || true)"
  if [[ "${overall}" == "blocker" ]]; then
    if [[ "${REMOTE_ALPHA_OPERATION_MODE}" != "apply" ]]; then
      return 1
    fi
    if [[ "${REMOTE_ALPHA_ROTATE_NONEMPTY_ROOTS}" == "true" ]]; then
      local rotation_apply_ready
      rotation_apply_ready="$(remote_alpha_prepare_es_writable_state_ownership_json_field "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_CHECK_OUTPUT_PATH}" "plan.rotation_apply_ready" 2>/dev/null || true)"
      if [[ "${rotation_apply_ready}" != "true" ]]; then
        return 1
      fi
    elif [[ "${REMOTE_ALPHA_FIX_PARENT_CHAIN}" == "true" ]]; then
      local parent_traversal_apply_ready
      parent_traversal_apply_ready="$(remote_alpha_prepare_es_writable_state_ownership_json_field "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_CHECK_OUTPUT_PATH}" "plan.parent_traversal_apply_ready" 2>/dev/null || true)"
      if [[ "${parent_traversal_apply_ready}" != "true" ]]; then
        return 1
      fi
    elif [[ "${REMOTE_ALPHA_RECONCILE_ARTIFACTS}" == "true" ]]; then
      local artifact_reconciliation_apply_ready
      artifact_reconciliation_apply_ready="$(remote_alpha_prepare_es_writable_state_ownership_json_field "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_CHECK_OUTPUT_PATH}" "plan.artifact_reconciliation_apply_ready" 2>/dev/null || true)"
      if [[ "${artifact_reconciliation_apply_ready}" != "true" ]]; then
        return 1
      fi
    else
      return 1
    fi
  fi
  if [[ "${REMOTE_ALPHA_OPERATION_MODE}" != "apply" ]]; then
    remote_alpha_prepare_es_writable_state_ownership_stage_visible_cleanup_if_needed || return 1
    return 0
  fi

  if [[ "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_SUDO_MODE}" == "interactive" ]]; then
    remote_alpha_prepare_es_writable_state_ownership_stage_remote_prepare_upload_root || {
      remote_alpha_prepare_es_writable_state_ownership_stage_note_wrapper_tooling_error "could not prepare remote upload root for interactive ES writable-state ownership apply staging"
      return 1
    }
    remote_alpha_prepare_es_writable_state_ownership_stage_upload_remote_tree "${local_upload_dir}" || {
      remote_alpha_prepare_es_writable_state_ownership_stage_note_wrapper_tooling_error "could not copy staged ES writable-state ownership helper tree for interactive apply"
      return 1
    }
    set +e
    remote_alpha_prepare_es_writable_state_ownership_stage_run_interactive_apply_sequence
    REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_APPLY_EXIT_CODE=$?
    set -e
  else
    set +e
    remote_alpha_prepare_es_writable_state_ownership_stage_run_remote_apply
    REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_APPLY_EXIT_CODE=$?
    set -e
  fi
  REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_APPLY_RAN="true"

  remote_alpha_prepare_es_writable_state_ownership_stage_fetch_remote_file \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_REMOTE_SUMMARY_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OWNERSHIP_APPLY_SUMMARY_OUTPUT_PATH}" || {
    remote_alpha_prepare_es_writable_state_ownership_stage_note_wrapper_tooling_error "could not fetch remote ES writable-state ownership apply summary"
    return 1
  }
  remote_alpha_prepare_es_writable_state_ownership_stage_visible_cleanup_if_needed || return 1
  if [[ "${REMOTE_ALPHA_PREPARE_ES_WRITABLE_STATE_OWNERSHIP_APPLY_EXIT_CODE}" != "0" ]]; then
    return 1
  fi
}

remote_alpha_prepare_es_writable_state_ownership_main() {
  if remote_alpha_prepare_es_writable_state_ownership_has_ssh_target "$@"; then
    remote_alpha_prepare_es_writable_state_ownership_stage_main "$@"
    return $?
  fi
  remote_alpha_prepare_es_writable_state_ownership_host_main "$@"
}
