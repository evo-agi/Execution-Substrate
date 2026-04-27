#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${REPO_ROOT:-}" ]]; then
  REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_HELPER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  REPO_ROOT="$(cd "${REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_HELPER_DIR}/../.." && pwd)"
fi

remote_alpha_migrate_es_service_user_summary_schema_version="execution-substrate.remote-alpha.es-service-user-migration-summary.v1"
remote_alpha_migrate_es_service_user_stage_schema_version="execution-substrate.remote-alpha.es-service-user-migration-stage-provenance.v1"
remote_alpha_migrate_es_service_user_remote_stage_root_default="/var/tmp/execution-substrate-remote-alpha/helper-staging"
remote_alpha_migrate_es_service_user_remote_summary_path_default="/var/tmp/execution-substrate-remote-alpha/es-service-user-migration-summary.json"
remote_alpha_migrate_es_service_user_backup_root_dir_default="/var/tmp/execution-substrate-remote-alpha"
remote_alpha_migrate_es_service_user_default_output_dir="${REPO_ROOT}/.out/remote-alpha-m75q"

REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_KEEP_STAGING_ON_FAILURE="false"
REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_SHOW_HELP="false"
REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_STAGING_OCCURRED="false"
REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_CHECKER_RAN="false"
REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_APPLY_RAN="false"
REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_TRANSIENT_STAGING_REMOVED="false"
REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_STAGING_RETAINED_FOR_DIAGNOSTICS="false"
REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_REMOTE_UPLOAD_PREPARED="false"
REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_REMOTE_CLEANUP_COMPLETED="false"
REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_CHECKER_EXIT_CODE=""
REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_APPLY_EXIT_CODE=""
REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_SUDO_UNAVAILABLE="false"
REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_WRAPPER_TOOLING_ERROR="false"
REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_FAILURE_CLASSIFICATION=""
REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_BLOCKER_DETAIL=""

REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_LOCAL_FILE_META_PATH=""
REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_STAGE_STAT_META_PATH=""
REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_CHECK_VALIDATION_META_PATH=""
REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_GIT_COMMIT=""
REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGING_ROOT=""
REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_UPLOAD_ROOT=""
REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_ARTIFACT_ROOT=""
REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGED_WRAPPER_PATH=""
REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGED_INTERNAL_PATH=""
REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGED_CHECKER_WRAPPER_PATH=""
REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGED_CHECKER_INTERNAL_PATH=""
REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGE_STAT_ARTIFACT_PATH=""
REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_CHECK_OUTPUT_ARTIFACT_PATH=""
REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_APPLY_STDOUT_ARTIFACT_PATH=""

remote_alpha_migrate_es_service_user_init_expected_slice_inputs() {
  remote_alpha_migrate_es_service_user_expected_service_name="${remote_alpha_migrate_es_service_user_expected_service_name:-es}"
  remote_alpha_migrate_es_service_user_expected_service_user="${remote_alpha_migrate_es_service_user_expected_service_user:-es}"
  remote_alpha_migrate_es_service_user_expected_service_group="${remote_alpha_migrate_es_service_user_expected_service_group:-es}"
  remote_alpha_migrate_es_service_user_expected_binary_path="${remote_alpha_migrate_es_service_user_expected_binary_path:-/usr/local/lib/execution-substrate/bin/es}"
  remote_alpha_migrate_es_service_user_expected_config_path="${remote_alpha_migrate_es_service_user_expected_config_path:-/etc/execution-substrate/es.json}"
  remote_alpha_migrate_es_service_user_expected_healthcheck_env_path="${remote_alpha_migrate_es_service_user_expected_healthcheck_env_path:-/etc/execution-substrate/healthcheck.env}"
  remote_alpha_migrate_es_service_user_expected_service_unit_path="${remote_alpha_migrate_es_service_user_expected_service_unit_path:-/etc/systemd/system/es.service}"
  remote_alpha_migrate_es_service_user_expected_service_dropin_dir="${remote_alpha_migrate_es_service_user_expected_service_dropin_dir:-/etc/systemd/system/es.service.d}"
  remote_alpha_migrate_es_service_user_expected_service_dropin_path="${remote_alpha_migrate_es_service_user_expected_service_dropin_path:-/etc/systemd/system/es.service.d/10-account.conf}"
}

remote_alpha_migrate_es_service_user_defaults() {
  remote_alpha_migrate_es_service_user_init_expected_slice_inputs
  REMOTE_ALPHA_OPERATION_MODE="check_only"
  REMOTE_ALPHA_SERVICE_NAME="${remote_alpha_migrate_es_service_user_expected_service_name}"
  REMOTE_ALPHA_SERVICE_USER="${remote_alpha_migrate_es_service_user_expected_service_user}"
  REMOTE_ALPHA_SERVICE_GROUP="${remote_alpha_migrate_es_service_user_expected_service_group}"
  REMOTE_ALPHA_BINARY_PATH="${remote_alpha_migrate_es_service_user_expected_binary_path}"
  REMOTE_ALPHA_CONFIG_PATH="${remote_alpha_migrate_es_service_user_expected_config_path}"
  REMOTE_ALPHA_HEALTHCHECK_ENV_PATH="${remote_alpha_migrate_es_service_user_expected_healthcheck_env_path}"
  REMOTE_ALPHA_SERVICE_UNIT_PATH="${remote_alpha_migrate_es_service_user_expected_service_unit_path}"
  REMOTE_ALPHA_SERVICE_DROPIN_DIR="${remote_alpha_migrate_es_service_user_expected_service_dropin_dir}"
  REMOTE_ALPHA_SERVICE_DROPIN_PATH="${remote_alpha_migrate_es_service_user_expected_service_dropin_path}"
  REMOTE_ALPHA_SUMMARY_PATH="${REMOTE_ALPHA_SUMMARY_PATH:-${remote_alpha_migrate_es_service_user_remote_summary_path_default}}"
  REMOTE_ALPHA_CHECKER_WRAPPER_PATH="${REMOTE_ALPHA_CHECKER_WRAPPER_PATH:-${REPO_ROOT}/scripts/remote_alpha_check_es_writable_state_readiness.sh}"
  remote_alpha_migrate_es_service_user_backup_root_dir="${REMOTE_ALPHA_TEST_BACKUP_ROOT:-${remote_alpha_migrate_es_service_user_backup_root_dir_default}}"
}

remote_alpha_migrate_es_service_user_usage() {
  cat <<'EOF'
Usage:
  scripts/remote_alpha_migrate_es_service_user.sh --ssh-target <user@host>
  scripts/remote_alpha_migrate_es_service_user.sh --ssh-target <user@host> --apply
  sudo scripts/remote_alpha_migrate_es_service_user.sh
  sudo scripts/remote_alpha_migrate_es_service_user.sh --apply

Repo-side staged wrapper flags:
  --ssh-target <user@host>
  --check-only
  --dry-run
  --apply
  --run-id <timestamp-or-id>
  --output-dir </path/to/output-dir>
  --check-output </path/to/es-service-user-migration-check-only.json>
  --apply-summary-output </path/to/es-service-user-migration-apply-summary.json>
  --apply-stdout-output </path/to/es-service-user-migration-apply-stdout.txt>
  --helper-staging-record-output </path/to/es-service-user-migration-helper-staging-record.json>
  --provenance-output </path/to/es-service-user-migration-helper-staging-record.json>
  --remote-summary-path </remote/path/to/es-service-user-migration-summary.json>
  --interactive-sudo
  --keep-staging-on-failure

Host-local helper flags:
  --check-only
  --dry-run
  --apply
  --summary-path </path/to/es-service-user-migration-summary.json>
  --help

Default behavior is non-mutating check-only for the long-lived es.service
only. This helper does not claim full ES/runtime de-root.
EOF
}

remote_alpha_migrate_es_service_user_reject_slice_override_env() {
  local name=$1
  local expected=$2
  local actual=""

  actual="$(printenv "${name}" 2>/dev/null || true)"
  if [[ -z "${actual}" ]]; then
    return 0
  fi
  if [[ "${actual}" != "${expected}" ]]; then
    printf 'remote alpha ES service-user migration does not accept %s override for this sealed long-lived ES service-user slice; expected repo-owned value %q (got %q)\n' "${name}" "${expected}" "${actual}" >&2
    return 1
  fi
  return 0
}

remote_alpha_migrate_es_service_user_require_pinned_slice_inputs() {
  remote_alpha_migrate_es_service_user_init_expected_slice_inputs
  remote_alpha_migrate_es_service_user_reject_slice_override_env "REMOTE_ALPHA_SERVICE_NAME" "${remote_alpha_migrate_es_service_user_expected_service_name}" || return 1
  remote_alpha_migrate_es_service_user_reject_slice_override_env "REMOTE_ALPHA_SERVICE_USER" "${remote_alpha_migrate_es_service_user_expected_service_user}" || return 1
  remote_alpha_migrate_es_service_user_reject_slice_override_env "REMOTE_ALPHA_SERVICE_GROUP" "${remote_alpha_migrate_es_service_user_expected_service_group}" || return 1
  remote_alpha_migrate_es_service_user_reject_slice_override_env "REMOTE_ALPHA_BINARY_PATH" "${remote_alpha_migrate_es_service_user_expected_binary_path}" || return 1
  remote_alpha_migrate_es_service_user_reject_slice_override_env "REMOTE_ALPHA_CONFIG_PATH" "${remote_alpha_migrate_es_service_user_expected_config_path}" || return 1
  remote_alpha_migrate_es_service_user_reject_slice_override_env "REMOTE_ALPHA_HEALTHCHECK_ENV_PATH" "${remote_alpha_migrate_es_service_user_expected_healthcheck_env_path}" || return 1
  remote_alpha_migrate_es_service_user_reject_slice_override_env "REMOTE_ALPHA_SERVICE_UNIT_PATH" "${remote_alpha_migrate_es_service_user_expected_service_unit_path}" || return 1
  remote_alpha_migrate_es_service_user_reject_slice_override_env "REMOTE_ALPHA_SERVICE_DROPIN_DIR" "${remote_alpha_migrate_es_service_user_expected_service_dropin_dir}" || return 1
  remote_alpha_migrate_es_service_user_reject_slice_override_env "REMOTE_ALPHA_SERVICE_DROPIN_PATH" "${remote_alpha_migrate_es_service_user_expected_service_dropin_path}" || return 1
}

remote_alpha_migrate_es_service_user_has_ssh_target() {
  local arg
  for arg in "$@"; do
    if [[ "${arg}" == "--ssh-target" ]]; then
      return 0
    fi
  done
  return 1
}

remote_alpha_migrate_es_service_user_require_root() {
  if [[ "$(id -u)" != "0" ]]; then
    echo "remote alpha ES service-user migration helper must run as root; use sudo scripts/remote_alpha_migrate_es_service_user.sh" >&2
    return 1
  fi
}

remote_alpha_migrate_es_service_user_require_command() {
  local name=$1
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "${name} is required" >&2
    return 1
  fi
}

remote_alpha_migrate_es_service_user_json_field() {
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

remote_alpha_migrate_es_service_user_parse_host_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --service-name)
        echo "remote alpha ES service-user migration does not accept --service-name for this sealed long-lived ES service-user slice" >&2
        return 2
        ;;
      --service-user)
        echo "remote alpha ES service-user migration does not accept --service-user for this sealed long-lived ES service-user slice" >&2
        return 2
        ;;
      --service-group)
        echo "remote alpha ES service-user migration does not accept --service-group for this sealed long-lived ES service-user slice" >&2
        return 2
        ;;
      --binary-path)
        echo "remote alpha ES service-user migration does not accept --binary-path for this sealed long-lived ES service-user slice" >&2
        return 2
        ;;
      --config-path)
        echo "remote alpha ES service-user migration does not accept --config-path for this sealed long-lived ES service-user slice" >&2
        return 2
        ;;
      --healthcheck-env-path)
        echo "remote alpha ES service-user migration does not accept --healthcheck-env-path for this sealed long-lived ES service-user slice" >&2
        return 2
        ;;
      --service-unit-path)
        echo "remote alpha ES service-user migration does not accept --service-unit-path for this sealed long-lived ES service-user slice" >&2
        return 2
        ;;
      --service-dropin-dir)
        echo "remote alpha ES service-user migration does not accept --service-dropin-dir for this sealed long-lived ES service-user slice" >&2
        return 2
        ;;
      --service-dropin-path)
        echo "remote alpha ES service-user migration does not accept --service-dropin-path for this sealed long-lived ES service-user slice" >&2
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
      --summary-path)
        REMOTE_ALPHA_SUMMARY_PATH="$2"
        shift 2
        ;;
      --help|-h)
        REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_SHOW_HELP="true"
        remote_alpha_migrate_es_service_user_usage
        return 1
        ;;
      *)
        echo "unknown argument: $1" >&2
        remote_alpha_migrate_es_service_user_usage >&2
        return 2
        ;;
    esac
  done
}

remote_alpha_migrate_es_service_user_python() {
  python3 - \
    "${remote_alpha_migrate_es_service_user_summary_schema_version}" \
    "${REMOTE_ALPHA_OPERATION_MODE}" \
    "${REMOTE_ALPHA_SUMMARY_PATH}" \
    "${REMOTE_ALPHA_SERVICE_NAME}" \
    "${REMOTE_ALPHA_SERVICE_USER}" \
    "${REMOTE_ALPHA_SERVICE_GROUP}" \
    "${REMOTE_ALPHA_BINARY_PATH}" \
    "${REMOTE_ALPHA_CONFIG_PATH}" \
    "${REMOTE_ALPHA_HEALTHCHECK_ENV_PATH}" \
    "${REMOTE_ALPHA_SERVICE_UNIT_PATH}" \
    "${REMOTE_ALPHA_SERVICE_DROPIN_DIR}" \
    "${REMOTE_ALPHA_SERVICE_DROPIN_PATH}" \
    "${remote_alpha_migrate_es_service_user_backup_root_dir}" \
    "${REMOTE_ALPHA_CHECKER_WRAPPER_PATH}" <<'PY'
import hashlib
import json
import os
import pathlib
import shutil
import stat as statmod
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

SCHEMA_VERSION = sys.argv[1]
MODE = sys.argv[2]
SUMMARY_PATH = sys.argv[3]
SERVICE_NAME = sys.argv[4]
SERVICE_USER = sys.argv[5]
SERVICE_GROUP = sys.argv[6]
BINARY_PATH = sys.argv[7]
CONFIG_PATH = sys.argv[8]
HEALTHCHECK_ENV_PATH = sys.argv[9]
SERVICE_UNIT_PATH = sys.argv[10]
SERVICE_DROPIN_DIR = sys.argv[11]
SERVICE_DROPIN_PATH = sys.argv[12]
BACKUP_ROOT_DIR = sys.argv[13]
CHECKER_WRAPPER_PATH = sys.argv[14]

DROPIN_TEXT = f"[Service]\nUser={SERVICE_USER}\nGroup={SERVICE_GROUP}\nUMask=0027\n"
MARKER_NAME = "ownership-normalization.json"
MARKER_SCHEMA_VERSION = "execution-substrate.es.runtime-ownership-normalization.v1"
RESULT_BUNDLE_NAME = "result.tar.gz"
CHECKER_SCHEMA_VERSION = "execution-substrate.remote-alpha.es-writable-state-readiness.v1"


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def make_status(classification, summary, **kwargs):
    payload = {
        "classification": classification,
        "summary": summary,
    }
    payload.update(kwargs)
    return payload


def run_command(args, check=False):
    return subprocess.run(args, check=check, capture_output=True, text=True)


def mode_string(mode_bits):
    return format(mode_bits & 0o7777, "04o")


def fallback_stat(path):
    rendered = os.fspath(path)
    try:
        info = os.lstat(rendered)
    except FileNotFoundError:
        return {
            "path": rendered,
            "exists": False,
            "uid": None,
            "gid": None,
            "mode": "",
            "mode_bits": 0,
            "file_type": "",
            "source": "lstat",
            "error": "not found",
        }
    except OSError as exc:
        return {
            "path": rendered,
            "exists": False,
            "uid": None,
            "gid": None,
            "mode": "",
            "mode_bits": 0,
            "file_type": "",
            "source": "lstat",
            "error": str(exc),
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

    mode_bits = statmod.S_IMODE(info.st_mode)
    return {
        "path": rendered,
        "exists": True,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": mode_string(mode_bits),
        "mode_bits": mode_bits,
        "file_type": file_type,
        "source": "lstat",
    }


def stat_path(path):
    rendered = os.fspath(path)
    proc = run_command(["stat", "-c", "%u\t%g\t%a\t%F", rendered])
    if proc.returncode == 0:
        parts = proc.stdout.strip().split("\t", 3)
        if len(parts) == 4:
            try:
                mode_bits = int(parts[2], 8)
                return {
                    "path": rendered,
                    "exists": True,
                    "uid": int(parts[0]),
                    "gid": int(parts[1]),
                    "mode": mode_string(mode_bits),
                    "mode_bits": mode_bits,
                    "file_type": parts[3].strip(),
                    "source": "stat",
                }
            except ValueError:
                pass
    return fallback_stat(rendered)


def sha256_file(path):
    data = pathlib.Path(path).read_bytes()
    return hashlib.sha256(data).hexdigest()


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


def selected_permission_bits(stat_info, uid, gid):
    mode_bits = stat_info["mode_bits"]
    if uid == stat_info["uid"]:
        return (mode_bits >> 6) & 0o7
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
                "uid": directory_stat["uid"],
                "gid": directory_stat["gid"],
            }
        )
        if not directory_stat["exists"]:
            return False, checked, f"directory does not exist: {directory}"
        if directory_stat["file_type"] == "symbolic link":
            continue
        if directory_stat["file_type"] != "directory":
            return False, checked, f"path is not a directory: {directory}"
        if selected_permission_bits(directory_stat, uid, gid) & 0o1 == 0:
            return False, checked, f"directory is not traversable by {SERVICE_USER}:{SERVICE_GROUP}: {directory}"
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
        "es_can_delete_entries": False,
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
    result["es_can_delete_entries"] = result["es_can_write"] and result["es_can_traverse"]
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
        "es_can_execute": False,
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
    result["es_can_execute"] = bool(bits & 0o1)
    return result


def parse_json_file(path):
    try:
        return json.loads(pathlib.Path(path).read_text(encoding="utf-8")), ""
    except FileNotFoundError:
        return None, "not found"
    except Exception as exc:  # noqa: BLE001
        return None, str(exc)


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
            line = raw.strip()
            if line:
                group_line = line
                break
    if result["group_exists"]:
        fields = group_line.split(":")
        if len(fields) < 4:
            return make_status("blocker", f"failed to parse service group entry for {SERVICE_GROUP}", **result)
        result["gid"] = int(fields[2])
        group_members = []
        for member in fields[3].split(","):
            member = member.strip()
            if member and member not in group_members:
                group_members.append(member)
        result["group_entry_members"] = group_members

        passwd_proc = run_command(["getent", "passwd"])
        if passwd_proc.returncode != 0:
            return make_status("blocker", "failed to enumerate passwd entries while checking es account narrowness", **result)
        primary_group_users = []
        for raw in passwd_proc.stdout.splitlines():
            line = raw.strip()
            if not line:
                continue
            fields = line.split(":")
            if len(fields) < 4:
                continue
            username = fields[0].strip()
            gid = fields[3].strip()
            if username and gid == str(result["gid"]) and username not in primary_group_users:
                primary_group_users.append(username)
        result["primary_group_users"] = primary_group_users
        combined = []
        for member in primary_group_users + group_members:
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
        return make_status(
            "blocker",
            "apply readiness is blocked because the dedicated es:es account is missing or incomplete: " + ", ".join(missing),
            **result,
        )

    unexpected_group_members = [member for member in result["group_members"] if member != SERVICE_USER]
    if unexpected_group_members:
        return make_status(
            "blocker",
            "apply readiness is blocked because the es group is broader than allowed for this slice: "
            + ", ".join(unexpected_group_members),
            unexpected_group_members=unexpected_group_members,
            **result,
        )

    if result["primary_group"] != SERVICE_GROUP:
        return make_status(
            "blocker",
            f"apply readiness is blocked because {SERVICE_USER} does not use primary group {SERVICE_GROUP}",
            **result,
        )

    if result["supplementary_groups"]:
        return make_status(
            "blocker",
            "apply readiness is blocked because the es account has supplementary groups: "
            + ", ".join(result["supplementary_groups"]),
            **result,
        )

    result["narrow_dedicated_account"] = True
    return make_status("pass", "dedicated es:es account exists and is narrow", **result)


def load_runtime_config():
    payload, error = parse_json_file(CONFIG_PATH)
    if payload is None:
        return make_status(
            "blocker",
            f"failed to read ES config: {error}",
            config_path=CONFIG_PATH,
            runtime={},
        )

    http = payload.get("http") or {}
    bind_address = str(http.get("bind_address") or "").strip()
    try:
        port = int(http.get("port") or 0)
    except Exception:  # noqa: BLE001
        port = 0

    tls = payload.get("tls") or {}
    deps = payload.get("dependencies") or {}
    artifact_registry = deps.get("artifact_registry") or {}
    execution_governance = deps.get("execution_governance") or {}
    execution = payload.get("execution") or {}

    runtime = {
        "bind_address": bind_address,
        "port": port,
        "health_url": f"https://{bind_address}:{port}/health" if bind_address and port > 0 else "",
        "contract_url": f"https://{bind_address}:{port}/v1/executions:contract" if bind_address and port > 0 else "",
        "tls": {
            "cert_file": str(tls.get("cert_file") or "").strip(),
            "key_file": str(tls.get("key_file") or "").strip(),
            "client_ca_file": str(tls.get("client_ca_file") or "").strip(),
        },
        "artifact_registry": {
            "client_cert_file": str(artifact_registry.get("client_cert_file") or "").strip(),
            "client_key_file": str(artifact_registry.get("client_key_file") or "").strip(),
            "root_ca_file": str(artifact_registry.get("root_ca_file") or "").strip(),
        },
        "execution_governance": {
            "client_cert_file": str(execution_governance.get("client_cert_file") or "").strip(),
            "client_key_file": str(execution_governance.get("client_key_file") or "").strip(),
            "root_ca_file": str(execution_governance.get("root_ca_file") or "").strip(),
        },
        "execution": {
            "staging_root_dir": str(execution.get("staging_root_dir") or "").strip(),
            "results_root_dir": str(execution.get("results_root_dir") or "").strip(),
            "runtime_support_binary": str(execution.get("runtime_support_binary") or "").strip(),
            "spire_workload_api_socket_path": str(execution.get("spire_workload_api_socket_path") or "").strip(),
        },
    }

    missing = []
    for field, value in [
        ("http.bind_address", bind_address),
        ("http.port", str(port) if port > 0 else ""),
        ("tls.cert_file", runtime["tls"]["cert_file"]),
        ("tls.key_file", runtime["tls"]["key_file"]),
        ("tls.client_ca_file", runtime["tls"]["client_ca_file"]),
        ("dependencies.artifact_registry.client_cert_file", runtime["artifact_registry"]["client_cert_file"]),
        ("dependencies.artifact_registry.client_key_file", runtime["artifact_registry"]["client_key_file"]),
        ("dependencies.artifact_registry.root_ca_file", runtime["artifact_registry"]["root_ca_file"]),
        ("dependencies.execution_governance.client_cert_file", runtime["execution_governance"]["client_cert_file"]),
        ("dependencies.execution_governance.client_key_file", runtime["execution_governance"]["client_key_file"]),
        ("dependencies.execution_governance.root_ca_file", runtime["execution_governance"]["root_ca_file"]),
        ("execution.staging_root_dir", runtime["execution"]["staging_root_dir"]),
        ("execution.results_root_dir", runtime["execution"]["results_root_dir"]),
        ("execution.runtime_support_binary", runtime["execution"]["runtime_support_binary"]),
    ]:
        if not value:
            missing.append(field)

    if missing:
        return make_status(
            "blocker",
            "ES config is missing required fields for this migration slice: " + ", ".join(missing),
            config_path=CONFIG_PATH,
            runtime=runtime,
        )

    return make_status("pass", "ES config includes the runtime paths required for this migration slice", config_path=CONFIG_PATH, runtime=runtime)


def inspect_service_meta():
    unit_name = SERVICE_NAME if SERVICE_NAME.endswith(".service") else SERVICE_NAME + ".service"
    proc = run_command(
        [
            "systemctl",
            "show",
            unit_name,
            "-p",
            "User",
            "-p",
            "Group",
            "-p",
            "ExecStart",
            "-p",
            "FragmentPath",
            "-p",
            "ActiveState",
            "-p",
            "SubState",
        ]
    )
    values = {
        "service": unit_name,
        "user": "",
        "group": "",
        "exec_start": "",
        "fragment_path": "",
        "active_state": "",
        "sub_state": "",
        "active": False,
        "effective_user": "root(default)",
        "effective_group": "root(default)",
    }
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
        elif key == "ExecStart":
            values["exec_start"] = value
        elif key == "FragmentPath":
            values["fragment_path"] = value
        elif key == "ActiveState":
            values["active_state"] = value
            values["active"] = value == "active"
        elif key == "SubState":
            values["sub_state"] = value
    if values["user"]:
        values["effective_user"] = values["user"]
    if values["group"]:
        values["effective_group"] = values["group"]

    if proc.returncode != 0 and not values["fragment_path"]:
        return make_status("blocker", "failed to inspect es.service via systemctl show", **values)

    if values["effective_user"] not in {"root(default)", SERVICE_USER}:
        return make_status(
            "blocker",
            f"unexpected es.service effective user {values['effective_user']!r} is outside the allowed Alpha or target identities",
            **values,
        )
    if values["effective_group"] not in {"root(default)", SERVICE_GROUP}:
        return make_status(
            "blocker",
            f"unexpected es.service effective group {values['effective_group']!r} is outside the allowed Alpha or target identities",
            **values,
        )

    summary = (
        "current Alpha service identity remains root(default) and is in scope for planned migration"
        if values["effective_user"] == "root(default)" and values["effective_group"] == "root(default)"
        else f"es.service already reports {values['effective_user']}:{values['effective_group']}"
    )
    classification = "pass"
    if values["active_state"] and values["active_state"] != "active":
        classification = "warning"
        summary = f"es.service is not currently active/running ({values['active_state']}/{values['sub_state']})"
    return make_status(classification, summary, **values)


def inspect_service_unit_plan(service_status):
    fragment_path = service_status.get("fragment_path", "")
    exec_start = service_status.get("exec_start", "")
    blockers = []
    if not fragment_path:
        blockers.append("systemctl did not report a FragmentPath for es.service")
    elif fragment_path != SERVICE_UNIT_PATH:
        blockers.append(
            f"es.service FragmentPath {fragment_path!r} did not match the sealed expected unit path {SERVICE_UNIT_PATH!r}"
        )
    if BINARY_PATH not in exec_start:
        blockers.append(f"ExecStart did not include the sealed ES binary path {BINARY_PATH}")
    if CONFIG_PATH not in exec_start:
        blockers.append(f"ExecStart did not include the sealed ES config path {CONFIG_PATH}")

    rollback_notes = [
        f"Restore or remove {SERVICE_DROPIN_PATH} using the backup snapshot before restarting es.service.",
        f"Keep Nomad task User: \"0:0\", the root-start runtime helper, helper-private SPIRE traversal, broad root selector scope, and Vault/workload-zone handoff unchanged during rollback.",
    ]
    plan = {
        "planned_dropin_path": SERVICE_DROPIN_PATH,
        "planned_dropin_dir": SERVICE_DROPIN_DIR,
        "planned_dropin_lines": DROPIN_TEXT.splitlines(),
        "rollback_notes": rollback_notes,
        "preserves_execstart": True,
        "preserves_service_semantics": True,
        "fragment_path": fragment_path,
        "exec_start": exec_start,
    }
    if blockers:
        return make_status("blocker", "service-unit change or rollback planning is blocked: " + "; ".join(blockers), plan=plan)
    return make_status("pass", "bounded systemd drop-in plan is available for es.service only", plan=plan)


def inspect_config_tls_readability(config_status, account_status):
    runtime = config_status.get("runtime") or {}
    if config_status["classification"] == "blocker":
        return make_status("blocker", "config/TLS readability cannot be evaluated because the ES config is invalid", items=[], runtime=runtime)
    if account_status["classification"] == "blocker":
        return make_status("blocker", "config/TLS readability cannot be evaluated because es:es account readiness is blocked", items=[], runtime=runtime)

    uid = account_status["uid"]
    gid = account_status["gid"]
    paths = [
        ("config", CONFIG_PATH),
        ("tls.cert_file", runtime["tls"]["cert_file"]),
        ("tls.key_file", runtime["tls"]["key_file"]),
        ("tls.client_ca_file", runtime["tls"]["client_ca_file"]),
        ("dependencies.artifact_registry.client_cert_file", runtime["artifact_registry"]["client_cert_file"]),
        ("dependencies.artifact_registry.client_key_file", runtime["artifact_registry"]["client_key_file"]),
        ("dependencies.artifact_registry.root_ca_file", runtime["artifact_registry"]["root_ca_file"]),
        ("dependencies.execution_governance.client_cert_file", runtime["execution_governance"]["client_cert_file"]),
        ("dependencies.execution_governance.client_key_file", runtime["execution_governance"]["client_key_file"]),
        ("dependencies.execution_governance.root_ca_file", runtime["execution_governance"]["root_ca_file"]),
    ]

    items = []
    blockers = []
    for field, path in paths:
        access = inspect_file_access(path, uid, gid)
        classification = "pass"
        reasons = []
        if not access["path_exists"]:
            classification = "blocker"
            reasons.append("path does not exist")
        elif access["file_type"] != "regular file":
            classification = "blocker"
            reasons.append("path is not a regular file")
        elif not access["es_can_read"]:
            classification = "blocker"
            reasons.append(f"{SERVICE_USER}:{SERVICE_GROUP} cannot read the path")
        items.append(
            {
                "field": field,
                "classification": classification,
                "summary": "readable by es:es" if classification == "pass" else "; ".join(reasons),
                **access,
            }
        )
        if classification == "blocker":
            blockers.append(f"{field} ({path})")

    if blockers:
        return make_status("blocker", "ES config/TLS readability is blocked for es:es: " + ", ".join(blockers), items=items)
    return make_status("pass", "ES config and referenced TLS files are readable by es:es", items=items)


def inspect_writable_state_manageability(config_status, account_status):
    runtime = config_status.get("runtime") or {}
    execution = runtime.get("execution") or {}
    staging_root = execution.get("staging_root_dir", "")
    results_root = execution.get("results_root_dir", "")
    if config_status["classification"] == "blocker":
        return make_status("blocker", "writable-state roots cannot be evaluated because ES config is invalid", items=[])
    if account_status["classification"] == "blocker":
        return make_status("blocker", "writable-state roots cannot be evaluated because es:es account readiness is blocked", items=[])

    uid = account_status["uid"]
    gid = account_status["gid"]
    items = []
    blockers = []
    for label, path in [("execution.staging_root_dir", staging_root), ("execution.results_root_dir", results_root)]:
        access = inspect_directory_access(path, uid, gid)
        reasons = []
        classification = "pass"
        if not access["path_exists"]:
            classification = "blocker"
            reasons.append("path does not exist")
        elif access["file_type"] != "directory":
            classification = "blocker"
            reasons.append("path is not a directory")
        else:
            if not access["es_can_traverse"]:
                classification = "blocker"
                reasons.append(f"{SERVICE_USER}:{SERVICE_GROUP} cannot traverse the directory")
            if not access["es_can_read"]:
                classification = "blocker"
                reasons.append(f"{SERVICE_USER}:{SERVICE_GROUP} cannot read the directory")
            if not access["es_can_write"]:
                classification = "blocker"
                reasons.append(f"{SERVICE_USER}:{SERVICE_GROUP} cannot write the directory")
            if not access["es_can_delete_entries"]:
                classification = "blocker"
                reasons.append(f"{SERVICE_USER}:{SERVICE_GROUP} cannot delete entries in the directory")
        items.append(
            {
                "field": label,
                "classification": classification,
                "summary": "manageable by es:es" if classification == "pass" else "; ".join(reasons),
                **access,
            }
        )
        if classification == "blocker":
            blockers.append(label)

    if blockers:
        return make_status("blocker", "writable-state root manageability is blocked for es:es: " + ", ".join(blockers), items=items)
    return make_status("pass", "staging and results roots are readable, writable, and deletable by es:es", items=items)


def inspect_target_service_user_startup_validation(config_status, account_status):
    runtime = config_status.get("runtime") or {}
    execution = runtime.get("execution") or {}
    if config_status["classification"] == "blocker":
        return make_status(
            "blocker",
            "target-service-user startup validation cannot be evaluated because the ES config is invalid",
            items=[],
        )
    if account_status["classification"] == "blocker":
        return make_status(
            "blocker",
            "target-service-user startup validation cannot be evaluated because es:es account readiness is blocked",
            items=[],
        )

    uid = account_status["uid"]
    gid = account_status["gid"]
    items = []
    blockers = []
    for field, path, require_execute in [
        ("service.exec_start_binary", BINARY_PATH, True),
        ("execution.runtime_support_binary", execution.get("runtime_support_binary", ""), False),
    ]:
        access = inspect_file_access(path, uid, gid)
        reasons = []
        classification = "pass"
        if not access["path_exists"]:
            classification = "blocker"
            reasons.append("path does not exist")
        elif access["file_type"] != "regular file":
            classification = "blocker"
            reasons.append("path is not a regular file")
        elif require_execute and not access["es_can_execute"]:
            classification = "blocker"
            reasons.append(f"{SERVICE_USER}:{SERVICE_GROUP} cannot execute the path")
        elif not require_execute and not access["es_can_read"]:
            classification = "blocker"
            reasons.append(f"{SERVICE_USER}:{SERVICE_GROUP} cannot read the path")
        items.append(
            {
                "field": field,
                "classification": classification,
                "summary": (
                    "usable by es:es for long-lived startup"
                    if classification == "pass"
                    else "; ".join(reasons)
                ),
                "require_execute": require_execute,
                **access,
            }
        )
        if classification == "blocker":
            blockers.append(f"{field} ({path})")

    if blockers:
        return make_status(
            "blocker",
            "target-service-user startup validation is blocked: " + ", ".join(blockers),
            raw_spire_socket_direct_access_required=False,
            items=items,
        )
    return make_status(
        "pass",
        "target service user can satisfy long-lived ES startup validation without direct raw SPIRE socket access",
        raw_spire_socket_direct_access_required=False,
        items=items,
    )


def inspect_helper_private_spire_runtime_input(config_status):
    runtime = config_status.get("runtime") or {}
    execution = runtime.get("execution") or {}
    spire_path = str(execution.get("spire_workload_api_socket_path") or "").strip()
    if config_status["classification"] == "blocker":
        return make_status(
            "blocker",
            "helper-private SPIRE runtime input cannot be evaluated because the ES config is invalid",
            socket_path=spire_path,
        )
    if not spire_path:
        return make_status(
            "blocker",
            "helper-private SPIRE runtime input is missing execution.spire_workload_api_socket_path",
            socket_path=spire_path,
            reason="spire_workload_api_socket_path_missing",
        )
    if not pathlib.Path(spire_path).is_absolute():
        return make_status(
            "blocker",
            "helper-private SPIRE runtime input is not an absolute path",
            socket_path=spire_path,
            reason="spire_workload_api_socket_path_not_absolute",
        )

    socket_stat = stat_path(spire_path)
    if not socket_stat["exists"]:
        reason = "spire_workload_api_socket_path_permission_denied"
        if socket_stat.get("error") not in {"Permission denied", "permission denied"}:
            reason = "spire_workload_api_socket_path_missing_or_unreadable"
        return make_status(
            "blocker",
            f"helper-private SPIRE runtime input is not usable: {socket_stat.get('error', 'path does not exist')}",
            socket_path=spire_path,
            reason=reason,
            stat=socket_stat,
            target_service_user_direct_access_required=False,
        )

    file_type = str(socket_stat.get("file_type") or "").lower()
    if "socket" not in file_type:
        return make_status(
            "blocker",
            "helper-private SPIRE runtime input is not a unix socket",
            socket_path=spire_path,
            reason="spire_workload_api_socket_path_not_socket",
            stat=socket_stat,
            target_service_user_direct_access_required=False,
        )

    return make_status(
        "pass",
        "helper-private SPIRE runtime input is a local unix socket and remains operator-validated rather than a direct es:es startup read requirement",
        socket_path=spire_path,
        reason="helper_private_spire_runtime_input_valid",
        stat=socket_stat,
        target_service_user_direct_access_required=False,
    )


def inspect_active_runs(config_status, writable_state_status):
    runtime = config_status.get("runtime") or {}
    execution = runtime.get("execution") or {}
    staging_root = execution.get("staging_root_dir", "")
    results_root = execution.get("results_root_dir", "")
    if writable_state_status["classification"] == "blocker":
        return make_status("blocker", "active-run status cannot safely rule out live work because writable-state manageability is blocked", observed_runs=[])

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
    for child in children:
        if not child.is_dir():
            observed.append(
                {
                    "run_id": child.name,
                    "classification": "blocker",
                    "summary": "unexpected non-directory entry under execution.staging_root_dir prevents safely ruling out live work",
                    "marker_path": str(child / "run" / "platform" / MARKER_NAME),
                    "retained_result_path": str(results_path / child.name / RESULT_BUNDLE_NAME),
                }
            )
            blockers.append(child.name)
            continue

        marker_path = child / "run" / "platform" / MARKER_NAME
        retained_bundle = results_path / child.name / RESULT_BUNDLE_NAME
        marker_exists = marker_path.exists()
        retained_exists = retained_bundle.exists()
        classification = "pass"
        summary = "completed-run evidence observed"
        if marker_exists:
            payload, error = parse_json_file(marker_path)
            if payload is None:
                classification = "blocker"
                summary = f"normalization marker could not be read: {error}"
            elif payload.get("schema_version") != MARKER_SCHEMA_VERSION:
                classification = "blocker"
                summary = "normalization marker schema_version is invalid"
            elif str(payload.get("run_id") or "").strip() != child.name:
                classification = "blocker"
                summary = "normalization marker run_id does not match the staging-root run directory"
        elif retained_exists:
            classification = "pass"
            summary = "retained result bundle observed for the run directory"
        else:
            classification = "blocker"
            summary = "active runs are present or cannot be safely ruled out because neither retained-result nor normalization-marker evidence was observed"

        observed.append(
            {
                "run_id": child.name,
                "classification": classification,
                "summary": summary,
                "marker_path": str(marker_path),
                "marker_exists": marker_exists,
                "retained_result_path": str(retained_bundle),
                "retained_result_exists": retained_exists,
            }
        )
        if classification == "blocker":
            blockers.append(child.name)

    if blockers:
        return make_status("blocker", "active runs are present or cannot be safely ruled out: " + ", ".join(blockers), observed_runs=observed)
    return make_status("pass", "all observed staging-root run directories look drained or retained", observed_runs=observed)


def inspect_future_checker(config_status):
    if config_status["classification"] == "blocker":
        return make_status("blocker", "future non-root-required checker cannot run because ES config is invalid", checker_available=False)
    checker_path = pathlib.Path(CHECKER_WRAPPER_PATH)
    if not checker_path.exists():
        return make_status("blocker", "future non-root-required checker wrapper is missing", checker_available=False, checker_path=str(checker_path))

    proc = run_command(["/bin/bash", str(checker_path), "--config-path", CONFIG_PATH, "--mode", "future-non-root-required"])
    stdout = proc.stdout.strip()
    if not stdout:
        return make_status(
            "blocker",
            "future non-root-required checker produced no JSON output",
            checker_available=True,
            checker_path=str(checker_path),
            exit_code=proc.returncode,
            stderr=proc.stderr.strip(),
        )

    try:
        payload = json.loads(stdout)
    except Exception as exc:  # noqa: BLE001
        return make_status(
            "blocker",
            f"future non-root-required checker output was not valid JSON: {exc}",
            checker_available=True,
            checker_path=str(checker_path),
            exit_code=proc.returncode,
            stdout=stdout,
            stderr=proc.stderr.strip(),
        )

    if payload.get("schema_version") != CHECKER_SCHEMA_VERSION:
        return make_status(
            "blocker",
            f"future non-root-required checker schema_version {payload.get('schema_version')!r} did not match the sealed readiness contract",
            checker_available=True,
            checker_path=str(checker_path),
            exit_code=proc.returncode,
            report=payload,
        )

    if payload.get("future_non_root_required") is not True:
        return make_status(
            "blocker",
            "future non-root-required checker did not affirm future_non_root_required=true",
            checker_available=True,
            checker_path=str(checker_path),
            exit_code=proc.returncode,
            report=payload,
        )

    if payload.get("future_non_root_ready") is not True or payload.get("overall_classification") != "pass":
        return make_status(
            "blocker",
            "future non-root-required readiness evidence is missing or still has blockers; this helper is not a dry planning-only apply exception",
            checker_available=True,
            checker_path=str(checker_path),
            exit_code=proc.returncode,
            report=payload,
        )

    return make_status(
        "pass",
        "future non-root-required writable-state readiness evidence is present and passing",
        checker_available=True,
        checker_path=str(checker_path),
        exit_code=proc.returncode,
        report=payload,
    )


def collect_findings(named_statuses):
    blockers = []
    warnings = []
    for scope, status in named_statuses:
        entry = {
            "scope": scope,
            "summary": status.get("summary", ""),
        }
        classification = status.get("classification")
        if classification == "blocker":
            blockers.append(entry)
        elif classification == "warning":
            warnings.append(entry)
    return blockers, warnings


def bounded_compatibility_edges():
    return [
        {
            "name": "root_start_runtime_helper",
            "classification": "warning",
            "planned_unchanged": True,
            "summary": "root-start runtime helper remains a bounded Option B compatibility edge and is explicitly left unchanged by this helper",
        },
        {
            "name": "nomad_task_user_0_0",
            "classification": "warning",
            "planned_unchanged": True,
            "summary": 'Nomad task User: "0:0" remains a bounded Option B compatibility edge and is explicitly left unchanged by this helper',
        },
        {
            "name": "helper_private_spire_traversal",
            "classification": "warning",
            "planned_unchanged": True,
            "summary": "helper-private SPIRE traversal remains a bounded Option B compatibility edge and is explicitly left unchanged by this helper",
        },
        {
            "name": "broad_root_selector_scope",
            "classification": "warning",
            "planned_unchanged": True,
            "summary": "broad root selector scope remains a bounded Option B compatibility edge and is explicitly left unchanged by this helper",
        },
        {
            "name": "vault_workload_zone_handoff",
            "classification": "warning",
            "planned_unchanged": True,
            "summary": "Vault/workload-zone handoff semantics remain a bounded Option B compatibility edge and are explicitly left unchanged by this helper",
        },
    ]


def inspect_preflight():
    service_account_status = inspect_service_account()
    config_status = load_runtime_config()
    service_status = inspect_service_meta()
    healthcheck_env_status = load_healthcheck_env(HEALTHCHECK_ENV_PATH)
    config_tls_readability_status = inspect_config_tls_readability(config_status, service_account_status)
    target_service_user_startup_validation_status = inspect_target_service_user_startup_validation(config_status, service_account_status)
    helper_private_spire_runtime_input_status = inspect_helper_private_spire_runtime_input(config_status)
    writable_state_manageability_status = inspect_writable_state_manageability(config_status, service_account_status)
    active_run_status = inspect_active_runs(config_status, writable_state_manageability_status)
    future_readiness_status = inspect_future_checker(config_status)
    service_unit_plan_status = inspect_service_unit_plan(service_status)

    blockers, warnings = collect_findings(
        [
            ("service_account_status", service_account_status),
            ("config_status", config_status),
            ("service_status", service_status),
            ("healthcheck_env_status", healthcheck_env_status),
            ("config_tls_readability_status", config_tls_readability_status),
            ("target_service_user_startup_validation_status", target_service_user_startup_validation_status),
            ("helper_private_spire_runtime_input_status", helper_private_spire_runtime_input_status),
            ("writable_state_manageability_status", writable_state_manageability_status),
            ("active_run_status", active_run_status),
            ("future_non_root_required_readiness_status", future_readiness_status),
            ("service_unit_plan_status", service_unit_plan_status),
        ]
    )

    overall = "blocker" if blockers else "warning" if warnings else "pass"
    apply_ready = not blockers
    runtime = config_status.get("runtime") or {}

    summary = {
        "schema_version": SCHEMA_VERSION,
        "checked_at": utc_now(),
        "mode": {
            "name": "check_only",
            "non_mutating": True,
            "explicit_apply_required": True,
            "writes_summary_file": False,
        },
        "slice": {
            "name": "long_lived_es_service_user_migration",
            "scope": "long-lived es.service only",
            "target_identity": {
                "user": SERVICE_USER,
                "group": SERVICE_GROUP,
            },
            "not_full_es_runtime_deroot": True,
        },
        "proof": {
            "check_only_is_not_proof": True,
            "host_mutation_performed": False,
            "live_apply_requires_explicit_approval_and_rollback_readiness": True,
            "governed_proof_run": False,
        },
        "service": service_status,
        "service_account_status": service_account_status,
        "config_status": config_status,
        "healthcheck_env_status": healthcheck_env_status,
        "config_tls_readability_status": config_tls_readability_status,
        "target_service_user_startup_validation_status": target_service_user_startup_validation_status,
        "helper_private_spire_runtime_input_status": helper_private_spire_runtime_input_status,
        "writable_state_manageability_status": writable_state_manageability_status,
        "active_run_status": active_run_status,
        "future_non_root_required_readiness_status": future_readiness_status,
        "service_unit_plan_status": service_unit_plan_status,
        "runtime_paths": {
            "config_path": CONFIG_PATH,
            "service_binary_path": BINARY_PATH,
            "healthcheck_env_path": HEALTHCHECK_ENV_PATH,
            "staging_root_dir": ((runtime.get("execution") or {}).get("staging_root_dir") or ""),
            "results_root_dir": ((runtime.get("execution") or {}).get("results_root_dir") or ""),
            "runtime_support_binary": ((runtime.get("execution") or {}).get("runtime_support_binary") or ""),
            "spire_workload_api_socket_path": ((runtime.get("execution") or {}).get("spire_workload_api_socket_path") or ""),
        },
        "bounded_compatibility_edges": bounded_compatibility_edges(),
        "not_claimed": {
            "full_es_runtime_deroot": True,
            "nomad_task_user_model_changes": True,
            "root_start_runtime_helper_changes": True,
            "helper_private_spire_traversal_changes": True,
            "broad_root_selector_scope_changes": True,
            "vault_workload_zone_handoff_changes": True,
            "governed_proof": True,
        },
        "plan": {
            "apply_ready": apply_ready,
            "dry_planning_only": False,
            "check_only_required_before_apply": True,
            "planned_service_dropin_path": SERVICE_DROPIN_PATH,
            "planned_service_dropin_lines": DROPIN_TEXT.splitlines(),
            "mutation_scope": ["systemd_dropin_only"],
            "blocked_by": blockers,
            "warning_count": len(warnings),
        },
        "blockers": blockers,
        "warnings": warnings,
        "overall_classification": overall,
        "result": {
            "ok": overall != "blocker",
            "status": "apply_ready" if apply_ready else "blocked",
            "apply_ready": apply_ready,
            "non_mutating": True,
            "governed_proof_run": False,
        },
    }
    return summary


def build_backup_snapshot(preflight):
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    pathlib.Path(BACKUP_ROOT_DIR).mkdir(parents=True, exist_ok=True)
    backup_dir = pathlib.Path(tempfile.mkdtemp(prefix=f"es-service-user-migration-{timestamp}-", dir=BACKUP_ROOT_DIR))

    unit_backup_dir = backup_dir / "systemd"
    unit_backup_dir.mkdir(parents=True, exist_ok=True)
    config_backup_path = backup_dir / "es.json"
    shutil.copy2(CONFIG_PATH, config_backup_path)

    live_unit_path = pathlib.Path(SERVICE_UNIT_PATH)
    if live_unit_path.exists():
        shutil.copy2(live_unit_path, unit_backup_dir / live_unit_path.name)

    live_dropin_dir = pathlib.Path(SERVICE_DROPIN_DIR)
    dropin_backup_dir = backup_dir / "dropins"
    copied_dropins = []
    if live_dropin_dir.is_dir():
        dropin_backup_dir.mkdir(parents=True, exist_ok=True)
        for entry in sorted(live_dropin_dir.iterdir(), key=lambda item: item.name):
            if entry.is_file():
                shutil.copy2(entry, dropin_backup_dir / entry.name)
                copied_dropins.append(str(dropin_backup_dir / entry.name))

    runtime = (preflight.get("config_status") or {}).get("runtime") or {}
    paths_to_digest = [
        CONFIG_PATH,
        *((preflight.get("config_tls_readability_status") or {}).get("items") or []),
    ]
    file_inventory = []
    seen_paths = set()
    for item in paths_to_digest:
        if isinstance(item, str):
            path = item
            field = "config"
        else:
            path = item.get("path", "")
            field = item.get("field", "")
        if not path or path in seen_paths:
            continue
        seen_paths.add(path)
        stat_info = stat_path(path)
        record = {
            "field": field,
            "path": path,
            "exists": stat_info["exists"],
            "owner_uid": stat_info["uid"],
            "owner_gid": stat_info["gid"],
            "mode": stat_info["mode"],
            "file_type": stat_info["file_type"],
        }
        if stat_info["exists"] and stat_info["file_type"] == "regular file":
            record["sha256"] = sha256_file(path)
        file_inventory.append(record)

    snapshot = {
        "schema_version": SCHEMA_VERSION,
        "created_at": utc_now(),
        "backup_path": str(backup_dir),
        "config_backup_path": str(config_backup_path),
        "service_unit_backup_dir": str(unit_backup_dir),
        "dropin_backup_dir": str(dropin_backup_dir),
        "copied_dropins": copied_dropins,
        "pre_mutation_service": preflight.get("service"),
        "pre_mutation_config_digest": sha256_file(CONFIG_PATH),
        "config_tls_inventory": file_inventory,
        "writable_state_roots": (preflight.get("writable_state_manageability_status") or {}).get("items", []),
        "active_run_evidence": preflight.get("active_run_status"),
        "future_non_root_required_evidence": preflight.get("future_non_root_required_readiness_status"),
        "rollback_notes": [
            f"Restore {CONFIG_PATH} from {config_backup_path} if ES config drift is introduced outside this helper.",
            f"Restore or remove {SERVICE_DROPIN_PATH} from {dropin_backup_dir if copied_dropins else 'the live drop-in path'} before restarting es.service.",
            "Do not change Nomad task User: \"0:0\", the root-start runtime helper, helper-private SPIRE traversal, broad root selector scope, or Vault/workload-zone handoff semantics during rollback.",
        ],
    }
    snapshot_path = backup_dir / "pre-apply-snapshot.json"
    snapshot_path.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    backup_path_file = os.environ.get("REMOTE_ALPHA_TEST_BACKUP_PATH_FILE", "").strip()
    if backup_path_file:
        pathlib.Path(backup_path_file).write_text(str(backup_dir), encoding="utf-8")
    backup_sentinel = os.environ.get("REMOTE_ALPHA_TEST_BACKUP_SENTINEL_PATH", "").strip()
    if backup_sentinel:
        pathlib.Path(backup_sentinel).write_text(str(snapshot_path), encoding="utf-8")

    return {
        "path": str(backup_dir),
        "snapshot_path": str(snapshot_path),
        "config_backup_path": str(config_backup_path),
        "service_unit_backup_dir": str(unit_backup_dir),
        "dropin_backup_dir": str(dropin_backup_dir),
        "rollback_notes": snapshot["rollback_notes"],
        "snapshot": snapshot,
    }


def write_dropin():
    tmpdir = pathlib.Path(tempfile.mkdtemp(prefix="es-service-user-dropin-"))
    try:
        temp_path = tmpdir / "10-account.conf"
        temp_path.write_text(DROPIN_TEXT, encoding="utf-8")
        run_command(["install", "-d", "-m", "0755", SERVICE_DROPIN_DIR]).check_returncode()
        run_command(["install", "-m", "0644", str(temp_path), SERVICE_DROPIN_PATH]).check_returncode()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def post_apply_validation():
    service_status = inspect_service_meta()
    healthcheck_env_status = load_healthcheck_env(HEALTHCHECK_ENV_PATH)
    runtime_status = load_runtime_config()
    health_result = make_status("not_observed", "health validation was not attempted")
    contract_result = make_status("not_observed", "contract validation was not attempted")
    blockers = []

    if service_status.get("effective_user") != SERVICE_USER:
        blockers.append(f"es.service effective user remained {service_status.get('effective_user')!r}")
    if service_status.get("effective_group") != SERVICE_GROUP:
        blockers.append(f"es.service effective group remained {service_status.get('effective_group')!r}")
    if service_status.get("active_state") != "active" or service_status.get("sub_state") != "running":
        blockers.append(
            f"es.service did not report active/running after restart ({service_status.get('active_state')}/{service_status.get('sub_state')})"
        )

    if healthcheck_env_status["classification"] == "pass" and runtime_status["classification"] == "pass":
        env_values = healthcheck_env_status["values"]
        runtime = runtime_status["runtime"]
        health_proc = run_command(
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
                runtime["health_url"],
            ]
        )
        if health_proc.returncode == 0:
            try:
                payload = json.loads(health_proc.stdout)
            except Exception as exc:  # noqa: BLE001
                health_result = make_status("blocker", f"/health response was not valid JSON: {exc}", url=runtime["health_url"])
            else:
                if payload.get("ready") is True and payload.get("status") == "healthy":
                    health_result = make_status("pass", "/health passed after service restart", url=runtime["health_url"])
                else:
                    health_result = make_status("blocker", "/health did not report healthy/ready after service restart", url=runtime["health_url"], payload=payload)
        else:
            health_result = make_status(
                "blocker",
                "/health request failed after service restart",
                url=runtime["health_url"],
                stderr=health_proc.stderr.strip() or health_proc.stdout.strip(),
            )

        contract_proc = run_command(
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
                runtime["contract_url"],
            ]
        )
        if contract_proc.returncode == 0:
            try:
                payload = json.loads(contract_proc.stdout)
            except Exception as exc:  # noqa: BLE001
                contract_result = make_status("blocker", f"/v1/executions:contract response was not valid JSON: {exc}", url=runtime["contract_url"])
            else:
                governed = payload.get("governed_execution") or {}
                if (
                    payload.get("schema_version") == "execution-substrate.producer-contract/v1"
                    and payload.get("service") == "execution"
                    and governed.get("contract") == "governed-execution-producer/v1"
                    and governed.get("enabled") is True
                ):
                    contract_result = make_status("pass", "/v1/executions:contract passed after service restart", url=runtime["contract_url"])
                else:
                    contract_result = make_status("blocker", "/v1/executions:contract did not match the expected ES producer contract", url=runtime["contract_url"], payload=payload)
        else:
            contract_result = make_status(
                "blocker",
                "/v1/executions:contract request failed after service restart",
                url=runtime["contract_url"],
                stderr=contract_proc.stderr.strip() or contract_proc.stdout.strip(),
            )
    else:
        blockers.append("post-apply validation prerequisites were unavailable")

    if health_result["classification"] == "blocker":
        blockers.append(health_result["summary"])
    if contract_result["classification"] == "blocker":
        blockers.append(contract_result["summary"])

    return {
        "service_status": service_status,
        "health_status": health_result,
        "contract_status": contract_result,
        "classification": "blocker" if blockers else "pass",
        "summary": "post-apply validation passed" if not blockers else "; ".join(blockers),
    }


def write_summary(path, payload):
    summary_path = pathlib.Path(path)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def check_only_main():
    summary = inspect_preflight()
    sys.stdout.write(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    sys.exit(0 if summary["overall_classification"] != "blocker" else 1)


def apply_main():
    preflight = inspect_preflight()
    backup = {
        "path": "",
        "snapshot_path": "",
        "config_backup_path": "",
        "service_unit_backup_dir": "",
        "dropin_backup_dir": "",
        "rollback_notes": [],
    }
    changes = {
        "changed_paths": [],
        "dropin": {
            "path": SERVICE_DROPIN_PATH,
            "before_exists": pathlib.Path(SERVICE_DROPIN_PATH).exists(),
            "before_sha256": sha256_file(SERVICE_DROPIN_PATH) if pathlib.Path(SERVICE_DROPIN_PATH).is_file() else "",
            "after_sha256": "",
            "applied_lines": DROPIN_TEXT.splitlines(),
        },
    }
    post_validation = {
        "classification": "not_observed",
        "summary": "mutation was not attempted",
    }
    result_ok = False
    result_status = "blocked_before_mutation"
    overall = "blocker"
    blockers = list(preflight.get("blockers", []))
    warnings = list(preflight.get("warnings", []))
    mutation_error = ""

    if preflight["plan"]["apply_ready"]:
        try:
            backup = build_backup_snapshot(preflight)
            write_dropin()
            changes["changed_paths"].append(SERVICE_DROPIN_PATH)
            changes["dropin"]["after_sha256"] = sha256_file(SERVICE_DROPIN_PATH)
            run_command(["systemctl", "daemon-reload"]).check_returncode()
            run_command(["systemctl", "restart", SERVICE_NAME + ".service"]).check_returncode()
            post_validation = post_apply_validation()
            if post_validation["classification"] == "pass":
                result_ok = True
                result_status = "applied"
                overall = "pass" if not warnings else "warning"
            else:
                result_status = "post_apply_validation_failed"
                overall = "blocker"
                blockers.append({"scope": "post_apply_validation", "summary": post_validation["summary"]})
        except Exception as exc:  # noqa: BLE001
            mutation_error = str(exc)
            post_validation = {
                "classification": "blocker",
                "summary": f"apply failed before post-apply validation completed: {exc}",
            }
            result_status = "mutation_failed"
            overall = "blocker"
            blockers.append({"scope": "mutation", "summary": mutation_error})

    payload = {
        "schema_version": SCHEMA_VERSION,
        "checked_at": utc_now(),
        "mode": {
            "name": "apply",
            "non_mutating": False,
            "explicit_apply_required": True,
            "writes_summary_file": True,
        },
        "slice": {
            "name": "long_lived_es_service_user_migration",
            "scope": "long-lived es.service only",
            "target_identity": {
                "user": SERVICE_USER,
                "group": SERVICE_GROUP,
            },
            "not_full_es_runtime_deroot": True,
        },
        "proof": {
            "check_only_rerun_before_mutation": True,
            "host_mutation_performed": result_status != "blocked_before_mutation",
            "live_apply_requires_explicit_approval_and_rollback_readiness": True,
            "governed_proof_run": False,
        },
        "preflight": preflight,
        "backup": backup,
        "changes": changes,
        "bounded_compatibility_edges": bounded_compatibility_edges(),
        "not_claimed": preflight["not_claimed"],
        "post_apply_validation": post_validation,
        "mutation_error": mutation_error,
        "blockers": blockers,
        "warnings": warnings,
        "overall_classification": overall,
        "result": {
            "ok": result_ok,
            "status": result_status,
            "apply_ready": preflight["plan"]["apply_ready"],
            "non_mutating": False,
            "governed_proof_run": False,
            "summary_path": SUMMARY_PATH,
        },
    }
    write_summary(SUMMARY_PATH, payload)
    try:
        os.chmod(SUMMARY_PATH, 0o644)
    except OSError:
        pass
    sys.stdout.write(SUMMARY_PATH + "\n")
    sys.exit(0 if result_ok else 1)


if MODE == "check_only":
    check_only_main()
elif MODE == "apply":
    apply_main()
else:
    raise SystemExit(f"unsupported mode: {MODE}")
PY
}

remote_alpha_migrate_es_service_user_host_main() {
  remote_alpha_migrate_es_service_user_require_pinned_slice_inputs || return 1
  remote_alpha_migrate_es_service_user_defaults
  remote_alpha_migrate_es_service_user_parse_host_args "$@" || return $?
  remote_alpha_migrate_es_service_user_require_root || return 1

  remote_alpha_migrate_es_service_user_require_command python3 || return 1
  remote_alpha_migrate_es_service_user_require_command curl || return 1
  remote_alpha_migrate_es_service_user_require_command systemctl || return 1
  remote_alpha_migrate_es_service_user_require_command getent || return 1
  remote_alpha_migrate_es_service_user_require_command id || return 1
  remote_alpha_migrate_es_service_user_require_command stat || return 1
  if [[ "${REMOTE_ALPHA_OPERATION_MODE}" == "apply" ]]; then
    remote_alpha_migrate_es_service_user_require_command install || return 1
  fi

  remote_alpha_migrate_es_service_user_python
}

remote_alpha_migrate_es_service_user_stage_defaults() {
  local run_id_default

  run_id_default="$(date -u +%Y%m%dT%H%M%SZ)-$$"
  REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_MODE="check_only"
  REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_RUN_ID="${run_id_default}"
  REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_OUTPUT_DIR=""
  REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_CHECK_OUTPUT_PATH=""
  REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_APPLY_SUMMARY_OUTPUT_PATH=""
  REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_APPLY_STDOUT_OUTPUT_PATH=""
  REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_PROVENANCE_OUTPUT_PATH=""
  REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_SUMMARY_PATH="${remote_alpha_migrate_es_service_user_remote_summary_path_default}"
  REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGE_ROOT="${remote_alpha_migrate_es_service_user_remote_stage_root_default}"
  REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_SSH_BIN="${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_SSH_BIN:-ssh}"
  REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_SCP_BIN="${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_SCP_BIN:-scp}"
  REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_SSH_TTY_FLAG="${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_SSH_TTY_FLAG:-}"
  REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_SUDO_MODE="${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_SUDO_MODE:-noninteractive}"
  REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_SSH_TARGET=""
}

remote_alpha_migrate_es_service_user_stage_validate_sudo_mode() {
  case "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_SUDO_MODE}" in
    noninteractive|interactive)
      ;;
    *)
      echo "unsupported sudo mode: ${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_SUDO_MODE}" >&2
      return 1
      ;;
  esac
}

remote_alpha_migrate_es_service_user_stage_parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --ssh-target)
        REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_SSH_TARGET="$2"
        shift 2
        ;;
      --interactive-sudo)
        REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_SUDO_MODE="interactive"
        shift
        ;;
      --check-only|--dry-run)
        REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_MODE="check_only"
        shift
        ;;
      --apply)
        REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_MODE="apply"
        shift
        ;;
      --run-id)
        REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_RUN_ID="$2"
        shift 2
        ;;
      --output-dir)
        REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_OUTPUT_DIR="$2"
        shift 2
        ;;
      --check-output)
        REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_CHECK_OUTPUT_PATH="$2"
        shift 2
        ;;
      --apply-summary-output)
        REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_APPLY_SUMMARY_OUTPUT_PATH="$2"
        shift 2
        ;;
      --apply-stdout-output)
        REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_APPLY_STDOUT_OUTPUT_PATH="$2"
        shift 2
        ;;
      --helper-staging-record-output|--provenance-output)
        REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_PROVENANCE_OUTPUT_PATH="$2"
        shift 2
        ;;
      --remote-summary-path)
        REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_SUMMARY_PATH="$2"
        shift 2
        ;;
      --keep-staging-on-failure)
        REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_KEEP_STAGING_ON_FAILURE="true"
        shift
        ;;
      --help|-h)
        remote_alpha_migrate_es_service_user_usage
        return 0
        ;;
      *)
        echo "unknown argument: $1" >&2
        remote_alpha_migrate_es_service_user_usage >&2
        return 2
        ;;
    esac
  done

  remote_alpha_migrate_es_service_user_stage_validate_sudo_mode || return 1

  if [[ -z "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_SSH_TARGET}" ]]; then
    echo "--ssh-target is required" >&2
    return 2
  fi
}

remote_alpha_migrate_es_service_user_stage_finalize_paths() {
  if [[ -z "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_OUTPUT_DIR}" ]]; then
    REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_OUTPUT_DIR="${remote_alpha_migrate_es_service_user_default_output_dir}"
  fi
  if [[ -z "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_CHECK_OUTPUT_PATH}" ]]; then
    REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_CHECK_OUTPUT_PATH="${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_OUTPUT_DIR}/es-service-user-migration-check-only.json"
  fi
  if [[ -z "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_APPLY_SUMMARY_OUTPUT_PATH}" ]]; then
    REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_APPLY_SUMMARY_OUTPUT_PATH="${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_OUTPUT_DIR}/es-service-user-migration-apply-summary.json"
  fi
  if [[ -z "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_APPLY_STDOUT_OUTPUT_PATH}" ]]; then
    REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_APPLY_STDOUT_OUTPUT_PATH="${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_OUTPUT_DIR}/es-service-user-migration-apply-stdout.txt"
  fi
  if [[ -z "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_PROVENANCE_OUTPUT_PATH}" ]]; then
    REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_PROVENANCE_OUTPUT_PATH="${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_OUTPUT_DIR}/es-service-user-migration-helper-staging-record.json"
  fi
}

remote_alpha_migrate_es_service_user_stage_ensure_parent_dir() {
  local path=$1
  mkdir -p "$(dirname "${path}")"
}

remote_alpha_migrate_es_service_user_stage_helper_paths() {
  printf '%s\n' \
    "${REPO_ROOT}/scripts/remote_alpha_migrate_es_service_user.sh" \
    "${REPO_ROOT}/scripts/internal/remote_alpha_migrate_es_service_user.sh" \
    "${REPO_ROOT}/scripts/remote_alpha_check_es_writable_state_readiness.sh" \
    "${REPO_ROOT}/scripts/internal/remote_alpha_check_es_writable_state_readiness.sh"
}

remote_alpha_migrate_es_service_user_stage_git_commit() {
  if command -v git >/dev/null 2>&1; then
    git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || true
    return 0
  fi
  printf '\n'
}

remote_alpha_migrate_es_service_user_stage_local_file_meta() {
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
    files.append(
        {
            "path": str(path),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
    )

output_path.write_text(json.dumps(files, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

remote_alpha_migrate_es_service_user_stage_make_local_upload_tree() {
  local upload_dir=$1

  mkdir -p "${upload_dir}/scripts/internal"
  cp "${REPO_ROOT}/scripts/remote_alpha_migrate_es_service_user.sh" "${upload_dir}/scripts/remote_alpha_migrate_es_service_user.sh"
  cp "${REPO_ROOT}/scripts/internal/remote_alpha_migrate_es_service_user.sh" "${upload_dir}/scripts/internal/remote_alpha_migrate_es_service_user.sh"
  cp "${REPO_ROOT}/scripts/remote_alpha_check_es_writable_state_readiness.sh" "${upload_dir}/scripts/remote_alpha_check_es_writable_state_readiness.sh"
  cp "${REPO_ROOT}/scripts/internal/remote_alpha_check_es_writable_state_readiness.sh" "${upload_dir}/scripts/internal/remote_alpha_check_es_writable_state_readiness.sh"
}

remote_alpha_migrate_es_service_user_stage_required_upload_paths() {
  printf '%s\n' \
    "scripts/remote_alpha_migrate_es_service_user.sh" \
    "scripts/internal/remote_alpha_migrate_es_service_user.sh" \
    "scripts/remote_alpha_check_es_writable_state_readiness.sh" \
    "scripts/internal/remote_alpha_check_es_writable_state_readiness.sh"
}

remote_alpha_migrate_es_service_user_stage_validate_local_upload_tree() {
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
  done < <(remote_alpha_migrate_es_service_user_stage_required_upload_paths)

  if (( ${#missing[@]} == 0 )); then
    return 0
  fi

  local joined_missing
  joined_missing="$(IFS=', '; printf '%s' "${missing[*]}")"
  printf 'local staged ES service-user migration upload tree is missing required files: %s\n' "${joined_missing}" >&2
  return 1
}

remote_alpha_migrate_es_service_user_stage_ssh() {
  "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_SSH_BIN}" "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_SSH_TARGET}" "$@"
}

remote_alpha_migrate_es_service_user_stage_ssh_with_tty() {
  "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_SSH_BIN}" -tt "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_SSH_TARGET}" "$@"
}

remote_alpha_migrate_es_service_user_stage_build_remote_bash_command() {
  local script=$1
  shift

  python3 - "${script}" "$@" <<'PY'
import shlex
import sys

parts = ["/bin/bash", "-c", sys.argv[1], "remote-alpha-stage", *sys.argv[2:]]
print(" ".join(shlex.quote(part) for part in parts))
PY
}

remote_alpha_migrate_es_service_user_stage_run_remote_batch() {
  local script=$1
  shift

  remote_alpha_migrate_es_service_user_stage_ssh /bin/bash -s -- "$@" <<<"${script}"
}

remote_alpha_migrate_es_service_user_stage_run_remote_batch_with_tty() {
  local script=$1
  shift
  local remote_command

  remote_command="$(remote_alpha_migrate_es_service_user_stage_build_remote_bash_command "${script}" "$@")"

  remote_alpha_migrate_es_service_user_stage_ssh_with_tty "${remote_command}"
}

remote_alpha_migrate_es_service_user_stage_scp() {
  "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_SCP_BIN}" "$@"
}

remote_alpha_migrate_es_service_user_stage_note_sudo_unavailable() {
  local message=$1
  REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_SUDO_UNAVAILABLE="true"
  REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_FAILURE_CLASSIFICATION="sudo_unavailable"
  if [[ -z "${REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_BLOCKER_DETAIL}" ]]; then
    REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_BLOCKER_DETAIL="${message}"
  fi
}

remote_alpha_migrate_es_service_user_stage_note_wrapper_tooling_error() {
  local message=$1
  REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_WRAPPER_TOOLING_ERROR="true"
  if [[ "${REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_FAILURE_CLASSIFICATION}" != "sudo_unavailable" ]]; then
    REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_FAILURE_CLASSIFICATION="wrapper_tooling_error"
  fi
  if [[ -z "${REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_BLOCKER_DETAIL}" ]]; then
    REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_BLOCKER_DETAIL="${message}"
  fi
}

remote_alpha_migrate_es_service_user_stage_noninteractive_sudo_preflight() {
  remote_alpha_migrate_es_service_user_stage_run_remote_batch \
    'set -euo pipefail
sudo -n true >/dev/null 2>&1'
}

remote_alpha_migrate_es_service_user_stage_remote_prepare_upload_root() {
  remote_alpha_migrate_es_service_user_stage_run_remote_batch \
    'set -euo pipefail
upload_root=$1
rm -rf -- "${upload_root}"
mkdir -p -- "${upload_root}/scripts/internal"' \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_UPLOAD_ROOT}"
}

remote_alpha_migrate_es_service_user_stage_remote_prepare_artifact_root() {
  remote_alpha_migrate_es_service_user_stage_run_remote_batch \
    'set -euo pipefail
artifact_root=$1
rm -rf -- "${artifact_root}"
mkdir -p -- "${artifact_root}"' \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_ARTIFACT_ROOT}"
}

remote_alpha_migrate_es_service_user_stage_remove_remote_artifact_root() {
  if [[ -z "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_ARTIFACT_ROOT}" ]]; then
    return 0
  fi
  remote_alpha_migrate_es_service_user_stage_run_remote_batch \
    'set -euo pipefail
artifact_root=$1
if [[ -n "${artifact_root}" ]]; then
  rm -rf -- "${artifact_root}" || true
fi' \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_ARTIFACT_ROOT}"
}

remote_alpha_migrate_es_service_user_stage_upload_remote_tree() {
  local upload_dir=$1
  local relative_path

  while IFS= read -r relative_path; do
    if [[ -z "${relative_path}" ]]; then
      continue
    fi
    remote_alpha_migrate_es_service_user_stage_scp \
      "${upload_dir}/${relative_path}" \
      "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_SSH_TARGET}:${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_UPLOAD_ROOT}/${relative_path}" || return 1
  done < <(remote_alpha_migrate_es_service_user_stage_required_upload_paths)
}

remote_alpha_migrate_es_service_user_stage_remove_remote_user_owned_roots() {
  if [[ -z "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_UPLOAD_ROOT}" && -z "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_ARTIFACT_ROOT}" ]]; then
    return 0
  fi
  remote_alpha_migrate_es_service_user_stage_run_remote_batch \
    'set -euo pipefail
upload_root=$1
artifact_root=$2
if [[ -n "${upload_root}" ]]; then
  rm -rf -- "${upload_root}" || true
fi
if [[ -n "${artifact_root}" ]]; then
  rm -rf -- "${artifact_root}" || true
fi' \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_UPLOAD_ROOT}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_ARTIFACT_ROOT}"
}

remote_alpha_migrate_es_service_user_stage_run_interactive_check_sequence() {
  local status=0
  local script

  script="$(cat <<EOF
set -euo pipefail
upload_root=\$1
staging_root=\$2
staged_wrapper=\$3
staged_internal=\$4
staged_checker_wrapper=\$5
staged_checker_internal=\$6
stage_stat_path=\$7
check_output=\$8

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
sudo install -m 0755 -o root -g root "\${upload_root}/scripts/remote_alpha_migrate_es_service_user.sh" "\${staging_root}/scripts/remote_alpha_migrate_es_service_user.sh"
sudo install -m 0644 -o root -g root "\${upload_root}/scripts/internal/remote_alpha_migrate_es_service_user.sh" "\${staging_root}/scripts/internal/remote_alpha_migrate_es_service_user.sh"
sudo install -m 0755 -o root -g root "\${upload_root}/scripts/remote_alpha_check_es_writable_state_readiness.sh" "\${staging_root}/scripts/remote_alpha_check_es_writable_state_readiness.sh"
sudo install -m 0644 -o root -g root "\${upload_root}/scripts/internal/remote_alpha_check_es_writable_state_readiness.sh" "\${staging_root}/scripts/internal/remote_alpha_check_es_writable_state_readiness.sh"
rm -rf -- "\${upload_root}"

for path in \
  "\${staging_root}" \
  "\${staging_root}/scripts" \
  "\${staging_root}/scripts/internal" \
  "\${staged_wrapper}" \
  "\${staged_internal}" \
  "\${staged_checker_wrapper}" \
  "\${staged_checker_internal}"
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
check_status=\$?
set -e

exit "\${check_status}"
EOF
)"

  set +e
  remote_alpha_migrate_es_service_user_stage_run_remote_batch_with_tty "${script}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_UPLOAD_ROOT}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGING_ROOT}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGED_WRAPPER_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGED_INTERNAL_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGED_CHECKER_WRAPPER_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGED_CHECKER_INTERNAL_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGE_STAT_ARTIFACT_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_CHECK_OUTPUT_ARTIFACT_PATH}"
  status=$?

  return "${status}"
}

remote_alpha_migrate_es_service_user_stage_run_interactive_apply_sequence() {
  local status=0
  local script

  script="$(cat <<EOF
set -euo pipefail
upload_root=\$1
staging_root=\$2
staged_wrapper=\$3
summary_path=\$4
apply_output=\$5

mkdir -p -- "\$(dirname "\${apply_output}")"

sudo -v
cleanup() {
  sudo rm -rf -- "\${staging_root}" || true
}
trap cleanup EXIT
sudo rm -rf -- "\${staging_root}"
sudo install -d -m 0755 -o root -g root "\${staging_root}"
sudo install -d -m 0755 -o root -g root "\${staging_root}/scripts"
sudo install -d -m 0755 -o root -g root "\${staging_root}/scripts/internal"
sudo install -m 0755 -o root -g root "\${upload_root}/scripts/remote_alpha_migrate_es_service_user.sh" "\${staging_root}/scripts/remote_alpha_migrate_es_service_user.sh"
sudo install -m 0644 -o root -g root "\${upload_root}/scripts/internal/remote_alpha_migrate_es_service_user.sh" "\${staging_root}/scripts/internal/remote_alpha_migrate_es_service_user.sh"
sudo install -m 0755 -o root -g root "\${upload_root}/scripts/remote_alpha_check_es_writable_state_readiness.sh" "\${staging_root}/scripts/remote_alpha_check_es_writable_state_readiness.sh"
sudo install -m 0644 -o root -g root "\${upload_root}/scripts/internal/remote_alpha_check_es_writable_state_readiness.sh" "\${staging_root}/scripts/internal/remote_alpha_check_es_writable_state_readiness.sh"
rm -rf -- "\${upload_root}"

set +e
sudo "\${staged_wrapper}" --apply --summary-path "\${summary_path}" >"\${apply_output}"
apply_status=\$?
set -e

exit "\${apply_status}"
EOF
)"

  set +e
  remote_alpha_migrate_es_service_user_stage_run_remote_batch_with_tty "${script}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_UPLOAD_ROOT}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGING_ROOT}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGED_WRAPPER_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_SUMMARY_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_APPLY_STDOUT_ARTIFACT_PATH}"
  status=$?

  return "${status}"
}

remote_alpha_migrate_es_service_user_stage_remote_install_staged_tree() {
  local sudo_cmd script
  if [[ "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_SUDO_MODE}" == "interactive" ]]; then
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
${sudo_cmd} install -m 0755 -o root -g root "\${upload_root}/scripts/remote_alpha_migrate_es_service_user.sh" "\${staging_root}/scripts/remote_alpha_migrate_es_service_user.sh"
${sudo_cmd} install -m 0644 -o root -g root "\${upload_root}/scripts/internal/remote_alpha_migrate_es_service_user.sh" "\${staging_root}/scripts/internal/remote_alpha_migrate_es_service_user.sh"
${sudo_cmd} install -m 0755 -o root -g root "\${upload_root}/scripts/remote_alpha_check_es_writable_state_readiness.sh" "\${staging_root}/scripts/remote_alpha_check_es_writable_state_readiness.sh"
${sudo_cmd} install -m 0644 -o root -g root "\${upload_root}/scripts/internal/remote_alpha_check_es_writable_state_readiness.sh" "\${staging_root}/scripts/internal/remote_alpha_check_es_writable_state_readiness.sh"
rm -rf -- "\${upload_root}"
EOF
)"

  if [[ "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_SUDO_MODE}" == "interactive" ]]; then
    remote_alpha_migrate_es_service_user_stage_run_remote_batch_with_tty "${script}" \
      "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_UPLOAD_ROOT}" \
      "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGING_ROOT}"
    return 0
  fi

  remote_alpha_migrate_es_service_user_stage_run_remote_batch "${script}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_UPLOAD_ROOT}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGING_ROOT}"
}

remote_alpha_migrate_es_service_user_stage_remote_stage_stat() {
  local output_path=$1
  local sudo_cmd script
  if [[ "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_SUDO_MODE}" == "interactive" ]]; then
    sudo_cmd="sudo"
    script="$(cat <<EOF
set -euo pipefail
staging_root=\$1
staged_wrapper=\$2
staged_internal=\$3
staged_checker_wrapper=\$4
staged_checker_internal=\$5
stage_stat_path=\$6

${sudo_cmd} stat -c '%U\t%G\t%a\t%n' \
  "\${staging_root}" \
  "\${staging_root}/scripts" \
  "\${staging_root}/scripts/internal" \
  "\${staged_wrapper}" \
  "\${staged_internal}" \
  "\${staged_checker_wrapper}" \
  "\${staged_checker_internal}" >"\${stage_stat_path}"
EOF
)"
  else
    sudo_cmd="sudo -n"
    script="$(cat <<EOF
set -euo pipefail
staging_root=\$1
staged_wrapper=\$2
staged_internal=\$3
staged_checker_wrapper=\$4
staged_checker_internal=\$5

${sudo_cmd} stat -c '%U\t%G\t%a\t%n' \
  "\${staging_root}" \
  "\${staging_root}/scripts" \
  "\${staging_root}/scripts/internal" \
  "\${staged_wrapper}" \
  "\${staged_internal}" \
  "\${staged_checker_wrapper}" \
  "\${staged_checker_internal}"
EOF
)"
  fi

  if [[ "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_SUDO_MODE}" == "interactive" ]]; then
    remote_alpha_migrate_es_service_user_stage_run_remote_batch_with_tty "${script}" \
      "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGING_ROOT}" \
      "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGED_WRAPPER_PATH}" \
      "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGED_INTERNAL_PATH}" \
      "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGED_CHECKER_WRAPPER_PATH}" \
      "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGED_CHECKER_INTERNAL_PATH}" \
      "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGE_STAT_ARTIFACT_PATH}"
    remote_alpha_migrate_es_service_user_stage_fetch_remote_file \
      "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGE_STAT_ARTIFACT_PATH}" \
      "${output_path}"
    return 0
  fi

  remote_alpha_migrate_es_service_user_stage_run_remote_batch "${script}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGING_ROOT}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGED_WRAPPER_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGED_INTERNAL_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGED_CHECKER_WRAPPER_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGED_CHECKER_INTERNAL_PATH}" >"${output_path}"
}

remote_alpha_migrate_es_service_user_stage_validate_stage_stat() {
  local stat_path=$1
  local output_path=$2

  python3 - "$stat_path" "$output_path" "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGING_ROOT}" <<'PY'
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
    item = {
        "path": path,
        "owner": owner,
        "group": group,
        "mode": mode_text,
        "root_owned": owner == "root",
        "not_group_or_other_writable": (mode_value & 0o022) == 0,
        "inside_staging_root": path == staging_root or path.startswith(staging_root + "/"),
    }
    items.append(item)
    if not item["root_owned"]:
        errors.append(f"path is not root-owned: {path}")
    if not item["not_group_or_other_writable"]:
        errors.append(f"path is group-writable or world-writable: {path}")
    if not item["inside_staging_root"]:
        errors.append(f"path is outside the staged helper root: {path}")

if len(items) != 7:
    errors.append(f"expected 7 staged helper paths, found {len(items)}")

payload = {
    "staged_root": staging_root,
    "items": items,
    "validation_errors": errors,
    "root_owned_before_execution": not errors and len(items) == 7,
}
output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
if errors:
    raise SystemExit(1)
PY
}

remote_alpha_migrate_es_service_user_stage_run_remote_check_only() {
  local output_path=$1
  local status=0
  local sudo_cmd script

  if [[ "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_SUDO_MODE}" == "interactive" ]]; then
    echo "interactive check-only collection must use remote artifact fetch helpers" >&2
    return 2
  fi
  sudo_cmd="sudo -n"
  script="$(cat <<EOF
set -euo pipefail
staged_wrapper=\$1
${sudo_cmd} "\${staged_wrapper}" --check-only
EOF
)"

  set +e
  remote_alpha_migrate_es_service_user_stage_run_remote_batch "${script}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGED_WRAPPER_PATH}" >"${output_path}"
  status=$?
  set -e

  return "${status}"
}

remote_alpha_migrate_es_service_user_stage_validate_check_report() {
  local report_path=$1
  local meta_path=$2

  python3 - "$report_path" "$meta_path" "${remote_alpha_migrate_es_service_user_summary_schema_version}" <<'PY'
import json
import pathlib
import sys

report_path = pathlib.Path(sys.argv[1])
meta_path = pathlib.Path(sys.argv[2])
expected_schema = sys.argv[3]

summary = {
    "valid_json": False,
    "accepted_evidence": False,
}
try:
    payload = json.loads(report_path.read_text(encoding="utf-8"))
except Exception as exc:  # noqa: BLE001
    summary["error"] = f"malformed helper JSON: {exc}"
    meta_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    raise SystemExit(1)

errors = []
summary.update(
    {
        "valid_json": True,
        "schema_version": payload.get("schema_version"),
        "mode_name": ((payload.get("mode") or {}).get("name")),
        "mode_non_mutating": ((payload.get("mode") or {}).get("non_mutating")),
        "apply_ready": ((payload.get("plan") or {}).get("apply_ready")),
        "overall_classification": payload.get("overall_classification"),
    }
)
if payload.get("schema_version") != expected_schema:
    errors.append(f"unexpected schema_version: {payload.get('schema_version')!r}")
mode = payload.get("mode") or {}
if mode.get("name") != "check_only":
    errors.append("helper check-only report must set mode.name=check_only")
if mode.get("non_mutating") is not True:
    errors.append("helper check-only report must set mode.non_mutating=true")
plan = payload.get("plan") or {}
if not isinstance(plan.get("apply_ready"), bool):
    errors.append("helper check-only report must include boolean plan.apply_ready")
if not isinstance(payload.get("blockers"), list):
    errors.append("helper check-only report must include blockers array")
if not isinstance(payload.get("warnings"), list):
    errors.append("helper check-only report must include warnings array")
if not isinstance(payload.get("bounded_compatibility_edges"), list):
    errors.append("helper check-only report must include bounded_compatibility_edges array")
not_claimed = payload.get("not_claimed") or {}
if not_claimed.get("full_es_runtime_deroot") is not True:
    errors.append("helper check-only report must state not_claimed.full_es_runtime_deroot=true")
proof = payload.get("proof") or {}
if proof.get("check_only_is_not_proof") is not True:
    errors.append("helper check-only report must state check_only_is_not_proof=true")
if proof.get("host_mutation_performed") is not False:
    errors.append("helper check-only report must state host_mutation_performed=false")

summary["errors"] = errors
summary["accepted_evidence"] = not errors
meta_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
if errors:
    raise SystemExit(1)
PY
}

remote_alpha_migrate_es_service_user_stage_run_remote_apply() {
  local output_path=$1
  local status=0
  local sudo_cmd script

  if [[ "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_SUDO_MODE}" == "interactive" ]]; then
    echo "interactive apply collection must use remote artifact fetch helpers" >&2
    return 2
  fi
  sudo_cmd="sudo -n"
  script="$(cat <<EOF
set -euo pipefail
staged_wrapper=\$1
summary_path=\$2
${sudo_cmd} "\${staged_wrapper}" --apply --summary-path "\${summary_path}"
EOF
)"

  set +e
  remote_alpha_migrate_es_service_user_stage_run_remote_batch "${script}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGED_WRAPPER_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_SUMMARY_PATH}" >"${output_path}"
  status=$?
  set -e

  return "${status}"
}

remote_alpha_migrate_es_service_user_stage_fetch_remote_file() {
  local remote_path=$1
  local local_path=$2
  remote_alpha_migrate_es_service_user_stage_scp "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_SSH_TARGET}:${remote_path}" "${local_path}"
}

remote_alpha_migrate_es_service_user_stage_remote_cleanup() {
  local cleanup_mode=${1:-deferred}

  if [[ "${REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_REMOTE_CLEANUP_COMPLETED}" == "true" ]]; then
    return 0
  fi
  if [[ "${REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_REMOTE_UPLOAD_PREPARED}" != "true" && "${REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_STAGING_OCCURRED}" != "true" && -z "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_ARTIFACT_ROOT}" ]]; then
    return 0
  fi

  local sudo_cmd script
  if [[ "${cleanup_mode}" == "visible_interactive" ]]; then
    sudo_cmd="sudo"
  else
    sudo_cmd="sudo -n"
  fi
  script="$(cat <<EOF
set -euo pipefail
staging_root=\$1
upload_root=\$2
artifact_root=\$3
${sudo_cmd} rm -rf -- "\${staging_root}" || true
rm -rf -- "\${upload_root}" || true
rm -rf -- "\${artifact_root}" || true
EOF
)"

  if [[ "${cleanup_mode}" == "visible_interactive" ]]; then
    remote_alpha_migrate_es_service_user_stage_run_remote_batch_with_tty "${script}" \
      "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGING_ROOT}" \
      "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_UPLOAD_ROOT}" \
      "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_ARTIFACT_ROOT}"
    REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_REMOTE_CLEANUP_COMPLETED="true"
    return 0
  fi

  remote_alpha_migrate_es_service_user_stage_run_remote_batch "${script}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGING_ROOT}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_UPLOAD_ROOT}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_ARTIFACT_ROOT}"
  REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_REMOTE_CLEANUP_COMPLETED="true"
}

remote_alpha_migrate_es_service_user_stage_visible_cleanup_if_needed() {
  if [[ "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_SUDO_MODE}" != "interactive" || "${REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_KEEP_STAGING_ON_FAILURE}" == "true" ]]; then
    return 0
  fi
  if ! remote_alpha_migrate_es_service_user_stage_remove_remote_user_owned_roots; then
    remote_alpha_migrate_es_service_user_stage_note_wrapper_tooling_error "could not remove remote transient upload or artifact roots after interactive staged ES service-user migration execution"
    echo "could not remove remote transient upload or artifact roots after interactive staged ES service-user migration execution" >&2
    return 1
  fi
  REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_REMOTE_CLEANUP_COMPLETED="true"
  if [[ "${REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_REMOTE_UPLOAD_PREPARED}" == "true" || "${REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_STAGING_OCCURRED}" == "true" ]]; then
    REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_TRANSIENT_STAGING_REMOVED="true"
  fi
}

remote_alpha_migrate_es_service_user_stage_write_provenance() {
  python3 - \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_PROVENANCE_OUTPUT_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_LOCAL_FILE_META_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_STAGE_STAT_META_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_CHECK_VALIDATION_META_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_MODE}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_SSH_TARGET}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGING_ROOT}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_SUMMARY_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_RUN_ID}" \
    "${REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_STAGING_OCCURRED}" \
    "${REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_CHECKER_RAN}" \
    "${REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_APPLY_RAN}" \
    "${REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_TRANSIENT_STAGING_REMOVED}" \
    "${REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_STAGING_RETAINED_FOR_DIAGNOSTICS}" \
    "${REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_CHECKER_EXIT_CODE}" \
    "${REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_APPLY_EXIT_CODE}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_CHECK_OUTPUT_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_APPLY_SUMMARY_OUTPUT_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_APPLY_STDOUT_OUTPUT_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_PROVENANCE_OUTPUT_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_GIT_COMMIT}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_SUDO_MODE}" \
    "${REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_SUDO_UNAVAILABLE}" \
    "${REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_WRAPPER_TOOLING_ERROR}" \
    "${REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_FAILURE_CLASSIFICATION}" \
    "${REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_BLOCKER_DETAIL}" \
    "${remote_alpha_migrate_es_service_user_stage_schema_version}" <<'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone

def read_json(path_text, default):
    if not path_text:
        return default
    path = pathlib.Path(path_text)
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return default


output_path = pathlib.Path(sys.argv[1])
local_meta = read_json(sys.argv[2], [])
stage_stat = read_json(sys.argv[3], {"items": [], "root_owned_before_execution": False, "validation_errors": []})
check_validation = read_json(sys.argv[4], {"valid_json": False, "accepted_evidence": False})
command_mode = sys.argv[5]
ssh_target = sys.argv[6]
remote_stage_root = sys.argv[7]
remote_summary_path = sys.argv[8]
run_id = sys.argv[9]
staging_occurred = sys.argv[10] == "true"
checker_ran = sys.argv[11] == "true"
apply_ran = sys.argv[12] == "true"
transient_staging_removed = sys.argv[13] == "true"
staging_retained = sys.argv[14] == "true"
checker_exit_code = sys.argv[15]
apply_exit_code = sys.argv[16]
check_output_path = sys.argv[17]
apply_summary_output_path = sys.argv[18]
apply_stdout_output_path = sys.argv[19]
provenance_output_path = sys.argv[20]
git_commit = sys.argv[21].strip()
sudo_mode = sys.argv[22]
sudo_unavailable = sys.argv[23] == "true"
wrapper_tooling_error = sys.argv[24] == "true"
failure_classification = sys.argv[25] or None
blocker_detail = sys.argv[26] or None
schema_version = sys.argv[27]

staged_files = []
for entry in local_meta:
    local_path = pathlib.Path(entry["path"])
    rel = local_path.name
    if local_path.parent.name == "internal":
        rel = "internal/" + rel
    elif "remote_alpha_check_es_writable_state_readiness" in local_path.name:
        rel = local_path.name
    remote_path = f"scripts/{rel}" if not rel.startswith("internal/") else f"scripts/{rel}"
    if "/scripts/" in entry["path"]:
        rel_local_path = entry["path"].split("/scripts/", 1)[1]
        rel_local_path = "scripts/" + rel_local_path
    else:
        rel_local_path = local_path.name
    staged_files.append(
        {
            "local_path": rel_local_path,
            "sha256": entry["sha256"],
            "remote_path": f"{remote_stage_root}/{remote_path}",
        }
    )

payload = {
    "schema_version": schema_version,
    "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "command_mode": command_mode,
    "ssh_target": ssh_target,
    "git_commit": git_commit,
    "local_git_commit": git_commit,
    "remote_stage_root": remote_stage_root,
    "remote_staged_path": remote_stage_root,
    "remote_summary_path": remote_summary_path,
    "run_id": run_id,
    "staging_occurred": staging_occurred,
    "checker_ran": checker_ran,
    "apply_ran": apply_ran,
    "transient_staging_removed": transient_staging_removed,
    "staging_retained_for_diagnostics": staging_retained,
    "checker_exit_code": checker_exit_code,
    "apply_exit_code": apply_exit_code,
    "check_output_path": check_output_path,
    "apply_summary_output_path": apply_summary_output_path,
    "apply_stdout_output_path": apply_stdout_output_path,
    "provenance_output_path": provenance_output_path,
    "sudo_mode": sudo_mode,
    "sudo_unavailable": sudo_unavailable,
    "wrapper_tooling_error": wrapper_tooling_error,
    "failure_classification": failure_classification,
    "blocker_detail": blocker_detail,
    "local_files": local_meta,
    "staged_files": staged_files,
    "remote_stage_stat": stage_stat,
    "check_only_validation": check_validation,
}
output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

remote_alpha_migrate_es_service_user_stage_finalize_on_exit() {
  local exit_code=$?
  local should_cleanup_remote="false"

  if [[ $exit_code -eq 0 || "${REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_KEEP_STAGING_ON_FAILURE}" != "true" ]]; then
    should_cleanup_remote="true"
  fi

  if [[ "${should_cleanup_remote}" == "true" ]]; then
    if [[ "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_SUDO_MODE}" == "interactive" ]]; then
      if [[ "${REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_REMOTE_CLEANUP_COMPLETED}" != "true" ]]; then
        if remote_alpha_migrate_es_service_user_stage_remove_remote_user_owned_roots >/dev/null 2>&1; then
          if [[ "${REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_REMOTE_UPLOAD_PREPARED}" == "true" || "${REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_STAGING_OCCURRED}" == "true" ]]; then
            REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_REMOTE_CLEANUP_COMPLETED="true"
            REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_TRANSIENT_STAGING_REMOVED="true"
          fi
        fi
      fi
    elif remote_alpha_migrate_es_service_user_stage_remote_cleanup >/dev/null 2>&1; then
      if [[ "${REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_REMOTE_UPLOAD_PREPARED}" == "true" || "${REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_STAGING_OCCURRED}" == "true" ]]; then
        REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_TRANSIENT_STAGING_REMOVED="true"
      fi
    fi
  else
    REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_STAGING_RETAINED_FOR_DIAGNOSTICS="true"
  fi

  if [[ -n "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_PROVENANCE_OUTPUT_PATH}" ]]; then
    if ! remote_alpha_migrate_es_service_user_stage_write_provenance; then
      echo "failed to write helper staging record" >&2
      if [[ $exit_code -eq 0 ]]; then
        exit_code=1
      fi
    fi
  fi

  return "${exit_code}"
}

remote_alpha_migrate_es_service_user_stage_main() {
  local local_upload_dir
  local stage_stat_path
  local tmpdir
  local check_status=0
  local apply_ready=""
  local overall=""
  local apply_status=0
  local helper_paths=()

  remote_alpha_migrate_es_service_user_stage_defaults
  remote_alpha_migrate_es_service_user_stage_parse_args "$@" || return $?
  remote_alpha_migrate_es_service_user_stage_finalize_paths

  remote_alpha_migrate_es_service_user_require_command python3 || return 1
  remote_alpha_migrate_es_service_user_require_command ssh || return 1
  remote_alpha_migrate_es_service_user_require_command scp || return 1

  remote_alpha_migrate_es_service_user_stage_ensure_parent_dir "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_CHECK_OUTPUT_PATH}"
  remote_alpha_migrate_es_service_user_stage_ensure_parent_dir "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_APPLY_SUMMARY_OUTPUT_PATH}"
  remote_alpha_migrate_es_service_user_stage_ensure_parent_dir "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_APPLY_STDOUT_OUTPUT_PATH}"
  remote_alpha_migrate_es_service_user_stage_ensure_parent_dir "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_PROVENANCE_OUTPUT_PATH}"

  tmpdir="$(mktemp -d)"
  trap "remote_alpha_migrate_es_service_user_stage_finalize_on_exit; rm -rf -- '${tmpdir}'" EXIT
  local_upload_dir="${tmpdir}/upload"
  stage_stat_path="${tmpdir}/stage-stat.txt"
  REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_LOCAL_FILE_META_PATH="${tmpdir}/local-file-meta.json"
  REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_STAGE_STAT_META_PATH="${tmpdir}/stage-stat.json"
  REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_CHECK_VALIDATION_META_PATH="${tmpdir}/check-validation.json"

  helper_paths=(
    "${REPO_ROOT}/scripts/remote_alpha_migrate_es_service_user.sh"
    "${REPO_ROOT}/scripts/internal/remote_alpha_migrate_es_service_user.sh"
    "${REPO_ROOT}/scripts/remote_alpha_check_es_writable_state_readiness.sh"
    "${REPO_ROOT}/scripts/internal/remote_alpha_check_es_writable_state_readiness.sh"
  )
  remote_alpha_migrate_es_service_user_stage_make_local_upload_tree "${local_upload_dir}" || {
    remote_alpha_migrate_es_service_user_stage_note_wrapper_tooling_error "could not assemble the local ES service-user migration upload tree"
    return 1
  }
  remote_alpha_migrate_es_service_user_stage_validate_local_upload_tree "${local_upload_dir}" || {
    remote_alpha_migrate_es_service_user_stage_note_wrapper_tooling_error "local ES service-user migration upload tree was missing required staged files"
    return 1
  }
  remote_alpha_migrate_es_service_user_stage_local_file_meta "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_LOCAL_FILE_META_PATH}" "${helper_paths[@]}"

  REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_GIT_COMMIT="$(remote_alpha_migrate_es_service_user_stage_git_commit)"
  REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGING_ROOT="${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGE_ROOT}/${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_RUN_ID}"
  REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_UPLOAD_ROOT="/tmp/execution-substrate-es-service-user-upload-${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_RUN_ID}"
  REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_ARTIFACT_ROOT="/tmp/execution-substrate-es-service-user-artifacts-${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_RUN_ID}"
  REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGE_STAT_ARTIFACT_PATH="${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_ARTIFACT_ROOT}/stage-stat.txt"
  REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_CHECK_OUTPUT_ARTIFACT_PATH="${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_ARTIFACT_ROOT}/check-only.json"
  REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_APPLY_STDOUT_ARTIFACT_PATH="${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_ARTIFACT_ROOT}/apply-stdout.txt"
  REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGED_WRAPPER_PATH="${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGING_ROOT}/scripts/remote_alpha_migrate_es_service_user.sh"
  REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGED_INTERNAL_PATH="${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGING_ROOT}/scripts/internal/remote_alpha_migrate_es_service_user.sh"
  REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGED_CHECKER_WRAPPER_PATH="${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGING_ROOT}/scripts/remote_alpha_check_es_writable_state_readiness.sh"
  REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGED_CHECKER_INTERNAL_PATH="${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGING_ROOT}/scripts/internal/remote_alpha_check_es_writable_state_readiness.sh"

  if [[ "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_SUDO_MODE}" == "noninteractive" ]]; then
    remote_alpha_migrate_es_service_user_stage_noninteractive_sudo_preflight || {
      remote_alpha_migrate_es_service_user_stage_note_sudo_unavailable "noninteractive sudo preflight failed for root-owned staged ES service-user migration execution"
      echo "noninteractive sudo preflight failed for root-owned staged ES service-user migration execution; rerun with --interactive-sudo from a visible terminal if a bounded password handoff is authorized" >&2
      return 1
    }
  fi

  remote_alpha_migrate_es_service_user_stage_remote_prepare_upload_root || {
    remote_alpha_migrate_es_service_user_stage_note_wrapper_tooling_error "could not prepare remote upload root for staged ES service-user migration helper tree"
    return 1
  }
  REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_REMOTE_UPLOAD_PREPARED="true"
  remote_alpha_migrate_es_service_user_stage_remote_prepare_artifact_root || {
    remote_alpha_migrate_es_service_user_stage_note_wrapper_tooling_error "could not prepare remote artifact root for staged ES service-user migration helper tree"
    return 1
  }
  remote_alpha_migrate_es_service_user_stage_upload_remote_tree "${local_upload_dir}" || {
    remote_alpha_migrate_es_service_user_stage_note_wrapper_tooling_error "could not copy staged ES service-user migration helper tree to remote upload root"
    return 1
  }
  if [[ "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_SUDO_MODE}" == "interactive" ]]; then
    if remote_alpha_migrate_es_service_user_stage_run_interactive_check_sequence; then
      check_status=0
    else
      check_status=$?
    fi
    if ! remote_alpha_migrate_es_service_user_stage_fetch_remote_file \
      "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_STAGE_STAT_ARTIFACT_PATH}" \
      "${stage_stat_path}"; then
      remote_alpha_migrate_es_service_user_stage_note_wrapper_tooling_error "could not fetch remote staged ES service-user migration helper ownership evidence"
      return 1
    fi
    REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_STAGING_OCCURRED="true"
    remote_alpha_migrate_es_service_user_stage_validate_stage_stat "${stage_stat_path}" "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_STAGE_STAT_META_PATH}" || {
      remote_alpha_migrate_es_service_user_stage_note_wrapper_tooling_error "staged ES service-user migration helper tree failed root-owned or non-writable validation"
      return 1
    }

    if ! remote_alpha_migrate_es_service_user_stage_fetch_remote_file \
      "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_CHECK_OUTPUT_ARTIFACT_PATH}" \
      "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_CHECK_OUTPUT_PATH}"; then
      remote_alpha_migrate_es_service_user_stage_note_wrapper_tooling_error "staged ES service-user migration helper did not produce fetchable check-only JSON output"
      echo "staged ES service-user migration helper did not produce fetchable check-only JSON output" >&2
      return 1
    fi
    REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_CHECKER_RAN="true"
    REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_CHECKER_EXIT_CODE="${check_status}"
  else
    remote_alpha_migrate_es_service_user_stage_remote_install_staged_tree || {
      remote_alpha_migrate_es_service_user_stage_note_wrapper_tooling_error "could not install staged ES service-user migration helper tree as root-owned remote staging"
      return 1
    }
    REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_STAGING_OCCURRED="true"

    remote_alpha_migrate_es_service_user_stage_remote_stage_stat "${stage_stat_path}" || {
      remote_alpha_migrate_es_service_user_stage_note_wrapper_tooling_error "could not verify remote staged ES service-user migration helper ownership and mode"
      return 1
    }
    remote_alpha_migrate_es_service_user_stage_validate_stage_stat "${stage_stat_path}" "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_STAGE_STAT_META_PATH}" || {
      remote_alpha_migrate_es_service_user_stage_note_wrapper_tooling_error "staged ES service-user migration helper tree failed root-owned or non-writable validation"
      return 1
    }

    set +e
    remote_alpha_migrate_es_service_user_stage_run_remote_check_only "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_CHECK_OUTPUT_PATH}"
    check_status=$?
    set -e
    REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_CHECKER_RAN="true"
    REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_CHECKER_EXIT_CODE="${check_status}"
  fi
  if [[ ! -s "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_CHECK_OUTPUT_PATH}" ]]; then
    remote_alpha_migrate_es_service_user_stage_note_wrapper_tooling_error "staged ES service-user migration helper did not produce local check-only JSON output"
    echo "staged ES service-user migration helper did not produce local check-only JSON output" >&2
    return 1
  fi
  remote_alpha_migrate_es_service_user_stage_validate_check_report "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_CHECK_OUTPUT_PATH}" "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_CHECK_VALIDATION_META_PATH}" || {
    remote_alpha_migrate_es_service_user_stage_note_wrapper_tooling_error "staged ES service-user migration check-only output was malformed or violated the non-mutating helper contract"
    return 1
  }

  apply_ready="$(remote_alpha_migrate_es_service_user_json_field "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_CHECK_OUTPUT_PATH}" "plan.apply_ready" 2>/dev/null || true)"
  overall="$(remote_alpha_migrate_es_service_user_json_field "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_CHECK_OUTPUT_PATH}" "overall_classification" 2>/dev/null || true)"
  if [[ "${check_status}" -gt 1 ]]; then
    remote_alpha_migrate_es_service_user_stage_note_wrapper_tooling_error "staged ES service-user migration helper exited with an unexpected transport or execution failure"
    return 1
  fi
  if [[ "${check_status}" != "0" && "${overall}" != "blocker" ]]; then
    remote_alpha_migrate_es_service_user_stage_note_wrapper_tooling_error "staged ES service-user migration helper exit code did not match the validated overall classification"
    return 1
  fi
  if [[ "${check_status}" == "0" && "${overall}" == "blocker" ]]; then
    remote_alpha_migrate_es_service_user_stage_note_wrapper_tooling_error "staged ES service-user migration helper reported blocker classification without a matching non-zero exit code"
    return 1
  fi

  if [[ "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_MODE}" == "check_only" ]]; then
    remote_alpha_migrate_es_service_user_stage_visible_cleanup_if_needed || return 1
    printf '%s\n' "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_CHECK_OUTPUT_PATH}"
    if [[ "${overall}" == "blocker" || "${check_status}" != "0" ]]; then
      return 1
    fi
    return 0
  fi

  if [[ "${apply_ready}" != "true" ]]; then
    remote_alpha_migrate_es_service_user_stage_visible_cleanup_if_needed || return 1
    printf '%s\n' "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_CHECK_OUTPUT_PATH}" >&2
    return 1
  fi

  if [[ "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_SUDO_MODE}" == "interactive" ]]; then
    remote_alpha_migrate_es_service_user_stage_remote_prepare_upload_root || {
      remote_alpha_migrate_es_service_user_stage_note_wrapper_tooling_error "could not prepare remote upload root for interactive ES service-user apply staging"
      return 1
    }
    remote_alpha_migrate_es_service_user_stage_upload_remote_tree "${local_upload_dir}" || {
      remote_alpha_migrate_es_service_user_stage_note_wrapper_tooling_error "could not copy staged ES service-user migration helper tree for interactive apply"
      return 1
    }
    set +e
    remote_alpha_migrate_es_service_user_stage_run_interactive_apply_sequence
    apply_status=$?
    set -e
    if ! remote_alpha_migrate_es_service_user_stage_fetch_remote_file \
      "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_APPLY_STDOUT_ARTIFACT_PATH}" \
      "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_APPLY_STDOUT_OUTPUT_PATH}"; then
      remote_alpha_migrate_es_service_user_stage_note_wrapper_tooling_error "could not fetch interactive ES service-user migration apply stdout artifact"
      return 1
    fi
  else
    set +e
    remote_alpha_migrate_es_service_user_stage_run_remote_apply "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_APPLY_STDOUT_OUTPUT_PATH}"
    apply_status=$?
    set -e
  fi
  REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_APPLY_RAN="true"
  REMOTE_ALPHA_MIGRATE_ES_SERVICE_USER_APPLY_EXIT_CODE="${apply_status}"
  remote_alpha_migrate_es_service_user_stage_fetch_remote_file \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_REMOTE_SUMMARY_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_APPLY_SUMMARY_OUTPUT_PATH}" || {
    remote_alpha_migrate_es_service_user_stage_note_wrapper_tooling_error "could not fetch remote ES service-user migration apply summary"
    return 1
  }

  remote_alpha_migrate_es_service_user_stage_visible_cleanup_if_needed || return 1
  printf '%s\n' "${REMOTE_ALPHA_STAGE_ES_SERVICE_USER_MIGRATION_APPLY_SUMMARY_OUTPUT_PATH}"
  if [[ "${apply_status}" != "0" ]]; then
    return 1
  fi
}

remote_alpha_migrate_es_service_user_main() {
  if remote_alpha_migrate_es_service_user_has_ssh_target "$@"; then
    remote_alpha_migrate_es_service_user_stage_main "$@"
    return $?
  fi

  remote_alpha_migrate_es_service_user_host_main "$@"
}
