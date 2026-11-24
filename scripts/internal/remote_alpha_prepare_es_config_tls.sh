#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${REPO_ROOT:-}" ]]; then
  REMOTE_ALPHA_ES_CONFIG_TLS_PREP_HELPER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  REPO_ROOT="$(cd "${REMOTE_ALPHA_ES_CONFIG_TLS_PREP_HELPER_DIR}/../.." && pwd)"
fi

remote_alpha_es_config_tls_prep_summary_schema_version="execution-substrate.remote-alpha.es-config-tls-prep-summary.v1"
remote_alpha_es_config_tls_prep_backup_root_dir_default="/var/tmp/execution-substrate-remote-alpha"

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

remote_alpha_es_config_tls_prep_init_expected_slice_inputs() {
  remote_alpha_es_config_tls_prep_expected_service_name="${remote_alpha_es_config_tls_prep_expected_service_name:-es}"
  remote_alpha_es_config_tls_prep_expected_prep_user="${remote_alpha_es_config_tls_prep_expected_prep_user:-es}"
  remote_alpha_es_config_tls_prep_expected_prep_group="${remote_alpha_es_config_tls_prep_expected_prep_group:-es}"
  remote_alpha_es_config_tls_prep_expected_binary_path="${remote_alpha_es_config_tls_prep_expected_binary_path:-/usr/local/lib/execution-substrate/bin/es}"
  remote_alpha_es_config_tls_prep_expected_config_path="${remote_alpha_es_config_tls_prep_expected_config_path:-/etc/execution-substrate/es.json}"
  remote_alpha_es_config_tls_prep_expected_healthcheck_env_path="${remote_alpha_es_config_tls_prep_expected_healthcheck_env_path:-/etc/execution-substrate/healthcheck.env}"
  remote_alpha_es_config_tls_prep_expected_service_unit_path="${remote_alpha_es_config_tls_prep_expected_service_unit_path:-/etc/systemd/system/es.service}"
  remote_alpha_es_config_tls_prep_expected_tls_dir="${remote_alpha_es_config_tls_prep_expected_tls_dir:-/etc/execution-substrate/es-tls}"
}

remote_alpha_es_config_tls_prep_defaults() {
  remote_alpha_es_config_tls_prep_init_expected_slice_inputs
  REMOTE_ALPHA_OPERATION_MODE="apply"
  REMOTE_ALPHA_SERVICE_NAME="${remote_alpha_es_config_tls_prep_expected_service_name}"
  REMOTE_ALPHA_PREP_USER="${remote_alpha_es_config_tls_prep_expected_prep_user}"
  REMOTE_ALPHA_PREP_GROUP="${remote_alpha_es_config_tls_prep_expected_prep_group}"
  REMOTE_ALPHA_BINARY_PATH="${remote_alpha_es_config_tls_prep_expected_binary_path}"
  REMOTE_ALPHA_CONFIG_PATH="${remote_alpha_es_config_tls_prep_expected_config_path}"
  REMOTE_ALPHA_HEALTHCHECK_ENV_PATH="${remote_alpha_es_config_tls_prep_expected_healthcheck_env_path}"
  REMOTE_ALPHA_SERVICE_UNIT_PATH="${remote_alpha_es_config_tls_prep_expected_service_unit_path}"
  REMOTE_ALPHA_TLS_DIR="${remote_alpha_es_config_tls_prep_expected_tls_dir}"
  REMOTE_ALPHA_SERVER_CERT_PATH="${REMOTE_ALPHA_TLS_DIR}/es-server-cert.pem"
  REMOTE_ALPHA_SERVER_KEY_PATH="${REMOTE_ALPHA_TLS_DIR}/es-server-key.pem"
  REMOTE_ALPHA_SERVER_CLIENT_CA_PATH="${REMOTE_ALPHA_TLS_DIR}/server-client-ca.pem"
  REMOTE_ALPHA_ARTIFACT_REGISTRY_CLIENT_CERT_PATH="${REMOTE_ALPHA_TLS_DIR}/artifact-registry-client-cert.pem"
  REMOTE_ALPHA_ARTIFACT_REGISTRY_CLIENT_KEY_PATH="${REMOTE_ALPHA_TLS_DIR}/artifact-registry-client-key.pem"
  REMOTE_ALPHA_ARTIFACT_REGISTRY_ROOT_CA_PATH="${REMOTE_ALPHA_TLS_DIR}/artifact-registry-root-ca.pem"
  REMOTE_ALPHA_EXECUTION_GOVERNANCE_CLIENT_CERT_PATH="${REMOTE_ALPHA_TLS_DIR}/execution-governance-client-cert.pem"
  REMOTE_ALPHA_EXECUTION_GOVERNANCE_CLIENT_KEY_PATH="${REMOTE_ALPHA_TLS_DIR}/execution-governance-client-key.pem"
  REMOTE_ALPHA_EXECUTION_GOVERNANCE_ROOT_CA_PATH="${REMOTE_ALPHA_TLS_DIR}/execution-governance-root-ca.pem"
  REMOTE_ALPHA_SUMMARY_PATH="${REMOTE_ALPHA_SUMMARY_PATH:-/var/tmp/execution-substrate-remote-alpha/es-config-tls-prep-summary.json}"
  REMOTE_ALPHA_SUMMARY_DIR="$(dirname "${REMOTE_ALPHA_SUMMARY_PATH}")"
  remote_alpha_es_config_tls_prep_backup_root_dir="${REMOTE_ALPHA_TEST_BACKUP_ROOT:-${remote_alpha_es_config_tls_prep_backup_root_dir_default}}"
}

remote_alpha_es_config_tls_prep_reject_slice_override_env() {
  local name=$1
  local expected=$2
  local actual=""

  actual="$(printenv "${name}" 2>/dev/null || true)"
  if [[ -z "${actual}" ]]; then
    return 0
  fi
  if [[ "${actual}" != "${expected}" ]]; then
    printf 'remote alpha ES config/TLS prep does not accept %s override for this sealed ES config/TLS ownership prep slice; expected repo-owned value %q (got %q)\n' "${name}" "${expected}" "${actual}" >&2
    return 1
  fi
  return 0
}

remote_alpha_es_config_tls_prep_require_pinned_slice_inputs() {
  remote_alpha_es_config_tls_prep_init_expected_slice_inputs
  remote_alpha_es_config_tls_prep_reject_slice_override_env "REMOTE_ALPHA_SERVICE_NAME" "${remote_alpha_es_config_tls_prep_expected_service_name}" || return 1
  remote_alpha_es_config_tls_prep_reject_slice_override_env "REMOTE_ALPHA_PREP_USER" "${remote_alpha_es_config_tls_prep_expected_prep_user}" || return 1
  remote_alpha_es_config_tls_prep_reject_slice_override_env "REMOTE_ALPHA_PREP_GROUP" "${remote_alpha_es_config_tls_prep_expected_prep_group}" || return 1
  remote_alpha_es_config_tls_prep_reject_slice_override_env "REMOTE_ALPHA_BINARY_PATH" "${remote_alpha_es_config_tls_prep_expected_binary_path}" || return 1
  remote_alpha_es_config_tls_prep_reject_slice_override_env "REMOTE_ALPHA_CONFIG_PATH" "${remote_alpha_es_config_tls_prep_expected_config_path}" || return 1
  remote_alpha_es_config_tls_prep_reject_slice_override_env "REMOTE_ALPHA_HEALTHCHECK_ENV_PATH" "${remote_alpha_es_config_tls_prep_expected_healthcheck_env_path}" || return 1
  remote_alpha_es_config_tls_prep_reject_slice_override_env "REMOTE_ALPHA_SERVICE_UNIT_PATH" "${remote_alpha_es_config_tls_prep_expected_service_unit_path}" || return 1
}

remote_alpha_es_config_tls_prep_usage() {
  cat <<'EOF'
Usage:
  sudo scripts/remote_alpha_prepare_es_config_tls.sh
  sudo scripts/remote_alpha_prepare_es_config_tls.sh --check-only

Optional flags:
  --check-only
  --dry-run
  --summary-path </path/to/es-config-tls-prep-summary.json>
  --help
EOF
}

remote_alpha_es_config_tls_prep_parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --service-name)
        echo "remote alpha ES config/TLS prep does not accept --service-name for this sealed ES config/TLS ownership prep slice" >&2
        return 2
        ;;
      --prep-user)
        echo "remote alpha ES config/TLS prep does not accept --prep-user for this sealed ES config/TLS ownership prep slice" >&2
        return 2
        ;;
      --prep-group)
        echo "remote alpha ES config/TLS prep does not accept --prep-group for this sealed ES config/TLS ownership prep slice" >&2
        return 2
        ;;
      --binary-path)
        echo "remote alpha ES config/TLS prep does not accept --binary-path for this sealed ES config/TLS ownership prep slice" >&2
        return 2
        ;;
      --config-path)
        echo "remote alpha ES config/TLS prep does not accept --config-path for this sealed ES config/TLS ownership prep slice" >&2
        return 2
        ;;
      --healthcheck-env-path)
        echo "remote alpha ES config/TLS prep does not accept --healthcheck-env-path for this sealed ES config/TLS ownership prep slice" >&2
        return 2
        ;;
      --service-unit-path)
        echo "remote alpha ES config/TLS prep does not accept --service-unit-path for this sealed ES config/TLS ownership prep slice" >&2
        return 2
        ;;
      --summary-path)
        REMOTE_ALPHA_SUMMARY_PATH="$2"
        REMOTE_ALPHA_SUMMARY_DIR="$(dirname "${REMOTE_ALPHA_SUMMARY_PATH}")"
        shift 2
        ;;
      --check-only|--dry-run)
        REMOTE_ALPHA_OPERATION_MODE="check_only"
        shift
        ;;
      --help|-h)
        remote_alpha_es_config_tls_prep_usage
        return 1
        ;;
      *)
        echo "unknown argument: $1" >&2
        remote_alpha_es_config_tls_prep_usage >&2
        return 2
        ;;
    esac
  done
}

remote_alpha_es_config_tls_prep_require_root() {
  if [[ "$(id -u)" != "0" ]]; then
    echo "remote alpha ES config/TLS prep must run as root; use sudo scripts/remote_alpha_prepare_es_config_tls.sh" >&2
    return 1
  fi
}

remote_alpha_es_config_tls_prep_require_command() {
  local name=$1
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "${name} is required" >&2
    return 1
  fi
}

remote_alpha_es_config_tls_prep_json_field() {
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

remote_alpha_es_config_tls_prep_systemctl_state() {
  local mode=$1
  local service_name=$2
  local unit_name="${service_name}"

  if [[ "${unit_name}" != *.service ]]; then
    unit_name="${unit_name}.service"
  fi

  if command -v systemctl >/dev/null 2>&1 && systemctl "${mode}" --quiet "${unit_name}" >/dev/null 2>&1; then
    printf 'true'
  else
    printf 'false'
  fi
}

remote_alpha_es_config_tls_prep_passwordless_sudo_for_ds() {
  local override_value="${REMOTE_ALPHA_TEST_PASSWORDLESS_SUDO_FOR_DS:-}"

  if [[ -n "${override_value}" ]]; then
    printf '%s' "${override_value}"
    return 0
  fi

  if [[ "$(id -u)" != "0" ]]; then
    printf 'unknown'
    return 0
  fi
  if ! command -v sudo >/dev/null 2>&1; then
    printf 'unknown'
    return 0
  fi

  if sudo -u ds -H sh -lc 'sudo -n true >/dev/null 2>&1'; then
    printf 'true'
  else
    printf 'false'
  fi
}

remote_alpha_es_config_tls_prep_ds_not_in_docker_group() {
  local groups=""

  if groups="$(id -nG ds 2>/dev/null)"; then
    if printf '%s\n' "${groups}" | tr ' ' '\n' | grep -qx 'docker'; then
      printf 'false'
    else
      printf 'true'
    fi
    return 0
  fi

  printf 'unknown'
}

remote_alpha_es_config_tls_prep_service_account_meta() {
  python3 - "${REMOTE_ALPHA_PREP_USER}" "${REMOTE_ALPHA_PREP_GROUP}" <<'PY'
import json
import subprocess
import sys

user = sys.argv[1]
expected_group = sys.argv[2]

result = {
    "status": "fail",
    "error": "",
    "user": user,
    "uid": "",
    "user_exists": False,
    "group_exists": False,
    "would_create_user": False,
    "would_create_group": False,
    "apply_ready": False,
    "blocker": False,
    "expected_primary_group": expected_group,
    "primary_group": "",
    "group_names": [],
    "supplementary_groups": [],
    "group_gid": "",
    "group_entry_members": [],
    "primary_group_users": [],
    "group_members": [],
    "unexpected_group_members": [],
    "narrow_dedicated_account": False,
}


def run_id(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["id", *args], check=False, capture_output=True, text=True)


group_proc = subprocess.run(["getent", "group", expected_group], check=False, capture_output=True, text=True)
if group_proc.returncode == 0:
    result["group_exists"] = True

group_line = ""
if result["group_exists"]:
    for raw in group_proc.stdout.splitlines():
        line = raw.strip()
        if line:
            group_line = line
            break
    group_fields = group_line.split(":")
    if len(group_fields) < 4:
        result["error"] = f"failed to parse ES prep group entry for {expected_group}"
        result["blocker"] = True
        print(json.dumps(result, sort_keys=True))
        sys.exit(0)

    result["group_gid"] = group_fields[2].strip()
    group_entry_members = []
    for member in group_fields[3].split(","):
        member = member.strip()
        if member and member not in group_entry_members:
            group_entry_members.append(member)
    result["group_entry_members"] = group_entry_members

    passwd_proc = subprocess.run(["getent", "passwd"], check=False, capture_output=True, text=True)
    if passwd_proc.returncode != 0:
        result["error"] = f"failed to enumerate passwd entries while checking ES prep group {expected_group}"
        result["blocker"] = True
        print(json.dumps(result, sort_keys=True))
        sys.exit(0)

    primary_group_users = []
    for raw in passwd_proc.stdout.splitlines():
        line = raw.strip()
        if not line:
            continue
        fields = line.split(":")
        if len(fields) < 4:
            continue
        member_name = fields[0].strip()
        member_gid = fields[3].strip()
        if member_name and member_gid == result["group_gid"] and member_name not in primary_group_users:
            primary_group_users.append(member_name)
    result["primary_group_users"] = primary_group_users

    group_members = []
    for member in primary_group_users + group_entry_members:
        if member and member not in group_members:
            group_members.append(member)
    result["group_members"] = group_members
    result["unexpected_group_members"] = [member for member in group_members if member != user]

uid_proc = run_id("-u", user)
if uid_proc.returncode == 0:
    result["user_exists"] = True
    result["uid"] = uid_proc.stdout.strip()

if result["user_exists"]:
    primary_group_proc = run_id("-gn", user)
    if primary_group_proc.returncode != 0:
        result["error"] = f"failed to read primary group for ES prep account user {user}"
        result["blocker"] = True
        print(json.dumps(result, sort_keys=True))
        sys.exit(0)
    result["primary_group"] = primary_group_proc.stdout.strip()

    group_names_proc = run_id("-nG", user)
    if group_names_proc.returncode != 0:
        result["error"] = f"failed to read group list for ES prep account user {user}"
        result["blocker"] = True
        print(json.dumps(result, sort_keys=True))
        sys.exit(0)

    group_names = []
    for item in group_names_proc.stdout.split():
        if item and item not in group_names:
            group_names.append(item)
    result["group_names"] = group_names
    result["supplementary_groups"] = [group for group in group_names if group != result["primary_group"]]

if not result["group_exists"]:
    if result["user_exists"]:
        result["error"] = f"existing ES prep account user {user} exists but group {expected_group} does not"
        result["blocker"] = True
        print(json.dumps(result, sort_keys=True))
        sys.exit(0)
    result["status"] = "missing"
    result["would_create_user"] = True
    result["would_create_group"] = True
    result["apply_ready"] = True
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

if result["unexpected_group_members"]:
    joined = ", ".join(result["unexpected_group_members"])
    result["error"] = (
        f"existing ES prep group {expected_group} is broader than this slice allows; "
        f"unexpected group members present: {joined}"
    )
    result["blocker"] = True
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

if not result["user_exists"]:
    result["status"] = "missing"
    result["would_create_user"] = True
    result["apply_ready"] = True
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

if result["primary_group"] != expected_group:
    result["error"] = f"existing ES prep account user {user} does not use primary group {expected_group}"
    result["blocker"] = True
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

if expected_group not in result["group_names"]:
    result["error"] = f"existing ES prep account user {user} is missing expected group {expected_group} in id -nG output"
    result["blocker"] = True
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

if result["supplementary_groups"]:
    joined = ", ".join(result["supplementary_groups"])
    result["error"] = (
        f"existing ES prep account user {user} is broader than this slice allows; "
        f"supplementary groups present: {joined}"
    )
    result["blocker"] = True
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

if user not in result["group_members"]:
    result["error"] = (
        f"failed to prove ES prep group {expected_group} membership for {user}; "
        "group enumeration did not include the prep account user"
    )
    result["blocker"] = True
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

result["apply_ready"] = True
result["narrow_dedicated_account"] = True
result["status"] = "pass"
print(json.dumps(result, sort_keys=True))
PY
}

remote_alpha_es_config_tls_prep_runtime_meta() {
  local config_read_path="${1:-${REMOTE_ALPHA_CONFIG_PATH}}"
  local reported_config_path="${2:-${config_read_path}}"

  python3 - "${config_read_path}" "${REMOTE_ALPHA_BINARY_PATH}" "${reported_config_path}" <<'PY'
import json
import sys
from pathlib import Path

config_path = Path(sys.argv[1])
binary_path = sys.argv[2]
reported_config_path = sys.argv[3]

result = {
    "status": "fail",
    "error": "",
    "binary_path": binary_path,
    "config_path": str(reported_config_path),
    "bind_address": "",
    "port": 0,
    "health_url": "",
    "contract_url": "",
    "tls": {
        "cert_file": "",
        "key_file": "",
        "client_ca_file": "",
    },
    "artifact_registry": {
        "base_url": "",
        "client_cert_file": "",
        "client_key_file": "",
        "root_ca_file": "",
    },
    "execution_governance": {
        "base_url": "",
        "client_cert_file": "",
        "client_key_file": "",
        "root_ca_file": "",
    },
    "local_state_paths": {
        "staging_root_dir": "",
        "results_root_dir": "",
        "spire_workload_api_socket_path": "",
    },
    "log_sink": "journald/stdout",
}

try:
    payload = json.loads(config_path.read_text(encoding="utf-8"))
except FileNotFoundError:
    result["error"] = "ES config file does not exist"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)
except Exception as exc:
    result["error"] = f"read or decode ES config: {exc}"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

http = payload.get("http") or {}
bind_address = str(http.get("bind_address") or "").strip()
try:
    port = int(http.get("port") or 0)
except Exception:
    port = 0
result["bind_address"] = bind_address
result["port"] = port
if bind_address and port > 0:
    base_url = f"https://{bind_address}:{port}"
    result["health_url"] = base_url + "/health"
    result["contract_url"] = base_url + "/v1/executions:contract"

tls = payload.get("tls") or {}
result["tls"]["cert_file"] = str(tls.get("cert_file") or "").strip()
result["tls"]["key_file"] = str(tls.get("key_file") or "").strip()
result["tls"]["client_ca_file"] = str(tls.get("client_ca_file") or "").strip()

deps = payload.get("dependencies") or {}
artifact_registry = deps.get("artifact_registry") or {}
execution_governance = deps.get("execution_governance") or {}
for key in ("base_url", "client_cert_file", "client_key_file", "root_ca_file"):
    result["artifact_registry"][key] = str(artifact_registry.get(key) or "").strip()
    result["execution_governance"][key] = str(execution_governance.get(key) or "").strip()

execution = payload.get("execution") or {}
result["local_state_paths"]["staging_root_dir"] = str(execution.get("staging_root_dir") or "").strip()
result["local_state_paths"]["results_root_dir"] = str(execution.get("results_root_dir") or "").strip()
result["local_state_paths"]["spire_workload_api_socket_path"] = str(execution.get("spire_workload_api_socket_path") or "").strip()

required_paths = [
    result["tls"]["cert_file"],
    result["tls"]["key_file"],
    result["tls"]["client_ca_file"],
    result["artifact_registry"]["base_url"],
    result["artifact_registry"]["client_cert_file"],
    result["artifact_registry"]["client_key_file"],
    result["artifact_registry"]["root_ca_file"],
    result["execution_governance"]["base_url"],
    result["execution_governance"]["client_cert_file"],
    result["execution_governance"]["client_key_file"],
    result["execution_governance"]["root_ca_file"],
]
if not result["health_url"] or not result["contract_url"] or any(not value for value in required_paths):
    result["error"] = "ES runtime metadata is missing required health, contract, TLS, or dependency inputs"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

result["status"] = "pass"
print(json.dumps(result, sort_keys=True))
PY
}

remote_alpha_es_config_tls_prep_health_env_meta() {
  python3 - "${REMOTE_ALPHA_HEALTHCHECK_ENV_PATH}" <<'PY'
import json
import pathlib
import sys

env_path = pathlib.Path(sys.argv[1])
result = {
    "status": "fail",
    "error": "",
    "ca_cert": "",
    "operator_cert": "",
    "operator_key": "",
}

try:
    lines = env_path.read_text(encoding="utf-8").splitlines()
except FileNotFoundError:
    result["error"] = "healthcheck env file does not exist"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)
except Exception as exc:
    result["error"] = f"read healthcheck env: {exc}"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

values = {}
for raw in lines:
    line = raw.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    key, value = line.split("=", 1)
    values[key.strip()] = value.strip()

result["ca_cert"] = values.get("CA_CERT", "")
result["operator_cert"] = values.get("OPERATOR_CERT", "")
result["operator_key"] = values.get("OPERATOR_KEY", "")

if not result["ca_cert"] or not result["operator_cert"] or not result["operator_key"]:
    result["error"] = "healthcheck env is missing CA_CERT, OPERATOR_CERT, or OPERATOR_KEY"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

result["status"] = "pass"
print(json.dumps(result, sort_keys=True))
PY
}

remote_alpha_es_config_tls_prep_verify_file_exists() {
  local label=$1
  local path=$2

  if [[ ! -e "${path}" ]]; then
    echo "${label} does not exist: ${path}" >&2
    return 1
  fi
}

remote_alpha_es_config_tls_prep_verify_runtime_paths() {
  local runtime_meta_path=$1
  local health_env_meta_path=$2
  local paths=()
  local value=""

  for field in \
    "binary_path" \
    "config_path" \
    "tls.cert_file" \
    "tls.key_file" \
    "tls.client_ca_file" \
    "artifact_registry.client_cert_file" \
    "artifact_registry.client_key_file" \
    "artifact_registry.root_ca_file" \
    "execution_governance.client_cert_file" \
    "execution_governance.client_key_file" \
    "execution_governance.root_ca_file"; do
    value="$(remote_alpha_es_config_tls_prep_json_field "${runtime_meta_path}" "${field}" 2>/dev/null || true)"
    [[ -n "${value}" ]] || continue
    paths+=("${field}:${value}")
  done

  for field in "ca_cert" "operator_cert" "operator_key"; do
    value="$(remote_alpha_es_config_tls_prep_json_field "${health_env_meta_path}" "${field}" 2>/dev/null || true)"
    [[ -n "${value}" ]] || continue
    paths+=("${field}:${value}")
  done

  local entry=""
  local label=""
  local path=""
  for entry in "${paths[@]}"; do
    label="${entry%%:*}"
    path="${entry#*:}"
    remote_alpha_es_config_tls_prep_verify_file_exists "${label}" "${path}" || return 1
  done
}

remote_alpha_es_config_tls_prep_assert_unit_execstart() {
  local exec_start=""

  exec_start="$(systemctl show "${REMOTE_ALPHA_SERVICE_NAME}.service" -p ExecStart 2>/dev/null || true)"
  if [[ -z "${exec_start}" ]]; then
    echo "failed to read ExecStart for ${REMOTE_ALPHA_SERVICE_NAME}.service" >&2
    return 1
  fi
  if [[ "${exec_start}" != *"${REMOTE_ALPHA_BINARY_PATH}"* ]]; then
    echo "es.service ExecStart does not contain expected binary path ${REMOTE_ALPHA_BINARY_PATH}" >&2
    return 1
  fi
  if [[ "${exec_start}" != *"${REMOTE_ALPHA_CONFIG_PATH}"* ]]; then
    echo "es.service ExecStart does not contain expected config path ${REMOTE_ALPHA_CONFIG_PATH}" >&2
    return 1
  fi
}

remote_alpha_es_config_tls_prep_ensure_group() {
  if getent group "${REMOTE_ALPHA_PREP_GROUP}" >/dev/null 2>&1; then
    return 0
  fi
  groupadd --system "${REMOTE_ALPHA_PREP_GROUP}"
}

remote_alpha_es_config_tls_prep_ensure_user() {
  if id -u "${REMOTE_ALPHA_PREP_USER}" >/dev/null 2>&1; then
    local account_meta_path=""
    local account_status=""
    local account_error=""

    account_meta_path="$(mktemp)"
    remote_alpha_es_config_tls_prep_service_account_meta >"${account_meta_path}"
    account_status="$(remote_alpha_es_config_tls_prep_json_field "${account_meta_path}" "status" 2>/dev/null || true)"
    if [[ "${account_status}" != "pass" ]]; then
      account_error="$(remote_alpha_es_config_tls_prep_json_field "${account_meta_path}" "error" 2>/dev/null || true)"
      rm -f -- "${account_meta_path}"
      if [[ -z "${account_error}" ]]; then
        account_error="existing ES prep account ${REMOTE_ALPHA_PREP_USER} is not acceptably narrow for this slice"
      fi
      echo "${account_error}" >&2
      return 1
    fi
    rm -f -- "${account_meta_path}"
    return 0
  fi

  local nologin_path=""
  nologin_path="$(command -v nologin 2>/dev/null || true)"
  if [[ -z "${nologin_path}" ]]; then
    nologin_path="/usr/sbin/nologin"
  fi

  useradd \
    --system \
    --gid "${REMOTE_ALPHA_PREP_GROUP}" \
    --home-dir /nonexistent \
    --no-create-home \
    --shell "${nologin_path}" \
    "${REMOTE_ALPHA_PREP_USER}"
}

remote_alpha_es_config_tls_prep_capture_config_copy() {
  local source_path=$1
  local destination_path=$2

  python3 - "${source_path}" "${destination_path}" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
destination.write_bytes(source.read_bytes())
PY
}

remote_alpha_es_config_tls_prep_backup_timestamp() {
  if [[ -n "${REMOTE_ALPHA_TEST_BACKUP_TIMESTAMP:-}" ]]; then
    printf '%s' "${REMOTE_ALPHA_TEST_BACKUP_TIMESTAMP}"
    return 0
  fi

  python3 - <<'PY'
from datetime import datetime, timezone

print(datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
PY
}

remote_alpha_es_config_tls_prep_create_backup_snapshot() {
  local backup_meta_path=$1
  local source_runtime_meta_path=$2
  local source_config_path=$3
  local pre_service_account_meta_path=$4
  local pre_service_meta_path=$5
  local backup_timestamp=""
  local backup_dir=""
  local config_backup_path=""
  local snapshot_manifest_path=""

  backup_timestamp="$(remote_alpha_es_config_tls_prep_backup_timestamp)"
  backup_dir="$(python3 - "${remote_alpha_es_config_tls_prep_backup_root_dir}" "${backup_timestamp}" <<'PY'
from pathlib import Path
import sys
import tempfile

root = Path(sys.argv[1])
timestamp = sys.argv[2].strip()
root.mkdir(parents=True, exist_ok=True)
print(tempfile.mkdtemp(prefix=f"es-config-tls-prep-{timestamp}-", dir=str(root)))
PY
)"
  if [[ -z "${backup_dir}" ]]; then
    echo "failed to create ES config/TLS prep backup directory" >&2
    return 1
  fi

  config_backup_path="${backup_dir}/es.json"
  snapshot_manifest_path="${backup_dir}/pre-apply-snapshot.json"
  remote_alpha_es_config_tls_prep_capture_config_copy "${source_config_path}" "${config_backup_path}"

  python3 - \
    "${backup_meta_path}" \
    "${snapshot_manifest_path}" \
    "${backup_dir}" \
    "${remote_alpha_es_config_tls_prep_backup_root_dir}" \
    "${config_backup_path}" \
    "${source_runtime_meta_path}" \
    "${pre_service_account_meta_path}" \
    "${pre_service_meta_path}" \
    "${REMOTE_ALPHA_CONFIG_PATH}" \
    "${REMOTE_ALPHA_TLS_DIR}" \
    "${REMOTE_ALPHA_PREP_USER}" \
    "${REMOTE_ALPHA_PREP_GROUP}" <<'PY'
import grp
import hashlib
import json
import pathlib
import pwd
import stat as statmod
import sys

backup_meta_path = pathlib.Path(sys.argv[1])
snapshot_manifest_path = pathlib.Path(sys.argv[2])
backup_dir = pathlib.Path(sys.argv[3])
backup_parent_dir = pathlib.Path(sys.argv[4])
config_backup_path = pathlib.Path(sys.argv[5])
source_runtime = json.loads(pathlib.Path(sys.argv[6]).read_text(encoding="utf-8"))
pre_service_account = json.loads(pathlib.Path(sys.argv[7]).read_text(encoding="utf-8"))
pre_service = json.loads(pathlib.Path(sys.argv[8]).read_text(encoding="utf-8"))
live_config_path = sys.argv[9]
dedicated_tls_dir = sys.argv[10]
prep_user = sys.argv[11]
prep_group = sys.argv[12]

tls_sources = [
    ("tls.cert_file", source_runtime.get("tls", {}).get("cert_file", "")),
    ("tls.key_file", source_runtime.get("tls", {}).get("key_file", "")),
    ("tls.client_ca_file", source_runtime.get("tls", {}).get("client_ca_file", "")),
    ("dependencies.artifact_registry.client_cert_file", source_runtime.get("artifact_registry", {}).get("client_cert_file", "")),
    ("dependencies.artifact_registry.client_key_file", source_runtime.get("artifact_registry", {}).get("client_key_file", "")),
    ("dependencies.artifact_registry.root_ca_file", source_runtime.get("artifact_registry", {}).get("root_ca_file", "")),
    ("dependencies.execution_governance.client_cert_file", source_runtime.get("execution_governance", {}).get("client_cert_file", "")),
    ("dependencies.execution_governance.client_key_file", source_runtime.get("execution_governance", {}).get("client_key_file", "")),
    ("dependencies.execution_governance.root_ca_file", source_runtime.get("execution_governance", {}).get("root_ca_file", "")),
]


def owner_name(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def group_name(gid: int) -> str:
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


def file_record(field: str, raw_path: str) -> dict[str, object]:
    path = pathlib.Path(str(raw_path or "").strip())
    data = path.read_bytes()
    st = path.stat()
    return {
        "field": field,
        "path": str(path),
        "size_bytes": len(data),
        "owner": owner_name(st.st_uid),
        "group": group_name(st.st_gid),
        "mode": format(statmod.S_IMODE(st.st_mode), "04o"),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def rollback_notes() -> list[str]:
    notes = [
        f"Restore {live_config_path} from {config_backup_path} before restarting es.service.",
        f"Use {snapshot_manifest_path} to verify the pre-apply source TLS paths, owner/group, mode, size, and sha256 before removing or replacing {dedicated_tls_dir}.",
        "Keep es.service User=/Group= unchanged during rollback; this slice does not de-root ES.",
    ]
    if pre_service_account.get("user_exists") is True or pre_service_account.get("group_exists") is True:
        notes.append(
            f"The pre-apply snapshot recorded {prep_user}:{prep_group} as pre-existing; do not remove that prep account/group as part of rollback."
        )
    else:
        notes.append(
            f"The pre-apply snapshot recorded {prep_user}:{prep_group} as absent before apply; remove the dedicated prep account/group only if you are explicitly undoing this prep slice and no later step depends on it."
        )
    notes.append("Restart es.service after restoring the pre-apply config/TLS posture.")
    return notes


snapshot = {
    "status": "created",
    "created": True,
    "parent_dir": str(backup_parent_dir),
    "path": str(backup_dir),
    "pre_apply_config_path": live_config_path,
    "pre_apply_config_copy": str(config_backup_path),
    "snapshot_manifest_path": str(snapshot_manifest_path),
    "pre_apply_source_tls": [file_record(field, path) for field, path in tls_sources],
    "pre_apply_prep_account": {
        "user": prep_user,
        "group": prep_group,
        "status": pre_service_account.get("status", ""),
        "user_exists": pre_service_account.get("user_exists") is True,
        "group_exists": pre_service_account.get("group_exists") is True,
        "would_create_user": pre_service_account.get("would_create_user") is True,
        "would_create_group": pre_service_account.get("would_create_group") is True,
    },
    "pre_apply_service": {
        "name": pre_service.get("service", "es"),
        "user": pre_service.get("user", ""),
        "group": pre_service.get("group", ""),
        "effective_user": pre_service.get("effective_user", ""),
        "effective_group": pre_service.get("effective_group", ""),
        "active_state": pre_service.get("active_state", ""),
        "sub_state": pre_service.get("sub_state", ""),
    },
    "rollback_notes": rollback_notes(),
}

snapshot_manifest_path.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")
backup_meta_path.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

  if [[ -n "${REMOTE_ALPHA_TEST_BACKUP_PATH_FILE:-}" ]]; then
    printf '%s\n' "${backup_dir}" > "${REMOTE_ALPHA_TEST_BACKUP_PATH_FILE}"
  fi
  if [[ -n "${REMOTE_ALPHA_TEST_BACKUP_SENTINEL_PATH:-}" ]]; then
    printf '%s\n' "${snapshot_manifest_path}" > "${REMOTE_ALPHA_TEST_BACKUP_SENTINEL_PATH}"
  fi
}

remote_alpha_es_config_tls_prep_prepare_tls_material() {
  local runtime_meta_path=$1
  local server_cert_source server_key_source server_ca_source
  local ars_client_cert_source ars_client_key_source ars_root_ca_source
  local egs_client_cert_source egs_client_key_source egs_root_ca_source

  server_cert_source="$(remote_alpha_es_config_tls_prep_json_field "${runtime_meta_path}" "tls.cert_file")"
  server_key_source="$(remote_alpha_es_config_tls_prep_json_field "${runtime_meta_path}" "tls.key_file")"
  server_ca_source="$(remote_alpha_es_config_tls_prep_json_field "${runtime_meta_path}" "tls.client_ca_file")"
  ars_client_cert_source="$(remote_alpha_es_config_tls_prep_json_field "${runtime_meta_path}" "artifact_registry.client_cert_file")"
  ars_client_key_source="$(remote_alpha_es_config_tls_prep_json_field "${runtime_meta_path}" "artifact_registry.client_key_file")"
  ars_root_ca_source="$(remote_alpha_es_config_tls_prep_json_field "${runtime_meta_path}" "artifact_registry.root_ca_file")"
  egs_client_cert_source="$(remote_alpha_es_config_tls_prep_json_field "${runtime_meta_path}" "execution_governance.client_cert_file")"
  egs_client_key_source="$(remote_alpha_es_config_tls_prep_json_field "${runtime_meta_path}" "execution_governance.client_key_file")"
  egs_root_ca_source="$(remote_alpha_es_config_tls_prep_json_field "${runtime_meta_path}" "execution_governance.root_ca_file")"

  python3 - \
    "${server_cert_source}" "${REMOTE_ALPHA_SERVER_CERT_PATH}" \
    "${server_key_source}" "${REMOTE_ALPHA_SERVER_KEY_PATH}" \
    "${server_ca_source}" "${REMOTE_ALPHA_SERVER_CLIENT_CA_PATH}" \
    "${ars_client_cert_source}" "${REMOTE_ALPHA_ARTIFACT_REGISTRY_CLIENT_CERT_PATH}" \
    "${ars_client_key_source}" "${REMOTE_ALPHA_ARTIFACT_REGISTRY_CLIENT_KEY_PATH}" \
    "${ars_root_ca_source}" "${REMOTE_ALPHA_ARTIFACT_REGISTRY_ROOT_CA_PATH}" \
    "${egs_client_cert_source}" "${REMOTE_ALPHA_EXECUTION_GOVERNANCE_CLIENT_CERT_PATH}" \
    "${egs_client_key_source}" "${REMOTE_ALPHA_EXECUTION_GOVERNANCE_CLIENT_KEY_PATH}" \
    "${egs_root_ca_source}" "${REMOTE_ALPHA_EXECUTION_GOVERNANCE_ROOT_CA_PATH}" <<'PY'
from pathlib import Path
import sys

pairs = []
args = sys.argv[1:]
for i in range(0, len(args), 2):
    pairs.append((Path(args[i]), Path(args[i + 1])))

for source, destination in pairs:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.resolve() == destination.resolve():
        continue
    destination.write_bytes(source.read_bytes())
PY

  chown root:"${REMOTE_ALPHA_PREP_GROUP}" "${REMOTE_ALPHA_TLS_DIR}"
  chmod 0710 "${REMOTE_ALPHA_TLS_DIR}"

  local path=""
  for path in \
    "${REMOTE_ALPHA_SERVER_CERT_PATH}" \
    "${REMOTE_ALPHA_SERVER_KEY_PATH}" \
    "${REMOTE_ALPHA_SERVER_CLIENT_CA_PATH}" \
    "${REMOTE_ALPHA_ARTIFACT_REGISTRY_CLIENT_CERT_PATH}" \
    "${REMOTE_ALPHA_ARTIFACT_REGISTRY_CLIENT_KEY_PATH}" \
    "${REMOTE_ALPHA_ARTIFACT_REGISTRY_ROOT_CA_PATH}" \
    "${REMOTE_ALPHA_EXECUTION_GOVERNANCE_CLIENT_CERT_PATH}" \
    "${REMOTE_ALPHA_EXECUTION_GOVERNANCE_CLIENT_KEY_PATH}" \
    "${REMOTE_ALPHA_EXECUTION_GOVERNANCE_ROOT_CA_PATH}"; do
    chown root:"${REMOTE_ALPHA_PREP_GROUP}" "${path}"
    chmod 0640 "${path}"
  done
}

remote_alpha_es_config_tls_prep_render_rewritten_config() {
  local source_config_path=$1
  local destination_config_path=$2

  python3 - \
    "${source_config_path}" \
    "${destination_config_path}" \
    "${REMOTE_ALPHA_SERVER_CERT_PATH}" \
    "${REMOTE_ALPHA_SERVER_KEY_PATH}" \
    "${REMOTE_ALPHA_SERVER_CLIENT_CA_PATH}" \
    "${REMOTE_ALPHA_ARTIFACT_REGISTRY_CLIENT_CERT_PATH}" \
    "${REMOTE_ALPHA_ARTIFACT_REGISTRY_CLIENT_KEY_PATH}" \
    "${REMOTE_ALPHA_ARTIFACT_REGISTRY_ROOT_CA_PATH}" \
    "${REMOTE_ALPHA_EXECUTION_GOVERNANCE_CLIENT_CERT_PATH}" \
    "${REMOTE_ALPHA_EXECUTION_GOVERNANCE_CLIENT_KEY_PATH}" \
    "${REMOTE_ALPHA_EXECUTION_GOVERNANCE_ROOT_CA_PATH}" <<'PY'
import json
import sys

config_path = sys.argv[1]
destination_path = sys.argv[2]
server_cert = sys.argv[3]
server_key = sys.argv[4]
server_ca = sys.argv[5]
ars_client_cert = sys.argv[6]
ars_client_key = sys.argv[7]
ars_root_ca = sys.argv[8]
egs_client_cert = sys.argv[9]
egs_client_key = sys.argv[10]
egs_root_ca = sys.argv[11]

with open(config_path, encoding="utf-8") as f:
    payload = json.load(f)

payload.setdefault("tls", {})
payload["tls"]["cert_file"] = server_cert
payload["tls"]["key_file"] = server_key
payload["tls"]["client_ca_file"] = server_ca

deps = payload.setdefault("dependencies", {})
artifact_registry = deps.setdefault("artifact_registry", {})
artifact_registry["client_cert_file"] = ars_client_cert
artifact_registry["client_key_file"] = ars_client_key
artifact_registry["root_ca_file"] = ars_root_ca

execution_governance = deps.setdefault("execution_governance", {})
execution_governance["client_cert_file"] = egs_client_cert
execution_governance["client_key_file"] = egs_client_key
execution_governance["root_ca_file"] = egs_root_ca

with open(destination_path, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2, sort_keys=True)
    f.write("\n")
PY
}

remote_alpha_es_config_tls_prep_rewrite_config() {
  local temp_path="${REMOTE_ALPHA_CONFIG_PATH}.tmp"

  remote_alpha_es_config_tls_prep_render_rewritten_config "${REMOTE_ALPHA_CONFIG_PATH}" "${temp_path}"
  python3 - "${temp_path}" "${REMOTE_ALPHA_CONFIG_PATH}" <<'PY'
import os
import sys

os.replace(sys.argv[1], sys.argv[2])
PY

  chown root:"${REMOTE_ALPHA_PREP_GROUP}" "${REMOTE_ALPHA_CONFIG_PATH}"
  chmod 0640 "${REMOTE_ALPHA_CONFIG_PATH}"
}

remote_alpha_es_config_tls_prep_config_rewrite_scope_meta() {
  local before_config_path=$1
  local after_config_path=$2

  python3 - "${before_config_path}" "${after_config_path}" <<'PY'
import json
import pathlib
import sys

before = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
after = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))

allowed_paths = {
    "tls.cert_file",
    "tls.key_file",
    "tls.client_ca_file",
    "dependencies.artifact_registry.client_cert_file",
    "dependencies.artifact_registry.client_key_file",
    "dependencies.artifact_registry.root_ca_file",
    "dependencies.execution_governance.client_cert_file",
    "dependencies.execution_governance.client_key_file",
    "dependencies.execution_governance.root_ca_file",
}
tracked_state_paths = {
    "execution.staging_root_dir",
    "execution.results_root_dir",
    "execution.spire_workload_api_socket_path",
}

changed_paths = []


def compare(left, right, prefix: str = ""):
    if isinstance(left, dict) and isinstance(right, dict):
        for key in sorted(set(left) | set(right)):
            next_prefix = f"{prefix}.{key}" if prefix else key
            if key not in left or key not in right:
                changed_paths.append(next_prefix)
                continue
            compare(left[key], right[key], next_prefix)
        return
    if isinstance(left, list) and isinstance(right, list):
        if left != right:
            changed_paths.append(prefix)
        return
    if left != right:
        changed_paths.append(prefix)


compare(before, after)

unexpected_paths = [path for path in changed_paths if path not in allowed_paths]
tracked_state = {}
tracked_state_unchanged = True
for path in sorted(tracked_state_paths):
    current = before
    updated = after
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        else:
            current = None
        if isinstance(updated, dict):
            updated = updated.get(part)
        else:
            updated = None
    same = current == updated
    tracked_state[path] = {
        "before": current,
        "after": updated,
        "unchanged": same,
    }
    if not same:
        tracked_state_unchanged = False

print(json.dumps({
    "status": "pass" if not unexpected_paths and tracked_state_unchanged else "fail",
    "allowed_paths": sorted(allowed_paths),
    "changed_paths": sorted(changed_paths),
    "unexpected_paths": sorted(unexpected_paths),
    "tracked_state_paths": tracked_state,
}, sort_keys=True))
PY
}

remote_alpha_es_config_tls_prep_assert_runtime_path_equals() {
  local runtime_meta_path=$1
  local field=$2
  local expected=$3
  local description=$4
  local actual=""

  actual="$(remote_alpha_es_config_tls_prep_json_field "${runtime_meta_path}" "${field}" 2>/dev/null || true)"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "ES config did not switch to dedicated ${description} path ${expected}" >&2
    return 1
  fi
}

remote_alpha_es_config_tls_prep_assert_dedicated_runtime_paths() {
  local runtime_meta_path=$1

  remote_alpha_es_config_tls_prep_assert_runtime_path_equals \
    "${runtime_meta_path}" \
    "tls.cert_file" \
    "${REMOTE_ALPHA_SERVER_CERT_PATH}" \
    "server cert" || return 1
  remote_alpha_es_config_tls_prep_assert_runtime_path_equals \
    "${runtime_meta_path}" \
    "tls.key_file" \
    "${REMOTE_ALPHA_SERVER_KEY_PATH}" \
    "server key" || return 1
  remote_alpha_es_config_tls_prep_assert_runtime_path_equals \
    "${runtime_meta_path}" \
    "tls.client_ca_file" \
    "${REMOTE_ALPHA_SERVER_CLIENT_CA_PATH}" \
    "server client CA" || return 1
  remote_alpha_es_config_tls_prep_assert_runtime_path_equals \
    "${runtime_meta_path}" \
    "artifact_registry.client_cert_file" \
    "${REMOTE_ALPHA_ARTIFACT_REGISTRY_CLIENT_CERT_PATH}" \
    "artifact-registry client cert" || return 1
  remote_alpha_es_config_tls_prep_assert_runtime_path_equals \
    "${runtime_meta_path}" \
    "artifact_registry.client_key_file" \
    "${REMOTE_ALPHA_ARTIFACT_REGISTRY_CLIENT_KEY_PATH}" \
    "artifact-registry client key" || return 1
  remote_alpha_es_config_tls_prep_assert_runtime_path_equals \
    "${runtime_meta_path}" \
    "artifact_registry.root_ca_file" \
    "${REMOTE_ALPHA_ARTIFACT_REGISTRY_ROOT_CA_PATH}" \
    "artifact-registry root CA" || return 1
  remote_alpha_es_config_tls_prep_assert_runtime_path_equals \
    "${runtime_meta_path}" \
    "execution_governance.client_cert_file" \
    "${REMOTE_ALPHA_EXECUTION_GOVERNANCE_CLIENT_CERT_PATH}" \
    "execution-governance client cert" || return 1
  remote_alpha_es_config_tls_prep_assert_runtime_path_equals \
    "${runtime_meta_path}" \
    "execution_governance.client_key_file" \
    "${REMOTE_ALPHA_EXECUTION_GOVERNANCE_CLIENT_KEY_PATH}" \
    "execution-governance client key" || return 1
  remote_alpha_es_config_tls_prep_assert_runtime_path_equals \
    "${runtime_meta_path}" \
    "execution_governance.root_ca_file" \
    "${REMOTE_ALPHA_EXECUTION_GOVERNANCE_ROOT_CA_PATH}" \
    "execution-governance root CA" || return 1
}

remote_alpha_es_config_tls_prep_service_meta() {
  local service_name=$1
  local unit_name="${service_name}"
  if [[ "${unit_name}" != *.service ]]; then
    unit_name="${unit_name}.service"
  fi

  python3 - "${service_name}" \
    "$(systemctl show "${unit_name}" -p User -p Group -p ExecStart -p FragmentPath -p ActiveState -p SubState 2>/dev/null || true)" \
    "$(remote_alpha_es_config_tls_prep_systemctl_state is-enabled "${unit_name}")" <<'PY'
import json
import sys

service_name = sys.argv[1]
show_output = sys.argv[2]
enabled = sys.argv[3].strip() == "true"

values = {
    "service": service_name,
    "user": "",
    "group": "",
    "exec_start": "",
    "fragment_path": "",
    "active": False,
    "active_state": "",
    "enabled": enabled,
    "sub_state": "",
    "effective_user": "root(default)",
    "effective_group": "root(default)",
}

for raw in show_output.splitlines():
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

print(json.dumps(values, sort_keys=True))
PY
}

remote_alpha_es_config_tls_prep_health_probe_meta() {
  local url=$1
  local health_env_meta_path=$2
  local response_path=$3
  local error_path=$4
  local dependency_field=$5
  local ca_cert operator_cert operator_key

  ca_cert="$(remote_alpha_es_config_tls_prep_json_field "${health_env_meta_path}" "ca_cert")"
  operator_cert="$(remote_alpha_es_config_tls_prep_json_field "${health_env_meta_path}" "operator_cert")"
  operator_key="$(remote_alpha_es_config_tls_prep_json_field "${health_env_meta_path}" "operator_key")"

  if ! curl --fail-with-body --silent --show-error \
    --cacert "${ca_cert}" \
    --cert "${operator_cert}" \
    --key "${operator_key}" \
    "${url}" >"${response_path}" 2>"${error_path}"; then
    python3 - "${url}" "${error_path}" <<'PY'
import json
import pathlib
import sys

print(json.dumps({
    "status": "fail",
    "url": sys.argv[1],
    "error": pathlib.Path(sys.argv[2]).read_text(encoding="utf-8", errors="replace").strip(),
}, sort_keys=True))
PY
    return 1
  fi

  python3 - "${url}" "${response_path}" "${dependency_field}" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
dependencies = ((payload.get("additional_properties") or {}).get("dependencies") or {})
dependency_field = sys.argv[3].strip()
result = {
    "status": "pass" if payload.get("ready") is True and payload.get("status") == "healthy" else "fail",
    "url": sys.argv[1],
    "ready": payload.get("ready") is True,
    "service": payload.get("service", ""),
}
if dependency_field:
    result[f"dependency_{dependency_field}"] = dependencies.get(dependency_field, "")
print(json.dumps(result, sort_keys=True))
PY
  return 0
}

remote_alpha_es_config_tls_prep_contract_probe_meta() {
  local runtime_meta_path=$1
  local health_env_meta_path=$2
  local response_path=$3
  local error_path=$4
  local url ca_cert operator_cert operator_key

  url="$(remote_alpha_es_config_tls_prep_json_field "${runtime_meta_path}" "contract_url")"
  ca_cert="$(remote_alpha_es_config_tls_prep_json_field "${health_env_meta_path}" "ca_cert")"
  operator_cert="$(remote_alpha_es_config_tls_prep_json_field "${health_env_meta_path}" "operator_cert")"
  operator_key="$(remote_alpha_es_config_tls_prep_json_field "${health_env_meta_path}" "operator_key")"

  if ! curl --fail-with-body --silent --show-error \
    --cacert "${ca_cert}" \
    --cert "${operator_cert}" \
    --key "${operator_key}" \
    "${url}" >"${response_path}" 2>"${error_path}"; then
    python3 - "${url}" "${error_path}" <<'PY'
import json
import pathlib
import sys

print(json.dumps({
    "status": "fail",
    "url": sys.argv[1],
    "error": pathlib.Path(sys.argv[2]).read_text(encoding="utf-8", errors="replace").strip(),
}, sort_keys=True))
PY
    return 1
  fi

  python3 - "${url}" "${response_path}" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
governed = payload.get("governed_execution") or {}
status = "pass"
if payload.get("schema_version") != "execution-substrate.producer-contract/v1":
    status = "fail"
if payload.get("service") != "execution":
    status = "fail"
if governed.get("contract") != "governed-execution-producer/v1":
    status = "fail"
if governed.get("enabled") is not True:
    status = "fail"
print(json.dumps({
    "status": status,
    "url": sys.argv[1],
    "schema_version": payload.get("schema_version", ""),
    "service": payload.get("service", ""),
    "governed_execution_contract": governed.get("contract", ""),
    "governed_execution_enabled": governed.get("enabled"),
}, sort_keys=True))
PY
  return 0
}

remote_alpha_es_config_tls_prep_ownership_meta() {
  local runtime_meta_path=$1
  local mode="${2:-validate}"
  local config_path tls_dir
  config_path="$(remote_alpha_es_config_tls_prep_json_field "${runtime_meta_path}" "config_path")"
  tls_dir="${REMOTE_ALPHA_TLS_DIR}"

  python3 - \
    "${mode}" \
    "${config_path}" "root:${REMOTE_ALPHA_PREP_GROUP}" "0640" "$(stat -c '%U:%G %a %n' "${config_path}" 2>/dev/null || true)" \
    "${tls_dir}" "root:${REMOTE_ALPHA_PREP_GROUP}" "0710" "$(stat -c '%U:%G %a %n' "${tls_dir}" 2>/dev/null || true)" \
    "${REMOTE_ALPHA_SERVER_CERT_PATH}" "root:${REMOTE_ALPHA_PREP_GROUP}" "0640" "$(stat -c '%U:%G %a %n' "${REMOTE_ALPHA_SERVER_CERT_PATH}" 2>/dev/null || true)" \
    "${REMOTE_ALPHA_SERVER_KEY_PATH}" "root:${REMOTE_ALPHA_PREP_GROUP}" "0640" "$(stat -c '%U:%G %a %n' "${REMOTE_ALPHA_SERVER_KEY_PATH}" 2>/dev/null || true)" \
    "${REMOTE_ALPHA_SERVER_CLIENT_CA_PATH}" "root:${REMOTE_ALPHA_PREP_GROUP}" "0640" "$(stat -c '%U:%G %a %n' "${REMOTE_ALPHA_SERVER_CLIENT_CA_PATH}" 2>/dev/null || true)" \
    "${REMOTE_ALPHA_ARTIFACT_REGISTRY_CLIENT_CERT_PATH}" "root:${REMOTE_ALPHA_PREP_GROUP}" "0640" "$(stat -c '%U:%G %a %n' "${REMOTE_ALPHA_ARTIFACT_REGISTRY_CLIENT_CERT_PATH}" 2>/dev/null || true)" \
    "${REMOTE_ALPHA_ARTIFACT_REGISTRY_CLIENT_KEY_PATH}" "root:${REMOTE_ALPHA_PREP_GROUP}" "0640" "$(stat -c '%U:%G %a %n' "${REMOTE_ALPHA_ARTIFACT_REGISTRY_CLIENT_KEY_PATH}" 2>/dev/null || true)" \
    "${REMOTE_ALPHA_ARTIFACT_REGISTRY_ROOT_CA_PATH}" "root:${REMOTE_ALPHA_PREP_GROUP}" "0640" "$(stat -c '%U:%G %a %n' "${REMOTE_ALPHA_ARTIFACT_REGISTRY_ROOT_CA_PATH}" 2>/dev/null || true)" \
    "${REMOTE_ALPHA_EXECUTION_GOVERNANCE_CLIENT_CERT_PATH}" "root:${REMOTE_ALPHA_PREP_GROUP}" "0640" "$(stat -c '%U:%G %a %n' "${REMOTE_ALPHA_EXECUTION_GOVERNANCE_CLIENT_CERT_PATH}" 2>/dev/null || true)" \
    "${REMOTE_ALPHA_EXECUTION_GOVERNANCE_CLIENT_KEY_PATH}" "root:${REMOTE_ALPHA_PREP_GROUP}" "0640" "$(stat -c '%U:%G %a %n' "${REMOTE_ALPHA_EXECUTION_GOVERNANCE_CLIENT_KEY_PATH}" 2>/dev/null || true)" \
    "${REMOTE_ALPHA_EXECUTION_GOVERNANCE_ROOT_CA_PATH}" "root:${REMOTE_ALPHA_PREP_GROUP}" "0640" "$(stat -c '%U:%G %a %n' "${REMOTE_ALPHA_EXECUTION_GOVERNANCE_ROOT_CA_PATH}" 2>/dev/null || true)" <<'PY'
import json
import sys

mode = sys.argv[1].strip() or "validate"

def normalize_mode(mode: str) -> str:
    mode = (mode or "").strip()
    if not mode:
        return ""
    return mode.zfill(4)


items = []
overall_ok = True
args = sys.argv[2:]
for i in range(0, len(args), 4):
    path = args[i]
    expected_owner = args[i + 1]
    expected_mode = normalize_mode(args[i + 2])
    stat_output = args[i + 3].strip()
    actual_owner = ""
    actual_mode = ""
    if stat_output:
        parts = stat_output.split()
        if len(parts) >= 2:
            actual_owner = parts[0]
            actual_mode = normalize_mode(parts[1])
    matches_expected = actual_owner == expected_owner and actual_mode == expected_mode
    if mode == "inspect":
        status = "matches" if matches_expected else "needs_change"
    else:
        status = "pass" if matches_expected else "fail"
    if not matches_expected:
        overall_ok = False
    items.append({
        "path": path,
        "expected_owner": expected_owner,
        "expected_mode": expected_mode,
        "actual_owner": actual_owner,
        "actual_mode": actual_mode,
        "change_required": not matches_expected,
        "status": status,
    })

print(json.dumps({
    "status": ("pass" if overall_ok else "needs_change") if mode == "inspect" else ("pass" if overall_ok else "fail"),
    "inspection_mode": mode,
    "items": items,
}, sort_keys=True))
PY
}

remote_alpha_es_config_tls_prep_write_summary() {
  local summary_path=$1
  local source_runtime_meta_path=$2
  local runtime_meta_path=$3
  local health_env_meta_path=$4
  local es_meta_path=$5
  local ags_meta_path=$6
  local ars_meta_path=$7
  local egs_meta_path=$8
  local es_health_meta_path=$9
  local es_contract_meta_path=${10}
  local ownership_meta_path=${11}
  local service_account_meta_path=${12}
  local pre_service_account_meta_path=${13}
  local rewrite_scope_meta_path=${14}
  local ds_not_in_docker_group=${15}
  local passwordless_sudo_for_ds=${16}
  local operation_mode=${17}
  local planned_summary_path=${18}
  local healthcheck_env_path=${19}
  local service_unit_path=${20}
  local pre_service_meta_path=${21}
  local backup_meta_path=${22}
  local backup_parent_dir=${23}

  python3 - "${summary_path}" \
    "${source_runtime_meta_path}" \
    "${runtime_meta_path}" \
    "${health_env_meta_path}" \
    "${es_meta_path}" \
    "${ags_meta_path}" \
    "${ars_meta_path}" \
    "${egs_meta_path}" \
    "${es_health_meta_path}" \
    "${es_contract_meta_path}" \
    "${ownership_meta_path}" \
    "${service_account_meta_path}" \
    "${pre_service_account_meta_path}" \
    "${rewrite_scope_meta_path}" \
    "${ds_not_in_docker_group}" \
    "${passwordless_sudo_for_ds}" \
    "${operation_mode}" \
    "${planned_summary_path}" \
    "${healthcheck_env_path}" \
    "${service_unit_path}" \
    "${pre_service_meta_path}" \
    "${backup_meta_path}" \
    "${backup_parent_dir}" \
    "${REMOTE_ALPHA_PREP_USER}" \
    "${REMOTE_ALPHA_PREP_GROUP}" \
    "${remote_alpha_es_config_tls_prep_summary_schema_version}" <<'PY'
import ipaddress
import json
import pathlib
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

summary_path = pathlib.Path(sys.argv[1])
source_runtime = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
runtime = json.loads(pathlib.Path(sys.argv[3]).read_text(encoding="utf-8"))
health_env = json.loads(pathlib.Path(sys.argv[4]).read_text(encoding="utf-8"))
es_meta = json.loads(pathlib.Path(sys.argv[5]).read_text(encoding="utf-8"))
ags_meta = json.loads(pathlib.Path(sys.argv[6]).read_text(encoding="utf-8"))
ars_meta = json.loads(pathlib.Path(sys.argv[7]).read_text(encoding="utf-8"))
egs_meta = json.loads(pathlib.Path(sys.argv[8]).read_text(encoding="utf-8"))
es_health = json.loads(pathlib.Path(sys.argv[9]).read_text(encoding="utf-8"))
es_contract = json.loads(pathlib.Path(sys.argv[10]).read_text(encoding="utf-8"))
ownership = json.loads(pathlib.Path(sys.argv[11]).read_text(encoding="utf-8"))
service_account = json.loads(pathlib.Path(sys.argv[12]).read_text(encoding="utf-8"))
pre_service_account = json.loads(pathlib.Path(sys.argv[13]).read_text(encoding="utf-8"))
rewrite_scope = json.loads(pathlib.Path(sys.argv[14]).read_text(encoding="utf-8"))
ds_not_in_docker_group = sys.argv[15]
passwordless_sudo_for_ds = sys.argv[16]
operation_mode = sys.argv[17].strip()
planned_summary_path = sys.argv[18].strip()
healthcheck_env_path = sys.argv[19].strip()
service_unit_path = sys.argv[20].strip()
pre_es_meta = json.loads(pathlib.Path(sys.argv[21]).read_text(encoding="utf-8"))
backup_meta_path = pathlib.Path(sys.argv[22].strip()) if sys.argv[22].strip() else None
backup_parent_dir = sys.argv[23].strip()
prep_user = sys.argv[24]
prep_group = sys.argv[25]
schema_version = sys.argv[26]
non_mutating = operation_mode == "check_only"


def url_host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").strip()
    except Exception:
        return ""


def is_loopback_host(host: str) -> bool:
    normalized = (host or "").strip().lower()
    if not normalized:
        return True
    if normalized == "localhost" or normalized.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def unique_strings(items):
    values = []
    for item in items:
        item = str(item or "").strip()
        if item and item not in values:
            values.append(item)
    return values


direct_https_urls = {
    "es_health": es_health.get("url", ""),
    "es_contract": es_contract.get("url", ""),
}
direct_https_hosts = {name: url_host(url) for name, url in direct_https_urls.items()}
direct_https_probe_statuses = {
    "es_health": es_health.get("status", ""),
    "es_contract": es_contract.get("status", ""),
}
direct_https_inferred = all(
    str(url).startswith("https://") for url in direct_https_urls.values()
) and all(
    not is_loopback_host(host) for host in direct_https_hosts.values()
) and all(
    status == "pass" for status in direct_https_probe_statuses.values()
)

if service_account.get("status") == "pass" and service_account.get("narrow_dedicated_account") is True:
    shared_unix_account_model = {
        "status": "derived",
        "value": False,
        "basis": "derived from validation.prep_account_narrowness",
        "primary_group": service_account.get("primary_group", ""),
        "supplementary_groups": service_account.get("supplementary_groups") or [],
    }
else:
    shared_unix_account_model = {
        "status": "not_proven",
        "value": None,
        "basis": "prep-account narrowness was not proved by validation.prep_account_narrowness",
        "primary_group": service_account.get("primary_group", ""),
        "supplementary_groups": service_account.get("supplementary_groups") or [],
    }

tls_files = [
    {
        "path": runtime["tls"]["cert_file"],
        "owner": f"root:{prep_group}",
        "mode": "0640",
    },
    {
        "path": runtime["tls"]["key_file"],
        "owner": f"root:{prep_group}",
        "mode": "0640",
    },
    {
        "path": runtime["tls"]["client_ca_file"],
        "owner": f"root:{prep_group}",
        "mode": "0640",
    },
    {
        "path": runtime["artifact_registry"]["client_cert_file"],
        "owner": f"root:{prep_group}",
        "mode": "0640",
    },
    {
        "path": runtime["artifact_registry"]["client_key_file"],
        "owner": f"root:{prep_group}",
        "mode": "0640",
    },
    {
        "path": runtime["artifact_registry"]["root_ca_file"],
        "owner": f"root:{prep_group}",
        "mode": "0640",
    },
    {
        "path": runtime["execution_governance"]["client_cert_file"],
        "owner": f"root:{prep_group}",
        "mode": "0640",
    },
    {
        "path": runtime["execution_governance"]["client_key_file"],
        "owner": f"root:{prep_group}",
        "mode": "0640",
    },
    {
        "path": runtime["execution_governance"]["root_ca_file"],
        "owner": f"root:{prep_group}",
        "mode": "0640",
    },
]

ownership_changes = []
for item in ownership.get("items") or []:
    ownership_changes.append({
        "path": item.get("path", ""),
        "current_owner": item.get("actual_owner", ""),
        "current_mode": item.get("actual_mode", ""),
        "planned_owner": item.get("expected_owner", ""),
        "planned_mode": item.get("expected_mode", ""),
        "change_required": item.get("change_required") is True,
        "status": item.get("status", ""),
    })

paths_read = unique_strings([
    source_runtime.get("binary_path", ""),
    source_runtime.get("config_path", ""),
    healthcheck_env_path,
    source_runtime.get("tls", {}).get("cert_file", ""),
    source_runtime.get("tls", {}).get("key_file", ""),
    source_runtime.get("tls", {}).get("client_ca_file", ""),
    source_runtime.get("artifact_registry", {}).get("client_cert_file", ""),
    source_runtime.get("artifact_registry", {}).get("client_key_file", ""),
    source_runtime.get("artifact_registry", {}).get("root_ca_file", ""),
    source_runtime.get("execution_governance", {}).get("client_cert_file", ""),
    source_runtime.get("execution_governance", {}).get("client_key_file", ""),
    source_runtime.get("execution_governance", {}).get("root_ca_file", ""),
    health_env.get("ca_cert", ""),
    health_env.get("operator_cert", ""),
    health_env.get("operator_key", ""),
    service_unit_path,
    *[item.get("path", "") for item in ownership.get("items") or []],
])

paths_written = unique_strings([
    runtime.get("config_path", ""),
    *[item.get("path", "") for item in ownership.get("items") or []],
    planned_summary_path,
])

service_identity_root_default = pre_es_meta.get("effective_user") == "root(default)" and pre_es_meta.get("effective_group") == "root(default)"
post_service_identity_root_default = es_meta.get("effective_user") == "root(default)" and es_meta.get("effective_group") == "root(default)"

backup = {
    "status": "not_run" if non_mutating else "not_created",
    "created": False,
    "parent_dir": backup_parent_dir,
    "path": "",
    "pre_apply_config_copy": "",
    "snapshot_manifest_path": "",
    "pre_apply_source_tls": [],
    "pre_apply_prep_account": {
        "user": prep_user,
        "group": prep_group,
        "status": pre_service_account.get("status", ""),
        "user_exists": pre_service_account.get("user_exists") is True,
        "group_exists": pre_service_account.get("group_exists") is True,
        "would_create_user": pre_service_account.get("would_create_user") is True,
        "would_create_group": pre_service_account.get("would_create_group") is True,
    },
    "pre_apply_service": {
        "name": pre_es_meta.get("service", "es"),
        "user": pre_es_meta.get("user", ""),
        "group": pre_es_meta.get("group", ""),
        "effective_user": pre_es_meta.get("effective_user", ""),
        "effective_group": pre_es_meta.get("effective_group", ""),
        "active_state": pre_es_meta.get("active_state", ""),
        "sub_state": pre_es_meta.get("sub_state", ""),
    },
    "rollback_notes": [],
}
if backup_meta_path is not None and backup_meta_path.exists():
    backup = json.loads(backup_meta_path.read_text(encoding="utf-8"))

warnings = []
blockers = []

if ds_not_in_docker_group != "true":
    warnings.append("ds_not_in_docker_group could not be proved true for the current host posture")
if passwordless_sudo_for_ds != "false":
    warnings.append("passwordless_sudo_for_ds could not be proved false for the current host posture")

if pre_service_account.get("blocker") is True or pre_service_account.get("status") == "fail":
    blockers.append(pre_service_account.get("error") or "ES prep account state is not acceptable for this slice")
if rewrite_scope.get("status") != "pass":
    blockers.append("planned ES config rewrite scope is broader than the allowed config/TLS path rewrite slice")
if not non_mutating and ownership.get("status") != "pass":
    blockers.append("applied ES config/TLS ownership does not match the required root:es ownership model")
if not service_identity_root_default:
    blockers.append("es.service does not currently resolve to root(default), so this slice would not preserve the required live service posture")
if es_health.get("status") != "pass":
    blockers.append("current ES /health probe did not pass")
if es_contract.get("status") != "pass":
    blockers.append("current ES producer-contract probe did not pass")

if blockers:
    result_status = "fail"
elif warnings:
    result_status = "warn"
else:
    result_status = "pass"

summary = {
    "schema_version": schema_version,
    "checked_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "mode": {
        "name": operation_mode,
        "non_mutating": non_mutating,
        "output": "stdout_json" if non_mutating else "summary_file",
    },
    "slice": {
        "name": "remote-alpha-es-config-tls-prep",
        "classification": "ownership_prep_slice",
        "not_a_new_happy_path_proof": True,
        "temporary_compatibility_edge": "live es.service stays root(default) while dedicated root:es readable config/TLS material is staged for a later ES de-root slice",
    },
    "service": {
        "name": "es",
        "live_user": es_meta["effective_user"],
        "live_group": es_meta["effective_group"],
        "binary_path": runtime["binary_path"],
        "config_path": runtime["config_path"],
        "health_url": runtime["health_url"],
        "contract_url": runtime["contract_url"],
        "active": es_meta["active"],
        "enabled": es_meta["enabled"],
        "fragment_path": es_meta["fragment_path"],
        "exec_start": es_meta["exec_start"],
    },
    "plan": {
        "paths_read": paths_read,
        "paths_written": paths_written,
        "ownership_changes": ownership_changes,
        "prep_account": {
            "user": prep_user,
            "group": prep_group,
            "user_exists": pre_service_account.get("user_exists") is True,
            "group_exists": pre_service_account.get("group_exists") is True,
            "exists": pre_service_account.get("narrow_dedicated_account") is True,
            "would_create_user": pre_service_account.get("would_create_user") is True,
            "would_create_group": pre_service_account.get("would_create_group") is True,
            "status": pre_service_account.get("status", ""),
            "apply_ready": pre_service_account.get("apply_ready") is True,
            "blocker": pre_service_account.get("blocker") is True,
        },
        "service_identity_would_remain_root_default": service_identity_root_default,
        "restart_required_in_apply_mode": True,
        "warnings": warnings,
        "blockers": blockers,
    },
    "backup": backup,
    "dependencies": {
        "server_tls": runtime["tls"],
        "artifact_registry": runtime["artifact_registry"],
        "execution_governance": runtime["execution_governance"],
        "local_state_paths": runtime["local_state_paths"],
        "log_sink": runtime["log_sink"],
    },
    "ownership_model": {
        "prep_account": {
            "user": prep_user,
            "group": prep_group,
            "primary_group": service_account.get("primary_group", ""),
            "supplementary_groups": service_account.get("supplementary_groups") or [],
            "narrow_dedicated_account": service_account.get("narrow_dedicated_account") is True,
        },
        "config_file": {
            "path": runtime["config_path"],
            "owner": f"root:{prep_group}",
            "mode": "0640",
        },
        "tls_directory": {
            "path": str(pathlib.Path(runtime["tls"]["cert_file"]).parent),
            "owner": f"root:{prep_group}",
            "mode": "0710",
        },
        "tls_files": tls_files,
        "live_service_posture": {
            "user": es_meta["effective_user"],
            "group": es_meta["effective_group"],
            "unchanged_root_default": service_identity_root_default and post_service_identity_root_default,
        },
        "writable_state": {
            "changed": False,
            "paths": runtime["local_state_paths"],
        },
    },
    "validation": {
        "local_es_health": es_health,
        "local_es_contract_probe": es_contract,
        "prep_account_narrowness": service_account,
        "ownership": ownership,
        "config_rewrite_scope": rewrite_scope,
        "ags_service_posture": ags_meta,
        "ars_service_posture": ars_meta,
        "egs_service_posture": egs_meta,
        "es_service_posture": es_meta,
    },
    "preserved_remote_path": {
        "direct_https_mtls": {
            "status": "inferred" if direct_https_inferred else "not_proven",
            "value": True if direct_https_inferred else None,
            "basis": "derived from current ES HTTPS endpoint config plus host-local HTTPS+mTLS probes; not a Mac-side reachability proof",
            "host_local_only": True,
            "urls": direct_https_urls,
            "hosts": direct_https_hosts,
            "probe_statuses": direct_https_probe_statuses,
        },
        "no_bridge": {
            "status": "operator_assertion",
            "value": True,
            "basis": "accepted Remote Supported-Host Alpha posture; this ES config/TLS prep helper does not validate transport topology directly",
        },
        "no_shared_filesystem": {
            "status": "operator_assertion",
            "value": True,
            "basis": "accepted Remote Supported-Host Alpha posture; this ES config/TLS prep helper does not validate Mac/remote filesystem separation directly",
        },
        "es_health_path": es_health.get("url", ""),
        "es_contract_path": es_contract.get("url", ""),
    },
    "security": {
        "ds_not_in_docker_group": ds_not_in_docker_group,
        "passwordless_sudo_for_ds": passwordless_sudo_for_ds,
        "secret_material_in_summary": False,
        "shared_unix_account_model_introduced": shared_unix_account_model,
    },
    "not_claimed": {
        "es_de_root": "not_claimed",
        "es_public_contract_changes": "not_claimed",
        "spire_selector_model_changes": "not_claimed",
        "spire_socket_traversal_changes": "not_claimed",
        "nomad_task_user_model_changes": "not_claimed",
        "vault_runtime_helper_changes": "not_claimed",
        "staging_or_results_ownership_changes": "not_claimed",
        "new_remote_happy_path_proof": "not_claimed",
    },
    "result": {
        "status": result_status,
        "ok": not blockers,
        "non_mutating": non_mutating,
    },
}

summary_path.parent.mkdir(parents=True, exist_ok=True)
summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

remote_alpha_es_config_tls_prep_main() {
  local source_config_copy_path source_runtime_meta_path runtime_meta_path health_env_meta_path
  local es_meta_path pre_es_meta_path ags_meta_path ars_meta_path egs_meta_path
  local planned_config_path check_only_report_path
  local es_health_result_path es_health_error_path
  local es_contract_result_path es_contract_error_path
  local es_health_meta_path es_contract_meta_path
  local ownership_meta_path service_account_meta_path pre_service_account_meta_path rewrite_scope_meta_path
  local backup_meta_path
  local tmpdir=""
  local ds_not_in_docker_group=""
  local passwordless_sudo_for_ds=""
  local service_account_status=""
  local check_only_ok=""
  local overall_ok=true

  remote_alpha_es_config_tls_prep_require_pinned_slice_inputs || return 1
  remote_alpha_es_config_tls_prep_defaults
  remote_alpha_es_config_tls_prep_parse_args "$@" || return $?
  remote_alpha_es_config_tls_prep_require_root || return 1

  remote_alpha_es_config_tls_prep_require_command python3 || return 1
  remote_alpha_prepare_output_dir "$(dirname "${REMOTE_ALPHA_SUMMARY_PATH}")" || return 1
  remote_alpha_prepare_output_dir "${remote_alpha_es_config_tls_prep_backup_root_dir}" || return 1
  remote_alpha_es_config_tls_prep_require_command curl || return 1
  remote_alpha_es_config_tls_prep_require_command systemctl || return 1
  remote_alpha_es_config_tls_prep_require_command getent || return 1
  remote_alpha_es_config_tls_prep_require_command stat || return 1
  if [[ "${REMOTE_ALPHA_OPERATION_MODE}" != "check_only" ]]; then
    remote_alpha_es_config_tls_prep_require_command groupadd || return 1
    remote_alpha_es_config_tls_prep_require_command useradd || return 1
    remote_alpha_es_config_tls_prep_require_command chown || return 1
    remote_alpha_es_config_tls_prep_require_command chmod || return 1
  fi

  tmpdir="$(mktemp -d)"
  trap "rm -rf -- '${tmpdir}'" EXIT

  source_config_copy_path="${tmpdir}/source-es-config.json"
  source_runtime_meta_path="${tmpdir}/source-runtime.json"
  runtime_meta_path="${tmpdir}/runtime.json"
  planned_config_path="${tmpdir}/planned-es-config.json"
  health_env_meta_path="${tmpdir}/health-env.json"
  es_meta_path="${tmpdir}/es-service.json"
  pre_es_meta_path="${tmpdir}/pre-es-service.json"
  ags_meta_path="${tmpdir}/ags-service.json"
  ars_meta_path="${tmpdir}/ars-service.json"
  egs_meta_path="${tmpdir}/egs-service.json"
  es_health_result_path="${tmpdir}/es-health-response.json"
  es_health_error_path="${tmpdir}/es-health-error.txt"
  es_health_meta_path="${tmpdir}/es-health-meta.json"
  es_contract_result_path="${tmpdir}/es-contract-response.json"
  es_contract_error_path="${tmpdir}/es-contract-error.txt"
  es_contract_meta_path="${tmpdir}/es-contract-meta.json"
  ownership_meta_path="${tmpdir}/ownership.json"
  service_account_meta_path="${tmpdir}/service-account.json"
  pre_service_account_meta_path="${tmpdir}/pre-service-account.json"
  rewrite_scope_meta_path="${tmpdir}/rewrite-scope.json"
  check_only_report_path="${tmpdir}/check-only-report.json"
  backup_meta_path="${tmpdir}/backup.json"

  remote_alpha_es_config_tls_prep_runtime_meta >"${source_runtime_meta_path}"
  if [[ "$(remote_alpha_es_config_tls_prep_json_field "${source_runtime_meta_path}" "status" 2>/dev/null || true)" != "pass" ]]; then
    cat "${source_runtime_meta_path}" >&2
    return 1
  fi

  remote_alpha_es_config_tls_prep_health_env_meta >"${health_env_meta_path}"
  if [[ "$(remote_alpha_es_config_tls_prep_json_field "${health_env_meta_path}" "status" 2>/dev/null || true)" != "pass" ]]; then
    cat "${health_env_meta_path}" >&2
    return 1
  fi

  remote_alpha_es_config_tls_prep_verify_runtime_paths "${source_runtime_meta_path}" "${health_env_meta_path}" || return 1
  remote_alpha_es_config_tls_prep_assert_unit_execstart || return 1
  remote_alpha_es_config_tls_prep_capture_config_copy "${REMOTE_ALPHA_CONFIG_PATH}" "${source_config_copy_path}"

  remote_alpha_es_config_tls_prep_service_account_meta >"${pre_service_account_meta_path}"
  service_account_status="$(remote_alpha_es_config_tls_prep_json_field "${pre_service_account_meta_path}" "status" 2>/dev/null || true)"
  if [[ "${REMOTE_ALPHA_OPERATION_MODE}" != "check_only" && "${service_account_status}" == "fail" ]]; then
    cat "${pre_service_account_meta_path}" >&2
    return 1
  fi

  remote_alpha_es_config_tls_prep_service_meta "${REMOTE_ALPHA_SERVICE_NAME}" >"${pre_es_meta_path}"

  remote_alpha_es_config_tls_prep_render_rewritten_config "${REMOTE_ALPHA_CONFIG_PATH}" "${planned_config_path}" || return 1
  remote_alpha_es_config_tls_prep_runtime_meta "${planned_config_path}" "${REMOTE_ALPHA_CONFIG_PATH}" >"${runtime_meta_path}"
  if [[ "$(remote_alpha_es_config_tls_prep_json_field "${runtime_meta_path}" "status" 2>/dev/null || true)" != "pass" ]]; then
    cat "${runtime_meta_path}" >&2
    return 1
  fi
  remote_alpha_es_config_tls_prep_assert_dedicated_runtime_paths "${runtime_meta_path}" || return 1
  remote_alpha_es_config_tls_prep_config_rewrite_scope_meta "${source_config_copy_path}" "${planned_config_path}" >"${rewrite_scope_meta_path}"

  if [[ "${REMOTE_ALPHA_OPERATION_MODE}" == "check_only" ]]; then
    remote_alpha_es_config_tls_prep_service_meta "${REMOTE_ALPHA_SERVICE_NAME}" >"${es_meta_path}"
    remote_alpha_es_config_tls_prep_service_meta "ags" >"${ags_meta_path}"
    remote_alpha_es_config_tls_prep_service_meta "ars" >"${ars_meta_path}"
    remote_alpha_es_config_tls_prep_service_meta "egs" >"${egs_meta_path}"

    remote_alpha_es_config_tls_prep_health_probe_meta \
      "$(remote_alpha_es_config_tls_prep_json_field "${source_runtime_meta_path}" "health_url" 2>/dev/null || true)" \
      "${health_env_meta_path}" \
      "${es_health_result_path}" \
      "${es_health_error_path}" \
      "artifact_registry" >"${es_health_meta_path}" || true

    remote_alpha_es_config_tls_prep_contract_probe_meta \
      "${source_runtime_meta_path}" \
      "${health_env_meta_path}" \
      "${es_contract_result_path}" \
      "${es_contract_error_path}" >"${es_contract_meta_path}" || true

    remote_alpha_es_config_tls_prep_ownership_meta "${runtime_meta_path}" inspect >"${ownership_meta_path}"

    ds_not_in_docker_group="$(remote_alpha_es_config_tls_prep_ds_not_in_docker_group)"
    passwordless_sudo_for_ds="$(remote_alpha_es_config_tls_prep_passwordless_sudo_for_ds)"

    remote_alpha_es_config_tls_prep_write_summary \
      "${check_only_report_path}" \
      "${source_runtime_meta_path}" \
      "${runtime_meta_path}" \
      "${health_env_meta_path}" \
      "${es_meta_path}" \
      "${ags_meta_path}" \
      "${ars_meta_path}" \
      "${egs_meta_path}" \
      "${es_health_meta_path}" \
      "${es_contract_meta_path}" \
      "${ownership_meta_path}" \
      "${pre_service_account_meta_path}" \
      "${pre_service_account_meta_path}" \
      "${rewrite_scope_meta_path}" \
      "${ds_not_in_docker_group}" \
      "${passwordless_sudo_for_ds}" \
      "${REMOTE_ALPHA_OPERATION_MODE}" \
      "${REMOTE_ALPHA_SUMMARY_PATH}" \
      "${REMOTE_ALPHA_HEALTHCHECK_ENV_PATH}" \
      "${REMOTE_ALPHA_SERVICE_UNIT_PATH}" \
      "${pre_es_meta_path}" \
      "" \
      "${remote_alpha_es_config_tls_prep_backup_root_dir}"

    cat "${check_only_report_path}"
    check_only_ok="$(remote_alpha_es_config_tls_prep_json_field "${check_only_report_path}" "result.ok" 2>/dev/null || true)"
    if [[ "${check_only_ok}" != "true" ]]; then
      return 1
    fi
    return 0
  fi

  remote_alpha_es_config_tls_prep_create_backup_snapshot \
    "${backup_meta_path}" \
    "${source_runtime_meta_path}" \
    "${REMOTE_ALPHA_CONFIG_PATH}" \
    "${pre_service_account_meta_path}" \
    "${pre_es_meta_path}" || return 1

  remote_alpha_es_config_tls_prep_ensure_group || return 1
  remote_alpha_es_config_tls_prep_ensure_user || return 1
  remote_alpha_es_config_tls_prep_service_account_meta >"${service_account_meta_path}"
  if [[ "$(remote_alpha_es_config_tls_prep_json_field "${service_account_meta_path}" "status" 2>/dev/null || true)" != "pass" ]]; then
    cat "${service_account_meta_path}" >&2
    return 1
  fi

  remote_alpha_es_config_tls_prep_prepare_tls_material "${source_runtime_meta_path}" || return 1
  remote_alpha_es_config_tls_prep_rewrite_config || return 1

  remote_alpha_es_config_tls_prep_runtime_meta >"${runtime_meta_path}"
  if [[ "$(remote_alpha_es_config_tls_prep_json_field "${runtime_meta_path}" "status" 2>/dev/null || true)" != "pass" ]]; then
    cat "${runtime_meta_path}" >&2
    return 1
  fi
  remote_alpha_es_config_tls_prep_assert_dedicated_runtime_paths "${runtime_meta_path}" || return 1

  remote_alpha_es_config_tls_prep_config_rewrite_scope_meta "${source_config_copy_path}" "${REMOTE_ALPHA_CONFIG_PATH}" >"${rewrite_scope_meta_path}"
  if [[ "$(remote_alpha_es_config_tls_prep_json_field "${rewrite_scope_meta_path}" "status" 2>/dev/null || true)" != "pass" ]]; then
    overall_ok=false
  fi

  systemctl restart "${REMOTE_ALPHA_SERVICE_NAME}.service" || overall_ok=false

  remote_alpha_es_config_tls_prep_service_meta "${REMOTE_ALPHA_SERVICE_NAME}" >"${es_meta_path}"
  remote_alpha_es_config_tls_prep_service_meta "ags" >"${ags_meta_path}"
  remote_alpha_es_config_tls_prep_service_meta "ars" >"${ars_meta_path}"
  remote_alpha_es_config_tls_prep_service_meta "egs" >"${egs_meta_path}"

  if [[ "$(remote_alpha_es_config_tls_prep_json_field "${es_meta_path}" "effective_user" 2>/dev/null || true)" != "root(default)" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_es_config_tls_prep_json_field "${es_meta_path}" "effective_group" 2>/dev/null || true)" != "root(default)" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_es_config_tls_prep_json_field "${es_meta_path}" "active" 2>/dev/null || true)" != "true" ]]; then
    overall_ok=false
  fi

  remote_alpha_es_config_tls_prep_health_probe_meta \
    "$(remote_alpha_es_config_tls_prep_json_field "${runtime_meta_path}" "health_url" 2>/dev/null || true)" \
    "${health_env_meta_path}" \
    "${es_health_result_path}" \
    "${es_health_error_path}" \
    "artifact_registry" >"${es_health_meta_path}" || overall_ok=false

  remote_alpha_es_config_tls_prep_contract_probe_meta \
    "${runtime_meta_path}" \
    "${health_env_meta_path}" \
    "${es_contract_result_path}" \
    "${es_contract_error_path}" >"${es_contract_meta_path}" || overall_ok=false

  if [[ "$(remote_alpha_es_config_tls_prep_json_field "${es_health_meta_path}" "status" 2>/dev/null || true)" != "pass" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_es_config_tls_prep_json_field "${es_contract_meta_path}" "status" 2>/dev/null || true)" != "pass" ]]; then
    overall_ok=false
  fi

  remote_alpha_es_config_tls_prep_ownership_meta "${runtime_meta_path}" >"${ownership_meta_path}"
  if [[ "$(remote_alpha_es_config_tls_prep_json_field "${ownership_meta_path}" "status" 2>/dev/null || true)" != "pass" ]]; then
    overall_ok=false
  fi

  ds_not_in_docker_group="$(remote_alpha_es_config_tls_prep_ds_not_in_docker_group)"
  passwordless_sudo_for_ds="$(remote_alpha_es_config_tls_prep_passwordless_sudo_for_ds)"
  # Record broader host-posture facts in the summary, but do not make them a
  # correctness precondition for this ES config/TLS ownership prep slice.

  remote_alpha_es_config_tls_prep_write_summary \
    "${REMOTE_ALPHA_SUMMARY_PATH}" \
    "${source_runtime_meta_path}" \
    "${runtime_meta_path}" \
    "${health_env_meta_path}" \
    "${es_meta_path}" \
    "${ags_meta_path}" \
    "${ars_meta_path}" \
    "${egs_meta_path}" \
    "${es_health_meta_path}" \
    "${es_contract_meta_path}" \
    "${ownership_meta_path}" \
    "${service_account_meta_path}" \
    "${pre_service_account_meta_path}" \
    "${rewrite_scope_meta_path}" \
    "${ds_not_in_docker_group}" \
    "${passwordless_sudo_for_ds}" \
    "${REMOTE_ALPHA_OPERATION_MODE}" \
    "${REMOTE_ALPHA_SUMMARY_PATH}" \
    "${REMOTE_ALPHA_HEALTHCHECK_ENV_PATH}" \
    "${REMOTE_ALPHA_SERVICE_UNIT_PATH}" \
    "${pre_es_meta_path}" \
    "${backup_meta_path}" \
    "${remote_alpha_es_config_tls_prep_backup_root_dir}"

  chmod 0644 "${REMOTE_ALPHA_SUMMARY_PATH}" 2>/dev/null || true

  if [[ "${overall_ok}" != "true" ]]; then
    echo "remote alpha ES config/TLS prep finished with validation failures; see ${REMOTE_ALPHA_SUMMARY_PATH}" >&2
    return 1
  fi

  printf '%s\n' "${REMOTE_ALPHA_SUMMARY_PATH}"
}
