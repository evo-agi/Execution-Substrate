if [[ -z "${REPO_ROOT:-}" ]]; then
  REMOTE_ALPHA_ARS_HARDENING_HELPER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  REPO_ROOT="$(cd "${REMOTE_ALPHA_ARS_HARDENING_HELPER_DIR}/../.." && pwd)"
fi

remote_alpha_ars_hardening_summary_schema_version="execution-substrate.remote-alpha.ars-service-hardening-summary.v1"

# Copy of remote_alpha_prepare_output_dir from scripts/internal/remote_alpha_output_dir.sh,
# which explains it; TestRemoteAlphaOutputDirCopiesMatch keeps the two identical.
remote_alpha_prepare_output_dir() {
  python3 -I - "$1" <<'REMOTE_ALPHA_OUTPUT_DIR_PY'
import os
import stat
import sys

if not sys.argv[1]:
    sys.exit("remote alpha output folder: no folder given")
if ".." in sys.argv[1].split("/"):
    sys.exit(f"remote alpha output folder: {sys.argv[1]} has a '..' component; refusing to check a path that is not canonical")
# The path is checked as given, never normalized: dropping "link/.." would
# check another folder than the one a later write through the link reaches.
parts = [part for part in os.path.join(os.getcwd(), sys.argv[1]).split("/") if part not in ("", ".")]
trusted = {0, os.geteuid()}
if os.environ.get("SUDO_UID", "").isdigit():
    trusted.add(int(os.environ["SUDO_UID"]))
# O_PATH reads a folder's owner and mode without read permission on it, so a
# folder that root keeps private still passes and sudo can hand it over.
flags = getattr(os, "O_PATH", os.O_RDONLY) | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
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

remote_alpha_ars_hardening_init_expected_slice_inputs() {
  remote_alpha_ars_hardening_expected_service_name="${remote_alpha_ars_hardening_expected_service_name:-ars}"
  remote_alpha_ars_hardening_expected_service_user="${remote_alpha_ars_hardening_expected_service_user:-ars}"
  remote_alpha_ars_hardening_expected_service_group="${remote_alpha_ars_hardening_expected_service_group:-ars}"
  remote_alpha_ars_hardening_expected_binary_path="${remote_alpha_ars_hardening_expected_binary_path:-/usr/local/lib/execution-substrate/bin/ars}"
  remote_alpha_ars_hardening_expected_config_path="${remote_alpha_ars_hardening_expected_config_path:-/etc/execution-substrate/ars.json}"
  remote_alpha_ars_hardening_expected_healthcheck_env_path="${remote_alpha_ars_hardening_expected_healthcheck_env_path:-/etc/execution-substrate/healthcheck.env}"
  remote_alpha_ars_hardening_expected_service_unit_path="${remote_alpha_ars_hardening_expected_service_unit_path:-/etc/systemd/system/ars.service}"
  remote_alpha_ars_hardening_expected_service_dropin_dir="${remote_alpha_ars_hardening_expected_service_dropin_dir:-/etc/systemd/system/ars.service.d}"
  remote_alpha_ars_hardening_expected_service_dropin_path="${remote_alpha_ars_hardening_expected_service_dropin_path:-/etc/systemd/system/ars.service.d/10-account.conf}"
  remote_alpha_ars_hardening_expected_tls_dir="${remote_alpha_ars_hardening_expected_tls_dir:-/etc/execution-substrate/ars-tls}"
  remote_alpha_ars_hardening_expected_shared_tls_dir="${remote_alpha_ars_hardening_expected_shared_tls_dir:-/etc/execution-substrate/tls}"
  remote_alpha_ars_hardening_expected_ags_config_path="${remote_alpha_ars_hardening_expected_ags_config_path:-/etc/execution-substrate/ags.json}"
  remote_alpha_ars_hardening_expected_bind_address="${remote_alpha_ars_hardening_expected_bind_address:-127.0.0.1}"
  remote_alpha_ars_hardening_expected_port="${remote_alpha_ars_hardening_expected_port:-8442}"
  remote_alpha_ars_hardening_expected_storage_root_dir="${remote_alpha_ars_hardening_expected_storage_root_dir:-/var/lib/execution-substrate/ars/blobs}"
  remote_alpha_ars_hardening_expected_storage_index_file="${remote_alpha_ars_hardening_expected_storage_index_file:-/var/lib/execution-substrate/ars/index.json}"
}

remote_alpha_ars_hardening_defaults() {
  remote_alpha_ars_hardening_init_expected_slice_inputs
  REMOTE_ALPHA_SERVICE_NAME="${remote_alpha_ars_hardening_expected_service_name}"
  REMOTE_ALPHA_SERVICE_USER="${remote_alpha_ars_hardening_expected_service_user}"
  REMOTE_ALPHA_SERVICE_GROUP="${remote_alpha_ars_hardening_expected_service_group}"
  REMOTE_ALPHA_BINARY_PATH="${remote_alpha_ars_hardening_expected_binary_path}"
  REMOTE_ALPHA_CONFIG_PATH="${remote_alpha_ars_hardening_expected_config_path}"
  REMOTE_ALPHA_HEALTHCHECK_ENV_PATH="${remote_alpha_ars_hardening_expected_healthcheck_env_path}"
  REMOTE_ALPHA_SERVICE_UNIT_PATH="${remote_alpha_ars_hardening_expected_service_unit_path}"
  REMOTE_ALPHA_SERVICE_DROPIN_DIR="${remote_alpha_ars_hardening_expected_service_dropin_dir}"
  REMOTE_ALPHA_SERVICE_DROPIN_PATH="${remote_alpha_ars_hardening_expected_service_dropin_path}"
  REMOTE_ALPHA_TLS_DIR="${remote_alpha_ars_hardening_expected_tls_dir}"
  REMOTE_ALPHA_TLS_CERT_PATH="${REMOTE_ALPHA_TLS_DIR}/ars-server-cert.pem"
  REMOTE_ALPHA_TLS_KEY_PATH="${REMOTE_ALPHA_TLS_DIR}/ars-server-key.pem"
  REMOTE_ALPHA_TLS_CLIENT_CA_PATH="${REMOTE_ALPHA_TLS_DIR}/runtime-ca.pem"
  REMOTE_ALPHA_AGS_CONFIG_PATH="${remote_alpha_ars_hardening_expected_ags_config_path}"
  REMOTE_ALPHA_SUMMARY_PATH="${REMOTE_ALPHA_SUMMARY_PATH:-/var/tmp/execution-substrate-remote-alpha/ars-service-hardening-summary.json}"
  REMOTE_ALPHA_SUMMARY_DIR="$(dirname "${REMOTE_ALPHA_SUMMARY_PATH}")"
}

remote_alpha_ars_hardening_reject_slice_override_env() {
  local name=$1
  local expected=$2
  local actual=""

  actual="$(printenv "${name}" 2>/dev/null || true)"
  if [[ -z "${actual}" ]]; then
    return 0
  fi
  if [[ "${actual}" != "${expected}" ]]; then
    printf 'remote alpha ARS hardening does not accept %s override for this sealed ARS de-root step within the current AGS sealed + ARS de-root tranche; expected repo-owned value %q (got %q)\n' "${name}" "${expected}" "${actual}" >&2
    return 1
  fi
  return 0
}

remote_alpha_ars_hardening_require_pinned_slice_inputs() {
  remote_alpha_ars_hardening_init_expected_slice_inputs
  remote_alpha_ars_hardening_reject_slice_override_env "REMOTE_ALPHA_SERVICE_NAME" "${remote_alpha_ars_hardening_expected_service_name}" || return 1
  remote_alpha_ars_hardening_reject_slice_override_env "REMOTE_ALPHA_SERVICE_USER" "${remote_alpha_ars_hardening_expected_service_user}" || return 1
  remote_alpha_ars_hardening_reject_slice_override_env "REMOTE_ALPHA_SERVICE_GROUP" "${remote_alpha_ars_hardening_expected_service_group}" || return 1
  remote_alpha_ars_hardening_reject_slice_override_env "REMOTE_ALPHA_BINARY_PATH" "${remote_alpha_ars_hardening_expected_binary_path}" || return 1
  remote_alpha_ars_hardening_reject_slice_override_env "REMOTE_ALPHA_CONFIG_PATH" "${remote_alpha_ars_hardening_expected_config_path}" || return 1
  remote_alpha_ars_hardening_reject_slice_override_env "REMOTE_ALPHA_HEALTHCHECK_ENV_PATH" "${remote_alpha_ars_hardening_expected_healthcheck_env_path}" || return 1
  remote_alpha_ars_hardening_reject_slice_override_env "REMOTE_ALPHA_SERVICE_UNIT_PATH" "${remote_alpha_ars_hardening_expected_service_unit_path}" || return 1
  remote_alpha_ars_hardening_reject_slice_override_env "REMOTE_ALPHA_SERVICE_DROPIN_DIR" "${remote_alpha_ars_hardening_expected_service_dropin_dir}" || return 1
  remote_alpha_ars_hardening_reject_slice_override_env "REMOTE_ALPHA_SERVICE_DROPIN_PATH" "${remote_alpha_ars_hardening_expected_service_dropin_path}" || return 1
}

remote_alpha_ars_hardening_usage() {
  cat <<'EOF'
Usage:
  sudo scripts/remote_alpha_harden_ars_service.sh

Optional flags:
  --summary-path </path/to/ars-service-hardening-summary.json>
  --help
EOF
}

remote_alpha_ars_hardening_parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --service-name)
        echo "remote alpha ARS hardening does not accept --service-name for this sealed ARS de-root step within the current AGS sealed + ARS de-root tranche" >&2
        return 2
        ;;
      --service-user)
        echo "remote alpha ARS hardening does not accept --service-user for this sealed ARS de-root step within the current AGS sealed + ARS de-root tranche" >&2
        return 2
        ;;
      --service-group)
        echo "remote alpha ARS hardening does not accept --service-group for this sealed ARS de-root step within the current AGS sealed + ARS de-root tranche" >&2
        return 2
        ;;
      --binary-path)
        echo "remote alpha ARS hardening does not accept --binary-path for this sealed ARS de-root step within the current AGS sealed + ARS de-root tranche" >&2
        return 2
        ;;
      --config-path)
        echo "remote alpha ARS hardening does not accept --config-path for this sealed ARS de-root step within the current AGS sealed + ARS de-root tranche" >&2
        return 2
        ;;
      --healthcheck-env-path)
        echo "remote alpha ARS hardening does not accept --healthcheck-env-path for this sealed ARS de-root step within the current AGS sealed + ARS de-root tranche" >&2
        return 2
        ;;
      --service-unit-path)
        echo "remote alpha ARS hardening does not accept --service-unit-path for this sealed ARS de-root step within the current AGS sealed + ARS de-root tranche" >&2
        return 2
        ;;
      --service-dropin-dir)
        echo "remote alpha ARS hardening does not accept --service-dropin-dir for this sealed ARS de-root step within the current AGS sealed + ARS de-root tranche" >&2
        return 2
        ;;
      --service-dropin-path)
        echo "remote alpha ARS hardening does not accept --service-dropin-path for this sealed ARS de-root step within the current AGS sealed + ARS de-root tranche" >&2
        return 2
        ;;
      --summary-path)
        REMOTE_ALPHA_SUMMARY_PATH="$2"
        REMOTE_ALPHA_SUMMARY_DIR="$(dirname "${REMOTE_ALPHA_SUMMARY_PATH}")"
        shift 2
        ;;
      --help|-h)
        remote_alpha_ars_hardening_usage
        return 1
        ;;
      *)
        echo "unknown argument: $1" >&2
        remote_alpha_ars_hardening_usage >&2
        return 2
        ;;
    esac
  done
}

remote_alpha_ars_hardening_require_root() {
  if [[ "$(id -u)" != "0" ]]; then
    echo "remote alpha ARS hardening must run as root; use sudo scripts/remote_alpha_harden_ars_service.sh" >&2
    return 1
  fi
}

remote_alpha_ars_hardening_require_command() {
  local name=$1
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "${name} is required" >&2
    return 1
  fi
}

remote_alpha_ars_hardening_json_field() {
  local json_path=$1
  local dotted_path=$2

  python3 -I - "${json_path}" "${dotted_path}" <<'PY'
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

remote_alpha_ars_hardening_systemctl_state() {
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

remote_alpha_ars_hardening_passwordless_sudo_for_ds() {
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

remote_alpha_ars_hardening_ds_not_in_docker_group() {
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

remote_alpha_ars_hardening_runtime_meta() {
  python3 -I - "${REMOTE_ALPHA_CONFIG_PATH}" "${REMOTE_ALPHA_BINARY_PATH}" <<'PY'
import json
import os
import ssl
import sys
from pathlib import Path

config_path = Path(sys.argv[1])
binary_path = sys.argv[2]

result = {
    "status": "fail",
    "error": "",
    "binary_path": binary_path,
    "config_path": str(config_path),
    "bind_address": "",
    "port": 0,
    "health_url": "",
    "health_probe_url": "",
    "health_probe_resolve": "",
    "tls": {
        "cert_file": "",
        "key_file": "",
        "client_ca_file": "",
    },
    "storage": {
        "root_dir": "",
        "index_file": "",
        "state_root_dir": "",
    },
    "local_state_paths": [],
    "log_sink": "journald",
    "dependencies": {
        "ags": False,
        "egs": False,
        "es": False,
    },
}

try:
    payload = json.loads(config_path.read_text(encoding="utf-8"))
except FileNotFoundError:
    result["error"] = "ARS config file does not exist"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)
except Exception as exc:
    result["error"] = f"read or decode ARS config: {exc}"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

http = payload.get("http") or {}
tls = payload.get("tls") or {}
storage = payload.get("storage") or {}

result["bind_address"] = str(http.get("bind_address") or "").strip()
result["port"] = int(http.get("port") or 0)
if result["bind_address"] and result["port"] > 0:
    result["health_url"] = f"https://{result['bind_address']}:{result['port']}/health"

result["tls"]["cert_file"] = str(tls.get("cert_file") or "").strip()
result["tls"]["key_file"] = str(tls.get("key_file") or "").strip()
result["tls"]["client_ca_file"] = str(tls.get("client_ca_file") or "").strip()
result["storage"]["root_dir"] = str(storage.get("root_dir") or "").strip()
result["storage"]["index_file"] = str(storage.get("index_file") or "").strip()

root_dir = result["storage"]["root_dir"]
index_file = result["storage"]["index_file"]
if root_dir and index_file:
    try:
        result["storage"]["state_root_dir"] = os.path.commonpath([root_dir, index_file])
    except Exception:
        result["storage"]["state_root_dir"] = str(Path(index_file).parent)
result["local_state_paths"] = [value for value in [root_dir, index_file] if value]

probe_host = result["bind_address"]
try:
    cert_info = ssl._ssl._test_decode_cert(result["tls"]["cert_file"])
except Exception:
    cert_info = {}

subject_alt_names = cert_info.get("subjectAltName") or []
dns_names = [value for kind, value in subject_alt_names if kind == "DNS"]
ip_names = [value for kind, value in subject_alt_names if kind == "IP Address"]

if result["bind_address"] in ip_names:
    probe_host = result["bind_address"]
elif dns_names:
    probe_host = dns_names[0]
    if result["bind_address"] and result["port"] > 0 and probe_host != result["bind_address"]:
        result["health_probe_resolve"] = f"{probe_host}:{result['port']}:{result['bind_address']}"
elif ip_names:
    probe_host = ip_names[0]

if probe_host and result["port"] > 0:
    result["health_probe_url"] = f"https://{probe_host}:{result['port']}/health"

required_paths = [
    result["binary_path"],
    result["config_path"],
    result["tls"]["cert_file"],
    result["tls"]["key_file"],
    result["tls"]["client_ca_file"],
    result["storage"]["root_dir"],
    result["storage"]["index_file"],
]
missing = [value for value in required_paths if not str(value).strip()]
if missing:
    result["error"] = "ARS runtime metadata is missing required file paths"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

result["status"] = "pass"
print(json.dumps(result, sort_keys=True))
PY
}

remote_alpha_ars_hardening_assert_runtime_shape() {
  local runtime_meta_path=$1
  local bind_address port root_dir index_file cert_file key_file ca_file

  bind_address="$(remote_alpha_ars_hardening_json_field "${runtime_meta_path}" "bind_address" 2>/dev/null || true)"
  port="$(remote_alpha_ars_hardening_json_field "${runtime_meta_path}" "port" 2>/dev/null || true)"
  root_dir="$(remote_alpha_ars_hardening_json_field "${runtime_meta_path}" "storage.root_dir" 2>/dev/null || true)"
  index_file="$(remote_alpha_ars_hardening_json_field "${runtime_meta_path}" "storage.index_file" 2>/dev/null || true)"
  cert_file="$(remote_alpha_ars_hardening_json_field "${runtime_meta_path}" "tls.cert_file" 2>/dev/null || true)"
  key_file="$(remote_alpha_ars_hardening_json_field "${runtime_meta_path}" "tls.key_file" 2>/dev/null || true)"
  ca_file="$(remote_alpha_ars_hardening_json_field "${runtime_meta_path}" "tls.client_ca_file" 2>/dev/null || true)"

  if [[ "${bind_address}" != "${remote_alpha_ars_hardening_expected_bind_address}" ]]; then
    echo "remote alpha ARS hardening expected bind_address ${remote_alpha_ars_hardening_expected_bind_address}, got ${bind_address}" >&2
    return 1
  fi
  if [[ "${port}" != "${remote_alpha_ars_hardening_expected_port}" ]]; then
    echo "remote alpha ARS hardening expected port ${remote_alpha_ars_hardening_expected_port}, got ${port}" >&2
    return 1
  fi
  if [[ "${root_dir}" != "${remote_alpha_ars_hardening_expected_storage_root_dir}" ]]; then
    echo "remote alpha ARS hardening expected storage.root_dir ${remote_alpha_ars_hardening_expected_storage_root_dir}, got ${root_dir}" >&2
    return 1
  fi
  if [[ "${index_file}" != "${remote_alpha_ars_hardening_expected_storage_index_file}" ]]; then
    echo "remote alpha ARS hardening expected storage.index_file ${remote_alpha_ars_hardening_expected_storage_index_file}, got ${index_file}" >&2
    return 1
  fi

  case "${cert_file}" in
    "${remote_alpha_ars_hardening_expected_shared_tls_dir}/ars-server-cert.pem"|\
    "${remote_alpha_ars_hardening_expected_tls_dir}/ars-server-cert.pem")
      ;;
    *)
      echo "remote alpha ARS hardening expected ars server cert under ${remote_alpha_ars_hardening_expected_shared_tls_dir} or ${remote_alpha_ars_hardening_expected_tls_dir}, got ${cert_file}" >&2
      return 1
      ;;
  esac
  case "${key_file}" in
    "${remote_alpha_ars_hardening_expected_shared_tls_dir}/ars-server-key.pem"|\
    "${remote_alpha_ars_hardening_expected_tls_dir}/ars-server-key.pem")
      ;;
    *)
      echo "remote alpha ARS hardening expected ars server key under ${remote_alpha_ars_hardening_expected_shared_tls_dir} or ${remote_alpha_ars_hardening_expected_tls_dir}, got ${key_file}" >&2
      return 1
      ;;
  esac
  case "${ca_file}" in
    "${remote_alpha_ars_hardening_expected_shared_tls_dir}/runtime-ca.pem"|\
    "${remote_alpha_ars_hardening_expected_tls_dir}/runtime-ca.pem")
      ;;
    *)
      echo "remote alpha ARS hardening expected ars client CA / runtime root CA under ${remote_alpha_ars_hardening_expected_shared_tls_dir} or ${remote_alpha_ars_hardening_expected_tls_dir}, got ${ca_file}" >&2
      return 1
      ;;
  esac
}

remote_alpha_ars_hardening_ags_runtime_meta() {
  python3 -I - "${REMOTE_ALPHA_AGS_CONFIG_PATH}" <<'PY'
import json
import sys
from pathlib import Path

config_path = Path(sys.argv[1])
result = {
    "status": "fail",
    "error": "",
    "config_path": str(config_path),
    "health_url": "",
    "publish_url": "",
}

try:
    payload = json.loads(config_path.read_text(encoding="utf-8"))
except FileNotFoundError:
    result["error"] = "AGS config file does not exist"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)
except Exception as exc:
    result["error"] = f"read or decode AGS config: {exc}"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

http = payload.get("http") or {}
bind_address = str(http.get("bind_address") or "").strip()
port = int(http.get("port") or 0)
if bind_address and port > 0:
    result["health_url"] = f"https://{bind_address}:{port}/health"
    result["publish_url"] = f"https://{bind_address}:{port}/v1/artifacts:publish"

if not result["health_url"] or not result["publish_url"]:
    result["error"] = "AGS runtime metadata is missing health or publish URL inputs"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

result["status"] = "pass"
print(json.dumps(result, sort_keys=True))
PY
}

remote_alpha_ars_hardening_health_env_meta() {
  python3 -I - "${REMOTE_ALPHA_HEALTHCHECK_ENV_PATH}" <<'PY'
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

remote_alpha_ars_hardening_verify_file_exists() {
  local label=$1
  local path=$2

  if [[ ! -e "${path}" ]]; then
    echo "${label} does not exist: ${path}" >&2
    return 1
  fi
}

remote_alpha_ars_hardening_verify_runtime_paths() {
  local runtime_meta_path=$1
  local health_env_meta_path=$2
  local ags_runtime_meta_path=$3
  local paths=()
  local value=""

  for field in \
    "binary_path" \
    "config_path" \
    "tls.cert_file" \
    "tls.key_file" \
    "tls.client_ca_file" \
    "storage.root_dir" \
    "storage.index_file"; do
    value="$(remote_alpha_ars_hardening_json_field "${runtime_meta_path}" "${field}" 2>/dev/null || true)"
    [[ -n "${value}" ]] || continue
    paths+=("${field}:${value}")
  done

  value="$(remote_alpha_ars_hardening_json_field "${ags_runtime_meta_path}" "config_path" 2>/dev/null || true)"
  if [[ -n "${value}" ]]; then
    paths+=("ags.config_path:${value}")
  fi

  for field in "ca_cert" "operator_cert" "operator_key"; do
    value="$(remote_alpha_ars_hardening_json_field "${health_env_meta_path}" "${field}" 2>/dev/null || true)"
    [[ -n "${value}" ]] || continue
    paths+=("${field}:${value}")
  done

  local entry=""
  local label=""
  local path=""
  for entry in "${paths[@]}"; do
    label="${entry%%:*}"
    path="${entry#*:}"
    remote_alpha_ars_hardening_verify_file_exists "${label}" "${path}" || return 1
  done
}

remote_alpha_ars_hardening_assert_unit_execstart() {
  local exec_start=""

  exec_start="$(systemctl show "${REMOTE_ALPHA_SERVICE_NAME}.service" -p ExecStart 2>/dev/null || true)"
  if [[ -z "${exec_start}" ]]; then
    echo "failed to read ExecStart for ${REMOTE_ALPHA_SERVICE_NAME}.service" >&2
    return 1
  fi
  if [[ "${exec_start}" != *"${REMOTE_ALPHA_BINARY_PATH}"* ]]; then
    echo "ars.service ExecStart does not contain expected binary path ${REMOTE_ALPHA_BINARY_PATH}" >&2
    return 1
  fi
  if [[ "${exec_start}" != *"${REMOTE_ALPHA_CONFIG_PATH}"* ]]; then
    echo "ars.service ExecStart does not contain expected config path ${REMOTE_ALPHA_CONFIG_PATH}" >&2
    return 1
  fi
}

remote_alpha_ars_hardening_ensure_group() {
  if getent group "${REMOTE_ALPHA_SERVICE_GROUP}" >/dev/null 2>&1; then
    return 0
  fi
  groupadd --system "${REMOTE_ALPHA_SERVICE_GROUP}"
}

remote_alpha_ars_hardening_ensure_user() {
  if id -u "${REMOTE_ALPHA_SERVICE_USER}" >/dev/null 2>&1; then
    local current_group=""
    current_group="$(id -gn "${REMOTE_ALPHA_SERVICE_USER}" 2>/dev/null || true)"
    if [[ "${current_group}" != "${REMOTE_ALPHA_SERVICE_GROUP}" ]]; then
      echo "existing ARS service user ${REMOTE_ALPHA_SERVICE_USER} does not use group ${REMOTE_ALPHA_SERVICE_GROUP}" >&2
      return 1
    fi
    return 0
  fi

  local nologin_path=""
  nologin_path="$(command -v nologin 2>/dev/null || true)"
  if [[ -z "${nologin_path}" ]]; then
    nologin_path="/usr/sbin/nologin"
  fi

  useradd \
    --system \
    --gid "${REMOTE_ALPHA_SERVICE_GROUP}" \
    --home-dir /nonexistent \
    --no-create-home \
    --shell "${nologin_path}" \
    "${REMOTE_ALPHA_SERVICE_USER}"
}

remote_alpha_ars_hardening_prepare_tls_material() {
  local runtime_meta_path=$1
  local cert_source key_source ca_source

  cert_source="$(remote_alpha_ars_hardening_json_field "${runtime_meta_path}" "tls.cert_file")"
  key_source="$(remote_alpha_ars_hardening_json_field "${runtime_meta_path}" "tls.key_file")"
  ca_source="$(remote_alpha_ars_hardening_json_field "${runtime_meta_path}" "tls.client_ca_file")"

  python3 -I - "${cert_source}" "${REMOTE_ALPHA_TLS_CERT_PATH}" "${key_source}" "${REMOTE_ALPHA_TLS_KEY_PATH}" "${ca_source}" "${REMOTE_ALPHA_TLS_CLIENT_CA_PATH}" <<'PY'
from pathlib import Path
import sys

pairs = [
    (Path(sys.argv[1]), Path(sys.argv[2])),
    (Path(sys.argv[3]), Path(sys.argv[4])),
    (Path(sys.argv[5]), Path(sys.argv[6])),
]

for source, destination in pairs:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.resolve() == destination.resolve():
        continue
    destination.write_bytes(source.read_bytes())
PY

  chown root:"${REMOTE_ALPHA_SERVICE_GROUP}" "${REMOTE_ALPHA_TLS_DIR}"
  chmod 0710 "${REMOTE_ALPHA_TLS_DIR}"

  local path=""
  for path in "${REMOTE_ALPHA_TLS_CERT_PATH}" "${REMOTE_ALPHA_TLS_KEY_PATH}" "${REMOTE_ALPHA_TLS_CLIENT_CA_PATH}"; do
    chown root:"${REMOTE_ALPHA_SERVICE_GROUP}" "${path}"
    chmod 0640 "${path}"
  done
}

remote_alpha_ars_hardening_rewrite_config() {
  python3 -I - "${REMOTE_ALPHA_CONFIG_PATH}" "${REMOTE_ALPHA_TLS_CERT_PATH}" "${REMOTE_ALPHA_TLS_KEY_PATH}" "${REMOTE_ALPHA_TLS_CLIENT_CA_PATH}" <<'PY'
import json
import os
import sys

config_path = sys.argv[1]
cert_path = sys.argv[2]
key_path = sys.argv[3]
ca_path = sys.argv[4]

with open(config_path, encoding="utf-8") as f:
    payload = json.load(f)

payload.setdefault("tls", {})
payload["tls"]["cert_file"] = cert_path
payload["tls"]["key_file"] = key_path
payload["tls"]["client_ca_file"] = ca_path

temp_path = config_path + ".tmp"
with open(temp_path, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2, sort_keys=True)
    f.write("\n")
os.replace(temp_path, config_path)
PY

  chown root:"${REMOTE_ALPHA_SERVICE_GROUP}" "${REMOTE_ALPHA_CONFIG_PATH}"
  chmod 0640 "${REMOTE_ALPHA_CONFIG_PATH}"
}

remote_alpha_ars_hardening_apply_state_permissions() {
  local runtime_meta_path=$1
  local state_root_dir blob_root index_file

  state_root_dir="$(remote_alpha_ars_hardening_json_field "${runtime_meta_path}" "storage.state_root_dir")"
  blob_root="$(remote_alpha_ars_hardening_json_field "${runtime_meta_path}" "storage.root_dir")"
  index_file="$(remote_alpha_ars_hardening_json_field "${runtime_meta_path}" "storage.index_file")"

  local service_uid service_gid
  service_uid="$(id -u "${REMOTE_ALPHA_SERVICE_USER}")" || return 1
  service_gid="$(getent group "${REMOTE_ALPHA_SERVICE_GROUP}" | cut -d: -f3)" || return 1

  # After the first run the ARS account owns this tree, and ARS keeps running
  # while the step runs again, so root must never act on a name in it: a plain
  # chown or chmod would follow a link the ARS account put there. Every object
  # is reached from the state root's parent, which the account cannot change,
  # by descriptors opened without following a symbolic link. Owners and modes
  # are set through those descriptors. Anything but a directory or a regular
  # file with one link is refused. A first walk only checks, so a tree that is
  # refused is left unchanged; the second walk checks each object again as it
  # sets it.
  python3 -I - "${state_root_dir}" "${blob_root}" "${index_file}" "${service_uid}" "${service_gid}" <<'PY'
import os
import stat
import sys

state_root, blob_root, index_file, uid_text, gid_text = sys.argv[1:6]
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
MAX_DEPTH = 16


class Refusal(Exception):
    pass


def direct_child(parent, path, label):
    if os.path.normpath(path) != path or os.path.dirname(path) != parent or os.path.basename(path) in ("", ".", ".."):
        raise Refusal(f"{label} must be directly under {parent}: {path}")
    return os.path.basename(path)


def open_dir(name, dir_fd, label, create):
    if create:
        try:
            os.mkdir(name, 0o750, dir_fd=dir_fd)
        except FileExistsError:
            pass
    try:
        return os.open(name, DIR_FLAGS, dir_fd=dir_fd)
    except OSError as exc:
        raise Refusal(f"{label} is not a directory or is a symbolic link ({exc.strerror})") from None


def own_file(name, dir_fd, label, owner, mode):
    try:
        fd = os.open(name, FILE_FLAGS, dir_fd=dir_fd)
    except OSError as exc:
        raise Refusal(f"{label} is missing, is not a regular file or is a symbolic link ({exc.strerror})") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise Refusal(f"{label} must be a regular file with one link")
        if owner is not None:
            os.fchown(fd, *owner)
            if mode is not None:
                os.fchmod(fd, mode)
    finally:
        os.close(fd)


def own_tree(dir_fd, label, owner, depth):
    if depth > MAX_DEPTH:
        raise Refusal(f"{label} is more than {MAX_DEPTH} directories below the state root")
    if owner is not None:
        os.fchown(dir_fd, *owner)
    for entry in sorted(os.listdir(dir_fd)):
        where = f"{label}/{entry}"
        info = os.stat(entry, dir_fd=dir_fd, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            child_fd = open_dir(entry, dir_fd, where, create=False)
            try:
                own_tree(child_fd, where, owner, depth + 1)
            finally:
                os.close(child_fd)
        elif stat.S_ISREG(info.st_mode):
            own_file(entry, dir_fd, where, owner, None)
        else:
            raise Refusal(f"{where} is not a directory or a regular file")


def main():
    if not uid_text.isdigit() or not gid_text.isdigit():
        raise Refusal("the ARS service account or group has no numeric ID")
    owner = (int(uid_text), int(gid_text))
    if not os.path.isabs(state_root) or os.path.normpath(state_root) != state_root or os.path.dirname(state_root) == state_root:
        raise Refusal(f"the ARS state root must be a clean absolute path below another directory: {state_root}")
    blob_name = direct_child(state_root, blob_root, "storage.root_dir")
    index_name = direct_child(state_root, index_file, "storage.index_file")
    if blob_name == index_name:
        raise Refusal("storage.root_dir and storage.index_file name the same entry")

    parent = os.path.dirname(state_root)
    os.makedirs(parent, mode=0o755, exist_ok=True)
    parent_fd = os.open(parent, DIR_FLAGS)
    try:
        parent_info = os.fstat(parent_fd)
        if parent_info.st_uid != os.geteuid() or parent_info.st_mode & 0o022:
            raise Refusal(f"{parent} must belong to the user running this step and must not be writable by group or others")
        root_fd = open_dir(os.path.basename(state_root), parent_fd, state_root, create=True)
    finally:
        os.close(parent_fd)
    try:
        blob_fd = open_dir(blob_name, root_fd, blob_root, create=True)
        try:
            own_file(index_name, root_fd, index_file, None, None)
            own_tree(root_fd, state_root, None, 0)
            own_tree(root_fd, state_root, owner, 0)
            os.fchmod(root_fd, 0o750)
            os.fchmod(blob_fd, 0o750)
        finally:
            os.close(blob_fd)
        own_file(index_name, root_fd, index_file, owner, 0o600)
    finally:
        os.close(root_fd)


try:
    main()
except Refusal as exc:
    print(f"remote alpha ARS hardening: {exc}; stopped without changing it", file=sys.stderr)
    sys.exit(1)
except OSError as exc:
    print(f"remote alpha ARS hardening: could not set the ARS state owners and modes: {exc}", file=sys.stderr)
    sys.exit(1)
PY
}

remote_alpha_ars_hardening_write_dropin() {
  mkdir -p "${REMOTE_ALPHA_SERVICE_DROPIN_DIR}"

  cat >"${REMOTE_ALPHA_SERVICE_DROPIN_PATH}" <<EOF
[Service]
User=${REMOTE_ALPHA_SERVICE_USER}
Group=${REMOTE_ALPHA_SERVICE_GROUP}
UMask=0027
EOF
  chmod 0644 "${REMOTE_ALPHA_SERVICE_DROPIN_PATH}"
}

remote_alpha_ars_hardening_service_meta() {
  local service_name=$1
  local unit_name="${service_name}"
  if [[ "${unit_name}" != *.service ]]; then
    unit_name="${unit_name}.service"
  fi

  python3 -I - "${service_name}" \
    "$(systemctl show "${unit_name}" -p User -p Group -p ExecStart -p FragmentPath -p ActiveState -p SubState 2>/dev/null || true)" \
    "$(remote_alpha_ars_hardening_systemctl_state is-enabled "${unit_name}")" <<'PY'
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

remote_alpha_ars_hardening_health_probe_meta() {
  local url=$1
  local resolve=$2
  local health_env_meta_path=$3
  local response_path=$4
  local error_path=$5
  local expected_service=$6
  local dependency_field=$7
  local ca_cert operator_cert operator_key
  local -a curl_args=()

  ca_cert="$(remote_alpha_ars_hardening_json_field "${health_env_meta_path}" "ca_cert")"
  operator_cert="$(remote_alpha_ars_hardening_json_field "${health_env_meta_path}" "operator_cert")"
  operator_key="$(remote_alpha_ars_hardening_json_field "${health_env_meta_path}" "operator_key")"

  if [[ -n "${resolve}" ]]; then
    curl_args+=(--resolve "${resolve}")
  fi

  if [[ ${#curl_args[@]} -gt 0 ]]; then
    if ! curl --fail-with-body --silent --show-error \
      --cacert "${ca_cert}" \
      --cert "${operator_cert}" \
      --key "${operator_key}" \
      "${curl_args[@]}" \
      "${url}" >"${response_path}" 2>"${error_path}"; then
      python3 -I - "${url}" "${error_path}" <<'PY'
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
  elif ! curl --fail-with-body --silent --show-error \
    --cacert "${ca_cert}" \
    --cert "${operator_cert}" \
    --key "${operator_key}" \
    "${url}" >"${response_path}" 2>"${error_path}"; then
    python3 -I - "${url}" "${error_path}" <<'PY'
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

  python3 -I - "${url}" "${response_path}" "${expected_service}" "${dependency_field}" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
dependencies = ((payload.get("additional_properties") or {}).get("dependencies") or {})
dependency_field = sys.argv[4].strip()
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

remote_alpha_ars_hardening_write_publish_request() {
  local request_path=$1

  python3 -I - "${request_path}" <<'PY'
import base64
import hashlib
import json
import pathlib
import sys

payload = b'#!/bin/sh\necho remote-alpha-ars-posture-publish-probe-host-local\n'
build_log = b'remote-alpha-ars-posture-publish-probe-host-local\n'

intent = {
    "kind": "remote-alpha-ars-posture-publish-probe-host-local",
    "entrypoint": "./entrypoint",
    "args": [],
    "scope": "remote-host-local-operator",
}
derivation = {
    "kind": "static-script",
    "platform": "docker",
    "constraints_profile": "bounded-default",
}

def labeled_digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()

def labeled_digest_json(value) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return labeled_digest_bytes(encoded)

request = {
    "artifact_payload_b64": base64.b64encode(payload).decode("ascii"),
    "artifact": {
        "artifact_type": "static-script",
        "intent_digest": labeled_digest_json(intent),
    },
    "publication": {
        "policy_decisions": [{"rule": "allow", "result": "applied"}],
        "build_log_digest": labeled_digest_bytes(build_log),
    },
    "admission": {
        "runtime": {
            "environment_variables": [],
            "required_capabilities": [],
        },
        "access": {
            "network_access": False,
        },
        "derivation": {
            "derivation_spec_digest": labeled_digest_json(derivation),
            "output_id": "runtime",
        },
        "workload": {
            "target_platform": "docker",
        },
    },
}

pathlib.Path(sys.argv[1]).write_text(json.dumps(request, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

remote_alpha_ars_hardening_publish_probe_meta() {
  local ags_runtime_meta_path=$1
  local health_env_meta_path=$2
  local response_path=$3
  local error_path=$4
  local request_path=$5
  local url ca_cert operator_cert operator_key

  url="$(remote_alpha_ars_hardening_json_field "${ags_runtime_meta_path}" "publish_url")"
  ca_cert="$(remote_alpha_ars_hardening_json_field "${health_env_meta_path}" "ca_cert")"
  operator_cert="$(remote_alpha_ars_hardening_json_field "${health_env_meta_path}" "operator_cert")"
  operator_key="$(remote_alpha_ars_hardening_json_field "${health_env_meta_path}" "operator_key")"

  remote_alpha_ars_hardening_write_publish_request "${request_path}"

  if curl --fail-with-body --silent --show-error \
    --cacert "${ca_cert}" \
    --cert "${operator_cert}" \
    --key "${operator_key}" \
    --header "content-type: application/json" \
    --data "@${request_path}" \
    "${url}" >"${response_path}" 2>"${error_path}"; then
    python3 -I - "${url}" "${response_path}" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
published = payload.get("published") is True
status = "pass" if published else "fail"
print(json.dumps({
    "status": status,
    "url": sys.argv[1],
    "published": published,
    "artifact_digest": payload.get("artifact_digest", ""),
}, sort_keys=True))
PY
    return 0
  fi

  python3 -I - "${url}" "${error_path}" <<'PY'
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
}

remote_alpha_ars_hardening_state_ownership_meta() {
  local runtime_meta_path=$1
  local config_path tls_dir blob_root index_file state_root
  config_path="$(remote_alpha_ars_hardening_json_field "${runtime_meta_path}" "config_path")"
  tls_dir="${REMOTE_ALPHA_TLS_DIR}"
  blob_root="$(remote_alpha_ars_hardening_json_field "${runtime_meta_path}" "storage.root_dir")"
  index_file="$(remote_alpha_ars_hardening_json_field "${runtime_meta_path}" "storage.index_file")"
  state_root="$(remote_alpha_ars_hardening_json_field "${runtime_meta_path}" "storage.state_root_dir")"

  python3 -I - \
    "${config_path}" "root:${REMOTE_ALPHA_SERVICE_GROUP}" "0640" "$(stat -c '%U:%G %a %n' "${config_path}" 2>/dev/null || true)" \
    "${tls_dir}" "root:${REMOTE_ALPHA_SERVICE_GROUP}" "0710" "$(stat -c '%U:%G %a %n' "${tls_dir}" 2>/dev/null || true)" \
    "${REMOTE_ALPHA_TLS_CERT_PATH}" "root:${REMOTE_ALPHA_SERVICE_GROUP}" "0640" "$(stat -c '%U:%G %a %n' "${REMOTE_ALPHA_TLS_CERT_PATH}" 2>/dev/null || true)" \
    "${REMOTE_ALPHA_TLS_KEY_PATH}" "root:${REMOTE_ALPHA_SERVICE_GROUP}" "0640" "$(stat -c '%U:%G %a %n' "${REMOTE_ALPHA_TLS_KEY_PATH}" 2>/dev/null || true)" \
    "${REMOTE_ALPHA_TLS_CLIENT_CA_PATH}" "root:${REMOTE_ALPHA_SERVICE_GROUP}" "0640" "$(stat -c '%U:%G %a %n' "${REMOTE_ALPHA_TLS_CLIENT_CA_PATH}" 2>/dev/null || true)" \
    "${state_root}" "${REMOTE_ALPHA_SERVICE_USER}:${REMOTE_ALPHA_SERVICE_GROUP}" "0750" "$(stat -c '%U:%G %a %n' "${state_root}" 2>/dev/null || true)" \
    "${blob_root}" "${REMOTE_ALPHA_SERVICE_USER}:${REMOTE_ALPHA_SERVICE_GROUP}" "0750" "$(stat -c '%U:%G %a %n' "${blob_root}" 2>/dev/null || true)" \
    "${index_file}" "${REMOTE_ALPHA_SERVICE_USER}:${REMOTE_ALPHA_SERVICE_GROUP}" "0600" "$(stat -c '%U:%G %a %n' "${index_file}" 2>/dev/null || true)" <<'PY'
import json
import sys

def normalize_mode(mode: str) -> str:
    mode = (mode or "").strip()
    if not mode:
        return ""
    return mode.zfill(4)

items = []
overall_ok = True
args = sys.argv[1:]
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
    status = "pass" if actual_owner == expected_owner and actual_mode == expected_mode else "fail"
    if status != "pass":
        overall_ok = False
    items.append({
        "path": path,
        "expected_owner": expected_owner,
        "expected_mode": expected_mode,
        "actual_owner": actual_owner,
        "actual_mode": actual_mode,
        "status": status,
    })

print(json.dumps({
    "status": "pass" if overall_ok else "fail",
    "items": items,
}, sort_keys=True))
PY
}

remote_alpha_ars_hardening_write_summary() {
  local summary_path=$1
  local runtime_meta_path=$2
  local ars_meta_path=$3
  local ags_meta_path=$4
  local egs_meta_path=$5
  local es_meta_path=$6
  local ars_health_meta_path=$7
  local ags_health_meta_path=$8
  local ags_publish_meta_path=$9
  local state_ownership_meta_path=${10}
  local ds_not_in_docker_group=${11}
  local passwordless_sudo_for_ds=${12}

  python3 -I - "${summary_path}" \
    "${runtime_meta_path}" \
    "${ars_meta_path}" \
    "${ags_meta_path}" \
    "${egs_meta_path}" \
    "${es_meta_path}" \
    "${ars_health_meta_path}" \
    "${ags_health_meta_path}" \
    "${ags_publish_meta_path}" \
    "${state_ownership_meta_path}" \
    "${ds_not_in_docker_group}" \
    "${passwordless_sudo_for_ds}" \
    "${REMOTE_ALPHA_SERVICE_USER}" \
    "${REMOTE_ALPHA_SERVICE_GROUP}" \
    "${REMOTE_ALPHA_SERVICE_DROPIN_PATH}" \
    "${remote_alpha_ars_hardening_summary_schema_version}" <<'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone

summary_path = pathlib.Path(sys.argv[1])
runtime = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
ars_meta = json.loads(pathlib.Path(sys.argv[3]).read_text(encoding="utf-8"))
ags_meta = json.loads(pathlib.Path(sys.argv[4]).read_text(encoding="utf-8"))
egs_meta = json.loads(pathlib.Path(sys.argv[5]).read_text(encoding="utf-8"))
es_meta = json.loads(pathlib.Path(sys.argv[6]).read_text(encoding="utf-8"))
ars_health = json.loads(pathlib.Path(sys.argv[7]).read_text(encoding="utf-8"))
ags_health = json.loads(pathlib.Path(sys.argv[8]).read_text(encoding="utf-8"))
ags_publish = json.loads(pathlib.Path(sys.argv[9]).read_text(encoding="utf-8"))
state_ownership = json.loads(pathlib.Path(sys.argv[10]).read_text(encoding="utf-8"))
ds_not_in_docker_group = sys.argv[11]
passwordless_sudo_for_ds = sys.argv[12]
service_user = sys.argv[13]
service_group = sys.argv[14]
dropin_path = sys.argv[15]
schema_version = sys.argv[16]

summary = {
    "schema_version": schema_version,
    "checked_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "slice": {
        "name": "remote-alpha-ars-service-hardening",
        "classification": "hardening_slice",
        "not_a_new_happy_path_proof": True,
    },
    "service": {
        "name": "ars",
        "user": service_user,
        "group": service_group,
        "binary_path": runtime["binary_path"],
        "config_path": runtime["config_path"],
        "health_url": runtime["health_url"],
        "active": ars_meta["active"],
        "enabled": ars_meta["enabled"],
        "fragment_path": ars_meta["fragment_path"],
        "exec_start": ars_meta["exec_start"],
    },
    "dependencies": {
        "server_tls": runtime["tls"],
        "blob_root": runtime["storage"]["root_dir"],
        "index_file": runtime["storage"]["index_file"],
        "local_state_paths": runtime["local_state_paths"],
        "log_sink": runtime["log_sink"],
        "runtime_dependency_on_ags": runtime["dependencies"]["ags"],
        "runtime_dependency_on_egs": runtime["dependencies"]["egs"],
        "runtime_dependency_on_es": runtime["dependencies"]["es"],
        "ags_runtime_dependency_preserved": True,
    },
    "ownership_model": {
        "account": {
            "user": service_user,
            "group": service_group,
        },
        "config_file": {
            "path": runtime["config_path"],
            "owner": f"root:{service_group}",
            "mode": "0640",
        },
        "tls_directory": {
            "path": str(pathlib.Path(runtime["tls"]["cert_file"]).parent),
            "owner": f"root:{service_group}",
            "mode": "0710",
        },
        "tls_files": [
            {
                "path": runtime["tls"]["cert_file"],
                "owner": f"root:{service_group}",
                "mode": "0640",
            },
            {
                "path": runtime["tls"]["key_file"],
                "owner": f"root:{service_group}",
                "mode": "0640",
            },
            {
                "path": runtime["tls"]["client_ca_file"],
                "owner": f"root:{service_group}",
                "mode": "0640",
            },
        ],
        "state_root": {
            "path": runtime["storage"]["state_root_dir"],
            "owner": f"{service_user}:{service_group}",
            "mode": "0750",
        },
        "blob_root": {
            "path": runtime["storage"]["root_dir"],
            "owner": f"{service_user}:{service_group}",
            "mode": "0750",
        },
        "index_file": {
            "path": runtime["storage"]["index_file"],
            "owner": f"{service_user}:{service_group}",
            "mode": "0600",
        },
        "systemd_dropin": {
            "path": dropin_path,
            "user": service_user,
            "group": service_group,
            "umask": "0027",
        },
    },
    "validation": {
        "local_ars_health": ars_health,
        "local_ags_health": ags_health,
        "local_ags_publish_probe": ags_publish,
        "state_ownership": state_ownership,
        "ags_service_posture": ags_meta,
        "egs_service_posture": egs_meta,
        "es_service_posture": es_meta,
        "mac_ags_health_probe": "not_exercised",
        "mac_ags_publish_probe": "not_exercised",
    },
    "preserved_remote_path": {
        "ars_loopback_only": runtime["bind_address"] == "127.0.0.1",
        "direct_https_mtls": True,
        "no_bridge": True,
        "no_shared_filesystem": True,
        "ags_health_path": ags_health.get("url", ""),
        "ags_publish_path": ags_publish.get("url", ""),
        "ags_posture_preserved": ags_meta.get("effective_user") == "ags" and ags_meta.get("effective_group") == "ags",
    },
    "security": {
        "ds_not_in_docker_group": ds_not_in_docker_group,
        "passwordless_sudo_for_ds": passwordless_sudo_for_ds,
        "secret_material_in_summary": False,
    },
    "not_claimed": {
        "es_or_egs_hardening": "not_claimed",
        "es_public_contract_changes": "not_claimed",
        "spire_selector_model_changes": "not_claimed",
        "new_remote_happy_path_proof": "not_claimed",
    },
}

summary_path.parent.mkdir(parents=True, exist_ok=True)
summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

remote_alpha_ars_hardening_main() {
  local source_runtime_meta_path runtime_meta_path ags_runtime_meta_path health_env_meta_path
  local ars_meta_path ags_meta_path egs_meta_path es_meta_path
  local ars_health_result_path ars_health_error_path ags_health_result_path ags_health_error_path
  local ags_publish_result_path ags_publish_error_path ags_publish_request_path
  local state_ownership_meta_path
  local tmpdir=""
  local ds_not_in_docker_group=""
  local passwordless_sudo_for_ds=""
  local overall_ok=true

  remote_alpha_ars_hardening_require_pinned_slice_inputs || return 1
  remote_alpha_ars_hardening_defaults
  remote_alpha_ars_hardening_parse_args "$@" || return $?
  remote_alpha_ars_hardening_require_root || return 1

  remote_alpha_ars_hardening_require_command python3 || return 1
  remote_alpha_prepare_output_dir "$(dirname "${REMOTE_ALPHA_SUMMARY_PATH}")" || return 1
  remote_alpha_ars_hardening_require_command curl || return 1
  remote_alpha_ars_hardening_require_command systemctl || return 1
  remote_alpha_ars_hardening_require_command getent || return 1
  remote_alpha_ars_hardening_require_command groupadd || return 1
  remote_alpha_ars_hardening_require_command useradd || return 1
  remote_alpha_ars_hardening_require_command chown || return 1
  remote_alpha_ars_hardening_require_command chmod || return 1
  remote_alpha_ars_hardening_require_command mkdir || return 1
  remote_alpha_ars_hardening_require_command stat || return 1

  tmpdir="$(mktemp -d)"
  trap "rm -rf -- '${tmpdir}'" EXIT

  source_runtime_meta_path="${tmpdir}/source-runtime.json"
  runtime_meta_path="${tmpdir}/runtime.json"
  ags_runtime_meta_path="${tmpdir}/ags-runtime.json"
  health_env_meta_path="${tmpdir}/health-env.json"
  ars_meta_path="${tmpdir}/ars-service.json"
  ags_meta_path="${tmpdir}/ags-service.json"
  egs_meta_path="${tmpdir}/egs-service.json"
  es_meta_path="${tmpdir}/es-service.json"
  ars_health_result_path="${tmpdir}/ars-health-response.json"
  ars_health_error_path="${tmpdir}/ars-health-error.txt"
  ags_health_result_path="${tmpdir}/ags-health-response.json"
  ags_health_error_path="${tmpdir}/ags-health-error.txt"
  ags_publish_result_path="${tmpdir}/ags-publish-response.json"
  ags_publish_error_path="${tmpdir}/ags-publish-error.txt"
  ags_publish_request_path="${tmpdir}/ags-publish-request.json"
  state_ownership_meta_path="${tmpdir}/state-ownership.json"

  remote_alpha_ars_hardening_runtime_meta >"${source_runtime_meta_path}"
  if [[ "$(remote_alpha_ars_hardening_json_field "${source_runtime_meta_path}" "status" 2>/dev/null || true)" != "pass" ]]; then
    cat "${source_runtime_meta_path}" >&2
    return 1
  fi

  remote_alpha_ars_hardening_assert_runtime_shape "${source_runtime_meta_path}" || return 1

  remote_alpha_ars_hardening_ags_runtime_meta >"${ags_runtime_meta_path}"
  if [[ "$(remote_alpha_ars_hardening_json_field "${ags_runtime_meta_path}" "status" 2>/dev/null || true)" != "pass" ]]; then
    cat "${ags_runtime_meta_path}" >&2
    return 1
  fi

  remote_alpha_ars_hardening_health_env_meta >"${health_env_meta_path}"
  if [[ "$(remote_alpha_ars_hardening_json_field "${health_env_meta_path}" "status" 2>/dev/null || true)" != "pass" ]]; then
    cat "${health_env_meta_path}" >&2
    return 1
  fi

  remote_alpha_ars_hardening_verify_runtime_paths "${source_runtime_meta_path}" "${health_env_meta_path}" "${ags_runtime_meta_path}" || return 1
  remote_alpha_ars_hardening_assert_unit_execstart || return 1

  remote_alpha_ars_hardening_ensure_group || return 1
  remote_alpha_ars_hardening_ensure_user || return 1
  remote_alpha_ars_hardening_prepare_tls_material "${source_runtime_meta_path}" || return 1
  remote_alpha_ars_hardening_rewrite_config || return 1

  remote_alpha_ars_hardening_runtime_meta >"${runtime_meta_path}"
  if [[ "$(remote_alpha_ars_hardening_json_field "${runtime_meta_path}" "status" 2>/dev/null || true)" != "pass" ]]; then
    cat "${runtime_meta_path}" >&2
    return 1
  fi

  if [[ "$(remote_alpha_ars_hardening_json_field "${runtime_meta_path}" "tls.cert_file" 2>/dev/null || true)" != "${REMOTE_ALPHA_TLS_CERT_PATH}" ]]; then
    echo "ARS config did not switch to dedicated cert path ${REMOTE_ALPHA_TLS_CERT_PATH}" >&2
    return 1
  fi
  if [[ "$(remote_alpha_ars_hardening_json_field "${runtime_meta_path}" "tls.key_file" 2>/dev/null || true)" != "${REMOTE_ALPHA_TLS_KEY_PATH}" ]]; then
    echo "ARS config did not switch to dedicated key path ${REMOTE_ALPHA_TLS_KEY_PATH}" >&2
    return 1
  fi
  if [[ "$(remote_alpha_ars_hardening_json_field "${runtime_meta_path}" "tls.client_ca_file" 2>/dev/null || true)" != "${REMOTE_ALPHA_TLS_CLIENT_CA_PATH}" ]]; then
    echo "ARS config did not switch to dedicated client CA path ${REMOTE_ALPHA_TLS_CLIENT_CA_PATH}" >&2
    return 1
  fi

  remote_alpha_ars_hardening_apply_state_permissions "${runtime_meta_path}" || return 1
  remote_alpha_ars_hardening_write_dropin || return 1

  systemctl daemon-reload
  systemctl enable "${REMOTE_ALPHA_SERVICE_NAME}.service" >/dev/null 2>&1 || overall_ok=false
  systemctl restart "${REMOTE_ALPHA_SERVICE_NAME}.service" || overall_ok=false

  remote_alpha_ars_hardening_service_meta "${REMOTE_ALPHA_SERVICE_NAME}" >"${ars_meta_path}"
  remote_alpha_ars_hardening_service_meta "ags" >"${ags_meta_path}"
  remote_alpha_ars_hardening_service_meta "egs" >"${egs_meta_path}"
  remote_alpha_ars_hardening_service_meta "es" >"${es_meta_path}"

  if [[ "$(remote_alpha_ars_hardening_json_field "${ars_meta_path}" "effective_user" 2>/dev/null || true)" != "${REMOTE_ALPHA_SERVICE_USER}" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_ars_hardening_json_field "${ars_meta_path}" "effective_group" 2>/dev/null || true)" != "${REMOTE_ALPHA_SERVICE_GROUP}" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_ars_hardening_json_field "${ars_meta_path}" "active" 2>/dev/null || true)" != "true" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_ars_hardening_json_field "${ars_meta_path}" "enabled" 2>/dev/null || true)" != "true" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_ars_hardening_json_field "${ags_meta_path}" "effective_user" 2>/dev/null || true)" != "ags" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_ars_hardening_json_field "${ags_meta_path}" "effective_group" 2>/dev/null || true)" != "ags" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_ars_hardening_json_field "${egs_meta_path}" "effective_user" 2>/dev/null || true)" != "egs" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_ars_hardening_json_field "${egs_meta_path}" "effective_group" 2>/dev/null || true)" != "egs" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_ars_hardening_json_field "${es_meta_path}" "effective_user" 2>/dev/null || true)" != "es" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_ars_hardening_json_field "${es_meta_path}" "effective_group" 2>/dev/null || true)" != "es" ]]; then
    overall_ok=false
  fi

  remote_alpha_ars_hardening_health_probe_meta \
    "$(remote_alpha_ars_hardening_json_field "${runtime_meta_path}" "health_probe_url" 2>/dev/null || true)" \
    "$(remote_alpha_ars_hardening_json_field "${runtime_meta_path}" "health_probe_resolve" 2>/dev/null || true)" \
    "${health_env_meta_path}" \
    "${ars_health_result_path}" \
    "${ars_health_error_path}" \
    "artifact-registry" \
    "storage" >"${tmpdir}/ars-health-meta.json" || overall_ok=false

  remote_alpha_ars_hardening_health_probe_meta \
    "$(remote_alpha_ars_hardening_json_field "${ags_runtime_meta_path}" "health_url" 2>/dev/null || true)" \
    "" \
    "${health_env_meta_path}" \
    "${ags_health_result_path}" \
    "${ags_health_error_path}" \
    "artifact-governance" \
    "artifact_registry" >"${tmpdir}/ags-health-meta.json" || overall_ok=false

  remote_alpha_ars_hardening_publish_probe_meta \
    "${ags_runtime_meta_path}" \
    "${health_env_meta_path}" \
    "${ags_publish_result_path}" \
    "${ags_publish_error_path}" \
    "${ags_publish_request_path}" >"${tmpdir}/ags-publish-meta.json" || overall_ok=false

  if [[ "$(remote_alpha_ars_hardening_json_field "${tmpdir}/ars-health-meta.json" "status" 2>/dev/null || true)" != "pass" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_ars_hardening_json_field "${tmpdir}/ags-health-meta.json" "status" 2>/dev/null || true)" != "pass" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_ars_hardening_json_field "${tmpdir}/ags-publish-meta.json" "status" 2>/dev/null || true)" != "pass" ]]; then
    overall_ok=false
  fi

  remote_alpha_ars_hardening_state_ownership_meta "${runtime_meta_path}" >"${state_ownership_meta_path}"
  if [[ "$(remote_alpha_ars_hardening_json_field "${state_ownership_meta_path}" "status" 2>/dev/null || true)" != "pass" ]]; then
    overall_ok=false
  fi

  ds_not_in_docker_group="$(remote_alpha_ars_hardening_ds_not_in_docker_group)"
  passwordless_sudo_for_ds="$(remote_alpha_ars_hardening_passwordless_sudo_for_ds)"
  if [[ "${ds_not_in_docker_group}" != "true" ]]; then
    overall_ok=false
  fi
  if [[ "${passwordless_sudo_for_ds}" != "false" ]]; then
    overall_ok=false
  fi

  remote_alpha_prepare_output_dir "$(dirname "${REMOTE_ALPHA_SUMMARY_PATH}")" || return 1
  remote_alpha_ars_hardening_write_summary \
    "${REMOTE_ALPHA_SUMMARY_PATH}" \
    "${runtime_meta_path}" \
    "${ars_meta_path}" \
    "${ags_meta_path}" \
    "${egs_meta_path}" \
    "${es_meta_path}" \
    "${tmpdir}/ars-health-meta.json" \
    "${tmpdir}/ags-health-meta.json" \
    "${tmpdir}/ags-publish-meta.json" \
    "${state_ownership_meta_path}" \
    "${ds_not_in_docker_group}" \
    "${passwordless_sudo_for_ds}"

  chmod 0644 "${REMOTE_ALPHA_SUMMARY_PATH}" 2>/dev/null || true

  if [[ "${overall_ok}" != "true" ]]; then
    echo "remote alpha ARS hardening finished with validation failures; see ${REMOTE_ALPHA_SUMMARY_PATH}" >&2
    return 1
  fi

  printf '%s\n' "${REMOTE_ALPHA_SUMMARY_PATH}"
}
