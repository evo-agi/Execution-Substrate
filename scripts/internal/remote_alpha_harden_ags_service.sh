if [[ -z "${REPO_ROOT:-}" ]]; then
  REMOTE_ALPHA_AGS_HARDENING_HELPER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  REPO_ROOT="$(cd "${REMOTE_ALPHA_AGS_HARDENING_HELPER_DIR}/../.." && pwd)"
fi

remote_alpha_ags_hardening_summary_schema_version="execution-substrate.remote-alpha.ags-service-hardening-summary.v1"

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

remote_alpha_ags_hardening_init_expected_slice_inputs() {
  remote_alpha_ags_hardening_expected_service_name="${remote_alpha_ags_hardening_expected_service_name:-ags}"
  remote_alpha_ags_hardening_expected_service_user="${remote_alpha_ags_hardening_expected_service_user:-ags}"
  remote_alpha_ags_hardening_expected_service_group="${remote_alpha_ags_hardening_expected_service_group:-ags}"
  remote_alpha_ags_hardening_expected_binary_path="${remote_alpha_ags_hardening_expected_binary_path:-/usr/local/lib/execution-substrate/bin/ags}"
  remote_alpha_ags_hardening_expected_config_path="${remote_alpha_ags_hardening_expected_config_path:-/etc/execution-substrate/ags.json}"
  remote_alpha_ags_hardening_expected_healthcheck_env_path="${remote_alpha_ags_hardening_expected_healthcheck_env_path:-/etc/execution-substrate/healthcheck.env}"
  remote_alpha_ags_hardening_expected_service_unit_path="${remote_alpha_ags_hardening_expected_service_unit_path:-/etc/systemd/system/ags.service}"
  remote_alpha_ags_hardening_expected_service_dropin_dir="${remote_alpha_ags_hardening_expected_service_dropin_dir:-/etc/systemd/system/ags.service.d}"
  remote_alpha_ags_hardening_expected_service_dropin_path="${remote_alpha_ags_hardening_expected_service_dropin_path:-/etc/systemd/system/ags.service.d/10-account.conf}"
}

remote_alpha_ags_hardening_defaults() {
  remote_alpha_ags_hardening_init_expected_slice_inputs
  REMOTE_ALPHA_SERVICE_NAME="${remote_alpha_ags_hardening_expected_service_name}"
  REMOTE_ALPHA_SERVICE_USER="${remote_alpha_ags_hardening_expected_service_user}"
  REMOTE_ALPHA_SERVICE_GROUP="${remote_alpha_ags_hardening_expected_service_group}"
  REMOTE_ALPHA_BINARY_PATH="${remote_alpha_ags_hardening_expected_binary_path}"
  REMOTE_ALPHA_CONFIG_PATH="${remote_alpha_ags_hardening_expected_config_path}"
  REMOTE_ALPHA_HEALTHCHECK_ENV_PATH="${remote_alpha_ags_hardening_expected_healthcheck_env_path}"
  REMOTE_ALPHA_SERVICE_UNIT_PATH="${remote_alpha_ags_hardening_expected_service_unit_path}"
  REMOTE_ALPHA_SERVICE_DROPIN_DIR="${remote_alpha_ags_hardening_expected_service_dropin_dir}"
  REMOTE_ALPHA_SERVICE_DROPIN_PATH="${remote_alpha_ags_hardening_expected_service_dropin_path}"
  REMOTE_ALPHA_SUMMARY_PATH="${REMOTE_ALPHA_SUMMARY_PATH:-/var/tmp/execution-substrate-remote-alpha/ags-service-hardening-summary.json}"
  REMOTE_ALPHA_SUMMARY_DIR="$(dirname "${REMOTE_ALPHA_SUMMARY_PATH}")"
}

remote_alpha_ags_hardening_reject_slice_override_env() {
  local name=$1
  local expected=$2
  local actual=""

  actual="$(printenv "${name}" 2>/dev/null || true)"
  if [[ -z "${actual}" ]]; then
    return 0
  fi
  if [[ "${actual}" != "${expected}" ]]; then
    printf 'remote alpha AGS hardening does not accept %s override for this sealed AGS step within the current AGS sealed + ARS de-root tranche; expected repo-owned value %q (got %q)\n' "${name}" "${expected}" "${actual}" >&2
    return 1
  fi
  return 0
}

remote_alpha_ags_hardening_require_pinned_slice_inputs() {
  remote_alpha_ags_hardening_init_expected_slice_inputs
  remote_alpha_ags_hardening_reject_slice_override_env "REMOTE_ALPHA_SERVICE_NAME" "${remote_alpha_ags_hardening_expected_service_name}" || return 1
  remote_alpha_ags_hardening_reject_slice_override_env "REMOTE_ALPHA_SERVICE_USER" "${remote_alpha_ags_hardening_expected_service_user}" || return 1
  remote_alpha_ags_hardening_reject_slice_override_env "REMOTE_ALPHA_SERVICE_GROUP" "${remote_alpha_ags_hardening_expected_service_group}" || return 1
  remote_alpha_ags_hardening_reject_slice_override_env "REMOTE_ALPHA_BINARY_PATH" "${remote_alpha_ags_hardening_expected_binary_path}" || return 1
  remote_alpha_ags_hardening_reject_slice_override_env "REMOTE_ALPHA_CONFIG_PATH" "${remote_alpha_ags_hardening_expected_config_path}" || return 1
  remote_alpha_ags_hardening_reject_slice_override_env "REMOTE_ALPHA_HEALTHCHECK_ENV_PATH" "${remote_alpha_ags_hardening_expected_healthcheck_env_path}" || return 1
  remote_alpha_ags_hardening_reject_slice_override_env "REMOTE_ALPHA_SERVICE_UNIT_PATH" "${remote_alpha_ags_hardening_expected_service_unit_path}" || return 1
  remote_alpha_ags_hardening_reject_slice_override_env "REMOTE_ALPHA_SERVICE_DROPIN_DIR" "${remote_alpha_ags_hardening_expected_service_dropin_dir}" || return 1
  remote_alpha_ags_hardening_reject_slice_override_env "REMOTE_ALPHA_SERVICE_DROPIN_PATH" "${remote_alpha_ags_hardening_expected_service_dropin_path}" || return 1
}

remote_alpha_ags_hardening_usage() {
  cat <<'EOF'
Usage:
  sudo scripts/remote_alpha_harden_ags_service.sh

Optional flags:
  --summary-path </path/to/ags-service-hardening-summary.json>
  --help
EOF
}

remote_alpha_ags_hardening_parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --service-name)
        echo "remote alpha AGS hardening does not accept --service-name for this sealed AGS step within the current AGS sealed + ARS de-root tranche" >&2
        return 2
        ;;
      --service-user)
        echo "remote alpha AGS hardening does not accept --service-user for this sealed AGS step within the current AGS sealed + ARS de-root tranche" >&2
        return 2
        ;;
      --service-group)
        echo "remote alpha AGS hardening does not accept --service-group for this sealed AGS step within the current AGS sealed + ARS de-root tranche" >&2
        return 2
        ;;
      --binary-path)
        echo "remote alpha AGS hardening does not accept --binary-path for this sealed AGS step within the current AGS sealed + ARS de-root tranche" >&2
        return 2
        ;;
      --config-path)
        echo "remote alpha AGS hardening does not accept --config-path for this sealed AGS step within the current AGS sealed + ARS de-root tranche" >&2
        return 2
        ;;
      --healthcheck-env-path)
        echo "remote alpha AGS hardening does not accept --healthcheck-env-path for this sealed AGS step within the current AGS sealed + ARS de-root tranche" >&2
        return 2
        ;;
      --service-unit-path)
        echo "remote alpha AGS hardening does not accept --service-unit-path for this sealed AGS step within the current AGS sealed + ARS de-root tranche" >&2
        return 2
        ;;
      --service-dropin-dir)
        echo "remote alpha AGS hardening does not accept --service-dropin-dir for this sealed AGS step within the current AGS sealed + ARS de-root tranche" >&2
        return 2
        ;;
      --service-dropin-path)
        echo "remote alpha AGS hardening does not accept --service-dropin-path for this sealed AGS step within the current AGS sealed + ARS de-root tranche" >&2
        return 2
        ;;
      --summary-path)
        REMOTE_ALPHA_SUMMARY_PATH="$2"
        REMOTE_ALPHA_SUMMARY_DIR="$(dirname "${REMOTE_ALPHA_SUMMARY_PATH}")"
        shift 2
        ;;
      --help|-h)
        remote_alpha_ags_hardening_usage
        return 1
        ;;
      *)
        echo "unknown argument: $1" >&2
        remote_alpha_ags_hardening_usage >&2
        return 2
        ;;
    esac
  done
}

remote_alpha_ags_hardening_require_root() {
  if [[ "$(id -u)" != "0" ]]; then
    echo "remote alpha AGS hardening must run as root; use sudo scripts/remote_alpha_harden_ags_service.sh" >&2
    return 1
  fi
}

remote_alpha_ags_hardening_require_command() {
  local name=$1
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "${name} is required" >&2
    return 1
  fi
}

remote_alpha_ags_hardening_json_field() {
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

remote_alpha_ags_hardening_systemctl_state() {
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

remote_alpha_ags_hardening_passwordless_sudo_for_ds() {
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

remote_alpha_ags_hardening_ds_not_in_docker_group() {
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

remote_alpha_ags_hardening_runtime_meta() {
  python3 - "${REMOTE_ALPHA_CONFIG_PATH}" "${REMOTE_ALPHA_BINARY_PATH}" <<'PY'
import json
import pathlib
import sys

config_path = pathlib.Path(sys.argv[1])
binary_path = sys.argv[2]

result = {
    "status": "fail",
    "error": "",
    "binary_path": binary_path,
    "config_path": str(config_path),
    "bind_address": "",
    "port": 0,
    "health_url": "",
    "publish_url": "",
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
        "server_name": "",
    },
    "signer": {
        "material_location": str(config_path),
    },
    "local_state_paths": [],
    "log_sink": "journald",
    "dependencies": {
        "ars": True,
        "egs": False,
        "es": False,
    },
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
tls = payload.get("tls") or {}
deps = (payload.get("dependencies") or {}).get("artifact_registry") or {}
result["bind_address"] = str(http.get("bind_address") or "").strip()
result["port"] = int(http.get("port") or 0)
if result["bind_address"] and result["port"] > 0:
    result["health_url"] = f"https://{result['bind_address']}:{result['port']}/health"
    result["publish_url"] = f"https://{result['bind_address']}:{result['port']}/v1/artifacts:publish"
result["tls"]["cert_file"] = str(tls.get("cert_file") or "").strip()
result["tls"]["key_file"] = str(tls.get("key_file") or "").strip()
result["tls"]["client_ca_file"] = str(tls.get("client_ca_file") or "").strip()
result["artifact_registry"]["base_url"] = str(deps.get("base_url") or "").strip()
result["artifact_registry"]["client_cert_file"] = str(deps.get("client_cert_file") or "").strip()
result["artifact_registry"]["client_key_file"] = str(deps.get("client_key_file") or "").strip()
result["artifact_registry"]["root_ca_file"] = str(deps.get("root_ca_file") or "").strip()
result["artifact_registry"]["server_name"] = str(deps.get("server_name") or "").strip()

required_paths = [
    result["binary_path"],
    result["config_path"],
    result["tls"]["cert_file"],
    result["tls"]["key_file"],
    result["tls"]["client_ca_file"],
    result["artifact_registry"]["client_cert_file"],
    result["artifact_registry"]["client_key_file"],
    result["artifact_registry"]["root_ca_file"],
]
missing = [value for value in required_paths if not str(value).strip()]
if missing:
    result["error"] = "AGS runtime metadata is missing required file paths"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

result["status"] = "pass"
print(json.dumps(result, sort_keys=True))
PY
}

remote_alpha_ags_hardening_health_env_meta() {
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

remote_alpha_ags_hardening_verify_file_exists() {
  local label=$1
  local path=$2

  if [[ ! -e "${path}" ]]; then
    echo "${label} does not exist: ${path}" >&2
    return 1
  fi
}

remote_alpha_ags_hardening_verify_runtime_paths() {
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
    "artifact_registry.root_ca_file"; do
    value="$(remote_alpha_ags_hardening_json_field "${runtime_meta_path}" "${field}" 2>/dev/null || true)"
    [[ -n "${value}" ]] || continue
    paths+=("${field}:${value}")
  done

  for field in "ca_cert" "operator_cert" "operator_key"; do
    value="$(remote_alpha_ags_hardening_json_field "${health_env_meta_path}" "${field}" 2>/dev/null || true)"
    [[ -n "${value}" ]] || continue
    paths+=("${field}:${value}")
  done

  local entry=""
  local label=""
  local path=""
  for entry in "${paths[@]}"; do
    label="${entry%%:*}"
    path="${entry#*:}"
    remote_alpha_ags_hardening_verify_file_exists "${label}" "${path}" || return 1
  done
}

remote_alpha_ags_hardening_assert_unit_execstart() {
  local exec_start=""

  exec_start="$(systemctl show "${REMOTE_ALPHA_SERVICE_NAME}.service" -p ExecStart 2>/dev/null || true)"
  if [[ -z "${exec_start}" ]]; then
    echo "failed to read ExecStart for ${REMOTE_ALPHA_SERVICE_NAME}.service" >&2
    return 1
  fi
  if [[ "${exec_start}" != *"${REMOTE_ALPHA_BINARY_PATH}"* ]]; then
    echo "ags.service ExecStart does not contain expected binary path ${REMOTE_ALPHA_BINARY_PATH}" >&2
    return 1
  fi
  if [[ "${exec_start}" != *"${REMOTE_ALPHA_CONFIG_PATH}"* ]]; then
    echo "ags.service ExecStart does not contain expected config path ${REMOTE_ALPHA_CONFIG_PATH}" >&2
    return 1
  fi
}

remote_alpha_ags_hardening_ensure_group() {
  if getent group "${REMOTE_ALPHA_SERVICE_GROUP}" >/dev/null 2>&1; then
    return 0
  fi
  groupadd --system "${REMOTE_ALPHA_SERVICE_GROUP}"
}

remote_alpha_ags_hardening_ensure_user() {
  if id -u "${REMOTE_ALPHA_SERVICE_USER}" >/dev/null 2>&1; then
    local current_group=""
    current_group="$(id -gn "${REMOTE_ALPHA_SERVICE_USER}" 2>/dev/null || true)"
    if [[ "${current_group}" != "${REMOTE_ALPHA_SERVICE_GROUP}" ]]; then
      echo "existing AGS service user ${REMOTE_ALPHA_SERVICE_USER} does not use group ${REMOTE_ALPHA_SERVICE_GROUP}" >&2
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

remote_alpha_ags_hardening_apply_permissions() {
  local runtime_meta_path=$1
  local config_path tls_cert_path tls_key_path tls_ca_path ars_cert_path ars_key_path ars_ca_path tls_dir

  config_path="$(remote_alpha_ags_hardening_json_field "${runtime_meta_path}" "config_path")"
  tls_cert_path="$(remote_alpha_ags_hardening_json_field "${runtime_meta_path}" "tls.cert_file")"
  tls_key_path="$(remote_alpha_ags_hardening_json_field "${runtime_meta_path}" "tls.key_file")"
  tls_ca_path="$(remote_alpha_ags_hardening_json_field "${runtime_meta_path}" "tls.client_ca_file")"
  ars_cert_path="$(remote_alpha_ags_hardening_json_field "${runtime_meta_path}" "artifact_registry.client_cert_file")"
  ars_key_path="$(remote_alpha_ags_hardening_json_field "${runtime_meta_path}" "artifact_registry.client_key_file")"
  ars_ca_path="$(remote_alpha_ags_hardening_json_field "${runtime_meta_path}" "artifact_registry.root_ca_file")"
  tls_dir="$(dirname "${tls_cert_path}")"

  chown root:"${REMOTE_ALPHA_SERVICE_GROUP}" "${config_path}"
  chmod 0640 "${config_path}"

  chown root:"${REMOTE_ALPHA_SERVICE_GROUP}" "${tls_dir}"
  chmod 0710 "${tls_dir}"

  local file_path=""
  for file_path in \
    "${tls_cert_path}" \
    "${tls_key_path}" \
    "${tls_ca_path}" \
    "${ars_cert_path}" \
    "${ars_key_path}" \
    "${ars_ca_path}"; do
    chown root:"${REMOTE_ALPHA_SERVICE_GROUP}" "${file_path}"
    chmod 0640 "${file_path}"
  done
}

remote_alpha_ags_hardening_write_dropin() {
  mkdir -p "${REMOTE_ALPHA_SERVICE_DROPIN_DIR}"

  cat >"${REMOTE_ALPHA_SERVICE_DROPIN_PATH}" <<EOF
[Service]
User=${REMOTE_ALPHA_SERVICE_USER}
Group=${REMOTE_ALPHA_SERVICE_GROUP}
EOF
  chmod 0644 "${REMOTE_ALPHA_SERVICE_DROPIN_PATH}"
}

remote_alpha_ags_hardening_service_meta() {
  local service_name=$1
  local unit_name="${service_name}"
  if [[ "${unit_name}" != *.service ]]; then
    unit_name="${unit_name}.service"
  fi

  python3 - "${service_name}" \
    "$(systemctl show "${unit_name}" -p User -p Group -p ExecStart -p FragmentPath -p ActiveState -p SubState 2>/dev/null || true)" \
    "$(remote_alpha_ags_hardening_systemctl_state is-enabled "${unit_name}")" <<'PY'
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

remote_alpha_ags_hardening_health_probe_meta() {
  local runtime_meta_path=$1
  local health_env_meta_path=$2
  local response_path="$3"
  local error_path="$4"
  local url ca_cert operator_cert operator_key

  url="$(remote_alpha_ags_hardening_json_field "${runtime_meta_path}" "health_url")"
  ca_cert="$(remote_alpha_ags_hardening_json_field "${health_env_meta_path}" "ca_cert")"
  operator_cert="$(remote_alpha_ags_hardening_json_field "${health_env_meta_path}" "operator_cert")"
  operator_key="$(remote_alpha_ags_hardening_json_field "${health_env_meta_path}" "operator_key")"

  if curl --fail-with-body --silent --show-error \
    --cacert "${ca_cert}" \
    --cert "${operator_cert}" \
    --key "${operator_key}" \
    "${url}" >"${response_path}" 2>"${error_path}"; then
    python3 - "${url}" "${response_path}" <<'PY'
import json
import pathlib
import sys

url = sys.argv[1]
payload = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
ready = payload.get("ready") is True
status = "pass" if ready and payload.get("status") == "healthy" else "fail"
print(json.dumps({
    "status": status,
    "url": url,
    "ready": ready,
    "service": payload.get("service", ""),
    "dependency_artifact_registry": ((payload.get("additional_properties") or {}).get("dependencies") or {}).get("artifact_registry", ""),
}, sort_keys=True))
PY
    return 0
  fi

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
}

remote_alpha_ags_hardening_write_publish_request() {
  local request_path=$1

  python3 - "${request_path}" <<'PY'
import base64
import hashlib
import json
import pathlib
import sys

# Use a host-local-specific probe identity so this landed AGS seal step in the
# current hardening tranche does not collide with the existing Mac-side
# control-plane publish probe.
payload = b'#!/bin/sh\necho remote-alpha-ags-publish-probe-host-local\n'
build_log = b'remote-alpha-ags-publish-probe-host-local\n'

intent = {
    "kind": "remote-alpha-ags-publish-probe-host-local",
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

remote_alpha_ags_hardening_publish_probe_meta() {
  local runtime_meta_path=$1
  local health_env_meta_path=$2
  local response_path="$3"
  local error_path="$4"
  local request_path="$5"
  local url ca_cert operator_cert operator_key

  url="$(remote_alpha_ags_hardening_json_field "${runtime_meta_path}" "publish_url")"
  ca_cert="$(remote_alpha_ags_hardening_json_field "${health_env_meta_path}" "ca_cert")"
  operator_cert="$(remote_alpha_ags_hardening_json_field "${health_env_meta_path}" "operator_cert")"
  operator_key="$(remote_alpha_ags_hardening_json_field "${health_env_meta_path}" "operator_key")"

  remote_alpha_ags_hardening_write_publish_request "${request_path}"

  if curl --fail-with-body --silent --show-error \
    --cacert "${ca_cert}" \
    --cert "${operator_cert}" \
    --key "${operator_key}" \
    --header "content-type: application/json" \
    --data "@${request_path}" \
    "${url}" >"${response_path}" 2>"${error_path}"; then
    python3 - "${url}" "${response_path}" <<'PY'
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
}

remote_alpha_ags_hardening_write_summary() {
  local summary_path=$1
  local runtime_meta_path=$2
  local ags_meta_path=$3
  local ars_meta_path=$4
  local egs_meta_path=$5
  local es_meta_path=$6
  local health_meta_path=$7
  local publish_meta_path=$8
  local ds_not_in_docker_group=$9
  local passwordless_sudo_for_ds=${10}

  python3 - "${summary_path}" \
    "${runtime_meta_path}" \
    "${ags_meta_path}" \
    "${ars_meta_path}" \
    "${egs_meta_path}" \
    "${es_meta_path}" \
    "${health_meta_path}" \
    "${publish_meta_path}" \
    "${ds_not_in_docker_group}" \
    "${passwordless_sudo_for_ds}" \
    "${REMOTE_ALPHA_SERVICE_USER}" \
    "${REMOTE_ALPHA_SERVICE_GROUP}" \
    "${REMOTE_ALPHA_SERVICE_DROPIN_PATH}" \
    "${REMOTE_ALPHA_CONFIG_PATH}" \
    "${remote_alpha_ags_hardening_summary_schema_version}" <<'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone

summary_path = pathlib.Path(sys.argv[1])
runtime = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
ags_meta = json.loads(pathlib.Path(sys.argv[3]).read_text(encoding="utf-8"))
ars_meta = json.loads(pathlib.Path(sys.argv[4]).read_text(encoding="utf-8"))
egs_meta = json.loads(pathlib.Path(sys.argv[5]).read_text(encoding="utf-8"))
es_meta = json.loads(pathlib.Path(sys.argv[6]).read_text(encoding="utf-8"))
health = json.loads(pathlib.Path(sys.argv[7]).read_text(encoding="utf-8"))
publish = json.loads(pathlib.Path(sys.argv[8]).read_text(encoding="utf-8"))
ds_not_in_docker_group = sys.argv[9]
passwordless_sudo_for_ds = sys.argv[10]
service_user = sys.argv[11]
service_group = sys.argv[12]
dropin_path = sys.argv[13]
config_path = sys.argv[14]
schema_version = sys.argv[15]

tls_files = [
    runtime["tls"]["cert_file"],
    runtime["tls"]["key_file"],
    runtime["tls"]["client_ca_file"],
    runtime["artifact_registry"]["client_cert_file"],
    runtime["artifact_registry"]["client_key_file"],
    runtime["artifact_registry"]["root_ca_file"],
]

summary = {
    "schema_version": schema_version,
    "checked_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "slice": {
        "name": "remote-alpha-ags-service-hardening",
        "classification": "hardening_slice",
        "not_a_new_happy_path_proof": True,
    },
    "service": {
        "name": "ags",
        "user": service_user,
        "group": service_group,
        "binary_path": runtime["binary_path"],
        "config_path": runtime["config_path"],
        "health_url": runtime["health_url"],
        "publish_url": runtime["publish_url"],
        "active": ags_meta["active"],
        "enabled": ags_meta["enabled"],
        "fragment_path": ags_meta["fragment_path"],
        "exec_start": ags_meta["exec_start"],
    },
    "dependencies": {
        "artifact_registry": runtime["artifact_registry"],
        "server_tls": runtime["tls"],
        "signer": runtime["signer"],
        "local_state_paths": runtime["local_state_paths"],
        "log_sink": runtime["log_sink"],
        "depends_on_ars": runtime["dependencies"]["ars"],
        "depends_on_egs": runtime["dependencies"]["egs"],
        "depends_on_es": runtime["dependencies"]["es"],
    },
    "ownership_model": {
        "account": {
            "user": service_user,
            "group": service_group,
        },
        "config_file": {
            "path": config_path,
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
                "path": path,
                "owner": f"root:{service_group}",
                "mode": "0640",
            }
            for path in tls_files
        ],
        "systemd_dropin": {
            "path": dropin_path,
            "user": service_user,
            "group": service_group,
        },
    },
    "validation": {
        "local_health": health,
        "local_publish_probe": publish,
        "ars_service_posture": ars_meta,
        "egs_service_posture": egs_meta,
        "es_service_posture": es_meta,
        "mac_health_probe": "not_exercised",
        "mac_publish_probe": "not_exercised",
    },
    "preserved_remote_path": {
        "direct_https_mtls": True,
        "no_bridge": True,
        "no_shared_filesystem": True,
        "ags_health_path": runtime["health_url"],
        "ags_publish_path": runtime["publish_url"],
        "current_cp_es_im_boundaries_preserved": True,
    },
    "security": {
        "ds_not_in_docker_group": ds_not_in_docker_group,
        "passwordless_sudo_for_ds": passwordless_sudo_for_ds,
        "secret_material_in_summary": False,
    },
    "not_claimed": {
        "es_runtime_hardening": "not_claimed",
        "submit_runtime_profile_changes": "not_claimed",
        "spire_selector_model_changes": "not_claimed",
        "new_remote_happy_path_proof": "not_claimed",
    },
}

summary_path.parent.mkdir(parents=True, exist_ok=True)
summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

remote_alpha_ags_hardening_main() {
  local runtime_meta_path health_env_meta_path ags_meta_path ars_meta_path egs_meta_path es_meta_path
  local health_result_path health_error_path publish_result_path publish_error_path publish_request_path
  local tmpdir=""
  local ds_not_in_docker_group=""
  local passwordless_sudo_for_ds=""
  local overall_ok=true

  remote_alpha_ags_hardening_require_pinned_slice_inputs || return 1
  remote_alpha_ags_hardening_defaults
  remote_alpha_ags_hardening_parse_args "$@" || return $?
  remote_alpha_ags_hardening_require_root || return 1

  remote_alpha_ags_hardening_require_command python3 || return 1
  remote_alpha_prepare_output_dir "$(dirname "${REMOTE_ALPHA_SUMMARY_PATH}")" || return 1
  remote_alpha_ags_hardening_require_command curl || return 1
  remote_alpha_ags_hardening_require_command systemctl || return 1
  remote_alpha_ags_hardening_require_command getent || return 1
  remote_alpha_ags_hardening_require_command groupadd || return 1
  remote_alpha_ags_hardening_require_command useradd || return 1
  remote_alpha_ags_hardening_require_command chown || return 1
  remote_alpha_ags_hardening_require_command chmod || return 1
  remote_alpha_ags_hardening_require_command mkdir || return 1

  tmpdir="$(mktemp -d)"
  trap "rm -rf -- '${tmpdir}'" EXIT

  runtime_meta_path="${tmpdir}/runtime.json"
  health_env_meta_path="${tmpdir}/health-env.json"
  ags_meta_path="${tmpdir}/ags-service.json"
  ars_meta_path="${tmpdir}/ars-service.json"
  egs_meta_path="${tmpdir}/egs-service.json"
  es_meta_path="${tmpdir}/es-service.json"
  health_result_path="${tmpdir}/health-response.json"
  health_error_path="${tmpdir}/health-error.txt"
  publish_result_path="${tmpdir}/publish-response.json"
  publish_error_path="${tmpdir}/publish-error.txt"
  publish_request_path="${tmpdir}/publish-request.json"

  remote_alpha_ags_hardening_runtime_meta >"${runtime_meta_path}"
  if [[ "$(remote_alpha_ags_hardening_json_field "${runtime_meta_path}" "status" 2>/dev/null || true)" != "pass" ]]; then
    cat "${runtime_meta_path}" >&2
    return 1
  fi

  remote_alpha_ags_hardening_health_env_meta >"${health_env_meta_path}"
  if [[ "$(remote_alpha_ags_hardening_json_field "${health_env_meta_path}" "status" 2>/dev/null || true)" != "pass" ]]; then
    cat "${health_env_meta_path}" >&2
    return 1
  fi

  remote_alpha_ags_hardening_verify_runtime_paths "${runtime_meta_path}" "${health_env_meta_path}" || return 1
  remote_alpha_ags_hardening_assert_unit_execstart || return 1

  remote_alpha_ags_hardening_ensure_group || return 1
  remote_alpha_ags_hardening_ensure_user || return 1
  remote_alpha_ags_hardening_apply_permissions "${runtime_meta_path}" || return 1
  remote_alpha_ags_hardening_write_dropin || return 1

  systemctl daemon-reload
  systemctl enable "${REMOTE_ALPHA_SERVICE_NAME}.service" >/dev/null 2>&1 || overall_ok=false
  systemctl restart "${REMOTE_ALPHA_SERVICE_NAME}.service" || overall_ok=false

  remote_alpha_ags_hardening_service_meta "${REMOTE_ALPHA_SERVICE_NAME}" >"${ags_meta_path}"
  remote_alpha_ags_hardening_service_meta "ars" >"${ars_meta_path}"
  remote_alpha_ags_hardening_service_meta "egs" >"${egs_meta_path}"
  remote_alpha_ags_hardening_service_meta "es" >"${es_meta_path}"

  if [[ "$(remote_alpha_ags_hardening_json_field "${ags_meta_path}" "effective_user" 2>/dev/null || true)" != "${REMOTE_ALPHA_SERVICE_USER}" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_ags_hardening_json_field "${ags_meta_path}" "effective_group" 2>/dev/null || true)" != "${REMOTE_ALPHA_SERVICE_GROUP}" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_ags_hardening_json_field "${ags_meta_path}" "active" 2>/dev/null || true)" != "true" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_ags_hardening_json_field "${ags_meta_path}" "enabled" 2>/dev/null || true)" != "true" ]]; then
    overall_ok=false
  fi

  if [[ "$(remote_alpha_ags_hardening_json_field "${ars_meta_path}" "effective_user" 2>/dev/null || true)" != "ars" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_ags_hardening_json_field "${ars_meta_path}" "effective_group" 2>/dev/null || true)" != "ars" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_ags_hardening_json_field "${egs_meta_path}" "effective_user" 2>/dev/null || true)" != "egs" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_ags_hardening_json_field "${egs_meta_path}" "effective_group" 2>/dev/null || true)" != "egs" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_ags_hardening_json_field "${es_meta_path}" "effective_user" 2>/dev/null || true)" != "es" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_ags_hardening_json_field "${es_meta_path}" "effective_group" 2>/dev/null || true)" != "es" ]]; then
    overall_ok=false
  fi

  remote_alpha_ags_hardening_health_probe_meta "${runtime_meta_path}" "${health_env_meta_path}" "${health_result_path}" "${health_error_path}" >"${tmpdir}/health-meta.json" || overall_ok=false
  remote_alpha_ags_hardening_publish_probe_meta "${runtime_meta_path}" "${health_env_meta_path}" "${publish_result_path}" "${publish_error_path}" "${publish_request_path}" >"${tmpdir}/publish-meta.json" || overall_ok=false

  if [[ "$(remote_alpha_ags_hardening_json_field "${tmpdir}/health-meta.json" "status" 2>/dev/null || true)" != "pass" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_ags_hardening_json_field "${tmpdir}/publish-meta.json" "status" 2>/dev/null || true)" != "pass" ]]; then
    overall_ok=false
  fi

  ds_not_in_docker_group="$(remote_alpha_ags_hardening_ds_not_in_docker_group)"
  passwordless_sudo_for_ds="$(remote_alpha_ags_hardening_passwordless_sudo_for_ds)"

  if [[ "${ds_not_in_docker_group}" != "true" ]]; then
    overall_ok=false
  fi
  if [[ "${passwordless_sudo_for_ds}" != "false" ]]; then
    overall_ok=false
  fi

  remote_alpha_prepare_output_dir "$(dirname "${REMOTE_ALPHA_SUMMARY_PATH}")" || return 1
  remote_alpha_ags_hardening_write_summary \
    "${REMOTE_ALPHA_SUMMARY_PATH}" \
    "${runtime_meta_path}" \
    "${ags_meta_path}" \
    "${ars_meta_path}" \
    "${egs_meta_path}" \
    "${es_meta_path}" \
    "${tmpdir}/health-meta.json" \
    "${tmpdir}/publish-meta.json" \
    "${ds_not_in_docker_group}" \
    "${passwordless_sudo_for_ds}"

  chmod 0644 "${REMOTE_ALPHA_SUMMARY_PATH}" 2>/dev/null || true

  if [[ "${overall_ok}" != "true" ]]; then
    echo "remote alpha AGS hardening finished with validation failures; see ${REMOTE_ALPHA_SUMMARY_PATH}" >&2
    return 1
  fi

  printf '%s\n' "${REMOTE_ALPHA_SUMMARY_PATH}"
}
