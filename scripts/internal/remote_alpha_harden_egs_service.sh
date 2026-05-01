if [[ -z "${REPO_ROOT:-}" ]]; then
  REMOTE_ALPHA_EGS_HARDENING_HELPER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  REPO_ROOT="$(cd "${REMOTE_ALPHA_EGS_HARDENING_HELPER_DIR}/../.." && pwd)"
fi

remote_alpha_egs_hardening_summary_schema_version="execution-substrate.remote-alpha.egs-service-hardening-summary.v2"

remote_alpha_egs_hardening_init_expected_slice_inputs() {
  remote_alpha_egs_hardening_expected_service_name="${remote_alpha_egs_hardening_expected_service_name:-egs}"
  remote_alpha_egs_hardening_expected_service_user="${remote_alpha_egs_hardening_expected_service_user:-egs}"
  remote_alpha_egs_hardening_expected_service_group="${remote_alpha_egs_hardening_expected_service_group:-egs}"
  remote_alpha_egs_hardening_expected_binary_path="${remote_alpha_egs_hardening_expected_binary_path:-/usr/local/lib/execution-substrate/bin/egs}"
  remote_alpha_egs_hardening_expected_config_path="${remote_alpha_egs_hardening_expected_config_path:-/etc/execution-substrate/egs.json}"
  remote_alpha_egs_hardening_expected_healthcheck_env_path="${remote_alpha_egs_hardening_expected_healthcheck_env_path:-/etc/execution-substrate/healthcheck.env}"
  remote_alpha_egs_hardening_expected_service_unit_path="${remote_alpha_egs_hardening_expected_service_unit_path:-/etc/systemd/system/egs.service}"
  remote_alpha_egs_hardening_expected_service_dropin_dir="${remote_alpha_egs_hardening_expected_service_dropin_dir:-/etc/systemd/system/egs.service.d}"
  remote_alpha_egs_hardening_expected_service_dropin_path="${remote_alpha_egs_hardening_expected_service_dropin_path:-/etc/systemd/system/egs.service.d/10-account.conf}"
  remote_alpha_egs_hardening_expected_tls_dir="${remote_alpha_egs_hardening_expected_tls_dir:-/etc/execution-substrate/egs-tls}"
  remote_alpha_egs_hardening_expected_shared_tls_dir="${remote_alpha_egs_hardening_expected_shared_tls_dir:-/etc/execution-substrate/tls}"
  remote_alpha_egs_hardening_expected_ags_config_path="${remote_alpha_egs_hardening_expected_ags_config_path:-/etc/execution-substrate/ags.json}"
  remote_alpha_egs_hardening_expected_es_config_path="${remote_alpha_egs_hardening_expected_es_config_path:-/etc/execution-substrate/es.json}"
  remote_alpha_egs_hardening_expected_bind_address="${remote_alpha_egs_hardening_expected_bind_address:-127.0.0.1}"
  remote_alpha_egs_hardening_expected_port="${remote_alpha_egs_hardening_expected_port:-8443}"
}

remote_alpha_egs_hardening_defaults() {
  remote_alpha_egs_hardening_init_expected_slice_inputs
  REMOTE_ALPHA_SERVICE_NAME="${remote_alpha_egs_hardening_expected_service_name}"
  REMOTE_ALPHA_SERVICE_USER="${remote_alpha_egs_hardening_expected_service_user}"
  REMOTE_ALPHA_SERVICE_GROUP="${remote_alpha_egs_hardening_expected_service_group}"
  REMOTE_ALPHA_BINARY_PATH="${remote_alpha_egs_hardening_expected_binary_path}"
  REMOTE_ALPHA_CONFIG_PATH="${remote_alpha_egs_hardening_expected_config_path}"
  REMOTE_ALPHA_HEALTHCHECK_ENV_PATH="${remote_alpha_egs_hardening_expected_healthcheck_env_path}"
  REMOTE_ALPHA_SERVICE_UNIT_PATH="${remote_alpha_egs_hardening_expected_service_unit_path}"
  REMOTE_ALPHA_SERVICE_DROPIN_DIR="${remote_alpha_egs_hardening_expected_service_dropin_dir}"
  REMOTE_ALPHA_SERVICE_DROPIN_PATH="${remote_alpha_egs_hardening_expected_service_dropin_path}"
  REMOTE_ALPHA_TLS_DIR="${remote_alpha_egs_hardening_expected_tls_dir}"
  REMOTE_ALPHA_TLS_CERT_PATH="${REMOTE_ALPHA_TLS_DIR}/egs-server-cert.pem"
  REMOTE_ALPHA_TLS_KEY_PATH="${REMOTE_ALPHA_TLS_DIR}/egs-server-key.pem"
  REMOTE_ALPHA_TLS_CLIENT_CA_PATH="${REMOTE_ALPHA_TLS_DIR}/runtime-ca.pem"
  REMOTE_ALPHA_AGS_CONFIG_PATH="${remote_alpha_egs_hardening_expected_ags_config_path}"
  REMOTE_ALPHA_ES_CONFIG_PATH="${remote_alpha_egs_hardening_expected_es_config_path}"
  REMOTE_ALPHA_SUMMARY_PATH="${REMOTE_ALPHA_SUMMARY_PATH:-/var/tmp/execution-substrate-remote-alpha/egs-service-hardening-summary.json}"
  REMOTE_ALPHA_SUMMARY_DIR="$(dirname "${REMOTE_ALPHA_SUMMARY_PATH}")"
}

remote_alpha_egs_hardening_reject_slice_override_env() {
  local name=$1
  local expected=$2
  local actual=""

  actual="$(printenv "${name}" 2>/dev/null || true)"
  if [[ -z "${actual}" ]]; then
    return 0
  fi
  if [[ "${actual}" != "${expected}" ]]; then
    printf 'remote alpha EGS hardening does not accept %s override for this sealed EGS de-root step within the current AGS sealed + ARS de-root + EGS de-root tranche; expected repo-owned value %q (got %q)\n' "${name}" "${expected}" "${actual}" >&2
    return 1
  fi
  return 0
}

remote_alpha_egs_hardening_require_pinned_slice_inputs() {
  remote_alpha_egs_hardening_init_expected_slice_inputs
  remote_alpha_egs_hardening_reject_slice_override_env "REMOTE_ALPHA_SERVICE_NAME" "${remote_alpha_egs_hardening_expected_service_name}" || return 1
  remote_alpha_egs_hardening_reject_slice_override_env "REMOTE_ALPHA_SERVICE_USER" "${remote_alpha_egs_hardening_expected_service_user}" || return 1
  remote_alpha_egs_hardening_reject_slice_override_env "REMOTE_ALPHA_SERVICE_GROUP" "${remote_alpha_egs_hardening_expected_service_group}" || return 1
  remote_alpha_egs_hardening_reject_slice_override_env "REMOTE_ALPHA_BINARY_PATH" "${remote_alpha_egs_hardening_expected_binary_path}" || return 1
  remote_alpha_egs_hardening_reject_slice_override_env "REMOTE_ALPHA_CONFIG_PATH" "${remote_alpha_egs_hardening_expected_config_path}" || return 1
  remote_alpha_egs_hardening_reject_slice_override_env "REMOTE_ALPHA_HEALTHCHECK_ENV_PATH" "${remote_alpha_egs_hardening_expected_healthcheck_env_path}" || return 1
  remote_alpha_egs_hardening_reject_slice_override_env "REMOTE_ALPHA_SERVICE_UNIT_PATH" "${remote_alpha_egs_hardening_expected_service_unit_path}" || return 1
  remote_alpha_egs_hardening_reject_slice_override_env "REMOTE_ALPHA_SERVICE_DROPIN_DIR" "${remote_alpha_egs_hardening_expected_service_dropin_dir}" || return 1
  remote_alpha_egs_hardening_reject_slice_override_env "REMOTE_ALPHA_SERVICE_DROPIN_PATH" "${remote_alpha_egs_hardening_expected_service_dropin_path}" || return 1
}

remote_alpha_egs_hardening_usage() {
  cat <<'EOF'
Usage:
  sudo scripts/remote_alpha_harden_egs_service.sh

Optional flags:
  --summary-path </path/to/egs-service-hardening-summary.json>
  --help
EOF
}

remote_alpha_egs_hardening_parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --service-name)
        echo "remote alpha EGS hardening does not accept --service-name for this sealed EGS de-root step within the current AGS sealed + ARS de-root + EGS de-root tranche" >&2
        return 2
        ;;
      --service-user)
        echo "remote alpha EGS hardening does not accept --service-user for this sealed EGS de-root step within the current AGS sealed + ARS de-root + EGS de-root tranche" >&2
        return 2
        ;;
      --service-group)
        echo "remote alpha EGS hardening does not accept --service-group for this sealed EGS de-root step within the current AGS sealed + ARS de-root + EGS de-root tranche" >&2
        return 2
        ;;
      --binary-path)
        echo "remote alpha EGS hardening does not accept --binary-path for this sealed EGS de-root step within the current AGS sealed + ARS de-root + EGS de-root tranche" >&2
        return 2
        ;;
      --config-path)
        echo "remote alpha EGS hardening does not accept --config-path for this sealed EGS de-root step within the current AGS sealed + ARS de-root + EGS de-root tranche" >&2
        return 2
        ;;
      --healthcheck-env-path)
        echo "remote alpha EGS hardening does not accept --healthcheck-env-path for this sealed EGS de-root step within the current AGS sealed + ARS de-root + EGS de-root tranche" >&2
        return 2
        ;;
      --service-unit-path)
        echo "remote alpha EGS hardening does not accept --service-unit-path for this sealed EGS de-root step within the current AGS sealed + ARS de-root + EGS de-root tranche" >&2
        return 2
        ;;
      --service-dropin-dir)
        echo "remote alpha EGS hardening does not accept --service-dropin-dir for this sealed EGS de-root step within the current AGS sealed + ARS de-root + EGS de-root tranche" >&2
        return 2
        ;;
      --service-dropin-path)
        echo "remote alpha EGS hardening does not accept --service-dropin-path for this sealed EGS de-root step within the current AGS sealed + ARS de-root + EGS de-root tranche" >&2
        return 2
        ;;
      --summary-path)
        REMOTE_ALPHA_SUMMARY_PATH="$2"
        REMOTE_ALPHA_SUMMARY_DIR="$(dirname "${REMOTE_ALPHA_SUMMARY_PATH}")"
        shift 2
        ;;
      --help|-h)
        remote_alpha_egs_hardening_usage
        return 1
        ;;
      *)
        echo "unknown argument: $1" >&2
        remote_alpha_egs_hardening_usage >&2
        return 2
        ;;
    esac
  done
}

remote_alpha_egs_hardening_require_root() {
  if [[ "$(id -u)" != "0" ]]; then
    echo "remote alpha EGS hardening must run as root; use sudo scripts/remote_alpha_harden_egs_service.sh" >&2
    return 1
  fi
}

remote_alpha_egs_hardening_require_command() {
  local name=$1
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "${name} is required" >&2
    return 1
  fi
}

remote_alpha_egs_hardening_json_field() {
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

remote_alpha_egs_hardening_systemctl_state() {
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

remote_alpha_egs_hardening_passwordless_sudo_for_ds() {
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

remote_alpha_egs_hardening_ds_not_in_docker_group() {
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

remote_alpha_egs_hardening_service_account_meta() {
  python3 - "${REMOTE_ALPHA_SERVICE_USER}" "${REMOTE_ALPHA_SERVICE_GROUP}" <<'PY'
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
    return subprocess.run(
        ["id", *args],
        check=False,
        capture_output=True,
        text=True,
    )


uid_proc = run_id("-u", user)
if uid_proc.returncode != 0:
    result["error"] = f"EGS service user {user} does not exist"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)
result["uid"] = uid_proc.stdout.strip()

primary_group_proc = run_id("-gn", user)
if primary_group_proc.returncode != 0:
    result["error"] = f"failed to read primary group for EGS service user {user}"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)
result["primary_group"] = primary_group_proc.stdout.strip()

group_names_proc = run_id("-nG", user)
if group_names_proc.returncode != 0:
    result["error"] = f"failed to read group list for EGS service user {user}"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

group_names = []
for item in group_names_proc.stdout.split():
    if item and item not in group_names:
        group_names.append(item)
result["group_names"] = group_names
result["supplementary_groups"] = [group for group in group_names if group != result["primary_group"]]

if result["primary_group"] != expected_group:
    result["error"] = f"existing EGS service user {user} does not use primary group {expected_group}"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

if expected_group not in group_names:
    result["error"] = f"existing EGS service user {user} is missing expected group {expected_group} in id -nG output"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

if result["supplementary_groups"]:
    joined = ", ".join(result["supplementary_groups"])
    result["error"] = (
        f"existing EGS service user {user} is broader than this slice allows; "
        f"supplementary groups present: {joined}"
    )
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

group_proc = subprocess.run(
    ["getent", "group", expected_group],
    check=False,
    capture_output=True,
    text=True,
)
if group_proc.returncode != 0:
    result["error"] = f"failed to read EGS service group entry for {expected_group}"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

group_line = ""
for raw in group_proc.stdout.splitlines():
    line = raw.strip()
    if line:
        group_line = line
        break

group_fields = group_line.split(":")
if len(group_fields) < 4:
    result["error"] = f"failed to parse EGS service group entry for {expected_group}"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

result["group_gid"] = group_fields[2].strip()
group_entry_members = []
for member in group_fields[3].split(","):
    member = member.strip()
    if member and member not in group_entry_members:
        group_entry_members.append(member)
result["group_entry_members"] = group_entry_members

passwd_proc = subprocess.run(
    ["getent", "passwd"],
    check=False,
    capture_output=True,
    text=True,
)
if passwd_proc.returncode != 0:
    result["error"] = f"failed to enumerate passwd entries while checking EGS group {expected_group}"
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

if user not in group_members:
    result["error"] = (
        f"failed to prove EGS service group {expected_group} membership for {user}; "
        "group enumeration did not include the service user"
    )
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

if result["unexpected_group_members"]:
    joined = ", ".join(result["unexpected_group_members"])
    result["error"] = (
        f"existing EGS service group {expected_group} is broader than this slice allows; "
        f"unexpected group members present: {joined}"
    )
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

result["narrow_dedicated_account"] = True
result["status"] = "pass"
print(json.dumps(result, sort_keys=True))
PY
}

remote_alpha_egs_hardening_runtime_meta() {
  python3 - "${REMOTE_ALPHA_CONFIG_PATH}" "${REMOTE_ALPHA_BINARY_PATH}" <<'PY'
import json
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
    "signer": {
        "material_location": str(config_path),
    },
    "runtime_trust": {
        "material_location": str(config_path),
    },
    "publication": {
        "material_location": str(config_path),
    },
    "local_state_paths": [],
    "log_sink": "journald",
    "dependencies": {
        "ags": False,
        "ars": False,
        "es": False,
    },
}

try:
    payload = json.loads(config_path.read_text(encoding="utf-8"))
except FileNotFoundError:
    result["error"] = "EGS config file does not exist"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)
except Exception as exc:
    result["error"] = f"read or decode EGS config: {exc}"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

http = payload.get("http") or {}
tls = payload.get("tls") or {}
result["bind_address"] = str(http.get("bind_address") or "").strip()
result["port"] = int(http.get("port") or 0)
if result["bind_address"] and result["port"] > 0:
    result["health_url"] = f"https://{result['bind_address']}:{result['port']}/health"

result["tls"]["cert_file"] = str(tls.get("cert_file") or "").strip()
result["tls"]["key_file"] = str(tls.get("key_file") or "").strip()
result["tls"]["client_ca_file"] = str(tls.get("client_ca_file") or "").strip()

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
]
missing = [value for value in required_paths if not str(value).strip()]
if missing:
    result["error"] = "EGS runtime metadata is missing required file paths"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

result["status"] = "pass"
print(json.dumps(result, sort_keys=True))
PY
}

remote_alpha_egs_hardening_assert_runtime_shape() {
  local runtime_meta_path=$1
  local bind_address port cert_file key_file ca_file

  bind_address="$(remote_alpha_egs_hardening_json_field "${runtime_meta_path}" "bind_address" 2>/dev/null || true)"
  port="$(remote_alpha_egs_hardening_json_field "${runtime_meta_path}" "port" 2>/dev/null || true)"
  cert_file="$(remote_alpha_egs_hardening_json_field "${runtime_meta_path}" "tls.cert_file" 2>/dev/null || true)"
  key_file="$(remote_alpha_egs_hardening_json_field "${runtime_meta_path}" "tls.key_file" 2>/dev/null || true)"
  ca_file="$(remote_alpha_egs_hardening_json_field "${runtime_meta_path}" "tls.client_ca_file" 2>/dev/null || true)"

  if [[ "${bind_address}" != "${remote_alpha_egs_hardening_expected_bind_address}" ]]; then
    echo "remote alpha EGS hardening expected bind_address ${remote_alpha_egs_hardening_expected_bind_address}, got ${bind_address}" >&2
    return 1
  fi
  if [[ "${port}" != "${remote_alpha_egs_hardening_expected_port}" ]]; then
    echo "remote alpha EGS hardening expected port ${remote_alpha_egs_hardening_expected_port}, got ${port}" >&2
    return 1
  fi

  case "${cert_file}" in
    "${remote_alpha_egs_hardening_expected_shared_tls_dir}/egs-server-cert.pem"|\
    "${remote_alpha_egs_hardening_expected_tls_dir}/egs-server-cert.pem")
      ;;
    *)
      echo "remote alpha EGS hardening expected egs server cert under ${remote_alpha_egs_hardening_expected_shared_tls_dir} or ${remote_alpha_egs_hardening_expected_tls_dir}, got ${cert_file}" >&2
      return 1
      ;;
  esac
  case "${key_file}" in
    "${remote_alpha_egs_hardening_expected_shared_tls_dir}/egs-server-key.pem"|\
    "${remote_alpha_egs_hardening_expected_tls_dir}/egs-server-key.pem")
      ;;
    *)
      echo "remote alpha EGS hardening expected egs server key under ${remote_alpha_egs_hardening_expected_shared_tls_dir} or ${remote_alpha_egs_hardening_expected_tls_dir}, got ${key_file}" >&2
      return 1
      ;;
  esac
  case "${ca_file}" in
    "${remote_alpha_egs_hardening_expected_shared_tls_dir}/runtime-ca.pem"|\
    "${remote_alpha_egs_hardening_expected_tls_dir}/runtime-ca.pem")
      ;;
    *)
      echo "remote alpha EGS hardening expected egs client CA / runtime root CA under ${remote_alpha_egs_hardening_expected_shared_tls_dir} or ${remote_alpha_egs_hardening_expected_tls_dir}, got ${ca_file}" >&2
      return 1
      ;;
  esac
}

remote_alpha_egs_hardening_ags_runtime_meta() {
  python3 - "${REMOTE_ALPHA_AGS_CONFIG_PATH}" <<'PY'
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

remote_alpha_egs_hardening_es_runtime_meta() {
  python3 - "${REMOTE_ALPHA_ES_CONFIG_PATH}" <<'PY'
import json
import sys
from pathlib import Path

config_path = Path(sys.argv[1])
result = {
    "status": "fail",
    "error": "",
    "config_path": str(config_path),
    "health_url": "",
    "contract_url": "",
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
port = int(http.get("port") or 0)
if bind_address and port > 0:
    base_url = f"https://{bind_address}:{port}"
    result["health_url"] = base_url + "/health"
    result["contract_url"] = base_url + "/v1/executions:contract"

if not result["health_url"] or not result["contract_url"]:
    result["error"] = "ES runtime metadata is missing health or contract URL inputs"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

result["status"] = "pass"
print(json.dumps(result, sort_keys=True))
PY
}

remote_alpha_egs_hardening_health_env_meta() {
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

remote_alpha_egs_hardening_verify_file_exists() {
  local label=$1
  local path=$2

  if [[ ! -e "${path}" ]]; then
    echo "${label} does not exist: ${path}" >&2
    return 1
  fi
}

remote_alpha_egs_hardening_verify_runtime_paths() {
  local runtime_meta_path=$1
  local health_env_meta_path=$2
  local ags_runtime_meta_path=$3
  local es_runtime_meta_path=$4
  local paths=()
  local value=""

  for field in \
    "binary_path" \
    "config_path" \
    "tls.cert_file" \
    "tls.key_file" \
    "tls.client_ca_file"; do
    value="$(remote_alpha_egs_hardening_json_field "${runtime_meta_path}" "${field}" 2>/dev/null || true)"
    [[ -n "${value}" ]] || continue
    paths+=("${field}:${value}")
  done

  value="$(remote_alpha_egs_hardening_json_field "${ags_runtime_meta_path}" "config_path" 2>/dev/null || true)"
  if [[ -n "${value}" ]]; then
    paths+=("ags.config_path:${value}")
  fi
  value="$(remote_alpha_egs_hardening_json_field "${es_runtime_meta_path}" "config_path" 2>/dev/null || true)"
  if [[ -n "${value}" ]]; then
    paths+=("es.config_path:${value}")
  fi

  for field in "ca_cert" "operator_cert" "operator_key"; do
    value="$(remote_alpha_egs_hardening_json_field "${health_env_meta_path}" "${field}" 2>/dev/null || true)"
    [[ -n "${value}" ]] || continue
    paths+=("${field}:${value}")
  done

  local entry=""
  local label=""
  local path=""
  for entry in "${paths[@]}"; do
    label="${entry%%:*}"
    path="${entry#*:}"
    remote_alpha_egs_hardening_verify_file_exists "${label}" "${path}" || return 1
  done
}

remote_alpha_egs_hardening_assert_unit_execstart() {
  local exec_start=""

  exec_start="$(systemctl show "${REMOTE_ALPHA_SERVICE_NAME}.service" -p ExecStart 2>/dev/null || true)"
  if [[ -z "${exec_start}" ]]; then
    echo "failed to read ExecStart for ${REMOTE_ALPHA_SERVICE_NAME}.service" >&2
    return 1
  fi
  if [[ "${exec_start}" != *"${REMOTE_ALPHA_BINARY_PATH}"* ]]; then
    echo "egs.service ExecStart does not contain expected binary path ${REMOTE_ALPHA_BINARY_PATH}" >&2
    return 1
  fi
  if [[ "${exec_start}" != *"${REMOTE_ALPHA_CONFIG_PATH}"* ]]; then
    echo "egs.service ExecStart does not contain expected config path ${REMOTE_ALPHA_CONFIG_PATH}" >&2
    return 1
  fi
}

remote_alpha_egs_hardening_ensure_group() {
  if getent group "${REMOTE_ALPHA_SERVICE_GROUP}" >/dev/null 2>&1; then
    return 0
  fi
  groupadd --system "${REMOTE_ALPHA_SERVICE_GROUP}"
}

remote_alpha_egs_hardening_ensure_user() {
  if id -u "${REMOTE_ALPHA_SERVICE_USER}" >/dev/null 2>&1; then
    local account_meta_path=""
    local account_status=""
    local account_error=""

    account_meta_path="$(mktemp)"
    remote_alpha_egs_hardening_service_account_meta >"${account_meta_path}"
    account_status="$(remote_alpha_egs_hardening_json_field "${account_meta_path}" "status" 2>/dev/null || true)"
    if [[ "${account_status}" != "pass" ]]; then
      account_error="$(remote_alpha_egs_hardening_json_field "${account_meta_path}" "error" 2>/dev/null || true)"
      rm -f -- "${account_meta_path}"
      if [[ -z "${account_error}" ]]; then
        account_error="existing EGS service user ${REMOTE_ALPHA_SERVICE_USER} is not acceptably narrow for this slice"
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
    --gid "${REMOTE_ALPHA_SERVICE_GROUP}" \
    --home-dir /nonexistent \
    --no-create-home \
    --shell "${nologin_path}" \
    "${REMOTE_ALPHA_SERVICE_USER}"
}

remote_alpha_egs_hardening_prepare_tls_material() {
  local runtime_meta_path=$1
  local cert_source key_source ca_source

  cert_source="$(remote_alpha_egs_hardening_json_field "${runtime_meta_path}" "tls.cert_file")"
  key_source="$(remote_alpha_egs_hardening_json_field "${runtime_meta_path}" "tls.key_file")"
  ca_source="$(remote_alpha_egs_hardening_json_field "${runtime_meta_path}" "tls.client_ca_file")"

  python3 - \
    "${cert_source}" "${REMOTE_ALPHA_TLS_CERT_PATH}" \
    "${key_source}" "${REMOTE_ALPHA_TLS_KEY_PATH}" \
    "${ca_source}" "${REMOTE_ALPHA_TLS_CLIENT_CA_PATH}" <<'PY'
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

remote_alpha_egs_hardening_rewrite_config() {
  python3 - "${REMOTE_ALPHA_CONFIG_PATH}" "${REMOTE_ALPHA_TLS_CERT_PATH}" "${REMOTE_ALPHA_TLS_KEY_PATH}" "${REMOTE_ALPHA_TLS_CLIENT_CA_PATH}" <<'PY'
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

remote_alpha_egs_hardening_write_dropin() {
  mkdir -p "${REMOTE_ALPHA_SERVICE_DROPIN_DIR}"

  cat >"${REMOTE_ALPHA_SERVICE_DROPIN_PATH}" <<EOF
[Service]
User=${REMOTE_ALPHA_SERVICE_USER}
Group=${REMOTE_ALPHA_SERVICE_GROUP}
UMask=0027
EOF
  chmod 0644 "${REMOTE_ALPHA_SERVICE_DROPIN_PATH}"
}

remote_alpha_egs_hardening_service_meta() {
  local service_name=$1
  local unit_name="${service_name}"
  if [[ "${unit_name}" != *.service ]]; then
    unit_name="${unit_name}.service"
  fi

  python3 - "${service_name}" \
    "$(systemctl show "${unit_name}" -p User -p Group -p ExecStart -p FragmentPath -p ActiveState -p SubState 2>/dev/null || true)" \
    "$(remote_alpha_egs_hardening_systemctl_state is-enabled "${unit_name}")" <<'PY'
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

remote_alpha_egs_hardening_health_probe_meta() {
  local url=$1
  local resolve=$2
  local health_env_meta_path=$3
  local response_path=$4
  local error_path=$5
  local dependency_field=$6
  local ca_cert operator_cert operator_key
  local -a curl_args=()

  ca_cert="$(remote_alpha_egs_hardening_json_field "${health_env_meta_path}" "ca_cert")"
  operator_cert="$(remote_alpha_egs_hardening_json_field "${health_env_meta_path}" "operator_cert")"
  operator_key="$(remote_alpha_egs_hardening_json_field "${health_env_meta_path}" "operator_key")"

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
  elif ! curl --fail-with-body --silent --show-error \
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

remote_alpha_egs_hardening_write_publish_request() {
  local request_path=$1

  python3 - "${request_path}" <<'PY'
import base64
import hashlib
import json
import pathlib
import sys

payload = b'#!/bin/sh\necho remote-alpha-egs-posture-publish-probe-host-local\n'
build_log = b'remote-alpha-egs-posture-publish-probe-host-local\n'

intent = {
    "kind": "remote-alpha-egs-posture-publish-probe-host-local",
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

remote_alpha_egs_hardening_publish_probe_meta() {
  local ags_runtime_meta_path=$1
  local health_env_meta_path=$2
  local response_path=$3
  local error_path=$4
  local request_path=$5
  local url ca_cert operator_cert operator_key

  url="$(remote_alpha_egs_hardening_json_field "${ags_runtime_meta_path}" "publish_url")"
  ca_cert="$(remote_alpha_egs_hardening_json_field "${health_env_meta_path}" "ca_cert")"
  operator_cert="$(remote_alpha_egs_hardening_json_field "${health_env_meta_path}" "operator_cert")"
  operator_key="$(remote_alpha_egs_hardening_json_field "${health_env_meta_path}" "operator_key")"

  remote_alpha_egs_hardening_write_publish_request "${request_path}"

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

remote_alpha_egs_hardening_contract_probe_meta() {
  local es_runtime_meta_path=$1
  local health_env_meta_path=$2
  local response_path=$3
  local error_path=$4
  local url ca_cert operator_cert operator_key

  url="$(remote_alpha_egs_hardening_json_field "${es_runtime_meta_path}" "contract_url")"
  ca_cert="$(remote_alpha_egs_hardening_json_field "${health_env_meta_path}" "ca_cert")"
  operator_cert="$(remote_alpha_egs_hardening_json_field "${health_env_meta_path}" "operator_cert")"
  operator_key="$(remote_alpha_egs_hardening_json_field "${health_env_meta_path}" "operator_key")"

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

remote_alpha_egs_hardening_ownership_meta() {
  local runtime_meta_path=$1
  local config_path tls_dir
  config_path="$(remote_alpha_egs_hardening_json_field "${runtime_meta_path}" "config_path")"
  tls_dir="${REMOTE_ALPHA_TLS_DIR}"

  python3 - \
    "${config_path}" "root:${REMOTE_ALPHA_SERVICE_GROUP}" "0640" "$(stat -c '%U:%G %a %n' "${config_path}" 2>/dev/null || true)" \
    "${tls_dir}" "root:${REMOTE_ALPHA_SERVICE_GROUP}" "0710" "$(stat -c '%U:%G %a %n' "${tls_dir}" 2>/dev/null || true)" \
    "${REMOTE_ALPHA_TLS_CERT_PATH}" "root:${REMOTE_ALPHA_SERVICE_GROUP}" "0640" "$(stat -c '%U:%G %a %n' "${REMOTE_ALPHA_TLS_CERT_PATH}" 2>/dev/null || true)" \
    "${REMOTE_ALPHA_TLS_KEY_PATH}" "root:${REMOTE_ALPHA_SERVICE_GROUP}" "0640" "$(stat -c '%U:%G %a %n' "${REMOTE_ALPHA_TLS_KEY_PATH}" 2>/dev/null || true)" \
    "${REMOTE_ALPHA_TLS_CLIENT_CA_PATH}" "root:${REMOTE_ALPHA_SERVICE_GROUP}" "0640" "$(stat -c '%U:%G %a %n' "${REMOTE_ALPHA_TLS_CLIENT_CA_PATH}" 2>/dev/null || true)" <<'PY'
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

remote_alpha_egs_hardening_write_summary() {
  local summary_path=$1
  local runtime_meta_path=$2
  local egs_meta_path=$3
  local ags_meta_path=$4
  local ars_meta_path=$5
  local es_meta_path=$6
  local egs_health_meta_path=$7
  local ags_health_meta_path=$8
  local ags_publish_meta_path=$9
  local es_health_meta_path=${10}
  local es_contract_meta_path=${11}
  local ownership_meta_path=${12}
  local service_account_meta_path=${13}
  local ds_not_in_docker_group=${14}
  local passwordless_sudo_for_ds=${15}

  python3 - "${summary_path}" \
    "${runtime_meta_path}" \
    "${egs_meta_path}" \
    "${ags_meta_path}" \
    "${ars_meta_path}" \
    "${es_meta_path}" \
    "${egs_health_meta_path}" \
    "${ags_health_meta_path}" \
    "${ags_publish_meta_path}" \
    "${es_health_meta_path}" \
    "${es_contract_meta_path}" \
    "${ownership_meta_path}" \
    "${service_account_meta_path}" \
    "${ds_not_in_docker_group}" \
    "${passwordless_sudo_for_ds}" \
    "${REMOTE_ALPHA_SERVICE_USER}" \
    "${REMOTE_ALPHA_SERVICE_GROUP}" \
    "${REMOTE_ALPHA_SERVICE_DROPIN_PATH}" \
    "${remote_alpha_egs_hardening_summary_schema_version}" <<'PY'
import ipaddress
import json
import pathlib
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

summary_path = pathlib.Path(sys.argv[1])
runtime = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
egs_meta = json.loads(pathlib.Path(sys.argv[3]).read_text(encoding="utf-8"))
ags_meta = json.loads(pathlib.Path(sys.argv[4]).read_text(encoding="utf-8"))
ars_meta = json.loads(pathlib.Path(sys.argv[5]).read_text(encoding="utf-8"))
es_meta = json.loads(pathlib.Path(sys.argv[6]).read_text(encoding="utf-8"))
egs_health = json.loads(pathlib.Path(sys.argv[7]).read_text(encoding="utf-8"))
ags_health = json.loads(pathlib.Path(sys.argv[8]).read_text(encoding="utf-8"))
ags_publish = json.loads(pathlib.Path(sys.argv[9]).read_text(encoding="utf-8"))
es_health = json.loads(pathlib.Path(sys.argv[10]).read_text(encoding="utf-8"))
es_contract = json.loads(pathlib.Path(sys.argv[11]).read_text(encoding="utf-8"))
ownership = json.loads(pathlib.Path(sys.argv[12]).read_text(encoding="utf-8"))
service_account = json.loads(pathlib.Path(sys.argv[13]).read_text(encoding="utf-8"))
ds_not_in_docker_group = sys.argv[14]
passwordless_sudo_for_ds = sys.argv[15]
service_user = sys.argv[16]
service_group = sys.argv[17]
dropin_path = sys.argv[18]
schema_version = sys.argv[19]


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


direct_https_urls = {
    "ags_health": ags_health.get("url", ""),
    "ags_publish": ags_publish.get("url", ""),
    "es_health": es_health.get("url", ""),
    "es_contract": es_contract.get("url", ""),
}
direct_https_hosts = {name: url_host(url) for name, url in direct_https_urls.items()}
direct_https_probe_statuses = {
    "ags_health": ags_health.get("status", ""),
    "ags_publish": ags_publish.get("status", ""),
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
        "basis": "derived from validation.service_account_narrowness",
        "primary_group": service_account.get("primary_group", ""),
        "supplementary_groups": service_account.get("supplementary_groups") or [],
        "group_members": service_account.get("group_members") or [],
        "unexpected_group_members": service_account.get("unexpected_group_members") or [],
    }
else:
    shared_unix_account_model = {
        "status": "not_proven",
        "value": None,
        "basis": "service-account narrowness was not proved by validation.service_account_narrowness",
        "primary_group": service_account.get("primary_group", ""),
        "supplementary_groups": service_account.get("supplementary_groups") or [],
        "group_members": service_account.get("group_members") or [],
        "unexpected_group_members": service_account.get("unexpected_group_members") or [],
    }

summary = {
    "schema_version": schema_version,
    "checked_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "slice": {
        "name": "remote-alpha-egs-service-hardening",
        "classification": "hardening_slice",
        "not_a_new_happy_path_proof": True,
    },
    "service": {
        "name": "egs",
        "user": service_user,
        "group": service_group,
        "binary_path": runtime["binary_path"],
        "config_path": runtime["config_path"],
        "health_url": runtime["health_url"],
        "active": egs_meta["active"],
        "enabled": egs_meta["enabled"],
        "fragment_path": egs_meta["fragment_path"],
        "exec_start": egs_meta["exec_start"],
    },
    "dependencies": {
        "server_tls": runtime["tls"],
        "signer": runtime["signer"],
        "runtime_trust": runtime["runtime_trust"],
        "publication": runtime["publication"],
        "local_state_paths": runtime["local_state_paths"],
        "log_sink": runtime["log_sink"],
        "runtime_dependency_on_ags": runtime["dependencies"]["ags"],
        "runtime_dependency_on_ars": runtime["dependencies"]["ars"],
        "runtime_dependency_on_es": runtime["dependencies"]["es"],
        "es_runtime_dependency_preserved": True,
    },
    "ownership_model": {
        "account": {
            "user": service_user,
            "group": service_group,
            "primary_group": service_account.get("primary_group", ""),
            "supplementary_groups": service_account.get("supplementary_groups") or [],
            "group_members": service_account.get("group_members") or [],
            "narrow_dedicated_account": service_account.get("narrow_dedicated_account") is True,
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
        "runtime_state": {
            "required": False,
            "paths": runtime["local_state_paths"],
        },
        "systemd_dropin": {
            "path": dropin_path,
            "user": service_user,
            "group": service_group,
            "umask": "0027",
        },
    },
    "validation": {
        "local_egs_health": egs_health,
        "local_ags_health": ags_health,
        "local_ags_publish_probe": ags_publish,
        "local_es_health": es_health,
        "local_es_contract_probe": es_contract,
        "service_account_narrowness": service_account,
        "ownership": ownership,
        "ags_service_posture": ags_meta,
        "ars_service_posture": ars_meta,
        "es_service_posture": es_meta,
    },
    "preserved_remote_path": {
        "egs_loopback_only": runtime["bind_address"] == "127.0.0.1",
        "direct_https_mtls": {
            "status": "inferred" if direct_https_inferred else "not_proven",
            "value": True if direct_https_inferred else None,
            "basis": "derived from current AGS/ES HTTPS endpoint config plus host-local HTTPS+mTLS probes; not a Mac-side reachability proof",
            "host_local_only": True,
            "urls": direct_https_urls,
            "hosts": direct_https_hosts,
            "probe_statuses": direct_https_probe_statuses,
        },
        "no_bridge": {
            "status": "operator_assertion",
            "value": True,
            "basis": "accepted Remote Supported-Host Alpha posture; this host-local EGS helper does not validate transport topology directly",
        },
        "no_shared_filesystem": {
            "status": "operator_assertion",
            "value": True,
            "basis": "accepted Remote Supported-Host Alpha posture; this host-local EGS helper does not validate Mac/remote filesystem separation directly",
        },
        "ags_health_path": ags_health.get("url", ""),
        "ags_publish_path": ags_publish.get("url", ""),
        "es_health_path": es_health.get("url", ""),
        "es_contract_path": es_contract.get("url", ""),
        "ags_posture_preserved": ags_meta.get("effective_user") == "ags" and ags_meta.get("effective_group") == "ags",
        "ars_posture_preserved": ars_meta.get("effective_user") == "ars" and ars_meta.get("effective_group") == "ars",
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
        "new_remote_happy_path_proof": "not_claimed",
    },
}

summary_path.parent.mkdir(parents=True, exist_ok=True)
summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

remote_alpha_egs_hardening_main() {
  local source_runtime_meta_path runtime_meta_path ags_runtime_meta_path es_runtime_meta_path health_env_meta_path
  local egs_meta_path ags_meta_path ars_meta_path es_meta_path
  local egs_health_result_path egs_health_error_path
  local ags_health_result_path ags_health_error_path
  local ags_publish_result_path ags_publish_error_path ags_publish_request_path
  local es_health_result_path es_health_error_path
  local es_contract_result_path es_contract_error_path
  local ownership_meta_path
  local service_account_meta_path
  local tmpdir=""
  local ds_not_in_docker_group=""
  local passwordless_sudo_for_ds=""
  local overall_ok=true

  remote_alpha_egs_hardening_require_pinned_slice_inputs || return 1
  remote_alpha_egs_hardening_defaults
  remote_alpha_egs_hardening_parse_args "$@" || return $?
  remote_alpha_egs_hardening_require_root || return 1

  remote_alpha_egs_hardening_require_command python3 || return 1
  remote_alpha_egs_hardening_require_command curl || return 1
  remote_alpha_egs_hardening_require_command systemctl || return 1
  remote_alpha_egs_hardening_require_command getent || return 1
  remote_alpha_egs_hardening_require_command groupadd || return 1
  remote_alpha_egs_hardening_require_command useradd || return 1
  remote_alpha_egs_hardening_require_command chown || return 1
  remote_alpha_egs_hardening_require_command chmod || return 1
  remote_alpha_egs_hardening_require_command mkdir || return 1
  remote_alpha_egs_hardening_require_command stat || return 1

  tmpdir="$(mktemp -d)"
  trap "rm -rf -- '${tmpdir}'" EXIT

  source_runtime_meta_path="${tmpdir}/source-runtime.json"
  runtime_meta_path="${tmpdir}/runtime.json"
  ags_runtime_meta_path="${tmpdir}/ags-runtime.json"
  es_runtime_meta_path="${tmpdir}/es-runtime.json"
  health_env_meta_path="${tmpdir}/health-env.json"
  egs_meta_path="${tmpdir}/egs-service.json"
  ags_meta_path="${tmpdir}/ags-service.json"
  ars_meta_path="${tmpdir}/ars-service.json"
  es_meta_path="${tmpdir}/es-service.json"
  egs_health_result_path="${tmpdir}/egs-health-response.json"
  egs_health_error_path="${tmpdir}/egs-health-error.txt"
  ags_health_result_path="${tmpdir}/ags-health-response.json"
  ags_health_error_path="${tmpdir}/ags-health-error.txt"
  ags_publish_result_path="${tmpdir}/ags-publish-response.json"
  ags_publish_error_path="${tmpdir}/ags-publish-error.txt"
  ags_publish_request_path="${tmpdir}/ags-publish-request.json"
  es_health_result_path="${tmpdir}/es-health-response.json"
  es_health_error_path="${tmpdir}/es-health-error.txt"
  es_contract_result_path="${tmpdir}/es-contract-response.json"
  es_contract_error_path="${tmpdir}/es-contract-error.txt"
  ownership_meta_path="${tmpdir}/ownership.json"

  remote_alpha_egs_hardening_runtime_meta >"${source_runtime_meta_path}"
  if [[ "$(remote_alpha_egs_hardening_json_field "${source_runtime_meta_path}" "status" 2>/dev/null || true)" != "pass" ]]; then
    cat "${source_runtime_meta_path}" >&2
    return 1
  fi

  remote_alpha_egs_hardening_assert_runtime_shape "${source_runtime_meta_path}" || return 1

  remote_alpha_egs_hardening_ags_runtime_meta >"${ags_runtime_meta_path}"
  if [[ "$(remote_alpha_egs_hardening_json_field "${ags_runtime_meta_path}" "status" 2>/dev/null || true)" != "pass" ]]; then
    cat "${ags_runtime_meta_path}" >&2
    return 1
  fi

  remote_alpha_egs_hardening_es_runtime_meta >"${es_runtime_meta_path}"
  if [[ "$(remote_alpha_egs_hardening_json_field "${es_runtime_meta_path}" "status" 2>/dev/null || true)" != "pass" ]]; then
    cat "${es_runtime_meta_path}" >&2
    return 1
  fi

  remote_alpha_egs_hardening_health_env_meta >"${health_env_meta_path}"
  if [[ "$(remote_alpha_egs_hardening_json_field "${health_env_meta_path}" "status" 2>/dev/null || true)" != "pass" ]]; then
    cat "${health_env_meta_path}" >&2
    return 1
  fi

  remote_alpha_egs_hardening_verify_runtime_paths "${source_runtime_meta_path}" "${health_env_meta_path}" "${ags_runtime_meta_path}" "${es_runtime_meta_path}" || return 1
  remote_alpha_egs_hardening_assert_unit_execstart || return 1

  remote_alpha_egs_hardening_ensure_group || return 1
  remote_alpha_egs_hardening_ensure_user || return 1
  service_account_meta_path="${tmpdir}/service-account.json"
  remote_alpha_egs_hardening_service_account_meta >"${service_account_meta_path}"
  if [[ "$(remote_alpha_egs_hardening_json_field "${service_account_meta_path}" "status" 2>/dev/null || true)" != "pass" ]]; then
    cat "${service_account_meta_path}" >&2
    return 1
  fi
  remote_alpha_egs_hardening_prepare_tls_material "${source_runtime_meta_path}" || return 1
  remote_alpha_egs_hardening_rewrite_config || return 1

  remote_alpha_egs_hardening_runtime_meta >"${runtime_meta_path}"
  if [[ "$(remote_alpha_egs_hardening_json_field "${runtime_meta_path}" "status" 2>/dev/null || true)" != "pass" ]]; then
    cat "${runtime_meta_path}" >&2
    return 1
  fi

  if [[ "$(remote_alpha_egs_hardening_json_field "${runtime_meta_path}" "tls.cert_file" 2>/dev/null || true)" != "${REMOTE_ALPHA_TLS_CERT_PATH}" ]]; then
    echo "EGS config did not switch to dedicated cert path ${REMOTE_ALPHA_TLS_CERT_PATH}" >&2
    return 1
  fi
  if [[ "$(remote_alpha_egs_hardening_json_field "${runtime_meta_path}" "tls.key_file" 2>/dev/null || true)" != "${REMOTE_ALPHA_TLS_KEY_PATH}" ]]; then
    echo "EGS config did not switch to dedicated key path ${REMOTE_ALPHA_TLS_KEY_PATH}" >&2
    return 1
  fi
  if [[ "$(remote_alpha_egs_hardening_json_field "${runtime_meta_path}" "tls.client_ca_file" 2>/dev/null || true)" != "${REMOTE_ALPHA_TLS_CLIENT_CA_PATH}" ]]; then
    echo "EGS config did not switch to dedicated client CA path ${REMOTE_ALPHA_TLS_CLIENT_CA_PATH}" >&2
    return 1
  fi

  remote_alpha_egs_hardening_write_dropin || return 1

  systemctl daemon-reload
  systemctl enable "${REMOTE_ALPHA_SERVICE_NAME}.service" >/dev/null 2>&1 || overall_ok=false
  systemctl restart "${REMOTE_ALPHA_SERVICE_NAME}.service" || overall_ok=false

  remote_alpha_egs_hardening_service_meta "${REMOTE_ALPHA_SERVICE_NAME}" >"${egs_meta_path}"
  remote_alpha_egs_hardening_service_meta "ags" >"${ags_meta_path}"
  remote_alpha_egs_hardening_service_meta "ars" >"${ars_meta_path}"
  remote_alpha_egs_hardening_service_meta "es" >"${es_meta_path}"

  if [[ "$(remote_alpha_egs_hardening_json_field "${egs_meta_path}" "effective_user" 2>/dev/null || true)" != "${REMOTE_ALPHA_SERVICE_USER}" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_egs_hardening_json_field "${egs_meta_path}" "effective_group" 2>/dev/null || true)" != "${REMOTE_ALPHA_SERVICE_GROUP}" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_egs_hardening_json_field "${egs_meta_path}" "active" 2>/dev/null || true)" != "true" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_egs_hardening_json_field "${egs_meta_path}" "enabled" 2>/dev/null || true)" != "true" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_egs_hardening_json_field "${ags_meta_path}" "effective_user" 2>/dev/null || true)" != "ags" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_egs_hardening_json_field "${ags_meta_path}" "effective_group" 2>/dev/null || true)" != "ags" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_egs_hardening_json_field "${ars_meta_path}" "effective_user" 2>/dev/null || true)" != "ars" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_egs_hardening_json_field "${ars_meta_path}" "effective_group" 2>/dev/null || true)" != "ars" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_egs_hardening_json_field "${es_meta_path}" "effective_user" 2>/dev/null || true)" != "es" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_egs_hardening_json_field "${es_meta_path}" "effective_group" 2>/dev/null || true)" != "es" ]]; then
    overall_ok=false
  fi

  remote_alpha_egs_hardening_health_probe_meta \
    "$(remote_alpha_egs_hardening_json_field "${runtime_meta_path}" "health_probe_url" 2>/dev/null || true)" \
    "$(remote_alpha_egs_hardening_json_field "${runtime_meta_path}" "health_probe_resolve" 2>/dev/null || true)" \
    "${health_env_meta_path}" \
    "${egs_health_result_path}" \
    "${egs_health_error_path}" \
    "" >"${tmpdir}/egs-health-meta.json" || overall_ok=false

  remote_alpha_egs_hardening_health_probe_meta \
    "$(remote_alpha_egs_hardening_json_field "${ags_runtime_meta_path}" "health_url" 2>/dev/null || true)" \
    "" \
    "${health_env_meta_path}" \
    "${ags_health_result_path}" \
    "${ags_health_error_path}" \
    "artifact_registry" >"${tmpdir}/ags-health-meta.json" || overall_ok=false

  remote_alpha_egs_hardening_publish_probe_meta \
    "${ags_runtime_meta_path}" \
    "${health_env_meta_path}" \
    "${ags_publish_result_path}" \
    "${ags_publish_error_path}" \
    "${ags_publish_request_path}" >"${tmpdir}/ags-publish-meta.json" || overall_ok=false

  remote_alpha_egs_hardening_health_probe_meta \
    "$(remote_alpha_egs_hardening_json_field "${es_runtime_meta_path}" "health_url" 2>/dev/null || true)" \
    "" \
    "${health_env_meta_path}" \
    "${es_health_result_path}" \
    "${es_health_error_path}" \
    "artifact_registry" >"${tmpdir}/es-health-meta.json" || overall_ok=false

  remote_alpha_egs_hardening_contract_probe_meta \
    "${es_runtime_meta_path}" \
    "${health_env_meta_path}" \
    "${es_contract_result_path}" \
    "${es_contract_error_path}" >"${tmpdir}/es-contract-meta.json" || overall_ok=false

  if [[ "$(remote_alpha_egs_hardening_json_field "${tmpdir}/egs-health-meta.json" "status" 2>/dev/null || true)" != "pass" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_egs_hardening_json_field "${tmpdir}/ags-health-meta.json" "status" 2>/dev/null || true)" != "pass" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_egs_hardening_json_field "${tmpdir}/ags-publish-meta.json" "status" 2>/dev/null || true)" != "pass" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_egs_hardening_json_field "${tmpdir}/es-health-meta.json" "status" 2>/dev/null || true)" != "pass" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_egs_hardening_json_field "${tmpdir}/es-contract-meta.json" "status" 2>/dev/null || true)" != "pass" ]]; then
    overall_ok=false
  fi

  remote_alpha_egs_hardening_ownership_meta "${runtime_meta_path}" >"${ownership_meta_path}"
  if [[ "$(remote_alpha_egs_hardening_json_field "${ownership_meta_path}" "status" 2>/dev/null || true)" != "pass" ]]; then
    overall_ok=false
  fi

  ds_not_in_docker_group="$(remote_alpha_egs_hardening_ds_not_in_docker_group)"
  passwordless_sudo_for_ds="$(remote_alpha_egs_hardening_passwordless_sudo_for_ds)"
  if [[ "${ds_not_in_docker_group}" != "true" ]]; then
    overall_ok=false
  fi
  if [[ "${passwordless_sudo_for_ds}" != "false" ]]; then
    overall_ok=false
  fi

  remote_alpha_egs_hardening_write_summary \
    "${REMOTE_ALPHA_SUMMARY_PATH}" \
    "${runtime_meta_path}" \
    "${egs_meta_path}" \
    "${ags_meta_path}" \
    "${ars_meta_path}" \
    "${es_meta_path}" \
    "${tmpdir}/egs-health-meta.json" \
    "${tmpdir}/ags-health-meta.json" \
    "${tmpdir}/ags-publish-meta.json" \
    "${tmpdir}/es-health-meta.json" \
    "${tmpdir}/es-contract-meta.json" \
    "${ownership_meta_path}" \
    "${service_account_meta_path}" \
    "${ds_not_in_docker_group}" \
    "${passwordless_sudo_for_ds}"

  chmod 0644 "${REMOTE_ALPHA_SUMMARY_PATH}" 2>/dev/null || true

  if [[ "${overall_ok}" != "true" ]]; then
    echo "remote alpha EGS hardening finished with validation failures; see ${REMOTE_ALPHA_SUMMARY_PATH}" >&2
    return 1
  fi

  printf '%s\n' "${REMOTE_ALPHA_SUMMARY_PATH}"
}
