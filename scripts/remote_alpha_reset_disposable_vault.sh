#!/usr/bin/env bash
set -euo pipefail
set +x
umask 077

CONFIRMATION_PHRASE="RESET DISPOSABLE REMOTE ALPHA VAULT"
DEFAULT_SERVICE_NAME="vault"
DEFAULT_WORKLOAD_AUTH_CHECKER="/home/ds/Scripts/execution-substrate-remote-alpha-check/scripts/remote_alpha_vault_workload_auth_check.sh"
REMOTE_HEALTH_CHECK_PATH="/home/ds/es-service-bringup-check/10_health_check.sh"
VAULT_WORKLOAD_AUTH_SUMMARY_PATH="/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-summary.json"

MODE="dry-run"
POST_UNSEAL_CHECK="false"
SERVICE_NAME="${REMOTE_ALPHA_VAULT_SERVICE_NAME:-${DEFAULT_SERVICE_NAME}}"
VAULT_CONFIG_PATH="${REMOTE_ALPHA_VAULT_CONFIG_PATH:-}"
VAULT_RAFT_PATH="${VAULT_RAFT_PATH:-}"
VAULT_ADDR_OVERRIDE="${VAULT_ADDR:-}"
VAULT_CACERT_OVERRIDE="${VAULT_CACERT:-}"
WORKLOAD_AUTH_CHECKER="${REMOTE_ALPHA_WORKLOAD_AUTH_CHECKER:-}"

info() {
  printf '[INFO] %s\n' "$*"
}

warn() {
  printf '[WARN] %s\n' "$*" >&2
}

die() {
  printf '[ERROR] %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage:
  remote_alpha_reset_disposable_vault.sh [--dry-run]
  remote_alpha_reset_disposable_vault.sh --unseal-only [--post-unseal-check]
  remote_alpha_reset_disposable_vault.sh --execute-reset [--post-unseal-check]

Options:
  --dry-run
      Read-only checks only. This is the default.
  --execute-reset
      Destructively move the configured Vault raft storage aside, reinitialize
      the disposable Remote Alpha Vault, and prompt for interactive unseal.
  --unseal-only
      Start/reach the existing Vault service and run interactive unseal only.
      This mode does not move raft storage and does not run vault operator init.
  --post-unseal-check
      After unseal, run the repo-supported Vault workload-auth checker with
      sudo in the operator's interactive terminal.
  --service-name <name>
      Vault systemd service name. Defaults to vault.
  --vault-config-path <path>
      Vault config path. Defaults to the -config path from systemd ExecStart.
  --vault-raft-path <path>
      Vault raft storage path. Overrides config parsing.
  --vault-addr <url>
      Vault CLI address. Defaults to VAULT_ADDR, config api_addr, or listener.
  --vault-cacert <path>
      Vault CLI CA path. Defaults to VAULT_CACERT or config listener CA.
  --workload-auth-checker <path>
      Repo-supported workload-auth checker path for --post-unseal-check.
  --help

This helper is for disposable Remote Alpha infrastructure only. It does not run
the full CP/ES proof and it must not be used as production Vault lifecycle
automation.
EOF
}

confirm() {
  local prompt=$1
  local answer
  printf '%s\n' "${prompt}" >&2
  printf 'Type exactly: %s\n' "${CONFIRMATION_PHRASE}" >&2
  printf '> ' >&2
  IFS= read -r answer
  [[ "${answer}" == "${CONFIRMATION_PHRASE}" ]] || die "confirmation phrase did not match; no changes made"
}

require_tty() {
  [[ -t 0 ]] || die "--execute-reset requires interactive stdin"
  [[ -t 1 ]] || die "--execute-reset requires interactive stdout"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required"
}

unit_name() {
  if [[ "${SERVICE_NAME}" == *.service ]]; then
    printf '%s' "${SERVICE_NAME}"
  else
    printf '%s.service' "${SERVICE_NAME}"
  fi
}

systemctl_property() {
  local prop=$1
  systemctl show "$(unit_name)" --property="${prop}" --value --no-pager 2>/dev/null || true
}

service_user_group() {
  local user group
  user="$(systemctl_property User)"
  group="$(systemctl_property Group)"
  [[ -n "${user}" ]] || user="root"
  [[ -n "${group}" ]] || group="${user}"
  printf '%s:%s' "${user}" "${group}"
}

execstart_config_path() {
  local exec_start
  exec_start="$(systemctl_property ExecStart)"
  python3 -I - "${exec_start}" <<'PY'
import re
import sys

value = sys.argv[1]
match = re.search(r"-config(?:=|\s+)([^\s;]+)", value)
if match:
    print(match.group(1))
PY
}

read_config_content() {
  local allow_interactive_sudo=$1
  [[ -n "${VAULT_CONFIG_PATH}" ]] || return 1

  if [[ -r "${VAULT_CONFIG_PATH}" ]]; then
    cat -- "${VAULT_CONFIG_PATH}"
    return 0
  fi

  if [[ "${allow_interactive_sudo}" == "yes" ]]; then
    sudo cat -- "${VAULT_CONFIG_PATH}"
    return 0
  fi

  if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    sudo -n cat -- "${VAULT_CONFIG_PATH}"
    return 0
  fi

  return 1
}

parse_config_field() {
  local field=$1
  local raw
  raw="$(cat)"
  FIELD="${field}" RAW_CONFIG="${raw}" python3 -I <<'PY'
import json
import os
import re

field = os.environ["FIELD"]
raw = os.environ["RAW_CONFIG"]

def emit(value: str) -> None:
    if value:
        print(value)

if field == "raft_path":
    for kind in ("raft", "file"):
        match = re.search(r"storage\s+\"" + re.escape(kind) + r"\"\s*\{(?P<body>.*?)\n\s*\}", raw, re.S)
        if not match:
            continue
        path = re.search(r"(?:^|\n)\s*path\s*=\s*\"([^\"]+)\"", match.group("body"))
        if path:
            emit(path.group(1).strip())
            break
elif field == "api_addr":
    match = re.search(r"(?:^|\n)\s*api_addr\s*=\s*\"([^\"]+)\"", raw)
    if match:
        emit(match.group(1).strip())
elif field == "listener_addr":
    match = re.search(r"listener\s+\"tcp\"\s*\{(?P<body>.*?)\n\s*\}", raw, re.S)
    if match:
        addr = re.search(r"(?:^|\n)\s*address\s*=\s*\"([^\"]+)\"", match.group("body"))
        tls_disable = re.search(r"(?:^|\n)\s*tls_disable\s*=\s*(true|1)", match.group("body"))
        if addr:
            host_port = addr.group(1).strip()
            scheme = "http" if tls_disable else "https"
            if host_port.startswith("0.0.0.0:"):
                host_port = "127.0.0.1:" + host_port.split(":", 1)[1]
            emit(f"{scheme}://{host_port}")
elif field == "tls_client_ca_file":
    match = re.search(r"listener\s+\"tcp\"\s*\{(?P<body>.*?)\n\s*\}", raw, re.S)
    if match:
        for key in ("tls_client_ca_file", "tls_ca_file"):
            item = re.search(r"(?:^|\n)\s*" + key + r"\s*=\s*\"([^\"]+)\"", match.group("body"))
            if item:
                emit(item.group(1).strip())
                break
elif field == "json_summary":
    result = {"raft_path": "", "api_addr": "", "listener_addr": "", "tls_client_ca_file": ""}
    for key in result:
        proc = re.search(r"(?:^|\n)\s*" + key + r"\s*=\s*\"([^\"]+)\"", raw)
        if proc:
            result[key] = proc.group(1).strip()
    print(json.dumps(result, sort_keys=True))
PY
}

config_field_from_file() {
  local allow_interactive_sudo=$1
  local field=$2
  if [[ "${allow_interactive_sudo}" == "yes" ]]; then
    read_config_content "${allow_interactive_sudo}" | parse_config_field "${field}"
  else
    read_config_content "${allow_interactive_sudo}" 2>/dev/null | parse_config_field "${field}"
  fi
}

ensure_config_path() {
  if [[ -z "${VAULT_CONFIG_PATH}" ]]; then
    VAULT_CONFIG_PATH="$(execstart_config_path)"
  fi
}

detect_raft_path() {
  local allow_interactive_sudo=$1
  local parsed=""

  if [[ -n "${VAULT_RAFT_PATH}" ]]; then
    printf '%s' "${VAULT_RAFT_PATH}"
    return 0
  fi

  ensure_config_path
  if [[ -n "${VAULT_CONFIG_PATH}" ]]; then
    parsed="$(config_field_from_file "${allow_interactive_sudo}" raft_path || true)"
    if [[ -n "${parsed}" ]]; then
      VAULT_RAFT_PATH="${parsed}"
      printf '%s' "${VAULT_RAFT_PATH}"
      return 0
    fi
  fi

  parsed="$(detect_single_raft_directory_candidate || true)"
  if [[ -n "${parsed}" ]]; then
    VAULT_RAFT_PATH="${parsed}"
    printf '%s' "${VAULT_RAFT_PATH}"
    return 0
  fi

  return 1
}

detect_single_raft_directory_candidate() {
  local root candidate found=""
  local count=0
  for root in /opt/vault /var/lib/vault /srv/vault; do
    [[ -d "${root}" ]] || continue
    while IFS= read -r candidate; do
      [[ -n "${candidate}" ]] || continue
      found="${candidate}"
      count=$((count + 1))
    done < <(find "${root}" -maxdepth 2 -type d -name raft 2>/dev/null | sort)
  done

  if [[ "${count}" -eq 1 ]]; then
    printf '%s' "${found}"
  elif [[ "${count}" -gt 1 ]]; then
    warn "multiple raft directory candidates found; supply --vault-raft-path explicitly"
  fi
}

detect_vault_addr() {
  local allow_interactive_sudo=$1
  local parsed=""
  local listener=""
  local summary_addr=""

  if [[ -n "${VAULT_ADDR_OVERRIDE}" ]]; then
    printf '%s' "${VAULT_ADDR_OVERRIDE}"
    return 0
  fi

  ensure_config_path
  if [[ -n "${VAULT_CONFIG_PATH}" ]]; then
    parsed="$(config_field_from_file "${allow_interactive_sudo}" api_addr || true)"
    listener="$(config_field_from_file "${allow_interactive_sudo}" listener_addr || true)"
    if [[ -n "${parsed}" ]]; then
      printf '%s' "${parsed}"
      return 0
    fi
    if [[ -n "${listener}" ]]; then
      printf '%s' "${listener}"
      return 0
    fi
  fi

  summary_addr="$(summary_field vault.address || true)"
  if [[ -n "${summary_addr}" ]]; then
    printf '%s' "${summary_addr}"
    return 0
  fi

  printf '%s' "https://127.0.0.1:8200"
}

detect_vault_cacert() {
  local allow_interactive_sudo=$1
  local parsed=""

  if [[ -n "${VAULT_CACERT_OVERRIDE}" ]]; then
    printf '%s' "${VAULT_CACERT_OVERRIDE}"
    return 0
  fi

  ensure_config_path
  if [[ -n "${VAULT_CONFIG_PATH}" ]]; then
    parsed="$(config_field_from_file "${allow_interactive_sudo}" tls_client_ca_file || true)"
    if [[ -n "${parsed}" ]]; then
      printf '%s' "${parsed}"
      return 0
    fi
  fi
}

validate_raft_path() {
  local path=$1
  [[ -n "${path}" ]] || die "VAULT_RAFT_PATH is empty"
  [[ "${path}" == /* ]] || die "VAULT_RAFT_PATH must be absolute: ${path}"
  [[ "${path}" != *$'\n'* ]] || die "VAULT_RAFT_PATH must not contain newlines"
  [[ "${path}" != *".."* ]] || die "VAULT_RAFT_PATH must not contain '..'"

  local trimmed="${path%/}"
  case "${trimmed}" in
    ""|"/"|"/var"|"/var/lib"|"/opt"|"/home"|"/etc"|"/usr"|"/tmp")
      die "refusing broad Vault raft path: ${path}"
      ;;
  esac
}

# The Vault account may write the directory that holds the raft directory
# (it owns /opt/vault on the box), and it may be able to replace the config
# that names the raft path. So the reset only moves a raft directory that is
# a real directory already belonging to the Vault account: moving and
# recreating it then gives that account nothing it did not own before.
require_vault_owned_raft_dir() {
  local path=$1
  local vault_user=$2
  local owner=""

  if sudo test -L "${path}"; then
    die "Vault raft path is a symbolic link: ${path}"
  fi
  sudo test -d "${path}" || die "Vault raft path is not an existing directory: ${path}"
  owner="$(sudo stat -c '%U' -- "${path}")"
  [[ "${owner}" == "${vault_user}" ]] || die "Vault raft path ${path} belongs to ${owner}, not to the Vault service user ${vault_user}; refusing to move it"
}

# Stops Vault, moves the raft directory aside and creates an empty one for the
# Vault account. The Vault account can choose the raft path and owns the
# directories below /opt/vault, so it can change any name in that path, not
# only the last one (audit 03 of PR #49, A03-1). Root therefore never acts on
# the path by name: one step reaches the raft directory's parent from / without
# following a link, moves the entry only if it is still a directory of the
# Vault account, creates the new one in the same parent and hands it over
# through its own descriptor, which a hard link cannot stand in for. The reset
# also refuses to continue while a process still runs as the Vault account.
replace_raft_directory() {
  local vault_user=$1
  local vault_group=$2
  local backup_path=$3

  info "Stopping $(unit_name)"
  sudo systemctl stop "$(unit_name)"
  if [[ "${vault_user}" != "root" ]] && sudo pgrep -u "${vault_user}" >/dev/null 2>&1; then
    die "processes still run as ${vault_user} after $(unit_name) stopped; nothing was moved and Vault stays stopped. List them with: pgrep -a -u ${vault_user}"
  fi
  info "Moving ${VAULT_RAFT_PATH} to ${backup_path} and recreating it for ${vault_user}:${vault_group}"
  # Every step works through a descriptor of the raft directory's parent,
  # reached from / without following a link, so no name the Vault account
  # can change (the raft entry, or a directory above it that it owns) can
  # point root anywhere else.
  local status=0
  sudo python3 -I - "${VAULT_RAFT_PATH}" "${backup_path##*/}" "${vault_user}" "${vault_group}" <<'PY' || status=$?
import grp
import os
import pwd
import stat
import sys

path, backup_name, user, group = sys.argv[1:5]
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def stop(code, message):
    print(f"[ERROR] {message}", file=sys.stderr)
    sys.exit(code)


uid = int(user) if user.isdigit() else pwd.getpwnam(user).pw_uid
gid = int(group) if group.isdigit() else grp.getgrnam(group).gr_gid
parts = [part for part in path.split("/") if part]
if not parts or any(part in (".", "..") for part in parts) or "/" in backup_name or backup_name in ("", ".", ".."):
    stop(2, f"refusing raft path {path}; nothing was moved and Vault stays stopped")
parent_fd = os.open("/", DIR_FLAGS)
for index, part in enumerate(parts[:-1]):
    try:
        next_fd = os.open(part, DIR_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        shown = "/" + "/".join(parts[: index + 1])
        stop(2, f"{shown} is not a directory or is a symbolic link ({exc.strerror}); nothing was moved and Vault stays stopped")
    os.close(parent_fd)
    parent_fd = next_fd
name = parts[-1]
try:
    info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
except OSError as exc:
    stop(2, f"{path} cannot be read ({exc.strerror}); nothing was moved and Vault stays stopped")
if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid:
    stop(2, f"{path} is no longer a directory of the Vault service user; nothing was moved and Vault stays stopped")
try:
    os.rename(name, backup_name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
except OSError as exc:
    stop(2, f"{path} could not be moved to {backup_name} ({exc.strerror}); nothing was moved and Vault stays stopped")


def recreate():
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
    except FileExistsError:
        stop(3, f"something created {path} after the move")
    try:
        new_fd = os.open(name, DIR_FLAGS, dir_fd=parent_fd)
    except OSError:
        stop(3, f"something replaced {path} after the move")
    new_info = os.fstat(new_fd)
    if new_info.st_uid != os.geteuid() or os.listdir(new_fd):
        stop(3, f"something replaced {path} after the move")
    os.fchown(new_fd, uid, gid)
    os.fchmod(new_fd, 0o700)


# The old directory has moved, so every failure from here on exits with 3.
try:
    recreate()
except SystemExit:
    raise
except BaseException as exc:
    stop(3, f"{path} was not recreated after the move ({exc})")
PY
  case "${status}" in
    0) ;;
    3) die "${VAULT_RAFT_PATH} was not recreated after the move; the old data is in ${backup_path} and Vault stays stopped" ;;
    *) die "the raft directory was not replaced (exit ${status}); nothing was moved and Vault stays stopped" ;;
  esac
}

detect_workload_auth_checker() {
  if [[ -n "${WORKLOAD_AUTH_CHECKER}" ]]; then
    printf '%s' "${WORKLOAD_AUTH_CHECKER}"
    return 0
  fi
  if [[ -x "${DEFAULT_WORKLOAD_AUTH_CHECKER}" ]]; then
    printf '%s' "${DEFAULT_WORKLOAD_AUTH_CHECKER}"
    return 0
  fi
  find /home/ds -path '*/scripts/remote_alpha_vault_workload_auth_check.sh' -type f -perm -u+x 2>/dev/null | sort | head -n 1
}

summary_field() {
  local dotted_path=$1
  [[ -r "${VAULT_WORKLOAD_AUTH_SUMMARY_PATH}" ]] || return 1
  python3 -I - "${VAULT_WORKLOAD_AUTH_SUMMARY_PATH}" "${dotted_path}" <<'PY'
import json
import sys

path = sys.argv[1]
dotted_path = sys.argv[2]
with open(path, encoding="utf-8") as handle:
    value = json.load(handle)
for part in dotted_path.split("."):
    if isinstance(value, dict):
        value = value.get(part)
    else:
        value = None
        break
if value is None:
    sys.exit(1)
if isinstance(value, bool):
    print("true" if value else "false")
else:
    print(value)
PY
}

vault_env_prefix() {
  local addr=$1
  local cacert=$2
  export VAULT_ADDR="${addr}"
  if [[ -n "${cacert}" && -r "${cacert}" ]]; then
    export VAULT_CACERT="${cacert}"
    unset VAULT_SKIP_VERIFY
  elif [[ -z "${VAULT_SKIP_VERIFY:-}" ]]; then
    export VAULT_SKIP_VERIFY="true"
  fi
  unset VAULT_TOKEN || true
}

vault_status_json() {
  set +e
  vault status -format=json 2>/dev/null
  local rc=$?
  set -e
  return "${rc}"
}

vault_status_field() {
  local field=$1
  local raw
  raw="$(cat)"
  STATUS_FIELD="${field}" STATUS_JSON="${raw}" python3 -I <<'PY'
import json
import os
import sys

field = os.environ["STATUS_FIELD"]
try:
    payload = json.loads(os.environ["STATUS_JSON"])
except Exception:
    sys.exit(1)
value = payload.get(field)
if isinstance(value, bool):
    print("true" if value else "false")
elif value is not None:
    print(value)
else:
    sys.exit(1)
PY
}

print_vault_status() {
  local status_json initialized sealed checked_at summary_initialized summary_sealed summary_status
  status_json="$(vault_status_json || true)"
  if [[ -z "${status_json}" ]]; then
    warn "Vault status is unavailable from the CLI at ${VAULT_ADDR}"
    checked_at="$(summary_field checked_at || true)"
    summary_initialized="$(summary_field vault.initialized || true)"
    summary_sealed="$(summary_field vault.sealed || true)"
    summary_status="$(summary_field vault.health_http_status || true)"
    if [[ -n "${checked_at}${summary_initialized}${summary_sealed}${summary_status}" ]]; then
      warn "Latest workload-auth summary observed checked_at=${checked_at:-unknown} initialized=${summary_initialized:-unknown} sealed=${summary_sealed:-unknown} health_http_status=${summary_status:-unknown}; this is evidence only and may be stale"
    fi
    return 1
  fi
  initialized="$(printf '%s' "${status_json}" | vault_status_field initialized || true)"
  sealed="$(printf '%s' "${status_json}" | vault_status_field sealed || true)"
  info "Vault initialized=${initialized:-unknown} sealed=${sealed:-unknown}"
}

dry_run() {
  local active fragment dropins identity raft_path addr cacert checker
  ensure_config_path
  active="$(systemctl_property ActiveState)"
  fragment="$(systemctl_property FragmentPath)"
  dropins="$(systemctl_property DropInPaths)"
  identity="$(service_user_group)"
  raft_path="$(detect_raft_path no || true)"
  addr="$(detect_vault_addr no)"
  cacert="$(detect_vault_cacert no || true)"
  checker="$(detect_workload_auth_checker || true)"

  info "Mode: dry-run"
  info "Vault unit: $(unit_name)"
  info "Vault service state: ${active:-unknown}"
  info "Vault service user/group: ${identity}"
  info "Vault unit path: ${fragment:-unknown}"
  info "Vault drop-ins: ${dropins:-none}"
  info "Vault config path: ${VAULT_CONFIG_PATH:-unknown}"
  if [[ -n "${raft_path}" ]]; then
    validate_raft_path "${raft_path}"
    info "Vault raft path detected: ${raft_path}"
  else
    warn "Vault raft path was not config-detected without interactive sudo; --execute-reset will re-check with sudo, or supply --vault-raft-path"
    if [[ -d /opt/vault/raft ]]; then
      warn "Candidate raft path exists: /opt/vault/raft"
    fi
  fi
  info "Vault CLI address: ${addr}"
  if [[ -n "${cacert}" ]]; then
    info "Vault CLI CA path: ${cacert}"
  else
    warn "Vault CLI CA path not detected; Vault CLI commands may use VAULT_SKIP_VERIFY=true for this local Alpha helper"
  fi
  vault_env_prefix "${addr}" "${cacert}"
  print_vault_status || true
  if [[ -n "${checker}" ]]; then
    info "Workload-auth checker: ${checker}"
  else
    warn "Workload-auth checker was not found"
  fi
  if [[ -e "${REMOTE_HEALTH_CHECK_PATH}" ]]; then
    info "Health-check path present: ${REMOTE_HEALTH_CHECK_PATH}"
  else
    warn "Health-check path missing: ${REMOTE_HEALTH_CHECK_PATH}"
  fi
  info "Dry-run complete; no host mutation was performed."
}

wait_for_vault_status() {
  local attempts=30
  local sleep_seconds=2
  local i
  local status_json
  for ((i = 1; i <= attempts; i++)); do
    status_json="$(vault_status_json || true)"
    if [[ -n "${status_json}" ]]; then
      return 0
    fi
    sleep "${sleep_seconds}"
  done
  die "Vault CLI did not become reachable at ${VAULT_ADDR}"
}

run_post_unseal_check_if_requested() {
  local checker
  if [[ "${POST_UNSEAL_CHECK}" == "true" ]]; then
    checker="$(detect_workload_auth_checker || true)"
    [[ -n "${checker}" ]] || die "--post-unseal-check requested but workload-auth checker was not found"
    [[ -x "${checker}" ]] || die "workload-auth checker is not executable: ${checker}"
    info "Running repo-supported workload-auth checker with sudo: ${checker}"
    sudo "${checker}"
  else
    info "Post-unseal workload-auth checker skipped; rerun with --post-unseal-check if desired."
  fi
}

run_unseal_only() {
  local active addr cacert status_json initialized sealed
  require_tty
  require_command systemctl
  require_command vault
  require_command python3
  require_command sudo

  ensure_config_path
  addr="$(detect_vault_addr yes)"
  cacert="$(detect_vault_cacert yes || true)"
  vault_env_prefix "${addr}" "${cacert}"

  info "Mode: unseal-only"
  info "Vault unit: $(unit_name)"
  info "Vault config path: ${VAULT_CONFIG_PATH:-unknown}"
  info "Vault CLI address: ${VAULT_ADDR}"
  active="$(systemctl_property ActiveState)"
  if [[ "${active}" != "active" ]]; then
    info "Starting $(unit_name) because current state is ${active:-unknown}"
    sudo systemctl start "$(unit_name)"
  else
    info "$(unit_name) is already active"
  fi

  wait_for_vault_status
  status_json="$(vault_status_json || true)"
  [[ -n "${status_json}" ]] || die "Vault status was unavailable before unseal"
  initialized="$(printf '%s' "${status_json}" | vault_status_field initialized || true)"
  sealed="$(printf '%s' "${status_json}" | vault_status_field sealed || true)"
  info "Vault initialized=${initialized:-unknown} sealed=${sealed:-unknown}"
  [[ "${initialized}" != "false" ]] || die "Vault is not initialized; --unseal-only will not run init"

  if [[ "${sealed}" == "false" ]]; then
    info "Vault already reports sealed=false; no unseal prompt needed."
  else
    warn "The next command prompts for the existing unseal key interactively."
    warn "Do not pass the unseal key as a command-line argument, paste it into chat, or store it in shell history."
    printf 'Press Enter to run vault operator unseal interactively, or Ctrl-C to stop. ' >&2
    IFS= read -r _
    vault operator unseal
  fi

  status_json="$(vault_status_json || true)"
  [[ -n "${status_json}" ]] || die "Vault status was unavailable after unseal"
  sealed="$(printf '%s' "${status_json}" | vault_status_field sealed || true)"
  [[ "${sealed}" == "false" ]] || die "Vault still reports sealed=${sealed:-unknown}"
  info "Vault sealed=false verified."

  run_post_unseal_check_if_requested
  print_mac_refresh_command
}

run_execute_reset() {
  local identity vault_user vault_group raft_path backup_path timestamp addr cacert status_json sealed
  require_tty
  require_command systemctl
  require_command vault
  require_command python3
  require_command sudo
  require_command pgrep

  ensure_config_path
  [[ -n "${VAULT_CONFIG_PATH}" ]] || die "could not detect Vault config path from systemd; supply --vault-config-path"

  identity="$(service_user_group)"
  vault_user="${identity%%:*}"
  vault_group="${identity#*:}"
  raft_path="$(detect_raft_path yes || true)"
  [[ -n "${raft_path}" ]] || die "could not detect Vault raft path; supply --vault-raft-path"
  validate_raft_path "${raft_path}"
  VAULT_RAFT_PATH="${raft_path}"
  require_vault_owned_raft_dir "${VAULT_RAFT_PATH}" "${vault_user}"

  addr="$(detect_vault_addr yes)"
  cacert="$(detect_vault_cacert yes || true)"
  vault_env_prefix "${addr}" "${cacert}"

  warn "DESTRUCTIVE DISPOSABLE REMOTE ALPHA VAULT RESET"
  warn "This will stop $(unit_name), move the existing Vault raft storage aside, and initialize a new Vault."
  warn "All existing Vault data in this disposable Alpha storage will become unavailable unless restored from the timestamped backup."
  warn "Codex must not run this mode. Only the operator should run it in an interactive SSH terminal."
  info "Vault unit: $(unit_name)"
  info "Vault service user/group: ${vault_user}:${vault_group}"
  info "Vault config path: ${VAULT_CONFIG_PATH}"
  info "Vault raft path to move: ${VAULT_RAFT_PATH}"
  confirm "Confirm destructive reset for disposable Remote Alpha Vault."

  [[ -d "${VAULT_RAFT_PATH}" ]] || die "Vault raft path is not an existing directory: ${VAULT_RAFT_PATH}"
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  backup_path="${VAULT_RAFT_PATH}.remote-alpha-reset-backup-${timestamp}"
  [[ ! -e "${backup_path}" ]] || die "backup path already exists: ${backup_path}"

  replace_raft_directory "${vault_user}" "${vault_group}" "${backup_path}"
  info "Starting $(unit_name)"
  sudo systemctl start "$(unit_name)"
  wait_for_vault_status

  warn "The next command prints the new unseal key and root token to this terminal."
  warn "Do not redirect, tee, screenshot, paste into chat, or store this output anywhere except your private password manager."
  printf 'Press Enter to run vault operator init interactively, or Ctrl-C to stop. ' >&2
  IFS= read -r _
  vault operator init -key-shares=1 -key-threshold=1

  warn "Store the newly printed unseal key and root token in your private password manager now."
  warn "Do not put either value in repo files, .out, logs, support bundles, retained bundles, shell history, or prompts."
  printf 'Press Enter after the secret material has been stored privately. ' >&2
  IFS= read -r _

  warn "The next command prompts for the unseal key interactively. Do not pass the key as a command-line argument."
  printf 'Press Enter to run vault operator unseal interactively. ' >&2
  IFS= read -r _
  vault operator unseal

  status_json="$(vault_status_json || true)"
  [[ -n "${status_json}" ]] || die "Vault status was unavailable after unseal"
  sealed="$(printf '%s' "${status_json}" | vault_status_field sealed || true)"
  [[ "${sealed}" == "false" ]] || die "Vault still reports sealed=${sealed:-unknown}"
  info "Vault sealed=false verified."
  info "Old raft storage backup: ${backup_path}"

  run_post_unseal_check_if_requested

  print_mac_refresh_command
}

print_mac_refresh_command() {
  cat <<'EOF'

After this script completes, run these commands on the Mac:

cd "/Users/ds/Repositories/Infrastructure Manager"
PYTHONPATH=src python3 -m infra_manager.cli remote-alpha-live-refresh \
  --profile-dir ".out/remote-alpha-m75q" \
  --ssh-alias host_to_remote_linux_m75q
EOF
}

main() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dry-run)
        MODE="dry-run"
        shift
        ;;
      --execute-reset)
        MODE="execute-reset"
        shift
        ;;
      --unseal-only)
        MODE="unseal-only"
        shift
        ;;
      --post-unseal-check)
        POST_UNSEAL_CHECK="true"
        shift
        ;;
      --service-name)
        SERVICE_NAME="$2"
        shift 2
        ;;
      --vault-config-path)
        VAULT_CONFIG_PATH="$2"
        shift 2
        ;;
      --vault-raft-path)
        VAULT_RAFT_PATH="$2"
        shift 2
        ;;
      --vault-addr)
        VAULT_ADDR_OVERRIDE="$2"
        shift 2
        ;;
      --vault-cacert)
        VAULT_CACERT_OVERRIDE="$2"
        shift 2
        ;;
      --workload-auth-checker)
        WORKLOAD_AUTH_CHECKER="$2"
        shift 2
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        usage >&2
        die "unknown argument: $1"
        ;;
    esac
  done

  case "${MODE}" in
    dry-run)
      dry_run
      ;;
    unseal-only)
      run_unseal_only
      ;;
    execute-reset)
      run_execute_reset
      ;;
    *)
      die "unknown mode: ${MODE}"
      ;;
  esac
}

# The tests source this file to call its functions. Run as a file, or read
# from standard input, it runs main.
if [[ "${BASH_SOURCE[0]:-$0}" == "$0" ]]; then
  main "$@"
fi
