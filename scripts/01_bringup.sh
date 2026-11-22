#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=scripts/internal/bringup.sh
source "${SCRIPT_DIR}/internal/bringup.sh"
# shellcheck source=scripts/internal/control_plane.sh
source "${SCRIPT_DIR}/internal/control_plane.sh"

ACTION="${1:-up}"
PROFILE="$(bringup_profile)"
BRINGUP_DIR="${BRINGUP_DIR:-${REPO_ROOT}/.tmp/bringup}"
PIDS_DIR="${BRINGUP_DIR}/pids"
LOGS_DIR="${BRINGUP_DIR}/logs"
READY_TIMEOUT_SECONDS="${READY_TIMEOUT_SECONDS:-30}"
STARTED_SERVICES=()

usage() {
  cat <<'EOF'
Usage:
  scripts/01_bringup.sh up
  scripts/01_bringup.sh check
  scripts/01_bringup.sh down

Environment:
  BRINGUP_PROFILE=full|prepare-only   default: full
  BRINGUP_DIR=/abs/path               default: .tmp/bringup under repo root
  READY_TIMEOUT_SECONDS=30            readiness wait timeout per dependency

Required for up:
  ARS_CONFIG EGS_CONFIG AGS_CONFIG ES_CONFIG
  ARS_URL EGS_URL AGS_URL ES_URL
  CA_CERT
  OPERATOR_CERT and OPERATOR_KEY, or ARS_READ_CERT and ARS_READ_KEY

Required additionally for full profile:
  NOMAD_CONFIG
  NOMAD_ADDR

Optional resolve helpers for local hostnames:
  ARS_RESOLVE EGS_RESOLVE AGS_RESOLVE ES_RESOLVE

Optional bounded Nomad proof override:
  NOMAD_CLIENT_CPU_TOTAL_COMPUTE=<positive integer>
    temporary slice-0 troubleshooting override for hosts that report cpu.totalcompute=0
    operator output will surface this as bounded-override mode rather than natural schedulability

Notes:
  check reports service health, prepare-ready state, and submit-ready state
  prepare-only proves bounded preflight readiness only; it intentionally skips submit readiness
  full-profile up still starts Nomad itself from NOMAD_CONFIG as bounded fallback/troubleshooting
  the supported Linux environment story is narrower: pre-managed non-dev Nomad plus natural schedulability without cpu_total_compute override
EOF
}

pid_file_for() {
  printf '%s/%s.pid\n' "${PIDS_DIR}" "$1"
}

log_file_for() {
  printf '%s/%s.log\n' "${LOGS_DIR}" "$1"
}

managed_pid() {
  local service=$1
  local pid_file
  pid_file="$(pid_file_for "${service}")"
  if [[ -f "${pid_file}" ]]; then
    tr -d '[:space:]' <"${pid_file}"
  fi
}

pid_is_running() {
  local pid=$1
  [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null
}

require_bringup_common_env() {
  local profile=$1
  local name

  validate_bringup_profile
  require_command curl
  require_command docker
  require_command python3

  for name in ARS_CONFIG EGS_CONFIG AGS_CONFIG ES_CONFIG; do
    require_readable_env "${name}"
  done
  for name in ARS_URL EGS_URL AGS_URL ES_URL CA_CERT; do
    require_env "${name}"
  done
  require_readable_env CA_CERT
  resolve_ars_read_credentials >/dev/null
  resolve_health_check_credentials >/dev/null

  if [[ "${profile}" == "full" ]]; then
    require_command nomad
    require_readable_env NOMAD_CONFIG
    require_env NOMAD_ADDR
    verify_es_submit_config_enabled "${ES_CONFIG}"
  fi
}

require_bringup_check_env() {
  local profile=$1

  validate_bringup_profile
  require_command curl
  require_command docker
  require_command python3

  require_env ARS_URL
  require_env EGS_URL
  require_env AGS_URL
  require_env ES_URL
  require_readable_env CA_CERT
  require_readable_env ES_CONFIG
  resolve_ars_read_credentials >/dev/null
  resolve_health_check_credentials >/dev/null

  if [[ "${profile}" == "full" ]]; then
    require_env NOMAD_ADDR
    verify_es_submit_config_enabled "${ES_CONFIG}"
  fi
}

start_managed_service() {
  local service=$1
  local command_path=$2
  local pid_file
  local log_file
  local pid

  pid_file="$(pid_file_for "${service}")"
  log_file="$(log_file_for "${service}")"

  mkdir -p "${PIDS_DIR}" "${LOGS_DIR}"

  pid="$(managed_pid "${service}")"
  if pid_is_running "${pid}"; then
    echo "${service} is already running under ${pid_file}" >&2
    return 1
  fi
  rm -f "${pid_file}"

  echo "==> starting ${service}"
  echo "logs: ${log_file}"
  (
    cd "${REPO_ROOT}"
    exec "${command_path}"
  ) >"${log_file}" 2>&1 &
  pid=$!
  echo "${pid}" >"${pid_file}"
  STARTED_SERVICES+=("${service}")
}

stop_managed_service() {
  local service=$1
  local pid_file
  local pid
  local waited=0
  local container_name=""

  pid_file="$(pid_file_for "${service}")"
  pid="$(managed_pid "${service}")"
  if managed_service_uses_container "${service}" && declare -f control_plane_container_name >/dev/null 2>&1; then
    container_name="$(control_plane_container_name "${service}")"
  fi
  if ! pid_is_running "${pid}"; then
    if [[ -n "${container_name}" ]]; then
      docker rm -f "${container_name}" >/dev/null 2>&1 || true
    fi
    rm -f "${pid_file}"
    return 0
  fi

  echo "==> stopping ${service} (pid ${pid})"
  if command -v pkill >/dev/null 2>&1; then
    pkill -TERM -P "${pid}" >/dev/null 2>&1 || true
  fi
  kill "${pid}" >/dev/null 2>&1 || true
  while pid_is_running "${pid}" && (( waited < 10 )); do
    sleep 1
    waited=$((waited + 1))
  done
  if pid_is_running "${pid}"; then
    if command -v pkill >/dev/null 2>&1; then
      pkill -KILL -P "${pid}" >/dev/null 2>&1 || true
    fi
    kill -KILL "${pid}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${container_name}" ]]; then
    docker rm -f "${container_name}" >/dev/null 2>&1 || true
  fi
  rm -f "${pid_file}"
}

stop_started_services_on_failure() {
  local index
  for ((index=${#STARTED_SERVICES[@]} - 1; index >= 0; index--)); do
    stop_managed_service "${STARTED_SERVICES[index]}"
  done
}

handle_failure() {
  local status=$?
  if (( status != 0 )) && ((${#STARTED_SERVICES[@]} > 0)); then
    echo "bring-up failed; stopping started services" >&2
    stop_started_services_on_failure || true
  fi
  return "${status}"
}

cmd_up() {
  require_bringup_common_env "${PROFILE}"
  trap handle_failure EXIT

  mkdir -p "${PIDS_DIR}" "${LOGS_DIR}"
  check_docker_ready
  ensure_control_plane_image "${LOGS_DIR}/control-plane-image-build.log"
  probe_control_plane_host_loopback
  verify_es_staging_invariant "${ES_CONFIG}"
  verify_ars_storage_for_operator "${ARS_CONFIG}"

  start_managed_service "ars" "${SCRIPT_DIR}/02_start_ars.sh"
  wait_for_service_ready "artifact-registry" "${ARS_URL}" "$(resolve_value ARS_RESOLVE)" "${READY_TIMEOUT_SECONDS}"
  check_workload_zone_vault_blob "${ES_CONFIG}" "$(resolve_value ARS_RESOLVE)"

  start_managed_service "egs" "${SCRIPT_DIR}/03_start_egs.sh"
  wait_for_service_ready "execution-governance" "${EGS_URL}" "$(resolve_value EGS_RESOLVE)" "${READY_TIMEOUT_SECONDS}"

  start_managed_service "ags" "${SCRIPT_DIR}/04_start_ags.sh"
  wait_for_service_ready "artifact-governance" "${AGS_URL}" "$(resolve_value AGS_RESOLVE)" "${READY_TIMEOUT_SECONDS}"

  start_managed_service "es" "${SCRIPT_DIR}/05_start_es.sh"
  wait_for_service_ready "execution" "${ES_URL}" "$(resolve_value ES_RESOLVE)" "${READY_TIMEOUT_SECONDS}"
  if [[ "${PROFILE}" == "full" ]]; then
    echo "prepare-ready: true (service health is up and the workload-zone Vault runtime-config blob has already been verified; submit readiness still depends on Docker and Nomad)"
  else
    echo "prepare-ready: true (prepare-only profile; submit readiness is intentionally skipped)"
  fi

  if [[ "${PROFILE}" == "full" ]]; then
    start_managed_service "nomad" "${SCRIPT_DIR}/06_start_nomad.sh"
    wait_for_nomad_ready "${READY_TIMEOUT_SECONDS}"
  fi

  VERIFY_RUNTIME_CONFIG=1 "${SCRIPT_DIR}/10_health_check.sh"

  trap - EXIT
  echo
  echo "bring-up complete"
  echo "profile: ${PROFILE}"
  if [[ "${PROFILE}" == "full" ]]; then
    echo "readiness: prepare-ready + submit-ready"
  else
    echo "readiness: prepare-ready"
    echo "submit readiness: skipped for prepare-only profile"
  fi
  echo "state dir: ${BRINGUP_DIR}"
  echo "next:"
  if [[ "${PROFILE}" == "full" ]]; then
    echo "  scripts/60_execute_loop.sh .examples/execution_loop/static_script_success.input.json"
  else
    echo "  scripts/30_prepare.sh   # after exporting PREPARE_JSON and the usual TLS/URL env"
  fi
  echo "  scripts/01_bringup.sh down"
}

cmd_check() {
  require_bringup_check_env "${PROFILE}"
  VERIFY_RUNTIME_CONFIG=1 "${SCRIPT_DIR}/10_health_check.sh"
}

cmd_down() {
  local service
  for service in nomad es ags egs ars; do
    stop_managed_service "${service}"
  done
  echo "bring-up processes stopped"
}

validate_bringup_profile

case "${ACTION}" in
  up)
    cmd_up
    ;;
  check)
    cmd_check
    ;;
  down)
    cmd_down
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage >&2
    exit 1
    ;;
esac
