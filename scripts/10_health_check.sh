#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/bringup.sh
source "${SCRIPT_DIR}/lib/bringup.sh"

PROFILE="$(bringup_profile)"
WAIT_FOR_READY="${WAIT_FOR_READY:-0}"
READY_TIMEOUT_SECONDS="${READY_TIMEOUT_SECONDS:-30}"
VERIFY_RUNTIME_CONFIG="${VERIFY_RUNTIME_CONFIG:-0}"

validate_env() {
  local name

  validate_bringup_profile
  require_command curl
  require_command python3
  require_env ARS_URL
  require_env EGS_URL
  require_env AGS_URL
  require_env ES_URL
  require_readable_env CA_CERT

  if [[ "${PROFILE}" == "full" ]]; then
    require_command docker
    require_env NOMAD_ADDR
  fi

  if [[ "${VERIFY_RUNTIME_CONFIG}" == "1" ]]; then
    require_readable_env ES_CONFIG
    resolve_ars_read_credentials >/dev/null
  fi
}

check_service() {
  local fallback_service=$1
  local url=$2
  local resolve_value=$3

  if [[ "${WAIT_FOR_READY}" == "1" ]]; then
    wait_for_service_ready "${fallback_service}" "${url}" "${resolve_value}" "${READY_TIMEOUT_SECONDS}"
  else
    check_service_ready_once "${fallback_service}" "${url}" "${resolve_value}"
  fi
}

validate_env

check_service "artifact-registry" "${ARS_URL}" "$(resolve_value ARS_RESOLVE)"
check_service "execution-governance" "${EGS_URL}" "$(resolve_value EGS_RESOLVE)"
check_service "artifact-governance" "${AGS_URL}" "$(resolve_value AGS_RESOLVE)"
check_service "execution" "${ES_URL}" "$(resolve_value ES_RESOLVE)"

if [[ "${VERIFY_RUNTIME_CONFIG}" == "1" ]]; then
  check_workload_zone_vault_blob "${ES_CONFIG}" "$(resolve_value ARS_RESOLVE)"
fi

if [[ "${PROFILE}" == "full" ]]; then
  if [[ "${WAIT_FOR_READY}" == "1" ]]; then
    wait_for_nomad_ready "${READY_TIMEOUT_SECONDS}"
  else
    check_nomad_ready_once
  fi
  check_docker_ready
fi
