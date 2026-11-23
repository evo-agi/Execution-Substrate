#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/internal/bringup.sh
source "${SCRIPT_DIR}/internal/bringup.sh"

PROFILE="$(bringup_profile)"
WAIT_FOR_READY="${WAIT_FOR_READY:-0}"
READY_TIMEOUT_SECONDS="${READY_TIMEOUT_SECONDS:-30}"
VERIFY_RUNTIME_CONFIG="${VERIFY_RUNTIME_CONFIG:-1}"

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
    require_readable_env ES_CONFIG
  fi

  if [[ "${PROFILE}" == "full" ]]; then
    require_command docker
    require_env NOMAD_ADDR
    require_readable_env NOMAD_CACERT
    default_bringup_nomad_token_file
    require_env NOMAD_TOKEN_FILE
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

print_check_section "service health"
check_service "artifact-registry" "${ARS_URL}" "$(resolve_value ARS_RESOLVE)"
check_service "execution-governance" "${EGS_URL}" "$(resolve_value EGS_RESOLVE)"
check_service "artifact-governance" "${AGS_URL}" "$(resolve_value AGS_RESOLVE)"
check_service "execution" "${ES_URL}" "$(resolve_value ES_RESOLVE)"

prepare_ready_verified=0
print_check_section "prepare readiness"
if [[ "${VERIFY_RUNTIME_CONFIG}" == "1" ]]; then
  check_workload_zone_vault_blob "${ES_CONFIG}" "$(resolve_value ARS_RESOLVE)"
  prepare_ready_verified=1
  echo "prepare-ready: true (ES admission surface is healthy and the workload-zone Vault runtime-config blob is readable and valid)"
else
  echo "prepare-ready: skipped (VERIFY_RUNTIME_CONFIG=0; workload-zone Vault runtime-config verification was not requested)"
fi

print_check_section "submit readiness"
if [[ "${PROFILE}" == "full" ]]; then
  check_es_submit_config_once "${ES_CONFIG}"
  nomad_startup_mode_line
  if [[ "${WAIT_FOR_READY}" == "1" ]]; then
    wait_for_nomad_ready "${READY_TIMEOUT_SECONDS}"
  else
    check_nomad_ready_once
  fi
  check_es_nomad_identity_once "${ES_CONFIG}"
  check_docker_ready
  check_runtime_profile_images_once "${ES_CONFIG}"
  check_runtime_profile_image_gc_policy_once "${ES_CONFIG}"
  supported_environment_line
  if [[ "${prepare_ready_verified}" == "1" ]]; then
    echo "submit-ready: true (prepare-ready, ES submit config, Docker, required runtime profile images, runtime image durability, Nomad client/leader, and Nomad pinned-identity checks all passed)"
  else
    echo "submit-ready: partial (Docker, required runtime profile images, runtime image durability, Nomad, and ES submit config passed, but prepare readiness was not fully verified)"
  fi
else
  echo "submit-ready: skipped (BRINGUP_PROFILE=prepare-only)"
fi
