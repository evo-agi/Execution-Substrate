#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/bringup.sh
source "${SCRIPT_DIR}/lib/bringup.sh"
# shellcheck source=scripts/lib/operator_failures.sh
source "${SCRIPT_DIR}/lib/operator_failures.sh"

PHASE="prepare"
PREPARE_URL="${ES_URL:-}/v1/executions:prepare"

required_envs=(
  ES_URL
  CA_CERT
  OPERATOR_CERT
  OPERATOR_KEY
  PREPARE_JSON
)

for name in "${required_envs[@]}"; do
  operator_require_env_or_die "${PHASE}" "${name}"
done

operator_require_readable_file_or_die "${PHASE}" "CA_CERT" "${CA_CERT}"
operator_require_readable_file_or_die "${PHASE}" "OPERATOR_CERT" "${OPERATOR_CERT}"
operator_require_readable_file_or_die "${PHASE}" "OPERATOR_KEY" "${OPERATOR_KEY}"
operator_require_json_file_or_die "${PHASE}" "PREPARE_JSON" "${PREPARE_JSON}"

tmp_response="$(mktemp)"
tmp_stderr="$(mktemp)"
trap 'rm -f "${tmp_response}" "${tmp_stderr}"' EXIT

operator_print_request_line POST "${PREPARE_URL}" "${PREPARE_JSON}" "${ES_RESOLVE:-}" "${OPERATOR_CERT}" "${OPERATOR_KEY}"

prepare_status=""
if operator_run_request POST "${PREPARE_URL}" "${PREPARE_JSON}" "${tmp_response}" "${ES_RESOLVE:-}" "${OPERATOR_CERT}" "${OPERATOR_KEY}" "${tmp_stderr}" prepare_status; then
  :
else
  curl_exit=$?
  if [[ -n "${PREPARE_RESPONSE:-}" ]]; then
    cp "${tmp_response}" "${PREPARE_RESPONSE}" 2>/dev/null || true
  fi
  operator_report_transport_failure "${PHASE}" "${curl_exit}" "${tmp_stderr}" "${PREPARE_URL}"
  exit "${curl_exit}"
fi

if [[ -n "${PREPARE_RESPONSE:-}" ]]; then
  cp "${tmp_response}" "${PREPARE_RESPONSE}"
  echo "saved prepare response to ${PREPARE_RESPONSE}"
fi

if [[ "${prepare_status}" != "200" ]]; then
  operator_report_http_failure "${PHASE}" "${prepare_status}" "${tmp_response}"
  exit 22
fi

echo "prepare: success"
operator_print_payload "${tmp_response}"
printf '\n'
echo "note: prepare proves bounded preflight only. Use scripts/01_bringup.sh check for submit-ready."
