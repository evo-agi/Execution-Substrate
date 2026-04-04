#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/bringup.sh
source "${SCRIPT_DIR}/lib/bringup.sh"
# shellcheck source=scripts/lib/operator_failures.sh
source "${SCRIPT_DIR}/lib/operator_failures.sh"

PHASE="submit"
SUBMIT_URL="${ES_URL:-}/v1/executions:submit"

required_envs=(
  ES_URL
  CA_CERT
  OPERATOR_CERT
  OPERATOR_KEY
  SUBMIT_JSON
)

for name in "${required_envs[@]}"; do
  operator_require_env_or_die "${PHASE}" "${name}"
done

operator_require_readable_file_or_die "${PHASE}" "CA_CERT" "${CA_CERT}"
operator_require_readable_file_or_die "${PHASE}" "OPERATOR_CERT" "${OPERATOR_CERT}"
operator_require_readable_file_or_die "${PHASE}" "OPERATOR_KEY" "${OPERATOR_KEY}"
operator_require_json_file_or_die "${PHASE}" "SUBMIT_JSON" "${SUBMIT_JSON}"

tmp_response="$(mktemp)"
tmp_stderr="$(mktemp)"
trap 'rm -f "${tmp_response}" "${tmp_stderr}"' EXIT

operator_print_request_line POST "${SUBMIT_URL}" "${SUBMIT_JSON}" "${ES_RESOLVE:-}" "${OPERATOR_CERT}" "${OPERATOR_KEY}"

submit_status=""
if operator_run_request POST "${SUBMIT_URL}" "${SUBMIT_JSON}" "${tmp_response}" "${ES_RESOLVE:-}" "${OPERATOR_CERT}" "${OPERATOR_KEY}" "${tmp_stderr}" submit_status; then
  :
else
  curl_exit=$?
  if [[ -n "${SUBMIT_RESPONSE:-}" ]]; then
    cp "${tmp_response}" "${SUBMIT_RESPONSE}" 2>/dev/null || true
  fi
  operator_report_transport_failure "${PHASE}" "${curl_exit}" "${tmp_stderr}" "${SUBMIT_URL}"
  exit "${curl_exit}"
fi

if [[ -n "${SUBMIT_RESPONSE:-}" ]]; then
  cp "${tmp_response}" "${SUBMIT_RESPONSE}"
  echo "saved submit response to ${SUBMIT_RESPONSE}"
fi

if [[ "${submit_status}" != "202" ]]; then
  operator_report_http_failure "${PHASE}" "${submit_status}" "${tmp_response}"
  exit 22
fi

echo "submit: accepted"
operator_print_payload "${tmp_response}"
printf '\n'

python3 - <<'PY' "${tmp_response}"
import json, pathlib, sys
payload = json.loads(pathlib.Path(sys.argv[1]).read_text())
for key in ("run_id", "status"):
    value = payload.get(key, "")
    if value:
        print(f"{key.upper()}={value}")
PY

echo "note: submit acceptance does not prove runtime success. Use RUN_ID with scripts/50_lifecycle.sh."
