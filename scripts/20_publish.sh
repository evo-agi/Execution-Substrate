#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/internal/bringup.sh
source "${SCRIPT_DIR}/internal/bringup.sh"
# shellcheck source=scripts/internal/operator_failures.sh
source "${SCRIPT_DIR}/internal/operator_failures.sh"

PHASE="publish"
PUBLISH_URL="${AGS_URL:-}/v1/artifacts:publish"

required_envs=(
  AGS_URL
  CA_CERT
  OPERATOR_CERT
  OPERATOR_KEY
  PUBLISH_JSON
)

for name in "${required_envs[@]}"; do
  operator_require_env_or_die "${PHASE}" "${name}"
done

operator_require_readable_file_or_die "${PHASE}" "CA_CERT" "${CA_CERT}"
operator_require_readable_file_or_die "${PHASE}" "OPERATOR_CERT" "${OPERATOR_CERT}"
operator_require_readable_file_or_die "${PHASE}" "OPERATOR_KEY" "${OPERATOR_KEY}"
operator_require_json_file_or_die "${PHASE}" "PUBLISH_JSON" "${PUBLISH_JSON}"

tmp_response="$(mktemp)"
tmp_stderr="$(mktemp)"
trap 'rm -f "${tmp_response}" "${tmp_stderr}"' EXIT

operator_print_request_line POST "${PUBLISH_URL}" "${PUBLISH_JSON}" "${AGS_RESOLVE:-}" "${OPERATOR_CERT}" "${OPERATOR_KEY}"

publish_status=""
if operator_run_request POST "${PUBLISH_URL}" "${PUBLISH_JSON}" "${tmp_response}" "${AGS_RESOLVE:-}" "${OPERATOR_CERT}" "${OPERATOR_KEY}" "${tmp_stderr}" publish_status; then
  :
else
  curl_exit=$?
  if [[ -n "${PUBLISH_RESPONSE:-}" ]]; then
    cp "${tmp_response}" "${PUBLISH_RESPONSE}" 2>/dev/null || true
  fi
  operator_report_transport_failure "${PHASE}" "${curl_exit}" "${tmp_stderr}" "${PUBLISH_URL}"
  exit "${curl_exit}"
fi

if [[ -n "${PUBLISH_RESPONSE:-}" ]]; then
  cp "${tmp_response}" "${PUBLISH_RESPONSE}"
  echo "saved publish response to ${PUBLISH_RESPONSE}"
fi

if [[ "${publish_status}" != "200" ]]; then
  operator_report_http_failure "${PHASE}" "${publish_status}" "${tmp_response}"
  exit 22
fi

echo "publish: success"
operator_print_payload "${tmp_response}"
printf '\n'

artifact_digest="$(python3 - <<'PY' "${tmp_response}"
import json, pathlib, sys
payload = json.loads(pathlib.Path(sys.argv[1]).read_text())
print(payload.get("artifact_digest", ""))
PY
)"

if [[ -n "${artifact_digest}" ]]; then
  echo "ARTIFACT_DIGEST=${artifact_digest}"
fi
