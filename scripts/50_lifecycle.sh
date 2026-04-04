#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/bringup.sh
source "${SCRIPT_DIR}/lib/bringup.sh"

WAIT_FOR_TERMINAL="${WAIT_FOR_TERMINAL:-0}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-120}"
POLL_INTERVAL_SECONDS="${POLL_INTERVAL_SECONDS:-2}"
DO_CANCEL="${DO_CANCEL:-0}"

required_envs=(
  RUN_ID
  ES_URL
  CA_CERT
  OPERATOR_CERT
  OPERATOR_KEY
)

for name in "${required_envs[@]}"; do
  require_env "${name}"
done

for path_name in CA_CERT OPERATOR_CERT OPERATOR_KEY; do
  require_readable_env "${path_name}"
done

status_path="$(mktemp)"
logs_path="$(mktemp)"
trap 'rm -f "${status_path}" "${logs_path}"' EXIT

curl_status() {
  curl_tls_get_to_file "${status_path}" "${ES_URL}/v1/executions/${RUN_ID}/status" "$(resolve_value ES_RESOLVE)" --cert "${OPERATOR_CERT}" --key "${OPERATOR_KEY}"
}

print_status_json() {
  printf '+ curl --fail-with-body --silent --show-error --cacert %q --cert %q --key %q %q | python3 -m json.tool\n' \
    "${CA_CERT}" "${OPERATOR_CERT}" "${OPERATOR_KEY}" "${ES_URL}/v1/executions/${RUN_ID}/status"
  python3 -m json.tool "${status_path}"
  printf '\n'
}

status_terminal() {
  python3 - <<'PY' "${status_path}"
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
raise SystemExit(0 if payload.get("terminal") is True else 1)
PY
}

print_logs() {
  printf '+ curl --fail-with-body --silent --show-error --cacert %q --cert %q --key %q %q\n' \
    "${CA_CERT}" "${OPERATOR_CERT}" "${OPERATOR_KEY}" "${ES_URL}/v1/executions/${RUN_ID}/logs"
  cat "${logs_path}"
  printf '\n\n'
}

deadline=$((SECONDS + TIMEOUT_SECONDS))

if [[ "${WAIT_FOR_TERMINAL}" == "1" ]]; then
  while true; do
    curl_status
    if status_terminal; then
      break
    fi
    if ((SECONDS >= deadline)); then
      echo "timed out waiting for execution ${RUN_ID} to become terminal" >&2
      print_status_json
      exit 1
    fi
    sleep "${POLL_INTERVAL_SECONDS}"
  done
else
  curl_status
fi

print_status_json

if curl_tls_get_to_file "${logs_path}" "${ES_URL}/v1/executions/${RUN_ID}/logs" "$(resolve_value ES_RESOLVE)" --cert "${OPERATOR_CERT}" --key "${OPERATOR_KEY}"; then
  print_logs
else
  echo "logs are not available yet" >&2
fi

if [[ "${DO_CANCEL}" == "1" ]]; then
  printf '+ curl --fail-with-body --silent --show-error --cacert %q --cert %q --key %q -X POST %q | python3 -m json.tool\n' \
    "${CA_CERT}" "${OPERATOR_CERT}" "${OPERATOR_KEY}" "${ES_URL}/v1/executions/${RUN_ID}:cancel"
  cancel_path="$(mktemp)"
  trap 'rm -f "${status_path}" "${logs_path}" "${cancel_path}"' EXIT
  curl_tls_get_to_file "${cancel_path}" "${ES_URL}/v1/executions/${RUN_ID}:cancel" "$(resolve_value ES_RESOLVE)" --cert "${OPERATOR_CERT}" --key "${OPERATOR_KEY}" -X POST
  python3 -m json.tool "${cancel_path}"
fi
