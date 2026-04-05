#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/internal/bringup.sh
source "${SCRIPT_DIR}/internal/bringup.sh"
# shellcheck source=scripts/internal/operator_failures.sh
source "${SCRIPT_DIR}/internal/operator_failures.sh"

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
  operator_require_env_or_die "lifecycle" "${name}"
done

operator_require_readable_file_or_die "lifecycle" "CA_CERT" "${CA_CERT}"
operator_require_readable_file_or_die "lifecycle" "OPERATOR_CERT" "${OPERATOR_CERT}"
operator_require_readable_file_or_die "lifecycle" "OPERATOR_KEY" "${OPERATOR_KEY}"
operator_validate_run_id_or_die "lifecycle" "${RUN_ID}"

status_path="$(mktemp)"
logs_path="$(mktemp)"
status_stderr="$(mktemp)"
logs_stderr="$(mktemp)"
cancel_path=""
cancel_stderr=""
trap 'rm -f "${status_path}" "${logs_path}" "${status_stderr}" "${logs_stderr}" "${cancel_path}" "${cancel_stderr}"' EXIT

status_url="${ES_URL}/v1/executions/${RUN_ID}/status"
logs_url="${ES_URL}/v1/executions/${RUN_ID}/logs"
cancel_url="${ES_URL}/v1/executions/${RUN_ID}:cancel"

fetch_status() {
  local status_http
  if operator_run_request GET "${status_url}" "" "${status_path}" "$(resolve_value ES_RESOLVE)" "${OPERATOR_CERT}" "${OPERATOR_KEY}" "${status_stderr}" status_http; then
    :
  else
    curl_exit=$?
    operator_report_transport_failure "lifecycle" "${curl_exit}" "${status_stderr}" "${status_url}"
    exit "${curl_exit}"
  fi

  if [[ "${status_http}" != "200" ]]; then
    operator_report_http_failure "lifecycle" "${status_http}" "${status_path}"
    exit 22
  fi
}

print_status_json() {
  operator_print_request_line GET "${status_url}" "" "$(resolve_value ES_RESOLVE)" "${OPERATOR_CERT}" "${OPERATOR_KEY}"
  operator_print_payload "${status_path}"
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

parse_status_snapshot() {
  python3 - <<'PY' "${status_path}"
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
abstract_state = payload.get("status", "")
terminal = bool(payload.get("terminal"))
exit_code = payload.get("exit_code", None)
print(abstract_state)
print("true" if terminal else "false")
print("null" if exit_code is None else json.dumps(exit_code))
PY
}

print_logs() {
  operator_print_request_line GET "${logs_url}" "" "$(resolve_value ES_RESOLVE)" "${OPERATOR_CERT}" "${OPERATOR_KEY}"
  cat "${logs_path}"
  printf '\n\n'
}

deadline=$((SECONDS + TIMEOUT_SECONDS))
current_status=""
terminal_state="false"
exit_code_json="null"

if [[ "${WAIT_FOR_TERMINAL}" == "1" ]]; then
  while true; do
    fetch_status
    if status_terminal; then
      break
    fi
    parsed_status="$(python3 - <<'PY' "${status_path}"
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
print(payload.get("status", ""))
PY
)"
    if ((SECONDS >= deadline)); then
      operator_report_local_failure "lifecycle" "$(operator_category_execution)" "timed out waiting for execution ${RUN_ID} to become terminal within ${TIMEOUT_SECONDS}s"
      print_status_json
      exit 1
    fi
    sleep "${POLL_INTERVAL_SECONDS}"
  done
else
  fetch_status
fi

parsed_status="$(parse_status_snapshot)"
current_status="$(printf '%s\n' "${parsed_status}" | sed -n '1p')"
terminal_state="$(printf '%s\n' "${parsed_status}" | sed -n '2p')"
exit_code_json="$(printf '%s\n' "${parsed_status}" | sed -n '3p')"

print_status_json

logs_http=""
if operator_run_request GET "${logs_url}" "" "${logs_path}" "$(resolve_value ES_RESOLVE)" "${OPERATOR_CERT}" "${OPERATOR_KEY}" "${logs_stderr}" logs_http; then
  :
else
  curl_exit=$?
  operator_report_transport_failure "logs" "${curl_exit}" "${logs_stderr}" "${logs_url}"
  exit "${curl_exit}"
fi

if [[ "${logs_http}" == "200" ]]; then
  print_logs
elif [[ "${logs_http}" == "409" && "${terminal_state}" != "true" ]]; then
  echo "logs: not ready yet (current execution status is ${current_status}); retry later or set WAIT_FOR_TERMINAL=1" >&2
else
  operator_report_http_failure "logs" "${logs_http}" "${logs_path}"
  exit 22
fi

if [[ "${terminal_state}" == "true" ]]; then
  if [[ "${exit_code_json}" == "null" ]]; then
    operator_report_local_failure "lifecycle" "$(operator_category_execution)" "execution ${RUN_ID} reached terminal state without an exit_code"
    exit 1
  fi
  if [[ "${exit_code_json}" != "0" ]]; then
    operator_report_local_failure "lifecycle" "$(operator_category_execution)" "execution ${RUN_ID} reached terminal state with exit_code=${exit_code_json}"
    exit 1
  fi
  echo "lifecycle: execution completed successfully"
fi

if [[ "${DO_CANCEL}" == "1" ]]; then
  cancel_path="$(mktemp)"
  cancel_stderr="$(mktemp)"
  cancel_http=""
  if operator_run_request POST "${cancel_url}" "" "${cancel_path}" "$(resolve_value ES_RESOLVE)" "${OPERATOR_CERT}" "${OPERATOR_KEY}" "${cancel_stderr}" cancel_http; then
    :
  else
    curl_exit=$?
    operator_report_transport_failure "cancel" "${curl_exit}" "${cancel_stderr}" "${cancel_url}"
    exit "${curl_exit}"
  fi
  if [[ "${cancel_http}" != "200" ]]; then
    operator_report_http_failure "cancel" "${cancel_http}" "${cancel_path}"
    exit 22
  fi
  operator_print_request_line POST "${cancel_url}" "" "$(resolve_value ES_RESOLVE)" "${OPERATOR_CERT}" "${OPERATOR_KEY}"
  operator_print_payload "${cancel_path}"
fi
