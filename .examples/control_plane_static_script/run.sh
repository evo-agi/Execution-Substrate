#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

DEFAULT_PAYLOAD_PATH="${REPO_ROOT}/.examples/execution_loop/artifacts/static-script-success.tar.gz"
DEFAULT_BUILD_LOG_PATH="${REPO_ROOT}/.examples/execution_loop/artifacts/build.log"
DEFAULT_WORKDIR_BASE="${REPO_ROOT}/.out"
DEFAULT_TIMEOUT_SECONDS=30
DEFAULT_POLL_INTERVAL_SECONDS=2
DEFAULT_FETCH_LOGS=1

require_env() {
  local name=$1
  if [[ -z "${!name:-}" ]]; then
    echo "${name} is required" >&2
    exit 1
  fi
}

require_readable() {
  local path=$1
  local label=$2
  if [[ ! -r "${path}" ]]; then
    echo "${label} must point to a readable file: ${path}" >&2
    exit 1
  fi
}

curl_request() {
  local method=$1
  local url=$2
  local body_path=$3
  local response_path=$4
  local resolve_value=$5
  local status_var=$6

  local args=(
    --silent
    --show-error
    --output "${response_path}"
    --write-out "%{http_code}"
    --cacert "${CA_CERT}"
    --cert "${CONTROL_PLANE_CERT}"
    --key "${CONTROL_PLANE_KEY}"
    --request "${method}"
  )
  if [[ -n "${resolve_value}" ]]; then
    args+=(--resolve "${resolve_value}")
  fi
  if [[ -n "${body_path}" ]]; then
    args+=(--header "content-type: application/json" --data "@${body_path}")
  fi

  local http_status=""
  if ! http_status="$(curl "${args[@]}" "${url}")"; then
    echo "transport failure for ${method} ${url}" >&2
    if [[ -f "${response_path}" ]]; then
      cat "${response_path}" >&2
    fi
    exit 1
  fi
  printf -v "${status_var}" "%s" "${http_status}"
}

parse_json_field() {
  local path=$1
  local expr=$2
  python3 - <<'PY' "${path}" "${expr}"
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
value = eval(sys.argv[2], {"payload": payload})
print("" if value is None else value)
PY
}

write_summary() {
  local summary_path=$1
  local workdir=$2
  local artifact_digest=$3
  local run_id=$4
  local status_value=$5
  local terminal_value=$6
  local logs_retrieved=$7
  local logs_bytes=$8
  local cancel_requested=$9
  local cancel_status=${10}

  python3 - <<'PY' "${summary_path}" "${workdir}" "${artifact_digest}" "${run_id}" "${status_value}" "${terminal_value}" "${logs_retrieved}" "${logs_bytes}" "${cancel_requested}" "${cancel_status}"
import json
import pathlib
import sys

payload = {
    "caller_path": "spiffe://execution.internal/service/control-plane",
    "api_surface": "direct_https_mtls",
    "workdir": sys.argv[2],
    "artifact_digest": sys.argv[3],
    "run_id": sys.argv[4],
    "status": sys.argv[5],
    "terminal": sys.argv[6] == "true",
    "logs_retrieved": sys.argv[7] == "true",
    "logs_bytes": int(sys.argv[8]),
    "cancel_requested": sys.argv[9] == "true",
    "cancel_status": sys.argv[10],
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

require_env "AGS_URL"
require_env "ES_URL"
require_env "CA_CERT"
require_env "CONTROL_PLANE_CERT"
require_env "CONTROL_PLANE_KEY"

PAYLOAD_PATH="${PAYLOAD_PATH:-${DEFAULT_PAYLOAD_PATH}}"
BUILD_LOG_PATH="${BUILD_LOG_PATH:-${DEFAULT_BUILD_LOG_PATH}}"
WORKDIR_BASE="${WORKDIR_BASE:-${DEFAULT_WORKDIR_BASE}}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-${DEFAULT_TIMEOUT_SECONDS}}"
POLL_INTERVAL_SECONDS="${POLL_INTERVAL_SECONDS:-${DEFAULT_POLL_INTERVAL_SECONDS}}"
WAIT_FOR_TERMINAL="${WAIT_FOR_TERMINAL:-0}"
CANCEL_AFTER_SUBMIT="${CANCEL_AFTER_SUBMIT:-0}"
FETCH_LOGS="${FETCH_LOGS:-${DEFAULT_FETCH_LOGS}}"

require_readable "${CA_CERT}" "CA_CERT"
require_readable "${CONTROL_PLANE_CERT}" "CONTROL_PLANE_CERT"
require_readable "${CONTROL_PLANE_KEY}" "CONTROL_PLANE_KEY"
require_readable "${PAYLOAD_PATH}" "PAYLOAD_PATH"
require_readable "${BUILD_LOG_PATH}" "BUILD_LOG_PATH"

mkdir -p "${WORKDIR_BASE}"
WORKDIR="$(mktemp -d "${WORKDIR_BASE%/}/control-plane-static-script.XXXXXX")"

PUBLISH_JSON="${WORKDIR}/publish.json"
PUBLISH_RESPONSE="${WORKDIR}/publish-response.json"
SUBMIT_JSON="${WORKDIR}/submit.json"
SUBMIT_RESPONSE="${WORKDIR}/submit-response.json"
STATUS_RESPONSE="${WORKDIR}/status-response.json"
LOGS_RESPONSE="${WORKDIR}/logs-response.txt"
CANCEL_RESPONSE="${WORKDIR}/cancel-response.json"
SUMMARY_JSON="${WORKDIR}/summary.json"

python3 - <<'PY' "${PAYLOAD_PATH}" "${BUILD_LOG_PATH}" "${PUBLISH_JSON}"
import base64
import hashlib
import json
import pathlib
import sys

payload_path = pathlib.Path(sys.argv[1])
build_log_path = pathlib.Path(sys.argv[2])
publish_json_path = pathlib.Path(sys.argv[3])

def labeled_digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()

def labeled_digest_json(value) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return labeled_digest_bytes(encoded)

intent = {
    "args": [],
    "entrypoint": "./entrypoint",
    "kind": "control-plane-static-script",
    "note": "first repo-owned control-plane integration path",
}
derivation_spec = {
    "constraints_profile": "bounded-default",
    "kind": "static-script",
    "platform": "docker",
}

publish_request = {
    "artifact_payload_b64": base64.b64encode(payload_path.read_bytes()).decode("ascii"),
    "artifact": {
        "artifact_type": "static-script",
        "intent_digest": labeled_digest_json(intent),
    },
    "publication": {
        "policy_decisions": [
            {"rule": "allow", "result": "applied"},
        ],
        "build_log_digest": labeled_digest_bytes(build_log_path.read_bytes()),
    },
    "admission": {
        "runtime": {
            "environment_variables": ["APP_MODE"],
            "required_capabilities": [],
        },
        "access": {
            "network_access": False,
        },
        "derivation": {
            "derivation_spec_digest": labeled_digest_json(derivation_spec),
            "output_id": "runtime",
        },
        "workload": {
            "target_platform": "docker",
        },
    },
}

publish_json_path.write_text(json.dumps(publish_request, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

echo "workdir=${WORKDIR}"

publish_status=""
curl_request "POST" "${AGS_URL}/v1/artifacts:publish" "${PUBLISH_JSON}" "${PUBLISH_RESPONSE}" "${AGS_RESOLVE:-}" publish_status
if [[ "${publish_status}" != "200" ]]; then
  echo "publish failed: http_status=${publish_status}" >&2
  cat "${PUBLISH_RESPONSE}" >&2
  exit 1
fi

ARTIFACT_DIGEST="$(parse_json_field "${PUBLISH_RESPONSE}" 'payload["artifact_digest"]')"
if [[ -z "${ARTIFACT_DIGEST}" ]]; then
  echo "publish response missing artifact_digest" >&2
  cat "${PUBLISH_RESPONSE}" >&2
  exit 1
fi
DERIVATION_SPEC_DIGEST="$(parse_json_field "${PUBLISH_JSON}" 'payload["admission"]["derivation"]["derivation_spec_digest"]')"
if [[ -z "${DERIVATION_SPEC_DIGEST}" ]]; then
  echo "publish request missing derivation_spec_digest" >&2
  cat "${PUBLISH_JSON}" >&2
  exit 1
fi
echo "publish: success artifact_digest=${ARTIFACT_DIGEST}"

python3 - <<'PY' "${SUBMIT_JSON}" "${ARTIFACT_DIGEST}" "${DERIVATION_SPEC_DIGEST}"
import json
import pathlib
import sys

submit_request = {
    "schema_version": "v1",
    "invocation": {
        "schema_version": "v1",
        "artifact_digest": sys.argv[2],
        "derivation_spec_digest": sys.argv[3],
        "output_id": "runtime",
        "env": {
            "APP_MODE": "test",
        },
    },
    "mode": "async",
    "resources": {
        "cpu": 10,
        "memory_mb": 128,
    },
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(submit_request, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

submit_status=""
curl_request "POST" "${ES_URL}/v1/executions:submit" "${SUBMIT_JSON}" "${SUBMIT_RESPONSE}" "${ES_RESOLVE:-}" submit_status
if [[ "${submit_status}" != "202" ]]; then
  echo "submit failed: http_status=${submit_status}" >&2
  cat "${SUBMIT_RESPONSE}" >&2
  exit 1
fi

RUN_ID="$(parse_json_field "${SUBMIT_RESPONSE}" 'payload["run_id"]')"
if [[ -z "${RUN_ID}" ]]; then
  echo "submit response missing run_id" >&2
  cat "${SUBMIT_RESPONSE}" >&2
  exit 1
fi
echo "submit: success run_id=${RUN_ID}"

deadline=$((SECONDS + TIMEOUT_SECONDS))
STATUS_VALUE=""
TERMINAL_VALUE="false"
EXIT_CODE_VALUE=""
LOGS_RETRIEVED="false"
LOGS_BYTES=0
CANCEL_REQUESTED="false"
CANCEL_STATUS=""

while (( SECONDS <= deadline )); do
  status_http=""
  curl_request "GET" "${ES_URL}/v1/executions/${RUN_ID}/status" "" "${STATUS_RESPONSE}" "${ES_RESOLVE:-}" status_http
  if [[ "${status_http}" == "200" ]]; then
    STATUS_VALUE="$(parse_json_field "${STATUS_RESPONSE}" 'payload.get("status", "")')"
    TERMINAL_VALUE="$(parse_json_field "${STATUS_RESPONSE}" 'str(payload.get("terminal", False)).lower()')"
    EXIT_CODE_VALUE="$(parse_json_field "${STATUS_RESPONSE}" '"" if payload.get("exit_code") is None else str(payload.get("exit_code"))')"
    if [[ "${CANCEL_AFTER_SUBMIT}" == "1" ]]; then
      break
    fi
    if [[ "${WAIT_FOR_TERMINAL}" != "1" || "${TERMINAL_VALUE}" == "true" ]]; then
      break
    fi
  else
    echo "status retrieval failed: http_status=${status_http}" >&2
    cat "${STATUS_RESPONSE}" >&2
    exit 1
  fi
  sleep "${POLL_INTERVAL_SECONDS}"
done

if [[ -z "${STATUS_VALUE}" ]]; then
  echo "status retrieval timed out for run_id=${RUN_ID}" >&2
  exit 1
fi

if [[ "${FETCH_LOGS}" == "1" ]]; then
  while (( SECONDS <= deadline )); do
    logs_http=""
    curl_request "GET" "${ES_URL}/v1/executions/${RUN_ID}/logs" "" "${LOGS_RESPONSE}" "${ES_RESOLVE:-}" logs_http
    if [[ "${logs_http}" == "200" ]]; then
      LOGS_BYTES="$(wc -c < "${LOGS_RESPONSE}" | tr -d '[:space:]')"
      if [[ "${LOGS_BYTES}" != "0" ]]; then
        LOGS_RETRIEVED="true"
        break
      fi
    elif [[ "${logs_http}" != "409" ]]; then
      echo "logs retrieval failed: http_status=${logs_http}" >&2
      cat "${LOGS_RESPONSE}" >&2
      exit 1
    fi
    sleep "${POLL_INTERVAL_SECONDS}"
  done
fi

if [[ "${FETCH_LOGS}" == "1" && "${LOGS_RETRIEVED}" != "true" ]]; then
  echo "logs retrieval timed out for run_id=${RUN_ID}" >&2
  cat "${LOGS_RESPONSE}" >&2
  exit 1
fi

if [[ "${CANCEL_AFTER_SUBMIT}" == "1" ]]; then
  cancel_http=""
  curl_request "POST" "${ES_URL}/v1/executions/${RUN_ID}:cancel" "" "${CANCEL_RESPONSE}" "${ES_RESOLVE:-}" cancel_http
  if [[ "${cancel_http}" != "200" ]]; then
    echo "cancel failed: http_status=${cancel_http}" >&2
    cat "${CANCEL_RESPONSE}" >&2
    exit 1
  fi
  CANCEL_REQUESTED="true"
  CANCEL_STATUS="$(parse_json_field "${CANCEL_RESPONSE}" 'payload.get("status", "")')"
  if [[ -z "${CANCEL_STATUS}" ]]; then
    echo "cancel response missing status" >&2
    cat "${CANCEL_RESPONSE}" >&2
    exit 1
  fi

  if [[ "${WAIT_FOR_TERMINAL}" == "1" ]]; then
    while (( SECONDS <= deadline )); do
      status_http=""
      curl_request "GET" "${ES_URL}/v1/executions/${RUN_ID}/status" "" "${STATUS_RESPONSE}" "${ES_RESOLVE:-}" status_http
      if [[ "${status_http}" == "200" ]]; then
        STATUS_VALUE="$(parse_json_field "${STATUS_RESPONSE}" 'payload.get("status", "")')"
        TERMINAL_VALUE="$(parse_json_field "${STATUS_RESPONSE}" 'str(payload.get("terminal", False)).lower()')"
        EXIT_CODE_VALUE="$(parse_json_field "${STATUS_RESPONSE}" '"" if payload.get("exit_code") is None else str(payload.get("exit_code"))')"
        if [[ "${TERMINAL_VALUE}" == "true" ]]; then
          break
        fi
      else
        echo "status retrieval failed: http_status=${status_http}" >&2
        cat "${STATUS_RESPONSE}" >&2
        exit 1
      fi
      sleep "${POLL_INTERVAL_SECONDS}"
    done
  fi
fi

if [[ "${WAIT_FOR_TERMINAL}" == "1" && "${TERMINAL_VALUE}" != "true" ]]; then
  echo "status retrieval timed out before terminal state for run_id=${RUN_ID}" >&2
  cat "${STATUS_RESPONSE}" >&2
  exit 1
fi

if [[ "${CANCEL_AFTER_SUBMIT}" != "1" && "${TERMINAL_VALUE}" == "true" && "${EXIT_CODE_VALUE}" != "0" ]]; then
  echo "execution failed: state=${STATUS_VALUE} exit_code=${EXIT_CODE_VALUE:-unknown}" >&2
  cat "${STATUS_RESPONSE}" >&2
  exit 1
fi

write_summary "${SUMMARY_JSON}" "${WORKDIR}" "${ARTIFACT_DIGEST}" "${RUN_ID}" "${STATUS_VALUE}" "${TERMINAL_VALUE}" "${LOGS_RETRIEVED}" "${LOGS_BYTES}" "${CANCEL_REQUESTED}" "${CANCEL_STATUS}"
echo "status: success state=${STATUS_VALUE} terminal=${TERMINAL_VALUE}"
if [[ "${FETCH_LOGS}" == "1" ]]; then
  echo "logs: success bytes=${LOGS_BYTES}"
fi
if [[ "${CANCEL_REQUESTED}" == "true" ]]; then
  echo "cancel: success status=${CANCEL_STATUS}"
fi
echo "summary=${SUMMARY_JSON}"
