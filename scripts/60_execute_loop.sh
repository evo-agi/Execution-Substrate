#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CANONICALIZE_JSON="${SCRIPT_DIR}/canonicalize_json.py"

DEFAULT_TIMEOUT_SECONDS=120
POLL_INTERVAL_SECONDS=2

WORKDIR=""
SUMMARY_PATH=""
INPUT_COPY_PATH=""
INTENT_PATH=""
DERIVATION_SPEC_PATH=""
BUILD_LOG_PATH=""
COMPUTED_DIGESTS_PATH=""
PUBLISH_JSON_PATH=""
PUBLISH_RESPONSE_PATH=""
PREPARE_JSON_PATH=""
PREPARE_RESPONSE_PATH=""
SUBMIT_JSON_PATH=""
SUBMIT_RESPONSE_PATH=""
STATUS_PATH=""
LOGS_PATH=""

SPEC_PATH=""
SPEC_NAME=""
RESOLVED_PAYLOAD_PATH=""
ARTIFACT_DIGEST=""
RUN_ID=""
NOMAD_JOB_ID=""
NOMAD_EVAL_ID=""
INTENT_DIGEST=""
DERIVATION_SPEC_DIGEST=""
BUILD_LOG_DIGEST=""

FAILED_PHASE=""
MESSAGE=""
ERROR_CODE=""
HTTP_STATUS=""
STATE=""
JOB_STATUS=""
ALLOCATION_ID=""
ALLOCATION_CLIENT_STATUS=""
TASK_STATE=""
EXIT_CODE_JSON="null"
TERMINAL="false"
LOGS_AVAILABLE="false"
OK="false"

usage() {
  cat <<'EOF'
Usage:
  scripts/60_execute_loop.sh /path/to/input.json

Required environment variables:
  AGS_URL
  ES_URL
  CA_CERT
  DEPLOY_CERT
  DEPLOY_KEY

Optional environment variables:
  WORKDIR_BASE   Base directory for per-run output workdirs
  AGS_RESOLVE    Optional curl --resolve value for AGS
  ES_RESOLVE     Optional curl --resolve value for ES
EOF
}

write_summary() {
  if [[ -z "${SUMMARY_PATH}" ]]; then
    return
  fi

  python3 - <<'PY' \
    "${SUMMARY_PATH}" \
    "${OK}" \
    "${FAILED_PHASE}" \
    "${MESSAGE}" \
    "${ERROR_CODE}" \
    "${HTTP_STATUS}" \
    "${SPEC_PATH}" \
    "${WORKDIR}" \
    "${ARTIFACT_DIGEST}" \
    "${INTENT_DIGEST}" \
    "${DERIVATION_SPEC_DIGEST}" \
    "${BUILD_LOG_DIGEST}" \
    "${RUN_ID}" \
    "${NOMAD_JOB_ID}" \
    "${NOMAD_EVAL_ID}" \
    "${STATE}" \
    "${TERMINAL}" \
    "${JOB_STATUS}" \
    "${ALLOCATION_ID}" \
    "${ALLOCATION_CLIENT_STATUS}" \
    "${TASK_STATE}" \
    "${EXIT_CODE_JSON}" \
    "${LOGS_PATH}" \
    "${LOGS_AVAILABLE}"
import json
import pathlib
import sys

summary_path = pathlib.Path(sys.argv[1])
http_status = sys.argv[6]
payload = {
    "ok": sys.argv[2] == "true",
    "failed_phase": sys.argv[3],
    "message": sys.argv[4],
    "error_code": sys.argv[5],
    "http_status": int(http_status) if http_status else None,
    "spec_path": sys.argv[7],
    "workdir": sys.argv[8],
    "artifact_digest": sys.argv[9],
    "intent_digest": sys.argv[10],
    "derivation_spec_digest": sys.argv[11],
    "build_log_digest": sys.argv[12],
    "run_id": sys.argv[13],
    "nomad_job_id": sys.argv[14],
    "nomad_eval_id": sys.argv[15],
    "state": sys.argv[16],
    "terminal": sys.argv[17] == "true",
    "job_status": sys.argv[18],
    "allocation_id": sys.argv[19],
    "allocation_client_status": sys.argv[20],
    "task_state": sys.argv[21],
    "exit_code": None if sys.argv[22] == "null" else json.loads(sys.argv[22]),
    "logs_path": sys.argv[23],
    "logs_available": sys.argv[24] == "true",
}
summary_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

finalize() {
  local exit_code=$?

  if [[ "${LOGS_AVAILABLE}" != "true" && -f "${LOGS_PATH}" ]]; then
    LOGS_AVAILABLE="true"
  fi

  if [[ "${OK}" != "true" && -z "${FAILED_PHASE}" ]]; then
    FAILED_PHASE="internal"
  fi
  if [[ "${OK}" != "true" && -z "${MESSAGE}" ]]; then
    MESSAGE="execution loop failed"
  fi

  write_summary
  exit "${exit_code}"
}

trap finalize EXIT

fail_phase() {
  local phase=$1
  local message=$2
  local error_code=${3:-}
  local http_status=${4:-}

  FAILED_PHASE="${phase}"
  MESSAGE="${message}"
  ERROR_CODE="${error_code}"
  HTTP_STATUS="${http_status}"
  OK="false"
  exit 1
}

require_env() {
  local name=$1
  if [[ -z "${!name:-}" ]]; then
    fail_phase "internal" "${name} is required"
  fi
}

require_readable() {
  local path=$1
  local label=$2
  if [[ ! -r "${path}" ]]; then
    fail_phase "internal" "${label} must point to a readable file: ${path}"
  fi
}

json_get() {
  local path=$1
  local python_expr=$2
  python3 - <<'PY' "${path}" "${python_expr}"
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
result = eval(sys.argv[2], {"payload": payload})
if result is None:
    print("")
else:
    print(result)
PY
}

json_error_fields() {
  local path=$1
  python3 - <<'PY' "${path}"
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
try:
    payload = json.loads(path.read_text(encoding="utf-8"))
except Exception:
    print("")
    print("")
    raise SystemExit(0)

code = payload.get("code", "")
message = payload.get("message") or payload.get("error") or ""
print(code)
print(message)
PY
}

curl_json() {
  local method=$1
  local url=$2
  local body_path=$3
  local response_path=$4
  local resolve_value=$5
  local status_var=$6

  local -a args
  args=(
    --silent
    --show-error
    --cacert "${CA_CERT}"
    --cert "${DEPLOY_CERT}"
    --key "${DEPLOY_KEY}"
    --output "${response_path}"
    --write-out "%{http_code}"
    -X "${method}"
  )

  if [[ -n "${resolve_value}" ]]; then
    args+=(--resolve "${resolve_value}")
  fi

  if [[ -n "${body_path}" ]]; then
    args+=(-H 'Content-Type: application/json' --data @"${body_path}")
  fi

  local status=""
  local curl_exit=0
  set +e
  status="$(curl "${args[@]}" "${url}")"
  curl_exit=$?
  set -e

  if [[ ${curl_exit} -ne 0 ]]; then
    return "${curl_exit}"
  fi

  printf -v "${status_var}" '%s' "${status}"
}

write_phase_http_error() {
  local phase=$1
  local status=$2
  local response_path=$3
  local fallback=$4

  local parsed
  parsed="$(json_error_fields "${response_path}")"
  local code
  local message
  code="$(printf '%s\n' "${parsed}" | sed -n '1p')"
  message="$(printf '%s\n' "${parsed}" | sed -n '2p')"

  if [[ -z "${message}" ]]; then
    message="${fallback}"
  fi

  fail_phase "${phase}" "${message}" "${code}" "${status}"
}

parse_status_snapshot() {
  python3 - <<'PY' "${STATUS_PATH}"
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))

terminal = bool(payload.get("terminal"))
allocation_id = payload.get("allocation_id", "")

if terminal:
    abstract_state = "terminal"
elif allocation_id:
    abstract_state = "running"
else:
    abstract_state = "submitted"

exit_code = payload.get("exit_code", None)
print(abstract_state)
print("true" if terminal else "false")
print(payload.get("job_status", ""))
print(allocation_id)
print(payload.get("allocation_client_status", ""))
print(payload.get("task_state", ""))
print("null" if exit_code is None else json.dumps(exit_code))
PY
}

compute_file_digest() {
  python3 - <<'PY' "$1"
import hashlib
import pathlib
import sys

data = pathlib.Path(sys.argv[1]).read_bytes()
print("sha256:" + hashlib.sha256(data).hexdigest())
PY
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

SPEC_PATH="${1:-${LOOP_SPEC:-}}"
if [[ -z "${SPEC_PATH}" ]]; then
  usage >&2
  fail_phase "internal" "input spec path is required"
fi

require_env AGS_URL
require_env ES_URL
require_env CA_CERT
require_env DEPLOY_CERT
require_env DEPLOY_KEY

require_readable "${CA_CERT}" "CA_CERT"
require_readable "${DEPLOY_CERT}" "DEPLOY_CERT"
require_readable "${DEPLOY_KEY}" "DEPLOY_KEY"
require_readable "${SPEC_PATH}" "input spec"
require_readable "${CANONICALIZE_JSON}" "canonicalize_json.py"

SPEC_PATH="$(python3 - <<'PY' "${SPEC_PATH}"
import pathlib
import sys
print(pathlib.Path(sys.argv[1]).resolve())
PY
)"

WORKDIR_BASE="${WORKDIR_BASE:-${TMPDIR:-/tmp}/execution-loop}"
mkdir -p "${WORKDIR_BASE}"

SPEC_NAME="$(python3 - <<'PY' "${SPEC_PATH}"
import json
import pathlib
import re
import sys

spec_path = pathlib.Path(sys.argv[1]).resolve()
payload = json.loads(spec_path.read_text(encoding="utf-8"))
name = str(payload.get("name") or spec_path.stem).strip()
name = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-")
print(name or "execution-loop")
PY
)"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
WORKDIR="${WORKDIR_BASE}/${SPEC_NAME}-${timestamp}-$$"
mkdir -p "${WORKDIR}"

SUMMARY_PATH="${WORKDIR}/summary.json"
INPUT_COPY_PATH="${WORKDIR}/input.json"
INTENT_PATH="${WORKDIR}/intent.json"
DERIVATION_SPEC_PATH="${WORKDIR}/derivation-spec.json"
BUILD_LOG_PATH="${WORKDIR}/build.log"
COMPUTED_DIGESTS_PATH="${WORKDIR}/computed-digests.json"
PUBLISH_JSON_PATH="${WORKDIR}/publish.json"
PUBLISH_RESPONSE_PATH="${WORKDIR}/publish-response.json"
PREPARE_JSON_PATH="${WORKDIR}/prepare.json"
PREPARE_RESPONSE_PATH="${WORKDIR}/prepare-response.json"
SUBMIT_JSON_PATH="${WORKDIR}/submit.json"
SUBMIT_RESPONSE_PATH="${WORKDIR}/submit-response.json"
STATUS_PATH="${WORKDIR}/status.json"
LOGS_PATH="${WORKDIR}/logs.txt"

cp "${SPEC_PATH}" "${INPUT_COPY_PATH}"

python3 - <<'PY' "${SPEC_PATH}" "${WORKDIR}"
import json
import pathlib
import sys

spec_path = pathlib.Path(sys.argv[1]).resolve()
workdir = pathlib.Path(sys.argv[2]).resolve()
payload = json.loads(spec_path.read_text(encoding="utf-8"))
spec_dir = spec_path.parent

intent = payload.get("intent")
if intent is None:
    raise SystemExit("input spec must contain intent")

derivation_spec = payload.get("derivation_spec")
if derivation_spec is None:
    raise SystemExit("input spec must contain derivation_spec")

raw_intent_path = workdir / "intent.raw.json"
raw_intent_path.write_text(json.dumps(intent, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

raw_derivation_path = workdir / "derivation-spec.raw.json"
raw_derivation_path.write_text(json.dumps(derivation_spec, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

build_log = payload.get("build_log", {})
resolved_payload_path = spec_dir.joinpath(payload["payload_path"]).resolve() if not pathlib.Path(payload["payload_path"]).is_absolute() else pathlib.Path(payload["payload_path"]).resolve()
if not resolved_payload_path.is_file():
    raise SystemExit(f"payload_path must point to a file: {resolved_payload_path}")

resolved_build_log_path = None
if "path" in build_log:
    candidate = pathlib.Path(build_log["path"])
    if not candidate.is_absolute():
        candidate = spec_dir.joinpath(candidate)
    resolved_build_log_path = candidate.resolve()
    if not resolved_build_log_path.is_file():
        raise SystemExit(f"build_log.path must point to a file: {resolved_build_log_path}")

metadata = {
    "payload_path": str(resolved_payload_path),
    "build_log_path": "" if resolved_build_log_path is None else str(resolved_build_log_path),
    "build_log_inline": build_log.get("inline", ""),
}
(workdir / "spec-metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

python3 "${CANONICALIZE_JSON}" canonicalize "${WORKDIR}/intent.raw.json" > "${INTENT_PATH}"
python3 "${CANONICALIZE_JSON}" canonicalize "${WORKDIR}/derivation-spec.raw.json" > "${DERIVATION_SPEC_PATH}"

INTENT_DIGEST="$(python3 "${CANONICALIZE_JSON}" digest "${INTENT_PATH}")"
DERIVATION_SPEC_DIGEST="$(python3 "${CANONICALIZE_JSON}" digest "${DERIVATION_SPEC_PATH}")"

RESOLVED_PAYLOAD_PATH="$(json_get "${WORKDIR}/spec-metadata.json" 'payload["payload_path"]')"
require_readable "${RESOLVED_PAYLOAD_PATH}" "payload_path"

resolved_build_log_path="$(json_get "${WORKDIR}/spec-metadata.json" 'payload["build_log_path"]')"
build_log_inline="$(json_get "${WORKDIR}/spec-metadata.json" 'payload["build_log_inline"]')"
if [[ -n "${resolved_build_log_path}" ]]; then
  cp "${resolved_build_log_path}" "${BUILD_LOG_PATH}"
elif [[ -n "${build_log_inline}" ]]; then
  printf '%s' "${build_log_inline}" > "${BUILD_LOG_PATH}"
else
  : > "${BUILD_LOG_PATH}"
fi
BUILD_LOG_DIGEST="$(compute_file_digest "${BUILD_LOG_PATH}")"

python3 - <<'PY' \
  "${COMPUTED_DIGESTS_PATH}" \
  "${INTENT_DIGEST}" \
  "${DERIVATION_SPEC_DIGEST}" \
  "${BUILD_LOG_DIGEST}" \
  "${INTENT_PATH}" \
  "${DERIVATION_SPEC_PATH}" \
  "${BUILD_LOG_PATH}"
import json
import pathlib
import sys

payload = {
    "intent_digest": sys.argv[2],
    "derivation_spec_digest": sys.argv[3],
    "build_log_digest": sys.argv[4],
    "intent_path": sys.argv[5],
    "derivation_spec_path": sys.argv[6],
    "build_log_path": sys.argv[7],
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

python3 - <<'PY' \
  "${SPEC_PATH}" \
  "${PUBLISH_JSON_PATH}" \
  "${PREPARE_JSON_PATH}" \
  "${SUBMIT_JSON_PATH}" \
  "${RESOLVED_PAYLOAD_PATH}" \
  "${INTENT_DIGEST}" \
  "${DERIVATION_SPEC_DIGEST}" \
  "${BUILD_LOG_DIGEST}"
import base64
import json
import pathlib
import sys

spec_path = pathlib.Path(sys.argv[1]).resolve()
publish_path = pathlib.Path(sys.argv[2]).resolve()
prepare_path = pathlib.Path(sys.argv[3]).resolve()
submit_path = pathlib.Path(sys.argv[4]).resolve()
payload_path = pathlib.Path(sys.argv[5]).resolve()
intent_digest = sys.argv[6]
derivation_spec_digest = sys.argv[7]
build_log_digest = sys.argv[8]

spec = json.loads(spec_path.read_text(encoding="utf-8"))
publish = spec["publish"]
prepare = spec.get("prepare", {})
submit = spec.get("submit", {})
caller = str(publish.get("caller", "deployment")).strip()

if caller not in ("deployment", "operator"):
    raise SystemExit(f"unsupported publish.caller {caller!r}")

artifact_payload_b64 = base64.b64encode(payload_path.read_bytes()).decode("ascii")

publish_request = {
    "artifact_payload_b64": artifact_payload_b64,
    "artifact": {
        "artifact_type": publish["artifact_type"],
        "intent_digest": intent_digest,
    },
    "publication": {
        "policy_decisions": publish["provenance"]["policy_decisions"],
        "build_log_digest": build_log_digest,
    },
    "admission": {
        "runtime": publish["runtime_interface"],
        "derivation": {
            "derivation_spec_digest": derivation_spec_digest,
            "output_id": publish["derivation"]["output_id"],
            "producer_run_id": publish["derivation"]["producer_run_id"],
            "constraints": publish["derivation"]["constraints"],
            "policy_version": publish["derivation"]["policy_version"],
        },
        "workload": {
            "artifact_class": publish["workload_identity"]["artifact_class"],
            "workload_type": publish["workload_identity"]["workload_type"],
            "module_path": publish["workload_identity"]["module_path"],
            "policy_version": publish["workload_identity"]["policy_version"],
        },
    },
}

expected_artifact_type = publish["derivation"].get("expected_artifact_type")
if expected_artifact_type:
    publish_request["admission"]["derivation"]["expected_artifact_type"] = expected_artifact_type

optional_binding_fields = (
    "service_name",
    "target_platform",
    "description",
    "workload_identity_id",
)
for field in optional_binding_fields:
    value = publish["workload_identity"].get(field)
    if value not in (None, ""):
        publish_request["admission"]["workload"][field] = value

invocation = {
    "schema_version": "v1",
    "artifact_digest": "",
    "derivation_spec_digest": derivation_spec_digest,
    "output_id": publish["derivation"]["output_id"],
}

env = prepare.get("env")
if env:
    invocation["env"] = env

prepare_request = {
    "schema_version": "v1",
    "invocation": invocation,
}

submit_request = {
    "schema_version": "v1",
    "invocation": dict(invocation),
}

mode = submit.get("mode")
if mode:
    submit_request["mode"] = mode

resources = submit.get("resources")
if resources:
    submit_request["resources"] = resources

if "timeout_seconds" in submit:
    submit_request["timeout_seconds"] = submit["timeout_seconds"]

publish_path.write_text(json.dumps(publish_request, indent=2, sort_keys=True) + "\n", encoding="utf-8")
prepare_path.write_text(json.dumps(prepare_request, indent=2, sort_keys=True) + "\n", encoding="utf-8")
submit_path.write_text(json.dumps(submit_request, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

echo "workdir=${WORKDIR}"

publish_status=""
if ! curl_json POST "${AGS_URL}/v1/artifacts:publish" "${PUBLISH_JSON_PATH}" "${PUBLISH_RESPONSE_PATH}" "${AGS_RESOLVE:-}" publish_status; then
  fail_phase "publish" "curl failed for POST ${AGS_URL}/v1/artifacts:publish" "curl_error"
fi
HTTP_STATUS="${publish_status}"
if [[ "${publish_status}" != "200" ]]; then
  write_phase_http_error "publish" "${publish_status}" "${PUBLISH_RESPONSE_PATH}" "publish request failed"
fi

ARTIFACT_DIGEST="$(json_get "${PUBLISH_RESPONSE_PATH}" 'payload.get("artifact_digest", "")')"
if [[ -z "${ARTIFACT_DIGEST}" ]]; then
  fail_phase "publish" "publish response did not include artifact_digest" "invalid_publish_response" "${publish_status}"
fi

python3 - <<'PY' "${PREPARE_JSON_PATH}" "${SUBMIT_JSON_PATH}" "${ARTIFACT_DIGEST}"
import json
import pathlib
import sys

prepare_path = pathlib.Path(sys.argv[1])
submit_path = pathlib.Path(sys.argv[2])
artifact_digest = sys.argv[3]

for path in (prepare_path, submit_path):
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["invocation"]["artifact_digest"] = artifact_digest
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

prepare_status=""
if ! curl_json POST "${ES_URL}/v1/executions:prepare" "${PREPARE_JSON_PATH}" "${PREPARE_RESPONSE_PATH}" "${ES_RESOLVE:-}" prepare_status; then
  fail_phase "prepare" "curl failed for POST ${ES_URL}/v1/executions:prepare" "curl_error"
fi
HTTP_STATUS="${prepare_status}"
if [[ "${prepare_status}" != "200" ]]; then
  write_phase_http_error "prepare" "${prepare_status}" "${PREPARE_RESPONSE_PATH}" "prepare request failed"
fi

prepare_success="$(json_get "${PREPARE_RESPONSE_PATH}" 'payload.get("success", False)')"
if [[ "${prepare_success}" != "True" ]]; then
  fail_phase "prepare" "prepare response was not successful" "prepare_unsuccessful" "${prepare_status}"
fi

submit_status=""
if ! curl_json POST "${ES_URL}/v1/executions:submit" "${SUBMIT_JSON_PATH}" "${SUBMIT_RESPONSE_PATH}" "${ES_RESOLVE:-}" submit_status; then
  fail_phase "submit" "curl failed for POST ${ES_URL}/v1/executions:submit" "curl_error"
fi
HTTP_STATUS="${submit_status}"
if [[ "${submit_status}" != "202" ]]; then
  write_phase_http_error "submit" "${submit_status}" "${SUBMIT_RESPONSE_PATH}" "submit request failed"
fi

RUN_ID="$(json_get "${SUBMIT_RESPONSE_PATH}" 'payload.get("run_id", "")')"
NOMAD_JOB_ID="$(json_get "${SUBMIT_RESPONSE_PATH}" 'payload.get("nomad_job_id", "")')"
NOMAD_EVAL_ID="$(json_get "${SUBMIT_RESPONSE_PATH}" 'payload.get("nomad_eval_id", "")')"

if [[ -z "${RUN_ID}" || -z "${NOMAD_JOB_ID}" || -z "${NOMAD_EVAL_ID}" ]]; then
  fail_phase "submit" "submit response omitted run metadata" "invalid_submit_response" "${submit_status}"
fi

deadline_seconds="$(python3 - <<'PY' "${SUBMIT_JSON_PATH}" "${DEFAULT_TIMEOUT_SECONDS}"
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if "timeout_seconds" not in payload:
    print(sys.argv[2])
else:
    print(payload["timeout_seconds"])
PY
)"
deadline_at=$(( $(date +%s) + deadline_seconds ))

while true; do
  now="$(date +%s)"
  if (( now > deadline_at )); then
    fail_phase "execution" "execution status polling timed out" "execution_timeout"
  fi

  status_http=""
  if ! curl_json GET "${ES_URL}/v1/executions/${RUN_ID}/status" "" "${STATUS_PATH}" "${ES_RESOLVE:-}" status_http; then
    fail_phase "execution" "curl failed for GET ${ES_URL}/v1/executions/${RUN_ID}/status" "curl_error"
  fi
  HTTP_STATUS="${status_http}"

  case "${status_http}" in
    200)
      ;;
    404)
      write_phase_http_error "execution" "${status_http}" "${STATUS_PATH}" "execution status not found"
      ;;
    503)
      write_phase_http_error "execution" "${status_http}" "${STATUS_PATH}" "execution status unavailable"
      ;;
    *)
      write_phase_http_error "execution" "${status_http}" "${STATUS_PATH}" "unexpected execution status response"
      ;;
  esac

  parsed_status="$(parse_status_snapshot)"
  STATE="$(printf '%s\n' "${parsed_status}" | sed -n '1p')"
  TERMINAL="$(printf '%s\n' "${parsed_status}" | sed -n '2p')"
  JOB_STATUS="$(printf '%s\n' "${parsed_status}" | sed -n '3p')"
  ALLOCATION_ID="$(printf '%s\n' "${parsed_status}" | sed -n '4p')"
  ALLOCATION_CLIENT_STATUS="$(printf '%s\n' "${parsed_status}" | sed -n '5p')"
  TASK_STATE="$(printf '%s\n' "${parsed_status}" | sed -n '6p')"
  EXIT_CODE_JSON="$(printf '%s\n' "${parsed_status}" | sed -n '7p')"

  if [[ "${STATE}" == "submitted" ]]; then
    sleep "${POLL_INTERVAL_SECONDS}"
    continue
  fi

  logs_http=""
  if ! curl_json GET "${ES_URL}/v1/executions/${RUN_ID}/logs" "" "${LOGS_PATH}" "${ES_RESOLVE:-}" logs_http; then
    fail_phase "logs" "curl failed for GET ${ES_URL}/v1/executions/${RUN_ID}/logs" "curl_error"
  fi
  HTTP_STATUS="${logs_http}"

  if [[ "${STATE}" == "running" ]]; then
    case "${logs_http}" in
      200)
        LOGS_AVAILABLE="true"
        ;;
      409)
        ;;
      404)
        write_phase_http_error "logs" "${logs_http}" "${LOGS_PATH}" "execution logs not found"
        ;;
      503)
        write_phase_http_error "logs" "${logs_http}" "${LOGS_PATH}" "execution logs unavailable"
        ;;
      *)
        write_phase_http_error "logs" "${logs_http}" "${LOGS_PATH}" "unexpected logs response"
        ;;
    esac

    sleep "${POLL_INTERVAL_SECONDS}"
    continue
  fi

  case "${logs_http}" in
    200)
      LOGS_AVAILABLE="true"
      ;;
    409)
      fail_phase "logs" "execution reached terminal state before logs became available" "logs_unavailable" "${logs_http}"
      ;;
    404)
      write_phase_http_error "logs" "${logs_http}" "${LOGS_PATH}" "execution logs not found"
      ;;
    503)
      write_phase_http_error "logs" "${logs_http}" "${LOGS_PATH}" "execution logs unavailable"
      ;;
    *)
      write_phase_http_error "logs" "${logs_http}" "${LOGS_PATH}" "unexpected logs response"
      ;;
  esac

  if [[ "${ALLOCATION_CLIENT_STATUS}" != "complete" ]]; then
    fail_phase "execution" "terminal allocation status is ${ALLOCATION_CLIENT_STATUS}" "execution_failed" "${status_http}"
  fi
  if [[ "${EXIT_CODE_JSON}" != "0" && "${EXIT_CODE_JSON}" != "null" ]]; then
    fail_phase "execution" "terminal exit code is ${EXIT_CODE_JSON}" "execution_failed" "${status_http}"
  fi

  OK="true"
  FAILED_PHASE=""
  MESSAGE="execution completed successfully"
  ERROR_CODE=""
  HTTP_STATUS="${status_http}"
  break
done

write_summary
exit 0
