#!/usr/bin/env bash

operator_category_auth() {
  printf '%s\n' "caller authorization / credential failure"
}

operator_category_trust() {
  printf '%s\n' "trust / evidence / admission failure"
}

operator_category_runtime_config() {
  printf '%s\n' "runtime-config reference or blob failure"
}

operator_category_readiness() {
  printf '%s\n' "service health / readiness failure"
}

operator_category_substrate() {
  printf '%s\n' "substrate failure (Docker / Nomad / runtime availability)"
}

operator_category_execution() {
  printf '%s\n' "execution failure after successful submit"
}

operator_category_input() {
  printf '%s\n' "operator misuse / invalid input"
}

operator_next_step_for_category() {
  local category=$1
  local phase=${2:-}

  case "${category}" in
    "$(operator_category_auth)")
      printf '%s\n' "Verify OPERATOR_CERT and OPERATOR_KEY authenticate as spiffe://execution.internal/operator, then retry ${phase}."
      ;;
    "$(operator_category_trust)")
      printf '%s\n' "Check the published artifact, aggregate evidence, and EGS trust inputs before retrying ${phase}."
      ;;
    "$(operator_category_runtime_config)")
      printf '%s\n' "Re-run scripts/01_bringup.sh check, then confirm ES_CONFIG.runtime_config.workload_zone_vault_config_ref.digest points at a readable ARS JSON blob."
      ;;
    "$(operator_category_readiness)")
      printf '%s\n' "Re-run scripts/01_bringup.sh check and restore service health or prepare-ready state before retrying ${phase}."
      ;;
    "$(operator_category_substrate)")
      printf '%s\n' "Re-run scripts/01_bringup.sh check, then verify Docker, Nomad leader/client readiness, and ES submit config before retrying ${phase}."
      ;;
    "$(operator_category_execution)")
      printf '%s\n' "Inspect lifecycle status/logs for the run. Non-success runs retain host staging under execution.staging_root_dir/<run_id> for debugging in this slice."
      ;;
    "$(operator_category_input)")
      printf '%s\n' "Check request JSON, env vars, readable file paths, and run_id values before retrying ${phase}."
      ;;
    *)
      printf '%s\n' "Inspect the response below and retry once the underlying issue is clear."
      ;;
  esac
}

operator_trimmed_file() {
  local path=$1
  python3 - <<'PY' "$path"
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
if not path.exists():
    print("")
    raise SystemExit(0)

print(path.read_text(encoding="utf-8", errors="replace").strip())
PY
}

operator_response_error_code() {
  local path=$1
  python3 - <<'PY' "$path"
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
if not path.exists():
    print("")
    raise SystemExit(0)

text = path.read_text(encoding="utf-8", errors="replace")
try:
    payload = json.loads(text)
except Exception:
    print("")
    raise SystemExit(0)

print(str(payload.get("code", "")).strip())
PY
}

operator_response_error_message() {
  local path=$1
  python3 - <<'PY' "$path"
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
if not path.exists():
    print("")
    raise SystemExit(0)

text = path.read_text(encoding="utf-8", errors="replace")
try:
    payload = json.loads(text)
except Exception:
    print(text.strip())
    raise SystemExit(0)

message = payload.get("message") or payload.get("error") or ""
print(str(message).strip())
PY
}

operator_print_payload() {
  local path=$1
  if [[ ! -s "${path}" ]]; then
    printf '(empty response)\n'
    return 0
  fi

  if python3 -m json.tool "${path}" 2>/dev/null; then
    return 0
  fi
  cat "${path}"
}

operator_first_nonempty_line() {
  local path=$1
  sed -n '/./{p;q;}' "${path}"
}

operator_print_request_line() {
  local method=$1
  local url=$2
  local body_path=${3:-}
  local resolve=${4:-}
  local cert=${5:-${OPERATOR_CERT:-}}
  local key=${6:-${OPERATOR_KEY:-}}

  printf '+ curl --silent --show-error --cacert %q --cert %q --key %q ' "${CA_CERT}" "${cert}" "${key}"
  if [[ -n "${resolve}" ]]; then
    printf -- '--resolve %q ' "${resolve}"
  fi
  printf -- '-X %q ' "${method}"
  if [[ -n "${body_path}" ]]; then
    printf -- '-H %q --data @%q ' 'Content-Type: application/json' "${body_path}"
  fi
  printf '%q\n' "${url}"
}

operator_run_request() {
  local method=$1
  local url=$2
  local body_path=$3
  local response_path=$4
  local resolve=$5
  local cert=$6
  local key=$7
  local stderr_path=$8
  local status_var=$9

  local -a args
  args=(
    --silent
    --show-error
    --cacert "${CA_CERT}"
    --cert "${cert}"
    --key "${key}"
    --output "${response_path}"
    --write-out "%{http_code}"
    -X "${method}"
  )

  if [[ -n "${resolve}" ]]; then
    args+=(--resolve "${resolve}")
  fi
  if [[ -n "${body_path}" ]]; then
    args+=(-H 'Content-Type: application/json' --data @"${body_path}")
  fi

  local http_status=""
  local curl_exit=0
  set +e
  http_status="$(curl "${args[@]}" "${url}" 2>"${stderr_path}")"
  curl_exit=$?
  set -e

  if (( curl_exit != 0 )); then
    return "${curl_exit}"
  fi

  printf -v "${status_var}" '%s' "${http_status}"
}

operator_category_for_transport_failure() {
  local curl_exit=$1
  local stderr_path=$2
  local detail

  detail="$(operator_trimmed_file "${stderr_path}")"
  case "${curl_exit}" in
    35|51|58|60|77)
      operator_category_auth
      return 0
      ;;
  esac

  if [[ "${detail}" == *"certificate"* || "${detail}" == *"SSL"* || "${detail}" == *"tls"* || "${detail}" == *"TLS"* ]]; then
    operator_category_auth
    return 0
  fi

  operator_category_readiness
}

operator_category_for_http_failure() {
  local phase=$1
  local status=$2
  local code=$3
  local body=$4

  case "${status}" in
    401)
      operator_category_auth
      return 0
      ;;
  esac

  if [[ "${status}" == "403" ]]; then
    case "${code}" in
      artifact_evidence_invalid|signer_not_allowed|signer_revoked|artifact_revoked)
        operator_category_trust
        return 0
        ;;
      publish_forbidden)
        operator_category_auth
        return 0
        ;;
    esac
    if [[ "${body}" == *"Authenticated caller identity required"* || "${body}" == *"Bootstrap PKI callers are not accepted"* || "${body}" == *"Caller not authorized for this operation"* ]]; then
      operator_category_auth
      return 0
    fi
  fi

  case "${code}" in
    invalid_request|invalid_run_id|unsupported_execution_mode|unsupported_artifact_type|unsupported_capabilities|mount_conflict|execution_not_found|artifact_fact_conflict)
      operator_category_input
      ;;
    artifact_evidence_not_found|artifact_evidence_invalid|artifact_evidence_unavailable|signer_not_allowed|signer_revoked|artifact_revoked|payload_unavailable|mount_artifact_invalid)
      operator_category_trust
      ;;
    workload_zone_vault_unavailable)
      operator_category_runtime_config
      ;;
    execution_runtime_unavailable|submission_failed)
      operator_category_substrate
      ;;
    logs_unavailable|artifact_registry_unavailable|publish_failed)
      operator_category_readiness
      ;;
    *)
      if (( status >= 500 )); then
        if [[ "${phase}" == "submit" || "${phase}" == "lifecycle" || "${phase}" == "execution" || "${phase}" == "logs" || "${phase}" == "cancel" ]]; then
          operator_category_substrate
        else
          operator_category_readiness
        fi
      elif (( status >= 400 )); then
        operator_category_input
      else
        operator_category_readiness
      fi
      ;;
  esac
}

operator_print_failure_report() {
  local phase=$1
  local category=$2
  local message=$3
  local next_step=$4
  local status=${5:-}
  local code=${6:-}

  printf '%s: failed\n' "${phase}" >&2
  printf 'failure category: %s\n' "${category}" >&2
  if [[ -n "${status}" ]]; then
    printf 'http status: %s\n' "${status}" >&2
  fi
  if [[ -n "${code}" ]]; then
    printf 'service code: %s\n' "${code}" >&2
  fi
  printf 'message: %s\n' "${message}" >&2
  printf 'next: %s\n' "${next_step}" >&2
}

operator_report_transport_failure() {
  local phase=$1
  local curl_exit=$2
  local stderr_path=$3
  local url=$4
  local detail
  local category
  local next_step

  detail="$(operator_trimmed_file "${stderr_path}")"
  if [[ -z "${detail}" ]]; then
    detail="curl failed for ${url}"
  fi
  category="$(operator_category_for_transport_failure "${curl_exit}" "${stderr_path}")"
  next_step="$(operator_next_step_for_category "${category}" "${phase}")"
  operator_print_failure_report "${phase}" "${category}" "${detail}" "${next_step}"
  if [[ -s "${stderr_path}" ]]; then
    printf 'curl stderr:\n' >&2
    cat "${stderr_path}" >&2
  fi
}

operator_report_http_failure() {
  local phase=$1
  local status=$2
  local response_path=$3
  local code
  local message
  local body
  local category
  local next_step

  code="$(operator_response_error_code "${response_path}")"
  message="$(operator_response_error_message "${response_path}")"
  body="$(operator_trimmed_file "${response_path}")"
  if [[ -z "${message}" ]]; then
    message="unexpected HTTP ${status} response"
  fi

  category="$(operator_category_for_http_failure "${phase}" "${status}" "${code}" "${body}")"
  next_step="$(operator_next_step_for_category "${category}" "${phase}")"
  operator_print_failure_report "${phase}" "${category}" "${message}" "${next_step}" "${status}" "${code}"
  printf 'response:\n' >&2
  operator_print_payload "${response_path}" >&2
}

operator_report_local_failure() {
  local phase=$1
  local category=$2
  local message=$3
  local next_step=${4:-}

  if [[ -z "${next_step}" ]]; then
    next_step="$(operator_next_step_for_category "${category}" "${phase}")"
  fi
  operator_print_failure_report "${phase}" "${category}" "${message}" "${next_step}"
}

operator_require_env_or_die() {
  local phase=$1
  local name=$2

  if [[ -z "${!name:-}" ]]; then
    operator_report_local_failure "${phase}" "$(operator_category_input)" "${name} is required"
    exit 1
  fi
}

operator_require_readable_file_or_die() {
  local phase=$1
  local label=$2
  local path=$3

  if [[ ! -r "${path}" ]]; then
    operator_report_local_failure "${phase}" "$(operator_category_input)" "${label} must point to a readable file: ${path}"
    exit 1
  fi
}

operator_require_json_file_or_die() {
  local phase=$1
  local label=$2
  local path=$3

  operator_require_readable_file_or_die "${phase}" "${label}" "${path}"

  if ! python3 - <<'PY' "${path}"
import json
import pathlib
import sys

json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
PY
  then
    operator_report_local_failure "${phase}" "$(operator_category_input)" "${label} must contain valid JSON: ${path}"
    exit 1
  fi
}

operator_validate_run_id_or_die() {
  local phase=$1
  local run_id=$2

  if [[ ! "${run_id}" =~ ^run-[0-9a-f]{16}$ ]]; then
    operator_report_local_failure "${phase}" "$(operator_category_input)" "RUN_ID must match run-<16 hex characters>: ${run_id}"
    exit 1
  fi
}
