#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=scripts/lib/bringup.sh
source "${SCRIPT_DIR}/lib/bringup.sh"
# shellcheck source=scripts/lib/operator_failures.sh
source "${SCRIPT_DIR}/lib/operator_failures.sh"

OUTPUT_DIR_BASE="${DIAGNOSTICS_OUTPUT_DIR:-${TMPDIR:-/tmp}/operator-diagnostics}"
BRINGUP_DIR="${BRINGUP_DIR:-${REPO_ROOT}/.tmp/bringup}"
BRINGUP_LOGS_DIR="${BRINGUP_DIR}/logs"

REQUESTED_CATEGORY=""
CATEGORY=""
CATEGORY_KEY=""
RUN_ID=""
BUNDLE_DIR=""
BUNDLE_STATUS="complete"
SUMMARY_PATH=""
COMPONENTS_PATH=""
BUNDLE_JSON_PATH=""

usage() {
  cat <<'EOF'
Usage:
  scripts/70_diagnostics.sh --category <auth|trust|runtime-config|readiness|substrate|execution|input>
  scripts/70_diagnostics.sh --run-id <run_id>
  scripts/70_diagnostics.sh --category <...> --run-id <run_id>

Options:
  --category <value>    Accepts the short aliases above or the surfaced failure labels
  --run-id <run_id>     Collect post-submit diagnostics through the public ES lifecycle path
  --output-dir <path>   Base directory for created bundles
  -h, --help            Show this help

Notes:
  The troubleshooting matrix remains the human-readable source of truth:
    /Users/ds/Repositories/Execution-Platform/.runbooks/system/v1_bringup.md
  This helper only gathers the bounded checks, logs, lifecycle output, and staging signals already referenced there.
  After collection, run scripts/71_diagnostics_summary.sh <bundle_dir|bundle.json> for a compact summary.
EOF
}

fail_usage() {
  printf '%s\n\n' "$1" >&2
  usage >&2
  exit 1
}

summary_line() {
  printf '%s\n' "$*" >>"${SUMMARY_PATH}"
}

record_component() {
  local name=$1
  local status=$2
  local criticality=$3
  local detail=$4

  printf '%s\t%s\t%s\t%s\n' "${name}" "${status}" "${criticality}" "${detail}" >>"${COMPONENTS_PATH}"
  if [[ "${criticality}" == "critical" && "${status}" != "collected" ]]; then
    BUNDLE_STATUS="partial"
  fi
}

bundle_path() {
  local rel=$1
  local path="${BUNDLE_DIR}/${rel}"
  mkdir -p "$(dirname "${path}")"
  printf '%s\n' "${path}"
}

copy_bringup_log() {
  local service=$1
  local source_path="${BRINGUP_LOGS_DIR}/${service}.log"
  local dest_path

  dest_path="$(bundle_path "logs/${service}.log")"
  if [[ -r "${source_path}" ]]; then
    cp "${source_path}" "${dest_path}"
    record_component "log:${service}" "collected" "optional" "${dest_path}"
    return 0
  fi

  printf 'bring-up log not found: %s\n' "${source_path}" >"${dest_path}.missing"
  record_component "log:${service}" "skipped" "optional" "${dest_path}.missing"
}

capture_command() {
  local name=$1
  local output_path=$2
  local criticality=$3
  shift 3

  local status=0
  set +e
  "$@" >"${output_path}" 2>&1
  status=$?
  set -e

  if (( status == 0 )); then
    record_component "${name}" "collected" "${criticality}" "${output_path}"
    return 0
  fi

  printf '\ncommand_exit=%d\n' "${status}" >>"${output_path}"
  record_component "${name}" "failed" "${criticality}" "${output_path}"
  return 0
}

capture_runtime_config_health_check() {
  local output_path
  local status=0

  output_path="$(bundle_path "checks/runtime-config-health-check.txt")"
  set +e
  (
    export BRINGUP_PROFILE=prepare-only
    export VERIFY_RUNTIME_CONFIG=1
    cd "${REPO_ROOT}"
    "${SCRIPT_DIR}/10_health_check.sh"
  ) >"${output_path}" 2>&1
  status=$?
  set -e

  if (( status == 0 )); then
    record_component "check:runtime-config-health" "collected" "critical" "${output_path}"
  else
    printf '\ncommand_exit=%d\n' "${status}" >>"${output_path}"
    record_component "check:runtime-config-health" "failed" "critical" "${output_path}"
  fi
}

capture_bringup_check() {
  local output_path

  output_path="$(bundle_path "checks/bringup-check.txt")"
  capture_command "check:bringup" "${output_path}" "critical" "${SCRIPT_DIR}/01_bringup.sh" check
}

capture_full_health_check() {
  local output_path
  local status=0

  output_path="$(bundle_path "checks/full-health-check.txt")"
  set +e
  (
    export BRINGUP_PROFILE=full
    export VERIFY_RUNTIME_CONFIG=1
    cd "${REPO_ROOT}"
    "${SCRIPT_DIR}/10_health_check.sh"
  ) >"${output_path}" 2>&1
  status=$?
  set -e

  if (( status == 0 )); then
    record_component "check:full-health" "collected" "critical" "${output_path}"
  else
    printf '\ncommand_exit=%d\n' "${status}" >>"${output_path}"
    record_component "check:full-health" "failed" "critical" "${output_path}"
  fi
}

capture_runtime_config_ref() {
  local output_path
  local status=0

  output_path="$(bundle_path "checks/runtime-config-ref.txt")"
  set +e
  python3 - <<'PY' "${ES_CONFIG:-}" >"${output_path}" 2>&1
import json
import pathlib
import sys

config_path = sys.argv[1].strip()
if not config_path:
    raise SystemExit("ES_CONFIG is required to inspect the runtime-config reference")

path = pathlib.Path(config_path)
if not path.is_file():
    raise SystemExit(f"ES_CONFIG is not readable: {config_path}")

cfg = json.loads(path.read_text(encoding="utf-8"))
runtime_cfg = cfg.get("runtime_config") or {}
vault_ref = runtime_cfg.get("workload_zone_vault_config_ref") or {}
digest = (vault_ref.get("digest") or "").strip()
if not digest:
    raise SystemExit("runtime_config.workload_zone_vault_config_ref.digest is missing")
print(f"digest={digest}")
PY
  status=$?
  set -e

  if (( status == 0 )); then
    record_component "check:runtime-config-ref" "collected" "critical" "${output_path}"
  else
    printf '\ncommand_exit=%d\n' "${status}" >>"${output_path}"
    record_component "check:runtime-config-ref" "failed" "critical" "${output_path}"
  fi
}

capture_es_submit_config() {
  local output_path
  local status=0

  output_path="$(bundle_path "checks/es-submit-config.txt")"
  set +e
  if [[ -z "${ES_CONFIG:-}" ]]; then
    printf 'ES_CONFIG is required to inspect submit config\n' >"${output_path}"
    status=1
  else
    check_es_submit_config_once "${ES_CONFIG}" >"${output_path}" 2>&1
    status=$?
  fi
  set -e

  if (( status == 0 )); then
    record_component "check:es-submit-config" "collected" "critical" "${output_path}"
  else
    record_component "check:es-submit-config" "failed" "critical" "${output_path}"
  fi
}

capture_nomad_readiness() {
  local output_path
  local status=0

  output_path="$(bundle_path "checks/nomad-readiness.txt")"
  set +e
  check_nomad_ready_once >"${output_path}" 2>&1
  status=$?
  set -e

  if (( status == 0 )); then
    record_component "check:nomad-readiness" "collected" "critical" "${output_path}"
  else
    record_component "check:nomad-readiness" "failed" "critical" "${output_path}"
  fi
}

capture_docker_info() {
  local output_path
  local status=0

  output_path="$(bundle_path "checks/docker-info.txt")"
  set +e
  {
    docker info
  } >"${output_path}" 2>&1
  status=$?
  set -e

  if (( status == 0 )); then
    record_component "check:docker-info" "collected" "critical" "${output_path}"
  else
    record_component "check:docker-info" "failed" "critical" "${output_path}"
  fi
}

require_es_request_env() {
  local output_path=$1
  local status=0
  local name

  : >"${output_path}"

  for name in ES_URL CA_CERT OPERATOR_CERT OPERATOR_KEY; do
    if [[ -z "${!name:-}" ]]; then
      printf '%s is required\n' "${name}" >>"${output_path}"
      status=1
    fi
  done

  if [[ -n "${CA_CERT:-}" && ! -r "${CA_CERT}" ]]; then
    printf 'CA_CERT is not readable: %s\n' "${CA_CERT}" >>"${output_path}"
    status=1
  fi
  if [[ -n "${OPERATOR_CERT:-}" && ! -r "${OPERATOR_CERT}" ]]; then
    printf 'OPERATOR_CERT is not readable: %s\n' "${OPERATOR_CERT}" >>"${output_path}"
    status=1
  fi
  if [[ -n "${OPERATOR_KEY:-}" && ! -r "${OPERATOR_KEY}" ]]; then
    printf 'OPERATOR_KEY is not readable: %s\n' "${OPERATOR_KEY}" >>"${output_path}"
    status=1
  fi

  return "${status}"
}

capture_run_status() {
  local response_path
  local stderr_path
  local status_path
  local http_status=""
  local curl_exit=0

  response_path="$(bundle_path "run/status.json")"
  stderr_path="$(bundle_path "run/status.stderr")"
  status_path="$(bundle_path "run/status.http")"

  if ! require_es_request_env "${stderr_path}"; then
    record_component "run:status" "failed" "critical" "${stderr_path}"
    return 0
  fi

  set +e
  operator_run_request GET "${ES_URL}/v1/executions/${RUN_ID}/status" "" "${response_path}" "${ES_RESOLVE:-}" "${OPERATOR_CERT}" "${OPERATOR_KEY}" "${stderr_path}" http_status
  curl_exit=$?
  set -e

  if (( curl_exit != 0 )); then
    printf 'curl_exit=%d\n' "${curl_exit}" >>"${stderr_path}"
    record_component "run:status" "failed" "critical" "${stderr_path}"
    return 0
  fi

  printf '%s\n' "${http_status}" >"${status_path}"
  record_component "run:status" "collected" "critical" "${response_path}"
}

capture_run_logs() {
  local response_path
  local stderr_path
  local status_path
  local http_status=""
  local curl_exit=0

  response_path="$(bundle_path "run/logs.txt")"
  stderr_path="$(bundle_path "run/logs.stderr")"
  status_path="$(bundle_path "run/logs.http")"

  if ! require_es_request_env "${stderr_path}"; then
    record_component "run:logs" "failed" "critical" "${stderr_path}"
    return 0
  fi

  set +e
  operator_run_request GET "${ES_URL}/v1/executions/${RUN_ID}/logs" "" "${response_path}" "${ES_RESOLVE:-}" "${OPERATOR_CERT}" "${OPERATOR_KEY}" "${stderr_path}" http_status
  curl_exit=$?
  set -e

  if (( curl_exit != 0 )); then
    printf 'curl_exit=%d\n' "${curl_exit}" >>"${stderr_path}"
    record_component "run:logs" "failed" "critical" "${stderr_path}"
    return 0
  fi

  printf '%s\n' "${http_status}" >"${status_path}"
  record_component "run:logs" "collected" "critical" "${response_path}"
}

capture_run_staging() {
  local summary_path
  local tree_path
  local status=0

  summary_path="$(bundle_path "run/staging-summary.txt")"
  tree_path="$(bundle_path "run/staging-tree.txt")"

  set +e
  python3 - <<'PY' "${ES_CONFIG:-}" "${RUN_ID}" "${summary_path}" "${tree_path}"
import json
import pathlib
import sys

config_path = sys.argv[1].strip()
run_id = sys.argv[2]
summary_path = pathlib.Path(sys.argv[3])
tree_path = pathlib.Path(sys.argv[4])

if not config_path:
    raise SystemExit("ES_CONFIG is required to inspect execution.staging_root_dir")

path = pathlib.Path(config_path)
if not path.is_file():
    raise SystemExit(f"ES_CONFIG is not readable: {config_path}")

cfg = json.loads(path.read_text(encoding="utf-8"))
execution = cfg.get("execution") or {}
staging_root = (execution.get("staging_root_dir") or "").strip()
if not staging_root:
    raise SystemExit("execution.staging_root_dir is missing from ES_CONFIG")

run_path = pathlib.Path(staging_root) / run_id
exists = run_path.exists()
summary_path.write_text(
    "\n".join(
        [
            f"staging_root_dir={staging_root}",
            f"run_path={run_path}",
            f"exists={'true' if exists else 'false'}",
        ]
    )
    + "\n",
    encoding="utf-8",
)

if exists:
    entries = [str(p) for p in sorted(run_path.rglob("*"))]
    tree_path.write_text(
        "\n".join([str(run_path)] + entries) + "\n",
        encoding="utf-8",
    )
PY
  status=$?
  set -e

  if (( status == 0 )); then
    record_component "run:staging" "collected" "optional" "${summary_path}"
    if [[ -f "${tree_path}" ]]; then
      record_component "run:staging-tree" "collected" "optional" "${tree_path}"
    fi
  else
    printf '\ncommand_exit=%d\n' "${status}" >>"${summary_path}"
    record_component "run:staging" "skipped" "optional" "${summary_path}"
  fi
}

collect_category_bundle() {
  case "${CATEGORY}" in
    "$(operator_category_auth)")
      summary_line "category_bundle=auth"
      copy_bringup_log "ags"
      copy_bringup_log "es"
      ;;
    "$(operator_category_trust)")
      summary_line "category_bundle=trust"
      copy_bringup_log "ags"
      copy_bringup_log "egs"
      copy_bringup_log "es"
      ;;
    "$(operator_category_runtime_config)")
      summary_line "category_bundle=runtime-config"
      capture_runtime_config_health_check
      capture_runtime_config_ref
      copy_bringup_log "ars"
      copy_bringup_log "es"
      ;;
    "$(operator_category_readiness)")
      summary_line "category_bundle=readiness"
      capture_bringup_check
      copy_bringup_log "ars"
      copy_bringup_log "egs"
      copy_bringup_log "ags"
      copy_bringup_log "es"
      ;;
    "$(operator_category_substrate)")
      summary_line "category_bundle=substrate"
      capture_full_health_check
      capture_es_submit_config
      capture_nomad_readiness
      capture_docker_info
      copy_bringup_log "nomad"
      copy_bringup_log "es"
      summary_line "note=Docker daemon logs are outside this repo and are not bundled here."
      ;;
    "$(operator_category_execution)")
      summary_line "category_bundle=execution"
      copy_bringup_log "nomad"
      copy_bringup_log "es"
      if [[ -z "${RUN_ID}" ]]; then
        summary_line "note=Add --run-id <run_id> to collect public ES status/logs output and retained staging inspection."
      fi
      ;;
    "$(operator_category_input)")
      summary_line "category_bundle=input"
      copy_bringup_log "ags"
      copy_bringup_log "es"
      ;;
  esac
}

collect_run_bundle() {
  summary_line "run_bundle=${RUN_ID}"
  capture_run_status
  capture_run_logs
  capture_run_staging
  copy_bringup_log "es"
  copy_bringup_log "nomad"
}

write_bundle_json() {
  python3 - <<'PY' \
    "${BUNDLE_JSON_PATH}" \
    "${SUMMARY_PATH}" \
    "${COMPONENTS_PATH}" \
    "${CATEGORY}" \
    "${CATEGORY_KEY}" \
    "${RUN_ID}" \
    "${BUNDLE_STATUS}" \
    "${BUNDLE_DIR}" \
    "${OPERATOR_TROUBLESHOOTING_RUNBOOK}"
import json
import pathlib
import sys

bundle_json = pathlib.Path(sys.argv[1])
summary_path = pathlib.Path(sys.argv[2])
components_path = pathlib.Path(sys.argv[3])

components = []
for line in components_path.read_text(encoding="utf-8").splitlines():
    name, status, criticality, detail = line.split("\t", 3)
    components.append(
        {
            "name": name,
            "status": status,
            "criticality": criticality,
            "detail": detail,
        }
    )

payload = {
    "category": sys.argv[4],
    "category_key": sys.argv[5],
    "run_id": sys.argv[6],
    "bundle_status": sys.argv[7],
    "bundle_dir": sys.argv[8],
    "troubleshooting_matrix": sys.argv[9],
    "summary_path": str(summary_path),
    "components": components,
}
bundle_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

while (($# > 0)); do
  case "$1" in
    --category)
      [[ $# -ge 2 ]] || fail_usage "--category requires a value"
      REQUESTED_CATEGORY=$2
      shift 2
      ;;
    --run-id)
      [[ $# -ge 2 ]] || fail_usage "--run-id requires a value"
      RUN_ID=$2
      shift 2
      ;;
    --output-dir)
      [[ $# -ge 2 ]] || fail_usage "--output-dir requires a value"
      OUTPUT_DIR_BASE=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail_usage "unknown argument: $1"
      ;;
  esac
done

if [[ -z "${REQUESTED_CATEGORY}" && -z "${RUN_ID}" ]]; then
  fail_usage "either --category or --run-id is required"
fi

if [[ -n "${REQUESTED_CATEGORY}" ]]; then
  CATEGORY="$(operator_normalize_category "${REQUESTED_CATEGORY}")" || fail_usage "unsupported category: ${REQUESTED_CATEGORY}"
  CATEGORY_KEY="$(operator_category_key "${CATEGORY}")" || fail_usage "unsupported category: ${REQUESTED_CATEGORY}"
fi

if [[ -n "${RUN_ID}" ]]; then
  operator_validate_run_id_or_die "diagnostics" "${RUN_ID}"
fi

bundle_name=""
if [[ -n "${CATEGORY_KEY}" && -n "${RUN_ID}" ]]; then
  bundle_name="${CATEGORY_KEY}-${RUN_ID}"
elif [[ -n "${RUN_ID}" ]]; then
  bundle_name="${RUN_ID}"
else
  bundle_name="${CATEGORY_KEY}"
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
BUNDLE_DIR="${OUTPUT_DIR_BASE}/${bundle_name}-${timestamp}-$$"
SUMMARY_PATH="${BUNDLE_DIR}/summary.txt"
COMPONENTS_PATH="${BUNDLE_DIR}/components.tsv"
BUNDLE_JSON_PATH="${BUNDLE_DIR}/bundle.json"

mkdir -p "${BUNDLE_DIR}"
: >"${SUMMARY_PATH}"
: >"${COMPONENTS_PATH}"

summary_line "bundle_dir=${BUNDLE_DIR}"
summary_line "troubleshooting_matrix=${OPERATOR_TROUBLESHOOTING_RUNBOOK}"
if [[ -n "${CATEGORY}" ]]; then
  summary_line "category=${CATEGORY}"
  summary_line "category_key=${CATEGORY_KEY}"
fi
if [[ -n "${RUN_ID}" ]]; then
  summary_line "run_id=${RUN_ID}"
fi

if [[ -n "${CATEGORY}" ]]; then
  collect_category_bundle
fi
if [[ -n "${RUN_ID}" ]]; then
  collect_run_bundle
fi

python3 - <<'PY' "${SUMMARY_PATH}" "${BUNDLE_STATUS}"
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
status_line = f"bundle_status={sys.argv[2]}"
text = path.read_text(encoding="utf-8")
path.write_text(text + status_line + "\n", encoding="utf-8")
PY

write_bundle_json

printf 'diagnostics bundle ready\n'
printf 'bundle_status=%s\n' "${BUNDLE_STATUS}"
printf 'bundle_dir=%s\n' "${BUNDLE_DIR}"
printf 'bundle_json=%s\n' "${BUNDLE_JSON_PATH}"
printf 'summary=%s\n' "${SUMMARY_PATH}"
printf 'troubleshooting_matrix=%s\n' "${OPERATOR_TROUBLESHOOTING_RUNBOOK}"
printf 'summary_hint=%s\n' "scripts/71_diagnostics_summary.sh <bundle_dir|bundle.json>"
