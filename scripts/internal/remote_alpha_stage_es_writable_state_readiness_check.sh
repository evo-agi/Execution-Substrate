#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${REPO_ROOT:-}" ]]; then
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_HELPER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  REPO_ROOT="$(cd "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_HELPER_DIR}/../.." && pwd)"
fi

remote_alpha_stage_es_writable_state_readiness_stage_schema_version="execution-substrate.remote-alpha.es-writable-state-readiness-stage-provenance.v1"
remote_alpha_stage_es_writable_state_readiness_checker_schema_version="execution-substrate.remote-alpha.es-writable-state-readiness.v1"
remote_alpha_stage_es_writable_state_readiness_remote_stage_root_default="/var/tmp/execution-substrate-remote-alpha/helper-staging"
remote_alpha_stage_es_writable_state_readiness_default_output_dir="${REPO_ROOT}/.out/remote-alpha-m75q"
remote_alpha_stage_es_writable_state_readiness_default_config_path="/etc/execution-substrate/es.json"
remote_alpha_stage_es_writable_state_readiness_default_mode="alpha-compat"

REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_KEEP_STAGING_ON_FAILURE="false"
REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_SSH_TARGET=""
REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_REMOTE_UPLOAD_ROOT=""
REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_REMOTE_STAGING_ROOT=""
REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_LOCAL_UPLOAD_DIR=""
REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_LOCAL_FILE_META_PATH=""
REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_STAGE_STAT_PATH=""
REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_REMOTE_META_PATH=""
REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_CHECKER_META_PATH=""
REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_SHOW_HELP="false"
REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_STAGING_OCCURRED="false"
REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_CHECKER_RAN="false"
REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_TRANSIENT_STAGING_REMOVED="false"
REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_STAGING_RETAINED_FOR_DIAGNOSTICS="false"
REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_SUDO_OR_PREFLIGHT_BLOCKER=""
REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_CHECKER_EXIT_CODE=""

remote_alpha_stage_es_writable_state_readiness_check_usage() {
  cat <<'EOF'
Usage:
  scripts/remote_alpha_stage_es_writable_state_readiness_check.sh --ssh-target <user@host>

Optional flags:
  --ssh-target <user@host>
  --mode <alpha-compat|future-non-root-required>
  --run-id <timestamp-or-id>
  --output-dir </path/to/output-dir>
  --readiness-output </path/to/es-writable-state-readiness.json>
  --helper-staging-record-output </path/to/es-writable-state-readiness-helper-staging-record.json>
  --provenance-output </path/to/es-writable-state-readiness-helper-staging-record.json>
  --keep-staging-on-failure
  --help

Default behavior stages the minimal checker helper tree, runs the staged
checker from a root-owned path, writes IM-compatible local evidence outputs,
and remains non-mutating except for temporary helper staging.
EOF
}

remote_alpha_stage_es_writable_state_readiness_check_defaults() {
  local run_id_default

  run_id_default="$(date -u +%Y%m%dT%H%M%SZ)-$$"
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_CHECKER_MODE="${remote_alpha_stage_es_writable_state_readiness_default_mode}"
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_RUN_ID="${run_id_default}"
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OUTPUT_DIR=""
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_READINESS_OUTPUT_PATH=""
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_PROVENANCE_OUTPUT_PATH=""
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_REMOTE_STAGE_ROOT="${remote_alpha_stage_es_writable_state_readiness_remote_stage_root_default}"
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_CONFIG_PATH="${remote_alpha_stage_es_writable_state_readiness_default_config_path}"
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_SSH_BIN="${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_SSH_BIN:-ssh}"
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_SCP_BIN="${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_SCP_BIN:-scp}"
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_SSH_TTY_FLAG="${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_SSH_TTY_FLAG:--tt}"
}

remote_alpha_stage_es_writable_state_readiness_check_validate_mode() {
  case "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_CHECKER_MODE}" in
    alpha-compat|future-non-root-required)
      ;;
    *)
      echo "unsupported checker mode: ${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_CHECKER_MODE}" >&2
      return 1
      ;;
  esac
}

remote_alpha_stage_es_writable_state_readiness_check_parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --ssh-target)
        REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_SSH_TARGET="$2"
        shift 2
        ;;
      --mode)
        REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_CHECKER_MODE="$2"
        shift 2
        ;;
      --run-id)
        REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_RUN_ID="$2"
        shift 2
        ;;
      --output-dir)
        REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OUTPUT_DIR="$2"
        shift 2
        ;;
      --readiness-output)
        REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_READINESS_OUTPUT_PATH="$2"
        shift 2
        ;;
      --helper-staging-record-output)
        REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_PROVENANCE_OUTPUT_PATH="$2"
        shift 2
        ;;
      --provenance-output)
        REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_PROVENANCE_OUTPUT_PATH="$2"
        shift 2
        ;;
      --keep-staging-on-failure)
        REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_KEEP_STAGING_ON_FAILURE="true"
        shift
        ;;
      --help|-h)
        REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_SHOW_HELP="true"
        remote_alpha_stage_es_writable_state_readiness_check_usage
        return 0
        ;;
      *)
        echo "unknown argument: $1" >&2
        remote_alpha_stage_es_writable_state_readiness_check_usage >&2
        return 2
        ;;
    esac
  done

  remote_alpha_stage_es_writable_state_readiness_check_validate_mode || return 1

  if [[ -z "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_SSH_TARGET}" ]]; then
    echo "--ssh-target is required" >&2
    return 2
  fi
}

remote_alpha_stage_es_writable_state_readiness_check_finalize_paths() {
  if [[ -z "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OUTPUT_DIR}" ]]; then
    REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OUTPUT_DIR="${remote_alpha_stage_es_writable_state_readiness_default_output_dir}"
  fi
  if [[ -z "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_READINESS_OUTPUT_PATH}" ]]; then
    REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_READINESS_OUTPUT_PATH="${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OUTPUT_DIR}/es-writable-state-readiness.json"
  fi
  if [[ -z "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_PROVENANCE_OUTPUT_PATH}" ]]; then
    REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_PROVENANCE_OUTPUT_PATH="${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_OUTPUT_DIR}/es-writable-state-readiness-helper-staging-record.json"
  fi
}

remote_alpha_stage_es_writable_state_readiness_check_require_command() {
  local name=$1
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "${name} is required" >&2
    return 1
  fi
}

remote_alpha_stage_es_writable_state_readiness_check_helper_paths() {
  printf '%s\n' \
    "${REPO_ROOT}/scripts/remote_alpha_check_es_writable_state_readiness.sh" \
    "${REPO_ROOT}/scripts/internal/remote_alpha_check_es_writable_state_readiness.sh"
}

remote_alpha_stage_es_writable_state_readiness_check_git_commit() {
  if command -v git >/dev/null 2>&1; then
    git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || true
    return 0
  fi
  printf '\n'
}

remote_alpha_stage_es_writable_state_readiness_check_ensure_parent_dir() {
  local path=$1
  mkdir -p "$(dirname "${path}")"
}

remote_alpha_stage_es_writable_state_readiness_check_make_local_upload_tree() {
  local upload_dir=$1

  mkdir -p "${upload_dir}/scripts/internal"
  cp "${REPO_ROOT}/scripts/remote_alpha_check_es_writable_state_readiness.sh" "${upload_dir}/scripts/remote_alpha_check_es_writable_state_readiness.sh"
  cp "${REPO_ROOT}/scripts/internal/remote_alpha_check_es_writable_state_readiness.sh" "${upload_dir}/scripts/internal/remote_alpha_check_es_writable_state_readiness.sh"
}

remote_alpha_stage_es_writable_state_readiness_check_local_file_meta() {
  local output_path=$1
  shift

  python3 - "$output_path" "$@" <<'PY'
import hashlib
import json
import pathlib
import sys

output_path = pathlib.Path(sys.argv[1])
files = []
for raw_path in sys.argv[2:]:
    path = pathlib.Path(raw_path)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    files.append({
        "path": str(path),
        "sha256": digest,
    })

output_path.write_text(json.dumps(files, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

remote_alpha_stage_es_writable_state_readiness_check_ssh() {
  local -a ssh_args
  ssh_args=()
  if [[ -n "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_SSH_TTY_FLAG}" ]]; then
    ssh_args+=("${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_SSH_TTY_FLAG}")
  fi
  "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_SSH_BIN}" "${ssh_args[@]}" "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_SSH_TARGET}" "$@"
}

remote_alpha_stage_es_writable_state_readiness_check_scp() {
  "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_SCP_BIN}" "$@"
}

remote_alpha_stage_es_writable_state_readiness_check_note_blocker() {
  local message=$1
  if [[ -z "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_SUDO_OR_PREFLIGHT_BLOCKER}" ]]; then
    REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_SUDO_OR_PREFLIGHT_BLOCKER="${message}"
  fi
}

remote_alpha_stage_es_writable_state_readiness_check_remote_prepare_upload_root() {
  remote_alpha_stage_es_writable_state_readiness_check_ssh /bin/bash -s -- "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_REMOTE_UPLOAD_ROOT}" <<'EOF'
set -euo pipefail
upload_root=$1
rm -rf -- "${upload_root}"
mkdir -p -- "${upload_root}"
EOF
}

remote_alpha_stage_es_writable_state_readiness_check_remote_install_staged_tree() {
  remote_alpha_stage_es_writable_state_readiness_check_ssh /bin/bash -s -- \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_REMOTE_UPLOAD_ROOT}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_REMOTE_STAGING_ROOT}" <<'EOF'
set -euo pipefail
upload_root=$1
staging_root=$2

sudo rm -rf -- "${staging_root}"
sudo install -d -m 0755 -o root -g root "${staging_root}"
sudo install -d -m 0755 -o root -g root "${staging_root}/scripts"
sudo install -d -m 0755 -o root -g root "${staging_root}/scripts/internal"
sudo install -m 0755 -o root -g root "${upload_root}/scripts/remote_alpha_check_es_writable_state_readiness.sh" "${staging_root}/scripts/remote_alpha_check_es_writable_state_readiness.sh"
sudo install -m 0644 -o root -g root "${upload_root}/scripts/internal/remote_alpha_check_es_writable_state_readiness.sh" "${staging_root}/scripts/internal/remote_alpha_check_es_writable_state_readiness.sh"
rm -rf -- "${upload_root}"
EOF
}

remote_alpha_stage_es_writable_state_readiness_check_remote_stage_stat() {
  local output_path=$1

  remote_alpha_stage_es_writable_state_readiness_check_ssh /bin/bash -s -- \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_REMOTE_STAGING_ROOT}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_REMOTE_STAGED_WRAPPER_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_REMOTE_STAGED_INTERNAL_PATH}" >"${output_path}" <<'EOF'
set -euo pipefail
staging_root=$1
staged_wrapper=$2
staged_internal=$3

sudo stat -c '%U\t%G\t%a\t%n' \
  "${staging_root}" \
  "${staging_root}/scripts" \
  "${staging_root}/scripts/internal" \
  "${staged_wrapper}" \
  "${staged_internal}"
EOF
}

remote_alpha_stage_es_writable_state_readiness_check_validate_stage_stat() {
  local stat_path=$1
  local output_path=$2

  python3 - "$stat_path" "$output_path" "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_REMOTE_STAGING_ROOT}" <<'PY'
import json
import pathlib
import sys

stat_path = pathlib.Path(sys.argv[1])
output_path = pathlib.Path(sys.argv[2])
staging_root = sys.argv[3]

items = []
errors = []

for raw_line in stat_path.read_text(encoding="utf-8").splitlines():
    if not raw_line.strip():
        continue
    owner, group, mode, path = raw_line.split("\t", 3)
    mode_text = mode.zfill(4)
    mode_value = int(mode_text, 8)
    root_owned = owner == "root"
    not_group_or_other_writable = (mode_value & 0o022) == 0
    inside_staging_root = path == staging_root or path.startswith(staging_root + "/")
    item = {
        "path": path,
        "owner": owner,
        "group": group,
        "mode": mode_text,
        "root_owned": root_owned,
        "not_group_or_other_writable": not_group_or_other_writable,
        "inside_staging_root": inside_staging_root,
    }
    items.append(item)
    if not root_owned:
        errors.append(f"path is not root-owned: {path}")
    if not not_group_or_other_writable:
        errors.append(f"path is group-writable or world-writable: {path}")
    if not inside_staging_root:
        errors.append(f"path is outside the staged helper root: {path}")

if len(items) != 5:
    errors.append(f"expected 5 staged helper paths, found {len(items)}")

payload = {
    "staged_root": staging_root,
    "items": items,
    "validation_errors": errors,
    "root_owned_before_execution": not errors and len(items) == 5,
}
output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if errors:
    raise SystemExit(1)
PY
}

remote_alpha_stage_es_writable_state_readiness_check_run_remote_checker() {
  local output_path=$1
  local status=0

  set +e
  remote_alpha_stage_es_writable_state_readiness_check_ssh /bin/bash -s -- \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_REMOTE_STAGED_WRAPPER_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_CONFIG_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_CHECKER_MODE}" >"${output_path}" <<'EOF'
set -euo pipefail
staged_wrapper=$1
config_path=$2
checker_mode=$3

sudo "${staged_wrapper}" --config-path "${config_path}" --mode "${checker_mode}"
EOF
  status=$?
  set -e

  return "${status}"
}

remote_alpha_stage_es_writable_state_readiness_check_validate_report() {
  local report_path=$1
  local meta_path=$2

  python3 - "$report_path" "$meta_path" "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_CHECKER_MODE}" "${remote_alpha_stage_es_writable_state_readiness_checker_schema_version}" <<'PY'
import json
import pathlib
import sys

report_path = pathlib.Path(sys.argv[1])
meta_path = pathlib.Path(sys.argv[2])
requested_mode = sys.argv[3]
expected_schema = sys.argv[4]
expected_future = requested_mode == "future-non-root-required"


def write_meta(payload):
    meta_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


summary = {
    "valid_json": False,
    "accepted_evidence": False,
    "requested_mode": requested_mode,
}

try:
    payload = json.loads(report_path.read_text(encoding="utf-8"))
except Exception as exc:  # noqa: BLE001
    summary["error"] = f"malformed checker JSON: {exc}"
    write_meta(summary)
    print(summary["error"], file=sys.stderr)
    raise SystemExit(1)

errors = []
blockers = payload.get("blockers")
warnings = payload.get("warnings")
bounded_edges = payload.get("bounded_compatibility_edges")
checker_mode = payload.get("checker_mode")
future_non_root_required = payload.get("future_non_root_required")
overall = payload.get("overall_classification")
target_owner = payload.get("target_owner_verification")

summary.update(
    {
        "valid_json": True,
        "schema_version": payload.get("schema_version"),
        "operation_mode": payload.get("operation_mode"),
        "non_mutating": payload.get("non_mutating"),
        "checker_mode": checker_mode,
        "checker_mode_matches_requested": checker_mode == requested_mode,
        "future_non_root_required": future_non_root_required,
        "future_non_root_required_matches_requested": future_non_root_required == expected_future,
        "future_non_root_ready": payload.get("future_non_root_ready"),
        "overall_classification": overall,
        "blocker_count": len(blockers) if isinstance(blockers, list) else None,
        "warning_count": len(warnings) if isinstance(warnings, list) else None,
        "target_owner_verification_status": target_owner.get("status") if isinstance(target_owner, dict) else None,
        "expected_exit_code": 1 if overall == "blocker" else 0,
    }
)

if payload.get("schema_version") != expected_schema:
    errors.append(f"unexpected checker schema_version: {payload.get('schema_version')!r}")
if payload.get("operation_mode") != "check_only":
    errors.append("checker output operation_mode must be check_only")
if payload.get("non_mutating") is not True:
    errors.append("checker output must claim non_mutating=true")
if not isinstance(checker_mode, str) or not checker_mode:
    errors.append("checker output must include checker_mode")
elif checker_mode != requested_mode:
    errors.append("checker output checker_mode did not match requested mode")
if not isinstance(future_non_root_required, bool):
    errors.append("checker output must include boolean future_non_root_required")
elif future_non_root_required != expected_future:
    errors.append("checker output future_non_root_required did not match requested mode")
if not isinstance(overall, str) or not overall:
    errors.append("checker output must include overall_classification")
if not isinstance(blockers, list):
    errors.append("checker output must include blockers array")
if not isinstance(warnings, list):
    errors.append("checker output must include warnings array")
if not isinstance(bounded_edges, list):
    errors.append("checker output must include bounded_compatibility_edges array")

for suspicious_key in (
    "governed_proof",
    "proof_authority",
    "approved_to_deroot_es",
    "approval_to_deroot_es",
    "service_user_migration_approved",
):
    value = payload.get(suspicious_key)
    if value not in (None, False, "", 0):
        errors.append(f"checker output must not claim proof or ES de-root authority via {suspicious_key}")

summary["errors"] = errors
summary["accepted_evidence"] = not errors
write_meta(summary)

if errors:
    for error in errors:
        print(error, file=sys.stderr)
    raise SystemExit(1)
PY
}

remote_alpha_stage_es_writable_state_readiness_check_expected_exit_code() {
  local meta_path=$1

  python3 - "$meta_path" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
value = payload.get("expected_exit_code")
if value not in (0, 1):
    raise SystemExit(1)
print(value)
PY
}

remote_alpha_stage_es_writable_state_readiness_check_remote_path_exists() {
  local remote_path=$1

  remote_alpha_stage_es_writable_state_readiness_check_ssh /bin/bash -s -- "${remote_path}" <<'EOF'
set -euo pipefail
remote_path=$1

if [[ -e "${remote_path}" ]]; then
  exit 0
fi
exit 1
EOF
}

remote_alpha_stage_es_writable_state_readiness_check_cleanup_remote() {
  if [[ -z "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_SSH_TARGET}" ]]; then
    return 0
  fi
  if [[ -z "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_REMOTE_UPLOAD_ROOT}" && -z "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_REMOTE_STAGING_ROOT}" ]]; then
    return 0
  fi

  remote_alpha_stage_es_writable_state_readiness_check_ssh /bin/bash -s -- \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_REMOTE_UPLOAD_ROOT}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_REMOTE_STAGING_ROOT}" <<'EOF' >/dev/null
set -euo pipefail
upload_root=$1
staging_root=$2

if [[ -n "${upload_root}" ]]; then
  rm -rf -- "${upload_root}" || true
fi
if [[ -n "${staging_root}" ]]; then
  sudo rm -rf -- "${staging_root}" || true
fi
EOF
}

remote_alpha_stage_es_writable_state_readiness_check_write_provenance() {
  local provenance_path=$1
  local git_commit=$2
  local exit_code=$3

  python3 - \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_LOCAL_FILE_META_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_REMOTE_META_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_CHECKER_META_PATH}" \
    "${provenance_path}" \
    "${git_commit}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_SSH_TARGET}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_REMOTE_STAGING_ROOT}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_REMOTE_STAGED_WRAPPER_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_REMOTE_STAGED_INTERNAL_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_RUN_ID}" \
    "${REPO_ROOT}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_CHECKER_MODE}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_READINESS_OUTPUT_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_STAGING_OCCURRED}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_CHECKER_RAN}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_TRANSIENT_STAGING_REMOVED}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_STAGING_RETAINED_FOR_DIAGNOSTICS}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_SUDO_OR_PREFLIGHT_BLOCKER}" \
    "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_CHECKER_EXIT_CODE}" \
    "${exit_code}" \
    "${remote_alpha_stage_es_writable_state_readiness_stage_schema_version}" <<'PY'
import json
import pathlib
from pathlib import PurePosixPath
import sys
from datetime import datetime, timezone


def read_json(path, default):
    if not path:
        return default
    p = pathlib.Path(path)
    if not p.exists():
        return default
    try:
        text = p.read_text(encoding="utf-8").strip()
        if not text:
            return default
        return json.loads(text)
    except Exception:  # noqa: BLE001
        return default


local_meta = read_json(sys.argv[1], [])
remote_meta = read_json(sys.argv[2], {"items": [], "root_owned_before_execution": False, "validation_errors": []})
checker_meta = read_json(sys.argv[3], {"valid_json": False, "accepted_evidence": False})
provenance_path = pathlib.Path(sys.argv[4])
git_commit = sys.argv[5]
repo_root = pathlib.Path(sys.argv[11]).resolve()
staged_root = sys.argv[7]

staged_files = []
for item in local_meta:
    path = pathlib.Path(item["path"]).resolve()
    try:
        local_path = path.relative_to(repo_root).as_posix()
    except ValueError:
        local_path = path.name
    staged_files.append(
        {
            "local_path": local_path,
            "sha256": item["sha256"],
            "remote_path": str(PurePosixPath(staged_root) / PurePosixPath(local_path)) if staged_root else local_path,
        }
    )

payload = {
    "schema_version": sys.argv[21],
    "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "run_id": sys.argv[10],
    "ssh_target": sys.argv[6],
    "git_commit": git_commit or None,
    "local_git_commit": git_commit or None,
    "requested_checker_mode": sys.argv[12],
    "local_outputs": {
        "readiness_output_path": sys.argv[13],
        "helper_staging_record_output_path": str(provenance_path),
    },
    "local_files": local_meta,
    "staged_files": staged_files,
    "remote_staged_path": staged_root or None,
    "staging_occurred": sys.argv[14] == "true",
    "checker_ran": sys.argv[15] == "true",
    "transient_staging_removed": sys.argv[16] == "true",
    "staging_retained_for_diagnostics": sys.argv[17] == "true",
    "sudo_or_preflight_blocker": sys.argv[18] or None,
    "checker_exit_code": int(sys.argv[19]) if sys.argv[19] else None,
    "wrapper_exit_code": int(sys.argv[20]),
    "remote_staging": {
        "staged_root": staged_root or None,
        "staged_wrapper_path": sys.argv[8] or None,
        "staged_internal_path": sys.argv[9] or None,
        "items": remote_meta.get("items") or [],
        "validation_errors": remote_meta.get("validation_errors") or [],
        "root_owned_before_execution": remote_meta.get("root_owned_before_execution") is True,
    },
    "checker": checker_meta,
}

provenance_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

remote_alpha_stage_es_writable_state_readiness_check_cleanup_on_exit() {
  local exit_code=$?
  local git_commit
  local should_cleanup_remote="false"

  if [[ $exit_code -eq 0 || "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_KEEP_STAGING_ON_FAILURE}" != "true" ]]; then
    should_cleanup_remote="true"
  fi

  if [[ "${should_cleanup_remote}" == "true" ]]; then
    if remote_alpha_stage_es_writable_state_readiness_check_cleanup_remote; then
      if [[ -n "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_REMOTE_STAGING_ROOT}" ]]; then
        REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_TRANSIENT_STAGING_REMOVED="true"
      fi
    fi
  else
    REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_STAGING_RETAINED_FOR_DIAGNOSTICS="true"
  fi

  git_commit="$(remote_alpha_stage_es_writable_state_readiness_check_git_commit)"
  if [[ -n "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_PROVENANCE_OUTPUT_PATH}" ]]; then
    if ! remote_alpha_stage_es_writable_state_readiness_check_write_provenance "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_PROVENANCE_OUTPUT_PATH}" "${git_commit}" "${exit_code}"; then
      echo "failed to write helper staging record" >&2
      if [[ $exit_code -eq 0 ]]; then
        exit_code=1
      fi
    fi
  fi

  if [[ -n "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_LOCAL_FILE_META_PATH}" ]]; then
    rm -f -- "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_LOCAL_FILE_META_PATH}"
  fi
  if [[ -n "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_STAGE_STAT_PATH}" ]]; then
    rm -f -- "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_STAGE_STAT_PATH}"
  fi
  if [[ -n "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_REMOTE_META_PATH}" ]]; then
    rm -f -- "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_REMOTE_META_PATH}"
  fi
  if [[ -n "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_CHECKER_META_PATH}" ]]; then
    rm -f -- "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_CHECKER_META_PATH}"
  fi
  if [[ -n "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_LOCAL_UPLOAD_DIR}" && -d "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_LOCAL_UPLOAD_DIR}" ]]; then
    rm -rf -- "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_LOCAL_UPLOAD_DIR}"
  fi

  return "${exit_code}"
}

remote_alpha_stage_es_writable_state_readiness_check_main() {
  local -a helper_paths
  local check_status=0
  local expected_exit_code

  remote_alpha_stage_es_writable_state_readiness_check_defaults
  remote_alpha_stage_es_writable_state_readiness_check_parse_args "$@" || return $?
  if [[ "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_SHOW_HELP}" == "true" ]]; then
    return 0
  fi
  remote_alpha_stage_es_writable_state_readiness_check_finalize_paths

  remote_alpha_stage_es_writable_state_readiness_check_require_command python3 || return 1
  remote_alpha_stage_es_writable_state_readiness_check_require_command "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_SSH_BIN}" || return 1
  remote_alpha_stage_es_writable_state_readiness_check_require_command "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_SCP_BIN}" || return 1

  helper_paths=()
  while IFS= read -r helper_path; do
    helper_paths+=("${helper_path}")
  done < <(remote_alpha_stage_es_writable_state_readiness_check_helper_paths)

  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_REMOTE_UPLOAD_ROOT="/tmp/execution-substrate-remote-alpha-helper-upload-${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_RUN_ID}"
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_REMOTE_STAGING_ROOT="${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_REMOTE_STAGE_ROOT}/${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_RUN_ID}"
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_REMOTE_STAGED_WRAPPER_PATH="${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_REMOTE_STAGING_ROOT}/scripts/remote_alpha_check_es_writable_state_readiness.sh"
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_REMOTE_STAGED_INTERNAL_PATH="${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_REMOTE_STAGING_ROOT}/scripts/internal/remote_alpha_check_es_writable_state_readiness.sh"

  remote_alpha_stage_es_writable_state_readiness_check_ensure_parent_dir "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_READINESS_OUTPUT_PATH}"
  remote_alpha_stage_es_writable_state_readiness_check_ensure_parent_dir "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_PROVENANCE_OUTPUT_PATH}"

  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_LOCAL_UPLOAD_DIR="$(mktemp -d)"
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_LOCAL_FILE_META_PATH="$(mktemp)"
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_STAGE_STAT_PATH="$(mktemp)"
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_REMOTE_META_PATH="$(mktemp)"
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_CHECKER_META_PATH="$(mktemp)"
  trap 'remote_alpha_stage_es_writable_state_readiness_check_cleanup_on_exit' EXIT

  remote_alpha_stage_es_writable_state_readiness_check_make_local_upload_tree "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_LOCAL_UPLOAD_DIR}"
  remote_alpha_stage_es_writable_state_readiness_check_local_file_meta "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_LOCAL_FILE_META_PATH}" "${helper_paths[@]}"

  remote_alpha_stage_es_writable_state_readiness_check_remote_prepare_upload_root || {
    remote_alpha_stage_es_writable_state_readiness_check_note_blocker "could not prepare remote upload root for staged checker helper tree"
    return 1
  }
  remote_alpha_stage_es_writable_state_readiness_check_scp -r "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_LOCAL_UPLOAD_DIR}/scripts" "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_SSH_TARGET}:${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_REMOTE_UPLOAD_ROOT}/" || {
    remote_alpha_stage_es_writable_state_readiness_check_note_blocker "could not copy staged checker helper tree to remote upload root"
    return 1
  }
  remote_alpha_stage_es_writable_state_readiness_check_remote_install_staged_tree || {
    remote_alpha_stage_es_writable_state_readiness_check_note_blocker "could not install staged checker helper tree as root-owned remote staging"
    return 1
  }
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_STAGING_OCCURRED="true"
  remote_alpha_stage_es_writable_state_readiness_check_remote_stage_stat "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_STAGE_STAT_PATH}" || {
    remote_alpha_stage_es_writable_state_readiness_check_note_blocker "could not verify remote staged helper ownership and mode"
    return 1
  }
  remote_alpha_stage_es_writable_state_readiness_check_validate_stage_stat "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_STAGE_STAT_PATH}" "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_REMOTE_META_PATH}" || {
    remote_alpha_stage_es_writable_state_readiness_check_note_blocker "staged checker helper tree failed root-owned or non-writable validation"
    echo "staged checker helper tree failed root-owned or non-writable validation" >&2
    return 1
  }

  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_CHECKER_RAN="true"
  if remote_alpha_stage_es_writable_state_readiness_check_run_remote_checker "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_READINESS_OUTPUT_PATH}"; then
    check_status=0
  else
    check_status=$?
  fi
  REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_CHECKER_EXIT_CODE="${check_status}"

  if [[ ! -s "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_READINESS_OUTPUT_PATH}" ]]; then
    remote_alpha_stage_es_writable_state_readiness_check_note_blocker "staged checker did not produce local readiness JSON output"
    echo "staged checker did not produce local readiness JSON output" >&2
    return 1
  fi

  remote_alpha_stage_es_writable_state_readiness_check_validate_report "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_READINESS_OUTPUT_PATH}" "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_CHECKER_META_PATH}" || {
    remote_alpha_stage_es_writable_state_readiness_check_note_blocker "staged checker output was malformed or violated the non-mutating readiness contract"
    return 1
  }

  expected_exit_code="$(remote_alpha_stage_es_writable_state_readiness_check_expected_exit_code "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_CHECKER_META_PATH}")" || {
    remote_alpha_stage_es_writable_state_readiness_check_note_blocker "could not derive the expected exit code from the validated checker output"
    return 1
  }
  if [[ "${check_status}" -ne "${expected_exit_code}" ]]; then
    remote_alpha_stage_es_writable_state_readiness_check_note_blocker "staged checker exit code did not match the validated overall classification"
    echo "staged checker exit code ${check_status} did not match validated output expectation ${expected_exit_code}" >&2
    return 1
  fi
  if [[ "${check_status}" -gt 1 ]]; then
    remote_alpha_stage_es_writable_state_readiness_check_note_blocker "staged checker exited with an unexpected transport or execution failure"
    echo "staged checker exited with unexpected status ${check_status}" >&2
    return 1
  fi

  printf '%s\n' "${REMOTE_ALPHA_STAGE_ES_WRITABLE_STATE_READINESS_OUTPUT_PATH}"
}
