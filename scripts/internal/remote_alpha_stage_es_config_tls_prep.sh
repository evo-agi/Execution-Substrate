#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${REPO_ROOT:-}" ]]; then
  REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_HELPER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  REPO_ROOT="$(cd "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_HELPER_DIR}/../.." && pwd)"
fi

remote_alpha_stage_es_config_tls_prep_remote_stage_root_default="/var/tmp/execution-substrate-remote-alpha/helper-staging"
remote_alpha_stage_es_config_tls_prep_remote_summary_path_default="/var/tmp/execution-substrate-remote-alpha/es-config-tls-prep-summary.json"
remote_alpha_stage_es_config_tls_prep_config_path="/etc/execution-substrate/es.json"
remote_alpha_stage_es_config_tls_prep_tls_dir="/etc/execution-substrate/es-tls"

REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_KEEP_STAGING_ON_FAILURE="false"
REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_SSH_TARGET=""
REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_UPLOAD_ROOT=""
REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_STAGING_ROOT=""
REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_LOCAL_UPLOAD_DIR=""
REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_LOCAL_FILE_META_PATH=""
REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_STAGE_STAT_PATH=""
REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_META_PATH=""
REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_SHOW_HELP="false"

remote_alpha_stage_es_config_tls_prep_usage() {
  cat <<'EOF'
Usage:
  scripts/remote_alpha_stage_es_config_tls_prep.sh --ssh-target <user@host>
  scripts/remote_alpha_stage_es_config_tls_prep.sh --ssh-target <user@host> --apply

Optional flags:
  --ssh-target <user@host>
  --apply
  --run-id <timestamp-or-id>
  --output-dir </path/to/output-dir>
  --check-output </path/to/es-config-tls-check-only.json>
  --apply-summary-output </path/to/es-config-tls-apply-summary.json>
  --apply-stdout-output </path/to/es-config-tls-apply-stdout.txt>
  --helper-staging-record-output </path/to/es-config-tls-helper-staging-record.json>
  --provenance-output </path/to/es-config-tls-helper-staging-record.json>
  --remote-summary-path </remote/path/to/es-config-tls-prep-summary.json>
  --keep-staging-on-failure
  --help

Default behavior is non-mutating check-only. Apply requires --apply.
EOF
}

remote_alpha_stage_es_config_tls_prep_defaults() {
  local run_id_default

  run_id_default="$(date -u +%Y%m%dT%H%M%SZ)-$$"
  REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_MODE="check_only"
  REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_RUN_ID="${run_id_default}"
  REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_OUTPUT_DIR=""
  REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_CHECK_OUTPUT_PATH=""
  REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_APPLY_SUMMARY_OUTPUT_PATH=""
  REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_APPLY_STDOUT_OUTPUT_PATH=""
  REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_PROVENANCE_OUTPUT_PATH=""
  REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_SUMMARY_PATH="${remote_alpha_stage_es_config_tls_prep_remote_summary_path_default}"
  REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_STAGE_ROOT="${remote_alpha_stage_es_config_tls_prep_remote_stage_root_default}"
  REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_SSH_BIN="${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_SSH_BIN:-ssh}"
  REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_SCP_BIN="${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_SCP_BIN:-scp}"
}

remote_alpha_stage_es_config_tls_prep_parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --ssh-target)
        REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_SSH_TARGET="$2"
        shift 2
        ;;
      --apply)
        REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_MODE="apply"
        shift
        ;;
      --run-id)
        REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_RUN_ID="$2"
        shift 2
        ;;
      --output-dir)
        REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_OUTPUT_DIR="$2"
        shift 2
        ;;
      --check-output)
        REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_CHECK_OUTPUT_PATH="$2"
        shift 2
        ;;
      --apply-summary-output)
        REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_APPLY_SUMMARY_OUTPUT_PATH="$2"
        shift 2
        ;;
      --apply-stdout-output)
        REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_APPLY_STDOUT_OUTPUT_PATH="$2"
        shift 2
        ;;
      --helper-staging-record-output)
        REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_PROVENANCE_OUTPUT_PATH="$2"
        shift 2
        ;;
      --provenance-output)
        REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_PROVENANCE_OUTPUT_PATH="$2"
        shift 2
        ;;
      --remote-summary-path)
        REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_SUMMARY_PATH="$2"
        shift 2
        ;;
      --keep-staging-on-failure)
        REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_KEEP_STAGING_ON_FAILURE="true"
        shift
        ;;
      --help|-h)
        REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_SHOW_HELP="true"
        remote_alpha_stage_es_config_tls_prep_usage
        return 0
        ;;
      *)
        echo "unknown argument: $1" >&2
        remote_alpha_stage_es_config_tls_prep_usage >&2
        return 2
        ;;
    esac
  done

  if [[ -z "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_SSH_TARGET}" ]]; then
    echo "--ssh-target is required" >&2
    return 2
  fi
}

remote_alpha_stage_es_config_tls_prep_finalize_paths() {
  if [[ -z "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_OUTPUT_DIR}" ]]; then
    REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_OUTPUT_DIR="${REPO_ROOT}/.out/remote-alpha-stage-es-config-tls-prep/${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_RUN_ID}"
  fi
  if [[ -z "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_CHECK_OUTPUT_PATH}" ]]; then
    REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_CHECK_OUTPUT_PATH="${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_OUTPUT_DIR}/es-config-tls-check-only.json"
  fi
  if [[ -z "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_APPLY_SUMMARY_OUTPUT_PATH}" ]]; then
    REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_APPLY_SUMMARY_OUTPUT_PATH="${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_OUTPUT_DIR}/es-config-tls-apply-summary.json"
  fi
  if [[ -z "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_APPLY_STDOUT_OUTPUT_PATH}" ]]; then
    REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_APPLY_STDOUT_OUTPUT_PATH="${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_OUTPUT_DIR}/es-config-tls-apply-stdout.txt"
  fi
  if [[ -z "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_PROVENANCE_OUTPUT_PATH}" ]]; then
    REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_PROVENANCE_OUTPUT_PATH="${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_OUTPUT_DIR}/es-config-tls-helper-staging-record.json"
  fi
}

remote_alpha_stage_es_config_tls_prep_require_command() {
  local name=$1
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "${name} is required" >&2
    return 1
  fi
}

remote_alpha_stage_es_config_tls_prep_helper_paths() {
  printf '%s\n' \
    "${REPO_ROOT}/scripts/remote_alpha_prepare_es_config_tls.sh" \
    "${REPO_ROOT}/scripts/internal/remote_alpha_prepare_es_config_tls.sh"
}

remote_alpha_stage_es_config_tls_prep_git_commit() {
  if command -v git >/dev/null 2>&1; then
    git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || true
    return 0
  fi
  printf '\n'
}

remote_alpha_stage_es_config_tls_prep_ensure_parent_dir() {
  local path=$1
  mkdir -p "$(dirname "${path}")"
}

remote_alpha_stage_es_config_tls_prep_make_local_upload_tree() {
  local upload_dir=$1

  mkdir -p "${upload_dir}/scripts/internal"
  cp "${REPO_ROOT}/scripts/remote_alpha_prepare_es_config_tls.sh" "${upload_dir}/scripts/remote_alpha_prepare_es_config_tls.sh"
  cp "${REPO_ROOT}/scripts/internal/remote_alpha_prepare_es_config_tls.sh" "${upload_dir}/scripts/internal/remote_alpha_prepare_es_config_tls.sh"
}

remote_alpha_stage_es_config_tls_prep_local_file_meta() {
  local output_path=$1
  shift

  python3 -I - "$output_path" "$@" <<'PY'
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

remote_alpha_stage_es_config_tls_prep_ssh() {
  "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_SSH_BIN}" "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_SSH_TARGET}" "$@"
}

remote_alpha_stage_es_config_tls_prep_scp() {
  "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_SCP_BIN}" "$@"
}

remote_alpha_stage_es_config_tls_prep_remote_prepare_upload_root() {
  remote_alpha_stage_es_config_tls_prep_ssh /bin/bash -s -- "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_UPLOAD_ROOT}" <<'EOF'
set -euo pipefail
upload_root=$1
rm -rf -- "${upload_root}"
mkdir -p -- "${upload_root}"
EOF
}

remote_alpha_stage_es_config_tls_prep_remote_install_staged_tree() {
  remote_alpha_stage_es_config_tls_prep_ssh /bin/bash -s -- \
    "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_UPLOAD_ROOT}" \
    "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_STAGING_ROOT}" <<'EOF'
set -euo pipefail
upload_root=$1
staging_root=$2

sudo rm -rf -- "${staging_root}"
sudo install -d -m 0755 -o root -g root "${staging_root}"
sudo install -d -m 0755 -o root -g root "${staging_root}/scripts"
sudo install -d -m 0755 -o root -g root "${staging_root}/scripts/internal"
sudo install -m 0755 -o root -g root "${upload_root}/scripts/remote_alpha_prepare_es_config_tls.sh" "${staging_root}/scripts/remote_alpha_prepare_es_config_tls.sh"
sudo install -m 0644 -o root -g root "${upload_root}/scripts/internal/remote_alpha_prepare_es_config_tls.sh" "${staging_root}/scripts/internal/remote_alpha_prepare_es_config_tls.sh"
rm -rf -- "${upload_root}"
EOF
}

remote_alpha_stage_es_config_tls_prep_remote_stage_stat() {
  local output_path=$1

  remote_alpha_stage_es_config_tls_prep_ssh /bin/bash -s -- \
    "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_STAGING_ROOT}" \
    "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_STAGED_WRAPPER_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_STAGED_INTERNAL_PATH}" >"${output_path}" <<'EOF'
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

remote_alpha_stage_es_config_tls_prep_validate_stage_stat() {
  local stat_path=$1
  local output_path=$2

  python3 -I - "$stat_path" "$output_path" "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_STAGING_ROOT}" <<'PY'
import json
import pathlib
import sys

stat_path = pathlib.Path(sys.argv[1])
output_path = pathlib.Path(sys.argv[2])
staging_root = sys.argv[3]

items = []
valid = True

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
    if not (root_owned and not_group_or_other_writable and inside_staging_root):
        valid = False

payload = {
    "staged_root": staging_root,
    "items": items,
    "root_owned_before_execution": valid and len(items) == 5,
}
output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if not valid or len(items) != 5:
    raise SystemExit(1)
PY
}

remote_alpha_stage_es_config_tls_prep_write_provenance() {
  local local_meta_path=$1
  local remote_meta_path=$2
  local provenance_path=$3
  local git_commit=$4

  python3 -I - "$local_meta_path" "$remote_meta_path" "$provenance_path" "$git_commit" "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_MODE}" "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_SSH_TARGET}" "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_STAGING_ROOT}" "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_STAGED_WRAPPER_PATH}" "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_STAGED_INTERNAL_PATH}" "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_SUMMARY_PATH}" "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_RUN_ID}" "${REPO_ROOT}" <<'PY'
import json
import pathlib
from pathlib import PurePosixPath
import sys
from datetime import datetime, timezone

local_meta = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
remote_meta = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
provenance_path = pathlib.Path(sys.argv[3])
git_commit = sys.argv[4]
repo_root = pathlib.Path(sys.argv[12]).resolve()

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
            "remote_path": str(PurePosixPath(staged_root) / PurePosixPath(local_path)),
        }
    )

payload = {
    "schema_version": "execution-substrate.remote-alpha.es-config-tls-prep-stage-provenance.v1",
    "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "run_id": sys.argv[11],
    "command_mode": sys.argv[5],
    "ssh_target": sys.argv[6],
    "git_commit": git_commit or None,
    "local_git_commit": git_commit or None,
    "local_files": local_meta,
    "remote_staged_path": staged_root,
    "staged_files": staged_files,
    "remote_staging": {
        "staged_root": staged_root,
        "staged_wrapper_path": sys.argv[8],
        "staged_internal_path": sys.argv[9],
        "remote_summary_path": sys.argv[10],
        "items": remote_meta["items"],
        "root_owned_before_execution": remote_meta["root_owned_before_execution"],
    },
}

provenance_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

remote_alpha_stage_es_config_tls_prep_run_remote_check_only() {
  local output_path=$1

  if ! remote_alpha_stage_es_config_tls_prep_ssh /bin/bash -s -- \
    "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_STAGED_WRAPPER_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_SUMMARY_PATH}" >"${output_path}" <<'EOF'
set -euo pipefail
staged_wrapper=$1
remote_summary_path=$2

sudo "${staged_wrapper}" --check-only --summary-path "${remote_summary_path}"
EOF
  then
    return 1
  fi
}

remote_alpha_stage_es_config_tls_prep_validate_check_only_report() {
  local report_path=$1

  python3 -I - "$report_path" "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_SUMMARY_PATH}" "${remote_alpha_stage_es_config_tls_prep_config_path}" "${remote_alpha_stage_es_config_tls_prep_tls_dir}" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
summary_path = sys.argv[2]
config_path = sys.argv[3]
tls_dir = sys.argv[4]

errors = []

result = report.get("result") or {}
plan = report.get("plan") or {}
validation = report.get("validation") or {}
rewrite_scope = validation.get("config_rewrite_scope") or {}
paths_written = plan.get("paths_written") or []
blockers = plan.get("blockers") or []

if result.get("ok") is not True:
    errors.append("check-only result.ok must be true")
if result.get("non_mutating") is not True:
    errors.append("check-only result.non_mutating must be true")
if blockers:
    errors.append("check-only plan.blockers must be empty before apply")
if plan.get("service_identity_would_remain_root_default") is not True:
    errors.append("check-only must prove es.service remains root(default)")
if rewrite_scope.get("status") != "pass":
    errors.append("check-only validation.config_rewrite_scope.status must be pass")

allowed = []
for path in paths_written:
    if path == summary_path:
        allowed.append(True)
        continue
    if path == config_path:
        allowed.append(True)
        continue
    if path == tls_dir or path.startswith(tls_dir + "/"):
        allowed.append(True)
        continue
    allowed.append(False)

if not all(allowed):
    disallowed = [path for path, ok in zip(paths_written, allowed) if not ok]
    errors.append("check-only planned writes are broader than the allowed ES config/TLS prep paths: " + ", ".join(disallowed))

if errors:
    for message in errors:
        print(message, file=sys.stderr)
    raise SystemExit(1)
PY
}

remote_alpha_stage_es_config_tls_prep_run_remote_apply() {
  local output_path=$1

  remote_alpha_stage_es_config_tls_prep_ssh /bin/bash -s -- \
    "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_STAGED_WRAPPER_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_SUMMARY_PATH}" >"${output_path}" <<'EOF'
set -euo pipefail
staged_wrapper=$1
remote_summary_path=$2

sudo "${staged_wrapper}" --summary-path "${remote_summary_path}"
EOF
}

remote_alpha_stage_es_config_tls_prep_remote_path_exists() {
  local remote_path=$1

  remote_alpha_stage_es_config_tls_prep_ssh /bin/bash -s -- "${remote_path}" <<'EOF'
set -euo pipefail
remote_path=$1

if [[ -e "${remote_path}" ]]; then
  exit 0
fi
exit 1
EOF
}

remote_alpha_stage_es_config_tls_prep_fetch_remote_file() {
  local remote_path=$1
  local local_path=$2

  remote_alpha_stage_es_config_tls_prep_scp "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_SSH_TARGET}:${remote_path}" "${local_path}"
}

remote_alpha_stage_es_config_tls_prep_cleanup_remote() {
  if [[ -z "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_SSH_TARGET}" ]]; then
    return 0
  fi
  if [[ -z "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_UPLOAD_ROOT}" && -z "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_STAGING_ROOT}" ]]; then
    return 0
  fi

  remote_alpha_stage_es_config_tls_prep_ssh /bin/bash -s -- \
    "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_UPLOAD_ROOT}" \
    "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_STAGING_ROOT}" <<'EOF' >/dev/null
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

remote_alpha_stage_es_config_tls_prep_cleanup_on_exit() {
  local exit_code=$?

  if [[ -n "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_LOCAL_FILE_META_PATH}" ]]; then
    rm -f -- "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_LOCAL_FILE_META_PATH}"
  fi
  if [[ -n "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_STAGE_STAT_PATH}" ]]; then
    rm -f -- "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_STAGE_STAT_PATH}"
  fi
  if [[ -n "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_META_PATH}" ]]; then
    rm -f -- "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_META_PATH}"
  fi
  if [[ -n "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_LOCAL_UPLOAD_DIR}" && -d "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_LOCAL_UPLOAD_DIR}" ]]; then
    rm -rf -- "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_LOCAL_UPLOAD_DIR}"
  fi

  if [[ $exit_code -eq 0 || "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_KEEP_STAGING_ON_FAILURE}" != "true" ]]; then
    remote_alpha_stage_es_config_tls_prep_cleanup_remote || true
  fi

  return "${exit_code}"
}

remote_alpha_stage_es_config_tls_prep_main() {
  local -a helper_paths
  local git_commit
  local check_only_status=0

  remote_alpha_stage_es_config_tls_prep_defaults
  remote_alpha_stage_es_config_tls_prep_parse_args "$@" || return $?
  if [[ "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_SHOW_HELP}" == "true" ]]; then
    return 0
  fi
  remote_alpha_stage_es_config_tls_prep_finalize_paths

  remote_alpha_stage_es_config_tls_prep_require_command python3 || return 1
  remote_alpha_stage_es_config_tls_prep_require_command "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_SSH_BIN}" || return 1
  remote_alpha_stage_es_config_tls_prep_require_command "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_SCP_BIN}" || return 1

  helper_paths=()
  while IFS= read -r helper_path; do
    helper_paths+=("${helper_path}")
  done < <(remote_alpha_stage_es_config_tls_prep_helper_paths)

  REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_UPLOAD_ROOT="/tmp/execution-substrate-remote-alpha-helper-upload-${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_RUN_ID}"
  REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_STAGING_ROOT="${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_STAGE_ROOT}/${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_RUN_ID}"
  REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_STAGED_WRAPPER_PATH="${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_STAGING_ROOT}/scripts/remote_alpha_prepare_es_config_tls.sh"
  REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_STAGED_INTERNAL_PATH="${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_STAGING_ROOT}/scripts/internal/remote_alpha_prepare_es_config_tls.sh"

  remote_alpha_stage_es_config_tls_prep_ensure_parent_dir "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_CHECK_OUTPUT_PATH}"
  remote_alpha_stage_es_config_tls_prep_ensure_parent_dir "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_PROVENANCE_OUTPUT_PATH}"
  if [[ "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_MODE}" == "apply" ]]; then
    remote_alpha_stage_es_config_tls_prep_ensure_parent_dir "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_APPLY_STDOUT_OUTPUT_PATH}"
    remote_alpha_stage_es_config_tls_prep_ensure_parent_dir "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_APPLY_SUMMARY_OUTPUT_PATH}"
  fi

  REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_LOCAL_UPLOAD_DIR="$(mktemp -d)"
  REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_LOCAL_FILE_META_PATH="$(mktemp)"
  REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_STAGE_STAT_PATH="$(mktemp)"
  REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_META_PATH="$(mktemp)"
  trap 'remote_alpha_stage_es_config_tls_prep_cleanup_on_exit' EXIT

  remote_alpha_stage_es_config_tls_prep_make_local_upload_tree "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_LOCAL_UPLOAD_DIR}"

  remote_alpha_stage_es_config_tls_prep_local_file_meta "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_LOCAL_FILE_META_PATH}" "${helper_paths[@]}"

  remote_alpha_stage_es_config_tls_prep_remote_prepare_upload_root || return 1
  remote_alpha_stage_es_config_tls_prep_scp -r "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_LOCAL_UPLOAD_DIR}/scripts" "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_SSH_TARGET}:${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_UPLOAD_ROOT}/" || return 1
  remote_alpha_stage_es_config_tls_prep_remote_install_staged_tree || return 1
  remote_alpha_stage_es_config_tls_prep_remote_stage_stat "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_STAGE_STAT_PATH}" || return 1
  remote_alpha_stage_es_config_tls_prep_validate_stage_stat "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_STAGE_STAT_PATH}" "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_META_PATH}" || return 1

  git_commit="$(remote_alpha_stage_es_config_tls_prep_git_commit)"
  remote_alpha_stage_es_config_tls_prep_write_provenance "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_LOCAL_FILE_META_PATH}" "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_META_PATH}" "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_PROVENANCE_OUTPUT_PATH}" "${git_commit}" || return 1

  if remote_alpha_stage_es_config_tls_prep_run_remote_check_only "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_CHECK_OUTPUT_PATH}"; then
    check_only_status=0
  else
    check_only_status=$?
  fi

  if [[ ! -s "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_CHECK_OUTPUT_PATH}" ]]; then
    echo "remote check-only did not produce JSON output" >&2
    return 1
  fi

  remote_alpha_stage_es_config_tls_prep_validate_check_only_report "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_CHECK_OUTPUT_PATH}" || return 1

  if [[ "${check_only_status}" -ne 0 ]]; then
    return "${check_only_status}"
  fi

  if [[ "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_MODE}" != "apply" ]]; then
    printf '%s\n' "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_CHECK_OUTPUT_PATH}"
    return 0
  fi

  remote_alpha_stage_es_config_tls_prep_run_remote_apply "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_APPLY_STDOUT_OUTPUT_PATH}" || {
    if remote_alpha_stage_es_config_tls_prep_remote_path_exists "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_SUMMARY_PATH}"; then
      remote_alpha_stage_es_config_tls_prep_fetch_remote_file "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_SUMMARY_PATH}" "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_APPLY_SUMMARY_OUTPUT_PATH}" || true
    fi
    return 1
  }

  remote_alpha_stage_es_config_tls_prep_remote_path_exists "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_SUMMARY_PATH}" || {
    echo "remote apply did not leave the expected summary at ${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_SUMMARY_PATH}" >&2
    return 1
  }
  remote_alpha_stage_es_config_tls_prep_fetch_remote_file "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_REMOTE_SUMMARY_PATH}" "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_APPLY_SUMMARY_OUTPUT_PATH}" || return 1

  printf '%s\n' "${REMOTE_ALPHA_STAGE_ES_CONFIG_TLS_PREP_APPLY_SUMMARY_OUTPUT_PATH}"
}
