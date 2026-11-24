#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${REPO_ROOT:-}" ]]; then
  REMOTE_ALPHA_DEPLOY_ES_BINARIES_HELPER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  REPO_ROOT="$(cd "${REMOTE_ALPHA_DEPLOY_ES_BINARIES_HELPER_DIR}/../.." && pwd)"
fi

remote_alpha_deploy_es_binaries_summary_schema_version="execution-substrate.remote-alpha.es-binary-deployment-summary.v1"
remote_alpha_deploy_es_binaries_stage_schema_version="execution-substrate.remote-alpha.es-binary-deployment-stage-provenance.v1"
remote_alpha_deploy_es_binaries_remote_stage_root_default="/var/tmp/execution-substrate-remote-alpha/helper-staging"
remote_alpha_deploy_es_binaries_remote_summary_path_default="/var/tmp/execution-substrate-remote-alpha/es-binary-deployment-summary.json"
remote_alpha_deploy_es_binaries_backup_root_dir_default="/var/tmp/execution-substrate-remote-alpha"
remote_alpha_deploy_es_binaries_default_output_dir="${REPO_ROOT}/.out/remote-alpha-m75q"
remote_alpha_deploy_es_binaries_required_go_version="go1.26.5"

REMOTE_ALPHA_DEPLOY_ES_BINARIES_KEEP_STAGING_ON_FAILURE="false"
REMOTE_ALPHA_DEPLOY_ES_BINARIES_SHOW_HELP="false"
REMOTE_ALPHA_DEPLOY_ES_BINARIES_STAGING_OCCURRED="false"
REMOTE_ALPHA_DEPLOY_ES_BINARIES_CHECKER_RAN="false"
REMOTE_ALPHA_DEPLOY_ES_BINARIES_APPLY_RAN="false"
REMOTE_ALPHA_DEPLOY_ES_BINARIES_TRANSIENT_STAGING_REMOVED="false"
REMOTE_ALPHA_DEPLOY_ES_BINARIES_STAGING_RETAINED_FOR_DIAGNOSTICS="false"
REMOTE_ALPHA_DEPLOY_ES_BINARIES_REMOTE_UPLOAD_PREPARED="false"
REMOTE_ALPHA_DEPLOY_ES_BINARIES_REMOTE_CLEANUP_COMPLETED="false"
REMOTE_ALPHA_DEPLOY_ES_BINARIES_CHECKER_EXIT_CODE=""
REMOTE_ALPHA_DEPLOY_ES_BINARIES_APPLY_EXIT_CODE=""
REMOTE_ALPHA_DEPLOY_ES_BINARIES_SUDO_UNAVAILABLE="false"
REMOTE_ALPHA_DEPLOY_ES_BINARIES_WRAPPER_TOOLING_ERROR="false"
REMOTE_ALPHA_DEPLOY_ES_BINARIES_FAILURE_CLASSIFICATION=""
REMOTE_ALPHA_DEPLOY_ES_BINARIES_BLOCKER_DETAIL=""

REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_LOCAL_FILE_META_PATH=""
REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_STAGE_STAT_META_PATH=""
REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_CHECK_VALIDATION_META_PATH=""
REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_GIT_COMMIT=""
REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_UPLOAD_ROOT=""
REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_ARTIFACT_ROOT=""
REMOTE_ALPHA_DEPLOY_ES_BINARIES_STAGE_REMOTE_STAGING_ROOT=""
REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_STAGED_WRAPPER_PATH=""
REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_STAGED_INTERNAL_PATH=""
REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_STAGE_STAT_ARTIFACT_PATH=""
REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_CHECK_OUTPUT_ARTIFACT_PATH=""

# Copy of remote_alpha_prepare_output_dir from scripts/internal/remote_alpha_output_dir.sh,
# which explains it; TestRemoteAlphaOutputDirCopiesMatch keeps the two identical.
remote_alpha_prepare_output_dir() {
  python3 -I - "$1" <<'REMOTE_ALPHA_OUTPUT_DIR_PY'
import os
import stat
import sys

if not sys.argv[1]:
    sys.exit("remote alpha output folder: no folder given")
if ".." in sys.argv[1].split("/"):
    sys.exit(f"remote alpha output folder: {sys.argv[1]} has a '..' component; refusing to check a path that is not canonical")
# The path is checked as given, never normalized: dropping "link/.." would
# check another folder than the one a later write through the link reaches.
parts = [part for part in os.path.join(os.getcwd(), sys.argv[1]).split("/") if part not in ("", ".")]
trusted = {0, os.geteuid()}
if os.environ.get("SUDO_UID", "").isdigit():
    trusted.add(int(os.environ["SUDO_UID"]))
# O_PATH reads a folder's owner and mode without read permission on it, so a
# folder that root keeps private still passes and sudo can hand it over.
flags = getattr(os, "O_PATH", os.O_RDONLY) | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
shown = "/"
fd = os.open("/", flags)
try:
    for index in range(len(parts) + 1):
        info = os.fstat(fd)
        last = index == len(parts)
        if info.st_uid not in trusted:
            sys.exit(
                f"remote alpha output folder: {shown} belongs to uid {info.st_uid}, not to root, "
                "the user running this step or the user who ran sudo; refusing to write under it"
            )
        if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH) and (
            last or info.st_uid != 0 or not info.st_mode & stat.S_ISVTX
        ):
            sys.exit(f"remote alpha output folder: {shown} can be written by its group or others; refusing to write under it")
        if last:
            break
        shown = "/" + "/".join(parts[: index + 1])
        try:
            next_fd = os.open(parts[index], flags, dir_fd=fd)
        except FileNotFoundError:
            try:
                os.mkdir(parts[index], 0o755, dir_fd=fd)
            except FileExistsError:
                pass
            next_fd = os.open(parts[index], flags, dir_fd=fd)
        os.close(fd)
        fd = next_fd
except OSError as exc:
    sys.exit(f"remote alpha output folder: {shown} is not a directory or is a symbolic link ({exc.strerror})")
finally:
    os.close(fd)
REMOTE_ALPHA_OUTPUT_DIR_PY
}

remote_alpha_deploy_es_binaries_init_expected_slice_inputs() {
  remote_alpha_deploy_es_binaries_expected_service_name="${remote_alpha_deploy_es_binaries_expected_service_name:-es}"
  remote_alpha_deploy_es_binaries_expected_binary_path="${remote_alpha_deploy_es_binaries_expected_binary_path:-/usr/local/lib/execution-substrate/bin/es}"
  remote_alpha_deploy_es_binaries_expected_runtime_support_path="${remote_alpha_deploy_es_binaries_expected_runtime_support_path:-/usr/local/bin/es-runtime-support}"
  remote_alpha_deploy_es_binaries_expected_config_path="${remote_alpha_deploy_es_binaries_expected_config_path:-/etc/execution-substrate/es.json}"
  remote_alpha_deploy_es_binaries_expected_healthcheck_env_path="${remote_alpha_deploy_es_binaries_expected_healthcheck_env_path:-/etc/execution-substrate/healthcheck.env}"
  remote_alpha_deploy_es_binaries_expected_service_unit_path="${remote_alpha_deploy_es_binaries_expected_service_unit_path:-/etc/systemd/system/es.service}"
}

remote_alpha_deploy_es_binaries_defaults() {
  remote_alpha_deploy_es_binaries_init_expected_slice_inputs
  REMOTE_ALPHA_OPERATION_MODE="check_only"
  REMOTE_ALPHA_SERVICE_NAME="${remote_alpha_deploy_es_binaries_expected_service_name}"
  REMOTE_ALPHA_BINARY_PATH="${remote_alpha_deploy_es_binaries_expected_binary_path}"
  REMOTE_ALPHA_RUNTIME_SUPPORT_PATH="${remote_alpha_deploy_es_binaries_expected_runtime_support_path}"
  REMOTE_ALPHA_CONFIG_PATH="${remote_alpha_deploy_es_binaries_expected_config_path}"
  REMOTE_ALPHA_HEALTHCHECK_ENV_PATH="${remote_alpha_deploy_es_binaries_expected_healthcheck_env_path}"
  REMOTE_ALPHA_SERVICE_UNIT_PATH="${remote_alpha_deploy_es_binaries_expected_service_unit_path}"
  REMOTE_ALPHA_SUMMARY_PATH="${REMOTE_ALPHA_SUMMARY_PATH:-${remote_alpha_deploy_es_binaries_remote_summary_path_default}}"
  REMOTE_ALPHA_SUMMARY_DIR="$(dirname "${REMOTE_ALPHA_SUMMARY_PATH}")"
  remote_alpha_deploy_es_binaries_backup_root_dir="${REMOTE_ALPHA_TEST_BACKUP_ROOT:-${remote_alpha_deploy_es_binaries_backup_root_dir_default}}"
}

remote_alpha_deploy_es_binaries_usage() {
  cat <<'EOF'
Usage:
  scripts/remote_alpha_deploy_es_binaries.sh --ssh-target <user@host>
  scripts/remote_alpha_deploy_es_binaries.sh --ssh-target <user@host> --apply
  sudo scripts/remote_alpha_deploy_es_binaries.sh
  sudo scripts/remote_alpha_deploy_es_binaries.sh --apply

Repo-side staged wrapper flags:
  --ssh-target <user@host>
  --check-only
  --dry-run
  --apply
  --run-id <timestamp-or-id>
  --output-dir </path/to/output-dir>
  --check-output </path/to/es-binary-deployment-check-only.json>
  --apply-summary-output </path/to/es-binary-deployment-apply-summary.json>
  --helper-staging-record-output </path/to/es-binary-deployment-helper-staging-record.json>
  --provenance-output </path/to/es-binary-deployment-helper-staging-record.json>
  --remote-summary-path </remote/path/to/es-binary-deployment-summary.json>
  --interactive-sudo
  --keep-staging-on-failure

Host-local helper flags:
  --check-only
  --dry-run
  --apply
  --summary-path </path/to/es-binary-deployment-summary.json>
  --help

Default behavior is non-mutating check-only for the sealed ES binary parity
deployment slice only.
EOF
}

remote_alpha_deploy_es_binaries_reject_slice_override_env() {
  local name=$1
  local expected=$2
  local actual=""

  actual="$(printenv "${name}" 2>/dev/null || true)"
  if [[ -z "${actual}" ]]; then
    return 0
  fi
  if [[ "${actual}" != "${expected}" ]]; then
    printf 'remote alpha ES binary deployment does not accept %s override for this sealed binary-parity slice; expected repo-owned value %q (got %q)\n' "${name}" "${expected}" "${actual}" >&2
    return 1
  fi
  return 0
}

remote_alpha_deploy_es_binaries_require_pinned_slice_inputs() {
  remote_alpha_deploy_es_binaries_init_expected_slice_inputs
  remote_alpha_deploy_es_binaries_reject_slice_override_env "REMOTE_ALPHA_SERVICE_NAME" "${remote_alpha_deploy_es_binaries_expected_service_name}" || return 1
  remote_alpha_deploy_es_binaries_reject_slice_override_env "REMOTE_ALPHA_BINARY_PATH" "${remote_alpha_deploy_es_binaries_expected_binary_path}" || return 1
  remote_alpha_deploy_es_binaries_reject_slice_override_env "REMOTE_ALPHA_RUNTIME_SUPPORT_PATH" "${remote_alpha_deploy_es_binaries_expected_runtime_support_path}" || return 1
  remote_alpha_deploy_es_binaries_reject_slice_override_env "REMOTE_ALPHA_CONFIG_PATH" "${remote_alpha_deploy_es_binaries_expected_config_path}" || return 1
  remote_alpha_deploy_es_binaries_reject_slice_override_env "REMOTE_ALPHA_HEALTHCHECK_ENV_PATH" "${remote_alpha_deploy_es_binaries_expected_healthcheck_env_path}" || return 1
  remote_alpha_deploy_es_binaries_reject_slice_override_env "REMOTE_ALPHA_SERVICE_UNIT_PATH" "${remote_alpha_deploy_es_binaries_expected_service_unit_path}" || return 1
}

remote_alpha_deploy_es_binaries_has_ssh_target() {
  local arg
  for arg in "$@"; do
    if [[ "${arg}" == "--ssh-target" ]]; then
      return 0
    fi
  done
  return 1
}

remote_alpha_deploy_es_binaries_require_root() {
  if [[ "$(id -u)" != "0" ]]; then
    echo "remote alpha ES binary deployment helper must run as root; use sudo scripts/remote_alpha_deploy_es_binaries.sh" >&2
    return 1
  fi
}

remote_alpha_deploy_es_binaries_require_command() {
  local name=$1
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "${name} is required" >&2
    return 1
  fi
}

remote_alpha_deploy_es_binaries_require_supported_go_toolchain() {
  local observed_version

  remote_alpha_deploy_es_binaries_require_command go || return 1
  observed_version="$(env GOTOOLCHAIN=local go version 2>/dev/null | awk '{print $3}' || true)"
  if [[ "${observed_version}" != "${remote_alpha_deploy_es_binaries_required_go_version}" ]]; then
    echo "unsupported Go toolchain: expected ${remote_alpha_deploy_es_binaries_required_go_version}, observed ${observed_version:-unavailable}" >&2
    return 1
  fi
}

remote_alpha_deploy_es_binaries_json_field() {
  local json_path=$1
  local dotted_path=$2

  python3 -I - "${json_path}" "${dotted_path}" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
value = payload
for part in sys.argv[2].split("."):
    if isinstance(value, dict):
        value = value.get(part)
    else:
        value = None
        break
if value is None:
    sys.exit(1)
if isinstance(value, bool):
    print("true" if value else "false")
elif isinstance(value, (dict, list)):
    print(json.dumps(value, sort_keys=True))
else:
    print(value)
PY
}

remote_alpha_deploy_es_binaries_parse_host_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --service-name)
        echo "remote alpha ES binary deployment does not accept --service-name for this sealed binary-parity slice" >&2
        return 2
        ;;
      --binary-path)
        echo "remote alpha ES binary deployment does not accept --binary-path for this sealed binary-parity slice" >&2
        return 2
        ;;
      --runtime-support-path)
        echo "remote alpha ES binary deployment does not accept --runtime-support-path for this sealed binary-parity slice" >&2
        return 2
        ;;
      --config-path)
        echo "remote alpha ES binary deployment does not accept --config-path for this sealed binary-parity slice" >&2
        return 2
        ;;
      --healthcheck-env-path)
        echo "remote alpha ES binary deployment does not accept --healthcheck-env-path for this sealed binary-parity slice" >&2
        return 2
        ;;
      --service-unit-path)
        echo "remote alpha ES binary deployment does not accept --service-unit-path for this sealed binary-parity slice" >&2
        return 2
        ;;
      --check-only|--dry-run)
        REMOTE_ALPHA_OPERATION_MODE="check_only"
        shift
        ;;
      --apply)
        REMOTE_ALPHA_OPERATION_MODE="apply"
        shift
        ;;
      --summary-path)
        REMOTE_ALPHA_SUMMARY_PATH="$2"
        REMOTE_ALPHA_SUMMARY_DIR="$(dirname "${REMOTE_ALPHA_SUMMARY_PATH}")"
        shift 2
        ;;
      --help|-h)
        REMOTE_ALPHA_DEPLOY_ES_BINARIES_SHOW_HELP="true"
        remote_alpha_deploy_es_binaries_usage
        return 1
        ;;
      *)
        echo "unknown argument: $1" >&2
        remote_alpha_deploy_es_binaries_usage >&2
        return 2
        ;;
    esac
  done
}

remote_alpha_deploy_es_binaries_python() {
  python3 -I - \
    "${remote_alpha_deploy_es_binaries_summary_schema_version}" \
    "${REMOTE_ALPHA_OPERATION_MODE}" \
    "${REMOTE_ALPHA_SUMMARY_PATH}" \
    "${REMOTE_ALPHA_SERVICE_NAME}" \
    "${REMOTE_ALPHA_BINARY_PATH}" \
    "${REMOTE_ALPHA_RUNTIME_SUPPORT_PATH}" \
    "${REMOTE_ALPHA_CONFIG_PATH}" \
    "${REMOTE_ALPHA_HEALTHCHECK_ENV_PATH}" \
    "${REMOTE_ALPHA_SERVICE_UNIT_PATH}" \
    "${remote_alpha_deploy_es_binaries_backup_root_dir}" \
    "${REPO_ROOT}" <<'PY'
import hashlib
import json
import os
import pathlib
import shutil
import stat as statmod
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

SCHEMA_VERSION = sys.argv[1]
MODE = sys.argv[2]
SUMMARY_PATH = sys.argv[3]
SERVICE_NAME = sys.argv[4]
BINARY_PATH = sys.argv[5]
RUNTIME_SUPPORT_PATH = sys.argv[6]
CONFIG_PATH = sys.argv[7]
HEALTHCHECK_ENV_PATH = sys.argv[8]
SERVICE_UNIT_PATH = sys.argv[9]
BACKUP_ROOT_DIR = sys.argv[10]
REPO_ROOT = pathlib.Path(sys.argv[11])
CURRENT_SUPPORTED_SERVICE_IDENTITY = ("es", "es")
SUPPORTED_GO_VERSION = "go1.26.5"


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def make_status(classification, summary, **kwargs):
    payload = {"classification": classification, "summary": summary}
    payload.update(kwargs)
    return payload


def run_command(args, env=None, cwd=None):
    return subprocess.run(args, capture_output=True, text=True, env=env, cwd=cwd)


def unsupported_go_toolchain_status():
    proc = run_command(["env", "GOTOOLCHAIN=local", "go", "version"])
    observed = ""
    if proc.stdout:
        parts = proc.stdout.strip().split()
        if len(parts) >= 3:
            observed = parts[2]
    if proc.returncode != 0 or observed != SUPPORTED_GO_VERSION:
        return make_status(
            "blocker",
            f"unsupported Go toolchain: expected {SUPPORTED_GO_VERSION}, observed {observed or 'unavailable'}",
        )
    return None


def mode_string(mode_bits):
    return format(mode_bits & 0o7777, "04o")


def sha256_file(path):
    data = pathlib.Path(path).read_bytes()
    return hashlib.sha256(data).hexdigest()


def stat_path(path):
    rendered = os.fspath(path)
    try:
        info = os.lstat(rendered)
    except FileNotFoundError:
        return {
            "path": rendered,
            "exists": False,
            "uid": None,
            "gid": None,
            "owner": "",
            "group": "",
            "mode": "",
            "mode_bits": 0,
            "size": 0,
            "file_type": "",
            "error": "not found",
        }
    mode_bits = statmod.S_IMODE(info.st_mode)
    if statmod.S_ISDIR(info.st_mode):
        file_type = "directory"
    elif statmod.S_ISREG(info.st_mode):
        file_type = "regular file"
    elif statmod.S_ISLNK(info.st_mode):
        file_type = "symbolic link"
    else:
        file_type = "other"
    owner = ""
    group = ""
    try:
        import pwd
        owner = pwd.getpwuid(info.st_uid).pw_name
    except Exception:  # noqa: BLE001
        owner = str(info.st_uid)
    try:
        import grp
        group = grp.getgrgid(info.st_gid).gr_name
    except Exception:  # noqa: BLE001
        group = str(info.st_gid)
    return {
        "path": rendered,
        "exists": True,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "owner": owner,
        "group": group,
        "mode": mode_string(mode_bits),
        "mode_bits": mode_bits,
        "size": info.st_size,
        "file_type": file_type,
    }


def service_identity_is_accepted(effective_user, effective_group):
    return (effective_user, effective_group) == CURRENT_SUPPORTED_SERVICE_IDENTITY


def parse_systemctl_show():
    unit_name = SERVICE_NAME if SERVICE_NAME.endswith(".service") else SERVICE_NAME + ".service"
    proc = run_command(
        [
            "systemctl",
            "show",
            unit_name,
            "--property=ExecStart,User,Group,ActiveState,SubState,FragmentPath,DropInPaths",
            "--no-pager",
        ]
    )
    fields = {
        "exec_start": "",
        "user": "",
        "group": "",
        "active_state": "",
        "sub_state": "",
        "fragment_path": "",
        "drop_in_paths": "",
        "effective_user": "root(default)",
        "effective_group": "root(default)",
    }
    if proc.returncode != 0:
        return make_status(
            "blocker",
            f"failed to inspect {unit_name} through systemctl show: {proc.stderr.strip() or proc.stdout.strip()}",
            **fields,
        )
    for raw in proc.stdout.splitlines():
        key, _, value = raw.partition("=")
        value = value.strip()
        if key == "ExecStart":
            fields["exec_start"] = value
        elif key == "User":
            fields["user"] = value
            fields["effective_user"] = value or "root(default)"
        elif key == "Group":
            fields["group"] = value
            fields["effective_group"] = value or "root(default)"
        elif key == "ActiveState":
            fields["active_state"] = value
        elif key == "SubState":
            fields["sub_state"] = value
        elif key == "FragmentPath":
            fields["fragment_path"] = value
        elif key == "DropInPaths":
            fields["drop_in_paths"] = value
    blockers = []
    if fields["fragment_path"] and fields["fragment_path"] != SERVICE_UNIT_PATH:
        blockers.append(f"service fragment path mismatch: {fields['fragment_path']}")
    if BINARY_PATH not in fields["exec_start"] or CONFIG_PATH not in fields["exec_start"]:
        blockers.append("service ExecStart does not match the pinned binary/config path")
    if not service_identity_is_accepted(fields["effective_user"], fields["effective_group"]):
        blockers.append(
            "service identity is not the current supported binary-deployment posture: "
            f"expected es:es, got {fields['effective_user']}:{fields['effective_group']}"
        )
    if fields["active_state"] != "active" or fields["sub_state"] != "running":
        blockers.append(
            f"service is not active/running: {fields['active_state'] or 'unknown'}/{fields['sub_state'] or 'unknown'}"
        )
    if blockers:
        return make_status("blocker", blockers[0], blockers=blockers, **fields)
    return make_status(
        "pass",
        "es.service matches the pinned binary slice posture and preserves the current supported es:es service identity",
        blockers=[],
        **fields,
    )


def load_healthcheck_env():
    values = {}
    try:
        lines = pathlib.Path(HEALTHCHECK_ENV_PATH).read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return make_status("blocker", "healthcheck env file does not exist", path=HEALTHCHECK_ENV_PATH, values={})
    except Exception as exc:  # noqa: BLE001
        return make_status("blocker", f"failed to read healthcheck env file: {exc}", path=HEALTHCHECK_ENV_PATH, values={})
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    missing = [key for key in ("CA_CERT", "OPERATOR_CERT", "OPERATOR_KEY") if not values.get(key)]
    if missing:
        return make_status(
            "blocker",
            "healthcheck env is missing required validation inputs: " + ", ".join(missing),
            path=HEALTHCHECK_ENV_PATH,
            values=values,
        )
    return make_status("pass", "healthcheck env contains the required validation inputs", path=HEALTHCHECK_ENV_PATH, values=values)


def load_runtime_config():
    try:
        payload = json.loads(pathlib.Path(CONFIG_PATH).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return make_status("blocker", "ES config file does not exist", path=CONFIG_PATH, runtime={})
    except Exception as exc:  # noqa: BLE001
        return make_status("blocker", f"failed to read ES config: {exc}", path=CONFIG_PATH, runtime={})

    http = payload.get("http") or {}
    bind_address = str(http.get("bind_address") or "").strip()
    try:
        port = int(http.get("port") or 0)
    except Exception:  # noqa: BLE001
        port = 0
    runtime = {
        "bind_address": bind_address,
        "port": port,
        "health_url": f"https://{bind_address}:{port}/health" if bind_address and port > 0 else "",
        "contract_url": f"https://{bind_address}:{port}/v1/executions:contract" if bind_address and port > 0 else "",
    }
    if not bind_address or port <= 0:
        return make_status("blocker", "ES config is missing http.bind_address or http.port", path=CONFIG_PATH, runtime=runtime)
    return make_status("pass", "ES config contains the runtime probe endpoints for this slice", path=CONFIG_PATH, runtime=runtime)


def curl_probe(url, env_values):
    args = [
        "curl",
        "-fsS",
        "--cacert",
        env_values["CA_CERT"],
        "--cert",
        env_values["OPERATOR_CERT"],
        "--key",
        env_values["OPERATOR_KEY"],
        url,
    ]
    proc = run_command(args)
    if proc.returncode != 0:
        return make_status("blocker", f"curl probe failed for {url}: {proc.stderr.strip() or proc.stdout.strip()}", url=url)
    return make_status("pass", f"curl probe passed for {url}", url=url, response=proc.stdout.strip())


def file_payload_status(path, expected_mode):
    meta = stat_path(path)
    payload = {
        "path": os.fspath(path),
        "exists": meta["exists"],
        "owner": meta["owner"],
        "group": meta["group"],
        "mode": meta["mode"],
        "size": meta["size"],
        "sha256": "",
    }
    if not meta["exists"]:
        return make_status("blocker", f"path does not exist: {path}", **payload)
    if meta["file_type"] != "regular file":
        return make_status("blocker", f"path is not a regular file: {path}", **payload)
    payload["sha256"] = sha256_file(path)
    if meta["mode"] != expected_mode:
        return make_status("warning", f"path mode differs from expected {expected_mode}: {path}", **payload)
    return make_status("pass", f"file metadata captured for {path}", **payload)


def git_commit(repo_root):
    proc = run_command(["git", "-C", os.fspath(repo_root), "rev-parse", "HEAD"])
    if proc.returncode != 0:
        return ""
    return proc.stdout.strip()


def git_status_short(repo_root):
    proc = run_command(["git", "-C", os.fspath(repo_root), "status", "--short"])
    if proc.returncode != 0:
        return []
    return [line.rstrip() for line in proc.stdout.splitlines() if line.strip()]


def compute_source_digest_manifest(repo_root):
    interesting = [
        repo_root / "go.mod",
        repo_root / "go.sum",
        repo_root / "cmd" / "es",
        repo_root / "cmd" / "es-runtime-support",
        repo_root / "es",
        repo_root / "internal",
    ]
    files = []
    for item in interesting:
        if item.is_file():
            files.append(item)
            continue
        if item.is_dir():
            for path in sorted(item.rglob("*")):
                if path.is_file():
                    files.append(path)
    manifest = []
    for path in files:
        manifest.append(
            {
                "path": os.fspath(path.relative_to(repo_root)),
                "sha256": sha256_file(path),
            }
        )
    return manifest


def build_local_payload(repo_root):
    go_status = unsupported_go_toolchain_status()
    if go_status is not None:
        return None, go_status

    tmpdir = pathlib.Path(tempfile.mkdtemp(prefix="es-binary-build-"))
    es_path = tmpdir / "es"
    runtime_path = tmpdir / "es-runtime-support"
    build_commands = [
        ["env", "GOTOOLCHAIN=local", "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "go", "build", "-o", os.fspath(es_path), "./cmd/es"],
        ["env", "GOTOOLCHAIN=local", "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "go", "build", "-o", os.fspath(runtime_path), "./cmd/es-runtime-support"],
    ]
    for command in build_commands:
        proc = run_command(command, cwd=os.fspath(repo_root))
        if proc.returncode != 0:
            return None, make_status(
                "blocker",
                f"failed to build repo-owned linux/amd64 payload through the established build path: {proc.stderr.strip() or proc.stdout.strip()}",
                build_commands=[" ".join(cmd) for cmd in build_commands],
            )
    provenance = {
        "source_kind": "local_build",
        "repo_root": os.fspath(repo_root),
        "git_commit": git_commit(repo_root),
        "git_status_short": git_status_short(repo_root),
        "dirty_worktree": bool(git_status_short(repo_root)),
        "build_commands": [" ".join(cmd) for cmd in build_commands],
        "source_file_digests": compute_source_digest_manifest(repo_root),
    }
    return {
        "es_path": es_path,
        "runtime_path": runtime_path,
        "provenance": provenance,
    }, make_status("pass", "built repo-owned linux/amd64 payload through the established build path")


def load_staged_payload(repo_root):
    payload_dir = repo_root / "payload"
    es_path = payload_dir / "es"
    runtime_path = payload_dir / "es-runtime-support"
    provenance_path = payload_dir / "build-provenance.json"
    if not es_path.exists() or not runtime_path.exists():
        return None, make_status("blocker", "staged payload binaries are missing from the sealed helper payload directory")
    provenance = {}
    if provenance_path.exists():
        try:
            provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            return None, make_status("blocker", f"staged build provenance is malformed: {exc}")
    return {
        "es_path": es_path,
        "runtime_path": runtime_path,
        "provenance": provenance,
    }, make_status("pass", "loaded staged linux/amd64 payload binaries")


def discover_payload():
    staged_payload, staged_status = load_staged_payload(REPO_ROOT)
    if staged_payload is not None:
        return staged_payload, staged_status
    if (REPO_ROOT / "cmd" / "es").exists() and (REPO_ROOT / "cmd" / "es-runtime-support").exists():
        return build_local_payload(REPO_ROOT)
    return None, staged_status


def compute_check_summary():
    payload, payload_status = discover_payload()
    service_status = parse_systemctl_show()
    runtime_config_status = load_runtime_config()
    health_env_status = load_healthcheck_env()
    binary_status = file_payload_status(BINARY_PATH, "0755")
    runtime_status = file_payload_status(RUNTIME_SUPPORT_PATH, "0755")
    local_binary_status = None
    local_runtime_status = None
    deployment_needed = False
    warnings = []
    blockers = []
    build_provenance = {}

    if payload is None:
        blockers.append({"scope": "local_payload", "summary": payload_status["summary"]})
        local_binary_status = make_status("blocker", "local es payload is unavailable", path="")
        local_runtime_status = make_status("blocker", "local runtime-support payload is unavailable", path="")
    else:
        build_provenance = payload.get("provenance", {})
        local_binary_status = file_payload_status(payload["es_path"], "0755")
        local_runtime_status = file_payload_status(payload["runtime_path"], "0755")
        if local_binary_status["classification"] == "blocker":
            blockers.append({"scope": "local_es_payload", "summary": local_binary_status["summary"]})
        if local_runtime_status["classification"] == "blocker":
            blockers.append({"scope": "local_runtime_support_payload", "summary": local_runtime_status["summary"]})

    for scope, status in [
        ("service_posture", service_status),
        ("runtime_config", runtime_config_status),
        ("healthcheck_env", health_env_status),
        ("live_es_binary", binary_status),
        ("live_runtime_support_binary", runtime_status),
    ]:
        if status["classification"] == "blocker":
            blockers.append({"scope": scope, "summary": status["summary"]})

    if payload is not None and binary_status["classification"] != "blocker" and runtime_status["classification"] != "blocker":
        deployment_needed = (
            local_binary_status.get("sha256") != binary_status.get("sha256")
            or local_runtime_status.get("sha256") != runtime_status.get("sha256")
        )
        if deployment_needed:
            warnings.append(
                {
                    "scope": "deployment_needed",
                    "summary": "live ES/runtime-helper hashes differ from the current repo-owned linux/amd64 payload and binary deployment is needed",
                }
            )

    dirty_worktree = bool(build_provenance.get("dirty_worktree"))
    if dirty_worktree:
        warnings.append(
            {
                "scope": "dirty_worktree",
                "summary": "local build provenance shows a dirty-worktree snapshot was used to produce the candidate payload",
            }
        )

    plan = {
        "deployment_needed": deployment_needed,
        "apply_ready": not blockers,
        "restart_required_in_apply_mode": True,
        "service_identity_matches_current_supported_posture": service_status.get("effective_user") == "es"
        and service_status.get("effective_group") == "es",
        "target_paths": [BINARY_PATH, RUNTIME_SUPPORT_PATH],
        "backup_parent_dir": BACKUP_ROOT_DIR,
        "blockers": blockers,
        "warnings": warnings,
    }

    overall = "blocker" if blockers else ("warning" if warnings else "pass")
    summary = {
        "schema_version": SCHEMA_VERSION,
        "mode": {
            "name": "check_only",
            "non_mutating": True,
            "explicit_apply_required": True,
        },
        "proof": {
            "check_only_is_not_proof": True,
            "host_mutation_performed": False,
        },
        "service": {
            "name": SERVICE_NAME,
            "binary_path": BINARY_PATH,
            "runtime_support_path": RUNTIME_SUPPORT_PATH,
            "config_path": CONFIG_PATH,
            "healthcheck_env_path": HEALTHCHECK_ENV_PATH,
            "service_unit_path": SERVICE_UNIT_PATH,
        },
        "build_provenance": build_provenance,
        "local_artifacts": {
            "es": local_binary_status,
            "runtime_support": local_runtime_status,
        },
        "live_targets": {
            "es": binary_status,
            "runtime_support": runtime_status,
            "config": {
                "path": CONFIG_PATH,
                "sha256": sha256_file(CONFIG_PATH) if pathlib.Path(CONFIG_PATH).exists() else "",
            },
        },
        "validation": {
            "es_service_posture": service_status,
            "runtime_config": runtime_config_status,
            "healthcheck_env": health_env_status,
        },
        "plan": plan,
        "blockers": blockers,
        "warnings": warnings,
        "not_claimed": {
            "service_user_change": True,
            "staging_or_results_ownership_change": True,
            "config_or_tls_rewrite": True,
            "governed_proof": True,
            "nomad_task_user_model_change": True,
            "runtime_helper_design_change": True,
            "vault_runtime_handoff_change": True,
        },
        "result": {
            "status": overall,
            "ok": not blockers,
            "non_mutating": True,
        },
        "overall_classification": overall,
    }
    return summary, payload


def write_json(path, payload):
    pathlib.Path(path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def install_binary(source_path, dest_path):
    dest = pathlib.Path(dest_path)
    temp_fd, temp_name = tempfile.mkstemp(prefix=f".{dest.name}.codex-", dir=os.fspath(dest.parent))
    os.close(temp_fd)
    temp_path = pathlib.Path(temp_name)
    shutil.copyfile(os.fspath(source_path), os.fspath(temp_path))
    os.chmod(os.fspath(temp_path), 0o755)
    try:
        os.chown(os.fspath(temp_path), 0, 0)
    except PermissionError:
        if os.geteuid() == 0:
            raise
    os.replace(os.fspath(temp_path), os.fspath(dest))


def create_backup(summary):
    backup_dir = pathlib.Path(BACKUP_ROOT_DIR) / ("es-binary-deployment-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    backup_dir.mkdir(parents=True, exist_ok=False)
    pre_apply = {
        "created_at": utc_now(),
        "service": summary["validation"]["es_service_posture"],
        "live_targets": summary["live_targets"],
        "config_sha256": summary["live_targets"]["config"]["sha256"],
    }
    shutil.copyfile(BINARY_PATH, backup_dir / "es.pre-apply")
    shutil.copyfile(RUNTIME_SUPPORT_PATH, backup_dir / "es-runtime-support.pre-apply")
    write_json(backup_dir / "pre-apply-snapshot.json", pre_apply)
    return {
        "status": "created",
        "path": os.fspath(backup_dir),
        "pre_apply_snapshot": os.fspath(backup_dir / "pre-apply-snapshot.json"),
        "pre_apply_es_binary_copy": os.fspath(backup_dir / "es.pre-apply"),
        "pre_apply_runtime_support_copy": os.fspath(backup_dir / "es-runtime-support.pre-apply"),
        "rollback_notes": [
            f"Install {backup_dir / 'es.pre-apply'} back to {BINARY_PATH} as root:root mode 0755.",
            f"Install {backup_dir / 'es-runtime-support.pre-apply'} back to {RUNTIME_SUPPORT_PATH} as root:root mode 0755.",
            f"Restart {SERVICE_NAME if SERVICE_NAME.endswith('.service') else SERVICE_NAME + '.service'} once after restoring the old binaries.",
        ],
    }


def run_apply():
    check_summary, payload = compute_check_summary()
    applied = False
    backup = {"status": "not_created", "path": "", "rollback_notes": []}

    summary = json.loads(json.dumps(check_summary))
    summary["mode"] = {
        "name": "apply",
        "non_mutating": False,
        "explicit_apply_required": True,
    }
    summary["proof"] = {
        "check_only_is_not_proof": False,
        "host_mutation_performed": False,
    }

    if check_summary["blockers"]:
        summary["result"] = {
            "status": "blocker",
            "ok": False,
            "non_mutating": True,
        }
        summary["overall_classification"] = "blocker"
        summary["backup"] = backup
        return summary

    if not check_summary["plan"]["deployment_needed"]:
        summary["result"] = {
            "status": "pass",
            "ok": True,
            "non_mutating": True,
        }
        summary["overall_classification"] = "pass"
        summary["backup"] = backup
        summary["post_apply_validation"] = {
            "es_service_posture": check_summary["validation"]["es_service_posture"],
            "health": make_status("not_observed", "service restart was skipped because deployment was not needed"),
            "contract": make_status("not_observed", "service restart was skipped because deployment was not needed"),
        }
        return summary

    backup = create_backup(check_summary)
    install_binary(payload["es_path"], BINARY_PATH)
    install_binary(payload["runtime_path"], RUNTIME_SUPPORT_PATH)
    applied = True
    unit_name = SERVICE_NAME if SERVICE_NAME.endswith(".service") else SERVICE_NAME + ".service"
    restart_proc = run_command(["systemctl", "restart", unit_name])
    if restart_proc.returncode != 0:
        summary["blockers"] = summary.get("blockers", []) + [
            {"scope": "service_restart", "summary": restart_proc.stderr.strip() or restart_proc.stdout.strip() or "systemctl restart failed"}
        ]
        summary["backup"] = backup
        summary["proof"]["host_mutation_performed"] = True
        summary["result"] = {"status": "blocker", "ok": False, "non_mutating": False}
        summary["overall_classification"] = "blocker"
        return summary

    service_status = parse_systemctl_show()
    runtime_config_status = load_runtime_config()
    health_env = load_healthcheck_env()
    health_status = make_status("not_observed", "health probe skipped because healthcheck env is invalid")
    contract_status = make_status("not_observed", "contract probe skipped because healthcheck env is invalid")
    if health_env["classification"] == "pass" and runtime_config_status["classification"] == "pass":
        health_status = curl_probe(runtime_config_status["runtime"]["health_url"], health_env["values"])
        contract_status = curl_probe(runtime_config_status["runtime"]["contract_url"], health_env["values"])

    live_es = file_payload_status(BINARY_PATH, "0755")
    live_runtime = file_payload_status(RUNTIME_SUPPORT_PATH, "0755")

    post_blockers = []
    for scope, status in [
        ("service_posture", service_status),
        ("health", health_status),
        ("contract", contract_status),
        ("live_es_binary", live_es),
        ("live_runtime_support_binary", live_runtime),
    ]:
        if status["classification"] == "blocker":
            post_blockers.append({"scope": scope, "summary": status["summary"]})
    if live_es.get("sha256") != check_summary["local_artifacts"]["es"].get("sha256"):
        post_blockers.append({"scope": "live_es_binary", "summary": "live es binary hash does not match the deployed payload"})
    if live_runtime.get("sha256") != check_summary["local_artifacts"]["runtime_support"].get("sha256"):
        post_blockers.append({"scope": "live_runtime_support_binary", "summary": "live runtime-support hash does not match the deployed payload"})

    summary["proof"]["host_mutation_performed"] = applied
    summary["backup"] = backup
    summary["changed_paths"] = [BINARY_PATH, RUNTIME_SUPPORT_PATH]
    summary["live_targets"]["es"] = live_es
    summary["live_targets"]["runtime_support"] = live_runtime
    summary["post_apply_validation"] = {
        "es_service_posture": service_status,
        "runtime_config": runtime_config_status,
        "health": health_status,
        "contract": contract_status,
    }
    summary["blockers"] = post_blockers
    summary["result"] = {
        "status": "blocker" if post_blockers else "pass",
        "ok": not post_blockers,
        "non_mutating": False,
    }
    summary["overall_classification"] = "blocker" if post_blockers else "pass"
    return summary


def main():
    if MODE == "check_only":
        summary, _payload = compute_check_summary()
        print(json.dumps(summary, indent=2, sort_keys=True))
        raise SystemExit(1 if summary["overall_classification"] == "blocker" else 0)
    summary = run_apply()
    pathlib.Path(SUMMARY_PATH).parent.mkdir(parents=True, exist_ok=True)
    write_json(SUMMARY_PATH, summary)
    raise SystemExit(1 if summary["overall_classification"] == "blocker" else 0)


main()
PY
}

remote_alpha_deploy_es_binaries_host_main() {
  remote_alpha_deploy_es_binaries_defaults
  remote_alpha_deploy_es_binaries_require_pinned_slice_inputs || return 1
  remote_alpha_deploy_es_binaries_parse_host_args "$@" || return $?
  if [[ "${REMOTE_ALPHA_DEPLOY_ES_BINARIES_SHOW_HELP}" == "true" ]]; then
    return 0
  fi

  remote_alpha_deploy_es_binaries_require_root || return 1
  remote_alpha_deploy_es_binaries_require_command python3 || return 1
  remote_alpha_prepare_output_dir "$(dirname "${REMOTE_ALPHA_SUMMARY_PATH}")" || return 1
  # Only apply writes backups; check-only must leave the backup root alone.
  if [[ "${REMOTE_ALPHA_OPERATION_MODE}" == "apply" ]]; then
    remote_alpha_prepare_output_dir "${remote_alpha_deploy_es_binaries_backup_root_dir}" || return 1
  fi
  remote_alpha_deploy_es_binaries_python
}

remote_alpha_deploy_es_binaries_stage_defaults() {
  remote_alpha_deploy_es_binaries_init_expected_slice_inputs
  REMOTE_ALPHA_OPERATION_MODE="check_only"
  REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
  REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_OUTPUT_DIR=""
  REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_CHECK_OUTPUT_PATH=""
  REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_APPLY_SUMMARY_OUTPUT_PATH=""
  REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_PROVENANCE_OUTPUT_PATH=""
  REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_STAGE_ROOT="${remote_alpha_deploy_es_binaries_remote_stage_root_default}"
  REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_SUMMARY_PATH="${remote_alpha_deploy_es_binaries_remote_summary_path_default}"
  REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_SSH_BIN="${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_SSH_BIN:-ssh}"
  REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_SCP_BIN="${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_SCP_BIN:-scp}"
  REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_SUDO_MODE="${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_SUDO_MODE:-noninteractive}"
}

remote_alpha_deploy_es_binaries_stage_validate_sudo_mode() {
  case "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_SUDO_MODE}" in
    noninteractive|interactive)
      ;;
    *)
      echo "unsupported sudo mode: ${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_SUDO_MODE}" >&2
      return 1
      ;;
  esac
}

remote_alpha_deploy_es_binaries_stage_parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --ssh-target)
        REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_SSH_TARGET="$2"
        shift 2
        ;;
      --check-only|--dry-run)
        REMOTE_ALPHA_OPERATION_MODE="check_only"
        shift
        ;;
      --apply)
        REMOTE_ALPHA_OPERATION_MODE="apply"
        shift
        ;;
      --run-id)
        REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_RUN_ID="$2"
        shift 2
        ;;
      --output-dir)
        REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_OUTPUT_DIR="$2"
        shift 2
        ;;
      --check-output)
        REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_CHECK_OUTPUT_PATH="$2"
        shift 2
        ;;
      --apply-summary-output)
        REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_APPLY_SUMMARY_OUTPUT_PATH="$2"
        shift 2
        ;;
      --helper-staging-record-output|--provenance-output)
        REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_PROVENANCE_OUTPUT_PATH="$2"
        shift 2
        ;;
      --remote-summary-path)
        REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_SUMMARY_PATH="$2"
        shift 2
        ;;
      --interactive-sudo)
        REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_SUDO_MODE="interactive"
        shift
        ;;
      --keep-staging-on-failure)
        REMOTE_ALPHA_DEPLOY_ES_BINARIES_KEEP_STAGING_ON_FAILURE="true"
        shift
        ;;
      --help|-h)
        REMOTE_ALPHA_DEPLOY_ES_BINARIES_SHOW_HELP="true"
        remote_alpha_deploy_es_binaries_usage
        return 0
        ;;
      *)
        echo "unknown argument: $1" >&2
        remote_alpha_deploy_es_binaries_usage >&2
        return 2
        ;;
    esac
  done

  remote_alpha_deploy_es_binaries_stage_validate_sudo_mode || return 1
  if [[ -z "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_SSH_TARGET:-}" ]]; then
    echo "--ssh-target is required" >&2
    return 2
  fi
}

remote_alpha_deploy_es_binaries_stage_finalize_paths() {
  if [[ -z "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_OUTPUT_DIR}" ]]; then
    REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_OUTPUT_DIR="${remote_alpha_deploy_es_binaries_default_output_dir}"
  fi
  if [[ -z "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_CHECK_OUTPUT_PATH}" ]]; then
    REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_CHECK_OUTPUT_PATH="${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_OUTPUT_DIR}/es-binary-deployment-check-only.json"
  fi
  if [[ -z "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_APPLY_SUMMARY_OUTPUT_PATH}" ]]; then
    REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_APPLY_SUMMARY_OUTPUT_PATH="${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_OUTPUT_DIR}/es-binary-deployment-apply-summary.json"
  fi
  if [[ -z "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_PROVENANCE_OUTPUT_PATH}" ]]; then
    REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_PROVENANCE_OUTPUT_PATH="${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_OUTPUT_DIR}/es-binary-deployment-helper-staging-record.json"
  fi
}

remote_alpha_deploy_es_binaries_stage_ensure_parent_dir() {
  local path=$1
  mkdir -p "$(dirname "${path}")"
}

remote_alpha_deploy_es_binaries_stage_helper_paths() {
  printf '%s\n' \
    "${REPO_ROOT}/scripts/remote_alpha_deploy_es_binaries.sh" \
    "${REPO_ROOT}/scripts/internal/remote_alpha_deploy_es_binaries.sh"
}

remote_alpha_deploy_es_binaries_stage_required_upload_paths() {
  printf '%s\n' \
    "scripts/remote_alpha_deploy_es_binaries.sh" \
    "scripts/internal/remote_alpha_deploy_es_binaries.sh" \
    "payload/es" \
    "payload/es-runtime-support" \
    "payload/build-provenance.json"
}

remote_alpha_deploy_es_binaries_stage_git_commit() {
  if command -v git >/dev/null 2>&1; then
    git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || true
    return 0
  fi
  printf '\n'
}

remote_alpha_deploy_es_binaries_stage_git_status_short() {
  if command -v git >/dev/null 2>&1; then
    git -C "${REPO_ROOT}" status --short 2>/dev/null || true
    return 0
  fi
  printf '\n'
}

remote_alpha_deploy_es_binaries_stage_make_local_payload_tree() {
  local payload_dir=$1
  mkdir -p "${payload_dir}"

  remote_alpha_deploy_es_binaries_require_supported_go_toolchain
  env GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "${payload_dir}/es" ./cmd/es
  env GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "${payload_dir}/es-runtime-support" ./cmd/es-runtime-support

  python3 -I - "${payload_dir}/build-provenance.json" "${REPO_ROOT}" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

output_path = pathlib.Path(sys.argv[1])
repo_root = pathlib.Path(sys.argv[2])

def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

paths = [
    repo_root / "go.mod",
    repo_root / "go.sum",
    repo_root / "cmd" / "es",
    repo_root / "cmd" / "es-runtime-support",
    repo_root / "es",
    repo_root / "internal",
]
manifest = []
for item in paths:
    if item.is_file():
        manifest.append({"path": str(item.relative_to(repo_root)), "sha256": sha256(item)})
        continue
    if item.is_dir():
        for path in sorted(item.rglob("*")):
            if path.is_file():
                manifest.append({"path": str(path.relative_to(repo_root)), "sha256": sha256(path)})

git_commit = ""
git_status = []
dirty = False
proc = subprocess.run(["git", "-C", str(repo_root), "rev-parse", "HEAD"], capture_output=True, text=True)
if proc.returncode == 0:
    git_commit = proc.stdout.strip()
proc = subprocess.run(["git", "-C", str(repo_root), "status", "--short"], capture_output=True, text=True)
if proc.returncode == 0:
    git_status = [line.rstrip() for line in proc.stdout.splitlines() if line.strip()]
    dirty = bool(git_status)

payload = {
    "source_kind": "local_build",
    "repo_root": str(repo_root),
    "git_commit": git_commit,
    "git_status_short": git_status,
    "dirty_worktree": dirty,
    "build_commands": [
        "env GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o payload/es ./cmd/es",
        "env GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o payload/es-runtime-support ./cmd/es-runtime-support",
    ],
    "source_file_digests": manifest,
}
output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

remote_alpha_deploy_es_binaries_stage_make_local_upload_tree() {
  local upload_dir=$1

  mkdir -p "${upload_dir}/scripts/internal" "${upload_dir}/payload"
  cp "${REPO_ROOT}/scripts/remote_alpha_deploy_es_binaries.sh" "${upload_dir}/scripts/remote_alpha_deploy_es_binaries.sh"
  cp "${REPO_ROOT}/scripts/internal/remote_alpha_deploy_es_binaries.sh" "${upload_dir}/scripts/internal/remote_alpha_deploy_es_binaries.sh"
  remote_alpha_deploy_es_binaries_stage_make_local_payload_tree "${upload_dir}/payload"
}

remote_alpha_deploy_es_binaries_stage_validate_local_upload_tree() {
  local upload_dir=$1
  local -a missing=()
  local relative_path

  while IFS= read -r relative_path; do
    if [[ -z "${relative_path}" ]]; then
      continue
    fi
    if [[ ! -f "${upload_dir}/${relative_path}" ]]; then
      missing+=("${relative_path}")
    fi
  done < <(remote_alpha_deploy_es_binaries_stage_required_upload_paths)

  if (( ${#missing[@]} == 0 )); then
    return 0
  fi

  local joined_missing
  joined_missing="$(IFS=', '; printf '%s' "${missing[*]}")"
  printf 'local staged ES binary deployment upload tree is missing required files: %s\n' "${joined_missing}" >&2
  return 1
}

remote_alpha_deploy_es_binaries_stage_local_file_meta() {
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
    files.append({"path": str(path), "sha256": digest})

output_path.write_text(json.dumps(files, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

remote_alpha_deploy_es_binaries_stage_ssh() {
  "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_SSH_BIN}" "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_SSH_TARGET}" "$@"
}

remote_alpha_deploy_es_binaries_stage_ssh_with_tty() {
  "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_SSH_BIN}" -tt "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_SSH_TARGET}" "$@"
}

remote_alpha_deploy_es_binaries_stage_build_remote_bash_command() {
  local script=$1
  shift

  python3 -I - "${script}" "$@" <<'PY'
import shlex
import sys

parts = ["/bin/bash", "-c", sys.argv[1], "remote-alpha-stage", *sys.argv[2:]]
print(" ".join(shlex.quote(part) for part in parts))
PY
}

remote_alpha_deploy_es_binaries_stage_run_remote_batch() {
  local script=$1
  shift
  remote_alpha_deploy_es_binaries_stage_ssh /bin/bash -s -- "$@" <<<"${script}"
}

remote_alpha_deploy_es_binaries_stage_run_remote_batch_with_tty() {
  local script=$1
  shift
  local remote_command

  remote_command="$(remote_alpha_deploy_es_binaries_stage_build_remote_bash_command "${script}" "$@")"
  remote_alpha_deploy_es_binaries_stage_ssh_with_tty "${remote_command}"
}

remote_alpha_deploy_es_binaries_stage_scp() {
  "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_SCP_BIN}" "$@"
}

remote_alpha_deploy_es_binaries_stage_note_blocker() {
  local message=$1
  if [[ -z "${REMOTE_ALPHA_DEPLOY_ES_BINARIES_BLOCKER_DETAIL}" ]]; then
    REMOTE_ALPHA_DEPLOY_ES_BINARIES_BLOCKER_DETAIL="${message}"
  fi
}

remote_alpha_deploy_es_binaries_stage_note_sudo_unavailable() {
  local message=$1
  REMOTE_ALPHA_DEPLOY_ES_BINARIES_SUDO_UNAVAILABLE="true"
  REMOTE_ALPHA_DEPLOY_ES_BINARIES_FAILURE_CLASSIFICATION="sudo_unavailable"
  remote_alpha_deploy_es_binaries_stage_note_blocker "${message}"
}

remote_alpha_deploy_es_binaries_stage_note_wrapper_tooling_error() {
  local message=$1
  REMOTE_ALPHA_DEPLOY_ES_BINARIES_WRAPPER_TOOLING_ERROR="true"
  if [[ "${REMOTE_ALPHA_DEPLOY_ES_BINARIES_FAILURE_CLASSIFICATION}" != "sudo_unavailable" ]]; then
    REMOTE_ALPHA_DEPLOY_ES_BINARIES_FAILURE_CLASSIFICATION="wrapper_tooling_error"
  fi
  remote_alpha_deploy_es_binaries_stage_note_blocker "${message}"
}

remote_alpha_deploy_es_binaries_stage_noninteractive_sudo_preflight() {
  remote_alpha_deploy_es_binaries_stage_run_remote_batch \
    'set -euo pipefail
sudo -n true >/dev/null 2>&1'
}

# The upload and artifact folders sit in /tmp under names others can guess, so
# each is made fresh and private (mkdir without -p fails if anyone planted it
# first) before root copies helpers out of it or the Mac trusts what it holds.
remote_alpha_deploy_es_binaries_stage_remote_prepare_upload_root() {
  remote_alpha_deploy_es_binaries_stage_run_remote_batch \
    'set -euo pipefail
upload_root=$1
rm -rf -- "${upload_root}"
mkdir -m 0700 -- "${upload_root}"
mkdir -p -- "${upload_root}/scripts/internal" "${upload_root}/payload"' \
    "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_UPLOAD_ROOT}"
}

remote_alpha_deploy_es_binaries_stage_remote_prepare_artifact_root() {
  remote_alpha_deploy_es_binaries_stage_run_remote_batch \
    'set -euo pipefail
artifact_root=$1
rm -rf -- "${artifact_root}"
mkdir -m 0700 -- "${artifact_root}"' \
    "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_ARTIFACT_ROOT}"
}

# Prints scripts/internal/remote_alpha_output_dir.sh followed by BODY, so a
# remote batch can check the host's artifact folder before root stages into it.
remote_alpha_deploy_es_binaries_stage_remote_batch_with_output_dir_check() {
  local body=$1
  local definition

  definition="$(cat -- "${REPO_ROOT}/scripts/internal/remote_alpha_output_dir.sh")" || return 1
  printf '%s\n%s\n' "${definition}" "${body}"
}

remote_alpha_deploy_es_binaries_stage_fetch_remote_file() {
  local remote_path=$1
  local local_path=$2
  remote_alpha_deploy_es_binaries_stage_scp "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_SSH_TARGET}:${remote_path}" "${local_path}"
}

remote_alpha_deploy_es_binaries_stage_upload_remote_tree() {
  local upload_dir=$1
  local relative_path

  while IFS= read -r relative_path; do
    if [[ -z "${relative_path}" ]]; then
      continue
    fi
    remote_alpha_deploy_es_binaries_stage_scp \
      "${upload_dir}/${relative_path}" \
      "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_SSH_TARGET}:${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_UPLOAD_ROOT}/${relative_path}" || return 1
  done < <(remote_alpha_deploy_es_binaries_stage_required_upload_paths)
}

remote_alpha_deploy_es_binaries_stage_remove_remote_user_owned_roots() {
  if [[ -z "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_UPLOAD_ROOT}" && -z "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_ARTIFACT_ROOT}" ]]; then
    return 0
  fi
  remote_alpha_deploy_es_binaries_stage_run_remote_batch \
    'set -euo pipefail
upload_root=$1
artifact_root=$2
if [[ -n "${upload_root}" ]]; then
  rm -rf -- "${upload_root}" || true
fi
if [[ -n "${artifact_root}" ]]; then
  rm -rf -- "${artifact_root}" || true
fi' \
    "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_UPLOAD_ROOT}" \
    "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_ARTIFACT_ROOT}"
}

remote_alpha_deploy_es_binaries_stage_remote_install_staged_tree() {
  local sudo_cmd body script
  if [[ "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_SUDO_MODE}" == "interactive" ]]; then
    sudo_cmd="sudo"
  else
    sudo_cmd="sudo -n"
  fi
  body="$(cat <<EOF
set -euo pipefail
upload_root=\$1
staging_root=\$2

remote_alpha_prepare_output_dir_as_root "\$(dirname "\${staging_root}")" ${sudo_cmd#sudo}
${sudo_cmd} rm -rf -- "\${staging_root}"
${sudo_cmd} install -d -m 0755 -o root -g root "\${staging_root}"
${sudo_cmd} install -d -m 0755 -o root -g root "\${staging_root}/scripts"
${sudo_cmd} install -d -m 0755 -o root -g root "\${staging_root}/scripts/internal"
${sudo_cmd} install -d -m 0755 -o root -g root "\${staging_root}/payload"
${sudo_cmd} install -m 0755 -o root -g root "\${upload_root}/scripts/remote_alpha_deploy_es_binaries.sh" "\${staging_root}/scripts/remote_alpha_deploy_es_binaries.sh"
${sudo_cmd} install -m 0644 -o root -g root "\${upload_root}/scripts/internal/remote_alpha_deploy_es_binaries.sh" "\${staging_root}/scripts/internal/remote_alpha_deploy_es_binaries.sh"
${sudo_cmd} install -m 0755 -o root -g root "\${upload_root}/payload/es" "\${staging_root}/payload/es"
${sudo_cmd} install -m 0755 -o root -g root "\${upload_root}/payload/es-runtime-support" "\${staging_root}/payload/es-runtime-support"
${sudo_cmd} install -m 0644 -o root -g root "\${upload_root}/payload/build-provenance.json" "\${staging_root}/payload/build-provenance.json"
rm -rf -- "\${upload_root}"
EOF
)"
  script="$(remote_alpha_deploy_es_binaries_stage_remote_batch_with_output_dir_check "${body}")" || return 1

  if [[ "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_SUDO_MODE}" == "interactive" ]]; then
    remote_alpha_deploy_es_binaries_stage_run_remote_batch_with_tty "${script}" \
      "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_UPLOAD_ROOT}" \
      "${REMOTE_ALPHA_DEPLOY_ES_BINARIES_STAGE_REMOTE_STAGING_ROOT}"
    return 0
  fi
  remote_alpha_deploy_es_binaries_stage_run_remote_batch "${script}" \
    "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_UPLOAD_ROOT}" \
    "${REMOTE_ALPHA_DEPLOY_ES_BINARIES_STAGE_REMOTE_STAGING_ROOT}"
}

remote_alpha_deploy_es_binaries_stage_run_interactive_check_sequence() {
  local body script status=0
  body="$(cat <<EOF
set -euo pipefail
upload_root=\$1
staging_root=\$2
staged_wrapper=\$3
stage_stat_path=\$4
check_output=\$5

mkdir -p -- "\$(dirname "\${stage_stat_path}")"
mkdir -p -- "\$(dirname "\${check_output}")"
sudo -v
remote_alpha_prepare_output_dir_as_root "\$(dirname "\${staging_root}")"
cleanup() {
  sudo rm -rf -- "\${staging_root}" || true
}
trap cleanup EXIT
sudo rm -rf -- "\${staging_root}"
sudo install -d -m 0755 -o root -g root "\${staging_root}"
sudo install -d -m 0755 -o root -g root "\${staging_root}/scripts"
sudo install -d -m 0755 -o root -g root "\${staging_root}/scripts/internal"
sudo install -d -m 0755 -o root -g root "\${staging_root}/payload"
sudo install -m 0755 -o root -g root "\${upload_root}/scripts/remote_alpha_deploy_es_binaries.sh" "\${staging_root}/scripts/remote_alpha_deploy_es_binaries.sh"
sudo install -m 0644 -o root -g root "\${upload_root}/scripts/internal/remote_alpha_deploy_es_binaries.sh" "\${staging_root}/scripts/internal/remote_alpha_deploy_es_binaries.sh"
sudo install -m 0755 -o root -g root "\${upload_root}/payload/es" "\${staging_root}/payload/es"
sudo install -m 0755 -o root -g root "\${upload_root}/payload/es-runtime-support" "\${staging_root}/payload/es-runtime-support"
sudo install -m 0644 -o root -g root "\${upload_root}/payload/build-provenance.json" "\${staging_root}/payload/build-provenance.json"
rm -rf -- "\${upload_root}"

for path in \
  "\${staging_root}" \
  "\${staging_root}/scripts" \
  "\${staging_root}/scripts/internal" \
  "\${staging_root}/payload" \
  "\${staging_root}/scripts/remote_alpha_deploy_es_binaries.sh" \
  "\${staging_root}/scripts/internal/remote_alpha_deploy_es_binaries.sh" \
  "\${staging_root}/payload/es" \
  "\${staging_root}/payload/es-runtime-support" \
  "\${staging_root}/payload/build-provenance.json"
do
  owner=\$(sudo stat -c '%U' "\${path}")
  group=\$(sudo stat -c '%G' "\${path}")
  mode=\$(sudo stat -c '%a' "\${path}")
  display_path="\${path}"
  if [[ -n "\${FAKE_REMOTE_ROOT:-}" && "\${display_path}" == "\${FAKE_REMOTE_ROOT}"* ]]; then
    display_path="\${display_path#\${FAKE_REMOTE_ROOT}}"
  fi
  printf '%s\t%s\t%s\t%s\n' "\${owner}" "\${group}" "\${mode}" "\${display_path}"
done >"\${stage_stat_path}"

set +e
sudo "\${staged_wrapper}" --check-only >"\${check_output}"
status=\$?
set -e
exit "\${status}"
EOF
)"
  script="$(remote_alpha_deploy_es_binaries_stage_remote_batch_with_output_dir_check "${body}")" || return 1
  set +e
  remote_alpha_deploy_es_binaries_stage_run_remote_batch_with_tty "${script}" \
    "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_UPLOAD_ROOT}" \
    "${REMOTE_ALPHA_DEPLOY_ES_BINARIES_STAGE_REMOTE_STAGING_ROOT}" \
    "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_STAGED_WRAPPER_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_STAGE_STAT_ARTIFACT_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_CHECK_OUTPUT_ARTIFACT_PATH}"
  status=$?
  set -e
  return "${status}"
}

remote_alpha_deploy_es_binaries_stage_validate_stage_stat() {
  local stat_path=$1
  local output_path=$2

  python3 -I - "$stat_path" "$output_path" "${REMOTE_ALPHA_DEPLOY_ES_BINARIES_STAGE_REMOTE_STAGING_ROOT}" <<'PY'
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
    parts = raw_line.split("\t", 3)
    if len(parts) != 4:
        parts = raw_line.split("\\t", 3)
    if len(parts) != 4:
        errors.append(f"unexpected staged helper stat line: {raw_line}")
        continue
    owner, group, mode, path = parts
    mode_text = mode.zfill(4)
    mode_value = int(mode_text, 8)
    root_owned = owner == "root"
    not_group_or_other_writable = (mode_value & 0o022) == 0
    inside_staging_root = path == staging_root or path.startswith(staging_root + "/")
    items.append(
        {
            "path": path,
            "owner": owner,
            "group": group,
            "mode": mode_text,
            "root_owned": root_owned,
            "not_group_or_other_writable": not_group_or_other_writable,
            "inside_staging_root": inside_staging_root,
        }
    )
    if not root_owned:
        errors.append(f"path is not root-owned: {path}")
    if not not_group_or_other_writable:
        errors.append(f"path is group-writable or world-writable: {path}")
    if not inside_staging_root:
        errors.append(f"path is outside the staged helper root: {path}")

if len(items) != 9:
    errors.append(f"expected 9 staged helper paths, found {len(items)}")

payload = {
    "staged_root": staging_root,
    "items": items,
    "validation_errors": errors,
    "root_owned_before_execution": not errors and len(items) == 9,
}
output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if errors:
    raise SystemExit(1)
PY
}

remote_alpha_deploy_es_binaries_stage_run_remote_check_only() {
  local output_path=$1
  local script
  script="$(cat <<EOF
set -euo pipefail
staged_wrapper=\$1
sudo -n "\${staged_wrapper}" --check-only
EOF
)"
  remote_alpha_deploy_es_binaries_stage_run_remote_batch "${script}" \
    "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_STAGED_WRAPPER_PATH}" >"${output_path}"
}

remote_alpha_deploy_es_binaries_stage_validate_check_report() {
  local report_path=$1
  local meta_path=$2

  python3 -I - "$report_path" "$meta_path" "${remote_alpha_deploy_es_binaries_summary_schema_version}" <<'PY'
import json
import pathlib
import sys

report_path = pathlib.Path(sys.argv[1])
meta_path = pathlib.Path(sys.argv[2])
expected_schema = sys.argv[3]
payload = {"valid_json": False, "accepted_evidence": False}

def write_meta(value):
    meta_path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")

try:
    report = json.loads(report_path.read_text(encoding="utf-8"))
except Exception as exc:  # noqa: BLE001
    payload["error"] = f"malformed check-only JSON: {exc}"
    write_meta(payload)
    raise SystemExit(1)

errors = []
if report.get("schema_version") != expected_schema:
    errors.append(f"unexpected schema_version: {report.get('schema_version')!r}")
mode = report.get("mode") or {}
proof = report.get("proof") or {}
plan = report.get("plan") or {}
if mode.get("name") != "check_only":
    errors.append("mode.name must be check_only")
if mode.get("non_mutating") is not True:
    errors.append("mode.non_mutating must be true")
if proof.get("host_mutation_performed") is not False:
    errors.append("proof.host_mutation_performed must be false")
if proof.get("check_only_is_not_proof") is not True:
    errors.append("proof.check_only_is_not_proof must be true")

payload.update(
    {
        "valid_json": True,
        "schema_version": report.get("schema_version"),
        "overall_classification": report.get("overall_classification"),
        "deployment_needed": plan.get("deployment_needed"),
        "apply_ready": plan.get("apply_ready"),
        "warning_count": len(report.get("warnings") or []),
        "blocker_count": len(report.get("blockers") or []),
        "expected_exit_code": 1 if report.get("overall_classification") == "blocker" else 0,
    }
)

if errors:
    payload["errors"] = errors
    write_meta(payload)
    raise SystemExit(1)

payload["accepted_evidence"] = True
payload["errors"] = []
write_meta(payload)
PY
}

remote_alpha_deploy_es_binaries_stage_run_remote_apply() {
  local script
  script="$(cat <<EOF
set -euo pipefail
staged_wrapper=\$1
summary_path=\$2
sudo -n "\${staged_wrapper}" --apply --summary-path "\${summary_path}" >/dev/null
EOF
)"
  remote_alpha_deploy_es_binaries_stage_run_remote_batch "${script}" \
    "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_STAGED_WRAPPER_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_SUMMARY_PATH}"
}

remote_alpha_deploy_es_binaries_stage_run_interactive_apply_sequence() {
  local body script status=0
  body="$(cat <<EOF
set -euo pipefail
upload_root=\$1
staging_root=\$2
staged_wrapper=\$3
summary_path=\$4

sudo -v
remote_alpha_prepare_output_dir_as_root "\$(dirname "\${staging_root}")"
cleanup() {
  sudo rm -rf -- "\${staging_root}" || true
}
trap cleanup EXIT
sudo rm -rf -- "\${staging_root}"
sudo install -d -m 0755 -o root -g root "\${staging_root}"
sudo install -d -m 0755 -o root -g root "\${staging_root}/scripts"
sudo install -d -m 0755 -o root -g root "\${staging_root}/scripts/internal"
sudo install -d -m 0755 -o root -g root "\${staging_root}/payload"
sudo install -m 0755 -o root -g root "\${upload_root}/scripts/remote_alpha_deploy_es_binaries.sh" "\${staging_root}/scripts/remote_alpha_deploy_es_binaries.sh"
sudo install -m 0644 -o root -g root "\${upload_root}/scripts/internal/remote_alpha_deploy_es_binaries.sh" "\${staging_root}/scripts/internal/remote_alpha_deploy_es_binaries.sh"
sudo install -m 0755 -o root -g root "\${upload_root}/payload/es" "\${staging_root}/payload/es"
sudo install -m 0755 -o root -g root "\${upload_root}/payload/es-runtime-support" "\${staging_root}/payload/es-runtime-support"
sudo install -m 0644 -o root -g root "\${upload_root}/payload/build-provenance.json" "\${staging_root}/payload/build-provenance.json"
rm -rf -- "\${upload_root}"

sudo "\${staged_wrapper}" --apply --summary-path "\${summary_path}" >/dev/null
EOF
)"
  script="$(remote_alpha_deploy_es_binaries_stage_remote_batch_with_output_dir_check "${body}")" || return 1
  set +e
  remote_alpha_deploy_es_binaries_stage_run_remote_batch_with_tty "${script}" \
    "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_UPLOAD_ROOT}" \
    "${REMOTE_ALPHA_DEPLOY_ES_BINARIES_STAGE_REMOTE_STAGING_ROOT}" \
    "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_STAGED_WRAPPER_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_SUMMARY_PATH}"
  status=$?
  set -e
  return "${status}"
}

remote_alpha_deploy_es_binaries_stage_remote_cleanup() {
  if [[ "${REMOTE_ALPHA_DEPLOY_ES_BINARIES_REMOTE_UPLOAD_PREPARED}" != "true" && "${REMOTE_ALPHA_DEPLOY_ES_BINARIES_STAGING_OCCURRED}" != "true" && -z "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_ARTIFACT_ROOT}" ]]; then
    return 0
  fi
  local body script
  # Root removes the staging folder only through an artifact folder that
  # passes the same check as staging did.
  body="$(cat <<EOF
set -euo pipefail
staging_root=\$1
upload_root=\$2
artifact_root=\$3
if [[ -n "\${staging_root}" ]] && remote_alpha_prepare_output_dir_as_root "\$(dirname "\${staging_root}")" -n; then
  sudo -n rm -rf -- "\${staging_root}" || true
fi
rm -rf -- "\${upload_root}" || true
rm -rf -- "\${artifact_root}" || true
EOF
)"
  script="$(remote_alpha_deploy_es_binaries_stage_remote_batch_with_output_dir_check "${body}")" || return 1
  remote_alpha_deploy_es_binaries_stage_run_remote_batch "${script}" \
    "${REMOTE_ALPHA_DEPLOY_ES_BINARIES_STAGE_REMOTE_STAGING_ROOT}" \
    "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_UPLOAD_ROOT}" \
    "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_ARTIFACT_ROOT}"
}

remote_alpha_deploy_es_binaries_stage_visible_cleanup_if_needed() {
  if [[ "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_SUDO_MODE}" != "interactive" ]]; then
    return 0
  fi
  if ! remote_alpha_deploy_es_binaries_stage_remove_remote_user_owned_roots; then
    remote_alpha_deploy_es_binaries_stage_note_wrapper_tooling_error "could not remove remote transient upload or artifact roots after interactive staged ES binary deployment execution"
    return 1
  fi
  REMOTE_ALPHA_DEPLOY_ES_BINARIES_REMOTE_CLEANUP_COMPLETED="true"
  REMOTE_ALPHA_DEPLOY_ES_BINARIES_TRANSIENT_STAGING_REMOVED="true"
  return 0
}

remote_alpha_deploy_es_binaries_stage_write_provenance() {
  python3 -I - \
    "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_PROVENANCE_OUTPUT_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_LOCAL_FILE_META_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_STAGE_STAT_META_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_CHECK_VALIDATION_META_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_CHECK_OUTPUT_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_APPLY_SUMMARY_OUTPUT_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_RUN_ID}" \
    "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_SSH_TARGET}" \
    "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_GIT_COMMIT}" \
    "${REMOTE_ALPHA_DEPLOY_ES_BINARIES_CHECKER_EXIT_CODE}" \
    "${REMOTE_ALPHA_DEPLOY_ES_BINARIES_APPLY_EXIT_CODE}" \
    "${REMOTE_ALPHA_DEPLOY_ES_BINARIES_STAGE_REMOTE_STAGING_ROOT}" \
    "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_STAGED_WRAPPER_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_STAGED_INTERNAL_PATH}" \
    "${REMOTE_ALPHA_DEPLOY_ES_BINARIES_STAGING_OCCURRED}" \
    "${REMOTE_ALPHA_DEPLOY_ES_BINARIES_STAGING_RETAINED_FOR_DIAGNOSTICS}" \
    "${REMOTE_ALPHA_DEPLOY_ES_BINARIES_TRANSIENT_STAGING_REMOVED}" \
    "${REMOTE_ALPHA_DEPLOY_ES_BINARIES_CHECKER_RAN}" \
    "${REMOTE_ALPHA_DEPLOY_ES_BINARIES_APPLY_RAN}" \
    "${REMOTE_ALPHA_DEPLOY_ES_BINARIES_SUDO_UNAVAILABLE}" \
    "${REMOTE_ALPHA_DEPLOY_ES_BINARIES_WRAPPER_TOOLING_ERROR}" \
    "${REMOTE_ALPHA_DEPLOY_ES_BINARIES_FAILURE_CLASSIFICATION}" \
    "${REMOTE_ALPHA_DEPLOY_ES_BINARIES_BLOCKER_DETAIL}" \
    "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_SUDO_MODE}" \
    "${REMOTE_ALPHA_DEPLOY_ES_BINARIES_REMOTE_CLEANUP_COMPLETED}" \
    "${remote_alpha_deploy_es_binaries_stage_schema_version}" <<'PY'
import json
import pathlib
import sys

(
    output_path,
    local_file_meta_path,
    stage_stat_meta_path,
    check_validation_meta_path,
    check_output_path,
    apply_summary_output_path,
    run_id,
    ssh_target,
    git_commit,
    checker_exit_code,
    apply_exit_code,
    remote_staged_path,
    staged_wrapper_path,
    staged_internal_path,
    staging_occurred,
    staging_retained_for_diagnostics,
    transient_staging_removed,
    checker_ran,
    apply_ran,
    sudo_unavailable,
    wrapper_tooling_error,
    failure_classification,
    blocker_detail,
    sudo_mode,
    remote_cleanup_completed,
    schema_version,
) = sys.argv[1:]

def load_json(path: str):
    p = pathlib.Path(path)
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))

payload = {
    "schema_version": schema_version,
    "run_id": run_id,
    "ssh_target": ssh_target,
    "git_commit": git_commit,
    "local_git_commit": git_commit,
    "local_files": load_json(local_file_meta_path) or [],
    "remote_staged_path": remote_staged_path,
    "remote_staging": load_json(stage_stat_meta_path) or {},
    "checker": load_json(check_validation_meta_path) or {},
    "checker_exit_code": int(checker_exit_code) if checker_exit_code else None,
    "apply_exit_code": int(apply_exit_code) if apply_exit_code else None,
    "checker_ran": checker_ran == "true",
    "apply_ran": apply_ran == "true",
    "staging_occurred": staging_occurred == "true",
    "staging_retained_for_diagnostics": staging_retained_for_diagnostics == "true",
    "transient_staging_removed": transient_staging_removed == "true",
    "sudo_unavailable": sudo_unavailable == "true",
    "wrapper_tooling_error": wrapper_tooling_error == "true",
    "failure_classification": failure_classification or None,
    "sudo_or_preflight_blocker": blocker_detail or None,
    "sudo_mode": sudo_mode,
    "remote_cleanup_completed": remote_cleanup_completed == "true",
    "local_outputs": {
        "check_output_path": pathlib.Path(check_output_path).name,
        "apply_summary_output_path": pathlib.Path(apply_summary_output_path).name,
        "helper_staging_record_output_path": pathlib.Path(output_path).name,
    },
    "staged_files": [
        {
            "local_path": "scripts/remote_alpha_deploy_es_binaries.sh",
            "remote_path": staged_wrapper_path,
        },
        {
            "local_path": "scripts/internal/remote_alpha_deploy_es_binaries.sh",
            "remote_path": staged_internal_path,
        },
        {
            "local_path": "payload/es",
            "remote_path": remote_staged_path + "/payload/es",
        },
        {
            "local_path": "payload/es-runtime-support",
            "remote_path": remote_staged_path + "/payload/es-runtime-support",
        },
    ],
}
pathlib.Path(output_path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

remote_alpha_deploy_es_binaries_stage_finalize_on_exit() {
  if [[ "${REMOTE_ALPHA_DEPLOY_ES_BINARIES_KEEP_STAGING_ON_FAILURE}" == "true" && "${REMOTE_ALPHA_DEPLOY_ES_BINARIES_WRAPPER_TOOLING_ERROR}" == "true" ]]; then
    REMOTE_ALPHA_DEPLOY_ES_BINARIES_STAGING_RETAINED_FOR_DIAGNOSTICS="true"
  else
    if [[ "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_SUDO_MODE}" == "interactive" ]]; then
      remote_alpha_deploy_es_binaries_stage_remove_remote_user_owned_roots >/dev/null 2>&1 || true
    elif remote_alpha_deploy_es_binaries_stage_remote_cleanup >/dev/null 2>&1; then
      REMOTE_ALPHA_DEPLOY_ES_BINARIES_REMOTE_CLEANUP_COMPLETED="true"
      REMOTE_ALPHA_DEPLOY_ES_BINARIES_TRANSIENT_STAGING_REMOVED="true"
    fi
  fi
  if [[ -n "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_PROVENANCE_OUTPUT_PATH:-}" ]]; then
    remote_alpha_deploy_es_binaries_stage_write_provenance >/dev/null 2>&1 || true
  fi
}

remote_alpha_deploy_es_binaries_stage_main() {
  remote_alpha_deploy_es_binaries_stage_defaults
  remote_alpha_deploy_es_binaries_stage_parse_args "$@" || return $?
  remote_alpha_deploy_es_binaries_stage_finalize_paths

  remote_alpha_deploy_es_binaries_require_command python3 || return 1
  remote_alpha_deploy_es_binaries_require_command ssh || return 1
  remote_alpha_deploy_es_binaries_require_command scp || return 1
  remote_alpha_deploy_es_binaries_require_supported_go_toolchain || return 1

  remote_alpha_deploy_es_binaries_stage_ensure_parent_dir "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_CHECK_OUTPUT_PATH}"
  remote_alpha_deploy_es_binaries_stage_ensure_parent_dir "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_APPLY_SUMMARY_OUTPUT_PATH}"
  remote_alpha_deploy_es_binaries_stage_ensure_parent_dir "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_PROVENANCE_OUTPUT_PATH}"

  local tmpdir local_upload_dir stage_stat_path
  tmpdir="$(mktemp -d)"
  local_upload_dir="${tmpdir}/upload"
  stage_stat_path="${tmpdir}/stage-stat.txt"
  REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_LOCAL_FILE_META_PATH="${tmpdir}/local-files.json"
  REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_STAGE_STAT_META_PATH="${tmpdir}/stage-stat.json"
  REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_CHECK_VALIDATION_META_PATH="${tmpdir}/check-validation.json"
  trap "remote_alpha_deploy_es_binaries_stage_finalize_on_exit; rm -rf -- '${tmpdir}'" EXIT

  if ! remote_alpha_deploy_es_binaries_stage_make_local_upload_tree "${local_upload_dir}"; then
    remote_alpha_deploy_es_binaries_stage_note_wrapper_tooling_error "could not assemble the local ES binary deployment upload tree"
    return 1
  fi
  remote_alpha_deploy_es_binaries_stage_validate_local_upload_tree "${local_upload_dir}" || {
    remote_alpha_deploy_es_binaries_stage_note_wrapper_tooling_error "local ES binary deployment upload tree was missing required staged files"
    return 1
  }
  REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_GIT_COMMIT="$(remote_alpha_deploy_es_binaries_stage_git_commit)"
  local helper_paths=(
    "${REPO_ROOT}/scripts/remote_alpha_deploy_es_binaries.sh"
    "${REPO_ROOT}/scripts/internal/remote_alpha_deploy_es_binaries.sh"
    "${local_upload_dir}/payload/es"
    "${local_upload_dir}/payload/es-runtime-support"
    "${local_upload_dir}/payload/build-provenance.json"
  )
  remote_alpha_deploy_es_binaries_stage_local_file_meta "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_LOCAL_FILE_META_PATH}" "${helper_paths[@]}"

  REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_UPLOAD_ROOT="/tmp/execution-substrate-es-binary-deployment-upload-${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_RUN_ID}"
  REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_ARTIFACT_ROOT="/tmp/execution-substrate-es-binary-deployment-artifacts-${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_RUN_ID}"
  REMOTE_ALPHA_DEPLOY_ES_BINARIES_STAGE_REMOTE_STAGING_ROOT="${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_STAGE_ROOT}/${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_RUN_ID}"
  REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_STAGED_WRAPPER_PATH="${REMOTE_ALPHA_DEPLOY_ES_BINARIES_STAGE_REMOTE_STAGING_ROOT}/scripts/remote_alpha_deploy_es_binaries.sh"
  REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_STAGED_INTERNAL_PATH="${REMOTE_ALPHA_DEPLOY_ES_BINARIES_STAGE_REMOTE_STAGING_ROOT}/scripts/internal/remote_alpha_deploy_es_binaries.sh"
  REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_STAGE_STAT_ARTIFACT_PATH="${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_ARTIFACT_ROOT}/stage-stat.txt"
  REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_CHECK_OUTPUT_ARTIFACT_PATH="${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_ARTIFACT_ROOT}/es-binary-deployment-check-only.json"

  if [[ "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_SUDO_MODE}" != "interactive" ]]; then
    remote_alpha_deploy_es_binaries_stage_noninteractive_sudo_preflight || {
      remote_alpha_deploy_es_binaries_stage_note_sudo_unavailable "noninteractive sudo preflight failed for root-owned staged ES binary deployment execution"
      return 1
    }
  fi

  remote_alpha_deploy_es_binaries_stage_remote_prepare_upload_root || {
    remote_alpha_deploy_es_binaries_stage_note_wrapper_tooling_error "could not prepare remote upload root for staged ES binary deployment helper tree"
    return 1
  }
  REMOTE_ALPHA_DEPLOY_ES_BINARIES_REMOTE_UPLOAD_PREPARED="true"
  remote_alpha_deploy_es_binaries_stage_remote_prepare_artifact_root || {
    remote_alpha_deploy_es_binaries_stage_note_wrapper_tooling_error "could not prepare remote artifact root for staged ES binary deployment helper tree"
    return 1
  }
  remote_alpha_deploy_es_binaries_stage_upload_remote_tree "${local_upload_dir}" || {
    remote_alpha_deploy_es_binaries_stage_note_wrapper_tooling_error "could not copy staged ES binary deployment helper tree to remote upload root"
    return 1
  }

  if [[ "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_SUDO_MODE}" == "interactive" ]]; then
    remote_alpha_deploy_es_binaries_stage_run_interactive_check_sequence
    REMOTE_ALPHA_DEPLOY_ES_BINARIES_CHECKER_EXIT_CODE=$?
    REMOTE_ALPHA_DEPLOY_ES_BINARIES_STAGING_OCCURRED="true"
    REMOTE_ALPHA_DEPLOY_ES_BINARIES_CHECKER_RAN="true"
    remote_alpha_deploy_es_binaries_stage_fetch_remote_file \
      "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_STAGE_STAT_ARTIFACT_PATH}" \
      "${stage_stat_path}" || {
      remote_alpha_deploy_es_binaries_stage_note_wrapper_tooling_error "could not fetch remote staged ES binary deployment helper ownership evidence"
      return 1
    }
    remote_alpha_deploy_es_binaries_stage_validate_stage_stat "${stage_stat_path}" "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_STAGE_STAT_META_PATH}" || {
      remote_alpha_deploy_es_binaries_stage_note_wrapper_tooling_error "staged ES binary deployment helper tree failed root-owned or non-writable validation"
      return 1
    }
    remote_alpha_deploy_es_binaries_stage_fetch_remote_file \
      "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_CHECK_OUTPUT_ARTIFACT_PATH}" \
      "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_CHECK_OUTPUT_PATH}" || {
      remote_alpha_deploy_es_binaries_stage_note_wrapper_tooling_error "staged ES binary deployment helper did not produce fetchable check-only JSON output"
      return 1
    }
  else
    remote_alpha_deploy_es_binaries_stage_remote_install_staged_tree || {
      remote_alpha_deploy_es_binaries_stage_note_wrapper_tooling_error "could not install staged ES binary deployment helper tree as root-owned remote staging"
      return 1
    }
    REMOTE_ALPHA_DEPLOY_ES_BINARIES_STAGING_OCCURRED="true"
    remote_alpha_deploy_es_binaries_stage_run_remote_batch \
      'set -euo pipefail
staging_root=$1
for path in \
  "${staging_root}" \
  "${staging_root}/scripts" \
  "${staging_root}/scripts/internal" \
  "${staging_root}/payload" \
  "${staging_root}/scripts/remote_alpha_deploy_es_binaries.sh" \
  "${staging_root}/scripts/internal/remote_alpha_deploy_es_binaries.sh" \
  "${staging_root}/payload/es" \
  "${staging_root}/payload/es-runtime-support" \
  "${staging_root}/payload/build-provenance.json"
do
  owner=$(sudo -n stat -c "%U" "${path}")
  group=$(sudo -n stat -c "%G" "${path}")
  mode=$(sudo -n stat -c "%a" "${path}")
  printf "%s\t%s\t%s\t%s\n" "${owner}" "${group}" "${mode}" "${path}"
done' \
      "${REMOTE_ALPHA_DEPLOY_ES_BINARIES_STAGE_REMOTE_STAGING_ROOT}" >"${stage_stat_path}" || {
      remote_alpha_deploy_es_binaries_stage_note_wrapper_tooling_error "could not verify remote staged ES binary deployment helper ownership and mode"
      return 1
    }
    remote_alpha_deploy_es_binaries_stage_validate_stage_stat "${stage_stat_path}" "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_STAGE_STAT_META_PATH}" || {
      remote_alpha_deploy_es_binaries_stage_note_wrapper_tooling_error "staged ES binary deployment helper tree failed root-owned or non-writable validation"
      return 1
    }
    set +e
    remote_alpha_deploy_es_binaries_stage_run_remote_check_only "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_CHECK_OUTPUT_PATH}"
    REMOTE_ALPHA_DEPLOY_ES_BINARIES_CHECKER_EXIT_CODE=$?
    set -e
    REMOTE_ALPHA_DEPLOY_ES_BINARIES_CHECKER_RAN="true"
  fi

  [[ -s "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_CHECK_OUTPUT_PATH}" ]] || {
    remote_alpha_deploy_es_binaries_stage_note_wrapper_tooling_error "staged ES binary deployment helper did not produce local check-only JSON output"
    return 1
  }
  remote_alpha_deploy_es_binaries_stage_validate_check_report "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_CHECK_OUTPUT_PATH}" "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_CHECK_VALIDATION_META_PATH}" || {
    remote_alpha_deploy_es_binaries_stage_note_wrapper_tooling_error "staged ES binary deployment check-only output was malformed or violated the non-mutating helper contract"
    return 1
  }

  local overall deployment_needed
  overall="$(remote_alpha_deploy_es_binaries_json_field "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_CHECK_OUTPUT_PATH}" "overall_classification" 2>/dev/null || true)"
  deployment_needed="$(remote_alpha_deploy_es_binaries_json_field "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_CHECK_OUTPUT_PATH}" "plan.deployment_needed" 2>/dev/null || true)"
  if [[ -z "${overall}" ]]; then
    remote_alpha_deploy_es_binaries_stage_note_wrapper_tooling_error "staged ES binary deployment helper exit code did not match the validated overall classification"
    return 1
  fi
  if [[ "${overall}" == "blocker" ]]; then
    return 1
  fi
  if [[ "${REMOTE_ALPHA_OPERATION_MODE}" != "apply" ]]; then
    remote_alpha_deploy_es_binaries_stage_visible_cleanup_if_needed || return 1
    return 0
  fi

  if [[ "${deployment_needed}" != "true" ]]; then
    remote_alpha_deploy_es_binaries_stage_visible_cleanup_if_needed || return 1
    return 0
  fi

  if [[ "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_SUDO_MODE}" == "interactive" ]]; then
    remote_alpha_deploy_es_binaries_stage_remote_prepare_upload_root || {
      remote_alpha_deploy_es_binaries_stage_note_wrapper_tooling_error "could not prepare remote upload root for interactive ES binary deployment apply staging"
      return 1
    }
    remote_alpha_deploy_es_binaries_stage_upload_remote_tree "${local_upload_dir}" || {
      remote_alpha_deploy_es_binaries_stage_note_wrapper_tooling_error "could not copy staged ES binary deployment helper tree for interactive apply"
      return 1
    }
    set +e
    remote_alpha_deploy_es_binaries_stage_run_interactive_apply_sequence
    REMOTE_ALPHA_DEPLOY_ES_BINARIES_APPLY_EXIT_CODE=$?
    set -e
  else
    set +e
    remote_alpha_deploy_es_binaries_stage_run_remote_apply
    REMOTE_ALPHA_DEPLOY_ES_BINARIES_APPLY_EXIT_CODE=$?
    set -e
  fi
  REMOTE_ALPHA_DEPLOY_ES_BINARIES_APPLY_RAN="true"

  remote_alpha_deploy_es_binaries_stage_fetch_remote_file \
    "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_REMOTE_SUMMARY_PATH}" \
    "${REMOTE_ALPHA_STAGE_ES_BINARY_DEPLOY_APPLY_SUMMARY_OUTPUT_PATH}" || {
    remote_alpha_deploy_es_binaries_stage_note_wrapper_tooling_error "could not fetch remote ES binary deployment apply summary"
    return 1
  }
  remote_alpha_deploy_es_binaries_stage_visible_cleanup_if_needed || return 1
  if [[ "${REMOTE_ALPHA_DEPLOY_ES_BINARIES_APPLY_EXIT_CODE}" != "0" ]]; then
    return 1
  fi
}

remote_alpha_deploy_es_binaries_main() {
  if remote_alpha_deploy_es_binaries_has_ssh_target "$@"; then
    remote_alpha_deploy_es_binaries_stage_main "$@"
    return $?
  fi
  remote_alpha_deploy_es_binaries_host_main "$@"
}
