#!/usr/bin/env bash
set -euo pipefail

remote_alpha_check_es_writable_state_readiness_schema_version="execution-substrate.remote-alpha.es-writable-state-readiness.v1"
remote_alpha_check_es_writable_state_readiness_default_config_path="/etc/execution-substrate/es.json"
remote_alpha_check_es_writable_state_readiness_default_mode="alpha-compat"

remote_alpha_check_es_writable_state_readiness_defaults() {
  REMOTE_ALPHA_ES_WRITABLE_STATE_CONFIG_PATH="${REMOTE_ALPHA_ES_WRITABLE_STATE_CONFIG_PATH:-${remote_alpha_check_es_writable_state_readiness_default_config_path}}"
  REMOTE_ALPHA_ES_WRITABLE_STATE_CHECKER_MODE="${REMOTE_ALPHA_ES_WRITABLE_STATE_CHECKER_MODE:-${remote_alpha_check_es_writable_state_readiness_default_mode}}"
}

remote_alpha_check_es_writable_state_readiness_usage() {
  cat <<'EOF'
Usage:
  scripts/remote_alpha_check_es_writable_state_readiness.sh

Optional flags:
  --config-path </path/to/es.json>
  --mode <alpha-compat|future-non-root-required>
  --help

Default behavior is check-only, non-mutating, and writes JSON to stdout.
EOF
}

remote_alpha_check_es_writable_state_readiness_validate_mode() {
  case "${REMOTE_ALPHA_ES_WRITABLE_STATE_CHECKER_MODE}" in
    alpha-compat|future-non-root-required)
      ;;
    *)
      echo "unsupported checker mode: ${REMOTE_ALPHA_ES_WRITABLE_STATE_CHECKER_MODE}" >&2
      return 1
      ;;
  esac
}

remote_alpha_check_es_writable_state_readiness_parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --config-path)
        REMOTE_ALPHA_ES_WRITABLE_STATE_CONFIG_PATH="$2"
        shift 2
        ;;
      --mode)
        REMOTE_ALPHA_ES_WRITABLE_STATE_CHECKER_MODE="$2"
        shift 2
        ;;
      --help|-h)
        remote_alpha_check_es_writable_state_readiness_usage
        return 1
        ;;
      *)
        echo "unknown argument: $1" >&2
        remote_alpha_check_es_writable_state_readiness_usage >&2
        return 2
        ;;
    esac
  done
}

remote_alpha_check_es_writable_state_readiness_require_command() {
  local name=$1
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "${name} is required" >&2
    return 1
  fi
}

remote_alpha_check_es_writable_state_readiness_main() {
  remote_alpha_check_es_writable_state_readiness_defaults
  remote_alpha_check_es_writable_state_readiness_parse_args "$@" || return $?
  remote_alpha_check_es_writable_state_readiness_validate_mode
  remote_alpha_check_es_writable_state_readiness_require_command python3

  python3 - \
    "${remote_alpha_check_es_writable_state_readiness_schema_version}" \
    "${REMOTE_ALPHA_ES_WRITABLE_STATE_CONFIG_PATH}" \
    "${REMOTE_ALPHA_ES_WRITABLE_STATE_CHECKER_MODE}" <<'PY'
import json
import os
import pathlib
import stat
import subprocess
import sys
from datetime import datetime, timezone

SCHEMA_VERSION = sys.argv[1]
CONFIG_PATH = sys.argv[2]
CHECKER_MODE = sys.argv[3]
CHECKER_MODE_ALPHA_COMPAT = "alpha-compat"
CHECKER_MODE_FUTURE_NON_ROOT_REQUIRED = "future-non-root-required"
WORKLOAD_UID = 10000
WORKLOAD_GID = 10000
REQUIRED_MARKER_PATHS = {"run/platform", "run/work", "run/result"}
RESULT_BUNDLE_NAME = "result.tar.gz"
MARKER_NAME = "ownership-normalization.json"
MARKER_SCHEMA_VERSION = "execution-substrate.es.runtime-ownership-normalization.v1"

if CHECKER_MODE not in {CHECKER_MODE_ALPHA_COMPAT, CHECKER_MODE_FUTURE_NON_ROOT_REQUIRED}:
    raise SystemExit(f"unsupported checker mode: {CHECKER_MODE}")


def make_status(classification, summary, **kwargs):
    payload = {
        "classification": classification,
        "summary": summary,
    }
    payload.update(kwargs)
    return payload


def future_non_root_required():
    return CHECKER_MODE == CHECKER_MODE_FUTURE_NON_ROOT_REQUIRED


def future_gate_classification():
    return "blocker" if future_non_root_required() else "warning"


def marker_presence_policy():
    if future_non_root_required():
        return {
            "mode": "future_non_root_required",
            "missing_marker_classification": "blocker",
            "present_invalid_classification": "blocker",
            "expected_owner_required": True,
            "summary": "future non-root-required mode is a readiness gate only: completed-run marker absence blocks, invalid present markers block, and expected es UID:GID plus stat ownership proof are required",
        }
    return {
        "mode": "alpha_compatibility",
        "missing_marker_classification": "warning",
        "present_invalid_classification": "blocker",
        "expected_owner_required": False,
        "summary": "alpha-compatible mode remains a non-mutating compatibility check: missing markers warn, invalid present markers fail closed, and target-owner proof may remain unverified",
    }


def normalize_output(payload):
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def parse_rfc3339(value):
    if not isinstance(value, str):
        raise ValueError("value is not a string")
    normalized = value.strip()
    if not normalized:
        raise ValueError("value is empty")
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    return datetime.fromisoformat(normalized)


def run_command(args):
    try:
        return subprocess.run(args, check=False, capture_output=True, text=True)
    except FileNotFoundError:
        return None


def mode_string(mode_bits):
    return format(mode_bits & 0o7777, "04o")


def fallback_stat(path):
    target = os.fspath(path)
    try:
        info = os.lstat(target)
    except FileNotFoundError:
        return {
            "path": target,
            "exists": False,
            "uid": None,
            "gid": None,
            "mode": "",
            "mode_bits": 0,
            "file_type": "",
            "source": "lstat",
            "error": "not found",
        }
    except OSError as exc:
        return {
            "path": target,
            "exists": False,
            "uid": None,
            "gid": None,
            "mode": "",
            "mode_bits": 0,
            "file_type": "",
            "source": "lstat",
            "error": str(exc),
        }

    if stat.S_ISDIR(info.st_mode):
        file_type = "directory"
    elif stat.S_ISREG(info.st_mode):
        file_type = "regular file"
    elif stat.S_ISLNK(info.st_mode):
        file_type = "symbolic link"
    elif stat.S_ISSOCK(info.st_mode):
        file_type = "socket"
    else:
        file_type = "other"

    mode_bits = stat.S_IMODE(info.st_mode)
    return {
        "path": target,
        "exists": True,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": mode_string(mode_bits),
        "mode_bits": mode_bits,
        "file_type": file_type,
        "source": "lstat",
    }


def stat_path(path):
    target = os.fspath(path)
    proc = run_command(["stat", "-c", "%u\t%g\t%a\t%F", target])
    if proc is not None and proc.returncode == 0:
        parts = proc.stdout.strip().split("\t", 3)
        if len(parts) == 4:
            try:
                mode_bits = int(parts[2], 8)
                return {
                    "path": target,
                    "exists": True,
                    "uid": int(parts[0]),
                    "gid": int(parts[1]),
                    "mode": mode_string(mode_bits),
                    "mode_bits": mode_bits,
                    "file_type": parts[3].strip(),
                    "source": "stat",
                }
            except ValueError:
                pass
    return fallback_stat(target)


def directory_chain(path, include_self):
    target = pathlib.Path(path).absolute()
    if not include_self:
        target = target.parent
    ordered = list(reversed([target, *target.parents]))
    deduped = []
    for item in ordered:
        rendered = os.fspath(item)
        if not deduped or deduped[-1] != rendered:
            deduped.append(rendered)
    return deduped


def selected_permission_bits(stat_info, uid, gid):
    mode_bits = stat_info["mode_bits"]
    if uid == stat_info["uid"]:
        return (mode_bits >> 6) & 0o7
    if gid == stat_info["gid"]:
        return (mode_bits >> 3) & 0o7
    return mode_bits & 0o7


def ensure_traversable(path, uid, gid, include_self):
    checked = []
    for directory in directory_chain(path, include_self=include_self):
        directory_stat = stat_path(directory)
        checked.append(
            {
                "path": directory,
                "exists": directory_stat["exists"],
                "file_type": directory_stat["file_type"],
                "mode": directory_stat["mode"],
            }
        )
        if not directory_stat["exists"]:
            return False, checked, f"directory does not exist: {directory}"
        if directory_stat["file_type"] == "symbolic link":
            continue
        if directory_stat["file_type"] != "directory":
            return False, checked, f"path is not a directory: {directory}"
        if selected_permission_bits(directory_stat, uid, gid) & 0o1 == 0:
            return False, checked, f"directory is not traversable by target UID:GID: {directory}"
    return True, checked, ""


def inspect_directory_access(path, uid, gid):
    directory_stat = stat_path(path)
    result = {
        "path": os.fspath(path),
        "path_exists": directory_stat["exists"],
        "file_type": directory_stat["file_type"],
        "owner_uid": directory_stat["uid"],
        "owner_gid": directory_stat["gid"],
        "mode": directory_stat["mode"],
        "mode_bits": directory_stat["mode_bits"],
        "es_can_traverse": False,
        "es_can_read": False,
        "es_can_write": False,
        "es_can_manage_entries": False,
        "access_error": "",
    }
    if not directory_stat["exists"]:
        result["access_error"] = directory_stat.get("error", "path does not exist")
        return result
    if directory_stat["file_type"] != "directory":
        result["access_error"] = "path is not a directory"
        return result

    traversable, checked, error = ensure_traversable(path, uid, gid, include_self=True)
    result["traversal_chain"] = checked
    result["es_can_traverse"] = traversable
    if not traversable:
        result["access_error"] = error
        return result

    bits = selected_permission_bits(directory_stat, uid, gid)
    result["es_can_read"] = bool(bits & 0o4)
    result["es_can_write"] = bool(bits & 0o2)
    result["es_can_manage_entries"] = result["es_can_write"] and result["es_can_traverse"]
    return result


def inspect_file_access(path, uid, gid):
    file_stat = stat_path(path)
    result = {
        "path": os.fspath(path),
        "path_exists": file_stat["exists"],
        "file_type": file_stat["file_type"],
        "owner_uid": file_stat["uid"],
        "owner_gid": file_stat["gid"],
        "mode": file_stat["mode"],
        "mode_bits": file_stat["mode_bits"],
        "es_can_read": False,
        "es_can_write": False,
        "access_error": "",
    }
    if not file_stat["exists"]:
        result["access_error"] = file_stat.get("error", "path does not exist")
        return result

    traversable, checked, error = ensure_traversable(path, uid, gid, include_self=False)
    result["traversal_chain"] = checked
    if not traversable:
        result["access_error"] = error
        return result

    bits = selected_permission_bits(file_stat, uid, gid)
    result["es_can_read"] = bool(bits & 0o4)
    result["es_can_write"] = bool(bits & 0o2)
    return result


def load_config(path):
    rendered = os.fspath(path)
    cfg_path = pathlib.Path(rendered)
    if not cfg_path.is_file():
        return make_status(
            "blocker",
            f"ES config path is not readable: {rendered}",
            path=rendered,
            exists=cfg_path.exists(),
            execution={},
        )

    try:
        payload = json.loads(cfg_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return make_status(
            "blocker",
            f"ES config path is not valid JSON: {exc}",
            path=rendered,
            exists=True,
            execution={},
        )

    execution = payload.get("execution") or {}
    staging_root = str(execution.get("staging_root_dir") or "").strip()
    results_root = str(execution.get("results_root_dir") or "").strip()

    errors = []
    if not staging_root:
        errors.append("execution.staging_root_dir is missing")
    if not results_root:
        errors.append("execution.results_root_dir is missing")
    if staging_root and not os.path.isabs(staging_root):
        errors.append("execution.staging_root_dir is not absolute")
    if results_root and not os.path.isabs(results_root):
        errors.append("execution.results_root_dir is not absolute")
    if staging_root and results_root:
        try:
            common = os.path.commonpath([staging_root, results_root])
        except ValueError:
            common = ""
        if common in {staging_root, results_root}:
            errors.append("execution.results_root_dir overlaps execution.staging_root_dir")

    classification = "pass" if not errors else "blocker"
    summary = "ES execution roots were read from config" if not errors else "; ".join(errors)
    return make_status(
        classification,
        summary,
        path=rendered,
        exists=True,
        execution={
            "staging_root_dir": staging_root,
            "results_root_dir": results_root,
        },
    )


def lookup_es_account():
    uid_proc = run_command(["id", "-u", "es"])
    gid_proc = run_command(["id", "-g", "es"])
    group_proc = run_command(["id", "-gn", "es"])

    if (
        uid_proc is not None
        and gid_proc is not None
        and group_proc is not None
        and uid_proc.returncode == 0
        and gid_proc.returncode == 0
        and group_proc.returncode == 0
    ):
        return make_status(
            "pass",
            f"es account resolved as UID:GID {uid_proc.stdout.strip()}:{gid_proc.stdout.strip()}",
            present=True,
            uid=int(uid_proc.stdout.strip()),
            gid=int(gid_proc.stdout.strip()),
            group=group_proc.stdout.strip(),
        )

    passwd_entry = ""
    group_entry = ""
    passwd_proc = run_command(["getent", "passwd", "es"])
    group_lookup_proc = run_command(["getent", "group", "es"])
    if passwd_proc is not None and passwd_proc.returncode == 0:
        passwd_entry = passwd_proc.stdout.strip()
    if group_lookup_proc is not None and group_lookup_proc.returncode == 0:
        group_entry = group_lookup_proc.stdout.strip()

    errors = []
    for label, proc in (("uid", uid_proc), ("gid", gid_proc), ("group", group_proc)):
        if proc is None:
            errors.append(f"{label} lookup command is unavailable")
            continue
        if proc.returncode != 0:
            stderr = proc.stderr.strip() or proc.stdout.strip() or f"id lookup exited {proc.returncode}"
            errors.append(f"{label} lookup failed: {stderr}")

    return make_status(
        "blocker" if future_non_root_required() else "warning",
        (
            "es account is missing or not queryable on this host"
            if future_non_root_required()
            else "es account is missing or not queryable on this host; alpha-compatible mode reports target-owner proof as unverified evidence only"
        ),
        present=False,
        uid=None,
        gid=None,
        group="",
        lookup_errors=errors,
        passwd_entry=passwd_entry,
        group_entry=group_entry,
    )


def inspect_root_status(path_value, label, es_account):
    rendered = str(path_value or "").strip()
    if not rendered:
        return make_status(
            "not_observed",
            f"{label} is not configured",
            path=rendered,
            path_exists=False,
        )
    if not es_account.get("present"):
        path_stat = stat_path(rendered)
        return make_status(
            future_gate_classification(),
            (
                f"{label} cannot be evaluated without es UID:GID"
                if future_non_root_required()
                else f"{label} cannot be validated against es ownership in alpha-compatible mode because es UID:GID is unavailable"
            ),
            path=rendered,
            path_exists=path_stat["exists"],
            owner_uid=path_stat["uid"],
            owner_gid=path_stat["gid"],
            mode=path_stat["mode"],
        )

    access = inspect_directory_access(rendered, es_account["uid"], es_account["gid"])
    if not access["path_exists"]:
        return make_status(
            "not_observed",
            f"{label} does not exist on this host",
            **access,
            owner_matches_es=False,
        )

    owner_matches_es = (
        access["owner_uid"] == es_account["uid"] and access["owner_gid"] == es_account["gid"]
    )
    classification = "pass"
    reasons = []
    if not owner_matches_es:
        classification = future_gate_classification()
        reasons.append("owner is not es:es")
    if not access["es_can_traverse"]:
        classification = future_gate_classification()
        reasons.append("path is not traversable by es")
    if not access["es_can_read"]:
        classification = future_gate_classification()
        reasons.append("path is not readable by es")
    if not access["es_can_manage_entries"]:
        classification = future_gate_classification()
        reasons.append("path is not writable/deletable by es")

    summary = (
        f"{label} is ES-owned and writable/readable for future non-root ES"
        if classification == "pass"
        else (
            f"{label} is not ready for future non-root ES: {'; '.join(reasons)}"
            if future_non_root_required()
            else f"{label} is not yet future non-root-ready evidence in alpha-compatible mode: {'; '.join(reasons)}"
        )
    )
    return make_status(
        classification,
        summary,
        **access,
        owner_matches_es=owner_matches_es,
        expected_uid=es_account["uid"],
        expected_gid=es_account["gid"],
    )


def inspect_target_owner_consistency(staging_root_status, results_root_status):
    staging_exists = staging_root_status.get("path_exists")
    results_exists = results_root_status.get("path_exists")
    staging_uid = staging_root_status.get("owner_uid")
    staging_gid = staging_root_status.get("owner_gid")
    results_uid = results_root_status.get("owner_uid")
    results_gid = results_root_status.get("owner_gid")

    if not staging_exists or not results_exists:
        return make_status(
            "not_observed",
            "staging/results target owner consistency could not be compared because one or both roots were not observed",
            staging_root_path=staging_root_status.get("path"),
            results_root_path=results_root_status.get("path"),
            same_target_owner=None,
        )
    if None in {staging_uid, staging_gid, results_uid, results_gid}:
        return make_status(
            future_gate_classification(),
            (
                "staging/results target owner consistency could not be compared because one or both roots did not expose owner UID:GID"
                if future_non_root_required()
                else "staging/results target owner consistency could not be fully compared in alpha-compatible mode because one or both roots did not expose owner UID:GID"
            ),
            staging_root_path=staging_root_status.get("path"),
            results_root_path=results_root_status.get("path"),
            same_target_owner=None,
        )

    same_target_owner = staging_uid == results_uid and staging_gid == results_gid
    classification = "pass" if same_target_owner else future_gate_classification()
    summary = (
        f"execution.staging_root_dir and execution.results_root_dir resolve to the same target owner UID:GID {staging_uid}:{staging_gid}"
        if same_target_owner
        else (
            f"execution.staging_root_dir resolves to {staging_uid}:{staging_gid} but execution.results_root_dir resolves to {results_uid}:{results_gid}; future non-root ES requires one shared target owner model"
            if future_non_root_required()
            else f"execution.staging_root_dir resolves to {staging_uid}:{staging_gid} but execution.results_root_dir resolves to {results_uid}:{results_gid}; alpha-compatible mode keeps this as evidence only and does not claim future non-root readiness"
        )
    )
    return make_status(
        classification,
        summary,
        staging_root_path=staging_root_status.get("path"),
        results_root_path=results_root_status.get("path"),
        staging_root_owner={"uid": staging_uid, "gid": staging_gid},
        results_root_owner={"uid": results_uid, "gid": results_gid},
        same_target_owner=same_target_owner,
    )


def discover_retained_bundles(results_root):
    root = pathlib.Path(results_root)
    if not root.is_dir():
        return []
    bundles = []
    for child in sorted(root.iterdir()):
        bundle_path = child / RESULT_BUNDLE_NAME
        if bundle_path.exists():
            bundles.append(bundle_path)
    return bundles


def discover_retained_run_dirs(results_root):
    root = pathlib.Path(results_root)
    if not root.is_dir():
        return []
    return [child for child in sorted(root.iterdir()) if child.is_dir()]


def inspect_retained_results(results_root_status, es_account):
    if results_root_status["classification"] == "blocker":
        return make_status(
            "blocker" if future_non_root_required() else "warning",
            (
                "retained-result readiness is blocked because execution.results_root_dir is not ready"
                if future_non_root_required()
                else "retained-result future-readiness cannot be proven in alpha-compatible mode because execution.results_root_dir is not yet es-manageable"
            ),
            observed_bundles=[],
        )
    if not results_root_status.get("path_exists"):
        return make_status(
            "not_observed",
            "no execution.results_root_dir was observed on this host",
            observed_bundles=[],
        )
    bundles = discover_retained_bundles(results_root_status["path"])
    if not bundles:
        return make_status(
            "not_observed",
            "no retained-result bundles were observed under execution.results_root_dir",
            observed_bundles=[],
        )
    if not es_account.get("present"):
        return make_status(
            future_gate_classification(),
            (
                "retained-result readiness cannot be evaluated without es UID:GID"
                if future_non_root_required()
                else "retained-result bundles were observed, but alpha-compatible mode cannot verify future es readability without es UID:GID"
            ),
            observed_bundles=[],
        )

    observed = []
    blocking = False
    for bundle_path in bundles:
        access = inspect_file_access(bundle_path, es_account["uid"], es_account["gid"])
        owner_matches_es = (
            access["owner_uid"] == es_account["uid"] and access["owner_gid"] == es_account["gid"]
        )
        bundle_classification = "pass"
        reasons = []
        if access["file_type"] != "regular file":
            bundle_classification = future_gate_classification()
            reasons.append("bundle path is not a regular file")
        if not owner_matches_es:
            bundle_classification = future_gate_classification()
            reasons.append("bundle owner is not es:es")
        if not access["es_can_read"]:
            bundle_classification = future_gate_classification()
            reasons.append("bundle is not readable by es")
        if bundle_classification == "blocker":
            blocking = True
        observed.append(
            {
                "run_id": bundle_path.parent.name,
                "classification": bundle_classification,
                "summary": (
                    "retained bundle is readable by es"
                    if bundle_classification == "pass"
                    else "; ".join(reasons)
                ),
                **access,
                "owner_matches_es": owner_matches_es,
            }
        )

    return make_status(
        "blocker" if blocking else "pass",
        (
            "one or more retained-result bundles are not readable by future non-root ES"
            if blocking
            else (
                "observed retained-result bundles are readable by es"
                if future_non_root_required()
                else "observed retained-result bundles are readable under the current alpha-compatible host posture"
            )
        ),
        observed_bundles=observed,
    )


def marker_validation(marker_path, platform_dir, access_account, run_id, expected_owner=None, require_marker=False):
    validation_mode = "non_root_required" if require_marker else "alpha_compatibility"
    access_uid = access_account["uid"] if access_account is not None else os.getuid()
    access_gid = access_account["gid"] if access_account is not None else os.getgid()
    access = inspect_file_access(marker_path, access_uid, access_gid)
    payload = {
        "marker_path": os.fspath(marker_path),
        "marker_exists": access["path_exists"],
        "marker_access": access,
        "validation_mode": validation_mode,
        "require_marker": require_marker,
        "expected_uid": None if expected_owner is None else expected_owner["uid"],
        "expected_gid": None if expected_owner is None else expected_owner["gid"],
        "target_owner_checked": False,
        "target_owner_verified": False,
        "target_owner_status": "not_observed",
        "classification": "pass",
        "issues": [],
        "payload": None,
    }
    if not access["path_exists"]:
        payload["target_owner_status"] = "not_observed"
        if require_marker:
            payload["classification"] = "blocker"
            payload["issues"].append(
                "normalization marker is required for future non-root ES readiness but was not observed"
            )
        else:
            payload["classification"] = "warning"
            payload["issues"].append(
                "normalization marker not observed; Alpha compatibility mode still accepts marker absence"
            )
        return payload
    if access["file_type"] != "regular file":
        payload["classification"] = "blocker"
        payload["issues"].append("normalization marker is not a regular file")
        return payload

    try:
        marker_payload = json.loads(pathlib.Path(marker_path).read_text(encoding="utf-8"))
    except Exception as exc:
        payload["classification"] = "blocker"
        payload["issues"].append(f"normalization marker is not valid JSON: {exc}")
        return payload

    payload["payload"] = marker_payload
    if marker_payload.get("schema_version") != MARKER_SCHEMA_VERSION:
        payload["classification"] = "blocker"
        payload["issues"].append("normalization marker schema_version is invalid")
    if marker_payload.get("status") != "normalized":
        payload["classification"] = "blocker"
        payload["issues"].append("normalization marker status is not normalized")
    marker_run_id = str(marker_payload.get("run_id") or "").strip()
    if marker_run_id == "":
        payload["classification"] = "blocker"
        payload["issues"].append("normalization marker run_id is missing")
    elif marker_run_id != run_id:
        payload["classification"] = "blocker"
        payload["issues"].append("normalization marker run_id does not match the run-scoped stage root")
    try:
        parse_rfc3339(marker_payload.get("completed_at"))
    except Exception as exc:
        payload["classification"] = "blocker"
        payload["issues"].append(f"normalization marker completed_at is invalid: {exc}")

    normalized_paths = marker_payload.get("paths_normalized")
    if not isinstance(normalized_paths, list):
        payload["classification"] = "blocker"
        payload["issues"].append("normalization marker paths_normalized is not a list")
    else:
        observed_paths = {str(item).strip() for item in normalized_paths if str(item).strip()}
        missing_paths = sorted(REQUIRED_MARKER_PATHS - observed_paths)
        if missing_paths:
            payload["classification"] = "blocker"
            payload["issues"].append(
                "normalization marker is missing required paths: " + ", ".join(missing_paths)
            )

    platform_access = inspect_directory_access(platform_dir, access_uid, access_gid)
    workload_platform_access = inspect_directory_access(platform_dir, WORKLOAD_UID, WORKLOAD_GID)
    workload_marker_access = inspect_file_access(marker_path, WORKLOAD_UID, WORKLOAD_GID)
    payload["platform_access"] = platform_access
    payload["workload_platform_access"] = workload_platform_access
    payload["workload_marker_access"] = workload_marker_access

    if not platform_access["path_exists"] or platform_access["file_type"] != "directory":
        payload["classification"] = "blocker"
        payload["issues"].append("run/platform is missing for the normalization marker")
    else:
        if expected_owner is not None and (
            platform_access["owner_uid"] != expected_owner["uid"]
            or platform_access["owner_gid"] != expected_owner["gid"]
        ):
            payload["classification"] = "blocker"
            payload["issues"].append("run/platform is not ES-owned")
        if platform_access["mode_bits"] & 0o022 != 0:
            payload["classification"] = "blocker"
            payload["issues"].append("run/platform is group- or world-writable")

    if access["owner_uid"] == WORKLOAD_UID or access["owner_gid"] == WORKLOAD_GID:
        payload["classification"] = "blocker"
        payload["issues"].append("normalization marker is workload-owned")
    if access["mode_bits"] & 0o022 != 0:
        payload["classification"] = "blocker"
        payload["issues"].append("normalization marker is group- or world-writable")
    if workload_platform_access["es_can_write"]:
        payload["classification"] = "blocker"
        payload["issues"].append("run/platform remains workload-writable")
    if workload_marker_access["es_can_write"]:
        payload["classification"] = "blocker"
        payload["issues"].append("normalization marker is workload-writable")

    if expected_owner is None:
        payload["target_owner_status"] = "unverified"
        if payload["classification"] == "pass":
            payload["classification"] = "warning"
        payload["issues"].append(
            "normalization marker target owner was not checked; this is marker evidence only, not future non-root-ready proof"
        )
        return payload

    payload["target_owner_checked"] = True
    if marker_payload.get("target_uid") != expected_owner["uid"]:
        payload["classification"] = "blocker"
        payload["target_owner_status"] = "mismatch"
        payload["issues"].append("normalization marker target_uid does not match expected es UID")
    if marker_payload.get("target_gid") != expected_owner["gid"]:
        payload["classification"] = "blocker"
        payload["target_owner_status"] = "mismatch"
        payload["issues"].append("normalization marker target_gid does not match expected es GID")
    if payload["target_owner_status"] == "not_observed":
        payload["target_owner_status"] = "verified"
        payload["target_owner_verified"] = True

    return payload


def preserved_marker_validation(marker_path, results_dir, access_account, run_id, expected_owner=None, require_marker=False):
    validation_mode = "non_root_required" if require_marker else "alpha_compatibility"
    access_uid = access_account["uid"] if access_account is not None else os.getuid()
    access_gid = access_account["gid"] if access_account is not None else os.getgid()
    access = inspect_file_access(marker_path, access_uid, access_gid)
    payload = {
        "marker_path": os.fspath(marker_path),
        "marker_exists": access["path_exists"],
        "marker_access": access,
        "validation_mode": validation_mode,
        "require_marker": require_marker,
        "expected_uid": None if expected_owner is None else expected_owner["uid"],
        "expected_gid": None if expected_owner is None else expected_owner["gid"],
        "target_owner_checked": False,
        "target_owner_verified": False,
        "target_owner_status": "not_observed",
        "classification": "pass",
        "issues": [],
        "payload": None,
        "evidence_source": "retained_result_preserved_marker",
    }
    if not access["path_exists"]:
        payload["target_owner_status"] = "not_observed"
        if require_marker:
            payload["classification"] = "blocker"
            payload["issues"].append(
                "preserved normalization evidence is required for future non-root ES readiness but was not observed"
            )
        else:
            payload["classification"] = "warning"
            payload["issues"].append(
                "preserved normalization evidence not observed; Alpha compatibility mode still accepts marker absence"
            )
        return payload
    if access["file_type"] != "regular file":
        payload["classification"] = "blocker"
        payload["issues"].append("preserved normalization evidence is not a regular file")
        return payload

    try:
        marker_payload = json.loads(pathlib.Path(marker_path).read_text(encoding="utf-8"))
    except Exception as exc:
        payload["classification"] = "blocker"
        payload["issues"].append(f"preserved normalization evidence is not valid JSON: {exc}")
        return payload

    payload["payload"] = marker_payload
    if marker_payload.get("schema_version") != MARKER_SCHEMA_VERSION:
        payload["classification"] = "blocker"
        payload["issues"].append("preserved normalization evidence schema_version is invalid")
    if marker_payload.get("status") != "normalized":
        payload["classification"] = "blocker"
        payload["issues"].append("preserved normalization evidence status is not normalized")
    marker_run_id = str(marker_payload.get("run_id") or "").strip()
    if marker_run_id == "":
        payload["classification"] = "blocker"
        payload["issues"].append("preserved normalization evidence run_id is missing")
    elif marker_run_id != run_id:
        payload["classification"] = "blocker"
        payload["issues"].append("preserved normalization evidence run_id does not match the retained-result directory")
    try:
        parse_rfc3339(marker_payload.get("completed_at"))
    except Exception as exc:
        payload["classification"] = "blocker"
        payload["issues"].append(f"preserved normalization evidence completed_at is invalid: {exc}")

    normalized_paths = marker_payload.get("paths_normalized")
    if not isinstance(normalized_paths, list):
        payload["classification"] = "blocker"
        payload["issues"].append("preserved normalization evidence paths_normalized is not a list")
    else:
        observed_paths = {str(item).strip() for item in normalized_paths if str(item).strip()}
        missing_paths = sorted(REQUIRED_MARKER_PATHS - observed_paths)
        if missing_paths:
            payload["classification"] = "blocker"
            payload["issues"].append(
                "preserved normalization evidence is missing required paths: " + ", ".join(missing_paths)
            )

    results_access = inspect_directory_access(results_dir, access_uid, access_gid)
    payload["results_dir_access"] = results_access
    if not results_access["path_exists"] or results_access["file_type"] != "directory":
        payload["classification"] = "blocker"
        payload["issues"].append("retained-result directory is missing for preserved normalization evidence")
    else:
        if expected_owner is not None and (
            results_access["owner_uid"] != expected_owner["uid"]
            or results_access["owner_gid"] != expected_owner["gid"]
        ):
            payload["classification"] = "blocker"
            payload["issues"].append("retained-result directory is not ES-owned")
        if results_access["mode_bits"] & 0o022 != 0:
            payload["classification"] = "blocker"
            payload["issues"].append("retained-result directory is group- or world-writable")

    if access["mode_bits"] & 0o022 != 0:
        payload["classification"] = "blocker"
        payload["issues"].append("preserved normalization evidence is group- or world-writable")

    if expected_owner is None:
        payload["target_owner_status"] = "unverified"
        if payload["classification"] == "pass":
            payload["classification"] = "warning"
        payload["issues"].append(
            "preserved normalization evidence target owner was not checked; this is evidence only, not future non-root-ready proof"
        )
        return payload

    payload["target_owner_checked"] = True
    if marker_payload.get("target_uid") != expected_owner["uid"]:
        payload["classification"] = "blocker"
        payload["target_owner_status"] = "mismatch"
        payload["issues"].append("preserved normalization evidence target_uid does not match expected es UID")
    if marker_payload.get("target_gid") != expected_owner["gid"]:
        payload["classification"] = "blocker"
        payload["target_owner_status"] = "mismatch"
        payload["issues"].append("preserved normalization evidence target_gid does not match expected es GID")
    if payload["target_owner_status"] == "not_observed":
        payload["target_owner_status"] = "verified"
        payload["target_owner_verified"] = True

    return payload


def append_future_gap(run_blockers, run_warnings, message):
    if future_non_root_required():
        run_blockers.append(message)
    else:
        run_warnings.append(message)


def inspect_completed_run_candidates(staging_root_status, results_root_status, es_account):
    if staging_root_status["classification"] == "blocker" and es_account.get("present") and future_non_root_required():
        return make_status(
            "blocker",
            "runtime normalization readiness is blocked because execution.staging_root_dir is not ready",
            observed_runs=[],
        )
    if not staging_root_status.get("path_exists"):
        return make_status(
            "not_observed",
            "no run-scoped staging roots were observed",
            observed_runs=[],
        )
    staging_root = pathlib.Path(staging_root_status["path"])
    results_root = pathlib.Path(results_root_status["path"]) if results_root_status.get("path") else None
    if not es_account.get("present"):
        observed_runs = []
        candidate_ids = set()
        for run_dir in sorted(p for p in staging_root.iterdir() if p.is_dir()):
            candidate_ids.add(run_dir.name)
        if results_root is not None:
            for retained_run_dir in discover_retained_run_dirs(results_root):
                candidate_ids.add(retained_run_dir.name)
        for run_id in sorted(candidate_ids):
            run_dir = staging_root / run_id
            marker_path = run_dir / "run" / "platform" / MARKER_NAME
            platform_dir = run_dir / "run" / "platform"
            retained_run_dir = results_root / run_id if results_root is not None else None
            preserved_marker_path = retained_run_dir / MARKER_NAME if retained_run_dir is not None else None
            retained_bundle = retained_run_dir / RESULT_BUNDLE_NAME if retained_run_dir is not None else None
            marker_exists = marker_path.exists() if run_dir.is_dir() else False
            preserved_marker_exists = preserved_marker_path.exists() if preserved_marker_path is not None else False
            bundle_exists = retained_bundle is not None and retained_bundle.exists()
            evidence_exists = marker_exists or preserved_marker_exists or bundle_exists
            if not evidence_exists:
                continue
            if marker_exists:
                marker_info = marker_validation(
                    marker_path,
                    platform_dir,
                    None,
                    run_id,
                    expected_owner=None,
                    require_marker=False,
                )
                summary = "marker evidence is present but target-owner proof is unverified because es UID:GID is unavailable"
            else:
                marker_info = preserved_marker_validation(
                    preserved_marker_path,
                    retained_run_dir,
                    None,
                    run_id,
                    expected_owner=None,
                    require_marker=False,
                )
                summary = "preserved retained-result evidence is present but target-owner proof is unverified because es UID:GID is unavailable"
            observed_runs.append(
                {
                    "run_id": run_id,
                    "classification": "warning",
                    "summary": summary,
                    "marker": marker_info,
                    "retained_bundle_path": os.fspath(retained_bundle) if retained_bundle is not None else "",
                    "retained_bundle_exists": bundle_exists,
                    "stage_root_present": run_dir.is_dir(),
                }
            )
        if not observed_runs:
            return make_status(
                "blocker" if future_non_root_required() else "warning",
                (
                    "runtime normalization readiness cannot be evaluated without es UID:GID"
                    if future_non_root_required()
                    else "runtime normalization evidence cannot be verified against es ownership in alpha-compatible mode because es UID:GID is unavailable"
                ),
                observed_runs=[],
            )
        return make_status(
            "blocker" if future_non_root_required() else "warning",
            (
                "runtime normalization readiness cannot be evaluated without es UID:GID"
                if future_non_root_required()
                else "observed completed run candidates carry only unverified marker evidence because es UID:GID is unavailable"
            ),
            observed_runs=observed_runs,
        )

    observed_runs = []
    blocking = False
    warning = False

    candidate_ids = set()
    for run_dir in sorted(p for p in staging_root.iterdir() if p.is_dir()):
        candidate_ids.add(run_dir.name)
    if results_root is not None:
        for retained_run_dir in discover_retained_run_dirs(results_root):
            candidate_ids.add(retained_run_dir.name)

    for run_id in sorted(candidate_ids):
        run_dir = staging_root / run_id
        marker_path = run_dir / "run" / "platform" / MARKER_NAME
        platform_dir = run_dir / "run" / "platform"
        work_dir = run_dir / "run" / "work"
        result_dir = run_dir / "run" / "result"
        retained_run_dir = results_root / run_id if results_root is not None else None
        preserved_marker_path = retained_run_dir / MARKER_NAME if retained_run_dir is not None else None
        retained_bundle = retained_run_dir / RESULT_BUNDLE_NAME if retained_run_dir is not None else None

        stage_root_present = run_dir.is_dir()
        marker_exists = marker_path.exists() if stage_root_present else False
        preserved_marker_exists = preserved_marker_path.exists() if preserved_marker_path is not None else False
        bundle_exists = retained_bundle is not None and retained_bundle.exists()
        completed_candidate = marker_exists or preserved_marker_exists or bundle_exists
        if not completed_candidate:
            continue

        run_issues = []
        run_warnings = []
        stage_access = None
        work_access = None
        result_access = None
        if stage_root_present:
            stage_access = inspect_directory_access(run_dir, es_account["uid"], es_account["gid"])
            if not (
                stage_access["path_exists"]
                and stage_access["owner_uid"] == es_account["uid"]
                and stage_access["owner_gid"] == es_account["gid"]
                and stage_access["es_can_manage_entries"]
            ):
                append_future_gap(run_issues, run_warnings, "run-scoped stage root is not ES-owned and deletable")

        if marker_exists:
            marker_info = marker_validation(
                marker_path,
                platform_dir,
                es_account,
                run_id,
                expected_owner={"uid": es_account["uid"], "gid": es_account["gid"]} if future_non_root_required() else None,
                require_marker=future_non_root_required(),
            )
        else:
            marker_info = preserved_marker_validation(
                preserved_marker_path,
                retained_run_dir,
                es_account,
                run_id,
                expected_owner={"uid": es_account["uid"], "gid": es_account["gid"]} if future_non_root_required() else None,
                require_marker=future_non_root_required(),
            )
        if marker_info["classification"] == "blocker":
            run_issues.extend(marker_info["issues"])
        elif marker_info["classification"] == "warning":
            run_warnings.extend(marker_info["issues"])

        if stage_root_present:
            work_access = inspect_directory_access(work_dir, es_account["uid"], es_account["gid"])
            if not work_access["path_exists"]:
                append_future_gap(run_issues, run_warnings, "run/work is missing for a completed run candidate")
            elif not (
                work_access["owner_uid"] == es_account["uid"]
                and work_access["owner_gid"] == es_account["gid"]
                and work_access["es_can_manage_entries"]
                and work_access["es_can_read"]
            ):
                append_future_gap(
                    run_issues,
                    run_warnings,
                    "run/work is not normalized to ES-owned readable/deletable state",
                )

            result_access = inspect_directory_access(result_dir, es_account["uid"], es_account["gid"])
            if not result_access["path_exists"]:
                append_future_gap(run_issues, run_warnings, "run/result is missing for a completed run candidate")
            elif not (
                result_access["owner_uid"] == es_account["uid"]
                and result_access["owner_gid"] == es_account["gid"]
                and result_access["es_can_read"]
                and result_access["es_can_traverse"]
            ):
                append_future_gap(
                    run_issues,
                    run_warnings,
                    "run/result is not normalized to ES-owned readable state",
                )
        elif not bundle_exists:
            append_future_gap(run_issues, run_warnings, "retained-result bundle is missing for preserved normalization evidence")

        run_classification = "blocker" if run_issues else "warning" if run_warnings else "pass"
        if run_classification == "blocker":
            blocking = True
        elif run_classification == "warning":
            warning = True

        observed_runs.append(
            {
                "run_id": run_id,
                "classification": run_classification,
                "summary": (
                    "completed run shows normalization evidence compatible with future non-root ES, including verified target ownership"
                    if run_classification == "pass"
                    else "; ".join(run_issues if run_issues else run_warnings)
                ),
                "stage_root": stage_access,
                "work_dir": work_access,
                "result_dir": result_access,
                "marker": marker_info,
                "retained_bundle_path": os.fspath(retained_bundle) if retained_bundle is not None else "",
                "retained_bundle_exists": bundle_exists,
                "stage_root_present": stage_root_present,
            }
        )

    if not observed_runs:
        return make_status(
            "not_observed",
            "no completed-run normalization evidence was observed under staging or preserved retained-result evidence",
            observed_runs=[],
        )

    return make_status(
        "blocker" if blocking else "warning" if warning else "pass",
        (
            "one or more completed run candidates are missing valid normalization evidence"
            if blocking
            else (
                "observed completed run candidates carry only unverified marker evidence and are not future non-root-ready proof"
                if warning
                else "observed completed run candidates satisfy the normalization contract"
            )
        ),
        observed_runs=observed_runs,
    )


def build_cleanup_status(staging_root_status, runtime_status):
    if staging_root_status["classification"] == "blocker":
        return make_status(
            "blocker" if future_non_root_required() else "warning",
            (
                "successful cleanup would not be ready for future non-root ES because execution.staging_root_dir is blocked"
                if future_non_root_required()
                else "successful cleanup remains future-readiness evidence only in alpha-compatible mode because execution.staging_root_dir is not yet es-manageable"
            ),
        )
    if runtime_status["classification"] == "blocker":
        return make_status(
            "blocker",
            (
                "successful cleanup would fail closed because completed runs are missing valid normalization evidence"
                if future_non_root_required()
                else "successful cleanup would fail closed because an invalid present normalization marker was observed"
            ),
        )
    if runtime_status["classification"] == "pass":
        return make_status(
            "pass",
            (
                "successful cleanup prerequisites are satisfied for the observed completed runs"
                if future_non_root_required()
                else "successful cleanup observations are alpha-compatible and do not require marker presence by default"
            ),
        )
    if runtime_status["classification"] == "warning":
        return make_status(
            "warning",
            (
                "successful cleanup remains blocked from future non-root-ready proof because completed runs carry only unverified marker evidence"
                if future_non_root_required()
                else "successful cleanup remains alpha-compatible, but the observed completed runs do not yet prove future non-root readiness"
            ),
        )
    if staging_root_status["classification"] == "pass":
        return make_status(
            "warning",
            (
                "execution.staging_root_dir is ES-manageable, but no completed-run normalization evidence was observed yet"
                if future_non_root_required()
                else "execution.staging_root_dir is available, but no completed-run normalization evidence was observed yet"
            ),
        )
    return make_status(
        "not_observed",
        "successful cleanup readiness was not observed",
    )


def overall_classification(*statuses):
    classes = [status["classification"] for status in statuses]
    if "blocker" in classes:
        return "blocker"
    if "warning" in classes:
        return "warning"
    if "pass" in classes:
        return "pass"
    return "not_observed"


def summarize_target_owner_verification(runtime_status):
    observed_runs = runtime_status.get("observed_runs") or []
    marker_statuses = []
    for run in observed_runs:
        marker = run.get("marker") or {}
        status = marker.get("target_owner_status")
        if status:
            marker_statuses.append(str(status))
    if not marker_statuses:
        return {
            "status": "not_observed",
            "summary": "no normalization-marker target-owner evidence was observed",
            "checked_against_expected_owner": future_non_root_required(),
        }
    unique = set(marker_statuses)
    if unique == {"verified"}:
        return {
            "status": "verified",
            "summary": "observed normalization markers match the expected es UID:GID",
            "checked_against_expected_owner": True,
        }
    if "mismatch" in unique:
        return {
            "status": "mismatch",
            "summary": "one or more observed normalization markers do not match the expected es UID:GID",
            "checked_against_expected_owner": future_non_root_required(),
        }
    if "unverified" in unique:
        return {
            "status": "unverified",
            "summary": "observed normalization markers remain evidence only because expected es UID:GID was not required or not available",
            "checked_against_expected_owner": future_non_root_required(),
        }
    if "not_observed" in unique:
        return {
            "status": "not_observed",
            "summary": "normalization marker target-owner proof was not observed",
            "checked_against_expected_owner": future_non_root_required(),
        }
    return {
        "status": "mixed",
        "summary": "observed normalization markers carry mixed target-owner verification states",
        "checked_against_expected_owner": future_non_root_required(),
    }


def collect_findings(statuses):
    blockers = []
    warnings = []
    for scope, status in statuses:
        classification = status.get("classification")
        entry = {
            "scope": scope,
            "summary": status.get("summary", ""),
        }
        if classification == "blocker":
            blockers.append(entry)
        elif classification == "warning":
            warnings.append(entry)
    return blockers, warnings


config_status = load_config(CONFIG_PATH)
es_account_status = lookup_es_account()
execution = config_status.get("execution") or {}
staging_root = execution.get("staging_root_dir") or ""
results_root = execution.get("results_root_dir") or ""

staging_root_status = inspect_root_status(staging_root, "execution.staging_root_dir", es_account_status)
results_root_status = inspect_root_status(results_root, "execution.results_root_dir", es_account_status)
target_owner_consistency_status = inspect_target_owner_consistency(staging_root_status, results_root_status)
retained_result_status = inspect_retained_results(results_root_status, es_account_status)
runtime_status = inspect_completed_run_candidates(staging_root_status, results_root_status, es_account_status)
cleanup_status = build_cleanup_status(staging_root_status, runtime_status)

bounded_compatibility_edges = [
    {
        "name": "root_start_runtime_helper",
        "classification": "warning",
        "summary": "root-start runtime helper remains an explicit Option B compatibility edge and is not a blocker by itself for this writable-state readiness check",
    },
    {
        "name": "nomad_task_user_0_0",
        "classification": "warning",
        "summary": 'Nomad task User: "0:0" remains an explicit Option B compatibility edge and is not a blocker by itself for this writable-state readiness check',
    },
    {
        "name": "helper_private_spire_traversal",
        "classification": "warning",
        "summary": "helper-private SPIRE traversal remains an explicit Option B compatibility edge and is not a blocker by itself for this writable-state readiness check",
    },
    {
        "name": "broad_root_selector_scope",
        "classification": "warning",
        "summary": "broad root selector scope remains an explicit Option B compatibility edge and is not a blocker by itself for this writable-state readiness check",
    },
]

overall = overall_classification(
    config_status,
    es_account_status,
    staging_root_status,
    results_root_status,
    target_owner_consistency_status,
    retained_result_status,
    cleanup_status,
    runtime_status,
)
target_owner_verification = summarize_target_owner_verification(runtime_status)
blockers, warnings = collect_findings(
    [
        ("config_status", config_status),
        ("es_account_status", es_account_status),
        ("staging_root_status", staging_root_status),
        ("results_root_status", results_root_status),
        ("target_owner_consistency_status", target_owner_consistency_status),
        ("retained_result_readiness_status", retained_result_status),
        ("cleanup_readiness_status", cleanup_status),
        ("runtime_normalization_contract_status", runtime_status),
    ]
)

payload = {
    "schema_version": SCHEMA_VERSION,
    "checked_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "operation_mode": "check_only",
    "non_mutating": True,
    "checker_mode": CHECKER_MODE,
    "future_non_root_required": future_non_root_required(),
    "future_non_root_ready": future_non_root_required() and overall == "pass",
    "marker_presence_policy": marker_presence_policy(),
    "target_owner_verification": target_owner_verification,
    "blockers": blockers,
    "warnings": warnings,
    "config_path": CONFIG_PATH,
    "overall_classification": overall,
    "config_status": config_status,
    "es_account_status": es_account_status,
    "staging_root_status": staging_root_status,
    "results_root_status": results_root_status,
    "target_owner_consistency_status": target_owner_consistency_status,
    "retained_result_readiness_status": retained_result_status,
    "cleanup_readiness_status": cleanup_status,
    "runtime_normalization_contract_status": runtime_status,
    "bounded_compatibility_edges": bounded_compatibility_edges,
}

sys.stdout.write(normalize_output(payload))
sys.exit(1 if payload["overall_classification"] == "blocker" else 0)
PY
}
