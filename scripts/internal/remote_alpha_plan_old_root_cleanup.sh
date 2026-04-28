#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${REPO_ROOT:-}" ]]; then
  REMOTE_ALPHA_PLAN_OLD_ROOT_CLEANUP_HELPER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  REPO_ROOT="$(cd "${REMOTE_ALPHA_PLAN_OLD_ROOT_CLEANUP_HELPER_DIR}/../.." && pwd)"
fi

remote_alpha_plan_old_root_cleanup_usage() {
  cat <<'EOF'
Usage:
  scripts/remote_alpha_plan_old_root_cleanup.sh [options] [<apply-summary-or-dir>...]

Options:
  --rollback-window <active|closed>
      Planning status for the rollback window. Defaults to active.
  --archive-evidence <not-captured|captured>
      Whether required non-secret archive evidence has already been captured
      outside the live host. Defaults to not-captured.
  --output </path/to/plan.json>
      Write the JSON plan to a file and print that file path.
  --help, -h
      Show this help text.

Default behavior is repo-local and non-mutating. The helper reads only local
apply-summary artifacts, does not SSH, does not use sudo, and does not mutate
the live host.
EOF
}

remote_alpha_plan_old_root_cleanup_main() {
  local rollback_window="active"
  local archive_evidence="not-captured"
  local output_path=""
  local -a inputs=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --rollback-window)
        if [[ $# -lt 2 ]]; then
          echo "--rollback-window requires a value" >&2
          return 2
        fi
        rollback_window="$2"
        shift 2
        ;;
      --archive-evidence)
        if [[ $# -lt 2 ]]; then
          echo "--archive-evidence requires a value" >&2
          return 2
        fi
        archive_evidence="$2"
        shift 2
        ;;
      --output)
        if [[ $# -lt 2 ]]; then
          echo "--output requires a path" >&2
          return 2
        fi
        output_path="$2"
        shift 2
        ;;
      --ssh-target)
        echo "remote alpha old-root cleanup planner does not accept --ssh-target; provide local apply-summary artifacts instead" >&2
        return 2
        ;;
      --help|-h)
        remote_alpha_plan_old_root_cleanup_usage
        return 0
        ;;
      --)
        shift
        while [[ $# -gt 0 ]]; do
          inputs+=("$1")
          shift
        done
        ;;
      -*)
        echo "unknown argument: $1" >&2
        remote_alpha_plan_old_root_cleanup_usage >&2
        return 2
        ;;
      *)
        inputs+=("$1")
        shift
        ;;
    esac
  done

  case "${rollback_window}" in
    active|closed)
      ;;
    *)
      echo "remote alpha old-root cleanup planner requires --rollback-window active|closed" >&2
      return 2
      ;;
  esac

  case "${archive_evidence}" in
    not-captured|captured)
      ;;
    *)
      echo "remote alpha old-root cleanup planner requires --archive-evidence not-captured|captured" >&2
      return 2
      ;;
  esac

  python3 - "${REPO_ROOT}" "${rollback_window}" "${archive_evidence}" "${output_path}" "${inputs[@]}" <<'PY'
import json
import os
import pathlib
import re
import sys
from datetime import datetime, timezone

SCHEMA_VERSION = "execution-substrate.remote-alpha.old-root-cleanup-plan.v1"
PATH_PATTERN = re.compile(r"^/.*(?:\.pre-es-writable-state-ownership-|\.reconcile-es-writable-state-ownership-).*$")


def json_pointer_escape(part):
    return part.replace("~", "~0").replace("/", "~1")


def walk_strings(value, pointer=""):
    if isinstance(value, dict):
        for key, nested in value.items():
            next_pointer = pointer + "/" + json_pointer_escape(str(key))
            yield from walk_strings(nested, next_pointer)
        return
    if isinstance(value, list):
        for index, nested in enumerate(value):
            next_pointer = pointer + "/" + str(index)
            yield from walk_strings(nested, next_pointer)
        return
    if isinstance(value, str):
        yield pointer or "/", value


def collect_artifacts(repo_root, raw_inputs):
    search_mode = "explicit_inputs"
    artifact_paths = []
    errors = []

    def add_file(path_obj):
        artifact_paths.append(path_obj.resolve())

    def add_input(path_text):
        path_obj = pathlib.Path(path_text)
        if not path_obj.is_absolute():
            path_obj = pathlib.Path.cwd() / path_obj
        if path_obj.is_file():
            add_file(path_obj)
            return
        if path_obj.is_dir():
            for candidate in sorted(path_obj.rglob("*apply-summary*.json")):
                if candidate.is_file():
                    add_file(candidate)
            return
        errors.append(f"input does not exist: {path_text}")

    for item in raw_inputs:
        add_input(item)

    if artifact_paths:
        unique = []
        seen = set()
        for item in artifact_paths:
            if item not in seen:
                seen.add(item)
                unique.append(item)
        return search_mode, unique, errors

    if raw_inputs:
        return search_mode, [], errors

    search_mode = "default_repo_out"
    default_root = pathlib.Path(repo_root) / ".out"
    if default_root.is_dir():
        for candidate in sorted(default_root.rglob("*apply-summary*.json")):
            if candidate.is_file():
                artifact_paths.append(candidate.resolve())
    return search_mode, artifact_paths, errors


def classify_root_kind(path_text):
    if ".pre-es-writable-state-ownership-" in path_text:
        return "preserved_root_rotation"
    if ".reconcile-es-writable-state-ownership-" in path_text:
        return "artifact_reconciliation_quarantine_root"
    return "unknown"


def infer_role(path_text, references):
    joined = " ".join([path_text] + [ref["json_pointer"] for ref in references]).lower()
    if "staging" in joined:
        return "staging"
    if "results" in joined:
        return "results"
    return "unknown"


def root_reason(root_kind, role):
    if root_kind == "preserved_root_rotation":
        if role == "staging":
            return "Old live staging root preserved during maintenance-window root rotation for rollback/debug/evidence."
        if role == "results":
            return "Old live results root preserved during maintenance-window root rotation for rollback/debug/evidence."
        return "Old live root preserved during maintenance-window root rotation for rollback/debug/evidence."
    if root_kind == "artifact_reconciliation_quarantine_root":
        if role == "staging":
            return "Quarantine root created during bounded artifact reconciliation to move incompatible stage roots outside the live staging tree."
        if role == "results":
            return "Quarantine root created during bounded artifact reconciliation to move incompatible retained-result roots outside the live results tree."
        return "Quarantine root created during bounded artifact reconciliation for incompatible preserved content."
    return "Preserved root referenced by apply-summary evidence."


def recommended_action(rollback_window, archive_evidence):
    if rollback_window == "active":
        return "retain"
    if archive_evidence != "captured":
        return "archive_later"
    return "delete_later"


def deletion_preconditions(root_kind):
    items = [
        "A separate cleanup/archive action is explicitly approved for this host and maintenance window.",
        "The rollback window is closed and operators have confirmed that no rollback still depends on the preserved root.",
        "The apply summary, backup snapshot, rollback notes, and any required non-secret support-bundle or checkpoint evidence are retained outside the live host.",
        "Operators have confirmed the preserved root contains no active, unknown, or still-needed debug state.",
    ]
    if root_kind == "preserved_root_rotation":
        items.extend(
            [
                "The fresh live execution.staging_root_dir and execution.results_root_dir are still accepted and no restore move-back of the preserved roots is planned.",
                "Any historical owner/mode evidence needed for audit or debugging has been archived without recursively re-owning the preserved contents.",
            ]
        )
    elif root_kind == "artifact_reconciliation_quarantine_root":
        items.extend(
            [
                "Any quarantined retained-result bundles, normalization evidence, or stage-root contents needed for future readiness or debugging have been archived separately.",
                "Operators have confirmed that exposing the quarantined path back under the live ES roots is no longer required.",
            ]
        )
    return items


def root_warnings(rollback_window, action):
    warnings = []
    if rollback_window == "active":
        warnings.append("Rollback window is still active; keep this root retained and do not archive or delete it yet.")
    elif action == "archive_later":
        warnings.append("Rollback window is closed, but archive evidence is not yet marked captured; archive planning must be completed before deletion is considered.")
    return warnings


def main():
    repo_root, rollback_window, archive_evidence, output_path, *raw_inputs = sys.argv[1:]
    search_mode, artifact_paths, errors = collect_artifacts(repo_root, raw_inputs)
    if errors:
        for item in errors:
            print(item, file=sys.stderr)
        sys.exit(1)
    if not artifact_paths:
        print("no local apply-summary artifacts were found for old-root cleanup planning", file=sys.stderr)
        sys.exit(1)

    roots = {}
    decode_errors = []
    for artifact_path in artifact_paths:
        try:
            with open(artifact_path, encoding="utf-8") as handle:
                payload = json.load(handle)
        except Exception as exc:  # noqa: BLE001
            decode_errors.append(f"failed to read {artifact_path}: {exc}")
            continue
        for pointer, value in walk_strings(payload):
            if not PATH_PATTERN.match(value):
                continue
            entry = roots.setdefault(
                value,
                {
                    "path": value,
                    "source_references": [],
                },
            )
            reference = {
                "artifact_path": os.fspath(artifact_path),
                "json_pointer": pointer,
            }
            if reference not in entry["source_references"]:
                entry["source_references"].append(reference)

    if decode_errors:
        for item in decode_errors:
            print(item, file=sys.stderr)
        sys.exit(1)

    root_items = []
    action = recommended_action(rollback_window, archive_evidence)
    for path_text in sorted(roots):
        entry = roots[path_text]
        root_kind = classify_root_kind(path_text)
        role = infer_role(path_text, entry["source_references"])
        item = {
            "path": path_text,
            "root_kind": root_kind,
            "role": role,
            "source_references": entry["source_references"],
            "recommended_action": action,
            "reason": root_reason(root_kind, role),
            "preconditions_before_deletion": deletion_preconditions(root_kind),
            "warnings": root_warnings(rollback_window, action),
        }
        root_items.append(item)

    warnings = []
    if rollback_window == "active":
        warnings.append("Rollback window is still active; preserved old roots remain retain-only planning targets.")
    elif archive_evidence != "captured":
        warnings.append("Archive evidence is not yet marked captured; deletion is still deferred even though the rollback window is closed.")
    if not root_items:
        warnings.append("No preserved old-root paths were referenced by the supplied apply-summary artifacts.")

    if root_items and action == "retain":
        summary = f"Found {len(root_items)} preserved old-root paths in local apply-summary artifacts; keep them retained while the rollback window remains active."
    elif root_items and action == "archive_later":
        summary = f"Found {len(root_items)} preserved old-root paths in local apply-summary artifacts; archive planning is the next later step before any deletion is considered."
    elif root_items:
        summary = f"Found {len(root_items)} preserved old-root paths in local apply-summary artifacts; deletion may be planned later only after the documented preconditions are satisfied."
    else:
        summary = "No preserved old-root paths were referenced by the supplied apply-summary artifacts."

    plan = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "non_mutating": True,
        "local_only": True,
        "ssh_used": False,
        "sudo_used": False,
        "archive_mutation_implemented": False,
        "delete_mutation_implemented": False,
        "rollback_window": {
            "status": rollback_window,
            "warning_active": rollback_window == "active",
        },
        "archive_evidence": {
            "status": archive_evidence,
        },
        "inputs": {
            "search_mode": search_mode,
            "artifacts": [os.fspath(path) for path in artifact_paths],
        },
        "roots": root_items,
        "warnings": warnings,
        "summary": summary,
        "result": {
            "status": "pass",
            "ok": True,
            "non_mutating": True,
        },
    }

    payload = json.dumps(plan, indent=2, sort_keys=True) + "\n"
    if output_path:
        output = pathlib.Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(payload, encoding="utf-8")
        print(os.fspath(output.resolve()))
        return
    print(payload, end="")


main()
PY
}
