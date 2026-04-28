#!/usr/bin/env bash
set -euo pipefail

remote_alpha_es_service_user_rollback_rehearsal_schema_version="execution-substrate.remote-alpha.es-service-user-rollback-rehearsal.v1"
remote_alpha_es_service_user_rollback_rehearsal_default_evidence_dir=".out/remote-alpha-m75q"
remote_alpha_es_service_user_rollback_rehearsal_default_json_name="es-service-user-rollback-rehearsal.json"
remote_alpha_es_service_user_rollback_rehearsal_default_markdown_name="es-service-user-rollback-rehearsal.md"

remote_alpha_es_service_user_rollback_rehearsal_defaults() {
  REMOTE_ALPHA_ES_SERVICE_USER_ROLLBACK_REHEARSAL_EVIDENCE_DIR="${REMOTE_ALPHA_ES_SERVICE_USER_ROLLBACK_REHEARSAL_EVIDENCE_DIR:-${remote_alpha_es_service_user_rollback_rehearsal_default_evidence_dir}}"
  REMOTE_ALPHA_ES_SERVICE_USER_ROLLBACK_REHEARSAL_JSON_OUTPUT="${REMOTE_ALPHA_ES_SERVICE_USER_ROLLBACK_REHEARSAL_JSON_OUTPUT:-}"
  REMOTE_ALPHA_ES_SERVICE_USER_ROLLBACK_REHEARSAL_MARKDOWN_OUTPUT="${REMOTE_ALPHA_ES_SERVICE_USER_ROLLBACK_REHEARSAL_MARKDOWN_OUTPUT:-}"
}

remote_alpha_es_service_user_rollback_rehearsal_usage() {
  cat <<'EOF'
Usage:
  scripts/remote_alpha_es_service_user_rollback_rehearsal.sh

Optional flags:
  --evidence-dir </path/to/local/evidence>
  --json-output </path/to/es-service-user-rollback-rehearsal.json>
  --markdown-output </path/to/es-service-user-rollback-rehearsal.md>
  --help

Default behavior is non-mutating, reads local evidence only, writes the JSON and
Markdown rehearsal artifacts, and prints the JSON artifact to stdout.
EOF
}

remote_alpha_es_service_user_rollback_rehearsal_parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --evidence-dir)
        REMOTE_ALPHA_ES_SERVICE_USER_ROLLBACK_REHEARSAL_EVIDENCE_DIR="$2"
        shift 2
        ;;
      --json-output)
        REMOTE_ALPHA_ES_SERVICE_USER_ROLLBACK_REHEARSAL_JSON_OUTPUT="$2"
        shift 2
        ;;
      --markdown-output)
        REMOTE_ALPHA_ES_SERVICE_USER_ROLLBACK_REHEARSAL_MARKDOWN_OUTPUT="$2"
        shift 2
        ;;
      --help|-h)
        remote_alpha_es_service_user_rollback_rehearsal_usage
        return 1
        ;;
      *)
        echo "unknown argument: $1" >&2
        remote_alpha_es_service_user_rollback_rehearsal_usage >&2
        return 2
        ;;
    esac
  done
}

remote_alpha_es_service_user_rollback_rehearsal_require_command() {
  local name=$1
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "${name} is required" >&2
    return 1
  fi
}

remote_alpha_es_service_user_rollback_rehearsal_main() {
  remote_alpha_es_service_user_rollback_rehearsal_defaults
  remote_alpha_es_service_user_rollback_rehearsal_parse_args "$@" || return $?
  remote_alpha_es_service_user_rollback_rehearsal_require_command python3

  if [[ -z "${REMOTE_ALPHA_ES_SERVICE_USER_ROLLBACK_REHEARSAL_JSON_OUTPUT}" ]]; then
    REMOTE_ALPHA_ES_SERVICE_USER_ROLLBACK_REHEARSAL_JSON_OUTPUT="${REMOTE_ALPHA_ES_SERVICE_USER_ROLLBACK_REHEARSAL_EVIDENCE_DIR}/${remote_alpha_es_service_user_rollback_rehearsal_default_json_name}"
  fi
  if [[ -z "${REMOTE_ALPHA_ES_SERVICE_USER_ROLLBACK_REHEARSAL_MARKDOWN_OUTPUT}" ]]; then
    REMOTE_ALPHA_ES_SERVICE_USER_ROLLBACK_REHEARSAL_MARKDOWN_OUTPUT="${REMOTE_ALPHA_ES_SERVICE_USER_ROLLBACK_REHEARSAL_EVIDENCE_DIR}/${remote_alpha_es_service_user_rollback_rehearsal_default_markdown_name}"
  fi

  mkdir -p "$(dirname "${REMOTE_ALPHA_ES_SERVICE_USER_ROLLBACK_REHEARSAL_JSON_OUTPUT}")"
  mkdir -p "$(dirname "${REMOTE_ALPHA_ES_SERVICE_USER_ROLLBACK_REHEARSAL_MARKDOWN_OUTPUT}")"

  python3 - \
    "${remote_alpha_es_service_user_rollback_rehearsal_schema_version}" \
    "${REMOTE_ALPHA_ES_SERVICE_USER_ROLLBACK_REHEARSAL_EVIDENCE_DIR}" \
    "${REMOTE_ALPHA_ES_SERVICE_USER_ROLLBACK_REHEARSAL_JSON_OUTPUT}" \
    "${REMOTE_ALPHA_ES_SERVICE_USER_ROLLBACK_REHEARSAL_MARKDOWN_OUTPUT}" <<'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone

SCHEMA_VERSION = sys.argv[1]
EVIDENCE_DIR = pathlib.Path(sys.argv[2])
JSON_OUTPUT_PATH = pathlib.Path(sys.argv[3])
MARKDOWN_OUTPUT_PATH = pathlib.Path(sys.argv[4])

SERVICE_USER_APPLY_SUMMARY_NAME = "es-service-user-migration-apply-summary.json"
SERVICE_USER_CHECK_ONLY_NAME = "es-service-user-migration-check-only.json"
WRITABLE_STATE_APPLY_SUMMARY_NAME = "es-writable-state-ownership-apply-summary.json"
BINARY_DEPLOYMENT_APPLY_SUMMARY_NAME = "es-binary-deployment-apply-summary.json"

EXPECTED_SERVICE_USER_SCHEMA = "execution-substrate.remote-alpha.es-service-user-migration-summary.v1"
EXPECTED_WRITABLE_STATE_SCHEMA = "execution-substrate.remote-alpha.es-writable-state-ownership-summary.v1"
EXPECTED_BINARY_DEPLOYMENT_SCHEMA = "execution-substrate.remote-alpha.es-binary-deployment-summary.v1"
EXPECTED_DROPIN_PATH = "/etc/systemd/system/es.service.d/10-account.conf"
EXPECTED_DROPIN_LINES = ["[Service]", "User=es", "Group=es", "UMask=0027"]
OLD_ROOT_SUMMARY = "old root was preserved for rollback/debug evidence"


def make_status(classification, summary, **kwargs):
    payload = {
        "classification": classification,
        "summary": summary,
    }
    payload.update(kwargs)
    return payload


def severity_rank(classification):
    return {"pass": 0, "warning": 1, "blocker": 2}.get(classification, 2)


def now_rfc3339():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def as_nonempty_string(value):
    if isinstance(value, str):
        trimmed = value.strip()
        if trimmed:
            return trimmed
    return ""


def as_string_list(value):
    if not isinstance(value, list):
        return None
    result = []
    for item in value:
        if not isinstance(item, str):
            return None
        result.append(item.strip())
    return result


def get_in(node, *path):
    current = node
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def normalize_json(payload):
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def load_json_artifact(path, expected_schema):
    if not path.exists():
        return None, make_status(
            "blocker",
            "required local evidence artifact is missing",
            path=str(path),
            expected_schema_version=expected_schema,
        )
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return None, make_status(
            "blocker",
            f"local evidence artifact is not valid JSON: {exc}",
            path=str(path),
            expected_schema_version=expected_schema,
        )
    schema_version = payload.get("schema_version")
    if schema_version != expected_schema:
        return payload, make_status(
            "blocker",
            "local evidence artifact schema_version does not match the documented slice contract",
            path=str(path),
            schema_version=schema_version,
            expected_schema_version=expected_schema,
        )
    return payload, make_status(
        "pass",
        "local evidence artifact was loaded successfully",
        path=str(path),
        schema_version=schema_version,
    )


def add_check(checks, findings, name, status):
    checks[name] = status
    if status["classification"] != "pass":
        findings.append({"check": name, **status})


def combine_classification(*statuses):
    highest = "pass"
    for status in statuses:
        if severity_rank(status["classification"]) > severity_rank(highest):
            highest = status["classification"]
    return highest


service_user_apply_path = EVIDENCE_DIR / SERVICE_USER_APPLY_SUMMARY_NAME
service_user_check_path = EVIDENCE_DIR / SERVICE_USER_CHECK_ONLY_NAME
writable_state_apply_path = EVIDENCE_DIR / WRITABLE_STATE_APPLY_SUMMARY_NAME
binary_deployment_apply_path = EVIDENCE_DIR / BINARY_DEPLOYMENT_APPLY_SUMMARY_NAME

service_user_apply, service_user_apply_status = load_json_artifact(
    service_user_apply_path,
    EXPECTED_SERVICE_USER_SCHEMA,
)
service_user_check, service_user_check_status = load_json_artifact(
    service_user_check_path,
    EXPECTED_SERVICE_USER_SCHEMA,
)
writable_state_apply, writable_state_apply_status = load_json_artifact(
    writable_state_apply_path,
    EXPECTED_WRITABLE_STATE_SCHEMA,
)
binary_deployment_apply, binary_deployment_apply_status = load_json_artifact(
    binary_deployment_apply_path,
    EXPECTED_BINARY_DEPLOYMENT_SCHEMA,
)

inputs = {
    "service_user_apply_summary": service_user_apply_status,
    "service_user_check_only": service_user_check_status,
    "writable_state_apply_summary": writable_state_apply_status,
    "binary_deployment_apply_summary": binary_deployment_apply_status,
}

checks = {}
findings = []
references = {
    "service_user_backup_path": "",
    "service_user_config_backup_path": "",
    "service_unit_backup_dir": "",
    "service_dropin_backup_dir": "",
    "planned_service_dropin_path": "",
    "applied_service_dropin_path": "",
    "binary_backup_path": "",
    "binary_pre_apply_es_binary_copy": "",
    "binary_pre_apply_runtime_support_copy": "",
    "writable_state_backup_path": "",
    "writable_state_quarantine_paths": {
        "staging": "",
        "results": "",
    },
    "preserved_old_root_paths": [],
}

service_user_backup = get_in(service_user_apply or {}, "backup") or {}
service_user_backup_path = as_nonempty_string(service_user_backup.get("path"))
service_user_config_backup_path = as_nonempty_string(service_user_backup.get("config_backup_path"))
service_user_snapshot_path = as_nonempty_string(service_user_backup.get("snapshot_path"))
service_user_backup_snapshot = get_in(service_user_backup, "snapshot") or {}

references["service_user_backup_path"] = service_user_backup_path
references["service_user_config_backup_path"] = service_user_config_backup_path
references["service_unit_backup_dir"] = as_nonempty_string(
    service_user_backup.get("service_unit_backup_dir")
    or service_user_backup_snapshot.get("service_unit_backup_dir")
)
references["service_dropin_backup_dir"] = as_nonempty_string(
    service_user_backup.get("dropin_backup_dir")
    or service_user_backup_snapshot.get("dropin_backup_dir")
)

service_user_backup_prereqs = combine_classification(
    service_user_apply_status,
)
if service_user_backup_prereqs == "blocker":
    add_check(
        checks,
        findings,
        "service_user_backup_recorded",
        make_status(
            "blocker",
            "service-user apply evidence is unavailable, so the backup record cannot be rehearsed locally",
        ),
    )
else:
    missing = []
    if not service_user_backup_path:
        missing.append("backup.path")
    if not service_user_config_backup_path:
        missing.append("backup.config_backup_path")
    if not service_user_snapshot_path:
        missing.append("backup.snapshot_path")
    if missing:
        add_check(
            checks,
            findings,
            "service_user_backup_recorded",
            make_status(
                "blocker",
                "service-user migration evidence does not record the full bounded backup path set",
                missing_fields=missing,
            ),
        )
    else:
        add_check(
            checks,
            findings,
            "service_user_backup_recorded",
            make_status(
                "pass",
                "service-user migration backup path, config backup, and snapshot path are recorded",
                backup_path=service_user_backup_path,
                config_backup_path=service_user_config_backup_path,
                snapshot_path=service_user_snapshot_path,
            ),
        )

if combine_classification(service_user_apply_status) == "blocker":
    add_check(
        checks,
        findings,
        "previous_service_unit_and_dropin_state_recorded",
        make_status(
            "blocker",
            "service-user apply evidence is unavailable, so the pre-apply service unit/drop-in state cannot be rehearsed locally",
        ),
    )
else:
    pre_mutation_service = get_in(service_user_backup_snapshot, "pre_mutation_service")
    copied_dropins = service_user_backup_snapshot.get("copied_dropins")
    unit_backup_dir = references["service_unit_backup_dir"]
    dropin_backup_dir = references["service_dropin_backup_dir"]
    missing = []
    if not isinstance(pre_mutation_service, dict):
        missing.append("backup.snapshot.pre_mutation_service")
    if copied_dropins is None or not isinstance(copied_dropins, list):
        missing.append("backup.snapshot.copied_dropins")
    if not unit_backup_dir:
        missing.append("backup.service_unit_backup_dir")
    if not dropin_backup_dir:
        missing.append("backup.dropin_backup_dir")
    if missing:
        add_check(
            checks,
            findings,
            "previous_service_unit_and_dropin_state_recorded",
            make_status(
                "blocker",
                "pre-apply service unit/drop-in state is not fully recorded in the service-user backup snapshot",
                missing_fields=missing,
            ),
        )
    else:
        add_check(
            checks,
            findings,
            "previous_service_unit_and_dropin_state_recorded",
            make_status(
                "pass",
                "pre-apply service unit posture and prior drop-in snapshot are recorded",
                pre_mutation_service=pre_mutation_service,
                copied_dropin_count=len(copied_dropins),
                service_unit_backup_dir=unit_backup_dir,
                dropin_backup_dir=dropin_backup_dir,
            ),
        )

service_user_check_plan = get_in(service_user_check or {}, "plan") or {}
planned_dropin_lines = as_string_list(service_user_check_plan.get("planned_service_dropin_lines"))
planned_dropin_path = as_nonempty_string(service_user_check_plan.get("planned_service_dropin_path"))
applied_dropin = get_in(service_user_apply or {}, "changes", "dropin") or {}
applied_dropin_lines = as_string_list(applied_dropin.get("applied_lines"))
applied_dropin_path = as_nonempty_string(applied_dropin.get("path"))
references["planned_service_dropin_path"] = planned_dropin_path
references["applied_service_dropin_path"] = applied_dropin_path

if combine_classification(service_user_apply_status, service_user_check_status) == "blocker":
    add_check(
        checks,
        findings,
        "current_intended_dropin_bounded",
        make_status(
            "blocker",
            "service-user check-only or apply evidence is unavailable, so bounded drop-in rehearsal cannot be completed locally",
        ),
    )
else:
    problems = []
    if planned_dropin_lines != EXPECTED_DROPIN_LINES:
        problems.append("check-only planned drop-in lines drift from the documented bounded slice")
    if applied_dropin_lines != EXPECTED_DROPIN_LINES:
        problems.append("apply summary applied drop-in lines drift from the documented bounded slice")
    if planned_dropin_path != EXPECTED_DROPIN_PATH:
        problems.append("check-only planned drop-in path drifted from the documented es.service drop-in path")
    if applied_dropin_path != EXPECTED_DROPIN_PATH:
        problems.append("apply summary drop-in path drifted from the documented es.service drop-in path")
    if problems:
        add_check(
            checks,
            findings,
            "current_intended_dropin_bounded",
            make_status(
                "blocker",
                "current intended service-user drop-in is not bounded to the documented es-only account change",
                expected_path=EXPECTED_DROPIN_PATH,
                expected_lines=EXPECTED_DROPIN_LINES,
                observed_planned_path=planned_dropin_path,
                observed_planned_lines=planned_dropin_lines,
                observed_applied_path=applied_dropin_path,
                observed_applied_lines=applied_dropin_lines,
                problems=problems,
            ),
        )
    else:
        add_check(
            checks,
            findings,
            "current_intended_dropin_bounded",
            make_status(
                "pass",
                "planned and applied service-user drop-in lines stay bounded to User=es, Group=es, and UMask=0027",
                path=EXPECTED_DROPIN_PATH,
                lines=EXPECTED_DROPIN_LINES,
            ),
        )

service_user_backup_notes = as_string_list(service_user_backup.get("rollback_notes"))
service_user_plan_notes = as_string_list(get_in(service_user_check or {}, "service_unit_plan_status", "plan", "rollback_notes"))
binary_backup = get_in(binary_deployment_apply or {}, "backup") or {}
binary_backup_notes = as_string_list(binary_backup.get("rollback_notes"))
writable_state_backup = get_in(writable_state_apply or {}, "backup") or {}
writable_backup_notes = as_string_list(writable_state_backup.get("rollback_notes"))

note_sets = {
    "service_user_apply_backup": service_user_backup_notes,
    "service_user_check_only_plan": service_user_plan_notes,
    "binary_deployment_backup": binary_backup_notes,
    "writable_state_backup": writable_backup_notes,
}
missing_note_sets = sorted(name for name, notes in note_sets.items() if not notes)
all_rollback_notes = []
for notes in note_sets.values():
    if notes:
        all_rollback_notes.extend(notes)

if missing_note_sets:
    add_check(
        checks,
        findings,
        "rollback_notes_exist",
        make_status(
            "blocker",
            "one or more bounded rollback evidence artifacts are missing rollback notes",
            missing_note_sets=missing_note_sets,
        ),
    )
else:
    add_check(
        checks,
        findings,
        "rollback_notes_exist",
        make_status(
            "pass",
            "rollback notes are recorded across the service-user, binary, and writable-state evidence set",
            note_set_count=len(note_sets),
            total_notes=len(all_rollback_notes),
        ),
    )

references["binary_backup_path"] = as_nonempty_string(binary_backup.get("path"))
references["binary_pre_apply_es_binary_copy"] = as_nonempty_string(binary_backup.get("pre_apply_es_binary_copy"))
references["binary_pre_apply_runtime_support_copy"] = as_nonempty_string(binary_backup.get("pre_apply_runtime_support_copy"))

if combine_classification(binary_deployment_apply_status) == "blocker":
    add_check(
        checks,
        findings,
        "binary_deployment_backup_referenced",
        make_status(
            "blocker",
            "binary deployment apply evidence is unavailable, so the rollback binary backup cannot be rehearsed locally",
        ),
    )
else:
    missing = []
    if not references["binary_backup_path"]:
        missing.append("backup.path")
    if not references["binary_pre_apply_es_binary_copy"]:
        missing.append("backup.pre_apply_es_binary_copy")
    if not references["binary_pre_apply_runtime_support_copy"]:
        missing.append("backup.pre_apply_runtime_support_copy")
    if missing:
        add_check(
            checks,
            findings,
            "binary_deployment_backup_referenced",
            make_status(
                "blocker",
                "binary deployment evidence does not record the bounded pre-apply backup set",
                missing_fields=missing,
            ),
        )
    else:
        add_check(
            checks,
            findings,
            "binary_deployment_backup_referenced",
            make_status(
                "pass",
                "binary deployment backup path and pre-apply binary copies are recorded",
                backup_path=references["binary_backup_path"],
                pre_apply_es_binary_copy=references["binary_pre_apply_es_binary_copy"],
                pre_apply_runtime_support_copy=references["binary_pre_apply_runtime_support_copy"],
            ),
        )

references["writable_state_backup_path"] = as_nonempty_string(writable_state_backup.get("path"))
quarantine_paths = get_in(writable_state_apply or {}, "quarantine_paths") or {}
references["writable_state_quarantine_paths"]["staging"] = as_nonempty_string(quarantine_paths.get("staging"))
references["writable_state_quarantine_paths"]["results"] = as_nonempty_string(quarantine_paths.get("results"))

if combine_classification(writable_state_apply_status) == "blocker":
    add_check(
        checks,
        findings,
        "writable_state_backup_and_quarantine_referenced",
        make_status(
            "blocker",
            "writable-state apply evidence is unavailable, so the rollback writable-state references cannot be rehearsed locally",
        ),
    )
else:
    missing = []
    if not references["writable_state_backup_path"]:
        missing.append("backup.path")
    if missing:
        add_check(
            checks,
            findings,
            "writable_state_backup_and_quarantine_referenced",
            make_status(
                "blocker",
                "writable-state ownership evidence does not record the bounded backup path",
                missing_fields=missing,
            ),
        )
    else:
        missing_quarantine = [
            name
            for name, value in references["writable_state_quarantine_paths"].items()
            if not value
        ]
        if missing_quarantine:
            add_check(
                checks,
                findings,
                "writable_state_backup_and_quarantine_referenced",
                make_status(
                    "warning",
                    "writable-state ownership evidence records the backup path but does not fully record the quarantine path set",
                    backup_path=references["writable_state_backup_path"],
                    missing_quarantine_paths=missing_quarantine,
                ),
            )
        else:
            add_check(
                checks,
                findings,
                "writable_state_backup_and_quarantine_referenced",
                make_status(
                    "pass",
                    "writable-state ownership backup and quarantine paths are recorded",
                    backup_path=references["writable_state_backup_path"],
                    quarantine_paths=references["writable_state_quarantine_paths"],
                ),
            )

quarantined_roots_observed = get_in(writable_state_backup or {}, "snapshot", "quarantined_roots_observed")
preserved_old_root_paths = []
staging_preserved = False
results_preserved = False
if isinstance(quarantined_roots_observed, list):
    for item in quarantined_roots_observed:
        if not isinstance(item, dict):
            continue
        path = as_nonempty_string(item.get("path"))
        summary = as_nonempty_string(item.get("summary"))
        if path and (OLD_ROOT_SUMMARY in summary or ".pre-es-writable-state-ownership-" in path):
            preserved_old_root_paths.append(
                {
                    "path": path,
                    "summary": summary,
                }
            )
            if "staging.pre-es-writable-state-ownership-" in path:
                staging_preserved = True
            if "results.pre-es-writable-state-ownership-" in path:
                results_preserved = True

references["preserved_old_root_paths"] = preserved_old_root_paths

if combine_classification(writable_state_apply_status) == "blocker":
    add_check(
        checks,
        findings,
        "old_root_era_state_preserved",
        make_status(
            "blocker",
            "writable-state apply evidence is unavailable, so preserved old-root rollback/debug state cannot be rehearsed locally",
        ),
    )
else:
    if staging_preserved and results_preserved:
        add_check(
            checks,
            findings,
            "old_root_era_state_preserved",
            make_status(
                "pass",
                "old root-era staging and results roots are preserved as rollback/debug/evidence state",
                preserved_paths=preserved_old_root_paths,
            ),
        )
    else:
        add_check(
            checks,
            findings,
            "old_root_era_state_preserved",
            make_status(
                "warning",
                "local writable-state evidence does not explicitly prove that both old root-era staging and results roots remain preserved",
                preserved_paths=preserved_old_root_paths,
                staging_preserved=staging_preserved,
                results_preserved=results_preserved,
            ),
        )


def is_unsafe_instruction(note):
    lowered = note.lower()
    if "rm -rf" in lowered or "chown -r" in lowered or "chmod -r" in lowered:
        return True
    mentions_recursive_mutation = ("recursive" in lowered or "recursively" in lowered) and not any(
        phrase in lowered
        for phrase in ["do not", "must not", "should not", "without recursive", "do n't"]
    )
    if mentions_recursive_mutation:
        return True
    broad_delete_tokens = [
        "delete all",
        "remove all",
        "delete everything",
        "wipe ",
        "broad deletion",
        "delete arbitrary",
    ]
    return any(token in lowered for token in broad_delete_tokens)


unsafe_notes = sorted({note for note in all_rollback_notes if is_unsafe_instruction(note)})
if unsafe_notes:
    add_check(
        checks,
        findings,
        "no_recursive_chown_or_broad_deletion_required",
        make_status(
            "blocker",
            "rollback notes include an unsafe recursive-mutation or broad-deletion instruction",
            unsafe_notes=unsafe_notes,
        ),
    )
else:
    add_check(
        checks,
        findings,
        "no_recursive_chown_or_broad_deletion_required",
        make_status(
            "pass",
            "recorded rollback notes do not require recursive chown or broad deletion",
        ),
    )

overall_classification = "pass"
for status in inputs.values():
    if severity_rank(status["classification"]) > severity_rank(overall_classification):
        overall_classification = status["classification"]
for status in checks.values():
    if severity_rank(status["classification"]) > severity_rank(overall_classification):
        overall_classification = status["classification"]

payload = {
    "schema_version": SCHEMA_VERSION,
    "checked_at": now_rfc3339(),
    "mode": {
        "name": "local_evidence_only",
        "non_mutating": True,
        "reads_local_evidence_only": True,
        "writes_artifacts": True,
    },
    "slice": {
        "name": "long_lived_es_service_user_migration_rollback_rehearsal",
        "classification": "bounded_slice_rule",
        "scope": "repo-local rollback rehearsal for the completed long-lived es.service service-user migration",
    },
    "proof": {
        "live_host_mutation_performed": False,
        "ssh_used": False,
        "sudo_used": False,
        "rollback_executed": False,
        "es_apply_executed": False,
        "governed_proof_run": False,
        "pr_or_merge_prep_performed": False,
    },
    "inputs": {
        "evidence_dir": str(EVIDENCE_DIR),
        "artifacts": inputs,
    },
    "checks": checks,
    "references": references,
    "findings": findings,
    "overall_classification": overall_classification,
    "result": {
        "ok": overall_classification != "blocker",
        "status": overall_classification,
        "json_output_path": str(JSON_OUTPUT_PATH),
        "markdown_output_path": str(MARKDOWN_OUTPUT_PATH),
    },
}

JSON_OUTPUT_PATH.write_text(normalize_json(payload), encoding="utf-8")

markdown_lines = [
    "# ES Service-User Rollback Rehearsal",
    "",
    f"- Overall classification: `{overall_classification}`",
    f"- Checked at: `{payload['checked_at']}`",
    f"- Evidence directory: `{EVIDENCE_DIR}`",
    "",
    "## Source Artifacts",
]
for name, status in inputs.items():
    artifact_path = status.get("path", "")
    markdown_lines.append(
        f"- `{name}`: `{status['classification']}`; {status['summary']}"
        + (f" (`{artifact_path}`)" if artifact_path else "")
    )

markdown_lines.extend(
    [
        "",
        "## Rollback Evidence Checks",
    ]
)
for name, status in checks.items():
    markdown_lines.append(f"- `{name}`: `{status['classification']}`; {status['summary']}")

markdown_lines.extend(
    [
        "",
        "## Referenced Paths",
        f"- Service-user backup: `{references['service_user_backup_path']}`",
        f"- Service-user config backup: `{references['service_user_config_backup_path']}`",
        f"- Service unit backup dir: `{references['service_unit_backup_dir']}`",
        f"- Service drop-in backup dir: `{references['service_dropin_backup_dir']}`",
        f"- Planned service drop-in path: `{references['planned_service_dropin_path']}`",
        f"- Applied service drop-in path: `{references['applied_service_dropin_path']}`",
        f"- Binary deployment backup: `{references['binary_backup_path']}`",
        f"- Binary pre-apply ES copy: `{references['binary_pre_apply_es_binary_copy']}`",
        f"- Binary pre-apply runtime-support copy: `{references['binary_pre_apply_runtime_support_copy']}`",
        f"- Writable-state backup: `{references['writable_state_backup_path']}`",
        f"- Writable-state quarantine staging path: `{references['writable_state_quarantine_paths']['staging']}`",
        f"- Writable-state quarantine results path: `{references['writable_state_quarantine_paths']['results']}`",
    ]
)
for item in preserved_old_root_paths:
    markdown_lines.append(f"- Preserved old-root evidence: `{item['path']}`; {item['summary']}")

markdown_lines.extend(
    [
        "",
        "## Findings",
    ]
)
if findings:
    for item in findings:
        markdown_lines.append(f"- `{item['check']}`: `{item['classification']}`; {item['summary']}")
else:
    markdown_lines.append("- No warnings or blockers were identified in the local rollback evidence set.")

markdown_lines.extend(
    [
        "",
        "## Safety Boundary",
        "- Local evidence only; no SSH, sudo, live-host mutation, rollback execution, ES apply, governed proof, or PR/merge prep occurred.",
    ]
)

MARKDOWN_OUTPUT_PATH.write_text("\n".join(markdown_lines) + "\n", encoding="utf-8")
sys.stdout.write(normalize_json(payload))
raise SystemExit(1 if overall_classification == "blocker" else 0)
PY
}
