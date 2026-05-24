#!/usr/bin/env bash
set -euo pipefail
set +x

DEFAULT_PROFILE_DIR=".out/remote-alpha-m75q"
DEFAULT_OUTPUT_ROOT=".out/remote-alpha-m75q/support-bundles"
DEFAULT_SSH_ALIAS="host_to_remote_linux_m75q"
IM_REPO="/Users/ds/Repositories/Infrastructure Manager"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REMOTE_ALPHA_ES_WRITABLE_STATE_READINESS_HELPER="${SCRIPT_DIR}/remote_alpha_stage_es_writable_state_readiness_check.sh"
REMOTE_ALPHA_VAULT_RESET_HELPER="${SCRIPT_DIR}/remote_alpha_reset_disposable_vault.sh"
READINESS_ARTIFACT_NAME="es-writable-state-readiness.json"
READINESS_STAGING_RECORD_ARTIFACT_NAME="es-writable-state-readiness-helper-staging-record.json"
READINESS_SESSION_DEFAULT_OUTPUT_PREFIX=".out/remote-alpha-m75q-readiness-session"
READINESS_SESSION_DEFAULT_MODE="alpha-compat"
READINESS_ARTIFACT_SCHEMA="execution-substrate.remote-alpha.es-writable-state-readiness.v1"
READINESS_STAGING_RECORD_SCHEMA="execution-substrate.remote-alpha.es-writable-state-readiness-stage-provenance.v1"

profile_dir="${DEFAULT_PROFILE_DIR}"
output_root="${DEFAULT_OUTPUT_ROOT}"
ssh_alias="${DEFAULT_SSH_ALIAS}"
subcommand=""
declare -a subcommand_args=()
declare -a facade_options_seen=()

die() {
  printf 'error: %s\n' "$*" >&2
  exit 2
}

reject_secret_args() {
  local arg flag
  local secret_flags=(
    "--root-token"
    "--unseal-key"
    "--client-token"
    "--vault-token"
    "--api-key"
    "--jwt-svid"
    "--private-key"
    "--password"
    "--secret"
  )

  for arg in "$@"; do
    for flag in "${secret_flags[@]}"; do
      if [[ "${arg}" == *"${flag}"* ]]; then
        die "secret material must never be passed by CLI args/env/logs/reports/artifacts"
      fi
    done
  done
}

require_option_value() {
  local option=$1
  local value_count=$2
  if [[ "${value_count}" -lt 2 ]]; then
    die "${option} requires a value"
  fi
}

validate_print_value() {
  local option=$1
  local value=$2
  case "${value}" in
    *$'\n'*|*$'\r'*|*\"*|*'`'*|*'$'*|*\\*)
      die "${option} value contains characters unsafe for printed double-quoted command text"
    ;;
  esac
}

route_die() {
  printf 'error: %s\n' "$*" >&2
  printf 'No helper execution routing occurred.\n' >&2
  exit 2
}

require_route_option_value() {
  local option=$1
  local value_count=$2
  local value=${3:-}
  if [[ "${value_count}" -lt 2 || -z "${value}" || "${value}" == --* ]]; then
    route_die "${option} requires a value"
  fi
}

require_route_option_not_seen() {
  local option=$1
  local seen=$2
  if [[ "${seen}" == "true" ]]; then
    route_die "duplicate option for es-writable-state-readiness-check: ${option}"
  fi
}

session_die() {
  printf 'error: %s\n' "$*" >&2
  printf 'No readiness route execution occurred.\n' >&2
  exit 2
}

require_session_option_value() {
  local option=$1
  local value_count=$2
  local value=${3:-}
  if [[ "${value_count}" -lt 2 || -z "${value}" || "${value}" == --* ]]; then
    session_die "${option} requires a value"
  fi
  case "${value}" in
    *$'\n'*|*$'\r'*)
      session_die "${option} value contains a newline"
      ;;
  esac
}

require_session_option_not_seen() {
  local option=$1
  local seen=$2
  if [[ "${seen}" == "true" ]]; then
    session_die "duplicate option for readiness-session: ${option}"
  fi
}

recovery_die() {
  printf 'error: %s\n' "$*" >&2
  printf 'No recovery-session live helper or IM execution occurred.\n' >&2
  exit 2
}

require_recovery_option_value() {
  local option=$1
  local value_count=$2
  local value=${3:-}
  if [[ "${value_count}" -lt 2 || -z "${value}" || "${value}" == --* ]]; then
    recovery_die "${option} requires a value"
  fi
  case "${value}" in
    *$'\n'*|*$'\r'*)
      recovery_die "${option} value contains a newline"
      ;;
  esac
}

require_recovery_option_not_seen() {
  local option=$1
  local seen=$2
  if [[ "${seen}" == "true" ]]; then
    recovery_die "duplicate option for recovery-session: ${option}"
  fi
}

print_double_quoted() {
  local option=$1
  local value=$2
  validate_print_value "${option}" "${value}"
  printf '"%s"' "${value}"
}

usage() {
  printf '%s\n' \
    "Remote Alpha operator facade" \
    "" \
    "P0i adds recovery-session vault-unseal-existing as an explicit host-local, secret-sensitive, non-destructive operator mode." \
    "Classification: bounded proof/support helper; evidence/projection only; no authority source." \
    "The human remains the operator; this script is a bounded ES Remote Alpha operator facade/workflow." \
    "Goal: minimize manual stitching, copying, and recovery sequencing; not eliminate prompts." \
    "Explicit interactive modes are allowed only when named, bounded, visible, and secret-safe." \
    "Noninteractive sudo is an ergonomic optimization, not a universal success criterion." \
    "Outputs are evidence/projection/diagnostics only, never authority." \
    "" \
    "Usage:" \
    "  remote_alpha_operator.sh help" \
    "  remote_alpha_operator.sh inventory" \
    "  remote_alpha_operator.sh print-refresh-command [options]" \
    "  remote_alpha_operator.sh print-support-bundle-command [options]" \
    "  remote_alpha_operator.sh print-im-commands [options]" \
    "  remote_alpha_operator.sh es-writable-state-readiness-check --ssh-target <user@host> [options]" \
    "  remote_alpha_operator.sh readiness-session --ssh-target <user@host> [options]" \
    "  remote_alpha_operator.sh recovery-session [--plan|--inventory|--next-steps|--evidence-check] [options]" \
    "  remote_alpha_operator.sh recovery-session vault-unseal-existing --host-local" \
    "" \
    "Options for printed command text only:" \
    "  --profile-dir .out/remote-alpha-m75q" \
    "  --output-root .out/remote-alpha-m75q/support-bundles" \
    "  --ssh-alias host_to_remote_linux_m75q" \
    "  --help, -h" \
    "" \
    "Implemented through P0i:" \
    "  es-writable-state-readiness-check - delegates only to scripts/remote_alpha_stage_es_writable_state_readiness_check.sh; check-only/non-mutating; requires --ssh-target; preserves es-writable-state-readiness.json and es-writable-state-readiness-helper-staging-record.json." \
    "  readiness-session - runs the existing readiness route; check-only/non-mutating; requires --ssh-target; uses a fresh output directory by default; verifies artifacts; scans for secret-like content; prints only non-secret artifact metadata and IM follow-up commands." \
    "  recovery-session - safe/local recovery skeleton; supports --plan, --inventory, --next-steps, schema-aware local evidence-check, and host-local vault-unseal-existing over the existing reset helper's --unseal-only mode; writes no summary." \
    "" \
    "The operator facade does not invoke IM refresh or support-bundle collection and does not add reset execution, Vault workload-auth, runtime identity, service-user, config/TLS, binary deployment, writable-state ownership, or generic staging routes." \
    "Secret material must never be passed by CLI args/env/logs/reports/artifacts."
}

inventory() {
  printf '%s\n' \
    "Remote Alpha operator inventory" \
    "classification: bounded proof/support helper; evidence/projection only; no authority source" \
    "implemented, future, and blocked entries are operator-workflow/evidence surfaces, not authority surfaces" \
    "interactive operator involvement is expected where an explicit mode says so" \
    "IM refresh and support-bundle steps remain separate IM evidence/provenance actions unless a later reviewed contract says otherwise" \
    "" \
    "implemented through P0i:" \
    "  help - show bounded facade scope and options" \
    "  inventory - show this static non-secret inventory" \
    "  print-refresh-command - print Mac-side IM live-refresh command text only" \
    "  print-support-bundle-command - print Mac-side IM support-bundle command text only" \
    "  print-im-commands - print both Mac-side IM command texts only" \
    "  es-writable-state-readiness-check - delegates to existing readiness staged helper; check-only/non-mutating; preserves es-writable-state-readiness.json and es-writable-state-readiness-helper-staging-record.json" \
    "  readiness-session - runs the existing readiness route; check-only/non-mutating; verifies the two expected artifacts; prints non-secret paths, byte counts, SHA-256 digests, schemas, blocker/warning counts, and sudo/checker status" \
    "  recovery-session - safe/local skeleton for recovery sequencing; prints plan, static helper inventory, next-step commands, performs schema-aware local JSON evidence interpretation, or runs explicit host-local vault-unseal-existing" \
    "  recovery-session vault-unseal-existing --host-local - delegates only to scripts/remote_alpha_reset_disposable_vault.sh --unseal-only; host-local; secret-sensitive; non-destructive; not reset; not workload-auth bootstrap; not IM; not CP proof" \
    "" \
    "future/not implemented:" \
    "  Vault destructive reset execution - not implemented in P0i; requires later audited destructive exact-phrase slice" \
    "  workload-auth check execution - not implemented in P0i; requires later audited live check slice" \
    "  runtime identity summary generation - not implemented in P0i; requires later audited evidence route" \
    "  Vault service-user check/apply execution - not implemented in P0i; remains separate" \
    "  runtime security check - not implemented in P0i; requires later audited slice" \
    "  other staged ES helper delegation - not implemented in P0i; requires later audited slice" \
    "" \
    "blocked/reopened:" \
    "  vault-workload-auth-bootstrap - blocked/reopened and not available in v1" \
    "" \
    "non-claims:" \
    "  not production, not HA, not multi-tenant, not a general deployment architecture" \
    "  not IM automation or reconciliation, not CP authority, not ES Vault token brokerage" \
    "  must not make IM a remote reconciler, CP a Vault/runtime recovery authority, ES a Vault token broker, or Remote Alpha a deployment architecture" \
    "  no operator-owned summary, support bundle, report, or new authority artifact is written; readiness artifacts remain delegated helper evidence"
}

recovery_session_usage() {
  printf '%s\n' \
    "Remote Alpha operator workflow: recovery-session" \
    "P0i scope: safe/local recovery planning and evidence interpretation plus explicit host-local vault-unseal-existing." \
    "The human remains the operator. Secret-sensitive unseal key entry happens only in the visible terminal owned by the delegated helper and Vault CLI." \
    "Codex must not receive, type, log, relay, persist, or summarize the unseal key." \
    "Outputs are evidence/projection/diagnostics only, never authority." \
    "" \
    "Usage:" \
    "  remote_alpha_operator.sh recovery-session" \
    "  remote_alpha_operator.sh recovery-session --help" \
    "  remote_alpha_operator.sh recovery-session --plan" \
    "  remote_alpha_operator.sh recovery-session --inventory" \
    "  remote_alpha_operator.sh recovery-session --next-steps [print options]" \
    "  remote_alpha_operator.sh recovery-session --evidence-check [evidence paths] [print options]" \
    "  remote_alpha_operator.sh recovery-session vault-unseal-existing --host-local" \
    "" \
    "Allowed flags for all modes:" \
    "  --help" \
    "  --plan" \
    "  --inventory" \
    "  --next-steps" \
    "  --evidence-check" \
    "  --ssh-alias <alias> (for printed IM commands only)" \
    "  --im-profile-dir <path> (for printed IM commands only)" \
    "  --support-output-root <path> (for printed IM commands only)" \
    "" \
    "Allowed only with --evidence-check:" \
    "  --vault-workload-auth-summary <path>" \
    "  --runtime-identity-summary <path>" \
    "  --vault-service-user-summary <path>" \
    "  --readiness-summary <path>" \
    "  --staging-record <path>" \
    "  --evidence-dir <path>" \
    "  --strict-known-schema" \
    "" \
    "Forbidden: --ssh-target, --interactive-sudo, --apply, --dry-run, --execute-reset, --unseal-only, --post-unseal-check, --governed-smoke-command, helper path overrides, arbitrary command strings, unknown flags, positional arguments, duplicate operational flags, secret-like arguments, and equals-form options." \
    "The evidence-check reads only supplied local JSON files, scans for secret-like content before parsing JSON, prints path/byte/SHA-256/schema/safe status metadata only, prints no full JSON, creates no summary file, and writes no .out." \
    "Recognized schemas are interpreted through explicit safe-field allowlists. Unknown schemas are allowed by default with schema_interpretation=unknown; --strict-known-schema fails unknown schemas."
}

recovery_session_vault_unseal_existing_usage() {
  printf '%s\n' \
    "Remote Alpha recovery-session mode: vault-unseal-existing" \
    "P0i scope: explicit host-local secret-sensitive non-destructive unseal flow." \
    "Must be run on the Remote Alpha host where Vault is installed and reachable." \
    "Requires --host-local. SSH, remote staging, and host detection are not enabled in this slice." \
    "Delegates only to: scripts/remote_alpha_reset_disposable_vault.sh --unseal-only" \
    "" \
    "Human operator model:" \
    "  The human remains the operator." \
    "  The operator enters any unseal key directly into the visible Vault/helper terminal prompt." \
    "  The operator facade does not prompt for, read, type, log, relay, persist, summarize, or accept unseal keys, root tokens, Vault tokens, API keys, passwords, or secret payloads." \
    "  Secret material must never be passed by CLI args, env files, logs, .out, reports, support bundles, retained bundles, or Codex output." \
    "" \
    "Usage:" \
    "  remote_alpha_operator.sh recovery-session vault-unseal-existing --host-local" \
    "" \
    "Allowed flags:" \
    "  --help" \
    "  --host-local" \
    "" \
    "Forbidden in P0i: --ssh-target, --execute-reset, --post-unseal-check, --apply, --dry-run, --interactive-sudo, --governed-smoke-command, arbitrary command strings, helper path overrides, unknown flags, duplicate flags, positional args beyond the submode, secret-like flags, and equals-form options." \
    "Non-claims: not reset, not workload-auth bootstrap or check, not IM refresh/support-bundle, not CP proof, not default noninteractive readiness validation, not ES Vault token brokerage, and not Remote Alpha deployment/provisioning/reconciliation architecture."
}

recovery_session_plan() {
  printf '%s\n' \
    "Remote Alpha recovery-session plan (P0i host-local unseal-existing added)" \
    "classification: bounded proof/support helper; evidence/projection/diagnostics only; no authority source" \
    "default behavior: print this plan/help and exit zero; no live tools run" \
    "" \
    "implemented safe/local or explicitly host-local:" \
    "  inventory/status - safe local planning and static inventory only; no host inspection" \
    "  evidence-check - local-only metadata check of supplied existing JSON evidence files" \
    "  next-steps - print readiness-session and IM command text only" \
    "  vault-unseal-existing --host-local - implemented host-local operator mode; secret-sensitive but non-destructive; delegates only to the existing reset helper's --unseal-only flow" \
    "" \
    "future explicit audited slices:" \
    "  disposable reset - future destructive exact-phrase mode; no root token or unseal key through args/env/logs/artifacts/Codex output" \
    "  workload-auth check execution - future audited live check; ES must not become a Vault token broker" \
    "  runtime identity summary generation - future audited evidence route; runtime identity remains a reopened seam" \
    "  service-user check/apply - remains separate; apply is mutating and not part of P0i recovery-session" \
    "" \
    "separate IM actions:" \
    "  IM refresh and support-bundle collection are printed only as separate IM evidence/provenance actions" \
    "  recovery-session does not execute IM and does not make IM authority" \
    "" \
    "non-claims:" \
    "  not CP recovery authority, not Vault production lifecycle, not ES Vault token brokerage" \
    "  not Remote Alpha deployment, provisioning, reconciliation, production, HA, or multi-tenant architecture" \
    "  no destructive reset/workload-auth/runtime-identity/service-user execution route is added in P0i" \
    "  vault-unseal-existing does not validate default noninteractive readiness"
}

recovery_session_inventory() {
  printf '%s\n' \
    "Remote Alpha recovery-session static helper inventory" \
    "classification: static safe/local inventory only; no live host state inspection; no helper execution" \
    "" \
    "safe/local:" \
    "  scripts/remote_alpha_operator.sh readiness-session - existing bounded workflow over es-writable-state-readiness-check; live only when separately invoked with --ssh-target; not executed by recovery-session" \
    "  recovery-session --plan, --inventory, --next-steps - print-only/local" \
    "  recovery-session --evidence-check - local-only schema-aware check of existing JSON evidence metadata; check-only; no summary file" \
    "  recovery-session vault-unseal-existing --host-local - implemented host-local explicit operator mode; secret-sensitive; non-destructive; delegates only to scripts/remote_alpha_reset_disposable_vault.sh --unseal-only" \
    "" \
    "check-only evidence helpers (future execution routes, not run by recovery-session P0i):" \
    "  scripts/remote_alpha_vault_workload_auth_check.sh - host-local root check; transient JWT/Vault token handling inside helper; future audited live check" \
    "  scripts/remote_alpha_runtime_identity_helper_summary.sh - host-local runtime identity helper summary; dry-run/check-only available; future audited evidence route" \
    "  scripts/remote_alpha_migrate_vault_service_user.sh --check-only - host-local Vault service-user migration check; check-only default; apply remains separate" \
    "" \
    "secret-sensitive or destructive helpers:" \
    "  scripts/remote_alpha_reset_disposable_vault.sh --unseal-only - implemented only through explicit host-local vault-unseal-existing; secret-sensitive; non-destructive" \
    "  scripts/remote_alpha_reset_disposable_vault.sh --execute-reset - future destructive exact-phrase mode" \
    "" \
    "blocked/reopened:" \
    "  vault-workload-auth-bootstrap - blocked/reopened; no root-token automation and no proof-secret bootstrap in P0i" \
    "" \
    "classifications present: safe/local, check-only, secret-sensitive, destructive, future, blocked/reopened" \
    "non-claims: inventory is evidence/projection/diagnostics only, never authority"
}

recovery_session_next_steps() {
  local im_profile_dir=$1
  local support_output_root=$2
  local im_ssh_alias=$3

  validate_print_value "--im-profile-dir" "${im_profile_dir}"
  validate_print_value "--support-output-root" "${support_output_root}"
  validate_print_value "--ssh-alias" "${im_ssh_alias}"

  printf '%s\n' \
    "Remote Alpha recovery-session next steps (printed only; no execution)" \
    "1. Existing ES readiness workflow example:" \
    "bash scripts/remote_alpha_operator.sh readiness-session --ssh-target <user@host> --interactive-sudo" \
    "" \
    "2. Separate IM evidence/provenance actions (printed only; not ES execution; not authority):" \
    "Mac-side Infrastructure Manager live refresh command:" \
    "cd \"${IM_REPO}\""
  printf 'PYTHONPATH=src python3 -m infra_manager.cli remote-alpha-live-refresh \\\n'
  printf '  --profile-dir '
  print_double_quoted "--im-profile-dir" "${im_profile_dir}"
  printf ' \\\n'
  printf '  --ssh-alias '
  print_double_quoted "--ssh-alias" "${im_ssh_alias}"
  printf '\n'
  printf '%s\n' \
    "" \
    "Mac-side Infrastructure Manager support-bundle command:" \
    "cd \"${IM_REPO}\""
  printf 'PYTHONPATH=src python3 -m infra_manager.cli remote-alpha-live-support-bundle \\\n'
  printf '  --profile-dir '
  print_double_quoted "--im-profile-dir" "${im_profile_dir}"
  printf ' \\\n'
  printf '  --output-root '
  print_double_quoted "--support-output-root" "${support_output_root}"
  printf '\n'
}

recovery_session_vault_unseal_existing() {
  local host_local_seen="false"

  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --help|-h)
        recovery_session_vault_unseal_existing_usage
        return 0
        ;;
      --host-local)
        require_recovery_option_not_seen "$1" "${host_local_seen}"
        host_local_seen="true"
        shift
        ;;
      --ssh-target|--ssh-target=*|--execute-reset|--execute-reset=*|--post-unseal-check|--post-unseal-check=*|--apply|--apply=*|--dry-run|--dry-run=*|--interactive-sudo|--interactive-sudo=*|--governed-smoke-command|--governed-smoke-command=*)
        recovery_die "recovery-session vault-unseal-existing forbids $1; P0i is host-local unseal-only and non-destructive"
        ;;
      --*=*)
        recovery_die "recovery-session vault-unseal-existing does not accept equals-form options: $1"
        ;;
      --*)
        recovery_die "unknown option for recovery-session vault-unseal-existing: $1"
        ;;
      *)
        recovery_die "unexpected positional argument for recovery-session vault-unseal-existing: $1"
        ;;
    esac
  done

  if [[ "${host_local_seen}" != "true" ]]; then
    recovery_die "recovery-session vault-unseal-existing requires --host-local; run it on the Remote Alpha host where Vault is installed and reachable"
  fi

  if [[ ! -x "${REMOTE_ALPHA_VAULT_RESET_HELPER}" ]]; then
    recovery_die "Vault reset helper is not executable: ${REMOTE_ALPHA_VAULT_RESET_HELPER}"
  fi

  printf '%s\n' \
    "Running host-local Vault unseal-only helper in the visible terminal." \
    "The operator enters any unseal key directly into the delegated Vault/helper prompt." \
    "The operator facade will not read, log, relay, persist, summarize, or capture secret material."
  exec "${REMOTE_ALPHA_VAULT_RESET_HELPER}" "--unseal-only"
}

recovery_session_evidence_check() {
  local strict_known_schema=$1
  local evidence_dir=$2
  shift 2

  if [[ "$#" -eq 0 && -z "${evidence_dir}" ]]; then
    printf '%s\n' "No recovery-session evidence paths supplied; nothing to check."
    printf '%s\n' "Evidence-check is local-only and treats supplied files as evidence/projection/diagnostics only, never authority."
    return 0
  fi

  python3 - "${strict_known_schema}" "${evidence_dir}" "$@" <<'PY'
import hashlib
import json
import pathlib
import re
import sys

strict_known_schema = sys.argv[1] == "true"
evidence_dir_arg = sys.argv[2]
args = sys.argv[3:]
if len(args) % 2 != 0:
    print("error: internal evidence-check argument mismatch", file=sys.stderr)
    raise SystemExit(2)

expected_evidence_filenames = [
    ("readiness-summary", "es-writable-state-readiness.json"),
    ("staging-record", "es-writable-state-readiness-helper-staging-record.json"),
    ("vault-workload-auth-summary", "vault-workload-auth-summary.json"),
    ("runtime-identity-summary", "runtime-identity-helper-summary.json"),
    ("vault-service-user-summary", "vault-service-user-migration-check-only.json"),
    ("vault-service-user-summary", "vault-service-user-migration-apply-summary.json"),
]

schema_interpretations = {
    "execution-substrate.remote-alpha.es-writable-state-readiness.v1": "readiness-summary",
    "execution-substrate.remote-alpha.es-writable-state-readiness-stage-provenance.v1": "readiness-staging-record",
    "execution-substrate.remote-alpha.vault-workload-auth-summary.v1": "vault-workload-auth-summary",
    "execution-substrate.remote-runtime-identity-helper-summary.v1alpha1": "runtime-identity-helper-summary",
    "execution-substrate.remote-alpha.vault-service-user-migration-summary.v1": "vault-service-user-migration-summary",
}

secret_key_pattern = re.compile(
    r'"(?:root[-_]?token|unseal[-_]?key|client[-_]?token|vault[-_]?token|api[-_]?key|jwt[-_]?svid|private[-_]?key|password|secret|secret[-_]?payload)"\s*:',
    re.IGNORECASE,
)
secret_value_patterns = [
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"\b(?:hvs|hvb|s)\.[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\b(?:xox[baprs]-[A-Za-z0-9-]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9]{20,})\b"),
]


def fail(path, classification, reason):
    print(f"error: evidence-check failed for {classification}", file=sys.stderr)
    print(f"path: {path}", file=sys.stderr)
    print(f"error_classification: {reason}", file=sys.stderr)
    raise SystemExit(1)


def print_scalar(name, value):
    if isinstance(value, bool):
        print(f"  {name}: {str(value).lower()}")
    elif isinstance(value, (str, int, float)) or value is None:
        print(f"  {name}: {value}")


def print_field(payload, field, output_name=None):
    if field in payload:
        print_scalar(output_name or field, payload[field])


def print_count(payload, field, output_name=None):
    value = payload.get(field)
    if isinstance(value, list):
        print(f"  {output_name or field + '_count'}: {len(value)}")
    elif isinstance(value, int):
        print(f"  {output_name or field + '_count'}: {value}")


def nested_dict(payload, *keys):
    current = payload
    for key in keys:
        if not isinstance(current, dict):
            return {}
        current = current.get(key)
    if isinstance(current, dict):
        return current
    return {}


def print_nested_field(payload, output_name, *keys):
    current = payload
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return
        current = current[key]
    print_scalar(output_name, current)


def print_common_status_counts(payload):
    for field in ("blockers", "warnings", "skipped", "requirements", "non_authority_labels"):
        print_count(payload, field)


def print_schema_specific_fields(payload, interpretation):
    if interpretation == "readiness-summary":
        for field in ("operation_mode", "non_mutating", "checker_mode", "overall_classification"):
            print_field(payload, field)
        for field in ("blockers", "warnings", "bounded_compatibility_edges"):
            print_count(payload, field)
    elif interpretation == "readiness-staging-record":
        for field in (
            "requested_checker_mode",
            "sudo_mode",
            "staging_occurred",
            "checker_ran",
            "sudo_unavailable",
            "wrapper_exit_code",
            "checker_exit_code",
            "transient_staging_removed",
            "staging_retained_for_diagnostics",
        ):
            print_field(payload, field)
        print_count(payload, "staged_files")
    elif interpretation == "vault-workload-auth-summary":
        for field in (
            "operation_mode",
            "mode",
            "collection_status",
            "overall_status",
            "overall_classification",
            "status",
            "result",
            "non_mutating",
        ):
            print_field(payload, field)
        print_common_status_counts(payload)
        auth_smoke = nested_dict(payload, "auth_smoke")
        for check_name in (
            "jwt_fetch",
            "vault_login",
            "token_lookup",
            "proof_read",
            "proof_runtime_secret",
            "token_revoked",
        ):
            check = nested_dict(auth_smoke, check_name)
            if "status" in check:
                print_scalar(f"auth_smoke.{check_name}_status", check["status"])
            if check_name == "proof_runtime_secret" and "field_present" in check:
                print_scalar("auth_smoke.proof_runtime_secret_field_present", check["field_present"])
    elif interpretation == "runtime-identity-helper-summary":
        for field in (
            "mode",
            "operation_mode",
            "collection_status",
            "overall_status",
            "overall_classification",
            "status",
            "result",
            "runtime_identity_helper_local_fetch",
            "non_mutating",
            "jwt_fetch_output_discarded",
            "output_discarded",
        ):
            print_field(payload, field)
        print_common_status_counts(payload)
        print_count(payload, "checks")
        print_nested_field(payload, "helper_binary.exists", "helper_binary", "exists")
        print_nested_field(payload, "spire_fetch_smoke.status", "spire_fetch_smoke", "status")
        print_nested_field(payload, "spire_fetch_smoke.output_discarded", "spire_fetch_smoke", "output_discarded")
    elif interpretation == "vault-service-user-migration-summary":
        for field in (
            "operation_mode",
            "mode",
            "collection_status",
            "overall_status",
            "overall_classification",
            "status",
            "result",
            "non_mutating",
            "apply_ready",
            "apply_performed",
            "sudo_unavailable",
        ):
            print_field(payload, field)
        print_common_status_counts(payload)


evidence_specs = []
missing_specs = []
if evidence_dir_arg:
    evidence_dir = pathlib.Path(evidence_dir_arg)
    if not evidence_dir.is_dir():
        fail(evidence_dir, "evidence-dir", "missing_directory")
    for classification, filename in expected_evidence_filenames:
        candidate = evidence_dir / filename
        if candidate.is_file():
            evidence_specs.append((classification, str(candidate), filename))
        else:
            missing_specs.append((classification, str(candidate), filename))

for i in range(0, len(args), 2):
    evidence_specs.append((args[i], args[i + 1], None))

print("Recovery-session evidence metadata (local-only; evidence/projection/diagnostics only; no authority):")
if evidence_dir_arg:
    print(f"evidence_dir: {evidence_dir_arg}")
    for classification, path, filename in missing_specs:
        print(f"- classification: {classification}")
        print(f"  expected_filename: {filename}")
        print(f"  path: {path}")
        print("  status: not_supplied")

for classification, path_text, expected_filename in evidence_specs:
    path = pathlib.Path(path_text)
    if not path.is_file():
        fail(path, classification, "missing_file")

    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        fail(path, classification, "not_utf8_json_text")

    if secret_key_pattern.search(text):
        fail(path, classification, "secret_like_key")
    for pattern in secret_value_patterns:
        if pattern.search(text):
            fail(path, classification, "secret_like_value")

    try:
        payload = json.loads(text)
    except Exception:
        fail(path, classification, "malformed_json")

    if not isinstance(payload, dict):
        fail(path, classification, "json_root_not_object")

    schema = payload.get("schema_version")
    interpretation = schema_interpretations.get(schema, "unknown")
    if strict_known_schema and interpretation == "unknown":
        fail(path, classification, "unknown_schema")

    print(f"- classification: {classification}")
    if expected_filename is not None:
        print(f"  expected_filename: {expected_filename}")
    print(f"  path: {path}")
    print(f"  bytes: {len(raw)}")
    print(f"  sha256: {hashlib.sha256(raw).hexdigest()}")
    if isinstance(schema, str):
        print(f"  schema_version: {schema}")
    else:
        print("  schema_version: None")
    print(f"  schema_interpretation: {interpretation}")
    if interpretation != "unknown":
        print_schema_specific_fields(payload, interpretation)
PY
}

recovery_session() {
  local mode=""
  local im_profile_dir="${DEFAULT_PROFILE_DIR}"
  local support_output_root="${DEFAULT_OUTPUT_ROOT}"
  local im_ssh_alias="${DEFAULT_SSH_ALIAS}"
  local mode_seen="false"
  local ssh_alias_seen="false"
  local im_profile_dir_seen="false"
  local support_output_root_seen="false"
  local strict_known_schema_seen="false"
  local evidence_dir_seen="false"
  local vault_workload_auth_summary_seen="false"
  local runtime_identity_summary_seen="false"
  local vault_service_user_summary_seen="false"
  local readiness_summary_seen="false"
  local staging_record_seen="false"
  local strict_known_schema="false"
  local evidence_dir=""
  local -a evidence_specs=()

  if [[ "${#facade_options_seen[@]}" -gt 0 ]]; then
    recovery_die "recovery-session does not accept top-level printed-command options before the subcommand: ${facade_options_seen[*]}"
  fi

  if [[ "$#" -gt 0 && "$1" == "vault-unseal-existing" ]]; then
    shift
    recovery_session_vault_unseal_existing "$@"
    return 0
  fi

  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --help|-h)
        require_recovery_option_not_seen "$1" "${mode_seen}"
        mode_seen="true"
        mode="help"
        shift
        ;;
      --plan)
        require_recovery_option_not_seen "$1" "${mode_seen}"
        mode_seen="true"
        mode="plan"
        shift
        ;;
      --inventory)
        require_recovery_option_not_seen "$1" "${mode_seen}"
        mode_seen="true"
        mode="inventory"
        shift
        ;;
      --next-steps)
        require_recovery_option_not_seen "$1" "${mode_seen}"
        mode_seen="true"
        mode="next-steps"
        shift
        ;;
      --evidence-check)
        require_recovery_option_not_seen "$1" "${mode_seen}"
        mode_seen="true"
        mode="evidence-check"
        shift
        ;;
      --ssh-alias)
        require_recovery_option_not_seen "$1" "${ssh_alias_seen}"
        require_recovery_option_value "$1" "$#" "${2:-}"
        validate_print_value "$1" "$2"
        ssh_alias_seen="true"
        im_ssh_alias=$2
        shift 2
        ;;
      --im-profile-dir)
        require_recovery_option_not_seen "$1" "${im_profile_dir_seen}"
        require_recovery_option_value "$1" "$#" "${2:-}"
        validate_print_value "$1" "$2"
        im_profile_dir_seen="true"
        im_profile_dir=$2
        shift 2
        ;;
      --support-output-root)
        require_recovery_option_not_seen "$1" "${support_output_root_seen}"
        require_recovery_option_value "$1" "$#" "${2:-}"
        validate_print_value "$1" "$2"
        support_output_root_seen="true"
        support_output_root=$2
        shift 2
        ;;
      --strict-known-schema)
        require_recovery_option_not_seen "$1" "${strict_known_schema_seen}"
        strict_known_schema_seen="true"
        strict_known_schema="true"
        shift
        ;;
      --evidence-dir)
        require_recovery_option_not_seen "$1" "${evidence_dir_seen}"
        require_recovery_option_value "$1" "$#" "${2:-}"
        evidence_dir_seen="true"
        evidence_dir=$2
        shift 2
        ;;
      --vault-workload-auth-summary)
        require_recovery_option_not_seen "$1" "${vault_workload_auth_summary_seen}"
        require_recovery_option_value "$1" "$#" "${2:-}"
        vault_workload_auth_summary_seen="true"
        evidence_specs+=("vault-workload-auth-summary" "$2")
        shift 2
        ;;
      --runtime-identity-summary)
        require_recovery_option_not_seen "$1" "${runtime_identity_summary_seen}"
        require_recovery_option_value "$1" "$#" "${2:-}"
        runtime_identity_summary_seen="true"
        evidence_specs+=("runtime-identity-summary" "$2")
        shift 2
        ;;
      --vault-service-user-summary)
        require_recovery_option_not_seen "$1" "${vault_service_user_summary_seen}"
        require_recovery_option_value "$1" "$#" "${2:-}"
        vault_service_user_summary_seen="true"
        evidence_specs+=("vault-service-user-summary" "$2")
        shift 2
        ;;
      --readiness-summary)
        require_recovery_option_not_seen "$1" "${readiness_summary_seen}"
        require_recovery_option_value "$1" "$#" "${2:-}"
        readiness_summary_seen="true"
        evidence_specs+=("readiness-summary" "$2")
        shift 2
        ;;
      --staging-record)
        require_recovery_option_not_seen "$1" "${staging_record_seen}"
        require_recovery_option_value "$1" "$#" "${2:-}"
        staging_record_seen="true"
        evidence_specs+=("staging-record" "$2")
        shift 2
        ;;
      --ssh-target|--ssh-target=*|--interactive-sudo|--interactive-sudo=*|--apply|--apply=*|--dry-run|--dry-run=*|--execute-reset|--execute-reset=*|--unseal-only|--unseal-only=*|--post-unseal-check|--post-unseal-check=*|--governed-smoke-command|--governed-smoke-command=*)
        recovery_die "recovery-session forbids $1; P0i is safe/local/print-only/evidence-check plus explicit host-local unseal-only"
        ;;
      --*=*)
        recovery_die "recovery-session does not accept equals-form options: $1"
        ;;
      --*)
        recovery_die "unknown option for recovery-session: $1"
        ;;
      *)
        recovery_die "unexpected positional argument for recovery-session: $1"
        ;;
    esac
  done

  if [[ -z "${mode}" ]]; then
    mode="plan"
  fi

  if [[ "${#evidence_specs[@]}" -gt 0 && "${mode}" != "evidence-check" ]]; then
    recovery_die "recovery-session evidence path flags require --evidence-check"
  fi
  if [[ -n "${evidence_dir}" && "${mode}" != "evidence-check" ]]; then
    recovery_die "recovery-session --evidence-dir requires --evidence-check"
  fi
  if [[ "${strict_known_schema}" == "true" && "${mode}" != "evidence-check" ]]; then
    recovery_die "recovery-session --strict-known-schema requires --evidence-check"
  fi

  case "${mode}" in
    help)
      recovery_session_usage
      ;;
    plan)
      recovery_session_plan
      ;;
    inventory)
      recovery_session_inventory
      ;;
    next-steps)
      recovery_session_next_steps "${im_profile_dir}" "${support_output_root}" "${im_ssh_alias}"
      ;;
    evidence-check)
      recovery_session_evidence_check "${strict_known_schema}" "${evidence_dir}" ${evidence_specs[@]+"${evidence_specs[@]}"}
      ;;
    *)
      recovery_die "unsupported recovery-session mode: ${mode}"
      ;;
  esac
}

print_refresh_command() {
  printf '%s\n' \
    "Mac-side Infrastructure Manager live refresh command (printed only; inert command text):" \
    "cd \"${IM_REPO}\""
  printf 'PYTHONPATH=src python3 -m infra_manager.cli remote-alpha-live-refresh \\\n'
  printf '  --profile-dir '
  print_double_quoted "--profile-dir" "${profile_dir}"
  printf ' \\\n'
  printf '  --ssh-alias '
  print_double_quoted "--ssh-alias" "${ssh_alias}"
  printf '\n'
}

print_support_bundle_command() {
  printf '%s\n' \
    "Mac-side Infrastructure Manager support-bundle command (printed only; inert command text):" \
    "cd \"${IM_REPO}\""
  printf 'PYTHONPATH=src python3 -m infra_manager.cli remote-alpha-live-support-bundle \\\n'
  printf '  --profile-dir '
  print_double_quoted "--profile-dir" "${profile_dir}"
  printf ' \\\n'
  printf '  --output-root '
  print_double_quoted "--output-root" "${output_root}"
  printf '\n'
}

print_im_commands() {
  print_refresh_command
  printf '\n'
  print_support_bundle_command
}

refuse_not_implemented() {
  local name=$1
  printf 'error: subcommand %q is not implemented in P0i and requires a later audited slice.\n' "${name}" >&2
  printf 'No helper execution routing occurred.\n' >&2
  exit 2
}

refuse_bootstrap() {
  printf 'error: vault-workload-auth-bootstrap is blocked/reopened and not available in v1.\n' >&2
  printf 'No helper execution routing occurred.\n' >&2
  exit 2
}

route_es_writable_state_readiness_check_usage() {
  printf '%s\n' \
    "Remote Alpha operator route: es-writable-state-readiness-check" \
    "Delegates only to scripts/remote_alpha_stage_es_writable_state_readiness_check.sh." \
    "Scope: check-only/non-mutating; evidence/projection only; requires --ssh-target." \
    "This route supports explicit --interactive-sudo; interactive sudo is operator-authorized and bounded to this route." \
    "The route does not eliminate the operator; it removes manual staging and command stitching." \
    "Artifacts remain evidence/projection only, not authority." \
    "" \
    "Usage:" \
    "  remote_alpha_operator.sh es-writable-state-readiness-check --ssh-target <user@host> [options]" \
    "" \
    "Allowed flags:" \
    "  --ssh-target <target>" \
    "  --mode alpha-compat|future-non-root-required" \
    "  --run-id <id>" \
    "  --output-dir <path>" \
    "  --readiness-output <path>" \
    "  --helper-staging-record-output <path>" \
    "  --provenance-output <path>" \
    "  --interactive-sudo" \
    "  --keep-staging-on-failure" \
    "  --help, -h" \
    "" \
    "Boundary: forbidden: --apply, --dry-run, arbitrary command strings, secret-like arguments." \
    "Duplicate route flags are rejected before delegation." \
    "Artifacts: preserves es-writable-state-readiness.json and es-writable-state-readiness-helper-staging-record.json." \
    "The operator route does not call Infrastructure Manager and writes no operator summary."
}

route_es_writable_state_readiness_check() {
  local ssh_target_seen="false"
  local mode_seen="false"
  local run_id_seen="false"
  local output_dir_seen="false"
  local readiness_output_seen="false"
  local helper_staging_record_output_seen="false"
  local provenance_output_seen="false"
  local interactive_sudo_seen="false"
  local keep_staging_on_failure_seen="false"
  local -a helper_args=()

  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --help|-h)
        route_es_writable_state_readiness_check_usage
        return 0
        ;;
      --ssh-target)
        require_route_option_not_seen "$1" "${ssh_target_seen}"
        require_route_option_value "$1" "$#" "${2:-}"
        ssh_target_seen="true"
        helper_args+=("$1" "$2")
        shift 2
        ;;
      --mode)
        require_route_option_not_seen "$1" "${mode_seen}"
        require_route_option_value "$1" "$#" "${2:-}"
        case "$2" in
          alpha-compat|future-non-root-required)
            ;;
          *)
            route_die "unsupported --mode for es-writable-state-readiness-check: $2"
            ;;
        esac
        mode_seen="true"
        helper_args+=("$1" "$2")
        shift 2
        ;;
      --run-id)
        require_route_option_not_seen "$1" "${run_id_seen}"
        require_route_option_value "$1" "$#" "${2:-}"
        run_id_seen="true"
        helper_args+=("$1" "$2")
        shift 2
        ;;
      --output-dir)
        require_route_option_not_seen "$1" "${output_dir_seen}"
        require_route_option_value "$1" "$#" "${2:-}"
        output_dir_seen="true"
        helper_args+=("$1" "$2")
        shift 2
        ;;
      --readiness-output)
        require_route_option_not_seen "$1" "${readiness_output_seen}"
        require_route_option_value "$1" "$#" "${2:-}"
        readiness_output_seen="true"
        helper_args+=("$1" "$2")
        shift 2
        ;;
      --helper-staging-record-output)
        require_route_option_not_seen "$1" "${helper_staging_record_output_seen}"
        require_route_option_value "$1" "$#" "${2:-}"
        helper_staging_record_output_seen="true"
        helper_args+=("$1" "$2")
        shift 2
        ;;
      --provenance-output)
        require_route_option_not_seen "$1" "${provenance_output_seen}"
        require_route_option_value "$1" "$#" "${2:-}"
        provenance_output_seen="true"
        helper_args+=("$1" "$2")
        shift 2
        ;;
      --interactive-sudo)
        require_route_option_not_seen "$1" "${interactive_sudo_seen}"
        interactive_sudo_seen="true"
        helper_args+=("$1")
        shift
        ;;
      --keep-staging-on-failure)
        require_route_option_not_seen "$1" "${keep_staging_on_failure_seen}"
        keep_staging_on_failure_seen="true"
        helper_args+=("$1")
        shift
        ;;
      --apply|--apply=*)
        route_die "es-writable-state-readiness-check forbids --apply; route is check-only/non-mutating"
        ;;
      --dry-run|--dry-run=*)
        route_die "es-writable-state-readiness-check forbids --dry-run; helper does not expose a documented dry-run route"
        ;;
      --*)
        route_die "unknown option for es-writable-state-readiness-check: $1"
        ;;
      *)
        route_die "unexpected positional argument for es-writable-state-readiness-check: $1"
        ;;
    esac
  done

  if [[ "${ssh_target_seen}" != "true" ]]; then
    route_die "es-writable-state-readiness-check requires --ssh-target <target>; host-local execution is not enabled through the operator route"
  fi

  if [[ ! -x "${REMOTE_ALPHA_ES_WRITABLE_STATE_READINESS_HELPER}" ]]; then
    route_die "readiness staged helper is not executable: ${REMOTE_ALPHA_ES_WRITABLE_STATE_READINESS_HELPER}"
  fi

  exec "${REMOTE_ALPHA_ES_WRITABLE_STATE_READINESS_HELPER}" "${helper_args[@]}"
}

readiness_session_usage() {
  printf '%s\n' \
    "Remote Alpha operator workflow: readiness-session" \
    "Runs the existing es-writable-state-readiness-check route and then verifies its two local artifacts." \
    "Scope: bounded ES Remote Alpha operator facade/workflow; evidence/projection/diagnostics only; no authority source." \
    "The human remains the operator. The workflow minimizes manual stitching; it does not eliminate prompts." \
    "Supports explicit --interactive-sudo only when the operator chooses that visible and secret-safe mode." \
    "Noninteractive sudo remains an ergonomic optimization, not a universal success criterion." \
    "Uses a fresh run-specific output directory by default unless --output-dir is supplied." \
    "" \
    "Usage:" \
    "  remote_alpha_operator.sh readiness-session --ssh-target <user@host> [options]" \
    "" \
    "Allowed flags:" \
    "  --ssh-target <target>" \
    "  --mode alpha-compat|future-non-root-required" \
    "  --output-dir <path>" \
    "  --run-id <id>" \
    "  --interactive-sudo" \
    "  --keep-staging-on-failure" \
    "  --ssh-alias <alias> (for printed IM commands only)" \
    "  --im-profile-dir <path> (for printed IM commands only)" \
    "  --support-output-root <path> (for printed IM commands only)" \
    "  --help, -h" \
    "" \
    "Boundary: forbidden: --apply, --dry-run, equals-form options, unknown flags, positional arguments, duplicate workflow flags, secret-like arguments." \
    "Post-run checks: verifies es-writable-state-readiness.json and es-writable-state-readiness-helper-staging-record.json, scans artifacts for secret-like content before reading JSON fields, validates schema names and check-only/non-mutating status, and confirms checker mode and checker-ran status." \
    "Output: prints only non-secret metadata: paths, byte counts, SHA-256 digests, schemas, blocker/warning counts, and sudo/checker status. It does not print full JSON." \
    "The workflow does not run Infrastructure Manager and writes no operator summary." \
    "IM follow-up commands are printed only as evidence/provenance actions, not authority."
}

readiness_session_validate_selected_output_dir() {
  local output_dir=$1
  local readiness_path="${output_dir}/${READINESS_ARTIFACT_NAME}"
  local staging_record_path="${output_dir}/${READINESS_STAGING_RECORD_ARTIFACT_NAME}"

  if [[ -e "${output_dir}" && ! -d "${output_dir}" ]]; then
    session_die "readiness-session output path exists but is not a directory: ${output_dir}"
  fi
  if [[ -e "${readiness_path}" ]]; then
    session_die "readiness-session refuses to reuse pre-existing artifact: ${readiness_path}"
  fi
  if [[ -e "${staging_record_path}" ]]; then
    session_die "readiness-session refuses to reuse pre-existing artifact: ${staging_record_path}"
  fi
}

readiness_session_validate_and_print_artifact_metadata() {
  local readiness_path=$1
  local staging_record_path=$2
  local requested_mode=$3

  python3 - \
    "${readiness_path}" \
    "${staging_record_path}" \
    "${requested_mode}" \
    "${READINESS_ARTIFACT_SCHEMA}" \
    "${READINESS_STAGING_RECORD_SCHEMA}" <<'PY'
import hashlib
import json
import pathlib
import re
import sys

readiness_path = pathlib.Path(sys.argv[1])
staging_record_path = pathlib.Path(sys.argv[2])
requested_mode = sys.argv[3]
readiness_schema = sys.argv[4]
staging_schema = sys.argv[5]

secret_key_pattern = re.compile(
    r'"(?:root[-_]?token|unseal[-_]?key|client[-_]?token|vault[-_]?token|api[-_]?key|jwt[-_]?svid|private[-_]?key|password|secret|secret[-_]?payload)"\s*:',
    re.IGNORECASE,
)
secret_value_patterns = [
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"\b(?:hvs|hvb|s)\.[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\b(?:xox[baprs]-[A-Za-z0-9-]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9]{20,})\b"),
]


def fail(message):
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def read_and_scan(path):
    if not path.is_file():
        fail(f"expected artifact is missing: {path}")
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        fail(f"artifact is not UTF-8 JSON text: {path}: {exc}")

    if secret_key_pattern.search(text):
        fail(f"secret-like key detected before JSON summary: {path}")
    for pattern in secret_value_patterns:
        if pattern.search(text):
            fail(f"secret-like value detected before JSON summary: {path}")

    try:
        payload = json.loads(text)
    except Exception as exc:  # noqa: BLE001
        fail(f"artifact is not valid JSON: {path}: {exc}")

    return {
        "path": str(path),
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "payload": payload,
    }


readiness = read_and_scan(readiness_path)
staging = read_and_scan(staging_record_path)
readiness_payload = readiness["payload"]
staging_payload = staging["payload"]

errors = []
if readiness_payload.get("schema_version") != readiness_schema:
    errors.append(f"unexpected readiness schema: {readiness_payload.get('schema_version')!r}")
if staging_payload.get("schema_version") != staging_schema:
    errors.append(f"unexpected staging record schema: {staging_payload.get('schema_version')!r}")
if readiness_payload.get("operation_mode") != "check_only":
    errors.append("readiness operation_mode must be check_only")
if readiness_payload.get("non_mutating") is not True:
    errors.append("readiness non_mutating must be true")
if readiness_payload.get("checker_mode") != requested_mode:
    errors.append("readiness checker_mode must match the requested mode")
if staging_payload.get("requested_checker_mode") != requested_mode:
    errors.append("staging record requested_checker_mode must match the requested mode")
if staging_payload.get("checker_ran") is not True:
    errors.append("staging record must indicate checker_ran=true")

blockers = readiness_payload.get("blockers")
warnings = readiness_payload.get("warnings")
if not isinstance(blockers, list):
    errors.append("readiness blockers must be an array")
if not isinstance(warnings, list):
    errors.append("readiness warnings must be an array")

if errors:
    for error in errors:
        print(f"error: {error}", file=sys.stderr)
    raise SystemExit(1)

checker = staging_payload.get("checker")
if not isinstance(checker, dict):
    checker = {}

print("Readiness session artifact metadata (evidence/projection/diagnostics only; no authority):")
print(f"  readiness_path: {readiness['path']}")
print(f"  readiness_bytes: {readiness['bytes']}")
print(f"  readiness_sha256: {readiness['sha256']}")
print(f"  readiness_schema: {readiness_payload.get('schema_version')}")
print(f"  readiness_operation_mode: {readiness_payload.get('operation_mode')}")
print(f"  readiness_non_mutating: {str(readiness_payload.get('non_mutating')).lower()}")
print(f"  readiness_checker_mode: {readiness_payload.get('checker_mode')}")
print(f"  readiness_overall_classification: {readiness_payload.get('overall_classification')}")
print(f"  readiness_blocker_count: {len(blockers)}")
print(f"  readiness_warning_count: {len(warnings)}")
print(f"  staging_record_path: {staging['path']}")
print(f"  staging_record_bytes: {staging['bytes']}")
print(f"  staging_record_sha256: {staging['sha256']}")
print(f"  staging_record_schema: {staging_payload.get('schema_version')}")
print(f"  staging_sudo_mode: {staging_payload.get('sudo_mode')}")
print(f"  staging_sudo_unavailable: {str(staging_payload.get('sudo_unavailable')).lower()}")
print(f"  staging_occurred: {str(staging_payload.get('staging_occurred')).lower()}")
print(f"  staging_checker_ran: {str(staging_payload.get('checker_ran')).lower()}")
print(f"  staging_checker_exit_code: {staging_payload.get('checker_exit_code')}")
print(f"  staging_wrapper_exit_code: {staging_payload.get('wrapper_exit_code')}")
print(f"  staging_transient_removed: {str(staging_payload.get('transient_staging_removed')).lower()}")
print(f"  checker_mode_matches_requested: {str(checker.get('checker_mode_matches_requested')).lower()}")
print(f"  checker_accepted_evidence: {str(checker.get('accepted_evidence')).lower()}")
PY
}

readiness_session_print_im_followups() {
  local im_profile_dir=$1
  local support_output_root=$2
  local im_ssh_alias=$3

  validate_print_value "--im-profile-dir" "${im_profile_dir}"
  validate_print_value "--support-output-root" "${support_output_root}"
  validate_print_value "--ssh-alias" "${im_ssh_alias}"

  printf '%s\n' \
    "" \
    "Follow-up IM evidence/provenance actions (printed only; not executed; not authority):" \
    "1. Mac-side Infrastructure Manager live refresh:" \
    "cd \"${IM_REPO}\""
  printf 'PYTHONPATH=src python3 -m infra_manager.cli remote-alpha-live-refresh \\\n'
  printf '  --profile-dir '
  print_double_quoted "--im-profile-dir" "${im_profile_dir}"
  printf ' \\\n'
  printf '  --ssh-alias '
  print_double_quoted "--ssh-alias" "${im_ssh_alias}"
  printf '\n'
  printf '%s\n' \
    "" \
    "2. Mac-side Infrastructure Manager support-bundle collection:" \
    "cd \"${IM_REPO}\""
  printf 'PYTHONPATH=src python3 -m infra_manager.cli remote-alpha-live-support-bundle \\\n'
  printf '  --profile-dir '
  print_double_quoted "--im-profile-dir" "${im_profile_dir}"
  printf ' \\\n'
  printf '  --output-root '
  print_double_quoted "--support-output-root" "${support_output_root}"
  printf '\n'
}

readiness_session() {
  local ssh_target=""
  local mode="${READINESS_SESSION_DEFAULT_MODE}"
  local output_dir=""
  local run_id=""
  local im_profile_dir="${DEFAULT_PROFILE_DIR}"
  local support_output_root="${DEFAULT_OUTPUT_ROOT}"
  local im_ssh_alias="${DEFAULT_SSH_ALIAS}"
  local ssh_target_seen="false"
  local mode_seen="false"
  local output_dir_seen="false"
  local run_id_seen="false"
  local interactive_sudo_seen="false"
  local keep_staging_on_failure_seen="false"
  local ssh_alias_seen="false"
  local im_profile_dir_seen="false"
  local support_output_root_seen="false"
  local interactive_sudo="false"
  local keep_staging_on_failure="false"
  local timestamp
  local readiness_path
  local staging_record_path
  local route_status=0
  local -a route_args=()

  if [[ "${#facade_options_seen[@]}" -gt 0 ]]; then
    session_die "readiness-session does not accept top-level printed-command options before the subcommand: ${facade_options_seen[*]}"
  fi

  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --help|-h)
        readiness_session_usage
        return 0
        ;;
      --ssh-target)
        require_session_option_not_seen "$1" "${ssh_target_seen}"
        require_session_option_value "$1" "$#" "${2:-}"
        ssh_target_seen="true"
        ssh_target=$2
        shift 2
        ;;
      --mode)
        require_session_option_not_seen "$1" "${mode_seen}"
        require_session_option_value "$1" "$#" "${2:-}"
        case "$2" in
          alpha-compat|future-non-root-required)
            ;;
          *)
            session_die "unsupported --mode for readiness-session: $2"
            ;;
        esac
        mode_seen="true"
        mode=$2
        shift 2
        ;;
      --output-dir)
        require_session_option_not_seen "$1" "${output_dir_seen}"
        require_session_option_value "$1" "$#" "${2:-}"
        output_dir_seen="true"
        output_dir=$2
        shift 2
        ;;
      --run-id)
        require_session_option_not_seen "$1" "${run_id_seen}"
        require_session_option_value "$1" "$#" "${2:-}"
        run_id_seen="true"
        run_id=$2
        shift 2
        ;;
      --interactive-sudo)
        require_session_option_not_seen "$1" "${interactive_sudo_seen}"
        interactive_sudo_seen="true"
        interactive_sudo="true"
        shift
        ;;
      --keep-staging-on-failure)
        require_session_option_not_seen "$1" "${keep_staging_on_failure_seen}"
        keep_staging_on_failure_seen="true"
        keep_staging_on_failure="true"
        shift
        ;;
      --ssh-alias)
        require_session_option_not_seen "$1" "${ssh_alias_seen}"
        require_session_option_value "$1" "$#" "${2:-}"
        validate_print_value "$1" "$2"
        ssh_alias_seen="true"
        im_ssh_alias=$2
        shift 2
        ;;
      --im-profile-dir)
        require_session_option_not_seen "$1" "${im_profile_dir_seen}"
        require_session_option_value "$1" "$#" "${2:-}"
        validate_print_value "$1" "$2"
        im_profile_dir=$2
        im_profile_dir_seen="true"
        shift 2
        ;;
      --support-output-root)
        require_session_option_not_seen "$1" "${support_output_root_seen}"
        require_session_option_value "$1" "$#" "${2:-}"
        validate_print_value "$1" "$2"
        support_output_root=$2
        support_output_root_seen="true"
        shift 2
        ;;
      --apply|--apply=*)
        session_die "readiness-session forbids --apply; workflow is check-only/non-mutating"
        ;;
      --dry-run|--dry-run=*)
        session_die "readiness-session forbids --dry-run; delegated route does not expose a documented dry-run mode"
        ;;
      --*=*)
        session_die "readiness-session does not accept equals-form options: $1"
        ;;
      --*)
        session_die "unknown option for readiness-session: $1"
        ;;
      *)
        session_die "unexpected positional argument for readiness-session: $1"
        ;;
    esac
  done

  if [[ "${ssh_target_seen}" != "true" ]]; then
    session_die "readiness-session requires --ssh-target <target>"
  fi

  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  if [[ -z "${run_id}" ]]; then
    run_id="readiness-session-${timestamp}-$$"
  fi
  if [[ -z "${output_dir}" ]]; then
    output_dir="${READINESS_SESSION_DEFAULT_OUTPUT_PREFIX}-${timestamp}-$$"
  fi

  readiness_session_validate_selected_output_dir "${output_dir}"

  route_args=(
    "es-writable-state-readiness-check"
    "--ssh-target" "${ssh_target}"
    "--mode" "${mode}"
    "--run-id" "${run_id}"
    "--output-dir" "${output_dir}"
  )
  if [[ "${interactive_sudo}" == "true" ]]; then
    route_args+=("--interactive-sudo")
  fi
  if [[ "${keep_staging_on_failure}" == "true" ]]; then
    route_args+=("--keep-staging-on-failure")
  fi

  printf '%s\n' "Running existing check-only readiness route; operator prompts may still occur in explicit interactive modes."
  "${SCRIPT_DIR}/remote_alpha_operator.sh" "${route_args[@]}" || route_status=$?
  if [[ "${route_status}" -ne 0 ]]; then
    printf 'error: readiness-session route execution failed; artifact metadata was not emitted.\n' >&2
    exit "${route_status}"
  fi

  readiness_path="${output_dir}/${READINESS_ARTIFACT_NAME}"
  staging_record_path="${output_dir}/${READINESS_STAGING_RECORD_ARTIFACT_NAME}"
  readiness_session_validate_and_print_artifact_metadata "${readiness_path}" "${staging_record_path}" "${mode}"
  readiness_session_print_im_followups "${im_profile_dir}" "${support_output_root}" "${im_ssh_alias}"
}

parse_facade_option_args() {
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --help|-h)
        shift
        ;;
      --profile-dir)
        require_option_value "$1" "$#"
        facade_options_seen+=("$1")
        profile_dir=$2
        shift 2
        ;;
      --profile-dir=*)
        facade_options_seen+=("--profile-dir")
        profile_dir=${1#--profile-dir=}
        shift
        ;;
      --output-root)
        require_option_value "$1" "$#"
        facade_options_seen+=("$1")
        output_root=$2
        shift 2
        ;;
      --output-root=*)
        facade_options_seen+=("--output-root")
        output_root=${1#--output-root=}
        shift
        ;;
      --ssh-alias)
        require_option_value "$1" "$#"
        facade_options_seen+=("$1")
        ssh_alias=$2
        shift 2
        ;;
      --ssh-alias=*)
        facade_options_seen+=("--ssh-alias")
        ssh_alias=${1#--ssh-alias=}
        shift
        ;;
      --*)
        die "unknown option: $1"
        ;;
      *)
        die "unexpected argument after subcommand: $1"
        ;;
    esac
  done
}

parse_args() {
  reject_secret_args "$@"

  if [[ "$#" -eq 0 ]]; then
    subcommand="help"
    return 0
  fi

  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --help|-h)
        subcommand="help"
        shift
        subcommand_args=("$@")
        return 0
        ;;
      --profile-dir)
        require_option_value "$1" "$#"
        facade_options_seen+=("$1")
        profile_dir=$2
        shift 2
        ;;
      --profile-dir=*)
        facade_options_seen+=("--profile-dir")
        profile_dir=${1#--profile-dir=}
        shift
        ;;
      --output-root)
        require_option_value "$1" "$#"
        facade_options_seen+=("$1")
        output_root=$2
        shift 2
        ;;
      --output-root=*)
        facade_options_seen+=("--output-root")
        output_root=${1#--output-root=}
        shift
        ;;
      --ssh-alias)
        require_option_value "$1" "$#"
        facade_options_seen+=("$1")
        ssh_alias=$2
        shift 2
        ;;
      --ssh-alias=*)
        facade_options_seen+=("--ssh-alias")
        ssh_alias=${1#--ssh-alias=}
        shift
        ;;
      --*)
        die "unknown option: $1"
        ;;
      *)
        subcommand=$1
        shift
        subcommand_args=("$@")
        return 0
        ;;
    esac
  done

  if [[ -z "${subcommand}" ]]; then
    subcommand="help"
  fi
}

main() {
  parse_args "$@"

  case "${subcommand}" in
    help)
      parse_facade_option_args ${subcommand_args[@]+"${subcommand_args[@]}"}
      usage
      ;;
    inventory)
      parse_facade_option_args ${subcommand_args[@]+"${subcommand_args[@]}"}
      inventory
      ;;
    print-refresh-command)
      parse_facade_option_args ${subcommand_args[@]+"${subcommand_args[@]}"}
      print_refresh_command
      ;;
    print-support-bundle-command)
      parse_facade_option_args ${subcommand_args[@]+"${subcommand_args[@]}"}
      print_support_bundle_command
      ;;
    print-im-commands)
      parse_facade_option_args ${subcommand_args[@]+"${subcommand_args[@]}"}
      print_im_commands
      ;;
    es-writable-state-readiness-check)
      route_es_writable_state_readiness_check ${subcommand_args[@]+"${subcommand_args[@]}"}
      ;;
    readiness-session)
      readiness_session ${subcommand_args[@]+"${subcommand_args[@]}"}
      ;;
    recovery-session)
      recovery_session ${subcommand_args[@]+"${subcommand_args[@]}"}
      ;;
    vault-workload-auth-bootstrap)
      refuse_bootstrap
      ;;
    vault-reset-disposable|vault-unseal|vault-unseal-existing|vault-workload-auth-check|runtime-identity-summary|vault-service-user-check|runtime-security-check)
      refuse_not_implemented "${subcommand}"
      ;;
    es-*)
      refuse_not_implemented "${subcommand}"
      ;;
    *)
      printf 'error: unknown subcommand %q is not implemented in P0i and requires a later audited slice.\n' "${subcommand}" >&2
      printf 'No helper execution routing occurred.\n' >&2
      exit 2
      ;;
  esac
}

main "$@"
