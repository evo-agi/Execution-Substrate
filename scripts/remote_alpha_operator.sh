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
REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_PUBLIC_HELPER="${SCRIPT_DIR}/remote_alpha_vault_workload_auth_check.sh"
REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_INTERNAL_HELPER="${SCRIPT_DIR}/internal/remote_alpha_vault_workload_auth_check.sh"
REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_PUBLIC_HELPER="${SCRIPT_DIR}/remote_alpha_vault_workload_auth_bootstrap.sh"
REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_INTERNAL_HELPER="${SCRIPT_DIR}/internal/remote_alpha_vault_workload_auth_bootstrap.sh"
REMOTE_ALPHA_VAULT_UNSEAL_STAGE_ROOT="/tmp/execution-substrate-remote-alpha-vault-unseal-existing"
REMOTE_ALPHA_VAULT_RESET_DRY_RUN_STAGE_ROOT="/tmp/execution-substrate-remote-alpha-vault-reset-disposable-dry-run"
REMOTE_ALPHA_VAULT_RESET_EXECUTE_STAGE_ROOT="/tmp/execution-substrate-remote-alpha-vault-reset-disposable-execute"
REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_STAGE_ROOT="/tmp/execution-substrate-remote-alpha-vault-workload-auth-check"
REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_REMOTE_SUMMARY="/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-summary.json"
REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_STAGE_ROOT="/tmp/execution-substrate-remote-alpha-vault-workload-auth-bootstrap"
REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_REMOTE_SUMMARY="/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json"
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
    "P0q adds recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --interactive-tty as a Mac-side staged bootstrap route while preserving safe plan/inventory modes and earlier recovery routes." \
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
    "  remote_alpha_operator.sh recovery-session vault-unseal-existing --ssh-target <user@host> --interactive-tty" \
    "  remote_alpha_operator.sh recovery-session vault-reset-disposable --ssh-target <user@host> --dry-run" \
    "  remote_alpha_operator.sh recovery-session vault-reset-disposable --ssh-target <user@host> --execute-reset --interactive-tty" \
    "  remote_alpha_operator.sh recovery-session vault-workload-auth-check --ssh-target <user@host> --interactive-tty" \
    "  remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap [--help|--plan|--inventory]" \
    "  remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <user@host> --execute-bootstrap --interactive-tty" \
    "" \
    "Options for printed command text only:" \
    "  --profile-dir .out/remote-alpha-m75q" \
    "  --output-root .out/remote-alpha-m75q/support-bundles" \
    "  --ssh-alias host_to_remote_linux_m75q" \
    "  --help, -h" \
    "" \
    "Implemented through P0q:" \
    "  es-writable-state-readiness-check - delegates only to scripts/remote_alpha_stage_es_writable_state_readiness_check.sh; check-only/non-mutating; requires --ssh-target; preserves es-writable-state-readiness.json and es-writable-state-readiness-helper-staging-record.json." \
    "  readiness-session - runs the existing readiness route; check-only/non-mutating; requires --ssh-target; uses a fresh output directory by default; verifies artifacts; scans for secret-like content; prints only non-secret artifact metadata and IM follow-up commands." \
    "  recovery-session - safe/local recovery skeleton; supports --plan, --inventory, --next-steps, schema-aware local evidence-check, host-local vault-unseal-existing, Mac-side interactive TTY vault-unseal-existing over the existing reset helper's --unseal-only mode, Mac-side vault-reset-disposable dry-run planning over the helper's --dry-run mode, Mac-side destructive vault-reset-disposable execute-reset over the helper's --execute-reset mode, Mac-side vault-workload-auth-check over the fixed workload-auth public/internal helper pair, safe vault-workload-auth-bootstrap planning, and Mac-side vault-workload-auth-bootstrap execution over the fixed bootstrap public/internal helper pair; writes no operator summary." \
    "" \
    "The operator facade does not invoke IM refresh or support-bundle collection and does not add ES Vault token brokerage, runtime identity, service-user, config/TLS, binary deployment, writable-state ownership, or generic helper dispatch." \
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
    "implemented through P0q:" \
    "  help - show bounded facade scope and options" \
    "  inventory - show this static non-secret inventory" \
    "  print-refresh-command - print Mac-side IM live-refresh command text only" \
    "  print-support-bundle-command - print Mac-side IM support-bundle command text only" \
    "  print-im-commands - print both Mac-side IM command texts only" \
    "  es-writable-state-readiness-check - delegates to existing readiness staged helper; check-only/non-mutating; preserves es-writable-state-readiness.json and es-writable-state-readiness-helper-staging-record.json" \
    "  readiness-session - runs the existing readiness route; check-only/non-mutating; verifies the two expected artifacts; prints non-secret paths, byte counts, SHA-256 digests, schemas, blocker/warning counts, and sudo/checker status" \
    "  recovery-session - safe/local skeleton for recovery sequencing; prints plan, static helper inventory, next-step commands, performs schema-aware local JSON evidence interpretation, or runs explicit vault-unseal-existing modes" \
    "  recovery-session vault-unseal-existing --host-local - delegates only to scripts/remote_alpha_reset_disposable_vault.sh --unseal-only; host-local; secret-sensitive; non-destructive; not reset; not workload-auth bootstrap; not IM; not CP proof" \
    "  recovery-session vault-unseal-existing --ssh-target <target> --interactive-tty - Mac-side route; stages only scripts/remote_alpha_reset_disposable_vault.sh to a route-specific remote scratch directory and invokes only --unseal-only through ssh -tt; no transcript, no summary, no support bundle" \
    "  recovery-session vault-reset-disposable --ssh-target <target> --dry-run - Mac-side dry-run planning route; stages only scripts/remote_alpha_reset_disposable_vault.sh to a route-specific remote scratch directory and invokes only --dry-run; non-destructive; no transcript, no summary, no support bundle" \
    "  recovery-session vault-reset-disposable --ssh-target <target> --execute-reset --interactive-tty - destructive Mac-side operator route; stages only scripts/remote_alpha_reset_disposable_vault.sh to a route-specific remote scratch directory and invokes only --execute-reset through ssh -tt; no transcript, no summary, no support bundle" \
    "  recovery-session vault-workload-auth-check --ssh-target <target> --interactive-tty - Mac-side staged evidence route; stages only scripts/remote_alpha_vault_workload_auth_check.sh and scripts/internal/remote_alpha_vault_workload_auth_check.sh; invokes only the staged public workload-auth helper through ssh -tt; leaves the canonical summary remote at /var/tmp/execution-substrate-remote-alpha/vault-workload-auth-summary.json; no transcript, no summary copy-back, no support bundle" \
    "  recovery-session vault-workload-auth-bootstrap [--help|--plan|--inventory] - safe local/print-only planning surface for post-reset Vault workload-auth bootstrap" \
    "  recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --interactive-tty - Mac-side staged bootstrap route; stages only scripts/remote_alpha_vault_workload_auth_bootstrap.sh and scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh; invokes only the staged public bootstrap helper through ssh -tt; leaves the canonical bootstrap summary remote at /var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json; no transcript, no summary copy-back, no support bundle" \
    "" \
    "future/not implemented:" \
    "  runtime identity summary generation - not implemented in P0q; requires later audited evidence route" \
    "  Vault service-user check/apply execution - not implemented in P0q; remains separate" \
    "  runtime security check - not implemented in P0q; requires later audited slice" \
    "  other staged ES helper delegation - not implemented in P0q; requires later audited slice" \
    "" \
    "blocked/reopened:" \
    "  live validation of vault-workload-auth-bootstrap execution - not performed in P0q" \
    "" \
    "non-claims:" \
    "  not production, not HA, not multi-tenant, not a general deployment architecture" \
    "  not IM automation or reconciliation, not CP authority, not ES Vault token brokerage" \
    "  vault-reset-disposable --dry-run is non-destructive planning only: it does not stop Vault, move raft storage, init or unseal Vault, run post-unseal checks, run IM, or collect support bundles" \
    "  vault-reset-disposable --execute-reset is destructive and must be run only when the operator intentionally wants to reset disposable Remote Alpha Vault state; it requires --interactive-tty and the existing exact confirmation phrase RESET DISPOSABLE REMOTE ALPHA VAULT in the visible remote helper/Vault terminal" \
    "  vault-workload-auth-check is separate post-reset evidence/projection only: not reset/unseal, not workload-auth bootstrap, not ES token brokerage, not IM refresh/support-bundle collection, not CP proof, not runtime identity generation, and not readiness authority" \
    "  vault-workload-auth-bootstrap configures expected Vault objects only: not workload-auth success, not reset/unseal, not workload-auth check, not IM/support-bundle/CP proof, not runtime identity generation, and not ES Vault token brokerage" \
    "  must not make IM a remote reconciler, CP a Vault/runtime recovery authority, ES a Vault token broker, or Remote Alpha a deployment architecture" \
    "  no operator-owned summary, support bundle, report, or new authority artifact is written; readiness artifacts remain delegated helper evidence"
}

recovery_session_usage() {
  printf '%s\n' \
    "Remote Alpha operator workflow: recovery-session" \
    "P0q scope: safe/local recovery planning and evidence interpretation plus explicit vault-unseal-existing modes, Mac-side vault-reset-disposable dry-run planning, Mac-side destructive vault-reset-disposable execute-reset, Mac-side vault-workload-auth-check evidence routing, safe vault-workload-auth-bootstrap planning, and Mac-side vault-workload-auth-bootstrap execution." \
    "The human remains the operator. Secret-sensitive unseal key entry happens only in the visible terminal owned by the delegated helper, SSH, and Vault CLI." \
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
    "  remote_alpha_operator.sh recovery-session vault-unseal-existing --ssh-target <user@host> --interactive-tty" \
    "  remote_alpha_operator.sh recovery-session vault-reset-disposable --ssh-target <user@host> --dry-run" \
    "  remote_alpha_operator.sh recovery-session vault-reset-disposable --ssh-target <user@host> --execute-reset --interactive-tty" \
    "  remote_alpha_operator.sh recovery-session vault-workload-auth-check --ssh-target <user@host> --interactive-tty" \
    "  remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap [--help|--plan|--inventory]" \
    "  remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <user@host> --execute-bootstrap --interactive-tty" \
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
    "Submode exception: recovery-session vault-reset-disposable --ssh-target <target> --dry-run is implemented as Mac-side dry-run planning only; it is non-destructive and does not stop Vault, move raft storage, init or unseal Vault, run post-unseal checks, run IM, or collect support bundles." \
    "Submode exception: recovery-session vault-reset-disposable --ssh-target <target> --execute-reset --interactive-tty is implemented as a destructive Mac-side operator route; it stages only the reset helper, invokes only --execute-reset, and relies on the human operator to type the exact confirmation phrase and Vault secrets only in the visible remote terminal." \
    "Submode exception: recovery-session vault-workload-auth-check --ssh-target <target> --interactive-tty is implemented as a Mac-side staged evidence route; it stages only the workload-auth public/internal helper pair, invokes only the staged public helper, leaves the canonical summary on the remote host, and does not bootstrap workload auth or broker Vault tokens." \
    "Submode exception: recovery-session vault-workload-auth-bootstrap [--help|--plan|--inventory] is safe local/print-only planning; it does not run SSH, sudo, Vault, workload-auth checks, reset/unseal, IM, support bundles, CP proof, runtime identity generation, or live bootstrap." \
    "Submode exception: recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --interactive-tty is a Mac-side staged bootstrap route; it stages only the bootstrap public/internal helper pair and relies on the human operator to type Vault bootstrap authority and proof secret values only in the visible remote helper prompt." \
    "The evidence-check reads only supplied local JSON files, scans for secret-like content before parsing JSON, prints path/byte/SHA-256/schema/safe status metadata only, prints no full JSON, creates no summary file, and writes no .out." \
    "Recognized schemas are interpreted through explicit safe-field allowlists. Unknown schemas are allowed by default with schema_interpretation=unknown; --strict-known-schema fails unknown schemas."
}

recovery_session_vault_unseal_existing_usage() {
  printf '%s\n' \
    "Remote Alpha recovery-session mode: vault-unseal-existing" \
    "P0j scope: explicit secret-sensitive non-destructive unseal-existing flow with host-local and Mac-side interactive TTY topologies." \
    "Host-local mode must be run on the Remote Alpha host where Vault is installed and reachable." \
    "Mac-side mode stages only scripts/remote_alpha_reset_disposable_vault.sh to the remote host and invokes only --unseal-only through ssh -tt." \
    "No transcript, log, .out, report, support bundle, operator summary, IM refresh, workload-auth check, reset, or CP proof is created or run." \
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
    "  remote_alpha_operator.sh recovery-session vault-unseal-existing --ssh-target <user@host> --interactive-tty" \
    "" \
    "Allowed flags:" \
    "  --help" \
    "  --host-local" \
    "  --ssh-target <target>" \
    "  --interactive-tty" \
    "" \
    "Topology rules: --host-local and --ssh-target are mutually exclusive; --ssh-target requires --interactive-tty; --interactive-tty requires --ssh-target; bare vault-unseal-existing fails; the SSH target must be a single target, not an option or shell command." \
    "Forbidden in P0j: --execute-reset, --post-unseal-check, --unseal-only, --apply, --dry-run, --interactive-sudo, --governed-smoke-command, --keep-staging-on-failure, arbitrary command strings, helper path overrides, unknown flags, duplicate flags, positional args beyond the submode, secret-like flags, and equals-form options." \
    "Non-claims: not reset, not workload-auth bootstrap or check, not IM refresh/support-bundle, not CP proof, not default noninteractive readiness validation, not ES Vault token brokerage, and not Remote Alpha deployment/provisioning/reconciliation architecture."
}

recovery_session_vault_reset_disposable_usage() {
  printf '%s\n' \
    "Remote Alpha recovery-session mode: vault-reset-disposable" \
    "P0m scope: explicit Mac-side disposable Vault reset dry-run planning route plus destructive execute-reset operator route." \
    "Dry-run stages only scripts/remote_alpha_reset_disposable_vault.sh to the remote host and invokes only --dry-run." \
    "Execute-reset stages only scripts/remote_alpha_reset_disposable_vault.sh to the remote host and invokes only --execute-reset through ssh -tt." \
    "The helper supports --dry-run; the operator facade passes it explicitly." \
    "Dry-run remains the prerequisite/planning route." \
    "Live execute-reset must be run only when the operator intentionally wants to reset disposable Remote Alpha Vault state." \
    "No transcript, tee/script capture, log, .out, report, support bundle, operator summary, IM refresh, workload-auth check, post-unseal check, runtime identity summary, or CP proof is created or run." \
    "Delegates only to: scripts/remote_alpha_reset_disposable_vault.sh --dry-run or scripts/remote_alpha_reset_disposable_vault.sh --execute-reset" \
    "" \
    "Non-destructive behavior:" \
    "  This is planning/inspection only." \
    "  It does not stop Vault." \
    "  It does not move raft storage." \
    "  It does not run vault operator init." \
    "  It does not unseal Vault." \
    "  It does not run post-unseal checks." \
    "  It does not run Infrastructure Manager." \
    "  It does not collect support bundles." \
    "  Execute-reset is a destructive explicit operator route and requires --interactive-tty." \
    "  Artifacts and outputs remain evidence/projection/diagnostics only, never authority." \
    "" \
    "Destructive execute-reset behavior:" \
    "  This is destructive for disposable Remote Alpha Vault state." \
    "  The existing exact confirmation phrase is RESET DISPOSABLE REMOTE ALPHA VAULT." \
    "  The operator types that phrase only in the visible remote helper/Vault terminal." \
    "  Vault init output, root token, unseal key, and Vault prompts are handled only by the human operator in the visible remote terminal." \
    "  The phrase and Vault secrets must never be passed by CLI args, env files, files, logs, .out, reports, support bundles, retained bundles, or Codex output." \
    "  The operator facade does not receive, parse, log, store, echo, summarize, or persist the phrase or secret material." \
    "" \
    "Usage:" \
    "  remote_alpha_operator.sh recovery-session vault-reset-disposable --ssh-target <user@host> --dry-run" \
    "  remote_alpha_operator.sh recovery-session vault-reset-disposable --ssh-target <user@host> --execute-reset --interactive-tty" \
    "" \
    "Allowed flags:" \
    "  --help" \
    "  --ssh-target <target>" \
    "  --dry-run" \
    "  --execute-reset" \
    "  --interactive-tty" \
    "" \
    "Topology rules: Mac-side only; --ssh-target is required; exactly one of --dry-run or --execute-reset is required; --execute-reset requires --interactive-tty; --dry-run rejects --interactive-tty; --host-local is not accepted; the SSH target must be a single target, not an option or shell command." \
    "Forbidden in P0m: --unseal-only, --post-unseal-check, --host-local, --interactive-sudo, --apply, --governed-smoke-command, --keep-staging-on-failure, workload-auth flags, IM commands, support-bundle commands, runtime-identity flags, arbitrary command strings, helper path overrides, unknown flags, duplicate flags, positional args beyond the submode, secret-like flags, and equals-form options." \
    "Non-claims: not workload-auth bootstrap or check, not IM refresh/support-bundle, not CP proof, not runtime identity generation, not default noninteractive readiness validation, not ES Vault token brokerage, and not Remote Alpha deployment/provisioning/reconciliation architecture."
}

recovery_session_vault_workload_auth_check_usage() {
  printf '%s\n' \
    "Remote Alpha recovery-session mode: vault-workload-auth-check" \
    "P0n scope: explicit Mac-side staged workload-auth evidence route, separate from reset/unseal." \
    "Mac-side mode stages only scripts/remote_alpha_vault_workload_auth_check.sh and scripts/internal/remote_alpha_vault_workload_auth_check.sh to the remote host." \
    "The public/internal relative layout is preserved so the public helper can source the internal helper." \
    "The remote command invokes only the staged public workload-auth helper through ssh -tt and uses the explicit interactive TTY path for root when required." \
    "No transcript, tee/script capture, log, .out, report, support bundle, operator summary, IM refresh, runtime identity generation, reset/unseal, workload-auth bootstrap, ES token brokerage, or CP proof is created or run." \
    "Canonical remote summary: /var/tmp/execution-substrate-remote-alpha/vault-workload-auth-summary.json" \
    "Summary is evidence/projection only, not readiness authority." \
    "" \
    "Secret posture:" \
    "  The route does not accept, parse, print, copy, log, relay, persist, summarize, or handle JWT-SVIDs, Vault client tokens, proof secret payloads, root tokens, unseal keys, API keys, private keys, passwords, or secret payloads." \
    "  It relies only on the existing helper's transient in-process handling and summary redaction behavior." \
    "  It does not print full summary JSON and does not copy the summary back to Mac .out." \
    "" \
    "Usage:" \
    "  remote_alpha_operator.sh recovery-session vault-workload-auth-check --ssh-target <user@host> --interactive-tty" \
    "" \
    "Allowed flags:" \
    "  --help" \
    "  --ssh-target <target>" \
    "  --interactive-tty" \
    "" \
    "Topology rules: Mac-side only; --ssh-target is required; --interactive-tty is required; --host-local is not accepted; the SSH target must be a single target, not an option or shell command." \
    "Forbidden in P0n: --host-local, --dry-run, --execute-reset, --unseal-only, --post-unseal-check, --apply, --interactive-sudo, --governed-smoke-command, helper override flags, Vault address/role/audience/path/proof-path overrides, SPIFFE ID overrides, config path overrides, summary path overrides, container probe image overrides, SPIRE socket overrides, arbitrary command strings, unknown flags, duplicate flags, positional args beyond the submode, secret-like flags, and equals-form options." \
    "Non-claims: not reset/unseal, not workload-auth bootstrap, not ES Vault token brokerage, not IM refresh/support-bundle, not CP proof, not runtime identity generation, not Vault production readiness, not governed execution proof, and not Remote Alpha deployment/provisioning/reconciliation architecture."
}

recovery_session_vault_workload_auth_bootstrap_usage() {
  printf '%s\n' \
    "Remote Alpha recovery-session mode: vault-workload-auth-bootstrap" \
    "P0q scope: safe local/print-only planning plus Mac-side staged bootstrap execution for post-reset Vault workload-auth bootstrap." \
    "Execution stages only the dedicated bootstrap public/internal helper pair and invokes only the staged public helper over ssh -tt." \
    "No workload-auth check, reset/unseal, IM execution, support-bundle collection, CP proof, runtime identity generation, Mac .out, report, support bundle, operator summary, helper bundle, unrelated helper staging, or generic helper dispatch occurs." \
    "" \
    "Usage:" \
    "  remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap" \
    "  remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --help" \
    "  remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --plan" \
    "  remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --inventory" \
    "  remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <user@host> --execute-bootstrap --interactive-tty" \
    "" \
    "Allowed flags:" \
    "  --help" \
    "  --plan" \
    "  --inventory" \
    "  --ssh-target <target> (only with --execute-bootstrap)" \
    "  --execute-bootstrap" \
    "  --interactive-tty (only with --execute-bootstrap)" \
    "" \
    "Default behavior: print the bootstrap plan/help and exit zero." \
    "Topology rules: --execute-bootstrap requires --ssh-target <target> and --interactive-tty; --ssh-target and --interactive-tty are valid only with --execute-bootstrap; the SSH target must be a single target, not an option or shell command." \
    "Forbidden in P0q: --host-local, --execute-reset, --dry-run, --unseal-only, --post-unseal-check, --apply, --interactive-sudo, --governed-smoke-command, --keep-staging-on-failure, helper override flags, proof secret value flags, arbitrary commands, unknown flags, duplicate flags, positional args beyond the submode/mode, secret-like flags, and equals-form options." \
    "Secret posture: Vault bootstrap authority and proof secret values are entered only through the visible/silent remote helper TTY prompt; never through CLI args, env vars, files, logs, .out, reports, support bundles, retained bundles, CP artifacts, transcripts, tee, script, or Codex output." \
    "Non-claims: not workload-auth success, not reset/unseal, not workload-auth check, not ES Vault token brokerage, not IM refresh/support-bundle, not CP proof, not runtime identity generation, not Vault production readiness, not governed execution proof, and not Remote Alpha deployment/provisioning/reconciliation architecture."
}

recovery_session_vault_workload_auth_bootstrap_plan() {
  printf '%s\n' \
    "Remote Alpha Vault workload-auth bootstrap plan (P0q safe modes plus staged execution)" \
    "classification: safe local planning text; evidence/projection/diagnostics only; no authority source" \
    "default behavior: print this plan/help and exit zero; no live tools run" \
    "" \
    "Safe post-reset triage basis:" \
    "  route mechanics partially passed: the Mac-side workload-auth evidence route wrote the canonical remote summary" \
    "  safe fields observed: vault.initialized=true, vault.sealed=false, vault.auth_mount=jwt, vault.role=service_execution, vault.audience=vault" \
    "  workload-auth functional failure: vault_workload_auth_smoke=fail and auth_smoke.vault_login=fail" \
    "  conservative classification: Vault JWT login rejected or not configured" \
    "  uncertainty: this does not prove which Vault object is missing or mismatched" \
    "" \
    "Likely post-reset Vault objects/config inferred from helper/docs/tests:" \
    "  auth mount: jwt" \
    "  JWT auth config: SPIRE JWT validation material and bound issuer" \
    "  role: service_execution" \
    "  role_type=jwt" \
    "  user_claim=sub" \
    "  bound_audiences=vault" \
    "  bound_subject=spiffe://execution.internal/workload" \
    "  policy such as runtime-identity-proof" \
    "  KV v2 proof secret path: proof-secrets/data/runtime-identity-vault-login" \
    "  KV v2 proof runtime secret path: proof-secrets/data/codex-runtime-profile" \
    "  proof runtime field shape: api_key present and non-empty; value never printed" \
    "  workload-zone config alignment: /etc/execution-substrate/vault/workload-zone-vault-config.json" \
    "" \
    "Implemented execution contract:" \
    "  recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --interactive-tty" \
    "  stages only scripts/remote_alpha_vault_workload_auth_bootstrap.sh and scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh" \
    "  root token must never be accepted as a CLI arg, env var, file, .out, report, support bundle, retained bundle, or Codex output" \
    "  any root-token use must happen only through an explicit visible or silent operator prompt in the named secret-sensitive mode" \
    "  no transcript capture, no tee, no script" \
    "  proof secret values must never be printed, copied, summarized, or logged" \
    "  bootstrap configures expected Vault objects only and must not claim workload-auth success" \
    "  remote-only summary: /var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json" \
    "  workload-auth check remains a separate command after bootstrap" \
    "" \
    "Non-claims:" \
    "  not workload-auth success" \
    "  not reset or unseal" \
    "  not workload-auth check execution" \
    "  not IM refresh or support-bundle collection" \
    "  not CP proof" \
    "  not runtime identity generation" \
    "  not ES Vault token brokerage" \
    "  not Vault production readiness" \
    "  not governed execution proof" \
    "  not Remote Alpha deployment, provisioning, or reconciliation architecture"
}

recovery_session_vault_workload_auth_bootstrap_inventory() {
  printf '%s\n' \
    "Remote Alpha Vault workload-auth bootstrap inventory (P0q)" \
    "classification: static local inventory only; no live host state inspection; no helper execution" \
    "" \
    "implemented in P0q:" \
    "  recovery-session vault-workload-auth-bootstrap --help - print safe usage and boundaries" \
    "  recovery-session vault-workload-auth-bootstrap --plan - print the inferred bootstrap plan and future execution contract" \
    "  recovery-session vault-workload-auth-bootstrap --inventory - print this static inventory" \
    "  recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --interactive-tty - stage the dedicated bootstrap helper pair and invoke only the public helper over ssh -tt" \
    "" \
    "not implemented/run in P0q:" \
    "  live validation - not performed" \
    "  workload-auth check execution, reset/unseal, IM, support bundle, CP proof, and runtime identity generation - not part of bootstrap" \
    "" \
    "likely bootstrap objects to account for later:" \
    "  auth mount jwt" \
    "  JWT auth config with SPIRE validation material and bound issuer" \
    "  role service_execution with role_type=jwt, user_claim=sub, bound_audiences=vault, bound_subject=spiffe://execution.internal/workload" \
    "  policy such as runtime-identity-proof" \
    "  KV v2 proof paths proof-secrets/data/runtime-identity-vault-login and proof-secrets/data/codex-runtime-profile" \
    "  api_key field present and non-empty; proof secret value never printed" \
    "  workload-zone config /etc/execution-substrate/vault/workload-zone-vault-config.json" \
    "" \
    "safe output posture:" \
    "  safe modes are text only; execution writes only a remote non-secret summary; no Mac .out; no operator summary; no support bundle; no report" \
    "  evidence/projection only; not authority" \
    "  ES does not broker Vault tokens; Vault owns token, secret, and lease authority; SPIRE owns JWT-SVID issuance"
}

recovery_session_plan() {
  printf '%s\n' \
    "Remote Alpha recovery-session plan (P0q Vault workload-auth bootstrap route added)" \
    "classification: bounded proof/support helper; evidence/projection/diagnostics only; no authority source" \
    "default behavior: print this plan/help and exit zero; no live tools run" \
    "" \
    "implemented safe/local or explicitly host-local:" \
    "  inventory/status - safe local planning and static inventory only; no host inspection" \
    "  evidence-check - local-only metadata check of supplied existing JSON evidence files" \
    "  next-steps - print readiness-session and IM command text only" \
    "  vault-unseal-existing --host-local - implemented host-local operator mode for the Linux Remote Alpha host; secret-sensitive but non-destructive; delegates only to the existing reset helper's --unseal-only flow" \
    "  vault-unseal-existing --ssh-target <target> --interactive-tty - implemented Mac-side operator mode; stages only the existing reset helper, invokes only --unseal-only over ssh -tt, and attempts cleanup without transcript capture" \
    "  vault-reset-disposable --ssh-target <target> --dry-run - implemented Mac-side dry-run planning mode; stages only the existing reset helper, invokes only --dry-run over SSH, and attempts cleanup without transcript capture" \
    "  vault-reset-disposable --ssh-target <target> --execute-reset --interactive-tty - implemented destructive Mac-side operator mode; stages only the existing reset helper, invokes only --execute-reset over ssh -tt, and attempts cleanup without transcript capture" \
    "  vault-workload-auth-check --ssh-target <target> --interactive-tty - implemented Mac-side staged evidence mode; stages only the workload-auth public/internal helper pair, invokes only the staged public helper over ssh -tt, leaves the canonical summary on the remote host, and attempts cleanup without transcript capture" \
    "  vault-workload-auth-bootstrap [--help|--plan|--inventory] - implemented safe local/print-only planning mode; no SSH, no sudo, no Vault, no root-token prompt, no proof secret creation, no workload-auth check, no JSON, no .out, no summary" \
    "  vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --interactive-tty - implemented Mac-side staged bootstrap mode; stages only the dedicated bootstrap public/internal helper pair, invokes only the public helper over ssh -tt, leaves the non-secret summary remote, and attempts cleanup without transcript capture" \
    "" \
    "future explicit audited slices:" \
    "  runtime identity summary generation - future audited evidence route; runtime identity remains a reopened seam" \
    "  service-user check/apply - remains separate; apply is mutating and not part of P0q recovery-session" \
    "  live validation of workload-auth bootstrap execution - future separate validation only if still needed" \
    "" \
    "separate IM actions:" \
    "  IM refresh and support-bundle collection are printed only as separate IM evidence/provenance actions" \
    "  recovery-session does not execute IM and does not make IM authority" \
    "" \
    "non-claims:" \
    "  not CP recovery authority, not Vault production lifecycle, not ES Vault token brokerage" \
    "  not Remote Alpha deployment, provisioning, reconciliation, production, HA, or multi-tenant architecture" \
    "  vault-reset-disposable --dry-run is non-destructive: it does not stop Vault, move raft storage, init or unseal Vault, run post-unseal checks, run IM, or collect support bundles" \
    "  vault-reset-disposable --execute-reset is destructive and requires the existing exact confirmation phrase RESET DISPOSABLE REMOTE ALPHA VAULT in the visible remote helper/Vault terminal" \
    "  vault-workload-auth-check is evidence/projection only: it is not workload-auth bootstrap, not ES Vault token brokerage, not readiness authority, and not reset/unseal" \
    "  vault-workload-auth-bootstrap configures expected Vault objects only: it is not workload-auth success, not ES Vault token brokerage, and not workload-auth check execution" \
    "  the phrase, Vault init output, root token, unseal key, and Vault prompt interactions are never accepted through args/env/files/logs/artifacts/Codex output" \
    "  no post-unseal/runtime-identity/service-user/IM/support-bundle/CP-proof bundling is added in P0q; workload-auth evidence and bootstrap execution remain separate routes" \
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
    "  recovery-session vault-unseal-existing --ssh-target <target> --interactive-tty - implemented Mac-side explicit operator mode; stages only scripts/remote_alpha_reset_disposable_vault.sh and invokes only --unseal-only through ssh -tt; no summary file" \
    "  recovery-session vault-reset-disposable --ssh-target <target> --dry-run - implemented Mac-side dry-run planning mode; stages only scripts/remote_alpha_reset_disposable_vault.sh and invokes only --dry-run through SSH; non-destructive; no summary file" \
    "  recovery-session vault-reset-disposable --ssh-target <target> --execute-reset --interactive-tty - implemented destructive Mac-side operator mode; stages only scripts/remote_alpha_reset_disposable_vault.sh and invokes only --execute-reset through ssh -tt; no summary file; no transcript capture" \
    "  recovery-session vault-workload-auth-check --ssh-target <target> --interactive-tty - implemented Mac-side staged evidence mode; stages only scripts/remote_alpha_vault_workload_auth_check.sh and scripts/internal/remote_alpha_vault_workload_auth_check.sh; invokes only the staged public helper through ssh -tt; leaves /var/tmp/execution-substrate-remote-alpha/vault-workload-auth-summary.json on the remote host; no summary copy-back; no transcript capture" \
    "  recovery-session vault-workload-auth-bootstrap [--help|--plan|--inventory] - safe local/print-only planning; no SSH, no sudo, no Vault, no root-token prompt, no proof secret creation, no workload-auth check, no .out, no JSON, no summary" \
    "  recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --interactive-tty - implemented Mac-side staged bootstrap mode; stages only scripts/remote_alpha_vault_workload_auth_bootstrap.sh and scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh; invokes only the staged public helper through ssh -tt; leaves /var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json on the remote host; no summary copy-back; no transcript capture" \
    "" \
    "check-only evidence helpers:" \
    "  scripts/remote_alpha_vault_workload_auth_check.sh - host-local root check; transient JWT/Vault token handling inside helper; now also reachable through the P0n Mac-side staged evidence route; not bootstrap; not ES token brokerage" \
    "  scripts/remote_alpha_runtime_identity_helper_summary.sh - host-local runtime identity helper summary; dry-run/check-only available; future audited evidence route" \
    "  scripts/remote_alpha_migrate_vault_service_user.sh --check-only - host-local Vault service-user migration check; check-only default; apply remains separate" \
    "" \
    "secret-sensitive or destructive helpers:" \
    "  scripts/remote_alpha_reset_disposable_vault.sh --dry-run - implemented through explicit Mac-side vault-reset-disposable dry-run planning; non-destructive; does not stop Vault, move raft storage, init, unseal, run post-unseal checks, run IM, or collect support bundles" \
    "  scripts/remote_alpha_reset_disposable_vault.sh --unseal-only - implemented through explicit host-local and Mac-side interactive TTY vault-unseal-existing; secret-sensitive; non-destructive" \
    "  scripts/remote_alpha_reset_disposable_vault.sh --execute-reset - implemented through explicit Mac-side vault-reset-disposable --execute-reset --interactive-tty; destructive exact-phrase operator mode; no post-unseal check, workload-auth check, IM refresh, support bundle, runtime identity, or CP proof bundling" \
    "" \
    "blocked/reopened:" \
    "  live vault-workload-auth-bootstrap validation - not run in P0q; no workload-auth success claim" \
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

recovery_session_vault_workload_auth_bootstrap() {
  local mode=""
  local mode_seen="false"
  local ssh_target_seen="false"
  local execute_bootstrap_seen="false"
  local interactive_tty_seen="false"
  local ssh_target=""

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
      --ssh-target)
        require_recovery_option_not_seen "$1" "${ssh_target_seen}"
        require_recovery_option_value "$1" "$#" "${2:-}"
        ssh_target_seen="true"
        ssh_target=$2
        shift 2
        ;;
      --execute-bootstrap)
        require_recovery_option_not_seen "$1" "${execute_bootstrap_seen}"
        require_recovery_option_not_seen "$1" "${mode_seen}"
        execute_bootstrap_seen="true"
        mode_seen="true"
        mode="execute-bootstrap"
        shift
        ;;
      --interactive-tty)
        require_recovery_option_not_seen "$1" "${interactive_tty_seen}"
        interactive_tty_seen="true"
        shift
        ;;
      --host-local|--host-local=*|--execute-reset|--execute-reset=*|--dry-run|--dry-run=*|--unseal-only|--unseal-only=*|--post-unseal-check|--post-unseal-check=*|--apply|--apply=*|--interactive-sudo|--interactive-sudo=*|--governed-smoke-command|--governed-smoke-command=*|--keep-staging-on-failure|--keep-staging-on-failure=*)
        recovery_die "recovery-session vault-workload-auth-bootstrap forbids $1; P0q does not combine bootstrap with reset, unseal, checks, IM, support bundles, runtime identity, or CP proof"
        ;;
      --vault-addr|--vault-addr=*|--vault-address|--vault-address=*|--vault-role|--vault-role=*|--role|--role=*|--vault-audience|--vault-audience=*|--audience|--audience=*|--auth-mount|--auth-mount=*|--vault-auth-mount|--vault-auth-mount=*|--vault-path|--vault-path=*|--proof-path|--proof-path=*|--proof-read-path|--proof-read-path=*|--proof-runtime-secret-path|--proof-runtime-secret-path=*|--proof-runtime-secret-field|--proof-runtime-secret-field=*|--spiffe-id|--spiffe-id=*|--workload-spiffe-id|--workload-spiffe-id=*|--summary-path|--summary-path=*|--config-path|--config-path=*|--workload-zone-config-path|--workload-zone-config-path=*|--container-probe-image|--container-probe-image=*|--spire-agent-socket-path|--spire-agent-socket-path=*|--spire-server-socket-path|--spire-server-socket-path=*)
        recovery_die "recovery-session vault-workload-auth-bootstrap forbids helper override flag $1; P0q uses fixed documented bootstrap values only"
        ;;
      --proof-secret-value|--proof-secret-value=*|--proof-runtime-secret-value|--proof-runtime-secret-value=*|--codex-credential-value|--codex-credential-value=*|--secret-value|--secret-value=*)
        recovery_die "recovery-session vault-workload-auth-bootstrap forbids proof secret value flag $1; proof secret values must never be passed, printed, copied, summarized, or logged"
        ;;
      --*=*)
        recovery_die "recovery-session vault-workload-auth-bootstrap does not accept equals-form options: $1"
        ;;
      --*)
        recovery_die "unknown option for recovery-session vault-workload-auth-bootstrap: $1"
        ;;
      *)
        recovery_die "unexpected positional argument for recovery-session vault-workload-auth-bootstrap: $1"
        ;;
    esac
  done

  if [[ -z "${mode}" ]]; then
    mode="plan"
  fi

  if [[ "${execute_bootstrap_seen}" != "true" && "${ssh_target_seen}" == "true" ]]; then
    recovery_die "recovery-session vault-workload-auth-bootstrap --ssh-target is valid only with --execute-bootstrap"
  fi
  if [[ "${execute_bootstrap_seen}" != "true" && "${interactive_tty_seen}" == "true" ]]; then
    recovery_die "recovery-session vault-workload-auth-bootstrap --interactive-tty is valid only with --execute-bootstrap"
  fi
  if [[ "${execute_bootstrap_seen}" == "true" && "${ssh_target_seen}" != "true" ]]; then
    recovery_die "recovery-session vault-workload-auth-bootstrap --execute-bootstrap requires --ssh-target <target>"
  fi
  if [[ "${execute_bootstrap_seen}" == "true" && "${interactive_tty_seen}" != "true" ]]; then
    recovery_die "recovery-session vault-workload-auth-bootstrap --execute-bootstrap requires --interactive-tty"
  fi
  if [[ "${execute_bootstrap_seen}" == "true" ]]; then
    recovery_session_vault_workload_auth_bootstrap_validate_ssh_target "${ssh_target}"
  fi

  case "${mode}" in
    help)
      recovery_session_vault_workload_auth_bootstrap_usage
      ;;
    plan)
      recovery_session_vault_workload_auth_bootstrap_plan
      ;;
    inventory)
      recovery_session_vault_workload_auth_bootstrap_inventory
      ;;
    execute-bootstrap)
      recovery_session_vault_workload_auth_bootstrap_remote "${ssh_target}"
      ;;
    *)
      recovery_die "unsupported recovery-session vault-workload-auth-bootstrap mode: ${mode}"
      ;;
  esac
}

recovery_session_vault_workload_auth_bootstrap_require_command() {
  command -v "$1" >/dev/null 2>&1 || recovery_die "$1 is required for Mac-side vault-workload-auth-bootstrap staging"
}

recovery_session_vault_workload_auth_bootstrap_require_local_tty() {
  [[ -t 0 ]] || recovery_die "recovery-session vault-workload-auth-bootstrap --execute-bootstrap requires visible local terminal stdin; no staging or SSH occurred"
  [[ -t 1 ]] || recovery_die "recovery-session vault-workload-auth-bootstrap --execute-bootstrap requires visible local terminal stdout; no staging or SSH occurred"
}

recovery_session_vault_workload_auth_bootstrap_validate_ssh_target() {
  local ssh_target=$1
  case "${ssh_target}" in
    -*|*[[:space:]]*|*';'*|*'`'*|*'$('*|*'|'*|*'&'*|*'<'*|*'>'*)
      recovery_die "recovery-session vault-workload-auth-bootstrap --ssh-target must be a single SSH target, not an option or shell command"
      ;;
  esac
}

recovery_session_vault_workload_auth_bootstrap_stage_remote() {
  local ssh_target=$1
  local remote_stage_dir=$2
  local remote_public_helper_path=$3
  local remote_internal_helper_path=$4

  ssh "${ssh_target}" /bin/bash -s -- "${remote_stage_dir}" <<'REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_PREPARE'
set -euo pipefail
stage_dir=$1
rm -rf -- "${stage_dir}"
mkdir -p -- "${stage_dir}/scripts/internal"
chmod 0700 "${stage_dir}" "${stage_dir}/scripts" "${stage_dir}/scripts/internal"
REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_PREPARE

  scp "${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_PUBLIC_HELPER}" "${ssh_target}:${remote_public_helper_path}"
  scp "${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_INTERNAL_HELPER}" "${ssh_target}:${remote_internal_helper_path}"
}

recovery_session_vault_workload_auth_bootstrap_cleanup_remote() {
  local ssh_target=$1
  local remote_stage_dir=$2

  ssh "${ssh_target}" /bin/bash -s -- "${remote_stage_dir}" <<'REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_CLEANUP'
set -euo pipefail
stage_dir=$1
rm -rf -- "${stage_dir}" || true
REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_CLEANUP
}

recovery_session_vault_workload_auth_bootstrap_run_remote() {
  local ssh_target=$1
  local remote_stage_dir=$2
  local remote_public_helper_path=$3
  local remote_internal_helper_path=$4
  local remote_command remote_shell_command

  printf -v remote_command 'set -euo pipefail; stage_dir=%q; helper_path=%q; internal_helper_path=%q; cleanup() { rm -rf -- "${stage_dir}" || true; }; trap cleanup EXIT; chmod 0700 "${helper_path}"; chmod 0600 "${internal_helper_path}" 2>/dev/null || true; "${helper_path}"' "${remote_stage_dir}" "${remote_public_helper_path}" "${remote_internal_helper_path}"
  printf -v remote_shell_command 'exec /bin/bash -c %q' "${remote_command}"
  ssh -tt "${ssh_target}" "${remote_shell_command}"
}

recovery_session_vault_workload_auth_bootstrap_remote() {
  local ssh_target=$1
  local run_id remote_stage_dir remote_public_helper_path remote_internal_helper_path remote_status cleanup_status

  recovery_session_vault_workload_auth_bootstrap_require_local_tty
  recovery_session_vault_workload_auth_bootstrap_require_command ssh
  recovery_session_vault_workload_auth_bootstrap_require_command scp

  if [[ ! -x "${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_PUBLIC_HELPER}" ]]; then
    recovery_die "Vault workload-auth bootstrap public helper is not executable: ${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_PUBLIC_HELPER}"
  fi
  if [[ ! -r "${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_INTERNAL_HELPER}" ]]; then
    recovery_die "Vault workload-auth bootstrap internal helper is not readable: ${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_INTERNAL_HELPER}"
  fi

  run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
  remote_stage_dir="${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_STAGE_ROOT}/${run_id}"
  remote_public_helper_path="${remote_stage_dir}/scripts/remote_alpha_vault_workload_auth_bootstrap.sh"
  remote_internal_helper_path="${remote_stage_dir}/scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh"

  printf '%s\n' \
    "Running Mac-side Vault workload-auth bootstrap through an explicit interactive SSH TTY." \
    "Staging only scripts/remote_alpha_vault_workload_auth_bootstrap.sh and scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh." \
    "Invoking only the staged public bootstrap helper; no helper override flags are accepted or passed." \
    "The operator enters Vault bootstrap authority and any proof secret value only into the visible remote helper prompt." \
    "Canonical bootstrap summary stays remote at ${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_REMOTE_SUMMARY}." \
    "No transcript, tee/script capture, .out, report, support bundle, operator summary, generated Mac artifact, workload-auth check, reset/unseal, IM refresh, runtime identity generation, ES token brokerage, or CP proof is created or run." \
    "The operator facade will not read, log, relay, persist, summarize, copy, or print root tokens, Vault tokens, proof secret material, JWT-SVIDs, API keys, private keys, passwords, or secret payloads."

  if ! recovery_session_vault_workload_auth_bootstrap_stage_remote "${ssh_target}" "${remote_stage_dir}" "${remote_public_helper_path}" "${remote_internal_helper_path}"; then
    recovery_session_vault_workload_auth_bootstrap_cleanup_remote "${ssh_target}" "${remote_stage_dir}" || true
    return 1
  fi

  set +e
  recovery_session_vault_workload_auth_bootstrap_run_remote "${ssh_target}" "${remote_stage_dir}" "${remote_public_helper_path}" "${remote_internal_helper_path}"
  remote_status=$?
  set -e

  set +e
  recovery_session_vault_workload_auth_bootstrap_cleanup_remote "${ssh_target}" "${remote_stage_dir}"
  cleanup_status=$?
  set -e
  if [[ "${cleanup_status}" -ne 0 ]]; then
    printf '%s\n' "warning: Mac-side vault-workload-auth-bootstrap could not verify remote staged helper cleanup; inspect the route-specific scratch path manually from a visible terminal." >&2
  fi

  if [[ "${remote_status}" -eq 0 ]]; then
    printf '%s\n' \
      "Mac-side vault-workload-auth-bootstrap route finished; staged helper cleanup was attempted." \
      "Canonical remote bootstrap summary path: ${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_REMOTE_SUMMARY}" \
      "The summary remains on the remote host; this route did not copy it back to Mac .out and did not print full summary JSON." \
      "Workload-auth check remains a separate post-bootstrap command and was not run here."
  else
    printf '%s\n' "Mac-side vault-workload-auth-bootstrap route failed; staged helper cleanup was attempted." >&2
  fi

  if [[ "${remote_status}" -eq 0 && "${cleanup_status}" -ne 0 ]]; then
    return "${cleanup_status}"
  fi
  return "${remote_status}"
}

recovery_session_vault_unseal_existing_require_command() {
  command -v "$1" >/dev/null 2>&1 || recovery_die "$1 is required for Mac-side vault-unseal-existing staging"
}

recovery_session_vault_unseal_existing_require_local_tty() {
  [[ -t 0 ]] || recovery_die "recovery-session vault-unseal-existing --ssh-target requires visible local terminal stdin; no staging or SSH occurred"
  [[ -t 1 ]] || recovery_die "recovery-session vault-unseal-existing --ssh-target requires visible local terminal stdout; no staging or SSH occurred"
}

recovery_session_vault_unseal_existing_validate_ssh_target() {
  local ssh_target=$1
  case "${ssh_target}" in
    -*|*[[:space:]]*|*';'*|*'`'*|*'$('*|*'|'*|*'&'*|*'<'*|*'>'*)
      recovery_die "recovery-session vault-unseal-existing --ssh-target must be a single SSH target, not an option or shell command"
      ;;
  esac
}

recovery_session_vault_unseal_existing_stage_remote() {
  local ssh_target=$1
  local remote_stage_dir=$2
  local remote_helper_path=$3

  ssh "${ssh_target}" /bin/bash -s -- "${remote_stage_dir}" <<'REMOTE_ALPHA_VAULT_UNSEAL_PREPARE'
set -euo pipefail
stage_dir=$1
rm -rf -- "${stage_dir}"
mkdir -p -- "${stage_dir}"
chmod 0700 "${stage_dir}"
REMOTE_ALPHA_VAULT_UNSEAL_PREPARE

  scp "${REMOTE_ALPHA_VAULT_RESET_HELPER}" "${ssh_target}:${remote_helper_path}"
}

recovery_session_vault_unseal_existing_cleanup_remote() {
  local ssh_target=$1
  local remote_stage_dir=$2

  ssh "${ssh_target}" /bin/bash -s -- "${remote_stage_dir}" <<'REMOTE_ALPHA_VAULT_UNSEAL_CLEANUP'
set -euo pipefail
stage_dir=$1
rm -rf -- "${stage_dir}" || true
REMOTE_ALPHA_VAULT_UNSEAL_CLEANUP
}

recovery_session_vault_unseal_existing_run_remote() {
  local ssh_target=$1
  local remote_stage_dir=$2
  local remote_helper_path=$3
  local remote_command remote_shell_command

  printf -v remote_command 'set -euo pipefail; stage_dir=%q; helper_path=%q; cleanup() { rm -rf -- "${stage_dir}" || true; }; trap cleanup EXIT; chmod 0700 "${helper_path}"; "${helper_path}" --unseal-only' "${remote_stage_dir}" "${remote_helper_path}"
  printf -v remote_shell_command 'exec /bin/bash -c %q' "${remote_command}"
  ssh -tt "${ssh_target}" "${remote_shell_command}"
}

recovery_session_vault_unseal_existing_remote() {
  local ssh_target=$1
  local run_id remote_stage_dir remote_helper_path remote_status cleanup_status

  recovery_session_vault_unseal_existing_require_local_tty
  recovery_session_vault_unseal_existing_require_command ssh
  recovery_session_vault_unseal_existing_require_command scp

  run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
  remote_stage_dir="${REMOTE_ALPHA_VAULT_UNSEAL_STAGE_ROOT}/${run_id}"
  remote_helper_path="${remote_stage_dir}/remote_alpha_reset_disposable_vault.sh"

  printf '%s\n' \
    "Running Mac-side Vault unseal-existing through an explicit interactive SSH TTY." \
    "Staging only scripts/remote_alpha_reset_disposable_vault.sh and invoking only --unseal-only." \
    "The operator enters any unseal key directly into the visible SSH/Vault/helper prompt." \
    "The operator facade will not read, log, relay, persist, summarize, or capture secret material."

  if ! recovery_session_vault_unseal_existing_stage_remote "${ssh_target}" "${remote_stage_dir}" "${remote_helper_path}"; then
    recovery_session_vault_unseal_existing_cleanup_remote "${ssh_target}" "${remote_stage_dir}" || true
    return 1
  fi

  set +e
  recovery_session_vault_unseal_existing_run_remote "${ssh_target}" "${remote_stage_dir}" "${remote_helper_path}"
  remote_status=$?
  set -e

  set +e
  recovery_session_vault_unseal_existing_cleanup_remote "${ssh_target}" "${remote_stage_dir}"
  cleanup_status=$?
  set -e
  if [[ "${cleanup_status}" -ne 0 ]]; then
    printf '%s\n' "warning: Mac-side vault-unseal-existing could not verify remote staged helper cleanup; inspect the route-specific scratch path manually from a visible terminal." >&2
  fi

  printf '%s\n' \
    "Mac-side vault-unseal-existing route finished; staged helper cleanup was attempted." \
    "Post-unseal evidence checks, IM refresh, support-bundle collection, and workload-auth checks are separate follow-up actions and were not executed here."

  if [[ "${remote_status}" -eq 0 && "${cleanup_status}" -ne 0 ]]; then
    return "${cleanup_status}"
  fi
  return "${remote_status}"
}

recovery_session_vault_unseal_existing() {
  local host_local_seen="false"
  local ssh_target_seen="false"
  local interactive_tty_seen="false"
  local ssh_target=""

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
      --ssh-target)
        require_recovery_option_not_seen "$1" "${ssh_target_seen}"
        require_recovery_option_value "$1" "$#" "${2:-}"
        ssh_target_seen="true"
        ssh_target=$2
        shift 2
        ;;
      --interactive-tty)
        require_recovery_option_not_seen "$1" "${interactive_tty_seen}"
        interactive_tty_seen="true"
        shift
        ;;
      --execute-reset|--execute-reset=*|--post-unseal-check|--post-unseal-check=*|--unseal-only|--unseal-only=*|--apply|--apply=*|--dry-run|--dry-run=*|--interactive-sudo|--interactive-sudo=*|--governed-smoke-command|--governed-smoke-command=*|--keep-staging-on-failure|--keep-staging-on-failure=*)
        recovery_die "recovery-session vault-unseal-existing forbids $1; P0j is unseal-only, non-destructive, and does not combine checks"
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

  if [[ "${host_local_seen}" == "true" && "${ssh_target_seen}" == "true" ]]; then
    recovery_die "recovery-session vault-unseal-existing requires exactly one topology: --host-local or --ssh-target <target> --interactive-tty"
  fi
  if [[ "${interactive_tty_seen}" == "true" && "${ssh_target_seen}" != "true" ]]; then
    recovery_die "recovery-session vault-unseal-existing --interactive-tty requires --ssh-target <target>"
  fi
  if [[ "${ssh_target_seen}" == "true" && "${interactive_tty_seen}" != "true" ]]; then
    recovery_die "recovery-session vault-unseal-existing --ssh-target requires --interactive-tty"
  fi
  if [[ "${host_local_seen}" != "true" && "${ssh_target_seen}" != "true" ]]; then
    recovery_die "recovery-session vault-unseal-existing requires --host-local or --ssh-target <target> --interactive-tty"
  fi
  if [[ "${ssh_target_seen}" == "true" ]]; then
    recovery_session_vault_unseal_existing_validate_ssh_target "${ssh_target}"
  fi

  if [[ ! -x "${REMOTE_ALPHA_VAULT_RESET_HELPER}" ]]; then
    recovery_die "Vault reset helper is not executable: ${REMOTE_ALPHA_VAULT_RESET_HELPER}"
  fi

  if [[ "${ssh_target_seen}" == "true" ]]; then
    recovery_session_vault_unseal_existing_remote "${ssh_target}"
    return $?
  fi

  printf '%s\n' \
    "Running host-local Vault unseal-only helper in the visible terminal." \
    "The operator enters any unseal key directly into the delegated Vault/helper prompt." \
    "The operator facade will not read, log, relay, persist, summarize, or capture secret material."
  exec "${REMOTE_ALPHA_VAULT_RESET_HELPER}" "--unseal-only"
}

recovery_session_vault_reset_disposable_require_command() {
  command -v "$1" >/dev/null 2>&1 || recovery_die "$1 is required for Mac-side vault-reset-disposable staging"
}

recovery_session_vault_reset_disposable_require_local_tty() {
  [[ -t 0 ]] || recovery_die "recovery-session vault-reset-disposable --execute-reset requires visible local terminal stdin; no staging or SSH occurred"
  [[ -t 1 ]] || recovery_die "recovery-session vault-reset-disposable --execute-reset requires visible local terminal stdout; no staging or SSH occurred"
}

recovery_session_vault_reset_disposable_validate_ssh_target() {
  local ssh_target=$1
  case "${ssh_target}" in
    -*|*[[:space:]]*|*';'*|*'`'*|*'$('*|*'|'*|*'&'*|*'<'*|*'>'*)
      recovery_die "recovery-session vault-reset-disposable --ssh-target must be a single SSH target, not an option or shell command"
      ;;
  esac
}

recovery_session_vault_reset_disposable_stage_remote() {
  local ssh_target=$1
  local remote_stage_dir=$2
  local remote_helper_path=$3

  ssh "${ssh_target}" /bin/bash -s -- "${remote_stage_dir}" <<'REMOTE_ALPHA_VAULT_RESET_DRY_RUN_PREPARE'
set -euo pipefail
stage_dir=$1
rm -rf -- "${stage_dir}"
mkdir -p -- "${stage_dir}"
chmod 0700 "${stage_dir}"
REMOTE_ALPHA_VAULT_RESET_DRY_RUN_PREPARE

  scp "${REMOTE_ALPHA_VAULT_RESET_HELPER}" "${ssh_target}:${remote_helper_path}"
}

recovery_session_vault_reset_disposable_cleanup_remote() {
  local ssh_target=$1
  local remote_stage_dir=$2

  ssh "${ssh_target}" /bin/bash -s -- "${remote_stage_dir}" <<'REMOTE_ALPHA_VAULT_RESET_DRY_RUN_CLEANUP'
set -euo pipefail
stage_dir=$1
rm -rf -- "${stage_dir}" || true
REMOTE_ALPHA_VAULT_RESET_DRY_RUN_CLEANUP
}

recovery_session_vault_reset_disposable_run_remote() {
  local ssh_target=$1
  local remote_stage_dir=$2
  local remote_helper_path=$3
  local helper_mode=$4
  local remote_command remote_shell_command

  case "${helper_mode}" in
    --dry-run)
      printf -v remote_command 'set -euo pipefail; stage_dir=%q; helper_path=%q; cleanup() { rm -rf -- "${stage_dir}" || true; }; trap cleanup EXIT; chmod 0700 "${helper_path}"; "${helper_path}" --dry-run' "${remote_stage_dir}" "${remote_helper_path}"
      printf -v remote_shell_command 'exec /bin/bash -c %q' "${remote_command}"
      ssh "${ssh_target}" "${remote_shell_command}"
      ;;
    --execute-reset)
      printf -v remote_command 'set -euo pipefail; stage_dir=%q; helper_path=%q; cleanup() { rm -rf -- "${stage_dir}" || true; }; trap cleanup EXIT; chmod 0700 "${helper_path}"; "${helper_path}" --execute-reset' "${remote_stage_dir}" "${remote_helper_path}"
      printf -v remote_shell_command 'exec /bin/bash -c %q' "${remote_command}"
      ssh -tt "${ssh_target}" "${remote_shell_command}"
      ;;
    *)
      recovery_die "internal error: unsupported vault-reset-disposable helper mode ${helper_mode}"
      ;;
  esac
}

recovery_session_vault_reset_disposable_remote() {
  local ssh_target=$1
  local helper_mode=$2
  local run_id remote_stage_dir remote_helper_path remote_status cleanup_status

  recovery_session_vault_reset_disposable_require_command ssh
  recovery_session_vault_reset_disposable_require_command scp
  if [[ "${helper_mode}" == "--execute-reset" ]]; then
    recovery_session_vault_reset_disposable_require_local_tty
  fi

  run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
  if [[ "${helper_mode}" == "--execute-reset" ]]; then
    remote_stage_dir="${REMOTE_ALPHA_VAULT_RESET_EXECUTE_STAGE_ROOT}/${run_id}"
  else
    remote_stage_dir="${REMOTE_ALPHA_VAULT_RESET_DRY_RUN_STAGE_ROOT}/${run_id}"
  fi
  remote_helper_path="${remote_stage_dir}/remote_alpha_reset_disposable_vault.sh"

  if [[ "${helper_mode}" == "--execute-reset" ]]; then
    printf '%s\n' \
      "Running Mac-side disposable Vault execute-reset through an explicit interactive SSH TTY." \
      "Staging only scripts/remote_alpha_reset_disposable_vault.sh and invoking only --execute-reset." \
      "This route is destructive for disposable Remote Alpha Vault state and should run only when the operator intentionally wants that reset." \
      "The operator handles confirmation, Vault init output, root token, unseal key, and Vault prompts only in the visible SSH/Vault/helper terminal." \
      "The operator facade will not read, log, relay, persist, summarize, or capture the confirmation phrase or secret material." \
      "No transcript, tee/script capture, .out, report, support bundle, operator summary, generated JSON, post-unseal check, workload-auth check, runtime identity summary, IM refresh, or CP proof is created or run."
  else
    printf '%s\n' \
      "Running Mac-side disposable Vault reset dry-run planning route." \
      "Staging only scripts/remote_alpha_reset_disposable_vault.sh and invoking only --dry-run." \
      "This route is non-destructive: it does not stop Vault, move raft storage, init or unseal Vault, run post-unseal checks, run workload-auth checks, run IM, or collect support bundles." \
      "No transcript, tee/script capture, .out, report, support bundle, operator summary, or generated JSON is created."
  fi

  if ! recovery_session_vault_reset_disposable_stage_remote "${ssh_target}" "${remote_stage_dir}" "${remote_helper_path}"; then
    recovery_session_vault_reset_disposable_cleanup_remote "${ssh_target}" "${remote_stage_dir}" || true
    return 1
  fi

  set +e
  recovery_session_vault_reset_disposable_run_remote "${ssh_target}" "${remote_stage_dir}" "${remote_helper_path}" "${helper_mode}"
  remote_status=$?
  set -e

  set +e
  recovery_session_vault_reset_disposable_cleanup_remote "${ssh_target}" "${remote_stage_dir}"
  cleanup_status=$?
  set -e
  if [[ "${cleanup_status}" -ne 0 ]]; then
    if [[ "${helper_mode}" == "--execute-reset" ]]; then
      printf '%s\n' "error: Mac-side vault-reset-disposable execute-reset could not verify remote staged helper cleanup; inspect the route-specific scratch path manually from a visible terminal." >&2
    else
      printf '%s\n' "warning: Mac-side vault-reset-disposable dry-run could not verify remote staged helper cleanup; inspect the route-specific scratch path manually." >&2
    fi
  fi

  if [[ "${helper_mode}" == "--execute-reset" ]]; then
    printf '%s\n' \
      "Mac-side vault-reset-disposable execute-reset route finished; staged helper cleanup was attempted." \
      "Post-reset evidence checks, post-unseal checks, workload-auth checks, runtime identity summaries, IM refresh, support-bundle collection, and CP proof were not executed here."
  else
    printf '%s\n' \
      "Mac-side vault-reset-disposable dry-run route finished; staged helper cleanup was attempted." \
      "Execute-reset is a separate destructive exact-phrase route; IM refresh and support-bundle collection were not executed here."
  fi

  if [[ "${remote_status}" -eq 0 && "${cleanup_status}" -ne 0 ]]; then
    return "${cleanup_status}"
  fi
  return "${remote_status}"
}

recovery_session_vault_reset_disposable() {
  local ssh_target_seen="false"
  local dry_run_seen="false"
  local execute_reset_seen="false"
  local interactive_tty_seen="false"
  local ssh_target=""

  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --help|-h)
        recovery_session_vault_reset_disposable_usage
        return 0
        ;;
      --ssh-target)
        require_recovery_option_not_seen "$1" "${ssh_target_seen}"
        require_recovery_option_value "$1" "$#" "${2:-}"
        ssh_target_seen="true"
        ssh_target=$2
        shift 2
        ;;
      --dry-run)
        require_recovery_option_not_seen "$1" "${dry_run_seen}"
        dry_run_seen="true"
        shift
        ;;
      --execute-reset)
        require_recovery_option_not_seen "$1" "${execute_reset_seen}"
        execute_reset_seen="true"
        shift
        ;;
      --interactive-tty)
        require_recovery_option_not_seen "$1" "${interactive_tty_seen}"
        interactive_tty_seen="true"
        shift
        ;;
      --unseal-only|--unseal-only=*|--post-unseal-check|--post-unseal-check=*|--host-local|--host-local=*|--interactive-sudo|--interactive-sudo=*|--apply|--apply=*|--governed-smoke-command|--governed-smoke-command=*|--keep-staging-on-failure|--keep-staging-on-failure=*)
        recovery_die "recovery-session vault-reset-disposable forbids $1; P0m does not combine reset, unseal, post-unseal checks, workload-auth, IM, support bundles, runtime identity, or CP proof"
        ;;
      --*=*)
        recovery_die "recovery-session vault-reset-disposable does not accept equals-form options: $1"
        ;;
      --*)
        recovery_die "unknown option for recovery-session vault-reset-disposable: $1"
        ;;
      *)
        recovery_die "unexpected positional argument for recovery-session vault-reset-disposable: $1"
        ;;
    esac
  done

  if [[ "${ssh_target_seen}" != "true" ]]; then
    recovery_die "recovery-session vault-reset-disposable requires --ssh-target <target>"
  fi
  if [[ "${dry_run_seen}" == "true" && "${execute_reset_seen}" == "true" ]]; then
    recovery_die "recovery-session vault-reset-disposable requires exactly one mode: --dry-run or --execute-reset"
  fi
  if [[ "${dry_run_seen}" != "true" && "${execute_reset_seen}" != "true" ]]; then
    recovery_die "recovery-session vault-reset-disposable requires --dry-run or --execute-reset"
  fi
  if [[ "${execute_reset_seen}" == "true" && "${interactive_tty_seen}" != "true" ]]; then
    recovery_die "recovery-session vault-reset-disposable --execute-reset requires --interactive-tty"
  fi
  if [[ "${dry_run_seen}" == "true" && "${interactive_tty_seen}" == "true" ]]; then
    recovery_die "recovery-session vault-reset-disposable forbids --interactive-tty with --dry-run; interactive TTY is only for --execute-reset"
  fi
  recovery_session_vault_reset_disposable_validate_ssh_target "${ssh_target}"

  if [[ ! -x "${REMOTE_ALPHA_VAULT_RESET_HELPER}" ]]; then
    recovery_die "Vault reset helper is not executable: ${REMOTE_ALPHA_VAULT_RESET_HELPER}"
  fi

  if [[ "${execute_reset_seen}" == "true" ]]; then
    recovery_session_vault_reset_disposable_remote "${ssh_target}" "--execute-reset"
  else
    recovery_session_vault_reset_disposable_remote "${ssh_target}" "--dry-run"
  fi
}

recovery_session_vault_workload_auth_check_require_command() {
  command -v "$1" >/dev/null 2>&1 || recovery_die "$1 is required for Mac-side vault-workload-auth-check staging"
}

recovery_session_vault_workload_auth_check_require_local_tty() {
  [[ -t 0 ]] || recovery_die "recovery-session vault-workload-auth-check requires visible local terminal stdin; no staging or SSH occurred"
  [[ -t 1 ]] || recovery_die "recovery-session vault-workload-auth-check requires visible local terminal stdout; no staging or SSH occurred"
}

recovery_session_vault_workload_auth_check_validate_ssh_target() {
  local ssh_target=$1
  case "${ssh_target}" in
    -*|*[[:space:]]*|*';'*|*'`'*|*'$('*|*'|'*|*'&'*|*'<'*|*'>'*)
      recovery_die "recovery-session vault-workload-auth-check --ssh-target must be a single SSH target, not an option or shell command"
      ;;
  esac
}

recovery_session_vault_workload_auth_check_stage_remote() {
  local ssh_target=$1
  local remote_stage_dir=$2
  local remote_public_helper_path=$3
  local remote_internal_helper_path=$4

  ssh "${ssh_target}" /bin/bash -s -- "${remote_stage_dir}" <<'REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_PREPARE'
set -euo pipefail
stage_dir=$1
rm -rf -- "${stage_dir}"
mkdir -p -- "${stage_dir}/scripts/internal"
chmod 0700 "${stage_dir}" "${stage_dir}/scripts" "${stage_dir}/scripts/internal"
REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_PREPARE

  scp "${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_PUBLIC_HELPER}" "${ssh_target}:${remote_public_helper_path}"
  scp "${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_INTERNAL_HELPER}" "${ssh_target}:${remote_internal_helper_path}"
}

recovery_session_vault_workload_auth_check_cleanup_remote() {
  local ssh_target=$1
  local remote_stage_dir=$2

  ssh "${ssh_target}" /bin/bash -s -- "${remote_stage_dir}" <<'REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_CLEANUP'
set -euo pipefail
stage_dir=$1
rm -rf -- "${stage_dir}" || true
REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_CLEANUP
}

recovery_session_vault_workload_auth_check_run_remote() {
  local ssh_target=$1
  local remote_stage_dir=$2
  local remote_public_helper_path=$3
  local remote_internal_helper_path=$4
  local remote_command remote_shell_command

  printf -v remote_command 'set -euo pipefail; stage_dir=%q; helper_path=%q; internal_helper_path=%q; cleanup() { rm -rf -- "${stage_dir}" || true; }; trap cleanup EXIT; chmod 0700 "${helper_path}"; chmod 0600 "${internal_helper_path}" 2>/dev/null || true; if [[ "$(id -u)" == "0" ]]; then "${helper_path}"; else sudo "${helper_path}"; fi' "${remote_stage_dir}" "${remote_public_helper_path}" "${remote_internal_helper_path}"
  printf -v remote_shell_command 'exec /bin/bash -c %q' "${remote_command}"
  ssh -tt "${ssh_target}" "${remote_shell_command}"
}

recovery_session_vault_workload_auth_check_print_success_next_steps() {
  printf '%s\n' \
    "Mac-side vault-workload-auth-check route finished; staged helper cleanup was attempted." \
    "Canonical remote summary path: ${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_REMOTE_SUMMARY}" \
    "The summary remains on the remote host; this route did not copy it back to Mac .out and did not print full summary JSON." \
    "After separate IM/local evidence collection makes the summary available locally, use:" \
    "bash scripts/remote_alpha_operator.sh recovery-session --evidence-check --vault-workload-auth-summary <local-path-to-vault-workload-auth-summary.json>" \
    "" \
    "Separate IM evidence/provenance actions (printed only; not executed; not authority):"
  print_refresh_command
  printf '\n'
  print_support_bundle_command
}

recovery_session_vault_workload_auth_check_remote() {
  local ssh_target=$1
  local run_id remote_stage_dir remote_public_helper_path remote_internal_helper_path remote_status cleanup_status

  recovery_session_vault_workload_auth_check_require_local_tty
  recovery_session_vault_workload_auth_check_require_command ssh
  recovery_session_vault_workload_auth_check_require_command scp

  run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
  remote_stage_dir="${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_STAGE_ROOT}/${run_id}"
  remote_public_helper_path="${remote_stage_dir}/scripts/remote_alpha_vault_workload_auth_check.sh"
  remote_internal_helper_path="${remote_stage_dir}/scripts/internal/remote_alpha_vault_workload_auth_check.sh"

  printf '%s\n' \
    "Running Mac-side Vault workload-auth evidence check through an explicit interactive SSH TTY." \
    "Staging only scripts/remote_alpha_vault_workload_auth_check.sh and scripts/internal/remote_alpha_vault_workload_auth_check.sh." \
    "Invoking only the staged public workload-auth helper; no helper override flags are accepted or passed." \
    "Canonical summary stays remote at ${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_REMOTE_SUMMARY}." \
    "No transcript, tee/script capture, .out, report, support bundle, operator summary, generated JSON, reset/unseal, IM refresh, runtime identity generation, workload-auth bootstrap, ES token brokerage, or CP proof is created or run." \
    "The operator facade will not read, log, relay, persist, summarize, copy, or print JWT-SVIDs, Vault tokens, proof secret material, root tokens, unseal keys, API keys, private keys, passwords, or secret payloads."

  if ! recovery_session_vault_workload_auth_check_stage_remote "${ssh_target}" "${remote_stage_dir}" "${remote_public_helper_path}" "${remote_internal_helper_path}"; then
    recovery_session_vault_workload_auth_check_cleanup_remote "${ssh_target}" "${remote_stage_dir}" || true
    return 1
  fi

  set +e
  recovery_session_vault_workload_auth_check_run_remote "${ssh_target}" "${remote_stage_dir}" "${remote_public_helper_path}" "${remote_internal_helper_path}"
  remote_status=$?
  set -e

  set +e
  recovery_session_vault_workload_auth_check_cleanup_remote "${ssh_target}" "${remote_stage_dir}"
  cleanup_status=$?
  set -e
  if [[ "${cleanup_status}" -ne 0 ]]; then
    printf '%s\n' "warning: Mac-side vault-workload-auth-check could not verify remote staged helper cleanup; inspect the route-specific scratch path manually from a visible terminal." >&2
  fi

  if [[ "${remote_status}" -eq 0 ]]; then
    recovery_session_vault_workload_auth_check_print_success_next_steps
  else
    printf '%s\n' "Mac-side vault-workload-auth-check route failed; staged helper cleanup was attempted." >&2
  fi

  if [[ "${remote_status}" -eq 0 && "${cleanup_status}" -ne 0 ]]; then
    return "${cleanup_status}"
  fi
  return "${remote_status}"
}

recovery_session_vault_workload_auth_check() {
  local ssh_target_seen="false"
  local interactive_tty_seen="false"
  local ssh_target=""

  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --help|-h)
        recovery_session_vault_workload_auth_check_usage
        return 0
        ;;
      --ssh-target)
        require_recovery_option_not_seen "$1" "${ssh_target_seen}"
        require_recovery_option_value "$1" "$#" "${2:-}"
        ssh_target_seen="true"
        ssh_target=$2
        shift 2
        ;;
      --interactive-tty)
        require_recovery_option_not_seen "$1" "${interactive_tty_seen}"
        interactive_tty_seen="true"
        shift
        ;;
      --host-local|--host-local=*|--dry-run|--dry-run=*|--execute-reset|--execute-reset=*|--unseal-only|--unseal-only=*|--post-unseal-check|--post-unseal-check=*|--apply|--apply=*|--interactive-sudo|--interactive-sudo=*|--governed-smoke-command|--governed-smoke-command=*)
        recovery_die "recovery-session vault-workload-auth-check forbids $1; P0n is a separate Mac-side evidence route and does not combine reset, unseal, IM, support bundles, runtime identity, or CP proof"
        ;;
      --vault-addr|--vault-addr=*|--vault-address|--vault-address=*|--vault-role|--vault-role=*|--role|--role=*|--vault-audience|--vault-audience=*|--audience|--audience=*|--auth-mount|--auth-mount=*|--vault-auth-mount|--vault-auth-mount=*|--vault-path|--vault-path=*|--proof-path|--proof-path=*|--proof-read-path|--proof-read-path=*|--proof-runtime-secret-path|--proof-runtime-secret-path=*|--proof-runtime-secret-field|--proof-runtime-secret-field=*|--spiffe-id|--spiffe-id=*|--workload-spiffe-id|--workload-spiffe-id=*|--summary-path|--summary-path=*|--config-path|--config-path=*|--workload-zone-config-path|--workload-zone-config-path=*|--container-probe-image|--container-probe-image=*|--spire-agent-socket-path|--spire-agent-socket-path=*|--spire-server-socket-path|--spire-server-socket-path=*)
        recovery_die "recovery-session vault-workload-auth-check forbids helper override flag $1; P0n uses fixed workload-auth helper defaults and the canonical remote summary path"
        ;;
      --*=*)
        recovery_die "recovery-session vault-workload-auth-check does not accept equals-form options: $1"
        ;;
      --*)
        recovery_die "unknown option for recovery-session vault-workload-auth-check: $1"
        ;;
      *)
        recovery_die "unexpected positional argument for recovery-session vault-workload-auth-check: $1"
        ;;
    esac
  done

  if [[ "${ssh_target_seen}" != "true" ]]; then
    recovery_die "recovery-session vault-workload-auth-check requires --ssh-target <target>"
  fi
  if [[ "${interactive_tty_seen}" != "true" ]]; then
    recovery_die "recovery-session vault-workload-auth-check requires --interactive-tty"
  fi
  recovery_session_vault_workload_auth_check_validate_ssh_target "${ssh_target}"

  if [[ ! -x "${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_PUBLIC_HELPER}" ]]; then
    recovery_die "Vault workload-auth public helper is not executable: ${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_PUBLIC_HELPER}"
  fi
  if [[ ! -r "${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_INTERNAL_HELPER}" ]]; then
    recovery_die "Vault workload-auth internal helper is not readable: ${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_INTERNAL_HELPER}"
  fi

  recovery_session_vault_workload_auth_check_remote "${ssh_target}"
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
  if [[ "$#" -gt 0 && "$1" == "vault-reset-disposable" ]]; then
    shift
    recovery_session_vault_reset_disposable "$@"
    return 0
  fi
  if [[ "$#" -gt 0 && "$1" == "vault-workload-auth-check" ]]; then
    shift
    recovery_session_vault_workload_auth_check "$@"
    return 0
  fi
  if [[ "$#" -gt 0 && "$1" == "vault-workload-auth-bootstrap" ]]; then
    shift
    recovery_session_vault_workload_auth_bootstrap "$@"
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
        recovery_die "recovery-session forbids $1 outside explicit submodes; P0q is safe/local/print-only/evidence-check plus explicit vault-unseal-existing, vault-reset-disposable, vault-workload-auth-check, and vault-workload-auth-bootstrap submodes"
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
  printf 'error: subcommand %q is not implemented as a top-level P0q route and requires a later audited slice when not exposed through an implemented recovery-session submode.\n' "${name}" >&2
  printf 'No helper execution routing occurred.\n' >&2
  exit 2
}

refuse_bootstrap() {
  printf 'error: top-level vault-workload-auth-bootstrap execution is blocked/reopened; use recovery-session vault-workload-auth-bootstrap --plan or the explicit P0q recovery-session execution route.\n' >&2
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
      printf 'error: unknown subcommand %q is not implemented in P0q and requires a later audited slice.\n' "${subcommand}" >&2
      printf 'No helper execution routing occurred.\n' >&2
      exit 2
      ;;
  esac
}

main "$@"
