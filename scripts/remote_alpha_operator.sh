#!/usr/bin/env bash
set -euo pipefail
set +x

DEFAULT_PROFILE_DIR=".out/remote-alpha-m75q"
DEFAULT_OUTPUT_ROOT=".out/remote-alpha-m75q/support-bundles"
DEFAULT_SSH_ALIAS="host_to_remote_linux_m75q"
IM_REPO="/Users/ds/Repositories/Infrastructure Manager"
SCRIPT_DIR=""
REMOTE_ALPHA_VAULT_RESET_HELPER=""
REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_PUBLIC_HELPER=""
REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_INTERNAL_HELPER=""
REMOTE_ALPHA_ES_SERVICE_TLS_RENEW_PUBLIC_HELPER=""
REMOTE_ALPHA_ES_SERVICE_TLS_RENEW_INTERNAL_HELPER=""
REMOTE_ALPHA_ES_TLS_STATUS_COLLECTOR=""
REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_RENEW_PUBLIC_HELPER=""
REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_RENEW_INTERNAL_HELPER=""
REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_STATUS_NONINTERACTIVE_RUNTIME=""
REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_STATUS_NONINTERACTIVE_REMOTE_COLLECTOR=""
REMOTE_ALPHA_VAULT_UNSEAL_STAGE_ROOT="/tmp/execution-substrate-remote-alpha-vault-unseal-existing"
REMOTE_ALPHA_VAULT_RESET_DRY_RUN_STAGE_ROOT="/tmp/execution-substrate-remote-alpha-vault-reset-disposable-dry-run"
REMOTE_ALPHA_VAULT_RESET_EXECUTE_STAGE_ROOT="/tmp/execution-substrate-remote-alpha-vault-reset-disposable-execute"
REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_STAGE_ROOT="/tmp/execution-substrate-remote-alpha-vault-workload-auth-bootstrap"
REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_REMOTE_SUMMARY_DIR="/var/tmp/execution-substrate-remote-alpha"
REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_REMOTE_SUMMARY="/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json"
REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_CONFIG="/etc/execution-substrate/vault/workload-zone-vault-config.json"
REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_SPIRE_SERVER_SOCKET="/run/spire/server/private/api.sock"
REMOTE_ALPHA_ES_SERVICE_TLS_STATUS_REMOTE_SUMMARY="/var/lib/execution-substrate-remote-alpha/v1/status/es-service-tls-status-summary.json"
REMOTE_ALPHA_ES_GOVERNANCE_TLS_STATUS_REMOTE_SUMMARY="/var/lib/execution-substrate-remote-alpha/v1/status/es-governance-tls-status-summary.json"
REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_RENEW_STAGE_ROOT="/tmp/execution-substrate-remote-alpha-operator-healthcheck-tls-renew"
REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_RENEW_REMOTE_SUMMARY="/var/tmp/execution-substrate-remote-alpha/operator-healthcheck-tls-renew-summary.json"

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

initialize_operator_paths() {
  if [[ -n "${SCRIPT_DIR}" ]]; then
    return 0
  fi
  SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
  REMOTE_ALPHA_VAULT_RESET_HELPER="${SCRIPT_DIR}/remote_alpha_reset_disposable_vault.sh"
  REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_PUBLIC_HELPER="${SCRIPT_DIR}/remote_alpha_vault_workload_auth_bootstrap.sh"
  REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_INTERNAL_HELPER="${SCRIPT_DIR}/internal/remote_alpha_vault_workload_auth_bootstrap.sh"
  REMOTE_ALPHA_OUTPUT_DIR_DEFINITION="${SCRIPT_DIR}/internal/remote_alpha_output_dir.sh"
  REMOTE_ALPHA_ES_SERVICE_TLS_RENEW_PUBLIC_HELPER="${SCRIPT_DIR}/remote_alpha_es_service_tls_renew.sh"
  REMOTE_ALPHA_ES_SERVICE_TLS_RENEW_INTERNAL_HELPER="${SCRIPT_DIR}/internal/remote_alpha_es_service_tls_renew.sh"
  REMOTE_ALPHA_ES_TLS_STATUS_COLLECTOR="${SCRIPT_DIR}/internal/remote_alpha_es_tls_status.py"
  REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_RENEW_PUBLIC_HELPER="${SCRIPT_DIR}/remote_alpha_operator_healthcheck_tls_renew.sh"
  REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_RENEW_INTERNAL_HELPER="${SCRIPT_DIR}/internal/remote_alpha_operator_healthcheck_tls_renew.sh"
  REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_STATUS_NONINTERACTIVE_RUNTIME="${SCRIPT_DIR}/remote_alpha_operator_healthcheck_tls_status_noninteractive.py"
  REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_STATUS_NONINTERACTIVE_REMOTE_COLLECTOR="${SCRIPT_DIR}/internal/remote_alpha_operator_healthcheck_tls_status_noninteractive_remote.py"
}

privacy_refuse() {
  printf '%s\n' 'error: secret material must never be passed by CLI args/env/logs/reports/artifacts' >&2
  exit 2
}

reject_secret_args() {
  local arg option_name skip_next="false" nocasematch_was_set="false"
  local normalized_arg
  local LC_ALL=C
  if shopt -q nocasematch; then
    nocasematch_was_set="true"
  else
    shopt -s nocasematch
  fi
  for arg in "$@"; do
    normalized_arg=${arg//_/-}
    if [[ "${normalized_arg}" =~ --([A-Za-z0-9_-]*-)?(root-token|unseal-key|client-token|vault-token|api-key|jwt-svid|private-key|password|secret|token-file|secret-value)([^A-Za-z0-9_-]|$) ]]; then
      privacy_refuse
    fi
    if [[ "${skip_next}" == "true" ]]; then
      skip_next="false"
      continue
    fi
    if [[ "${arg}" != --* ]]; then
      continue
    fi
    option_name=${arg%%=*}
    option_name=${option_name#--}
    option_name=${option_name//_/-}
    if [[ "${arg}" != *=* ]]; then
      case "${option_name}" in
        profile-dir|output-root|ssh-alias|im-profile-dir|support-output-root|evidence-dir|vault-workload-auth-summary|runtime-identity-summary|vault-service-user-summary|readiness-summary|staging-record|ssh-target|format)
          skip_next="true"
          ;;
      esac
    fi
  done
  if [[ "${nocasematch_was_set}" != "true" ]]; then
    shopt -u nocasematch
  fi
}

retired_operator_evidence_compatibility() {
  printf '%s\n' 'remote alpha operator evidence ingestion, staging, aggregation, and projection compatibility is retired; no artifact inspection, helper execution, staging, or evidence projection occurred' >&2
  printf '%s\n' 'use the owning producer directly only under its separately documented contract; this operator facade provides no compatibility adapter' >&2
  exit 2
}

reject_retired_operator_evidence_args() {
  local first=${1:-} second=${2:-} arg
  case "${first}" in
    vault-workload-auth-check|runtime-identity-summary|vault-service-user-check)
      retired_operator_evidence_compatibility
      ;;
  esac
  if [[ "${first}" == "recovery-session" ]]; then
    case "${second}" in
      vault-workload-auth-check|runtime-identity-summary)
        retired_operator_evidence_compatibility
        ;;
    esac
  fi
  for arg in "$@"; do
    case "${arg}" in
      --evidence-check|--evidence-check=*|--evidence-dir|--evidence-dir=*|--strict-known-schema|--strict-known-schema=*|--vault-workload-auth-summary|--vault-workload-auth-summary=*|--runtime-identity-summary|--runtime-identity-summary=*|--vault-service-user-summary|--vault-service-user-summary=*)
        retired_operator_evidence_compatibility
        ;;
    esac
  done
}

refuse_retired_historical_evidence_option() {
  printf '%s\n' 'error: retired historical ES evidence options are unavailable' >&2
  exit 2
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

recovery_die() {
  printf 'error: %s\n' "$*" >&2
  printf 'No recovery-session live helper or IM execution occurred.\n' >&2
  exit 2
}

# P0s/P0t contact may have run a stage helper even when its response is unproved.
recovery_es_tls_status_postcontact_die() {
  local route=$1 detail=$2
  printf 'error: %s\n' "${route} ${detail}" >&2
  printf '%s\n' "${route}: remote phase unproved after status contact; stage disposition unproved unless root completed verified removal; inspect protected status independently" >&2
  exit 2
}

recovery_es_tls_diagnostic_postcontact_die() {
  local route=$1 detail=$2
  printf 'error: %s\n' "${route} ${detail}" >&2
  printf '%s\n' "${route}: remote phase unproved after diagnostic contact; stage disposition unproved unless root completed verified removal; no P0t status accepted" >&2
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
    "P0q adds recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --interactive-tty as a Mac-side staged bootstrap route, plus --prepare-summary-path, --prepare-config-readability, and --prepare-spire-bundle-read as bounded remote preparation for bootstrap prerequisites, while preserving safe plan/inventory modes and earlier recovery routes." \
    "Operator ingestion, staging, aggregation, discovery, and projection compatibility for the retired evidence families is unavailable; use an owning producer only under its separate contract." \
    "P0s uses a dedicated status-only collector for artifact-registry evidence; es-service-tls-renew is held before host contact." \
    "P0t uses the same collector mechanics with a fixed execution-governance scope and distinct evidence; es-governance-tls-renew is held before host contact." \
    "P0u adds recovery-session operator-healthcheck-tls-status and operator-healthcheck-tls-renew as bounded Mac-side host-local operator healthcheck client TLS routes over one fixed public/internal helper pair." \
    "Implemented through P0s, P0t, and P0u; P0v adds only the dedicated read-only noninteractive operator-healthcheck TLS status route." \
    "P0v adds recovery-session operator-healthcheck-tls-status-noninteractive --ssh-target <target> --format json as an implemented read-only no-prompt status observation route over one fixed local Python runtime and one streamed fixed remote collector." \
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
    "  remote_alpha_operator.sh es-writable-state-readiness-check  # retired; fixed exit 2" \
    "  remote_alpha_operator.sh readiness-session  # retired; fixed exit 2" \
    "  remote_alpha_operator.sh recovery-session [--plan|--inventory|--next-steps] [options]" \
    "  remote_alpha_operator.sh recovery-session vault-unseal-existing --host-local" \
    "  remote_alpha_operator.sh recovery-session vault-unseal-existing --ssh-target <user@host> --interactive-tty" \
    "  remote_alpha_operator.sh recovery-session vault-reset-disposable --ssh-target <user@host> --dry-run" \
    "  remote_alpha_operator.sh recovery-session vault-reset-disposable --ssh-target <user@host> --execute-reset --interactive-tty" \
    "  remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap [--help|--plan|--inventory]" \
    "  remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <user@host> --prepare-summary-path --interactive-tty" \
    "  remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <user@host> --prepare-config-readability --interactive-tty" \
    "  remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <user@host> --prepare-spire-bundle-read --interactive-tty" \
    "  remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <user@host> --execute-bootstrap --prepare-summary-path --prepare-config-readability --prepare-spire-bundle-read --interactive-tty" \
    "  remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <user@host> --execute-bootstrap --interactive-tty" \
    "  remote_alpha_operator.sh recovery-session es-service-tls-status --ssh-target <user@host> --interactive-tty" \
    "  es-service-tls-renew is held before host contact; --execute-renew is refused on status." \
    "  remote_alpha_operator.sh recovery-session es-governance-tls-status --ssh-target <user@host> --interactive-tty" \
    "  remote_alpha_operator.sh recovery-session es-governance-tls-grammar-diagnostic --verify-only" \
    "  remote_alpha_operator.sh recovery-session es-governance-tls-grammar-diagnostic --ssh-target <user@host> --interactive-tty" \
    "  es-governance-tls-renew is held before host contact; --execute-renew is refused on status." \
    "  remote_alpha_operator.sh recovery-session operator-healthcheck-tls-status --ssh-target <user@host> --interactive-tty" \
    "  remote_alpha_operator.sh recovery-session operator-healthcheck-tls-renew --ssh-target <user@host> --interactive-tty --execute-renew" \
    "  remote_alpha_operator.sh recovery-session operator-healthcheck-tls-status-noninteractive --ssh-target <user@host> --format json" \
    "" \
    "Options for printed command text only:" \
    "  --profile-dir .out/remote-alpha-m75q" \
    "  --output-root .out/remote-alpha-m75q/support-bundles" \
    "  --ssh-alias host_to_remote_linux_m75q" \
    "  --help, -h" \
    "" \
    "Implemented through P0s, P0t, P0u, and P0v:" \
    "  es-writable-state-readiness-check - retired fixed exit-2 route; no host inspection, staging, mutation, or evidence production." \
    "  readiness-session - retired fixed exit-2 workflow; no current readiness projection or artifact refresh." \
    "  recovery-session - safe/local recovery skeleton; supports --plan, --inventory, --next-steps, host-local vault-unseal-existing, Mac-side interactive TTY vault-unseal-existing, disposable Vault reset planning and execution, bounded workload-auth bootstrap, bounded TLS status/renew routes, and read-only operator-healthcheck-tls-status-noninteractive; writes no operator summary." \
    "" \
    "The operator facade does not invoke IM refresh or support-bundle collection and does not add ES Vault token brokerage, runtime identity generation, service-user, generic config/TLS deployment, binary deployment, writable-state ownership, or generic helper dispatch." \
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
    "implemented through the retained P0q, P0s, P0t, P0u, and P0v surfaces:" \
    "  help - show bounded facade scope and options" \
    "  inventory - show this static non-secret inventory" \
    "  print-refresh-command - print Mac-side IM live-refresh command text only" \
    "  print-support-bundle-command - print Mac-side IM support-bundle command text only" \
    "  print-im-commands - print both Mac-side IM command texts only" \
    "  es-writable-state-readiness-check - retired; fixed exit 2 and no effects" \
    "  readiness-session - retired; fixed exit 2 and no effects" \
    "  recovery-session - safe/local skeleton for recovery sequencing; prints plan, static helper inventory, next-step commands, or runs retained explicit submodes" \
    "  scripts/remote_alpha_vault_workload_auth_check.sh - optional owner-local proof emitter under its separate contract; no operator-facade reachability" \
    "  scripts/remote_alpha_runtime_identity_helper_summary.sh - optional owner-local proof emitter under its separate contract; no operator-facade reachability" \
    "  scripts/remote_alpha_migrate_vault_service_user.sh --check-only - optional owner-local proof emitter under its separate contract; no operator-facade reachability" \
    "  recovery-session vault-unseal-existing --host-local - delegates only to scripts/remote_alpha_reset_disposable_vault.sh --unseal-only; host-local; secret-sensitive; non-destructive; not reset; not workload-auth bootstrap; not IM; not CP proof" \
    "  recovery-session vault-unseal-existing --ssh-target <target> --interactive-tty - Mac-side route; stages only scripts/remote_alpha_reset_disposable_vault.sh to a route-specific remote scratch directory and invokes only --unseal-only through ssh -tt; no transcript, no summary, no support bundle" \
    "  recovery-session vault-reset-disposable --ssh-target <target> --dry-run - Mac-side dry-run planning route; stages only scripts/remote_alpha_reset_disposable_vault.sh to a route-specific remote scratch directory and invokes only --dry-run; non-destructive; no transcript, no summary, no support bundle" \
    "  recovery-session vault-reset-disposable --ssh-target <target> --execute-reset --interactive-tty - destructive Mac-side operator route; stages only scripts/remote_alpha_reset_disposable_vault.sh to a route-specific remote scratch directory and invokes only --execute-reset through ssh -tt; no transcript, no summary, no support bundle" \
    "  recovery-session vault-workload-auth-bootstrap [--help|--plan|--inventory] - safe local/print-only planning surface for post-reset Vault workload-auth bootstrap" \
    "  recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-summary-path --interactive-tty - Mac-side bounded filesystem preparation route; prepares only /var/tmp/execution-substrate-remote-alpha and the bootstrap summary/temp writability path through a visible SSH TTY; may trigger an OS sudo prompt; no Vault/root/proof prompt, no helper staging, no summary creation, no .out" \
    "  recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-config-readability --interactive-tty - Mac-side bounded filesystem preparation route; prepares only helper-user readability for /etc/execution-substrate/vault/workload-zone-vault-config.json through fixed-path user ACLs when needed; may trigger an OS sudo prompt; no Vault/root/proof prompt, no helper staging, no config content printing, no .out" \
    "  recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-spire-bundle-read --interactive-tty - Mac-side bounded capability/filesystem preparation route; prepares only helper-user access for the fixed SPIRE server bundle-read command through fixed-path user ACLs when needed; may trigger an OS sudo prompt; no Vault/root/proof prompt, no helper staging, no SPIRE bundle printing, no .out" \
    "  recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --prepare-summary-path --prepare-config-readability --prepare-spire-bundle-read --interactive-tty - prepare the bootstrap summary path, then config readability, then SPIRE bundle-read access, then stage and invoke the dedicated bootstrap helper; helper preflights still run before Vault/root/proof prompts" \
    "  recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --interactive-tty - Mac-side staged bootstrap route; stages only scripts/remote_alpha_vault_workload_auth_bootstrap.sh and scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh; invokes only the staged public bootstrap helper through ssh -tt; leaves the canonical bootstrap summary remote at /var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json; no transcript, no summary copy-back, no support bundle" \
    "  recovery-session es-service-tls-status --ssh-target <target> --interactive-tty - stages only scripts/internal/remote_alpha_es_tls_status.py, invokes fixed artifact-registry scope through visible sudo, and leaves protected canonical evidence remote." \
    "  recovery-session es-service-tls-renew - held before SSH, SCP, staging, and sudo; no renewal authority." \
    "  recovery-session es-governance-tls-status --ssh-target <target> --interactive-tty - stages only scripts/internal/remote_alpha_es_tls_status.py, invokes fixed execution-governance scope through visible sudo, and leaves protected canonical evidence remote." \
    "  recovery-session es-governance-tls-grammar-diagnostic --verify-only or --ssh-target <target> --interactive-tty - separate bounded P0t first-rejection diagnostic; no status publication, renewal, repair, or restoration." \
    "  recovery-session es-governance-tls-renew - held before SSH, SCP, staging, and sudo; no renewal authority." \
    "  recovery-session operator-healthcheck-tls-status --ssh-target <target> --interactive-tty - Mac-side staged host-local operator healthcheck TLS evidence route; stages only scripts/remote_alpha_operator_healthcheck_tls_renew.sh and scripts/internal/remote_alpha_operator_healthcheck_tls_renew.sh; invokes only --status through ssh -tt; leaves the canonical summary remote at /var/tmp/execution-substrate-remote-alpha/operator-healthcheck-tls-renew-summary.json; no transcript, no summary copy-back, no support bundle" \
    "  recovery-session operator-healthcheck-tls-renew --ssh-target <target> --interactive-tty --execute-renew - Mac-side staged host-local operator healthcheck TLS recovery route; stages only the same fixed helper pair and invokes only --execute-renew through ssh -tt; currently fails closed before backup/install with unsupported_signing_topology until a documented CA custody/signing design exists and does not restart ES" \
    "  recovery-session operator-healthcheck-tls-status-noninteractive --ssh-target <target> --format json - ES-owned read-only no-prompt operator healthcheck TLS status route; Bash performs contact-free preflight only, then execs the fixed local Python runtime; the runtime streams a fixed collector over SSH stdin; no Bash JSON, no scp, no remote helper staging, no remote summary, no TTY, no renewal, no scheduling" \
    "" \
    "future/not implemented:" \
    "  Vault service-user check/apply execution - remains owner-local and separate from this facade" \
    "  runtime security check - requires a later audited slice" \
    "  other staged ES helper delegation - requires a later audited slice" \
    "" \
    "blocked/reopened:" \
    "  live validation of vault-workload-auth-bootstrap execution - not performed in P0q" \
    "" \
    "non-claims:" \
    "  not production, not HA, not multi-tenant, not a general deployment architecture" \
    "  not IM automation or reconciliation, not CP authority, not ES Vault token brokerage" \
    "  vault-reset-disposable --dry-run is non-destructive planning only: it does not stop Vault, move raft storage, init or unseal Vault, run post-unseal checks, run IM, or collect support bundles" \
    "  vault-reset-disposable --execute-reset is destructive and must be run only when the operator intentionally wants to reset disposable Remote Alpha Vault state; it requires --interactive-tty and the existing exact confirmation phrase RESET DISPOSABLE REMOTE ALPHA VAULT in the visible remote helper/Vault terminal" \
    "  vault-workload-auth-bootstrap configures expected Vault objects only: not workload-auth success, not reset/unseal, not workload-auth check, not IM/support-bundle/CP proof, not runtime identity generation, and not ES Vault token brokerage" \
    "  es-service-tls-status is bounded artifact-registry evidence only; es-service-tls-renew is held; no IM, CP, monitor, scheduler, or restoration authority." \
    "  es-governance-tls-status is bounded execution-governance evidence only; es-governance-tls-renew is held; no IM, CP, monitor, scheduler, or restoration authority." \
    "  operator-healthcheck-tls status/renew is bounded host-local operator healthcheck client TLS recovery only: not generic TLS deployment, not IM reconciliation, not CP proof, not Vault/SPIRE/Nomad changes, not workload-auth, not runtime identity, and not production readiness" \
    "  operator-healthcheck-tls-status-noninteractive is read-only evidence/projection only: not renewal, not signer/custody resolution, not ES runtime truth, not MA/IM/CP/Bridge authority, not scheduled execution, and not live proof" \
    "  must not make IM a remote reconciler, CP a Vault/runtime recovery authority, ES a Vault token broker, or Remote Alpha a deployment architecture" \
    "  no operator-owned summary, support bundle, report, or new authority artifact is written; archived readiness artifacts are historical evidence only and are never refreshed by this facade"
}

recovery_session_usage() {
  printf '%s\n' \
    "Remote Alpha operator workflow: recovery-session" \
    "P0u scope: safe/local recovery planning plus explicit vault-unseal-existing modes, Mac-side disposable Vault reset planning and execution, bounded workload-auth bootstrap and prerequisite preparation, bounded ARS/AGS/ES and ES/EGS TLS status/renew routing, and bounded operator-healthcheck client TLS status/renew routing." \
    "P0v scope: safe/local recovery planning plus explicit read-only operator-healthcheck TLS noninteractive status routing." \
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
    "  remote_alpha_operator.sh recovery-session vault-unseal-existing --host-local" \
    "  remote_alpha_operator.sh recovery-session vault-unseal-existing --ssh-target <user@host> --interactive-tty" \
    "  remote_alpha_operator.sh recovery-session vault-reset-disposable --ssh-target <user@host> --dry-run" \
    "  remote_alpha_operator.sh recovery-session vault-reset-disposable --ssh-target <user@host> --execute-reset --interactive-tty" \
    "  remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap [--help|--plan|--inventory]" \
    "  remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <user@host> --prepare-summary-path --interactive-tty" \
    "  remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <user@host> --prepare-config-readability --interactive-tty" \
    "  remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <user@host> --prepare-spire-bundle-read --interactive-tty" \
    "  remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <user@host> --execute-bootstrap --prepare-summary-path --prepare-config-readability --prepare-spire-bundle-read --interactive-tty" \
    "  remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <user@host> --execute-bootstrap --interactive-tty" \
    "  remote_alpha_operator.sh recovery-session es-service-tls-status --ssh-target <user@host> --interactive-tty" \
    "  es-service-tls-renew is held before contact." \
    "  remote_alpha_operator.sh recovery-session es-governance-tls-status --ssh-target <user@host> --interactive-tty" \
    "  remote_alpha_operator.sh recovery-session es-governance-tls-grammar-diagnostic --verify-only" \
    "  remote_alpha_operator.sh recovery-session es-governance-tls-grammar-diagnostic --ssh-target <user@host> --interactive-tty" \
    "  es-governance-tls-renew is held before contact." \
    "  remote_alpha_operator.sh recovery-session operator-healthcheck-tls-status --ssh-target <user@host> --interactive-tty" \
    "  remote_alpha_operator.sh recovery-session operator-healthcheck-tls-renew --ssh-target <user@host> --interactive-tty --execute-renew" \
    "  remote_alpha_operator.sh recovery-session operator-healthcheck-tls-status-noninteractive --ssh-target <user@host> --format json" \
    "" \
    "Allowed flags for all modes:" \
    "  --help" \
    "  --plan" \
    "  --inventory" \
    "  --next-steps" \
    "  --ssh-alias <alias> (for printed IM commands only)" \
    "  --im-profile-dir <path> (for printed IM commands only)" \
    "  --support-output-root <path> (for printed IM commands only)" \
    "" \
    "" \
    "Forbidden: --ssh-target, --interactive-sudo, --apply, --dry-run, --execute-reset, --execute-renew, --unseal-only, --post-unseal-check, --governed-smoke-command, helper path overrides, arbitrary command strings, unknown flags, positional arguments, duplicate operational flags, secret-like arguments, and equals-form options." \
    "Submode exception: recovery-session vault-reset-disposable --ssh-target <target> --dry-run is implemented as Mac-side dry-run planning only; it is non-destructive and does not stop Vault, move raft storage, init or unseal Vault, run post-unseal checks, run IM, or collect support bundles." \
    "Submode exception: recovery-session vault-reset-disposable --ssh-target <target> --execute-reset --interactive-tty is implemented as a destructive Mac-side operator route; it stages only the reset helper, invokes only --execute-reset, and relies on the human operator to type the exact confirmation phrase and Vault secrets only in the visible remote terminal." \
    "Submode exception: recovery-session vault-workload-auth-bootstrap [--help|--plan|--inventory] is safe local/print-only planning; it does not run SSH, sudo, Vault, workload-auth checks, reset/unseal, IM, support bundles, CP proof, runtime identity generation, or live bootstrap." \
    "Submode exception: recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-summary-path --interactive-tty is bounded remote filesystem preparation only; it may use an OS sudo prompt through the visible SSH TTY and must not stage helpers, run Vault, or create a bootstrap summary." \
    "Submode exception: recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-spire-bundle-read --interactive-tty is bounded remote SPIRE bundle-read access preparation only; it may use an OS sudo prompt through the visible SSH TTY and must not stage helpers, run Vault, print SPIRE bundle material, or create a bootstrap summary." \
    "Submode exception: recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --interactive-tty is a Mac-side staged bootstrap route; it stages only the bootstrap public/internal helper pair and relies on the human operator to type Vault bootstrap authority and proof secret values only in the visible remote helper prompt." \
    "Submode exception: recovery-session es-service-tls-status stages only the dedicated status collector with fixed artifact-registry scope; the collector self-cleans before observation and publishes protected evidence." \
    "Submode exception: recovery-session es-service-tls-renew is held before contact; a status pass grants no renewal authority." \
    "Submode exception: recovery-session es-governance-tls-status stages only the dedicated status collector with fixed execution-governance scope; the collector self-cleans before observation and publishes protected evidence." \
    "Submode exception: recovery-session es-governance-tls-renew is held before contact; a status pass grants no renewal authority." \
    "Submode exception: recovery-session operator-healthcheck-tls-status --ssh-target <target> --interactive-tty is a Mac-side staged host-local operator healthcheck TLS evidence route; it stages only the operator healthcheck TLS public/internal helper pair, invokes only --status, leaves the canonical summary on the remote host, and performs no mutation." \
    "Submode exception: recovery-session operator-healthcheck-tls-renew --ssh-target <target> --interactive-tty --execute-renew is a Mac-side staged host-local operator healthcheck TLS recovery route; it stages only the same helper pair, invokes only --execute-renew, and currently fails closed before backup/install with unsupported_signing_topology until a documented CA custody/signing design exists." \
    "Submode exception: recovery-session operator-healthcheck-tls-status-noninteractive --ssh-target <target> --format json is a read-only no-prompt status route; Bash performs contact-free local preflight and execs the fixed local Python runtime, which streams a fixed collector over SSH stdin and emits the final bounded JSON; no Bash JSON, no scp, no helper staging, no remote summary, no TTY, no renewal, no scheduling." \
    "The operator facade provides no evidence-file ingestion, schema interpretation, automatic discovery, aggregation, or projection adapter." \
    "Archived historical ES readiness, staging, and ES service-user migration v1 bytes are not discovered, parsed, or projected by this live operator. Unknown schemas fail closed."
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

recovery_session_vault_workload_auth_bootstrap_usage() {
  printf '%s\n' \
    "Remote Alpha recovery-session mode: vault-workload-auth-bootstrap" \
    "P0q scope: safe local/print-only planning plus bounded summary-path, config-readability, and SPIRE bundle-read preparation and Mac-side staged bootstrap execution for post-reset Vault workload-auth bootstrap." \
    "Preparation runs only fixed remote filesystem/capability commands for the canonical bootstrap summary path, fixed workload-zone config readability, and fixed SPIRE server bundle-read access; execution stages only the dedicated bootstrap public/internal helper pair and invokes only the staged public helper over ssh -tt." \
    "No workload-auth check, reset/unseal, IM execution, support-bundle collection, CP proof, runtime identity generation, Mac .out, report, support bundle, operator summary, helper bundle, unrelated helper staging, or generic helper dispatch occurs." \
    "" \
    "Usage:" \
    "  remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap" \
    "  remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --help" \
    "  remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --plan" \
    "  remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --inventory" \
    "  remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <user@host> --prepare-summary-path --interactive-tty" \
    "  remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <user@host> --prepare-config-readability --interactive-tty" \
    "  remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <user@host> --prepare-spire-bundle-read --interactive-tty" \
    "  remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <user@host> --execute-bootstrap --prepare-summary-path --prepare-config-readability --prepare-spire-bundle-read --interactive-tty" \
    "  remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <user@host> --execute-bootstrap --interactive-tty" \
    "" \
    "Allowed flags:" \
    "  --help" \
    "  --plan" \
    "  --inventory" \
    "  --ssh-target <target> (only with --execute-bootstrap, --prepare-summary-path, --prepare-config-readability, and/or --prepare-spire-bundle-read)" \
    "  --execute-bootstrap" \
    "  --prepare-summary-path" \
    "  --prepare-config-readability" \
    "  --prepare-spire-bundle-read" \
    "  --interactive-tty (only with --execute-bootstrap, --prepare-summary-path, --prepare-config-readability, and/or --prepare-spire-bundle-read)" \
    "" \
    "Default behavior: print the bootstrap plan/help and exit zero." \
    "Topology rules: --execute-bootstrap, --prepare-summary-path, --prepare-config-readability, and --prepare-spire-bundle-read each require --ssh-target <target> and --interactive-tty; --ssh-target and --interactive-tty are valid only with those action flags; combined execution prepares the summary path, then config readability, then SPIRE bundle-read access before helper staging or any Vault/root/proof prompt; the SSH target must be a single target, not an option or shell command." \
    "Forbidden in P0q: --host-local, --execute-reset, --dry-run, --unseal-only, --post-unseal-check, --apply, --interactive-sudo, --governed-smoke-command, --keep-staging-on-failure, helper override flags, proof secret value flags, arbitrary commands, unknown flags, duplicate flags, positional args beyond the submode/mode, secret-like flags, and equals-form options." \
    "Secret posture: summary-path, config-readability, and SPIRE bundle-read preparation may prompt only for OS sudo through the visible SSH TTY; Vault bootstrap authority and proof secret values are entered only through the visible/silent remote helper TTY prompt after preparation and helper preflights pass; never through CLI args, env vars, files, logs, .out, reports, support bundles, retained bundles, CP artifacts, transcripts, tee, script, or Codex output." \
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
    "  JWT auth config: SPIRE JWT validation material selected for the workload trust domain and bound issuer" \
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
    "  recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-summary-path --interactive-tty" \
    "  runs only bounded remote filesystem preparation for /var/tmp/execution-substrate-remote-alpha and the bootstrap summary/temp path" \
    "  may use visible OS sudo to make the summary directory/file owner-writable by the helper user with narrow permissions; no Vault/root/proof prompt occurs" \
    "  recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-config-readability --interactive-tty" \
    "  runs only bounded remote filesystem preparation for /etc/execution-substrate/vault/workload-zone-vault-config.json readability by the helper user; may use fixed-path user ACLs through visible OS sudo; no Vault/root/proof prompt occurs and config contents are never printed" \
    "  recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-spire-bundle-read --interactive-tty" \
    "  runs only bounded remote capability/filesystem preparation for fixed SPIRE server bundle-read access by the helper user: spire-server bundle show -format spiffe -socketPath /run/spire/server/private/api.sock; may use fixed-path user ACLs through visible OS sudo; bundle output is discarded and never printed" \
    "  recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --interactive-tty" \
    "  optional combined form may add --prepare-summary-path, --prepare-config-readability, and --prepare-spire-bundle-read, which run in that order before helper staging and before any Vault/root/proof prompt" \
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
    "  recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-summary-path --interactive-tty - run only the bounded remote filesystem preparation command for the canonical bootstrap summary path" \
    "  recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-config-readability --interactive-tty - run only the bounded remote filesystem preparation command for fixed workload-zone config readability by the helper user" \
    "  recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-spire-bundle-read --interactive-tty - run only the bounded remote capability/filesystem preparation command for fixed SPIRE server bundle-read access by the helper user" \
    "  recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --prepare-summary-path --prepare-config-readability --prepare-spire-bundle-read --interactive-tty - prepare the summary path, then config readability, then SPIRE bundle-read access before staging the dedicated bootstrap helper pair" \
    "  recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --interactive-tty - stage the dedicated bootstrap helper pair and invoke only the public helper over ssh -tt" \
    "" \
    "not implemented/run in P0q:" \
    "  live validation - not performed" \
    "  workload-auth check execution, reset/unseal, IM, support bundle, CP proof, and runtime identity generation - not part of bootstrap" \
    "" \
    "likely bootstrap objects to account for later:" \
    "  auth mount jwt" \
    "  JWT auth config with SPIRE validation material selected for the workload trust domain and bound issuer" \
    "  role service_execution with role_type=jwt, user_claim=sub, bound_audiences=vault, bound_subject=spiffe://execution.internal/workload" \
    "  policy such as runtime-identity-proof" \
    "  KV v2 proof paths proof-secrets/data/runtime-identity-vault-login and proof-secrets/data/codex-runtime-profile" \
    "  api_key field present and non-empty; proof secret value never printed" \
    "  workload-zone config /etc/execution-substrate/vault/workload-zone-vault-config.json" \
    "" \
    "safe output posture:" \
    "  safe modes are text only; preparation creates no final bootstrap summary and no Mac artifact; execution writes only a remote non-secret summary; no Mac .out; no operator summary; no support bundle; no report" \
    "  evidence/projection only; not authority" \
    "  ES does not broker Vault tokens; Vault owns token, secret, and lease authority; SPIRE owns JWT-SVID issuance"
}

recovery_session_plan() {
  printf '%s\n' \
    "Remote Alpha recovery-session plan (P0u operator healthcheck TLS status/renew route added)" \
    "Remote Alpha recovery-session plan (P0v operator healthcheck TLS noninteractive status route added)" \
    "classification: bounded proof/support helper; evidence/projection/diagnostics only; no authority source" \
    "default behavior: print this plan/help and exit zero; no live tools run" \
    "" \
    "implemented safe/local or explicitly host-local:" \
    "  inventory/status - safe local planning and static inventory only; no host inspection" \
    "  next-steps - print readiness-session and IM command text only" \
    "  vault-unseal-existing --host-local - implemented host-local operator mode for the Linux Remote Alpha host; secret-sensitive but non-destructive; delegates only to the existing reset helper's --unseal-only flow" \
    "  vault-unseal-existing --ssh-target <target> --interactive-tty - implemented Mac-side operator mode; stages only the existing reset helper, invokes only --unseal-only over ssh -tt, and attempts cleanup without transcript capture" \
    "  vault-reset-disposable --ssh-target <target> --dry-run - implemented Mac-side dry-run planning mode; stages only the existing reset helper, invokes only --dry-run over SSH, and attempts cleanup without transcript capture" \
    "  vault-reset-disposable --ssh-target <target> --execute-reset --interactive-tty - implemented destructive Mac-side operator mode; stages only the existing reset helper, invokes only --execute-reset over ssh -tt, and attempts cleanup without transcript capture" \
    "  vault-workload-auth-bootstrap [--help|--plan|--inventory] - implemented safe local/print-only planning mode; no SSH, no sudo, no Vault, no root-token prompt, no proof secret creation, no workload-auth check, no JSON, no .out, no summary" \
    "  vault-workload-auth-bootstrap --ssh-target <target> --prepare-summary-path --interactive-tty - implemented bounded remote filesystem preparation mode; prepares only the bootstrap summary directory/file/temp writability path through ssh -tt, may request OS sudo, and creates no final bootstrap summary" \
    "  vault-workload-auth-bootstrap --ssh-target <target> --prepare-config-readability --interactive-tty - implemented bounded remote filesystem preparation mode; prepares only fixed workload-zone config readability by the helper user through ssh -tt, may request OS sudo for user ACLs, and prints no config contents" \
    "  vault-workload-auth-bootstrap --ssh-target <target> --prepare-spire-bundle-read --interactive-tty - implemented bounded remote capability/filesystem preparation mode; prepares only fixed SPIRE server bundle-read access by the helper user through ssh -tt, may request OS sudo for user ACLs, and prints no SPIRE bundle contents" \
    "  vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --prepare-summary-path --prepare-config-readability --prepare-spire-bundle-read --interactive-tty - implemented combined preparation plus staged bootstrap mode; summary preparation, config readability preparation, then SPIRE bundle-read preparation run before helper staging and before any Vault/root/proof prompt" \
    "  vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --interactive-tty - implemented Mac-side staged bootstrap mode; stages only the dedicated bootstrap public/internal helper pair, invokes only the public helper over ssh -tt, leaves the non-secret summary remote, and attempts cleanup without transcript capture" \
    "  es-service-tls-status --ssh-target <target> --interactive-tty - dedicated collector stages one file, self-cleans before status work, and writes /var/lib/execution-substrate-remote-alpha/v1/status/es-service-tls-status-summary.json." \
    "  es-service-tls-renew - held before contact pending a separately designed contract." \
    "  es-governance-tls-status --ssh-target <target> --interactive-tty - dedicated collector stages one file, self-cleans before status work, and writes /var/lib/execution-substrate-remote-alpha/v1/status/es-governance-tls-status-summary.json." \
    "  es-governance-tls-grammar-diagnostic --verify-only or --ssh-target <target> --interactive-tty - separate bounded first-rejection diagnostic; no status publication, renewal, repair, or restoration." \
    "  es-governance-tls-renew - held before contact pending a separately designed contract." \
    "  operator-healthcheck-tls-status --ssh-target <target> --interactive-tty - implemented Mac-side staged host-local operator healthcheck TLS evidence mode; stages only the operator healthcheck TLS public/internal helper pair, invokes only --status over ssh -tt, leaves the canonical summary on the remote host, and performs no mutation" \
    "  operator-healthcheck-tls-renew --ssh-target <target> --interactive-tty --execute-renew - implemented Mac-side staged host-local operator healthcheck TLS recovery mode; stages only the same helper pair, invokes only --execute-renew over ssh -tt, currently fails closed before backup/install with unsupported_signing_topology until a documented CA custody/signing design exists, and does not restart ES" \
    "  operator-healthcheck-tls-status-noninteractive --ssh-target <target> --format json - implemented read-only no-prompt status mode; Bash execs a fixed local Python runtime that streams a fixed remote collector over SSH stdin and emits bounded JSON; no TTY, no scp, no helper staging, no remote summary, no renewal, no scheduling" \
    "" \
    "future explicit audited slices:" \
    "  service-user check/apply - remains separate; apply is mutating and not part of P0s recovery-session" \
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
    "  vault-workload-auth-bootstrap configures expected Vault objects only: it is not workload-auth success, not ES Vault token brokerage, and not workload-auth check execution" \
    "  es-service-tls-status is bounded evidence only; renewal is held; no TLS deployment, IM, CP, monitor, scheduler, or production readiness authority." \
    "  es-governance-tls-status is bounded evidence only; renewal is held; no TLS deployment, IM, CP, monitor, scheduler, or production readiness authority." \
    "  operator-healthcheck-tls status/renew is bounded host-local operator healthcheck client TLS recovery only: it is not generic TLS deployment, not IM reconciliation, not CP proof, not Vault/SPIRE/Nomad changes, not workload-auth, not runtime identity, and not production readiness" \
    "  the phrase, Vault init output, root token, unseal key, and Vault prompt interactions are never accepted through args/env/files/logs/artifacts/Codex output" \
    "  no post-unseal/service-user/IM/support-bundle/CP-proof bundling is added in P0u" \
    "  no post-unseal/service-user/IM/support-bundle/CP-proof bundling is added in P0v; workload-auth evidence, workload-auth bootstrap execution, runtime identity summary evidence, ES service TLS renewal, ES governance TLS renewal, operator healthcheck TLS renewal, and operator healthcheck TLS noninteractive status remain separate routes" \
    "  vault-unseal-existing does not validate default noninteractive readiness"
}

recovery_session_inventory() {
  printf '%s\n' \
    "Remote Alpha recovery-session static helper inventory" \
    "classification: static safe/local inventory only; no live host state inspection; no helper execution" \
    "" \
    "safe/local:" \
    "  scripts/remote_alpha_operator.sh readiness-session - retired fixed exit-2 workflow; no host contact or evidence production" \
    "  recovery-session --plan, --inventory, --next-steps - print-only/local" \
    "  recovery-session vault-unseal-existing --host-local - implemented host-local explicit operator mode; secret-sensitive; non-destructive; delegates only to scripts/remote_alpha_reset_disposable_vault.sh --unseal-only" \
    "  recovery-session vault-unseal-existing --ssh-target <target> --interactive-tty - implemented Mac-side explicit operator mode; stages only scripts/remote_alpha_reset_disposable_vault.sh and invokes only --unseal-only through ssh -tt; no summary file" \
    "  recovery-session vault-reset-disposable --ssh-target <target> --dry-run - implemented Mac-side dry-run planning mode; stages only scripts/remote_alpha_reset_disposable_vault.sh and invokes only --dry-run through SSH; non-destructive; no summary file" \
    "  recovery-session vault-reset-disposable --ssh-target <target> --execute-reset --interactive-tty - implemented destructive Mac-side operator mode; stages only scripts/remote_alpha_reset_disposable_vault.sh and invokes only --execute-reset through ssh -tt; no summary file; no transcript capture" \
    "  recovery-session vault-workload-auth-bootstrap [--help|--plan|--inventory] - safe local/print-only planning; no SSH, no sudo, no Vault, no root-token prompt, no proof secret creation, no workload-auth check, no .out, no JSON, no summary" \
    "  recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-summary-path --interactive-tty - bounded remote filesystem preparation only for /var/tmp/execution-substrate-remote-alpha and the bootstrap summary/temp path; may request OS sudo through ssh -tt; no helper staging, no Vault, no final summary" \
    "  recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-config-readability --interactive-tty - bounded remote filesystem preparation only for /etc/execution-substrate/vault/workload-zone-vault-config.json helper-user readability; may request OS sudo through ssh -tt for fixed-path user ACLs; no helper staging, no Vault, no config content printing" \
    "  recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-spire-bundle-read --interactive-tty - bounded remote capability/filesystem preparation only for fixed SPIRE server bundle-read access; may request OS sudo through ssh -tt for fixed-path user ACLs; no helper staging, no Vault, no SPIRE bundle content printing" \
    "  recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --prepare-summary-path --prepare-config-readability --prepare-spire-bundle-read --interactive-tty - combined route that prepares the summary path, then config readability, then SPIRE bundle-read access before staging the bootstrap helper pair and before any Vault/root/proof prompt" \
    "  recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --interactive-tty - implemented Mac-side staged bootstrap mode; stages only scripts/remote_alpha_vault_workload_auth_bootstrap.sh and scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh; invokes only the staged public helper through ssh -tt; leaves /var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json on the remote host; no summary copy-back; no transcript capture" \
    "  recovery-session es-service-tls-status --ssh-target <target> --interactive-tty - stages one dedicated collector, selects artifact-registry, and leaves only protected canonical summary remote; no legacy fallback." \
    "  recovery-session es-service-tls-renew - held before contact; no helper staged or invoked." \
    "  recovery-session es-governance-tls-status --ssh-target <target> --interactive-tty - stages one dedicated collector, selects execution-governance, and leaves only protected canonical summary remote; no legacy fallback." \
    "  recovery-session es-governance-tls-grammar-diagnostic --verify-only or --ssh-target <target> --interactive-tty - separate P0t grammar localization; stages one collector in live mode, emits at most one closed terminal line, and publishes no status summary." \
    "  recovery-session es-governance-tls-renew - held before contact; no helper staged or invoked." \
    "  recovery-session operator-healthcheck-tls-status --ssh-target <target> --interactive-tty - implemented Mac-side staged host-local operator healthcheck TLS evidence mode; stages only scripts/remote_alpha_operator_healthcheck_tls_renew.sh and scripts/internal/remote_alpha_operator_healthcheck_tls_renew.sh; invokes only --status through ssh -tt; leaves /var/tmp/execution-substrate-remote-alpha/operator-healthcheck-tls-renew-summary.json on the remote host; no summary copy-back; no transcript capture" \
    "  recovery-session operator-healthcheck-tls-renew --ssh-target <target> --interactive-tty --execute-renew - implemented Mac-side staged host-local operator healthcheck TLS recovery mode; stages only scripts/remote_alpha_operator_healthcheck_tls_renew.sh and scripts/internal/remote_alpha_operator_healthcheck_tls_renew.sh; invokes only --execute-renew through ssh -tt; currently fails closed before backup/install with unsupported_signing_topology until a documented CA custody/signing design exists; leaves /var/tmp/execution-substrate-remote-alpha/operator-healthcheck-tls-renew-summary.json on the remote host; no summary copy-back; no transcript capture; no ES restart" \
    "  recovery-session operator-healthcheck-tls-status-noninteractive --ssh-target <target> --format json - implemented ES-owned read-only no-prompt status route; uses scripts/remote_alpha_operator_healthcheck_tls_status_noninteractive.py and streams scripts/internal/remote_alpha_operator_healthcheck_tls_status_noninteractive_remote.py over SSH stdin; no Bash JSON, no scp, no helper staging, no remote summary, no TTY, no renewal, no scheduling" \
    "" \
    "check-only evidence helpers:" \
    "  scripts/remote_alpha_vault_workload_auth_check.sh - optional owner-local host check under its separate contract; no operator-facade reachability" \
    "  scripts/remote_alpha_runtime_identity_helper_summary.sh - optional owner-local proof emitter under its separate contract; no operator-facade reachability" \
    "  scripts/remote_alpha_es_service_tls_renew.sh --status - host-local internal TLS status helper; now also reachable through the P0s Mac-side staged evidence route; renew remains a separate explicit --execute-renew route" \
    "  scripts/remote_alpha_es_service_tls_renew.sh --scope execution-governance --status - host-local ES/EGS governance TLS status helper; now also reachable through the P0t Mac-side staged evidence route; renew remains a separate explicit --execute-renew route" \
    "  scripts/remote_alpha_operator_healthcheck_tls_renew.sh --status - host-local operator healthcheck client TLS status helper; now also reachable through the P0u Mac-side staged evidence route; renew remains a separate explicit --execute-renew route" \
    "  scripts/remote_alpha_operator_healthcheck_tls_status_noninteractive.py --ssh-target <target> --format json - local P0v final route-schema emitter; owns SSH construction, bounds, protocol validation, redaction, and final JSON" \
    "  scripts/internal/remote_alpha_operator_healthcheck_tls_status_noninteractive_remote.py - fixed streamed P0v remote collector; emits only the internal protocol and writes no remote file" \
    "  scripts/remote_alpha_migrate_vault_service_user.sh --check-only - optional owner-local Vault service-user proof emitter under its separate contract; no operator-facade reachability" \
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
    "non-claims: inventory is evidence/projection/diagnostics only, never authority; es-service-tls, es-governance-tls, and operator-healthcheck-tls are not generic TLS deployment, IM reconciliation, CP proof, Vault/SPIRE/Nomad change, EGS trust-model redesign, workload-auth, runtime identity, or production readiness"
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
    "Remote Alpha ES existing-host readiness is retired; select a separately governed setup or migration contract." \
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
  local prepare_summary_path_seen="false"
  local prepare_config_readability_seen="false"
  local prepare_spire_bundle_read_seen="false"
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
        execute_bootstrap_seen="true"
        shift
        ;;
      --prepare-summary-path)
        require_recovery_option_not_seen "$1" "${prepare_summary_path_seen}"
        prepare_summary_path_seen="true"
        shift
        ;;
      --prepare-config-readability)
        require_recovery_option_not_seen "$1" "${prepare_config_readability_seen}"
        prepare_config_readability_seen="true"
        shift
        ;;
      --prepare-spire-bundle-read)
        require_recovery_option_not_seen "$1" "${prepare_spire_bundle_read_seen}"
        prepare_spire_bundle_read_seen="true"
        shift
        ;;
      --interactive-tty)
        require_recovery_option_not_seen "$1" "${interactive_tty_seen}"
        interactive_tty_seen="true"
        shift
        ;;
      --host-local|--host-local=*|--execute-reset|--execute-reset=*|--dry-run|--dry-run=*|--unseal-only|--unseal-only=*|--post-unseal-check|--post-unseal-check=*|--apply|--apply=*|--interactive-sudo|--interactive-sudo=*|--governed-smoke-command|--governed-smoke-command=*|--keep-staging-on-failure|--keep-staging-on-failure=*)
        recovery_die "recovery-session vault-workload-auth-bootstrap received a forbidden option category"
        ;;
      --vault-addr|--vault-addr=*|--vault-address|--vault-address=*|--vault-role|--vault-role=*|--role|--role=*|--vault-audience|--vault-audience=*|--audience|--audience=*|--auth-mount|--auth-mount=*|--vault-auth-mount|--vault-auth-mount=*|--vault-path|--vault-path=*|--proof-path|--proof-path=*|--proof-read-path|--proof-read-path=*|--proof-runtime-secret-path|--proof-runtime-secret-path=*|--proof-runtime-secret-field|--proof-runtime-secret-field=*|--spiffe-id|--spiffe-id=*|--workload-spiffe-id|--workload-spiffe-id=*|--summary-path|--summary-path=*|--config-path|--config-path=*|--workload-zone-config-path|--workload-zone-config-path=*|--container-probe-image|--container-probe-image=*|--spire-agent-socket-path|--spire-agent-socket-path=*|--spire-server-socket-path|--spire-server-socket-path=*)
        recovery_die "recovery-session vault-workload-auth-bootstrap accepts only fixed documented bootstrap values"
        ;;
      --proof-secret-value|--proof-secret-value=*|--proof-runtime-secret-value|--proof-runtime-secret-value=*|--codex-credential-value|--codex-credential-value=*|--secret-value|--secret-value=*)
        recovery_die "proof secret values must never be passed to recovery-session vault-workload-auth-bootstrap"
        ;;
      --*=*)
        recovery_die "recovery-session vault-workload-auth-bootstrap does not accept equals-form options"
        ;;
      --*)
        recovery_die "recovery-session vault-workload-auth-bootstrap received an unknown option"
        ;;
      *)
        recovery_die "recovery-session vault-workload-auth-bootstrap received an unexpected positional argument"
        ;;
    esac
  done

  if [[ -z "${mode}" ]]; then
    if [[ "${execute_bootstrap_seen}" == "true" ]]; then
      mode="execute-bootstrap"
    elif [[ ( "${prepare_summary_path_seen}" == "true" && "${prepare_config_readability_seen}" == "true" ) || ( "${prepare_summary_path_seen}" == "true" && "${prepare_spire_bundle_read_seen}" == "true" ) || ( "${prepare_config_readability_seen}" == "true" && "${prepare_spire_bundle_read_seen}" == "true" ) ]]; then
      mode="prepare-bootstrap-prereqs"
    elif [[ "${prepare_summary_path_seen}" == "true" ]]; then
      mode="prepare-summary-path"
    elif [[ "${prepare_config_readability_seen}" == "true" ]]; then
      mode="prepare-config-readability"
    elif [[ "${prepare_spire_bundle_read_seen}" == "true" ]]; then
      mode="prepare-spire-bundle-read"
    else
      mode="plan"
    fi
  elif [[ "${execute_bootstrap_seen}" == "true" || "${prepare_summary_path_seen}" == "true" || "${prepare_config_readability_seen}" == "true" || "${prepare_spire_bundle_read_seen}" == "true" ]]; then
    recovery_die "recovery-session vault-workload-auth-bootstrap safe modes are mutually exclusive with --execute-bootstrap, --prepare-summary-path, --prepare-config-readability, and --prepare-spire-bundle-read"
  fi

  if [[ "${execute_bootstrap_seen}" != "true" && "${prepare_summary_path_seen}" != "true" && "${prepare_config_readability_seen}" != "true" && "${prepare_spire_bundle_read_seen}" != "true" && "${ssh_target_seen}" == "true" ]]; then
    recovery_die "recovery-session vault-workload-auth-bootstrap --ssh-target is valid only with --execute-bootstrap, --prepare-summary-path, --prepare-config-readability, or --prepare-spire-bundle-read"
  fi
  if [[ "${execute_bootstrap_seen}" != "true" && "${prepare_summary_path_seen}" != "true" && "${prepare_config_readability_seen}" != "true" && "${prepare_spire_bundle_read_seen}" != "true" && "${interactive_tty_seen}" == "true" ]]; then
    recovery_die "recovery-session vault-workload-auth-bootstrap --interactive-tty is valid only with --execute-bootstrap, --prepare-summary-path, --prepare-config-readability, or --prepare-spire-bundle-read"
  fi
  if [[ "${execute_bootstrap_seen}" == "true" && "${ssh_target_seen}" != "true" ]]; then
    recovery_die "recovery-session vault-workload-auth-bootstrap --execute-bootstrap requires --ssh-target <target>"
  fi
  if [[ "${execute_bootstrap_seen}" == "true" && "${interactive_tty_seen}" != "true" ]]; then
    recovery_die "recovery-session vault-workload-auth-bootstrap --execute-bootstrap requires --interactive-tty"
  fi
  if [[ "${prepare_summary_path_seen}" == "true" && "${ssh_target_seen}" != "true" ]]; then
    recovery_die "recovery-session vault-workload-auth-bootstrap --prepare-summary-path requires --ssh-target <target>"
  fi
  if [[ "${prepare_summary_path_seen}" == "true" && "${interactive_tty_seen}" != "true" ]]; then
    recovery_die "recovery-session vault-workload-auth-bootstrap --prepare-summary-path requires --interactive-tty"
  fi
  if [[ "${prepare_config_readability_seen}" == "true" && "${ssh_target_seen}" != "true" ]]; then
    recovery_die "recovery-session vault-workload-auth-bootstrap --prepare-config-readability requires --ssh-target <target>"
  fi
  if [[ "${prepare_config_readability_seen}" == "true" && "${interactive_tty_seen}" != "true" ]]; then
    recovery_die "recovery-session vault-workload-auth-bootstrap --prepare-config-readability requires --interactive-tty"
  fi
  if [[ "${prepare_spire_bundle_read_seen}" == "true" && "${ssh_target_seen}" != "true" ]]; then
    recovery_die "recovery-session vault-workload-auth-bootstrap --prepare-spire-bundle-read requires --ssh-target <target>"
  fi
  if [[ "${prepare_spire_bundle_read_seen}" == "true" && "${interactive_tty_seen}" != "true" ]]; then
    recovery_die "recovery-session vault-workload-auth-bootstrap --prepare-spire-bundle-read requires --interactive-tty"
  fi
  if [[ "${execute_bootstrap_seen}" == "true" || "${prepare_summary_path_seen}" == "true" || "${prepare_config_readability_seen}" == "true" || "${prepare_spire_bundle_read_seen}" == "true" ]]; then
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
    prepare-summary-path)
      recovery_session_vault_workload_auth_bootstrap_prepare_summary_path_remote "${ssh_target}"
      ;;
    prepare-config-readability)
      recovery_session_vault_workload_auth_bootstrap_prepare_config_readability_remote "${ssh_target}"
      ;;
    prepare-spire-bundle-read)
      recovery_session_vault_workload_auth_bootstrap_prepare_spire_bundle_read_remote "${ssh_target}"
      ;;
    prepare-bootstrap-prereqs)
      if [[ "${prepare_summary_path_seen}" == "true" ]]; then
        recovery_session_vault_workload_auth_bootstrap_prepare_summary_path_remote "${ssh_target}"
      fi
      if [[ "${prepare_config_readability_seen}" == "true" ]]; then
        recovery_session_vault_workload_auth_bootstrap_prepare_config_readability_remote "${ssh_target}"
      fi
      if [[ "${prepare_spire_bundle_read_seen}" == "true" ]]; then
        recovery_session_vault_workload_auth_bootstrap_prepare_spire_bundle_read_remote "${ssh_target}"
      fi
      ;;
    execute-bootstrap)
      recovery_session_vault_workload_auth_bootstrap_remote "${ssh_target}" "${prepare_summary_path_seen}" "${prepare_config_readability_seen}" "${prepare_spire_bundle_read_seen}"
      ;;
    *)
      recovery_die "unsupported recovery-session vault-workload-auth-bootstrap mode: ${mode}"
      ;;
  esac
}

recovery_session_vault_workload_auth_bootstrap_require_command() {
  command -v "$1" >/dev/null 2>&1 || recovery_die "required local command for vault-workload-auth-bootstrap staging is unavailable"
}

recovery_session_vault_workload_auth_bootstrap_require_local_tty() {
  [[ -t 0 ]] || recovery_die "recovery-session vault-workload-auth-bootstrap --execute-bootstrap/--prepare-summary-path/--prepare-config-readability/--prepare-spire-bundle-read requires visible local terminal stdin; no staging or SSH occurred"
  [[ -t 1 ]] || recovery_die "recovery-session vault-workload-auth-bootstrap --execute-bootstrap/--prepare-summary-path/--prepare-config-readability/--prepare-spire-bundle-read requires visible local terminal stdout; no staging or SSH occurred"
}

recovery_session_vault_workload_auth_bootstrap_validate_ssh_target() {
  local ssh_target=$1
  case "${ssh_target}" in
    -*|*[[:space:]]*|*';'*|*'`'*|*'$('*|*'|'*|*'&'*|*'<'*|*'>'*)
      recovery_die "recovery-session vault-workload-auth-bootstrap --ssh-target must be a single SSH target, not an option or shell command"
      ;;
  esac
}

recovery_session_vault_workload_auth_bootstrap_single_quote_remote() {
  local value=$1
  local escaped
  escaped="$(printf '%s' "${value}" | sed "s/'/'\\\\''/g")"
  printf "'%s'" "${escaped}"
}

recovery_session_vault_workload_auth_bootstrap_prepare_summary_path_remote() {
  local ssh_target=$1
  local remote_prepare_command remote_prepare_command_quoted summary_dir_literal summary_path_literal output_dir_definition

  recovery_session_vault_workload_auth_bootstrap_require_local_tty
  recovery_session_vault_workload_auth_bootstrap_require_command ssh
  initialize_operator_paths
  # The remote command checks the summary folder with remote_alpha_prepare_output_dir
  # before any sudo step, so its definition travels at the front of the command.
  output_dir_definition="$(cat -- "${REMOTE_ALPHA_OUTPUT_DIR_DEFINITION}")" ||
    recovery_die "could not read ${REMOTE_ALPHA_OUTPUT_DIR_DEFINITION}"

  printf '%s\n' \
    "Preparing Remote Alpha Vault workload-auth bootstrap summary path through an explicit interactive SSH TTY." \
    "This is OS/filesystem preparation only for ${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_REMOTE_SUMMARY_DIR} and ${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_REMOTE_SUMMARY}." \
    "It may request only an OS sudo password through the visible remote terminal if the helper user cannot write the summary directory; SSH stdin stays attached to that terminal so sudo owns prompt echo handling." \
    "No Vault, root token, proof secret, workload-auth check, reset/unseal, IM refresh, support bundle, CP proof, runtime identity generation, Mac .out, operator summary, transcript, tee, or script capture is run or created."

  printf -v summary_dir_literal '%q' "${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_REMOTE_SUMMARY_DIR}"
  printf -v summary_path_literal '%q' "${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_REMOTE_SUMMARY}"
  read -r -d '' remote_prepare_command <<'REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_PREPARE_SUMMARY' || true
set -euo pipefail
summary_dir=__REMOTE_ALPHA_BOOTSTRAP_SUMMARY_DIR__
summary_path=__REMOTE_ALPHA_BOOTSTRAP_SUMMARY_PATH__
helper_user="$(id -un)"
helper_group="$(id -gn)"
prep_tmp="${summary_dir}/.vault-workload-auth-bootstrap-summary.prepare.$$"
sudo_ready="false"

die_prepare() {
  printf 'summary_path_prepare_status=fail\n' >&2
  printf 'error_classification=%s\n' "$1" >&2
  rm -f -- "${prep_tmp}" 2>/dev/null || true
  exit 1
}

prepare_sudo() {
  if [[ "${sudo_ready}" != "true" ]]; then
    sudo -v -p "Remote Alpha OS sudo password for summary path preparation: " || die_prepare "summary_path_sudo_authorization_failed"
    sudo_ready="true"
  fi
}

run_sudo() {
  prepare_sudo
  sudo -n "$@"
}

# The summary folder is the shared Remote Alpha artifact folder that root
# helpers write into later. remote_alpha_prepare_output_dir creates it (as
# this user, 0700) when it is missing and refuses a symbolic link on the way, a
# folder another account owns or a folder its group or others can write, so
# sudo below only ever acts on a folder root or this user already owns.
if ! (umask 077 && remote_alpha_prepare_output_dir "${summary_dir}"); then
  die_prepare "summary_parent_unsafe"
fi

if [[ ! -w "${summary_dir}" || ! -x "${summary_dir}" ]]; then
  run_sudo chown -h "${helper_user}:${helper_group}" -- "${summary_dir}" || die_prepare "summary_parent_sudo_prepare_failed"
  chmod 0750 -- "${summary_dir}" || die_prepare "summary_parent_chmod_failed"
fi

if [[ ! -w "${summary_dir}" || ! -x "${summary_dir}" ]]; then
  die_prepare "summary_parent_not_writable_after_prepare"
fi

if [[ -L "${summary_path}" ]]; then
  die_prepare "summary_path_symlink"
fi

if [[ -e "${summary_path}" && ! -f "${summary_path}" ]]; then
  die_prepare "summary_path_not_regular"
fi

if [[ -f "${summary_path}" && ! -w "${summary_path}" ]]; then
  run_sudo chown -h "${helper_user}:${helper_group}" -- "${summary_path}" || die_prepare "summary_path_chown_failed"
  chmod 0600 -- "${summary_path}" || die_prepare "summary_path_chmod_failed"
fi

if [[ -f "${summary_path}" && ! -w "${summary_path}" ]]; then
  die_prepare "summary_path_not_writable_after_prepare"
fi

rm -f -- "${prep_tmp}" 2>/dev/null || true
if ! (umask 077 && : > "${prep_tmp}"); then
  die_prepare "summary_temp_write_failed"
fi
rm -f -- "${prep_tmp}" || die_prepare "summary_temp_cleanup_failed"

printf 'summary_path_prepare_status=pass\n'
printf 'summary_parent=%s\n' "${summary_dir}"
printf 'summary_path=%s\n' "${summary_path}"
printf 'helper_user=%s\n' "${helper_user}"
printf 'summary_parent_policy=owner_writable_0750_when_sudo_needed\n'
printf 'summary_file_policy=existing_regular_file_owner_writable_0600_when_sudo_needed\n'
printf 'final_summary_created=false\n'
printf 'vault_run=false\n'
printf 'workload_auth_check_run=false\n'
printf 'reset_unseal_im_support_bundle_cp_runtime_identity_run=false\n'
REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_PREPARE_SUMMARY

  remote_prepare_command="${remote_prepare_command/__REMOTE_ALPHA_BOOTSTRAP_SUMMARY_DIR__/${summary_dir_literal}}"
  remote_prepare_command="${remote_prepare_command/__REMOTE_ALPHA_BOOTSTRAP_SUMMARY_PATH__/${summary_path_literal}}"
  remote_prepare_command="${output_dir_definition}"$'\n'"${remote_prepare_command}"
  remote_prepare_command_quoted="$(recovery_session_vault_workload_auth_bootstrap_single_quote_remote "${remote_prepare_command}")"
  ssh -tt "${ssh_target}" "/bin/bash -c ${remote_prepare_command_quoted}"
}

recovery_session_vault_workload_auth_bootstrap_prepare_config_readability_remote() {
  local ssh_target=$1
  local remote_prepare_command remote_prepare_command_quoted config_path_literal

  recovery_session_vault_workload_auth_bootstrap_require_local_tty
  recovery_session_vault_workload_auth_bootstrap_require_command ssh

  printf '%s\n' \
    "Preparing Remote Alpha Vault workload-auth bootstrap config readability through an explicit interactive SSH TTY." \
    "This is OS/filesystem preparation only for ${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_CONFIG}." \
    "It may request only an OS sudo password through the visible remote terminal if the helper user cannot read the fixed config path; SSH stdin stays attached to that terminal so sudo owns prompt echo handling." \
    "It uses fixed-path user ACLs for the helper user when needed; it does not chown /etc directories, world-read config, print config contents, or touch unrelated evidence files." \
    "No Vault, root token, proof secret, workload-auth check, reset/unseal, IM refresh, support bundle, CP proof, runtime identity generation, Mac .out, operator summary, transcript, tee, or script capture is run or created."

  printf -v config_path_literal '%q' "${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_CONFIG}"
  read -r -d '' remote_prepare_command <<'REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_PREPARE_CONFIG' || true
set -euo pipefail
config_path=__REMOTE_ALPHA_BOOTSTRAP_CONFIG_PATH__
helper_user="$(id -un)"
config_parent="${config_path%/*}"
config_grandparent="${config_parent%/*}"
sudo_ready="false"
acl_applied="false"

die_prepare() {
  printf 'config_readability_prepare_status=fail\n' >&2
  printf 'error_classification=%s\n' "$1" >&2
  printf 'config_path=%s\n' "${config_path}" >&2
  printf 'config_contents_printed=false\n' >&2
  printf 'vault_run=false\n' >&2
  printf 'workload_auth_check_run=false\n' >&2
  printf 'reset_unseal_im_support_bundle_cp_runtime_identity_run=false\n' >&2
  exit 1
}

prepare_sudo() {
  if [[ "${sudo_ready}" != "true" ]]; then
    sudo -v -p "Remote Alpha OS sudo password for config readability preparation: " || die_prepare "config_readability_sudo_authorization_failed"
    sudo_ready="true"
  fi
}

run_sudo() {
  prepare_sudo
  sudo -n "$@"
}

require_setfacl() {
  command -v setfacl >/dev/null 2>&1 || die_prepare "config_readability_acl_tool_missing"
}

if [[ ! -d "${config_grandparent}" ]]; then
  die_prepare "config_grandparent_missing"
fi

if [[ ! -d "${config_parent}" ]]; then
  die_prepare "config_parent_missing"
fi

if [[ ! -x "${config_grandparent}" ]]; then
  require_setfacl
  run_sudo setfacl -m "u:${helper_user}:--x" -- "${config_grandparent}" || die_prepare "config_grandparent_acl_failed"
  acl_applied="true"
fi

if [[ ! -x "${config_parent}" ]]; then
  require_setfacl
  run_sudo setfacl -m "u:${helper_user}:--x" -- "${config_parent}" || die_prepare "config_parent_acl_failed"
  acl_applied="true"
fi

if [[ ! -e "${config_path}" ]]; then
  die_prepare "config_missing"
fi

if [[ ! -f "${config_path}" ]]; then
  die_prepare "config_not_regular"
fi

if [[ -r "${config_path}" ]]; then
  printf 'config_readability_prepare_status=pass\n'
  printf 'config_path=%s\n' "${config_path}"
  printf 'helper_user=%s\n' "${helper_user}"
  printf 'config_readability_policy=fixed_path_user_acl_when_needed\n'
  printf 'config_acl_applied=%s\n' "${acl_applied}"
  printf 'config_contents_printed=false\n'
  printf 'vault_run=false\n'
  printf 'workload_auth_check_run=false\n'
  printf 'reset_unseal_im_support_bundle_cp_runtime_identity_run=false\n'
  exit 0
fi

require_setfacl
if [[ ! -x "${config_grandparent}" ]]; then
  run_sudo setfacl -m "u:${helper_user}:--x" -- "${config_grandparent}" || die_prepare "config_grandparent_acl_failed"
fi
if [[ ! -x "${config_parent}" ]]; then
  run_sudo setfacl -m "u:${helper_user}:--x" -- "${config_parent}" || die_prepare "config_parent_acl_failed"
fi
run_sudo setfacl -m "u:${helper_user}:r--" -- "${config_path}" || die_prepare "config_file_acl_failed"
acl_applied="true"

if [[ ! -r "${config_path}" ]]; then
  die_prepare "config_not_readable_after_prepare"
fi

printf 'config_readability_prepare_status=pass\n'
printf 'config_path=%s\n' "${config_path}"
printf 'helper_user=%s\n' "${helper_user}"
printf 'config_readability_policy=fixed_path_user_acl_when_needed\n'
printf 'config_acl_applied=%s\n' "${acl_applied}"
printf 'config_contents_printed=false\n'
printf 'vault_run=false\n'
printf 'workload_auth_check_run=false\n'
printf 'reset_unseal_im_support_bundle_cp_runtime_identity_run=false\n'
REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_PREPARE_CONFIG

  remote_prepare_command="${remote_prepare_command/__REMOTE_ALPHA_BOOTSTRAP_CONFIG_PATH__/${config_path_literal}}"
  remote_prepare_command_quoted="$(recovery_session_vault_workload_auth_bootstrap_single_quote_remote "${remote_prepare_command}")"
  ssh -tt "${ssh_target}" "/bin/bash -c ${remote_prepare_command_quoted}"
}

recovery_session_vault_workload_auth_bootstrap_prepare_spire_bundle_read_remote() {
  local ssh_target=$1
  local remote_prepare_command remote_prepare_command_quoted spire_socket_literal

  recovery_session_vault_workload_auth_bootstrap_require_local_tty
  recovery_session_vault_workload_auth_bootstrap_require_command ssh

  printf '%s\n' \
    "Preparing Remote Alpha Vault workload-auth bootstrap SPIRE bundle-read access through an explicit interactive SSH TTY." \
    "This is OS/filesystem/capability preparation only for spire-server bundle show -format spiffe -socketPath ${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_SPIRE_SERVER_SOCKET}." \
    "It may request only an OS sudo password through the visible remote terminal if the helper user cannot access the fixed SPIRE server socket path; SSH stdin stays attached to that terminal so sudo owns prompt echo handling." \
    "It uses fixed-path user ACLs for the helper user when needed; it does not expose the socket to workloads or world/group principals, print SPIRE bundle contents, copy bundle contents, or touch Vault config." \
    "No Vault, root token, proof secret, workload-auth check, reset/unseal, IM refresh, support bundle, CP proof, runtime identity generation, Mac .out, operator summary, transcript, tee, or script capture is run or created."

  printf -v spire_socket_literal '%q' "${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_SPIRE_SERVER_SOCKET}"
  read -r -d '' remote_prepare_command <<'REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_PREPARE_SPIRE' || true
set -euo pipefail
spire_socket=__REMOTE_ALPHA_BOOTSTRAP_SPIRE_SOCKET_PATH__
helper_user="$(id -un)"
spire_parent="${spire_socket%/*}"
spire_server_dir="${spire_parent%/*}"
spire_root="${spire_server_dir%/*}"
sudo_ready="false"
acl_applied="false"
spire_socket_access_classification="unknown"

die_prepare() {
  printf 'spire_bundle_read_prepare_status=fail\n' >&2
  printf 'error_classification=%s\n' "$1" >&2
  printf 'spire_server_socket_path=%s\n' "${spire_socket}" >&2
  printf 'spire_socket_access_classification=%s\n' "${spire_socket_access_classification}" >&2
  printf 'bundle_contents_printed=false\n' >&2
  printf 'vault_run=false\n' >&2
  printf 'workload_auth_check_run=false\n' >&2
  printf 'reset_unseal_im_support_bundle_cp_runtime_identity_run=false\n' >&2
  exit 1
}

prepare_sudo() {
  if [[ "${sudo_ready}" != "true" ]]; then
    sudo -v -p "Remote Alpha OS sudo password for SPIRE bundle-read preparation: " || die_prepare "spire_bundle_read_sudo_authorization_failed"
    sudo_ready="true"
  fi
}

run_sudo() {
  prepare_sudo
  sudo -n "$@"
}

require_setfacl() {
  command -v setfacl >/dev/null 2>&1 || die_prepare "spire_bundle_read_acl_tool_missing"
}

require_spire_server_active_when_systemd_visible() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl is-active --quiet spire-server >/dev/null 2>&1 || die_prepare "spire_server_inactive_or_unknown"
  fi
}

probe_spire_bundle_read() {
  command -v spire-server >/dev/null 2>&1 || return 127
  spire-server bundle show -format spiffe -socketPath "${spire_socket}" >/dev/null 2>/dev/null
}

sudo_path_test() {
  local predicate=$1
  local path=$2
  prepare_sudo
  sudo -n test "${predicate}" "${path}" >/dev/null 2>/dev/null
}

require_sudo_visible_spire_path_shape() {
  local dir
  for dir in "${spire_root}" "${spire_server_dir}" "${spire_parent}"; do
    sudo_path_test -d "${dir}" || die_prepare "spire_socket_parent_missing"
  done
  sudo_path_test -e "${spire_socket}" || die_prepare "spire_socket_missing"
  sudo_path_test -S "${spire_socket}" || die_prepare "spire_socket_not_socket"
}

helper_can_access_spire_socket() {
  local dir
  for dir in "${spire_root}" "${spire_server_dir}" "${spire_parent}"; do
    [[ -x "${dir}" ]] || return 1
  done
  [[ -S "${spire_socket}" && -r "${spire_socket}" && -w "${spire_socket}" ]]
}

if probe_spire_bundle_read; then
  spire_socket_access_classification="spire_socket_present_accessible"
  printf 'spire_bundle_read_prepare_status=pass\n'
  printf 'spire_server_socket_path=%s\n' "${spire_socket}"
  printf 'helper_user=%s\n' "${helper_user}"
  printf 'spire_bundle_read_policy=fixed_path_user_acl_when_needed\n'
  printf 'spire_socket_access_classification=%s\n' "${spire_socket_access_classification}"
  printf 'spire_socket_acl_applied=false\n'
  printf 'bundle_output_discarded=true\n'
  printf 'bundle_contents_printed=false\n'
  printf 'vault_run=false\n'
  printf 'workload_auth_check_run=false\n'
  printf 'reset_unseal_im_support_bundle_cp_runtime_identity_run=false\n'
  exit 0
fi

command -v spire-server >/dev/null 2>&1 || die_prepare "spire_server_command_missing"
require_spire_server_active_when_systemd_visible

if helper_can_access_spire_socket; then
  spire_socket_access_classification="spire_socket_present_accessible"
  die_prepare "spire_bundle_show_failed"
fi

require_sudo_visible_spire_path_shape
spire_socket_access_classification="spire_socket_present_needs_acl"
require_setfacl
for dir in "${spire_root}" "${spire_server_dir}" "${spire_parent}"; do
  if [[ ! -x "${dir}" ]]; then
    run_sudo setfacl -m "u:${helper_user}:--x" -- "${dir}" || die_prepare "spire_socket_parent_acl_failed"
    acl_applied="true"
  fi
done

if [[ ! -r "${spire_socket}" || ! -w "${spire_socket}" ]]; then
  run_sudo setfacl -m "u:${helper_user}:rw-" -- "${spire_socket}" || die_prepare "spire_socket_acl_failed"
  acl_applied="true"
fi

helper_can_access_spire_socket || die_prepare "spire_bundle_show_failed"

if ! probe_spire_bundle_read; then
  die_prepare "spire_bundle_show_failed"
fi

printf 'spire_bundle_read_prepare_status=pass\n'
printf 'spire_server_socket_path=%s\n' "${spire_socket}"
printf 'helper_user=%s\n' "${helper_user}"
printf 'spire_bundle_read_policy=fixed_path_user_acl_when_needed\n'
printf 'spire_socket_access_classification=%s\n' "${spire_socket_access_classification}"
printf 'spire_socket_acl_applied=%s\n' "${acl_applied}"
printf 'bundle_output_discarded=true\n'
printf 'bundle_contents_printed=false\n'
printf 'vault_run=false\n'
printf 'workload_auth_check_run=false\n'
printf 'reset_unseal_im_support_bundle_cp_runtime_identity_run=false\n'
REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_PREPARE_SPIRE

  remote_prepare_command="${remote_prepare_command/__REMOTE_ALPHA_BOOTSTRAP_SPIRE_SOCKET_PATH__/${spire_socket_literal}}"
  remote_prepare_command_quoted="$(recovery_session_vault_workload_auth_bootstrap_single_quote_remote "${remote_prepare_command}")"
  ssh -tt "${ssh_target}" "/bin/bash -c ${remote_prepare_command_quoted}"
}

recovery_session_vault_workload_auth_bootstrap_stage_remote() {
  local ssh_target=$1
  local remote_stage_dir=$2
  local remote_public_helper_path=$3
  local remote_internal_helper_path=$4

  ssh "${ssh_target}" /bin/bash -s -- "${remote_stage_dir}" <<'REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_PREPARE'
set -euo pipefail
stage_dir=$1
# A new folder directly under /tmp, made with mkdir and no -p: a folder or
# link someone planted at this name makes staging fail, and nobody but this
# user (and root) can change what is staged in it.
mkdir -m 0700 -- "${stage_dir}"
mkdir -m 0700 -- "${stage_dir}/scripts" "${stage_dir}/scripts/internal"
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
# Remove only a real folder this user owns: when staging failed because
# something else was at this name, leave it alone.
if [[ -d "${stage_dir}" && ! -L "${stage_dir}" && -O "${stage_dir}" ]]; then
  rm -rf -- "${stage_dir}" || true
fi
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
  local prepare_summary_path=${2:-false}
  local prepare_config_readability=${3:-false}
  local prepare_spire_bundle_read=${4:-false}
  local run_id remote_stage_dir remote_public_helper_path remote_internal_helper_path remote_status cleanup_status

  recovery_session_vault_workload_auth_bootstrap_require_local_tty
  recovery_session_vault_workload_auth_bootstrap_require_command ssh
  recovery_session_vault_workload_auth_bootstrap_require_command scp

  initialize_operator_paths
  if [[ ! -x "${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_PUBLIC_HELPER}" ]]; then
    recovery_die "Vault workload-auth bootstrap public helper is unavailable"
  fi
  if [[ ! -r "${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_INTERNAL_HELPER}" ]]; then
    recovery_die "Vault workload-auth bootstrap internal helper is unavailable"
  fi

  run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
  remote_stage_dir="${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_STAGE_ROOT}-${run_id}"
  remote_public_helper_path="${remote_stage_dir}/scripts/remote_alpha_vault_workload_auth_bootstrap.sh"
  remote_internal_helper_path="${remote_stage_dir}/scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh"

  if [[ "${prepare_summary_path}" == "true" ]]; then
    recovery_session_vault_workload_auth_bootstrap_prepare_summary_path_remote "${ssh_target}"
  fi
  if [[ "${prepare_config_readability}" == "true" ]]; then
    recovery_session_vault_workload_auth_bootstrap_prepare_config_readability_remote "${ssh_target}"
  fi
  if [[ "${prepare_spire_bundle_read}" == "true" ]]; then
    recovery_session_vault_workload_auth_bootstrap_prepare_spire_bundle_read_remote "${ssh_target}"
  fi

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
  command -v "$1" >/dev/null 2>&1 || recovery_die "required local command for vault-unseal-existing staging is unavailable"
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
# A new folder directly under /tmp, made with mkdir and no -p: a folder or
# link someone planted at this name makes staging fail, and nobody but this
# user (and root) can change what is staged in it.
mkdir -m 0700 -- "${stage_dir}"
REMOTE_ALPHA_VAULT_UNSEAL_PREPARE

  scp "${REMOTE_ALPHA_VAULT_RESET_HELPER}" "${ssh_target}:${remote_helper_path}"
}

recovery_session_vault_unseal_existing_cleanup_remote() {
  local ssh_target=$1
  local remote_stage_dir=$2

  ssh "${ssh_target}" /bin/bash -s -- "${remote_stage_dir}" <<'REMOTE_ALPHA_VAULT_UNSEAL_CLEANUP'
set -euo pipefail
stage_dir=$1
# Remove only a real folder this user owns: when staging failed because
# something else was at this name, leave it alone.
if [[ -d "${stage_dir}" && ! -L "${stage_dir}" && -O "${stage_dir}" ]]; then
  rm -rf -- "${stage_dir}" || true
fi
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
  remote_stage_dir="${REMOTE_ALPHA_VAULT_UNSEAL_STAGE_ROOT}-${run_id}"
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
        recovery_die "recovery-session vault-unseal-existing received a forbidden option category"
        ;;
      --*=*)
        recovery_die "recovery-session vault-unseal-existing does not accept equals-form options"
        ;;
      --*)
        recovery_die "recovery-session vault-unseal-existing received an unknown option"
        ;;
      *)
        recovery_die "recovery-session vault-unseal-existing received an unexpected positional argument"
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

  initialize_operator_paths
  if [[ ! -x "${REMOTE_ALPHA_VAULT_RESET_HELPER}" ]]; then
    recovery_die "Vault reset helper is unavailable"
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
  command -v "$1" >/dev/null 2>&1 || recovery_die "required local command for vault-reset-disposable staging is unavailable"
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
# A new folder directly under /tmp, made with mkdir and no -p: a folder or
# link someone planted at this name makes staging fail, and nobody but this
# user (and root) can change what is staged in it.
mkdir -m 0700 -- "${stage_dir}"
REMOTE_ALPHA_VAULT_RESET_DRY_RUN_PREPARE

  scp "${REMOTE_ALPHA_VAULT_RESET_HELPER}" "${ssh_target}:${remote_helper_path}"
}

recovery_session_vault_reset_disposable_cleanup_remote() {
  local ssh_target=$1
  local remote_stage_dir=$2

  ssh "${ssh_target}" /bin/bash -s -- "${remote_stage_dir}" <<'REMOTE_ALPHA_VAULT_RESET_DRY_RUN_CLEANUP'
set -euo pipefail
stage_dir=$1
# Remove only a real folder this user owns: when staging failed because
# something else was at this name, leave it alone.
if [[ -d "${stage_dir}" && ! -L "${stage_dir}" && -O "${stage_dir}" ]]; then
  rm -rf -- "${stage_dir}" || true
fi
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
    remote_stage_dir="${REMOTE_ALPHA_VAULT_RESET_EXECUTE_STAGE_ROOT}-${run_id}"
  else
    remote_stage_dir="${REMOTE_ALPHA_VAULT_RESET_DRY_RUN_STAGE_ROOT}-${run_id}"
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
        recovery_die "recovery-session vault-reset-disposable received a forbidden option category"
        ;;
      --*=*)
        recovery_die "recovery-session vault-reset-disposable does not accept equals-form options"
        ;;
      --*)
        recovery_die "recovery-session vault-reset-disposable received an unknown option"
        ;;
      *)
        recovery_die "recovery-session vault-reset-disposable received an unexpected positional argument"
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

  initialize_operator_paths
  if [[ ! -x "${REMOTE_ALPHA_VAULT_RESET_HELPER}" ]]; then
    recovery_die "Vault reset helper is unavailable"
  fi

  if [[ "${execute_reset_seen}" == "true" ]]; then
    recovery_session_vault_reset_disposable_remote "${ssh_target}" "--execute-reset"
  else
    recovery_session_vault_reset_disposable_remote "${ssh_target}" "--dry-run"
  fi
}

recovery_session_es_service_tls_require_command() {
  command -v "$1" >/dev/null 2>&1 || recovery_die "$1 is required for Mac-side es-service-tls staging"
}

recovery_session_es_service_tls_require_local_tty() {
  [[ -t 0 ]] || recovery_die "recovery-session es-service-tls requires visible local terminal stdin; no staging or SSH occurred"
  [[ -t 1 ]] || recovery_die "recovery-session es-service-tls requires visible local terminal stdout; no staging or SSH occurred"
}

recovery_session_es_service_tls_validate_ssh_target() {
  local ssh_target=$1
  case "${ssh_target}" in
    -*|*[[:space:]]*|*';'*|*'`'*|*'$('*|*'|'*|*'&'*|*'<'*|*'>'*)
      recovery_die "recovery-session es-service-tls --ssh-target must be a single SSH target, not an option or shell command"
      ;;
  esac
}

recovery_session_es_service_tls_cleanup_remote() {
  local ssh_target=$1
  local remote_stage_dir=$2

  ssh "${ssh_target}" /bin/bash -s -- "${remote_stage_dir}" <<'REMOTE_ALPHA_ES_SERVICE_TLS_CLEANUP'
set -euo pipefail
stage_dir=$1
# Remove only a real folder this user owns: when staging failed because
# something else was at this name, leave it alone.
if [[ -d "${stage_dir}" && ! -L "${stage_dir}" && -O "${stage_dir}" ]]; then
  rm -rf -- "${stage_dir}" || true
fi
REMOTE_ALPHA_ES_SERVICE_TLS_CLEANUP
}

recovery_session_es_tls_usage() {
  local route=$1
  local scope=$2
  printf '%s\n' \
    "Remote Alpha recovery-session mode: ${route}" \
    "P0s/P0t status-only collector; renewal is held pending a separately designed contract." \
    "Stages only scripts/internal/remote_alpha_es_tls_status.py in one generated /tmp invocation directory." \
    "The collector self-cleans its stage before status work and writes only the fixed protected summary." \
    "Collector exit zero means a completed observation was published; inspect an accepted fresh result.status for pass or fail." \
    "The summary is evidence only and grants no renewal, monitor, scheduler, IM, CP, or restoration authority." \
    "" \
    "Usage: remote_alpha_operator.sh recovery-session ${route} --ssh-target <user@host> --interactive-tty" \
    "Fixed scope: ${scope}" \
    "Allowed flags: --help, --ssh-target <target>, --interactive-tty" \
    "--execute-renew and all path, helper, output, and command overrides are refused before contact." \
    "No summary copy-back, transcript, support bundle, or raw TLS/config output is produced."
}

recovery_session_es_tls_diagnostic_usage() {
  printf '%s\n' \
    "Remote Alpha recovery-session mode: es-governance-tls-grammar-diagnostic" \
    "Fixed execution-governance first-rejection diagnostic; no protected P0t status is published." \
    "Stages only scripts/internal/remote_alpha_es_tls_status.py with verified source and custody." \
    "A completed diagnostic line is advisory, not TLS pass, readiness, restoration or retry authority." \
    "Usage: remote_alpha_operator.sh recovery-session es-governance-tls-grammar-diagnostic --ssh-target <user@host> --interactive-tty" \
    "Local only: remote_alpha_operator.sh recovery-session es-governance-tls-grammar-diagnostic --verify-only" \
    "Allowed flags: --help alone, --ssh-target <target> with --interactive-tty for live use, or --verify-only alone." \
    "No raw native output, transcript, summary copy-back, renewal, service action or automatic retry."
}

remote_alpha_es_tls_status_shell_quote() {
  local value=$1
  value=${value//\'/\'\\\'\'}
  printf "'%s'" "${value}"
}

remote_alpha_es_tls_status_remote_wrapper() {
  local stage_dir=$1 stage_identity=$2 scope=$3 collector_digest=$4 diagnostic_mode=${5:-status}
  local LC_ALL=C stage_dev stage_ino wrapper remote_command
  [[ "${stage_dir}" =~ ^/tmp/\.es-tls-status-[0-9a-f]{32}$ ]] || return 2
  [[ "${stage_identity}" =~ ^[1-9][0-9]{0,19}:[1-9][0-9]{0,19}$ ]] || return 2
  stage_dev=${stage_identity%%:*}
  stage_ino=${stage_identity#*:}
  [[ ${#stage_dev} -lt 20 || "${stage_dev}" < 18446744073709551615 || "${stage_dev}" == 18446744073709551615 ]] || return 2
  [[ ${#stage_ino} -lt 20 || "${stage_ino}" < 18446744073709551615 || "${stage_ino}" == 18446744073709551615 ]] || return 2
  case "${scope}" in artifact-registry|execution-governance) ;; *) return 2 ;; esac
  [[ "${collector_digest}" =~ ^[0-9a-f]{64}$ ]] || return 2
  case "${diagnostic_mode}" in
    status) ;;
    grammar-diagnostic) [[ "${scope}" == execution-governance ]] || return 2 ;;
    *) return 2 ;;
  esac
  IFS= read -r -d '' wrapper <<'REMOTE_ALPHA_ES_TLS_STATUS_REMOTE_WRAPPER' || true
set -euo pipefail
stage_dir=$1
stage_identity=$2
scope=$3
collector_digest=$4
diagnostic_mode=${5:-status}
collector="${stage_dir}/remote_alpha_es_tls_status.py"

[[ "${stage_dir}" =~ ^/tmp/\.es-tls-status-[0-9a-f]{32}$ ]]
[[ "${stage_identity}" =~ ^[0-9]+:[0-9]+$ ]]
case "${scope}" in artifact-registry|execution-governance) ;; *) exit 2 ;; esac
[[ "${collector_digest}" =~ ^[0-9a-f]{64}$ ]]
case "${diagnostic_mode}" in
  status) ;;
  grammar-diagnostic) [[ "${scope}" == execution-governance ]] ;;
  *) exit 2 ;;
esac
/usr/bin/python3 -I -B - "${collector}" "${stage_identity}" <<'REMOTE_ALPHA_ES_TLS_STATUS_MODE'
import os
import stat
import sys

path, identity = sys.argv[1:]
directory, name = os.path.split(path)
expected_identity = tuple(int(part) for part in identity.split(":"))
def leaf_identity(info):
    return (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode), info.st_uid, info.st_gid,
            stat.S_IMODE(info.st_mode), info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    directory_info = os.fstat(directory_fd)
    directory_entry = os.stat(directory, follow_symlinks=False)
    if (not stat.S_ISDIR(directory_info.st_mode) or directory_info.st_uid != os.geteuid() or
            stat.S_IMODE(directory_info.st_mode) != 0o700 or
            (directory_info.st_dev, directory_info.st_ino) != expected_identity or
            (directory_entry.st_dev, directory_entry.st_ino) != expected_identity):
        raise SystemExit(1)
    entry_info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    if (not stat.S_ISREG(entry_info.st_mode) or entry_info.st_uid != os.geteuid() or
            stat.S_IMODE(entry_info.st_mode) not in (0o600, 0o644) or entry_info.st_nlink != 1):
        raise SystemExit(1)
    file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory_fd)
    try:
        file_info = os.fstat(file_fd)
        if leaf_identity(file_info) != leaf_identity(entry_info):
            raise SystemExit(1)
        os.fchmod(file_fd, 0o600)
        after = os.fstat(file_fd)
        after_entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (stat.S_IMODE(after.st_mode) != 0o600 or leaf_identity(after) != leaf_identity(after_entry) or
                (after.st_dev, after.st_ino) != (entry_info.st_dev, entry_info.st_ino)):
            raise SystemExit(1)
    finally:
        os.close(file_fd)
finally:
    os.close(directory_fd)
REMOTE_ALPHA_ES_TLS_STATUS_MODE
# The fixed root bootstrap loads only digest-bound bytes from the staged leaf.
# On handoff, a rejected stage remains diagnostic residue.
IFS= read -r -d '' bootstrap <<'REMOTE_ALPHA_ES_TLS_STATUS_BOOTSTRAP' || true
import atexit
import hashlib
import os
import pwd
import re
import signal
import stat
import sys

_FAILURE_WITNESS_COUPLINGS = {
    "bootstrap_entry": ("invocation_unproved", "caller_identity_unproved"),
    "stage_custody": ("stage_custody_unproved", "source_unproved"),
    "stage_disposition": ("stage_disposition_unproved",),
    "collector_load": ("collector_load_unproved",),
    "collector_entry": ("invocation_unproved",),
    "protected_ancestry": ("protected_state_unproved",),
    "scope_lock": ("lock_state_unproved", "lock_acquisition_unproved"),
    "process_capability": ("process_capability_unproved",),
    "prior_snapshot": ("prior_summary_unaccepted", "prior_read_unproved"),
    "collection": ("fixed_input_unproved", "fixed_command_unproved",
                   "openssl_child_unproved", "openssl_grammar_unaccepted"),
    "record_encoding": ("record_unaccepted",),
    "publication_precommit": ("publication_unproved",),
}

def format_failure_witness(scope_value, origin, source, source_digest, phase, reason):
    fields = (scope_value, origin, source, source_digest, phase, reason)
    if any(type(value) is not str for value in fields):
        return None
    if scope_value not in ("artifact-registry", "execution-governance", "unknown"):
        return None
    if origin not in ("bootstrap", "collector") or source not in ("verified", "unverified"):
        return None
    if ((source == "verified" and re.fullmatch(r"[0-9a-f]{64}", source_digest) is None) or
            (source == "unverified" and source_digest != "none")):
        return None
    if phase not in _FAILURE_WITNESS_COUPLINGS:
        return None
    bootstrap_phase = phase in ("bootstrap_entry", "stage_custody", "stage_disposition", "collector_load")
    if (origin == "bootstrap") is not bootstrap_phase:
        return None
    if reason not in _FAILURE_WITNESS_COUPLINGS[phase] and reason not in ("interrupted", "unknown"):
        return None
    if scope_value == "unknown" and (origin != "bootstrap" or phase != "bootstrap_entry"):
        return None
    if origin == "collector" and (source != "verified" or scope_value == "unknown"):
        return None
    if (phase == "bootstrap_entry" and source != "unverified") or (
            phase in ("stage_disposition", "collector_load") and source != "verified"):
        return None
    line = ("ES_TLS_STATUS_FAILURE_V1 scope=" + scope_value + " origin=" + origin +
            " source=" + source + " collector_sha256=" + source_digest +
            " phase=" + phase + " reason=" + reason + "\n").encode("ascii")
    return line if len(line) <= 512 else None

def write_failure_witness(line):
    # Independently opened output-only terminal; never touch inherited OFDs.
    fd = None
    try:
        fd = os.open("/dev/tty", os.O_WRONLY | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC)
        if os.isatty(fd):
            os.write(fd, line)  # One best-effort write; short/blocked output is not retried.
    except BaseException:
        pass
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except BaseException:
                pass

scope_value = "unknown"
source_verified = False
verified_digest = "none"
bootstrap_phase = "bootstrap_entry"
bootstrap_reason = "invocation_unproved"
owned_fds = {"parent": False, "directory": False, "file": False}
stage_closeout = False
collector_started = False
collector_failure_exit = False
collector_namespace = None
uncaught = [False]

def emit_failure_witness():
    if uncaught[0] or any(owned_fds.values()):
        return
    if collector_started:
        if (stage_closeout is not True or collector_failure_exit is not True or
                type(collector_namespace) is not dict or
                collector_namespace.get("WITNESS_CLOSEOUT_PROVED") is not True or
                collector_namespace.get("WITNESS_DISPOSITION_UNPROVED") is not False):
            return
        selection = collector_namespace.get("WITNESS_SELECTION")
        if type(selection) is not tuple or len(selection) != 2:
            return
        line = format_failure_witness(scope_value, "collector", "verified", verified_digest,
                                      selection[0], selection[1])
    else:
        line = format_failure_witness(scope_value, "bootstrap",
                                      "verified" if source_verified else "unverified",
                                      verified_digest, bootstrap_phase, bootstrap_reason)
    if line is not None:
        write_failure_witness(line)

def quiet_unhandled(_kind, _value, _traceback):
    uncaught[0] = True  # Never print an arbitrary exception or infer its disposition.

sys.excepthook = quiet_unhandled
diagnostic_mode = len(sys.argv) == 8 and sys.argv[-1] == "grammar-diagnostic"
if len(sys.argv) != 7 and not diagnostic_mode:
    raise SystemExit(1)
if not diagnostic_mode:
    atexit.register(emit_failure_witness)

stage, basename, digest, scope, expected_dev, expected_ino = sys.argv[1:7]
def strict_uint64(value):
    if re.fullmatch(r"(?:0|[1-9][0-9]{0,19})", value) is None:
        raise SystemExit(1)
    number = int(value)
    if number == 0 or number > 18446744073709551615:
        raise SystemExit(1)
    return number
expected_identity = (strict_uint64(expected_dev), strict_uint64(expected_ino))
if (re.fullmatch(r"/tmp/\.es-tls-status-[0-9a-f]{32}", stage) is None or
        basename != "remote_alpha_es_tls_status.py" or
        re.fullmatch(r"[0-9a-f]{64}", digest) is None or
        scope not in ("artifact-registry", "execution-governance") or
        (diagnostic_mode and scope != "execution-governance")):
    raise SystemExit(1)
scope_value = scope
bootstrap_reason = "caller_identity_unproved"
if os.geteuid() != 0 or os.environ.get("SUDO_USER") != "ds":
    raise SystemExit(1)
try:
    operator = pwd.getpwnam("ds")
    operator_uid, operator_gid = operator.pw_uid, operator.pw_gid
    if (operator_uid == 0 or int(os.environ.get("SUDO_UID", "")) != operator_uid or
            int(os.environ.get("SUDO_GID", "")) != operator_gid):
        raise ValueError()
except (KeyError, ValueError):
    raise SystemExit(1)
bootstrap_phase = "stage_custody"
bootstrap_reason = "stage_custody_unproved"
interrupted = [False]
for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM):
    signal.signal(signum, lambda _signum, _frame: interrupted.__setitem__(0, True))
def check_signal():
    global bootstrap_reason
    if interrupted[0]:
        bootstrap_reason = "interrupted"
        raise SystemExit(1)
def leaf_identity(info):
    return (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode), info.st_uid, info.st_gid,
            stat.S_IMODE(info.st_mode), info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
def check_access(fd):
    if any(attr not in ("security.selinux", "com.apple.provenance") for attr in os.listxattr(fd)):
        raise SystemExit(1)
parent_fd = os.open("/tmp", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
owned_fds["parent"] = True
try:
    parent = os.fstat(parent_fd)
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_gid != 0 or
            stat.S_IMODE(parent.st_mode) != 0o1777):
        raise SystemExit(1)
    check_access(parent_fd)
    name = os.path.basename(stage)
    entry_dir = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if (not stat.S_ISDIR(entry_dir.st_mode) or
            (entry_dir.st_dev, entry_dir.st_ino) != expected_identity or
            entry_dir.st_uid != operator_uid or entry_dir.st_gid != operator_gid or
            stat.S_IMODE(entry_dir.st_mode) != 0o700 or entry_dir.st_nlink < 2):
        raise SystemExit(1)
    dir_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=parent_fd)
    owned_fds["directory"] = True
    try:
        directory = os.fstat(dir_fd)
        entry_dir = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != operator_uid or
                directory.st_gid != operator_gid or
                stat.S_IMODE(directory.st_mode) != 0o700 or directory.st_nlink < 2 or
                (directory.st_dev, directory.st_ino) != expected_identity or
                (entry_dir.st_dev, entry_dir.st_ino) != expected_identity):
            raise SystemExit(1)
        check_access(dir_fd)
        if os.listdir(dir_fd) != [basename]:
            raise SystemExit(1)
        entry = os.stat(basename, dir_fd=dir_fd, follow_symlinks=False)
        if (not stat.S_ISREG(entry.st_mode) or entry.st_uid != operator_uid or
                entry.st_gid != operator_gid or
                stat.S_IMODE(entry.st_mode) != 0o600 or entry.st_nlink != 1 or
                entry.st_size > 1048576):
            raise SystemExit(1)
        file_fd = os.open(basename, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                          dir_fd=dir_fd)
        owned_fds["file"] = True
        try:
            opened = os.fstat(file_fd)
            if leaf_identity(opened) != leaf_identity(entry):
                raise SystemExit(1)
            check_access(file_fd)
            chunks = []
            total = 0
            while True:
                block = os.read(file_fd, min(16384, 1048577 - total))
                if not block:
                    break
                total += len(block)
                if total > 1048576:
                    raise SystemExit(1)
                chunks.append(block)
            payload = b"".join(chunks)
            after = os.fstat(file_fd)
            current = os.stat(basename, dir_fd=dir_fd, follow_symlinks=False)
            if (total != opened.st_size or leaf_identity(after) != leaf_identity(opened) or
                    leaf_identity(current) != leaf_identity(opened)):
                raise SystemExit(1)
            bootstrap_reason = "source_unproved"
            if hashlib.sha256(payload).hexdigest() != digest:
                raise SystemExit(1)
            source_verified = True
            verified_digest = digest
            check_signal()
            bootstrap_phase = "stage_disposition"
            bootstrap_reason = "stage_disposition_unproved"
            os.fchown(dir_fd, 0, 0)
            current_dir = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            current = os.stat(basename, dir_fd=dir_fd, follow_symlinks=False)
            if (os.fstat(dir_fd).st_uid != 0 or os.fstat(dir_fd).st_gid != 0 or
                    (current_dir.st_dev, current_dir.st_ino) !=
                    expected_identity or
                    leaf_identity(current) != leaf_identity(opened)):
                raise SystemExit(1)
            os.unlink(basename, dir_fd=dir_fd)
        finally:
            os.close(file_fd)
            owned_fds["file"] = False
        if os.listdir(dir_fd):
            raise SystemExit(1)
        current_dir = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if ((current_dir.st_dev, current_dir.st_ino) != expected_identity or
                (os.fstat(dir_fd).st_dev, os.fstat(dir_fd).st_ino) != expected_identity):
            raise SystemExit(1)
        os.rmdir(name, dir_fd=parent_fd)
        check_signal()
    finally:
        os.close(dir_fd)
        owned_fds["directory"] = False
finally:
    os.close(parent_fd)
    owned_fds["parent"] = False
stage_closeout = True
if diagnostic_mode:
    label = "<verified-es-tls-grammar-diagnostic>"
    sys.argv = [label]
    namespace = {"__name__": "_es_tls_grammar_diagnostic", "__file__": label,
                 "ES_TLS_GRAMMAR_DIAGNOSTIC_BOOTSTRAP_VERIFIED": True,
                 "ES_TLS_GRAMMAR_DIAGNOSTIC_BOOTSTRAP_INTERRUPTED": interrupted,
                 "ES_TLS_GRAMMAR_DIAGNOSTIC_SOURCE_SHA256": digest}
else:
    label = "<verified-es-tls-status-collector>"
    sys.argv = [label, "--scope", scope]
    namespace = {"__name__": "__main__", "__file__": label,
                 "ES_TLS_STATUS_BOOTSTRAP_VERIFIED": True,
                 "ES_TLS_STATUS_BOOTSTRAP_INTERRUPTED": interrupted}
bootstrap_phase = "collector_load"
bootstrap_reason = "collector_load_unproved"
try:
    compiled_payload = compile(payload, label, "exec")
except BaseException:
    raise SystemExit(1)
collector_namespace = namespace
collector_started = True
try:
    exec(compiled_payload, namespace)
except SystemExit as stopped:
    if diagnostic_mode:
        raise SystemExit(1)
    # Preserve only the collector's fixed integer exit contract. Python must
    # never print a hostile SystemExit payload on the operator terminal.
    if type(stopped.code) is int and stopped.code in (0, 1, 2):
        collector_failure_exit = stopped.code == 1
        raise SystemExit(stopped.code)
    raise SystemExit(1)
except BaseException:
    raise SystemExit(1)
if diagnostic_mode:
    try:
        entry = namespace.get("diagnostic_main")
        formatter = namespace.get("format_diagnostic_line")
        if not callable(entry) or not callable(formatter):
            raise SystemExit(1)
        result = entry()
        line = formatter(result, digest)
        if (type(result) is not dict or type(line) is not bytes or
                not line.startswith(b"ES_TLS_GRAMMAR_DIAGNOSTIC_V2 ") or
                not line.endswith(b"\n") or line.count(b"\n") != 1 or
                len(line) > 2048 or not line.isascii()):
            raise SystemExit(1)
    except BaseException:
        raise SystemExit(1)
    write_failure_witness(line)  # One output-only terminal attempt; no status witness is installed.
    if result["outcome"] in ("first_grammar_rejection", "no_grammar_rejection_reached"):
        raise SystemExit(0)
    raise SystemExit(1)
# The verified collector's __main__ path exits explicitly. A return is not a
# completed record and cannot earn a witness.
raise SystemExit(1)
REMOTE_ALPHA_ES_TLS_STATUS_BOOTSTRAP
stage_dev=${stage_identity%%:*}
stage_ino=${stage_identity#*:}
if [[ "${diagnostic_mode}" == grammar-diagnostic ]]; then
  sudo LC_ALL=C /usr/bin/python3 -I -B -c "${bootstrap}" "${stage_dir}" \
    remote_alpha_es_tls_status.py "${collector_digest}" "${scope}" "${stage_dev}" "${stage_ino}" grammar-diagnostic
else
  sudo LC_ALL=C /usr/bin/python3 -I -B -c "${bootstrap}" "${stage_dir}" \
    remote_alpha_es_tls_status.py "${collector_digest}" "${scope}" "${stage_dev}" "${stage_ino}"
fi
REMOTE_ALPHA_ES_TLS_STATUS_REMOTE_WRAPPER
  remote_command="/bin/bash -c $(remote_alpha_es_tls_status_shell_quote "${wrapper}") -- $(remote_alpha_es_tls_status_shell_quote "${stage_dir}") $(remote_alpha_es_tls_status_shell_quote "${stage_identity}") $(remote_alpha_es_tls_status_shell_quote "${scope}") $(remote_alpha_es_tls_status_shell_quote "${collector_digest}")"
  if [[ "${diagnostic_mode}" == grammar-diagnostic ]]; then
    remote_command="${remote_command} $(remote_alpha_es_tls_status_shell_quote "${diagnostic_mode}")"
  fi
  [[ ${#remote_command} -le 32768 ]] || return 2
  printf '%s' "${remote_command}"
}

recovery_session_es_tls_status() {
  local route=$1
  local scope=$2
  shift 2
  local diagnostic=false verify_only=false help_seen=false
  [[ "${route}" != es-governance-tls-grammar-diagnostic ]] || diagnostic=true
  local ssh_target_seen=false interactive_tty_seen=false ssh_target=""
  local option
  for option in "$@"; do
    case "${option}" in
      --execute-renew|--execute-renew=*)
        recovery_die "${route} refuses --execute-renew; P0s/P0t renewal is held before host contact"
        ;;
    esac
  done
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --help|-h)
        if [[ "${diagnostic}" == true ]]; then
          [[ "${help_seen}" == false ]] || recovery_die "${route} duplicate help flag"
          help_seen=true
          shift
        else
          recovery_session_es_tls_usage "${route}" "${scope}"
          return 0
        fi
        ;;
      --ssh-target)
        require_recovery_option_not_seen "$1" "${ssh_target_seen}"
        require_recovery_option_value "$1" "$#" "${2:-}"
        ssh_target_seen=true
        ssh_target=$2
        shift 2
        ;;
      --interactive-tty)
        require_recovery_option_not_seen "$1" "${interactive_tty_seen}"
        interactive_tty_seen=true
        shift
        ;;
      --verify-only)
        [[ "${diagnostic}" == true ]] || recovery_die "${route} refuses --verify-only"
        require_recovery_option_not_seen "$1" "${verify_only}"
        verify_only=true
        shift
        ;;
      --execute-renew|--execute-renew=*)
        recovery_die "${route} refuses --execute-renew; P0s/P0t renewal is held before host contact"
        ;;
      --*=*)
        recovery_die "${route} does not accept equals-form options: $1"
        ;;
      --*)
        recovery_die "${route} refuses unsupported option: $1"
        ;;
      *)
        recovery_die "${route} refuses positional argument: $1"
        ;;
    esac
  done
  if [[ "${diagnostic}" == true && "${help_seen}" == true ]]; then
    [[ "${ssh_target_seen}" == false && "${interactive_tty_seen}" == false && "${verify_only}" == false ]] || recovery_die "${route} --help must stand alone"
    recovery_session_es_tls_diagnostic_usage
    return 0
  fi
  initialize_operator_paths
  if [[ "${diagnostic}" == true && "${verify_only}" == true ]]; then
    [[ "${ssh_target_seen}" == false && "${interactive_tty_seen}" == false ]] || recovery_die "${route} --verify-only must stand alone"
    [[ -r "${REMOTE_ALPHA_ES_TLS_STATUS_COLLECTOR}" && -f "${REMOTE_ALPHA_ES_TLS_STATUS_COLLECTOR}" && ! -L "${REMOTE_ALPHA_ES_TLS_STATUS_COLLECTOR}" ]] || recovery_die "diagnostic collector source is not a regular readable file"
    local verify_digest verify_command
    verify_digest="$(/usr/bin/shasum -a 256 "${REMOTE_ALPHA_ES_TLS_STATUS_COLLECTOR}" | /usr/bin/cut -d ' ' -f 1)" || recovery_die "diagnostic collector digest derivation failed"
    [[ "${verify_digest}" =~ ^[0-9a-f]{64}$ ]] || recovery_die "diagnostic collector digest derivation failed"
    verify_command="$(remote_alpha_es_tls_status_remote_wrapper "/tmp/.es-tls-status-00000000000000000000000000000000" "18446744073709551615:18446744073709551615" "execution-governance" "${verify_digest}" grammar-diagnostic)" || recovery_die "diagnostic fixed command construction failed"
    [[ ${#verify_command} -le 32768 ]] || recovery_die "diagnostic fixed command too large"
    unset verify_command
    printf '%s\n' "${route}: local source and command construction verified; no host contact or P0t status observation occurred."
    return 0
  fi
  [[ "${ssh_target_seen}" == true ]] || recovery_die "${route} requires --ssh-target <target>"
  if [[ ! "${ssh_target}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*(@[A-Za-z0-9][A-Za-z0-9._-]*)?$ || ${#ssh_target} -gt 255 ]]; then
    recovery_die "${route} --ssh-target must be a single SSH target"
  fi
  [[ "${interactive_tty_seen}" == true ]] || recovery_die "${route} requires --interactive-tty"
  [[ -t 0 && -t 1 ]] || recovery_die "${route} requires a visible local terminal; no host contact occurred"
  command -v ssh >/dev/null 2>&1 || recovery_die "ssh is required for ${route}"
  command -v scp >/dev/null 2>&1 || recovery_die "scp is required for ${route}"
  [[ -r "${REMOTE_ALPHA_ES_TLS_STATUS_COLLECTOR}" ]] || recovery_die "status collector is not readable"

  local run_id remote_stage_dir remote_collector stage_identity collector_digest remote_command preflight_command
  [[ -f "${REMOTE_ALPHA_ES_TLS_STATUS_COLLECTOR}" && ! -L "${REMOTE_ALPHA_ES_TLS_STATUS_COLLECTOR}" ]] || recovery_die "status collector source is not a regular file"
  collector_digest="$(/usr/bin/shasum -a 256 "${REMOTE_ALPHA_ES_TLS_STATUS_COLLECTOR}" | /usr/bin/cut -d ' ' -f 1)" || recovery_die "status collector digest derivation failed"
  [[ "${collector_digest}" =~ ^[0-9a-f]{64}$ ]] || recovery_die "status collector digest derivation failed"
  run_id="$(/usr/bin/uuidgen | /usr/bin/tr -d '-' | /usr/bin/tr '[:upper:]' '[:lower:]')"
  [[ "${run_id}" =~ ^[0-9a-f]{32}$ ]] || recovery_die "status stage identifier generation failed"
  remote_stage_dir="/tmp/.es-tls-status-${run_id}"
  remote_collector="${remote_stage_dir}/remote_alpha_es_tls_status.py"
  if [[ "${diagnostic}" == true ]]; then
    preflight_command="$(remote_alpha_es_tls_status_remote_wrapper "${remote_stage_dir}" "18446744073709551615:18446744073709551615" "${scope}" "${collector_digest}" grammar-diagnostic)" || recovery_die "${route} fixed remote command preflight failed; no host contact occurred"
  else
    preflight_command="$(remote_alpha_es_tls_status_remote_wrapper "${remote_stage_dir}" "18446744073709551615:18446744073709551615" "${scope}" "${collector_digest}")" || recovery_die "${route} fixed remote command preflight failed; no host contact occurred"
  fi
  unset preflight_command
  if [[ "${diagnostic}" == true ]]; then
    printf '%s\n' "${route}: staging one fixed diagnostic source; no protected P0t summary will be published."
  else
    printf '%s\n' "${route}: staging one dedicated status collector; scope=${scope}; protected summary remains remote."
  fi
  if ! stage_identity="$(ssh "${ssh_target}" /bin/bash -s -- "${remote_stage_dir}" <<'REMOTE_ALPHA_ES_TLS_STATUS_STAGE' | /usr/bin/python3 -I -B -c '
import re, sys
raw = sys.stdin.buffer.read(64)
match = re.fullmatch(rb"([1-9][0-9]{0,19}):([1-9][0-9]{0,19})\n", raw)
if match is None or any(int(part) > 18446744073709551615 for part in match.groups()):
    raise SystemExit(1)
sys.stdout.write(raw[:-1].decode("ascii"))
'
set -euo pipefail
stage_dir=$1
[[ "${stage_dir}" =~ ^/tmp/\.es-tls-status-[0-9a-f]{32}$ ]]
/usr/bin/python3 -I -B - "${stage_dir}" <<'REMOTE_ALPHA_ES_TLS_STATUS_CREATE'
import os
import re
import stat
import sys

stage = sys.argv[1]
if re.fullmatch(r"/tmp/\.es-tls-status-[0-9a-f]{32}", stage) is None:
    raise SystemExit(1)
name = os.path.basename(stage)
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
def check_access(fd):
    if any(attr not in ("security.selinux", "com.apple.provenance") for attr in os.listxattr(fd)):
        raise SystemExit(1)
def main():
    parent_fd = os.open("/tmp", flags)
    try:
        parent = os.fstat(parent_fd)
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_gid != 0 or
                stat.S_IMODE(parent.st_mode) != 0o1777):
            raise SystemExit(1)
        check_access(parent_fd)
        try:
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise SystemExit(1)
        prior_umask = os.umask(0)
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        finally:
            os.umask(prior_umask)
        directory_fd = os.open(name, flags, dir_fd=parent_fd)
        try:
            info = os.fstat(directory_fd)
            entry = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or
                    info.st_gid != os.getegid() or stat.S_IMODE(info.st_mode) != 0o700 or
                    info.st_nlink < 2 or (info.st_dev, info.st_ino) != (entry.st_dev, entry.st_ino) or
                    os.listdir(directory_fd) != []):
                raise SystemExit(1)
            check_access(directory_fd)
            if any(value <= 0 or value > 18446744073709551615 for value in (info.st_dev, info.st_ino)):
                raise SystemExit(1)
            print(f"{info.st_dev}:{info.st_ino}")
        finally:
            os.close(directory_fd)
    finally:
        os.close(parent_fd)
try:
    main()
except (OSError, ValueError):
    raise SystemExit(1)
REMOTE_ALPHA_ES_TLS_STATUS_CREATE
REMOTE_ALPHA_ES_TLS_STATUS_STAGE
)"; then
    if [[ "${diagnostic}" == true ]]; then
      recovery_es_tls_diagnostic_postcontact_die "${route}" "stage creation or custody acquisition failed; possible stage residue retained"
    else
      recovery_es_tls_status_postcontact_die "${route}" "stage creation or custody acquisition failed; possible diagnostic residue retained"
    fi
  fi
  if ! scp "${REMOTE_ALPHA_ES_TLS_STATUS_COLLECTOR}" "${ssh_target}:${remote_collector}"; then
    if [[ "${diagnostic}" == true ]]; then
      recovery_es_tls_diagnostic_postcontact_die "${route}" "upload failed; stage retained as diagnostic residue"
    else
      recovery_es_tls_status_postcontact_die "${route}" "upload failed; stage retained as diagnostic residue; no fresh status generation accepted"
    fi
  fi
  if [[ "${diagnostic}" == true ]]; then
    remote_command="$(remote_alpha_es_tls_status_remote_wrapper "${remote_stage_dir}" "${stage_identity}" "${scope}" "${collector_digest}" grammar-diagnostic)" || recovery_es_tls_diagnostic_postcontact_die "${route}" "fixed remote command construction failed; stage retained as diagnostic residue"
  else
    remote_command="$(remote_alpha_es_tls_status_remote_wrapper "${remote_stage_dir}" "${stage_identity}" "${scope}" "${collector_digest}")" || recovery_es_tls_status_postcontact_die "${route}" "fixed remote command construction failed; stage retained as diagnostic residue; no fresh status generation accepted"
  fi
  if ! ssh -tt "${ssh_target}" "${remote_command}"; then
    if [[ "${diagnostic}" == true ]]; then
      recovery_es_tls_diagnostic_postcontact_die "${route}" "interactive SSH failed"
    else
      recovery_es_tls_status_postcontact_die "${route}" "interactive SSH failed"
    fi
  fi
  if [[ "${diagnostic}" == true ]]; then
    printf '%s\n' "${route}: diagnostic invocation acknowledged; only a complete closed terminal line is usable, and no P0t status was published."
  else
    printf '%s\n' "${route}: collector published a completed observation; validate the fresh protected record for result.status."
  fi
}

recovery_session_es_service_tls() {
  recovery_session_es_tls_status es-service-tls-status artifact-registry "$@"
}

recovery_session_es_governance_tls() {
  recovery_session_es_tls_status es-governance-tls-status execution-governance "$@"
}

recovery_session_es_governance_tls_grammar_diagnostic() {
  recovery_session_es_tls_status es-governance-tls-grammar-diagnostic execution-governance "$@"
}

recovery_session_operator_healthcheck_tls_status_noninteractive_usage() {
  printf '%s\n' \
    "Remote Alpha recovery-session mode: operator-healthcheck-tls-status-noninteractive" \
    "P0v scope: implemented ES-owned read-only no-prompt operator healthcheck TLS status observation route." \
    "Bash parses/refuses route args, performs contact-free local prerequisite checks, constructs no JSON, performs no SSH/SCP/sudo/staging/cleanup/summary behavior, and execs the fixed local Python runtime." \
    "The local runtime owns SSH construction, bounded subprocess handling, internal protocol validation, final route JSON emission, and redaction." \
    "The fixed remote collector is streamed over SSH stdin, writes no remote file or summary, and emits only an internal protocol document." \
    "" \
    "Usage:" \
    "  remote_alpha_operator.sh recovery-session operator-healthcheck-tls-status-noninteractive --ssh-target <user@host> --format json" \
    "" \
    "Allowed flags:" \
    "  --help" \
    "  --ssh-target <target>" \
    "  --format json" \
    "" \
    "Topology rules: no local TTY requirement; no pseudo-TTY; no Bash SSH invocation; no scp; no helper staging; no remote summary; no renewal; no scheduling; the SSH target must be a single target, not an option or shell command." \
    "Forbidden in P0v: --interactive-tty, --execute-renew, --status, --check-only, --summary-path, --output, helper/path/command/SSH/privilege/runtime/collector/schema/timeout/limit overrides, arbitrary command strings, unknown flags, duplicate flags, positional args beyond the submode, secret-like flags, and equals-form options." \
    "Non-claims: evidence/projection only; not renewal, not signer/custody resolution, not ES runtime truth, not CP/IM/MA/Bridge/Coordinator authority, not production readiness, not operational acceptance, and not live proof."
}

recovery_session_p0v_die() {
  printf 'error: %s\n' "$*" >&2
  printf 'No recovery-session live helper or IM execution occurred.\n' >&2
  exit 2
}

require_recovery_session_p0v_option_value() {
  local option=$1
  local value_count=$2
  local value=${3:-}
  if [[ "${value_count}" -lt 2 || -z "${value}" || "${value}" == --* ]]; then
    recovery_session_p0v_die "${option} requires a value"
  fi
  case "${value}" in
    *$'\n'*|*$'\r'*)
      recovery_session_p0v_die "${option} value contains a newline"
      ;;
  esac
}

require_recovery_session_p0v_option_not_seen() {
  local option=$1
  local seen=$2
  if [[ "${seen}" == "true" ]]; then
    recovery_session_p0v_die "duplicate option for operator-healthcheck-tls-status-noninteractive: ${option}"
  fi
}

recovery_session_p0v_validate_ssh_target() {
  local ssh_target=$1
  case "${ssh_target}" in
    -*|*[[:space:]]*|*';'*|*'`'*|*'$('*|*'|'*|*'&'*|*'<'*|*'>'*)
      recovery_session_p0v_die "operator-healthcheck-tls-status-noninteractive --ssh-target must be a single SSH target, not an option or shell command"
      ;;
  esac
}

recovery_session_p0v_require_local_prerequisite() {
  command -v "$1" >/dev/null 2>&1 || recovery_session_p0v_die "operator-healthcheck-tls-status-noninteractive local prerequisite failed"
}

recovery_session_p0v_python3_path=""

recovery_session_p0v_resolve_python3() {
  local resolved
  resolved=$(command -v python3 2>/dev/null || true)
  if [[ -z "${resolved}" || "${resolved}" != /* || ! -x "${resolved}" ]]; then
    recovery_session_p0v_die "operator-healthcheck-tls-status-noninteractive local prerequisite failed"
  fi
  "${resolved}" -I -S -B -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1 || recovery_session_p0v_die "operator-healthcheck-tls-status-noninteractive local prerequisite failed"
  recovery_session_p0v_python3_path=${resolved}
}

recovery_session_p0v_require_fixed_ssh() {
  if [[ ! -x /usr/bin/ssh || ! -e /dev/null ]]; then
    recovery_session_p0v_die "operator-healthcheck-tls-status-noninteractive local prerequisite failed"
  fi
}

recovery_session_operator_healthcheck_tls_status_noninteractive() {
  local ssh_target_seen="false"
  local format_seen="false"
  local ssh_target=""
  local output_format=""

  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --help|-h)
        recovery_session_operator_healthcheck_tls_status_noninteractive_usage
        return 0
        ;;
      --ssh-target)
        require_recovery_session_p0v_option_not_seen "$1" "${ssh_target_seen}"
        require_recovery_session_p0v_option_value "$1" "$#" "${2:-}"
        ssh_target_seen="true"
        ssh_target=$2
        shift 2
        ;;
      --format)
        require_recovery_session_p0v_option_not_seen "$1" "${format_seen}"
        require_recovery_session_p0v_option_value "$1" "$#" "${2:-}"
        if [[ "$2" != "json" ]]; then
          recovery_session_p0v_die "operator-healthcheck-tls-status-noninteractive requires --format json"
        fi
        format_seen="true"
        output_format=$2
        shift 2
        ;;
      --interactive-tty|--interactive-tty=*|--execute-renew|--execute-renew=*|--status|--status=*|--check-only|--check-only=*|--summary-path|--summary-path=*|--output|--output=*)
        recovery_session_p0v_die "operator-healthcheck-tls-status-noninteractive forbids interactive, renewal, status-helper, summary, and output override flags"
        ;;
      --host-local|--host-local=*|--dry-run|--dry-run=*|--scope|--scope=*|--apply|--apply=*|--execute-reset|--execute-reset=*|--unseal-only|--unseal-only=*|--post-unseal-check|--post-unseal-check=*|--execute-bootstrap|--execute-bootstrap=*|--prepare-summary-path|--prepare-summary-path=*|--prepare-config-readability|--prepare-config-readability=*|--prepare-spire-bundle-read|--prepare-spire-bundle-read=*|--interactive-sudo|--interactive-sudo=*|--governed-smoke-command|--governed-smoke-command=*)
        recovery_session_p0v_die "operator-healthcheck-tls-status-noninteractive forbids unrelated recovery-mode flags"
        ;;
      --runtime|--runtime=*|--runtime-path|--runtime-path=*|--collector|--collector=*|--collector-path|--collector-path=*|--helper|--helper=*|--helper-path|--helper-path=*|--ssh-option|--ssh-option=*|--ssh-command|--ssh-command=*|--remote-command|--remote-command=*|--privilege-command|--privilege-command=*|--sudo-command|--sudo-command=*|--schema|--schema=*|--timeout|--timeout=*|--limit|--limit=*|--operator-cert-path|--operator-cert-path=*|--operator-key-path|--operator-key-path=*|--ca-path|--ca-path=*|--cert-path|--cert-path=*|--key-path|--key-path=*|--signing-ca-path|--signing-ca-path=*)
        recovery_session_p0v_die "operator-healthcheck-tls-status-noninteractive forbids helper, path, command, SSH, privilege, runtime, collector, schema, timeout, and limit overrides"
        ;;
      --*=*)
        recovery_session_p0v_die "operator-healthcheck-tls-status-noninteractive does not accept equals-form options"
        ;;
      --*)
        recovery_session_p0v_die "unknown option for operator-healthcheck-tls-status-noninteractive"
        ;;
      *)
        recovery_session_p0v_die "unexpected positional argument for operator-healthcheck-tls-status-noninteractive"
        ;;
    esac
  done

  if [[ "${ssh_target_seen}" != "true" ]]; then
    recovery_session_p0v_die "operator-healthcheck-tls-status-noninteractive requires --ssh-target <target>"
  fi
  if [[ "${format_seen}" != "true" || "${output_format}" != "json" ]]; then
    recovery_session_p0v_die "operator-healthcheck-tls-status-noninteractive requires --format json"
  fi

  recovery_session_p0v_validate_ssh_target "${ssh_target}"
  recovery_session_p0v_resolve_python3
  recovery_session_p0v_require_fixed_ssh
  initialize_operator_paths
  if [[ ! -r "${REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_STATUS_NONINTERACTIVE_RUNTIME}" ]]; then
    recovery_session_p0v_die "operator-healthcheck-tls-status-noninteractive local prerequisite failed"
  fi
  if [[ ! -r "${REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_STATUS_NONINTERACTIVE_REMOTE_COLLECTOR}" ]]; then
    recovery_session_p0v_die "operator-healthcheck-tls-status-noninteractive local prerequisite failed"
  fi

  exec "${recovery_session_p0v_python3_path}" -I -S -B "${REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_STATUS_NONINTERACTIVE_RUNTIME}" \
    --ssh-target "${ssh_target}" \
    --format json
}

recovery_session_operator_healthcheck_tls_usage() {
  printf '%s\n' \
    "Remote Alpha recovery-session mode: operator-healthcheck-tls-status/operator-healthcheck-tls-renew" \
    "P0u scope: bounded Mac-side Remote Alpha host-local operator healthcheck client TLS status and renewal route." \
    "Mac-side mode stages only scripts/remote_alpha_operator_healthcheck_tls_renew.sh and scripts/internal/remote_alpha_operator_healthcheck_tls_renew.sh to the remote host." \
    "The remote command invokes only --status or --execute-renew through ssh -tt and uses the explicit interactive TTY path for OS sudo when required." \
    "No transcript, tee/script capture, .out, report, support bundle, operator summary, IM refresh, CP proof, Vault, SPIRE, Nomad, reset/unseal, workload-auth bootstrap/check, runtime identity summary, ES service restart, or general deployment/provisioning/reconciliation is created or run by the facade." \
    "Canonical remote summary: /var/tmp/execution-substrate-remote-alpha/operator-healthcheck-tls-renew-summary.json" \
    "Summary is evidence/projection only, not readiness authority." \
    "" \
    "Secret posture:" \
    "  The route does not accept, parse, print, copy, log, relay, persist, summarize, or handle private keys, certificate PEM bodies, Vault tokens, root tokens, unseal keys, API keys, JWT-SVIDs, passwords, proof secrets, or secret payloads." \
    "  It relies only on the helper's public certificate metadata, key-public-digest matching, current file policy metadata, verification/probe summaries, unsupported-signing-topology classification, and not-run backup/install/probe metadata." \
    "  It does not print full summary JSON and does not copy the summary back to Mac .out." \
    "" \
    "Usage:" \
    "  remote_alpha_operator.sh recovery-session operator-healthcheck-tls-status --ssh-target <user@host> --interactive-tty" \
    "  remote_alpha_operator.sh recovery-session operator-healthcheck-tls-renew --ssh-target <user@host> --interactive-tty --execute-renew" \
    "" \
    "Allowed flags:" \
    "  --help" \
    "  --ssh-target <target>" \
    "  --interactive-tty" \
    "  --execute-renew (only with operator-healthcheck-tls-renew)" \
    "" \
    "Topology rules: Mac-side only; --ssh-target is required; --interactive-tty is required; --execute-renew is required for operator-healthcheck-tls-renew and forbidden for operator-healthcheck-tls-status; --host-local is not accepted; the SSH target must be a single target, not an option or shell command." \
    "Forbidden in P0u: --host-local, --dry-run, --check-only, --status, --scope, --apply, --execute-reset, --unseal-only, --post-unseal-check, --execute-bootstrap, --prepare-summary-path, --prepare-config-readability, --prepare-spire-bundle-read, --interactive-sudo, --governed-smoke-command, helper override flags, output/summary path overrides, TLS path overrides, arbitrary command strings, unknown flags, duplicate flags, positional args beyond the submode, secret-like flags, and equals-form options." \
    "Non-claims: not generic TLS deployment, not IM reconciliation, not CP proof, not Vault/SPIRE/Nomad changes, not workload-auth bootstrap/check, not runtime identity evidence, not ES service TLS renewal, not ES restart, not production readiness, and not Remote Alpha deployment/provisioning/reconciliation architecture."
}

recovery_session_operator_healthcheck_tls_stage_remote() {
  local ssh_target=$1
  local remote_stage_dir=$2
  local remote_public_helper_path=$3
  local remote_internal_helper_path=$4

  ssh "${ssh_target}" /bin/bash -s -- "${remote_stage_dir}" <<'REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_PREPARE'
set -euo pipefail
stage_dir=$1
# A new folder directly under /tmp, made with mkdir and no -p: a folder or
# link someone planted at this name makes staging fail, and nobody but this
# user (and root) can change what is staged in it.
mkdir -m 0700 -- "${stage_dir}"
mkdir -m 0700 -- "${stage_dir}/scripts" "${stage_dir}/scripts/internal"
REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_PREPARE

  scp "${REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_RENEW_PUBLIC_HELPER}" "${ssh_target}:${remote_public_helper_path}"
  scp "${REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_RENEW_INTERNAL_HELPER}" "${ssh_target}:${remote_internal_helper_path}"
}

recovery_session_operator_healthcheck_tls_run_remote() {
  local ssh_target=$1
  local remote_stage_dir=$2
  local remote_public_helper_path=$3
  local remote_internal_helper_path=$4
  local helper_mode=$5
  local remote_command remote_shell_command

  case "${helper_mode}" in
    --status|--execute-renew)
      ;;
    *)
      recovery_die "internal error: unsupported operator-healthcheck-tls helper mode ${helper_mode}"
      ;;
  esac

  printf -v remote_command 'set -euo pipefail; stage_dir=%q; helper_path=%q; internal_helper_path=%q; cleanup() { rm -rf -- "${stage_dir}" || true; }; trap cleanup EXIT; chmod 0700 "${helper_path}"; chmod 0600 "${internal_helper_path}" 2>/dev/null || true; if [[ "$(id -u)" == "0" ]]; then "${helper_path}" %q; else sudo "${helper_path}" %q; fi' "${remote_stage_dir}" "${remote_public_helper_path}" "${remote_internal_helper_path}" "${helper_mode}" "${helper_mode}"
  printf -v remote_shell_command 'exec /bin/bash -c %q' "${remote_command}"
  ssh -tt "${ssh_target}" "${remote_shell_command}"
}

recovery_session_operator_healthcheck_tls_print_success_next_steps() {
  local helper_mode=$1
  if [[ "${helper_mode}" == "--execute-renew" ]]; then
    printf '%s\n' \
      "Mac-side operator-healthcheck-tls-renew route finished; staged helper cleanup was attempted." \
      "Canonical remote summary path: ${REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_RENEW_REMOTE_SUMMARY}" \
      "The summary remains on the remote host; this route did not copy it back to Mac .out and did not print full summary JSON." \
      "The helper currently fails closed before backup/install with unsupported_signing_topology until a documented CA custody/signing design exists; it did not restart ES." \
      "Separate IM refresh/support-bundle and CP proof actions were not run."
  else
    printf '%s\n' \
      "Mac-side operator-healthcheck-tls-status route finished; staged helper cleanup was attempted." \
      "Canonical remote summary path: ${REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_RENEW_REMOTE_SUMMARY}" \
      "The summary remains on the remote host; this route did not copy it back to Mac .out and did not print full summary JSON." \
      "Status mode is non-mutating and does not restart services." \
      "Renew, IM refresh/support-bundle, and CP proof actions were not run."
  fi
}

recovery_session_operator_healthcheck_tls_remote() {
  local ssh_target=$1
  local helper_mode=$2
  local run_id remote_stage_dir remote_public_helper_path remote_internal_helper_path remote_status cleanup_status

  recovery_session_es_service_tls_require_local_tty
  recovery_session_es_service_tls_require_command ssh
  recovery_session_es_service_tls_require_command scp

  run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
  remote_stage_dir="${REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_RENEW_STAGE_ROOT}-${run_id}"
  remote_public_helper_path="${remote_stage_dir}/scripts/remote_alpha_operator_healthcheck_tls_renew.sh"
  remote_internal_helper_path="${remote_stage_dir}/scripts/internal/remote_alpha_operator_healthcheck_tls_renew.sh"

  if [[ "${helper_mode}" == "--execute-renew" ]]; then
    printf '%s\n' \
      "Running Mac-side operator healthcheck TLS renewal through an explicit interactive SSH TTY." \
      "Staging only scripts/remote_alpha_operator_healthcheck_tls_renew.sh and scripts/internal/remote_alpha_operator_healthcheck_tls_renew.sh." \
      "Invoking only the staged public helper with --execute-renew; no helper override flags are accepted or passed." \
      "The helper is bounded to /etc/execution-substrate/tls/operator-client-cert.pem and /etc/execution-substrate/tls/operator-client-key.pem and may request only OS sudo through the visible remote terminal." \
      "Renewal currently fails closed before backup/install with unsupported_signing_topology until a documented CA custody/signing design exists; any future renewed certificate must use URI spiffe://execution.internal/operator/local and must not restart ES unless a later documented path proves it necessary." \
      "Canonical summary stays remote at ${REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_RENEW_REMOTE_SUMMARY}." \
      "No transcript, tee/script capture, .out, report, support bundle, operator summary, generated Mac artifact, reset/unseal, workload-auth bootstrap/check, runtime identity summary, IM refresh, Vault/SPIRE/Nomad change, ES token brokerage, or CP proof is created or run." \
      "The operator facade will not read, log, relay, persist, summarize, copy, or print private keys, PEM bodies, Vault tokens, JWT-SVIDs, API keys, passwords, or secret payloads."
  else
    printf '%s\n' \
      "Running Mac-side operator healthcheck TLS status through an explicit interactive SSH TTY." \
      "Staging only scripts/remote_alpha_operator_healthcheck_tls_renew.sh and scripts/internal/remote_alpha_operator_healthcheck_tls_renew.sh." \
      "Invoking only the staged public helper with --status; no helper override flags are accepted or passed." \
      "Status mode is non-mutating and bounded to host-local operator healthcheck client TLS evidence." \
      "Canonical summary stays remote at ${REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_RENEW_REMOTE_SUMMARY}." \
      "No transcript, tee/script capture, .out, report, support bundle, operator summary, generated Mac artifact, renew, service restart, reset/unseal, workload-auth bootstrap/check, runtime identity summary, IM refresh, Vault/SPIRE/Nomad change, ES token brokerage, or CP proof is created or run."
  fi

  if ! recovery_session_operator_healthcheck_tls_stage_remote "${ssh_target}" "${remote_stage_dir}" "${remote_public_helper_path}" "${remote_internal_helper_path}"; then
    recovery_session_es_service_tls_cleanup_remote "${ssh_target}" "${remote_stage_dir}" || true
    return 1
  fi

  set +e
  recovery_session_operator_healthcheck_tls_run_remote "${ssh_target}" "${remote_stage_dir}" "${remote_public_helper_path}" "${remote_internal_helper_path}" "${helper_mode}"
  remote_status=$?
  set -e

  set +e
  recovery_session_es_service_tls_cleanup_remote "${ssh_target}" "${remote_stage_dir}"
  cleanup_status=$?
  set -e
  if [[ "${cleanup_status}" -ne 0 ]]; then
    printf '%s\n' "warning: Mac-side operator-healthcheck-tls route could not verify remote staged helper cleanup; inspect the route-specific scratch path manually from a visible terminal." >&2
  fi

  if [[ "${remote_status}" -eq 0 ]]; then
    recovery_session_operator_healthcheck_tls_print_success_next_steps "${helper_mode}"
  else
    printf '%s\n' "Mac-side operator-healthcheck-tls route failed; staged helper cleanup was attempted." >&2
  fi

  if [[ "${remote_status}" -eq 0 && "${cleanup_status}" -ne 0 ]]; then
    return "${cleanup_status}"
  fi
  return "${remote_status}"
}

recovery_session_operator_healthcheck_tls() {
  local route_kind=$1
  shift
  local ssh_target_seen="false"
  local interactive_tty_seen="false"
  local execute_renew_seen="false"
  local ssh_target=""
  local helper_mode

  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --help|-h)
        recovery_session_operator_healthcheck_tls_usage
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
      --execute-renew)
        require_recovery_option_not_seen "$1" "${execute_renew_seen}"
        execute_renew_seen="true"
        shift
        ;;
      --host-local|--host-local=*|--dry-run|--dry-run=*|--check-only|--check-only=*|--status|--status=*|--scope|--scope=*|--apply|--apply=*|--execute-reset|--execute-reset=*|--unseal-only|--unseal-only=*|--post-unseal-check|--post-unseal-check=*|--execute-bootstrap|--execute-bootstrap=*|--prepare-summary-path|--prepare-summary-path=*|--prepare-config-readability|--prepare-config-readability=*|--prepare-spire-bundle-read|--prepare-spire-bundle-read=*|--interactive-sudo|--interactive-sudo=*|--governed-smoke-command|--governed-smoke-command=*)
        recovery_die "recovery-session operator-healthcheck-tls forbids $1; P0u is a separate bounded host-local operator healthcheck client TLS status/renew route and does not combine reset, unseal, workload-auth, runtime identity, IM, support bundles, Vault/SPIRE/Nomad changes, generic TLS deployment, ES service TLS renewal, or CP proof"
        ;;
      --summary-path|--summary-path=*|--output|--output=*|--es-config-path|--es-config-path=*|--healthcheck-env-path|--healthcheck-env-path=*|--operator-cert-path|--operator-cert-path=*|--operator-key-path|--operator-key-path=*|--ca-path|--ca-path=*|--cert-path|--cert-path=*|--key-path|--key-path=*|--signing-ca-path|--signing-ca-path=*)
        recovery_die "recovery-session operator-healthcheck-tls forbids helper override flag $1; P0u uses fixed documented operator healthcheck TLS paths and the canonical remote summary path"
        ;;
      --*=*)
        recovery_die "recovery-session operator-healthcheck-tls does not accept equals-form options: $1"
        ;;
      --*)
        recovery_die "unknown option for recovery-session operator-healthcheck-tls: $1"
        ;;
      *)
        recovery_die "unexpected positional argument for recovery-session operator-healthcheck-tls: $1"
        ;;
    esac
  done

  if [[ "${ssh_target_seen}" != "true" ]]; then
    recovery_die "recovery-session operator-healthcheck-tls requires --ssh-target <target>"
  fi
  if [[ "${interactive_tty_seen}" != "true" ]]; then
    recovery_die "recovery-session operator-healthcheck-tls requires --interactive-tty"
  fi
  if [[ "${route_kind}" == "renew" && "${execute_renew_seen}" != "true" ]]; then
    recovery_die "recovery-session operator-healthcheck-tls-renew requires --execute-renew"
  fi
  if [[ "${route_kind}" == "status" && "${execute_renew_seen}" == "true" ]]; then
    recovery_die "recovery-session operator-healthcheck-tls-status forbids --execute-renew"
  fi
  recovery_session_es_service_tls_validate_ssh_target "${ssh_target}"

  initialize_operator_paths
  if [[ ! -x "${REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_RENEW_PUBLIC_HELPER}" ]]; then
    recovery_die "operator healthcheck TLS public helper is unavailable"
  fi
  if [[ ! -r "${REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_RENEW_INTERNAL_HELPER}" ]]; then
    recovery_die "operator healthcheck TLS internal helper is unavailable"
  fi

  if [[ "${route_kind}" == "renew" ]]; then
    helper_mode="--execute-renew"
  else
    helper_mode="--status"
  fi
  recovery_session_operator_healthcheck_tls_remote "${ssh_target}" "${helper_mode}"
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

  if [[ "${#facade_options_seen[@]}" -gt 0 ]]; then
    recovery_die "recovery-session does not accept top-level printed-command options before the subcommand"
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
  if [[ "$#" -gt 0 && "$1" == "vault-workload-auth-bootstrap" ]]; then
    shift
    recovery_session_vault_workload_auth_bootstrap "$@"
    return 0
  fi
  if [[ "$#" -gt 0 && "$1" == "es-service-tls-status" ]]; then
    shift
    recovery_session_es_service_tls "$@"
    return 0
  fi
  if [[ "$#" -gt 0 && "$1" == "es-service-tls-renew" ]]; then
    shift
    recovery_die "es-service-tls-renew is held pending a separately designed contract; no host contact occurred"
    return 0
  fi
  if [[ "$#" -gt 0 && "$1" == "es-governance-tls-status" ]]; then
    shift
    recovery_session_es_governance_tls "$@"
    return 0
  fi
  if [[ "$#" -gt 0 && "$1" == "es-governance-tls-grammar-diagnostic" ]]; then
    shift
    recovery_session_es_governance_tls_grammar_diagnostic "$@"
    return 0
  fi
  if [[ "$#" -gt 0 && "$1" == "es-governance-tls-renew" ]]; then
    shift
    recovery_die "es-governance-tls-renew is held pending a separately designed contract; no host contact occurred"
    return 0
  fi
  if [[ "$#" -gt 0 && "$1" == "operator-healthcheck-tls-status-noninteractive" ]]; then
    shift
    recovery_session_operator_healthcheck_tls_status_noninteractive "$@"
    return 0
  fi
  if [[ "$#" -gt 0 && "$1" == "operator-healthcheck-tls-status" ]]; then
    shift
    recovery_session_operator_healthcheck_tls "status" "$@"
    return 0
  fi
  if [[ "$#" -gt 0 && "$1" == "operator-healthcheck-tls-renew" ]]; then
    shift
    recovery_session_operator_healthcheck_tls "renew" "$@"
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
      --readiness-summary|--readiness-summary=*|--staging-record|--staging-record=*)
        refuse_retired_historical_evidence_option
        ;;
      --ssh-target|--ssh-target=*|--interactive-sudo|--interactive-sudo=*|--apply|--apply=*|--dry-run|--dry-run=*|--execute-reset|--execute-reset=*|--execute-renew|--execute-renew=*|--unseal-only|--unseal-only=*|--post-unseal-check|--post-unseal-check=*|--governed-smoke-command|--governed-smoke-command=*)
        recovery_die "recovery-session received an option reserved for an explicit submode"
        ;;
      --*=*)
        recovery_die "recovery-session does not accept equals-form options"
        ;;
      --*)
        recovery_die "recovery-session received an unknown option"
        ;;
      *)
        recovery_die "recovery-session received an unexpected positional argument"
        ;;
    esac
  done

  if [[ -z "${mode}" ]]; then
    mode="plan"
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
  printf '%s\n' 'error: this subcommand category is unavailable as a top-level operator route' >&2
  printf 'No helper execution routing occurred.\n' >&2
  exit 2
}

refuse_bootstrap() {
  printf 'error: top-level vault-workload-auth-bootstrap execution is blocked/reopened; use recovery-session vault-workload-auth-bootstrap --plan or the explicit P0q recovery-session execution route.\n' >&2
  printf 'No helper execution routing occurred.\n' >&2
  exit 2
}

retired_es_existing_host_route() {
  printf '%s\n' 'remote alpha existing-host ES writable-state and service-user migration routes are retired; no host inspection, staging, mutation, or evidence production occurred' >&2
  printf '%s\n' 'provision a fresh host through a separately selected setup contract, or select a separately governed existing-host migration contract' >&2
  return 2
}

route_es_writable_state_readiness_check() {
  retired_es_existing_host_route
}

readiness_session() {
  retired_es_existing_host_route
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
        die "unknown facade option"
        ;;
      *)
        die "unexpected facade argument"
        ;;
    esac
  done
}

parse_args() {
  reject_secret_args "$@"
  reject_retired_operator_evidence_args "$@"

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
        die "unknown facade option"
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
    vault-reset-disposable|vault-unseal|vault-unseal-existing|runtime-security-check)
      refuse_not_implemented "${subcommand}"
      ;;
    es-*)
      refuse_not_implemented "${subcommand}"
      ;;
    *)
      printf '%s\n' 'error: unknown operator subcommand' >&2
      printf 'No helper execution routing occurred.\n' >&2
      exit 2
      ;;
  esac
}

main "$@"
