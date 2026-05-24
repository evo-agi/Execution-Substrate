#!/usr/bin/env bash
set -euo pipefail
set +x

DEFAULT_PROFILE_DIR=".out/remote-alpha-m75q"
DEFAULT_OUTPUT_ROOT=".out/remote-alpha-m75q/support-bundles"
DEFAULT_SSH_ALIAS="host_to_remote_linux_m75q"
IM_REPO="/Users/ds/Repositories/Infrastructure Manager"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REMOTE_ALPHA_ES_WRITABLE_STATE_READINESS_HELPER="${SCRIPT_DIR}/remote_alpha_stage_es_writable_state_readiness_check.sh"

profile_dir="${DEFAULT_PROFILE_DIR}"
output_root="${DEFAULT_OUTPUT_ROOT}"
ssh_alias="${DEFAULT_SSH_ALIAS}"
subcommand=""
declare -a subcommand_args=()

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
    "P0d implements one check-only staged-helper route plus inert print-command helpers." \
    "Classification: bounded proof/support helper; evidence/projection only; no authority source." \
    "" \
    "Usage:" \
    "  remote_alpha_operator.sh help" \
    "  remote_alpha_operator.sh inventory" \
    "  remote_alpha_operator.sh print-refresh-command [options]" \
    "  remote_alpha_operator.sh print-support-bundle-command [options]" \
    "  remote_alpha_operator.sh print-im-commands [options]" \
    "  remote_alpha_operator.sh es-writable-state-readiness-check --ssh-target <user@host> [options]" \
    "" \
    "Options for printed command text only:" \
    "  --profile-dir .out/remote-alpha-m75q" \
    "  --output-root .out/remote-alpha-m75q/support-bundles" \
    "  --ssh-alias host_to_remote_linux_m75q" \
    "  --help, -h" \
    "" \
    "Implemented P0d route:" \
    "  es-writable-state-readiness-check - delegates only to scripts/remote_alpha_stage_es_writable_state_readiness_check.sh; check-only/non-mutating; requires --ssh-target; preserves es-writable-state-readiness.json and es-writable-state-readiness-helper-staging-record.json." \
    "" \
    "The operator facade does not invoke IM refresh or support-bundle collection and does not add reset/unseal, Vault workload-auth, runtime identity, service-user, config/TLS, binary deployment, writable-state ownership, or generic staging routes." \
    "Secret material must never be passed by CLI args/env/logs/reports/artifacts."
}

inventory() {
  printf '%s\n' \
    "Remote Alpha operator inventory" \
    "classification: bounded proof/support helper; evidence/projection only; no authority source" \
    "" \
    "implemented in P0d:" \
    "  help - show bounded facade scope and options" \
    "  inventory - show this static non-secret inventory" \
    "  print-refresh-command - print Mac-side IM live-refresh command text only" \
    "  print-support-bundle-command - print Mac-side IM support-bundle command text only" \
    "  print-im-commands - print both Mac-side IM command texts only" \
    "  es-writable-state-readiness-check - delegates to existing readiness staged helper; check-only/non-mutating; preserves es-writable-state-readiness.json and es-writable-state-readiness-helper-staging-record.json" \
    "" \
    "future/not implemented:" \
    "  Vault reset/unseal - not implemented in P0d; requires later audited slice" \
    "  workload-auth check - not implemented in P0d; requires later audited slice" \
    "  runtime identity summary - not implemented in P0d; requires later audited slice" \
    "  Vault service-user check - not implemented in P0d; requires later audited slice" \
    "  runtime security check - not implemented in P0d; requires later audited slice" \
    "  other staged ES helper delegation - not implemented in P0d; requires later audited slice" \
    "" \
    "blocked/reopened:" \
    "  vault-workload-auth-bootstrap - blocked/reopened and not available in v1" \
    "" \
    "non-claims:" \
    "  not production, not HA, not multi-tenant, not a general deployment architecture" \
    "  not IM automation or reconciliation, not CP authority, not ES Vault token brokerage" \
    "  no operator-owned summary, support bundle, report, or generated artifact is written"
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
  printf 'error: subcommand %q is not implemented in P0d and requires a later audited slice.\n' "${name}" >&2
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

parse_facade_option_args() {
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --help|-h)
        shift
        ;;
      --profile-dir)
        require_option_value "$1" "$#"
        profile_dir=$2
        shift 2
        ;;
      --profile-dir=*)
        profile_dir=${1#--profile-dir=}
        shift
        ;;
      --output-root)
        require_option_value "$1" "$#"
        output_root=$2
        shift 2
        ;;
      --output-root=*)
        output_root=${1#--output-root=}
        shift
        ;;
      --ssh-alias)
        require_option_value "$1" "$#"
        ssh_alias=$2
        shift 2
        ;;
      --ssh-alias=*)
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
        profile_dir=$2
        shift 2
        ;;
      --profile-dir=*)
        profile_dir=${1#--profile-dir=}
        shift
        ;;
      --output-root)
        require_option_value "$1" "$#"
        output_root=$2
        shift 2
        ;;
      --output-root=*)
        output_root=${1#--output-root=}
        shift
        ;;
      --ssh-alias)
        require_option_value "$1" "$#"
        ssh_alias=$2
        shift 2
        ;;
      --ssh-alias=*)
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
      printf 'error: unknown subcommand %q is not implemented in P0d and requires a later audited slice.\n' "${subcommand}" >&2
      printf 'No helper execution routing occurred.\n' >&2
      exit 2
      ;;
  esac
}

main "$@"
