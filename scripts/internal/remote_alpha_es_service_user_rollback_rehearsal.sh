#!/usr/bin/env bash
set -euo pipefail

remote_alpha_es_service_user_rollback_rehearsal_main() {
  printf '%s\n' 'remote alpha existing-host ES writable-state and service-user migration routes are retired; no host inspection, staging, mutation, or evidence production occurred' >&2
  printf '%s\n' 'provision a fresh host through a separately selected setup contract, or select a separately governed existing-host migration contract' >&2
  return 2
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  remote_alpha_es_service_user_rollback_rehearsal_main "$@"
fi
