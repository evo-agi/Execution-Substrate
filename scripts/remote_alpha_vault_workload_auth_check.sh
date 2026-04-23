#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

source "${REPO_ROOT}/scripts/internal/remote_alpha_vault_workload_auth_check.sh"

remote_alpha_vault_require_root
remote_alpha_vault_workload_auth_check_main "$@"
