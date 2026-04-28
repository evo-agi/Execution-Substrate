#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/internal/remote_alpha_plan_old_root_cleanup.sh
source "${SCRIPT_DIR}/internal/remote_alpha_plan_old_root_cleanup.sh"

remote_alpha_plan_old_root_cleanup_main "$@"
