#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/internal/remote_alpha_harden_ags_service.sh
source "${SCRIPT_DIR}/internal/remote_alpha_harden_ags_service.sh"

remote_alpha_ags_hardening_require_root
remote_alpha_ags_hardening_main "$@"
