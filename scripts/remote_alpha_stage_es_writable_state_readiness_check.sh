#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/internal/remote_alpha_stage_es_writable_state_readiness_check.sh
source "${SCRIPT_DIR}/internal/remote_alpha_stage_es_writable_state_readiness_check.sh"

remote_alpha_stage_es_writable_state_readiness_check_main "$@"
