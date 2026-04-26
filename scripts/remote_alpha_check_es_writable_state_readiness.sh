#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/internal/remote_alpha_check_es_writable_state_readiness.sh
source "${SCRIPT_DIR}/internal/remote_alpha_check_es_writable_state_readiness.sh"

remote_alpha_check_es_writable_state_readiness_main "$@"
