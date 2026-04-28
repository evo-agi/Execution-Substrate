#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="${BASH_SOURCE[0]%/*}"
SCRIPT_DIR="$(cd "${SCRIPT_DIR}" && pwd)"
# shellcheck source=scripts/internal/remote_alpha_runtime_security_boundary_check.sh
source "${SCRIPT_DIR}/internal/remote_alpha_runtime_security_boundary_check.sh"

remote_alpha_runtime_security_boundary_main "$@"
