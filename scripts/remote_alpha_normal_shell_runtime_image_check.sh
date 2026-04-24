#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

source "${REPO_ROOT}/scripts/internal/remote_alpha_normal_shell_runtime_image_check.sh"

remote_alpha_runtime_image_require_root
remote_alpha_runtime_image_check_main "$@"
