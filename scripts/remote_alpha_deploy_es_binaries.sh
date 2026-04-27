#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/internal/remote_alpha_deploy_es_binaries.sh
source "${SCRIPT_DIR}/internal/remote_alpha_deploy_es_binaries.sh"

remote_alpha_deploy_es_binaries_main "$@"
