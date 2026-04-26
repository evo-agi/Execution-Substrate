#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/internal/remote_alpha_stage_es_config_tls_prep.sh
source "${SCRIPT_DIR}/internal/remote_alpha_stage_es_config_tls_prep.sh"

remote_alpha_stage_es_config_tls_prep_main "$@"
