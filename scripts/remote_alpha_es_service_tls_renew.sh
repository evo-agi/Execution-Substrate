#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/internal/remote_alpha_es_service_tls_renew.sh
source "${SCRIPT_DIR}/internal/remote_alpha_es_service_tls_renew.sh"

remote_alpha_es_service_tls_renew_main "$@"
