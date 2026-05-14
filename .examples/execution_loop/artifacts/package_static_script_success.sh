#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
OUTPUT="${SCRIPT_DIR}/static-script-success.tar.gz"
SOURCE="${SCRIPT_DIR}/static-script-success-entrypoint.sh"

python3 "${REPO_ROOT}/scripts/package_example_archive.py" "${SOURCE}" "${OUTPUT}" "entrypoint"
