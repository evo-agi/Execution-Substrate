#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="${SCRIPT_DIR}/dist"

mkdir -p "${DIST_DIR}"

printf '+ tar -C %q -czf %q %q\n' "${SCRIPT_DIR}" "${DIST_DIR}/runtime_identity_reference.tar.gz" "entrypoint"
tar -C "${SCRIPT_DIR}" -czf "${DIST_DIR}/runtime_identity_reference.tar.gz" entrypoint

printf 'Wrote %s\n' "${DIST_DIR}/runtime_identity_reference.tar.gz"
