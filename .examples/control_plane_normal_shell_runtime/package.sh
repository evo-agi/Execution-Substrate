#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="${SCRIPT_DIR}/dist"
OUTPUT="${DIST_DIR}/control_plane_normal_shell_runtime.tar.gz"

mkdir -p "${DIST_DIR}"

printf '+ tar -C %q -czf %q %q\n' "${SCRIPT_DIR}" "${OUTPUT}" "entrypoint"
tar -C "${SCRIPT_DIR}" -czf "${OUTPUT}" entrypoint

printf 'Wrote %s\n' "${OUTPUT}"
