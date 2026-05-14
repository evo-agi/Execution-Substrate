#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DIST_DIR="${SCRIPT_DIR}/dist"
OUTPUT="${DIST_DIR}/runtime_identity_reference.tar.gz"

mkdir -p "${DIST_DIR}"

python3 "${REPO_ROOT}/scripts/package_example_archive.py" "${SCRIPT_DIR}/entrypoint" "${OUTPUT}" "entrypoint"
