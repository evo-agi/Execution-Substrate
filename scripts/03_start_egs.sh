#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${EGS_CONFIG:-}" ]]; then
  echo "EGS_CONFIG is required" >&2
  exit 1
fi
if [[ ! -r "${EGS_CONFIG}" ]]; then
  echo "EGS_CONFIG must point to a readable file: ${EGS_CONFIG}" >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

printf '+ cd %q && ' "${REPO_ROOT}"
printf '%q ' go run ./cmd/egs -config "${EGS_CONFIG}"
printf '\n'

cd "${REPO_ROOT}"
exec go run ./cmd/egs -config "${EGS_CONFIG}"
