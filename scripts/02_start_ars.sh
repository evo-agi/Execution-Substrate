#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${ARS_CONFIG:-}" ]]; then
  echo "ARS_CONFIG is required" >&2
  exit 1
fi
if [[ ! -r "${ARS_CONFIG}" ]]; then
  echo "ARS_CONFIG must point to a readable file: ${ARS_CONFIG}" >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

printf '+ cd %q && ' "${REPO_ROOT}"
printf '%q ' go run ./cmd/ars -config "${ARS_CONFIG}"
printf '\n'

cd "${REPO_ROOT}"
exec go run ./cmd/ars -config "${ARS_CONFIG}"
