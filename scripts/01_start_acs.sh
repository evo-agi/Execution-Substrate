#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${ACS_CONFIG:-}" ]]; then
  echo "ACS_CONFIG is required" >&2
  exit 1
fi
if [[ ! -r "${ACS_CONFIG}" ]]; then
  echo "ACS_CONFIG must point to a readable file: ${ACS_CONFIG}" >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

printf '+ cd %q && ' "${REPO_ROOT}"
printf '%q ' go run ./cmd/acs -config "${ACS_CONFIG}"
printf '\n'

cd "${REPO_ROOT}"
exec go run ./cmd/acs -config "${ACS_CONFIG}"
