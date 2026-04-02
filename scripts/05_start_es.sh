#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${ES_CONFIG:-}" ]]; then
  echo "ES_CONFIG is required" >&2
  exit 1
fi
if [[ ! -r "${ES_CONFIG}" ]]; then
  echo "ES_CONFIG must point to a readable file: ${ES_CONFIG}" >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

printf '+ cd %q && ' "${REPO_ROOT}"
printf '%q ' go run ./cmd/es -config "${ES_CONFIG}"
printf '\n'

cd "${REPO_ROOT}"
exec go run ./cmd/es -config "${ES_CONFIG}"
