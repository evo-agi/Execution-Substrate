#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${AGS_CONFIG:-}" ]]; then
  echo "AGS_CONFIG is required" >&2
  exit 1
fi
if [[ ! -r "${AGS_CONFIG}" ]]; then
  echo "AGS_CONFIG must point to a readable file: ${AGS_CONFIG}" >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

printf '+ cd %q && ' "${REPO_ROOT}"
printf '%q ' go run ./cmd/ags -config "${AGS_CONFIG}"
printf '\n'

cd "${REPO_ROOT}"
exec go run ./cmd/ags -config "${AGS_CONFIG}"
