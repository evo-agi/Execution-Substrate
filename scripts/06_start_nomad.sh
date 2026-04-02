#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${NOMAD_CONFIG:-}" ]]; then
  echo "NOMAD_CONFIG is required" >&2
  exit 1
fi
if [[ ! -r "${NOMAD_CONFIG}" ]]; then
  echo "NOMAD_CONFIG must point to a readable file: ${NOMAD_CONFIG}" >&2
  exit 1
fi

printf '+ '
printf '%q ' nomad agent -dev "-config=${NOMAD_CONFIG}"
printf '\n'

exec nomad agent -dev "-config=${NOMAD_CONFIG}"
