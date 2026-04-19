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

NOMAD_ARGS=(agent "-config=${NOMAD_CONFIG}")

if [[ -n "${NOMAD_CLIENT_CPU_TOTAL_COMPUTE:-}" ]]; then
  if ! [[ "${NOMAD_CLIENT_CPU_TOTAL_COMPUTE}" =~ ^[0-9]+$ ]] || (( NOMAD_CLIENT_CPU_TOTAL_COMPUTE <= 0 )); then
    echo "NOMAD_CLIENT_CPU_TOTAL_COMPUTE must be a positive integer when set" >&2
    exit 1
  fi

  override_dir="${BRINGUP_DIR:-$(pwd)/.tmp/bringup}"
  override_path="${override_dir}/nomad-client-overrides.hcl"
  mkdir -p "${override_dir}"
  cat >"${override_path}" <<EOF
client {
  cpu_total_compute = ${NOMAD_CLIENT_CPU_TOTAL_COMPUTE}
}
EOF
  echo "nomad override: cpu_total_compute=${NOMAD_CLIENT_CPU_TOTAL_COMPUTE} (temporary bounded slice-0 override; this host is not naturally self-schedulable)" >&2
  NOMAD_ARGS+=("-config=${override_path}")
fi

printf '+ '
printf '%q ' nomad "${NOMAD_ARGS[@]}"
printf '\n'

exec nomad "${NOMAD_ARGS[@]}"
