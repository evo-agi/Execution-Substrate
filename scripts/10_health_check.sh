#!/usr/bin/env bash
set -euo pipefail

required_envs=(
  ARS_URL
  EGS_URL
  AGS_URL
  ES_URL
  NOMAD_ADDR
  CA_CERT
)

for name in "${required_envs[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    echo "${name} is required" >&2
    exit 1
  fi
done

if [[ ! -r "${CA_CERT}" ]]; then
  echo "CA_CERT must point to a readable file: ${CA_CERT}" >&2
  exit 1
fi

run_health() {
  local url="$1"
  printf '+ curl --fail-with-body --silent --show-error --cacert %q %q | python3 -m json.tool\n' "${CA_CERT}" "${url}"
  curl --fail-with-body --silent --show-error --cacert "${CA_CERT}" "${url}" | python3 -m json.tool
  printf '\n'
}

run_health "${ARS_URL}/health"
run_health "${EGS_URL}/health"
run_health "${AGS_URL}/health"
run_health "${ES_URL}/health"

printf '+ %q %q\n' nomad status
nomad status
printf '\n'

printf '+ %q %q > /dev/null\n' docker info
docker info >/dev/null
echo "docker info succeeded"
