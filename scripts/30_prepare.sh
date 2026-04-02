#!/usr/bin/env bash
set -euo pipefail

required_envs=(
  ES_URL
  CA_CERT
  DEPLOY_CERT
  DEPLOY_KEY
  PREPARE_JSON
)

for name in "${required_envs[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    echo "${name} is required" >&2
    exit 1
  fi
done

for path_name in CA_CERT DEPLOY_CERT DEPLOY_KEY PREPARE_JSON; do
  path_value="${!path_name}"
  if [[ ! -r "${path_value}" ]]; then
    echo "${path_name} must point to a readable file: ${path_value}" >&2
    exit 1
  fi
done

tmp_response="$(mktemp)"
trap 'rm -f "${tmp_response}"' EXIT

printf '+ curl --fail-with-body --silent --show-error --cacert %q --cert %q --key %q -H %q --data @%q %q | tee %q\n' \
  "${CA_CERT}" "${DEPLOY_CERT}" "${DEPLOY_KEY}" 'Content-Type: application/json' "${PREPARE_JSON}" \
  "${ES_URL}/v1/executions:prepare" "${tmp_response}"
curl --fail-with-body --silent --show-error \
  --cacert "${CA_CERT}" \
  --cert "${DEPLOY_CERT}" \
  --key "${DEPLOY_KEY}" \
  -H 'Content-Type: application/json' \
  --data @"${PREPARE_JSON}" \
  "${ES_URL}/v1/executions:prepare" | tee "${tmp_response}"
printf '\n'

if [[ -n "${PREPARE_RESPONSE:-}" ]]; then
  cp "${tmp_response}" "${PREPARE_RESPONSE}"
  echo "saved prepare response to ${PREPARE_RESPONSE}"
fi
