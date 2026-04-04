#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/bringup.sh
source "${SCRIPT_DIR}/lib/bringup.sh"

required_envs=(
  ES_URL
  CA_CERT
  DEPLOY_CERT
  DEPLOY_KEY
  SUBMIT_JSON
)

for name in "${required_envs[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    echo "${name} is required" >&2
    exit 1
  fi
done

for path_name in CA_CERT DEPLOY_CERT DEPLOY_KEY SUBMIT_JSON; do
  path_value="${!path_name}"
  if [[ ! -r "${path_value}" ]]; then
    echo "${path_name} must point to a readable file: ${path_value}" >&2
    exit 1
  fi
done

resolve_args=()
if [[ -n "${ES_RESOLVE:-}" ]]; then
  resolve_args+=(--resolve "${ES_RESOLVE}")
fi

tmp_response="$(mktemp)"
trap 'rm -f "${tmp_response}"' EXIT

printf '+ curl --fail-with-body --silent --show-error --cacert %q --cert %q --key %q -H %q --data @%q %q | tee %q\n' \
  "${CA_CERT}" "${DEPLOY_CERT}" "${DEPLOY_KEY}" 'Content-Type: application/json' "${SUBMIT_JSON}" \
  "${ES_URL}/v1/executions:submit" "${tmp_response}"
curl --fail-with-body --silent --show-error \
  --cacert "${CA_CERT}" \
  --cert "${DEPLOY_CERT}" \
  --key "${DEPLOY_KEY}" \
  "${resolve_args[@]}" \
  -H 'Content-Type: application/json' \
  --data @"${SUBMIT_JSON}" \
  "${ES_URL}/v1/executions:submit" | tee "${tmp_response}"
printf '\n'

if [[ -n "${SUBMIT_RESPONSE:-}" ]]; then
  cp "${tmp_response}" "${SUBMIT_RESPONSE}"
  echo "saved submit response to ${SUBMIT_RESPONSE}"
fi

python3 - <<'PY' "${tmp_response}"
import json, pathlib, sys
payload = json.loads(pathlib.Path(sys.argv[1]).read_text())
for key in ("run_id", "status"):
    value = payload.get(key, "")
    if value:
        print(f"{key.upper()}={value}")
PY
