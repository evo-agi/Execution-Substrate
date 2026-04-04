#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/bringup.sh
source "${SCRIPT_DIR}/lib/bringup.sh"

required_envs=(
  AGS_URL
  CA_CERT
  OPERATOR_CERT
  OPERATOR_KEY
  PUBLISH_JSON
)

for name in "${required_envs[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    echo "${name} is required" >&2
    exit 1
  fi
done

for path_name in CA_CERT OPERATOR_CERT OPERATOR_KEY PUBLISH_JSON; do
  path_value="${!path_name}"
  if [[ ! -r "${path_value}" ]]; then
    echo "${path_name} must point to a readable file: ${path_value}" >&2
    exit 1
  fi
done

resolve_args=()
if [[ -n "${AGS_RESOLVE:-}" ]]; then
  resolve_args+=(--resolve "${AGS_RESOLVE}")
fi

tmp_response="$(mktemp)"
trap 'rm -f "${tmp_response}"' EXIT

printf '+ curl --fail-with-body --silent --show-error --cacert %q --cert %q --key %q -H %q --data @%q %q | tee %q\n' \
  "${CA_CERT}" "${OPERATOR_CERT}" "${OPERATOR_KEY}" 'Content-Type: application/json' "${PUBLISH_JSON}" \
  "${AGS_URL}/v1/artifacts:publish" "${tmp_response}"
curl --fail-with-body --silent --show-error \
  --cacert "${CA_CERT}" \
  --cert "${OPERATOR_CERT}" \
  --key "${OPERATOR_KEY}" \
  "${resolve_args[@]}" \
  -H 'Content-Type: application/json' \
  --data @"${PUBLISH_JSON}" \
  "${AGS_URL}/v1/artifacts:publish" | tee "${tmp_response}"
printf '\n'

if [[ -n "${PUBLISH_RESPONSE:-}" ]]; then
  cp "${tmp_response}" "${PUBLISH_RESPONSE}"
  echo "saved publish response to ${PUBLISH_RESPONSE}"
fi

artifact_digest="$(python3 - <<'PY' "${tmp_response}"
import json, pathlib, sys
payload = json.loads(pathlib.Path(sys.argv[1]).read_text())
print(payload.get("artifact_digest", ""))
PY
)"

if [[ -n "${artifact_digest}" ]]; then
  echo "ARTIFACT_DIGEST=${artifact_digest}"
fi
