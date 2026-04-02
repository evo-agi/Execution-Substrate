#!/usr/bin/env bash
set -euo pipefail

required_envs=(
  RUN_ID
  NOMAD_JOB_ID
  NOMAD_EVAL_ID
  NOMAD_ADDR
  ES_URL
  CA_CERT
  DEPLOY_CERT
  DEPLOY_KEY
)

for name in "${required_envs[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    echo "${name} is required" >&2
    exit 1
  fi
done

for path_name in CA_CERT DEPLOY_CERT DEPLOY_KEY; do
  path_value="${!path_name}"
  if [[ ! -r "${path_value}" ]]; then
    echo "${path_name} must point to a readable file: ${path_value}" >&2
    exit 1
  fi
done

printf '+ '
printf '%q ' nomad job status "${NOMAD_JOB_ID}"
printf '\n'
nomad job status "${NOMAD_JOB_ID}"
printf '\n'

printf '+ '
printf '%q ' nomad eval status "${NOMAD_EVAL_ID}"
printf '\n'
nomad eval status "${NOMAD_EVAL_ID}"
printf '\n'

printf '+ curl --fail-with-body --silent --show-error --cacert %q --cert %q --key %q %q | python3 -m json.tool\n' \
  "${CA_CERT}" "${DEPLOY_CERT}" "${DEPLOY_KEY}" "${ES_URL}/v1/executions/${RUN_ID}/status"
curl --fail-with-body --silent --show-error \
  --cacert "${CA_CERT}" \
  --cert "${DEPLOY_CERT}" \
  --key "${DEPLOY_KEY}" \
  "${ES_URL}/v1/executions/${RUN_ID}/status" | python3 -m json.tool
printf '\n'

printf '+ curl --fail-with-body --silent --show-error --cacert %q --cert %q --key %q %q\n' \
  "${CA_CERT}" "${DEPLOY_CERT}" "${DEPLOY_KEY}" "${ES_URL}/v1/executions/${RUN_ID}/logs"
curl --fail-with-body --silent --show-error \
  --cacert "${CA_CERT}" \
  --cert "${DEPLOY_CERT}" \
  --key "${DEPLOY_KEY}" \
  "${ES_URL}/v1/executions/${RUN_ID}/logs"
printf '\n\n'

alloc_id="${ALLOC_ID:-}"
if [[ -z "${alloc_id}" ]]; then
  printf '+ '
  printf '%q ' nomad job allocs -json "${NOMAD_JOB_ID}"
  printf '| python3 - <<'"'"'PY'"'"'\n'
  alloc_id="$(nomad job allocs -json "${NOMAD_JOB_ID}" | python3 - <<'PY'
import json, sys
allocs = json.load(sys.stdin)
if not allocs:
    raise SystemExit("no allocations found")
print(allocs[0]["ID"])
PY
)"
fi

echo "ALLOC_ID=${alloc_id}"
printf '\n'

printf '+ '
printf '%q ' nomad alloc status "${alloc_id}"
printf '\n'
nomad alloc status "${alloc_id}"
printf '\n'

printf '+ '
printf '%q ' nomad alloc logs -stdout "${alloc_id}"
printf '\n'
nomad alloc logs -stdout "${alloc_id}"
printf '\n'

if [[ "${DO_CANCEL:-0}" == "1" ]]; then
  printf '+ curl --fail-with-body --silent --show-error --cacert %q --cert %q --key %q -X POST %q | python3 -m json.tool\n' \
    "${CA_CERT}" "${DEPLOY_CERT}" "${DEPLOY_KEY}" "${ES_URL}/v1/executions/${RUN_ID}:cancel"
  curl --fail-with-body --silent --show-error \
    --cacert "${CA_CERT}" \
    --cert "${DEPLOY_CERT}" \
    --key "${DEPLOY_KEY}" \
    -X POST \
    "${ES_URL}/v1/executions/${RUN_ID}:cancel" | python3 -m json.tool
fi
