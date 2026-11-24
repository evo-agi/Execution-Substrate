#!/usr/bin/env bash
set -euo pipefail

# Lock a host's Nomad so that only ES can submit jobs.
#
# Run as root on the host that runs Nomad and ES, after Nomad runs with
# `acl { enabled = true }` (scripts/70_linux_setup.sh writes that config):
#
#   sudo scripts/nomad_acl_setup.sh            # provision: bootstrap if needed,
#                                              # namespace, policies, token files
#   sudo scripts/nomad_acl_setup.sh check      # verify the lock
#   sudo scripts/nomad_acl_setup.sh rotate     # replace the ES and observer tokens
#   sudo scripts/nomad_acl_setup.sh placement  # after every Nomad start: a node
#                                              # with a host-mode network, and
#                                              # plans of ES's job shapes with
#                                              # ES's token that place
#
# Files, all in NOMAD_ACL_DIR (default /etc/execution-substrate/nomad-acl):
#   management-token  root only (0600). Nomad's bootstrap management token.
#                     Never give it to ES or to an operator script.
#   es-token          0400, owned by the user ES runs as (ES_USER). Point
#                     es.json's nomad.token_file here.
#   observer-token    0400, owned by OBSERVER_USER. Read-only token for
#                     readiness checks: export NOMAD_TOKEN_FILE=<this path>.
#
# Environment:
#   NOMAD_ADDR      default http://127.0.0.1:4646 (loopback only)
#   NOMAD_ACL_DIR   default /etc/execution-substrate/nomad-acl
#   ES_USER         user ES runs as; default root (the supported-local
#                   service-root-v1 profile). Remote Alpha's es.service: es
#   OBSERVER_USER   operator who runs readiness checks; default SUDO_USER, else root
#   NOMAD_USER      user Nomad runs as; default root (nomad.service). Nothing
#                   is sent to a listener on NOMAD_ADDR that another user owns.
#   ES_CONFIG       placement: ES's config, for its nomad.datacenter; default
#                   /etc/execution-substrate/es.json
#   NOMAD_STARTED_AT  placement: Unix time just before the latest Nomad start;
#                   node state the servers kept from before it does not count
#   NOMAD_PLACEMENT_WAIT_SECONDS  placement: default 60
#
# ES reads its token only at startup: restart ES after `rotate`.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOL="${SCRIPT_DIR}/internal/nomad_acl.py"
ACTION="${1:-provision}"
NOMAD_ADDR="${NOMAD_ADDR:-http://127.0.0.1:4646}"
NOMAD_ACL_DIR="${NOMAD_ACL_DIR:-/etc/execution-substrate/nomad-acl}"
ES_USER="${ES_USER:-root}"
OBSERVER_USER="${OBSERVER_USER:-${SUDO_USER:-root}}"
NOMAD_USER="${NOMAD_USER:-root}"

usage() {
  sed -n '4,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

owner_of_user() {
  local user=$1
  local uid
  local gid
  if ! uid="$(id -u "${user}" 2>/dev/null)" || ! gid="$(id -g "${user}" 2>/dev/null)"; then
    echo "nomad acl setup: user ${user} does not exist" >&2
    return 1
  fi
  printf '%s:%s\n' "${uid}" "${gid}"
}

case "${ACTION}" in
  provision|check|rotate|placement)
    ;;
  -h|--help|help)
    usage
    exit 0
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

if (( EUID != 0 )); then
  echo "nomad acl setup: run as root (sudo), because the management token file is root-only" >&2
  exit 1
fi
if [[ ! "${NOMAD_ACL_DIR}" =~ ^/[^[:space:]]+$ || "${NOMAD_ACL_DIR}" == "/" ]]; then
  echo "nomad acl setup: NOMAD_ACL_DIR must be an absolute path" >&2
  exit 1
fi

ES_OWNER="$(owner_of_user "${ES_USER}")"
OBSERVER_OWNER="$(owner_of_user "${OBSERVER_USER}")"
NOMAD_OWNER="$(owner_of_user "${NOMAD_USER}")"
NOMAD_UID="${NOMAD_OWNER%%:*}"

if [[ "${ACTION}" == "check" ]]; then
  exec python3 -I "${TOOL}" check \
    --addr "${NOMAD_ADDR}" \
    --nomad-uid "${NOMAD_UID}" \
    --es-token-file "${NOMAD_ACL_DIR}/es-token" \
    --es-token-owner "${ES_OWNER}" \
    --observer-token-file "${NOMAD_ACL_DIR}/observer-token" \
    --observer-token-owner "${OBSERVER_OWNER}" \
    --management-token-file "${NOMAD_ACL_DIR}/management-token"
fi

if [[ "${ACTION}" == "placement" ]]; then
  exec python3 -I "${TOOL}" placement \
    --addr "${NOMAD_ADDR}" \
    --nomad-uid "${NOMAD_UID}" \
    --es-token-file "${NOMAD_ACL_DIR}/es-token" \
    --es-token-owner "${ES_OWNER}" \
    --observer-token-file "${NOMAD_ACL_DIR}/observer-token" \
    --observer-token-owner "${OBSERVER_OWNER}" \
    --es-config "${ES_CONFIG:-/etc/execution-substrate/es.json}" \
    --fresh-after "${NOMAD_STARTED_AT:-0}" \
    --wait-seconds "${NOMAD_PLACEMENT_WAIT_SECONDS:-60}"
fi

if [[ ! -d "${NOMAD_ACL_DIR}" ]]; then
  install -d -o root -g root -m 0755 "${NOMAD_ACL_DIR}"
fi

ROTATE=()
if [[ "${ACTION}" == "rotate" ]]; then
  ROTATE=(--rotate)
fi

python3 -I "${TOOL}" provision \
  --addr "${NOMAD_ADDR}" \
  --nomad-uid "${NOMAD_UID}" \
  --management-token-file "${NOMAD_ACL_DIR}/management-token" \
  --es-token-file "${NOMAD_ACL_DIR}/es-token" \
  --es-token-owner "${ES_OWNER}" \
  --observer-token-file "${NOMAD_ACL_DIR}/observer-token" \
  --observer-token-owner "${OBSERVER_OWNER}" \
  ${ROTATE[@]+"${ROTATE[@]}"}

python3 -I "${TOOL}" check \
  --addr "${NOMAD_ADDR}" \
  --nomad-uid "${NOMAD_UID}" \
  --es-token-file "${NOMAD_ACL_DIR}/es-token" \
  --es-token-owner "${ES_OWNER}" \
  --observer-token-file "${NOMAD_ACL_DIR}/observer-token" \
  --observer-token-owner "${OBSERVER_OWNER}" \
  --management-token-file "${NOMAD_ACL_DIR}/management-token"

echo
echo "next:"
echo "  set nomad.token_file to ${NOMAD_ACL_DIR}/es-token in ES's config and restart ES"
echo "  export NOMAD_TOKEN_FILE=${NOMAD_ACL_DIR}/observer-token before readiness checks"
echo "  after every Nomad start, run this script's placement action: it checks that Nomad can place ES's jobs"
