#!/usr/bin/env bash

# Nomad access control (ACL) helpers shared by the bring-up, health-check and
# proof scripts. ES submits only with its own least-privilege token in
# namespace es-submit-v1 (see scripts/internal/nomad_acl.py). Operator checks
# read Nomad with a read-only observer token named by NOMAD_TOKEN_FILE.
#
# A token is read from its file and handed to curl through a configuration on
# a file descriptor, so it never appears on a command line. Requests to Nomad
# use no proxy and follow no redirect, so a token reaches only the loopback
# Nomad. This file has no top-level effects.

NOMAD_ACL_NAMESPACE="es-submit-v1"

nomad_acl_tool() {
  printf '%s\n' "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/nomad_acl.py"
}

# nomad_token_from_file <path>: print the token held in <path> (no newline).
nomad_token_from_file() {
  local path=$1
  local token=""

  if [[ -z "${path}" || -L "${path}" || ! -f "${path}" || ! -r "${path}" ]]; then
    echo "nomad: token file is missing, unreadable or a symbolic link: ${path:-<unset>}" >&2
    return 1
  fi
  IFS= read -r token <"${path}" || true
  if [[ ! "${token}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
    echo "nomad: token file does not hold one Nomad token: ${path}" >&2
    return 1
  fi
  printf '%s' "${token}"
}

# nomad_api_get <api-path> <output-file>: GET ${NOMAD_ADDR}<api-path> with the
# token from NOMAD_TOKEN_FILE.
nomad_api_get() {
  local api_path=$1
  local output_path=$2
  local token

  if [[ -z "${NOMAD_TOKEN_FILE:-}" ]]; then
    echo "nomad: NOMAD_TOKEN_FILE is required to read ${api_path} from an ACL-enforcing Nomad" >&2
    return 1
  fi
  token="$(nomad_token_from_file "${NOMAD_TOKEN_FILE}")" || return 1
  curl --noproxy '*' --fail-with-body --silent --show-error \
    --config <(printf 'header = "X-Nomad-Token: %s"\n' "${token}") \
    "${NOMAD_ADDR}${api_path}" >"${output_path}"
}

# nomad_acl_state_check: refuse unless Nomad enforces ACLs and holds no
# anonymous policy. ES itself checks the same two facts before each submit.
nomad_acl_state_check() {
  local self_path
  local anonymous_status

  self_path="$(mktemp)"
  if ! curl --noproxy '*' --fail-with-body --silent --show-error "${NOMAD_ADDR}/v1/acl/token/self" >"${self_path}"; then
    rm -f "${self_path}"
    echo "nomad: ACL self request failed for ${NOMAD_ADDR}/v1/acl/token/self" >&2
    return 1
  fi
  if ! python3 -I - "${self_path}" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        document = json.load(handle)
except (OSError, ValueError):
    document = None
accessor = document.get("AccessorID") if isinstance(document, dict) else None
if accessor == "acls-disabled":
    print(
        "nomad: ACLs are disabled; ES refuses to submit to a Nomad that accepts jobs without a token "
        "(add `acl { enabled = true }` to the Nomad configuration, restart Nomad, and provision tokens "
        "with scripts/internal/nomad_acl.py)",
        file=sys.stderr,
    )
    raise SystemExit(1)
if accessor != "anonymous":
    print("nomad: unexpected answer from /v1/acl/token/self without a token", file=sys.stderr)
    raise SystemExit(1)
PY
  then
    rm -f "${self_path}"
    return 1
  fi
  rm -f "${self_path}"

  anonymous_status="$(curl --noproxy '*' --silent --output /dev/null --write-out '%{http_code}' "${NOMAD_ADDR}/v1/acl/policy/anonymous")" || anonymous_status="000"
  if [[ "${anonymous_status}" != "404" ]]; then
    echo "nomad: an anonymous ACL policy exists or could not be checked (HTTP ${anonymous_status}); ES refuses to submit while requests without a token hold capabilities" >&2
    return 1
  fi
  echo "nomad: acl=enforced anonymous_policy=absent"
}

# nomad_acl_validate_dir_placement <acl-dir> <scope>...: refuse unless
# <acl-dir> is a clean absolute path below the root that overlaps none of the
# given scopes (for example a proof directory a cleanup step may remove) and
# is not under /tmp/es-proof-*. Metadata only: nothing is opened or created.
nomad_acl_validate_dir_placement() {
  local acl_dir=$1
  shift

  python3 -I - "${acl_dir}" "$@" <<'PY'
import posixpath
import sys

acl_dir, *scopes = sys.argv[1:]


def clean_absolute(path):
    return (
        bool(path)
        and path.startswith("/")
        and not path.startswith("//")
        and path.strip() == path
        and "\x00" not in path
        and posixpath.normpath(path) == path
    )


def overlaps(left, right):
    return left == right or left.startswith(right + "/") or right.startswith(left + "/")


valid = clean_absolute(acl_dir) and acl_dir != "/" and not any(c.isspace() for c in acl_dir)
for scope in scopes:
    if not clean_absolute(scope) or scope == "/" or (valid and overlaps(acl_dir, scope)):
        valid = False
parts = acl_dir.split("/")
if len(parts) > 2 and parts[1] == "tmp" and parts[2].startswith("es-proof-"):
    valid = False
if not valid:
    raise SystemExit("nomad: the Nomad ACL token directory must be a clean absolute path outside the proof, staging, results and SPIRE socket directories")
PY
}
