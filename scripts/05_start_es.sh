#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/internal/bringup.sh
source "${SCRIPT_DIR}/internal/bringup.sh"
# shellcheck source=scripts/internal/control_plane.sh
source "${SCRIPT_DIR}/internal/control_plane.sh"

if [[ -z "${ES_CONFIG:-}" ]]; then
  echo "ES_CONFIG is required" >&2
  exit 1
fi
if [[ ! -r "${ES_CONFIG}" ]]; then
  echo "ES_CONFIG must point to a readable file: ${ES_CONFIG}" >&2
  exit 1
fi

REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
IMAGE="$(control_plane_image_ref)"
CONTAINER_NAME="$(control_plane_container_name es)"
MOUNT_SPECS=()

# Without a supported-local roots profile, verify_es_staging_invariant creates
# missing execution roots as the calling operator and requires both roots to be
# writable by that operator. ES's startup capability probe then requires a
# result directory that ES creates naturally to carry the roots' UID and GID
# (probeNaturalResultDirectory in es/admission/execution_roots.go), so ES runs
# as the operator's effective UID and primary GID instead of the image's
# default root user. Docker gives that identity no supplementary groups. Both
# IDs must be numeric: docker run --user with an empty UID runs as root. The
# identity is derived before any image build, root creation or container
# change. On a user-namespace-remapped daemon, Docker itself refuses the host
# network that this launcher requires, so bring-up cannot start ES there;
# rootless Docker is untested and unsupported for bring-up. The service-root-v1
# profile keeps the default user because its roots are 0:0.
USER_SPECS=()
if [[ -z "${SUPPORTED_LOCAL_ES_ROOTS_PROFILE:-}" ]]; then
  ES_CONTAINER_UID="$(id -u)"
  ES_CONTAINER_GID="$(id -g)"
  if [[ ! "${ES_CONTAINER_UID}" =~ ^[0-9]+$ || ! "${ES_CONTAINER_GID}" =~ ^[0-9]+$ ]]; then
    printf 'cannot run ES as the operator: id -u and id -g must print numeric IDs, got %q and %q\n' "${ES_CONTAINER_UID}" "${ES_CONTAINER_GID}" >&2
    exit 1
  fi
  USER_SPECS=(--user "${ES_CONTAINER_UID}:${ES_CONTAINER_GID}")
fi

ensure_control_plane_image "${BRINGUP_DIR:-${REPO_ROOT}/.tmp/bringup}/logs/control-plane-image-build.log"
verify_es_staging_invariant "${ES_CONFIG}"
docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true

while IFS= read -r spec; do
  [[ -n "${spec}" ]] || continue
  MOUNT_SPECS+=(-v "${spec}")
done < <(control_plane_mount_specs es "${ES_CONFIG}")

printf '+ '
printf '%q ' docker run --rm --name "${CONTAINER_NAME}" --network host ${USER_SPECS[@]+"${USER_SPECS[@]}"} "${MOUNT_SPECS[@]}" "${IMAGE}" "$(control_plane_binary_path es)" -config "${ES_CONFIG}"
printf '\n'

cd "${REPO_ROOT}"
exec docker run --rm --name "${CONTAINER_NAME}" --network host ${USER_SPECS[@]+"${USER_SPECS[@]}"} "${MOUNT_SPECS[@]}" "${IMAGE}" "$(control_plane_binary_path es)" -config "${ES_CONFIG}"
