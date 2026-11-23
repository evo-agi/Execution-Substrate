#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/internal/bringup.sh
source "${SCRIPT_DIR}/internal/bringup.sh"
# shellcheck source=scripts/internal/control_plane.sh
source "${SCRIPT_DIR}/internal/control_plane.sh"

if [[ -z "${ARS_CONFIG:-}" ]]; then
  echo "ARS_CONFIG is required" >&2
  exit 1
fi
if [[ ! -r "${ARS_CONFIG}" ]]; then
  echo "ARS_CONFIG must point to a readable file: ${ARS_CONFIG}" >&2
  exit 1
fi

REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
IMAGE="$(control_plane_image_ref)"
CONTAINER_NAME="$(control_plane_container_name ars)"
MOUNT_SPECS=()

# ARS runs as the operator's numeric effective UID and primary GID
# (control_plane_operator_user) instead of the image's default root user, so it
# holds no more host authority than the operator who started it. The identity
# is derived before any image build, storage change or container change.
CONTAINER_USER="$(control_plane_operator_user ARS)"

ensure_control_plane_image "${BRINGUP_DIR:-${REPO_ROOT}/.tmp/bringup}/logs/control-plane-image-build.log"
# The storage check runs in a container with ARS's name and writes the index
# the way ARS does, so the ARS container this launcher replaces goes first.
docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
# scripts/01_bringup.sh stops this launcher with SIGTERM to its child processes
# and to the launcher, waits for the launcher to end, and then removes ARS's
# container by name. During the check, that container is the check's own, so
# the launcher stays until the check, which passes the signal on to its probe,
# has removed its files and ended: bash runs these traps only once the check
# has returned.
trap 'exit 143' TERM
trap 'exit 129' HUP
verify_ars_storage_for_operator "${ARS_CONFIG}" "${CONTAINER_USER}"
trap - TERM HUP
# scripts/01_bringup.sh up starts ARS's readiness wait only once this check
# has passed, because on large storage the check takes a while. It names a file
# for this launcher to create then. The file only reports a passed check; there
# is no way to skip the check.
if [[ -n "${ARS_STORAGE_CHECK_PASSED_FILE:-}" ]]; then
  : >"${ARS_STORAGE_CHECK_PASSED_FILE}"
fi

while IFS= read -r spec; do
  [[ -n "${spec}" ]] || continue
  MOUNT_SPECS+=(-v "${spec}")
done < <(control_plane_mount_specs ars "${ARS_CONFIG}")

printf '+ '
printf '%q ' docker run --rm --name "${CONTAINER_NAME}" --network host --user "${CONTAINER_USER}" "${MOUNT_SPECS[@]}" "${IMAGE}" "$(control_plane_binary_path ars)" -config "${ARS_CONFIG}"
printf '\n'

cd "${REPO_ROOT}"
exec docker run --rm --name "${CONTAINER_NAME}" --network host --user "${CONTAINER_USER}" "${MOUNT_SPECS[@]}" "${IMAGE}" "$(control_plane_binary_path ars)" -config "${ARS_CONFIG}"
