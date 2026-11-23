#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/internal/bringup.sh
source "${SCRIPT_DIR}/internal/bringup.sh"
# shellcheck source=scripts/internal/control_plane.sh
source "${SCRIPT_DIR}/internal/control_plane.sh"

if [[ -z "${EGS_CONFIG:-}" ]]; then
  echo "EGS_CONFIG is required" >&2
  exit 1
fi
if [[ ! -r "${EGS_CONFIG}" ]]; then
  echo "EGS_CONFIG must point to a readable file: ${EGS_CONFIG}" >&2
  exit 1
fi

REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
IMAGE="$(control_plane_image_ref)"
CONTAINER_NAME="$(control_plane_container_name egs)"
MOUNT_SPECS=()

# EGS runs as the operator's numeric effective UID and primary GID
# (control_plane_operator_user) instead of the image's default root user, so it
# holds no more host authority than the operator who started it. The identity
# is derived before any image build, storage change or container change.
CONTAINER_USER="$(control_plane_operator_user EGS)"

ensure_control_plane_image "${BRINGUP_DIR:-${REPO_ROOT}/.tmp/bringup}/logs/control-plane-image-build.log"
docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true

while IFS= read -r spec; do
  [[ -n "${spec}" ]] || continue
  MOUNT_SPECS+=(-v "${spec}")
done < <(control_plane_mount_specs egs "${EGS_CONFIG}")

printf '+ '
printf '%q ' docker run --rm --name "${CONTAINER_NAME}" --network host --user "${CONTAINER_USER}" "${MOUNT_SPECS[@]}" "${IMAGE}" "$(control_plane_binary_path egs)" -config "${EGS_CONFIG}"
printf '\n'

cd "${REPO_ROOT}"
exec docker run --rm --name "${CONTAINER_NAME}" --network host --user "${CONTAINER_USER}" "${MOUNT_SPECS[@]}" "${IMAGE}" "$(control_plane_binary_path egs)" -config "${EGS_CONFIG}"
