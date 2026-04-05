#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/bringup.sh
source "${SCRIPT_DIR}/lib/bringup.sh"
# shellcheck source=scripts/lib/control_plane.sh
source "${SCRIPT_DIR}/lib/control_plane.sh"

if [[ -z "${AGS_CONFIG:-}" ]]; then
  echo "AGS_CONFIG is required" >&2
  exit 1
fi
if [[ ! -r "${AGS_CONFIG}" ]]; then
  echo "AGS_CONFIG must point to a readable file: ${AGS_CONFIG}" >&2
  exit 1
fi

REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
IMAGE="$(control_plane_image_ref)"
CONTAINER_NAME="$(control_plane_container_name ags)"
MOUNT_SPECS=()

ensure_control_plane_image "${BRINGUP_DIR:-${REPO_ROOT}/.tmp/bringup}/logs/control-plane-image-build.log"
docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true

while IFS= read -r spec; do
  [[ -n "${spec}" ]] || continue
  MOUNT_SPECS+=(-v "${spec}")
done < <(control_plane_mount_specs ags "${AGS_CONFIG}")

printf '+ '
printf '%q ' docker run --rm --name "${CONTAINER_NAME}" --network host "${MOUNT_SPECS[@]}" "${IMAGE}" "$(control_plane_binary_path ags)" -config "${AGS_CONFIG}"
printf '\n'

cd "${REPO_ROOT}"
exec docker run --rm --name "${CONTAINER_NAME}" --network host "${MOUNT_SPECS[@]}" "${IMAGE}" "$(control_plane_binary_path ags)" -config "${AGS_CONFIG}"
