#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

EXPECTED_CONTROL_PLANE_NORMAL_SHELL_IMAGE="execution-substrate/control-plane-normal-shell:supported-local"
EXPECTED_CONTROL_PLANE_NORMAL_SHELL_DOCKERFILE="${REPO_ROOT}/es/runtimeprofiles/control_plane_normal_shell/Dockerfile"
EXPECTED_CONTROL_PLANE_NORMAL_SHELL_CODEX_CLI_PATH="/usr/local/bin/codex"
EXPECTED_CONTROL_PLANE_NORMAL_SHELL_CODEX_REALIZATION="proof"

require_pinned_remote_alpha_value() {
  local name=$1
  local expected=$2
  local actual="${!name-}"

  if [[ -n "${actual}" ]] && [[ "${actual}" != "${expected}" ]]; then
    printf 'remote alpha normal-shell runtime image recipe is pinned: %s must be %q (got %q)\n' "${name}" "${expected}" "${actual}" >&2
    exit 1
  fi
}

require_pinned_remote_alpha_value "CONTROL_PLANE_NORMAL_SHELL_IMAGE" "${EXPECTED_CONTROL_PLANE_NORMAL_SHELL_IMAGE}"
require_pinned_remote_alpha_value "CONTROL_PLANE_NORMAL_SHELL_DOCKERFILE" "${EXPECTED_CONTROL_PLANE_NORMAL_SHELL_DOCKERFILE}"
require_pinned_remote_alpha_value "CONTROL_PLANE_NORMAL_SHELL_CODEX_CLI_PATH" "${EXPECTED_CONTROL_PLANE_NORMAL_SHELL_CODEX_CLI_PATH}"
require_pinned_remote_alpha_value "CONTROL_PLANE_NORMAL_SHELL_CODEX_REALIZATION" "${EXPECTED_CONTROL_PLANE_NORMAL_SHELL_CODEX_REALIZATION}"

export CONTROL_PLANE_NORMAL_SHELL_IMAGE="${EXPECTED_CONTROL_PLANE_NORMAL_SHELL_IMAGE}"
export CONTROL_PLANE_NORMAL_SHELL_DOCKERFILE="${EXPECTED_CONTROL_PLANE_NORMAL_SHELL_DOCKERFILE}"
export CONTROL_PLANE_NORMAL_SHELL_CODEX_CLI_PATH="${EXPECTED_CONTROL_PLANE_NORMAL_SHELL_CODEX_CLI_PATH}"
export CONTROL_PLANE_NORMAL_SHELL_CODEX_REALIZATION="${EXPECTED_CONTROL_PLANE_NORMAL_SHELL_CODEX_REALIZATION}"

exec bash "${REPO_ROOT}/scripts/build_control_plane_normal_shell_image.sh"
