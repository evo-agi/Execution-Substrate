#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

IMAGE="${CONTROL_PLANE_NORMAL_SHELL_IMAGE:-execution-substrate/control-plane-normal-shell:local}"
DOCKERFILE="${CONTROL_PLANE_NORMAL_SHELL_DOCKERFILE:-${REPO_ROOT}/es/runtimeprofiles/control_plane_normal_shell/Dockerfile}"
CODEX_NPM_PACKAGE="${CONTROL_PLANE_NORMAL_SHELL_CODEX_NPM_PACKAGE:-@openai/codex}"
CODEX_NPM_VERSION="${CONTROL_PLANE_NORMAL_SHELL_CODEX_NPM_VERSION:-latest}"
CODEX_CLI_PATH="${CONTROL_PLANE_NORMAL_SHELL_CODEX_CLI_PATH:-/usr/local/bin/codex}"
CODEX_REALIZATION="${CONTROL_PLANE_NORMAL_SHELL_CODEX_REALIZATION:-npm}"

if [[ ! -r "${DOCKERFILE}" ]]; then
  echo "Control Plane normal-shell runtime profile Dockerfile is not readable: ${DOCKERFILE}" >&2
  exit 1
fi

docker build \
  --build-arg "CODEX_NPM_PACKAGE=${CODEX_NPM_PACKAGE}" \
  --build-arg "CODEX_NPM_VERSION=${CODEX_NPM_VERSION}" \
  --build-arg "CODEX_CLI_PATH=${CODEX_CLI_PATH}" \
  --build-arg "CODEX_REALIZATION=${CODEX_REALIZATION}" \
  -t "${IMAGE}" \
  -f "${DOCKERFILE}" \
  "${REPO_ROOT}"

printf '%s\n' "${IMAGE}"
