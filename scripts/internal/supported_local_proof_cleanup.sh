#!/usr/bin/env bash
set -euo pipefail

if [[ -n "${EXECUTION_SUBSTRATE_REPO_ROOT:-}" ]]; then
  REPO_ROOT="${EXECUTION_SUBSTRATE_REPO_ROOT}"
else
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
fi

ACTION="${1:-cleanup-stale}"
PROOF_PARENT="${SUPPORTED_LOCAL_PROOF_PARENT:-/tmp}"
PROOF_GLOB="${SUPPORTED_LOCAL_PROOF_GLOB:-es-proof-*}"
CURRENT_PROOF_DIR="${SUPPORTED_LOCAL_PROOF_DIR:-}"
RUN_BRINGUP_DOWN="${SUPPORTED_LOCAL_CLEANUP_RUN_BRINGUP_DOWN:-1}"

usage() {
  cat <<'EOF'
Usage:
  scripts/internal/supported_local_proof_cleanup.sh cleanup-stale

Environment:
  SUPPORTED_LOCAL_PROOF_PARENT=/tmp
  SUPPORTED_LOCAL_PROOF_GLOB=es-proof-*
  SUPPORTED_LOCAL_PROOF_DIR=/tmp/es-proof-current   optional current proof dir to preserve
  SUPPORTED_LOCAL_CLEANUP_RUN_BRINGUP_DOWN=1        set to 0 to skip scripts/01_bringup.sh down

This helper removes only proof-owned supported-local guest scratch. It does not
touch host .out evidence, the pre-managed Nomad service, unrelated Nomad jobs,
or unrelated Docker state.
EOF
}

log() {
  printf '%s\n' "$*"
}

remove_path_owned() {
  local path=$1
  local label=$2

  if [[ ! -e "${path}" ]]; then
    return 0
  fi
  if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    log "cleanup: removing ${label} via sudo ${path}"
    sudo -n rm -rf "${path}"
    return 0
  fi

  rm -rf "${path}"
}

proof_dir_is_owned() {
  local dir=$1

  [[ -d "${dir}" ]] || return 1
  case "$(basename "${dir}")" in
    es-proof-*)
      ;;
    *)
      return 1
      ;;
  esac

  for marker in \
    env.sh \
    managed-secrets.conf \
    ars.json \
    egs.json \
    ags.json \
    es.json \
    artifact-index.json \
    Dockerfile \
    workload-zone-vault-config-digest.txt \
    vault-dev.pid \
    spire-agent.pid \
    spire-server.pid
  do
    if [[ -e "${dir}/${marker}" ]]; then
      return 0
    fi
  done

  [[ -d "${dir}/bringup-state" ]] && return 0
  [[ -d "${dir}/workdirs" ]] && return 0
  [[ -d "${dir}/ars-storage" ]] && return 0
  [[ -d "${dir}/es-staging" ]] && return 0
  [[ -d "${dir}/payload" ]] && return 0
  [[ -d "${dir}/spire" ]] && return 0
  [[ -d "${dir}/spire-data" ]] && return 0
  [[ -d "${dir}/tls" ]] && return 0
  [[ -d "${dir}/vault" ]] && return 0
  return 1
}

bootstrap_dir_for() {
  printf '%s.bootstrap\n' "$1"
}

signal_pid_if_matches() {
  local pid_file=$1
  local label=$2
  local args_substring=$3
  local pid=""
  local args=""

  [[ -r "${pid_file}" ]] || return 0

  pid="$(tr -d '[:space:]' <"${pid_file}")"
  [[ -n "${pid}" ]] || return 0
  if ! kill -0 "${pid}" 2>/dev/null; then
    return 0
  fi

  args="$(ps -p "${pid}" -o args= 2>/dev/null || true)"
  if [[ -z "${args}" ]]; then
    return 0
  fi
  if [[ "${args}" != *"${args_substring}"* ]]; then
    log "cleanup: leaving ${pid_file}; pid ${pid} no longer matches ${label}"
    return 0
  fi

  log "cleanup: stopping ${label} pid ${pid}"
  kill "${pid}" >/dev/null 2>&1 || true
  for _ in $(seq 1 20); do
    if ! kill -0 "${pid}" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done

  kill -KILL "${pid}" >/dev/null 2>&1 || true
}

stop_vault_dev_listener_on_port() {
  local port=$1
  local pid=""
  local args=""

  [[ -n "${port}" ]] || return 0
  command -v ss >/dev/null 2>&1 || return 0

  pid="$(
    ss -ltnp "( sport = :${port} )" 2>/dev/null \
      | grep -o 'pid=[0-9]*' \
      | head -n 1 \
      | cut -d= -f2 || true
  )"
  [[ -n "${pid}" ]] || return 0
  args="$(ps -p "${pid}" -o args= 2>/dev/null || true)"
  if [[ "${args}" != *"vault server"* ]] || [[ "${args}" != *"-dev"* ]]; then
    return 0
  fi

  log "cleanup: stopping proof-owned Vault dev listener on port ${port} (pid ${pid})"
  kill "${pid}" >/dev/null 2>&1 || true
  for _ in $(seq 1 20); do
    if ! kill -0 "${pid}" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done

  kill -KILL "${pid}" >/dev/null 2>&1 || true
}

stop_vault_dev_listener_from_dir() {
  local dir=$1
  local port=""

  if [[ -r "${dir}/managed-secrets.conf" ]]; then
    port="$(
      python3 - <<'PY' "${dir}/managed-secrets.conf"
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
match = re.search(r'^PROOF_VAULT_PORT="([0-9]+)"$', text, re.MULTILINE)
print(match.group(1) if match else "")
PY
    )"
  fi

  stop_vault_dev_listener_on_port "${port}"
}

bringup_down_for_dir() {
  local dir=$1

  if [[ "${RUN_BRINGUP_DOWN}" != "1" ]]; then
    return 0
  fi
  if [[ ! -x "${REPO_ROOT}/scripts/01_bringup.sh" ]]; then
    return 0
  fi

  log "cleanup: stopping repo-owned control-plane state for ${dir}"
  (
    cd "${REPO_ROOT}"
    BRINGUP_DIR="${dir}/bringup-state" scripts/01_bringup.sh down
  )
}

cleanup_owned_dir() {
  local dir=$1
  local bootstrap_dir

  bootstrap_dir="$(bootstrap_dir_for "${dir}")"

  bringup_down_for_dir "${dir}"
  signal_pid_if_matches "${dir}/spire-agent.pid" "proof-owned SPIRE agent" "spire-agent"
  signal_pid_if_matches "${dir}/spire-server.pid" "proof-owned SPIRE server" "spire-server"
  signal_pid_if_matches "${dir}/vault-dev.pid" "proof-owned Vault dev server" "vault server -dev"
  stop_vault_dev_listener_from_dir "${dir}"

  log "cleanup: removing proof-owned guest scratch ${dir}"
  remove_path_owned "${dir}" "proof-owned guest scratch"

  if [[ -e "${bootstrap_dir}" ]]; then
    log "cleanup: removing proof-owned bootstrap scratch ${bootstrap_dir}"
    remove_path_owned "${bootstrap_dir}" "proof-owned bootstrap scratch"
  fi
}

cleanup_orphan_bootstrap_dirs() {
  local found=0
  local bootstrap_dir
  local proof_dir

  shopt -s nullglob
  for bootstrap_dir in "${PROOF_PARENT}"/${PROOF_GLOB}.bootstrap; do
    proof_dir="${bootstrap_dir%.bootstrap}"
    if [[ -n "${CURRENT_PROOF_DIR}" ]] && [[ "${proof_dir}" == "${CURRENT_PROOF_DIR}" ]]; then
      continue
    fi
    if [[ -d "${proof_dir}" ]]; then
      continue
    fi
    found=1
    log "cleanup: removing orphan proof-owned bootstrap scratch ${bootstrap_dir}"
    remove_path_owned "${bootstrap_dir}" "orphan proof-owned bootstrap scratch"
  done
  shopt -u nullglob
  if (( found > 0 )); then
    return 0
  fi
  return 1
}

cleanup_stale() {
  local found=0
  local dir

  log "cleanup: scanning ${PROOF_PARENT}/${PROOF_GLOB} for stale proof-owned guest scratch"

  shopt -s nullglob
  for dir in "${PROOF_PARENT}"/${PROOF_GLOB}; do
    [[ -d "${dir}" ]] || continue
    if [[ -n "${CURRENT_PROOF_DIR}" ]] && [[ "${dir}" == "${CURRENT_PROOF_DIR}" ]]; then
      log "cleanup: preserving current proof dir ${dir}"
      continue
    fi
    if ! proof_dir_is_owned "${dir}"; then
      log "cleanup: leaving ${dir}; missing supported-local proof markers"
      continue
    fi
    found=1
    cleanup_owned_dir "${dir}"
  done
  shopt -u nullglob

  if cleanup_orphan_bootstrap_dirs; then
    found=1
  fi

  if (( found == 0 )); then
    log "cleanup: no stale proof-owned guest scratch found"
  fi
}

case "${ACTION}" in
  cleanup-stale)
    cleanup_stale
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage >&2
    exit 1
    ;;
esac
