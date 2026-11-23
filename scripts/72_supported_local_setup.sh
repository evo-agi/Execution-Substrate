#!/usr/bin/env bash
set -euo pipefail

if [[ -n "${EXECUTION_SUBSTRATE_REPO_ROOT:-}" ]]; then
  REPO_ROOT="${EXECUTION_SUBSTRATE_REPO_ROOT}"
  SCRIPT_DIR="${REPO_ROOT}/scripts"
else
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
fi
source "${SCRIPT_DIR}/internal/supported_local_retained_result_auth.sh"
source "${SCRIPT_DIR}/internal/spire_release.sh"
ES_ROOTS_HELPER="${SCRIPT_DIR}/internal/supported_local_execution_roots.py"
ES_ROOTS_PROFILE="service-root-v1"

ACTION="${1:-setup}"
PROOF_DIR="${SUPPORTED_LOCAL_PROOF_DIR:-/tmp/execution-substrate-supported-local-proof}"
PROOF_ID="${SUPPORTED_LOCAL_PROOF_ID:-supported-local}"
PORT_BASE="${SUPPORTED_LOCAL_PORT_BASE:-18440}"
RUNTIME_SUPPORT_INSTALL_PATH="${SUPPORTED_LOCAL_RUNTIME_SUPPORT_BINARY:-/usr/local/bin/es-runtime-support}"
WORKLOAD_SPIFFE_ID="${SUPPORTED_LOCAL_WORKLOAD_SPIFFE_ID:-spiffe://execution.internal/workload}"
SPIRE_VERSION="${SUPPORTED_LOCAL_SPIRE_VERSION:-1.14.4}"
SPIRE_TRUST_DOMAIN="${SUPPORTED_LOCAL_SPIRE_TRUST_DOMAIN:-execution.internal}"
SPIRE_JWT_ISSUER="${SUPPORTED_LOCAL_SPIRE_JWT_ISSUER:-spiffe://execution.internal}"
SPIRE_AGENT_SPIFFE_ID="${SUPPORTED_LOCAL_SPIRE_AGENT_SPIFFE_ID:-spiffe://execution.internal/spire-agent}"
PREBUILT_RUNTIME_SUPPORT_BINARY="${SUPPORTED_LOCAL_PREBUILT_RUNTIME_SUPPORT_BINARY:-}"
PREBUILT_SPIRE_TARBALL="${SUPPORTED_LOCAL_PREBUILT_SPIRE_TARBALL:-}"
VAULT_ADDRESS="${SUPPORTED_LOCAL_VAULT_ADDRESS:-}"
VAULT_BIND_ADDRESS="${SUPPORTED_LOCAL_VAULT_BIND_ADDRESS:-0.0.0.0}"
VAULT_PUBLIC_HOST="${SUPPORTED_LOCAL_VAULT_PUBLIC_HOST:-}"
VAULT_PORT="${SUPPORTED_LOCAL_VAULT_PORT:-$((PORT_BASE + 20))}"
VAULT_AUTH_MOUNT="${SUPPORTED_LOCAL_VAULT_AUTH_MOUNT:-jwt}"
VAULT_AUTH_ROLE="${SUPPORTED_LOCAL_VAULT_AUTH_ROLE:-service_execution}"
VAULT_JWT_AUDIENCE="${SUPPORTED_LOCAL_VAULT_JWT_AUDIENCE:-vault}"
VAULT_SECRET_PATH="${SUPPORTED_LOCAL_VAULT_SECRET_PATH:-proof-secrets/data/runtime-identity-vault-login}"
VAULT_ROOT_TOKEN="${SUPPORTED_LOCAL_VAULT_ROOT_TOKEN:-${SUPPORTED_LOCAL_VAULT_TOKEN:-}}"
VAULT_SECRET_VALUE="${SUPPORTED_LOCAL_VAULT_SECRET_VALUE:-}"
CODEX_RUNTIME_PROFILE_IMAGE="${SUPPORTED_LOCAL_CODEX_RUNTIME_PROFILE_IMAGE:-execution-substrate/control-plane-normal-shell:supported-local}"
CODEX_CLI_PATH="${SUPPORTED_LOCAL_CODEX_CLI_PATH:-/usr/local/bin/codex}"
CODEX_REALIZATION="${SUPPORTED_LOCAL_CODEX_REALIZATION:-proof}"
CODEX_CREDENTIAL_SECRET_PATH="${SUPPORTED_LOCAL_CODEX_CREDENTIAL_SECRET_PATH:-proof-secrets/data/codex-runtime-profile}"
CODEX_CREDENTIAL_SECRET_FIELD="${SUPPORTED_LOCAL_CODEX_CREDENTIAL_SECRET_FIELD:-api_key}"
CODEX_CREDENTIAL_VALUE="${SUPPORTED_LOCAL_CODEX_CREDENTIAL_VALUE:-}"
BUILD_CODEX_RUNTIME_PROFILE_IMAGE="${SUPPORTED_LOCAL_BUILD_CODEX_RUNTIME_PROFILE_IMAGE:-1}"
ALLOW_CONTROL_PLANE_CALLER="${SUPPORTED_LOCAL_ALLOW_CONTROL_PLANE:-0}"
RETAINED_RESULT_AUTH_STORE_ID="${SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_STORE_ID:-}"
RETAINED_RESULT_AUTH_KEY_ID="${SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_ID:-}"
RETAINED_RESULT_AUTH_KEY_FILE="${SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_FILE:-}"
GO_REQUIRED_VERSION="go1.26.5"

ARS_PORT=$((PORT_BASE + 2))
EGS_PORT=$((PORT_BASE + 3))
AGS_PORT=$((PORT_BASE + 4))
ES_PORT=$((PORT_BASE + 5))
SPIRE_SERVER_PORT="${SUPPORTED_LOCAL_SPIRE_SERVER_PORT:-$((PORT_BASE + 30))}"

ARS_HOST="server.artifact-registry.internal"
EGS_HOST="server.execution-governance.internal"
AGS_HOST="server.artifact-governance.internal"
ES_HOST="server.execution.internal"

usage() {
  cat <<'EOF'
Usage:
  scripts/72_supported_local_setup.sh setup

This helper prepares the repo-owned supported-local proof environment on a Linux
host/VM that already satisfies the supported-host baseline (Docker healthy,
packaged pre-managed non-dev nomad.service, natural cpu.totalcompute).

What it writes under /tmp/execution-substrate-supported-local-proof by default:
  - generated control-plane Dockerfile for guest-writable image builds
  - runtime CA and leaf certs
  - proof-scoped real SPIRE server/agent binaries, config, data, and sockets
  - SPIRE bundle-derived JWT validation material for Vault dev/test
  - ARS/EGS/AGS/ES JSON configs
  - ARS storage root plus workload-zone Vault blob
  - managed-secrets.conf for generated proof bootstrap material
  - operator env.sh for scripts/01_bringup.sh and scripts/60_execute_loop.sh
  - a proof-scoped real SPIRE Workload API Unix socket
  - a proof-scoped real Vault dev/test target for credential-flow and Codex proof material

This helper is the guest-side setup layer for the supported-local proof path.
On the current Apple Silicon Mac, the canonical proof record lives on the host
under .out/es-proof-<id>; any guest /tmp workspace is internal Lima scratch.

The SPIRE release file, downloaded or prebuilt, is unpacked only if its
SHA-256 is the one that scripts/internal/spire_release.sha256 pins for it.
A SPIRE version with no line there for any supported architecture is refused
before setup changes anything; one with no line for this host's architecture
is refused before the download.

Optional environment variables:
  SUPPORTED_LOCAL_PROOF_DIR=/abs/path
  SUPPORTED_LOCAL_PROOF_ID=<proof-id>
  SUPPORTED_LOCAL_PORT_BASE=18440
  SUPPORTED_LOCAL_RUNTIME_SUPPORT_BINARY=/abs/path/to/es-runtime-support
  SUPPORTED_LOCAL_SPIRE_VERSION=1.14.4
  SUPPORTED_LOCAL_PREBUILT_SPIRE_TARBALL=/abs/path/to/spire-linux-arm64-musl.tar.gz
  SUPPORTED_LOCAL_VAULT_ADDRESS=https://<container-reachable-host>:<port>
  SUPPORTED_LOCAL_VAULT_BIND_ADDRESS=0.0.0.0
  SUPPORTED_LOCAL_VAULT_PUBLIC_HOST=<container-reachable-host>
  SUPPORTED_LOCAL_VAULT_PORT=18460
  SUPPORTED_LOCAL_VAULT_AUTH_MOUNT=jwt
  SUPPORTED_LOCAL_VAULT_AUTH_ROLE=service_execution
  SUPPORTED_LOCAL_VAULT_JWT_AUDIENCE=vault
  SUPPORTED_LOCAL_VAULT_SECRET_PATH=proof-secrets/data/runtime-identity-vault-login
  SUPPORTED_LOCAL_VAULT_ROOT_TOKEN=<proof-root-token>
  SUPPORTED_LOCAL_CODEX_RUNTIME_PROFILE_IMAGE=execution-substrate/control-plane-normal-shell:supported-local
  SUPPORTED_LOCAL_CODEX_CLI_PATH=/usr/local/bin/codex
  SUPPORTED_LOCAL_CODEX_REALIZATION=proof
  SUPPORTED_LOCAL_CODEX_CREDENTIAL_SECRET_PATH=proof-secrets/data/codex-runtime-profile
  SUPPORTED_LOCAL_CODEX_CREDENTIAL_SECRET_FIELD=api_key
  SUPPORTED_LOCAL_CODEX_CREDENTIAL_VALUE=<proof-material>
  SUPPORTED_LOCAL_BUILD_CODEX_RUNTIME_PROFILE_IMAGE=1
  SUPPORTED_LOCAL_ALLOW_CONTROL_PLANE=1
  SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_STORE_ID=<stable non-secret identifier>
  SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_ID=<stable non-secret identifier>
  SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_FILE=/external/private/keys/key
  SUPPORTED_LOCAL_ES_ROOTS_PROFILE=service-root-v1   only accepted profile
EOF
}

require_command() {
  local name=$1
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "${name} is required" >&2
    exit 1
  fi
}

require_supported_go_toolchain() {
  local observed_version

  require_command go
  observed_version="$(env GOTOOLCHAIN=local go version 2>/dev/null | awk '{print $3}' || true)"
  if [[ "${observed_version}" != "${GO_REQUIRED_VERSION}" ]]; then
    echo "unsupported Go toolchain: expected ${GO_REQUIRED_VERSION}, observed ${observed_version:-unavailable}" >&2
    exit 1
  fi
}

supported_local_setup_requires_local_go() {
  # local-Go-required: setup always runs local Go helpers and may compile
  # es-runtime-support. Prebuilt runtime-support/SPIRE inputs bypass only their
  # own build/download steps; they are not a no-local-Go setup path.
  # prebuilt/no-local-Go: not applicable for this setup entry point.
  return 0
}

preflight_supported_local_setup_go_if_required() {
  if supported_local_setup_requires_local_go; then
    require_supported_go_toolchain
  fi
}

preflight_supported_local_setup_retained_result_auth() {
  local proof_dir="${1:-${PROOF_DIR}}"
  supported_local_validate_retained_result_auth \
    "${RETAINED_RESULT_AUTH_STORE_ID}" \
    "${RETAINED_RESULT_AUTH_KEY_ID}" \
    "${RETAINED_RESULT_AUTH_KEY_FILE}" \
    "${proof_dir}" \
    "${proof_dir}/es-staging" \
    "${proof_dir}/es-results"
}

preflight_supported_local_setup_execution_roots() {
  if [[ "${SUPPORTED_LOCAL_ES_ROOTS_PROFILE:-${ES_ROOTS_PROFILE}}" != "${ES_ROOTS_PROFILE}" ]]; then
    echo "supported-local execution-root profile is invalid" >&2
    return 1
  fi
  if [[ -n "${CONTROL_PLANE_IMAGE:-}" && "${CONTROL_PLANE_IMAGE}" != "execution-substrate/control-plane:supported-local" ]]; then
    echo "supported-local service image is incompatible" >&2
    return 1
  fi
  if [[ -n "${CONTROL_PLANE_DOCKERFILE:-}" && "${CONTROL_PLANE_DOCKERFILE}" != "${PROOF_DIR}/Dockerfile" ]]; then
    echo "supported-local service Dockerfile is incompatible" >&2
    return 1
  fi
  if ! python3 "${ES_ROOTS_HELPER}" preflight "${PROOF_DIR}" "${PROOF_ID}" >/dev/null 2>&1; then
    echo "supported-local execution-root scope is invalid" >&2
    return 1
  fi
  if (( EUID != 0 )); then
    if ! command -v sudo >/dev/null 2>&1 || ! sudo -n true >/dev/null 2>&1; then
      echo "supported-local execution-root privilege is unavailable" >&2
      return 1
    fi
  fi
}

preflight_supported_local_setup_spire_pin() {
  # The exact release file depends on the Go architecture and is looked up
  # again where it is used. Here, before any effect, refuse a SPIRE version
  # that has no pinned release file for any supported architecture.
  local arch
  for arch in amd64 arm64; do
    if spire_release_pinned_sha256 "spire-${SPIRE_VERSION}-linux-${arch}-musl.tar.gz" >/dev/null 2>&1; then
      return 0
    fi
  done
  spire_release_pinned_sha256 "spire-${SPIRE_VERSION}-linux-amd64-musl.tar.gz" >/dev/null
  return 1
}

provision_supported_local_execution_roots() {
  local binding
  if ! binding="$(python3 "${ES_ROOTS_HELPER}" bind "${PROOF_DIR}" "${PROOF_ID}" 2>/dev/null)"; then
    echo "supported-local execution roots invalid" >&2
    return 1
  fi
  if (( EUID == 0 )); then
    if ! python3 "${ES_ROOTS_HELPER}" provision "${PROOF_DIR}" "${PROOF_ID}" "${binding}" >/dev/null 2>&1; then
      echo "supported-local execution roots invalid" >&2
      return 1
    fi
  elif ! sudo -n python3 "${ES_ROOTS_HELPER}" provision "${PROOF_DIR}" "${PROOF_ID}" "${binding}" >/dev/null 2>&1; then
    echo "supported-local execution roots invalid" >&2
    return 1
  fi
}

write_supported_local_execution_root_evidence() {
  local proof_dir=$1
  if ! python3 - "${proof_dir}" >/dev/null 2>&1 <<'PY'
import json
import os
import stat
import sys

payload = (json.dumps({
    "schema": "supported-local-execution-roots-setup-safe-v1",
    "profile": "service-root-v1",
    "configured_root_uid": 0,
    "configured_root_gid": 0,
    "configured_root_mode": "0755",
    "static_root_owner_mode_checked": True,
    "operator_write_access_required": False,
    "container_identity_or_behavioral_capability_proved": False,
}, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
root_fd = os.open(sys.argv[1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    name = "execution-roots-setup-safe.json"
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=root_fd)
    try:
        os.fchmod(fd, 0o600)
        if os.write(fd, payload) != len(payload):
            raise OSError()
        os.fsync(fd)
        held = os.fstat(fd)
        visible = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        if (not stat.S_ISREG(held.st_mode) or held.st_nlink != 1 or
                stat.S_IMODE(held.st_mode) != 0o600 or held.st_size != len(payload) or
                (held.st_dev, held.st_ino, held.st_uid, held.st_gid, held.st_mode) !=
                (visible.st_dev, visible.st_ino, visible.st_uid, visible.st_gid, visible.st_mode)):
            raise OSError()
    finally:
        os.close(fd)
finally:
    os.close(root_fd)
PY
  then
    echo "supported-local execution roots invalid" >&2
    return 1
  fi
}

supported_local_setup_repair_test_sentinel() {
  if [[ "${SUPPORTED_LOCAL_REPAIR_TEST_SENTINEL:-}" == "after-go-preflight" ]]; then
    echo "supported-local setup exact Go preflight complete"
    exit 0
  fi
}

stop_background_process() {
  local pid_file=$1
  local pid=""

  if [[ -r "${pid_file}" ]]; then
    pid="$(tr -d '[:space:]' <"${pid_file}")"
  fi
  if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
    kill "${pid}" >/dev/null 2>&1 || true
    wait "${pid}" >/dev/null 2>&1 || true
  fi
}

stop_vault_dev_listener() {
  local port=$1
  local pid=""
  local args=""

  if ! command -v ss >/dev/null 2>&1; then
    return 0
  fi

  pid="$(
    ss -ltnp "( sport = :${port} )" 2>/dev/null \
      | grep -o 'pid=[0-9]*' \
      | head -n 1 \
      | cut -d= -f2 || true
  )"
  if [[ -z "${pid}" ]]; then
    return 0
  fi

  args="$(ps -p "${pid}" -o args= 2>/dev/null || true)"
  if [[ "${args}" == *"vault server"* ]] && [[ "${args}" == *"-dev"* ]]; then
    kill "${pid}" >/dev/null 2>&1 || true
    wait "${pid}" >/dev/null 2>&1 || true
  fi
}

generate_random_hex() {
  python3 - <<'PY'
import secrets
print(secrets.token_hex(16))
PY
}

make_leaf_certificate() {
  local tls_dir=$1
  local ca_cert=$2
  local ca_key=$3
  local prefix=$4
  local common_name=$5
  local san=$6

  openssl req -new -newkey rsa:2048 -nodes \
    -keyout "${tls_dir}/${prefix}-key.pem" \
    -out "${tls_dir}/${prefix}.csr" \
    -subj "/CN=${common_name}" >/dev/null 2>&1
  cat > "${tls_dir}/${prefix}.ext" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=${san}
EOF
  openssl x509 -req \
    -in "${tls_dir}/${prefix}.csr" \
    -CA "${ca_cert}" \
    -CAkey "${ca_key}" \
    -CAcreateserial \
    -out "${tls_dir}/${prefix}-cert.pem" \
    -days 30 \
    -extfile "${tls_dir}/${prefix}.ext" >/dev/null 2>&1
}

build_runtime_support_binary() {
  local output_path="${PROOF_DIR}/bin/es-runtime-support"
  local target_arch

  echo "==> building es-runtime-support to ${output_path}"
  require_supported_go_toolchain
  target_arch="$(env GOTOOLCHAIN=local go env GOARCH)"
  mkdir -p "$(dirname "${output_path}")"
  (
    cd "${REPO_ROOT}"
    env GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH="${target_arch}" go build -o "${output_path}" ./cmd/es-runtime-support
  )
  echo "==> installing es-runtime-support to ${RUNTIME_SUPPORT_INSTALL_PATH}"
  if install -m 0755 "${output_path}" "${RUNTIME_SUPPORT_INSTALL_PATH}" 2>/dev/null; then
    return 0
  fi
  require_command sudo
  sudo install -m 0755 "${output_path}" "${RUNTIME_SUPPORT_INSTALL_PATH}"
}

install_prebuilt_binary() {
  local source_path=$1
  local destination_path=$2
  local label=$3

  if [[ ! -r "${source_path}" ]]; then
    echo "${label} prebuilt binary is not readable: ${source_path}" >&2
    exit 1
  fi

  echo "==> using prebuilt ${label} binary from ${source_path}"
  mkdir -p "$(dirname "${destination_path}")"
  if install -m 0755 "${source_path}" "${destination_path}" 2>/dev/null; then
    return 0
  fi
  require_command sudo
  sudo install -m 0755 "${source_path}" "${destination_path}"
}

prepare_runtime_support_binary() {
  if [[ -n "${PREBUILT_RUNTIME_SUPPORT_BINARY}" ]]; then
    install_prebuilt_binary "${PREBUILT_RUNTIME_SUPPORT_BINARY}" "${RUNTIME_SUPPORT_INSTALL_PATH}" "es-runtime-support"
    return 0
  fi
  build_runtime_support_binary
}

build_codex_runtime_profile_image() {
  if [[ "${BUILD_CODEX_RUNTIME_PROFILE_IMAGE}" == "0" ]]; then
    echo "==> skipping Control Plane normal-shell runtime profile image build"
    return 0
  fi

  echo "==> building Control Plane normal-shell runtime profile image ${CODEX_RUNTIME_PROFILE_IMAGE}"
  CONTROL_PLANE_NORMAL_SHELL_IMAGE="${CODEX_RUNTIME_PROFILE_IMAGE}" \
  CONTROL_PLANE_NORMAL_SHELL_CODEX_CLI_PATH="${CODEX_CLI_PATH}" \
  CONTROL_PLANE_NORMAL_SHELL_CODEX_REALIZATION="${CODEX_REALIZATION}" \
    bash "${REPO_ROOT}/scripts/build_control_plane_normal_shell_image.sh" > "${PROOF_DIR}/control-plane-normal-shell-image.txt"
}

install_prebuilt_file() {
  local source_path=$1
  local destination_path=$2
  local label=$3

  if [[ ! -r "${source_path}" ]]; then
    echo "${label} prebuilt file is not readable: ${source_path}" >&2
    exit 1
  fi

  echo "==> using prebuilt ${label} from ${source_path}"
  mkdir -p "$(dirname "${destination_path}")"
  cp "${source_path}" "${destination_path}"
}

spire_release_arch() {
  local arch

  require_supported_go_toolchain
  arch="$(env GOTOOLCHAIN=local go env GOARCH)"
  case "${arch}" in
    amd64|arm64)
      printf '%s\n' "${arch}"
      ;;
    *)
      echo "unsupported SPIRE release architecture: ${arch}" >&2
      exit 1
      ;;
  esac
}

prepare_spire_distribution() {
  local tarball_path=$1
  local extract_root=$2
  local asset_arch
  local asset_name
  local download_url
  local extracted_dir

  asset_arch="$(spire_release_arch)"
  asset_name="spire-${SPIRE_VERSION}-linux-${asset_arch}-musl.tar.gz"
  download_url="https://github.com/spiffe/spire/releases/download/v${SPIRE_VERSION}/${asset_name}"

  # Only a release file with a SHA-256 pinned in
  # scripts/internal/spire_release.sha256 is used, downloaded or prebuilt.
  # The pin is looked up before the download, and the file is checked where
  # it lands, before it is unpacked.
  if ! spire_release_pinned_sha256 "${asset_name}" >/dev/null; then
    exit 1
  fi

  mkdir -p "$(dirname "${tarball_path}")"
  if [[ -n "${PREBUILT_SPIRE_TARBALL}" ]]; then
    install_prebuilt_file "${PREBUILT_SPIRE_TARBALL}" "${tarball_path}" "SPIRE distribution"
  else
    echo "==> downloading official SPIRE distribution ${SPIRE_VERSION}"
    curl -L --fail --silent --show-error -o "${tarball_path}" "${download_url}"
  fi
  chmod 600 "${tarball_path}"
  if ! spire_release_verify "${tarball_path}" "${asset_name}"; then
    rm -f -- "${tarball_path}"
    echo "refused the SPIRE distribution; nothing was unpacked" >&2
    exit 1
  fi

  rm -rf "${extract_root}"
  mkdir -p "${extract_root}"
  tar -xzf "${tarball_path}" -C "${extract_root}"

  extracted_dir="$(find "${extract_root}" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
  if [[ -z "${extracted_dir}" ]]; then
    echo "failed to unpack SPIRE distribution into ${extract_root}" >&2
    exit 1
  fi
  if [[ ! -x "${extracted_dir}/bin/spire-server" || ! -x "${extracted_dir}/bin/spire-agent" ]]; then
    echo "SPIRE distribution did not contain spire-server and spire-agent binaries" >&2
    exit 1
  fi

  install -m 0755 "${extracted_dir}/bin/spire-server" "${PROOF_DIR}/bin/spire-server"
  install -m 0755 "${extracted_dir}/bin/spire-agent" "${PROOF_DIR}/bin/spire-agent"
}

detect_docker_bridge_gateway() {
  local gateway
  gateway="$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null || true)"
  gateway="${gateway//$'\r'/}"
  gateway="${gateway//$'\n'/}"
  if [[ -z "${gateway}" ]]; then
    echo "failed to determine Docker bridge gateway for supported-local Vault dev/test reachability" >&2
    exit 1
  fi
  printf '%s\n' "${gateway}"
}

wait_for_unix_socket() {
  local socket_path=$1
  local description=$2

  for _ in $(seq 1 50); do
    if [[ -S "${socket_path}" ]]; then
      return 0
    fi
    sleep 0.1
  done

  echo "${description} did not appear at ${socket_path}" >&2
  return 1
}

wait_for_local_tcp_listener() {
  local port=$1
  local description=$2

  for _ in $(seq 1 50); do
    if python3 - <<'PY' "${port}"
import socket
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(0.2)
try:
    sock.connect(("127.0.0.1", int(sys.argv[1])))
except OSError:
    raise SystemExit(1)
finally:
    sock.close()
PY
    then
      return 0
    fi
    sleep 0.1
  done

  echo "${description} did not appear on port ${port}" >&2
  return 1
}

normalize_kv_v2_logical_path() {
  local api_path="${1#/}"
  if [[ "${api_path}" != */data/* ]]; then
    echo "SUPPORTED_LOCAL_VAULT_SECRET_PATH must be a KV v2 API path containing /data/: ${1}" >&2
    exit 1
  fi
  printf '%s/%s\n' "$(kv_v2_mount_from_api_path "${api_path}")" "${api_path#*/data/}"
}

kv_v2_mount_from_api_path() {
  local api_path="${1#/}"
  if [[ "${api_path}" != */data/* ]]; then
    echo "SUPPORTED_LOCAL_VAULT_SECRET_PATH must be a KV v2 API path containing /data/: ${1}" >&2
    exit 1
  fi
  printf '%s\n' "${api_path%%/data/*}"
}

write_spire_configs() {
  local proof_dir=$1
  local server_config="${proof_dir}/spire/server/server.conf"
  local agent_config="${proof_dir}/spire/agent/agent.conf"
  local server_socket="${proof_dir}/spire-server/private/api.sock"
  local agent_socket="${proof_dir}/spire-agent/public/api.sock"

  mkdir -p \
    "$(dirname "${server_config}")" \
    "$(dirname "${agent_config}")" \
    "$(dirname "${server_socket}")" \
    "$(dirname "${agent_socket}")" \
    "${proof_dir}/spire-data/server" \
    "${proof_dir}/spire-data/agent"

  cat > "${server_config}" <<EOF
server {
    bind_address = "127.0.0.1"
    bind_port = "${SPIRE_SERVER_PORT}"
    socket_path = "${server_socket}"
    trust_domain = "${SPIRE_TRUST_DOMAIN}"
    data_dir = "${proof_dir}/spire-data/server"
    log_level = "DEBUG"
    ca_ttl = "168h"
    default_x509_svid_ttl = "48h"
    default_jwt_svid_ttl = "15m"
    jwt_key_type = "rsa-2048"
    jwt_issuer = "${SPIRE_JWT_ISSUER}"
}

plugins {
    DataStore "sql" {
        plugin_data {
            database_type = "sqlite3"
            connection_string = "${proof_dir}/spire-data/server/datastore.sqlite3"
        }
    }

    KeyManager "disk" {
        plugin_data {
            keys_path = "${proof_dir}/spire-data/server/keys.json"
        }
    }

    NodeAttestor "join_token" {
        plugin_data {}
    }
}
EOF

  cat > "${agent_config}" <<EOF
agent {
    data_dir = "${proof_dir}/spire-data/agent"
    log_level = "DEBUG"
    trust_domain = "${SPIRE_TRUST_DOMAIN}"
    server_address = "127.0.0.1"
    server_port = "${SPIRE_SERVER_PORT}"
    socket_path = "${agent_socket}"
    insecure_bootstrap = true
}

plugins {
    KeyManager "disk" {
        plugin_data {
            directory = "${proof_dir}/spire-data/agent"
        }
    }

    NodeAttestor "join_token" {
        plugin_data {}
    }

    WorkloadAttestor "unix" {
        plugin_data {}
    }
}
EOF
}

start_spire_server() {
  local proof_dir=$1
  local log_path=$2
  local pid_path=$3
  local server_config="${proof_dir}/spire/server/server.conf"
  local server_socket="${proof_dir}/spire-server/private/api.sock"

  : > "${log_path}"
  chmod 600 "${log_path}"

  echo "==> starting proof-scoped SPIRE server"
  nohup "${proof_dir}/bin/spire-server" run -config "${server_config}" >"${log_path}" 2>&1 &
  echo "$!" > "${pid_path}"

  wait_for_unix_socket "${server_socket}" "SPIRE server admin socket"
  "${proof_dir}/bin/spire-server" healthcheck -socketPath "${server_socket}" > "${proof_dir}/spire-server-health.txt"
}

generate_spire_join_token() {
  local proof_dir=$1
  local token_output
  local join_token
  local server_socket="${proof_dir}/spire-server/private/api.sock"

  token_output="$("${proof_dir}/bin/spire-server" token generate -socketPath "${server_socket}" -spiffeID "${SPIRE_AGENT_SPIFFE_ID}")"
  printf '%s\n' "${token_output}" > "${proof_dir}/spire-join-token.txt"
  join_token="$(printf '%s\n' "${token_output}" | awk '/^Token:/ {print $2; exit}')"
  if [[ -z "${join_token}" ]]; then
    echo "failed to parse SPIRE join token output" >&2
    exit 1
  fi
  printf '%s\n' "${join_token}"
}

start_spire_agent() {
  local proof_dir=$1
  local join_token=$2
  local log_path=$3
  local pid_path=$4
  local agent_config="${proof_dir}/spire/agent/agent.conf"
  local agent_socket="${proof_dir}/spire-agent/public/api.sock"

  : > "${log_path}"
  chmod 600 "${log_path}"

  echo "==> starting proof-scoped SPIRE agent"
  nohup "${proof_dir}/bin/spire-agent" run -config "${agent_config}" -joinToken "${join_token}" >"${log_path}" 2>&1 &
  echo "$!" > "${pid_path}"

  wait_for_unix_socket "${agent_socket}" "SPIRE Workload API socket"
  "${proof_dir}/bin/spire-agent" healthcheck -socketPath "${agent_socket}" > "${proof_dir}/spire-agent-health.txt"
}

wait_for_attested_spire_agent() {
  local proof_dir=$1
  local server_socket="${proof_dir}/spire-server/private/api.sock"

  for _ in $(seq 1 50); do
    if "${proof_dir}/bin/spire-server" entry show -socketPath "${server_socket}" -spiffeID "${SPIRE_AGENT_SPIFFE_ID}" > "${proof_dir}/spire-agent-entry.txt" 2>/dev/null; then
      return 0
    fi
    sleep 0.2
  done

  echo "SPIRE agent registration entry did not appear for SPIFFE ID ${SPIRE_AGENT_SPIFFE_ID}" >&2
  return 1
}

register_spire_workload_entry() {
  local proof_dir=$1
  local server_socket="${proof_dir}/spire-server/private/api.sock"

  echo "==> registering proof-scoped SPIRE workload entry"
  "${proof_dir}/bin/spire-server" entry create \
    -socketPath "${server_socket}" \
    -parentID "${SPIRE_AGENT_SPIFFE_ID}" \
    -spiffeID "${WORKLOAD_SPIFFE_ID}" \
    -selector unix:uid:0 \
    -selector unix:gid:0 > "${proof_dir}/spire-workload-entry-create.txt"
  "${proof_dir}/bin/spire-server" entry show \
    -socketPath "${server_socket}" \
    -spiffeID "${WORKLOAD_SPIFFE_ID}" > "${proof_dir}/spire-workload-entry.txt"
}

write_spire_bundle_artifacts() {
  local proof_dir=$1
  local bundle_path="${proof_dir}/spire-bundle.spiffe.json"
  local output_path="${proof_dir}/tls/spire-jwt-validation-pub.pem"
  local helper_source="${proof_dir}/spire/extract_spire_jwt_pubkey.go"
  local server_socket="${proof_dir}/spire-server/private/api.sock"

  echo "==> writing proof-scoped SPIRE bundle and JWT validation key"
  "${proof_dir}/bin/spire-server" bundle show -format spiffe -socketPath "${server_socket}" > "${bundle_path}"

  cat > "${helper_source}" <<'EOF'
package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
)

type bundle struct {
	Keys []jwk `json:"keys"`
}

type bundleMap struct {
	TrustDomains map[string]bundle `json:"trust_domains"`
}

type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: extract_spire_jwt_pubkey <bundle.json> <output.pem>")
		os.Exit(1)
	}

	input, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "read bundle: %v\n", err)
		os.Exit(1)
	}

	if tryDirectBundle(input, os.Args[2]) == nil {
		return
	}
	if err := tryBundleMap(input, os.Args[2]); err != nil {
		fmt.Fprintf(os.Stderr, "extract jwt validation public key: %v\n", err)
		os.Exit(1)
	}
}

func tryDirectBundle(input []byte, outputPath string) error {
	var direct bundle
	if err := json.Unmarshal(input, &direct); err != nil {
		return err
	}
	return writeJWTKey(direct.Keys, outputPath)
}

func tryBundleMap(input []byte, outputPath string) error {
	var mapped bundleMap
	if err := json.Unmarshal(input, &mapped); err != nil {
		return err
	}
	for _, item := range mapped.TrustDomains {
		if err := writeJWTKey(item.Keys, outputPath); err == nil {
			return nil
		}
	}
	return fmt.Errorf("no jwt-svid rsa key found in bundle data")
}

func writeJWTKey(keys []jwk, outputPath string) error {
	for _, key := range keys {
		if key.Use != "jwt-svid" || key.Kty != "RSA" {
			continue
		}
		modulusBytes, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			return fmt.Errorf("decode jwk modulus: %w", err)
		}
		exponentBytes, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			return fmt.Errorf("decode jwk exponent: %w", err)
		}
		exponent := 0
		for _, b := range exponentBytes {
			exponent = (exponent << 8) | int(b)
		}
		publicKey := &rsa.PublicKey{
			N: new(big.Int).SetBytes(modulusBytes),
			E: exponent,
		}
		der, err := x509.MarshalPKIXPublicKey(publicKey)
		if err != nil {
			return fmt.Errorf("marshal pkix public key: %w", err)
		}
		file, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer file.Close()
		if err := pem.Encode(file, &pem.Block{Type: "PUBLIC KEY", Bytes: der}); err != nil {
			return fmt.Errorf("encode pem: %w", err)
		}
		if err := file.Chmod(0o600); err != nil {
			return fmt.Errorf("chmod output file: %w", err)
		}
		return nil
	}
	return fmt.Errorf("no jwt-svid rsa key found")
}
EOF

  require_supported_go_toolchain
  env GOTOOLCHAIN=local go run "${helper_source}" "${bundle_path}" "${output_path}"
}

write_managed_secrets_file() {
  local path=$1
  local vault_address=$2
  local vault_local_address=$3
  local vault_public_host=$4
  local vault_port=$5
  local vault_root_token=$6
  local vault_secret_value=$7
  local vault_secret_mount=$8
  local vault_secret_logical_path=$9
  local codex_runtime_profile_image=${10}
  local codex_cli_path=${11}
  local codex_realization=${12}
  local codex_credential_secret_path=${13}
  local codex_credential_secret_field=${14}
  local codex_credential_value=${15}

  cat > "${path}" <<EOF
SUPPORTED_LOCAL_PROOF_ID="${PROOF_ID}"
PROOF_RUNTIME_SUPPORT_BINARY="${RUNTIME_SUPPORT_INSTALL_PATH}"
PROOF_VAULT_BIND_ADDRESS="${VAULT_BIND_ADDRESS}"
PROOF_VAULT_PUBLIC_HOST="${vault_public_host}"
PROOF_VAULT_PORT="${vault_port}"
PROOF_VAULT_ADDR="${vault_address}"
PROOF_VAULT_LOCAL_ADDR="${vault_local_address}"
PROOF_VAULT_AUTH_MOUNT="${VAULT_AUTH_MOUNT}"
PROOF_VAULT_AUTH_ROLE="${VAULT_AUTH_ROLE}"
PROOF_VAULT_BOUND_AUDIENCE="${VAULT_JWT_AUDIENCE}"
PROOF_VAULT_BOUND_SUBJECT="${WORKLOAD_SPIFFE_ID}"
PROOF_VAULT_BOUND_ISSUER="${SPIRE_JWT_ISSUER}"
PROOF_VAULT_SECRET_PATH="${VAULT_SECRET_PATH}"
PROOF_VAULT_SECRET_MOUNT="${vault_secret_mount}"
PROOF_VAULT_SECRET_LOGICAL_PATH="${vault_secret_logical_path}"
PROOF_VAULT_SECRET_VALUE="${vault_secret_value}"
PROOF_VAULT_ROOT_TOKEN="${vault_root_token}"
PROOF_CODEX_RUNTIME_PROFILE_IMAGE="${codex_runtime_profile_image}"
PROOF_CODEX_CLI_PATH="${codex_cli_path}"
PROOF_CODEX_REALIZATION="${codex_realization}"
PROOF_CODEX_CREDENTIAL_SECRET_PATH="${codex_credential_secret_path}"
PROOF_CODEX_CREDENTIAL_SECRET_FIELD="${codex_credential_secret_field}"
PROOF_CODEX_CREDENTIAL_VALUE="${codex_credential_value}"
PROOF_VAULT_CA_CERT_FILE="${PROOF_DIR}/tls/vault-dev/vault-ca.pem"
PROOF_VAULT_SERVER_CERT_FILE="${PROOF_DIR}/tls/vault-dev/vault-cert.pem"
PROOF_VAULT_SERVER_KEY_FILE="${PROOF_DIR}/tls/vault-dev/vault-key.pem"
PROOF_SPIRE_VERSION="${SPIRE_VERSION}"
PROOF_SPIRE_TRUST_DOMAIN="${SPIRE_TRUST_DOMAIN}"
PROOF_SPIRE_JWT_ISSUER="${SPIRE_JWT_ISSUER}"
PROOF_SPIRE_AGENT_SPIFFE_ID="${SPIRE_AGENT_SPIFFE_ID}"
PROOF_SPIRE_SERVER_SOCKET_PATH="${PROOF_DIR}/spire-server/private/api.sock"
PROOF_SPIRE_AGENT_SOCKET_PATH="${PROOF_DIR}/spire-agent/public/api.sock"
PROOF_SPIRE_BUNDLE_FILE="${PROOF_DIR}/spire-bundle.spiffe.json"
PROOF_SPIRE_JWT_VALIDATION_PUB_FILE="${PROOF_DIR}/tls/spire-jwt-validation-pub.pem"
EOF
  chmod 600 "${path}"
}

vault_with_proof_env() {
  local proof_dir=$1
  local vault_local_address=$2
  local vault_root_token=$3
  shift 3

  VAULT_ADDR="${vault_local_address}" \
  VAULT_CACERT="${proof_dir}/tls/vault-dev/vault-ca.pem" \
  VAULT_TOKEN="${vault_root_token}" \
  vault "$@"
}

proof_vault_api_read() {
  local proof_dir=$1
  local vault_local_address=$2
  local vault_root_token=$3
  local api_path=$4

  curl --fail-with-body --silent --show-error \
    --cacert "${proof_dir}/tls/vault-dev/vault-ca.pem" \
    -H "X-Vault-Token: ${vault_root_token}" \
    "${vault_local_address}/v1/${api_path#/}"
}

ensure_vault_auth_mount() {
  local proof_dir=$1
  local vault_local_address=$2
  local vault_root_token=$3
  local auth_mount=$4
  local auth_type=$5
  local auth_state=""
  local auth_json=""

  auth_json="$(proof_vault_api_read "${proof_dir}" "${vault_local_address}" "${vault_root_token}" sys/auth)"
  auth_state="$(
      python3 - <<'PY' "${auth_mount}" "${auth_type}" "${auth_json}"
import json
import sys

mount = sys.argv[1].strip("/") + "/"
want_type = sys.argv[2].strip()
entry = (json.loads(sys.argv[3]).get("data") or {}).get(mount)
if entry is None:
    print("missing")
else:
    got_type = (entry.get("type") or "").strip()
    if got_type != want_type:
        print(f"wrong-type:{got_type}")
    else:
        print("ok")
PY
  )"

  case "${auth_state}" in
    missing)
      echo "==> enabling proof-scoped Vault auth mount ${auth_mount}/ (${auth_type})"
      vault_with_proof_env "${proof_dir}" "${vault_local_address}" "${vault_root_token}" auth enable -path="${auth_mount}" "${auth_type}" >/dev/null
      ;;
    ok)
      echo "==> verified proof-scoped Vault auth mount ${auth_mount}/ (${auth_type})"
      ;;
    wrong-type:*)
      echo "proof Vault auth mount ${auth_mount}/ exists with unexpected type ${auth_state#wrong-type:}" >&2
      exit 1
      ;;
    *)
      echo "unexpected Vault auth mount state for ${auth_mount}/: ${auth_state}" >&2
      exit 1
      ;;
  esac
}

ensure_vault_kv_v2_mount() {
  local proof_dir=$1
  local vault_local_address=$2
  local vault_root_token=$3
  local vault_secret_api_path=$4
  local vault_secret_mount=""
  local mount_state=""
  local mounts_json=""

  vault_secret_mount="$(kv_v2_mount_from_api_path "${vault_secret_api_path}")"
  mounts_json="$(proof_vault_api_read "${proof_dir}" "${vault_local_address}" "${vault_root_token}" sys/mounts)"
  mount_state="$(
      python3 - <<'PY' "${vault_secret_mount}" "${mounts_json}"
import json
import sys

mount = sys.argv[1].strip("/") + "/"
entry = (json.loads(sys.argv[2]).get("data") or {}).get(mount)
if entry is None:
    print("missing")
else:
    got_type = (entry.get("type") or "").strip()
    version = ((entry.get("options") or {}).get("version") or "").strip()
    if got_type != "kv":
        print(f"wrong-type:{got_type}")
    elif version != "2":
        print(f"wrong-version:{version or '<empty>'}")
    else:
        print("ok")
PY
  )"

  case "${mount_state}" in
    missing)
      echo "==> enabling proof-scoped Vault KV v2 mount ${vault_secret_mount}/"
      vault_with_proof_env "${proof_dir}" "${vault_local_address}" "${vault_root_token}" secrets enable -path="${vault_secret_mount}" -version=2 kv >/dev/null
      ;;
    ok)
      echo "==> verified proof-scoped Vault KV v2 mount ${vault_secret_mount}/"
      ;;
    wrong-type:*)
      echo "proof Vault secret mount ${vault_secret_mount}/ exists with unexpected type ${mount_state#wrong-type:}" >&2
      exit 1
      ;;
    wrong-version:*)
      echo "proof Vault secret mount ${vault_secret_mount}/ exists without KV v2 versioning (${mount_state#wrong-version:})" >&2
      exit 1
      ;;
    *)
      echo "unexpected Vault secrets mount state for ${vault_secret_mount}/: ${mount_state}" >&2
      exit 1
      ;;
  esac
}

start_vault_dev_server() {
  local log_path=$1
  local pid_path=$2
  local vault_root_token=$3
  local vault_public_host=$4
  local cert_dir="${PROOF_DIR}/tls/vault-dev"

  mkdir -p "${cert_dir}"
  : > "${log_path}"
  chmod 600 "${log_path}"

  echo "==> starting proof-scoped Vault dev/test target"
  nohup vault server \
    -dev \
    -dev-tls \
    -dev-no-store-token \
    -dev-root-token-id="${vault_root_token}" \
    -dev-listen-address="${VAULT_BIND_ADDRESS}:${VAULT_PORT}" \
    -dev-tls-cert-dir="${cert_dir}" \
    -dev-tls-san="${vault_public_host}" \
    -dev-cluster-json="${PROOF_DIR}/vault-dev-cluster.json" >"${log_path}" 2>&1 &
  echo "$!" > "${pid_path}"

  wait_for_local_tcp_listener "${VAULT_PORT}" "Vault dev/test HTTPS listener"
}

configure_vault_dev_target() {
  local proof_dir=$1
  local vault_local_address=$2
  local vault_root_token=$3
  local vault_secret_value=$4
  local codex_secret_path=$5
  local codex_secret_field=$6
  local codex_secret_value=$7
  local policy_path="${proof_dir}/vault/runtime-identity-proof.hcl"
  local vault_secret_logical_path
  local codex_secret_logical_path

  vault_secret_logical_path="$(normalize_kv_v2_logical_path "${VAULT_SECRET_PATH}")"
  codex_secret_logical_path="$(normalize_kv_v2_logical_path "${codex_secret_path}")"
  mkdir -p "$(dirname "${policy_path}")"
  cat > "${policy_path}" <<EOF
path "${VAULT_SECRET_PATH#/}" {
  capabilities = ["read"]
}

path "${codex_secret_path#/}" {
  capabilities = ["read"]
}
EOF

  echo "==> configuring proof-scoped Vault JWT auth, KV v2 mounts, and secrets"
  ensure_vault_auth_mount "${proof_dir}" "${vault_local_address}" "${vault_root_token}" "${VAULT_AUTH_MOUNT}" jwt
  ensure_vault_kv_v2_mount "${proof_dir}" "${vault_local_address}" "${vault_root_token}" "${VAULT_SECRET_PATH}"
  ensure_vault_kv_v2_mount "${proof_dir}" "${vault_local_address}" "${vault_root_token}" "${codex_secret_path}"

  vault_with_proof_env "${proof_dir}" "${vault_local_address}" "${vault_root_token}" policy write runtime-identity-proof "${policy_path}" >/dev/null

  vault_with_proof_env "${proof_dir}" "${vault_local_address}" "${vault_root_token}" write "auth/${VAULT_AUTH_MOUNT}/config" \
    jwt_validation_pubkeys=@"${proof_dir}/tls/spire-jwt-validation-pub.pem" \
    bound_issuer="${SPIRE_JWT_ISSUER}" >/dev/null

  vault_with_proof_env "${proof_dir}" "${vault_local_address}" "${vault_root_token}" write "auth/${VAULT_AUTH_MOUNT}/role/${VAULT_AUTH_ROLE}" \
    role_type=jwt \
    user_claim=sub \
    bound_audiences="${VAULT_JWT_AUDIENCE}" \
    bound_subject="${WORKLOAD_SPIFFE_ID}" \
    token_policies=runtime-identity-proof >/dev/null

  vault_with_proof_env "${proof_dir}" "${vault_local_address}" "${vault_root_token}" kv put "${vault_secret_logical_path}" message="${vault_secret_value}" >/dev/null
  vault_with_proof_env "${proof_dir}" "${vault_local_address}" "${vault_root_token}" kv put "${codex_secret_logical_path}" "${codex_secret_field}=${codex_secret_value}" >/dev/null
}

write_runtime_blob_and_configs() {
  local proof_dir=$1
  local vault_address=$2
  local vault_auth_mount=$3
  local vault_auth_role=$4
  local vault_jwt_audience=$5
  local codex_runtime_profile_image=$6
  local codex_cli_path=$7
  local codex_credential_secret_path=$8
  local codex_credential_secret_field=$9
  local tls_dir="${proof_dir}/tls"
  local ars_storage="${proof_dir}/ars-storage"
  local index_path="${proof_dir}/artifact-index.json"
  local staging_root="${proof_dir}/es-staging"
  local results_root="${proof_dir}/es-results"
  local socket_path="${proof_dir}/spire-agent/public/api.sock"
  local digest_file="${proof_dir}/workload-zone-vault-config-digest.txt"

  preflight_supported_local_setup_retained_result_auth "${proof_dir}"

  python3 - <<'PY' \
    "${proof_dir}" \
    "${tls_dir}" \
    "${ars_storage}" \
    "${index_path}" \
    "${staging_root}" \
    "${results_root}" \
    "${socket_path}" \
    "${digest_file}" \
    "${RUNTIME_SUPPORT_INSTALL_PATH}" \
    "${vault_address}" \
    "${vault_auth_mount}" \
    "${vault_auth_role}" \
    "${vault_jwt_audience}" \
    "${codex_runtime_profile_image}" \
    "${codex_cli_path}" \
    "${codex_credential_secret_path}" \
    "${codex_credential_secret_field}" \
    "${ARS_PORT}" \
    "${EGS_PORT}" \
    "${AGS_PORT}" \
    "${ES_PORT}" \
    "${ARS_HOST}" \
    "${EGS_HOST}" \
    "${AGS_HOST}" \
    "${ES_HOST}" \
    "${RETAINED_RESULT_AUTH_STORE_ID}" \
    "${RETAINED_RESULT_AUTH_KEY_ID}" \
    "${RETAINED_RESULT_AUTH_KEY_FILE}"
import hashlib
import json
import os
import pathlib
import sys

proof_dir = pathlib.Path(sys.argv[1])
tls_dir = pathlib.Path(sys.argv[2])
ars_storage = pathlib.Path(sys.argv[3])
index_path = pathlib.Path(sys.argv[4])
staging_root = pathlib.Path(sys.argv[5])
results_root = pathlib.Path(sys.argv[6])
socket_path = pathlib.Path(sys.argv[7])
digest_file = pathlib.Path(sys.argv[8])
runtime_support_binary = sys.argv[9]
vault_address = sys.argv[10]
vault_auth_mount = sys.argv[11]
vault_auth_role = sys.argv[12]
vault_jwt_audience = sys.argv[13]
codex_runtime_profile_image = sys.argv[14]
codex_cli_path = sys.argv[15]
codex_credential_secret_path = sys.argv[16]
codex_credential_secret_field = sys.argv[17]
ars_port = int(sys.argv[18])
egs_port = int(sys.argv[19])
ags_port = int(sys.argv[20])
es_port = int(sys.argv[21])
ars_host = sys.argv[22]
egs_host = sys.argv[23]
ags_host = sys.argv[24]
es_host = sys.argv[25]
result_auth_store_id = sys.argv[26]
result_auth_key_id = sys.argv[27]
result_auth_key_file = sys.argv[28]
allow_control_plane = os.environ.get("SUPPORTED_LOCAL_ALLOW_CONTROL_PLANE", "0").strip().lower() in {"1", "true", "yes"}
operator_and_maybe_control_plane = ["operator/local"]
if allow_control_plane:
    operator_and_maybe_control_plane.append("service/control-plane")

blob = {
    "vault_config": {
        "address": vault_address,
        "auth_mount": vault_auth_mount,
        "auth_role": vault_auth_role,
        "jwt_audience": vault_jwt_audience,
        "ca_bundle_pem": (proof_dir / "tls" / "vault-dev" / "vault-ca.pem").read_text(encoding="utf-8"),
    }
}
blob_bytes = (json.dumps(blob, separators=(",", ":")) + "\n").encode("utf-8")
digest = "sha256:" + hashlib.sha256(blob_bytes).hexdigest()
blob_path = ars_storage / "sha256" / digest[7:9] / digest[9:11] / digest
blob_path.parent.mkdir(parents=True, exist_ok=True)
blob_path.write_bytes(blob_bytes)
digest_file.write_text(digest + "\n", encoding="utf-8")
index_path.write_text("{}\n", encoding="utf-8")
# The renderer serializes the two roots already provisioned by setup. It does
# not create, adopt, or normalize execution state.

ars_cfg = {
    "http": {"bind_address": "127.0.0.1", "port": ars_port, "read_timeout_seconds": 5, "write_timeout_seconds": 5, "shutdown_timeout_seconds": 5},
    "tls": {
        "cert_file": str(tls_dir / "ars-server-cert.pem"),
        "key_file": str(tls_dir / "ars-server-key.pem"),
        "client_ca_file": str(tls_dir / "runtime-ca.pem"),
    },
    "security": {"bootstrap_issuer_common_name": "Bootstrap Root CA Example"},
    "authorization": {"allowed_spiffe_path_prefixes": ["service/execution", "service/artifact-governance", "operator/local"]},
    "storage": {"root_dir": str(ars_storage), "index_file": str(index_path)},
}
egs_cfg = {
    "http": {"bind_address": "127.0.0.1", "port": egs_port, "read_timeout_seconds": 5, "write_timeout_seconds": 5, "shutdown_timeout_seconds": 5},
    "tls": {
        "cert_file": str(tls_dir / "egs-server-cert.pem"),
        "key_file": str(tls_dir / "egs-server-key.pem"),
        "client_ca_file": str(tls_dir / "runtime-ca.pem"),
    },
    "security": {"bootstrap_issuer_common_name": "Bootstrap Root CA Example"},
    "signer": {
        "algorithm": "ed25519",
        "key_id": "egs-key-1",
        "private_key_hex": "3333333333333333333333333333333333333333333333333333333333333333",
        "public_key_hex": "17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce",
    },
    "runtime_trust": {
        "signer_policy": {"allowed_signers": ["ags-key-1"], "revoked_signers": []},
        "artifact_policy": {"revoked_artifacts": []},
    },
    "publication": {"update_revision": 1, "version": "v1"},
}
ags_cfg = {
    "http": {"bind_address": "127.0.0.1", "port": ags_port, "read_timeout_seconds": 5, "write_timeout_seconds": 5, "shutdown_timeout_seconds": 5},
    "tls": {
        "cert_file": str(tls_dir / "ags-server-cert.pem"),
        "key_file": str(tls_dir / "ags-server-key.pem"),
        "client_ca_file": str(tls_dir / "runtime-ca.pem"),
    },
    "security": {"bootstrap_issuer_common_name": "Bootstrap Root CA Example"},
    "authorization": {"allowed_spiffe_path_prefixes": operator_and_maybe_control_plane},
    "dependencies": {
        "artifact_registry": {
            "base_url": f"https://127.0.0.1:{ars_port}",
            "server_name": ars_host,
            "client_cert_file": str(tls_dir / "ags-client-cert.pem"),
            "client_key_file": str(tls_dir / "ags-client-key.pem"),
            "root_ca_file": str(tls_dir / "runtime-ca.pem"),
            "timeout_seconds": 5,
        }
    },
    "signer": {
        "algorithm": "ed25519",
        "key_id": "ags-key-1",
        "private_key_hex": "1111111111111111111111111111111111111111111111111111111111111111",
        "public_key_hex": "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
    },
}
es_cfg = {
    "http": {"bind_address": "127.0.0.1", "port": es_port, "read_timeout_seconds": 5, "write_timeout_seconds": 5, "shutdown_timeout_seconds": 5},
    "tls": {
        "cert_file": str(tls_dir / "es-server-cert.pem"),
        "key_file": str(tls_dir / "es-server-key.pem"),
        "client_ca_file": str(tls_dir / "runtime-ca.pem"),
    },
    "security": {"bootstrap_issuer_common_name": "Bootstrap Root CA Example"},
    "authorization": {"allowed_spiffe_path_prefixes": operator_and_maybe_control_plane},
    "dependencies": {
        "artifact_registry": {
            "base_url": f"https://127.0.0.1:{ars_port}",
            "server_name": ars_host,
            "client_cert_file": str(tls_dir / "execution-client-cert.pem"),
            "client_key_file": str(tls_dir / "execution-client-key.pem"),
            "root_ca_file": str(tls_dir / "runtime-ca.pem"),
            "timeout_seconds": 5,
        },
        "execution_governance": {
            "base_url": f"https://127.0.0.1:{egs_port}",
            "server_name": egs_host,
            "client_cert_file": str(tls_dir / "execution-client-cert.pem"),
            "client_key_file": str(tls_dir / "execution-client-key.pem"),
            "root_ca_file": str(tls_dir / "runtime-ca.pem"),
            "timeout_seconds": 5,
        },
    },
    "runtime_config": {"workload_zone_vault_config_ref": {"digest": digest}},
    "verification": {
        "trust_model": {"algorithm": "ed25519", "key_id": "egs-key-1", "public_key_hex": "17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce"},
        "provenance": {"algorithm": "ed25519", "key_id": "ags-key-1", "public_key_hex": "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"},
        "derivation_attestation": {"algorithm": "ed25519", "key_id": "ags-key-1", "public_key_hex": "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"},
        "workload_identity_binding": {"algorithm": "ed25519", "key_id": "ags-key-1", "public_key_hex": "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"},
    },
    "workload_vault_auth": {"default_mode": "vault_identity_jwt"},
    "nomad": {"base_url": "http://127.0.0.1:4646", "datacenter": "dc1", "timeout_seconds": 5},
    "execution": {
        "staging_root_dir": str(staging_root),
        "results_root_dir": str(results_root),
        "retained_result_auth": {
            "store_id": result_auth_store_id,
            "key_id": result_auth_key_id,
            "key_file": result_auth_key_file,
        },
        "base_image": "python:3.13-alpine",
        "runtime_support_binary": runtime_support_binary,
        "spire_workload_api_socket_path": str(socket_path),
        "runtime_profiles": {
            "control_plane_normal_shell": {
                "enabled": True,
                "image": codex_runtime_profile_image,
                "codex_cli_path": codex_cli_path,
                "credential_vault_secret_path": codex_credential_secret_path,
                "credential_vault_secret_field": codex_credential_secret_field,
            }
        },
    },
}

for name, payload in (
    ("ars.json", ars_cfg),
    ("egs.json", egs_cfg),
    ("ags.json", ags_cfg),
    ("es.json", es_cfg),
):
    (proof_dir / name).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

write_env_file() {
  local env_path=$1

  cat > "${env_path}" <<EOF
export SUPPORTED_LOCAL_PROOF_ID="${PROOF_ID}"
export SUPPORTED_LOCAL_PROOF_DIR="${PROOF_DIR}"
export SUPPORTED_LOCAL_ES_ROOTS_PROFILE="${ES_ROOTS_PROFILE}"
export SUPPORTED_LOCAL_MANAGED_SECRETS="${PROOF_DIR}/managed-secrets.conf"
export BRINGUP_DIR="${PROOF_DIR}/bringup-state"
export READY_TIMEOUT_SECONDS=60
export CONTROL_PLANE_IMAGE="execution-substrate/control-plane:supported-local"
export CONTROL_PLANE_DOCKERFILE="${PROOF_DIR}/Dockerfile"
export ARS_CONFIG="${PROOF_DIR}/ars.json"
export EGS_CONFIG="${PROOF_DIR}/egs.json"
export AGS_CONFIG="${PROOF_DIR}/ags.json"
export ES_CONFIG="${PROOF_DIR}/es.json"
export ARS_URL="https://${ARS_HOST}:${ARS_PORT}"
export EGS_URL="https://${EGS_HOST}:${EGS_PORT}"
export AGS_URL="https://${AGS_HOST}:${AGS_PORT}"
export ES_URL="https://${ES_HOST}:${ES_PORT}"
export NOMAD_ADDR="http://127.0.0.1:4646"
export ARS_RESOLVE="${ARS_HOST}:${ARS_PORT}:127.0.0.1"
export EGS_RESOLVE="${EGS_HOST}:${EGS_PORT}:127.0.0.1"
export AGS_RESOLVE="${AGS_HOST}:${AGS_PORT}:127.0.0.1"
export ES_RESOLVE="${ES_HOST}:${ES_PORT}:127.0.0.1"
export CA_CERT="${PROOF_DIR}/tls/runtime-ca.pem"
export OPERATOR_CERT="${PROOF_DIR}/tls/operator-client-cert.pem"
export OPERATOR_KEY="${PROOF_DIR}/tls/operator-client-key.pem"
export ARS_READ_CERT="${PROOF_DIR}/tls/execution-client-cert.pem"
export ARS_READ_KEY="${PROOF_DIR}/tls/execution-client-key.pem"
export WORKDIR_BASE="${PROOF_DIR}/workdirs"
EOF

  if [[ "${ALLOW_CONTROL_PLANE_CALLER}" == "1" ]]; then
    cat >> "${env_path}" <<EOF
export CONTROL_PLANE_CERT="${PROOF_DIR}/tls/control-plane-client-cert.pem"
export CONTROL_PLANE_KEY="${PROOF_DIR}/tls/control-plane-client-key.pem"
EOF
  fi
}

setup() {
  require_command openssl
  require_command python3
  require_command curl
  require_command tar
  require_command vault
  require_command docker
  require_command nomad

  if [[ "$(uname -s)" != "Linux" ]]; then
    echo "scripts/72_supported_local_setup.sh must run on the Linux host/VM that will run Docker and Nomad" >&2
    exit 1
  fi
  if [[ -z "${PROOF_DIR}" || "${PROOF_DIR}" == "/" ]]; then
    echo "SUPPORTED_LOCAL_PROOF_DIR is unsafe" >&2
    exit 1
  fi

  # Exact Go preflight for local-Go-required setup paths must precede proof/process/workspace mutation.
  preflight_supported_local_setup_go_if_required
  supported_local_setup_repair_test_sentinel
  preflight_supported_local_setup_retained_result_auth
  preflight_supported_local_setup_execution_roots
  preflight_supported_local_setup_spire_pin

  local vault_public_host
  local vault_address
  local vault_local_address
  local vault_root_token
  local vault_secret_value
  local vault_secret_mount
  local vault_secret_logical_path
  local codex_credential_value

  vault_public_host="${VAULT_PUBLIC_HOST}"
  if [[ -z "${vault_public_host}" ]]; then
    vault_public_host="$(detect_docker_bridge_gateway)"
  fi
  vault_address="${VAULT_ADDRESS}"
  if [[ -z "${vault_address}" ]]; then
    vault_address="https://${vault_public_host}:${VAULT_PORT}"
  fi
  vault_local_address="https://127.0.0.1:${VAULT_PORT}"
  vault_root_token="${VAULT_ROOT_TOKEN}"
  if [[ -z "${vault_root_token}" ]]; then
    vault_root_token="$(generate_random_hex)"
  fi
  vault_secret_value="${VAULT_SECRET_VALUE}"
  if [[ -z "${vault_secret_value}" ]]; then
    vault_secret_value="runtime-identity-ok-${PROOF_ID}"
  fi
  codex_credential_value="${CODEX_CREDENTIAL_VALUE}"
  if [[ -z "${codex_credential_value}" ]]; then
    codex_credential_value="codex-runtime-profile-ok-${PROOF_ID}"
  fi
  vault_secret_mount="$(kv_v2_mount_from_api_path "${VAULT_SECRET_PATH}")"
  vault_secret_logical_path="$(normalize_kv_v2_logical_path "${VAULT_SECRET_PATH}")"

  stop_background_process "${PROOF_DIR}/spire-agent.pid"
  stop_background_process "${PROOF_DIR}/spire-server.pid"
  stop_background_process "${PROOF_DIR}/vault-dev.pid"
  stop_vault_dev_listener "${VAULT_PORT}"
  # This setup selects a fresh proof root; retained failed roots belong to the
  # wrapper's separately bounded cleanup, not an in-place owner migration.
  mkdir -- "${PROOF_DIR}"
  mkdir -p "${PROOF_DIR}/tls" "${PROOF_DIR}/ars-storage" "${PROOF_DIR}/bin" "${PROOF_DIR}/logs" "${PROOF_DIR}/workdirs" "${PROOF_DIR}/downloads" "${PROOF_DIR}/spire"
  provision_supported_local_execution_roots

  build_codex_runtime_profile_image
  prepare_runtime_support_binary
  prepare_spire_distribution "${PROOF_DIR}/downloads/spire.tar.gz" "${PROOF_DIR}/spire/dist"

  echo "==> generating guest-writable control-plane Dockerfile"
  bash "${REPO_ROOT}/scripts/generate_control_plane_dockerfile.sh" "${PROOF_DIR}/Dockerfile" >/dev/null

  echo "==> generating runtime CA and leaf certificates"
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "${PROOF_DIR}/tls/runtime-ca-key.pem" \
    -out "${PROOF_DIR}/tls/runtime-ca.pem" \
    -subj '/CN=Runtime Root CA Example' \
    -days 30 >/dev/null 2>&1

  make_leaf_certificate "${PROOF_DIR}/tls" "${PROOF_DIR}/tls/runtime-ca.pem" "${PROOF_DIR}/tls/runtime-ca-key.pem" "ars-server" "${ARS_HOST}" "DNS:${ARS_HOST}"
  make_leaf_certificate "${PROOF_DIR}/tls" "${PROOF_DIR}/tls/runtime-ca.pem" "${PROOF_DIR}/tls/runtime-ca-key.pem" "egs-server" "${EGS_HOST}" "DNS:${EGS_HOST}"
  make_leaf_certificate "${PROOF_DIR}/tls" "${PROOF_DIR}/tls/runtime-ca.pem" "${PROOF_DIR}/tls/runtime-ca-key.pem" "ags-server" "${AGS_HOST}" "DNS:${AGS_HOST}"
  make_leaf_certificate "${PROOF_DIR}/tls" "${PROOF_DIR}/tls/runtime-ca.pem" "${PROOF_DIR}/tls/runtime-ca-key.pem" "es-server" "${ES_HOST}" "DNS:${ES_HOST}"
  make_leaf_certificate "${PROOF_DIR}/tls" "${PROOF_DIR}/tls/runtime-ca.pem" "${PROOF_DIR}/tls/runtime-ca-key.pem" "execution-client" "client.execution" "DNS:client.execution,URI:spiffe://execution.internal/service/execution"
  make_leaf_certificate "${PROOF_DIR}/tls" "${PROOF_DIR}/tls/runtime-ca.pem" "${PROOF_DIR}/tls/runtime-ca-key.pem" "ags-client" "client.artifact-governance" "DNS:client.artifact-governance,URI:spiffe://execution.internal/service/artifact-governance"
  make_leaf_certificate "${PROOF_DIR}/tls" "${PROOF_DIR}/tls/runtime-ca.pem" "${PROOF_DIR}/tls/runtime-ca-key.pem" "operator-client" "client.operator" "DNS:client.operator,URI:spiffe://execution.internal/operator/local"
  if [[ "${ALLOW_CONTROL_PLANE_CALLER}" == "1" ]]; then
    make_leaf_certificate "${PROOF_DIR}/tls" "${PROOF_DIR}/tls/runtime-ca.pem" "${PROOF_DIR}/tls/runtime-ca-key.pem" "control-plane-client" "client.control-plane" "DNS:client.control-plane,URI:spiffe://execution.internal/service/control-plane"
  fi
  chmod 600 "${PROOF_DIR}/tls/runtime-ca-key.pem"

  write_spire_configs "${PROOF_DIR}"
  start_spire_server "${PROOF_DIR}" "${PROOF_DIR}/logs/spire-server.log" "${PROOF_DIR}/spire-server.pid"
  start_spire_agent "${PROOF_DIR}" "$(generate_spire_join_token "${PROOF_DIR}")" "${PROOF_DIR}/logs/spire-agent.log" "${PROOF_DIR}/spire-agent.pid"
  wait_for_attested_spire_agent "${PROOF_DIR}"
  register_spire_workload_entry "${PROOF_DIR}"
  write_spire_bundle_artifacts "${PROOF_DIR}"
  start_vault_dev_server "${PROOF_DIR}/logs/vault-dev.log" "${PROOF_DIR}/vault-dev.pid" "${vault_root_token}" "${vault_public_host}"
  configure_vault_dev_target \
    "${PROOF_DIR}" \
    "${vault_local_address}" \
    "${vault_root_token}" \
    "${vault_secret_value}" \
    "${CODEX_CREDENTIAL_SECRET_PATH}" \
    "${CODEX_CREDENTIAL_SECRET_FIELD}" \
    "${codex_credential_value}"
  write_managed_secrets_file \
    "${PROOF_DIR}/managed-secrets.conf" \
    "${vault_address}" \
    "${vault_local_address}" \
    "${vault_public_host}" \
    "${VAULT_PORT}" \
    "${vault_root_token}" \
    "${vault_secret_value}" \
    "${vault_secret_mount}" \
    "${vault_secret_logical_path}" \
    "${CODEX_RUNTIME_PROFILE_IMAGE}" \
    "${CODEX_CLI_PATH}" \
    "${CODEX_REALIZATION}" \
    "${CODEX_CREDENTIAL_SECRET_PATH}" \
    "${CODEX_CREDENTIAL_SECRET_FIELD}" \
    "${codex_credential_value}"

  echo "==> writing proof configs and workload-zone Vault blob"
  write_runtime_blob_and_configs \
    "${PROOF_DIR}" \
    "${vault_address}" \
    "${VAULT_AUTH_MOUNT}" \
    "${VAULT_AUTH_ROLE}" \
    "${VAULT_JWT_AUDIENCE}" \
    "${CODEX_RUNTIME_PROFILE_IMAGE}" \
    "${CODEX_CLI_PATH}" \
    "${CODEX_CREDENTIAL_SECRET_PATH}" \
    "${CODEX_CREDENTIAL_SECRET_FIELD}"
  if ! python3 "${ES_ROOTS_HELPER}" check "${PROOF_DIR}" "${PROOF_ID}" "${PROOF_DIR}/es.json" >/dev/null 2>&1; then
    echo "supported-local execution roots invalid" >&2
    return 1
  fi
  write_supported_local_execution_root_evidence "${PROOF_DIR}"
  write_env_file "${PROOF_DIR}/env.sh"

  cat <<EOF
supported local proof environment is ready under:
  ${PROOF_DIR}

next steps:
  cd "${REPO_ROOT}"
  source "${PROOF_DIR}/env.sh"
  source "${PROOF_DIR}/managed-secrets.conf"
  "${REPO_ROOT}/.examples/runtime_identity_vault_login/package.sh"
  "${REPO_ROOT}/.examples/control_plane_normal_shell_runtime/package.sh"
  export BRINGUP_PROFILE=prepare-only
  scripts/01_bringup.sh up
  BRINGUP_PROFILE=full scripts/01_bringup.sh check
  scripts/60_execute_loop.sh .examples/execution_loop/runtime_identity_vault_success.input.json
  scripts/60_execute_loop.sh .examples/execution_loop/control_plane_normal_shell_runtime.input.json
  scripts/01_bringup.sh down
EOF
}

# bash -s has no top-level source filename; a sourced file does. Both direct
# file execution and the proof wrapper's stdin transport dispatch once.
if [[ -z "${BASH_SOURCE[0]-}" || "${BASH_SOURCE[0]-}" == "$0" ]]; then
case "${ACTION}" in
  setup)
    setup
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage >&2
    exit 1
    ;;
esac
fi
