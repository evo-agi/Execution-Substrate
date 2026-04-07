#!/usr/bin/env bash
set -euo pipefail

if [[ -n "${EXECUTION_SUBSTRATE_REPO_ROOT:-}" ]]; then
  REPO_ROOT="${EXECUTION_SUBSTRATE_REPO_ROOT}"
  SCRIPT_DIR="${REPO_ROOT}/scripts"
else
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
fi

ACTION="${1:-setup}"
PROOF_DIR="${SUPPORTED_LOCAL_PROOF_DIR:-/tmp/execution-substrate-supported-local-proof}"
PROOF_ID="${SUPPORTED_LOCAL_PROOF_ID:-supported-local}"
PORT_BASE="${SUPPORTED_LOCAL_PORT_BASE:-18440}"
RUNTIME_SUPPORT_INSTALL_PATH="${SUPPORTED_LOCAL_RUNTIME_SUPPORT_BINARY:-/usr/local/bin/es-runtime-support}"
WORKLOAD_SPIFFE_ID="${SUPPORTED_LOCAL_WORKLOAD_SPIFFE_ID:-spiffe://execution.internal/workload}"
WORKLOAD_JWT_ISSUER="${SUPPORTED_LOCAL_WORKLOAD_JWT_ISSUER:-spiffe://execution.internal/mock-workload-api}"
PREBUILT_RUNTIME_SUPPORT_BINARY="${SUPPORTED_LOCAL_PREBUILT_RUNTIME_SUPPORT_BINARY:-}"
PREBUILT_WORKLOAD_API_BINARY="${SUPPORTED_LOCAL_PREBUILT_WORKLOAD_API_BINARY:-}"
VAULT_ADDRESS="${SUPPORTED_LOCAL_VAULT_ADDRESS:-}"
VAULT_BIND_ADDRESS="${SUPPORTED_LOCAL_VAULT_BIND_ADDRESS:-0.0.0.0}"
VAULT_PUBLIC_HOST="${SUPPORTED_LOCAL_VAULT_PUBLIC_HOST:-}"
VAULT_PORT="${SUPPORTED_LOCAL_VAULT_PORT:-$((PORT_BASE + 20))}"
VAULT_AUTH_MOUNT="${SUPPORTED_LOCAL_VAULT_AUTH_MOUNT:-jwt}"
VAULT_AUTH_ROLE="${SUPPORTED_LOCAL_VAULT_AUTH_ROLE:-service_execution}"
VAULT_JWT_AUDIENCE="${SUPPORTED_LOCAL_VAULT_JWT_AUDIENCE:-vault}"
VAULT_SECRET_PATH="${SUPPORTED_LOCAL_VAULT_SECRET_PATH:-secret/data/runtime-identity-vault-login}"
VAULT_ROOT_TOKEN="${SUPPORTED_LOCAL_VAULT_ROOT_TOKEN:-${SUPPORTED_LOCAL_VAULT_TOKEN:-}}"
VAULT_SECRET_VALUE="${SUPPORTED_LOCAL_VAULT_SECRET_VALUE:-}"

ARS_PORT=$((PORT_BASE + 2))
EGS_PORT=$((PORT_BASE + 3))
AGS_PORT=$((PORT_BASE + 4))
ES_PORT=$((PORT_BASE + 5))

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
  - JWT signing material for the repo-owned mock SPIFFE Workload API
  - ARS/EGS/AGS/ES JSON configs
  - ARS storage root plus workload-zone Vault blob
  - managed-secrets.conf for generated proof bootstrap material
  - operator env.sh for scripts/01_bringup.sh and scripts/60_execute_loop.sh
  - a repo-owned mock SPIFFE Workload API Unix socket
  - a proof-scoped real Vault dev/test target for the useful credential flow

This helper is the guest-side setup layer for the supported-local proof path.
On the current Apple Silicon Mac, the canonical proof record lives on the host
under .out/es-proof-<id>; any guest /tmp workspace is internal Lima scratch.

Optional environment variables:
  SUPPORTED_LOCAL_PROOF_DIR=/abs/path
  SUPPORTED_LOCAL_PROOF_ID=<proof-id>
  SUPPORTED_LOCAL_PORT_BASE=18440
  SUPPORTED_LOCAL_RUNTIME_SUPPORT_BINARY=/abs/path/to/es-runtime-support
  SUPPORTED_LOCAL_VAULT_ADDRESS=https://<container-reachable-host>:<port>
  SUPPORTED_LOCAL_VAULT_BIND_ADDRESS=0.0.0.0
  SUPPORTED_LOCAL_VAULT_PUBLIC_HOST=<container-reachable-host>
  SUPPORTED_LOCAL_VAULT_PORT=18460
  SUPPORTED_LOCAL_VAULT_AUTH_MOUNT=jwt
  SUPPORTED_LOCAL_VAULT_AUTH_ROLE=service_execution
  SUPPORTED_LOCAL_VAULT_JWT_AUDIENCE=vault
  SUPPORTED_LOCAL_VAULT_SECRET_PATH=secret/data/runtime-identity-vault-login
  SUPPORTED_LOCAL_VAULT_ROOT_TOKEN=<proof-root-token>
EOF
}

require_command() {
  local name=$1
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "${name} is required" >&2
    exit 1
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

  echo "==> building es-runtime-support to ${output_path}"
  mkdir -p "$(dirname "${output_path}")"
  (
    cd "${REPO_ROOT}"
    env CGO_ENABLED=0 GOOS=linux GOARCH="$(go env GOARCH)" go build -o "${output_path}" ./cmd/es-runtime-support
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

prepare_workload_api_binary() {
  local output_path=$1

  if [[ -n "${PREBUILT_WORKLOAD_API_BINARY}" ]]; then
    install_prebuilt_binary "${PREBUILT_WORKLOAD_API_BINARY}" "${output_path}" "es-workload-api-mock"
    return 0
  fi

  echo "==> building repo-owned mock SPIFFE Workload API"
  mkdir -p "$(dirname "${output_path}")"
  (
    cd "${REPO_ROOT}"
    env CGO_ENABLED=0 GOOS=linux GOARCH="$(go env GOARCH)" go build -o "${output_path}" ./cmd/es-workload-api-mock
  )
  chmod 0755 "${output_path}"
}

start_mock_workload_api() {
  local binary_path=$1
  local socket_path=$2
  local log_path=$3
  local pid_path=$4
  local signing_key_path=$5

  echo "==> starting repo-owned mock SPIFFE Workload API"
  nohup "${binary_path}" \
    -socket "${socket_path}" \
    -subject "${WORKLOAD_SPIFFE_ID}" \
    -issuer "${WORKLOAD_JWT_ISSUER}" \
    -signing-key-file "${signing_key_path}" >"${log_path}" 2>&1 &
  echo "$!" > "${pid_path}"

  for _ in $(seq 1 50); do
    if [[ -S "${socket_path}" ]]; then
      return 0
    fi
    sleep 0.1
  done

  echo "mock SPIFFE Workload API socket did not appear at ${socket_path}" >&2
  return 1
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

generate_workload_jwt_signing_material() {
  local tls_dir=$1
  local private_key_path="${tls_dir}/workload-jwt-signing-key.pem"
  local public_key_path="${tls_dir}/workload-jwt-validation-pub.pem"

  echo "==> generating workload JWT signing material for Vault validation"
  openssl genrsa -traditional -out "${private_key_path}" 2048 >/dev/null 2>&1
  openssl rsa -in "${private_key_path}" -pubout -out "${public_key_path}" >/dev/null 2>&1
  chmod 600 "${private_key_path}"
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
  printf '%s/%s\n' "${api_path%%/data/*}" "${api_path#*/data/}"
}

write_managed_secrets_file() {
  local path=$1
  local vault_address=$2
  local vault_local_address=$3
  local vault_public_host=$4
  local vault_port=$5
  local vault_root_token=$6
  local vault_secret_value=$7
  local vault_secret_logical_path=$8

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
PROOF_VAULT_BOUND_ISSUER="${WORKLOAD_JWT_ISSUER}"
PROOF_VAULT_SECRET_PATH="${VAULT_SECRET_PATH}"
PROOF_VAULT_SECRET_LOGICAL_PATH="${vault_secret_logical_path}"
PROOF_VAULT_SECRET_VALUE="${vault_secret_value}"
PROOF_VAULT_ROOT_TOKEN="${vault_root_token}"
PROOF_VAULT_CA_CERT_FILE="${PROOF_DIR}/tls/vault-dev/vault-ca.pem"
PROOF_VAULT_SERVER_CERT_FILE="${PROOF_DIR}/tls/vault-dev/vault-cert.pem"
PROOF_VAULT_SERVER_KEY_FILE="${PROOF_DIR}/tls/vault-dev/vault-key.pem"
PROOF_WORKLOAD_JWT_SIGNING_KEY_FILE="${PROOF_DIR}/tls/workload-jwt-signing-key.pem"
PROOF_WORKLOAD_JWT_VALIDATION_PUB_FILE="${PROOF_DIR}/tls/workload-jwt-validation-pub.pem"
EOF
  chmod 600 "${path}"
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
  local policy_path="${proof_dir}/vault/runtime-identity-proof.hcl"
  local vault_secret_logical_path

  vault_secret_logical_path="$(normalize_kv_v2_logical_path "${VAULT_SECRET_PATH}")"
  mkdir -p "$(dirname "${policy_path}")"
  cat > "${policy_path}" <<EOF
path "${VAULT_SECRET_PATH#/}" {
  capabilities = ["read"]
}
EOF

  echo "==> configuring proof-scoped Vault JWT auth and secret"
  VAULT_ADDR="${vault_local_address}" \
  VAULT_CACERT="${proof_dir}/tls/vault-dev/vault-ca.pem" \
  VAULT_TOKEN="${vault_root_token}" \
  vault policy write runtime-identity-proof "${policy_path}" >/dev/null

  VAULT_ADDR="${vault_local_address}" \
  VAULT_CACERT="${proof_dir}/tls/vault-dev/vault-ca.pem" \
  VAULT_TOKEN="${vault_root_token}" \
  vault auth enable -path="${VAULT_AUTH_MOUNT}" jwt >/dev/null

  VAULT_ADDR="${vault_local_address}" \
  VAULT_CACERT="${proof_dir}/tls/vault-dev/vault-ca.pem" \
  VAULT_TOKEN="${vault_root_token}" \
  vault write "auth/${VAULT_AUTH_MOUNT}/config" \
    jwt_validation_pubkeys=@"${proof_dir}/tls/workload-jwt-validation-pub.pem" \
    bound_issuer="${WORKLOAD_JWT_ISSUER}" >/dev/null

  VAULT_ADDR="${vault_local_address}" \
  VAULT_CACERT="${proof_dir}/tls/vault-dev/vault-ca.pem" \
  VAULT_TOKEN="${vault_root_token}" \
  vault write "auth/${VAULT_AUTH_MOUNT}/role/${VAULT_AUTH_ROLE}" \
    role_type=jwt \
    user_claim=sub \
    bound_audiences="${VAULT_JWT_AUDIENCE}" \
    bound_subject="${WORKLOAD_SPIFFE_ID}" \
    token_policies=runtime-identity-proof >/dev/null

  VAULT_ADDR="${vault_local_address}" \
  VAULT_CACERT="${proof_dir}/tls/vault-dev/vault-ca.pem" \
  VAULT_TOKEN="${vault_root_token}" \
  vault kv put "${vault_secret_logical_path}" message="${vault_secret_value}" >/dev/null
}

write_runtime_blob_and_configs() {
  local proof_dir=$1
  local vault_address=$2
  local vault_auth_mount=$3
  local vault_auth_role=$4
  local vault_jwt_audience=$5
  local tls_dir="${proof_dir}/tls"
  local ars_storage="${proof_dir}/ars-storage"
  local index_path="${proof_dir}/artifact-index.json"
  local staging_root="${proof_dir}/es-staging"
  local socket_path="${proof_dir}/mock-spire.sock"
  local digest_file="${proof_dir}/workload-zone-vault-config-digest.txt"

  python3 - <<'PY' \
    "${proof_dir}" \
    "${tls_dir}" \
    "${ars_storage}" \
    "${index_path}" \
    "${staging_root}" \
    "${socket_path}" \
    "${digest_file}" \
    "${RUNTIME_SUPPORT_INSTALL_PATH}" \
    "${vault_address}" \
    "${vault_auth_mount}" \
    "${vault_auth_role}" \
    "${vault_jwt_audience}" \
    "${ARS_PORT}" \
    "${EGS_PORT}" \
    "${AGS_PORT}" \
    "${ES_PORT}" \
    "${ARS_HOST}" \
    "${EGS_HOST}" \
    "${AGS_HOST}" \
    "${ES_HOST}"
import hashlib
import json
import pathlib
import sys

proof_dir = pathlib.Path(sys.argv[1])
tls_dir = pathlib.Path(sys.argv[2])
ars_storage = pathlib.Path(sys.argv[3])
index_path = pathlib.Path(sys.argv[4])
staging_root = pathlib.Path(sys.argv[5])
socket_path = pathlib.Path(sys.argv[6])
digest_file = pathlib.Path(sys.argv[7])
runtime_support_binary = sys.argv[8]
vault_address = sys.argv[9]
vault_auth_mount = sys.argv[10]
vault_auth_role = sys.argv[11]
vault_jwt_audience = sys.argv[12]
ars_port = int(sys.argv[13])
egs_port = int(sys.argv[14])
ags_port = int(sys.argv[15])
es_port = int(sys.argv[16])
ars_host = sys.argv[17]
egs_host = sys.argv[18]
ags_host = sys.argv[19]
es_host = sys.argv[20]

blob = {
    "vault_config": {
        "address": vault_address,
        "auth_mount": vault_auth_mount,
        "auth_role": vault_auth_role,
        "jwt_audience": vault_jwt_audience,
    }
}
blob_bytes = (json.dumps(blob, separators=(",", ":")) + "\n").encode("utf-8")
digest = "sha256:" + hashlib.sha256(blob_bytes).hexdigest()
blob_path = ars_storage / "sha256" / digest[7:9] / digest[9:11] / digest
blob_path.parent.mkdir(parents=True, exist_ok=True)
blob_path.write_bytes(blob_bytes)
digest_file.write_text(digest + "\n", encoding="utf-8")
index_path.write_text("{}\n", encoding="utf-8")
staging_root.mkdir(parents=True, exist_ok=True)

ars_cfg = {
    "http": {"bind_address": "127.0.0.1", "port": ars_port, "read_timeout_seconds": 5, "write_timeout_seconds": 5, "shutdown_timeout_seconds": 5},
    "tls": {
        "cert_file": str(tls_dir / "ars-server-cert.pem"),
        "key_file": str(tls_dir / "ars-server-key.pem"),
        "client_ca_file": str(tls_dir / "runtime-ca.pem"),
    },
    "security": {"bootstrap_issuer_common_name": "Bootstrap Root CA Example"},
    "authorization": {"allowed_spiffe_path_prefixes": ["service/execution", "service/artifact-governance", "operator"]},
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
        "base_image": "python:3.13-alpine",
        "runtime_support_binary": runtime_support_binary,
        "spire_workload_api_socket_path": str(socket_path),
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
}

setup() {
  require_command go
  require_command openssl
  require_command python3
  require_command vault
  require_command docker
  require_command nomad

  if [[ "$(uname -s)" != "Linux" ]]; then
    echo "scripts/72_supported_local_setup.sh must run on the Linux host/VM that will run Docker and Nomad" >&2
    exit 1
  fi
  if [[ -z "${PROOF_DIR}" || "${PROOF_DIR}" == "/" ]]; then
    echo "SUPPORTED_LOCAL_PROOF_DIR is unsafe: ${PROOF_DIR}" >&2
    exit 1
  fi

  local vault_public_host
  local vault_address
  local vault_local_address
  local vault_root_token
  local vault_secret_value
  local vault_secret_logical_path

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
  vault_secret_logical_path="$(normalize_kv_v2_logical_path "${VAULT_SECRET_PATH}")"

  stop_background_process "${PROOF_DIR}/mock-spire.pid"
  stop_background_process "${PROOF_DIR}/vault-dev.pid"
  stop_vault_dev_listener "${VAULT_PORT}"
  rm -rf "${PROOF_DIR}"
  mkdir -p "${PROOF_DIR}/tls" "${PROOF_DIR}/ars-storage" "${PROOF_DIR}/es-staging" "${PROOF_DIR}/bin" "${PROOF_DIR}/logs" "${PROOF_DIR}/workdirs"

  prepare_runtime_support_binary
  prepare_workload_api_binary "${PROOF_DIR}/bin/es-workload-api-mock"

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
  make_leaf_certificate "${PROOF_DIR}/tls" "${PROOF_DIR}/tls/runtime-ca.pem" "${PROOF_DIR}/tls/runtime-ca-key.pem" "operator-client" "client.operator" "DNS:client.operator,URI:spiffe://execution.internal/operator"
  chmod 600 "${PROOF_DIR}/tls/runtime-ca-key.pem"
  generate_workload_jwt_signing_material "${PROOF_DIR}/tls"

  start_mock_workload_api \
    "${PROOF_DIR}/bin/es-workload-api-mock" \
    "${PROOF_DIR}/mock-spire.sock" \
    "${PROOF_DIR}/logs/mock-spire.log" \
    "${PROOF_DIR}/mock-spire.pid" \
    "${PROOF_DIR}/tls/workload-jwt-signing-key.pem"
  start_vault_dev_server "${PROOF_DIR}/logs/vault-dev.log" "${PROOF_DIR}/vault-dev.pid" "${vault_root_token}" "${vault_public_host}"
  configure_vault_dev_target "${PROOF_DIR}" "${vault_local_address}" "${vault_root_token}" "${vault_secret_value}"
  write_managed_secrets_file \
    "${PROOF_DIR}/managed-secrets.conf" \
    "${vault_address}" \
    "${vault_local_address}" \
    "${vault_public_host}" \
    "${VAULT_PORT}" \
    "${vault_root_token}" \
    "${vault_secret_value}" \
    "${vault_secret_logical_path}"

  echo "==> writing proof configs and workload-zone Vault blob"
  write_runtime_blob_and_configs "${PROOF_DIR}" "${vault_address}" "${VAULT_AUTH_MOUNT}" "${VAULT_AUTH_ROLE}" "${VAULT_JWT_AUDIENCE}"
  write_env_file "${PROOF_DIR}/env.sh"

  cat <<EOF
supported local proof environment is ready under:
  ${PROOF_DIR}

next steps:
  cd "${REPO_ROOT}"
  source "${PROOF_DIR}/env.sh"
  source "${PROOF_DIR}/managed-secrets.conf"
  "${REPO_ROOT}/.examples/runtime_identity_vault_login/package.sh"
  export BRINGUP_PROFILE=prepare-only
  scripts/01_bringup.sh up
  BRINGUP_PROFILE=full scripts/01_bringup.sh check
  scripts/60_execute_loop.sh .examples/execution_loop/runtime_identity_vault_success.input.json
  scripts/01_bringup.sh down
EOF
}

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
