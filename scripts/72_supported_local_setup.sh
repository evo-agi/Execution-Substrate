#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

ACTION="${1:-setup}"
PROOF_DIR="${SUPPORTED_LOCAL_PROOF_DIR:-/tmp/execution-substrate-supported-local-proof}"
PORT_BASE="${SUPPORTED_LOCAL_PORT_BASE:-18440}"
RUNTIME_SUPPORT_INSTALL_PATH="${SUPPORTED_LOCAL_RUNTIME_SUPPORT_BINARY:-/usr/local/bin/es-runtime-support}"
WORKLOAD_SPIFFE_ID="${SUPPORTED_LOCAL_WORKLOAD_SPIFFE_ID:-spiffe://execution.internal/workload}"
VAULT_ADDRESS="${SUPPORTED_LOCAL_VAULT_ADDRESS:-https://127.0.0.1:8200}"
VAULT_AUTH_MOUNT="${SUPPORTED_LOCAL_VAULT_AUTH_MOUNT:-jwt}"
VAULT_AUTH_ROLE="${SUPPORTED_LOCAL_VAULT_AUTH_ROLE:-service_execution}"
VAULT_JWT_AUDIENCE="${SUPPORTED_LOCAL_VAULT_JWT_AUDIENCE:-vault}"

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
  - ARS/EGS/AGS/ES JSON configs
  - ARS storage root plus workload-zone Vault blob
  - operator env.sh for scripts/01_bringup.sh and scripts/60_execute_loop.sh
  - a repo-owned mock SPIFFE Workload API Unix socket

The current generated workload-zone Vault blob is intentionally only a
structurally valid placeholder for supported-host qualification and the static
script smoke path. Useful credential-flow proof still requires the dedicated
Vault-login runbook to point that blob at a reachable mock Vault endpoint.

Optional environment variables:
  SUPPORTED_LOCAL_PROOF_DIR=/abs/path
  SUPPORTED_LOCAL_PORT_BASE=18440
  SUPPORTED_LOCAL_RUNTIME_SUPPORT_BINARY=/usr/local/bin/es-runtime-support
  SUPPORTED_LOCAL_VAULT_ADDRESS=https://127.0.0.1:8200
  SUPPORTED_LOCAL_VAULT_AUTH_MOUNT=jwt
  SUPPORTED_LOCAL_VAULT_AUTH_ROLE=service_execution
  SUPPORTED_LOCAL_VAULT_JWT_AUDIENCE=vault
EOF
}

require_command() {
  local name=$1
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "${name} is required" >&2
    exit 1
  fi
}

stop_existing_mock() {
  local pid_file=$1
  local socket_path=$2
  local pid=""
  local args=""

  if [[ -r "${pid_file}" ]]; then
    pid="$(tr -d '[:space:]' <"${pid_file}")"
  fi
  if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
    args="$(ps -p "${pid}" -o args= 2>/dev/null || true)"
    if [[ "${args}" == *"es-workload-api-mock"* ]] && [[ "${args}" == *"${socket_path}"* ]]; then
      kill "${pid}" >/dev/null 2>&1 || true
      wait "${pid}" >/dev/null 2>&1 || true
    fi
  fi
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

install_runtime_support_binary() {
  local output_path=$1

  echo "==> building es-runtime-support"
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

start_mock_workload_api() {
  local binary_path=$1
  local socket_path=$2
  local log_path=$3
  local pid_path=$4

  echo "==> starting repo-owned mock SPIFFE Workload API"
  nohup "${binary_path}" -socket "${socket_path}" -subject "${WORKLOAD_SPIFFE_ID}" >"${log_path}" 2>&1 &
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

write_runtime_blob_and_configs() {
  local proof_dir=$1
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
    "${VAULT_ADDRESS}" \
    "${VAULT_AUTH_MOUNT}" \
    "${VAULT_AUTH_ROLE}" \
    "${VAULT_JWT_AUDIENCE}" \
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
        "base_image": "alpine:3.20",
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
export SUPPORTED_LOCAL_PROOF_DIR="${PROOF_DIR}"
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

  stop_existing_mock "${PROOF_DIR}/mock-spire.pid" "${PROOF_DIR}/mock-spire.sock"
  rm -rf "${PROOF_DIR}"
  mkdir -p "${PROOF_DIR}/tls" "${PROOF_DIR}/ars-storage" "${PROOF_DIR}/es-staging" "${PROOF_DIR}/bin" "${PROOF_DIR}/logs" "${PROOF_DIR}/workdirs"

  install_runtime_support_binary "${PROOF_DIR}/bin/es-runtime-support"

  echo "==> building repo-owned mock SPIFFE Workload API"
  (
    cd "${REPO_ROOT}"
    env CGO_ENABLED=0 GOOS=linux GOARCH="$(go env GOARCH)" go build -o "${PROOF_DIR}/bin/es-workload-api-mock" ./cmd/es-workload-api-mock
  )

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

  start_mock_workload_api "${PROOF_DIR}/bin/es-workload-api-mock" "${PROOF_DIR}/mock-spire.sock" "${PROOF_DIR}/logs/mock-spire.log" "${PROOF_DIR}/mock-spire.pid"

  echo "==> writing proof configs and workload-zone Vault blob"
  write_runtime_blob_and_configs "${PROOF_DIR}"
  write_env_file "${PROOF_DIR}/env.sh"

  cat <<EOF
supported local proof environment is ready under:
  ${PROOF_DIR}

next steps:
  cd "${REPO_ROOT}"
  source "${PROOF_DIR}/env.sh"
  export BRINGUP_PROFILE=prepare-only
  scripts/01_bringup.sh up
  BRINGUP_PROFILE=full scripts/01_bringup.sh check
  scripts/60_execute_loop.sh .examples/execution_loop/static_script_success.input.json
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
