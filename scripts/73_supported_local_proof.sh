#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

ACTION="${1:-run}"
SUPPORTED_LOCAL_INSTANCE="${SUPPORTED_LOCAL_INSTANCE:-es-lima-qemu-arm64}"
SUPPORTED_LOCAL_REPO_ROOT_IN_GUEST="${SUPPORTED_LOCAL_REPO_ROOT_IN_GUEST:-/Users/ds/Repositories/Execution Substrate}"
SUPPORTED_LOCAL_PROOF_ID="${SUPPORTED_LOCAL_PROOF_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
SUPPORTED_LOCAL_HOST_PROOF_DIR="${SUPPORTED_LOCAL_HOST_PROOF_DIR:-${REPO_ROOT}/.out/es-proof-${SUPPORTED_LOCAL_PROOF_ID}}"
SUPPORTED_LOCAL_GUEST_PROOF_DIR="${SUPPORTED_LOCAL_GUEST_PROOF_DIR:-/tmp/es-proof-${SUPPORTED_LOCAL_PROOF_ID}}"
SUPPORTED_LOCAL_GUEST_BOOTSTRAP_DIR="${SUPPORTED_LOCAL_GUEST_BOOTSTRAP_DIR:-${SUPPORTED_LOCAL_GUEST_PROOF_DIR}.bootstrap}"
SUPPORTED_LOCAL_GUEST_REPO_ROOT="${SUPPORTED_LOCAL_GUEST_REPO_ROOT:-${SUPPORTED_LOCAL_GUEST_BOOTSTRAP_DIR}/repo}"
SUPPORTED_LOCAL_PORT_BASE="${SUPPORTED_LOCAL_PORT_BASE:-18440}"
SUPPORTED_LOCAL_INPUT_SPEC="${SUPPORTED_LOCAL_INPUT_SPEC:-${REPO_ROOT}/.examples/execution_loop/runtime_identity_vault_success.input.json}"
SUPPORTED_LOCAL_DIST_PAYLOAD="${SUPPORTED_LOCAL_DIST_PAYLOAD:-${REPO_ROOT}/.examples/runtime_identity_vault_login/dist/runtime_identity_vault_login.tar.gz}"
SUPPORTED_LOCAL_SPIRE_VERSION="${SUPPORTED_LOCAL_SPIRE_VERSION:-1.14.4}"
SUPPORTED_LOCAL_SPIRE_ASSET="${SUPPORTED_LOCAL_SPIRE_ASSET:-spire-${SUPPORTED_LOCAL_SPIRE_VERSION}-linux-arm64-musl.tar.gz}"
SUPPORTED_LOCAL_SPIRE_URL="${SUPPORTED_LOCAL_SPIRE_URL:-https://github.com/spiffe/spire/releases/download/v${SUPPORTED_LOCAL_SPIRE_VERSION}/${SUPPORTED_LOCAL_SPIRE_ASSET}}"
SUPPORTED_LOCAL_PREBUILT_SPIRE_TARBALL="${SUPPORTED_LOCAL_PREBUILT_SPIRE_TARBALL:-}"

CONTROL_PLANE_STARTED="false"

usage() {
  cat <<'EOF'
Usage:
  scripts/73_supported_local_proof.sh run

This is the canonical supported-local proof wrapper for the current Apple
Silicon Mac + Lima qemu reference path. It:
  - creates the canonical proof workspace under .out/es-proof-<id>/
  - cleans stale proof-owned guest /tmp/es-proof-* scratch before bootstrap
  - stages a fresh snapshot of the current host worktree into guest proof scratch
  - packages the bounded runtime-identity Vault-login workload
  - cross-compiles the current Linux runtime-support binary from this working tree
  - stages a proof-scoped real SPIRE server/agent distribution into the guest
  - invokes scripts/72_supported_local_setup.sh inside the Linux guest
  - runs supported-host qualification without cpu_total_compute override
  - boots the proof-scoped real SPIRE dev/test path used by the helper
  - boots the proof-scoped real Vault dev/test target used by that proof
  - runs the higher-value useful credential-flow proof
  - copies resulting guest evidence back into the canonical .out workspace
  - removes successful guest /tmp/es-proof-* scratch after host evidence is preserved

Optional environment variables:
  SUPPORTED_LOCAL_INSTANCE=es-lima-qemu-arm64
  SUPPORTED_LOCAL_REPO_ROOT_IN_GUEST=/Users/ds/Repositories/Execution Substrate
  SUPPORTED_LOCAL_PROOF_ID=<proof-id>
  SUPPORTED_LOCAL_HOST_PROOF_DIR=/abs/path/.out/es-proof-<id>
  SUPPORTED_LOCAL_GUEST_PROOF_DIR=/tmp/es-proof-<id>
  SUPPORTED_LOCAL_GUEST_REPO_ROOT=/tmp/es-proof-<id>.bootstrap/repo
  SUPPORTED_LOCAL_PORT_BASE=18440
  SUPPORTED_LOCAL_SPIRE_VERSION=1.14.4
  SUPPORTED_LOCAL_PREBUILT_SPIRE_TARBALL=/abs/path/to/spire-linux-arm64-musl.tar.gz
EOF
}

require_command() {
  local name=$1
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "${name} is required" >&2
    exit 1
  fi
}

run_guest_stdin() {
  limactl shell "${SUPPORTED_LOCAL_INSTANCE}" -- \
    env \
      GUEST_REPO_ROOT="${SUPPORTED_LOCAL_GUEST_REPO_ROOT}" \
      GUEST_PROOF_DIR="${SUPPORTED_LOCAL_GUEST_PROOF_DIR}" \
      GUEST_BOOTSTRAP_DIR="${SUPPORTED_LOCAL_GUEST_BOOTSTRAP_DIR}" \
    bash -seuo pipefail
}

collect_guest_workspace() {
  mkdir -p "${SUPPORTED_LOCAL_HOST_PROOF_DIR}"
  if ! limactl shell "${SUPPORTED_LOCAL_INSTANCE}" -- \
    env GUEST_PROOF_DIR="${SUPPORTED_LOCAL_GUEST_PROOF_DIR}" \
    bash -lc 'if [[ -d "${GUEST_PROOF_DIR}" ]]; then tar --ignore-failed-read --exclude=spire-agent/public/api.sock --exclude=spire-server/private/api.sock -C "${GUEST_PROOF_DIR}" -cf - . 2>/dev/null; fi' \
    | tar -C "${SUPPORTED_LOCAL_HOST_PROOF_DIR}" -xf - 2>/dev/null; then
    return 0
  fi
}

cleanup_stale_guest_proof_scratch() {
  limactl shell "${SUPPORTED_LOCAL_INSTANCE}" -- \
    env \
      "EXECUTION_SUBSTRATE_REPO_ROOT=${SUPPORTED_LOCAL_GUEST_REPO_ROOT}" \
      "SUPPORTED_LOCAL_PROOF_PARENT=/tmp" \
      "SUPPORTED_LOCAL_PROOF_DIR=${SUPPORTED_LOCAL_GUEST_PROOF_DIR}" \
    bash -s -- cleanup-stale < "${REPO_ROOT}/scripts/internal/supported_local_proof_cleanup.sh"
}

cleanup_control_plane() {
  if [[ "${CONTROL_PLANE_STARTED}" == "true" ]]; then
    run_guest_stdin <<'EOF' >/dev/null 2>&1 || true
cd "$GUEST_REPO_ROOT"
if [[ -f "$GUEST_PROOF_DIR/env.sh" ]]; then
  source "$GUEST_PROOF_DIR/env.sh"
  scripts/01_bringup.sh down
fi
EOF
  fi
  run_guest_stdin <<'EOF' >/dev/null 2>&1 || true
stop_pid_file() {
  local pid_file=$1
  local pid=""
  if [[ -r "${pid_file}" ]]; then
    pid="$(tr -d '[:space:]' < "${pid_file}")"
  fi
  if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
    kill "${pid}" >/dev/null 2>&1 || true
    wait "${pid}" >/dev/null 2>&1 || true
  fi
}

stop_pid_file "$GUEST_PROOF_DIR/vault-dev.pid"
stop_pid_file "$GUEST_PROOF_DIR/spire-agent.pid"
stop_pid_file "$GUEST_PROOF_DIR/spire-server.pid"
rm -rf "$GUEST_BOOTSTRAP_DIR"
EOF
  CONTROL_PLANE_STARTED="false"
}

remove_current_guest_scratch() {
  run_guest_stdin <<'EOF' >/dev/null 2>&1 || true
remove_path() {
  local path=$1

  if [[ ! -e "${path}" ]]; then
    return 0
  fi
  if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    sudo -n rm -rf "${path}"
    return 0
  fi

  rm -rf "${path}"
}

remove_path "$GUEST_PROOF_DIR"
remove_path "$GUEST_BOOTSTRAP_DIR"
EOF
}

finalize() {
  local status=$?
  cleanup_control_plane
  collect_guest_workspace || true
  exit "${status}"
}

write_proof_metadata() {
  python3 - <<'PY' \
    "${SUPPORTED_LOCAL_HOST_PROOF_DIR}/proof-metadata.json" \
    "${SUPPORTED_LOCAL_INSTANCE}" \
    "${SUPPORTED_LOCAL_REPO_ROOT_IN_GUEST}" \
    "${SUPPORTED_LOCAL_GUEST_REPO_ROOT}" \
    "${SUPPORTED_LOCAL_GUEST_PROOF_DIR}" \
    "${SUPPORTED_LOCAL_HOST_PROOF_DIR}" \
    "${SUPPORTED_LOCAL_INPUT_SPEC}" \
    "${SUPPORTED_LOCAL_PROOF_ID}"
import json
import pathlib
import sys

payload = {
    "instance": sys.argv[2],
    "mounted_repo_root_in_guest": sys.argv[3],
    "guest_repo_root": sys.argv[4],
    "guest_proof_dir": sys.argv[5],
    "host_proof_dir": sys.argv[6],
    "input_spec": sys.argv[7],
    "proof_id": sys.argv[8],
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

prepare_host_repo_snapshot() {
  local snapshot_path="${SUPPORTED_LOCAL_HOST_PROOF_DIR}/host-repo-snapshot.tar.gz"
  local snapshot_sha_path="${SUPPORTED_LOCAL_HOST_PROOF_DIR}/host-repo-snapshot.sha256"
  local snapshot_listing_path="${SUPPORTED_LOCAL_HOST_PROOF_DIR}/host-repo-snapshot-files.txt"

  (
    cd "${REPO_ROOT}"
    tar \
      --exclude='.git' \
      --exclude='.out' \
      --exclude='.tmp' \
      -czf "${snapshot_path}" \
      .
  )

  python3 - <<'PY' "${snapshot_path}" "${snapshot_sha_path}"
import hashlib
import pathlib
import sys

snapshot_path = pathlib.Path(sys.argv[1])
digest = hashlib.sha256(snapshot_path.read_bytes()).hexdigest()
pathlib.Path(sys.argv[2]).write_text(digest + "\n", encoding="utf-8")
PY

  tar -tzf "${snapshot_path}" | LC_ALL=C sort > "${snapshot_listing_path}"
}

prepare_host_inputs() {
  local payload_copy="${SUPPORTED_LOCAL_HOST_PROOF_DIR}/payload/runtime_identity_vault_login.tar.gz"
  local spec_copy="${SUPPORTED_LOCAL_HOST_PROOF_DIR}/runtime_identity_vault_success.input.json"

  mkdir -p "${SUPPORTED_LOCAL_HOST_PROOF_DIR}/payload"
  "${REPO_ROOT}/.examples/runtime_identity_vault_login/package.sh" | tee "${SUPPORTED_LOCAL_HOST_PROOF_DIR}/host-package-workload.txt"
  cp "${SUPPORTED_LOCAL_DIST_PAYLOAD}" "${payload_copy}"

  python3 - <<'PY' \
    "${SUPPORTED_LOCAL_INPUT_SPEC}" \
    "${spec_copy}" \
    "${SUPPORTED_LOCAL_GUEST_PROOF_DIR}/payload/runtime_identity_vault_login.tar.gz"
import json
import pathlib
import sys

spec = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
spec["payload_path"] = sys.argv[3]
pathlib.Path(sys.argv[2]).write_text(json.dumps(spec, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

prepare_host_tooling() {
  mkdir -p "${SUPPORTED_LOCAL_HOST_PROOF_DIR}/bin"

  (
    cd "${REPO_ROOT}"
    env CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build \
      -o "${SUPPORTED_LOCAL_HOST_PROOF_DIR}/bin/es-runtime-support" \
      ./cmd/es-runtime-support
  )

  if [[ -n "${SUPPORTED_LOCAL_PREBUILT_SPIRE_TARBALL}" ]]; then
    cp "${SUPPORTED_LOCAL_PREBUILT_SPIRE_TARBALL}" "${SUPPORTED_LOCAL_HOST_PROOF_DIR}/bin/${SUPPORTED_LOCAL_SPIRE_ASSET}"
  else
    curl -L --fail --silent --show-error \
      -o "${SUPPORTED_LOCAL_HOST_PROOF_DIR}/bin/${SUPPORTED_LOCAL_SPIRE_ASSET}" \
      "${SUPPORTED_LOCAL_SPIRE_URL}"
  fi
}

prepare_guest_bootstrap_dir() {
  limactl shell "${SUPPORTED_LOCAL_INSTANCE}" -- \
    env \
      GUEST_BOOTSTRAP_DIR="${SUPPORTED_LOCAL_GUEST_BOOTSTRAP_DIR}" \
      GUEST_PROOF_DIR="${SUPPORTED_LOCAL_GUEST_PROOF_DIR}" \
      GUEST_REPO_ROOT="${SUPPORTED_LOCAL_GUEST_REPO_ROOT}" \
    bash -lc 'rm -rf "${GUEST_BOOTSTRAP_DIR}" && mkdir -p "${GUEST_BOOTSTRAP_DIR}" "${GUEST_PROOF_DIR}" "$(dirname "${GUEST_REPO_ROOT}")"'
}

copy_repo_snapshot_to_guest() {
  limactl shell "${SUPPORTED_LOCAL_INSTANCE}" -- \
    env GUEST_BOOTSTRAP_DIR="${SUPPORTED_LOCAL_GUEST_BOOTSTRAP_DIR}" \
    bash -lc 'cat > "${GUEST_BOOTSTRAP_DIR}/repo-snapshot.tar.gz"' \
    < "${SUPPORTED_LOCAL_HOST_PROOF_DIR}/host-repo-snapshot.tar.gz"
}

extract_guest_repo_snapshot() {
  local host_snapshot_sha
  host_snapshot_sha="$(tr -d '[:space:]' < "${SUPPORTED_LOCAL_HOST_PROOF_DIR}/host-repo-snapshot.sha256")"

  limactl shell "${SUPPORTED_LOCAL_INSTANCE}" -- \
    env \
      GUEST_BOOTSTRAP_DIR="${SUPPORTED_LOCAL_GUEST_BOOTSTRAP_DIR}" \
      GUEST_PROOF_DIR="${SUPPORTED_LOCAL_GUEST_PROOF_DIR}" \
      GUEST_REPO_ROOT="${SUPPORTED_LOCAL_GUEST_REPO_ROOT}" \
      HOST_REPO_SNAPSHOT_SHA256="${host_snapshot_sha}" \
    bash -seuo pipefail <<'EOF'
python3 - <<'PY' "${GUEST_BOOTSTRAP_DIR}/repo-snapshot.tar.gz" "${GUEST_PROOF_DIR}/guest-repo-snapshot.sha256"
import hashlib
import pathlib
import sys

snapshot_path = pathlib.Path(sys.argv[1])
digest = hashlib.sha256(snapshot_path.read_bytes()).hexdigest()
pathlib.Path(sys.argv[2]).write_text(digest + "\n", encoding="utf-8")
print(digest)
PY

guest_sha="$(tr -d '[:space:]' < "${GUEST_PROOF_DIR}/guest-repo-snapshot.sha256")"
if [[ "${guest_sha}" != "${HOST_REPO_SNAPSHOT_SHA256}" ]]; then
  echo "guest repo snapshot digest mismatch: host=${HOST_REPO_SNAPSHOT_SHA256} guest=${guest_sha}" >&2
  exit 1
fi

rm -rf "${GUEST_REPO_ROOT}"
mkdir -p "${GUEST_REPO_ROOT}"
tar -xzf "${GUEST_BOOTSTRAP_DIR}/repo-snapshot.tar.gz" -C "${GUEST_REPO_ROOT}"
printf '%s\n' "${GUEST_REPO_ROOT}" > "${GUEST_PROOF_DIR}/guest-repo-root.txt"
printf '%s\n' "${HOST_REPO_SNAPSHOT_SHA256}" > "${GUEST_PROOF_DIR}/repo-snapshot-match.txt"
EOF
}

copy_tooling_to_guest() {
  limactl shell "${SUPPORTED_LOCAL_INSTANCE}" -- \
    env GUEST_BOOTSTRAP_DIR="${SUPPORTED_LOCAL_GUEST_BOOTSTRAP_DIR}" \
    bash -lc 'mkdir -p "${GUEST_BOOTSTRAP_DIR}"'

  limactl shell "${SUPPORTED_LOCAL_INSTANCE}" -- \
    env GUEST_BOOTSTRAP_DIR="${SUPPORTED_LOCAL_GUEST_BOOTSTRAP_DIR}" \
    bash -lc 'cat > "${GUEST_BOOTSTRAP_DIR}/es-runtime-support"' \
    < "${SUPPORTED_LOCAL_HOST_PROOF_DIR}/bin/es-runtime-support"

  limactl shell "${SUPPORTED_LOCAL_INSTANCE}" -- \
    env GUEST_BOOTSTRAP_DIR="${SUPPORTED_LOCAL_GUEST_BOOTSTRAP_DIR}" \
    bash -lc 'cat > "${GUEST_BOOTSTRAP_DIR}/spire.tar.gz"' \
    < "${SUPPORTED_LOCAL_HOST_PROOF_DIR}/bin/${SUPPORTED_LOCAL_SPIRE_ASSET}"

  limactl shell "${SUPPORTED_LOCAL_INSTANCE}" -- \
    env GUEST_BOOTSTRAP_DIR="${SUPPORTED_LOCAL_GUEST_BOOTSTRAP_DIR}" \
    bash -lc 'chmod 0755 "${GUEST_BOOTSTRAP_DIR}/es-runtime-support" && chmod 0644 "${GUEST_BOOTSTRAP_DIR}/spire.tar.gz"'
}

setup_guest_environment() {
  local -a cmd=(
    limactl shell "${SUPPORTED_LOCAL_INSTANCE}" --
    env
    "EXECUTION_SUBSTRATE_REPO_ROOT=${SUPPORTED_LOCAL_GUEST_REPO_ROOT}"
    "SUPPORTED_LOCAL_PROOF_DIR=${SUPPORTED_LOCAL_GUEST_PROOF_DIR}"
    "SUPPORTED_LOCAL_PROOF_ID=${SUPPORTED_LOCAL_PROOF_ID}"
    "SUPPORTED_LOCAL_PORT_BASE=${SUPPORTED_LOCAL_PORT_BASE}"
    "SUPPORTED_LOCAL_PREBUILT_RUNTIME_SUPPORT_BINARY=${SUPPORTED_LOCAL_GUEST_BOOTSTRAP_DIR}/es-runtime-support"
    "SUPPORTED_LOCAL_PREBUILT_SPIRE_TARBALL=${SUPPORTED_LOCAL_GUEST_BOOTSTRAP_DIR}/spire.tar.gz"
    "SUPPORTED_LOCAL_SPIRE_VERSION=${SUPPORTED_LOCAL_SPIRE_VERSION}"
  )

  if [[ -n "${SUPPORTED_LOCAL_VAULT_ADDRESS:-}" ]]; then
    cmd+=("SUPPORTED_LOCAL_VAULT_ADDRESS=${SUPPORTED_LOCAL_VAULT_ADDRESS}")
  fi
  if [[ -n "${SUPPORTED_LOCAL_VAULT_PUBLIC_HOST:-}" ]]; then
    cmd+=("SUPPORTED_LOCAL_VAULT_PUBLIC_HOST=${SUPPORTED_LOCAL_VAULT_PUBLIC_HOST}")
  fi
  if [[ -n "${SUPPORTED_LOCAL_VAULT_PORT:-}" ]]; then
    cmd+=("SUPPORTED_LOCAL_VAULT_PORT=${SUPPORTED_LOCAL_VAULT_PORT}")
  fi
  if [[ -n "${SUPPORTED_LOCAL_VAULT_SECRET_VALUE:-}" ]]; then
    cmd+=("SUPPORTED_LOCAL_VAULT_SECRET_VALUE=${SUPPORTED_LOCAL_VAULT_SECRET_VALUE}")
  fi
  if [[ -n "${SUPPORTED_LOCAL_VAULT_ROOT_TOKEN:-}" ]]; then
    cmd+=("SUPPORTED_LOCAL_VAULT_ROOT_TOKEN=${SUPPORTED_LOCAL_VAULT_ROOT_TOKEN}")
  elif [[ -n "${SUPPORTED_LOCAL_VAULT_TOKEN:-}" ]]; then
    cmd+=("SUPPORTED_LOCAL_VAULT_TOKEN=${SUPPORTED_LOCAL_VAULT_TOKEN}")
  fi

  cmd+=(bash -s -- setup)
  "${cmd[@]}" < "${REPO_ROOT}/scripts/72_supported_local_setup.sh" | tee "${SUPPORTED_LOCAL_HOST_PROOF_DIR}/host-guest-setup.txt"
}

copy_inputs_to_guest() {
  limactl shell "${SUPPORTED_LOCAL_INSTANCE}" -- \
    env GUEST_PROOF_DIR="${SUPPORTED_LOCAL_GUEST_PROOF_DIR}" \
    bash -lc 'mkdir -p "${GUEST_PROOF_DIR}/payload"'

  limactl shell "${SUPPORTED_LOCAL_INSTANCE}" -- \
    env GUEST_PROOF_DIR="${SUPPORTED_LOCAL_GUEST_PROOF_DIR}" \
    bash -lc 'cat > "${GUEST_PROOF_DIR}/payload/runtime_identity_vault_login.tar.gz"' \
    < "${SUPPORTED_LOCAL_HOST_PROOF_DIR}/payload/runtime_identity_vault_login.tar.gz"

  limactl shell "${SUPPORTED_LOCAL_INSTANCE}" -- \
    env GUEST_PROOF_DIR="${SUPPORTED_LOCAL_GUEST_PROOF_DIR}" \
    bash -lc 'cat > "${GUEST_PROOF_DIR}/runtime_identity_vault_success.input.json"' \
    < "${SUPPORTED_LOCAL_HOST_PROOF_DIR}/runtime_identity_vault_success.input.json"
}

capture_supported_host_evidence() {
  run_guest_stdin <<'EOF'
cd "$GUEST_REPO_ROOT"
source "$GUEST_PROOF_DIR/env.sh"
systemctl is-enabled nomad > "$GUEST_PROOF_DIR/systemctl-is-enabled-nomad.txt"
systemctl is-active nomad > "$GUEST_PROOF_DIR/systemctl-is-active-nomad.txt"
systemctl status nomad --no-pager --full > "$GUEST_PROOF_DIR/systemctl-status-nomad.txt"
curl --fail-with-body --silent --show-error "$NOMAD_ADDR/v1/agent/self" > "$GUEST_PROOF_DIR/nomad-agent-self.json"
curl --fail-with-body --silent --show-error "$NOMAD_ADDR/v1/status/leader" > "$GUEST_PROOF_DIR/nomad-leader.json"
curl --fail-with-body --silent --show-error "$NOMAD_ADDR/v1/nodes" > "$GUEST_PROOF_DIR/nomad-nodes.json"
python3 - <<'PY' "$GUEST_PROOF_DIR/node-details.json" "$NOMAD_ADDR"
import json
import pathlib
import sys
import urllib.request

out_path = pathlib.Path(sys.argv[1])
base_url = sys.argv[2].rstrip("/")
nodes = json.load(urllib.request.urlopen(base_url + "/v1/nodes"))
details = []
for node in nodes:
    node_id = (node.get("ID") or "").strip()
    if not node_id:
        continue
    details.append(json.load(urllib.request.urlopen(base_url + f"/v1/node/{node_id}")))
out_path.write_text(json.dumps(details, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
docker info > "$GUEST_PROOF_DIR/docker-info.txt"
{
  grep -R -n 'cpu_total_compute\|NOMAD_CLIENT_CPU_TOTAL_COMPUTE' /etc/nomad.d || true
  env | grep '^NOMAD_CLIENT_CPU_TOTAL_COMPUTE=' || true
} > "$GUEST_PROOF_DIR/nomad-compute-override-check.txt"
EOF
}

capture_execution_evidence() {
  run_guest_stdin <<'EOF'
cd "$GUEST_REPO_ROOT"
source "$GUEST_PROOF_DIR/env.sh"
python3 - <<'PY' "$GUEST_PROOF_DIR"
import json
import pathlib
import sys

proof_dir = pathlib.Path(sys.argv[1])
workdirs = sorted([path for path in (proof_dir / "workdirs").iterdir() if path.is_dir()])
if not workdirs:
    raise SystemExit("no execution-loop workdirs found")
latest = workdirs[-1]
for name in (
    "summary.json",
    "status.json",
    "logs.txt",
    "publish-response.json",
    "prepare-response.json",
    "submit-response.json",
):
    src = latest / name
    if src.exists():
        (proof_dir / name).write_bytes(src.read_bytes())

summary = json.loads((latest / "summary.json").read_text(encoding="utf-8"))
(proof_dir / "latest-workdir.txt").write_text(str(latest) + "\n", encoding="utf-8")
(proof_dir / "run-id.txt").write_text((summary.get("run_id") or "").strip() + "\n", encoding="utf-8")
PY

run_id="$(tr -d '[:space:]' < "$GUEST_PROOF_DIR/run-id.txt")"
if [[ -z "${run_id}" ]]; then
  echo "missing run_id in execution summary" >&2
  exit 1
fi
job_id="exec-${run_id}"
nomad job status "${job_id}" > "$GUEST_PROOF_DIR/nomad-job-status.txt"
nomad job allocs -json "${job_id}" > "$GUEST_PROOF_DIR/nomad-job-allocs.json"
alloc_id="$(python3 - <<'PY' "$GUEST_PROOF_DIR/nomad-job-allocs.json"
import json
import pathlib
import sys

allocs = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if not allocs:
    raise SystemExit("no allocations found for job")
print((allocs[0].get("ID") or "").strip())
PY
)"
nomad alloc status "${alloc_id}" > "$GUEST_PROOF_DIR/nomad-alloc-status.txt"

staging_root="$(python3 - <<'PY' "$GUEST_PROOF_DIR/es.json"
import json
import pathlib
import sys

cfg = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
print(cfg["execution"]["staging_root_dir"])
PY
)"
if [[ -d "${staging_root}/${run_id}" ]]; then
  echo "present" > "$GUEST_PROOF_DIR/staging-check.txt"
else
  echo "absent" > "$GUEST_PROOF_DIR/staging-check.txt"
fi
EOF
}

run() {
  require_command limactl
  require_command go
  require_command python3
  require_command tar
  require_command curl

  if [[ -e "${SUPPORTED_LOCAL_HOST_PROOF_DIR}" ]]; then
    echo "host proof dir already exists: ${SUPPORTED_LOCAL_HOST_PROOF_DIR}" >&2
    exit 1
  fi

  mkdir -p "${SUPPORTED_LOCAL_HOST_PROOF_DIR}"
  write_proof_metadata
  trap finalize EXIT

  prepare_host_repo_snapshot
  prepare_host_inputs
  prepare_host_tooling
  prepare_guest_bootstrap_dir
  copy_repo_snapshot_to_guest
  extract_guest_repo_snapshot
  cleanup_stale_guest_proof_scratch | tee "${SUPPORTED_LOCAL_HOST_PROOF_DIR}/cleanup-guest-scratch.txt"
  copy_tooling_to_guest
  setup_guest_environment
  copy_inputs_to_guest
  collect_guest_workspace

  run_guest_stdin <<'EOF' >/dev/null 2>&1 || true
cd "$GUEST_REPO_ROOT"
if [[ -f "$GUEST_PROOF_DIR/env.sh" ]]; then
  source "$GUEST_PROOF_DIR/env.sh"
  scripts/01_bringup.sh down
fi
EOF

  run_guest_stdin <<'EOF' | tee "${SUPPORTED_LOCAL_HOST_PROOF_DIR}/prepare-only-up.txt"
cd "$GUEST_REPO_ROOT"
source "$GUEST_PROOF_DIR/env.sh"
export BRINGUP_PROFILE=prepare-only
scripts/01_bringup.sh up
EOF
  CONTROL_PLANE_STARTED="true"

  run_guest_stdin <<'EOF' | tee "${SUPPORTED_LOCAL_HOST_PROOF_DIR}/full-check.txt"
cd "$GUEST_REPO_ROOT"
source "$GUEST_PROOF_DIR/env.sh"
BRINGUP_PROFILE=full scripts/01_bringup.sh check
EOF
  capture_supported_host_evidence

  run_guest_stdin <<'EOF' | tee "${SUPPORTED_LOCAL_HOST_PROOF_DIR}/execute-loop.txt"
cd "$GUEST_REPO_ROOT"
source "$GUEST_PROOF_DIR/env.sh"
scripts/60_execute_loop.sh "$GUEST_PROOF_DIR/runtime_identity_vault_success.input.json"
EOF
  capture_execution_evidence

  cleanup_control_plane
  collect_guest_workspace
  remove_current_guest_scratch
  trap - EXIT
}

case "${ACTION}" in
  run)
    run
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage >&2
    exit 1
    ;;
esac
