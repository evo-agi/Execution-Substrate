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
SUPPORTED_LOCAL_PORT_BASE="${SUPPORTED_LOCAL_PORT_BASE:-18440}"
SUPPORTED_LOCAL_INPUT_SPEC="${SUPPORTED_LOCAL_INPUT_SPEC:-${REPO_ROOT}/.examples/execution_loop/runtime_identity_vault_success.input.json}"
SUPPORTED_LOCAL_DIST_PAYLOAD="${SUPPORTED_LOCAL_DIST_PAYLOAD:-${REPO_ROOT}/.examples/runtime_identity_vault_login/dist/runtime_identity_vault_login.tar.gz}"

CONTROL_PLANE_STARTED="false"

usage() {
  cat <<'EOF'
Usage:
  scripts/73_supported_local_proof.sh run

This is the canonical supported-local proof wrapper for the current Apple
Silicon Mac + Lima qemu reference path. It:
  - creates the canonical proof workspace under .out/es-proof-<id>/
  - packages the bounded runtime-identity Vault-login workload
  - invokes scripts/72_supported_local_setup.sh inside the Linux guest
  - runs supported-host qualification without cpu_total_compute override
  - runs the higher-value useful credential-flow proof
  - copies resulting guest evidence back into the canonical .out workspace

Optional environment variables:
  SUPPORTED_LOCAL_INSTANCE=es-lima-qemu-arm64
  SUPPORTED_LOCAL_REPO_ROOT_IN_GUEST=/Users/ds/Repositories/Execution Substrate
  SUPPORTED_LOCAL_PROOF_ID=<proof-id>
  SUPPORTED_LOCAL_HOST_PROOF_DIR=/abs/path/.out/es-proof-<id>
  SUPPORTED_LOCAL_GUEST_PROOF_DIR=/tmp/es-proof-<id>
  SUPPORTED_LOCAL_PORT_BASE=18440
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
      GUEST_REPO_ROOT="${SUPPORTED_LOCAL_REPO_ROOT_IN_GUEST}" \
      GUEST_PROOF_DIR="${SUPPORTED_LOCAL_GUEST_PROOF_DIR}" \
    bash -seuo pipefail
}

collect_guest_workspace() {
  mkdir -p "${SUPPORTED_LOCAL_HOST_PROOF_DIR}"
  if ! limactl shell "${SUPPORTED_LOCAL_INSTANCE}" -- \
    env GUEST_PROOF_DIR="${SUPPORTED_LOCAL_GUEST_PROOF_DIR}" \
    bash -lc 'if [[ -d "${GUEST_PROOF_DIR}" ]]; then tar --ignore-failed-read --exclude=mock-spire.sock -C "${GUEST_PROOF_DIR}" -cf - . 2>/dev/null; fi' \
    | tar -C "${SUPPORTED_LOCAL_HOST_PROOF_DIR}" -xf - 2>/dev/null; then
    return 0
  fi
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

stop_pid_file "$GUEST_PROOF_DIR/mock-vault.pid"
stop_pid_file "$GUEST_PROOF_DIR/mock-spire.pid"
EOF
  CONTROL_PLANE_STARTED="false"
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
    "${SUPPORTED_LOCAL_GUEST_PROOF_DIR}" \
    "${SUPPORTED_LOCAL_HOST_PROOF_DIR}" \
    "${SUPPORTED_LOCAL_INPUT_SPEC}" \
    "${SUPPORTED_LOCAL_PROOF_ID}"
import json
import pathlib
import sys

payload = {
    "instance": sys.argv[2],
    "guest_repo_root": sys.argv[3],
    "guest_proof_dir": sys.argv[4],
    "host_proof_dir": sys.argv[5],
    "input_spec": sys.argv[6],
    "proof_id": sys.argv[7],
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
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

setup_guest_environment() {
  local -a cmd=(
    limactl shell "${SUPPORTED_LOCAL_INSTANCE}" --
    env
    "EXECUTION_SUBSTRATE_REPO_ROOT=${SUPPORTED_LOCAL_REPO_ROOT_IN_GUEST}"
    "SUPPORTED_LOCAL_PROOF_DIR=${SUPPORTED_LOCAL_GUEST_PROOF_DIR}"
    "SUPPORTED_LOCAL_PROOF_ID=${SUPPORTED_LOCAL_PROOF_ID}"
    "SUPPORTED_LOCAL_PORT_BASE=${SUPPORTED_LOCAL_PORT_BASE}"
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
  if [[ -n "${SUPPORTED_LOCAL_VAULT_TOKEN:-}" ]]; then
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
  require_command python3
  require_command tar

  if [[ -e "${SUPPORTED_LOCAL_HOST_PROOF_DIR}" ]]; then
    echo "host proof dir already exists: ${SUPPORTED_LOCAL_HOST_PROOF_DIR}" >&2
    exit 1
  fi

  mkdir -p "${SUPPORTED_LOCAL_HOST_PROOF_DIR}"
  write_proof_metadata
  trap finalize EXIT

  prepare_host_inputs
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
