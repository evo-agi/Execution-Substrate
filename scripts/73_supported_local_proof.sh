#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PARENT_ROOT="$(cd "${REPO_ROOT}/.." && pwd)"
source "${SCRIPT_DIR}/internal/supported_local_retained_result_auth.sh"
source "${SCRIPT_DIR}/internal/spire_release.sh"

ACTION="${1:-run}"
SUPPORTED_LOCAL_INSTANCE="${SUPPORTED_LOCAL_INSTANCE:-es-lima-qemu-arm64}"
SUPPORTED_LOCAL_REPO_ROOT_IN_GUEST="${SUPPORTED_LOCAL_REPO_ROOT_IN_GUEST:-/Users/ds/Repositories/Execution Substrate}"
SUPPORTED_LOCAL_PROOF_ID="${SUPPORTED_LOCAL_PROOF_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
SUPPORTED_LOCAL_HOST_PROOF_DIR="${SUPPORTED_LOCAL_HOST_PROOF_DIR:-${REPO_ROOT}/.out/es-proof-${SUPPORTED_LOCAL_PROOF_ID}}"
SUPPORTED_LOCAL_HOST_BOOTSTRAP_DIR="${PARENT_ROOT}/es-proof-bootstrap-${SUPPORTED_LOCAL_PROOF_ID}"
SUPPORTED_LOCAL_GUEST_PROOF_DIR="${SUPPORTED_LOCAL_GUEST_PROOF_DIR:-/tmp/es-proof-${SUPPORTED_LOCAL_PROOF_ID}}"
SUPPORTED_LOCAL_GUEST_BOOTSTRAP_DIR="${SUPPORTED_LOCAL_GUEST_BOOTSTRAP_DIR:-${SUPPORTED_LOCAL_GUEST_PROOF_DIR}.bootstrap}"
SUPPORTED_LOCAL_GUEST_REPO_ROOT="${SUPPORTED_LOCAL_GUEST_REPO_ROOT:-${SUPPORTED_LOCAL_GUEST_BOOTSTRAP_DIR}/repo}"
SUPPORTED_LOCAL_PORT_BASE="${SUPPORTED_LOCAL_PORT_BASE:-18440}"
SUPPORTED_LOCAL_INPUT_SPEC="${SUPPORTED_LOCAL_INPUT_SPEC:-${REPO_ROOT}/.examples/execution_loop/runtime_identity_vault_success.input.json}"
SUPPORTED_LOCAL_DIST_PAYLOAD="${SUPPORTED_LOCAL_DIST_PAYLOAD:-}"
SUPPORTED_LOCAL_CP_NORMAL_SHELL_INPUT_SPEC="${SUPPORTED_LOCAL_CP_NORMAL_SHELL_INPUT_SPEC:-${REPO_ROOT}/.examples/execution_loop/control_plane_normal_shell_runtime.input.json}"
SUPPORTED_LOCAL_CP_NORMAL_SHELL_DIST_PAYLOAD="${SUPPORTED_LOCAL_CP_NORMAL_SHELL_DIST_PAYLOAD:-}"
SUPPORTED_LOCAL_SPIRE_VERSION="${SUPPORTED_LOCAL_SPIRE_VERSION:-1.14.4}"
SUPPORTED_LOCAL_SPIRE_ASSET="${SUPPORTED_LOCAL_SPIRE_ASSET:-spire-${SUPPORTED_LOCAL_SPIRE_VERSION}-linux-arm64-musl.tar.gz}"
SUPPORTED_LOCAL_SPIRE_URL="${SUPPORTED_LOCAL_SPIRE_URL:-https://github.com/spiffe/spire/releases/download/v${SUPPORTED_LOCAL_SPIRE_VERSION}/${SUPPORTED_LOCAL_SPIRE_ASSET}}"
SUPPORTED_LOCAL_PREBUILT_SPIRE_TARBALL="${SUPPORTED_LOCAL_PREBUILT_SPIRE_TARBALL:-}"
GO_REQUIRED_VERSION="go1.26.5"

CONTROL_PLANE_STARTED="false"
GUEST_COLLECTION_READY="false"
HOST_BOOTSTRAP_IDENTITY=""

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
  - runs the bounded Control Plane normal-shell runtime-contract proof
  - publishes projected guest evidence into exclusive .out generations
  - keeps source and transport inputs in separate private host bootstrap scratch
  - removes successful guest /tmp/es-proof-* scratch after host evidence is preserved

The SPIRE release file, downloaded or prebuilt, is staged for the guest only
if its SHA-256 is the one that scripts/internal/spire_release.sha256 pins for
SUPPORTED_LOCAL_SPIRE_ASSET, and the guest setup checks it again before it
unpacks it. A release file with no line there is refused before the wrapper
creates anything.

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
  SUPPORTED_LOCAL_CP_NORMAL_SHELL_INPUT_SPEC=/abs/path/to/control_plane_normal_shell_runtime.input.json
  SUPPORTED_LOCAL_CP_NORMAL_SHELL_DIST_PAYLOAD=/abs/path/to/control_plane_normal_shell_runtime.tar.gz
  SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_STORE_ID=<stable non-secret identifier>
  SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_ID=<stable non-secret identifier>
  SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_FILE=/guest/external/private/keys/key
  SUPPORTED_LOCAL_NOMAD_ACL_DIR=/etc/execution-substrate/nomad-acl   (in the guest)

The guest's Nomad must enforce access control (ACLs). Run
scripts/70_linux_setup.sh in the guest first; guest setup then keeps or
issues ES's Nomad token and a read-only observer token for evidence capture.
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

supported_local_proof_requires_local_go() {
  # local-Go-required: the proof wrapper cross-builds es-runtime-support before
  # it writes host proof state. A prebuilt SPIRE tarball bypasses only the SPIRE
  # download; it is not a no-local-Go proof path.
  # prebuilt/no-local-Go: not applicable for this proof entry point.
  return 0
}

preflight_supported_local_proof_go_if_required() {
  if supported_local_proof_requires_local_go; then
    require_supported_go_toolchain
  fi
}

preflight_supported_local_proof_retained_result_auth() {
  supported_local_validate_retained_result_auth \
    "${SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_STORE_ID:-}" \
    "${SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_ID:-}" \
    "${SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_FILE:-}" \
    "${SUPPORTED_LOCAL_GUEST_PROOF_DIR}" \
    "${SUPPORTED_LOCAL_GUEST_PROOF_DIR}/es-staging" \
    "${SUPPORTED_LOCAL_GUEST_PROOF_DIR}/es-results" \
    "${SUPPORTED_LOCAL_GUEST_BOOTSTRAP_DIR}" \
    "${SUPPORTED_LOCAL_GUEST_REPO_ROOT}" \
    "${SUPPORTED_LOCAL_REPO_ROOT_IN_GUEST}" \
    "${SUPPORTED_LOCAL_HOST_PROOF_DIR}" \
    "${SUPPORTED_LOCAL_HOST_BOOTSTRAP_DIR}"
}

preflight_supported_local_proof_bootstrap_scope() {
  python3 -I - "${REPO_ROOT}" "${PARENT_ROOT}" "${SUPPORTED_LOCAL_HOST_PROOF_DIR}" \
    "${SUPPORTED_LOCAL_HOST_BOOTSTRAP_DIR}" "${SUPPORTED_LOCAL_GUEST_PROOF_DIR}" \
    "${SUPPORTED_LOCAL_GUEST_BOOTSTRAP_DIR}" "${SUPPORTED_LOCAL_GUEST_REPO_ROOT}" \
    "${SUPPORTED_LOCAL_REPO_ROOT_IN_GUEST}" "${SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_FILE:-}" \
    "${SUPPORTED_LOCAL_PROOF_ID}" <<'PY'
import os
import re
import sys

repo, parent, evidence, scratch, guest, bootstrap, guest_repo, mounted, key, proof_id = sys.argv[1:]
def clean(path):
    return path.startswith('/') and not path.startswith('//') and path != '/' and os.path.normpath(path) == path
def overlaps(left, right):
    return left == right or left.startswith(right + '/') or right.startswith(left + '/')
if not all(clean(path) for path in (repo, parent, evidence, scratch, guest, bootstrap, guest_repo, mounted)):
    raise SystemExit('supported-local proof scope is invalid')
if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', proof_id):
    raise SystemExit('supported-local proof id is invalid')
if os.path.dirname(scratch) != parent or os.path.basename(scratch) != 'es-proof-bootstrap-' + proof_id:
    raise SystemExit('supported-local bootstrap placement is invalid')
if any(overlaps(scratch, path) for path in (repo, evidence, guest, bootstrap, guest_repo, mounted)):
    raise SystemExit('supported-local bootstrap scope overlaps another scope')
if key and overlaps(scratch, key):
    raise SystemExit('supported-local bootstrap scope overlaps retained-result key')
PY
}

supported_local_proof_repair_test_sentinel() {
  if [[ "${SUPPORTED_LOCAL_REPAIR_TEST_SENTINEL:-}" == "after-go-preflight" ]]; then
    echo "supported-local proof exact Go preflight complete"
    exit 0
  fi
}

run_guest_stdin() {
  limactl shell "${SUPPORTED_LOCAL_INSTANCE}" -- \
    env \
      GUEST_REPO_ROOT="${SUPPORTED_LOCAL_GUEST_REPO_ROOT}" \
      GUEST_PROOF_DIR="${SUPPORTED_LOCAL_GUEST_PROOF_DIR}" \
      GUEST_BOOTSTRAP_DIR="${SUPPORTED_LOCAL_GUEST_BOOTSTRAP_DIR}" \
      EVIDENCE_LABEL="${EVIDENCE_LABEL:-}" \
    bash -seuo pipefail
}

collect_guest_workspace() {
  local generation=${1:?safe evidence generation required}
  case "${generation}" in setup|final|failure) ;; *) return 1 ;; esac
  if ! limactl shell "${SUPPORTED_LOCAL_INSTANCE}" -- \
    bash -s -- collect-safe "${SUPPORTED_LOCAL_GUEST_PROOF_DIR}" \
    < "${SCRIPT_DIR}/internal/supported_local_proof_evidence.sh" 2>/dev/null \
    | bash "${SCRIPT_DIR}/internal/supported_local_proof_evidence.sh" \
      receive-safe "${SUPPORTED_LOCAL_HOST_PROOF_DIR}" "${generation}" 2>/dev/null; then
    echo "supported-local safe evidence collection failed" >&2
    return 1
  fi
}

create_private_host_bootstrap_dir() {
  HOST_BOOTSTRAP_IDENTITY="$(python3 -I "${SCRIPT_DIR}/internal/supported_local_proof_source_snapshot.py" \
    create-scratch "${SUPPORTED_LOCAL_HOST_BOOTSTRAP_DIR}" "${SUPPORTED_LOCAL_PROOF_ID}")"
}

cleanup_host_bootstrap_scratch() {
  if [[ -z "${HOST_BOOTSTRAP_IDENTITY}" ]]; then
    [[ ! -e "${SUPPORTED_LOCAL_HOST_BOOTSTRAP_DIR}" && ! -L "${SUPPORTED_LOCAL_HOST_BOOTSTRAP_DIR}" ]]
    return
  fi
  python3 -I "${SCRIPT_DIR}/internal/supported_local_proof_source_snapshot.py" \
    cleanup-scratch "${SUPPORTED_LOCAL_HOST_BOOTSTRAP_DIR}" "${HOST_BOOTSTRAP_IDENTITY}"
}

finalize_host_evidence_manifest() {
  python3 -I "${SCRIPT_DIR}/internal/supported_local_proof_host_manifest.py" \
    finalize "${SUPPORTED_LOCAL_HOST_PROOF_DIR}"
}

write_phase_status() {
  local phase=$1 status=$2
  python3 -I - "${SUPPORTED_LOCAL_HOST_PROOF_DIR}" "${phase}" "${status}" <<'PY'
import json
import os
import pathlib
import sys

root, phase, status = sys.argv[1:]
allowed = {'source-snapshot', 'input-preparation', 'package-identity', 'package-normal-shell', 'runtime-support-build',
           'spire-stage', 'guest-bootstrap', 'snapshot-transfer', 'snapshot-extract', 'snapshot-drop',
           'cleanup-guest-scratch', 'tooling-transfer', 'guest-setup', 'input-transfer',
           'prepare-only-up', 'full-check', 'supported-host-capture', 'runtime-identity-execute',
           'normal-shell-execute', 'runtime-identity-capture', 'normal-shell-capture',
           'result-validation', 'guest-cleanup'}
if phase not in allowed or not status.isdecimal() or int(status) > 255:
    raise SystemExit('invalid proof phase status')
path = pathlib.Path(root) / ('phase-' + phase + '.json')
data = (json.dumps({'schema': 'supported-local-proof-phase-v1', 'phase': phase,
                    'success': int(status) == 0, 'exit_code': int(status)},
                   sort_keys=True, separators=(',', ':')) + '\n').encode()
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
try:
    with os.fdopen(fd, 'wb', closefd=False) as output:
        output.write(data)
    os.fchmod(fd, 0o600)
finally:
    os.close(fd)
PY
}

run_phase() {
  local phase=$1 status=0
  shift
  "$@" >/dev/null 2>&1 || status=$?
  if ! write_phase_status "${phase}" "${status}" >/dev/null 2>&1; then
    echo "supported-local proof phase projection failed: ${phase}" >&2
    if [[ "${status}" -ne 0 ]]; then return "${status}"; fi
    return 1
  fi
  if [[ "${status}" -ne 0 ]]; then
    echo "supported-local proof phase failed: ${phase}" >&2
    return "${status}"
  fi
}

create_private_host_proof_dir() {
  python3 -I - "${SUPPORTED_LOCAL_HOST_PROOF_DIR}" <<'PY'
import os
import pathlib
import stat
import sys

target = pathlib.Path(sys.argv[1])
if not target.is_absolute() or os.path.normpath(str(target)) != str(target):
    raise SystemExit("host proof directory must be a clean absolute path")
old_umask = os.umask(0o077)
try:
    os.mkdir(target, 0o700)
finally:
    os.umask(old_umask)
metadata = os.lstat(target)
if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700 or metadata.st_uid != os.geteuid():
    raise SystemExit("host proof directory is not a private real directory")
descriptor = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    observed = os.fstat(descriptor)
    if (observed.st_dev, observed.st_ino) != (metadata.st_dev, metadata.st_ino):
        raise SystemExit("host proof directory identity changed")
finally:
    os.close(descriptor)
PY
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
  run_guest_stdin <<'EOF'
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
  local original_status=${status}
  local collection_ok=true
  local scratch_removed=false
  trap - EXIT
  if [[ "${status}" -ne 0 && "${GUEST_COLLECTION_READY}" == "true" ]]; then
    cleanup_control_plane
    if ! collect_guest_workspace failure; then
      collection_ok=false
      echo "supported-local failure evidence collection failed" >&2
    fi
  fi
  if cleanup_host_bootstrap_scratch; then
    scratch_removed=true
  else
    echo "supported-local bootstrap scratch retained: exact cleanup could not be proved" >&2
    if [[ "${status}" -eq 0 ]]; then status=1; fi
  fi
  if ! write_proof_closeout "${original_status}" "${collection_ok}" "${scratch_removed}"; then
    echo "supported-local proof closeout projection failed" >&2
    if [[ "${status}" -eq 0 ]]; then status=1; fi
  fi
  if ! finalize_host_evidence_manifest; then
    echo "supported-local host evidence manifest failed" >&2
    if [[ "${status}" -eq 0 ]]; then status=1; fi
  fi
  exit "${status}"
}

write_proof_closeout() {
  python3 -I - "${SUPPORTED_LOCAL_HOST_PROOF_DIR}" "$1" "$2" "$3" <<'PY'
import json
import os
import pathlib
import sys

root, status, collection, scratch_removed = sys.argv[1:]
if not status.isdecimal() or int(status) > 255 or collection not in ('true', 'false') or scratch_removed not in ('true', 'false'):
    raise SystemExit('invalid proof closeout status')
data = (json.dumps({'schema': 'supported-local-proof-closeout-v1',
                    'primary_exit_code': int(status), 'failure_collection_succeeded': collection == 'true',
                    'bootstrap_scratch_removed': scratch_removed == 'true'},
                   sort_keys=True, separators=(',', ':')) + '\n').encode()
fd = os.open(pathlib.Path(root) / 'proof-closeout.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
try:
    with os.fdopen(fd, 'wb', closefd=False) as output:
        output.write(data)
    os.fchmod(fd, 0o600)
finally:
    os.close(fd)
PY
}

write_proof_metadata() {
  python3 -I - <<'PY' \
    "${SUPPORTED_LOCAL_HOST_PROOF_DIR}/proof-metadata.json" \
    "${SUPPORTED_LOCAL_PROOF_ID}"
import json
import os
import sys

data = (json.dumps({"schema": "supported-local-proof-metadata-v2", "proof_id": sys.argv[2]},
                   sort_keys=True, separators=(",", ":")) + "\n").encode()
fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
try:
    with os.fdopen(fd, "wb", closefd=False) as output:
        output.write(data)
    os.fchmod(fd, 0o600)
finally:
    os.close(fd)
PY
}

prepare_host_repo_snapshot() {
  python3 -I "${SCRIPT_DIR}/internal/supported_local_proof_source_snapshot.py" snapshot \
    "${REPO_ROOT}" "${SUPPORTED_LOCAL_HOST_BOOTSTRAP_DIR}" "${SUPPORTED_LOCAL_HOST_PROOF_DIR}"
}

prepare_host_inputs() {
  local payload_copy="${SUPPORTED_LOCAL_HOST_BOOTSTRAP_DIR}/payload/runtime_identity_vault_login.tar.gz"
  local spec_copy="${SUPPORTED_LOCAL_HOST_BOOTSTRAP_DIR}/runtime_identity_vault_success.input.json"
  local cp_payload_copy="${SUPPORTED_LOCAL_HOST_BOOTSTRAP_DIR}/payload/control_plane_normal_shell_runtime.tar.gz"
  local cp_spec_copy="${SUPPORTED_LOCAL_HOST_BOOTSTRAP_DIR}/control_plane_normal_shell_runtime.input.json"

  mkdir -m 0700 "${SUPPORTED_LOCAL_HOST_BOOTSTRAP_DIR}/payload"
  if [[ -n "${SUPPORTED_LOCAL_DIST_PAYLOAD}" ]]; then
    run_phase package-identity cp "${SUPPORTED_LOCAL_DIST_PAYLOAD}" "${payload_copy}" || return $?
  else
    run_phase package-identity python3 -I "${REPO_ROOT}/scripts/package_example_archive.py" \
      "${REPO_ROOT}/.examples/runtime_identity_vault_login/entrypoint" "${payload_copy}" entrypoint || return $?
  fi
  if [[ -n "${SUPPORTED_LOCAL_CP_NORMAL_SHELL_DIST_PAYLOAD}" ]]; then
    run_phase package-normal-shell cp "${SUPPORTED_LOCAL_CP_NORMAL_SHELL_DIST_PAYLOAD}" "${cp_payload_copy}" || return $?
  else
    run_phase package-normal-shell python3 -I "${REPO_ROOT}/scripts/package_example_archive.py" \
      "${REPO_ROOT}/.examples/control_plane_normal_shell_runtime/entrypoint" "${cp_payload_copy}" entrypoint || return $?
  fi

  python3 -I - <<'PY' \
    "${SUPPORTED_LOCAL_INPUT_SPEC}" \
    "${spec_copy}" \
    "${SUPPORTED_LOCAL_GUEST_PROOF_DIR}/payload/runtime_identity_vault_login.tar.gz"
import json
import os
import pathlib
import sys

spec = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
spec["payload_path"] = sys.argv[3]
pathlib.Path(sys.argv[2]).write_text(json.dumps(spec, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

  python3 -I - <<'PY' \
    "${SUPPORTED_LOCAL_CP_NORMAL_SHELL_INPUT_SPEC}" \
    "${cp_spec_copy}" \
    "${SUPPORTED_LOCAL_GUEST_PROOF_DIR}/payload/control_plane_normal_shell_runtime.tar.gz"
import json
import pathlib
import sys

spec = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
spec["payload_path"] = sys.argv[3]
pathlib.Path(sys.argv[2]).write_text(json.dumps(spec, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

prepare_host_tooling() {
  mkdir -m 0700 "${SUPPORTED_LOCAL_HOST_BOOTSTRAP_DIR}/bin"
  require_supported_go_toolchain

  build_runtime_support() {
    (
      cd "${REPO_ROOT}"
      env GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build \
        -o "${SUPPORTED_LOCAL_HOST_BOOTSTRAP_DIR}/bin/es-runtime-support" \
        ./cmd/es-runtime-support
    )
  }
  run_phase runtime-support-build build_runtime_support

  run_phase spire-stage stage_spire_distribution
}

# Stages the SPIRE release file for the guest only after its SHA-256 matches
# the one pinned for SUPPORTED_LOCAL_SPIRE_ASSET. The pin is looked up before
# the download, and the staged copy is the file that is checked.
stage_spire_distribution() {
  local staged="${SUPPORTED_LOCAL_HOST_BOOTSTRAP_DIR}/bin/spire.tar.gz"

  if ! spire_release_pinned_sha256 "${SUPPORTED_LOCAL_SPIRE_ASSET}" >/dev/null; then
    return 1
  fi
  if [[ -n "${SUPPORTED_LOCAL_PREBUILT_SPIRE_TARBALL}" ]]; then
    if ! cp "${SUPPORTED_LOCAL_PREBUILT_SPIRE_TARBALL}" "${staged}"; then
      return 1
    fi
  elif ! curl -L --fail --silent --show-error -o "${staged}" "${SUPPORTED_LOCAL_SPIRE_URL}"; then
    return 1
  fi
  if ! spire_release_verify "${staged}" "${SUPPORTED_LOCAL_SPIRE_ASSET}"; then
    rm -f -- "${staged}"
    return 1
  fi
}

prepare_guest_bootstrap_dir() {
  limactl shell "${SUPPORTED_LOCAL_INSTANCE}" -- \
    env \
      GUEST_BOOTSTRAP_DIR="${SUPPORTED_LOCAL_GUEST_BOOTSTRAP_DIR}" \
      GUEST_PROOF_DIR="${SUPPORTED_LOCAL_GUEST_PROOF_DIR}" \
      GUEST_REPO_ROOT="${SUPPORTED_LOCAL_GUEST_REPO_ROOT}" \
    bash -lc 'rm -rf "${GUEST_BOOTSTRAP_DIR}" && mkdir -p "${GUEST_BOOTSTRAP_DIR}" "$(dirname "${GUEST_REPO_ROOT}")"'
}

copy_repo_snapshot_to_guest() {
  limactl shell "${SUPPORTED_LOCAL_INSTANCE}" -- \
    env GUEST_BOOTSTRAP_DIR="${SUPPORTED_LOCAL_GUEST_BOOTSTRAP_DIR}" \
    bash -lc 'cat > "${GUEST_BOOTSTRAP_DIR}/repo-snapshot.tar.gz"' \
    < "${SUPPORTED_LOCAL_HOST_BOOTSTRAP_DIR}/host-repo-snapshot.tar.gz"
}

extract_guest_repo_snapshot() {
  local host_snapshot_sha
  host_snapshot_sha="$(python3 -I - <<'PY' "${SUPPORTED_LOCAL_HOST_PROOF_DIR}/source-snapshot.json"
import json
import pathlib
import sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text())['sha256']
print(value)
PY
)"

  limactl shell "${SUPPORTED_LOCAL_INSTANCE}" -- \
    env \
      GUEST_BOOTSTRAP_DIR="${SUPPORTED_LOCAL_GUEST_BOOTSTRAP_DIR}" \
      GUEST_PROOF_DIR="${SUPPORTED_LOCAL_GUEST_PROOF_DIR}" \
      GUEST_REPO_ROOT="${SUPPORTED_LOCAL_GUEST_REPO_ROOT}" \
      HOST_REPO_SNAPSHOT_SHA256="${host_snapshot_sha}" \
    bash -seuo pipefail <<'EOF'
python3 -I - <<'PY' "${GUEST_BOOTSTRAP_DIR}/repo-snapshot.tar.gz" "${GUEST_BOOTSTRAP_DIR}/guest-repo-snapshot.sha256"
import hashlib
import pathlib
import sys

snapshot_path = pathlib.Path(sys.argv[1])
digest = hashlib.sha256(snapshot_path.read_bytes()).hexdigest()
pathlib.Path(sys.argv[2]).write_text(digest + "\n", encoding="utf-8")
print(digest)
PY

guest_sha="$(tr -d '[:space:]' < "${GUEST_BOOTSTRAP_DIR}/guest-repo-snapshot.sha256")"
if [[ "${guest_sha}" != "${HOST_REPO_SNAPSHOT_SHA256}" ]]; then
  echo "guest repo snapshot digest mismatch: host=${HOST_REPO_SNAPSHOT_SHA256} guest=${guest_sha}" >&2
  exit 1
fi

rm -rf "${GUEST_REPO_ROOT}"
mkdir -p "${GUEST_REPO_ROOT}"
tar -xzf "${GUEST_BOOTSTRAP_DIR}/repo-snapshot.tar.gz" -C "${GUEST_REPO_ROOT}"
printf '%s\n' "${GUEST_REPO_ROOT}" > "${GUEST_BOOTSTRAP_DIR}/guest-repo-root.txt"
printf '%s\n' "${HOST_REPO_SNAPSHOT_SHA256}" > "${GUEST_BOOTSTRAP_DIR}/repo-snapshot-match.txt"
EOF
}

copy_tooling_to_guest() {
  limactl shell "${SUPPORTED_LOCAL_INSTANCE}" -- \
    env GUEST_BOOTSTRAP_DIR="${SUPPORTED_LOCAL_GUEST_BOOTSTRAP_DIR}" \
    bash -lc 'mkdir -p "${GUEST_BOOTSTRAP_DIR}"'

  limactl shell "${SUPPORTED_LOCAL_INSTANCE}" -- \
    env GUEST_BOOTSTRAP_DIR="${SUPPORTED_LOCAL_GUEST_BOOTSTRAP_DIR}" \
    bash -lc 'cat > "${GUEST_BOOTSTRAP_DIR}/es-runtime-support"' \
    < "${SUPPORTED_LOCAL_HOST_BOOTSTRAP_DIR}/bin/es-runtime-support"

  limactl shell "${SUPPORTED_LOCAL_INSTANCE}" -- \
    env GUEST_BOOTSTRAP_DIR="${SUPPORTED_LOCAL_GUEST_BOOTSTRAP_DIR}" \
    bash -lc 'cat > "${GUEST_BOOTSTRAP_DIR}/spire.tar.gz"' \
    < "${SUPPORTED_LOCAL_HOST_BOOTSTRAP_DIR}/bin/spire.tar.gz"

  limactl shell "${SUPPORTED_LOCAL_INSTANCE}" -- \
    env GUEST_BOOTSTRAP_DIR="${SUPPORTED_LOCAL_GUEST_BOOTSTRAP_DIR}" \
    bash -lc 'chmod 0755 "${GUEST_BOOTSTRAP_DIR}/es-runtime-support" && chmod 0644 "${GUEST_BOOTSTRAP_DIR}/spire.tar.gz"'
}

build_supported_local_guest_setup_command() {
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
    "SUPPORTED_LOCAL_ALLOW_CONTROL_PLANE=${SUPPORTED_LOCAL_ALLOW_CONTROL_PLANE:-1}"
    "SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_STORE_ID=${SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_STORE_ID:-}"
    "SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_ID=${SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_ID:-}"
    "SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_FILE=${SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_FILE:-}"
  )

  if [[ -n "${SUPPORTED_LOCAL_NOMAD_ACL_DIR:-}" ]]; then
    cmd+=("SUPPORTED_LOCAL_NOMAD_ACL_DIR=${SUPPORTED_LOCAL_NOMAD_ACL_DIR}")
  fi
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
  if [[ -n "${SUPPORTED_LOCAL_CODEX_RUNTIME_PROFILE_IMAGE:-}" ]]; then
    cmd+=("SUPPORTED_LOCAL_CODEX_RUNTIME_PROFILE_IMAGE=${SUPPORTED_LOCAL_CODEX_RUNTIME_PROFILE_IMAGE}")
  fi
  if [[ -n "${SUPPORTED_LOCAL_CODEX_CLI_PATH:-}" ]]; then
    cmd+=("SUPPORTED_LOCAL_CODEX_CLI_PATH=${SUPPORTED_LOCAL_CODEX_CLI_PATH}")
  fi
  if [[ -n "${SUPPORTED_LOCAL_CODEX_REALIZATION:-}" ]]; then
    cmd+=("SUPPORTED_LOCAL_CODEX_REALIZATION=${SUPPORTED_LOCAL_CODEX_REALIZATION}")
  fi
  if [[ -n "${SUPPORTED_LOCAL_CODEX_CREDENTIAL_SECRET_PATH:-}" ]]; then
    cmd+=("SUPPORTED_LOCAL_CODEX_CREDENTIAL_SECRET_PATH=${SUPPORTED_LOCAL_CODEX_CREDENTIAL_SECRET_PATH}")
  fi
  if [[ -n "${SUPPORTED_LOCAL_CODEX_CREDENTIAL_SECRET_FIELD:-}" ]]; then
    cmd+=("SUPPORTED_LOCAL_CODEX_CREDENTIAL_SECRET_FIELD=${SUPPORTED_LOCAL_CODEX_CREDENTIAL_SECRET_FIELD}")
  fi
  if [[ -n "${SUPPORTED_LOCAL_CODEX_CREDENTIAL_VALUE:-}" ]]; then
    cmd+=("SUPPORTED_LOCAL_CODEX_CREDENTIAL_VALUE=${SUPPORTED_LOCAL_CODEX_CREDENTIAL_VALUE}")
  fi
  if [[ -n "${SUPPORTED_LOCAL_BUILD_CODEX_RUNTIME_PROFILE_IMAGE:-}" ]]; then
    cmd+=("SUPPORTED_LOCAL_BUILD_CODEX_RUNTIME_PROFILE_IMAGE=${SUPPORTED_LOCAL_BUILD_CODEX_RUNTIME_PROFILE_IMAGE}")
  fi

  cmd+=(bash -s -- setup)
  SUPPORTED_LOCAL_GUEST_SETUP_CMD=("${cmd[@]}")
}

setup_guest_environment() {
  build_supported_local_guest_setup_command
  "${SUPPORTED_LOCAL_GUEST_SETUP_CMD[@]}" < "${REPO_ROOT}/scripts/72_supported_local_setup.sh"
}

copy_inputs_to_guest() {
  # Setup exclusively creates the fresh proof root. Move only fixed nonsecret
  # snapshot metadata from earlier bootstrap scratch after setup has returned.
  limactl shell "${SUPPORTED_LOCAL_INSTANCE}" -- \
    env GUEST_BOOTSTRAP_DIR="${SUPPORTED_LOCAL_GUEST_BOOTSTRAP_DIR}" GUEST_PROOF_DIR="${SUPPORTED_LOCAL_GUEST_PROOF_DIR}" \
    bash -lc 'cp -- "${GUEST_BOOTSTRAP_DIR}/guest-repo-snapshot.sha256" "${GUEST_BOOTSTRAP_DIR}/guest-repo-root.txt" "${GUEST_BOOTSTRAP_DIR}/repo-snapshot-match.txt" "${GUEST_PROOF_DIR}/"'

  limactl shell "${SUPPORTED_LOCAL_INSTANCE}" -- \
    env GUEST_PROOF_DIR="${SUPPORTED_LOCAL_GUEST_PROOF_DIR}" \
    bash -lc 'mkdir -p "${GUEST_PROOF_DIR}/payload"'

  limactl shell "${SUPPORTED_LOCAL_INSTANCE}" -- \
    env GUEST_PROOF_DIR="${SUPPORTED_LOCAL_GUEST_PROOF_DIR}" \
    bash -lc 'cat > "${GUEST_PROOF_DIR}/payload/runtime_identity_vault_login.tar.gz"' \
    < "${SUPPORTED_LOCAL_HOST_BOOTSTRAP_DIR}/payload/runtime_identity_vault_login.tar.gz"

  limactl shell "${SUPPORTED_LOCAL_INSTANCE}" -- \
    env GUEST_PROOF_DIR="${SUPPORTED_LOCAL_GUEST_PROOF_DIR}" \
    bash -lc 'cat > "${GUEST_PROOF_DIR}/runtime_identity_vault_success.input.json"' \
    < "${SUPPORTED_LOCAL_HOST_BOOTSTRAP_DIR}/runtime_identity_vault_success.input.json"

  limactl shell "${SUPPORTED_LOCAL_INSTANCE}" -- \
    env GUEST_PROOF_DIR="${SUPPORTED_LOCAL_GUEST_PROOF_DIR}" \
    bash -lc 'cat > "${GUEST_PROOF_DIR}/payload/control_plane_normal_shell_runtime.tar.gz"' \
    < "${SUPPORTED_LOCAL_HOST_BOOTSTRAP_DIR}/payload/control_plane_normal_shell_runtime.tar.gz"

  limactl shell "${SUPPORTED_LOCAL_INSTANCE}" -- \
    env GUEST_PROOF_DIR="${SUPPORTED_LOCAL_GUEST_PROOF_DIR}" \
    bash -lc 'cat > "${GUEST_PROOF_DIR}/control_plane_normal_shell_runtime.input.json"' \
    < "${SUPPORTED_LOCAL_HOST_BOOTSTRAP_DIR}/control_plane_normal_shell_runtime.input.json"
}

capture_supported_host_evidence() {
  run_guest_stdin <<'EOF'
cd "$GUEST_REPO_ROOT"
source "$GUEST_PROOF_DIR/env.sh"
# Nomad enforces ACLs: reads use the read-only observer token named by
# NOMAD_TOKEN_FILE (env.sh), sent in a header, never on a command line.
source "$GUEST_REPO_ROOT/scripts/internal/nomad_acl.sh"
projector="$GUEST_REPO_ROOT/scripts/internal/supported_local_proof_projection.py"
systemctl show nomad --no-pager --property=Id,LoadState,ActiveState,SubState,UnitFileState,MainPID,ExecMainStatus |
  python3 -I "$projector" host-systemd - "$GUEST_PROOF_DIR/nomad-service-safe.json"
nomad_acl_state_check >/dev/null
nomad_api_get /v1/agent/self /dev/stdout |
  python3 -I "$projector" host-agent - "$GUEST_PROOF_DIR/nomad-agent-safe.json"
nomad_api_get /v1/status/leader /dev/stdout |
  python3 -I "$projector" host-leader - "$GUEST_PROOF_DIR/nomad-leader-safe.json"
nomad_api_get /v1/nodes /dev/stdout |
  python3 -I "$projector" host-nodes - "$GUEST_PROOF_DIR/nomad-nodes-safe.json"
python3 -I "$projector" fetch-node-details "$NOMAD_ADDR" "$GUEST_PROOF_DIR/node-details-safe.json"
docker info --format '{{json .}}' |
  python3 -I "$projector" host-docker - "$GUEST_PROOF_DIR/docker-info-safe.json"
if grep -R -q 'cpu_total_compute\|NOMAD_CLIENT_CPU_TOTAL_COMPUTE' /etc/nomad.d || [[ -n "${NOMAD_CLIENT_CPU_TOTAL_COMPUTE:-}" ]]; then
  printf 'true\n'
else
  printf 'false\n'
fi | python3 -I "$projector" host-compute-override - "$GUEST_PROOF_DIR/nomad-compute-override-safe.json"
EOF
}

capture_execution_evidence() {
  local evidence_label=${1:-}
  EVIDENCE_LABEL="${evidence_label}" run_guest_stdin <<'EOF'
cd "$GUEST_REPO_ROOT"
source "$GUEST_PROOF_DIR/env.sh"
python3 -I - <<'PY' "$GUEST_PROOF_DIR" "${EVIDENCE_LABEL:-}"
import json
import os
import pathlib
import re
import sys

proof_dir = pathlib.Path(sys.argv[1])
label = sys.argv[2].strip()
if label not in ("", "runtime-identity-vault", "control-plane-normal-shell"):
    raise SystemExit("invalid proof evidence label")
workdirs = sorted([path for path in (proof_dir / "workdirs").iterdir() if path.is_dir()], key=lambda path: path.stat().st_mtime)
if not workdirs:
    raise SystemExit("no execution-loop workdirs found")
latest = workdirs[-1]

def write_evidence(name, data):
    output_name = f"{label}-{name}" if label else name
    (proof_dir / output_name).write_bytes(data)

for name in (
    "summary.json",
):
    src = latest / name
    if src.exists():
        write_evidence(name, src.read_bytes())

status_path = latest / "status.json"
if status_path.is_file():
    import subprocess
    projector = os.path.join(os.environ["GUEST_REPO_ROOT"], "scripts/internal/supported_local_proof_projection.py")
    output_name = f"{label}-status-safe.json" if label else "status-safe.json"
    subprocess.run(["python3", "-I", projector, "execution-status", str(status_path), str(proof_dir / output_name)], check=True)

# Workload stdout can contain the proof secret value. Keep only fixed boolean
# markers; never copy raw logs to the top-level evidence projection.
logs_path = latest / "logs.txt"
if label in ("runtime-identity-vault", "control-plane-normal-shell") and logs_path.is_file():
    if logs_path.stat().st_size > (32 << 20):
        raise SystemExit("execution log exceeds proof assertion read bound")
    log_bytes = logs_path.read_bytes()
    if len(log_bytes) > (32 << 20):
        raise SystemExit("execution log exceeds proof assertion read bound")
    assertions = {"schema": "supported-local-proof-log-assertions-v1"}
    if label == "runtime-identity-vault":
        assertions.update({
            "identity_endpoint_used": b"PLATFORM-ENDPOINT-USED" in log_bytes,
            "identity_jwt_received": b"IDENTITY-JWT-RECEIVED" in log_bytes,
            "vault_login_success": b"VAULT-LOGIN-SUCCESS" in log_bytes,
            "secret_read_success": b"SECRET-READ-SUCCESS:" in log_bytes,
        })
    else:
        assertions["runtime_contract_proved"] = b"CP-NORMAL-SHELL-RUNTIME-CONTRACT-PROVED" in log_bytes
    (proof_dir / f"{label}-log-assertions.json").write_text(
        json.dumps(assertions, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
    )

summary = json.loads((latest / "summary.json").read_text(encoding="utf-8"))
if label == "control-plane-normal-shell":
    if summary.get("workdir") != str(latest) or summary.get("result_path") != str(latest / "result.tar.gz"):
        raise SystemExit("normal-shell proof result binding invalid")
run_id = summary.get("run_id")
if not isinstance(run_id, str) or re.fullmatch(r"run-[0-9a-f]{16}", run_id) is None:
    raise SystemExit("invalid proof run id")
(proof_dir / "run-id.txt").write_bytes((run_id + "\n").encode("utf-8"))
PY

run_id="$(tr -d '[:space:]' < "$GUEST_PROOF_DIR/run-id.txt")"
if [[ -z "${run_id}" ]]; then
  echo "missing run_id in execution summary" >&2
  exit 1
fi
job_id="exec-${run_id}"
# ES's jobs live in its own namespace; the read-only observer token reads
# them. The token reaches the nomad CLI through its environment only.
source "$GUEST_REPO_ROOT/scripts/internal/nomad_acl.sh"
observer_token="$(nomad_token_from_file "${NOMAD_TOKEN_FILE:-}")"
nomad_observer() {
  NOMAD_TOKEN="${observer_token}" NOMAD_NAMESPACE="${NOMAD_ACL_NAMESPACE}" nomad "$@"
}
nomad_observer job status "${job_id}" >/dev/null
alloc_id="$(nomad_observer job allocs -json "${job_id}" | python3 -I -c '
import json
import re
import sys
def reject_nonstandard_constant(_value):
    raise ValueError("nonstandard JSON constant")
try:
    allocs = json.load(sys.stdin, parse_constant=reject_nonstandard_constant)
except (ValueError, UnicodeError):
    raise SystemExit("proof allocation list invalid") from None
if not isinstance(allocs, list):
    raise SystemExit("proof allocation list invalid")
if len(allocs) != 1:
    raise SystemExit("proof allocation count must be exactly one")
if not isinstance(allocs[0], dict):
    raise SystemExit("proof allocation entry invalid")
value = allocs[0].get("ID")
if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value) is None:
    raise SystemExit("proof allocation id invalid")
print(value)
'
)"
nomad_observer alloc status "${alloc_id}" >/dev/null
python3 -I - <<'PY' "$GUEST_PROOF_DIR" "${EVIDENCE_LABEL:-}" "${run_id}" "${job_id}" "${alloc_id}"
import json
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
label = sys.argv[2]
run_id, job_id, allocation_id = sys.argv[3:]
data = (json.dumps({"schema": "supported-local-nomad-execution-safe-v1",
                    "run_id": run_id, "job_id": job_id, "allocation_id": allocation_id,
                    "job_observed": True, "allocation_observed": True},
                   sort_keys=True, separators=(",", ":")) + "\n").encode()
(root / (f"{label}-nomad-execution-safe.json" if label else "nomad-execution-safe.json")).write_bytes(data)
PY

staging_state="$(python3 -I - <<'PY' "$GUEST_PROOF_DIR/es.json" "${run_id}"
import json
import os
import pathlib
import stat
import sys

try:
    cfg = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
    staging_root = cfg["execution"]["staging_root_dir"]
    if not isinstance(staging_root, str) or not os.path.isabs(staging_root):
        raise ValueError()
    root_fd = os.open(staging_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            entry = os.stat(sys.argv[2], dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            print("absent")
        else:
            if not stat.S_ISDIR(entry.st_mode):
                raise ValueError()
            print("present")
    finally:
        os.close(root_fd)
except (OSError, ValueError, KeyError, TypeError, UnicodeError):
    raise SystemExit("proof staging observation invalid") from None
PY
)"
printf '%s\n' "${staging_state}" > "$GUEST_PROOF_DIR/staging-check.txt"

if [[ -n "${EVIDENCE_LABEL:-}" ]]; then
  cp "$GUEST_PROOF_DIR/staging-check.txt" "$GUEST_PROOF_DIR/${EVIDENCE_LABEL}-staging-check.txt"
fi
EOF
}

validate_control_plane_normal_shell_result_bundle() {
  run_guest_stdin <<'EOF'
python3 -I "$GUEST_REPO_ROOT/scripts/internal/supported_local_proof_projection.py" captured-result \
  "$GUEST_PROOF_DIR" \
  "$GUEST_PROOF_DIR/control-plane-normal-shell-result-evidence.json"
EOF
}

run() {
  require_command limactl
  require_command python3
  require_command tar
  require_command curl

  # Exact Go preflight for local-Go-required proof paths must precede proof/process/workspace mutation.
  preflight_supported_local_proof_go_if_required
  supported_local_proof_repair_test_sentinel
  preflight_supported_local_proof_retained_result_auth
  preflight_supported_local_proof_bootstrap_scope
  # Refuse a SPIRE release file with no pin before any host effect; the
  # spire-stage phase checks the staged copy against it later.
  spire_release_pinned_sha256 "${SUPPORTED_LOCAL_SPIRE_ASSET}" >/dev/null

  umask 077
  create_private_host_proof_dir
  trap finalize EXIT
  create_private_host_bootstrap_dir
  write_proof_metadata

  run_phase source-snapshot prepare_host_repo_snapshot
  run_phase input-preparation prepare_host_inputs
  prepare_host_tooling
  run_phase guest-bootstrap prepare_guest_bootstrap_dir
  GUEST_COLLECTION_READY="true"
  run_phase snapshot-transfer copy_repo_snapshot_to_guest
  run_phase snapshot-extract extract_guest_repo_snapshot
  run_phase snapshot-drop rm -- "${SUPPORTED_LOCAL_HOST_BOOTSTRAP_DIR}/host-repo-snapshot.tar.gz"
  run_phase cleanup-guest-scratch cleanup_stale_guest_proof_scratch
  run_phase tooling-transfer copy_tooling_to_guest
  run_phase guest-setup setup_guest_environment
  run_phase input-transfer copy_inputs_to_guest
  collect_guest_workspace setup

  run_guest_stdin <<'EOF' >/dev/null 2>&1 || true
cd "$GUEST_REPO_ROOT"
if [[ -f "$GUEST_PROOF_DIR/env.sh" ]]; then
  source "$GUEST_PROOF_DIR/env.sh"
  scripts/01_bringup.sh down
fi
EOF

  run_phase prepare-only-up run_guest_stdin <<'EOF'
cd "$GUEST_REPO_ROOT"
source "$GUEST_PROOF_DIR/env.sh"
export BRINGUP_PROFILE=prepare-only
scripts/01_bringup.sh up
EOF
  CONTROL_PLANE_STARTED="true"

  run_phase full-check run_guest_stdin <<'EOF'
cd "$GUEST_REPO_ROOT"
source "$GUEST_PROOF_DIR/env.sh"
BRINGUP_PROFILE=full scripts/01_bringup.sh check
EOF
  run_phase supported-host-capture capture_supported_host_evidence

  run_phase runtime-identity-execute run_guest_stdin <<'EOF'
cd "$GUEST_REPO_ROOT"
source "$GUEST_PROOF_DIR/env.sh"
scripts/60_execute_loop.sh "$GUEST_PROOF_DIR/runtime_identity_vault_success.input.json"
EOF
  run_phase runtime-identity-capture capture_execution_evidence runtime-identity-vault

  run_phase normal-shell-execute run_guest_stdin <<'EOF'
cd "$GUEST_REPO_ROOT"
source "$GUEST_PROOF_DIR/env.sh"
export OPERATOR_CERT="$CONTROL_PLANE_CERT"
export OPERATOR_KEY="$CONTROL_PLANE_KEY"
export FETCH_RESULT=1
scripts/60_execute_loop.sh "$GUEST_PROOF_DIR/control_plane_normal_shell_runtime.input.json"
EOF
  run_phase normal-shell-capture capture_execution_evidence control-plane-normal-shell
  run_phase result-validation validate_control_plane_normal_shell_result_bundle

  cleanup_control_plane
  collect_guest_workspace final
  run_phase guest-cleanup remove_current_guest_scratch
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
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
fi
