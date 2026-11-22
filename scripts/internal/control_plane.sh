#!/usr/bin/env bash

control_plane_image_ref() {
  printf '%s\n' "${CONTROL_PLANE_IMAGE:-execution-substrate/control-plane:local}"
}

control_plane_dockerfile_path() {
  printf '%s\n' "${CONTROL_PLANE_DOCKERFILE:-$(bringup_repo_root)/.out/Dockerfile}"
}

control_plane_dockerfile_generator_path() {
  printf '%s\n' "$(bringup_repo_root)/scripts/generate_control_plane_dockerfile.sh"
}

ensure_default_control_plane_dockerfile() {
  local dockerfile_path=$1
  local generator

  if [[ -n "${CONTROL_PLANE_DOCKERFILE:-}" ]]; then
    return 0
  fi

  generator="$(control_plane_dockerfile_generator_path)"
  require_readable_path "control-plane Dockerfile generator" "${generator}" || return 1

  mkdir -p "$(dirname "${dockerfile_path}")"
  if ! bash "${generator}" "${dockerfile_path}" >/dev/null; then
    echo "control-plane Dockerfile generation failed for ${dockerfile_path}" >&2
    return 1
  fi
}

control_plane_image_build_mode() {
  printf '%s\n' "${CONTROL_PLANE_IMAGE_BUILD:-always}"
}

control_plane_target_arch() {
  local machine
  local goarch

  if [[ -n "${CONTROL_PLANE_TARGETARCH:-}" ]]; then
    printf '%s\n' "${CONTROL_PLANE_TARGETARCH}"
    return 0
  fi

  machine="$(uname -m)"
  case "${machine}" in
    x86_64|amd64)
      printf 'amd64\n'
      return 0
      ;;
    aarch64|arm64)
      printf 'arm64\n'
      return 0
      ;;
  esac

  if command -v go >/dev/null 2>&1; then
    goarch="$(env GOTOOLCHAIN=local go env GOARCH 2>/dev/null || true)"
    case "${goarch}" in
      amd64|arm64)
        printf '%s\n' "${goarch}"
        return 0
        ;;
    esac
  fi

  echo "unable to determine control-plane image target architecture for ${machine}" >&2
  return 1
}

control_plane_binary_path() {
  local service=$1
  case "${service}" in
    ars|ags|egs|es|cgs)
      printf '/usr/local/bin/%s\n' "${service}"
      ;;
    *)
      echo "unknown control-plane service: ${service}" >&2
      return 1
      ;;
  esac
}

control_plane_container_name() {
  local service=$1
  python3 - <<'PY' "${service}" "${BRINGUP_DIR:-$(bringup_repo_root)/.tmp/bringup}"
import hashlib
import re
import sys

service = sys.argv[1]
seed = sys.argv[2]
digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]
name = f"execution-substrate-{digest}-{service}"
print(re.sub(r"[^A-Za-z0-9_.-]+", "-", name))
PY
}

ensure_control_plane_image() {
  local log_file=$1
  local image
  local dockerfile
  local mode
  local repo_root
  local target_arch

  image="$(control_plane_image_ref)"
  dockerfile="$(control_plane_dockerfile_path)"
  mode="$(control_plane_image_build_mode)"
  repo_root="$(bringup_repo_root)"
  target_arch="$(control_plane_target_arch)" || return 1

  ensure_default_control_plane_dockerfile "${dockerfile}" || return 1
  require_readable_path "control-plane Dockerfile" "${dockerfile}" || return 1

  case "${mode}" in
    always)
      ;;
    if-missing)
      if docker image inspect "${image}" >/dev/null 2>&1; then
        return 0
      fi
      ;;
    never)
      if docker image inspect "${image}" >/dev/null 2>&1; then
        return 0
      fi
      echo "control-plane image ${image} is missing and CONTROL_PLANE_IMAGE_BUILD=never" >&2
      return 1
      ;;
    *)
      echo "CONTROL_PLANE_IMAGE_BUILD must be always, if-missing, or never" >&2
      return 1
      ;;
  esac

  if docker image inspect "${image}" >/dev/null 2>&1; then
    echo "==> rebuilding control-plane image ${image}"
  else
    echo "==> building control-plane image ${image}"
  fi

  mkdir -p "$(dirname "${log_file}")"
  if ! docker build --build-arg "TARGETARCH=${target_arch}" -t "${image}" -f "${dockerfile}" "${repo_root}" >"${log_file}" 2>&1; then
    echo "control-plane image build failed; see ${log_file}" >&2
    return 1
  fi
}

# control_plane_operator_user prints the calling operator's numeric effective
# UID and primary GID as UID:GID for docker run --user. The generic bring-up
# launchers run ARS, EGS, AGS and ES as that identity, so no service holds more
# host authority than the operator who started it and every file a service
# writes belongs to that operator. Docker gives the identity no supplementary
# groups. Both IDs must be numeric, because docker run --user with an empty UID
# runs as root. Command substitutions do not inherit errexit, so each id call
# is checked explicitly.
control_plane_operator_user() {
  local service=$1
  local uid
  local gid

  uid="$(id -u)" || return 1
  gid="$(id -g)" || return 1
  if [[ ! "${uid}" =~ ^[0-9]+$ || ! "${gid}" =~ ^[0-9]+$ ]]; then
    printf 'cannot run %s as the operator: id -u and id -g must print numeric IDs, got %q and %q\n' "${service}" "${uid}" "${gid}" >&2
    return 1
  fi
  printf '%s:%s\n' "${uid}" "${gid}"
}

# verify_ars_storage_for_operator checks, before ARS starts as the operator,
# that the operator can use ARS's storage: storage.root_dir and
# storage.index_file must be absolute, the root is created as the operator when
# it is missing (otherwise Docker would create the bind source as root), the
# index file must already exist (ARS refuses to start without it), and every
# directory under the root plus the index file's directory must be writable and
# searchable, and every file there readable, by the operator. ARS writes blobs
# and the index as 0600 files, so storage that an earlier bring-up wrote as
# root is unusable until the operator owns it again.
verify_ars_storage_for_operator() {
  local config_path=$1

  python3 - "${config_path}" <<'PY'
import json
import os
import pathlib
import shlex
import stat
import sys

prefix = "ARS storage check failed"
cfg = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
storage = cfg.get("storage") if isinstance(cfg.get("storage"), dict) else {}
root_dir = storage.get("root_dir") if isinstance(storage.get("root_dir"), str) else ""
index_file = storage.get("index_file") if isinstance(storage.get("index_file"), str) else ""
root_dir = root_dir.strip()
index_file = index_file.strip()


def refuse(message, path=None, recursive=False):
    if path is not None:
        owner = f"{os.getuid()}:{os.getgid()}"
        chown = "chown -R" if recursive else "chown"
        message += (
            f": {path}. ARS runs as your UID and primary group ({owner}); if an earlier"
            f" bring-up wrote this storage as root, hand it back with:"
            f" sudo {chown} {owner} {shlex.quote(str(fix_path or path))}"
        )
    print(f"{prefix}: {message}", file=sys.stderr)
    raise SystemExit(1)


fix_path = None
if not os.path.isabs(root_dir):
    refuse("storage.root_dir must be an absolute path")
if not os.path.isabs(index_file):
    refuse("storage.index_file must be an absolute path")
root = pathlib.Path(os.path.normpath(root_dir))
index = pathlib.Path(os.path.normpath(index_file))

if not root.exists():
    root.mkdir(parents=True)
if not root.is_dir():
    refuse(f"storage.root_dir is not a directory: {root}")
if not index.is_file():
    refuse(f"storage.index_file must be an existing regular file: {index}")

SEARCH_WRITE = os.W_OK | os.X_OK

# The index directory and file get a non-recursive hint: the index may sit in
# a directory that also holds other services' state.
if not os.access(index.parent, SEARCH_WRITE):
    refuse("directory is not writable and searchable by you", index.parent)
if not os.access(index, os.R_OK):
    refuse("file is not readable by you", index)

# Everything under the storage root belongs to ARS, so its hint is recursive
# from the root.
fix_path = root


def walk_error(error):
    refuse("cannot list directory", error.filename, recursive=True)


for current, dirs, files in os.walk(root, onerror=walk_error):
    if not os.access(current, SEARCH_WRITE):
        refuse("directory is not writable and searchable by you", current, recursive=True)
    for name in files:
        path = os.path.join(current, name)
        if stat.S_ISREG(os.lstat(path).st_mode) and not os.access(path, os.R_OK):
            refuse("file is not readable by you", path, recursive=True)
PY
}

control_plane_mount_specs() {
  local service=$1
  local config_path=$2

  python3 - <<'PY' "${service}" "${config_path}"
import json
import os
import pathlib
import sys

service = sys.argv[1]
config_path = pathlib.Path(sys.argv[2]).resolve()
cfg = json.loads(config_path.read_text(encoding="utf-8"))

ro_files = {str(config_path)}
rw_dirs = set()

def walk(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(child, str) and key.endswith("_file") and os.path.isabs(child):
                ro_files.add(os.path.normpath(child))
            else:
                walk(child)
    elif isinstance(value, list):
        for child in value:
            walk(child)

def get_path(*segments):
    current = cfg
    for segment in segments:
        if not isinstance(current, dict) or segment not in current:
            return ""
        current = current[segment]
    return current.strip() if isinstance(current, str) else ""

walk(cfg)

if service == "ars":
    root_dir = get_path("storage", "root_dir")
    index_file = get_path("storage", "index_file")
    if root_dir and os.path.isabs(root_dir):
        rw_dirs.add(os.path.normpath(root_dir))
    if index_file and os.path.isabs(index_file):
        rw_dirs.add(os.path.normpath(str(pathlib.Path(index_file).parent)))
elif service == "es":
    staging_root = get_path("execution", "staging_root_dir")
    results_root = get_path("execution", "results_root_dir")
    spire_socket = get_path("execution", "spire_workload_api_socket_path")
    if staging_root and os.path.isabs(staging_root):
        rw_dirs.add(os.path.normpath(staging_root))
    if results_root and os.path.isabs(results_root):
        rw_dirs.add(os.path.normpath(results_root))
    if spire_socket and os.path.isabs(spire_socket):
        ro_files.add(os.path.normpath(spire_socket))

def is_ancestor(parent, child):
    if parent == child:
        return True
    parent_parts = pathlib.Path(parent).parts
    child_parts = pathlib.Path(child).parts
    return len(parent_parts) < len(child_parts) and child_parts[:len(parent_parts)] == parent_parts

rw_dirs = {path for path in rw_dirs if os.path.isabs(path)}
collapsed_rw = sorted(
    path for path in rw_dirs
    if not any(other != path and is_ancestor(other, path) for other in rw_dirs)
)

ro_files = {path for path in ro_files if os.path.isabs(path)}
ro_files = sorted(
    path for path in ro_files
    if not any(is_ancestor(parent, path) for parent in collapsed_rw)
)

for path in collapsed_rw:
    print(f"{path}:{path}:rw")
for path in ro_files:
    print(f"{path}:{path}:ro")
PY
}

verify_supported_local_es_root_profile() {
  local config_path=$1
  local error_prefix=$2
  local proof_dir="${SUPPORTED_LOCAL_PROOF_DIR:-}"
  local staging_root
  local results_root
  local roots_helper
  local mount_specs
  local spec
  local staging_found=0
  local results_found=0

  if [[ -z "${proof_dir}" || -z "${SUPPORTED_LOCAL_PROOF_ID:-}" ||
        "${config_path}" != "${proof_dir}/es.json" ]]; then
    echo "${error_prefix}: supported-local proof config or roots are mismatched" >&2
    return 1
  fi
  if [[ "$(control_plane_image_ref)" != "execution-substrate/control-plane:supported-local" ]]; then
    echo "${error_prefix}: supported-local service image is incompatible" >&2
    return 1
  fi
  if [[ "${CONTROL_PLANE_DOCKERFILE:-}" != "${proof_dir}/Dockerfile" ]]; then
    echo "${error_prefix}: supported-local service Dockerfile is incompatible" >&2
    return 1
  fi

  roots_helper="$(bringup_repo_root)/scripts/internal/supported_local_execution_roots.py"
  if ! python3 "${roots_helper}" check "${proof_dir}" "${SUPPORTED_LOCAL_PROOF_ID}" "${config_path}" >/dev/null 2>&1; then
    echo "${error_prefix}: supported-local root owner, mode, or identity is invalid" >&2
    return 1
  fi

  # The checked helper binds both config fields to these exact proof children.
  # Require the ES container mount derivation to retain each same-path rw bind.
  staging_root="${proof_dir}/es-staging"
  results_root="${proof_dir}/es-results"
  if ! mount_specs="$(control_plane_mount_specs es "${config_path}" 2>/dev/null)"; then
    echo "${error_prefix}: supported-local ES mounts are invalid" >&2
    return 1
  fi
  while IFS= read -r spec; do
    if [[ "${spec}" == "${staging_root}:${staging_root}:rw" ]]; then
      staging_found=1
    fi
    if [[ "${spec}" == "${results_root}:${results_root}:rw" ]]; then
      results_found=1
    fi
  done <<< "${mount_specs}"
  if (( staging_found == 0 )); then
    echo "${error_prefix}: ES container is not mounted with ${staging_root}:${staging_root}:rw" >&2
    return 1
  fi
  if (( results_found == 0 )); then
    echo "${error_prefix}: ES container is not mounted with ${results_root}:${results_root}:rw" >&2
    return 1
  fi
}

verify_es_staging_invariant() {
  local config_path=$1
  local proof_path
  local staging_root
  local results_root
  local roots_profile="${SUPPORTED_LOCAL_ES_ROOTS_PROFILE:-}"
  local roots_output
  local root_line
  local -a es_roots
  local staging_found=0
  local results_found=0

  case "${roots_profile}" in
    "")
      ;;
    service-root-v1)
      ;;
    *)
      echo "ES staging invariant failed: unsupported supported-local roots profile" >&2
      return 1
      ;;
  esac

  if ! roots_output="$(python3 - "${config_path}" 2>/dev/null <<'PY'
import json
import pathlib
import sys

cfg = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
execution = cfg.get("execution") or {}
staging_root = (execution.get("staging_root_dir") or "").strip()
results_root = (execution.get("results_root_dir") or "").strip()
if not staging_root:
    raise SystemExit("missing execution.staging_root_dir")
if not results_root:
    raise SystemExit("missing execution.results_root_dir")
print(staging_root)
print(results_root)
PY
)"; then
    echo "ES staging invariant failed: execution roots config is invalid" >&2
    return 1
  fi
  es_roots=()
  while IFS= read -r root_line; do
    es_roots+=("${root_line}")
  done <<< "${roots_output}"
  if (( ${#es_roots[@]} != 2 )); then
    echo "ES staging invariant failed: execution roots config is invalid" >&2
    return 1
  fi
  staging_root="${es_roots[0]}"
  results_root="${es_roots[1]}"

  if [[ "${staging_root}" != /* ]]; then
    echo "ES staging invariant failed: execution.staging_root_dir must be absolute: ${staging_root}" >&2
    return 1
  fi
  if [[ "${results_root}" != /* ]]; then
    echo "ES staging invariant failed: execution.results_root_dir must be absolute: ${results_root}" >&2
    return 1
  fi
  if python3 - <<'PY' "${staging_root}" "${results_root}"
import os
import sys

staging_root = sys.argv[1]
results_root = sys.argv[2]
raise SystemExit(0 if os.path.commonpath([staging_root, results_root]) in {staging_root, results_root} else 1)
PY
  then
    echo "ES staging invariant failed: execution.results_root_dir must be separate from execution.staging_root_dir" >&2
    return 1
  fi
  if [[ "${roots_profile}" == "service-root-v1" ]]; then
    verify_supported_local_es_root_profile "${config_path}" "ES staging invariant failed" || return 1
  fi
  if [[ -z "${roots_profile}" ]]; then
    if [[ ! -d "${staging_root}" ]]; then
      mkdir -p "${staging_root}"
    fi
    if [[ ! -d "${results_root}" ]]; then
      mkdir -p "${results_root}"
    fi
    if [[ ! -d "${staging_root}" ]]; then
      echo "ES staging invariant failed: staging root does not exist: ${staging_root}" >&2
      return 1
    fi
    if [[ ! -d "${results_root}" ]]; then
      echo "ES staging invariant failed: results root does not exist: ${results_root}" >&2
      return 1
    fi
    if [[ ! -w "${staging_root}" ]]; then
      echo "ES staging invariant failed: staging root is not writable: ${staging_root}" >&2
      return 1
    fi
    if [[ ! -w "${results_root}" ]]; then
      echo "ES staging invariant failed: results root is not writable: ${results_root}" >&2
      return 1
    fi
  fi

  while IFS= read -r spec; do
    [[ -n "${spec}" ]] || continue
    if [[ "${spec}" == "${staging_root}:${staging_root}:rw" ]]; then
      staging_found=1
    fi
    if [[ "${spec}" == "${results_root}:${results_root}:rw" ]]; then
      results_found=1
    fi
  done < <(control_plane_mount_specs es "${config_path}")

  if (( staging_found == 0 )); then
    echo "ES staging invariant failed: ES container is not mounted with ${staging_root}:${staging_root}:rw" >&2
    return 1
  fi
  if (( results_found == 0 )); then
    echo "ES staging invariant failed: ES container is not mounted with ${results_root}:${results_root}:rw" >&2
    return 1
  fi

  proof_path="${BRINGUP_DIR}/staging-invariant.json"
  mkdir -p "$(dirname "${proof_path}")"
  python3 - <<'PY' "${proof_path}" "${staging_root}" "${results_root}" "${roots_profile}"
import json
import pathlib
import sys

payload = {
    "host_staging_path": sys.argv[2],
    "es_container_mount_path": sys.argv[2],
    "host_results_path": sys.argv[3],
    "es_container_results_path": sys.argv[3],
    "path_translation": False,
}
if sys.argv[4] == "service-root-v1":
    payload.update({
        "supported_local_es_roots_profile": "service-root-v1",
        "static_root_owner_mode_checked": True,
        "configured_root_uid": 0,
        "configured_root_gid": 0,
        "configured_root_mode": "0755",
        "operator_write_access_required": False,
        "container_identity_or_behavioral_capability_proved": False,
    })
pathlib.Path(sys.argv[1]).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

probe_control_plane_host_loopback() {
  local temp_dir=""
  local probe_path=""
  local port
  local server_pid=""
  local output
  local image

  cleanup_probe_control_plane_host_loopback() {
    if [[ -n "${server_pid:-}" ]]; then
      kill "${server_pid}" >/dev/null 2>&1 || true
      wait "${server_pid}" >/dev/null 2>&1 || true
    fi
    if [[ -n "${temp_dir:-}" ]]; then
      rm -rf "${temp_dir}"
    fi
  }

  temp_dir="$(mktemp -d)"
  probe_path="${temp_dir}/index.html"
  printf 'slice0-host-loopback-ok\n' >"${probe_path}"
  image="$(control_plane_image_ref)"

  port="$(python3 - <<'PY'
import socket

sock = socket.socket()
sock.bind(("127.0.0.1", 0))
print(sock.getsockname()[1])
sock.close()
PY
)"

  python3 -m http.server "${port}" --bind 127.0.0.1 --directory "${temp_dir}" >/dev/null 2>&1 &
  server_pid=$!
  trap cleanup_probe_control_plane_host_loopback RETURN
  sleep 1

  if ! output="$(docker run --rm --network host "${image}" wget -q -O - "http://127.0.0.1:${port}" 2>/dev/null)"; then
    echo "slice-0 requires Docker host networking that can reach host loopback from a container; current host does not provide that capability" >&2
    return 1
  fi
  if [[ "${output}" != "slice0-host-loopback-ok" ]]; then
    echo "slice-0 requires Docker host networking that preserves host loopback semantics; probe returned unexpected output" >&2
    return 1
  fi

  trap - RETURN
  cleanup_probe_control_plane_host_loopback
}
