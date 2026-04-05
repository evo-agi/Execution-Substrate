#!/usr/bin/env bash

control_plane_image_ref() {
  printf '%s\n' "${CONTROL_PLANE_IMAGE:-execution-platform/control-plane:local}"
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
  if [[ -n "${CONTROL_PLANE_TARGETARCH:-}" ]]; then
    printf '%s\n' "${CONTROL_PLANE_TARGETARCH}"
    return 0
  fi

  if command -v go >/dev/null 2>&1; then
    go env GOARCH
    return 0
  fi

  case "$(uname -m)" in
    x86_64|amd64)
      printf 'amd64\n'
      ;;
    aarch64|arm64)
      printf 'arm64\n'
      ;;
    *)
      echo "unable to determine control-plane image target architecture for $(uname -m)" >&2
      return 1
      ;;
  esac
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
name = f"execution-platform-{digest}-{service}"
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
    if staging_root and os.path.isabs(staging_root):
        rw_dirs.add(os.path.normpath(staging_root))

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

verify_es_staging_invariant() {
  local config_path=$1
  local proof_path
  local staging_root
  local found=0

  staging_root="$(python3 - <<'PY' "${config_path}"
import json
import pathlib
import sys

cfg = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
execution = cfg.get("execution") or {}
staging_root = (execution.get("staging_root_dir") or "").strip()
if not staging_root:
    raise SystemExit("missing execution.staging_root_dir")
print(staging_root)
PY
)" || return 1

  if [[ "${staging_root}" != /* ]]; then
    echo "ES staging invariant failed: execution.staging_root_dir must be absolute: ${staging_root}" >&2
    return 1
  fi
  if [[ ! -d "${staging_root}" ]]; then
    mkdir -p "${staging_root}"
  fi
  if [[ ! -d "${staging_root}" ]]; then
    echo "ES staging invariant failed: staging root does not exist: ${staging_root}" >&2
    return 1
  fi
  if [[ ! -w "${staging_root}" ]]; then
    echo "ES staging invariant failed: staging root is not writable: ${staging_root}" >&2
    return 1
  fi

  while IFS= read -r spec; do
    [[ -n "${spec}" ]] || continue
    if [[ "${spec}" == "${staging_root}:${staging_root}:rw" ]]; then
      found=1
      break
    fi
  done < <(control_plane_mount_specs es "${config_path}")

  if (( found == 0 )); then
    echo "ES staging invariant failed: ES container is not mounted with ${staging_root}:${staging_root}:rw" >&2
    return 1
  fi

  proof_path="${BRINGUP_DIR}/staging-invariant.json"
  mkdir -p "$(dirname "${proof_path}")"
  python3 - <<'PY' "${proof_path}" "${staging_root}"
import json
import pathlib
import sys

payload = {
    "host_staging_path": sys.argv[2],
    "es_container_mount_path": sys.argv[2],
    "path_translation": False,
}
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
