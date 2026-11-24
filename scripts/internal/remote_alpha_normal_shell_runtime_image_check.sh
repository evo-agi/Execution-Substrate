if [[ -z "${REPO_ROOT:-}" ]]; then
  REMOTE_ALPHA_RUNTIME_IMAGE_HELPER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  REPO_ROOT="$(cd "${REMOTE_ALPHA_RUNTIME_IMAGE_HELPER_DIR}/../.." && pwd)"
fi

remote_alpha_normal_shell_runtime_image_summary_schema_version="execution-substrate.remote-alpha.normal-shell-runtime-image-summary.v1"
remote_alpha_runtime_image_expected_ref="execution-substrate/control-plane-normal-shell:supported-local"
remote_alpha_runtime_image_expected_codex_cli_path="/usr/local/bin/codex"
remote_alpha_runtime_image_expected_recipe_script="scripts/remote_alpha_build_normal_shell_runtime_image.sh"
remote_alpha_runtime_image_expected_recipe_builder_script="scripts/build_control_plane_normal_shell_image.sh"
remote_alpha_runtime_image_expected_dockerfile="es/runtimeprofiles/control_plane_normal_shell/Dockerfile"
remote_alpha_runtime_image_expected_codex_realization="proof"

# Copy of remote_alpha_prepare_output_dir from scripts/internal/remote_alpha_output_dir.sh,
# which explains it; TestRemoteAlphaOutputDirCopiesMatch keeps the two identical.
remote_alpha_prepare_output_dir() {
  python3 -I - "$1" <<'REMOTE_ALPHA_OUTPUT_DIR_PY'
import os
import stat
import sys

if not sys.argv[1]:
    sys.exit("remote alpha output folder: no folder given")
if ".." in sys.argv[1].split("/"):
    sys.exit(f"remote alpha output folder: {sys.argv[1]} has a '..' component; refusing to check a path that is not canonical")
# The path is checked as given, never normalized: dropping "link/.." would
# check another folder than the one a later write through the link reaches.
parts = [part for part in os.path.join(os.getcwd(), sys.argv[1]).split("/") if part not in ("", ".")]
trusted = {0, os.geteuid()}
if os.environ.get("SUDO_UID", "").isdigit():
    trusted.add(int(os.environ["SUDO_UID"]))
# O_PATH reads a folder's owner and mode without read permission on it, so a
# folder that root keeps private still passes and sudo can hand it over.
flags = getattr(os, "O_PATH", os.O_RDONLY) | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
shown = "/"
fd = os.open("/", flags)
try:
    for index in range(len(parts) + 1):
        info = os.fstat(fd)
        last = index == len(parts)
        if info.st_uid not in trusted:
            sys.exit(
                f"remote alpha output folder: {shown} belongs to uid {info.st_uid}, not to root, "
                "the user running this step or the user who ran sudo; refusing to write under it"
            )
        if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH) and (
            last or info.st_uid != 0 or not info.st_mode & stat.S_ISVTX
        ):
            sys.exit(f"remote alpha output folder: {shown} can be written by its group or others; refusing to write under it")
        if last:
            break
        shown = "/" + "/".join(parts[: index + 1])
        try:
            next_fd = os.open(parts[index], flags, dir_fd=fd)
        except FileNotFoundError:
            try:
                os.mkdir(parts[index], 0o755, dir_fd=fd)
            except FileExistsError:
                pass
            next_fd = os.open(parts[index], flags, dir_fd=fd)
        os.close(fd)
        fd = next_fd
except OSError as exc:
    sys.exit(f"remote alpha output folder: {shown} is not a directory or is a symbolic link ({exc.strerror})")
finally:
    os.close(fd)
REMOTE_ALPHA_OUTPUT_DIR_PY
}

remote_alpha_runtime_image_defaults() {
  REMOTE_ALPHA_RUNTIME_IMAGE_REF="${remote_alpha_runtime_image_expected_ref}"
  REMOTE_ALPHA_CODEX_CLI_PATH="${remote_alpha_runtime_image_expected_codex_cli_path}"
  REMOTE_ALPHA_SUMMARY_PATH="${REMOTE_ALPHA_SUMMARY_PATH:-/var/tmp/execution-substrate-remote-alpha/normal-shell-runtime-image-summary.json}"
  REMOTE_ALPHA_DOCKER_SERVICE_NAME="${REMOTE_ALPHA_DOCKER_SERVICE_NAME:-docker}"
  REMOTE_ALPHA_NOMAD_SERVICE_NAME="${REMOTE_ALPHA_NOMAD_SERVICE_NAME:-nomad}"
}

remote_alpha_runtime_image_reject_slice_override_env() {
  local name=$1
  local expected=$2
  local actual=""

  actual="$(printenv "${name}" 2>/dev/null || true)"

  if [[ -z "${actual}" ]]; then
    return 0
  fi

  if [[ "${actual}" != "${expected}" ]]; then
    printf 'remote alpha normal-shell runtime image check does not accept %s override for this sealed slice; expected repo-owned value %q (got %q)\n' "${name}" "${expected}" "${actual}" >&2
    return 1
  fi

  return 0
}

remote_alpha_runtime_image_require_pinned_slice_inputs() {
  remote_alpha_runtime_image_reject_slice_override_env "REMOTE_ALPHA_RUNTIME_IMAGE_REF" "${remote_alpha_runtime_image_expected_ref}" || return 1
  remote_alpha_runtime_image_reject_slice_override_env "REMOTE_ALPHA_CODEX_CLI_PATH" "${remote_alpha_runtime_image_expected_codex_cli_path}" || return 1
  remote_alpha_runtime_image_reject_slice_override_env "REMOTE_ALPHA_BUILD_SCRIPT" "${remote_alpha_runtime_image_expected_recipe_script}" || return 1
}

remote_alpha_runtime_image_usage() {
  cat <<'EOF'
Usage:
  sudo scripts/remote_alpha_normal_shell_runtime_image_check.sh

Optional flags:
  --summary-path </path/to/normal-shell-runtime-image-summary.json>
  --help
EOF
}

remote_alpha_runtime_image_parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --image-ref)
        echo "remote alpha normal-shell runtime image check does not accept --image-ref for this sealed slice" >&2
        return 2
        ;;
      --codex-cli-path)
        echo "remote alpha normal-shell runtime image check does not accept --codex-cli-path for this sealed slice" >&2
        return 2
        ;;
      --summary-path)
        REMOTE_ALPHA_SUMMARY_PATH="$2"
        shift 2
        ;;
      --help|-h)
        remote_alpha_runtime_image_usage
        return 1
        ;;
      *)
        echo "unknown argument: $1" >&2
        remote_alpha_runtime_image_usage >&2
        return 2
        ;;
    esac
  done
}

remote_alpha_runtime_image_require_root() {
  if [[ "$(id -u)" != "0" ]]; then
    echo "remote alpha normal-shell runtime image check must run as root; use sudo scripts/remote_alpha_normal_shell_runtime_image_check.sh" >&2
    return 1
  fi
}

remote_alpha_runtime_image_require_command() {
  local name=$1
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "${name} is required" >&2
    return 1
  fi
}

remote_alpha_runtime_image_systemctl_state() {
  local mode=$1
  local service_name=$2

  if command -v systemctl >/dev/null 2>&1 && systemctl "${mode}" --quiet "${service_name}" >/dev/null 2>&1; then
    printf 'true'
  else
    printf 'false'
  fi
}

remote_alpha_runtime_image_passwordless_sudo_for_ds() {
  local override_value="${REMOTE_ALPHA_TEST_PASSWORDLESS_SUDO_FOR_DS:-}"

  if [[ -n "${override_value}" ]]; then
    printf '%s' "${override_value}"
    return 0
  fi

  if [[ "$(id -u)" != "0" ]]; then
    printf 'unknown'
    return 0
  fi
  if ! command -v sudo >/dev/null 2>&1; then
    printf 'unknown'
    return 0
  fi

  if sudo -u ds -H sh -lc 'sudo -n true >/dev/null 2>&1'; then
    printf 'true'
  else
    printf 'false'
  fi
}

remote_alpha_runtime_image_ds_not_in_docker_group() {
  local groups=""

  if groups="$(id -nG ds 2>/dev/null)"; then
    if printf '%s\n' "${groups}" | tr ' ' '\n' | grep -qx 'docker'; then
      printf 'false'
    else
      printf 'true'
    fi
    return 0
  fi

  printf 'unknown'
}

remote_alpha_runtime_image_build_context_meta() {
  python3 - "${REPO_ROOT}" \
    "${remote_alpha_runtime_image_expected_recipe_script}" \
    "${remote_alpha_runtime_image_expected_recipe_builder_script}" \
    "${remote_alpha_runtime_image_expected_ref}" \
    "${remote_alpha_runtime_image_expected_dockerfile}" \
    "${remote_alpha_runtime_image_expected_codex_cli_path}" \
    "${remote_alpha_runtime_image_expected_codex_realization}" <<'PY'
import json
import hashlib
import os
import pathlib
import re
import sys

repo_root = pathlib.Path(sys.argv[1])
expected_recipe_script = sys.argv[2]
expected_recipe_builder_script = sys.argv[3]
expected_image_ref = sys.argv[4]
expected_dockerfile = sys.argv[5]
expected_codex_cli_path = sys.argv[6]
expected_codex_realization = sys.argv[7]
override = os.environ.get("REMOTE_ALPHA_TEST_BUILD_CONTEXT_FILES_JSON", "").strip()
if override:
    files = json.loads(override)
else:
    files = [
        expected_recipe_script,
        "scripts/build_control_plane_normal_shell_image.sh",
        "es/runtimeprofiles/control_plane_normal_shell/Dockerfile",
        "es/runtimeprofiles/control_plane_normal_shell/proof-codex-shim.py",
        ".dockerignore",
    ]

patterns = [
    re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    re.compile(r"(?:^|[^A-Za-z0-9])(?:hvs|s|b)\.[A-Za-z0-9._-]{12,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"-----BEGIN [A-Z0-9 ]+-----"),
]

result = {
    "files": files,
    "safe": True,
    "failure_reasons": [],
    "expected_recipe_script": expected_recipe_script,
    "expected_recipe_script_present": False,
    "expected_recipe_script_sha256": "",
    "recipe_matches_slice": False,
}

for rel in files:
    path = repo_root / rel
    if not path.is_file():
        result["safe"] = False
        result["failure_reasons"].append(f"build context file is missing: {rel}")
        continue
    text = path.read_text(encoding="utf-8", errors="replace")
    for pattern in patterns:
        if pattern.search(text):
            result["safe"] = False
            result["failure_reasons"].append(f"build context file matched secret-like pattern {pattern.pattern}: {rel}")
            break

recipe_path = repo_root / expected_recipe_script
builder_path = repo_root / expected_recipe_builder_script
if recipe_path.is_file():
    recipe_text = recipe_path.read_text(encoding="utf-8", errors="replace")
    result["expected_recipe_script_present"] = True
    result["expected_recipe_script_sha256"] = hashlib.sha256(recipe_text.encode("utf-8")).hexdigest()
    required_fragments = [
        f'EXPECTED_CONTROL_PLANE_NORMAL_SHELL_IMAGE="{expected_image_ref}"',
        f'EXPECTED_CONTROL_PLANE_NORMAL_SHELL_DOCKERFILE="${{REPO_ROOT}}/{expected_dockerfile}"',
        f'EXPECTED_CONTROL_PLANE_NORMAL_SHELL_CODEX_CLI_PATH="{expected_codex_cli_path}"',
        f'EXPECTED_CONTROL_PLANE_NORMAL_SHELL_CODEX_REALIZATION="{expected_codex_realization}"',
        'require_pinned_remote_alpha_value "CONTROL_PLANE_NORMAL_SHELL_IMAGE" "${EXPECTED_CONTROL_PLANE_NORMAL_SHELL_IMAGE}"',
        'require_pinned_remote_alpha_value "CONTROL_PLANE_NORMAL_SHELL_DOCKERFILE" "${EXPECTED_CONTROL_PLANE_NORMAL_SHELL_DOCKERFILE}"',
        'require_pinned_remote_alpha_value "CONTROL_PLANE_NORMAL_SHELL_CODEX_CLI_PATH" "${EXPECTED_CONTROL_PLANE_NORMAL_SHELL_CODEX_CLI_PATH}"',
        'require_pinned_remote_alpha_value "CONTROL_PLANE_NORMAL_SHELL_CODEX_REALIZATION" "${EXPECTED_CONTROL_PLANE_NORMAL_SHELL_CODEX_REALIZATION}"',
        'export CONTROL_PLANE_NORMAL_SHELL_IMAGE="${EXPECTED_CONTROL_PLANE_NORMAL_SHELL_IMAGE}"',
        'export CONTROL_PLANE_NORMAL_SHELL_DOCKERFILE="${EXPECTED_CONTROL_PLANE_NORMAL_SHELL_DOCKERFILE}"',
        'export CONTROL_PLANE_NORMAL_SHELL_CODEX_CLI_PATH="${EXPECTED_CONTROL_PLANE_NORMAL_SHELL_CODEX_CLI_PATH}"',
        'export CONTROL_PLANE_NORMAL_SHELL_CODEX_REALIZATION="${EXPECTED_CONTROL_PLANE_NORMAL_SHELL_CODEX_REALIZATION}"',
        f'exec bash "${{REPO_ROOT}}/{expected_recipe_builder_script}"',
    ]
    missing_fragments = [fragment for fragment in required_fragments if fragment not in recipe_text]
    if builder_path.is_file() and not missing_fragments:
        result["recipe_matches_slice"] = True
    else:
        if not builder_path.is_file():
            result["failure_reasons"].append(f"expected recipe builder script is missing: {expected_recipe_builder_script}")
        if missing_fragments:
            result["failure_reasons"].append(f"expected recipe script does not match the sealed remote alpha slice: {expected_recipe_script}")
else:
    result["failure_reasons"].append(f"expected recipe script is missing: {expected_recipe_script}")

print(json.dumps(result, sort_keys=True))
PY
}

remote_alpha_runtime_image_docker_info_ok() {
  if docker info >/dev/null 2>&1; then
    printf 'true'
  else
    printf 'false'
  fi
}

remote_alpha_runtime_image_nomad_meta() {
  local output=""

  if ! command -v nomad >/dev/null 2>&1; then
    python3 - <<'PY'
import json
print(json.dumps({"ready": False, "ready_nodes": 0, "error": "nomad command not found"}, sort_keys=True))
PY
    return 0
  fi

  # Nomad enforces ACLs: read node status with the read-only observer token
  # named by NOMAD_TOKEN_FILE, handed to the nomad CLI in its environment only.
  local token=""
  if [[ -n "${NOMAD_TOKEN_FILE:-}" ]]; then
    source "${REPO_ROOT}/scripts/internal/nomad_acl.sh"
    if ! token="$(nomad_token_from_file "${NOMAD_TOKEN_FILE}" 2>/dev/null)"; then
      python3 - <<'PY'
import json
print(json.dumps({"ready": False, "ready_nodes": 0, "error": "nomad observer token file is missing or invalid"}, sort_keys=True))
PY
      return 0
    fi
  fi

  if ! output="$(NOMAD_TOKEN="${token}" nomad node status -json 2>/dev/null)"; then
    python3 - <<'PY'
import json
print(json.dumps({"ready": False, "ready_nodes": 0, "error": "nomad node status did not succeed"}, sort_keys=True))
PY
    return 0
  fi

  printf '%s' "${output}" | python3 /dev/fd/3 3<<'PY'
import json
import sys

result = {
    "ready": False,
    "ready_nodes": 0,
    "error": "",
}

try:
    nodes = json.load(sys.stdin)
except Exception as exc:
    result["error"] = f"decode nomad node status json: {exc}"
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0)

if not isinstance(nodes, list):
    result["error"] = "nomad node status json was not a list"
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0)

ready_nodes = [node for node in nodes if isinstance(node, dict) and str(node.get("Status") or "").strip() == "ready"]
result["ready_nodes"] = len(ready_nodes)
result["ready"] = bool(ready_nodes)
print(json.dumps(result, sort_keys=True))
PY
}

remote_alpha_runtime_image_inspect_meta() {
  local image_ref=$1
  local output=""

  if ! command -v docker >/dev/null 2>&1; then
    python3 - "${image_ref}" <<'PY'
import json
import sys
print(json.dumps({
    "ref": sys.argv[1],
    "present": False,
    "status": "fail",
    "image_id": "",
    "repo_digests": [],
    "architecture": "",
    "os": "",
    "created": "",
    "size_bytes": 0,
    "error": "docker command not found",
}, sort_keys=True))
PY
    return 0
  fi

  if ! output="$(docker image inspect "${image_ref}" 2>/dev/null)"; then
    python3 - "${image_ref}" <<'PY'
import json
import sys
print(json.dumps({
    "ref": sys.argv[1],
    "present": False,
    "status": "fail",
    "image_id": "",
    "repo_digests": [],
    "architecture": "",
    "os": "",
    "created": "",
    "size_bytes": 0,
    "error": "runtime image is not present in the Docker daemon",
}, sort_keys=True))
PY
    return 0
  fi

  printf '%s' "${output}" | python3 /dev/fd/3 "${image_ref}" 3<<'PY'
import json
import sys

image_ref = sys.argv[1]
payload = json.load(sys.stdin)
item = payload[0] if isinstance(payload, list) and payload else {}
print(json.dumps({
    "ref": image_ref,
    "present": True,
    "status": "pass",
    "image_id": str(item.get("Id") or "").strip(),
    "repo_digests": item.get("RepoDigests") or [],
    "architecture": str(item.get("Architecture") or "").strip(),
    "os": str(item.get("Os") or "").strip(),
    "created": str(item.get("Created") or "").strip(),
    "size_bytes": int(item.get("Size") or 0),
    "error": "",
}, sort_keys=True))
PY
}

remote_alpha_runtime_image_minimal_run() {
  local image_ref=$1
  local codex_cli_path=$2
  local stdout_path=$3
  local stderr_path=$4

  if ! command -v docker >/dev/null 2>&1; then
    python3 - <<'PY'
import json
print(json.dumps({
    "status": "not_exercised",
    "safe": True,
    "stdout_lines": [],
    "stderr_lines": [],
    "codex_realization": "unknown",
    "error": "docker command not found",
}, sort_keys=True))
PY
    return 0
  fi

  if docker run --rm --entrypoint /bin/sh -e "CODEX_CLI_PATH=${codex_cli_path}" "${image_ref}" \
    -lc 'python3 --version 2>&1; git --version 2>&1; if [ -x "$CODEX_CLI_PATH" ]; then "$CODEX_CLI_PATH" --version 2>&1 || "$CODEX_CLI_PATH" --help 2>&1; else echo "missing codex cli: $CODEX_CLI_PATH" >&2; exit 3; fi' \
    >"${stdout_path}" 2>"${stderr_path}"; then
    REMOTE_ALPHA_RUNTIME_IMAGE_RUN_STATUS="pass"
  else
    REMOTE_ALPHA_RUNTIME_IMAGE_RUN_STATUS="fail"
  fi

  python3 - "${stdout_path}" "${stderr_path}" "${REMOTE_ALPHA_RUNTIME_IMAGE_RUN_STATUS}" <<'PY'
import json
import pathlib
import re
import sys

stdout_path = pathlib.Path(sys.argv[1])
stderr_path = pathlib.Path(sys.argv[2])
status = sys.argv[3]
stdout_text = stdout_path.read_text(encoding="utf-8", errors="replace")
stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace")
combined = stdout_text + "\n" + stderr_text
patterns = [
    re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    re.compile(r"(?:^|[^A-Za-z0-9])(?:hvs|s|b)\.[A-Za-z0-9._-]{12,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"-----BEGIN [A-Z0-9 ]+-----"),
]

safe = not any(pattern.search(combined) for pattern in patterns)
if "supported-local-proof-codex-shim/v1" in combined:
    codex_realization = "proof"
elif "supported-local-placeholder-codex/v1" in combined:
    codex_realization = "placeholder"
else:
    codex_realization = "unknown"
error = ""
if status != "pass":
    error = "minimal container run failed"
elif not safe:
    error = "minimal container run output contained secret-like material"

print(json.dumps({
    "status": status,
    "safe": safe,
    "stdout_lines": stdout_text.splitlines(),
    "stderr_lines": stderr_text.splitlines(),
    "codex_realization": codex_realization,
    "error": error,
}, sort_keys=True))
PY
}

remote_alpha_runtime_image_validate_summary_file() {
  local summary_path=$1

  python3 - "${summary_path}" <<'PY'
import pathlib
import re
import sys

summary_path = pathlib.Path(sys.argv[1])
text = summary_path.read_text(encoding="utf-8")
patterns = [
    re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    re.compile(r"(?:^|[^A-Za-z0-9])(?:hvs|s|b)\.[A-Za-z0-9._-]{12,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"-----BEGIN [A-Z0-9 ]+-----"),
]

for pattern in patterns:
    if pattern.search(text):
        raise SystemExit(f"summary contains secret-like material matching {pattern.pattern}: {summary_path}")
PY
}

remote_alpha_runtime_image_write_summary() {
  local summary_path=$1
  local build_meta_path=$2
  local image_meta_path=$3
  local host_meta_path=$4
  local run_meta_path=$5

  python3 - "${summary_path}" "${build_meta_path}" "${image_meta_path}" "${host_meta_path}" "${run_meta_path}" "${remote_alpha_normal_shell_runtime_image_summary_schema_version}" <<'PY'
import json
import sys

summary_path = sys.argv[1]
build_meta = json.load(open(sys.argv[2], encoding="utf-8"))
image_meta = json.load(open(sys.argv[3], encoding="utf-8"))
host_meta = json.load(open(sys.argv[4], encoding="utf-8"))
run_meta = json.load(open(sys.argv[5], encoding="utf-8"))
schema_version = sys.argv[6]

codex_realization = str(run_meta.get("codex_realization") or "unknown")
codex_realization_expected = codex_realization == "proof"
codex_credential_posture = "no_real_credentials" if codex_realization_expected else "undetermined"

summary = {
    "schema_version": schema_version,
    "checked_at": host_meta.get("checked_at"),
    "image": {
        "ref": image_meta.get("ref"),
        "present": bool(image_meta.get("present")),
        "image_id": image_meta.get("image_id") or "",
        "repo_digests": image_meta.get("repo_digests") or [],
        "architecture": image_meta.get("architecture") or "",
        "os": image_meta.get("os") or "",
        "created": image_meta.get("created") or "",
        "size_bytes": image_meta.get("size_bytes") or 0,
    },
    "build": {
        "expected_recipe_script": build_meta.get("expected_recipe_script") or "",
        "expected_recipe_script_present": bool(build_meta.get("expected_recipe_script_present")),
        "expected_recipe_script_sha256": build_meta.get("expected_recipe_script_sha256") or "",
        "build_context_files": build_meta.get("files") or [],
        "recipe_matches_slice": bool(build_meta.get("recipe_matches_slice")),
        "codex_realization": codex_realization,
        "codex_credential_posture": codex_credential_posture,
        "real_codex_credentials_required_for_build": False,
    },
    "host": {
        "hostname": host_meta.get("hostname"),
        "docker_service_active": host_meta.get("docker_service_active"),
        "nomad_ready": host_meta.get("nomad_ready"),
    },
    "validation": {
        "image_present": "pass" if image_meta.get("status") == "pass" else "fail",
        "docker_info_ok": host_meta.get("docker_info_ok"),
        "minimal_container_run": {
            "status": run_meta.get("status") or "not_exercised",
            "safe": bool(run_meta.get("safe")),
            "stdout_lines": run_meta.get("stdout_lines") or [],
            "stderr_lines": run_meta.get("stderr_lines") or [],
        },
        "codex_realization_expected": codex_realization_expected,
    },
    "security": {
        "ds_not_in_docker_group": host_meta.get("ds_not_in_docker_group"),
        "passwordless_sudo_for_ds": host_meta.get("passwordless_sudo_for_ds"),
        "no_real_codex_credentials_in_build_context": bool(build_meta.get("safe")),
        "no_api_keys_or_tokens_printed": bool(build_meta.get("safe")) and bool(run_meta.get("safe")),
    },
    "readiness_not_claimed": {
        "runtime_profile_ready": "not_claimed",
        "submit_ready": "not_claimed",
        "es_services_healthy": "not_claimed",
        "producer_contract_compatible": "not_claimed",
        "retained_result_fetch": "not_claimed",
    },
}

failure_reasons = []
for meta in (build_meta, image_meta, host_meta, run_meta):
    error = str(meta.get("error") or "").strip()
    if error:
      failure_reasons.append(error)
for reason in build_meta.get("failure_reasons") or []:
    failure_reasons.append(str(reason))
if not codex_realization_expected:
    failure_reasons.append("current no-real-credential proof posture was not proved from the container smoke")
summary["failure_reasons"] = failure_reasons

with open(summary_path, "w", encoding="utf-8") as handle:
    json.dump(summary, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
}

remote_alpha_runtime_image_check_main() {
  local tmp_dir=""
  local build_meta_path=""
  local image_meta_path=""
  local host_meta_path=""
  local run_meta_path=""
  local summary_tmp_path=""
  local run_stdout_path=""
  local run_stderr_path=""
  local overall_ok=true
  local docker_service_active="false"
  local nomad_service_active="false"
  local docker_info_ok="false"
  local ds_not_in_docker_group="unknown"
  local passwordless_sudo_for_ds="unknown"

  remote_alpha_runtime_image_require_pinned_slice_inputs || return 1
  remote_alpha_runtime_image_defaults
  remote_alpha_runtime_image_parse_args "$@" || return $?

  remote_alpha_runtime_image_require_command python3 || return 1
  remote_alpha_prepare_output_dir "$(dirname "${REMOTE_ALPHA_SUMMARY_PATH}")" || return 1
  remote_alpha_runtime_image_require_command hostname || return 1
  remote_alpha_runtime_image_require_command id || return 1
  remote_alpha_runtime_image_require_command docker || return 1
  remote_alpha_runtime_image_require_command nomad || return 1
  remote_alpha_runtime_image_require_command systemctl || return 1

  tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/remote-alpha-runtime-image.XXXXXX")"
  build_meta_path="${tmp_dir}/build-meta.json"
  image_meta_path="${tmp_dir}/image-meta.json"
  host_meta_path="${tmp_dir}/host-meta.json"
  run_meta_path="${tmp_dir}/run-meta.json"
  summary_tmp_path="${tmp_dir}/summary.json"
  run_stdout_path="${tmp_dir}/minimal-run.stdout"
  run_stderr_path="${tmp_dir}/minimal-run.stderr"
  trap 'rm -rf "'"${tmp_dir}"'"' EXIT

  remote_alpha_runtime_image_build_context_meta >"${build_meta_path}"
  remote_alpha_runtime_image_inspect_meta "${REMOTE_ALPHA_RUNTIME_IMAGE_REF}" >"${image_meta_path}"

  docker_service_active="$(remote_alpha_runtime_image_systemctl_state is-active "${REMOTE_ALPHA_DOCKER_SERVICE_NAME}")"
  nomad_service_active="$(remote_alpha_runtime_image_systemctl_state is-active "${REMOTE_ALPHA_NOMAD_SERVICE_NAME}")"
  docker_info_ok="$(remote_alpha_runtime_image_docker_info_ok)"
  ds_not_in_docker_group="$(remote_alpha_runtime_image_ds_not_in_docker_group)"
  passwordless_sudo_for_ds="$(remote_alpha_runtime_image_passwordless_sudo_for_ds)"

  export REMOTE_ALPHA_DOCKER_SERVICE_ACTIVE="${docker_service_active}"
  export REMOTE_ALPHA_NOMAD_SERVICE_ACTIVE="${nomad_service_active}"
  export REMOTE_ALPHA_DOCKER_INFO_OK="${docker_info_ok}"
  export REMOTE_ALPHA_CHECKED_AT
  REMOTE_ALPHA_CHECKED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  export REMOTE_ALPHA_HOSTNAME
  REMOTE_ALPHA_HOSTNAME="$(hostname)"

  python3 - "${host_meta_path}" "$(remote_alpha_runtime_image_nomad_meta)" "${ds_not_in_docker_group}" "${passwordless_sudo_for_ds}" <<'PY'
import json
import os
import pathlib
import sys

host_meta_path = pathlib.Path(sys.argv[1])
nomad_meta = json.loads(sys.argv[2])
ds_not_in_docker_group = sys.argv[3].strip()
passwordless_sudo_for_ds = sys.argv[4].strip()

def parse_bool(value):
    if value == "true":
        return True
    if value == "false":
        return False
    return None

payload = {
    "checked_at": os.environ["REMOTE_ALPHA_CHECKED_AT"],
    "hostname": os.environ["REMOTE_ALPHA_HOSTNAME"],
    "docker_service_active": os.environ["REMOTE_ALPHA_DOCKER_SERVICE_ACTIVE"] == "true",
    "nomad_service_active": os.environ["REMOTE_ALPHA_NOMAD_SERVICE_ACTIVE"] == "true",
    "docker_info_ok": os.environ["REMOTE_ALPHA_DOCKER_INFO_OK"] == "true",
    "nomad_ready": bool(nomad_meta.get("ready")),
    "ready_nodes": int(nomad_meta.get("ready_nodes") or 0),
    "ds_not_in_docker_group": parse_bool(ds_not_in_docker_group),
    "passwordless_sudo_for_ds": parse_bool(passwordless_sudo_for_ds),
    "error": "",
}

failure_reasons = []
if nomad_meta.get("error"):
    failure_reasons.append(str(nomad_meta["error"]))
if not payload["docker_service_active"]:
    failure_reasons.append("docker service is not active")
if not payload["nomad_service_active"]:
    failure_reasons.append("nomad service is not active")
if not payload["docker_info_ok"]:
    failure_reasons.append("docker info did not succeed")
if not payload["nomad_ready"]:
    failure_reasons.append("nomad did not report a ready node")
if payload["ds_not_in_docker_group"] is not True:
    failure_reasons.append("ds must remain outside the docker group")
if payload["passwordless_sudo_for_ds"] is not False:
    failure_reasons.append("passwordless sudo for ds must remain disabled")
if failure_reasons:
    payload["error"] = "; ".join(failure_reasons)

host_meta_path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
PY

  if [[ "$(python3 - "${build_meta_path}" <<'PY'
import json, sys
print("true" if json.load(open(sys.argv[1], encoding="utf-8")).get("safe") else "false")
PY
  )" != "true" ]]; then
    overall_ok=false
  fi
  if [[ "$(python3 - "${build_meta_path}" <<'PY'
import json, sys
print("true" if json.load(open(sys.argv[1], encoding="utf-8")).get("recipe_matches_slice") else "false")
PY
)" != "true" ]]; then
    overall_ok=false
  fi

  if [[ "${docker_service_active}" != "true" ]]; then
    overall_ok=false
  fi
  if [[ "${nomad_service_active}" != "true" ]]; then
    overall_ok=false
  fi
  if [[ "${docker_info_ok}" != "true" ]]; then
    overall_ok=false
  fi
  if [[ "$(python3 - "${host_meta_path}" <<'PY'
import json, sys
print("true" if json.load(open(sys.argv[1], encoding="utf-8")).get("nomad_ready") else "false")
PY
)" != "true" ]]; then
    overall_ok=false
  fi
  if [[ "${ds_not_in_docker_group}" != "true" ]]; then
    overall_ok=false
  fi
  if [[ "${passwordless_sudo_for_ds}" != "false" ]]; then
    overall_ok=false
  fi

  if [[ "$(python3 - "${image_meta_path}" <<'PY'
import json, sys
print("true" if json.load(open(sys.argv[1], encoding="utf-8")).get("present") else "false")
PY
)" == "true" ]]; then
    remote_alpha_runtime_image_minimal_run \
      "${REMOTE_ALPHA_RUNTIME_IMAGE_REF}" \
      "${REMOTE_ALPHA_CODEX_CLI_PATH}" \
      "${run_stdout_path}" \
      "${run_stderr_path}" >"${run_meta_path}"
  else
    python3 - "${run_meta_path}" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "w", encoding="utf-8") as handle:
    json.dump({
        "status": "not_exercised",
        "safe": True,
        "stdout_lines": [],
        "stderr_lines": [],
        "codex_realization": "unknown",
        "error": "minimal container run skipped because runtime image is not present",
    }, handle, sort_keys=True)
PY
  fi

  remote_alpha_runtime_image_write_summary \
    "${summary_tmp_path}" \
    "${build_meta_path}" \
    "${image_meta_path}" \
    "${host_meta_path}" \
    "${run_meta_path}"

  remote_alpha_runtime_image_validate_summary_file "${summary_tmp_path}"

  remote_alpha_prepare_output_dir "$(dirname "${REMOTE_ALPHA_SUMMARY_PATH}")" || return 1
  install -m 0644 "${summary_tmp_path}" "${REMOTE_ALPHA_SUMMARY_PATH}"

  if [[ "$(python3 - "${run_meta_path}" <<'PY'
import json, sys
meta = json.load(open(sys.argv[1], encoding="utf-8"))
print("true" if meta.get("status") == "pass" and meta.get("safe") and meta.get("codex_realization") == "proof" else "false")
PY
)" != "true" ]]; then
    overall_ok=false
  fi

  if [[ "$(python3 - "${image_meta_path}" <<'PY'
import json, sys
print("true" if json.load(open(sys.argv[1], encoding="utf-8")).get("status") == "pass" else "false")
PY
)" != "true" ]]; then
    overall_ok=false
  fi

  if [[ "${overall_ok}" != "true" ]]; then
    echo "remote alpha normal-shell runtime image check failed; see ${REMOTE_ALPHA_SUMMARY_PATH}" >&2
    return 1
  fi
}
