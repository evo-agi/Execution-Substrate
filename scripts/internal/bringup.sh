#!/usr/bin/env bash

bringup_repo_root() {
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  printf '%s\n' "$script_dir"
}

bringup_profile() {
  printf '%s\n' "${BRINGUP_PROFILE:-full}"
}

managed_service_uses_container() {
  local service=$1
  case "${service}" in
    ars|ags|egs|es|cgs)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

print_check_section() {
  local title=$1
  printf '\n==> %s\n' "${title}"
}

validate_bringup_profile() {
  local profile
  profile="$(bringup_profile)"
  case "$profile" in
    full|prepare-only)
      ;;
    *)
      echo "BRINGUP_PROFILE must be full or prepare-only" >&2
      return 1
      ;;
  esac
}

nomad_managed_locally() {
  local pid_file
  local pid

  pid_file="${BRINGUP_DIR:-$(bringup_repo_root)/.tmp/bringup}/pids/nomad.pid"
  if [[ ! -r "${pid_file}" ]]; then
    return 1
  fi

  pid="$(tr -d '[:space:]' <"${pid_file}")"
  [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null
}

nomad_startup_mode_line() {
  if [[ "$(bringup_profile)" != "full" ]]; then
    return 0
  fi

  if ! nomad_managed_locally; then
    printf 'nomad-startup-mode: pre-managed (this bring-up/check path is using an already-running Nomad endpoint via NOMAD_ADDR)\n'
    return 0
  fi

  if [[ "$(id -u)" == "0" ]]; then
    printf 'nomad-startup-mode: managed-local (current full-profile bring-up started Nomad itself as root; still treat this as bounded fallback/troubleshooting)\n'
    return 0
  fi

  printf 'nomad-startup-mode: managed-local (current full-profile bring-up starts Nomad itself as uid=%s; this is bounded fallback/troubleshooting, not the supported Linux environment)\n' "$(id -u)"
}

nomad_client_override_path() {
  local base_dir="${BRINGUP_DIR:-$(bringup_repo_root)/.tmp/bringup}"
  printf '%s/nomad-client-overrides.hcl\n' "${base_dir}"
}

nomad_cpu_total_compute_override_value() {
  local override_path
  override_path="$(nomad_client_override_path)"

  if [[ -r "${override_path}" ]]; then
    python3 - <<'PY' "${override_path}"
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
match = re.search(r"cpu_total_compute\s*=\s*([0-9]+)", text)
if not match:
    raise SystemExit(1)
print(match.group(1))
PY
    return
  fi

  if [[ -n "${NOMAD_CLIENT_CPU_TOTAL_COMPUTE:-}" ]]; then
    printf '%s\n' "${NOMAD_CLIENT_CPU_TOTAL_COMPUTE}"
    return
  fi

  return 1
}

nomad_schedulability_mode_line() {
  local override_value
  if override_value="$(nomad_cpu_total_compute_override_value 2>/dev/null)"; then
    printf 'submit-ready-mode: bounded-override (cpu_total_compute=%s; this host is not naturally self-schedulable)\n' "${override_value}"
  else
    printf 'submit-ready-mode: natural\n'
  fi
}

supported_environment_line() {
  local override_value
  if override_value="$(nomad_cpu_total_compute_override_value 2>/dev/null)"; then
    printf 'supported-environment: bounded-fallback (explicit cpu_total_compute=%s override is active)\n' "${override_value}"
    return 0
  fi

  if nomad_managed_locally; then
    printf 'supported-environment: bounded-fallback (current full-profile bring-up manages a local Nomad process; the supported Linux environment remains a pre-managed naturally schedulable Nomad service)\n'
    return 0
  fi

  printf 'supported-environment: supported (Nomad is not managed by this bring-up and no cpu_total_compute override is active)\n'
}

require_env() {
  local name=$1
  if [[ -z "${!name:-}" ]]; then
    echo "${name} is required" >&2
    return 1
  fi
}

require_readable_path() {
  local label=$1
  local path=$2
  if [[ ! -r "$path" ]]; then
    echo "${label} must point to a readable file: ${path}" >&2
    return 1
  fi
}

require_readable_env() {
  local name=$1
  require_env "$name" || return 1
  require_readable_path "$name" "${!name}" || return 1
}

require_command() {
  local name=$1
  if ! command -v "$name" >/dev/null 2>&1; then
    echo "${name} is required" >&2
    return 1
  fi
}

resolve_value() {
  local name=$1
  printf '%s\n' "${!name:-}"
}

curl_tls_get_to_file() {
  local output_path=$1
  local url=$2
  local resolve="${3:-}"
  shift 3

  local -a args
  args=(
    --fail-with-body
    --silent
    --show-error
    --cacert "${CA_CERT}"
  )

  if [[ -n "$resolve" ]]; then
    args+=(--resolve "$resolve")
  fi

  while (($# > 0)); do
    args+=("$1")
    shift
  done

  args+=("$url")
  curl "${args[@]}" >"$output_path"
}

resolve_health_check_credentials() {
  local cert="${OPERATOR_CERT:-${ARS_READ_CERT:-}}"
  local key="${OPERATOR_KEY:-${ARS_READ_KEY:-}}"

  if [[ -z "${cert}" || -z "${key}" ]]; then
    echo "service health verification requires OPERATOR_CERT/OPERATOR_KEY or ARS_READ_CERT/ARS_READ_KEY" >&2
    return 1
  fi
  require_readable_path "health-check client cert" "${cert}" || return 1
  require_readable_path "health-check client key" "${key}" || return 1

  printf '%s\n%s\n' "${cert}" "${key}"
}

service_health_summary() {
  local payload_path=$1
  local fallback_service=$2
  python3 - <<'PY' "$payload_path" "$fallback_service"
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
service = payload.get("service") or sys.argv[2]
status = payload.get("status", "")
ready = payload.get("ready") is True
print(f"{service}: status={status} ready={str(ready).lower()}")
raise SystemExit(0 if ready else 1)
PY
}

check_service_ready_once() {
  local fallback_service=$1
  local url=$2
  local resolve="${3:-}"
  local cert_key
  local cert
  local key
  local response_path
  local summary
  local status=0

  cert_key="$(resolve_health_check_credentials)" || return 1
  cert="$(printf '%s\n' "${cert_key}" | sed -n '1p')"
  key="$(printf '%s\n' "${cert_key}" | sed -n '2p')"

  response_path="$(mktemp)"

  if ! curl_tls_get_to_file "${response_path}" "${url}/health" "${resolve}" --cert "${cert}" --key "${key}"; then
    echo "${fallback_service}: health request failed for ${url}/health" >&2
    status=1
  elif ! summary="$(service_health_summary "${response_path}" "${fallback_service}")"; then
    echo "${summary}" >&2
    python3 -m json.tool "${response_path}" >&2 || cat "${response_path}" >&2
    status=1
  else
    echo "${summary}"
  fi

  rm -f "${response_path}"
  return "${status}"
}

wait_for_service_ready() {
  local fallback_service=$1
  local url=$2
  local resolve="${3:-}"
  local timeout_seconds=${4:-30}
  local deadline=$((SECONDS + timeout_seconds))
  local last_error=""

  while ((SECONDS < deadline)); do
    if last_error="$(check_service_ready_once "${fallback_service}" "${url}" "${resolve}" 2>&1)"; then
      echo "${last_error}"
      return 0
    fi
    sleep 1
  done

  echo "${last_error}" >&2
  return 1
}

check_nomad_ready_once() {
  local leader_path
  local nodes_path
  local agent_path
  local summary
  local status=0

  leader_path="$(mktemp)"
  nodes_path="$(mktemp)"
  agent_path="$(mktemp)"

  if ! curl --fail-with-body --silent --show-error "${NOMAD_ADDR}/v1/status/leader" >"${leader_path}"; then
    echo "nomad: leader request failed for ${NOMAD_ADDR}/v1/status/leader" >&2
    status=1
  elif ! curl --fail-with-body --silent --show-error "${NOMAD_ADDR}/v1/agent/self" >"${agent_path}"; then
    echo "nomad: agent self request failed for ${NOMAD_ADDR}/v1/agent/self" >&2
    status=1
  elif ! curl --fail-with-body --silent --show-error "${NOMAD_ADDR}/v1/nodes" >"${nodes_path}"; then
    echo "nomad: node request failed for ${NOMAD_ADDR}/v1/nodes" >&2
    status=1
  elif ! summary="$(python3 - <<'PY' "${NOMAD_ADDR}" "${leader_path}" "${nodes_path}" "${agent_path}"
import glob
import json
import os
import pathlib
import sys
import urllib.error
import urllib.request

base_url = sys.argv[1].rstrip("/")
leader = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
if not isinstance(leader, str) or not leader.strip():
    print("nomad: leader missing", file=sys.stderr)
    raise SystemExit(1)

agent_self = json.loads(pathlib.Path(sys.argv[4]).read_text(encoding="utf-8"))
config = agent_self.get("config") or {}
if config.get("DevMode") is True:
    print(
        "nomad: agent is running in -dev mode; this is unsupported for the slice-0 supported environment",
        file=sys.stderr,
    )
    raise SystemExit(1)

nodes = json.loads(pathlib.Path(sys.argv[3]).read_text(encoding="utf-8"))
ready_nodes = [node for node in nodes if node.get("Status") == "ready"]
if not ready_nodes:
    print("nomad: no ready client nodes", file=sys.stderr)
    raise SystemExit(1)

def parse_int(value):
    try:
        return int(str(value).strip() or "0")
    except Exception:
        return 0

schedulable = []
reasons = []

for node in ready_nodes:
    node_id = (node.get("ID") or "").strip()
    node_name = (node.get("Name") or node_id or "unknown").strip()
    if not node_id:
        reasons.append(f"{node_name}=missing-id")
        continue
    try:
        with urllib.request.urlopen(f"{base_url}/v1/node/{node_id}") as response:
            detail = json.load(response)
    except urllib.error.URLError as exc:
        reasons.append(f"{node_name}=detail-unavailable:{exc.reason}")
        continue

    attrs = detail.get("Attributes") or {}
    drivers = detail.get("Drivers") or {}
    docker = drivers.get("docker") or {}
    cpu_total_compute = parse_int(attrs.get("cpu.totalcompute"))

    if cpu_total_compute <= 0:
        reasons.append(f"{node_name}=cpu.totalcompute:{cpu_total_compute}")
        continue
    if docker.get("Healthy") is not True:
        reasons.append(f"{node_name}=docker:{docker.get('HealthDescription') or 'unhealthy'}")
        continue

    schedulable.append((node_name, cpu_total_compute))

if not schedulable:
    print("nomad: no ready client nodes with positive cpu.totalcompute and healthy docker driver", file=sys.stderr)
    if reasons:
        print("nomad: " + ", ".join(reasons), file=sys.stderr)
        if all("=cpu.totalcompute:0" in reason for reason in reasons):
            print(
                "nomad: this host is not naturally self-schedulable for slice-0 bring-up; rerun only with explicit NOMAD_CLIENT_CPU_TOTAL_COMPUTE as a bounded troubleshooting override",
                file=sys.stderr,
            )
            cpuinfo_text = pathlib.Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="ignore")
            freq_candidates = []
            for pattern in (
                "/sys/devices/system/cpu/cpu*/cpufreq/cpuinfo_max_freq",
                "/sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq",
                "/sys/devices/system/cpu/cpu*/cpufreq/base_frequency",
            ):
                freq_candidates.extend(glob.glob(pattern))
            readable_freq_paths = []
            for candidate in freq_candidates:
                try:
                    text = pathlib.Path(candidate).read_text(encoding="utf-8", errors="ignore").strip()
                except OSError:
                    continue
                if text:
                    readable_freq_paths.append(candidate)
            if not readable_freq_paths and "cpu mhz" not in cpuinfo_text.lower():
                print(
                    "nomad: host exposes no CPU frequency data via cpufreq or /proc/cpuinfo; Nomad CPU fingerprinting can remain at cpu.totalcompute=0 on this VM/startup profile",
                    file=sys.stderr,
                )
            if os.geteuid() != 0:
                print(
                    f"nomad: current bring-up starts Nomad as non-root uid={os.geteuid()}; Nomad's Docker driver docs treat this as bounded fallback for CPU-core/NUMA behavior",
                    file=sys.stderr,
                )
    raise SystemExit(1)

details = ", ".join(f"{name}:cpu.totalcompute={cpu}" for name, cpu in schedulable)
print(f"nomad: leader={leader} mode=non-dev ready_nodes={len(ready_nodes)} schedulable_nodes={len(schedulable)} {details}")
PY
)"; then
    status=1
  else
    echo "${summary}"
    nomad_schedulability_mode_line
  fi

  rm -f "${leader_path}" "${nodes_path}" "${agent_path}"
  return "${status}"
}

wait_for_nomad_ready() {
  local timeout_seconds=${1:-30}
  local deadline=$((SECONDS + timeout_seconds))
  local last_error=""

  while ((SECONDS < deadline)); do
    if last_error="$(check_nomad_ready_once 2>&1)"; then
      echo "${last_error}"
      return 0
    fi
    sleep 1
  done

  echo "${last_error}" >&2
  return 1
}

check_docker_ready() {
  if ! docker info >/dev/null 2>&1; then
    echo "docker: docker info failed; submit readiness requires a reachable Docker daemon" >&2
    return 1
  fi
  echo "docker: ready (docker info succeeded)"
}

verify_es_submit_config_enabled() {
  local config_path=$1
  python3 - <<'PY' "$config_path"
import json
import os
import pathlib
import stat
import sys

cfg = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))

def require_non_empty(path):
    cur = cfg
    for segment in path:
        if not isinstance(cur, dict) or segment not in cur:
            raise SystemExit(f"ES submit config is incomplete: missing {'.'.join(path)}")
        cur = cur[segment]
    if not isinstance(cur, str) or not cur.strip():
        raise SystemExit(f"ES submit config is incomplete: missing {'.'.join(path)}")

for path in (
    ("nomad", "base_url"),
    ("nomad", "datacenter"),
    ("execution", "staging_root_dir"),
    ("execution", "base_image"),
    ("execution", "runtime_support_binary"),
    ("execution", "spire_workload_api_socket_path"),
):
    require_non_empty(path)
PY
}

check_es_submit_config_once() {
  local config_path=$1
  local summary

  if ! summary="$(python3 - <<'PY' "$config_path"
import json
import os
import pathlib
import stat
import sys
from urllib.parse import urlparse

cfg = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))

def require_non_empty(path):
    cur = cfg
    for segment in path:
        if not isinstance(cur, dict) or segment not in cur:
            raise SystemExit(f"es submit config: missing {'.'.join(path)}")
        cur = cur[segment]
    if not isinstance(cur, str) or not cur.strip():
        raise SystemExit(f"es submit config: missing {'.'.join(path)}")
    return cur.strip()

base_url = require_non_empty(("nomad", "base_url"))
datacenter = require_non_empty(("nomad", "datacenter"))
staging_root_dir = require_non_empty(("execution", "staging_root_dir"))
base_image = require_non_empty(("execution", "base_image"))
runtime_support_binary = require_non_empty(("execution", "runtime_support_binary"))
spire_socket_path = require_non_empty(("execution", "spire_workload_api_socket_path"))

parsed = urlparse(base_url)
if parsed.scheme not in ("http", "https") or not parsed.netloc:
    raise SystemExit("es submit config: nomad.base_url must be a valid absolute http(s) URL")

staging_root = pathlib.Path(staging_root_dir)
if not staging_root.is_absolute():
    raise SystemExit("es submit config: execution.staging_root_dir must be an absolute path")
if not staging_root.exists():
    raise SystemExit(f"es submit config: execution.staging_root_dir does not exist: {staging_root_dir}")
if not staging_root.is_dir():
    raise SystemExit(f"es submit config: execution.staging_root_dir is not a directory: {staging_root_dir}")
if not os.access(staging_root_dir, os.W_OK):
    raise SystemExit(f"es submit config: execution.staging_root_dir is not writable: {staging_root_dir}")
if not pathlib.Path(runtime_support_binary).is_absolute():
    raise SystemExit("es submit config: execution.runtime_support_binary must be an absolute path")
spire_socket = pathlib.Path(spire_socket_path)
if not spire_socket.is_absolute():
    raise SystemExit("es submit config: execution.spire_workload_api_socket_path must be an absolute path")
if not spire_socket.exists():
    raise SystemExit(f"es submit config: execution.spire_workload_api_socket_path does not exist: {spire_socket_path}")
mode = spire_socket.stat().st_mode
if not stat.S_ISSOCK(mode):
    raise SystemExit(f"es submit config: execution.spire_workload_api_socket_path is not a Unix socket: {spire_socket_path}")

print(
    "es submit config: "
    f"base_url={base_url} "
    f"datacenter={datacenter} "
    f"staging_root_dir={staging_root_dir} "
    f"base_image={base_image} "
    f"runtime_support_binary={runtime_support_binary} "
    f"spire_workload_api_socket_path={spire_socket_path} "
    "ready=true"
)
PY
)"; then
    return 1
  fi

  echo "${summary}"
}

resolve_ars_read_credentials() {
  local cert="${ARS_READ_CERT:-${OPERATOR_CERT:-}}"
  local key="${ARS_READ_KEY:-${OPERATOR_KEY:-}}"

  if [[ -z "${cert}" || -z "${key}" ]]; then
    echo "ARS blob readiness verification requires ARS_READ_CERT/ARS_READ_KEY or OPERATOR_CERT/OPERATOR_KEY" >&2
    return 1
  fi
  require_readable_path "ARS read client cert" "${cert}" || return 1
  require_readable_path "ARS read client key" "${key}" || return 1

  printf '%s\n%s\n' "${cert}" "${key}"
}

check_workload_zone_vault_blob() {
  local config_path=$1
  local resolve="${2:-}"
  local cert_key
  local cert
  local key
  local digest
  local response_path
  local summary
  local status=0

  cert_key="$(resolve_ars_read_credentials)" || return 1
  cert="$(printf '%s\n' "${cert_key}" | sed -n '1p')"
  key="$(printf '%s\n' "${cert_key}" | sed -n '2p')"

  digest="$(python3 - <<'PY' "$config_path"
import json
import pathlib
import sys

cfg = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
runtime_cfg = cfg.get("runtime_config") or {}
vault_ref = runtime_cfg.get("workload_zone_vault_config_ref") or {}
digest = (vault_ref.get("digest") or "").strip()
if not digest:
    raise SystemExit("runtime_config.workload_zone_vault_config_ref.digest is required for workload-zone Vault blob verification")
print(digest)
PY
)" || return 1

  response_path="$(mktemp)"

  if ! curl_tls_get_to_file "${response_path}" "${ARS_URL}/v1/blobs/${digest}:json" "${resolve}" --cert "${cert}" --key "${key}"; then
    echo "workload-zone vault blob read failed for digest ${digest}" >&2
    status=1
  elif ! summary="$(python3 - <<'PY' "${response_path}" "${digest}"
import json
import pathlib
import sys
from urllib.parse import urlparse

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
vault = payload.get("vault_config")
if not isinstance(vault, dict):
    print("workload-zone vault blob is missing vault_config", file=sys.stderr)
    raise SystemExit(1)

address = (vault.get("address") or "").strip()
parsed = urlparse(address)
if not address or parsed.scheme != "https" or not parsed.netloc:
    print("workload-zone vault blob has invalid vault_config.address", file=sys.stderr)
    raise SystemExit(1)

for field in ("auth_mount", "auth_role", "jwt_audience"):
    value = (vault.get(field) or "").strip()
    if not value:
        print(f"workload-zone vault blob is missing vault_config.{field}", file=sys.stderr)
        raise SystemExit(1)

print(f"workload-zone vault blob: digest={sys.argv[2]} ready=true")
PY
)"; then
    status=1
  else
    echo "${summary}"
  fi

  rm -f "${response_path}"
  return "${status}"
}
