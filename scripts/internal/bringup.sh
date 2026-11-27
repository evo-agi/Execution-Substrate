#!/usr/bin/env bash

# Direct health and diagnostics entrypoints source only bringup.sh. Load the
# read-only supported-local root validator they share with staging preflight.
# shellcheck source=scripts/internal/control_plane.sh
source "$(dirname "${BASH_SOURCE[0]}")/control_plane.sh"
# shellcheck source=scripts/internal/nomad_acl.sh
source "$(dirname "${BASH_SOURCE[0]}")/nomad_acl.sh"

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
    python3 -I - <<'PY' "${override_path}"
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
  python3 -I - <<'PY' "$payload_path" "$fallback_service"
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
    python3 -I -m json.tool "${response_path}" >&2 || cat "${response_path}" >&2
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

  if ! nomad_curl --fail-with-body --silent --show-error "${NOMAD_ADDR}/v1/status/leader" >"${leader_path}"; then
    echo "nomad: leader request failed for ${NOMAD_ADDR}/v1/status/leader" >&2
    status=1
  elif ! nomad_acl_state_check; then
    status=1
  elif ! nomad_api_get "/v1/agent/self" "${agent_path}"; then
    echo "nomad: agent self request failed for ${NOMAD_ADDR}/v1/agent/self" >&2
    status=1
  elif ! nomad_runtime_posture_check "${agent_path}"; then
    status=1
  elif ! nomad_api_get "/v1/nodes" "${nodes_path}"; then
    echo "nomad: node request failed for ${NOMAD_ADDR}/v1/nodes" >&2
    status=1
  elif ! summary="$(python3 -I - <<'PY' "${NOMAD_ADDR}" "${leader_path}" "${nodes_path}" "${agent_path}" "${NOMAD_TOKEN_FILE}" "${NOMAD_CACERT}"
import glob
import json
import os
import pathlib
import ssl
import sys
import urllib.error
import urllib.request

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# HTTPS with TLS 1.3, trusting only Nomad's CA; no proxy and no redirects:
# a token reaches only the loopback Nomad.
nomad_tls = ssl.create_default_context(cafile=sys.argv[6])
nomad_tls.minimum_version = ssl.TLSVersion.TLSv1_3
nomad_opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=nomad_tls), _NoRedirect()
)

base_url = sys.argv[1].rstrip("/")
if not base_url.startswith("https://"):
    print("nomad: NOMAD_ADDR must use https", file=sys.stderr)
    raise SystemExit(1)
with open(sys.argv[5], encoding="ascii") as token_file:
    nomad_token = token_file.readline().strip()
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
        request = urllib.request.Request(f"{base_url}/v1/node/{node_id}", headers={"X-Nomad-Token": nomad_token})
        with nomad_opener.open(request) as response:
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
    # ES's jobs (network mode none, or bridge, and no Nomad network block)
    # need a host-mode network on the node; without one, every plan fails
    # with "missing network".
    networks = (detail.get("NodeResources") or {}).get("Networks") or []
    if not any(isinstance(network, dict) and network.get("Mode") == "host" for network in networks):
        reasons.append(f"{node_name}=no-host-network")
        continue

    schedulable.append((node_name, cpu_total_compute))

if not schedulable:
    print(
        "nomad: no ready client nodes with positive cpu.totalcompute, healthy docker driver and a host-mode network",
        file=sys.stderr,
    )
    if reasons:
        print("nomad: " + ", ".join(reasons), file=sys.stderr)
        if any(reason.endswith("=no-host-network") for reason in reasons):
            print(
                "nomad: a node takes its host network from the interface its client's network_interface names, or "
                'from the default route\'s; pin network_interface = "lo" (scripts/70_linux_setup.sh), which holds on '
                "Wi-Fi and on a cable alike",
                file=sys.stderr,
            )
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

wait_for_nomad_leader() {
  local timeout_seconds=${1:-30}
  local deadline=$((SECONDS + timeout_seconds))
  local leader=""

  while ((SECONDS < deadline)); do
    if leader="$(nomad_curl --fail --silent "${NOMAD_ADDR}/v1/status/leader" 2>/dev/null)" && [[ "${leader}" =~ ^\"[^\"]+\"$ ]]; then
      return 0
    fi
    sleep 1
  done
  echo "nomad: no leader at ${NOMAD_ADDR} within ${timeout_seconds}s" >&2
  return 1
}

es_config_nomad_token_file() {
  local config_path=$1
  python3 -I - "${config_path}" <<'PY'
import json
import os
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    cfg = json.load(handle)
value = (cfg.get("nomad") or {}).get("token_file") if isinstance(cfg, dict) else None
if not isinstance(value, str) or not os.path.isabs(value) or os.path.normpath(value) != value:
    raise SystemExit("es config: nomad.token_file must be a clean absolute path")
print(value)
PY
}

# Bring-up keeps its managed-local Nomad ACL material under BRINGUP_DIR. When
# NOMAD_TOKEN_FILE is unset and that observer token exists, operator checks
# use it.
bringup_nomad_acl_dir() {
  printf '%s/nomad-acl\n' "${BRINGUP_DIR:-$(bringup_repo_root)/.tmp/bringup}"
}

default_bringup_nomad_token_file() {
  local observer
  observer="$(bringup_nomad_acl_dir)/observer-token"
  if [[ -z "${NOMAD_TOKEN_FILE:-}" && -f "${observer}" ]]; then
    export NOMAD_TOKEN_FILE="${observer}"
  fi
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

runtime_profile_images_from_es_config() {
  local config_path=$1
  python3 -I - <<'PY' "$config_path"
import json
import pathlib
import sys

cfg = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
execution = cfg.get("execution") or {}
runtime_profiles = execution.get("runtime_profiles") or {}
normal_shell = runtime_profiles.get("control_plane_normal_shell") or {}

if normal_shell.get("enabled") is True:
    image = normal_shell.get("image")
    if not isinstance(image, str) or not image.strip():
        raise SystemExit("runtime profile image: missing execution.runtime_profiles.control_plane_normal_shell.image")
    print(image.strip())
PY
}

# workload_egress_line reports the temporary compatibility edge of the
# workload grants contract (.docs/execution_lifecycle/contracts.md, section
# 5B): while any grant rule in ES configuration gives the egress lane
# "unrestricted", granted runs have no egress filter of their own. Egress
# lanes (Workstream F slice F1, WI-4) remove that lane. ES startup validates
# the grants; this only reports them. It reads the keys it needs exactly:
# like ES (es/config/exact_keys.go), it refuses a file with a key repeated in
# any object, or with a key spelled in another letter case along the path it
# reads (admission_policy, workload_grants, rules, egress_lane). ES also
# refuses a key in another letter case anywhere else in the file; for such a
# file this line still prints its answer. So for every file ES starts with,
# the line reports the lanes ES reads.
workload_egress_line() {
  local config_path=$1
  python3 -I - "${config_path}" <<'PY'
import json
import sys

REFUSED = "; ES refuses such a file"


def exact_pairs(pairs):
    seen = set()
    for key, _ in pairs:
        if key in seen:
            raise SystemExit(f"es config: the key {key!r} appears more than once in one object{REFUSED}")
        seen.add(key)
    return dict(pairs)


def refuse_constant(name):
    raise SystemExit(f"es config: {name} is not JSON{REFUSED}")


def member(value, key, where):
    if not isinstance(value, dict):
        return None
    for other in value:
        if other != key and other.casefold() == key.casefold():
            raise SystemExit(f"es config: {where}{other!r} must be spelled exactly {key!r}{REFUSED}")
    return value.get(key)


with open(sys.argv[1], encoding="utf-8") as handle:
    cfg = json.load(handle, object_pairs_hook=exact_pairs, parse_constant=refuse_constant)
policy = member(cfg, "admission_policy", "")
grants = member(policy, "workload_grants", "admission_policy.")
rules = member(grants, "rules", "admission_policy.workload_grants.")
if rules is not None and not isinstance(rules, list):
    raise SystemExit("es config: admission_policy.workload_grants.rules must be a list")
unrestricted = [
    rule for index, rule in enumerate(rules or [])
    if member(rule, "egress_lane", f"admission_policy.workload_grants.rules[{index}].") == "unrestricted"
]
if unrestricted:
    print(f"workload_egress_unrestricted=true ({len(unrestricted)} workload grant rule(s) give the egress lane "
          "unrestricted: granted runs have no egress filter of their own until egress lanes land)")
else:
    print("workload_egress_unrestricted=false (no workload grant rule gives the egress lane unrestricted)")
PY
}

check_runtime_profile_images_once() {
  local config_path=$1
  local images
  local image
  local status=0

  images="$(runtime_profile_images_from_es_config "${config_path}")" || return 1
  if [[ -z "${images}" ]]; then
    echo "runtime profile images: none enabled"
    return 0
  fi

  while IFS= read -r image; do
    if [[ -z "${image}" ]]; then
      continue
    fi
    if ! docker image inspect "${image}" >/dev/null 2>&1; then
      echo "runtime profile image: missing ${image} (execution.runtime_profiles.control_plane_normal_shell.image); build or pull it in the Docker daemon used by Nomad before submit" >&2
      status=1
      continue
    fi
    echo "runtime profile image: ${image} present"
  done <<<"${images}"

  return "${status}"
}

check_runtime_profile_image_gc_policy_once() {
  local config_path=$1
  local images
  local response_path
  local summary
  local status=0

  images="$(runtime_profile_images_from_es_config "${config_path}")" || return 1
  if [[ -z "${images}" ]]; then
    echo "runtime profile image durability: no enabled runtime-profile images"
    return 0
  fi

  response_path="$(mktemp)"

  if ! nomad_api_get "/v1/agent/self" "${response_path}"; then
    echo "runtime profile image durability: nomad agent self request failed for ${NOMAD_ADDR}/v1/agent/self" >&2
    status=1
  elif ! summary="$(python3 -I - <<'PY' "${response_path}" "${images}"
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
images = [line.strip() for line in sys.argv[2].splitlines() if line.strip()]
config = payload.get("config") or {}
# The supported Nomad sets image garbage collection in its explicit Docker
# plugin block, so readiness reads it there (the older client option
# docker.cleanup.image is no longer written).
plugins = [plugin for plugin in (config.get("Plugins") or []) if isinstance(plugin, dict) and plugin.get("Name") == "docker"]
plugin_config = (plugins[0].get("Config") or {}) if len(plugins) == 1 else {}
gc = plugin_config.get("gc") if isinstance(plugin_config, dict) else None
# Nomad 2.1 reports a plugin's nested block as an object, Nomad 2.0 as a
# list that holds one object.
if isinstance(gc, list) and len(gc) == 1:
    gc = gc[0]
if not isinstance(gc, dict) or gc.get("image") is not False:
    image_list = ", ".join(images)
    print(
        "runtime profile image durability: missing nomad docker plugin setting "
        f'gc.image = false for enabled runtime profile image(s): {image_list}',
        file=sys.stderr,
    )
    raise SystemExit(1)
print("runtime profile image durability: nomad docker plugin gc.image=false")
PY
)"; then
    status=1
  else
    echo "${summary}"
  fi

  rm -f "${response_path}"
  return "${status}"
}

verify_es_submit_config_enabled() {
  local config_path=$1
  python3 -I - <<'PY' "$config_path"
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
    ("nomad", "server_name"),
    ("nomad", "root_ca_file"),
    ("nomad", "server_spki_sha256"),
    ("nomad", "datacenter"),
    ("nomad", "token_file"),
    ("execution", "staging_root_dir"),
    ("execution", "results_root_dir"),
    ("execution", "base_image"),
    ("execution", "runtime_support_binary"),
    ("execution", "spire_workload_api_socket_path"),
):
    require_non_empty(path)
PY
}

check_es_submit_config_once() {
  local config_path=$1
  local roots_profile="${SUPPORTED_LOCAL_ES_ROOTS_PROFILE:-}"
  local summary

  case "${roots_profile}" in
    "")
      ;;
    service-root-v1)
      verify_supported_local_es_root_profile "${config_path}" "es submit config" || return 1
      ;;
    *)
      echo "es submit config: unsupported supported-local roots profile" >&2
      return 1
      ;;
  esac

  if ! summary="$(python3 -I - <<'PY' "$config_path" "$roots_profile"
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
token_file = require_non_empty(("nomad", "token_file"))
staging_root_dir = require_non_empty(("execution", "staging_root_dir"))
results_root_dir = require_non_empty(("execution", "results_root_dir"))
base_image = require_non_empty(("execution", "base_image"))
runtime_support_binary = require_non_empty(("execution", "runtime_support_binary"))
spire_socket_path = require_non_empty(("execution", "spire_workload_api_socket_path"))

parsed = urlparse(base_url)
if parsed.scheme != "https" or not parsed.netloc:
    raise SystemExit("es submit config: nomad.base_url must be Nomad's https:// address")

staging_root = pathlib.Path(staging_root_dir)
results_root = pathlib.Path(results_root_dir)
if not staging_root.is_absolute():
    raise SystemExit("es submit config: execution.staging_root_dir must be an absolute path")
if not results_root.is_absolute():
    raise SystemExit("es submit config: execution.results_root_dir must be an absolute path")
if os.path.commonpath([str(staging_root), str(results_root)]) in {str(staging_root), str(results_root)}:
    raise SystemExit("es submit config: execution.results_root_dir must be separate from execution.staging_root_dir")
if not staging_root.exists():
    raise SystemExit(f"es submit config: execution.staging_root_dir does not exist: {staging_root_dir}")
if not staging_root.is_dir():
    raise SystemExit(f"es submit config: execution.staging_root_dir is not a directory: {staging_root_dir}")
if sys.argv[2] != "service-root-v1" and not os.access(staging_root_dir, os.W_OK):
    raise SystemExit(f"es submit config: execution.staging_root_dir is not writable: {staging_root_dir}")
if not results_root.exists():
    raise SystemExit(f"es submit config: execution.results_root_dir does not exist: {results_root_dir}")
if not results_root.is_dir():
    raise SystemExit(f"es submit config: execution.results_root_dir is not a directory: {results_root_dir}")
if sys.argv[2] != "service-root-v1" and not os.access(results_root_dir, os.W_OK):
    raise SystemExit(f"es submit config: execution.results_root_dir is not writable: {results_root_dir}")
if not pathlib.Path(runtime_support_binary).is_absolute():
    raise SystemExit("es submit config: execution.runtime_support_binary must be an absolute path")
# The token file may be readable only by ES's user, so this checks its
# placement and type without opening it; ES checks its custody at startup.
if not os.path.isabs(token_file) or os.path.normpath(token_file) != token_file:
    raise SystemExit("es submit config: nomad.token_file must be a clean absolute path")
try:
    token_mode = os.lstat(token_file).st_mode
except OSError:
    raise SystemExit(f"es submit config: nomad.token_file does not exist: {token_file}")
if not stat.S_ISREG(token_mode):
    raise SystemExit(f"es submit config: nomad.token_file is not a regular file: {token_file}")
if stat.S_IMODE(token_mode) not in (0o400, 0o600):
    raise SystemExit(f"es submit config: nomad.token_file must have mode 0400 or 0600: {token_file}")
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
    f"token_file={token_file} "
    f"staging_root_dir={staging_root_dir} "
    f"results_root_dir={results_root_dir} "
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

# ES's own TLS checks against the running Nomad: TLS 1.3, ES's CA and server
# name, the pinned key, and nomad.base_url being the NOMAD_ADDR the other
# checks use. It completes a handshake and sends no request. Callers run it
# after Nomad readiness, so a Nomad that is still starting is waited for first.
check_es_nomad_identity_once() {
  local config_path=$1

  python3 -I "$(dirname "${BASH_SOURCE[0]}")/nomad_tls_identity.py" check "${config_path}" "${NOMAD_ADDR:-}"
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

  digest="$(python3 -I - <<'PY' "$config_path"
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
  elif ! summary="$(python3 -I - <<'PY' "${response_path}" "${digest}"
import json
import pathlib
import ssl
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

ca_bundle = vault.get("ca_bundle_pem")
ca_state = "absent"
if ca_bundle is not None:
    if not isinstance(ca_bundle, str) or not ca_bundle.strip():
        print("workload-zone vault blob has invalid vault_config.ca_bundle_pem", file=sys.stderr)
        raise SystemExit(1)
    try:
        ssl.create_default_context(cadata=ca_bundle)
    except Exception as exc:
        print(f"workload-zone vault blob has invalid vault_config.ca_bundle_pem: {exc}", file=sys.stderr)
        raise SystemExit(1)
    ca_state = "present"

print(f"workload-zone vault blob: digest={sys.argv[2]} vault_ca_bundle={ca_state} ready=true")
PY
)"; then
    status=1
  else
    echo "${summary}"
  fi

  rm -f "${response_path}"
  return "${status}"
}
