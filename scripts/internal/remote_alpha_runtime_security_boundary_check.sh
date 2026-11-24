#!/usr/bin/env bash
set -euo pipefail

remote_alpha_runtime_security_boundary_schema="execution-substrate.remote-alpha.runtime-security-boundary-check.v1"
remote_alpha_runtime_security_boundary_default_config_path="/etc/execution-substrate/es.json"
remote_alpha_runtime_security_boundary_default_workload_zone_config_path="/etc/execution-substrate/vault/workload-zone-vault-config.json"

remote_alpha_runtime_security_boundary_defaults() {
  REMOTE_ALPHA_RUNTIME_SECURITY_BOUNDARY_CONFIG_PATH="${REMOTE_ALPHA_RUNTIME_SECURITY_BOUNDARY_CONFIG_PATH:-${remote_alpha_runtime_security_boundary_default_config_path}}"
  REMOTE_ALPHA_RUNTIME_SECURITY_BOUNDARY_WORKLOAD_ZONE_CONFIG_PATH="${REMOTE_ALPHA_RUNTIME_SECURITY_BOUNDARY_WORKLOAD_ZONE_CONFIG_PATH:-${remote_alpha_runtime_security_boundary_default_workload_zone_config_path}}"
  REMOTE_ALPHA_RUNTIME_SECURITY_BOUNDARY_SUMMARY_PATH="${REMOTE_ALPHA_RUNTIME_SECURITY_BOUNDARY_SUMMARY_PATH:-}"
  REMOTE_ALPHA_RUNTIME_SECURITY_BOUNDARY_ACCEPT_CVE_31431_MITIGATION_RISK="${REMOTE_ALPHA_RUNTIME_SECURITY_BOUNDARY_ACCEPT_CVE_31431_MITIGATION_RISK:-0}"
}

remote_alpha_runtime_security_boundary_usage() {
  cat <<'EOF'
Usage:
  scripts/remote_alpha_runtime_security_boundary_check.sh

Optional flags:
  --config-path </path/to/es.json>
  --workload-zone-config-path </path/to/workload-zone-vault-config.json>
  --summary-path <runtime-security-boundary-check.json>
  --accept-cve-31431-mitigation-risk-for-internal-alpha
  --help

Default behavior is check-only, non-mutating, and writes JSON to stdout.
The CVE-2026-31431 mitigation-risk flag is evidence-only, non-mutating, and
only downgrades a verified module-disable mitigation from blocker to warning for
a bounded internal Remote Alpha proof; it is not kernel patch authority.
EOF
}

remote_alpha_runtime_security_boundary_parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --config-path)
        REMOTE_ALPHA_RUNTIME_SECURITY_BOUNDARY_CONFIG_PATH="$2"
        shift 2
        ;;
      --workload-zone-config-path)
        REMOTE_ALPHA_RUNTIME_SECURITY_BOUNDARY_WORKLOAD_ZONE_CONFIG_PATH="$2"
        shift 2
        ;;
      --summary-path)
        REMOTE_ALPHA_RUNTIME_SECURITY_BOUNDARY_SUMMARY_PATH="$2"
        shift 2
        ;;
      --accept-cve-31431-mitigation-risk-for-internal-alpha)
        REMOTE_ALPHA_RUNTIME_SECURITY_BOUNDARY_ACCEPT_CVE_31431_MITIGATION_RISK=1
        shift
        ;;
      --help|-h)
        remote_alpha_runtime_security_boundary_usage
        return 1
        ;;
      *)
        echo "unknown argument: $1" >&2
        remote_alpha_runtime_security_boundary_usage >&2
        return 2
        ;;
    esac
  done
}

remote_alpha_runtime_security_boundary_require_command() {
  local name=$1
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "${name} is required" >&2
    return 1
  fi
}

remote_alpha_runtime_security_boundary_validate_summary_file() {
  local summary_path=$1

  python3 -I - "${summary_path}" <<'PY'
import pathlib
import re
import sys

summary_path = pathlib.Path(sys.argv[1])
text = summary_path.read_text(encoding="utf-8")

secret_patterns = [
    re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    re.compile(r"(?:^|[^A-Za-z0-9])(?:hvs|s|b)\.[A-Za-z0-9._-]{12,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----"),
    re.compile(r'(?i)(?:unseal[_ -]?key|root[_ -]?token|client[_ -]?token)["' + "'" + r']?\s*[:=]\s*["' + "'" + r']?[A-Za-z0-9+/=._-]{8,}'),
    re.compile(r'(?i)raw[_ -]?secret[_ -]?payload["' + "'" + r']?\s*[:=]\s*["' + "'" + r']?[A-Za-z0-9+/=._-]{8,}'),
    re.compile(r'(?i)codex.{0,16}(?:credential|token|api[_ -]?key)["' + "'" + r']?\s*[:=]\s*["' + "'" + r']?[A-Za-z0-9+/=._-]{8,}'),
]
overclaim_patterns = [
    re.compile(r"full ES/runtime de-root", re.IGNORECASE),
    re.compile(r"rootless Nomad client", re.IGNORECASE),
    re.compile(r"governed execution proof", re.IGNORECASE),
    re.compile(r"Vault production readiness", re.IGNORECASE),
    re.compile(r"workload credential success", re.IGNORECASE),
    re.compile(r"support-bundle authority", re.IGNORECASE),
    re.compile(r"kernel patch authority", re.IGNORECASE),
    re.compile(r"production safety proof", re.IGNORECASE),
]

for pattern in secret_patterns:
    if pattern.search(text):
        raise SystemExit(f"summary contains secret-like material matching {pattern.pattern}: {summary_path}")
for pattern in overclaim_patterns:
    if pattern.search(text):
        raise SystemExit(f"summary contains overclaim text matching {pattern.pattern}: {summary_path}")
PY
}

remote_alpha_runtime_security_boundary_main() {
  local summary_tmp_path=""

  remote_alpha_runtime_security_boundary_defaults
  remote_alpha_runtime_security_boundary_parse_args "$@" || return $?
  remote_alpha_runtime_security_boundary_require_command python3 || return 1

  summary_tmp_path="${TMPDIR:-/tmp}/remote-alpha-runtime-security-boundary.${PPID:-0}.$$.$RANDOM.json"

  python3 -I - \
    "${remote_alpha_runtime_security_boundary_schema}" \
    "${REMOTE_ALPHA_RUNTIME_SECURITY_BOUNDARY_CONFIG_PATH}" \
    "${REMOTE_ALPHA_RUNTIME_SECURITY_BOUNDARY_WORKLOAD_ZONE_CONFIG_PATH}" \
    "${summary_tmp_path}" \
    "${REMOTE_ALPHA_RUNTIME_SECURITY_BOUNDARY_ACCEPT_CVE_31431_MITIGATION_RISK}" <<'PY'
import json
import os
import pathlib
import pwd
import re
import shutil
import socket
import stat
import subprocess
import sys
from datetime import datetime, timezone

SCHEMA = sys.argv[1]
CONFIG_PATH = pathlib.Path(sys.argv[2])
WORKLOAD_ZONE_CONFIG_PATH = pathlib.Path(sys.argv[3])
SUMMARY_PATH = pathlib.Path(sys.argv[4])
ACCEPT_CVE_31431_MITIGATION_RISK = str(sys.argv[5]).lower() in {"1", "true", "yes"}

NON_AUTHORITY_LABELS = [
    "not_service_health",
    "not_submit_readiness",
    "not_runtime_profile_readiness",
    "not_producer_contract_compatibility",
    "not_retained_result_readiness",
    "not_governed_proof",
    "not_workload_credential_success_proof",
    "not_vault_production_ready",
    "not_support_bundle_authority",
]
EXPLICIT_NON_CLAIMS = [
    "not_service_health",
    "not_submit_readiness",
    "not_runtime_profile_readiness",
    "not_full_es_runtime_deroot",
    "not_rootless_nomad_client",
    "not_governed_execution_proof",
    "not_vault_production_ready",
    "not_workload_credential_success_proof",
    "not_support_bundle_authority",
    "not_kernel_patch",
    "not_production_safety_proof",
]


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json_file(path):
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, f"{path} does not exist"
    except OSError as exc:
        return None, f"could not read {path}: {exc}"
    try:
        payload = json.loads(text)
    except Exception as exc:
        return None, f"could not decode json from {path}: {exc}"
    return payload, ""


def run_command(args):
    if shutil.which(args[0]) is None:
        return None
    try:
        return subprocess.run(args, check=False, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(
            args=args,
            returncode=124,
            stdout=exc.stdout or "",
            stderr=(exc.stderr or "") + "\ncommand timed out",
        )
    except FileNotFoundError:
        return None


def service_show(service_name):
    proc = run_command(
        ["systemctl", "show", service_name, "--property=User,Group,UMask,FragmentPath,ExecStart", "--no-pager"]
    )
    if proc is None:
        return None, "systemctl command not found"
    if proc.returncode != 0:
        return None, f"systemctl show {service_name} failed"

    payload = {}
    for line in proc.stdout.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        payload[key] = value

    raw_user = str(payload.get("User") or "").strip()
    raw_group = str(payload.get("Group") or "").strip()
    user = raw_user or "root"
    group = raw_group or "root"
    return {
        "service_name": service_name,
        "user": user,
        "group": group,
        "umask": str(payload.get("UMask") or "").strip(),
        "fragment_path": str(payload.get("FragmentPath") or "").strip(),
        "exec_start": str(payload.get("ExecStart") or "").strip(),
        "root_managed": user in {"root", "0"},
    }, ""


def socket_meta(path_text):
    if not path_text:
        return {"path": "", "exists": False, "is_socket": False}
    target = pathlib.Path(path_text)
    try:
        info = os.lstat(target)
    except FileNotFoundError:
        return {"path": path_text, "exists": False, "is_socket": False}
    except OSError:
        return {"path": path_text, "exists": False, "is_socket": False}
    return {
        "path": path_text,
        "exists": True,
        "is_socket": stat.S_ISSOCK(info.st_mode),
    }


def spire_selectors():
    proc = run_command(["spire-server", "entry", "show"])
    if proc is None:
        return None, "spire-server command not found"
    if proc.returncode != 0:
        return None, "spire-server entry show failed"

    selectors = []
    for line in proc.stdout.splitlines():
        if "Selector" not in line or ":" not in line:
            continue
        selector = line.split(":", 1)[1].strip()
        if selector:
            selectors.append(selector)
    selectors = sorted(set(selectors))
    if not selectors:
        return None, "spire-server entry show did not report selectors"
    return {
        "selectors": selectors,
        "alpha_only": "unix:uid:0" in selectors and "unix:gid:0" in selectors,
    }, ""


def strip_ansi(text):
    return re.sub(r"\x1b\[[0-9;]*m", "", text or "")


def command_text(proc):
    if proc is None:
        return ""
    return strip_ansi(((proc.stdout or "") + (proc.stderr or "")).strip())


def first_nonempty_line(text):
    for line in (text or "").splitlines():
        line = line.strip()
        if line:
            return line
    return ""


def read_os_release():
    path = pathlib.Path("/etc/os-release")
    if not path.exists():
        return {"available": False, "path": os.fspath(path)}
    payload = {}
    try:
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            if not raw_line or raw_line.startswith("#") or "=" not in raw_line:
                continue
            key, value = raw_line.split("=", 1)
            payload[key] = value.strip().strip('"')
    except OSError as exc:
        return {"available": False, "path": os.fspath(path), "error": str(exc)}
    return {
        "available": True,
        "path": os.fspath(path),
        "id": payload.get("ID", ""),
        "id_like": payload.get("ID_LIKE", ""),
        "pretty_name": payload.get("PRETTY_NAME", ""),
        "version_id": payload.get("VERSION_ID", ""),
        "version_codename": payload.get("VERSION_CODENAME") or payload.get("UBUNTU_CODENAME", ""),
    }


def collect_package_inventory(kernel_release):
    package_names = [
        f"linux-image-{kernel_release}" if kernel_release else "",
        "linux-generic",
        "linux-headers-generic",
        "kmod",
        "docker-ce",
        "docker-ce-cli",
        "docker.io",
        "containerd",
        "containerd.io",
        "runc",
        "crun",
        "podman",
        "fuse-overlayfs",
        "nomad",
        "vault",
    ]
    package_names = [name for name in package_names if name]
    inventory = {
        "kernel_release": kernel_release,
        "query_tool": "unknown",
        "packages": {},
        "missing_or_unmatched": [],
        "query_error": "",
    }

    if shutil.which("dpkg-query"):
        inventory["query_tool"] = "dpkg-query"
        proc = run_command(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${Status}\n", *package_names])
        text = command_text(proc)
        for line in text.splitlines():
            if not line.strip():
                continue
            if "no packages found matching" in line:
                inventory["missing_or_unmatched"].append(line.strip())
                continue
            parts = line.split("\t")
            if len(parts) >= 3:
                inventory["packages"][parts[0]] = {"version": parts[1], "status": parts[2]}
        if proc is not None and proc.returncode not in (0, 1):
            inventory["query_error"] = first_nonempty_line(text)
        return inventory

    if shutil.which("rpm"):
        inventory["query_tool"] = "rpm"
        proc = run_command(["rpm", "-q", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\tinstalled\n", *package_names])
        text = command_text(proc)
        for line in text.splitlines():
            if "\t" in line:
                name, version, status = line.split("\t", 2)
                inventory["packages"][name] = {"version": version, "status": status}
            elif "is not installed" in line:
                inventory["missing_or_unmatched"].append(line.strip())
        if proc is not None and proc.returncode not in (0, 1):
            inventory["query_error"] = first_nonempty_line(text)
        return inventory

    if shutil.which("pacman"):
        inventory["query_tool"] = "pacman"
        proc = run_command(["pacman", "-Q", *package_names])
        text = command_text(proc)
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                inventory["packages"][parts[0]] = {"version": parts[1], "status": "installed"}
            elif line.strip():
                inventory["missing_or_unmatched"].append(line.strip())
        if proc is not None and proc.returncode not in (0, 1):
            inventory["query_error"] = first_nonempty_line(text)
        return inventory

    return inventory


def parse_key_value_lines(text):
    payload = {}
    for line in (text or "").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        payload[key.strip()] = value.strip()
    return payload


def collect_docker_inventory():
    inventory = {
        "binary_present": shutil.which("docker") is not None,
        "version_observed": False,
        "version_summary": "",
        "info_observed": False,
        "info_error": "",
        "storage_driver": "",
        "cgroup_driver": "",
        "default_runtime": "",
        "runtimes": [],
        "security_options": [],
    }
    if not inventory["binary_present"]:
        inventory["info_error"] = "docker command not found"
        return inventory

    version_proc = run_command(["docker", "version"])
    version_text = command_text(version_proc)
    inventory["version_observed"] = version_proc is not None and version_proc.returncode == 0
    inventory["version_summary"] = "\n".join(version_text.splitlines()[:12])

    format_text = (
        "StorageDriver={{.Driver}}\n"
        "CgroupDriver={{.CgroupDriver}}\n"
        "DefaultRuntime={{.DefaultRuntime}}\n"
        "Runtimes={{json .Runtimes}}\n"
        "SecurityOptions={{json .SecurityOptions}}"
    )
    info_proc = run_command(["docker", "info", "--format", format_text])
    info_text = command_text(info_proc)
    if info_proc is None:
        inventory["info_error"] = "docker info unavailable"
        return inventory
    if info_proc.returncode != 0:
        stderr_text = strip_ansi((info_proc.stderr or "").strip())
        inventory["info_error"] = first_nonempty_line(stderr_text) or first_nonempty_line(info_text) or f"docker info exited {info_proc.returncode}"
        return inventory

    inventory["info_observed"] = True
    values = parse_key_value_lines(info_text)
    inventory["storage_driver"] = values.get("StorageDriver", "")
    inventory["cgroup_driver"] = values.get("CgroupDriver", "")
    inventory["default_runtime"] = values.get("DefaultRuntime", "")
    try:
        runtimes_payload = json.loads(values.get("Runtimes") or "{}")
        if isinstance(runtimes_payload, dict):
            inventory["runtimes"] = sorted(runtimes_payload.keys())
    except Exception:
        inventory["runtimes"] = []
    try:
        security_options = json.loads(values.get("SecurityOptions") or "[]")
        if isinstance(security_options, list):
            inventory["security_options"] = [str(item) for item in security_options]
    except Exception:
        inventory["security_options"] = []
    return inventory


def collect_nomad_inventory():
    inventory = {
        "binary_present": shutil.which("nomad") is not None,
        "version_observed": False,
        "version_summary": "",
        "agent_api_observed": False,
        "node_api_observed": False,
        "agent": {},
        "node": {},
        "api_error": "",
    }
    if inventory["binary_present"]:
        proc = run_command(["nomad", "version"])
        text = command_text(proc)
        inventory["version_observed"] = proc is not None and proc.returncode == 0
        inventory["version_summary"] = "\n".join(text.splitlines()[:4])

    try:
        import urllib.request

        # Nomad enforces ACLs: read with the read-only observer token named by
        # NOMAD_TOKEN_FILE, sent only in the request header.
        nomad_headers = {}
        token_file = os.environ.get("NOMAD_TOKEN_FILE", "")
        if token_file:
            descriptor = os.open(token_file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise ValueError("nomad observer token file is not a regular file")
                token_text = os.read(descriptor, 64).decode("ascii")
            finally:
                os.close(descriptor)
            if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\n?", token_text, re.ASCII):
                raise ValueError("nomad observer token file does not hold one token")
            nomad_headers["X-Nomad-Token"] = token_text.rstrip("\n")

        def nomad_get(path):
            return urllib.request.Request("http://127.0.0.1:4646" + path, headers=nomad_headers)

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        # No proxy and no redirects: the observer token reaches only Nomad.
        nomad_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

        with nomad_opener.open(nomad_get("/v1/agent/self"), timeout=3) as response:
            agent_payload = json.loads(response.read().decode("utf-8"))
        config = agent_payload.get("config") or agent_payload.get("Config") or {}
        member = agent_payload.get("member") or agent_payload.get("Member") or {}
        inventory["agent_api_observed"] = True
        inventory["agent"] = {
            "member_name": member.get("name") or member.get("Name") or "",
            "member_addr": member.get("addr") or member.get("Addr") or "",
            "server_enabled": bool((config.get("Server") or {}).get("Enabled")),
            "datacenter": config.get("Datacenter") or "",
        }

        with nomad_opener.open(nomad_get("/v1/nodes"), timeout=3) as response:
            nodes_payload = json.loads(response.read().decode("utf-8"))
        if isinstance(nodes_payload, list) and nodes_payload:
            node_id = str(nodes_payload[0].get("ID") or "")
            with nomad_opener.open(nomad_get(f"/v1/node/{node_id}"), timeout=3) as response:
                node_payload = json.loads(response.read().decode("utf-8"))
            attributes = node_payload.get("Attributes") or {}
            drivers = node_payload.get("Drivers") or {}
            inventory["node_api_observed"] = True
            inventory["node"] = {
                "id": node_payload.get("ID") or "",
                "name": node_payload.get("Name") or "",
                "status": node_payload.get("Status") or "",
                "cpu_totalcompute": attributes.get("cpu.totalcompute") or "",
                "kernel_name": attributes.get("kernel.name") or "",
                "kernel_version": attributes.get("kernel.version") or "",
                "os_name": attributes.get("os.name") or "",
                "os_version": attributes.get("os.version") or "",
                "docker_driver_detected": attributes.get("driver.docker") == "1",
                "docker_driver_version": attributes.get("driver.docker.version") or "",
                "docker_driver_runtimes": attributes.get("driver.docker.runtimes") or "",
                "drivers": {
                    name: {
                        "detected": bool(details.get("Detected")),
                        "healthy": bool(details.get("Healthy")),
                        "health_description": str(details.get("HealthDescription") or ""),
                    }
                    for name, details in drivers.items()
                    if isinstance(details, dict)
                },
            }
    except Exception as exc:
        inventory["api_error"] = str(exc)

    return inventory


def collect_runtime_path_inventory(docker_inventory, nomad_inventory):
    binaries = {
        name: shutil.which(name) is not None
        for name in ("fuse-overlayfs", "podman", "crun", "runc", "containerd", "docker")
    }
    process_matches = []
    ps_proc = run_command(["ps", "-eo", "comm,args"])
    ps_text = command_text(ps_proc)
    for line in ps_text.splitlines():
        if re.search(r"\b(dockerd|containerd|runc|crun|podman|fuse-overlayfs|nomad)\b", line):
            process_matches.append(line.strip())

    mount_matches = []
    for path_text in ("/proc/mounts", "/proc/self/mountinfo"):
        path = pathlib.Path(path_text)
        if not path.exists():
            continue
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                if re.search(r"fuse|overlay", line, re.IGNORECASE):
                    mount_matches.append(line.strip())
        except OSError:
            continue

    docker_storage_driver = str(docker_inventory.get("storage_driver") or "")
    docker_runtimes = {str(item) for item in docker_inventory.get("runtimes") or []}
    nomad_docker_runtimes = str((nomad_inventory.get("node") or {}).get("docker_driver_runtimes") or "")

    fuse_in_path = "unknown"
    if docker_inventory.get("info_observed"):
        fuse_in_path = "yes" if docker_storage_driver == "fuse-overlayfs" else "no"
    elif binaries.get("fuse-overlayfs") or any("fuse-overlayfs" in line for line in process_matches + mount_matches):
        fuse_in_path = "unknown"

    podman_crun_in_path = "unknown"
    if "crun" in docker_runtimes or "crun" in nomad_docker_runtimes:
        podman_crun_in_path = "yes"
    elif nomad_inventory.get("node_api_observed") and not binaries.get("podman") and not binaries.get("crun"):
        podman_crun_in_path = "no"

    idmapped_mount_setattr_in_path = "unknown"
    if podman_crun_in_path == "no" and fuse_in_path == "no":
        idmapped_mount_setattr_in_path = "no"

    return {
        "binaries": binaries,
        "process_matches": process_matches[:20],
        "mount_matches": mount_matches[:20],
        "fuse_fuse_overlayfs_in_actual_path": fuse_in_path,
        "podman_crun_in_actual_path": podman_crun_in_path,
        "idmapped_mount_setattr_in_actual_path": idmapped_mount_setattr_in_path,
    }


def classify_vendor_cve_text(text):
    lowered = (text or "").lower()
    if "is not resolved" in lowered or "still affected" in lowered or "no fix is available yet" in lowered:
        return "vulnerable"
    if "is resolved" in lowered or "already fixed" in lowered or "no affected packages" in lowered:
        return "fixed"
    if "does not affect" in lowered or "not affected" in lowered:
        return "not_affected"
    return "unknown"


def collect_vendor_cve_status(cve_id):
    result = {
        "classification": "unknown",
        "vendor_status_directly_observed": False,
        "evidence_source": "none",
        "command": "",
        "returncode": None,
        "summary_lines": [],
    }

    if shutil.which("pro"):
        proc = run_command(["pro", "fix", cve_id, "--dry-run"])
        text = command_text(proc)
        classification = classify_vendor_cve_text(text)
        interesting = []
        for line in text.splitlines():
            stripped = line.strip()
            lowered = stripped.lower()
            if (
                cve_id.lower() in lowered
                or "affected source package" in lowered
                or "packages are still affected" in lowered
                or "no fix is available yet" in lowered
                or "is not resolved" in lowered
                or "is resolved" in lowered
                or "not affected" in lowered
            ):
                interesting.append(stripped)
        result.update(
            {
                "classification": classification,
                "vendor_status_directly_observed": classification != "unknown",
                "evidence_source": "ubuntu_pro_fix_dry_run",
                "command": f"pro fix {cve_id} --dry-run",
                "returncode": None if proc is None else proc.returncode,
                "summary_lines": interesting[:12],
            }
        )
        return result

    for tool in ("dnf", "yum"):
        if shutil.which(tool):
            proc = run_command([tool, "updateinfo", "info", "--cve", cve_id])
            text = command_text(proc)
            classification = "unknown"
            lowered = text.lower()
            if "no matching" in lowered or "not found" in lowered:
                classification = "not_affected"
            elif cve_id.lower() in lowered:
                classification = "vulnerable"
            result.update(
                {
                    "classification": classification,
                    "vendor_status_directly_observed": classification != "unknown",
                    "evidence_source": f"{tool}_updateinfo",
                    "command": f"{tool} updateinfo info --cve {cve_id}",
                    "returncode": None if proc is None else proc.returncode,
                    "summary_lines": [line.strip() for line in text.splitlines()[:12] if line.strip()],
                }
            )
            return result

    return result


def collect_loaded_module_status(module_name):
    proc_modules = pathlib.Path(os.environ.get("REMOTE_ALPHA_RUNTIME_SECURITY_BOUNDARY_PROC_MODULES_PATH", "/proc/modules"))
    normalized = module_name.replace("-", "_")
    if proc_modules.exists():
        try:
            text = proc_modules.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return None, os.fspath(proc_modules), f"could not read {proc_modules}: {exc}"
        loaded = any(
            line.split() and line.split()[0].replace("-", "_") == normalized
            for line in text.splitlines()
        )
        return loaded, os.fspath(proc_modules), ""

    lsmod_proc = run_command(["lsmod"])
    if lsmod_proc is None:
        return None, "none", "lsmod command not found and /proc/modules is unavailable"
    lsmod_text = command_text(lsmod_proc)
    loaded = any(
        line.split() and line.split()[0].replace("-", "_") == normalized
        for line in lsmod_text.splitlines()
    )
    return loaded, "lsmod", "" if lsmod_proc.returncode == 0 else "lsmod returned non-zero status"


def modprobe_install_command_blocks_load(command):
    tokens = str(command or "").strip().split()
    if not tokens:
        return False
    first = pathlib.PurePosixPath(tokens[0]).name
    return first in {"false", "true", ":"}


def parse_modprobe_policy_text(text, source_label):
    sources = []
    module_expr = r"algif[_-]aead"
    blacklist_re = re.compile(rf"^\s*blacklist\s+{module_expr}\b")
    install_re = re.compile(rf"^\s*install\s+{module_expr}\s+(.+?)\s*$")

    for line_number, raw_line in enumerate((text or "").splitlines(), start=1):
        stripped = raw_line.split("#", 1)[0].strip()
        if not stripped:
            continue
        if blacklist_re.match(stripped):
            sources.append(f"{source_label}:{line_number}:blacklist algif_aead")
            continue
        install_match = install_re.match(stripped)
        if install_match and modprobe_install_command_blocks_load(install_match.group(1)):
            sources.append(f"{source_label}:{line_number}:install algif_aead blocks load")
    return sources


def parse_modprobe_dry_run_policy(text, source_label):
    sources = parse_modprobe_policy_text(text, source_label)
    for line_number, raw_line in enumerate((text or "").splitlines(), start=1):
        stripped = raw_line.split("#", 1)[0].strip()
        if not stripped:
            continue
        dry_run_install = re.match(r"^\s*install\s+(.+?)\s*$", stripped)
        if dry_run_install and modprobe_install_command_blocks_load(dry_run_install.group(1)):
            sources.append(f"{source_label}:{line_number}:dry-run install blocks load")
    return sources


def collect_algif_aead_autoload_policy():
    sources = []
    checked_sources = []

    for directory in ("/etc/modprobe.d", "/lib/modprobe.d", "/usr/lib/modprobe.d"):
        root = pathlib.Path(directory)
        if not root.is_dir():
            checked_sources.append(f"{directory}:not_present")
            continue
        for candidate in sorted(root.glob("*.conf")):
            checked_sources.append(os.fspath(candidate))
            try:
                text = candidate.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            sources.extend(parse_modprobe_policy_text(text, os.fspath(candidate)))

    showconfig_proc = run_command(["modprobe", "--showconfig"])
    if showconfig_proc is None:
        checked_sources.append("modprobe --showconfig:command_not_found")
    else:
        checked_sources.append(f"modprobe --showconfig:returncode={showconfig_proc.returncode}")
        sources.extend(parse_modprobe_policy_text(command_text(showconfig_proc), "modprobe --showconfig"))

    dry_run_proc = run_command(["modprobe", "-n", "-v", "algif_aead"])
    if dry_run_proc is None:
        checked_sources.append("modprobe -n -v algif_aead:command_not_found")
    else:
        checked_sources.append(f"modprobe -n -v algif_aead:returncode={dry_run_proc.returncode}")
        sources.extend(parse_modprobe_dry_run_policy(command_text(dry_run_proc), "modprobe -n -v algif_aead"))

    deduped_sources = []
    seen = set()
    for source in sources:
        if source in seen:
            continue
        seen.add(source)
        deduped_sources.append(source)

    return {
        "blocked": bool(deduped_sources),
        "blocking_policy_source": deduped_sources[0] if deduped_sources else "",
        "blocking_policy_sources": deduped_sources[:12],
        "checked_sources": checked_sources[:40],
    }


def collect_algif_aead_status():
    module_loaded, module_loaded_source, module_loaded_error = collect_loaded_module_status("algif_aead")
    modinfo_proc = run_command(["modinfo", "-F", "filename", "algif_aead"])
    modinfo_text = command_text(modinfo_proc)
    module_present = None
    if modinfo_proc is not None:
        module_present = bool(modinfo_text and "not found" not in modinfo_text.lower() and modinfo_proc.returncode == 0)
    autoload_policy = collect_algif_aead_autoload_policy()
    autoload_blocked = bool(autoload_policy["blocked"])
    mitigation_verified = module_loaded is False and autoload_blocked

    return {
        "algif_aead_module_present": module_present,
        "algif_aead_loaded": module_loaded,
        "algif_aead_loaded_evidence_source": module_loaded_source,
        "algif_aead_loaded_observed": module_loaded is not None,
        "algif_aead_autoload_blocked": autoload_blocked,
        "algif_aead_blocking_policy_source": autoload_policy["blocking_policy_source"],
        "algif_aead_blocking_policy_sources": autoload_policy["blocking_policy_sources"],
        "algif_aead_policy_checked_sources": autoload_policy["checked_sources"],
        "algif_aead_mitigation_verified": mitigation_verified,
        "algif_aead_mitigation_warning": (
            "algif_aead is not loaded and autoload blocking policy was observed; this is not a kernel patch and not proof of production safety."
            if mitigation_verified
            else ""
        ),
        "algif_aead_loaded_error": module_loaded_error,
        "module_loaded": module_loaded,
        "module_present": module_present,
        "module_filename": first_nonempty_line(modinfo_text),
        "mitigation_or_fix_status": "unknown",
        "module_load_attempted": False,
        "module_unload_attempted": False,
    }


def apply_cve_31431_algif_mitigation(cve_31431, algif_aead_status):
    result = dict(cve_31431)
    vendor_classification = str(result.get("classification") or "unknown")
    result["vendor_package_classification"] = vendor_classification
    result["algif_aead_mitigation_verified"] = bool(
        algif_aead_status.get("algif_aead_mitigation_verified")
    )
    result["not_patch_authority"] = True
    result["not_production_safety_proof"] = True

    if vendor_classification == "vulnerable" and result["algif_aead_mitigation_verified"]:
        result["classification"] = "mitigated_not_fixed"
        result["mitigation_kind"] = "algif_aead_module_disable"
        result["mitigation_warning"] = (
            "Vendor/package evidence still reports CVE-2026-31431 vulnerable, "
            "but algif_aead was not loaded and non-mutating modprobe policy evidence "
            "showed autoload blocking. This is not a kernel patch and not proof of production safety."
        )
        result["risk_acceptance_required_for_internal_alpha"] = True
        result["risk_accepted_for_internal_alpha"] = ACCEPT_CVE_31431_MITIGATION_RISK
    else:
        result["mitigation_kind"] = ""
        result["mitigation_warning"] = ""
        result["risk_acceptance_required_for_internal_alpha"] = False
        result["risk_accepted_for_internal_alpha"] = False

    return result


def extract_nomad_config_paths(exec_start):
    if not exec_start:
        return []
    matches = re.findall(r"-config(?:=|\s+)([^ ;}]+)", exec_start)
    paths = []
    for raw_path in matches:
        path_text = str(raw_path).strip().strip('"').strip("'")
        if path_text:
            paths.append(path_text)
    return sorted(set(paths))


def parse_nomad_role_flags(text):
    roles = {}
    ambiguous_roles = []
    for role_name in ("server", "client"):
        matches = re.findall(
            rf"(?ims)\b{role_name}\s*\{{.*?\benabled\s*=\s*(true|false)",
            text,
        )
        if not matches:
            continue
        normalized = {match.lower() == "true" for match in matches}
        if len(normalized) != 1:
            ambiguous_roles.append(role_name)
            continue
        roles[role_name] = normalized.pop()
    return roles, ambiguous_roles


def collect_nomad_role_evidence(nomad_service):
    evidence = {
        "systemd_unit": {
            "available": nomad_service is not None,
        },
        "local_config": {
            "available": False,
            "config_paths_considered": [],
            "config_paths_read": [],
            "missing_paths": [],
            "parse_errors": [],
            "ambiguous_roles": [],
            "detected_roles": [],
        },
    }
    if nomad_service is not None:
        evidence["systemd_unit"].update(
            {
                "service_name": str(nomad_service.get("service_name") or "nomad"),
                "user": str(nomad_service.get("user") or ""),
                "group": str(nomad_service.get("group") or ""),
                "fragment_path": str(nomad_service.get("fragment_path") or ""),
                "exec_start": str(nomad_service.get("exec_start") or ""),
                "root_managed": bool(nomad_service.get("root_managed")),
            }
        )

    config_candidates = extract_nomad_config_paths(str((nomad_service or {}).get("exec_start") or ""))
    if not config_candidates:
        config_candidates = ["/etc/nomad.d"]
    evidence["local_config"]["config_paths_considered"] = config_candidates

    enabled_sources = {"server": [], "client": []}
    disabled_sources = {"server": [], "client": []}
    ambiguous_roles = set()

    for path_text in config_candidates:
        target = pathlib.Path(path_text)
        if target.is_dir():
            candidate_files = sorted(
                child
                for child in target.iterdir()
                if child.is_file() and child.suffix in {".hcl", ".json"}
            )
        elif target.is_file():
            candidate_files = [target]
        else:
            evidence["local_config"]["missing_paths"].append(path_text)
            continue

        evidence["local_config"]["available"] = True
        if not candidate_files:
            evidence["local_config"]["missing_paths"].append(path_text)
            continue

        for candidate in candidate_files:
            try:
                text = candidate.read_text(encoding="utf-8")
            except OSError as exc:
                evidence["local_config"]["parse_errors"].append(f"could not read {candidate}: {exc}")
                continue

            evidence["local_config"]["config_paths_read"].append(os.fspath(candidate))
            role_flags, file_ambiguous_roles = parse_nomad_role_flags(text)
            ambiguous_roles.update(file_ambiguous_roles)
            for role_name, enabled in role_flags.items():
                if enabled:
                    enabled_sources[role_name].append(os.fspath(candidate))
                else:
                    disabled_sources[role_name].append(os.fspath(candidate))

    detected_roles = []
    for role_name in ("server", "client"):
        if enabled_sources[role_name] and disabled_sources[role_name]:
            ambiguous_roles.add(role_name)
            continue
        if enabled_sources[role_name]:
            detected_roles.append(role_name)

    evidence["local_config"]["ambiguous_roles"] = sorted(ambiguous_roles)
    evidence["local_config"]["detected_roles"] = detected_roles
    evidence["local_config"]["role_sources"] = {
        role_name: enabled_sources[role_name]
        for role_name in ("server", "client")
        if enabled_sources[role_name]
    }
    combined_single_node_service = set(detected_roles) == {"server", "client"}

    return {
        "roles_detected": detected_roles,
        "combined_single_node_service": combined_single_node_service,
        "role_evidence": evidence,
    }


config_payload, config_error = read_json_file(CONFIG_PATH)
execution = {}
if isinstance(config_payload, dict):
    execution = config_payload.get("execution") or {}
if not isinstance(execution, dict):
    execution = {}

runtime_support_binary = str(execution.get("runtime_support_binary") or "").strip()
spire_socket_path = str(execution.get("spire_workload_api_socket_path") or "").strip()
spire_socket = socket_meta(spire_socket_path)

workload_zone_payload, workload_zone_error = read_json_file(WORKLOAD_ZONE_CONFIG_PATH)
vault_config = {}
if isinstance(workload_zone_payload, dict):
    vault_config = workload_zone_payload.get("vault_config") or {}
if not isinstance(vault_config, dict):
    vault_config = {}

nomad_service, nomad_service_error = service_show("nomad")
vault_service, vault_service_error = service_show("vault")
selector_info, selector_error = spire_selectors()
nomad_role_context = collect_nomad_role_evidence(nomad_service)

uname_proc = run_command(["uname", "-a"])
kernel_release_proc = run_command(["uname", "-r"])
kernel_release = command_text(kernel_release_proc).splitlines()[0].strip() if kernel_release_proc else ""
os_release = read_os_release()
package_inventory = collect_package_inventory(kernel_release)
docker_inventory = collect_docker_inventory()
nomad_inventory = collect_nomad_inventory()
runtime_path_inventory = collect_runtime_path_inventory(docker_inventory, nomad_inventory)
cve_31431 = collect_vendor_cve_status("CVE-2026-31431")
cve_31465 = collect_vendor_cve_status("CVE-2026-31465")
algif_aead_status = collect_algif_aead_status()
cve_31431 = apply_cve_31431_algif_mitigation(cve_31431, algif_aead_status)
algif_aead_status["mitigation_or_fix_status"] = cve_31431.get("classification") or "unknown"
vendor_status_directly_observed = bool(
    cve_31431.get("vendor_status_directly_observed") and cve_31465.get("vendor_status_directly_observed")
)

service_inventory = {}
service_errors = {}
for service_name in ("nomad", "vault", "es", "ags", "ars", "egs", "docker", "spire-server", "spire-agent"):
    if service_name == "nomad":
        service_payload, service_error = nomad_service, nomad_service_error
    elif service_name == "vault":
        service_payload, service_error = vault_service, vault_service_error
    else:
        service_payload, service_error = service_show(service_name)
    if service_payload is None:
        service_inventory[service_name] = {"observed": False, "error": service_error}
        if service_error:
            service_errors[service_name] = service_error
    else:
        service_inventory[service_name] = dict(service_payload)
        service_inventory[service_name]["observed"] = True

runtime_chain_observation = "unknown"
if docker_inventory.get("info_observed") and nomad_inventory.get("node_api_observed"):
    runtime_chain_observation = "observed"
elif docker_inventory.get("info_observed") or nomad_inventory.get("node_api_observed"):
    runtime_chain_observation = "partial"

runtime_inventory = {
    "classification": "runtime_inventory_evidence_only",
    "uname": command_text(uname_proc),
    "os_release": os_release,
    "packages": package_inventory,
    "services": service_inventory,
}

cve_readiness = {
    "classification": "cve_runtime_inventory_evidence_only",
    "vendor_status_directly_observed": vendor_status_directly_observed,
    "cve_2026_31431": cve_31431,
    "cve_2026_31465": cve_31465,
    "algif_aead": algif_aead_status,
    "not_patch_authority": True,
    "not_kernel_patch": True,
    "not_production_safety_proof": True,
}

runtime_chain = {
    "classification": "runtime_chain_evidence_only",
    "docker_nomad_runtime_storage_chain": runtime_chain_observation,
    "docker": docker_inventory,
    "nomad": nomad_inventory,
    "fuse_fuse_overlayfs_in_actual_path": runtime_path_inventory["fuse_fuse_overlayfs_in_actual_path"],
    "podman_crun_in_actual_path": runtime_path_inventory["podman_crun_in_actual_path"],
    "idmapped_mount_setattr_in_actual_path": runtime_path_inventory["idmapped_mount_setattr_in_actual_path"],
    "runtime_path_inventory": runtime_path_inventory,
}

surfaces = {}
least_privilege_findings = []
accepted_compatibility_edges = []
blockers = []
not_evaluated = []


def add_surface(name, classification, severity, summary, **details):
    payload = {
        "classification": classification,
        "summary": summary,
    }
    payload.update(details)
    surfaces[name] = payload

    least_privilege_findings.append(
        {
            "surface": name,
            "classification": classification,
            "severity": severity,
            "summary": summary,
        }
    )
    if classification == "accepted_compatibility_edge":
        accepted_compatibility_edges.append({"surface": name, "summary": summary})
    if severity == "blocker":
        blockers.append({"surface": name, "summary": summary})
    if details.get("observation_status") == "not_evaluated":
        not_evaluated.append(
            {
                "surface": name,
                "summary": str(details.get("observation_reason") or "observation unavailable"),
            }
        )

def nomad_role_surface(role_name):
    roles_detected = list(nomad_role_context["roles_detected"])
    combined_single_node_service = bool(nomad_role_context["combined_single_node_service"])
    details = {
        "service_name": "nomad",
        "nomad_roles_detected": roles_detected,
        "role_evidence": nomad_role_context["role_evidence"],
    }

    if nomad_service is None:
        details.update(
            {
                "observation_status": "not_evaluated",
                "observation_reason": nomad_service_error or "systemctl show nomad was unavailable",
                "evaluation_source": "nomad_service_unavailable",
                "independently_evaluated": False,
            }
        )
        summary = (
            f"Nomad {role_name} least-privilege posture was not independently evaluated because the local nomad.service observation was unavailable."
        )
        return "not_evaluated", "blocker", summary, details

    details.update(nomad_service)

    if role_name not in roles_detected:
        details.update(
            {
                "observation_status": "not_evaluated",
                "observation_reason": (
                    f"one combined nomad.service observation did not prove a distinct local {role_name} role"
                ),
                "evaluation_source": "combined_nomad_systemd_unit",
                "independently_evaluated": False,
            }
        )
        summary = (
            f"Nomad {role_name} least-privilege posture was not independently evaluated: one combined nomad.service observation did not prove a separate local {role_name} privilege surface."
        )
        return "not_evaluated", "blocker", summary, details

    if combined_single_node_service:
        details.update(
            {
                "observation_status": "observed",
                "evaluation_source": "combined_nomad_systemd_unit",
                "independently_evaluated": False,
                "combined_single_node_service": True,
            }
        )
        summary = (
            f"Nomad {role_name} least-privilege closeout remains blocked: current local evidence shows a combined single-node nomad.service carrying both server and client roles, so the {role_name} privilege surface was not independently evaluated."
        )
        return "blocker", "blocker", summary, details

    details.update(
        {
            "observation_status": "observed",
            "evaluation_source": "local_nomad_role_evidence",
            "independently_evaluated": True,
            "combined_single_node_service": False,
        }
    )
    summary = (
        f"Nomad {role_name} least-privilege closeout remains blocked on the current Remote Alpha substrate."
    )
    return "blocker", "blocker", summary, details


nomad_server_classification, nomad_server_severity, nomad_server_summary, nomad_server_details = nomad_role_surface(
    "server"
)
add_surface(
    "nomad_server_privilege_posture",
    nomad_server_classification,
    nomad_server_severity,
    nomad_server_summary,
    **nomad_server_details,
)

nomad_client_classification, nomad_client_severity, nomad_client_summary, nomad_client_details = nomad_role_surface(
    "client"
)
add_surface(
    "nomad_client_privilege_posture",
    nomad_client_classification,
    nomad_client_severity,
    nomad_client_summary,
    **nomad_client_details,
)

add_surface(
    "nomad_client_root_dependency",
    "accepted_mvp_substrate_dependency",
    "info",
    "The current Nomad client root posture remains an accepted MVP substrate dependency; this checker does not treat the client as de-rooted.",
    accepted_mvp_substrate_dependency=True,
    de_rooted=False,
    nomad_roles_detected=nomad_role_context["roles_detected"],
    evaluation_source=str(nomad_client_details.get("evaluation_source") or ""),
    independently_evaluated=bool(nomad_client_details.get("independently_evaluated", False)),
)

add_surface(
    "nomad_task_user_posture",
    "accepted_compatibility_edge",
    "warning",
    "Nomad task launch still uses the documented compatibility-edge user boundary.",
    task_user="0:0",
    workload_user="10000:10000",
    de_rooted=False,
)

runtime_helper_details = {
    "root_start": True,
    "runtime_support_binary_path": runtime_support_binary,
    "observation_status": "observed",
}
if not runtime_support_binary:
    runtime_helper_details["observation_status"] = "not_evaluated"
    runtime_helper_details["observation_reason"] = config_error or "execution.runtime_support_binary was not available"
add_surface(
    "runtime_helper_root_start_posture",
    "accepted_compatibility_edge",
    "warning",
    "The ES runtime helper/supervisor still starts from root as a documented compatibility edge.",
    **runtime_helper_details,
)

spire_traversal_details = {
    "helper_private": True,
    "raw_socket_visible_to_workloads": False,
    "workload_endpoint_env": "EXEC_WORKLOAD_IDENTITY_ENDPOINT",
    "configured_host_socket_path": spire_socket.get("path") or "",
    "host_socket_exists": bool(spire_socket.get("exists")),
    "host_socket_is_unix_socket": bool(spire_socket.get("is_socket")),
    "observation_status": "observed",
}
if not spire_socket_path:
    spire_traversal_details["observation_status"] = "not_evaluated"
    spire_traversal_details["observation_reason"] = config_error or "execution.spire_workload_api_socket_path was not available"
add_surface(
    "spire_helper_private_socket_traversal",
    "accepted_compatibility_edge",
    "warning",
    "Raw SPIRE traversal remains helper-private; workloads must not receive direct raw-socket access.",
    **spire_traversal_details,
)

broad_root_details = {
    "alpha_only": True,
    "selectors": ["unix:gid:0", "unix:uid:0"],
    "observation_status": "observed",
}
if selector_info is None:
    broad_root_details["observation_status"] = "not_evaluated"
    broad_root_details["observation_reason"] = selector_error
else:
    broad_root_details.update(selector_info)
add_surface(
    "broad_root_selector_posture",
    "accepted_compatibility_edge",
    "warning",
    "The current broad root selector posture remains an Alpha-only compatibility edge.",
    **broad_root_details,
)

add_surface(
    "workload_visible_identity_endpoint_contract",
    "current_invariant",
    "info",
    "Workloads must discover identity through the workload-visible endpoint contract, not a raw SPIRE socket.",
    endpoint_env_var="EXEC_WORKLOAD_IDENTITY_ENDPOINT",
    raw_spire_socket_exposed_to_workloads=False,
)

vault_service_details = {
    "service_name": "vault",
    "observation_status": "observed",
}
vault_service_severity = "info"
vault_service_summary = (
    "Vault service posture is operator-owned; this checker records the observed service account without certifying remote Vault lifecycle readiness."
)
if vault_service is None:
    vault_service_details["observation_status"] = "not_evaluated"
    vault_service_details["observation_reason"] = vault_service_error
else:
    vault_service_details.update(vault_service)
    if vault_service.get("root_managed"):
        vault_service_severity = "warning"
        vault_service_summary = (
            "Vault service posture remained root-managed when observed; this is operator-owned least-privilege debt and not a remote Vault lifecycle certification."
        )
add_surface(
    "vault_service_account_posture",
    "operator_owned_posture",
    vault_service_severity,
    vault_service_summary,
    **vault_service_details,
)

add_surface(
    "vault_secret_leakage_checks",
    "current_invariant",
    "info",
    "Checker output is validated to avoid persisting JWT, Vault-token, key, Codex-credential, or raw-secret material.",
    jwt_svid_material_persisted=False,
    vault_token_persisted=False,
    root_token_persisted=False,
    unseal_key_persisted=False,
    pem_private_key_persisted=False,
    api_key_persisted=False,
    codex_credentials_persisted=False,
    raw_secret_payload_persisted=False,
)

workload_zone_details = {
    "workload_side_auth": True,
    "es_brokers_vault_tokens": False,
    "workload_zone_config_path": os.fspath(WORKLOAD_ZONE_CONFIG_PATH),
    "vault_address": str(vault_config.get("address") or "").strip(),
    "auth_mount": str(vault_config.get("auth_mount") or "").strip(),
    "auth_role": str(vault_config.get("auth_role") or "").strip(),
    "jwt_audience": str(vault_config.get("jwt_audience") or "").strip(),
    "observation_status": "observed",
}
if not vault_config:
    workload_zone_details["observation_status"] = "not_evaluated"
    workload_zone_details["observation_reason"] = workload_zone_error or "vault_config was not available"
add_surface(
    "workload_zone_handoff_posture",
    "accepted_compatibility_edge",
    "warning",
    "Workload-side Vault auth remains a non-secret handoff boundary; ES stages metadata only and does not broker tokens.",
    **workload_zone_details,
)

add_surface(
    "es_vault_token_brokerage",
    "current_invariant",
    "info",
    "ES must not fetch, mint, broker, store, rotate, parse, or validate Vault tokens.",
    brokered_by_es=False,
)

add_surface(
    "host_runtime_inventory",
    "evidence_only",
    "info",
    "Host/runtime inventory is non-secret evidence only and does not prove service health or runtime readiness.",
    observation_status="observed" if runtime_inventory.get("uname") else "not_evaluated",
    os_release=runtime_inventory["os_release"],
    package_query_tool=package_inventory.get("query_tool", "unknown"),
    service_names=sorted(service_inventory.keys()),
)

is_linux_host = command_text(uname_proc).lower().startswith("linux")
cve_31431_classification = str(cve_31431.get("classification") or "unknown")
cve_31431_severity = "info"
cve_31431_surface_classification = "evidence_only"
cve_31431_summary = (
    "CVE-2026-31431 readiness is recorded from host-observed vendor evidence when available; unknown or vulnerable Linux target status is a Remote Alpha readiness blocker."
)
if is_linux_host and cve_31431_classification in {"vulnerable", "unknown"}:
    cve_31431_severity = "blocker"
    cve_31431_surface_classification = "blocker"
elif is_linux_host and cve_31431_classification == "mitigated_not_fixed":
    cve_31431_severity = "warning"
    cve_31431_summary = (
        "CVE-2026-31431 remains vendor/package vulnerable but algif_aead module-disable mitigation evidence was verified; "
        "this is not a kernel patch and not proof of production safety."
    )
    if not ACCEPT_CVE_31431_MITIGATION_RISK:
        cve_31431_severity = "blocker"
        cve_31431_surface_classification = "blocker"
        cve_31431_summary += " Explicit bounded internal Remote Alpha mitigation-risk acceptance is required before treating this as non-blocking."
add_surface(
    "cve_2026_31431_readiness",
    cve_31431_surface_classification,
    cve_31431_severity,
    cve_31431_summary,
    classification_value=cve_31431_classification,
    vendor_status_directly_observed=bool(cve_31431.get("vendor_status_directly_observed")),
    evidence_source=str(cve_31431.get("evidence_source") or "none"),
    vendor_package_classification=str(cve_31431.get("vendor_package_classification") or "unknown"),
    mitigation_kind=str(cve_31431.get("mitigation_kind") or ""),
    risk_acceptance_required_for_internal_alpha=bool(
        cve_31431.get("risk_acceptance_required_for_internal_alpha")
    ),
    risk_accepted_for_internal_alpha=bool(cve_31431.get("risk_accepted_for_internal_alpha")),
    not_kernel_patch=True,
    not_production_safety_proof=True,
    algif_aead=algif_aead_status,
)

cve_31465_classification = str(cve_31465.get("classification") or "unknown")
fuse_path_classification = runtime_chain["fuse_fuse_overlayfs_in_actual_path"]
cve_31465_severity = "info"
cve_31465_surface_classification = "evidence_only"
if cve_31465_classification in {"vulnerable", "unknown"} and fuse_path_classification == "yes":
    cve_31465_severity = "blocker"
    cve_31465_surface_classification = "blocker"
elif cve_31465_classification in {"vulnerable", "unknown"}:
    cve_31465_severity = "warning"
add_surface(
    "cve_2026_31465_readiness",
    cve_31465_surface_classification,
    cve_31465_severity,
    "CVE-2026-31465 readiness is recorded with FUSE/fuse-overlayfs path context; vulnerable or unknown status is a blocker when FUSE/fuse-overlayfs/rootless storage is in the actual path.",
    classification_value=cve_31465_classification,
    vendor_status_directly_observed=bool(cve_31465.get("vendor_status_directly_observed")),
    evidence_source=str(cve_31465.get("evidence_source") or "none"),
    fuse_fuse_overlayfs_in_actual_path=fuse_path_classification,
)

runtime_chain_severity = "info" if runtime_chain_observation == "observed" else "blocker"
runtime_chain_surface_classification = "evidence_only" if runtime_chain_observation == "observed" else "not_evaluated"
add_surface(
    "docker_nomad_runtime_storage_chain",
    runtime_chain_surface_classification,
    runtime_chain_severity,
    "Docker/Nomad runtime and storage-chain inventory is evidence only; it must be observed before a Remote Alpha CVE readiness proof is claimed.",
    observation_status="observed" if runtime_chain_observation == "observed" else "not_evaluated",
    observation_reason="" if runtime_chain_observation == "observed" else "Docker info and Nomad node detail were not both observed.",
    docker_nomad_runtime_storage_chain=runtime_chain_observation,
    docker_storage_driver=str(docker_inventory.get("storage_driver") or ""),
    docker_default_runtime=str(docker_inventory.get("default_runtime") or ""),
    docker_runtimes=docker_inventory.get("runtimes") or [],
    nomad_docker_driver_detected=bool((nomad_inventory.get("node") or {}).get("docker_driver_detected")),
    nomad_docker_driver_runtimes=str((nomad_inventory.get("node") or {}).get("docker_driver_runtimes") or ""),
    fuse_fuse_overlayfs_in_actual_path=runtime_chain["fuse_fuse_overlayfs_in_actual_path"],
    podman_crun_in_actual_path=runtime_chain["podman_crun_in_actual_path"],
    idmapped_mount_setattr_in_actual_path=runtime_chain["idmapped_mount_setattr_in_actual_path"],
)

add_surface(
    "support_evidence_non_authoritative",
    "current_invariant",
    "info",
    "Support and evidence artifacts remain non-authoritative diagnostics.",
    non_authoritative=True,
    labels=NON_AUTHORITY_LABELS,
)

try:
    effective_user = pwd.getpwuid(os.geteuid()).pw_name
except KeyError:
    effective_user = str(os.geteuid())

explicit_non_claims = list(EXPLICIT_NON_CLAIMS)
if "not_cve_patch_authority" not in explicit_non_claims:
    explicit_non_claims.append("not_cve_patch_authority")

summary = {
    "mode": "check_only",
    "non_mutating": True,
    "schema": SCHEMA,
    "generated_at": utc_now(),
    "host": {
        "hostname": socket.gethostname(),
        "effective_uid": os.geteuid(),
        "effective_user": effective_user,
        "config_path": os.fspath(CONFIG_PATH),
        "workload_zone_config_path": os.fspath(WORKLOAD_ZONE_CONFIG_PATH),
    },
    "runtime_inventory": runtime_inventory,
    "cve_readiness": cve_readiness,
    "runtime_chain": runtime_chain,
    "surfaces": surfaces,
    "accepted_compatibility_edges": accepted_compatibility_edges,
    "least_privilege_findings": least_privilege_findings,
    "blockers": blockers,
    "not_evaluated": not_evaluated,
    "redaction": {
        "jwt_svid_material_persisted": False,
        "vault_token_persisted": False,
        "root_token_persisted": False,
        "unseal_key_persisted": False,
        "pem_private_key_persisted": False,
        "api_key_persisted": False,
        "codex_credentials_persisted": False,
        "raw_secret_payload_persisted": False,
    },
    "non_authority_labels": NON_AUTHORITY_LABELS,
    "explicit_non_claims": explicit_non_claims,
}

SUMMARY_PATH.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

  remote_alpha_runtime_security_boundary_validate_summary_file "${summary_tmp_path}"

  if [[ -n "${REMOTE_ALPHA_RUNTIME_SECURITY_BOUNDARY_SUMMARY_PATH}" ]]; then
    mkdir -p "$(dirname "${REMOTE_ALPHA_RUNTIME_SECURITY_BOUNDARY_SUMMARY_PATH}")"
    install -m 0644 "${summary_tmp_path}" "${REMOTE_ALPHA_RUNTIME_SECURITY_BOUNDARY_SUMMARY_PATH}"
  fi

  cat "${summary_tmp_path}"

  python3 -I - "${summary_tmp_path}" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
blockers = payload.get("blockers") or []
not_evaluated = payload.get("not_evaluated") or []
sys.exit(1 if blockers or not_evaluated else 0)
PY
}
