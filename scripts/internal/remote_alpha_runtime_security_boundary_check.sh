#!/usr/bin/env bash
set -euo pipefail

remote_alpha_runtime_security_boundary_schema="execution-substrate.remote-alpha.runtime-security-boundary-check.v1"
remote_alpha_runtime_security_boundary_default_config_path="/etc/execution-substrate/es.json"
remote_alpha_runtime_security_boundary_default_workload_zone_config_path="/etc/execution-substrate/vault/workload-zone-vault-config.json"

remote_alpha_runtime_security_boundary_defaults() {
  REMOTE_ALPHA_RUNTIME_SECURITY_BOUNDARY_CONFIG_PATH="${REMOTE_ALPHA_RUNTIME_SECURITY_BOUNDARY_CONFIG_PATH:-${remote_alpha_runtime_security_boundary_default_config_path}}"
  REMOTE_ALPHA_RUNTIME_SECURITY_BOUNDARY_WORKLOAD_ZONE_CONFIG_PATH="${REMOTE_ALPHA_RUNTIME_SECURITY_BOUNDARY_WORKLOAD_ZONE_CONFIG_PATH:-${remote_alpha_runtime_security_boundary_default_workload_zone_config_path}}"
  REMOTE_ALPHA_RUNTIME_SECURITY_BOUNDARY_SUMMARY_PATH="${REMOTE_ALPHA_RUNTIME_SECURITY_BOUNDARY_SUMMARY_PATH:-}"
}

remote_alpha_runtime_security_boundary_usage() {
  cat <<'EOF'
Usage:
  scripts/remote_alpha_runtime_security_boundary_check.sh

Optional flags:
  --config-path </path/to/es.json>
  --workload-zone-config-path </path/to/workload-zone-vault-config.json>
  --summary-path <runtime-security-boundary-check.json>
  --help

Default behavior is check-only, non-mutating, and writes JSON to stdout.
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

  python3 - "${summary_path}" <<'PY'
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

  python3 - \
    "${remote_alpha_runtime_security_boundary_schema}" \
    "${REMOTE_ALPHA_RUNTIME_SECURITY_BOUNDARY_CONFIG_PATH}" \
    "${REMOTE_ALPHA_RUNTIME_SECURITY_BOUNDARY_WORKLOAD_ZONE_CONFIG_PATH}" \
    "${summary_tmp_path}" <<'PY'
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
    "not_full_es_runtime_deroot",
    "not_rootless_nomad_client",
    "not_governed_execution_proof",
    "not_vault_production_ready",
    "not_workload_credential_success_proof",
    "not_support_bundle_authority",
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
        return subprocess.run(args, check=False, capture_output=True, text=True)
    except FileNotFoundError:
        return None


def service_show(service_name):
    proc = run_command(
        ["systemctl", "show", service_name, "--property=User,Group,FragmentPath,ExecStart", "--no-pager"]
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
    "explicit_non_claims": EXPLICIT_NON_CLAIMS,
}

SUMMARY_PATH.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

  remote_alpha_runtime_security_boundary_validate_summary_file "${summary_tmp_path}"

  if [[ -n "${REMOTE_ALPHA_RUNTIME_SECURITY_BOUNDARY_SUMMARY_PATH}" ]]; then
    mkdir -p "$(dirname "${REMOTE_ALPHA_RUNTIME_SECURITY_BOUNDARY_SUMMARY_PATH}")"
    install -m 0644 "${summary_tmp_path}" "${REMOTE_ALPHA_RUNTIME_SECURITY_BOUNDARY_SUMMARY_PATH}"
  fi

  cat "${summary_tmp_path}"

  python3 - "${summary_tmp_path}" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
blockers = payload.get("blockers") or []
not_evaluated = payload.get("not_evaluated") or []
sys.exit(1 if blockers or not_evaluated else 0)
PY
}
