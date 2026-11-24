#!/usr/bin/env bash
set -euo pipefail
set +x

remote_alpha_es_service_tls_renew_schema_version="execution-substrate.remote-alpha.es-service-tls-renew-summary.v1"
remote_alpha_es_governance_tls_renew_schema_version="execution-substrate.remote-alpha.es-governance-tls-renew-summary.v1"
remote_alpha_es_service_tls_renew_backup_root_default="/var/tmp/execution-substrate-remote-alpha"
remote_alpha_es_service_tls_renew_summary_path_default="/var/tmp/execution-substrate-remote-alpha/es-service-tls-renew-summary.json"
remote_alpha_es_governance_tls_renew_summary_path_default="/var/tmp/execution-substrate-remote-alpha/es-governance-tls-renew-summary.json"

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

remote_alpha_es_service_tls_renew_init_expected_inputs() {
  remote_alpha_es_service_tls_renew_expected_ars_config_path="${remote_alpha_es_service_tls_renew_expected_ars_config_path:-/etc/execution-substrate/ars.json}"
  remote_alpha_es_service_tls_renew_expected_ags_config_path="${remote_alpha_es_service_tls_renew_expected_ags_config_path:-/etc/execution-substrate/ags.json}"
  remote_alpha_es_service_tls_renew_expected_es_config_path="${remote_alpha_es_service_tls_renew_expected_es_config_path:-/etc/execution-substrate/es.json}"
  remote_alpha_es_service_tls_renew_expected_egs_config_path="${remote_alpha_es_service_tls_renew_expected_egs_config_path:-/etc/execution-substrate/egs.json}"
  remote_alpha_es_service_tls_renew_expected_ars_tls_dir="${remote_alpha_es_service_tls_renew_expected_ars_tls_dir:-/etc/execution-substrate/ars-tls}"
  remote_alpha_es_service_tls_renew_expected_ags_tls_dir="${remote_alpha_es_service_tls_renew_expected_ags_tls_dir:-/etc/execution-substrate/tls}"
  remote_alpha_es_service_tls_renew_expected_es_tls_dir="${remote_alpha_es_service_tls_renew_expected_es_tls_dir:-/etc/execution-substrate/es-tls}"
  remote_alpha_es_service_tls_renew_expected_egs_tls_dir="${remote_alpha_es_service_tls_renew_expected_egs_tls_dir:-/etc/execution-substrate/egs-tls}"
}

remote_alpha_es_service_tls_renew_defaults() {
  remote_alpha_es_service_tls_renew_init_expected_inputs
  REMOTE_ALPHA_TLS_SCOPE="artifact-registry"
  REMOTE_ALPHA_OPERATION_MODE="status"
  REMOTE_ALPHA_SUMMARY_PATH_EXPLICIT="false"
  REMOTE_ALPHA_SUMMARY_PATH="${REMOTE_ALPHA_SUMMARY_PATH:-${remote_alpha_es_service_tls_renew_summary_path_default}}"
  REMOTE_ALPHA_BACKUP_ROOT="${REMOTE_ALPHA_TEST_BACKUP_ROOT:-${remote_alpha_es_service_tls_renew_backup_root_default}}"
  REMOTE_ALPHA_CERT_DAYS="${REMOTE_ALPHA_TEST_CERT_DAYS:-90}"
  REMOTE_ALPHA_ARS_CONFIG_PATH="${remote_alpha_es_service_tls_renew_expected_ars_config_path}"
  REMOTE_ALPHA_AGS_CONFIG_PATH="${remote_alpha_es_service_tls_renew_expected_ags_config_path}"
  REMOTE_ALPHA_ES_CONFIG_PATH="${remote_alpha_es_service_tls_renew_expected_es_config_path}"
  REMOTE_ALPHA_EGS_CONFIG_PATH="${remote_alpha_es_service_tls_renew_expected_egs_config_path}"
  REMOTE_ALPHA_ARS_TLS_DIR="${remote_alpha_es_service_tls_renew_expected_ars_tls_dir}"
  REMOTE_ALPHA_AGS_TLS_DIR="${remote_alpha_es_service_tls_renew_expected_ags_tls_dir}"
  REMOTE_ALPHA_ES_TLS_DIR="${remote_alpha_es_service_tls_renew_expected_es_tls_dir}"
  REMOTE_ALPHA_EGS_TLS_DIR="${remote_alpha_es_service_tls_renew_expected_egs_tls_dir}"
  REMOTE_ALPHA_ARS_CA_PATH="${REMOTE_ALPHA_ARS_TLS_DIR}/runtime-ca.pem"
  REMOTE_ALPHA_ARS_SERVER_CERT_PATH="${REMOTE_ALPHA_ARS_TLS_DIR}/ars-server-cert.pem"
  REMOTE_ALPHA_ARS_SERVER_KEY_PATH="${REMOTE_ALPHA_ARS_TLS_DIR}/ars-server-key.pem"
  REMOTE_ALPHA_AGS_CLIENT_CERT_PATH="${REMOTE_ALPHA_AGS_TLS_DIR}/ags-client-cert.pem"
  REMOTE_ALPHA_AGS_CLIENT_KEY_PATH="${REMOTE_ALPHA_AGS_TLS_DIR}/ags-client-key.pem"
  REMOTE_ALPHA_AGS_ROOT_CA_PATH="${REMOTE_ALPHA_AGS_TLS_DIR}/runtime-ca.pem"
  REMOTE_ALPHA_ES_CLIENT_CERT_PATH="${REMOTE_ALPHA_ES_TLS_DIR}/artifact-registry-client-cert.pem"
  REMOTE_ALPHA_ES_CLIENT_KEY_PATH="${REMOTE_ALPHA_ES_TLS_DIR}/artifact-registry-client-key.pem"
  REMOTE_ALPHA_ES_ROOT_CA_PATH="${REMOTE_ALPHA_ES_TLS_DIR}/artifact-registry-root-ca.pem"
  REMOTE_ALPHA_EGS_CA_PATH="${REMOTE_ALPHA_EGS_TLS_DIR}/runtime-ca.pem"
  REMOTE_ALPHA_EGS_SERVER_CERT_PATH="${REMOTE_ALPHA_EGS_TLS_DIR}/egs-server-cert.pem"
  REMOTE_ALPHA_EGS_SERVER_KEY_PATH="${REMOTE_ALPHA_EGS_TLS_DIR}/egs-server-key.pem"
  REMOTE_ALPHA_ES_GOVERNANCE_CLIENT_CERT_PATH="${REMOTE_ALPHA_ES_TLS_DIR}/execution-governance-client-cert.pem"
  REMOTE_ALPHA_ES_GOVERNANCE_CLIENT_KEY_PATH="${REMOTE_ALPHA_ES_TLS_DIR}/execution-governance-client-key.pem"
  REMOTE_ALPHA_ES_GOVERNANCE_ROOT_CA_PATH="${REMOTE_ALPHA_ES_TLS_DIR}/execution-governance-root-ca.pem"
}

remote_alpha_es_service_tls_renew_usage() {
  cat <<'EOF'
Usage:
  sudo scripts/remote_alpha_es_service_tls_renew.sh --status
  sudo scripts/remote_alpha_es_service_tls_renew.sh --execute-renew
  sudo scripts/remote_alpha_es_service_tls_renew.sh --scope execution-governance --status
  sudo scripts/remote_alpha_es_service_tls_renew.sh --scope execution-governance --execute-renew

Optional flags:
  --scope artifact-registry|execution-governance
  --status
  --check-only
  --execute-renew
  --summary-path </path/to/tls-renew-summary.json>
  --help

Status/check-only is non-mutating. Renew requires --execute-renew.
Default scope is artifact-registry. execution-governance is bounded to ES -> EGS trust-model mTLS.
EOF
}

remote_alpha_es_service_tls_renew_reject_secret_arg() {
  local arg=$1
  case "${arg}" in
    *root-token*|*unseal-key*|*client-token*|*vault-token*|*api-key*|*jwt-svid*|*private-key*|*password*|*secret*)
      echo "remote alpha ES service TLS renewal does not accept secret-like CLI arguments" >&2
      return 2
      ;;
  esac
}

remote_alpha_es_service_tls_renew_parse_args() {
  while [[ $# -gt 0 ]]; do
    remote_alpha_es_service_tls_renew_reject_secret_arg "$1" || return $?
    case "$1" in
      --scope)
        if [[ $# -lt 2 || -z "${2:-}" || "${2:-}" == --* ]]; then
          echo "--scope requires a value" >&2
          return 2
        fi
        case "$2" in
          artifact-registry|execution-governance)
            REMOTE_ALPHA_TLS_SCOPE="$2"
            ;;
          *)
            echo "unsupported --scope: $2" >&2
            return 2
            ;;
        esac
        shift 2
        ;;
      --status|--check-only)
        REMOTE_ALPHA_OPERATION_MODE="status"
        shift
        ;;
      --execute-renew)
        REMOTE_ALPHA_OPERATION_MODE="execute_renew"
        shift
        ;;
      --summary-path)
        if [[ $# -lt 2 || -z "${2:-}" || "${2:-}" == --* ]]; then
          echo "--summary-path requires a value" >&2
          return 2
        fi
        REMOTE_ALPHA_SUMMARY_PATH="$2"
        REMOTE_ALPHA_SUMMARY_PATH_EXPLICIT="true"
        shift 2
        ;;
      --help|-h)
        remote_alpha_es_service_tls_renew_usage
        REMOTE_ALPHA_OPERATION_MODE="help"
        shift
        ;;
      --apply|--dry-run|--interactive-sudo|--reset|--unseal-only|--post-unseal-check|--workload-auth-check|--runtime-identity-summary|--im-refresh|--support-bundle|--cp-proof)
        echo "remote alpha ES service TLS renewal forbids $1; this helper is bounded to ARS/AGS/ES internal TLS status or renewal only" >&2
        return 2
        ;;
      --*=*)
        echo "remote alpha ES service TLS renewal does not accept equals-form options: $1" >&2
        return 2
        ;;
      --*)
        echo "unknown argument: $1" >&2
        remote_alpha_es_service_tls_renew_usage >&2
        return 2
        ;;
      *)
        echo "unexpected positional argument: $1" >&2
        return 2
        ;;
    esac
  done
}

remote_alpha_es_service_tls_renew_apply_scope_defaults() {
  case "${REMOTE_ALPHA_TLS_SCOPE}" in
    artifact-registry)
      remote_alpha_es_service_tls_renew_current_schema_version="${remote_alpha_es_service_tls_renew_schema_version}"
      if [[ "${REMOTE_ALPHA_SUMMARY_PATH_EXPLICIT}" != "true" ]]; then
        REMOTE_ALPHA_SUMMARY_PATH="${remote_alpha_es_service_tls_renew_summary_path_default}"
      fi
      ;;
    execution-governance)
      remote_alpha_es_service_tls_renew_current_schema_version="${remote_alpha_es_governance_tls_renew_schema_version}"
      if [[ "${REMOTE_ALPHA_SUMMARY_PATH_EXPLICIT}" != "true" ]]; then
        REMOTE_ALPHA_SUMMARY_PATH="${remote_alpha_es_governance_tls_renew_summary_path_default}"
      fi
      ;;
    *)
      echo "unsupported TLS renewal scope: ${REMOTE_ALPHA_TLS_SCOPE}" >&2
      return 2
      ;;
  esac
}

remote_alpha_es_service_tls_renew_require_root() {
  if [[ "$(id -u)" != "0" && -z "${REMOTE_ALPHA_TEST_ALLOW_NON_ROOT:-}" ]]; then
    echo "remote alpha ES service TLS renewal must run as root; use sudo scripts/remote_alpha_es_service_tls_renew.sh" >&2
    return 1
  fi
}

remote_alpha_es_service_tls_renew_require_command() {
  local name=$1
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "${name} is required" >&2
    return 1
  fi
}

remote_alpha_es_service_tls_renew_timestamp() {
  if [[ -n "${REMOTE_ALPHA_TEST_TIMESTAMP:-}" ]]; then
    printf '%s' "${REMOTE_ALPHA_TEST_TIMESTAMP}"
    return 0
  fi
  date -u +%Y%m%dT%H%M%SZ
}

remote_alpha_es_service_tls_renew_topology_json() {
  python3 - "$@" <<'PY'
import json
import pathlib
import sys
from urllib.parse import urlparse

(
    ars_config_path,
    ags_config_path,
    es_config_path,
    egs_config_path,
    ars_ca_path,
    ars_server_cert_path,
    ars_server_key_path,
    ags_client_cert_path,
    ags_client_key_path,
    ags_root_ca_path,
    es_client_cert_path,
    es_client_key_path,
    es_root_ca_path,
) = sys.argv[1:]

covered_paths = {
    ars_ca_path,
    ars_server_cert_path,
    ars_server_key_path,
    ags_client_cert_path,
    ags_client_key_path,
    ags_root_ca_path,
    es_client_cert_path,
    es_client_key_path,
    es_root_ca_path,
}


def read_json(path_text):
    path = pathlib.Path(path_text)
    try:
        return json.loads(path.read_text(encoding="utf-8")), ""
    except Exception as exc:  # noqa: BLE001
        return {}, f"read or parse {path}: {exc}"


def nested(payload, *keys):
    current = payload
    for key in keys:
        if not isinstance(current, dict):
            return ""
        current = current.get(key)
    if current is None:
        return ""
    return str(current).strip()


def check_eq(items, label, actual, expected, blockers):
    ok = actual == expected
    items.append({"field": label, "actual": actual, "expected": expected, "status": "pass" if ok else "fail"})
    if not ok:
        blockers.append(f"{label} expected {expected}, got {actual}")


def is_loopback_ars_url(value):
    try:
        parsed = urlparse(value)
    except Exception:
        return False
    return parsed.scheme == "https" and parsed.hostname in {"127.0.0.1", "localhost"} and parsed.port == 8442


payloads = {}
errors = []
for label, path in (("ars", ars_config_path), ("ags", ags_config_path), ("es", es_config_path), ("egs", egs_config_path)):
    payload, error = read_json(path)
    payloads[label] = payload
    if error and label != "egs":
        errors.append(error)

blockers = list(errors)
items = []

ars = payloads["ars"]
ags = payloads["ags"]
es = payloads["es"]
egs = payloads["egs"]

check_eq(items, "ars.tls.client_ca_file", nested(ars, "tls", "client_ca_file"), ars_ca_path, blockers)
check_eq(items, "ars.tls.cert_file", nested(ars, "tls", "cert_file"), ars_server_cert_path, blockers)
check_eq(items, "ars.tls.key_file", nested(ars, "tls", "key_file"), ars_server_key_path, blockers)

ags_ars_url = nested(ags, "dependencies", "artifact_registry", "base_url")
items.append({
    "field": "ags.dependencies.artifact_registry.base_url",
    "actual": ags_ars_url,
    "expected": "https://127.0.0.1:8442 or https://localhost:8442",
    "status": "pass" if is_loopback_ars_url(ags_ars_url) else "fail",
})
if not is_loopback_ars_url(ags_ars_url):
    blockers.append(f"ags.dependencies.artifact_registry.base_url is outside the bounded loopback ARS route: {ags_ars_url}")
check_eq(items, "ags.dependencies.artifact_registry.client_cert_file", nested(ags, "dependencies", "artifact_registry", "client_cert_file"), ags_client_cert_path, blockers)
check_eq(items, "ags.dependencies.artifact_registry.client_key_file", nested(ags, "dependencies", "artifact_registry", "client_key_file"), ags_client_key_path, blockers)
check_eq(items, "ags.dependencies.artifact_registry.root_ca_file", nested(ags, "dependencies", "artifact_registry", "root_ca_file"), ags_root_ca_path, blockers)

es_ars_url = nested(es, "dependencies", "artifact_registry", "base_url")
items.append({
    "field": "es.dependencies.artifact_registry.base_url",
    "actual": es_ars_url,
    "expected": "https://127.0.0.1:8442 or https://localhost:8442",
    "status": "pass" if is_loopback_ars_url(es_ars_url) else "fail",
})
if not is_loopback_ars_url(es_ars_url):
    blockers.append(f"es.dependencies.artifact_registry.base_url is outside the bounded loopback ARS route: {es_ars_url}")
check_eq(items, "es.dependencies.artifact_registry.client_cert_file", nested(es, "dependencies", "artifact_registry", "client_cert_file"), es_client_cert_path, blockers)
check_eq(items, "es.dependencies.artifact_registry.client_key_file", nested(es, "dependencies", "artifact_registry", "client_key_file"), es_client_key_path, blockers)
check_eq(items, "es.dependencies.artifact_registry.root_ca_file", nested(es, "dependencies", "artifact_registry", "root_ca_file"), es_root_ca_path, blockers)

related = []
for service, payload in (("ags", ags), ("es", es), ("egs", egs)):
    for field in ("cert_file", "key_file", "client_ca_file"):
        value = nested(payload, "tls", field)
        if value:
            related.append({"field": f"{service}.tls.{field}", "path": value, "covered_by_renewal": value in covered_paths})
            if value in covered_paths:
                blockers.append(f"{service}.tls.{field} uses a path covered by ARS dependency renewal: {value}")

print(json.dumps({
    "status": "pass" if not blockers else "fail",
    "blockers": blockers,
    "config_paths": {
        "ars": ars_config_path,
        "ags": ags_config_path,
        "es": es_config_path,
        "egs": egs_config_path,
    },
    "checks": items,
    "related_service_tls": related,
    "covered_paths": sorted(covered_paths),
    "bounded_topology": {
        "name": "remote-alpha-internal-ars-artifact-registry-mtls",
        "ars_dependency_base_urls": [ags_ars_url, es_ars_url],
        "server_name": "server.artifact-registry.internal",
        "services_affected": ["ars.service", "ags.service", "es.service"],
        "services_intentionally_not_restarted": ["egs.service", "vault.service", "spire-agent.service", "spire-server.service", "nomad.service"],
    },
}, sort_keys=True))
PY
}

remote_alpha_es_governance_tls_renew_topology_json() {
  python3 - "$@" <<'PY'
import json
import pathlib
import sys
from urllib.parse import urlparse

(
    ars_config_path,
    ags_config_path,
    es_config_path,
    egs_config_path,
    egs_ca_path,
    egs_server_cert_path,
    egs_server_key_path,
    es_client_cert_path,
    es_client_key_path,
    es_root_ca_path,
) = sys.argv[1:]

covered_paths = {
    egs_ca_path,
    egs_server_cert_path,
    egs_server_key_path,
    es_client_cert_path,
    es_client_key_path,
    es_root_ca_path,
}


def read_json(path_text, required=True):
    path = pathlib.Path(path_text)
    try:
        return json.loads(path.read_text(encoding="utf-8")), ""
    except Exception as exc:  # noqa: BLE001
        if required:
            return {}, f"read or parse {path}: {exc}"
        return {}, ""


def nested(payload, *keys):
    current = payload
    for key in keys:
        if not isinstance(current, dict):
            return ""
        current = current.get(key)
    if current is None:
        return ""
    return str(current).strip()


def check_eq(items, label, actual, expected, blockers):
    ok = actual == expected
    items.append({"field": label, "actual": actual, "expected": expected, "status": "pass" if ok else "fail"})
    if not ok:
        blockers.append(f"{label} expected {expected}, got {actual}")


def is_loopback_egs_url(value):
    try:
        parsed = urlparse(value)
    except Exception:
        return False
    return parsed.scheme == "https" and parsed.hostname in {"127.0.0.1", "localhost"} and parsed.port == 8443


payloads = {}
errors = []
for label, path in (("ars", ars_config_path), ("ags", ags_config_path), ("es", es_config_path), ("egs", egs_config_path)):
    payload, error = read_json(path, required=label in {"ags", "es", "egs"})
    payloads[label] = payload
    if error:
        errors.append(error)

blockers = list(errors)
items = []

ars = payloads["ars"]
ags = payloads["ags"]
es = payloads["es"]
egs = payloads["egs"]

check_eq(items, "egs.tls.cert_file", nested(egs, "tls", "cert_file"), egs_server_cert_path, blockers)
check_eq(items, "egs.tls.key_file", nested(egs, "tls", "key_file"), egs_server_key_path, blockers)
check_eq(items, "egs.tls.client_ca_file", nested(egs, "tls", "client_ca_file"), egs_ca_path, blockers)

es_egs_url = nested(es, "dependencies", "execution_governance", "base_url")
items.append({
    "field": "es.dependencies.execution_governance.base_url",
    "actual": es_egs_url,
    "expected": "https://127.0.0.1:8443 or https://localhost:8443",
    "status": "pass" if is_loopback_egs_url(es_egs_url) else "fail",
})
if not is_loopback_egs_url(es_egs_url):
    blockers.append(f"es.dependencies.execution_governance.base_url is outside the bounded loopback EGS route: {es_egs_url}")
check_eq(items, "es.dependencies.execution_governance.client_cert_file", nested(es, "dependencies", "execution_governance", "client_cert_file"), es_client_cert_path, blockers)
check_eq(items, "es.dependencies.execution_governance.client_key_file", nested(es, "dependencies", "execution_governance", "client_key_file"), es_client_key_path, blockers)
check_eq(items, "es.dependencies.execution_governance.root_ca_file", nested(es, "dependencies", "execution_governance", "root_ca_file"), es_root_ca_path, blockers)
check_eq(items, "es.dependencies.execution_governance.server_name", nested(es, "dependencies", "execution_governance", "server_name"), "server.execution-governance.internal", blockers)

ags_dependencies = ags.get("dependencies") if isinstance(ags, dict) else None
ags_client_to_egs_material = "out_of_scope_absent"
if isinstance(ags_dependencies, dict) and "execution_governance" in ags_dependencies:
    ags_client_to_egs_material = "out_of_scope_present"
    blockers.append("AGS execution_governance dependency material is out of scope for P0t")

related = []
for service, payload in (("ars", ars), ("ags", ags), ("es", es), ("egs", egs)):
    for field in ("cert_file", "key_file", "client_ca_file"):
        value = nested(payload, "tls", field)
        if value:
            related.append({"field": f"{service}.tls.{field}", "path": value, "covered_by_renewal": value in covered_paths})
            if service not in {"egs"} and value in covered_paths:
                blockers.append(f"{service}.tls.{field} uses a path covered by ES governance renewal: {value}")
    deps = payload.get("dependencies") if isinstance(payload, dict) else None
    if isinstance(deps, dict):
        for dep_name, dep in deps.items():
            if not isinstance(dep, dict):
                continue
            for field in ("client_cert_file", "client_key_file", "root_ca_file"):
                value = str(dep.get(field) or "").strip()
                if value:
                    related.append({"field": f"{service}.dependencies.{dep_name}.{field}", "path": value, "covered_by_renewal": value in covered_paths})
                    if not (service == "es" and dep_name == "execution_governance") and value in covered_paths:
                        blockers.append(f"{service}.dependencies.{dep_name}.{field} uses a path covered by ES governance renewal: {value}")

print(json.dumps({
    "status": "pass" if not blockers else "fail",
    "blockers": blockers,
    "config_paths": {
        "ars": ars_config_path,
        "ags": ags_config_path,
        "es": es_config_path,
        "egs": egs_config_path,
    },
    "checks": items,
    "related_service_tls": related,
    "covered_paths": sorted(covered_paths),
    "bounded_topology": {
        "name": "remote-alpha-internal-es-to-egs-execution-governance-mtls",
        "egs_dependency_base_urls": [es_egs_url],
        "server_name": "server.execution-governance.internal",
        "egs_client_ca_same_runtime_ca_file": nested(egs, "tls", "client_ca_file") == egs_ca_path,
        "es_root_ca_is_execution_governance_copy": nested(es, "dependencies", "execution_governance", "root_ca_file") == es_root_ca_path,
        "ags_client_to_egs_material": ags_client_to_egs_material,
        "services_affected": ["egs.service", "es.service"],
        "services_intentionally_not_restarted": ["ars.service", "ags.service", "vault.service", "spire-agent.service", "spire-server.service", "nomad.service"],
    },
}, sort_keys=True))
PY
}

remote_alpha_es_service_tls_renew_collect_status() {
  local mode=$1
  local summary_path=$2
  local topology_path=$3
  local backup_meta_path=${4:-}
  local restart_meta_path=${5:-}
  local curl_meta_path=${6:-}

  python3 - \
    "${mode}" \
    "${summary_path}" \
    "${topology_path}" \
    "${backup_meta_path}" \
    "${restart_meta_path}" \
    "${curl_meta_path}" \
    "${remote_alpha_es_service_tls_renew_current_schema_version}" \
    "${REMOTE_ALPHA_TLS_SCOPE}" \
    "${REMOTE_ALPHA_ARS_CA_PATH}" \
    "${REMOTE_ALPHA_ARS_SERVER_CERT_PATH}" \
    "${REMOTE_ALPHA_ARS_SERVER_KEY_PATH}" \
    "${REMOTE_ALPHA_AGS_CLIENT_CERT_PATH}" \
    "${REMOTE_ALPHA_AGS_CLIENT_KEY_PATH}" \
    "${REMOTE_ALPHA_AGS_ROOT_CA_PATH}" \
    "${REMOTE_ALPHA_ES_CLIENT_CERT_PATH}" \
    "${REMOTE_ALPHA_ES_CLIENT_KEY_PATH}" \
    "${REMOTE_ALPHA_ES_ROOT_CA_PATH}" \
    "${REMOTE_ALPHA_EGS_CA_PATH}" \
    "${REMOTE_ALPHA_EGS_SERVER_CERT_PATH}" \
    "${REMOTE_ALPHA_EGS_SERVER_KEY_PATH}" \
    "${REMOTE_ALPHA_ES_GOVERNANCE_CLIENT_CERT_PATH}" \
    "${REMOTE_ALPHA_ES_GOVERNANCE_CLIENT_KEY_PATH}" \
    "${REMOTE_ALPHA_ES_GOVERNANCE_ROOT_CA_PATH}" <<'PY'
import datetime as dt
import hashlib
import json
import pathlib
import re
import subprocess
import sys
from email.utils import parsedate_to_datetime

mode = sys.argv[1]
summary_path = pathlib.Path(sys.argv[2])
topology_path = pathlib.Path(sys.argv[3])
backup_meta_path = pathlib.Path(sys.argv[4]) if sys.argv[4] else None
restart_meta_path = pathlib.Path(sys.argv[5]) if sys.argv[5] else None
curl_meta_path = pathlib.Path(sys.argv[6]) if sys.argv[6] else None
schema_version = sys.argv[7]
scope = sys.argv[8]
(
    ars_ca_path,
    ars_server_cert_path,
    ars_server_key_path,
    ags_client_cert_path,
    ags_client_key_path,
    ags_root_ca_path,
    es_client_cert_path,
    es_client_key_path,
    es_root_ca_path,
    egs_ca_path,
    egs_server_cert_path,
    egs_server_key_path,
    es_governance_client_cert_path,
    es_governance_client_key_path,
    es_governance_root_ca_path,
) = sys.argv[9:]

if scope == "artifact-registry":
    certs = [
        ("ars_trusted_runtime_client_ca", ars_ca_path, "ca"),
        ("ars_server", ars_server_cert_path, "server"),
        ("ags_artifact_registry_client", ags_client_cert_path, "client"),
        ("ags_artifact_registry_root_ca", ags_root_ca_path, "ca"),
        ("es_artifact_registry_client", es_client_cert_path, "client"),
        ("es_artifact_registry_root_ca", es_root_ca_path, "ca"),
    ]
    key_pairs = [
        ("ars_server", ars_server_cert_path, ars_server_key_path),
        ("ags_artifact_registry_client", ags_client_cert_path, ags_client_key_path),
        ("es_artifact_registry_client", es_client_cert_path, es_client_key_path),
    ]
    verification_inputs = [
        ("ags_client_cert_against_ars_client_ca", ars_ca_path, ags_client_cert_path, "sslclient", ""),
        ("es_client_cert_against_ars_client_ca", ars_ca_path, es_client_cert_path, "sslclient", ""),
        ("ars_server_cert_against_ags_root_ca", ags_root_ca_path, ars_server_cert_path, "sslserver", "server.artifact-registry.internal"),
        ("ars_server_cert_against_es_root_ca", es_root_ca_path, ars_server_cert_path, "sslserver", "server.artifact-registry.internal"),
    ]
    slice_summary = {
        "name": "remote-alpha-es-service-tls-renewal",
        "classification": "bounded_remote_alpha_internal_service_tls_recovery",
        "bounded_topology": "ARS loopback artifact-registry mTLS used by AGS and ES",
        "not_a_deployment_system": True,
        "not_im_reconciliation": True,
        "not_cp_authority": True,
        "not_production_readiness": True,
    }
elif scope == "execution-governance":
    certs = [
        ("egs_trusted_runtime_client_ca", egs_ca_path, "ca"),
        ("egs_server", egs_server_cert_path, "server"),
        ("es_execution_governance_client", es_governance_client_cert_path, "client"),
        ("es_execution_governance_root_ca", es_governance_root_ca_path, "ca"),
    ]
    key_pairs = [
        ("egs_server", egs_server_cert_path, egs_server_key_path),
        ("es_execution_governance_client", es_governance_client_cert_path, es_governance_client_key_path),
    ]
    verification_inputs = [
        ("es_execution_governance_client_cert_against_egs_client_ca", egs_ca_path, es_governance_client_cert_path, "sslclient", ""),
        ("egs_server_cert_against_es_execution_governance_root_ca", es_governance_root_ca_path, egs_server_cert_path, "sslserver", "server.execution-governance.internal"),
    ]
    slice_summary = {
        "name": "remote-alpha-es-governance-tls-renewal",
        "classification": "bounded_remote_alpha_internal_es_to_egs_governance_tls_recovery",
        "bounded_topology": "EGS loopback execution-governance mTLS used by ES trust-model fetch",
        "not_a_deployment_system": True,
        "not_im_reconciliation": True,
        "not_cp_authority": True,
        "not_egs_trust_model_redesign": True,
        "not_production_readiness": True,
    }
else:
    print(f"unsupported scope: {scope}", file=sys.stderr)
    raise SystemExit(2)

secret_patterns = [
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"\b(?:hvs|hvb|s)\.[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
]


def run(args, input_bytes=None):
    return subprocess.run(args, input=input_bytes, check=False, capture_output=True)


def text_output(proc):
    return (proc.stdout + proc.stderr).decode("utf-8", errors="replace").strip()


def safe_error(value):
    value = value.replace("\n", " | ")
    return value[:500]


def parse_openssl_date(value):
    value = value.strip()
    if "=" in value:
        value = value.split("=", 1)[1].strip()
    try:
        parsed = parsedate_to_datetime(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.astimezone(dt.timezone.utc)
    except Exception:
        return None


def cert_pubkey_digest(cert_path):
    pub = run(["openssl", "x509", "-in", cert_path, "-pubkey", "-noout"])
    if pub.returncode != 0:
        return "", safe_error(text_output(pub))
    der = run(["openssl", "pkey", "-pubin", "-outform", "DER"], input_bytes=pub.stdout)
    if der.returncode != 0:
        return "", safe_error(text_output(der))
    return hashlib.sha256(der.stdout).hexdigest(), ""


def key_pubkey_digest(key_path):
    der = run(["openssl", "pkey", "-in", key_path, "-pubout", "-outform", "DER"])
    if der.returncode != 0:
        return "", safe_error(text_output(der))
    return hashlib.sha256(der.stdout).hexdigest(), ""


def cert_ext(cert_path, name):
    proc = run(["openssl", "x509", "-in", cert_path, "-noout", "-ext", name])
    if proc.returncode != 0:
        return ""
    lines = [line.strip() for line in proc.stdout.decode("utf-8", errors="replace").splitlines()]
    lines = [line for line in lines if line and not line.startswith("X509v3")]
    return " ".join(lines)


def cert_record(label, path_text, role):
    path = pathlib.Path(path_text)
    record = {
        "label": label,
        "path": path_text,
        "role": role,
        "exists": path.is_file(),
        "sha256": "",
        "subject": "",
        "issuer": "",
        "not_before": "",
        "not_after": "",
        "expired": None,
        "not_yet_valid": None,
        "fingerprint_sha256": "",
        "public_key_sha256": "",
        "subject_alt_name": "",
        "extended_key_usage": "",
        "status": "fail",
        "error": "",
    }
    if not path.is_file():
        record["error"] = "missing_cert_file"
        return record
    data = path.read_bytes()
    record["sha256"] = hashlib.sha256(data).hexdigest()
    for field, args in (
        ("subject", ["openssl", "x509", "-in", path_text, "-noout", "-subject"]),
        ("issuer", ["openssl", "x509", "-in", path_text, "-noout", "-issuer"]),
        ("fingerprint_sha256", ["openssl", "x509", "-in", path_text, "-noout", "-fingerprint", "-sha256"]),
    ):
        proc = run(args)
        if proc.returncode != 0:
            record["error"] = safe_error(text_output(proc))
            return record
        value = proc.stdout.decode("utf-8", errors="replace").strip()
        if field in {"subject", "issuer"} and "=" in value:
            value = value.split("=", 1)[1].strip()
        if field == "fingerprint_sha256" and "=" in value:
            value = value.split("=", 1)[1].replace(":", "").strip().lower()
        record[field] = value
    proc = run(["openssl", "x509", "-in", path_text, "-noout", "-dates"])
    if proc.returncode != 0:
        record["error"] = safe_error(text_output(proc))
        return record
    dates = {}
    for raw in proc.stdout.decode("utf-8", errors="replace").splitlines():
        if "=" in raw:
            key, value = raw.split("=", 1)
            dates[key.strip()] = value.strip()
    not_before = parse_openssl_date("notBefore=" + dates.get("notBefore", ""))
    not_after = parse_openssl_date("notAfter=" + dates.get("notAfter", ""))
    now = dt.datetime.now(dt.timezone.utc)
    if not_before is not None:
        record["not_before"] = not_before.isoformat().replace("+00:00", "Z")
        record["not_yet_valid"] = now < not_before
    if not_after is not None:
        record["not_after"] = not_after.isoformat().replace("+00:00", "Z")
        record["expired"] = now > not_after
    digest, error = cert_pubkey_digest(path_text)
    record["public_key_sha256"] = digest
    if error:
        record["error"] = error
        return record
    record["subject_alt_name"] = cert_ext(path_text, "subjectAltName")
    record["extended_key_usage"] = cert_ext(path_text, "extendedKeyUsage")
    if record["expired"] or record["not_yet_valid"]:
        record["status"] = "fail"
    else:
        record["status"] = "pass"
    return record


def key_pair_record(label, cert_path, key_path):
    key = pathlib.Path(key_path)
    cert_digest, cert_error = cert_pubkey_digest(cert_path)
    key_digest, key_error = key_pubkey_digest(key_path) if key.is_file() else ("", "missing_key_file")
    matches = cert_digest and key_digest and cert_digest == key_digest
    return {
        "label": label,
        "cert_path": cert_path,
        "key_path": key_path,
        "key_exists": key.is_file(),
        "cert_public_key_sha256": cert_digest,
        "key_public_key_sha256": key_digest,
        "matches": bool(matches),
        "status": "pass" if matches else "fail",
        "error": cert_error or key_error,
        "private_key_pem_printed": False,
    }


def verify_record(label, ca_path, cert_path, purpose="", hostname=""):
    args = ["openssl", "verify"]
    if purpose:
        args.extend(["-purpose", purpose])
    if hostname:
        args.extend(["-verify_hostname", hostname])
    args.extend(["-CAfile", ca_path, cert_path])
    proc = run(args)
    output = safe_error(text_output(proc))
    return {
        "label": label,
        "ca_path": ca_path,
        "cert_path": cert_path,
        "purpose": purpose,
        "hostname": hostname,
        "status": "pass" if proc.returncode == 0 else "fail",
        "output": output,
    }


topology = json.loads(topology_path.read_text(encoding="utf-8"))
cert_records = [cert_record(*item) for item in certs]
key_records = [key_pair_record(*item) for item in key_pairs]
verify_records = [verify_record(*item) for item in verification_inputs]

backup = {"status": "not_run", "path": "", "private_key_material_in_summary": False}
if backup_meta_path and backup_meta_path.is_file():
    backup = json.loads(backup_meta_path.read_text(encoding="utf-8"))
restarts = {"status": "not_run", "services": []}
if restart_meta_path and restart_meta_path.is_file():
    restarts = json.loads(restart_meta_path.read_text(encoding="utf-8"))
curl_probes = {"status": "not_run", "items": []}
if curl_meta_path and curl_meta_path.is_file():
    curl_probes = json.loads(curl_meta_path.read_text(encoding="utf-8"))

blockers = []
blockers.extend(topology.get("blockers") or [])
for record in cert_records:
    if record.get("status") != "pass":
        blockers.append(f"certificate {record['label']} status={record.get('status')} expired={record.get('expired')} error={record.get('error')}")
for record in key_records:
    if record.get("status") != "pass":
        blockers.append(f"key pair {record['label']} does not match")
for record in verify_records:
    if record.get("status") != "pass":
        blockers.append(f"verification {record['label']} failed")
if mode == "execute_renew":
    if restarts.get("status") != "pass":
        blockers.append("service restart set did not pass")
    if curl_probes.get("status") != "pass":
        blockers.append("post-renew mTLS probes did not pass")

summary = {
    "schema_version": schema_version,
    "checked_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    "scope": {
        "name": scope,
        "fixed_helper_scope": scope,
    },
    "mode": {
        "name": mode,
        "non_mutating": mode == "status",
        "execute_renew": mode == "execute_renew",
    },
    "slice": slice_summary,
    "topology": topology,
    "certificates": cert_records,
    "key_pairs": key_records,
    "verification": verify_records,
    "backup": backup,
    "service_restarts": restarts,
    "mtls_probes": curl_probes,
    "security": {
        "private_key_pem_bodies_printed": False,
        "private_key_pem_bodies_in_summary": False,
        "ca_private_key_persisted": False,
        "summary_contains_public_certificate_metadata_only": True,
    },
    "not_claimed": {
        "general_deployment": "not_claimed",
        "provisioning_or_reconciliation": "not_claimed",
        "infrastructure_manager_authority": "not_claimed",
        "control_plane_authority": "not_claimed",
        "vault_or_spire_or_nomad_changes": "not_claimed",
        "egs_trust_model_redesign": "not_claimed",
        "governed_execution_proof": "not_claimed",
        "production_readiness": "not_claimed",
        "mac_side_health_refresh": "not_claimed",
    },
    "result": {
        "status": "pass" if not blockers else "fail",
        "ok": not blockers,
        "blockers": blockers,
    },
}

encoded = json.dumps(summary, indent=2, sort_keys=True) + "\n"
for pattern in secret_patterns:
    if pattern.search(encoded):
        print("summary redaction failure: secret-like material detected", file=sys.stderr)
        raise SystemExit(1)
summary_path.parent.mkdir(parents=True, exist_ok=True)
summary_path.write_text(encoded, encoding="utf-8")
print(str(summary_path))
if blockers:
    raise SystemExit(1)
PY
}

remote_alpha_es_service_tls_renew_create_backup() {
  local backup_meta_path=$1
  local timestamp backup_dir material_dir path rel target
  shift
  timestamp="$(remote_alpha_es_service_tls_renew_timestamp)"
  remote_alpha_prepare_output_dir "${REMOTE_ALPHA_BACKUP_ROOT}" || return 1
  backup_dir="$(mktemp -d "${REMOTE_ALPHA_BACKUP_ROOT}/es-service-tls-renew-${timestamp}-XXXXXX")"
  material_dir="${backup_dir}/material"
  mkdir -p -- "${material_dir}"
  chmod 0700 "${backup_dir}" "${material_dir}" 2>/dev/null || true

  for path in "$@"; do
    rel="${path#/}"
    target="${material_dir}/${rel}"
    mkdir -p -- "$(dirname "${target}")"
    cp -p -- "${path}" "${target}"
  done

  python3 - "${backup_meta_path}" "${backup_dir}" "${material_dir}" "$@" <<'PY'
import hashlib
import json
import pathlib
import sys
from datetime import datetime, timezone

backup_meta_path = pathlib.Path(sys.argv[1])
backup_dir = pathlib.Path(sys.argv[2])
material_dir = pathlib.Path(sys.argv[3])
paths = [pathlib.Path(item) for item in sys.argv[4:]]

items = []
for path in paths:
    backup_path = material_dir / str(path).lstrip("/")
    is_key = path.name.endswith("-key.pem")
    entry = {
        "path": str(path),
        "backup_path": str(backup_path),
        "exists": backup_path.is_file(),
        "size_bytes": backup_path.stat().st_size if backup_path.is_file() else 0,
        "private_key": is_key,
    }
    if backup_path.is_file() and not is_key:
        entry["sha256"] = hashlib.sha256(backup_path.read_bytes()).hexdigest()
    items.append(entry)

payload = {
    "status": "created",
    "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "path": str(backup_dir),
    "material_dir": str(material_dir),
    "items": items,
    "private_key_material_in_summary": False,
    "rollback_note": "Restore the backed-up files to their original absolute paths, restore owner/group/mode policy, then restart the services named by the active scope's exact_affected_service_set.",
}
backup_meta_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

  if [[ -n "${REMOTE_ALPHA_TEST_BACKUP_SENTINEL_PATH:-}" ]]; then
    printf '%s\n' "${backup_dir}" >"${REMOTE_ALPHA_TEST_BACKUP_SENTINEL_PATH}"
  fi
}

remote_alpha_es_service_tls_renew_generate_leaf() {
  local work_dir=$1
  local ca_cert=$2
  local ca_key=$3
  local name=$4
  local subject=$5
  local san=$6
  local eku=$7
  local ext_path="${work_dir}/${name}.ext"
  local csr_path="${work_dir}/${name}.csr"

  cat >"${ext_path}" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=${eku}
subjectAltName=${san}
EOF
  openssl req -newkey rsa:2048 -nodes \
    -keyout "${work_dir}/${name}-key.pem" \
    -out "${csr_path}" \
    -subj "/CN=${subject}" >/dev/null 2>&1
  openssl x509 -req \
    -in "${csr_path}" \
    -CA "${ca_cert}" \
    -CAkey "${ca_key}" \
    -CAcreateserial \
    -out "${work_dir}/${name}-cert.pem" \
    -days "${REMOTE_ALPHA_CERT_DAYS}" \
    -sha256 \
    -extfile "${ext_path}" >/dev/null 2>&1
}

remote_alpha_es_service_tls_renew_generate_material() {
  local work_dir=$1
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "${work_dir}/runtime-ca-key.pem" \
    -out "${work_dir}/runtime-ca.pem" \
    -subj "/CN=Remote Alpha Internal Runtime Root CA" \
    -days "${REMOTE_ALPHA_CERT_DAYS}" \
    -sha256 >/dev/null 2>&1

  remote_alpha_es_service_tls_renew_generate_leaf \
    "${work_dir}" \
    "${work_dir}/runtime-ca.pem" \
    "${work_dir}/runtime-ca-key.pem" \
    "ars-server" \
    "server.artifact-registry.internal" \
    "DNS:server.artifact-registry.internal,IP:127.0.0.1" \
    "serverAuth"
  remote_alpha_es_service_tls_renew_generate_leaf \
    "${work_dir}" \
    "${work_dir}/runtime-ca.pem" \
    "${work_dir}/runtime-ca-key.pem" \
    "ags-client" \
    "client.service.artifact-governance" \
    "DNS:client.artifact-governance,URI:spiffe://execution.internal/service/artifact-governance" \
    "clientAuth"
  remote_alpha_es_service_tls_renew_generate_leaf \
    "${work_dir}" \
    "${work_dir}/runtime-ca.pem" \
    "${work_dir}/runtime-ca-key.pem" \
    "es-client" \
    "client.service.execution" \
    "DNS:client.execution,URI:spiffe://execution.internal/service/execution" \
    "clientAuth"

  rm -f -- "${work_dir}/runtime-ca-key.pem" "${work_dir}"/*.csr "${work_dir}"/*.srl
}

remote_alpha_es_governance_tls_renew_generate_material() {
  local work_dir=$1
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "${work_dir}/runtime-ca-key.pem" \
    -out "${work_dir}/runtime-ca.pem" \
    -subj "/CN=Remote Alpha Internal EGS Runtime Root CA" \
    -days "${REMOTE_ALPHA_CERT_DAYS}" \
    -sha256 >/dev/null 2>&1

  remote_alpha_es_service_tls_renew_generate_leaf \
    "${work_dir}" \
    "${work_dir}/runtime-ca.pem" \
    "${work_dir}/runtime-ca-key.pem" \
    "egs-server" \
    "server.execution-governance.internal" \
    "DNS:server.execution-governance.internal,IP:127.0.0.1" \
    "serverAuth"
  remote_alpha_es_service_tls_renew_generate_leaf \
    "${work_dir}" \
    "${work_dir}/runtime-ca.pem" \
    "${work_dir}/runtime-ca-key.pem" \
    "es-governance-client" \
    "client.service.execution" \
    "DNS:client.execution,URI:spiffe://execution.internal/service/execution" \
    "clientAuth"

  rm -f -- "${work_dir}/runtime-ca-key.pem" "${work_dir}"/*.csr "${work_dir}"/*.srl
}

remote_alpha_es_service_tls_renew_install_material() {
  local work_dir=$1

  install -d -o root -g ars -m 0710 "${REMOTE_ALPHA_ARS_TLS_DIR}"
  install -d -o root -g ags -m 0710 "${REMOTE_ALPHA_AGS_TLS_DIR}"
  install -d -o root -g es -m 0710 "${REMOTE_ALPHA_ES_TLS_DIR}"

  install -o root -g ars -m 0640 "${work_dir}/runtime-ca.pem" "${REMOTE_ALPHA_ARS_CA_PATH}"
  install -o root -g ars -m 0640 "${work_dir}/ars-server-cert.pem" "${REMOTE_ALPHA_ARS_SERVER_CERT_PATH}"
  install -o root -g ars -m 0640 "${work_dir}/ars-server-key.pem" "${REMOTE_ALPHA_ARS_SERVER_KEY_PATH}"

  install -o root -g ags -m 0640 "${work_dir}/ags-client-cert.pem" "${REMOTE_ALPHA_AGS_CLIENT_CERT_PATH}"
  install -o root -g ags -m 0640 "${work_dir}/ags-client-key.pem" "${REMOTE_ALPHA_AGS_CLIENT_KEY_PATH}"
  install -o root -g ags -m 0640 "${work_dir}/runtime-ca.pem" "${REMOTE_ALPHA_AGS_ROOT_CA_PATH}"

  install -o root -g es -m 0640 "${work_dir}/es-client-cert.pem" "${REMOTE_ALPHA_ES_CLIENT_CERT_PATH}"
  install -o root -g es -m 0640 "${work_dir}/es-client-key.pem" "${REMOTE_ALPHA_ES_CLIENT_KEY_PATH}"
  install -o root -g es -m 0640 "${work_dir}/runtime-ca.pem" "${REMOTE_ALPHA_ES_ROOT_CA_PATH}"
}

remote_alpha_es_governance_tls_renew_install_material() {
  local work_dir=$1

  install -d -o root -g egs -m 0710 "${REMOTE_ALPHA_EGS_TLS_DIR}"
  install -d -o root -g es -m 0710 "${REMOTE_ALPHA_ES_TLS_DIR}"

  install -o root -g egs -m 0640 "${work_dir}/runtime-ca.pem" "${REMOTE_ALPHA_EGS_CA_PATH}"
  install -o root -g egs -m 0640 "${work_dir}/egs-server-cert.pem" "${REMOTE_ALPHA_EGS_SERVER_CERT_PATH}"
  install -o root -g egs -m 0640 "${work_dir}/egs-server-key.pem" "${REMOTE_ALPHA_EGS_SERVER_KEY_PATH}"

  install -o root -g es -m 0640 "${work_dir}/es-governance-client-cert.pem" "${REMOTE_ALPHA_ES_GOVERNANCE_CLIENT_CERT_PATH}"
  install -o root -g es -m 0640 "${work_dir}/es-governance-client-key.pem" "${REMOTE_ALPHA_ES_GOVERNANCE_CLIENT_KEY_PATH}"
  install -o root -g es -m 0640 "${work_dir}/runtime-ca.pem" "${REMOTE_ALPHA_ES_GOVERNANCE_ROOT_CA_PATH}"
}

remote_alpha_es_service_tls_renew_restart_services() {
  local restart_meta_path=$1
  local service
  local -a services=("ars.service" "ags.service" "es.service")
  local -a statuses=()
  local overall="pass"

  for service in "${services[@]}"; do
    if systemctl restart "${service}"; then
      statuses+=("${service}:pass")
    else
      statuses+=("${service}:fail")
      overall="fail"
    fi
  done

  python3 - "${restart_meta_path}" "${overall}" "${statuses[@]}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
overall = sys.argv[2]
items = []
for raw in sys.argv[3:]:
    service, status = raw.split(":", 1)
    items.append({"service": service, "status": status})
path.write_text(json.dumps({
    "status": overall,
    "services": items,
    "exact_affected_service_set": ["ars.service", "ags.service", "es.service"],
    "intentionally_not_restarted": ["egs.service", "vault.service", "spire-agent.service", "spire-server.service", "nomad.service"],
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

remote_alpha_es_governance_tls_renew_restart_services() {
  local restart_meta_path=$1
  local service es_active_status="not_run"
  local -a services=("egs.service" "es.service")
  local -a statuses=()
  local overall="pass"

  for service in "${services[@]}"; do
    if systemctl restart "${service}"; then
      statuses+=("${service}:pass")
    else
      statuses+=("${service}:fail")
      overall="fail"
    fi
  done

  if systemctl is-active --quiet es.service; then
    es_active_status="pass"
  else
    es_active_status="fail"
    overall="fail"
  fi

  python3 - "${restart_meta_path}" "${overall}" "${es_active_status}" "${statuses[@]}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
overall = sys.argv[2]
es_active_status = sys.argv[3]
items = []
for raw in sys.argv[4:]:
    service, status = raw.split(":", 1)
    items.append({"service": service, "status": status})
path.write_text(json.dumps({
    "status": overall,
    "services": items,
    "exact_affected_service_set": ["egs.service", "es.service"],
    "es_service_active": {"service": "es.service", "status": es_active_status},
    "intentionally_not_restarted": ["ars.service", "ags.service", "vault.service", "spire-agent.service", "spire-server.service", "nomad.service"],
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

remote_alpha_es_service_tls_renew_curl_probe() {
  local label=$1
  local cert=$2
  local key=$3
  local ca=$4
  local output_path=$5
  local error_path=$6

  if curl --fail-with-body --silent --show-error \
    --resolve server.artifact-registry.internal:8442:127.0.0.1 \
    --cacert "${ca}" \
    --cert "${cert}" \
    --key "${key}" \
    "https://server.artifact-registry.internal:8442/health" >"${output_path}" 2>"${error_path}"; then
    printf '%s:pass\n' "${label}"
  else
    printf '%s:fail:%s\n' "${label}" "$(tr '\n' ' ' <"${error_path}" | cut -c1-300)"
  fi
}

remote_alpha_es_governance_tls_renew_curl_probe() {
  local output_path=$1
  local error_path=$2

  if curl --fail-with-body --silent --show-error \
    --resolve server.execution-governance.internal:8443:127.0.0.1 \
    --cacert "${REMOTE_ALPHA_ES_GOVERNANCE_ROOT_CA_PATH}" \
    --cert "${REMOTE_ALPHA_ES_GOVERNANCE_CLIENT_CERT_PATH}" \
    --key "${REMOTE_ALPHA_ES_GOVERNANCE_CLIENT_KEY_PATH}" \
    "https://server.execution-governance.internal:8443/v1/trust-model" >"${output_path}" 2>"${error_path}"; then
    printf 'es_client_to_egs_trust_model:pass\n'
  else
    printf 'es_client_to_egs_trust_model:fail:%s\n' "$(tr '\n' ' ' <"${error_path}" | cut -c1-300)"
  fi
}

remote_alpha_es_service_tls_renew_post_renew_probes() {
  local curl_meta_path=$1
  local tmpdir=$2
  local ags_result es_result overall

  ags_result="$(remote_alpha_es_service_tls_renew_curl_probe "ags_client_to_ars_health" "${REMOTE_ALPHA_AGS_CLIENT_CERT_PATH}" "${REMOTE_ALPHA_AGS_CLIENT_KEY_PATH}" "${REMOTE_ALPHA_AGS_ROOT_CA_PATH}" "${tmpdir}/ags-ars-health.json" "${tmpdir}/ags-ars-health.err")"
  es_result="$(remote_alpha_es_service_tls_renew_curl_probe "es_client_to_ars_health" "${REMOTE_ALPHA_ES_CLIENT_CERT_PATH}" "${REMOTE_ALPHA_ES_CLIENT_KEY_PATH}" "${REMOTE_ALPHA_ES_ROOT_CA_PATH}" "${tmpdir}/es-ars-health.json" "${tmpdir}/es-ars-health.err")"
  overall="pass"
  [[ "${ags_result}" == *":pass" ]] || overall="fail"
  [[ "${es_result}" == *":pass" ]] || overall="fail"

  python3 - "${curl_meta_path}" "${overall}" "${ags_result}" "${es_result}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
overall = sys.argv[2]
items = []
for raw in sys.argv[3:]:
    parts = raw.split(":", 2)
    item = {"label": parts[0], "status": parts[1], "url": "https://server.artifact-registry.internal:8442/health"}
    if len(parts) == 3:
        item["error"] = parts[2]
    items.append(item)
path.write_text(json.dumps({"status": overall, "items": items}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

remote_alpha_es_governance_tls_renew_post_renew_probes() {
  local curl_meta_path=$1
  local tmpdir=$2
  local result overall

  result="$(remote_alpha_es_governance_tls_renew_curl_probe "${tmpdir}/es-egs-trust-model.json" "${tmpdir}/es-egs-trust-model.err")"
  overall="pass"
  [[ "${result}" == *":pass" ]] || overall="fail"

  python3 - "${curl_meta_path}" "${overall}" "${result}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
overall = sys.argv[2]
raw = sys.argv[3]
parts = raw.split(":", 2)
item = {"label": parts[0], "status": parts[1], "url": "https://server.execution-governance.internal:8443/v1/trust-model"}
if len(parts) == 3:
    item["error"] = parts[2]
path.write_text(json.dumps({"status": overall, "items": [item]}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

remote_alpha_es_service_tls_renew_build_topology() {
  local topology_path=$1
  case "${REMOTE_ALPHA_TLS_SCOPE}" in
    artifact-registry)
      remote_alpha_es_service_tls_renew_topology_json \
        "${REMOTE_ALPHA_ARS_CONFIG_PATH}" \
        "${REMOTE_ALPHA_AGS_CONFIG_PATH}" \
        "${REMOTE_ALPHA_ES_CONFIG_PATH}" \
        "${REMOTE_ALPHA_EGS_CONFIG_PATH}" \
        "${REMOTE_ALPHA_ARS_CA_PATH}" \
        "${REMOTE_ALPHA_ARS_SERVER_CERT_PATH}" \
        "${REMOTE_ALPHA_ARS_SERVER_KEY_PATH}" \
        "${REMOTE_ALPHA_AGS_CLIENT_CERT_PATH}" \
        "${REMOTE_ALPHA_AGS_CLIENT_KEY_PATH}" \
        "${REMOTE_ALPHA_AGS_ROOT_CA_PATH}" \
        "${REMOTE_ALPHA_ES_CLIENT_CERT_PATH}" \
        "${REMOTE_ALPHA_ES_CLIENT_KEY_PATH}" \
        "${REMOTE_ALPHA_ES_ROOT_CA_PATH}" >"${topology_path}"
      ;;
    execution-governance)
      remote_alpha_es_governance_tls_renew_topology_json \
        "${REMOTE_ALPHA_ARS_CONFIG_PATH}" \
        "${REMOTE_ALPHA_AGS_CONFIG_PATH}" \
        "${REMOTE_ALPHA_ES_CONFIG_PATH}" \
        "${REMOTE_ALPHA_EGS_CONFIG_PATH}" \
        "${REMOTE_ALPHA_EGS_CA_PATH}" \
        "${REMOTE_ALPHA_EGS_SERVER_CERT_PATH}" \
        "${REMOTE_ALPHA_EGS_SERVER_KEY_PATH}" \
        "${REMOTE_ALPHA_ES_GOVERNANCE_CLIENT_CERT_PATH}" \
        "${REMOTE_ALPHA_ES_GOVERNANCE_CLIENT_KEY_PATH}" \
        "${REMOTE_ALPHA_ES_GOVERNANCE_ROOT_CA_PATH}" >"${topology_path}"
      ;;
    *)
      echo "unsupported TLS renewal scope: ${REMOTE_ALPHA_TLS_SCOPE}" >&2
      return 2
      ;;
  esac
}

remote_alpha_es_service_tls_renew_main() {
  local tmpdir topology_path backup_meta_path restart_meta_path curl_meta_path work_dir status=0

  remote_alpha_es_service_tls_renew_defaults
  remote_alpha_es_service_tls_renew_parse_args "$@" || return $?
  if [[ "${REMOTE_ALPHA_OPERATION_MODE}" == "help" ]]; then
    return 0
  fi
  remote_alpha_es_service_tls_renew_apply_scope_defaults || return $?
  remote_alpha_es_service_tls_renew_require_root || return 1
  remote_alpha_es_service_tls_renew_require_command python3 || return 1
  remote_alpha_prepare_output_dir "$(dirname "${REMOTE_ALPHA_SUMMARY_PATH}")" || return 1
  # Only a renewal writes backups; status must leave the backup root alone.
  if [[ "${REMOTE_ALPHA_OPERATION_MODE}" == "execute_renew" ]]; then
    remote_alpha_prepare_output_dir "${REMOTE_ALPHA_BACKUP_ROOT}" || return 1
  fi
  remote_alpha_es_service_tls_renew_require_command openssl || return 1

  tmpdir="$(mktemp -d)"
  work_dir=""
  trap 'rm -rf -- "${tmpdir:-}" "${work_dir:-}" 2>/dev/null || true' EXIT
  topology_path="${tmpdir}/topology.json"
  backup_meta_path="${tmpdir}/backup.json"
  restart_meta_path="${tmpdir}/restarts.json"
  curl_meta_path="${tmpdir}/curl-probes.json"

  remote_alpha_es_service_tls_renew_build_topology "${topology_path}" || return 1

  if [[ "${REMOTE_ALPHA_OPERATION_MODE}" == "status" ]]; then
    remote_alpha_es_service_tls_renew_collect_status "status" "${REMOTE_ALPHA_SUMMARY_PATH}" "${topology_path}" || return $?
    return 0
  fi

  remote_alpha_es_service_tls_renew_require_command install || return 1
  remote_alpha_es_service_tls_renew_require_command systemctl || return 1
  remote_alpha_es_service_tls_renew_require_command curl || return 1

  if [[ "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "${topology_path}")" != "pass" ]]; then
    remote_alpha_es_service_tls_renew_collect_status "execute_renew" "${REMOTE_ALPHA_SUMMARY_PATH}" "${topology_path}" || true
    return 1
  fi

  case "${REMOTE_ALPHA_TLS_SCOPE}" in
    artifact-registry)
      remote_alpha_es_service_tls_renew_create_backup \
        "${backup_meta_path}" \
        "${REMOTE_ALPHA_ARS_CA_PATH}" \
        "${REMOTE_ALPHA_ARS_SERVER_CERT_PATH}" \
        "${REMOTE_ALPHA_ARS_SERVER_KEY_PATH}" \
        "${REMOTE_ALPHA_AGS_CLIENT_CERT_PATH}" \
        "${REMOTE_ALPHA_AGS_CLIENT_KEY_PATH}" \
        "${REMOTE_ALPHA_AGS_ROOT_CA_PATH}" \
        "${REMOTE_ALPHA_ES_CLIENT_CERT_PATH}" \
        "${REMOTE_ALPHA_ES_CLIENT_KEY_PATH}" \
        "${REMOTE_ALPHA_ES_ROOT_CA_PATH}" || return 1
      ;;
    execution-governance)
      remote_alpha_es_service_tls_renew_create_backup \
        "${backup_meta_path}" \
        "${REMOTE_ALPHA_EGS_CA_PATH}" \
        "${REMOTE_ALPHA_EGS_SERVER_CERT_PATH}" \
        "${REMOTE_ALPHA_EGS_SERVER_KEY_PATH}" \
        "${REMOTE_ALPHA_ES_GOVERNANCE_CLIENT_CERT_PATH}" \
        "${REMOTE_ALPHA_ES_GOVERNANCE_CLIENT_KEY_PATH}" \
        "${REMOTE_ALPHA_ES_GOVERNANCE_ROOT_CA_PATH}" || return 1
      ;;
    *)
      echo "unsupported TLS renewal scope: ${REMOTE_ALPHA_TLS_SCOPE}" >&2
      return 2
      ;;
  esac

  work_dir="$(mktemp -d)"
  chmod 0700 "${work_dir}" 2>/dev/null || true
  case "${REMOTE_ALPHA_TLS_SCOPE}" in
    artifact-registry)
      remote_alpha_es_service_tls_renew_generate_material "${work_dir}" || return 1
      remote_alpha_es_service_tls_renew_install_material "${work_dir}" || return 1
      ;;
    execution-governance)
      remote_alpha_es_governance_tls_renew_generate_material "${work_dir}" || return 1
      remote_alpha_es_governance_tls_renew_install_material "${work_dir}" || return 1
      ;;
  esac
  rm -rf -- "${work_dir}"
  work_dir=""

  case "${REMOTE_ALPHA_TLS_SCOPE}" in
    artifact-registry)
      remote_alpha_es_service_tls_renew_restart_services "${restart_meta_path}" || status=1
      remote_alpha_es_service_tls_renew_post_renew_probes "${curl_meta_path}" "${tmpdir}" || status=1
      ;;
    execution-governance)
      remote_alpha_es_governance_tls_renew_restart_services "${restart_meta_path}" || status=1
      remote_alpha_es_governance_tls_renew_post_renew_probes "${curl_meta_path}" "${tmpdir}" || status=1
      ;;
  esac
  remote_alpha_es_service_tls_renew_collect_status "execute_renew" "${REMOTE_ALPHA_SUMMARY_PATH}" "${topology_path}" "${backup_meta_path}" "${restart_meta_path}" "${curl_meta_path}" || status=1
  return "${status}"
}
