#!/usr/bin/env bash
set -euo pipefail
set +x

remote_alpha_operator_healthcheck_tls_schema_version="execution-substrate.remote-alpha.operator-healthcheck-tls-renew-summary.v1"
remote_alpha_operator_healthcheck_tls_summary_path_default="/var/tmp/execution-substrate-remote-alpha/operator-healthcheck-tls-renew-summary.json"
remote_alpha_operator_healthcheck_tls_backup_root_default="/var/tmp/execution-substrate-remote-alpha"

remote_alpha_operator_healthcheck_tls_defaults() {
  REMOTE_ALPHA_OPERATION_MODE="status"
  REMOTE_ALPHA_SUMMARY_PATH="${REMOTE_ALPHA_SUMMARY_PATH:-${remote_alpha_operator_healthcheck_tls_summary_path_default}}"
  REMOTE_ALPHA_SUMMARY_PATH_EXPLICIT="false"
  REMOTE_ALPHA_BACKUP_ROOT="${REMOTE_ALPHA_TEST_BACKUP_ROOT:-${remote_alpha_operator_healthcheck_tls_backup_root_default}}"

  REMOTE_ALPHA_ES_CONFIG_PATH="${remote_alpha_operator_healthcheck_tls_expected_es_config_path:-/etc/execution-substrate/es.json}"
  REMOTE_ALPHA_HEALTHCHECK_ENV_PATH="${remote_alpha_operator_healthcheck_tls_expected_healthcheck_env_path:-/etc/execution-substrate/healthcheck.env}"
  REMOTE_ALPHA_OPERATOR_CERT_PATH="${remote_alpha_operator_healthcheck_tls_expected_operator_cert_path:-/etc/execution-substrate/tls/operator-client-cert.pem}"
  REMOTE_ALPHA_OPERATOR_KEY_PATH="${remote_alpha_operator_healthcheck_tls_expected_operator_key_path:-/etc/execution-substrate/tls/operator-client-key.pem}"
  REMOTE_ALPHA_HEALTHCHECK_SERVER_CA_PATH="${remote_alpha_operator_healthcheck_tls_expected_healthcheck_server_ca_path:-/etc/execution-substrate/tls/combined-service-ca-bundle.pem}"
  REMOTE_ALPHA_EXPECTED_OPERATOR_SPIFFE_URI="${REMOTE_ALPHA_EXPECTED_OPERATOR_SPIFFE_URI:-spiffe://execution.internal/operator/local}"
  REMOTE_ALPHA_LEGACY_OPERATOR_SPIFFE_URI="${REMOTE_ALPHA_LEGACY_OPERATOR_SPIFFE_URI:-spiffe://execution.internal/operator}"
}

remote_alpha_operator_healthcheck_tls_usage() {
  cat <<'EOF'
Usage:
  sudo scripts/remote_alpha_operator_healthcheck_tls_renew.sh --status
  sudo scripts/remote_alpha_operator_healthcheck_tls_renew.sh --execute-renew

Optional flags:
  --status
  --check-only
  --execute-renew
  --summary-path </path/to/operator-healthcheck-tls-renew-summary.json>
  --help

Status/check-only is non-mutating. Renew requires --execute-renew and currently
fails closed with unsupported_signing_topology before backup/install until a
documented CA custody/signing design exists.
This helper is bounded to the fixed Remote Alpha host-local operator healthcheck client TLS material only.
EOF
}

remote_alpha_operator_healthcheck_tls_reject_secret_arg() {
  local arg=$1
  case "${arg}" in
    *root-token*|*unseal-key*|*client-token*|*vault-token*|*api-key*|*jwt-svid*|*private-key*|*password*|*secret*|*BEGIN*PRIVATE*KEY*|*BEGIN*CERTIFICATE*|*hvs.*|*hvb.*)
      echo "remote alpha operator healthcheck TLS renewal does not accept secret-like CLI arguments" >&2
      return 2
      ;;
  esac
}

remote_alpha_operator_healthcheck_tls_parse_args() {
  while [[ $# -gt 0 ]]; do
    remote_alpha_operator_healthcheck_tls_reject_secret_arg "$1" || return $?
    case "$1" in
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
        remote_alpha_operator_healthcheck_tls_usage
        REMOTE_ALPHA_OPERATION_MODE="help"
        shift
        ;;
      --apply|--dry-run|--interactive-sudo|--reset|--unseal-only|--post-unseal-check|--workload-auth-check|--workload-auth-bootstrap|--runtime-identity-summary|--im-refresh|--support-bundle|--cp-proof|--scope)
        echo "remote alpha operator healthcheck TLS renewal forbids $1; this helper is bounded to host-local operator healthcheck client TLS status or renewal only" >&2
        return 2
        ;;
      --*=*)
        echo "remote alpha operator healthcheck TLS renewal does not accept equals-form options: $1" >&2
        return 2
        ;;
      --*)
        echo "unknown argument: $1" >&2
        remote_alpha_operator_healthcheck_tls_usage >&2
        return 2
        ;;
      *)
        echo "unexpected positional argument: $1" >&2
        return 2
        ;;
    esac
  done
}

remote_alpha_operator_healthcheck_tls_require_root() {
  if [[ "$(id -u)" != "0" && -z "${REMOTE_ALPHA_TEST_ALLOW_NON_ROOT:-}" ]]; then
    echo "remote alpha operator healthcheck TLS renewal must run as root; use sudo scripts/remote_alpha_operator_healthcheck_tls_renew.sh" >&2
    return 1
  fi
}

remote_alpha_operator_healthcheck_tls_require_command() {
  local name=$1
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "${name} is required" >&2
    return 1
  fi
}

remote_alpha_operator_healthcheck_tls_timestamp() {
  if [[ -n "${REMOTE_ALPHA_TEST_TIMESTAMP:-}" ]]; then
    printf '%s' "${REMOTE_ALPHA_TEST_TIMESTAMP}"
    return 0
  fi
  date -u +%Y%m%dT%H%M%SZ
}

remote_alpha_operator_healthcheck_tls_collect_status() {
  local mode=$1
  local summary_path=$2
  local probe_meta_path=${3:-}
  local backup_meta_path=${4:-}
  local install_meta_path=${5:-}
  local restart_meta_path=${6:-}

  python3 - \
    "${mode}" \
    "${summary_path}" \
    "${probe_meta_path}" \
    "${backup_meta_path}" \
    "${install_meta_path}" \
    "${restart_meta_path}" \
    "${remote_alpha_operator_healthcheck_tls_schema_version}" \
    "${REMOTE_ALPHA_ES_CONFIG_PATH}" \
    "${REMOTE_ALPHA_HEALTHCHECK_ENV_PATH}" \
    "${REMOTE_ALPHA_OPERATOR_CERT_PATH}" \
    "${REMOTE_ALPHA_OPERATOR_KEY_PATH}" \
    "${REMOTE_ALPHA_HEALTHCHECK_SERVER_CA_PATH}" \
    "${REMOTE_ALPHA_EXPECTED_OPERATOR_SPIFFE_URI}" \
    "${REMOTE_ALPHA_LEGACY_OPERATOR_SPIFFE_URI}" <<'PY'
import datetime as dt
import hashlib
import json
import pathlib
import re
import subprocess
import sys
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse

mode = sys.argv[1]
summary_path = pathlib.Path(sys.argv[2])
probe_meta_path = pathlib.Path(sys.argv[3]) if sys.argv[3] else None
backup_meta_path = pathlib.Path(sys.argv[4]) if sys.argv[4] else None
install_meta_path = pathlib.Path(sys.argv[5]) if sys.argv[5] else None
restart_meta_path = pathlib.Path(sys.argv[6]) if sys.argv[6] else None
schema_version = sys.argv[7]
es_config_path = pathlib.Path(sys.argv[8])
healthcheck_env_path = pathlib.Path(sys.argv[9])
operator_cert_path = sys.argv[10]
operator_key_path = sys.argv[11]
healthcheck_server_ca_path = sys.argv[12]
expected_spiffe_uri = sys.argv[13]
legacy_spiffe_uri = sys.argv[14]

secret_patterns = [
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"-----BEGIN CERTIFICATE-----"),
    re.compile(r"\b(?:hvs|hvb|s)\.[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
]


def run(args, input_bytes=None):
    return subprocess.run(args, input=input_bytes, check=False, capture_output=True)


def text_output(proc):
    return (proc.stdout + proc.stderr).decode("utf-8", errors="replace").strip()


def safe_error(value):
    return value.replace("\n", " | ")[:500]


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


def read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8")), ""
    except Exception as exc:
        return {}, f"read_or_parse_failed:{safe_error(str(exc))}"


def nested(payload, *keys):
    current = payload
    for key in keys:
        if not isinstance(current, dict):
            return ""
        current = current.get(key)
    return "" if current is None else str(current).strip()


def read_env(path):
    values = {}
    if not path.is_file():
        return values, "missing_healthcheck_env"
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip().strip("'\"")
        values[key.strip()] = value
    return values, ""


def derive_probe_urls(env_values):
    health = env_values.get("HEALTH_URL") or env_values.get("ES_HEALTH_URL") or env_values.get("EXECUTION_SUBSTRATE_HEALTH_URL")
    contract = env_values.get("CONTRACT_URL") or env_values.get("ES_CONTRACT_URL") or env_values.get("EXECUTION_SUBSTRATE_CONTRACT_URL")
    base = env_values.get("ES_BASE_URL") or env_values.get("EXECUTION_SUBSTRATE_BASE_URL")
    if not health and base:
        health = base.rstrip("/") + "/health"
    if not contract and base:
        contract = base.rstrip("/") + "/v1/executions:contract"
    if health and not contract:
        parsed = urlparse(health)
        if parsed.scheme and parsed.netloc:
            contract = f"{parsed.scheme}://{parsed.netloc}/v1/executions:contract"
    return health or "https://127.0.0.1:8444/health", contract or "https://127.0.0.1:8444/v1/executions:contract"


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


def cert_record(path_text):
    path = pathlib.Path(path_text)
    record = {
        "label": "operator_healthcheck_client",
        "path": path_text,
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
    record["status"] = "fail" if record["expired"] or record["not_yet_valid"] else "pass"
    return record


def key_pair_record(cert_path, key_path):
    key = pathlib.Path(key_path)
    cert_digest, cert_error = cert_pubkey_digest(cert_path)
    key_digest, key_error = key_pubkey_digest(key_path) if key.is_file() else ("", "missing_key_file")
    matches = bool(cert_digest and key_digest and cert_digest == key_digest)
    return {
        "label": "operator_healthcheck_client",
        "cert_path": cert_path,
        "key_path": key_path,
        "key_exists": key.is_file(),
        "cert_public_key_sha256": cert_digest,
        "key_public_key_sha256": key_digest,
        "matches": matches,
        "status": "pass" if matches else "fail",
        "error": cert_error or key_error,
        "private_key_pem_printed": False,
    }


def verify_record(label, ca_path, cert_path):
    if not ca_path:
        return {"label": label, "status": "skipped", "reason": "no_client_ca_configured"}
    args = ["openssl", "verify", "-purpose", "sslclient", "-CAfile", ca_path, cert_path]
    proc = run(args)
    return {
        "label": label,
        "ca_path": ca_path,
        "cert_path": cert_path,
        "purpose": "sslclient",
        "status": "pass" if proc.returncode == 0 else "fail",
        "output": safe_error(text_output(proc)),
    }


def file_policy(path_text):
    path = pathlib.Path(path_text)
    if not path.exists():
        return {"path": path_text, "exists": False}
    st = path.stat()
    return {"path": path_text, "exists": True, "uid": st.st_uid, "gid": st.st_gid, "mode": f"{st.st_mode & 0o777:04o}"}


es_config, es_error = read_json(es_config_path)
env_values, env_error = read_env(healthcheck_env_path)
health_url, contract_url = derive_probe_urls(env_values)
es_client_ca = nested(es_config, "tls", "client_ca_file")
if not es_client_ca:
    es_client_ca = env_values.get("CLIENT_CA_CERT") or env_values.get("ES_CLIENT_CA_CERT") or ""

cert = cert_record(operator_cert_path)
key_pair = key_pair_record(operator_cert_path, operator_key_path)
identity = {
    "expected_uri": expected_spiffe_uri,
    "legacy_uri": legacy_spiffe_uri,
    "subject_alt_name": cert.get("subject_alt_name", ""),
    "matches_current_allowlist": expected_spiffe_uri in cert.get("subject_alt_name", ""),
    "legacy_operator_uri_present": legacy_spiffe_uri in cert.get("subject_alt_name", ""),
}
identity["status"] = "pass" if identity["matches_current_allowlist"] else "fail"
if identity["legacy_operator_uri_present"] and not identity["matches_current_allowlist"]:
    identity["classification"] = "legacy_operator_identity_requires_operator_local_renewal"
else:
    identity["classification"] = "current_operator_local_identity" if identity["matches_current_allowlist"] else "operator_identity_mismatch"

verification = [
    verify_record("operator_client_cert_against_es_server_client_ca", es_client_ca, operator_cert_path),
]

probe_meta = {"status": "not_run", "items": []}
if probe_meta_path and probe_meta_path.is_file():
    probe_meta = json.loads(probe_meta_path.read_text(encoding="utf-8"))
backup = {"status": "not_run", "path": "", "private_key_material_in_summary": False}
if backup_meta_path and backup_meta_path.is_file():
    backup = json.loads(backup_meta_path.read_text(encoding="utf-8"))
install_policy = {"status": "not_run", "items": []}
if install_meta_path and install_meta_path.is_file():
    install_policy = json.loads(install_meta_path.read_text(encoding="utf-8"))
service_restarts = {
    "status": "not_required",
    "exact_affected_service_set": [],
    "intentionally_not_restarted": ["es.service", "ags.service", "ars.service", "egs.service", "vault.service", "spire-agent.service", "spire-server.service", "nomad.service"],
    "reason": "client certificate renewal does not require ES service restart",
}
if restart_meta_path and restart_meta_path.is_file():
    service_restarts = json.loads(restart_meta_path.read_text(encoding="utf-8"))

unsupported_renewal_next_step = (
    "Operator healthcheck client certificate renewal requires a future documented "
    "CA custody/signing design before any backup, install, service restart, or "
    "post-renew probe may run."
)
renewal_topology = {
    "status": "unsupported" if mode == "execute_renew" else "not_applicable",
    "failure_class": "unsupported_signing_topology" if mode == "execute_renew" else "",
    "mutation_started": False,
    "backup_allowed": False if mode == "execute_renew" else None,
    "install_allowed": False if mode == "execute_renew" else None,
    "service_restart_allowed": False if mode == "execute_renew" else None,
    "retained_remote_ca_key_required": False,
    "documented_signing_topology": False,
    "next_step": unsupported_renewal_next_step if mode == "execute_renew" else "",
}

blockers = []
if es_error:
    blockers.append(f"es_config:{es_error}")
if env_error:
    blockers.append(f"healthcheck_env:{env_error}")
if cert.get("status") != "pass":
    blockers.append(f"operator certificate status={cert.get('status')} expired={cert.get('expired')} error={cert.get('error')}")
if key_pair.get("status") != "pass":
    blockers.append("operator certificate and key public keys do not match")
if identity.get("status") != "pass":
    blockers.append(f"operator certificate SAN must include {expected_spiffe_uri}")
for record in verification:
    if record.get("status") == "fail":
        blockers.append(f"verification {record['label']} failed")
if mode == "execute_renew":
    blockers.append("unsupported_signing_topology: renew requires a future documented CA custody/signing design before backup/install")

summary = {
    "schema_version": schema_version,
    "checked_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    "mode": {
        "name": mode,
        "non_mutating": mode == "status",
        "execute_renew": mode == "execute_renew",
    },
    "slice": {
        "name": "remote-alpha-operator-healthcheck-client-tls-renewal",
        "classification": "bounded_remote_alpha_host_local_operator_healthcheck_client_tls_recovery",
        "not_a_deployment_system": True,
        "not_im_reconciliation": True,
        "not_cp_authority": True,
        "not_production_readiness": True,
    },
    "topology": {
        "es_config_path": str(es_config_path),
        "healthcheck_env_path": str(healthcheck_env_path),
        "operator_cert_path": operator_cert_path,
        "operator_key_path": operator_key_path,
        "server_ca_bundle_path": healthcheck_server_ca_path,
        "es_server_client_ca_path": es_client_ca,
        "health_url": health_url,
        "contract_url": contract_url,
        "covered_paths": [operator_cert_path, operator_key_path],
        "conditionally_used_paths": [healthcheck_server_ca_path],
        "intentionally_not_covered": [
            "ES server certificates",
            "AGS/ARS/EGS internal service TLS",
            "Vault, SPIRE, Nomad, workload-auth, runtime identity, CP proof, IM refresh, support bundles, and general deployment",
        ],
    },
    "certificate": cert,
    "key_pair": key_pair,
    "identity": identity,
    "renewal_topology": renewal_topology,
    "verification": verification,
    "probes": probe_meta,
    "backup": backup,
    "install_policy": install_policy,
    "service_restarts": service_restarts,
    "file_policy_before_or_current": {
        "operator_cert": file_policy(operator_cert_path),
        "operator_key": file_policy(operator_key_path),
    },
    "security": {
        "private_key_pem_bodies_printed": False,
        "private_key_pem_bodies_in_summary": False,
        "certificate_pem_bodies_in_summary": False,
        "summary_contains_public_certificate_metadata_only": True,
    },
    "not_claimed": {
        "general_deployment": "not_claimed",
        "provisioning_or_reconciliation": "not_claimed",
        "infrastructure_manager_authority": "not_claimed",
        "control_plane_authority": "not_claimed",
        "vault_or_spire_or_nomad_changes": "not_claimed",
        "workload_auth_or_runtime_identity": "not_claimed",
        "governed_execution_proof": "not_claimed",
        "production_readiness": "not_claimed",
        "mac_side_health_refresh": "not_claimed",
    },
    "result": {
        "status": "pass" if not blockers else "fail",
        "ok": not blockers,
        "failure_class": "unsupported_signing_topology" if mode == "execute_renew" else "",
        "next_step": unsupported_renewal_next_step if mode == "execute_renew" else "",
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

remote_alpha_operator_healthcheck_tls_create_backup() {
  local backup_meta_path=$1
  local timestamp backup_dir material_dir path rel target
  shift
  timestamp="$(remote_alpha_operator_healthcheck_tls_timestamp)"
  mkdir -p -- "${REMOTE_ALPHA_BACKUP_ROOT}"
  backup_dir="$(mktemp -d "${REMOTE_ALPHA_BACKUP_ROOT}/operator-healthcheck-tls-renew-${timestamp}-XXXXXX")"
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
    "rollback_note": "Restore the backed-up operator cert/key to their original absolute paths and owner/group/mode policy; ES restart is not expected for client certificate rollback.",
}
backup_meta_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

  if [[ -n "${REMOTE_ALPHA_TEST_BACKUP_SENTINEL_PATH:-}" ]]; then
    printf '%s\n' "${backup_dir}" >"${REMOTE_ALPHA_TEST_BACKUP_SENTINEL_PATH}"
  fi
}

remote_alpha_operator_healthcheck_tls_es_client_ca_path() {
  python3 - "${REMOTE_ALPHA_ES_CONFIG_PATH}" "${REMOTE_ALPHA_HEALTHCHECK_ENV_PATH}" <<'PY'
import json
import pathlib
import sys

es_config = pathlib.Path(sys.argv[1])
health_env = pathlib.Path(sys.argv[2])
try:
    payload = json.loads(es_config.read_text(encoding="utf-8"))
    value = str(((payload.get("tls") or {}).get("client_ca_file")) or "").strip()
except Exception:
    value = ""
if not value and health_env.is_file():
    for raw in health_env.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        if key.strip() in {"CLIENT_CA_CERT", "ES_CLIENT_CA_CERT"}:
            value = raw_value.strip().strip("'\"")
            break
print(value)
PY
}

remote_alpha_operator_healthcheck_tls_file_policy() {
  local cert_meta_path=$1
  python3 - "${cert_meta_path}" "${REMOTE_ALPHA_OPERATOR_CERT_PATH}" "${REMOTE_ALPHA_OPERATOR_KEY_PATH}" <<'PY'
import json
import pathlib
import sys

out = pathlib.Path(sys.argv[1])
items = []
for label, path_text in (("operator_cert", sys.argv[2]), ("operator_key", sys.argv[3])):
    path = pathlib.Path(path_text)
    st = path.stat()
    items.append({
        "label": label,
        "path": path_text,
        "uid": str(st.st_uid),
        "gid": str(st.st_gid),
        "mode": f"{st.st_mode & 0o777:04o}",
    })
out.write_text(json.dumps({"items": items}, sort_keys=True) + "\n", encoding="utf-8")
PY
}

remote_alpha_operator_healthcheck_tls_install_material() {
  local work_dir=$1
  local policy_path=$2
  local install_meta_path=$3
  local cert_uid cert_gid cert_mode key_uid key_gid key_mode

  remote_alpha_operator_healthcheck_tls_file_policy "${policy_path}"
  cert_uid="$(python3 -c 'import json,sys; p=json.load(open(sys.argv[1])); print(p["items"][0]["uid"])' "${policy_path}")"
  cert_gid="$(python3 -c 'import json,sys; p=json.load(open(sys.argv[1])); print(p["items"][0]["gid"])' "${policy_path}")"
  cert_mode="$(python3 -c 'import json,sys; p=json.load(open(sys.argv[1])); print(p["items"][0]["mode"])' "${policy_path}")"
  key_uid="$(python3 -c 'import json,sys; p=json.load(open(sys.argv[1])); print(p["items"][1]["uid"])' "${policy_path}")"
  key_gid="$(python3 -c 'import json,sys; p=json.load(open(sys.argv[1])); print(p["items"][1]["gid"])' "${policy_path}")"
  key_mode="$(python3 -c 'import json,sys; p=json.load(open(sys.argv[1])); print(p["items"][1]["mode"])' "${policy_path}")"

  install -o "${cert_uid}" -g "${cert_gid}" -m "${cert_mode}" "${work_dir}/operator-client-cert.pem" "${REMOTE_ALPHA_OPERATOR_CERT_PATH}"
  install -o "${key_uid}" -g "${key_gid}" -m "${key_mode}" "${work_dir}/operator-client-key.pem" "${REMOTE_ALPHA_OPERATOR_KEY_PATH}"

  python3 - "${install_meta_path}" "${policy_path}" <<'PY'
import json
import pathlib
import sys

out = pathlib.Path(sys.argv[1])
policy = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
out.write_text(json.dumps({
    "status": "pass",
    "policy": "preserve_existing_owner_group_mode",
    "items": policy["items"],
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

remote_alpha_operator_healthcheck_tls_restart_meta() {
  local restart_meta_path=$1
  python3 - "${restart_meta_path}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
path.write_text(json.dumps({
    "status": "not_required",
    "exact_affected_service_set": [],
    "intentionally_not_restarted": ["es.service", "ags.service", "ars.service", "egs.service", "vault.service", "spire-agent.service", "spire-server.service", "nomad.service"],
    "reason": "Remote Alpha operator healthcheck client certificate renewal updates client-side material only; ES does not need a service restart for this client identity.",
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

remote_alpha_operator_healthcheck_tls_probe_urls() {
  python3 - "${REMOTE_ALPHA_HEALTHCHECK_ENV_PATH}" <<'PY'
import pathlib
import sys
from urllib.parse import urlparse

env_path = pathlib.Path(sys.argv[1])
values = {}
if env_path.is_file():
    for raw in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip("'\"")
health = values.get("HEALTH_URL") or values.get("ES_HEALTH_URL") or values.get("EXECUTION_SUBSTRATE_HEALTH_URL")
contract = values.get("CONTRACT_URL") or values.get("ES_CONTRACT_URL") or values.get("EXECUTION_SUBSTRATE_CONTRACT_URL")
base = values.get("ES_BASE_URL") or values.get("EXECUTION_SUBSTRATE_BASE_URL")
if not health and base:
    health = base.rstrip("/") + "/health"
if not contract and base:
    contract = base.rstrip("/") + "/v1/executions:contract"
if health and not contract:
    parsed = urlparse(health)
    if parsed.scheme and parsed.netloc:
        contract = f"{parsed.scheme}://{parsed.netloc}/v1/executions:contract"
health = health or "https://127.0.0.1:8444/health"
contract = contract or "https://127.0.0.1:8444/v1/executions:contract"
for label, url in (("health", health), ("contract", contract)):
    parsed = urlparse(url)
    safe = parsed.scheme == "https" and parsed.hostname in {"127.0.0.1", "localhost"}
    print(f"{label}\t{url}\t{'safe' if safe else 'unsafe'}")
PY
}

remote_alpha_operator_healthcheck_tls_run_probes() {
  local probe_meta_path=$1
  local tmpdir=$2
  local line label url safe result status error overall="pass"
  local -a records=()

  if [[ -n "${REMOTE_ALPHA_TEST_SKIP_OPERATOR_HEALTHCHECK_TLS_PROBES:-}" ]]; then
    python3 - "${probe_meta_path}" <<'PY'
import json
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
path.write_text(json.dumps({"status": "skipped", "reason": "test_skip", "items": []}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
    return 0
  fi

  if ! command -v curl >/dev/null 2>&1; then
    python3 - "${probe_meta_path}" <<'PY'
import json
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
path.write_text(json.dumps({"status": "skipped", "reason": "curl_missing", "items": []}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
    return 0
  fi

  while IFS=$'\t' read -r label url safe; do
    if [[ "${safe}" != "safe" ]]; then
      records+=("${label}|${url}|skipped|unsafe_nonlocal_url")
      continue
    fi
    if curl --fail-with-body --silent --show-error \
      --cacert "${REMOTE_ALPHA_HEALTHCHECK_SERVER_CA_PATH}" \
      --cert "${REMOTE_ALPHA_OPERATOR_CERT_PATH}" \
      --key "${REMOTE_ALPHA_OPERATOR_KEY_PATH}" \
      "${url}" >"${tmpdir}/${label}.out" 2>"${tmpdir}/${label}.err"; then
      records+=("${label}|${url}|pass|")
    else
      overall="fail"
      error="$(tr '\n' ' ' <"${tmpdir}/${label}.err" | cut -c1-300)"
      records+=("${label}|${url}|fail|${error}")
    fi
  done < <(remote_alpha_operator_healthcheck_tls_probe_urls)

  for result in "${records[@]}"; do
    IFS='|' read -r _ _ status _ <<<"${result}"
    if [[ "${status}" == "fail" ]]; then
      overall="fail"
    fi
  done

  python3 - "${probe_meta_path}" "${overall}" "${REMOTE_ALPHA_OPERATOR_CERT_PATH}" "${REMOTE_ALPHA_OPERATOR_KEY_PATH}" "${records[@]}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
overall = sys.argv[2]
cert_path = sys.argv[3]
key_path = sys.argv[4]
items = []
for raw in sys.argv[5:]:
    label, url, status, error = raw.split("|", 3)
    item = {
        "label": label,
        "url": url,
        "method": "GET",
        "status": status,
        "cert_path": cert_path,
        "key_path": key_path,
        "uses_renewed_operator_identity": True,
        "response_body_recorded": False,
    }
    if error:
        item["error"] = error
    items.append(item)
if items and all(item["status"] == "skipped" for item in items):
    overall = "skipped"
path.write_text(json.dumps({"status": overall, "items": items}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

remote_alpha_operator_healthcheck_tls_main_execute_renew() {
  echo "unsupported_signing_topology: operator healthcheck TLS renewal requires a future documented CA custody/signing design before backup/install" >&2
  return 1
}

remote_alpha_operator_healthcheck_tls_renew_main() {
  local tmpdir probe_meta_path backup_meta_path install_meta_path restart_meta_path work_dir status=0

  remote_alpha_operator_healthcheck_tls_defaults
  remote_alpha_operator_healthcheck_tls_parse_args "$@" || return $?
  if [[ "${REMOTE_ALPHA_OPERATION_MODE}" == "help" ]]; then
    return 0
  fi
  remote_alpha_operator_healthcheck_tls_require_root || return 1
  remote_alpha_operator_healthcheck_tls_require_command python3 || return 1
  remote_alpha_operator_healthcheck_tls_require_command openssl || return 1

  tmpdir="$(mktemp -d)"
  work_dir="${tmpdir}/new-material"
  trap 'rm -rf -- "${tmpdir:-}" 2>/dev/null || true' EXIT
  probe_meta_path="${tmpdir}/probes.json"
  backup_meta_path="${tmpdir}/backup.json"
  install_meta_path="${tmpdir}/install-policy.json"
  restart_meta_path="${tmpdir}/service-restarts.json"

  if [[ "${REMOTE_ALPHA_OPERATION_MODE}" == "status" ]]; then
    remote_alpha_operator_healthcheck_tls_run_probes "${probe_meta_path}" "${tmpdir}" || true
    remote_alpha_operator_healthcheck_tls_collect_status "status" "${REMOTE_ALPHA_SUMMARY_PATH}" "${probe_meta_path}" || return $?
    return 0
  fi

  remote_alpha_operator_healthcheck_tls_main_execute_renew "${tmpdir}" "${backup_meta_path}" "${install_meta_path}" "${restart_meta_path}" "${probe_meta_path}" "${work_dir}" || status=1
  remote_alpha_operator_healthcheck_tls_collect_status "execute_renew" "${REMOTE_ALPHA_SUMMARY_PATH}" "${probe_meta_path}" "${backup_meta_path}" "${install_meta_path}" "${restart_meta_path}" || status=1
  return "${status}"
}
