remote_alpha_vault_workload_auth_bootstrap_schema_version="execution-substrate.remote-alpha.vault-workload-auth-bootstrap-summary.v1"

remote_alpha_vault_workload_auth_bootstrap_defaults() {
  REMOTE_ALPHA_BOOTSTRAP_WORKLOAD_ZONE_CONFIG_PATH="${REMOTE_ALPHA_BOOTSTRAP_WORKLOAD_ZONE_CONFIG_PATH:-/etc/execution-substrate/vault/workload-zone-vault-config.json}"
  REMOTE_ALPHA_BOOTSTRAP_SUMMARY_PATH="${REMOTE_ALPHA_BOOTSTRAP_SUMMARY_PATH:-/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json}"
  REMOTE_ALPHA_BOOTSTRAP_SPIRE_SERVER_SOCKET_PATH="${REMOTE_ALPHA_BOOTSTRAP_SPIRE_SERVER_SOCKET_PATH:-/run/spire/server/private/api.sock}"
  REMOTE_ALPHA_BOOTSTRAP_SPIRE_SERVER_COMMAND="${REMOTE_ALPHA_BOOTSTRAP_SPIRE_SERVER_COMMAND:-spire-server}"
  REMOTE_ALPHA_BOOTSTRAP_BOUND_ISSUER="${REMOTE_ALPHA_BOOTSTRAP_BOUND_ISSUER:-spiffe://execution.internal}"
}

remote_alpha_vault_workload_auth_bootstrap_usage() {
  cat <<'EOF'
Usage:
  scripts/remote_alpha_vault_workload_auth_bootstrap.sh
  scripts/remote_alpha_vault_workload_auth_bootstrap.sh --help

Purpose:
  Configure the Remote Alpha Vault workload-auth objects documented by the ES
  recovery-session bootstrap contract.

Secret posture:
  The human operator enters Vault bootstrap authority and the proof secret
  value only through visible/silent prompts on the remote TTY.
  Root tokens, Vault tokens, proof secret values, JWT-SVID payloads, API keys,
  private keys, passwords, and secret payloads are never accepted through CLI
  args, environment variables, files, logs, summaries, reports, .out, support
  bundles, retained bundles, CP artifacts, transcripts, tee, script, or Codex
  output.

Vault API strategy:
  This helper uses an in-process Python HTTPS client. It does not use
  VAULT_TOKEN, vault login, Vault CLI token files, token-bearing CLI args,
  tee, script, or transcript capture.

Configured objects:
  auth mount jwt
  auth/jwt/config with SPIRE JWT validation material and bound issuer
  role service_execution
  policy runtime-identity-proof
  KV v2 proof paths proof-secrets/data/runtime-identity-vault-login and
  proof-secrets/data/codex-runtime-profile
  proof runtime field api_key present and non-empty, value never printed
  workload-zone config alignment at
  /etc/execution-substrate/vault/workload-zone-vault-config.json

Summary:
  Remote-only non-secret summary:
  /var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json
  The helper preflights summary writability and workload-zone config readability
  before any secret prompt, SPIRE query, or Vault write. It then preflights the
  fixed SPIRE server bundle-read command needed for JWT validation material
  before any secret prompt or Vault write. If a preflight fails, it fails before
  prompts with non-secret classification such as summary_preflight_failed,
  config_unreadable, or spire_bundle_show_failed. After summary preflight,
  failure summaries record only safe phase/class labels and never raw
  exceptions, raw SPIRE/Vault output, bundle contents, headers, config contents,
  or operator-entered prompt values.

Non-claims:
  This helper does not run workload-auth checks, reset, unseal, IM refresh,
  support-bundle collection, CP proof, runtime identity generation, governed
  smoke, or readiness validation. It does not claim workload-auth success,
  runtime-profile readiness, submit readiness, Vault production readiness, or
  Remote Alpha deployment/provisioning/reconciliation architecture.
EOF
}

remote_alpha_vault_workload_auth_bootstrap_reject_secret_env() {
  local name
  for name in VAULT_TOKEN ROOT_TOKEN REMOTE_ALPHA_BOOTSTRAP_ROOT_TOKEN REMOTE_ALPHA_BOOTSTRAP_VAULT_TOKEN REMOTE_ALPHA_BOOTSTRAP_PROOF_SECRET_VALUE REMOTE_ALPHA_PROOF_SECRET_VALUE; do
    if [[ -n "${!name:-}" ]]; then
      printf 'error: %s must not be supplied through the environment; use the remote TTY prompt only\n' "${name}" >&2
      return 2
    fi
  done
}

remote_alpha_vault_workload_auth_bootstrap_parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --help|-h)
        remote_alpha_vault_workload_auth_bootstrap_usage
        return 64
        ;;
      --root-token|--root-token=*|--unseal-key|--unseal-key=*|--client-token|--client-token=*|--vault-token|--vault-token=*|--api-key|--api-key=*|--jwt-svid|--jwt-svid=*|--private-key|--private-key=*|--password|--password=*|--secret|--secret=*|--proof-secret-value|--proof-secret-value=*|--proof-runtime-secret-value|--proof-runtime-secret-value=*|--secret-value|--secret-value=*)
        printf 'error: secret material must never be supplied through helper CLI arguments\n' >&2
        return 2
        ;;
      *=*)
        printf 'error: env-like assignments are not accepted as helper arguments; use documented non-secret environment configuration only\n' >&2
        return 2
        ;;
      --*)
        printf 'error: unknown argument: %s\n' "$1" >&2
        return 2
        ;;
      *)
        printf 'error: unexpected positional argument: %s\n' "$1" >&2
        return 2
        ;;
    esac
  done
}

remote_alpha_vault_workload_auth_bootstrap_require_command() {
  local name=$1
  if ! command -v "${name}" >/dev/null 2>&1; then
    printf '%s is required\n' "${name}" >&2
    return 1
  fi
}

remote_alpha_vault_workload_auth_bootstrap_validate_summary_file() {
  local summary_path=$1
  shift || true

  python3 - "${summary_path}" "$@" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
secret_values = [value for value in sys.argv[2:] if value]
text = path.read_text(encoding="utf-8")

for value in secret_values:
    if value and value in text:
        print("error: summary contains operator-entered secret material", file=sys.stderr)
        raise SystemExit(1)

patterns = [
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"\b(?:hvs|hvb|s)\.[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\b(?:xox[baprs]-[A-Za-z0-9-]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9]{20,})\b"),
]
for pattern in patterns:
    if pattern.search(text):
        print("error: summary contains secret-like material", file=sys.stderr)
        raise SystemExit(1)
PY
}

remote_alpha_vault_workload_auth_bootstrap_execute() {
  python3 - \
    "${REMOTE_ALPHA_BOOTSTRAP_WORKLOAD_ZONE_CONFIG_PATH}" \
    "${REMOTE_ALPHA_BOOTSTRAP_SUMMARY_PATH}" \
    "${REMOTE_ALPHA_BOOTSTRAP_SPIRE_SERVER_SOCKET_PATH}" \
    "${REMOTE_ALPHA_BOOTSTRAP_SPIRE_SERVER_COMMAND}" \
    "${REMOTE_ALPHA_BOOTSTRAP_BOUND_ISSUER}" \
    "${remote_alpha_vault_workload_auth_bootstrap_schema_version}" <<'PY'
import base64
import datetime as dt
import getpass
import hashlib
import json
import os
import pathlib
import re
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

CONFIG_PATH = pathlib.Path(sys.argv[1])
SUMMARY_PATH = pathlib.Path(sys.argv[2])
SPIRE_SOCKET = sys.argv[3]
SPIRE_COMMAND = sys.argv[4]
BOUND_ISSUER = sys.argv[5]
SCHEMA_VERSION = sys.argv[6]

AUTH_MOUNT = "jwt"
ROLE = "service_execution"
AUDIENCE = "vault"
WORKLOAD_SUBJECT = "spiffe://execution.internal/workload"
POLICY_NAME = "runtime-identity-proof"
PROOF_READ_PATH = "proof-secrets/data/runtime-identity-vault-login"
PROOF_RUNTIME_SECRET_PATH = "proof-secrets/data/codex-runtime-profile"
PROOF_RUNTIME_SECRET_FIELD = "api_key"
PROOF_READ_FIELD = "message"


def trust_domain_from_spiffe_id(value):
    prefix = "spiffe://"
    text = str(value or "").strip()
    if not text.startswith(prefix):
        return ""
    return text[len(prefix) :].split("/", 1)[0].strip()


WORKLOAD_TRUST_DOMAIN = trust_domain_from_spiffe_id(WORKLOAD_SUBJECT) or "unknown"


def utc_now():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


summary = {
    "schema_version": SCHEMA_VERSION,
    "generated_at": utc_now(),
    "operation_mode": "execute_bootstrap",
    "configured_objects": {
        "auth_mount": AUTH_MOUNT,
        "jwt_auth_config": f"auth/{AUTH_MOUNT}/config",
        "role": ROLE,
        "policy": POLICY_NAME,
        "kv_v2_mount": "proof-secrets",
        "proof_paths": [
            PROOF_READ_PATH,
            PROOF_RUNTIME_SECRET_PATH,
        ],
        "proof_runtime_secret_field_label": PROOF_RUNTIME_SECRET_FIELD,
        "workload_zone_config_path": str(CONFIG_PATH),
        "bound_issuer": BOUND_ISSUER,
        "bound_subject": WORKLOAD_SUBJECT,
        "validation_trust_domain": WORKLOAD_TRUST_DOMAIN,
        "bound_audiences": [AUDIENCE],
    },
    "operations": {},
    "secret_prompts_started": False,
    "vault_operations_started": False,
    "last_completed_operation": None,
    "next_operation": "summary_preflight",
    "redaction": {
        "root_token_recorded": False,
        "vault_token_recorded": False,
        "proof_secret_value_recorded": False,
        "jwt_svid_recorded": False,
        "api_key_value_recorded": False,
        "raw_vault_output_recorded": False,
        "raw_http_headers_recorded": False,
        "transcript_recorded": False,
        "operator_prompt_values_recorded": False,
    },
    "readiness_not_claimed": [
        "workload_auth_success",
        "runtime_profile_ready",
        "submit_ready",
        "vault_production_readiness",
        "governed_execution_proof",
        "im_authority",
        "cp_recovery_authority",
    ],
    "non_authority_labels": [
        "evidence_projection_only",
        "not_es_vault_token_brokerage",
        "not_remote_alpha_deployment_architecture",
    ],
}


class BootstrapFailure(Exception):
    def __init__(self, phase, failure_class, message_class=None, exit_code=1):
        super().__init__(phase)
        self.phase = phase
        self.failure_class = failure_class
        self.message_class = message_class
        self.exit_code = exit_code


class VaultAPIError(Exception):
    def __init__(self, failure_class, message_class):
        super().__init__(message_class)
        self.failure_class = failure_class
        self.message_class = message_class


def set_status(name, status, **extra):
    payload = {"status": status}
    payload.update(extra)
    summary["operations"][name] = payload
    if status == "pass":
        summary["last_completed_operation"] = name
        summary["next_operation"] = None


def set_next_operation(name):
    summary["next_operation"] = name


def safe_message_class(exc):
    name = type(exc).__name__
    name = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    cleaned = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").lower()
    return cleaned or "exception"


def vault_http_failure_class(status):
    if status == 401:
        return "vault_auth_failed"
    if status == 403:
        return "vault_permission_denied"
    return "vault_api_error"


def classify_exception(exc):
    if isinstance(exc, BootstrapFailure):
        return exc.failure_class, exc.message_class or "bootstrap_failure"
    if isinstance(exc, VaultAPIError):
        return exc.failure_class, exc.message_class
    if isinstance(exc, urllib.error.HTTPError):
        return vault_http_failure_class(exc.code), f"http_{exc.code}"
    if isinstance(exc, urllib.error.URLError):
        reason = getattr(exc, "reason", None)
        if isinstance(reason, ssl.SSLError):
            return "vault_tls_error", "tls_error"
        return "vault_unreachable", "url_error"
    if isinstance(exc, ssl.SSLError):
        return "vault_tls_error", "tls_error"
    if isinstance(exc, (json.JSONDecodeError, ValueError)):
        return "invalid_response", safe_message_class(exc)
    return "unexpected_exception", safe_message_class(exc)


def record_failure(phase, failure_class, operation=None, message_class=None):
    safe_phase = phase or "unexpected"
    safe_operation = operation or safe_phase
    summary["overall_status"] = "fail"
    summary["failure_phase"] = safe_phase
    summary["failure_class"] = failure_class
    if message_class:
        summary["failure_message_class"] = message_class
    if summary.get("next_operation") is None:
        summary["next_operation"] = safe_phase
    set_status(safe_operation, "fail", error_classification=failure_class)


def raise_failure(phase, failure_class, operation=None, message_class=None, exit_code=1):
    record_failure(phase, failure_class, operation=operation, message_class=message_class)
    raise BootstrapFailure(phase, failure_class, message_class=message_class, exit_code=exit_code)


def fail_from_exception(phase, exc, operation=None):
    failure_class, message_class = classify_exception(exc)
    raise_failure(phase, failure_class, operation=operation, message_class=message_class)


class SummaryPreflightError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def cleanup_path(path):
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except Exception:
        pass


def preflight_summary_writable():
    parent = SUMMARY_PATH.parent
    preflight_temp = parent / f".{SUMMARY_PATH.name}.preflight.{os.getpid()}.tmp"

    try:
        if parent.exists() and not parent.is_dir():
            raise SummaryPreflightError("summary_parent_not_directory")
        try:
            parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError:
            raise SummaryPreflightError("summary_parent_create_failed")
        if not os.access(parent, os.W_OK | os.X_OK):
            raise SummaryPreflightError("summary_parent_not_writable")
        if SUMMARY_PATH.exists():
            if not SUMMARY_PATH.is_file():
                raise SummaryPreflightError("summary_path_not_regular")
            if not os.access(SUMMARY_PATH, os.W_OK):
                raise SummaryPreflightError("summary_path_not_writable")
        try:
            fd = os.open(str(preflight_temp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except OSError:
            raise SummaryPreflightError("summary_temp_create_failed")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write("summary_preflight=pass\n")
        except OSError:
            cleanup_path(preflight_temp)
            raise SummaryPreflightError("summary_temp_write_failed")
        try:
            preflight_temp.unlink()
        except OSError:
            raise SummaryPreflightError("summary_temp_cleanup_failed")
        set_status("summary_preflight", "pass", path=str(SUMMARY_PATH), parent=str(parent))
    except SummaryPreflightError:
        cleanup_path(preflight_temp)
        raise


def report_summary_preflight_failure(reason):
    print("Remote Alpha Vault workload-auth bootstrap preflight failed.")
    print("failure_class=summary_preflight_failed")
    print(f"error_classification={reason}")
    print(f"summary_path={SUMMARY_PATH}")
    print(f"summary_parent={SUMMARY_PATH.parent}")
    print("No Vault bootstrap prompts were read and no Vault writes were attempted.")


def preflight_config_readable():
    set_next_operation("config_load")
    try:
        if not CONFIG_PATH.exists():
            raise_failure("config_load", "config_missing")
        if not CONFIG_PATH.is_file():
            raise_failure("config_load", "config_invalid", message_class="config_path_not_regular")
        if not os.access(CONFIG_PATH, os.R_OK):
            raise_failure("config_load", "config_unreadable", message_class="permission_denied")
        try:
            with CONFIG_PATH.open("rb") as handle:
                handle.read(1)
        except PermissionError:
            raise_failure("config_load", "config_unreadable", message_class="permission_error")
        except OSError:
            raise_failure("config_load", "config_unreadable", message_class="read_error")
    except BootstrapFailure:
        raise


def load_config():
    set_next_operation("config_load")
    try:
        raw = CONFIG_PATH.read_bytes()
    except FileNotFoundError:
        raise_failure("config_load", "config_missing")
    except PermissionError:
        raise_failure("config_load", "config_unreadable", message_class="permission_error")
    except OSError:
        raise_failure("config_load", "config_unreadable", message_class="read_error")
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        raise_failure("config_load", "config_invalid", message_class="invalid_json")
    vault = payload.get("vault_config")
    if not isinstance(vault, dict):
        raise_failure("config_load", "config_invalid", message_class="missing_vault_config")
    address = str(vault.get("address") or "").strip()
    auth_mount = str(vault.get("auth_mount") or "").strip()
    auth_role = str(vault.get("auth_role") or "").strip()
    jwt_audience = str(vault.get("jwt_audience") or "").strip()
    ca_bundle_pem = str(vault.get("ca_bundle_pem") or "").strip()
    parsed = urllib.parse.urlparse(address)
    if parsed.scheme != "https" or not parsed.netloc:
        raise_failure("config_load", "config_invalid", message_class="vault_address_not_https")
    expected = {
        "auth_mount": (auth_mount, AUTH_MOUNT),
        "auth_role": (auth_role, ROLE),
        "jwt_audience": (jwt_audience, AUDIENCE),
    }
    for field, (actual, wanted) in expected.items():
        if actual != wanted:
            raise_failure("config_load", "config_invalid", message_class=f"{field}_mismatch")
    set_status("config_load", "pass", path=str(CONFIG_PATH), digest=digest)
    set_status("workload_zone_config", "pass", path=str(CONFIG_PATH), digest=digest)
    return address.rstrip("/"), ca_bundle_pem


def der_len(length):
    if length < 128:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def der_tlv(tag, body):
    return bytes([tag]) + der_len(len(body)) + body


def der_integer(value):
    raw = int(value).to_bytes((int(value).bit_length() + 7) // 8 or 1, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return der_tlv(0x02, raw)


def rsa_public_key_pem(n_b64, e_b64):
    n = int.from_bytes(base64.urlsafe_b64decode(n_b64 + "=" * (-len(n_b64) % 4)), "big")
    e = int.from_bytes(base64.urlsafe_b64decode(e_b64 + "=" * (-len(e_b64) % 4)), "big")
    rsa_public = der_tlv(0x30, der_integer(n) + der_integer(e))
    rsa_oid = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"
    alg_id = der_tlv(0x30, rsa_oid + der_tlv(0x05, b""))
    bit_string = der_tlv(0x03, b"\x00" + rsa_public)
    spki = der_tlv(0x30, alg_id + bit_string)
    b64 = base64.b64encode(spki).decode("ascii")
    lines = ["-----BEGIN PUBLIC KEY-----"]
    lines.extend(b64[i : i + 64] for i in range(0, len(b64), 64))
    lines.append("-----END PUBLIC KEY-----")
    return "\n".join(lines) + "\n"


def spire_bundle_validation_keys(payload):
    trust_domains = payload.get("trust_domains")
    if isinstance(trust_domains, dict):
        for label in (WORKLOAD_TRUST_DOMAIN, f"spiffe://{WORKLOAD_TRUST_DOMAIN}"):
            bundle = trust_domains.get(label)
            if not isinstance(bundle, dict):
                continue
            keys = bundle.get("keys")
            if not isinstance(keys, list):
                raise_failure(
                    "jwt_auth_config",
                    "invalid_response",
                    operation="spire_jwt_validation_material",
                    message_class="jwt_validation_trust_domain_missing_keys",
                )
            return keys, "spiffe_bundle_map_workload_trust_domain", label, len(trust_domains)
        raise_failure(
            "jwt_auth_config",
            "invalid_response",
            operation="spire_jwt_validation_material",
            message_class="jwt_validation_trust_domain_missing",
        )

    keys = payload.get("keys")
    if isinstance(keys, list):
        return keys, "spiffe_bundle_direct_workload_trust_domain", WORKLOAD_TRUST_DOMAIN, 1

    raise_failure(
        "jwt_auth_config",
        "invalid_response",
        operation="spire_jwt_validation_material",
        message_class="spire_bundle_missing_keys",
    )


def extract_jwt_validation_pubkey():
    set_next_operation("jwt_auth_config")
    try:
        proc = subprocess.run(
            [SPIRE_COMMAND, "bundle", "show", "-format", "spiffe", "-socketPath", SPIRE_SOCKET],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except FileNotFoundError:
        raise_failure("jwt_auth_config", "invalid_response", operation="spire_jwt_validation_material", message_class="spire_server_command_missing")
    except subprocess.CalledProcessError:
        raise_failure("jwt_auth_config", "invalid_response", operation="spire_jwt_validation_material", message_class="spire_bundle_show_failed")
    try:
        payload = json.loads(proc.stdout)
    except Exception:
        raise_failure("jwt_auth_config", "invalid_response", operation="spire_jwt_validation_material", message_class="spire_bundle_json_invalid")
    if not isinstance(payload, dict):
        raise_failure("jwt_auth_config", "invalid_response", operation="spire_jwt_validation_material", message_class="spire_bundle_json_not_object")

    candidates, source_label, selected_trust_domain, trust_domain_count = spire_bundle_validation_keys(payload)
    jwt_svid_rsa_keys = []
    for key in candidates:
        if not isinstance(key, dict):
            continue
        if key.get("use") == "jwt-svid" and key.get("kty") == "RSA" and key.get("n") and key.get("e"):
            jwt_svid_rsa_keys.append(key)
    if jwt_svid_rsa_keys:
        key = jwt_svid_rsa_keys[0]
        pem = rsa_public_key_pem(str(key["n"]), str(key["e"]))
        set_status(
            "spire_jwt_validation_material",
            "pass",
            source="spire-server bundle show -format spiffe",
            validation_material_source=source_label,
            selected_trust_domain=selected_trust_domain,
            trust_domain_count=trust_domain_count,
            key_count=len(candidates),
            jwt_svid_rsa_key_count=len(jwt_svid_rsa_keys),
            vault_jwt_config_shape="jwt_validation_pubkeys_array_pem_bound_issuer",
            public_key_digest="sha256:" + hashlib.sha256(pem.encode("utf-8")).hexdigest(),
        )
        return pem
    raise_failure("jwt_auth_config", "invalid_response", operation="spire_jwt_validation_material", message_class="no_jwt_svid_rsa_key")


def preflight_spire_bundle_read():
    return extract_jwt_validation_pubkey()


def make_opener(ca_bundle_pem):
    set_next_operation("vault_client_init")
    try:
        if ca_bundle_pem:
            context = ssl.create_default_context(cadata=ca_bundle_pem)
        else:
            context = ssl.create_default_context()
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
    except Exception as exc:
        fail_from_exception("vault_client_init", exc)
    set_status("vault_client_init", "pass")
    return opener


def vault_request(opener, token, method, address, path, payload=None, allowed_statuses=(200, 204)):
    summary["vault_operations_started"] = True
    body = None
    headers = {
        "Accept": "application/json",
        "X-Vault-Token": token,
    }
    if payload is not None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(address + "/v1/" + path.lstrip("/"), data=body, headers=headers, method=method)
    try:
        with opener.open(request, timeout=10) as response:
            raw = response.read().decode("utf-8", errors="replace")
            status = response.status
    except urllib.error.HTTPError as exc:
        exc.read()
        if exc.code not in allowed_statuses:
            raise VaultAPIError(vault_http_failure_class(exc.code), f"http_{exc.code}") from None
        return {}
    except urllib.error.URLError as exc:
        failure_class, message_class = classify_exception(exc)
        raise VaultAPIError(failure_class, message_class) from None
    if status not in allowed_statuses:
        raise VaultAPIError(vault_http_failure_class(status), f"http_{status}")
    if not raw.strip():
        return {}
    try:
        return json.loads(raw)
    except Exception:
        raise VaultAPIError("invalid_response", "invalid_json") from None


def mount_from_kv_path(path):
    marker = "/data/"
    if marker not in path:
        raise ValueError("path_not_kv_v2_data_path")
    return path.split(marker, 1)[0]


def ensure_auth_mount(opener, token, address):
    phase = "jwt_auth_mount"
    set_next_operation(phase)
    try:
        payload = vault_request(opener, token, "GET", address, "sys/auth")
        if f"{AUTH_MOUNT}/" in payload:
            set_status(phase, "pass", mount=AUTH_MOUNT, already_present=True)
            return
        vault_request(opener, token, "POST", address, f"sys/auth/{AUTH_MOUNT}", {"type": "jwt"}, allowed_statuses=(200, 204))
        set_status(phase, "pass", mount=AUTH_MOUNT, already_present=False)
    except Exception as exc:
        fail_from_exception(phase, exc)


def ensure_kv_mount(opener, token, address):
    phase = "kv_v2_mount"
    set_next_operation(phase)
    mount = mount_from_kv_path(PROOF_READ_PATH)
    if mount != mount_from_kv_path(PROOF_RUNTIME_SECRET_PATH):
        raise_failure(phase, "config_invalid", message_class="proof_paths_use_different_mounts")
    try:
        payload = vault_request(opener, token, "GET", address, "sys/mounts")
        if f"{mount}/" in payload:
            set_status(phase, "pass", mount=mount, already_present=True)
            return mount
        vault_request(opener, token, "POST", address, f"sys/mounts/{mount}", {"type": "kv", "options": {"version": "2"}}, allowed_statuses=(200, 204))
        set_status(phase, "pass", mount=mount, already_present=False)
        return mount
    except Exception as exc:
        fail_from_exception(phase, exc)


def configure_policy(opener, token, address):
    phase = "runtime_identity_policy"
    set_next_operation(phase)
    policy = f'''path "{PROOF_READ_PATH}" {{
  capabilities = ["read"]
}}

path "{PROOF_RUNTIME_SECRET_PATH}" {{
  capabilities = ["read"]
}}
'''
    try:
        vault_request(opener, token, "PUT", address, f"sys/policies/acl/{POLICY_NAME}", {"policy": policy}, allowed_statuses=(200, 204))
        set_status(phase, "pass", policy_name=POLICY_NAME, digest="sha256:" + hashlib.sha256(policy.encode("utf-8")).hexdigest())
    except Exception as exc:
        fail_from_exception(phase, exc)


def configure_jwt(opener, token, address, validation_pubkey):
    phase = "jwt_auth_config"
    set_next_operation(phase)
    try:
        vault_request(
            opener,
            token,
            "POST",
            address,
            f"auth/{AUTH_MOUNT}/config",
            {"jwt_validation_pubkeys": [validation_pubkey], "bound_issuer": BOUND_ISSUER},
            allowed_statuses=(200, 204),
        )
        set_status(
            phase,
            "pass",
            auth_mount=AUTH_MOUNT,
            bound_issuer=BOUND_ISSUER,
            validation_material_field="jwt_validation_pubkeys",
            vault_jwt_config_shape="jwt_validation_pubkeys_array_pem_bound_issuer",
        )
    except Exception as exc:
        fail_from_exception(phase, exc)


def configure_role(opener, token, address):
    phase = "service_execution_role"
    set_next_operation(phase)
    try:
        vault_request(
            opener,
            token,
            "POST",
            address,
            f"auth/{AUTH_MOUNT}/role/{ROLE}",
            {
                "role_type": "jwt",
                "user_claim": "sub",
                "bound_audiences": [AUDIENCE],
                "bound_subject": WORKLOAD_SUBJECT,
                "token_policies": [POLICY_NAME],
            },
            allowed_statuses=(200, 204),
        )
        set_status(phase, "pass", role=ROLE, role_type="jwt", user_claim="sub")
    except Exception as exc:
        fail_from_exception(phase, exc)


def write_proof_secrets(opener, token, address, proof_secret):
    phase = "proof_secret_runtime_identity_vault_login"
    set_next_operation(phase)
    try:
        vault_request(
            opener,
            token,
            "POST",
            address,
            PROOF_READ_PATH,
            {"data": {PROOF_READ_FIELD: proof_secret}},
            allowed_statuses=(200, 204),
        )
        set_status(phase, "pass", path=PROOF_READ_PATH, field_label=PROOF_READ_FIELD, value_recorded=False)
    except Exception as exc:
        fail_from_exception(phase, exc)

    phase = "proof_secret_codex_runtime_profile"
    set_next_operation(phase)
    try:
        vault_request(
            opener,
            token,
            "POST",
            address,
            PROOF_RUNTIME_SECRET_PATH,
            {"data": {PROOF_RUNTIME_SECRET_FIELD: proof_secret}},
            allowed_statuses=(200, 204),
        )
        set_status(phase, "pass", path=PROOF_RUNTIME_SECRET_PATH, field_label=PROOF_RUNTIME_SECRET_FIELD, value_recorded=False)
    except Exception as exc:
        fail_from_exception(phase, exc)


def validate_summary_no_secrets(text, secrets):
    for value in secrets:
        if value and value in text:
            raise RuntimeError("summary_contains_operator_secret")
    patterns = [
        "-----BEGIN PRIVATE KEY-----",
        " hvs.",
        " hvb.",
        " sk-",
    ]
    if any(pattern in text for pattern in patterns):
        raise RuntimeError("summary_contains_secret_like_material")


def write_summary(secrets=()):
    text = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    try:
        validate_summary_no_secrets(text, secrets)
    except Exception:
        record_failure("final_redaction", "redaction_blocked", message_class="summary_redaction_failed")
        raise
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=str(SUMMARY_PATH.parent),
            prefix=f"{SUMMARY_PATH.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_path = pathlib.Path(handle.name)
            handle.write(text)
        os.chmod(temp_path, 0o600)
        temp_path.replace(SUMMARY_PATH)
    except Exception:
        if temp_path is not None:
            cleanup_path(temp_path)
        record_failure("summary_write", "summary_write_failed", message_class="summary_write_failed")
        raise


def prompt_secret(prompt):
    return getpass.getpass(prompt=prompt)


def main():
    address = ""
    ca_bundle_pem = ""
    validation_pubkey = ""
    root_token = ""
    proof_secret = ""
    exit_code = 0
    secret_values_for_scan = []
    try:
        preflight_summary_writable()
    except SummaryPreflightError as exc:
        report_summary_preflight_failure(exc.reason)
        return 1

    try:
        preflight_config_readable()
        address, ca_bundle_pem = load_config()
        validation_pubkey = preflight_spire_bundle_read()
        set_next_operation("prompt_bootstrap_authority")
        summary["secret_prompts_started"] = True
        try:
            root_token = prompt_secret("Vault bootstrap authority token (input hidden; not logged): ").strip()
        except KeyboardInterrupt:
            raise_failure("prompt_bootstrap_authority", "prompt_interrupted", message_class="keyboard_interrupt")
        except (EOFError, OSError):
            raise_failure("prompt_bootstrap_authority", "prompt_unavailable", message_class="prompt_unavailable")
        except Exception as exc:
            failure_class, message_class = classify_exception(exc)
            if failure_class == "unexpected_exception":
                failure_class = "prompt_unavailable"
            raise_failure("prompt_bootstrap_authority", failure_class, message_class=message_class)
        if not root_token:
            raise_failure("prompt_bootstrap_authority", "prompt_unavailable", message_class="empty_prompt")
        set_status("prompt_bootstrap_authority", "pass", prompt_source="remote_tty", value_recorded=False)
        set_next_operation("prompt_proof_secret")
        try:
            proof_secret = prompt_secret("Proof secret value for runtime proof paths (input hidden; not logged): ")
        except KeyboardInterrupt:
            raise_failure("prompt_proof_secret", "prompt_interrupted", message_class="keyboard_interrupt")
        except (EOFError, OSError):
            raise_failure("prompt_proof_secret", "prompt_unavailable", message_class="prompt_unavailable")
        except Exception as exc:
            failure_class, message_class = classify_exception(exc)
            if failure_class == "unexpected_exception":
                failure_class = "prompt_unavailable"
            raise_failure("prompt_proof_secret", failure_class, message_class=message_class)
        if not proof_secret:
            raise_failure("prompt_proof_secret", "prompt_unavailable", message_class="empty_prompt")
        set_status("prompt_proof_secret", "pass", prompt_source="remote_tty", value_recorded=False)
        secret_values_for_scan = [root_token, proof_secret]

        opener = make_opener(ca_bundle_pem)
        ensure_auth_mount(opener, root_token, address)
        ensure_kv_mount(opener, root_token, address)
        configure_policy(opener, root_token, address)
        configure_jwt(opener, root_token, address, validation_pubkey)
        configure_role(opener, root_token, address)
        write_proof_secrets(opener, root_token, address, proof_secret)
        summary["overall_status"] = "pass"
    except BootstrapFailure as exc:
        summary["overall_status"] = "fail"
        exit_code = exc.exit_code
    except SystemExit as exc:
        if "failure_phase" not in summary:
            phase = summary.get("next_operation") or "unexpected"
            record_failure(phase, "unexpected_exception", message_class="system_exit")
        summary["overall_status"] = "fail"
        exit_code = int(exc.code or 1)
    except Exception as exc:
        if "failure_phase" not in summary:
            phase = summary.get("next_operation") or "unexpected"
            failure_class, message_class = classify_exception(exc)
            record_failure(phase, failure_class, message_class=message_class)
        summary["overall_status"] = "fail"
        exit_code = 1
    finally:
        try:
            write_summary(secret_values_for_scan)
        except Exception:
            exit_code = 1
        root_token = None
        proof_secret = None
        validation_pubkey = None

    print("Remote Alpha Vault workload-auth bootstrap helper finished.")
    print(f"Remote summary path: {SUMMARY_PATH}")
    print("Summary is non-secret evidence/projection only and was not copied to Mac .out.")
    print("Workload-auth check, reset/unseal, IM refresh, support-bundle collection, CP proof, and runtime identity generation were not run.")
    print("Non-claims: not workload-auth success, not runtime-profile readiness, not submit readiness, not Vault production readiness, not ES Vault token brokerage.")
    return exit_code


raise SystemExit(main())
PY
}

remote_alpha_vault_workload_auth_bootstrap_main() {
  remote_alpha_vault_workload_auth_bootstrap_defaults
  local parse_status
  set +e
  remote_alpha_vault_workload_auth_bootstrap_parse_args "$@"
  parse_status=$?
  set -e
  if [[ "${parse_status}" -eq 64 ]]; then
    return 0
  fi
  if [[ "${parse_status}" -ne 0 ]]; then
    return "${parse_status}"
  fi
  remote_alpha_vault_workload_auth_bootstrap_reject_secret_env || return $?
  remote_alpha_vault_workload_auth_bootstrap_require_command python3 || return 1
  remote_alpha_vault_workload_auth_bootstrap_execute
}
