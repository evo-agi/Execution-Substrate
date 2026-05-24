remote_alpha_vault_summary_schema_version="execution-substrate.remote-alpha.vault-workload-auth-summary.v1"

remote_alpha_vault_workload_auth_defaults() {
  REMOTE_ALPHA_VAULT_ADDRESS="${REMOTE_ALPHA_VAULT_ADDRESS:-https://172.17.0.1:8200}"
  REMOTE_ALPHA_VAULT_AUTH_MOUNT="${REMOTE_ALPHA_VAULT_AUTH_MOUNT:-jwt}"
  REMOTE_ALPHA_VAULT_ROLE="${REMOTE_ALPHA_VAULT_ROLE:-service_execution}"
  REMOTE_ALPHA_VAULT_AUDIENCE="${REMOTE_ALPHA_VAULT_AUDIENCE:-vault}"
  REMOTE_ALPHA_WORKLOAD_SPIFFE_ID="${REMOTE_ALPHA_WORKLOAD_SPIFFE_ID:-spiffe://execution.internal/workload}"
  REMOTE_ALPHA_WORKLOAD_ZONE_CONFIG_PATH="${REMOTE_ALPHA_WORKLOAD_ZONE_CONFIG_PATH:-/etc/execution-substrate/vault/workload-zone-vault-config.json}"
  REMOTE_ALPHA_SUMMARY_PATH="${REMOTE_ALPHA_SUMMARY_PATH:-/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-summary.json}"
  REMOTE_ALPHA_SPIRE_AGENT_SOCKET_PATH="${REMOTE_ALPHA_SPIRE_AGENT_SOCKET_PATH:-/run/spire/sockets/agent.sock}"
  REMOTE_ALPHA_SPIRE_SERVER_SOCKET_PATH="${REMOTE_ALPHA_SPIRE_SERVER_SOCKET_PATH:-/run/spire/server/private/api.sock}"
  REMOTE_ALPHA_VAULT_SERVICE_NAME="${REMOTE_ALPHA_VAULT_SERVICE_NAME:-vault}"
  REMOTE_ALPHA_SPIRE_AGENT_SERVICE_NAME="${REMOTE_ALPHA_SPIRE_AGENT_SERVICE_NAME:-spire-agent}"
  REMOTE_ALPHA_SPIRE_SERVER_SERVICE_NAME="${REMOTE_ALPHA_SPIRE_SERVER_SERVICE_NAME:-spire-server}"
  REMOTE_ALPHA_PROOF_READ_PATH="${REMOTE_ALPHA_PROOF_READ_PATH:-proof-secrets/data/runtime-identity-vault-login}"
  REMOTE_ALPHA_PROOF_RUNTIME_SECRET_PATH="${REMOTE_ALPHA_PROOF_RUNTIME_SECRET_PATH:-proof-secrets/data/codex-runtime-profile}"
  REMOTE_ALPHA_PROOF_RUNTIME_SECRET_FIELD="${REMOTE_ALPHA_PROOF_RUNTIME_SECRET_FIELD:-api_key}"
  REMOTE_ALPHA_CONTAINER_PROBE_IMAGE="${REMOTE_ALPHA_CONTAINER_PROBE_IMAGE:-}"
}

remote_alpha_vault_workload_auth_usage() {
  cat <<'EOF'
Usage:
  sudo scripts/remote_alpha_vault_workload_auth_check.sh

Optional flags:
  --vault-address <https://host:port>
  --auth-mount <mount>
  --role <role>
  --audience <audience>
  --workload-spiffe-id <spiffe://...>
  --workload-zone-config-path </path/to/workload-zone-vault-config.json>
  --summary-path </path/to/vault-workload-auth-summary.json>
  --proof-read-path <vault logical path>
  --proof-runtime-secret-path <vault logical path>
  --proof-runtime-secret-field <field name>
  --container-probe-image <pre-existing curlimages/curl style image>
  --spire-agent-socket-path </run/spire/sockets/agent.sock>
  --spire-server-socket-path </run/spire/server/private/api.sock>
  --help
EOF
}

remote_alpha_vault_workload_auth_parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --vault-address)
        REMOTE_ALPHA_VAULT_ADDRESS="$2"
        shift 2
        ;;
      --auth-mount)
        REMOTE_ALPHA_VAULT_AUTH_MOUNT="$2"
        shift 2
        ;;
      --role)
        REMOTE_ALPHA_VAULT_ROLE="$2"
        shift 2
        ;;
      --audience)
        REMOTE_ALPHA_VAULT_AUDIENCE="$2"
        shift 2
        ;;
      --workload-spiffe-id)
        REMOTE_ALPHA_WORKLOAD_SPIFFE_ID="$2"
        shift 2
        ;;
      --workload-zone-config-path)
        REMOTE_ALPHA_WORKLOAD_ZONE_CONFIG_PATH="$2"
        shift 2
        ;;
      --summary-path)
        REMOTE_ALPHA_SUMMARY_PATH="$2"
        shift 2
        ;;
      --proof-read-path)
        REMOTE_ALPHA_PROOF_READ_PATH="$2"
        shift 2
        ;;
      --proof-runtime-secret-path)
        REMOTE_ALPHA_PROOF_RUNTIME_SECRET_PATH="$2"
        shift 2
        ;;
      --proof-runtime-secret-field)
        REMOTE_ALPHA_PROOF_RUNTIME_SECRET_FIELD="$2"
        shift 2
        ;;
      --container-probe-image)
        REMOTE_ALPHA_CONTAINER_PROBE_IMAGE="$2"
        shift 2
        ;;
      --spire-agent-socket-path)
        REMOTE_ALPHA_SPIRE_AGENT_SOCKET_PATH="$2"
        shift 2
        ;;
      --spire-server-socket-path)
        REMOTE_ALPHA_SPIRE_SERVER_SOCKET_PATH="$2"
        shift 2
        ;;
      --help|-h)
        remote_alpha_vault_workload_auth_usage
        return 1
        ;;
      *)
        echo "unknown argument: $1" >&2
        remote_alpha_vault_workload_auth_usage >&2
        return 2
        ;;
    esac
  done
}

remote_alpha_vault_require_root() {
  if [[ "$(id -u)" != "0" ]]; then
    echo "remote alpha Vault/workload-auth check must run as root; use sudo scripts/remote_alpha_vault_workload_auth_check.sh" >&2
    return 1
  fi
}

remote_alpha_vault_require_command() {
  local name=$1
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "${name} is required" >&2
    return 1
  fi
}

remote_alpha_vault_json_field() {
  local json_path=$1
  local dotted_path=$2

  python3 - "${json_path}" "${dotted_path}" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
value = payload
for part in sys.argv[2].split("."):
    if isinstance(value, dict):
        value = value.get(part)
    else:
        value = None
        break
if value is None:
    sys.exit(1)
if isinstance(value, bool):
    print("true" if value else "false")
elif isinstance(value, (dict, list)):
    print(json.dumps(value, sort_keys=True))
else:
    print(value)
PY
}

remote_alpha_vault_systemctl_state() {
  local mode=$1
  local service_name=$2

  if command -v systemctl >/dev/null 2>&1 && systemctl "${mode}" --quiet "${service_name}" >/dev/null 2>&1; then
    printf 'true'
  else
    printf 'false'
  fi
}

remote_alpha_vault_validate_workload_zone_config() {
  local config_path=$1
  local expected_address=$2
  local expected_mount=$3
  local expected_role=$4
  local expected_audience=$5

  python3 - "${config_path}" "${expected_address}" "${expected_mount}" "${expected_role}" "${expected_audience}" <<'PY'
import hashlib
import json
import pathlib
import ssl
import sys
from urllib.parse import urlparse

config_path = pathlib.Path(sys.argv[1])
expected_address = sys.argv[2].strip()
expected_mount = sys.argv[3].strip()
expected_role = sys.argv[4].strip()
expected_audience = sys.argv[5].strip()

result = {
    "path": str(config_path),
    "digest": "",
    "validation_result": "fail",
    "validation_error": "",
    "address": "",
    "auth_mount": "",
    "auth_role": "",
    "jwt_audience": "",
    "ca_bundle_present": False,
    "ca_bundle_pem": "",
}

try:
    raw = config_path.read_bytes()
except FileNotFoundError:
    result["validation_error"] = "workload-zone config file does not exist"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)
except OSError as exc:
    result["validation_error"] = f"read workload-zone config file: {exc}"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

result["digest"] = "sha256:" + hashlib.sha256(raw).hexdigest()

try:
    payload = json.loads(raw.decode("utf-8"))
except Exception as exc:
    result["validation_error"] = f"decode workload-zone config json: {exc}"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

vault = payload.get("vault_config")
if not isinstance(vault, dict):
    result["validation_error"] = "workload-zone config is missing vault_config"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

address = str(vault.get("address") or "").strip()
auth_mount = str(vault.get("auth_mount") or "").strip()
auth_role = str(vault.get("auth_role") or "").strip()
jwt_audience = str(vault.get("jwt_audience") or "").strip()
ca_bundle_pem = str(vault.get("ca_bundle_pem") or "").strip()

result["address"] = address
result["auth_mount"] = auth_mount
result["auth_role"] = auth_role
result["jwt_audience"] = jwt_audience
result["ca_bundle_present"] = bool(ca_bundle_pem)
result["ca_bundle_pem"] = ca_bundle_pem

if not address:
    result["validation_error"] = "vault_config.address is required"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)
parsed = urlparse(address)
if parsed.scheme != "https" or not parsed.netloc:
    result["validation_error"] = "vault_config.address must be a valid absolute https URL"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)
if not auth_mount:
    result["validation_error"] = "vault_config.auth_mount is required"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)
if not auth_role:
    result["validation_error"] = "vault_config.auth_role is required"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)
if not jwt_audience:
    result["validation_error"] = "vault_config.jwt_audience is required"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)
if ca_bundle_pem:
    try:
        ssl.create_default_context(cadata=ca_bundle_pem)
    except Exception as exc:
        result["validation_error"] = f"vault_config.ca_bundle_pem is invalid: {exc}"
        print(json.dumps(result, sort_keys=True))
        sys.exit(0)

for field_name, actual, expected in (
    ("address", address, expected_address),
    ("auth_mount", auth_mount, expected_mount),
    ("auth_role", auth_role, expected_role),
    ("jwt_audience", jwt_audience, expected_audience),
):
    if expected and actual != expected:
        result["validation_error"] = f"vault_config.{field_name}={actual!r} does not match expected {expected!r}"
        print(json.dumps(result, sort_keys=True))
        sys.exit(0)

result["validation_result"] = "pass"
print(json.dumps(result, sort_keys=True))
PY
}

remote_alpha_vault_write_ca_bundle() {
  local config_meta_path=$1
  local output_path=$2

  python3 - "${config_meta_path}" "${output_path}" <<'PY'
import json
import pathlib
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
bundle = str(payload.get("ca_bundle_pem") or "")
if not bundle:
    sys.exit(1)
path = pathlib.Path(sys.argv[2])
path.write_text(bundle, encoding="utf-8")
path.chmod(0o600)
PY
}

remote_alpha_vault_health_probe() {
  local vault_address=$1
  local ca_bundle_path=${2:-}

  python3 - "${vault_address}" "${ca_bundle_path}" <<'PY'
import json
import ssl
import sys
import urllib.error
import urllib.request

vault_address = sys.argv[1].strip().rstrip("/")
ca_bundle_path = sys.argv[2].strip()

result = {
    "status": "fail",
    "http_status": None,
    "initialized": None,
    "sealed": None,
    "storage": "unknown",
    "error": "",
}

context = ssl.create_default_context(cafile=ca_bundle_path or None)
request = urllib.request.Request(vault_address + "/v1/sys/health", headers={"Accept": "application/json"})

try:
    with urllib.request.urlopen(request, timeout=10, context=context) as response:
        body = response.read().decode("utf-8")
        status = response.status
except urllib.error.HTTPError as exc:
    body = exc.read().decode("utf-8", errors="replace")
    status = exc.code
except Exception as exc:
    result["error"] = f"vault health request failed: {exc}"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

result["http_status"] = status
try:
    payload = json.loads(body)
except Exception as exc:
    result["error"] = f"vault health response was not json: {exc}"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

result["initialized"] = payload.get("initialized")
result["sealed"] = payload.get("sealed")
result["storage"] = str(payload.get("storage_type") or "unknown")
result["status"] = "pass"
print(json.dumps(result, sort_keys=True))
PY
}

remote_alpha_vault_extract_first_jwt() {
  local output=""

  if output="$(spire-agent api fetch jwt -socketPath "${REMOTE_ALPHA_SPIRE_AGENT_SOCKET_PATH}" -audience "${REMOTE_ALPHA_VAULT_AUDIENCE}" 2>/dev/null)"; then
    :
  elif output="$(spire-agent api fetch jwt -socketPath "${REMOTE_ALPHA_SPIRE_AGENT_SOCKET_PATH}" -audience "${REMOTE_ALPHA_VAULT_AUDIENCE}" -output json 2>/dev/null)"; then
    :
  elif output="$(spire-agent api fetch jwt -socketPath "${REMOTE_ALPHA_SPIRE_AGENT_SOCKET_PATH}" -audience "${REMOTE_ALPHA_VAULT_AUDIENCE}" -write /dev/stdout 2>/dev/null)"; then
    :
  else
    return 1
  fi

  printf '%s' "${output}" | python3 /dev/fd/3 3<<'PY'
import re
import sys

match = re.search(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", sys.stdin.read())
if not match:
    sys.exit(1)
print(match.group(0))
PY
}

remote_alpha_vault_jwt_metadata() {
  local expected_spiffe_id=$1
  local expected_audience=$2
  local expected_issuer=${3:-}
  local expected_issuer_source=${4:-unknown}

  python3 /dev/fd/3 "${expected_spiffe_id}" "${expected_audience}" "${expected_issuer}" "${expected_issuer_source}" 3<<'PY'
import base64
import json
import sys

expected_spiffe_id = sys.argv[1].strip()
expected_audience = sys.argv[2].strip()
expected_issuer = sys.argv[3].strip()
expected_issuer_source = sys.argv[4].strip() or "unknown"
token = sys.stdin.read().strip()


def issuer_class(value, expected=""):
    text = str(value or "").strip()
    if not text:
        return "empty"
    if expected and text == expected:
        return "matches_expected"
    if text.startswith("spiffe://"):
        rest = text[len("spiffe://") :]
        if "/" in rest.strip("/"):
            return "spiffe_id"
        return "spiffe_trust_domain"
    if text.startswith("https://"):
        return "https_url"
    if text.startswith("http://"):
        return "http_url"
    return "other_nonempty"

result = {
    "status": "fail",
    "subject": "",
    "audience": [],
    "audience_matches_expected": False,
    "subject_matches_expected": False,
    "issuer_matches_expected": None,
    "issuer_expected_source": expected_issuer_source,
    "issuer_expected_class": issuer_class(expected_issuer) if expected_issuer else "unknown",
    "issuer_actual_class": "unknown",
    "error": "",
}

parts = token.split(".")
if len(parts) < 2:
    result["error"] = "jwt did not contain at least two segments"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

payload_part = parts[1]
payload_part += "=" * ((4 - (len(payload_part) % 4)) % 4)
try:
    payload = json.loads(base64.urlsafe_b64decode(payload_part.encode("ascii")).decode("utf-8"))
except Exception as exc:
    result["error"] = f"decode jwt payload: {exc}"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

subject = str(payload.get("sub") or "").strip()
audience = payload.get("aud") or []
if isinstance(audience, str):
    audience = [audience]
audience = [str(item).strip() for item in audience if str(item).strip()]
issuer = str(payload.get("iss") or "").strip()

result["subject"] = subject
result["audience"] = audience
result["issuer_actual_class"] = issuer_class(issuer, expected_issuer)
result["subject_matches_expected"] = subject == expected_spiffe_id
result["audience_matches_expected"] = expected_audience in audience
if expected_issuer:
    result["issuer_matches_expected"] = issuer == expected_issuer
if result["subject_matches_expected"] and result["audience_matches_expected"]:
    result["status"] = "pass"
else:
    result["error"] = "jwt claims did not match expected subject/audience"
print(json.dumps(result, sort_keys=True))
PY
}

remote_alpha_vault_login_raw() {
  local vault_address=$1
  local ca_bundle_path=$2
  local auth_mount=$3
  local role=$4

  python3 /dev/fd/3 "${vault_address}" "${ca_bundle_path}" "${auth_mount}" "${role}" 3<<'PY'
import json
import re
import ssl
import sys
import urllib.error
import urllib.request

vault_address = sys.argv[1].strip().rstrip("/")
ca_bundle_path = sys.argv[2].strip()
auth_mount = sys.argv[3].strip().strip("/")
role = sys.argv[4].strip()
jwt_value = sys.stdin.read().strip()

context = ssl.create_default_context(cafile=ca_bundle_path or None)
payload = json.dumps({"role": role, "jwt": jwt_value}).encode("utf-8")
request = urllib.request.Request(
    vault_address + "/v1/auth/" + auth_mount + "/login",
    data=payload,
    headers={"Accept": "application/json", "Content-Type": "application/json"},
    method="POST",
)

SAFE_CLASSES = {
    "auth_mount_missing_or_unreachable",
    "role_missing_or_rejected",
    "invalid_jwt",
    "invalid_audience",
    "invalid_subject",
    "invalid_issuer_or_validation_key",
    "permission_denied",
    "vault_api_error",
    "invalid_response",
    "tls_or_connectivity_error",
    "unknown",
}


def safe_class(value):
    text = str(value or "").strip()
    return text if text in SAFE_CLASSES else "unknown"


def vault_errors(parsed):
    errors = []
    if isinstance(parsed, dict):
        raw_errors = parsed.get("errors")
        if isinstance(raw_errors, str):
            raw_errors = [raw_errors]
        if isinstance(raw_errors, list):
            for item in raw_errors:
                text = str(item or "").strip()
                if text:
                    errors.append(text)
    return errors


def classify_failure(status, errors, invalid_response=False, request_failed=False):
    if request_failed:
        return "tls_or_connectivity_error"
    if invalid_response:
        return "invalid_response"

    joined = " ".join(errors).lower()
    joined = re.sub(r"eyj[a-z0-9_-]+\.[a-z0-9_-]+\.[a-z0-9_-]+", " jwt_svid_redacted ", joined)
    joined = re.sub(r"(?:hvs|s|b)\.[a-z0-9._-]{12,}", " vault_token_redacted ", joined)
    if "no handler for route" in joined or "unsupported path" in joined or "missing client token" in joined:
        return "auth_mount_missing_or_unreachable"
    if status == 404:
        return "auth_mount_missing_or_unreachable"
    if "audience" in joined or re.search(r"\baud\b", joined):
        return "invalid_audience"
    if "bound_subject" in joined or "subject" in joined or "claim \"sub\"" in joined or "claim 'sub'" in joined or "sub claim" in joined:
        return "invalid_subject"
    if "issuer" in joined or "validation key" in joined or "validation pubkey" in joined or "public key" in joined or "signature" in joined:
        return "invalid_issuer_or_validation_key"
    if "role" in joined and (
        "not found" in joined
        or "could not be found" in joined
        or "missing" in joined
        or "invalid" in joined
        or "rejected" in joined
        or "denied" in joined
    ):
        return "role_missing_or_rejected"
    if "jwt" in joined and (
        "invalid" in joined
        or "malformed" in joined
        or "expired" in joined
        or "parse" in joined
        or "not valid" in joined
    ):
        return "invalid_jwt"
    if status in (401, 403):
        return "permission_denied"
    if status is not None and status >= 500:
        return "vault_api_error"
    return "unknown"


def fail_result(status, failure_class, error_count=0):
    failure_class = safe_class(failure_class)
    return {
        "status": "fail",
        "http_status": status,
        "error": f"vault login failed: {failure_class}",
        "error_count": int(error_count),
        "error_class": failure_class,
        "failure_phase": "vault_login",
        "failure_class": failure_class,
        "raw_error_recorded": False,
        "client_token": "",
    }


try:
    with urllib.request.urlopen(request, timeout=10, context=context) as response:
        body = response.read().decode("utf-8")
        status = response.status
except urllib.error.HTTPError as exc:
    body = exc.read().decode("utf-8", errors="replace")
    status = exc.code
except Exception as exc:
    print(json.dumps(fail_result(None, classify_failure(None, [], request_failed=True)), sort_keys=True))
    sys.exit(0)

try:
    response_payload = json.loads(body)
except Exception as exc:
    print(json.dumps(fail_result(status, classify_failure(status, [], invalid_response=True)), sort_keys=True))
    sys.exit(0)

client_token = ""
auth_payload = response_payload.get("auth") if isinstance(response_payload, dict) else None
if isinstance(auth_payload, dict):
    client_token = str(auth_payload.get("client_token") or "").strip()

if status < 400 and client_token:
    result = {
        "status": "pass",
        "http_status": status,
        "error": "",
        "error_count": 0,
        "error_class": "unknown",
        "failure_phase": "",
        "failure_class": "unknown",
        "raw_error_recorded": False,
        "client_token": client_token,
    }
else:
    errors = vault_errors(response_payload)
    failure_class = classify_failure(
        status,
        errors,
        invalid_response=(status < 400 and not client_token),
    )
    result = fail_result(status, failure_class, len(errors))
print(json.dumps(result, sort_keys=True))
PY
}

remote_alpha_vault_login_metadata() {
  python3 /dev/fd/3 3<<'PY'
import json
import sys

payload = json.loads(sys.stdin.read())
auth_payload = payload.get("auth")

safe_classes = {
    "auth_mount_missing_or_unreachable",
    "role_missing_or_rejected",
    "invalid_jwt",
    "invalid_audience",
    "invalid_subject",
    "invalid_issuer_or_validation_key",
    "permission_denied",
    "vault_api_error",
    "invalid_response",
    "tls_or_connectivity_error",
    "unknown",
}


def safe_class(value):
    text = str(value or "").strip()
    return text if text in safe_classes else "unknown"


def int_or_zero(value):
    try:
        return int(value)
    except Exception:
        return 0


result = {
    "status": str(payload.get("status") or "").strip(),
    "http_status": payload.get("http_status"),
    "error": str(payload.get("error") or "").strip(),
    "error_count": int_or_zero(payload.get("error_count")),
    "error_class": safe_class(payload.get("error_class")),
    "failure_phase": str(payload.get("failure_phase") or "").strip(),
    "failure_class": safe_class(payload.get("failure_class")),
    "raw_error_recorded": bool(payload.get("raw_error_recorded")),
    "policy_names": [],
    "token_ttl_seconds": None,
}

if isinstance(auth_payload, dict):
    policies = auth_payload.get("policies") or auth_payload.get("token_policies") or []
    if isinstance(policies, str):
        policies = [policies]
    result["policy_names"] = [str(item).strip() for item in policies if str(item).strip()]

    ttl_value = auth_payload.get("lease_duration")
    if isinstance(ttl_value, (int, float)):
        result["token_ttl_seconds"] = int(ttl_value)
    elif isinstance(ttl_value, str) and ttl_value.isdigit():
        result["token_ttl_seconds"] = int(ttl_value)

print(json.dumps(result, sort_keys=True))
PY
}

remote_alpha_vault_login_token() {
  python3 /dev/fd/3 3<<'PY'
import json
import sys

payload = json.loads(sys.stdin.read())
print(str(payload.get("client_token") or "").strip())
PY
}

remote_alpha_vault_lookup_self() {
  local vault_address=$1
  local ca_bundle_path=$2

  python3 /dev/fd/3 "${vault_address}" "${ca_bundle_path}" 3<<'PY'
import json
import ssl
import sys
import urllib.error
import urllib.request

vault_address = sys.argv[1].strip().rstrip("/")
ca_bundle_path = sys.argv[2].strip()
token = sys.stdin.read().strip()

result = {
    "status": "fail",
    "policy_names": [],
    "token_ttl_seconds": None,
    "error": "",
}

context = ssl.create_default_context(cafile=ca_bundle_path or None)
request = urllib.request.Request(
    vault_address + "/v1/auth/token/lookup-self",
    headers={
        "Accept": "application/json",
        "X-Vault-Token": token,
    },
    method="GET",
)

try:
    with urllib.request.urlopen(request, timeout=10, context=context) as response:
        payload = json.loads(response.read().decode("utf-8"))
except urllib.error.HTTPError as exc:
    result["error"] = f"vault token lookup failed with status {exc.code}"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)
except Exception as exc:
    result["error"] = f"vault token lookup request failed: {exc}"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

data = payload.get("data")
if not isinstance(data, dict):
    result["error"] = "vault token lookup response did not include data"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

policies = data.get("policies") or data.get("token_policies") or []
if isinstance(policies, str):
    policies = [policies]
result["policy_names"] = [str(item).strip() for item in policies if str(item).strip()]

ttl_value = data.get("ttl")
if isinstance(ttl_value, (int, float)):
    result["token_ttl_seconds"] = int(ttl_value)
elif isinstance(ttl_value, str) and ttl_value.isdigit():
    result["token_ttl_seconds"] = int(ttl_value)

result["status"] = "pass"
print(json.dumps(result, sort_keys=True))
PY
}

remote_alpha_vault_proof_read() {
  local vault_address=$1
  local ca_bundle_path=$2
  local proof_path=$3

  python3 /dev/fd/3 "${vault_address}" "${ca_bundle_path}" "${proof_path}" 3<<'PY'
import json
import ssl
import sys
import urllib.error
import urllib.request

vault_address = sys.argv[1].strip().rstrip("/")
ca_bundle_path = sys.argv[2].strip()
proof_path = sys.argv[3].strip().strip("/")
token = sys.stdin.read().strip()

result = {
    "status": "fail",
    "path": proof_path,
    "error": "",
}

context = ssl.create_default_context(cafile=ca_bundle_path or None)
request = urllib.request.Request(
    vault_address + "/v1/" + proof_path,
    headers={"Accept": "application/json", "X-Vault-Token": token},
)

try:
    with urllib.request.urlopen(request, timeout=10, context=context) as response:
        payload = json.loads(response.read().decode("utf-8"))
except urllib.error.HTTPError as exc:
    if exc.code == 404:
        result["status"] = "not_exercised"
        result["error"] = "proof path was not present"
        print(json.dumps(result, sort_keys=True))
        sys.exit(0)
    result["error"] = f"proof read failed with status {exc.code}"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)
except Exception as exc:
    result["error"] = f"proof read request failed: {exc}"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

data = payload.get("data")
if isinstance(data, dict):
    result["status"] = "pass"
else:
    result["error"] = "proof read response did not include data"
print(json.dumps(result, sort_keys=True))
PY
}

remote_alpha_vault_secret_field_probe() {
  local vault_address=$1
  local ca_bundle_path=$2
  local secret_path=$3
  local secret_field=$4

  python3 /dev/fd/3 "${vault_address}" "${ca_bundle_path}" "${secret_path}" "${secret_field}" 3<<'PY'
import json
import ssl
import sys
import urllib.error
import urllib.request

vault_address = sys.argv[1].strip().rstrip("/")
ca_bundle_path = sys.argv[2].strip()
secret_path = sys.argv[3].strip().strip("/")
secret_field = sys.argv[4].strip()
token = sys.stdin.read().strip()

result = {
    "status": "fail",
    "path": secret_path,
    "field": secret_field,
    "field_present": False,
    "field_nonempty": False,
    "field_shape": "unknown",
    "error": "",
}

context = ssl.create_default_context(cafile=ca_bundle_path or None)
request = urllib.request.Request(
    vault_address + "/v1/" + secret_path,
    headers={"Accept": "application/json", "X-Vault-Token": token},
)

try:
    with urllib.request.urlopen(request, timeout=10, context=context) as response:
        payload = json.loads(response.read().decode("utf-8"))
except urllib.error.HTTPError as exc:
    if exc.code == 404:
        result["status"] = "not_exercised"
        result["error"] = "proof runtime secret path was not present"
        print(json.dumps(result, sort_keys=True))
        sys.exit(0)
    result["error"] = f"proof runtime secret read failed with status {exc.code}"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)
except Exception as exc:
    result["error"] = f"proof runtime secret read request failed: {exc}"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

data = payload.get("data")
if isinstance(data, dict):
    nested = data.get("data")
    if isinstance(nested, dict):
        data = nested

if not isinstance(data, dict):
    result["error"] = "proof runtime secret response did not include a data object"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

if secret_field not in data:
    result["field_shape"] = "absent"
    result["error"] = f"proof runtime secret field {secret_field!r} was not present"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

value = data.get(secret_field)
result["field_present"] = True

if value is None:
    result["field_shape"] = "null"
    result["error"] = f"proof runtime secret field {secret_field!r} was null"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

if isinstance(value, str):
    result["field_shape"] = "string"
    result["field_nonempty"] = bool(value.strip())
elif isinstance(value, bool):
    result["field_shape"] = "bool"
    result["field_nonempty"] = True
elif isinstance(value, (int, float)):
    result["field_shape"] = "number"
    result["field_nonempty"] = True
elif isinstance(value, dict):
    result["field_shape"] = "object"
    result["field_nonempty"] = bool(value)
elif isinstance(value, list):
    result["field_shape"] = "array"
    result["field_nonempty"] = bool(value)
else:
    result["field_shape"] = type(value).__name__
    result["field_nonempty"] = True

if not result["field_nonempty"]:
    result["error"] = f"proof runtime secret field {secret_field!r} was empty"
    print(json.dumps(result, sort_keys=True))
    sys.exit(0)

result["status"] = "pass"
print(json.dumps(result, sort_keys=True))
PY
}

remote_alpha_vault_revoke_self() {
  local vault_address=$1
  local ca_bundle_path=$2

  python3 /dev/fd/3 "${vault_address}" "${ca_bundle_path}" 3<<'PY'
import json
import ssl
import sys
import urllib.error
import urllib.request

vault_address = sys.argv[1].strip().rstrip("/")
ca_bundle_path = sys.argv[2].strip()
token = sys.stdin.read().strip()

result = {"status": "fail", "error": ""}
context = ssl.create_default_context(cafile=ca_bundle_path or None)
request = urllib.request.Request(
    vault_address + "/v1/auth/token/revoke-self",
    data=b"{}",
    headers={
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-Vault-Token": token,
    },
    method="POST",
)

try:
    with urllib.request.urlopen(request, timeout=10, context=context):
        result["status"] = "pass"
except urllib.error.HTTPError as exc:
    result["error"] = f"token revoke failed with status {exc.code}"
except Exception as exc:
    result["error"] = f"token revoke request failed: {exc}"

print(json.dumps(result, sort_keys=True))
PY
}

remote_alpha_vault_spire_server_command() {
  if [[ -n "${REMOTE_ALPHA_SPIRE_SERVER_SOCKET_PATH}" ]]; then
    spire-server "$@" -socketPath "${REMOTE_ALPHA_SPIRE_SERVER_SOCKET_PATH}"
  else
    spire-server "$@"
  fi
}

remote_alpha_vault_spire_trust_domain() {
  local output=""

  if output="$(remote_alpha_vault_spire_server_command bundle show -format spiffe 2>/dev/null)"; then
    printf '%s' "${output}" | python3 /dev/fd/3 3<<'PY'
import re
import sys

match = re.search(r"spiffe://([A-Za-z0-9._-]+)", sys.stdin.read())
if not match:
    sys.exit(1)
print(match.group(1))
PY
    return 0
  fi

  python3 - "${REMOTE_ALPHA_WORKLOAD_SPIFFE_ID}" <<'PY'
import sys
value = sys.argv[1].strip()
prefix = "spiffe://"
if value.startswith(prefix):
    trust_domain = value[len(prefix):].split("/", 1)[0]
    if trust_domain:
        print(trust_domain)
        sys.exit(0)
sys.exit(1)
PY
}

remote_alpha_vault_registration_selectors_json() {
  local output=""

  if ! output="$(remote_alpha_vault_spire_server_command entry show -spiffeID "${REMOTE_ALPHA_WORKLOAD_SPIFFE_ID}" 2>/dev/null)"; then
    printf '[]'
    return 0
  fi

  printf '%s' "${output}" | python3 /dev/fd/3 3<<'PY'
import json
import re
import sys

selectors = sorted(set(re.findall(r"unix:[A-Za-z]+:[^,\s]+", sys.stdin.read())))
print(json.dumps(selectors, sort_keys=True))
PY
}

remote_alpha_vault_listener_addresses_json() {
  if ! command -v ss >/dev/null 2>&1; then
    printf '[]'
    return 0
  fi

  python3 - "${REMOTE_ALPHA_VAULT_ADDRESS}" <<'PY'
import sys
from urllib.parse import urlparse

parsed = urlparse(sys.argv[1].strip())
port = parsed.port or (443 if parsed.scheme == "https" else 80)
print(port)
PY
}

remote_alpha_vault_collect_listener_addresses() {
  local port=$1
  local output=""

  if ! output="$(ss -ltnH "( sport = :${port} )" 2>/dev/null)"; then
    printf '[]'
    return 0
  fi

  printf '%s' "${output}" | python3 /dev/fd/3 3<<'PY'
import json
import sys

addresses = []
for line in sys.stdin.read().splitlines():
    fields = line.split()
    if len(fields) >= 4:
        address = fields[3].strip()
        if address and address not in addresses:
            addresses.append(address)
print(json.dumps(addresses, sort_keys=True))
PY
}

remote_alpha_vault_access_probe_for_user() {
  local socket_path=$1
  local target_user=$2
  local override_name=$3
  local override_value=""

  override_value="${!override_name:-}"
  if [[ -n "${override_value}" ]]; then
    printf '%s' "${override_value}"
    return 0
  fi

  python3 - "${socket_path}" "${target_user}" <<'PY'
import os
import pwd
import socket
import sys

socket_path = sys.argv[1]
target_user = sys.argv[2]

if os.geteuid() != 0:
    print("unknown")
    raise SystemExit(0)

record = pwd.getpwnam(target_user)
try:
    os.setgroups([])
    os.setgid(record.pw_gid)
    os.setuid(record.pw_uid)
except Exception:
    print("unknown")
    raise SystemExit(0)

client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.settimeout(1)
try:
    client.connect(socket_path)
except Exception:
    print("false")
else:
    print("true")
finally:
    client.close()
PY
}

remote_alpha_vault_access_probe_for_uid() {
  local socket_path=$1
  local target_uid=$2
  local target_gid=$3
  local override_name=$4
  local override_value=""

  override_value="${!override_name:-}"
  if [[ -n "${override_value}" ]]; then
    printf '%s' "${override_value}"
    return 0
  fi

  python3 - "${socket_path}" "${target_uid}" "${target_gid}" <<'PY'
import os
import socket
import sys

socket_path = sys.argv[1]
target_uid = int(sys.argv[2])
target_gid = int(sys.argv[3])

if os.geteuid() != 0:
    print("unknown")
    raise SystemExit(0)

try:
    os.setgroups([])
    os.setgid(target_gid)
    os.setuid(target_uid)
except Exception:
    print("unknown")
    raise SystemExit(0)

client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.settimeout(1)
try:
    client.connect(socket_path)
except Exception:
    print("false")
else:
    print("true")
finally:
    client.close()
PY
}

remote_alpha_vault_passwordless_sudo_for_ds() {
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

remote_alpha_vault_ds_not_in_docker_group() {
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

remote_alpha_vault_container_probe() {
  local image=$1
  local ca_bundle_path=$2
  local vault_address=$3

  if [[ -z "${image}" ]]; then
    printf 'not_exercised'
    return 0
  fi
  if ! command -v docker >/dev/null 2>&1; then
    printf 'not_exercised'
    return 0
  fi
  if [[ -z "${ca_bundle_path}" ]]; then
    printf 'not_exercised'
    return 0
  fi
  if ! docker image inspect "${image}" >/dev/null 2>&1; then
    printf 'not_exercised'
    return 0
  fi

  if docker run --rm --network bridge -v "${ca_bundle_path}:/tmp/vault-ca.pem:ro" "${image}" \
    --silent --show-error --fail --cacert /tmp/vault-ca.pem "${vault_address%/}/v1/sys/health" >/dev/null 2>&1; then
    printf 'pass'
  else
    printf 'fail'
  fi
}

remote_alpha_vault_validate_summary_file() {
  local summary_path=$1
  shift

  python3 - "${summary_path}" "$@" <<'PY'
import pathlib
import re
import sys

summary_path = pathlib.Path(sys.argv[1])
text = summary_path.read_text(encoding="utf-8")
deny_values = [value for value in sys.argv[2:] if value]
patterns = [
    re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    re.compile(r"(?:^|[^A-Za-z0-9])(?:hvs|s|b)\.[A-Za-z0-9._-]{12,}"),
    re.compile(r"-----BEGIN [A-Z0-9 ]+-----"),
]

for deny_value in deny_values:
    if deny_value in text:
        raise SystemExit(f"summary contains denied runtime secret material: {summary_path}")

for pattern in patterns:
    if pattern.search(text):
        raise SystemExit(f"summary contains secret-like material matching {pattern.pattern}: {summary_path}")
PY
}

remote_alpha_vault_write_summary() {
  local summary_path=$1
  local config_meta_path=$2
  local health_meta_path=$3
  local jwt_meta_path=$4
  local login_meta_path=$5
  local lookup_meta_path=$6
  local proof_read_meta_path=$7
  local proof_runtime_secret_meta_path=$8
  local revoke_meta_path=$9

  python3 - "${summary_path}" "${config_meta_path}" "${health_meta_path}" "${jwt_meta_path}" "${login_meta_path}" "${lookup_meta_path}" "${proof_read_meta_path}" "${proof_runtime_secret_meta_path}" "${revoke_meta_path}" <<'PY'
import json
import os
import sys
from urllib.parse import urlparse

summary_path = sys.argv[1]
config_meta = json.load(open(sys.argv[2], encoding="utf-8"))
health_meta = json.load(open(sys.argv[3], encoding="utf-8"))
jwt_meta = json.load(open(sys.argv[4], encoding="utf-8"))
login_meta = json.load(open(sys.argv[5], encoding="utf-8"))
lookup_meta = json.load(open(sys.argv[6], encoding="utf-8"))
proof_read_meta = json.load(open(sys.argv[7], encoding="utf-8"))
proof_runtime_secret_meta = json.load(open(sys.argv[8], encoding="utf-8"))
revoke_meta = json.load(open(sys.argv[9], encoding="utf-8"))

def bool_env(name):
    value = os.environ.get(name, "").strip().lower()
    if value == "true":
        return True
    if value == "false":
        return False
    return None

def json_env(name, fallback):
    raw = os.environ.get(name, "").strip()
    if not raw:
        return fallback
    return json.loads(raw)

safe_login_failure_classes = {
    "auth_mount_missing_or_unreachable",
    "role_missing_or_rejected",
    "invalid_jwt",
    "invalid_audience",
    "invalid_subject",
    "invalid_issuer_or_validation_key",
    "permission_denied",
    "vault_api_error",
    "invalid_response",
    "tls_or_connectivity_error",
    "unknown",
}


def safe_login_failure_class(value):
    text = str(value or "").strip()
    return text if text in safe_login_failure_classes else "unknown"


def optional_int(value):
    if value is None:
        return None
    try:
        return int(value)
    except Exception:
        return None

listener_addresses = json_env("REMOTE_ALPHA_LISTENER_ADDRESSES_JSON", [])
expected_listener = ""
parsed_address = urlparse(os.environ["REMOTE_ALPHA_VAULT_ADDRESS"].strip())
if parsed_address.hostname:
    expected_listener = f"{parsed_address.hostname}:{parsed_address.port or 443}"

listener_scope_ok = None
if listener_addresses:
    listener_scope_ok = all(address == expected_listener for address in listener_addresses)

selector_scope = json_env("REMOTE_ALPHA_SELECTORS_JSON", [])
registration_alpha_only = "unix:uid:0" in selector_scope and "unix:gid:0" in selector_scope

proof_status = proof_read_meta.get("status") or "unknown"
proof_runtime_secret_status = proof_runtime_secret_meta.get("status") or "unknown"
token_lookup_required = True
proof_read_required = True
proof_runtime_secret_required = True
token_revoke_required = True

policy_names = lookup_meta.get("policy_names") or login_meta.get("policy_names") or []
token_ttl_seconds = lookup_meta.get("token_ttl_seconds")
if token_ttl_seconds is None:
    token_ttl_seconds = login_meta.get("token_ttl_seconds")

jwt_issuer_verified = jwt_meta.get("issuer_matches_expected")
if jwt_issuer_verified is None:
    jwt_issuer_verified = "unknown"

auth_smoke = {
    "jwt_fetch": jwt_meta.get("status") or "fail",
    "vault_login": login_meta.get("status") or "fail",
    "token_lookup": lookup_meta.get("status") or "fail",
    "proof_read": proof_status,
    "proof_runtime_secret": proof_runtime_secret_status,
    "token_revoked": revoke_meta.get("status") or "fail",
    "jwt_subject_verified": bool(jwt_meta.get("subject_matches_expected")),
    "jwt_audience_verified": bool(jwt_meta.get("audience_matches_expected")),
    "jwt_issuer_verified": jwt_issuer_verified,
    "jwt_issuer_expected_source": jwt_meta.get("issuer_expected_source") or "unknown",
    "jwt_issuer_expected_class": jwt_meta.get("issuer_expected_class") or "unknown",
    "jwt_issuer_actual_class": jwt_meta.get("issuer_actual_class") or "unknown",
}

if auth_smoke["vault_login"] == "fail":
    failure_class = safe_login_failure_class(login_meta.get("failure_class"))
    error_class = safe_login_failure_class(login_meta.get("error_class"))
    auth_smoke["vault_login_failure_phase"] = str(login_meta.get("failure_phase") or "vault_login")
    auth_smoke["vault_login_failure_class"] = failure_class
    login_http_status = optional_int(login_meta.get("http_status"))
    if login_http_status is not None:
        auth_smoke["vault_login_http_status"] = login_http_status
    auth_smoke["vault_login_error_count"] = optional_int(login_meta.get("error_count")) or 0
    auth_smoke["vault_login_error_class"] = error_class
    auth_smoke["vault_login_raw_error_recorded"] = bool(login_meta.get("raw_error_recorded"))
    if failure_class == "invalid_issuer_or_validation_key":
        if jwt_issuer_verified is False:
            auth_smoke["vault_login_failure_alignment_hint"] = "issuer_mismatch"
        elif jwt_issuer_verified is True:
            auth_smoke["vault_login_failure_alignment_hint"] = "validation_key_mismatch_or_rotation"
        else:
            auth_smoke["vault_login_failure_alignment_hint"] = "issuer_or_key_unknown"

lookup_ok = lookup_meta.get("status") == "pass" if token_lookup_required else lookup_meta.get("status") in {"pass", "not_exercised"}
proof_ok = proof_status == "pass" if proof_read_required else proof_status in {"pass", "not_exercised"}
proof_runtime_secret_ok = (
    proof_runtime_secret_status == "pass"
    if proof_runtime_secret_required
    else proof_runtime_secret_status in {"pass", "not_exercised"}
)
revoke_ok = revoke_meta.get("status") == "pass" if token_revoke_required else revoke_meta.get("status") in {"pass", "not_exercised"}
smoke_ok = (
    jwt_meta.get("status") == "pass"
    and login_meta.get("status") == "pass"
    and lookup_ok
    and proof_ok
    and proof_runtime_secret_ok
    and revoke_ok
)

summary = {
    "schema_version": os.environ["REMOTE_ALPHA_SUMMARY_SCHEMA_VERSION"],
    "checked_at": os.environ["REMOTE_ALPHA_CHECKED_AT"],
    "vault_workload_auth_smoke": "pass" if smoke_ok else "fail",
    "host_identity": {
        "hostname": os.environ["REMOTE_ALPHA_HOSTNAME"],
        "euid": int(os.environ["REMOTE_ALPHA_EFFECTIVE_UID"]),
        "summary_kind": "safe_host_local",
    },
    "vault": {
        "alpha_internal": True,
        "address": os.environ["REMOTE_ALPHA_VAULT_ADDRESS"],
        "auth_mount": os.environ["REMOTE_ALPHA_VAULT_AUTH_MOUNT"],
        "role": os.environ["REMOTE_ALPHA_VAULT_ROLE"],
        "audience": os.environ["REMOTE_ALPHA_VAULT_AUDIENCE"],
        "policy_names": policy_names,
        "initialized": health_meta.get("initialized"),
        "sealed": health_meta.get("sealed"),
        "storage": health_meta.get("storage") or "unknown",
        "service_active": bool_env("REMOTE_ALPHA_VAULT_SERVICE_ACTIVE"),
        "service_enabled": bool_env("REMOTE_ALPHA_VAULT_SERVICE_ENABLED"),
        "token_ttl_seconds": token_ttl_seconds,
        "health_http_status": health_meta.get("http_status"),
        "listener_addresses": listener_addresses,
        "listener_scope_ok": listener_scope_ok,
    },
    "spire": {
        "trust_domain": os.environ["REMOTE_ALPHA_TRUST_DOMAIN"],
        "socket_path": os.environ["REMOTE_ALPHA_SPIRE_AGENT_SOCKET_PATH"],
        "agent_service_active": bool_env("REMOTE_ALPHA_SPIRE_AGENT_SERVICE_ACTIVE"),
        "server_service_active": bool_env("REMOTE_ALPHA_SPIRE_SERVER_SERVICE_ACTIVE"),
        "agent_healthcheck": os.environ["REMOTE_ALPHA_SPIRE_AGENT_HEALTHCHECK"],
        "server_healthcheck": os.environ["REMOTE_ALPHA_SPIRE_SERVER_HEALTHCHECK"],
    },
    "workload": {
        "spiffe_id": os.environ["REMOTE_ALPHA_WORKLOAD_SPIFFE_ID"],
        "registration_selector_scope": selector_scope,
        "registration_alpha_only": registration_alpha_only,
    },
    "reachability": {
        "host_vault_health": health_meta.get("status") or "unknown",
        "docker_bridge_vault_health": os.environ["REMOTE_ALPHA_CONTAINER_PROBE_STATUS"],
    },
    "workload_zone_config": {
        "path": config_meta.get("path") or os.environ["REMOTE_ALPHA_WORKLOAD_ZONE_CONFIG_PATH"],
        "digest": config_meta.get("digest") or "",
        "validation_result": config_meta.get("validation_result") or "fail",
        "validation_error": config_meta.get("validation_error") or "",
        "address": config_meta.get("address") or "",
        "auth_mount": config_meta.get("auth_mount") or "",
        "auth_role": config_meta.get("auth_role") or "",
        "jwt_audience": config_meta.get("jwt_audience") or "",
        "ca_bundle_present": bool(config_meta.get("ca_bundle_present")),
    },
    "auth_smoke": auth_smoke,
    "auth_smoke_requirements": {
        "token_lookup_required": token_lookup_required,
        "proof_read_required": proof_read_required,
        "proof_runtime_secret_required": proof_runtime_secret_required,
        "token_revoked_required": token_revoke_required,
        "proof_read_path": os.environ["REMOTE_ALPHA_PROOF_READ_PATH"],
        "proof_runtime_secret_path": os.environ["REMOTE_ALPHA_PROOF_RUNTIME_SECRET_PATH"],
        "proof_runtime_secret_field": os.environ["REMOTE_ALPHA_PROOF_RUNTIME_SECRET_FIELD"],
    },
    "proof_runtime_secret": {
        "status": proof_runtime_secret_status,
        "path": proof_runtime_secret_meta.get("path") or os.environ["REMOTE_ALPHA_PROOF_RUNTIME_SECRET_PATH"],
        "field": proof_runtime_secret_meta.get("field") or os.environ["REMOTE_ALPHA_PROOF_RUNTIME_SECRET_FIELD"],
        "field_present": bool(proof_runtime_secret_meta.get("field_present")),
        "field_nonempty": bool(proof_runtime_secret_meta.get("field_nonempty")),
        "field_shape": proof_runtime_secret_meta.get("field_shape") or "unknown",
    },
    "security": {
        "ds_not_in_docker_group": bool_env("REMOTE_ALPHA_DS_NOT_IN_DOCKER_GROUP"),
        "passwordless_sudo_for_ds": bool_env("REMOTE_ALPHA_PASSWORDLESS_SUDO_FOR_DS"),
        "raw_spire_socket_access_ds": bool_env("REMOTE_ALPHA_RAW_SPIRE_SOCKET_ACCESS_DS"),
        "raw_spire_socket_access_uid_10000": bool_env("REMOTE_ALPHA_RAW_SPIRE_SOCKET_ACCESS_UID_10000"),
    },
    "redaction": {
        "jwt_persisted": False,
        "vault_client_token_persisted": False,
        "root_token_persisted": False,
        "secret_payload_persisted": False,
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
for meta in (config_meta, health_meta, jwt_meta, login_meta, lookup_meta, proof_read_meta, proof_runtime_secret_meta, revoke_meta):
    error = str(meta.get("error") or "").strip()
    if error:
        failure_reasons.append(error)
summary["failure_reasons"] = failure_reasons

with open(summary_path, "w", encoding="utf-8") as handle:
    json.dump(summary, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
}

remote_alpha_vault_workload_auth_check_main() {
  local tmp_dir=""
  local config_meta_path=""
  local health_meta_path=""
  local jwt_meta_path=""
  local login_meta_path=""
  local lookup_meta_path=""
  local proof_read_meta_path=""
  local proof_runtime_secret_meta_path=""
  local revoke_meta_path=""
  local summary_tmp_path=""
  local ca_bundle_path=""
  local jwt_value=""
  local expected_jwt_issuer=""
  local expected_jwt_issuer_source="unknown"
  local vault_login_raw=""
  local vault_token=""
  local listener_port=""
  local overall_ok=true
  local container_probe_status="not_exercised"
  local ds_not_in_docker_group="unknown"
  local passwordless_sudo_for_ds="unknown"
  local raw_spire_socket_access_ds="unknown"
  local raw_spire_socket_access_uid_10000="unknown"

  remote_alpha_vault_workload_auth_defaults
  remote_alpha_vault_workload_auth_parse_args "$@" || return $?

  remote_alpha_vault_require_command python3 || return 1
  remote_alpha_vault_require_command hostname || return 1
  remote_alpha_vault_require_command id || return 1
  remote_alpha_vault_require_command spire-agent || return 1
  remote_alpha_vault_require_command spire-server || return 1
  remote_alpha_vault_require_command systemctl || return 1

  tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/remote-alpha-vault-auth.XXXXXX")"
  config_meta_path="${tmp_dir}/config-meta.json"
  health_meta_path="${tmp_dir}/health-meta.json"
  jwt_meta_path="${tmp_dir}/jwt-meta.json"
  login_meta_path="${tmp_dir}/login-meta.json"
  lookup_meta_path="${tmp_dir}/lookup-meta.json"
  proof_read_meta_path="${tmp_dir}/proof-read-meta.json"
  proof_runtime_secret_meta_path="${tmp_dir}/proof-runtime-secret-meta.json"
  revoke_meta_path="${tmp_dir}/revoke-meta.json"
  summary_tmp_path="${tmp_dir}/summary.json"
  ca_bundle_path="${tmp_dir}/vault-ca.pem"
  trap 'rm -rf "'"${tmp_dir}"'"' EXIT

  remote_alpha_vault_validate_workload_zone_config \
    "${REMOTE_ALPHA_WORKLOAD_ZONE_CONFIG_PATH}" \
    "${REMOTE_ALPHA_VAULT_ADDRESS}" \
    "${REMOTE_ALPHA_VAULT_AUTH_MOUNT}" \
    "${REMOTE_ALPHA_VAULT_ROLE}" \
    "${REMOTE_ALPHA_VAULT_AUDIENCE}" >"${config_meta_path}"

  if [[ "$(remote_alpha_vault_json_field "${config_meta_path}" "validation_result" 2>/dev/null || true)" != "pass" ]]; then
    overall_ok=false
  fi

  if [[ "$(remote_alpha_vault_json_field "${config_meta_path}" "ca_bundle_present" 2>/dev/null || true)" == "true" ]]; then
    remote_alpha_vault_write_ca_bundle "${config_meta_path}" "${ca_bundle_path}" || overall_ok=false
  else
    ca_bundle_path=""
  fi

  remote_alpha_vault_health_probe "${REMOTE_ALPHA_VAULT_ADDRESS}" "${ca_bundle_path}" >"${health_meta_path}"

  if [[ "$(remote_alpha_vault_json_field "${health_meta_path}" "status" 2>/dev/null || true)" != "pass" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_vault_json_field "${health_meta_path}" "initialized" 2>/dev/null || true)" != "true" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_vault_json_field "${health_meta_path}" "sealed" 2>/dev/null || true)" != "false" ]]; then
    overall_ok=false
  fi

  export REMOTE_ALPHA_SUMMARY_SCHEMA_VERSION="${remote_alpha_vault_summary_schema_version}"
  export REMOTE_ALPHA_CHECKED_AT
  REMOTE_ALPHA_CHECKED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  export REMOTE_ALPHA_HOSTNAME
  REMOTE_ALPHA_HOSTNAME="$(hostname)"
  export REMOTE_ALPHA_EFFECTIVE_UID
  REMOTE_ALPHA_EFFECTIVE_UID="$(id -u)"
  export REMOTE_ALPHA_VAULT_SERVICE_ACTIVE
  REMOTE_ALPHA_VAULT_SERVICE_ACTIVE="$(remote_alpha_vault_systemctl_state is-active "${REMOTE_ALPHA_VAULT_SERVICE_NAME}")"
  export REMOTE_ALPHA_VAULT_SERVICE_ENABLED
  REMOTE_ALPHA_VAULT_SERVICE_ENABLED="$(remote_alpha_vault_systemctl_state is-enabled "${REMOTE_ALPHA_VAULT_SERVICE_NAME}")"
  export REMOTE_ALPHA_SPIRE_AGENT_SERVICE_ACTIVE
  REMOTE_ALPHA_SPIRE_AGENT_SERVICE_ACTIVE="$(remote_alpha_vault_systemctl_state is-active "${REMOTE_ALPHA_SPIRE_AGENT_SERVICE_NAME}")"
  export REMOTE_ALPHA_SPIRE_SERVER_SERVICE_ACTIVE
  REMOTE_ALPHA_SPIRE_SERVER_SERVICE_ACTIVE="$(remote_alpha_vault_systemctl_state is-active "${REMOTE_ALPHA_SPIRE_SERVER_SERVICE_NAME}")"
  export REMOTE_ALPHA_SPIRE_AGENT_HEALTHCHECK="fail"
  if spire-agent healthcheck -socketPath "${REMOTE_ALPHA_SPIRE_AGENT_SOCKET_PATH}" >/dev/null 2>&1; then
    REMOTE_ALPHA_SPIRE_AGENT_HEALTHCHECK="pass"
  else
    overall_ok=false
  fi
  export REMOTE_ALPHA_SPIRE_SERVER_HEALTHCHECK="fail"
  if remote_alpha_vault_spire_server_command healthcheck >/dev/null 2>&1; then
    REMOTE_ALPHA_SPIRE_SERVER_HEALTHCHECK="pass"
  else
    overall_ok=false
  fi
  export REMOTE_ALPHA_VAULT_ADDRESS REMOTE_ALPHA_VAULT_AUTH_MOUNT REMOTE_ALPHA_VAULT_ROLE REMOTE_ALPHA_VAULT_AUDIENCE
  export REMOTE_ALPHA_PROOF_READ_PATH REMOTE_ALPHA_PROOF_RUNTIME_SECRET_PATH REMOTE_ALPHA_PROOF_RUNTIME_SECRET_FIELD
  export REMOTE_ALPHA_WORKLOAD_SPIFFE_ID REMOTE_ALPHA_WORKLOAD_ZONE_CONFIG_PATH REMOTE_ALPHA_SPIRE_AGENT_SOCKET_PATH
  export REMOTE_ALPHA_TRUST_DOMAIN
  REMOTE_ALPHA_TRUST_DOMAIN="$(remote_alpha_vault_spire_trust_domain 2>/dev/null || true)"
  if [[ -z "${REMOTE_ALPHA_TRUST_DOMAIN}" ]]; then
    REMOTE_ALPHA_TRUST_DOMAIN="unknown"
    overall_ok=false
  fi
  if [[ "${REMOTE_ALPHA_TRUST_DOMAIN}" != "unknown" ]]; then
    expected_jwt_issuer="spiffe://${REMOTE_ALPHA_TRUST_DOMAIN}"
    expected_jwt_issuer_source="repo_bound_issuer_from_trust_domain"
  fi
  export REMOTE_ALPHA_SELECTORS_JSON
  REMOTE_ALPHA_SELECTORS_JSON="$(remote_alpha_vault_registration_selectors_json)"
  export REMOTE_ALPHA_LISTENER_ADDRESSES_JSON
  listener_port="$(remote_alpha_vault_listener_addresses_json)"
  REMOTE_ALPHA_LISTENER_ADDRESSES_JSON="$(remote_alpha_vault_collect_listener_addresses "${listener_port}")"

  echo '{"status":"not_exercised","error":"proof read not attempted"}' >"${proof_read_meta_path}"
  echo '{"status":"not_exercised","path":"","field":"","field_present":false,"field_nonempty":false,"field_shape":"unknown","error":"proof runtime secret check not attempted"}' >"${proof_runtime_secret_meta_path}"
  echo '{"status":"not_exercised","error":"token revoke not attempted"}' >"${revoke_meta_path}"
  echo '{"status":"not_exercised","policy_names":[],"token_ttl_seconds":null,"error":"token lookup not attempted"}' >"${lookup_meta_path}"
  echo '{"status":"not_exercised","policy_names":[],"token_ttl_seconds":null,"error":"vault login not attempted"}' >"${login_meta_path}"
  echo '{"status":"fail","subject":"","audience":[],"audience_matches_expected":false,"subject_matches_expected":false,"issuer_matches_expected":null,"issuer_expected_source":"unknown","issuer_expected_class":"unknown","issuer_actual_class":"unknown","error":"jwt fetch not attempted"}' >"${jwt_meta_path}"

  if jwt_value="$(remote_alpha_vault_extract_first_jwt 2>/dev/null)"; then
    printf '%s' "${jwt_value}" | remote_alpha_vault_jwt_metadata \
      "${REMOTE_ALPHA_WORKLOAD_SPIFFE_ID}" \
      "${REMOTE_ALPHA_VAULT_AUDIENCE}" \
      "${expected_jwt_issuer}" \
      "${expected_jwt_issuer_source}" >"${jwt_meta_path}"
  fi
  if [[ "$(remote_alpha_vault_json_field "${jwt_meta_path}" "status" 2>/dev/null || true)" != "pass" ]]; then
    overall_ok=false
  fi

  if [[ "$(remote_alpha_vault_json_field "${jwt_meta_path}" "status" 2>/dev/null || true)" == "pass" ]]; then
    vault_login_raw="$(printf '%s' "${jwt_value}" | remote_alpha_vault_login_raw \
      "${REMOTE_ALPHA_VAULT_ADDRESS}" \
      "${ca_bundle_path}" \
      "${REMOTE_ALPHA_VAULT_AUTH_MOUNT}" \
      "${REMOTE_ALPHA_VAULT_ROLE}")"
    printf '%s' "${vault_login_raw}" | remote_alpha_vault_login_metadata >"${login_meta_path}"
    vault_token="$(printf '%s' "${vault_login_raw}" | remote_alpha_vault_login_token)"
    if [[ "$(remote_alpha_vault_json_field "${login_meta_path}" "status" 2>/dev/null || true)" == "pass" && -n "${vault_token}" ]]; then
      printf '%s' "${vault_token}" | remote_alpha_vault_lookup_self "${REMOTE_ALPHA_VAULT_ADDRESS}" "${ca_bundle_path}" >"${lookup_meta_path}"

      if [[ -n "${REMOTE_ALPHA_PROOF_READ_PATH}" ]]; then
        printf '%s' "${vault_token}" | remote_alpha_vault_proof_read \
          "${REMOTE_ALPHA_VAULT_ADDRESS}" \
          "${ca_bundle_path}" \
          "${REMOTE_ALPHA_PROOF_READ_PATH}" >"${proof_read_meta_path}"
      fi

      if [[ -n "${REMOTE_ALPHA_PROOF_RUNTIME_SECRET_PATH}" && -n "${REMOTE_ALPHA_PROOF_RUNTIME_SECRET_FIELD}" ]]; then
        printf '%s' "${vault_token}" | remote_alpha_vault_secret_field_probe \
          "${REMOTE_ALPHA_VAULT_ADDRESS}" \
          "${ca_bundle_path}" \
          "${REMOTE_ALPHA_PROOF_RUNTIME_SECRET_PATH}" \
          "${REMOTE_ALPHA_PROOF_RUNTIME_SECRET_FIELD}" >"${proof_runtime_secret_meta_path}"
      fi

      printf '%s' "${vault_token}" | remote_alpha_vault_revoke_self "${REMOTE_ALPHA_VAULT_ADDRESS}" "${ca_bundle_path}" >"${revoke_meta_path}"
    fi
  fi

  if [[ "$(remote_alpha_vault_json_field "${login_meta_path}" "status" 2>/dev/null || true)" != "pass" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_vault_json_field "${lookup_meta_path}" "status" 2>/dev/null || true)" != "pass" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_vault_json_field "${proof_read_meta_path}" "status" 2>/dev/null || true)" != "pass" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_vault_json_field "${proof_runtime_secret_meta_path}" "status" 2>/dev/null || true)" != "pass" ]]; then
    overall_ok=false
  fi
  if [[ "$(remote_alpha_vault_json_field "${revoke_meta_path}" "status" 2>/dev/null || true)" != "pass" ]]; then
    overall_ok=false
  fi

  ds_not_in_docker_group="$(remote_alpha_vault_ds_not_in_docker_group)"
  passwordless_sudo_for_ds="$(remote_alpha_vault_passwordless_sudo_for_ds)"
  raw_spire_socket_access_ds="$(remote_alpha_vault_access_probe_for_user "${REMOTE_ALPHA_SPIRE_AGENT_SOCKET_PATH}" ds REMOTE_ALPHA_TEST_RAW_SPIRE_SOCKET_ACCESS_DS)"
  raw_spire_socket_access_uid_10000="$(remote_alpha_vault_access_probe_for_uid "${REMOTE_ALPHA_SPIRE_AGENT_SOCKET_PATH}" 10000 10000 REMOTE_ALPHA_TEST_RAW_SPIRE_SOCKET_ACCESS_UID_10000)"
  export REMOTE_ALPHA_DS_NOT_IN_DOCKER_GROUP="${ds_not_in_docker_group}"
  export REMOTE_ALPHA_PASSWORDLESS_SUDO_FOR_DS="${passwordless_sudo_for_ds}"
  export REMOTE_ALPHA_RAW_SPIRE_SOCKET_ACCESS_DS="${raw_spire_socket_access_ds}"
  export REMOTE_ALPHA_RAW_SPIRE_SOCKET_ACCESS_UID_10000="${raw_spire_socket_access_uid_10000}"

  if [[ "${ds_not_in_docker_group}" != "true" ]]; then
    overall_ok=false
  fi
  if [[ "${passwordless_sudo_for_ds}" != "false" ]]; then
    overall_ok=false
  fi
  if [[ "${raw_spire_socket_access_ds}" != "false" ]]; then
    overall_ok=false
  fi
  if [[ "${raw_spire_socket_access_uid_10000}" != "false" ]]; then
    overall_ok=false
  fi

  container_probe_status="$(remote_alpha_vault_container_probe "${REMOTE_ALPHA_CONTAINER_PROBE_IMAGE}" "${ca_bundle_path}" "${REMOTE_ALPHA_VAULT_ADDRESS}")"
  export REMOTE_ALPHA_CONTAINER_PROBE_STATUS="${container_probe_status}"
  if [[ "${container_probe_status}" != "pass" && "${container_probe_status}" != "not_exercised" ]]; then
    overall_ok=false
  fi

  remote_alpha_vault_write_summary \
    "${summary_tmp_path}" \
    "${config_meta_path}" \
    "${health_meta_path}" \
    "${jwt_meta_path}" \
    "${login_meta_path}" \
    "${lookup_meta_path}" \
    "${proof_read_meta_path}" \
    "${proof_runtime_secret_meta_path}" \
    "${revoke_meta_path}"

  remote_alpha_vault_validate_summary_file "${summary_tmp_path}" "${jwt_value}" "${vault_token}"

  mkdir -p "$(dirname "${REMOTE_ALPHA_SUMMARY_PATH}")"
  mv "${summary_tmp_path}" "${REMOTE_ALPHA_SUMMARY_PATH}"
  chmod 0644 "${REMOTE_ALPHA_SUMMARY_PATH}" 2>/dev/null || true

  printf 'wrote %s\n' "${REMOTE_ALPHA_SUMMARY_PATH}"

  if [[ "${overall_ok}" == "true" ]]; then
    return 0
  fi
  return 1
}
